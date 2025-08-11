/// <reference types="@cloudflare/workers-types" />
export interface Env {
  ALLOWED_DOMAINS: KVNamespace; // KV: keys are allowed email domains, value '1'
  DB: D1Database;               // D1 database binding
  MC_QUEUE: Queue;              // Cloudflare Queue binding
  FINGERPRINT_SALT: string;     // random secret for hashing fingerprints
}

// ---- Utilities ----
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };

function json(body: unknown, init?: number | ResponseInit) {
  if (typeof init === 'number') return new Response(JSON.stringify(body), { status: init, headers: JSON_HEADERS });
  return new Response(JSON.stringify(body), { ...init, headers: { ...JSON_HEADERS, ...(init as ResponseInit)?.headers } });
}

function text(body: string, status = 500) {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8' } });
}

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function getClientIp(req: Request): string | undefined {
  return req.headers.get('cf-connecting-ip') ?? undefined;
}

async function makeFingerprint(req: Request, salt: string): Promise<string> {
  const ua = req.headers.get('user-agent') ?? '';
  const acc = req.headers.get('accept') ?? '';
  const lang = req.headers.get('accept-language') ?? '';
  const ip = getClientIp(req) ?? '';
  return sha256Hex(`${salt}|${ua}|${acc}|${lang}|${ip}`);
}

function sleep(ms: number) {
  return new Promise(res => setTimeout(res, ms));
}
function jitter(min = 25, max = 75) {
  return Math.floor(min + Math.random() * (max - min + 1));
}

// ---- Domain allow-list check via KV ----
async function isDomainAllowed(env: Env, email: string): Promise<boolean> {
  const domain = email.split('@')[1]?.toLowerCase().trim();
  if (!domain) return false;
  const hit = await env.ALLOWED_DOMAINS.get(domain);
  return !!hit;
}

// ---- Atomic coupon allocation + redemption (no BEGIN; bounded retry + revert-on-conflict) ----
async function redeemAtomic(env: Env, emailHash: string, fingerprint: string) {
  const now = Math.floor(Date.now() / 1000);

  // Quick duplicate check (cheap)
  const dup = await env.DB
    .prepare('SELECT 1 FROM redemptions WHERE email_hash = ?1 OR fingerprint = ?2 LIMIT 1')
    .bind(emailHash, fingerprint)
    .first();
  if (dup) return { status: 409 as const, error: 'Already redeemed' };

  const MAX_TRIES = 3;
  for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
    try {
      // Claim one coupon atomically
      const allocate = await env.DB.prepare(
        `WITH pick AS (
           SELECT code FROM coupons
           WHERE redeemed_at IS NULL
           LIMIT 1
         )
         UPDATE coupons
         SET redeemed_at = ?1, redeemed_by_email_hash = ?2, fingerprint = ?3
         WHERE code IN (SELECT code FROM pick)
         RETURNING code`
      ).bind(now, emailHash, fingerprint).first<{ code: string }>();

      // Nothing to claim
      if (!allocate?.code) {
        // On first/second attempt, brief retry in case of transient lock/contention
        if (attempt < MAX_TRIES) { await sleep(jitter()); continue; }
        return { status: 410 as const, error: 'No coupons available' };
      }

      const code = allocate.code;

      // Persist redemption. If uniqueness fails, revert and surface 409.
      try {
        await env.DB.prepare(
          'INSERT INTO redemptions (email_hash, fingerprint, redeemed_at, coupon_code) VALUES (?1, ?2, ?3, ?4)'
        ).bind(emailHash, fingerprint, now, code).run();

        return { status: 200 as const, coupon: code };
      } catch (e: any) {
        // Revert the claim so stock isn’t burned
        await env.DB
          .prepare('UPDATE coupons SET redeemed_at = NULL, redeemed_by_email_hash = NULL, fingerprint = NULL WHERE code = ?1')
          .bind(code)
          .run();

        const msg = String(e?.message || e);
        // Likely uniqueness conflict -> treat as duplicate redemption
        if (/UNIQUE|constraint/i.test(msg)) {
          return { status: 409 as const, error: 'Already redeemed' };
        }

        // Other insert error → small retry, then bubble on last attempt
        if (attempt < MAX_TRIES) {
          await sleep(jitter());
          continue;
        }
        throw e;
      }
    } catch (e) {
      // Allocation error (e.g., transient lock) → small retry
      if (attempt < MAX_TRIES) {
        await sleep(jitter());
        continue;
      }
      // Final failure bubbles to caller
      throw e;
    }
  }

  // Should not reach here
  return { status: 500 as const, error: 'Unknown error' };
}

// ---- HTTP handler ----
async function handleRedeem(req: Request, env: Env, ctx: ExecutionContext) {
  if (req.method !== 'POST') return text('Method Not Allowed', 405);

  const ct = req.headers.get('content-type') || '';
  if (!ct.includes('application/json')) return json({ error: 'Unsupported media type' }, 415);

  let body: any;
  try { body = await req.json(); } catch { return json({ error: 'Invalid JSON body' }, 400); }

  const firstName = String(body.firstName || '').trim();
  const lastName  = String(body.lastName || '').trim();
  const email     = String(body.email || '').trim().toLowerCase();
  const consent   = Boolean(body.consent);

  if (!firstName || !lastName || !email) return json({ error: 'Missing required fields' }, 400);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Invalid email format' }, 400);
  if (!consent) return json({ error: 'Consent required' }, 400);

  // 1) Domain allow-list via KV
  if (!(await isDomainAllowed(env, email))) return json({ error: 'Email domain not allowed' }, 403);

  // 2) Derive stable identifiers
  const emailHash = await sha256Hex(email);
  const fingerprint = await makeFingerprint(req, env.FINGERPRINT_SALT);

  // 3) Atomic reservation & write (with retries inside)
  const result = await redeemAtomic(env, emailHash, fingerprint);
  if ('error' in result) return json({ error: result.error }, result.status);

  // 4) Enqueue Mailchimp payload (fire-and-forget)
  const payload = { firstName, lastName, email, consent, coupon: result.coupon, redeemedAt: Date.now() };
  ctx.waitUntil(env.MC_QUEUE.send(payload));

  return json({ coupon: result.coupon }, 200);
}

// Basic health endpoint and route switcher
function notFound() { return json({ error: 'Not found' }, 404); }

async function router(req: Request, env: Env, ctx: ExecutionContext) {
  const url = new URL(req.url);
  if (url.pathname === '/api/redeem-coupon') return handleRedeem(req, env, ctx);
  if (url.pathname === '/health') return json({ ok: true });
  return notFound();
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    try {
      return await router(request, env, ctx);
    } catch (err: any) {
      const msg = err?.message || 'Server error';
      return json({ error: msg }, 500);
    }
  }
};