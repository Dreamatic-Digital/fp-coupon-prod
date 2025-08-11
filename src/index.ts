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
  const sid  = req.headers.get('x-client-session') ?? '';
  return sha256Hex(`${salt}|${ua}|${acc}|${lang}|${sid}`);
}

function sleep(ms: number) { return new Promise(res => setTimeout(res, ms)); }
function jitter(min = 25, max = 75) { return Math.floor(min + Math.random() * (max - min + 1)); }

// ---- Domain allow-list check via KV ----
async function isDomainAllowed(env: Env, email: string): Promise<boolean> {
  const domain = email.split('@')[1]?.toLowerCase().trim();
  if (!domain) return false;
  const hit = await env.ALLOWED_DOMAINS.get(domain);
  return !!hit;
}

// ---- Atomic coupon allocation using only `coupons` table ----
// - No SQL BEGIN/COMMIT
// - Bounded retry (3x) with tiny jitter
// - Enforced one-per-email/fingerprint via partial UNIQUE indexes on coupons
async function redeemAtomic(env: Env, emailHash: string, fingerprint: string) {
  const now = Math.floor(Date.now() / 1000);

  // Fast duplicate check (cheap path)
  const dup = await env.DB
    .prepare('SELECT 1 FROM coupons WHERE redeemed_by_email_hash = ?1 OR fingerprint = ?2 LIMIT 1')
    .bind(emailHash, fingerprint)
    .first();
  if (dup) return { status: 409 as const, error: 'Already redeemed' };

  const MAX_TRIES = 3;
  for (let attempt = 1; attempt <= MAX_TRIES; attempt++) {
    try {
      // Claim ONE available coupon atomically and stamp ownership
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

      if (!allocate?.code) {
        // brief retry in case of momentary contention; otherwise out of stock
        if (attempt < MAX_TRIES) { await sleep(jitter()); continue; }
        return { status: 410 as const, error: 'No coupons available' };
      }

      // If partial UNIQUE indexes exist, a competing request trying to use the same
      // email/fingerprint would make this UPDATE fail with a UNIQUE constraint error,
      // which we'd catch in the catch-block and translate to 409. Since we got here,
      // the claim succeeded.
      return { status: 200 as const, coupon: allocate.code };
    } catch (e: any) {
      const msg = String(e?.message || e);

      // If UNIQUE constraint tripped (because another row already has this email/fp), surface 409
      if (/UNIQUE|constraint/i.test(msg)) {
        return { status: 409 as const, error: 'Already redeemed' };
      }

      // Transient error → quick retry
      if (attempt < MAX_TRIES) {
        await sleep(jitter());
        continue;
      }

      // Final failure bubbles
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

  // 2.5) (Optional but recommended) Ensure partial UNIQUE indexes once — cheap/idempotent
  //      These prevent multiple coupons being assigned to the same email/fingerprint.
  try {
    await env.DB.prepare(
      "CREATE UNIQUE INDEX IF NOT EXISTS ux_coupons_email_once ON coupons(redeemed_by_email_hash) WHERE redeemed_by_email_hash IS NOT NULL"
    ).run();
    await env.DB.prepare(
      "CREATE UNIQUE INDEX IF NOT EXISTS ux_coupons_fp_once ON coupons(fingerprint) WHERE fingerprint IS NOT NULL"
    ).run();
  } catch { /* ignore if not supported or already created */ }

  // 3) Atomic reservation & write (with internal retries)
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