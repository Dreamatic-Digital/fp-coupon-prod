export interface Env {
  ALLOWED_DOMAINS: KVNamespace; // KV: keys are allowed email domains, value '1'
  DB: D1Database;               // D1 database binding
  MC_QUEUE: Queue;              // Cloudflare Queue binding
  FINGERPRINT_SALT: string;     // random secret for hashing fingerprints
  // Mailchimp consumer bindings (used by the queue consumer only)
  MAILCHIMP_API_KEY?: string;   // e.g. 'usX-xxxxxxxxxxxxxx'
  MAILCHIMP_LIST_ID?: string;   // audience/list to add members to
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
  // Cloudflare provides this header
  return req.headers.get('cf-connecting-ip') ?? undefined;
}

async function makeFingerprint(req: Request, salt: string): Promise<string> {
  const ua = req.headers.get('user-agent') ?? '';
  const acc = req.headers.get('accept') ?? '';
  const lang = req.headers.get('accept-language') ?? '';
  const ip = getClientIp(req) ?? '';
  return sha256Hex(`${salt}|${ua}|${acc}|${lang}|${ip}`);
}

// ---- Schema helpers ----
const SCHEMA = {
  coupons: `CREATE TABLE IF NOT EXISTS coupons (
    code TEXT PRIMARY KEY,
    redeemed_at INTEGER,
    redeemed_by_email_hash TEXT,
    fingerprint TEXT
  );`,
  redemptions: `CREATE TABLE IF NOT EXISTS redemptions (
    email_hash TEXT UNIQUE,
    fingerprint TEXT UNIQUE,
    redeemed_at INTEGER NOT NULL,
    coupon_code TEXT NOT NULL,
    UNIQUE(email_hash),
    UNIQUE(fingerprint)
  );`
};

async function ensureSchema(db: D1Database) {
  // Idempotent, cheap on SQLite
  await db.exec(`${SCHEMA.coupons}\n${SCHEMA.redemptions}`);
}

// ---- Domain allow-list check via KV ----
async function isDomainAllowed(env: Env, email: string): Promise<boolean> {
  const domain = email.split('@')[1]?.toLowerCase().trim();
  if (!domain) return false;
  const hit = await env.ALLOWED_DOMAINS.get(domain);
  return !!hit;
}

// ---- Atomic coupon allocation + redemption ----
async function redeemAtomic(env: Env, emailHash: string, fingerprint: string) {
  const now = Math.floor(Date.now() / 1000);
  const tx = await env.DB.prepare('BEGIN IMMEDIATE').run();
  try {
    // Block repeat redemptions by email or fingerprint
    const dup = await env.DB.prepare(
      'SELECT 1 FROM redemptions WHERE email_hash = ?1 OR fingerprint = ?2 LIMIT 1'
    ).bind(emailHash, fingerprint).first();
    if (dup) {
      await env.DB.exec('ROLLBACK');
      return { status: 409 as const, error: 'Already redeemed' };
    }

    // Allocate ONE available coupon and mark it redeemed in a single statement
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
      await env.DB.exec('ROLLBACK');
      return { status: 410 as const, error: 'No coupons available' };
    }

    const code = allocate.code;

    // Record redemption log (unique guarantees)
    await env.DB.prepare(
      'INSERT INTO redemptions (email_hash, fingerprint, redeemed_at, coupon_code) VALUES (?1, ?2, ?3, ?4)'
    ).bind(emailHash, fingerprint, now, code).run();

    await env.DB.exec('COMMIT');
    return { status: 200 as const, coupon: code };
  } catch (err) {
    await env.DB.exec('ROLLBACK');
    throw err;
  }
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

  // 3) Ensure schema (safe if already created)
  await ensureSchema(env.DB);

  // 4) Atomic reservation & write
  const result = await redeemAtomic(env, emailHash, fingerprint);
  if ('error' in result) return json({ error: result.error }, result.status);

  // 5) Enqueue Mailchimp payload (decoupled from request path)
  const payload = {
    firstName, lastName, email, consent, coupon: result.coupon,
    redeemedAt: Date.now()
  };
  // Fire-and-forget enqueue; if this throws we still return 200 so the UX is snappy.
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

// ---- Queue consumer (Mailchimp) ----
// Processes details and pushes them to Mailchimp with simple back-off on rate limits. The
// consumer lives in the same Worker for simplicity; scale by moving to a dedicated Worker if needed.

async function pushToMailchimp(env: Env, item: any) {
  const apiKey = env.MAILCHIMP_API_KEY;
  const listId = env.MAILCHIMP_LIST_ID;
  if (!apiKey || !listId) return; // If not configured, treat as a no-op.

  const [key, dc] = apiKey.split('-');
  if (!dc) throw new Error('MAILCHIMP_API_KEY must include data centre suffix, e.g. us21-xxxx');
  const url = `https://${dc}.api.mailchimp.com/3.0/lists/${listId}/members`;

  const member = {
    email_address: item.email,
    status_if_new: 'subscribed',
    status: 'subscribed',
    merge_fields: { FNAME: item.firstName, LNAME: item.lastName },
    marketing_permissions: item.consent ? undefined : undefined // adjust as needed
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'authorization': 'Basic ' + btoa(`anystring:${apiKey}`),
      'content-type': 'application/json'
    },
    body: JSON.stringify(member)
  });

  if (res.status === 429 || res.status >= 500) {
    // Signal retry by throwing; the platform will re-deliver with backoff
    const txt = await res.text();
    const err = new Error(`Mailchimp backoff: ${res.status} ${txt}`);
    (err as any).retryable = true;
    throw err;
  }

  if (!res.ok) {
    // Non-retryable (4xx other than 429) – log and drop
    const txt = await res.text();
    console.warn('Mailchimp non-retryable', res.status, txt);
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    try {
      return await router(request, env, ctx);
    } catch (err: any) {
      const msg = err?.message || 'Server error';
      return json({ error: msg }, 500);
    }
  },

  // Cloudflare Queues consumer entrypoint
  async queue(batch: MessageBatch<any>, env: Env, ctx: ExecutionContext) {
    // Process sequentially to keep within vendor limits; for higher throughput, micro-batch with Promise.allSettled
    for (const msg of batch.messages) {
      try {
        await pushToMailchimp(env, msg.body);
        msg.ack();
      } catch (err: any) {
        console.warn('Queue processing error', err?.message || err);
        // Let the platform retry with exponential backoff
        msg.retry();
      }
    }
  }
};