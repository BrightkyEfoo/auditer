import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";

/**
 * Password hashing for the email+password login path.
 *
 * scrypt from node:crypto — no new dependency, and memory-hard, so a leaked
 * digest costs an attacker RAM per guess instead of just GPU cycles. The cost
 * parameters travel WITH the digest (`scrypt$N$r$p$salt$hash`) so raising N
 * later re-verifies existing rows instead of locking every account out; a
 * rehash-on-login upgrade can be layered on top without a format change.
 */

const N = 16384; // 128 * N * r = 16 MiB of state per hash — under node's 32 MiB maxmem default
const R = 8;
const P = 1;
const KEYLEN = 64;
const SALT_BYTES = 16;

/** Fixed salt for the decoy hash below — it never authenticates anything. */
const DECOY_SALT = Buffer.alloc(SALT_BYTES, 0x2a);

/** scrypt as a promise; node only exposes the callback form. */
function derive(
  password: string,
  salt: Buffer,
  n: number,
  r: number,
  p: number,
  keylen: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, { N: n, r, p }, (err, key) => {
      if (err) reject(err);
      else resolve(key);
    });
  });
}

/** Hash a plaintext password into the storable `scrypt$...` string. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const key = await derive(password, salt, N, R, P, KEYLEN);
  return ["scrypt", N, R, P, salt.toString("base64"), key.toString("base64")].join("$");
}

/**
 * Constant-time verify. Returns false rather than throwing on a missing or
 * malformed digest, so callers can pass `user?.passwordHash` straight from the
 * row without branching on OAuth-only accounts first.
 */
export async function verifyPassword(
  password: string,
  stored: string | null | undefined,
): Promise<boolean> {
  if (!stored) return false;

  const [tag, nRaw, rRaw, pRaw, saltB64, hashB64] = stored.split("$");
  if (tag !== "scrypt" || !nRaw || !rRaw || !pRaw || !saltB64 || !hashB64) return false;

  const n = Number(nRaw);
  const r = Number(rRaw);
  const p = Number(pRaw);
  // Bound the parameters read back from the row: a tampered or corrupted N
  // would turn one login attempt into a self-inflicted memory DoS.
  if (!Number.isSafeInteger(n) || n < 1024 || n > 1 << 20) return false;
  if (!Number.isSafeInteger(r) || r < 1 || r > 32) return false;
  if (!Number.isSafeInteger(p) || p < 1 || p > 16) return false;

  const salt = Buffer.from(saltB64, "base64");
  const expected = Buffer.from(hashB64, "base64");
  if (salt.length === 0 || expected.length === 0) return false;

  let key: Buffer;
  try {
    key = await derive(password, salt, n, r, p, expected.length);
  } catch {
    return false; // scrypt refused the parameters (e.g. maxmem) — treat as a bad digest
  }
  // Lengths match by construction (keylen = expected.length); timingSafeEqual
  // throws on a mismatch, so keep the guard rather than trust the arithmetic.
  if (key.length !== expected.length) return false;
  return timingSafeEqual(key, expected);
}

/**
 * Burn one scrypt round on a throwaway digest.
 *
 * Login calls this when the email is unknown. Without it, "no such account"
 * returns in microseconds while "wrong password" takes a full KDF round — a
 * timing side channel that enumerates accounts just as well as a distinct error
 * message would.
 */
export async function decoyVerify(password: string): Promise<void> {
  await derive(password, DECOY_SALT, N, R, P, KEYLEN);
}

// ── Credential rate limiting ────────────────────────────────────────────────

const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;
/** Sweep threshold — a rotating-IP flood must not grow the map without bound. */
const SWEEP_AT = 5000;

const attempts = new Map<string, { count: number; resetAt: number }>();

/**
 * Per-IP throttle on the credential endpoints: 10 attempts per 15 minutes.
 *
 * PER-PROCESS ONLY. The counters live in this process's heap: they reset on
 * deploy and each replica keeps its own tally, so N replicas mean N times the
 * budget. That is enough to blunt naive online guessing and nothing more — the
 * real limiter is a shared Valkey counter keyed on (ip, route), which lands
 * with the Valkey work. Do not treat this as an abuse control.
 *
 * Returns true when the attempt is allowed.
 */
export function allowCredentialAttempt(ip: string): boolean {
  const now = Date.now();

  // Lazy cleanup: only walk the map once it is big enough to matter, so the
  // common path stays a single lookup instead of a full scan per request.
  if (attempts.size >= SWEEP_AT) {
    for (const [key, bucket] of attempts) {
      if (bucket.resetAt <= now) attempts.delete(key);
    }
  }

  const bucket = attempts.get(ip);
  if (!bucket || bucket.resetAt <= now) {
    attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (bucket.count >= MAX_ATTEMPTS) return false;
  bucket.count += 1;
  return true;
}
