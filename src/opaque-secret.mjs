import {randomBytes,createHash,timingSafeEqual} from 'node:crypto';
import {IdentityError} from './identity-error.mjs';
const check = (ok, code) => { if (!ok) throw new IdentityError(code); };
const kinds = new Set(['service_credential', 'access_token', 'session_refresh', 'ws_ticket', 'first_admin', 'pairing_challenge']);
export function opaqueVerifier(kind, secret) {
  check(kinds.has(kind), 'secret_kind');
  check(typeof secret === 'string' && /^[A-Za-z0-9_-]{43}$/.test(secret), 'secret_encoding');
  const bytes = Buffer.from(secret, 'base64url');
  try {
    check(bytes.length === 32 && bytes.toString('base64url') === secret, 'secret_encoding');
    return createHash('sha256').update('LeafSeamer/opaque-verifier/v1\0').update(kind).update('\0').update(bytes).digest();
  } finally { bytes.fill(0); }
}
export function createOpaqueSecret(kind) {
  const bytes = randomBytes(32);
  try { const secret = bytes.toString('base64url'); return {secret, verifier: opaqueVerifier(kind, secret)}; }
  finally { bytes.fill(0); }
}
export function verifyOpaqueSecret(kind, secret, verifier) {
  check(Buffer.isBuffer(verifier) && verifier.length === 32, 'secret_verifier');
  const actual = opaqueVerifier(kind, secret);
  try { return timingSafeEqual(actual, verifier); } finally { actual.fill(0); }
}
