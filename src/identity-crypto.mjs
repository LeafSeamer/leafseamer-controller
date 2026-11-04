import {randomBytes, createHash, timingSafeEqual} from 'node:crypto';
import argon2 from 'argon2';

export const passwordProfile = 'identity-runtime/1';
export class IdentityError extends Error {
  constructor(code) { super(code); this.name = 'IdentityError'; this.code = code; }
}
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
export function validateLogin(login) {
  check(typeof login === 'string' && login.isWellFormed() && [...login].length >= 1 && [...login].length <= 128 && !/[\x00-\x1f\x7f]/.test(login), 'login_input');
}
function passwordBytes(password) {
  check(typeof password === 'string' && password.isWellFormed() && [...password].length >= 16 && [...password].length <= 4096, 'password_input');
  return Buffer.from(password, 'utf8');
}
const phcPattern = /^\$argon2id\$v=19\$m=65536,p=1,t=3\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{43})$/;
function parsePhc(phc) {
  check(typeof phc === 'string', 'password_profile');
  const match = phcPattern.exec(phc); check(match !== null && match[0] === phc, 'password_profile');
  const salt = Buffer.from(match[1], 'base64'), digest = Buffer.from(match[2], 'base64');
  check(salt.length === 16 && digest.length === 32 && salt.toString('base64').replace(/=+$/, '') === match[1] && digest.toString('base64').replace(/=+$/, '') === match[2], 'password_profile');
  return {salt, digest};
}
const options = {type: argon2.argon2id, version: 19, memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32};
let active = 0;
const queue = [];
function reserve() {
  if (active < 2) { active++; return Promise.resolve(); }
  if (queue.length === 8) return Promise.reject(new IdentityError('password_busy'));
  return new Promise(resolve => queue.push(resolve));
}
function release() { const next = queue.shift(); if (next) next(); else active--; }
export async function hashPassword(password) {
  const bytes = passwordBytes(password);
  let acquired = false;
  try {
    await reserve(); acquired = true;
    const phc = await argon2.hash(bytes, {...options, salt: randomBytes(16)});
    parsePhc(phc); return phc;
  } finally { bytes.fill(0); if (acquired) release(); }
}
export async function verifyPassword(password, phc, profile = passwordProfile) {
  check(profile === passwordProfile, 'password_profile');
  const {salt, digest} = parsePhc(phc), bytes = passwordBytes(password);
  let acquired = false, actual;
  try {
    await reserve(); acquired = true;
    actual = await argon2.hash(bytes, {...options, salt, raw: true});
    return timingSafeEqual(actual, digest);
  } finally { bytes.fill(0); actual?.fill(0); if (acquired) release(); }
}
