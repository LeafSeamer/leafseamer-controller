import {randomBytes, timingSafeEqual} from 'node:crypto';
import argon2 from 'argon2';

export const passwordProfile = 'identity-runtime/1';
export {IdentityError} from './identity-error.mjs';
import {IdentityError} from './identity-error.mjs';
export {opaqueVerifier,createOpaqueSecret,verifyOpaqueSecret} from './opaque-secret.mjs';
const check = (ok, code) => { if (!ok) throw new IdentityError(code); };
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
