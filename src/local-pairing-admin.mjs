import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import {canonical} from './auth-clock-value.mjs';
import {contractSelection} from './sdk/index.mjs';
import {pairingFields} from './peer-pairing-value.mjs';

export const localPairingPath = '/auth/local-pairing/v1';
export const localPairingLimit = 32768;
export const localPairingOperations = Object.freeze(['stage', 'export', 'inspect', 'prove', 'activate', 'read-audience', 'grant-audience']);
export const loopbackHost = host => ['127.0.0.1', '::1', '[::1]'].includes(host);

export class LocalPairingError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const check = (valid, code = 'local_pairing_input') => { if (!valid) throw new LocalPairingError(code); };

function request(origin, route, method, ca, extra, value = undefined) {
  const bytes = value === undefined ? null : Buffer.from(canonical(value));
  check(bytes === null || bytes.length <= localPairingLimit);
  return new Promise((resolve, reject) => {
    const fail = () => reject(new LocalPairingError('local_pairing_transport'));
    const req = https.request(origin + route, {method, ca, agent: false, minVersion: 'TLSv1.2', rejectUnauthorized: true,
      headers: {'Origin': origin, 'X-LeafSeamer-Contract': contractSelection.contract_id,
        'X-LeafSeamer-Contract-Digest': contractSelection.contract_digest,
        ...(bytes && {'Content-Type': 'application/json', 'Content-Length': String(bytes.length)}), ...extra}}, res => {
      const chunks = [];
      let length = 0;
      res.on('data', chunk => {
        length += chunk.length;
        if (length > localPairingLimit) res.destroy();
        else chunks.push(chunk);
      });
      res.once('error', fail);
      res.once('aborted', fail);
      res.once('end', () => resolve({status: res.statusCode, headers: res.headers, bytes: Buffer.concat(chunks, length)}));
    });
    const timeout = setTimeout(() => req.destroy(), 8000);
    req.once('close', () => clearTimeout(timeout));
    req.once('error', fail);
    req.end(bytes);
  });
}

export async function runLocalPairingAdmin({origin, caFile, input}) {
  let site;
  try { site = new URL(origin); } catch { throw new LocalPairingError('local_pairing_origin'); }
  check(site.origin === origin && site.protocol === 'https:' && loopbackHost(site.hostname), 'local_pairing_origin');
  check(typeof caFile === 'string' && path.isAbsolute(caFile), 'local_pairing_trust');
  const fd = fs.openSync(caFile, 'r');
  let ca;
  try {
    const stat = fs.fstatSync(fd);
    check(stat.isFile() && stat.size > 0 && stat.size <= 65536, 'local_pairing_trust');
    ca = Buffer.alloc(stat.size);
    check(fs.readSync(fd, ca, 0, ca.length, null) === ca.length, 'local_pairing_trust');
  } finally { fs.closeSync(fd); }
  pairingFields(input, 'login,password,operation,request');
  const {login, password, operation, request: body} = input;
  check(typeof login === 'string' && typeof password === 'string' && localPairingOperations.includes(operation));
  const session = await request(origin, '/auth/sessions', 'POST', ca, {}, {login, password});
  check(session.status === 201, 'local_pairing_login');
  const cookie = session.headers['set-cookie']?.[0]?.split(';', 1)[0], csrf = session.headers['x-csrf-token'];
  check(/^leafseamer_session=v1\.[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/.test(cookie) && /^[A-Za-z0-9_-]{43}$/.test(csrf), 'local_pairing_login');
  const auth = {'Cookie': cookie, 'X-CSRF-Token': csrf};
  let result;
  try {
    const response = await request(origin, localPairingPath, 'POST', ca, auth, {operation, request: body});
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(response.bytes)); }
    catch { throw new LocalPairingError(response.status === 200 ? 'local_pairing_response' : 'local_pairing_rejected'); }
    if (response.status !== 200) {
      throw new LocalPairingError(typeof value?.error === 'string' && /^(?:peer_pairing|local_pairing|remote_authorization)_[a-z_]{1,60}$/.test(value.error) ?
        value.error : 'local_pairing_rejected');
    }
    check(response.bytes.toString('utf8') === canonical(value), 'local_pairing_response');
    result = response.bytes;
  } finally {
    // 会话清理不改变管理操作的持久结果，失联时由现有会话到期机制回收。
    await request(origin, '/auth/sessions/current', 'DELETE', ca, auth).catch(() => {});
  }
  return result;
}
