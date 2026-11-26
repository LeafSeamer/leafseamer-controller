import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import {canonical} from './auth-clock-value.mjs';
import {contractSelection} from './sdk/index.mjs';
import {pairingFields} from './peer-pairing-value.mjs';
import {localExtensionOperations,localExtensionPath} from './local-extension-management.mjs';
import {localEventOperations} from './local-event-management.mjs';
import {localRunEndorsementOperations} from './local-pairing-management.mjs';

export const localPairingPath = '/auth/local-pairing/v1';
export const localPairingLimit = 32768;
export const localPairingOperations = Object.freeze(['stage', 'export', 'inspect', 'prove', 'activate', 'read-audience', 'grant-audience',
  ...localEventOperations,...localRunEndorsementOperations]);
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

async function runLocalAdmin({origin, caFile, input}, {route,operations,prefix}){
  const requireInput=(valid,suffix='input')=>check(valid,prefix+'_'+suffix);
  let site;
  try { site = new URL(origin); } catch { throw new LocalPairingError(prefix+'_origin'); }
  requireInput(site.origin === origin && site.protocol === 'https:' && loopbackHost(site.hostname),'origin');
  requireInput(typeof caFile === 'string' && path.isAbsolute(caFile),'trust');
  const fd = fs.openSync(caFile, 'r');
  let ca;
  try {
    const stat = fs.fstatSync(fd);
    requireInput(stat.isFile() && stat.size > 0 && stat.size <= 65536,'trust');
    ca = Buffer.alloc(stat.size);
    requireInput(fs.readSync(fd, ca, 0, ca.length, null) === ca.length,'trust');
  } finally { fs.closeSync(fd); }
  pairingFields(input, 'login,password,operation,request');
  const {login, password, operation, request: body} = input;
  requireInput(typeof login === 'string' && typeof password === 'string' && operations.includes(operation));
  const session = await request(origin, '/auth/sessions', 'POST', ca, {}, {login, password});
  requireInput(session.status === 201,'login');
  const cookie = session.headers['set-cookie']?.[0]?.split(';', 1)[0], csrf = session.headers['x-csrf-token'];
  requireInput(/^leafseamer_session=v1\.[a-f0-9-]{36}\.[A-Za-z0-9_-]{43}$/.test(cookie) && /^[A-Za-z0-9_-]{43}$/.test(csrf),'login');
  const auth = {'Cookie': cookie, 'X-CSRF-Token': csrf};
  let result;
  try {
    const response = await request(origin, route, 'POST', ca, auth, {operation, request: body});
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(response.bytes)); }
    catch { throw new LocalPairingError(prefix+(response.status === 200 ? '_response' : '_rejected')); }
    if (response.status !== 200) {
      const errors=route===localPairingPath?/^(?:peer_pairing|local_pairing|remote_authorization|event_scope|service_identity|service_consumer|service_token|run_endorsement|subscription)_[a-z_]{1,60}$/:
        /^(?:local_extension|extension|worker_launch|worker_authorization)_[a-z_]{1,65}$/;
      throw new LocalPairingError(typeof value?.error === 'string' && errors.test(value.error)?value.error:prefix+'_rejected');
    }
    requireInput(response.bytes.toString('utf8') === canonical(value),'response');
    result = response.bytes;
  } finally {
    // 会话清理不改变管理操作的持久结果，失联时由现有会话到期机制回收。
    await request(origin, '/auth/sessions/current', 'DELETE', ca, auth).catch(() => {});
  }
  return result;
}

export const runLocalPairingAdmin=input=>runLocalAdmin(input,{route:localPairingPath,operations:localPairingOperations,prefix:'local_pairing'});
export const runLocalExtensionAdmin=input=>runLocalAdmin(input,{route:localExtensionPath,operations:localExtensionOperations.filter(name=>!name.startsWith('lookup-')),
  prefix:'local_extension'});
