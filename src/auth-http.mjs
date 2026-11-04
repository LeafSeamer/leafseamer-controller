import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';

const routes = new Map([
  ['/auth/sessions', 'POST'], ['/auth/sessions/refresh', 'POST'],
  ['/auth/service-tokens', 'POST'], ['/api/v1/session', 'GET'],
]);
const maximumBody = 16384, maximumPending = 16, bodyDeadline = 2000;
const rawPairs = flat => Array.from({length: flat.length / 2}, (_, i) => [flat[2 * i], flat[2 * i + 1]]);
const credentialPattern = /^v1\.([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/;
const cookieFlags = '; Path=/auth; Secure; HttpOnly; SameSite=Strict';
const clearCookie = ['set-cookie', 'leafseamer_session=' + cookieFlags + '; Max-Age=0'];
const reject = code => { const error = new Error(code); error.code = code; error.name = 'IdentityError'; throw error; };
function credential(value) {
  const match = typeof value === 'string' ? credentialPattern.exec(value) : null;
  if (!match || Buffer.from(match[2], 'base64url').toString('base64url') !== match[2]) reject('session_invalid');
  return {credential_id: match[1], secret: match[2]};
}
function cookieInput(req) {
  const values = (req.headers.cookie ?? '').split(';').map(v => v.trim()).filter(v => v.split('=')[0] === 'leafseamer_session');
  if (values.length !== 1) reject('session_invalid');
  return {...credential(values[0].slice('leafseamer_session='.length)), csrf: req.headers['x-csrf-token']};
}
const wireCredential = (id, secret) => 'v1.' + id + '.' + secret;
const timestamp = (value, up = false) => new Date(Number((BigInt(value) + (up ? 999999n : 0n)) / 1000000n)).toISOString();
function sessionView(session, permissions, revision, until = null) {
  const end = [session.expires_ns, session.idle_before_ns, ...(until ? [until] : [])].map(BigInt).reduce((a, b) => a < b ? a : b);
  return {principal_id: session.principal_id, session_id: session.session_id, issuer_id: session.issuer_id, issuer_epoch: session.issuer_epoch,
    authorization_revision: revision, permissions, validity: {not_before: timestamp(session.not_before_ns, true), not_after: timestamp(end), authorization_policy_revision: revision}};
}
function failure(error) {
  if (error?.name === 'ClockError') return [503, 'CLOCK_UNTRUSTED'];
  if (['login_invalid', 'session_invalid', 'session_expired', 'token_invalid', 'token_expired', 'password_invalid'].includes(error?.code)) return [401, 'AUTH_REQUIRED'];
  if (['local_authorization_denied', 'local_authorization_audience', 'http_origin', 'http_tls', 'http_permission', 'http_extension'].includes(error?.code)) return [403, 'PERMISSION_DENIED'];
  if (['login_throttled', 'password_busy', 'token_capacity'].includes(error?.code)) return [429, 'CAPACITY_EXCEEDED'];
  if (error?.code === 'token_request_invalid') return [422, 'INVALID_REQUEST'];
  if (['local_authorization_unavailable', 'token_authority_unavailable'].includes(error?.code)) return [503, 'WORKER_NOT_READY'];
  return [503, 'CRITICAL_STORAGE_UNAVAILABLE'];
}

// origin与sessions只能由可信本地启动装配。代理身份头不能开启认证入口。
export function createAuthenticationHttp({serviceId, serviceBootId, sessions = null, origin = null}) {
  const adapter = createHttpAdapter(selection);
  let site = null;
  if (origin !== null) {
    try { site = new URL(origin); } catch { throw new Error('authentication_origin'); }
    if (site.protocol !== 'https:' || site.origin !== origin || site.username || site.password || site.pathname !== '/' || site.search || site.hash) throw new Error('authentication_origin');
  }
  let pending = 0;
  function empty(res, status, headers = {}) {
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, {...headers, 'Cache-Control': 'no-store', Connection: 'close', 'Content-Length': '0'}); res.end(); }
  }
  async function reply(res, request, status, code, {data, extraHeaders = [], beforeSend = () => {}} = {}) {
    const requestId = crypto.randomUUID();
    const body = Buffer.from(JSON.stringify({request_id: requestId, service_id: serviceId, service_boot_id: serviceBootId,
      protocol_version: selection.contract_id, selection, ...(code ? {error: {code, message_key: code.toLowerCase(), request_id: requestId,
        details: {}, existing_command_id: null, existing_operation_id: null, retry_advice: 'do_not_retry'}} : {data})}));
    const headers = [['content-type', 'application/json'], ['content-length', String(body.length)],
      ['x-leafseamer-contract', selection.contract_id], ['x-leafseamer-contract-digest', selection.contract_digest],
      ['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['connection', 'close'], ...extraHeaders];
    // 任何响应字段或选择失配均在发送响应头前失败，不能交付半个可信结果。
    await adapter.decodeResponse(body, adapter.prepareResponse(request, String(status), headers));
    beforeSend();
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, Object.fromEntries(headers)); res.end(body); }
  }
  async function dispatch(req, res, request, body) {
    if (!sessions || !site) { await reply(res, request, 503, 'WORKER_NOT_READY'); return; }
    const operation = request.operation_id;
    try {
      if (!(req.socket instanceof TLSSocket) || req.socket.encrypted !== true || !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol())) reject('http_tls');
      if (req.headers.host !== site.host || (operation !== 'getSession' || req.headers.origin !== undefined) && req.headers.origin !== origin ||
          req.headers['sec-fetch-site'] === 'cross-site') reject('http_origin');
      if (operation === 'login' || operation === 'refreshSession') {
        const old = operation === 'refreshSession' ? cookieInput(req) : null;
        const result = old ? sessions.refresh(old) : await sessions.login(body);
        const current = {credential_id: result.credential_id, secret: result.secret, csrf: old?.csrf ?? result.csrf};
        const view = () => { const v = sessions.presentation(current); return sessionView(v.session, v.authorization.permissions, v.authorization.revision); };
        const data = view();
        await reply(res, request, old ? 200 : 201, null, {data,
          extraHeaders: [['set-cookie', 'leafseamer_session=' + wireCredential(current.credential_id, current.secret) + cookieFlags], ['x-csrf-token', current.csrf]],
          beforeSend() { if (JSON.stringify(view()) !== JSON.stringify(data)) reject('local_authorization_denied'); }});
      } else if (operation === 'issueToken') {
        if (body.extension_instance_id !== null) reject('http_extension');
        const current = cookieInput(req);
        const issued = sessions.issueToken(current, {request_id: crypto.randomUUID(), audience: body.audience, requested_scopes: body.requested_scopes});
        if (issued.replay || !issued.secret) reject('token_invalid');
        const proof = {token_id: issued.token.token_id, secret: issued.secret};
        sessions.verifyToken(proof, serviceId);
        // expires_in为签发期限的秒数提示，服务器始终重新判断原绝对截止；响应不续期。
        const seconds = Number((BigInt(issued.token.expires_ns) - BigInt(issued.token.not_before_ns)) / 1000000000n);
        if (seconds < 1) reject('token_expired');
        await reply(res, request, 201, null, {data: {access_token: wireCredential(issued.token.token_id, issued.secret), token_type: 'Bearer', expires_in: seconds, audience: issued.token.audience},
          beforeSend() { sessions.verifyToken(proof, serviceId); }});
      } else {
        const bearer = typeof req.headers.authorization === 'string' ? /^Bearer (.+)$/i.exec(req.headers.authorization) : null;
        const decoded = credential(bearer?.[1]), proof = {token_id: decoded.credential_id, secret: decoded.secret};
        const view = () => {
          const v = sessions.verifyToken(proof, serviceId); if (!v.permissions.includes('session.read')) reject('http_permission');
          return sessionView({...v, not_before_ns: v.session_not_before_ns, expires_ns: v.session_expires_ns, idle_before_ns: v.session_idle_before_ns}, v.permissions, v.policy_revision, v.expires_ns);
        };
        const data = view();
        await reply(res, request, 200, null, {data, beforeSend() { if (JSON.stringify(view()) !== JSON.stringify(data)) reject('local_authorization_denied'); }});
      }
    } catch (error) {
      const [status, code] = failure(error);
      await reply(res, request, status, code, {extraHeaders: status === 401 && operation !== 'getSession' ? [clearCookie] : []});
    }
  }
  async function serve(req, res) {
    let request;
    try { request = adapter.prepareRequest('controller', req.method, req.url, rawPairs(req.rawHeaders)); }
    catch { empty(res, 400); return; }
    if (pending >= maximumPending) { await reply(res, request, 429, 'CAPACITY_EXCEEDED'); return; }
    if (req.headers['transfer-encoding'] !== undefined && req.headers['transfer-encoding'] !== 'chunked') { empty(res, 400); return; }
    if (Number(req.headers['content-length'] ?? 0) > maximumBody) { await reply(res, request, 413, 'PAYLOAD_TOO_LARGE'); return; }
    pending++;
    try {
      const bytes = await new Promise((resolve, reject) => {
        const chunks = []; let size = 0, settled = false;
        const finish = (error, value) => {
          if (settled) return; settled = true; clearTimeout(timer);
          req.off('data', data); req.off('end', end); req.off('aborted', abort); req.off('error', abort); res.off('close', abort);
          req.pause(); error ? reject(error) : resolve(value);
        };
        const data = chunk => { size += chunk.length; if (size > maximumBody) finish(413); else chunks.push(chunk); };
        const end = () => finish(null, Buffer.concat(chunks, size));
        const abort = () => finish(400);
        const timer = setTimeout(() => finish(408), bodyDeadline); timer.unref();
        req.on('data', data); req.once('end', end); req.once('aborted', abort); req.once('error', abort); res.once('close', abort);
      });
      let decoded;
      try { decoded = await adapter.decodeRequest(bytes, request); }
      catch { await reply(res, request, 400, 'INVALID_REQUEST'); return; }
      await dispatch(req, res, request, decoded?.value ?? null);
    } catch (status) {
      if (status === 413) await reply(res, request, 413, 'PAYLOAD_TOO_LARGE');
      else empty(res, status === 408 ? 408 : status === 400 ? 400 : 503);
    } finally { pending--; }
  }
  return Object.freeze({handle(req, res) {
    const method = routes.get(req.url?.split('?')[0]);
    if (!method) return false;
    if (req.method !== method) { empty(res, 405, {Allow: method}); return true; }
    void serve(req, res).catch(() => empty(res, 503)); return true;
  }});
}
