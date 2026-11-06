import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {createHttpAdapter,WireError} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {canonical} from './auth-clock-value.mjs';

const routes = new Map([
  ['/auth/sessions', 'POST'], ['/auth/sessions/refresh', 'POST'],
  ['/auth/service-tokens', 'POST'], ['/api/v1/session', 'GET'],
  ['/auth/sessions/current', 'DELETE'],
  ['/api/v1/request-contexts', 'POST'],
  ['/api/v1/commands', 'POST'], ['/api/v1/commands/lookup', 'POST'], ['/api/v1/commands/reject', 'POST'],
  ['/api/v1/devices', 'GET'],
]);
const maximumBody = 16384, maximumPending = 16, bodyDeadline = 2000;
const commandReads=['getCommand','getCommandEvidence','getCommandEvidenceRevision'];
const commandOperations = ['submitCommand', 'lookupCommandAdmission', 'rejectCommandAdmission',...commandReads];
const controlWrites=['acquireControl','releaseControl','offerTransfer','acceptTransfer','cancelTransfer'];
const controlOperations=['getControl','getControlOperation','getTransfer','lookupControlRequest',...controlWrites];
const readOperations = ['getSession', 'listDevices', 'getControl','getControlOperation','getTransfer',...commandReads];
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
function tokenInput(req) {
  const bearer = typeof req.headers.authorization === 'string' ? /^Bearer (.+)$/i.exec(req.headers.authorization) : null;
  const decoded = credential(bearer?.[1]); return {token_id: decoded.credential_id, secret: decoded.secret};
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
  if (error?.code === 'command_request_invalid') return [422, 'INVALID_REQUEST'];
  if (['command_permission', 'command_namespace','command_control_owner'].includes(error?.code)) return [403, 'PERMISSION_DENIED'];
  if(error?.code==='command_control_conflict')return [409,'REVISION_CONFLICT'];
  if(['command_capability','command_parameters','command_preconditions','command_completion','command_evidence_timeout'].includes(error?.code))return [422,'INVALID_REQUEST'];
  if(error?.code==='command_not_found')return [404,'NOT_FOUND'];
  if (error?.code === 'command_conflict') return [409, 'IDEMPOTENCY_CONFLICT'];
  if (error?.code === 'command_capacity') return [429, 'CAPACITY_EXCEEDED'];
  if (['command_admission_unavailable','command_control_pending','command_execution_unavailable','command_gate_not_ready'].includes(error?.code)) return [503, 'WORKER_NOT_READY'];
  if (['control_permission','control_target_permission','control_context'].includes(error?.code)) return [403,'PERMISSION_DENIED'];
  if (error?.code==='control_input') return [422,'INVALID_REQUEST'];
  if (error?.code==='control_conflict') return [409,'REVISION_CONFLICT'];
  if (error?.code==='control_not_found') return [404,'NOT_FOUND'];
  if (error?.code==='control_capacity') return [429,'CAPACITY_EXCEEDED'];
  if (error?.code?.startsWith('control_')) return [503,'WORKER_NOT_READY'];
  if (error?.code === 'device_read_denied') return [403, 'PERMISSION_DENIED'];
  if (error?.code === 'device_not_found') return [404, 'NOT_FOUND'];
  if (error?.code === 'device_cursor_invalid') return [422, 'INVALID_REQUEST'];
  if (error?.code === 'device_cursor_stale') return [409, 'REVISION_CONFLICT'];
  if (error?.code === 'device_migration_required') return [503, 'WORKER_NOT_READY'];
  if (['request_context_invalid', 'request_context_operation', 'request_context_time'].includes(error?.code)) return [422, 'INVALID_REQUEST'];
  if (['request_context_denied', 'request_context_permission'].includes(error?.code)) return [403, 'PERMISSION_DENIED'];
  if (['request_context_closed', 'request_context_expired'].includes(error?.code)) return [410, 'REQUEST_EXPIRED'];
  if (error?.code === 'request_context_capacity') return [429, 'CAPACITY_EXCEEDED'];
  if (error?.code === 'request_context_migration_required') return [503, 'WORKER_NOT_READY'];
  if (['local_authorization_unavailable', 'token_authority_unavailable'].includes(error?.code)) return [503, 'WORKER_NOT_READY'];
  return [503, 'CRITICAL_STORAGE_UNAVAILABLE'];
}

// origin与sessions只能由可信本地启动装配。代理身份头不能开启认证入口。
export function createAuthenticationHttp({serviceId, databaseInstanceId, serviceBootId, sessions = null, origin = null, onFailure = null}) {
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
    const envelope = {request_id: requestId, service_id: serviceId, service_boot_id: serviceBootId,
      protocol_version: selection.contract_id, selection, ...(code ? {error: {code, message_key: code.toLowerCase(), request_id: requestId,
        details: {}, existing_command_id: null, existing_operation_id: null, retry_advice: 'do_not_retry'}} : {data})};
    // 命令裁决契约使用具名原结果及独立Error，不能套用身份信封。
    const commandError = {400: 'invalid', 401: 'unauthenticated', 403: 'forbidden', 409: 'conflict', 413: 'invalid', 422: 'invalid', 429: 'capacity', 503: 'unavailable'};
    const readError={400:'invalid',401:'unauthenticated',403:'forbidden',404:'not_found',413:'payload_too_large',422:'invalid_semantics',429:'capacity',503:'unavailable'};
    const body = Buffer.from(JSON.stringify(commandReads.includes(request.operation_id)?
      (code?{code:readError[status]??'unavailable',request_id:requestId,retry_action:'read_current'}:data):controlOperations.includes(request.operation_id) ?
      (code ? {code, message: code.toLowerCase(), retry_instruction: 'query_original'} : data) : commandOperations.includes(request.operation_id) ?
      (code ? {code: commandError[status] ?? 'unavailable', request_id: requestId} : data) : envelope));
    const headers = [['content-type', 'application/json'], ['content-length', String(body.length)],
      ['x-leafseamer-contract', selection.contract_id], ['x-leafseamer-contract-digest', selection.contract_digest],
      ['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['connection', 'close'], ...extraHeaders];
    // 任何响应字段或选择失配均在发送响应头前失败，不能交付半个可信结果。
    // 本地生成且受SDK大小上限约束的响应在微任务内完成校验，避免让出的定时器片被同步writer占满。
    // 保留原解析截止、节点/字节预算及发送前当前性复核；外部请求仍用默认公平分片。
    await adapter.decodeResponse(body, adapter.prepareResponse(request, String(status), headers),{yieldNow:()=>Promise.resolve()});
    beforeSend();
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, Object.fromEntries(headers)); res.end(body); }
  }
  async function dispatch(req, res, request, body) {
    if (!sessions || !site) { await reply(res, request, 503, 'WORKER_NOT_READY'); return; }
    const operation = request.operation_id;
    try {
      if (!(req.socket instanceof TLSSocket) || req.socket.encrypted !== true || !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol())) reject('http_tls');
      if (req.headers.host !== site.host || (!readOperations.includes(operation) || req.headers.origin !== undefined) && req.headers.origin !== origin ||
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
      } else if (operation === 'logoutSession') {
        const result = sessions.logout(cookieInput(req)), record = result.propagation;
        const data = {operation_ref: {authority_service_id: serviceId, database_instance_id: databaseInstanceId,
          kind: 'session_revocation', id: record.id, revision: record.revision}, local_session_state: 'revoked', propagation: {
          operation_id: record.id, selector: {kind: 'session', issuer_id: record.issuer_id, issuer_epoch: record.issuer_epoch,
            target_id: record.session_id, revision_floor: record.revision_floor}, issuer_commit_revision: record.revision_floor,
          target_service_ids: record.target_service_ids, state: 'accepted', receipts: [], reason: 'logout', audit_id: record.tx_id}};
        await reply(res, request, 202, null, {data, extraHeaders: [clearCookie], beforeSend() { sessions.confirmLogout(result.operation_ref); }});
      } else if (operation === 'listDevices' || operation === 'getControl') {
        const proof = tokenInput(req);
        const view = () => operation === 'listDevices' ? sessions.listDevices(proof, request.parameters.query.cursor) : sessions.getControl(proof, request.parameters.path.device_id);
        const data = view();
        await reply(res, request, 200, null, {data, beforeSend() { if (canonical(view()) !== canonical(data)) reject('device_registry_integrity'); }});
      } else if(controlOperations.includes(operation)){
        const proof=tokenInput(req),parameters=request.parameters.path;
        if(!readOperations.includes(operation)){
          sessions.verifyTokenCsrf(proof,req.headers['x-csrf-token']);
        }
        if(controlWrites.includes(operation)){
          const result=await sessions.changeControl(proof,operation,parameters,body);
          await reply(res,request,result.replay?200:202,null,{data:result.receipt,beforeSend(){sessions.verifyToken(proof,serviceId);}});
        }else if(operation==='lookupControlRequest'){
          const data=await sessions.lookupControlRequest(proof,body);await reply(res,request,200,null,{data,beforeSend(){sessions.verifyToken(proof,serviceId);}});
        }else{
          const read=()=>operation==='getControlOperation'?sessions.getControlOperation(proof,parameters.operation_id):sessions.getTransfer(proof,parameters.device_id,parameters.transfer_id);
          const data=read();await reply(res,request,200,null,{data,beforeSend(){if(canonical(read())!==canonical(data))reject('control_changed');}});
        }
      } else if(commandReads.includes(operation)){
        const proof=tokenInput(req),p=request.parameters.path,read=()=>operation==='getCommand'?sessions.getCommand(proof,p.command_id):
          operation==='getCommandEvidence'?sessions.getCommandEvidence(proof,p.command_id,request.parameters.query):sessions.getCommandEvidenceRevision(proof,p.command_id,p.evidence_id,p.revision),data=read();
        await reply(res,request,200,null,{data,beforeSend(){if(canonical(read())!==canonical(data))reject('command_binding');}});
      } else if (commandOperations.includes(operation)) {
        const proof = tokenInput(req), result = await sessions[operation](proof, body,{withStatus:true});
        const data=operation==='submitCommand'?result.adjudication:result;
        const identity = operation === 'lookupCommandAdmission' ? body : data.identity;
        const permission = operation === 'rejectCommandAdmission' ? 'command.cancel' : 'command.read';
        await reply(res, request, operation==='submitCommand'&&!result.replay?202:200, null, {data, beforeSend() { sessions.confirmCommandResult(proof, identity, permission, data); }});
      } else if (operation === 'createRequestContext') {
        const proof = tokenInput(req), data = sessions.createRequestContext(proof, body);
        await reply(res, request, 201, null, {data, beforeSend() {
          if (canonical(sessions.getRequestContext(proof, data.context_id)) !== canonical(data)) reject('request_context_binding');
        }});
      } else {
        const proof = tokenInput(req);
        const view = () => {
          const v = sessions.verifyToken(proof, serviceId); if (!v.permissions.includes('session.read')) reject('http_permission');
          return sessionView({...v, not_before_ns: v.session_not_before_ns, expires_ns: v.session_expires_ns, idle_before_ns: v.session_idle_before_ns}, v.permissions, v.policy_revision, v.expires_ns);
        };
        const data = view();
        await reply(res, request, 200, null, {data, beforeSend() { if (JSON.stringify(view()) !== JSON.stringify(data)) reject('local_authorization_denied'); }});
      }
    } catch (error) {
      // 可信本机装配只接收分类，不传递凭据、请求正文或异常全文；观察失败不改变HTTP结果。
      try{onFailure?.({operation_id:operation,error_name:error?.name??'Error',code:error instanceof WireError?error.reason:error?.code??'http_internal'});}catch{}
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
    const pathname = req.url?.split('?')[0];
    const method = routes.get(pathname) ?? (/^\/api\/v1\/commands\/[^/]+(?:\/evidence(?:\/[^/]+\/revisions\/[^/]+)?)?$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/control$/.test(pathname)||/^\/api\/v1\/control-operations\/[^/]+$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/control\/transfers\/[^/]+$/.test(pathname)?'GET':
      /^\/api\/v1\/devices\/[^/]+\/control\/(acquire|release|transfers)$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/control\/transfers\/[^/]+\/(accept|cancel)$/.test(pathname)||pathname==='/api/v1/control-requests/lookup'?'POST':null);
    if (!method) return false;
    if (req.method !== method) { empty(res, 405, {Allow: method}); return true; }
    void serve(req, res).catch(() => empty(res, 503)); return true;
  }});
}
