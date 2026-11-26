import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {createHttpAdapter,WireError} from './sdk/http.mjs';
import {profile} from './sdk/runtime/panel-wire/decoder.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {canonical} from './auth-clock-value.mjs';
import {pairingFields} from './peer-pairing-value.mjs';
import {localPairingLimit, localPairingOperations, localPairingPath, loopbackHost} from './local-pairing-admin.mjs';
import {localExtensionOperations,localExtensionPath} from './local-extension-management.mjs';

const routes = new Map([
  ['/auth/sessions', 'POST'], ['/auth/sessions/refresh', 'POST'],
  ['/auth/service-tokens', 'POST'], ['/api/v1/session', 'GET'],
  ['/auth/sessions/current', 'DELETE'],
  ['/api/v1/request-contexts', 'POST'],
  ['/api/v1/commands', 'POST'], ['/api/v1/commands/lookup', 'POST'], ['/api/v1/commands/reject', 'POST'],
  ['/api/v1/devices', 'GET'],
  ['/api/v1/subscriptions', 'POST'],
  ['/api/v1/ws-tickets', 'POST'],
]);
const maximumBody = 16384, maximumPending = 16, bodyDeadline = 2000;
const commandReads=['getCommand','getCommandEvidence','getCommandEvidenceRevision'];
const commandOperations = ['submitCommand', 'lookupCommandAdmission', 'rejectCommandAdmission',...commandReads];
const controlWrites=['acquireControl','releaseControl','offerTransfer','acceptTransfer','cancelTransfer'];
const controlOperations=['getControl','getControlOperation','getTransfer','lookupControlRequest',...controlWrites];
const deviceCatalogReads = ['getCapabilities','getSceneCatalog'];
const snapshotReads=['getSnapshot','getSnapshotPage'];
const subscriptionReads=['getSubscription','getSubscriptionConnection',...snapshotReads];
const subscriptionOperations = ['createSubscription','closeSubscription','issueWsTicket',...subscriptionReads];
const subscriptionItem = /^\/api\/v1\/subscriptions\/[^/]+$/;
const subscriptionReadPath = /^\/api\/v1\/subscriptions\/[^/]+\/(?:snapshot|connections\/[^/]+|snapshots\/[^/]+\/pages\/[^/]+)$/;
const subscriptionCodes={400:'invalid_request',401:'authentication_required',403:'forbidden',404:'not_found_or_invisible',
  409:'conflict',410:'gone',412:'binding_invalid',413:'payload_too_large',429:'capacity_exceeded',503:'source_unavailable'};
const snapshotProfile=profile({max_message_bytes:262144,max_depth:48,max_value_nodes:1048576,max_object_members:65536,max_string_utf8_bytes:262144,parse_deadline_ms:5000});
const readOperations = ['getSession', 'listDevices', ...deviceCatalogReads, 'getControl','getControlOperation','getTransfer',...commandReads];
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
function readBody(req, res, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      req.off('data', data); req.off('end', end); req.off('aborted', abort); req.off('error', abort); res.off('close', abort);
      req.pause();
      error ? reject(error) : resolve(value);
    };
    const data = chunk => { size += chunk.length; if (size > limit) finish(413); else chunks.push(chunk); };
    const end = () => finish(null, Buffer.concat(chunks, size));
    const abort = () => finish(400);
    const timer = setTimeout(() => finish(408), bodyDeadline);
    timer.unref();
    req.on('data', data); req.once('end', end); req.once('aborted', abort); req.once('error', abort); res.once('close', abort);
  });
}
const timestamp = (value, up = false) => new Date(Number((BigInt(value) + (up ? 999999n : 0n)) / 1000000n)).toISOString();
function sessionView(session, permissions, revision, until = null) {
  const end = [session.expires_ns, session.idle_before_ns, ...(until ? [until] : [])].map(BigInt).reduce((a, b) => a < b ? a : b);
  return {principal_id: session.principal_id, session_id: session.session_id, issuer_id: session.issuer_id, issuer_epoch: session.issuer_epoch,
    authorization_revision: revision, permissions, validity: {not_before: timestamp(session.not_before_ns, true), not_after: timestamp(end), authorization_policy_revision: revision}};
}
function failure(error) {
  if (error?.name === 'ClockError' || error?.code === 'command_reference_changed') return [503, 'CLOCK_UNTRUSTED'];
  if (['login_invalid', 'session_invalid', 'session_expired', 'token_invalid', 'token_expired', 'password_invalid'].includes(error?.code)) return [401, 'AUTH_REQUIRED'];
  if (['local_authorization_denied', 'local_authorization_audience', 'http_origin', 'http_tls', 'http_permission', 'http_extension'].includes(error?.code)) return [403, 'PERMISSION_DENIED'];
  if (['remote_authorization_missing','remote_authorization_denied','remote_authorization_expired','remote_authorization_parent',
    'peer_pairing_state','peer_pairing_expired','peer_pairing_activation','peer_pairing_configuration_missing','peer_pairing_configuration_changed'].includes(error?.code)) return [403,'PERMISSION_DENIED'];
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
  if (['device_capabilities_unavailable','device_capabilities_changed'].includes(error?.code)) return [503, 'WORKER_NOT_READY'];
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

function subscriptionFailure(error) {
  const code=error?.code??'';
  if (error?.name==='ClockError'||code==='event_scope_unavailable') return 503;
  if (['token_invalid','token_expired','token_time_invalid','session_invalid','session_expired'].includes(code)) return 401;
  if (['subscription_conflict','subscription_slot_busy','subscription_revision','subscription_changed','subscription_state'].includes(code)) return 409;
  if (['subscription_gone','subscription_expired','subscription_ticket_expired','request_context_closed','request_context_expired','event_scope_inactive','snapshot_deadline'].includes(code)) return 410;
  if (['subscription_generation','subscription_binding','subscription_connection'].includes(code)) return 412;
  if (code==='subscription_not_found') return 404;
  if (code==='subscription_capacity') return 429;
  if (code==='subscription_input') return 400;
  if (['subscription_forbidden','subscription_revoked','subscription_authorization_changed','event_scope_missing','event_scope_scope',
    'http_tls','http_origin','request_context_denied','request_context_permission','local_authorization_denied','local_authorization_parent'].includes(code)) return 403;
  return 503;
}

// origin与sessions只能由可信本地启动装配。代理身份头不能开启认证入口。
export function createAuthenticationHttp({serviceId, databaseInstanceId, serviceBootId, sessions = null, origin = null, onFailure = null, localPairing = null, localExtension = null}) {
  const adapter = createHttpAdapter(selection);
  let site = null;
  if (origin !== null) {
    try { site = new URL(origin); } catch { throw new Error('authentication_origin'); }
    if (site.protocol !== 'https:' || site.origin !== origin || site.username || site.password || site.pathname !== '/' || site.search || site.hash) throw new Error('authentication_origin');
  }
  let pending = 0;
  function browserOrigin(req){
    const pathname=req.url?.split('?')[0];
    return req.headers.origin===undefined&&site&&req.method==='GET'&&
      (subscriptionItem.test(pathname)||subscriptionReadPath.test(pathname))&&req.headers.host===site.host&&
      req.headers['sec-fetch-site']==='same-origin'&&req.socket instanceof TLSSocket&&req.socket.encrypted===true?origin:undefined;
  }
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
    const subscription = subscriptionOperations.includes(request.operation_id);
    const body = Buffer.from(JSON.stringify(subscription ?
      (code ? {code:subscriptionCodes[status],request_id:requestId,retry_action:status===409?'read_current':'do_not_retry'} : data) : commandReads.includes(request.operation_id)?
      (code?{code:readError[status]??'unavailable',request_id:requestId,retry_action:'read_current'}:data):controlOperations.includes(request.operation_id) ?
      (code ? {code, message: code.toLowerCase(), retry_instruction: 'query_original'} : data) : commandOperations.includes(request.operation_id) ?
      (code ? {code: commandError[status] ?? 'unavailable', request_id: requestId} : data) : envelope));
    const headers = [['content-type', 'application/json'], ['content-length', String(body.length)],
      ['x-leafseamer-contract', selection.contract_id], ['x-leafseamer-contract-digest', selection.contract_digest],
      ['cache-control', 'no-store'], ['x-content-type-options', 'nosniff'], ['connection', 'close'], ...extraHeaders];
    // 任何响应字段或选择失配均在发送响应头前失败，不能交付半个可信结果。
    // 本地生成且受SDK大小上限约束的响应在微任务内完成校验，避免让出的定时器片被同步writer占满。
    // 保留原解析截止、节点/字节预算及发送前当前性复核；外部请求仍用默认公平分片。
    await adapter.decodeResponse(body, adapter.prepareResponse(request, String(status), headers),{
      yieldNow:()=>Promise.resolve(),...(snapshotReads.includes(request.operation_id)&&{profile:snapshotProfile})});
    beforeSend();
    if (!res.destroyed && !res.headersSent) { res.writeHead(status, Object.fromEntries(headers)); res.end(body); }
  }
  async function dispatch(req, res, request, body) {
    if (!sessions || !site) { await reply(res, request, 503, 'WORKER_NOT_READY'); return; }
    const operation = request.operation_id;
    try {
      if (!(req.socket instanceof TLSSocket) || req.socket.encrypted !== true || !['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol())) reject('http_tls');
      if (req.headers.host !== site.host || (!readOperations.includes(operation) || req.headers.origin !== undefined) && (req.headers.origin??browserOrigin(req)) !== origin ||
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
        sessions.verifyToken(proof, issued.token.audience);
        // expires_in为签发期限的秒数提示，服务器始终重新判断原绝对截止；响应不续期。
        const seconds = Number((BigInt(issued.token.expires_ns) - BigInt(issued.token.not_before_ns)) / 1000000000n);
        if (seconds < 1) reject('token_expired');
        await reply(res, request, 201, null, {data: {access_token: wireCredential(issued.token.token_id, issued.secret), token_type: 'Bearer', expires_in: seconds, audience: issued.token.audience},
          beforeSend() { sessions.verifyToken(proof, issued.token.audience); }});
      } else if (operation === 'logoutSession') {
        const result = sessions.logout(cookieInput(req)), record = result.propagation;
        const data = {operation_ref: {authority_service_id: serviceId, database_instance_id: databaseInstanceId,
          kind: 'session_revocation', id: record.id, revision: record.revision}, local_session_state: 'revoked', propagation: {
          operation_id: record.id, selector: {kind: 'session', issuer_id: record.issuer_id, issuer_epoch: record.issuer_epoch,
            target_id: record.session_id, revision_floor: record.revision_floor}, issuer_commit_revision: record.revision_floor,
          target_service_ids: record.target_service_ids, state: 'accepted', receipts: [], reason: 'logout', audit_id: record.tx_id}};
        await reply(res, request, 202, null, {data, extraHeaders: [clearCookie], beforeSend() { sessions.confirmLogout(result.operation_ref); }});
      } else if (operation === 'listDevices' || operation === 'getControl' || deviceCatalogReads.includes(operation)) {
        const proof = tokenInput(req);
        const view = () => operation === 'listDevices' ? sessions.listDevices(proof, request.parameters.query.cursor) :
          sessions[operation](proof, request.parameters.path.device_id);
        const data = view();
        await reply(res, request, 200, null, {data, beforeSend() { if (canonical(view()) !== canonical(data)) reject(deviceCatalogReads.includes(operation) ? 'device_capabilities_changed' : 'device_registry_integrity'); }});
      } else if(subscriptionOperations.includes(operation)){
        const subscriptions=sessions.serviceSubscriptions;
        if(!subscriptions?.human)reject('subscription_unavailable');
        const account=subscriptions.human;
        const proof=tokenInput(req),csrf=req.headers['x-csrf-token'];
        const key=request.parameters.path.subscription_id,query=request.parameters.query;
        if(operation==='issueWsTicket'){
          if(!subscriptions.tickets)reject('subscription_unavailable');
          const result=subscriptions.tickets.issue(proof,csrf,body,origin),issued=result.status===201;
          await reply(res,request,result.status,null,{data:result.view,beforeSend(){
            subscriptions.tickets.confirm(proof,issued?result.view.binding:result.view,issued);
          }});
          return;
        }
        if(snapshotReads.includes(operation)||operation==='getSubscriptionConnection'){
          if(!account.readSnapshot)reject('subscription_unavailable');
          const p=request.parameters.path;
          const read=()=>operation==='getSubscriptionConnection'?account.readAttempt(proof,key,p.attempt_id):
            account.readSnapshot(proof,key,query.expected_connection_generation,operation==='getSnapshotPage'?{snapshot_id:p.snapshot_id,page_index:p.page_index}:null);
          const data=read();
          await reply(res,request,200,null,{data,beforeSend(){if(canonical(read())!==canonical(data))reject('subscription_changed');}});
          return;
        }
        const result=operation==='createSubscription'?account.create(proof,csrf,body):
          account.access(proof,key,operation==='closeSubscription'?{expected_revision:query.expected_revision,csrf}:null);
        const data=result.view;
        await reply(res,request,result.status,null,{data,beforeSend(){
          if(canonical(account.access(proof,data.binding.subscription_id).view)!==canonical(data))reject('subscription_changed');
        }});
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
      if(subscriptionOperations.includes(operation)){await reply(res,request,subscriptionFailure(error),'subscription_error');return;}
      const [status, code] = failure(error);
      await reply(res, request, status, code, {extraHeaders: status === 401 && operation !== 'getSession' ? [clearCookie] : []});
    }
  }
  async function serve(req, res) {
    let request;
    try {
      const headers=rawPairs(req.rawHeaders),derivedOrigin=browserOrigin(req);
      if(derivedOrigin!==undefined)headers.push(['origin',derivedOrigin]);
      request = adapter.prepareRequest('controller', req.method, req.url, headers);
    }
    catch { empty(res, 400); return; }
    if (pending >= maximumPending) { await reply(res, request, 429, 'CAPACITY_EXCEEDED'); return; }
    if (req.headers['transfer-encoding'] !== undefined && req.headers['transfer-encoding'] !== 'chunked') { empty(res, 400); return; }
    if (Number(req.headers['content-length'] ?? 0) > maximumBody) { await reply(res, request, 413, 'PAYLOAD_TOO_LARGE'); return; }
    pending++;
    try {
      const bytes = await readBody(req, res, maximumBody);
      let decoded;
      try { decoded = await adapter.decodeRequest(bytes, request); }
      catch { await reply(res, request, 400, 'INVALID_REQUEST'); return; }
      await dispatch(req, res, request, decoded?.value ?? null);
    } catch (status) {
      if (status === 413) await reply(res, request, 413, 'PAYLOAD_TOO_LARGE');
      else empty(res, status === 408 ? 408 : status === 400 ? 400 : 503);
    } finally { pending--; }
  }
  async function serveLocalManagement(req, res, extension) {
    const prefix=extension?'local_extension':'local_pairing';
    const operations=extension?localExtensionOperations:localPairingOperations;
    const manage=extension?localExtension:localPairing;
    const respond = (status, value) => {
      if (res.destroyed || res.headersSent) return;
      const bytes = Buffer.from(canonical(value));
      if (bytes.length > localPairingLimit) { empty(res, 503); return; }
      res.writeHead(status, {'Content-Type': 'application/json', 'Content-Length': bytes.length,
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', Connection: 'close'});
      res.end(bytes);
    };
    if (req.method !== 'POST') { empty(res, 405, {Allow: 'POST'}); return; }
    if (!site || !(req.socket instanceof TLSSocket) || !req.socket.encrypted || !loopbackHost(req.socket.remoteAddress) ||
      !loopbackHost(req.socket.localAddress) || req.headers.host !== site.host || req.headers.origin !== origin ||
      req.headers['sec-fetch-site'] === 'cross-site' || req.headers.forwarded !== undefined ||
      Object.keys(req.headers).some(key => key.startsWith('x-forwarded-'))) {
      respond(403, {error: prefix+'_origin'}); return;
    }
    const length = Number(req.headers['content-length']);
    if (length > localPairingLimit) { respond(413, {error: prefix+'_size'}); return; }
    if (!Number.isInteger(length) || length < 1 || req.headers['content-type'] !== 'application/json' ||
      req.headers['transfer-encoding'] !== undefined || req.headers['content-encoding'] !== undefined) {
      respond(400, {error: prefix+'_input'}); return;
    }
    if (pending >= maximumPending) { respond(429, {error: prefix+'_capacity'}); return; }
    pending++;
    try {
      const auth = cookieInput(req);
      const bytes = await readBody(req, res, localPairingLimit);
      let body;
      try {
        const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
        body = JSON.parse(text);
        pairingFields(body, 'operation,request');
        if (!operations.includes(body.operation) || bytes.length !== length || canonical(body) !== text) throw new Error();
      } catch { respond(400, {error: prefix+'_input'}); return; }
      respond(200, await manage(auth, body.operation, body.request));
    } catch (error) {
      if (error === 400 || error === 408 || error === 413) respond(error, {error: prefix+'_input'});
      else if (['session_invalid','session_expired'].includes(error.code)) respond(401, {error: prefix+'_session'});
      else if(extension&&/^(?:extension|worker_launch|worker_authorization)_[a-z_]{1,65}$/.test(error.code)){
        const status=/^extension_management_(?:denied|recent_required)$/.test(error.code)?403:
          error.code==='extension_management_not_found'?404:/_input$/.test(error.code)?422:
          /_capacity$/.test(error.code)?429:/_(?:unavailable|integrity)$/.test(error.code)?503:409;
        respond(status,{error:error.code});
      }
      else if (!extension&&/^(?:peer_pairing|remote_authorization)_[a-z_]{1,59}$/.test(error.code)) {
        const status = /_management(?:_changed)?$/.test(error.code) ? 403 :
          ['peer_pairing_input', 'remote_authorization_request'].includes(error.code) ? 422 : 409;
        respond(status, {error: error.code});
      } else if (!extension&&/^subscription_[a-z_]{1,50}$/.test(error.code)) {
        respond(subscriptionFailure(error),{error:error.code});
      } else if (!extension&&/^(?:event_scope|service_identity|service_consumer|service_token|run_endorsement)_[a-z_]{1,60}$/.test(error.code)) {
        const status=/_management(?:_denied|_changed)?$/.test(error.code)||['run_endorsement_permission','run_endorsement_recent'].includes(error.code)?403:
          /_(?:input|request)$/.test(error.code)?422:/_capacity$/.test(error.code)?429:
          /_(?:writer|integrity|unavailable)$/.test(error.code)?503:409;
        respond(status,{error:error.code});
      } else respond(503, {error: prefix+'_unavailable'});
    } finally { pending--; }
  }
  return Object.freeze({handle(req, res) {
    if (req.url === localPairingPath && localPairing !== null) {
      void serveLocalManagement(req, res, false).catch(() => empty(res, 503)); return true;
    }
    if (req.url === localExtensionPath && localExtension !== null) {
      void serveLocalManagement(req, res, true).catch(() => empty(res, 503)); return true;
    }
    const pathname = req.url?.split('?')[0];
    const method = routes.get(pathname) ?? (subscriptionItem.test(pathname)?'GET, DELETE':subscriptionReadPath.test(pathname)||/^\/api\/v1\/commands\/[^/]+(?:\/evidence(?:\/[^/]+\/revisions\/[^/]+)?)?$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/(?:control|capabilities|scene-catalog)$/.test(pathname)||/^\/api\/v1\/control-operations\/[^/]+$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/control\/transfers\/[^/]+$/.test(pathname)?'GET':
      /^\/api\/v1\/devices\/[^/]+\/control\/(acquire|release|transfers)$/.test(pathname)||/^\/api\/v1\/devices\/[^/]+\/control\/transfers\/[^/]+\/(accept|cancel)$/.test(pathname)||pathname==='/api/v1/control-requests/lookup'?'POST':null);
    if (!method) return false;
    if (!method.split(', ').includes(req.method)) { empty(res, 405, {Allow: method}); return true; }
    void serve(req, res).catch(() => empty(res, 503)); return true;
  }});
}
