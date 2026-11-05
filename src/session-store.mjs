import crypto from 'node:crypto';
import {IdentityError, validateLogin, hashPassword, verifyPassword, createOpaqueSecret, verifyOpaqueSecret} from './identity-crypto.mjs';
import {clockInteger} from './native-clock.mjs';
import {seal, ref, canonical} from './auth-clock-value.mjs';
import {accessTokenService} from './access-token-store.mjs';
import {requestContextService} from './request-context-store.mjs';
import {commandAdmissionStore} from './command-admission-store.mjs';
import {deviceRegistryReader} from './device-registry-store.mjs';
import {deviceControlStore} from './device-control-store.mjs';

const HOUR = 3600000000000n, MINUTE = 60000000000n, MAX = (1n << 64n) - 1n;
const fail = code => { throw new IdentityError(code); };
const pad = n => { if (n < 0n || n > MAX) fail('session_time_range'); return String(n).padStart(20, '0'); };
const csrfHash = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value) || Buffer.from(value, 'base64url').toString('base64url') !== value) fail('session_invalid');
  return crypto.createHash('sha256').update('LeafSeamer/session-csrf/v1\0').update(value).digest();
};
function rows(db, sql, ...args) {
  const statement = db.prepare(sql), names = statement.columns().map(c => c.name);
  return statement.raw().all(...args).map(values => Object.fromEntries(names.map((name, i) => [name, values[i]])));
}

// 内部人员会话服务；clock由同服务认证时钟装配，HTTP Cookie与Origin边界另由传输层落实。
export function sessionStore(db, serviceId, clock, authority = null, tokensEnabled = false, contextBinding = null, createExtensionManagement = null,controlBarrier=null) {
  let stopped = false, dummy = null;
  const buckets = new Map(), global = {start: process.hrtime.bigint(), failed: 0, pending: 0};
  const salt = crypto.randomBytes(32);
  function live() { if (stopped || !db.open) fail('session_service_stopped'); }
  function time() {
    live(); const value = clock.current(), lower = clockInteger(value.lower_ns), upper = clockInteger(value.upper_ns);
    if (lower > upper) fail('session_clock_invalid');
    const found = db.prepare('SELECT digest, body FROM authentication_clock_acquisition WHERE id = ? AND revision = ?').raw().get(value.acquisition_ref.id, value.acquisition_ref.revision);
    if (!found || found[0] !== value.acquisition_ref.digest || JSON.parse(found[1].toString()).service_id !== serviceId) fail('session_clock_source');
    return {lower, upper, acquisition: value.acquisition_ref};
  }
  function writer(fn) {
    live(); if (db.inTransaction) fail('session_outer_transaction');
    try { return db.transaction(fn).immediate(); }
    catch (error) { if (!(error instanceof IdentityError) && error?.name !== 'ClockError') stopped = true; throw error; }
  }
  function reserve(login) {
    const now = process.hrtime.bigint();
    const reset = bucket => { if (now < bucket.start) fail('session_rate_clock'); if (now - bucket.start >= MINUTE && bucket.pending === 0) { bucket.start = now; bucket.failed = 0; } };
    reset(global);
    for (const [key, b] of buckets) if (now - b.start >= MINUTE && b.pending === 0) buckets.delete(key);
    const key = crypto.createHmac('sha256', salt).update(login).digest('hex');
    let bucket = buckets.get(key);
    if (!bucket) { if (buckets.size >= 4096) fail('login_throttled'); bucket = {start: now, failed: 0, pending: 0}; buckets.set(key, bucket); }
    reset(bucket);
    if (global.failed + global.pending >= 60 || bucket.failed + bucket.pending >= 5) fail('login_throttled');
    global.pending++; bucket.pending++;
    return success => { global.pending--; bucket.pending--; if (!success) { global.failed++; bucket.failed++; } };
  }
  function principal(login) {
    return rows(db, 'SELECT p.*, s.issuer_id, s.issuer_epoch, s.kind FROM local_principal p JOIN subject s ON s.principal_id = p.principal_id WHERE p.login = ?', login)[0];
  }
  function view(session) {
    return {session_id: session.session_id, principal_id: session.principal_id, principal_kind: 'human', issuer_id: session.issuer_id,
      issuer_epoch: session.issuer_epoch, revision: String(session.revision), state: session.state, not_before_ns: String(BigInt(session.not_before_ns)),
      expires_ns: String(BigInt(session.expires_ns)), idle_before_ns: String(BigInt(session.idle_before_ns)), recent_before_ns: String(BigInt(session.recent_before_ns))};
  }
  function terminal(session, cause, now) {
    const prior = rows(db, 'SELECT body FROM session_revocation WHERE session_id = ?', session.session_id)[0];
    if (prior) return JSON.parse(prior.body.toString());
    const targets = [...new Set([serviceId, ...rows(db, 'SELECT audience AS target FROM session_audience WHERE session_id = ? UNION SELECT target_service_id AS target FROM session_target_binding WHERE session_id = ? LIMIT 4097', session.session_id, session.session_id).map(r => r.target)])].sort();
    if (targets.length > 4096) fail('session_target_budget');
    const operation = seal({format: 'session-revocation/1', id: crypto.randomUUID(), revision: '1', issuer_id: session.issuer_id, issuer_epoch: session.issuer_epoch,
      session_id: session.session_id, cause, revision_floor: String(session.revision + 1), target_service_ids: targets,
      acquisition_ref: now.acquisition, tx_id: crypto.randomUUID(), propagation: 'pending'});
    const bytes = Buffer.from(canonical(operation)); if (bytes.length > 32768) fail('session_target_budget');
    db.prepare('INSERT INTO session_revocation VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(operation.id, session.session_id, cause, session.revision + 1, now.acquisition.id, operation.tx_id, operation.digest, bytes);
    db.prepare('INSERT INTO session_revocation_floor VALUES (?, ?, ?)').run(session.session_id, session.revision + 1, operation.id);
    db.prepare('UPDATE auth_session SET state = ?, revision = revision + 1, terminal_operation_id = ? WHERE session_id = ? AND state = ?')
      .run(cause === 'expired' ? 'expired' : 'revoked', operation.id, session.session_id, 'active');
    db.prepare("UPDATE session_refresh_credential SET state = 'revoked' WHERE session_id = ? AND state = 'active'").run(session.session_id);
    for (const target of targets) {
      db.prepare("INSERT INTO session_revocation_target VALUES (?, ?, 'pending')").run(operation.id, target);
      db.prepare('INSERT INTO session_revocation_outbox VALUES (?, ?)').run(operation.id, target);
    }
    return operation;
  }
  function authenticated(input, now, refresh = false) {
    if (!input || Object.keys(input).sort().join(',') !== 'credential_id,csrf,secret') fail('session_invalid');
    if (typeof input.credential_id !== 'string' || input.credential_id.length !== 36 || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.credential_id)) fail('session_invalid');
    const credential = rows(db, 'SELECT * FROM session_refresh_credential WHERE credential_id = ?', input.credential_id)[0];
    if (!credential || !verifyOpaqueSecret('session_refresh', input.secret, credential.verifier)) fail('session_invalid');
    const session = rows(db, 'SELECT * FROM auth_session WHERE session_id = ?', credential.session_id)[0];
    if (!session || !crypto.timingSafeEqual(csrfHash(input.csrf), session.csrf_verifier) || session.state !== 'active') fail('session_invalid');
    if (refresh && credential.state === 'consumed') {
      const operation = terminal(session, 'refresh_reuse', now);
      db.prepare('INSERT OR IGNORE INTO session_refresh_reuse VALUES (?, ?, ?)').run(credential.credential_id, operation.id, now.acquisition.id);
      return {denied: 'session_invalid'};
    }
    if (credential.state !== 'active') fail('session_invalid');
    const p = rows(db, 'SELECT state FROM local_principal WHERE principal_id = ?', session.principal_id)[0];
    if (p?.state !== 'active') fail('session_invalid');
    if (now.upper >= BigInt(session.expires_ns) || now.upper >= BigInt(session.idle_before_ns)) {
      terminal(session, 'expired', now); return {denied: 'session_expired'};
    }
    if (now.lower < BigInt(session.not_before_ns)) fail('session_time_invalid');
    return {session, credential};
  }
  const deliver = result => { if (result.denied) fail(result.denied); return result; };
  function authorization(session) {
    if (!authority?.current) fail('local_authorization_unavailable');
    const value = authority.current(session.principal_id);
    if (value.state !== 'active' || value.issuer_id !== session.issuer_id || value.issuer_epoch !== session.issuer_epoch) fail('local_authorization_denied');
    return value;
  }
  const {authorizeToken, ...tokens} = accessTokenService({db, serviceId, authority, enabled: tokensEnabled, writer, time, authenticated, terminal, rows, pad});
  let contextCurrent;
  const contexts = requestContextService({db, binding: contextBinding, writer, time, authorizeToken, rows, pad,attachCurrent:current=>{contextCurrent=current;}});
  const commands = commandAdmissionStore({db, binding: contextBinding, writer, time, authorizeToken, rows});
  const devices = deviceRegistryReader(db, contextBinding?.service);
  const controls=Number(contextBinding?.service.schema_revision)>=26&&controlBarrier?deviceControlStore({db,service:contextBinding.service,bootId:contextBinding.bootId,
   writer,time,authorizeToken,contextCurrent,authority,devices,barriers:controlBarrier}):null;
  const extensionManagement=createExtensionManagement?.((input,permission,recent)=>{
    const proof=authorizeToken(input,serviceId);if(proof.denied)fail(proof.denied);
    if(proof.principal_kind!=='human'||!proof.permissions.includes(permission))fail('extension_management_denied');
    if(recent){const session=rows(db,'SELECT recent_before_ns FROM auth_session WHERE session_id=?',proof.session_id)[0];
      if(!session||time().upper>=BigInt(session.recent_before_ns))fail('extension_management_recent_required');}
    return proof;
  });
  function readDevice(input, permission, read) {
    return deliver(writer(() => {
      const proof = authorizeToken(input, serviceId); if (proof.denied) return proof;
      if (!proof.permissions.includes(permission)) fail('device_read_denied');
      const result = read();
      const last = authorizeToken(input, serviceId); if (last.denied) return last;
      if (!last.permissions.includes(permission)) fail('device_read_denied'); return result;
    }));
  }
  return Object.freeze({
    ...tokens, ...contexts, ...commands,
    verifyTokenCsrf(input,csrf){return deliver(writer(()=>{const proof=authorizeToken(input,serviceId);if(proof.denied)return proof;
      const row=db.prepare('SELECT csrf_verifier FROM auth_session WHERE session_id=?').raw().get(proof.session_id);
      if(!row||!crypto.timingSafeEqual(csrfHash(csrf),row[0]))fail('session_invalid');return proof;}));},
    changeControl(input,method,parameters,request){if(!controls)fail('control_unavailable');return controls.invoke(input,method,parameters,request);},
    getControlOperation(input,id){if(!controls)fail('control_unavailable');return controls.getOperation(input,id);},
    getTransfer(input,device,id){if(!controls)fail('control_unavailable');return controls.getTransfer(input,device,id);},
    lookupControlRequest(input,request){if(!controls)fail('control_unavailable');return controls.lookup(input,request);},
    approveExtension(input,request){if(!extensionManagement)fail('extension_management_unavailable');return extensionManagement.approve(input,request);},
    revokeExtensionApproval(input,request){if(!extensionManagement)fail('extension_management_unavailable');return extensionManagement.revoke(input,request);},
    lookupExtensionApproval(input,requestId){if(!extensionManagement)fail('extension_management_unavailable');return extensionManagement.query(input,requestId);},
    getExtensionApproval(input,approvalRef){if(!extensionManagement)fail('extension_management_unavailable');return extensionManagement.current(input,approvalRef);},
    planExtension(input,request){if(!extensionManagement?.plans)fail('extension_plans_unavailable');return extensionManagement.plans.create(input,request);},
    lookupExtensionPlan(input,requestId){if(!extensionManagement?.plans)fail('extension_plans_unavailable');return extensionManagement.plans.query(input,requestId);},
    getCurrentExtensionPlan(input,planRef){if(!extensionManagement?.plans)fail('extension_plans_unavailable');return extensionManagement.plans.current(input,planRef);},
    activateExtension(input,request){if(!extensionManagement?.lifecycle)fail('extension_activation_unavailable');return extensionManagement.lifecycle.accept(input,'activate',request);},
    enableExtension(input,request){if(!extensionManagement?.lifecycle)fail('extension_activation_unavailable');return extensionManagement.lifecycle.accept(input,'enable',request);},
    lookupExtensionActivation(input,requestId){if(!extensionManagement?.lifecycle)fail('extension_activation_unavailable');return extensionManagement.lifecycle.query(input,requestId);},
    listDevices(input, cursor) { return readDevice(input, 'device.read', () => devices.list(cursor)); },
    getControl(input, deviceId) { return readDevice(input, 'control.read', () => devices.control(deviceId)); },
    localPermissions(input) {
      if (!authority?.current) fail('local_authorization_unavailable');
      return deliver(writer(() => { const found = authenticated(input, time()); return found.denied ? found : authority.current(found.session.principal_id); }));
    },
    presentation(input) {
      return deliver(writer(() => {
        const now = time(), found = authenticated(input, now); if (found.denied) return found;
        return {session: view(found.session), authorization: authorization(found.session)};
      }));
    },
    replaceLocalPermissions(input, request) {
      if (!authority?.replace) fail('local_authorization_unavailable');
      const result = writer(() => {
        const now = time(), found = authenticated(input, now); if (found.denied) return found;
        const operation = authority.replace(found, request, now);
        const last = time(); if (last.upper >= BigInt(found.session.recent_before_ns)) fail('local_authorization_management_denied');
        return operation;
      });
      deliver(result); time(); return result;
    },
    async login(input) {
      live(); time();
      if (!input || Object.keys(input).sort().join(',') !== 'login,password') fail('login_invalid');
      input = Object.freeze({...input}); validateLogin(input.login);
      const release = reserve(input.login); let success = false;
      try {
        dummy ??= hashPassword(crypto.randomBytes(32).toString('hex'));
        const dummyPhc = await dummy, original = principal(input.login);
        const valid = await verifyPassword(input.password, original?.password_phc ?? dummyPhc);
        if (!valid || !original || original.kind !== 'human' || original.state !== 'active') fail('login_invalid');
        const credential = createOpaqueSecret('session_refresh'), credentialId = crypto.randomUUID(), sessionId = crypto.randomUUID(), csrf = crypto.randomBytes(32).toString('base64url');
        const result = writer(() => {
          const now = time(), current = principal(input.login);
          if (!current || current.principal_id !== original.principal_id || current.revision !== original.revision || current.password_phc !== original.password_phc || current.state !== 'active') fail('login_invalid');
          if (authority?.current) authorization(current);
          const tx = crypto.randomUUID();
          db.prepare("INSERT INTO auth_session VALUES (?, ?, ?, ?, 'active', 1, ?, ?, ?, ?, ?, ?, ?, NULL)")
            .run(sessionId, current.principal_id, current.issuer_id, current.issuer_epoch, pad(now.lower), pad(now.lower + 8n * HOUR), pad(now.lower + 30n * MINUTE), pad(now.lower + 5n * MINUTE), csrfHash(csrf), now.acquisition.id, tx);
          db.prepare("INSERT INTO session_refresh_credential VALUES (?, ?, ?, 'active', ?, ?, NULL)").run(credentialId, sessionId, credential.verifier, now.acquisition.id, tx);
          db.prepare('INSERT INTO session_audience VALUES (?, ?, ?)').run(sessionId, serviceId, tx);
          const row = rows(db, 'SELECT * FROM auth_session WHERE session_id = ?', sessionId)[0];
          const last = time(); if (last.upper >= BigInt(row.idle_before_ns)) fail('session_time_invalid');
          return {session: view(row), credential_id: credentialId, secret: credential.secret, csrf};
        });
        // 提交后时间失信不交付秘密；DB保留已提交事实，不再生成补偿会话。
        time(); success = true; return result;
      } finally { release(success); }
    },
    current(input) {
      return deliver(writer(() => { const found = authenticated(input, time()); return found.denied ? found : {session: view(found.session)}; }));
    },
    refresh(input) {
      const credential = createOpaqueSecret('session_refresh'), id = crypto.randomUUID();
      const result = writer(() => {
        const now = time(), found = authenticated(input, now, true); if (found.denied) return found;
        if (authority?.current) authorization(found.session);
        const tx = crypto.randomUUID(), expiry = BigInt(found.session.expires_ns), proposed = now.lower + 30n * MINUTE;
        const candidate = proposed < expiry ? proposed : expiry;
        const idle = candidate > BigInt(found.session.idle_before_ns) ? candidate : BigInt(found.session.idle_before_ns);
        db.prepare("UPDATE session_refresh_credential SET state = 'consumed', consumed_tx_id = ? WHERE credential_id = ? AND state = 'active'").run(tx, input.credential_id);
        db.prepare("INSERT INTO session_refresh_credential VALUES (?, ?, ?, 'active', ?, ?, NULL)").run(id, found.session.session_id, credential.verifier, now.acquisition.id, tx);
        db.prepare('UPDATE auth_session SET idle_before_ns = ? WHERE session_id = ?').run(pad(idle), found.session.session_id);
        const last = time(); if (last.upper >= idle) fail('session_time_invalid');
        return {session: view({...found.session, idle_before_ns: pad(idle)}), credential_id: id, secret: credential.secret};
      });
      deliver(result); time(); return result;
    },
    logout(input) {
      return deliver(writer(() => {
        const now = time(), found = authenticated(input, now); if (found.denied) return found;
        const operation = terminal(found.session, 'logout', now);
        return {operation_ref: ref(operation), local_session_state: 'revoked', propagation: operation};
      }));
    },
    confirmLogout(operationRef) {
      return writer(() => {
        time();
        const original = rows(db, 'SELECT r.digest, r.body FROM session_revocation r JOIN auth_session s ON s.terminal_operation_id = r.operation_id WHERE r.operation_id = ? AND s.state = ?', operationRef.id, 'revoked')[0];
        if (!original || original.digest !== operationRef.digest) fail('session_revocation_unavailable');
        const body = JSON.parse(original.body.toString());
        if (body.cause !== 'logout' || body.revision !== operationRef.revision) fail('session_revocation_unavailable');
        return true;
      });
    },
    stop() { controls?.close(); stopped = true; salt.fill(0); buckets.clear(); }
  });
}
