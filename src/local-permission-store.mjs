import crypto from 'node:crypto';
import {IdentityError} from './identity-crypto.mjs';
import {canonical, checked, digest, ref, seal} from './auth-clock-value.mjs';

// 身份管理的首期产品权限目录。设备写、配对内部用途和其它服务不从管理员名称推导。
export const localIdentityPermissions = Object.freeze(['auth.manage', 'auth.read', 'identity.read', 'request.create', 'session.read', 'status.read']);
const supported = new Set([...localIdentityPermissions, 'control.read', 'device.read', 'extension.read', 'command.read', 'command.cancel']);
const fail = code => { throw new IdentityError(code); };
const revisionKey = value => String(value).padStart(20, '0');
const maxRevision = (1n << 64n) - 1n;
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const rows = (db, sql, ...args) => {
  const q = db.prepare(sql), names = q.columns().map(c => c.name);
  return q.raw().all(...args).map(values => Object.fromEntries(names.map((n, i) => [n, values[i]])));
};
function append(db, body) {
  const value = seal(body), bytes = Buffer.from(canonical(value));
  if (bytes.length > 16384) fail('local_authorization_budget');
  db.prepare('INSERT INTO local_permission_revision VALUES (?, ?, ?, ?, ?, ?)')
    .run(value.principal_id, revisionKey(value.revision), value.id, value.state, value.digest, bytes);
  return value;
}

// 只在首次管理员或显式schema升级的原事务中调用，不在查询/登录时补建授权。
export function initializeLocalPermissions(db, service) {
  if (!db.inTransaction) fail('local_authorization_transaction');
  for (const row of rows(db, `SELECT a.principal_id, a.initialization_tx_id, s.issuer_id, s.issuer_epoch
      FROM local_authorization a JOIN subject s ON s.principal_id = a.principal_id
      WHERE a.role = 'administrator' AND s.kind = 'human'
      AND NOT EXISTS (SELECT 1 FROM local_permission_head h WHERE h.principal_id = a.principal_id)`)) {
    const value = append(db, {format: 'local-permission/1', id: crypto.randomUUID(), revision: '1',
      ...row, service_id: service.service_id, database_instance_id: service.database_instance_id,
      permissions: [...localIdentityPermissions], state: 'active', operation_id: null});
    db.prepare('INSERT INTO local_permission_head VALUES (?, ?, ?)').run(row.principal_id, revisionKey(1), value.id);
  }
}

export function localPermissionStore(db, service) {
  const transaction = () => { if (!db.open || !db.inTransaction) fail('local_authorization_transaction'); };
  function current(principalId) {
    transaction();
    const row = rows(db, `SELECT r.* FROM local_permission_head h JOIN local_permission_revision r
      ON r.principal_id = h.principal_id AND r.revision = h.revision AND r.id = h.id WHERE h.principal_id = ?`, principalId)[0];
    if (!row) fail('local_authorization_unavailable');
    const value = checked(JSON.parse(row.body.toString()));
    if (value.id !== row.id || value.digest !== row.digest || value.principal_id !== principalId || value.revision !== String(BigInt(row.revision)) ||
        value.state !== row.state || value.service_id !== service.service_id || value.database_instance_id !== service.database_instance_id ||
        !Array.isArray(value.permissions) || value.permissions.some(p => !supported.has(p))) fail('local_authorization_invalid');
    return value;
  }
  function resolve(binding) {
    transaction();
    if (binding.audience !== service.service_id) fail('local_authorization_audience');
    const parent = rows(db, `SELECT s.*, p.revision AS subject_revision, p.state AS principal_state, c.state AS credential_state
      FROM auth_session s JOIN local_principal p ON p.principal_id = s.principal_id
      JOIN session_refresh_credential c ON c.session_id = s.session_id WHERE s.session_id = ? AND c.credential_id = ?`, binding.session_id, binding.credential_id)[0];
    if (!parent || parent.state !== 'active' || parent.principal_state !== 'active' || parent.credential_state === 'revoked' ||
        parent.principal_id !== binding.principal_id || parent.issuer_id !== binding.issuer_id || parent.issuer_epoch !== binding.issuer_epoch ||
        String(parent.revision) !== binding.session_revision) fail('local_authorization_parent');
    const grant = current(parent.principal_id);
    if (grant.state !== 'active' || grant.issuer_id !== parent.issuer_id || grant.issuer_epoch !== parent.issuer_epoch ||
        !Array.isArray(binding.requested_scopes) || binding.requested_scopes.length === 0 ||
        binding.requested_scopes.some(p => !grant.permissions.includes(p))) fail('local_authorization_denied');
    const {requested_scopes, ...identity} = binding;
    return seal({id: grant.id, revision: grant.revision, ...identity, subject_revision: parent.subject_revision,
      policy_revision: grant.revision, permissions: [...requested_scopes].sort(),
      scope_digest: digest({service_id: service.service_id, database_instance_id: service.database_instance_id, grant_ref: ref(grant)}),
      not_before_ns: String(BigInt(parent.not_before_ns)), expires_ns: String(BigInt(parent.expires_ns))});
  }
  function replace(found, request, now) {
    transaction();
    const actor = current(found.session.principal_id);
    if (actor.state !== 'active' || !actor.permissions.includes('auth.manage') || now.upper >= BigInt(found.session.recent_before_ns)) fail('local_authorization_management_denied');
    if (!request || Object.keys(request).sort().join(',') !== 'expected_revision,permissions,principal_id,request_id' ||
        !uuid(request.request_id) || !uuid(request.principal_id) || typeof request.expected_revision !== 'string' ||
        !/^[1-9][0-9]{0,19}$/.test(request.expected_revision) || BigInt(request.expected_revision) > maxRevision ||
        !Array.isArray(request.permissions) || request.permissions.length > supported.size ||
        new Set(request.permissions).size !== request.permissions.length || request.permissions.some(p => !supported.has(p))) fail('local_authorization_request');
    request = {...request, permissions: [...request.permissions].sort()};
    const requestDigest = digest(request);
    const prior = rows(db, 'SELECT request_digest, body FROM local_permission_operation WHERE actor_credential_id = ? AND request_id = ?', found.credential.credential_id, request.request_id)[0];
    if (prior) { if (prior.request_digest !== requestDigest) fail('local_authorization_conflict'); return JSON.parse(prior.body.toString()); }
    const old = current(request.principal_id);
    if (old.revision !== request.expected_revision) fail('local_authorization_revision');
    if (old.state !== 'active' || BigInt(old.revision) >= maxRevision) fail('local_authorization_pending');
    const targets = [...new Set([service.service_id, ...rows(db, `SELECT a.audience AS target FROM session_audience a
      JOIN auth_session s ON s.session_id = a.session_id WHERE s.principal_id = ? UNION SELECT b.target_service_id AS target
      FROM session_target_binding b JOIN auth_session s ON s.session_id = b.session_id WHERE s.principal_id = ? LIMIT 4097`, old.principal_id, old.principal_id).map(r => r.target)])].sort();
    if (targets.length > 4096) fail('local_authorization_budget');
    const reduced = old.permissions.some(p => !request.permissions.includes(p)), operationId = crypto.randomUUID();
    const {digest: _digest, ...body} = old;
    const value = append(db, {...body, id: crypto.randomUUID(), revision: String(BigInt(old.revision) + 1n),
      permissions: request.permissions, state: reduced ? 'pending' : 'active', operation_id: operationId});
    const operation = seal({format: 'local-permission-operation/1', id: operationId, revision: '1', principal_id: old.principal_id,
      previous_ref: ref(old), current_ref: ref(value), target_service_ids: targets, state: 'pending', reduced,
      acquisition_ref: now.acquisition, actor_session_id: found.session.session_id, actor_credential_id: found.credential.credential_id});
    const bytes = Buffer.from(canonical(operation)); if (bytes.length > 32768) fail('local_authorization_budget');
    const changed = db.prepare('UPDATE local_permission_head SET revision = ?, id = ? WHERE principal_id = ? AND revision = ?')
      .run(revisionKey(value.revision), value.id, old.principal_id, revisionKey(old.revision));
    if (changed.changes !== 1) throw new Error('local_authorization_head_write');
    db.prepare("UPDATE access_token SET state = 'revoked' WHERE state = 'active' AND session_id IN (SELECT session_id FROM auth_session WHERE principal_id = ?)").run(old.principal_id);
    db.prepare('INSERT INTO local_permission_operation VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(operation.id, found.credential.credential_id, request.request_id, requestDigest, old.principal_id, revisionKey(value.revision), value.id, now.acquisition.id, bytes);
    for (const target of targets) {
      db.prepare("INSERT INTO local_permission_target VALUES (?, ?, 'pending')").run(operation.id, target);
      db.prepare('INSERT INTO local_permission_outbox VALUES (?, ?)').run(operation.id, target);
    }
    return operation;
  }
  return Object.freeze({resolve, current, replace});
}
