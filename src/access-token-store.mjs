import crypto from 'node:crypto';
import {IdentityError, createOpaqueSecret, verifyOpaqueSecret} from './identity-crypto.mjs';
import {clockInteger} from './native-clock.mjs';
import {canonical, checked, digest, fields, same} from './auth-clock-value.mjs';

const fail = code => { throw new IdentityError(code); };
const uuid = value => typeof value === 'string' && value.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const names = values => Array.isArray(values) && values.length >= 1 && values.length <= 64 &&
  values.every(v => typeof v === 'string' && /^[a-z][a-z0-9_.:-]{0,127}$/.test(v) && v.trim() === v) && new Set(values).size === values.length;

// 只由同库sessionStore装配。authority必须读取当前可信授权/配对来源，不能映射请求自报批准。
export function accessTokenService({db, serviceId, authority, enabled, writer, time, authenticated, terminal, rows, pad}) {
  const available = () => { if (!enabled) fail('token_migration_required'); if (!authority || typeof authority.resolve !== 'function') fail('token_authority_unavailable'); };
  function grant(session, credential, audience, requested, now) {
    available();
    const resolved = authority.resolve(Object.freeze({issuer_id: session.issuer_id, issuer_epoch: session.issuer_epoch,
      principal_id: session.principal_id, session_id: session.session_id, credential_id: credential.credential_id,
      session_revision: String(session.revision), audience, requested_scopes: Object.freeze([...requested])}));
    const bytes = canonical(resolved); if (typeof bytes !== 'string' || Buffer.byteLength(bytes) > 32768) fail('token_authorization_invalid');
    const value = JSON.parse(bytes);
    fields(value, ['id', 'revision', 'digest', 'issuer_id', 'issuer_epoch', 'principal_id', 'session_id', 'credential_id',
      'subject_revision', 'session_revision', 'policy_revision', 'audience', 'permissions', 'scope_digest', 'not_before_ns', 'expires_ns']);
    checked(value);
    const principal = rows(db, 'SELECT revision, state FROM local_principal WHERE principal_id = ?', session.principal_id)[0];
    if (!principal || principal.state !== 'active' || value.subject_revision !== principal.revision || value.issuer_id !== session.issuer_id ||
      value.issuer_epoch !== session.issuer_epoch || value.principal_id !== session.principal_id || value.session_id !== session.session_id ||
      value.credential_id !== credential.credential_id || value.session_revision !== String(session.revision) || value.audience !== audience ||
      !names(value.permissions) || value.permissions.some(p => !requested.includes(p)) || !same(value.permissions, [...value.permissions].sort()) ||
      typeof value.scope_digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value.scope_digest) || value.scope_digest.length !== 71 ||
      clockInteger(value.policy_revision) === 0n || clockInteger(value.not_before_ns) > now.lower || clockInteger(value.expires_ns) <= now.upper) fail('token_authorization_invalid');
    return value;
  }
  function metadata(row) {
    return {token_id: row.token_id, audience: row.audience, session_id: row.session_id, credential_id: row.credential_id,
      not_before_ns: String(BigInt(row.not_before_ns)), expires_ns: String(BigInt(row.expires_ns)), state: row.state,
      authorization_digest: row.authorization_digest};
  }
  const deliver = result => { if (result.denied) fail(result.denied); return result; };
  return {
    issueToken(sessionInput, request) {
      available();
      if (!request || Object.keys(request).sort().join(',') !== 'audience,request_id,requested_scopes' ||
        !uuid(request.request_id) || !uuid(request.audience) || !names(request.requested_scopes)) fail('token_request_invalid');
      request = {request_id: request.request_id, audience: request.audience, requested_scopes: [...request.requested_scopes].sort()};
      const requestDigest = digest(request), secret = createOpaqueSecret('access_token'), tokenId = crypto.randomUUID();
      const result = writer(() => {
        const now = time(), found = authenticated(sessionInput, now); if (found.denied) return found;
        const old = rows(db, 'SELECT * FROM access_token WHERE credential_id = ? AND request_id = ?', found.credential.credential_id, request.request_id)[0];
        if (old) {
          if (old.request_digest !== requestDigest) fail('token_request_conflict');
          // 重复请求只返回非秘密历史信息；不能再交付或重新生成可兑换秘密。
          return {token: metadata(old), replay: true, secret: null};
        }
        const authorization = grant(found.session, found.credential, request.audience, request.requested_scopes, now);
        db.prepare("UPDATE access_token SET state = 'expired' WHERE credential_id = ? AND state = 'active' AND expires_ns <= ?").run(found.credential.credential_id, pad(now.upper));
        const count = db.prepare("SELECT count(*) FROM access_token WHERE credential_id = ? AND state = 'active'").pluck().get(found.credential.credential_id);
        if (count >= 8) return {denied: 'token_capacity'};
        const expiry = [now.lower + 60000000000n, BigInt(found.session.expires_ns), BigInt(found.session.idle_before_ns), clockInteger(authorization.expires_ns)]
          .reduce((a, b) => a < b ? a : b);
        if (expiry <= now.upper) fail('token_time_invalid');
        const tx = crypto.randomUUID();
        db.prepare("INSERT INTO access_token VALUES (?, ?, ?, ?, ?, ?, 'identity-runtime/1:access_token', ?, 'active', ?, ?, ?, ?, ?, ?)")
          .run(tokenId, found.credential.credential_id, found.session.session_id, request.request_id, requestDigest, secret.verifier,
            request.audience, pad(now.lower), pad(expiry), authorization.digest, Buffer.from(canonical(authorization)), now.acquisition.id, tx);
        db.prepare('INSERT OR IGNORE INTO session_audience VALUES (?, ?, ?)').run(found.session.session_id, request.audience, tx);
        const last = time();
        if (last.upper >= expiry || !same(grant(found.session, found.credential, request.audience, request.requested_scopes, last), authorization)) fail('token_authorization_changed');
        return {token: metadata(rows(db, 'SELECT * FROM access_token WHERE token_id = ?', tokenId)[0]), replay: false, secret: secret.secret};
      });
      deliver(result); time(); return result;
    },
    // audience必须由已认证的本地目标或mTLS对端导出；此函数不接受公开HTTP自报对端。
    verifyToken(input, audience) {
      available();
      if (!input || Object.keys(input).sort().join(',') !== 'secret,token_id' || !uuid(input.token_id) || !uuid(audience)) fail('token_invalid');
      return deliver(writer(() => {
        const now = time(), row = rows(db, 'SELECT * FROM access_token WHERE token_id = ?', input.token_id)[0];
        if (!row || row.audience !== audience || !verifyOpaqueSecret('access_token', input.secret, row.verifier) || row.state !== 'active') fail('token_invalid');
        const session = rows(db, 'SELECT * FROM auth_session WHERE session_id = ?', row.session_id)[0];
        const credential = rows(db, 'SELECT * FROM session_refresh_credential WHERE credential_id = ?', row.credential_id)[0];
        if (!session || session.state !== 'active' || !credential || credential.session_id !== session.session_id || credential.state === 'revoked') fail('token_invalid');
        if (now.upper >= BigInt(session.expires_ns) || now.upper >= BigInt(session.idle_before_ns)) {
          terminal(session, 'expired', now); return {denied: 'token_invalid'};
        }
        if (now.upper >= BigInt(row.expires_ns)) {
          db.prepare("UPDATE access_token SET state = 'expired' WHERE token_id = ? AND state = 'active'").run(row.token_id);
          return {denied: 'token_expired'};
        }
        if (now.lower < BigInt(row.not_before_ns)) fail('token_time_invalid');
        const original = checked(JSON.parse(row.authorization_body.toString()));
        if (original.digest !== row.authorization_digest) fail('token_authorization_invalid');
        const current = grant(session, credential, audience, original.permissions, now);
        if (!same(current, original)) {
          db.prepare("UPDATE access_token SET state = 'revoked' WHERE token_id = ? AND state = 'active'").run(row.token_id);
          return {denied: 'token_invalid'};
        }
        const last = time(); if (last.upper >= BigInt(row.expires_ns)) {
          db.prepare("UPDATE access_token SET state = 'expired' WHERE token_id = ? AND state = 'active'").run(row.token_id);
          return {denied: 'token_expired'};
        }
        if (!same(grant(session, credential, audience, original.permissions, last), original)) {
          db.prepare("UPDATE access_token SET state = 'revoked' WHERE token_id = ? AND state = 'active'").run(row.token_id);
          return {denied: 'token_invalid'};
        }
        return {active: true, principal_kind: 'human', issuer_id: session.issuer_id, issuer_epoch: session.issuer_epoch,
          principal_id: session.principal_id, session_id: session.session_id, credential_id: row.credential_id, audience,
          permissions: original.permissions, scope_digest: original.scope_digest, expires_ns: String(BigInt(row.expires_ns)),
          policy_revision: original.policy_revision, authorization_revision: original.revision,
          session_not_before_ns: String(BigInt(session.not_before_ns)), session_expires_ns: String(BigInt(session.expires_ns)),
          session_idle_before_ns: String(BigInt(session.idle_before_ns)),
          acquisition_ref: last.acquisition, authorization_digest: original.digest};
      }));
    }
  };
}
