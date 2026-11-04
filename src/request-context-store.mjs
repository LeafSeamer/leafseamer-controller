import crypto from 'node:crypto';
import {IdentityError} from './identity-crypto.mjs';
import {canonical, digest} from './auth-clock-value.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {createHttpAdapter} from './sdk/http.mjs';
const fail = code => { throw new IdentityError(code); };
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const millisecond = 1000000n;
const iso = value => new Date(Number(value / millisecond)).toISOString();

// 开发预算有界且不回收历史；完整生产容量profile与命令去重writer另行接入。
export function requestContextService({db, binding, writer, time, authorizeToken, rows, pad}) {
  const adapter = createHttpAdapter(selection);
  const available = () => { if (!binding) fail('request_context_migration_required'); };
  const deliver = result => { if (result.denied) fail(result.denied); return result; };
  function operations(names, proof) {
    if (!Array.isArray(names) || names.length < 1 || names.length > 32 || names.some(n => typeof n !== 'string') || new Set(names).size !== names.length) fail('request_context_invalid');
    for (const name of names) {
      let op;
      try { op = adapter.describe('controller', name); } catch { fail('request_context_operation'); }
      if (op.transport !== 'http-headers' || !op.security.some(group => Object.keys(group).some(k => k.endsWith('__bearerAuth'))) ||
          !proof.permissions.includes(op.extensions['x-permission'] ?? op.extensions['x-required-permission'])) fail('request_context_permission');
    }
    return [...names].sort();
  }
  function current(input, id, operation) {
    const proof = authorizeToken(input, binding.service.service_id); if (proof.denied) return proof;
    const row = rows(db, 'SELECT * FROM request_context WHERE context_id = ?', id)[0];
    if (!row || row.issuer_id !== proof.issuer_id || row.issuer_epoch !== proof.issuer_epoch || row.principal_id !== proof.principal_id ||
        row.session_id !== proof.session_id || row.credential_id !== proof.credential_id || row.token_id !== input.token_id) fail('request_context_denied');
    if (row.state !== 'active' || row.service_boot_id !== binding.bootId || row.context_epoch !== binding.service.request_epoch) fail('request_context_closed');
    const now = time();
    if (now.upper >= BigInt(row.expires_ns)) {
      db.prepare("UPDATE request_context SET state = 'expired', closed_reason = 'expired' WHERE context_id = ?").run(id);
      return {denied: 'request_context_expired'};
    }
    if (now.lower < BigInt(row.not_before_ns)) fail('request_context_time');
    const stored = JSON.parse(row.body.toString());
    if (digest(stored) !== row.body_digest || stored.authorization_digest !== proof.authorization_digest || stored.scope_digest !== proof.scope_digest) fail('request_context_binding');
    operations(stored.context.operations, proof);
    if (operation !== undefined && !stored.context.operations.includes(operation)) fail('request_context_permission');
    return stored.context;
  }
  return {
    createRequestContext(input, request) {
      available();
      if (!request || Object.keys(request).sort().join(',') !== 'audience,max_unique_requests,operations,selection,ttl_ms' ||
          !uuid(request.audience) || !Number.isSafeInteger(request.ttl_ms) || request.ttl_ms < 1 || request.ttl_ms > 86400000 ||
          !Number.isSafeInteger(request.max_unique_requests) || request.max_unique_requests < 1 || request.max_unique_requests > 4096 ||
          canonical(request.selection) !== canonical(selection)) fail('request_context_invalid');
      const result = writer(() => {
        const proof = authorizeToken(input, binding.service.service_id); if (proof.denied) return proof;
        if (request.audience !== binding.service.service_id || !proof.permissions.includes('request.create')) fail('request_context_permission');
        const allowed = operations(request.operations, proof), now = time();
        const before = now.lower - 60000000000n;
        if (db.prepare('SELECT count(*) FROM request_context').pluck().get() >= 4096 ||
            db.prepare('SELECT count(*) FROM request_context WHERE principal_id = ? AND not_before_ns >= ?').pluck().get(proof.principal_id, pad(before > 0n ? before : 0n)) >= 64) fail('request_context_capacity');
        const start = (now.lower + millisecond - 1n) / millisecond * millisecond;
        const requested = now.lower + BigInt(Math.min(request.ttl_ms, 60000)) * millisecond;
        const expiry = (requested < BigInt(proof.expires_ns) ? requested : BigInt(proof.expires_ns)) / millisecond * millisecond;
        if (expiry <= now.upper || expiry <= start) fail('request_context_time');
        const context = {context_id: crypto.randomUUID(), service_id: binding.service.service_id, issuer_id: proof.issuer_id, issuer_epoch: proof.issuer_epoch,
          principal_id: proof.principal_id, audience: request.audience, operations: allowed, context_epoch: binding.service.request_epoch,
          issued_at: iso(start), expires_at: iso(expiry), ttl_ms: Number((expiry - start) / millisecond), max_unique_requests: Math.min(request.max_unique_requests, 256), selection};
        const original = {context, authorization_digest: proof.authorization_digest, scope_digest: proof.scope_digest};
        const bytes = Buffer.from(canonical(original)); if (bytes.length > 16384) fail('request_context_invalid');
        db.prepare("INSERT INTO request_context VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'active', NULL, ?, ?, ?, ?)")
          .run(context.context_id, context.service_id, binding.service.database_instance_id, context.issuer_id, context.issuer_epoch, context.principal_id,
            context.context_epoch, binding.bootId, proof.session_id, proof.credential_id, input.token_id, pad(now.lower), pad(expiry), context.max_unique_requests,
            bytes, digest(original), now.acquisition.id, crypto.randomUUID());
        // 同writer提交前再核凭据和上下文；任何失效回滚新签发。
        const last = current(input, context.context_id);
        if (last.denied) fail(last.denied);
        return context;
      });
      return deliver(result);
    },
    getRequestContext(input, id, operation) {
      available(); if (!uuid(id)) fail('request_context_invalid');
      return deliver(writer(() => current(input, id, operation)));
    },
  };
}
