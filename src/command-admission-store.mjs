import crypto from 'node:crypto';
import {IdentityError} from './identity-crypto.mjs';
import {canonical, digest} from './auth-clock-value.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {createHttpAdapter} from './sdk/http.mjs';

const fail = code => { throw new IdentityError(code); };
const bytes = value => Buffer.from(canonical(value));
const version = 'command-admission/0.1.0-draft.1';
// 只排除具名顶层运输字段，嵌套同名业务字段仍参与摘要。
export function commandContent({context_id, idempotency_key, correlation_id, ...content}) { return content; }

export function commandAdmissionStore({db, binding, writer, time, authorizeToken, rows}) {
  const adapter = createHttpAdapter(selection), service = binding?.service;
  const scope = service && {authority_service_id: service.service_id, database_instance_id: service.database_instance_id};
  const available = () => { if (!service || Number(service.schema_revision) < 9) fail('command_admission_unavailable'); };
  const deliver = value => { if (value.denied) fail(value.denied); return value; };
  async function validate(operation, input) {
    available();
    try {
      const op = adapter.describe('controller', operation), body = Buffer.from(JSON.stringify(input));
      if (body.length > 16384) fail('command_request_invalid');
      const request = adapter.prepareRequest('controller', 'POST', op.path, [['Content-Type', 'application/json'],
        ['X-LeafSeamer-Contract', selection.contract_id], ['X-LeafSeamer-Contract-Digest', selection.contract_digest]]);
      return (await adapter.decodeRequest(body, request)).value;
    } catch { fail('command_request_invalid'); }
  }
  function authenticate(input, permission) {
    const proof = authorizeToken(input, service.service_id); if (proof.denied) return proof;
    if (proof.principal_kind !== 'human' || !proof.permissions.includes(permission)) fail('command_permission');
    return proof;
  }
  function ownership(proof, key) {
    if (canonical(key.target_scope) !== canonical(scope) || key.operation_id !== 'createCommand' ||
      key.issuer_id !== proof.issuer_id || key.issuer_epoch !== proof.issuer_epoch || key.principal_id !== proof.principal_id) fail('command_permission');
    const context = rows(db, `SELECT * FROM request_context WHERE service_id=? AND database_instance_id=? AND issuer_id=?
      AND issuer_epoch=? AND principal_id=? AND context_epoch=? ORDER BY context_id LIMIT 1`, service.service_id, service.database_instance_id,
      key.issuer_id, key.issuer_epoch, key.principal_id, key.request_epoch)[0];
    if (!context) fail('command_namespace');
    const original = JSON.parse(context.body.toString());
    if (digest(original) !== context.body_digest || canonical(original.context.selection) !== canonical(selection)) fail('command_binding');
    return context;
  }
  function find(identity) {
    const k = identity.key;
    const row = rows(db, `SELECT k.key_id,k.request_digest,a.adjudication_digest,a.adjudication_body FROM ca_namespace n
      JOIN ca_request_key k USING(namespace_id) JOIN ca_adjudication a USING(key_id)
      WHERE n.issuer_id=? AND n.issuer_epoch=? AND n.principal_id=? AND n.request_epoch=? AND k.operation_id=? AND k.idempotency_key=?`,
      k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch, k.operation_id, k.idempotency_key)[0];
    if (!row) return null;
    if (row.request_digest !== identity.request_digest) fail('command_conflict');
    const value = JSON.parse(row.adjudication_body.toString()), {adjudication_digest, ...body} = value;
    if (digest(body) !== adjudication_digest || adjudication_digest !== row.adjudication_digest || canonical(value.identity) !== canonical(identity)) fail('command_binding');
    return {keyId: row.key_id, value};
  }
  function recheck(input, permission, identity) {
    const proof = authenticate(input, permission); if (proof.denied) return proof;
    ownership(proof, identity.key); return proof;
  }
  function lookup(input, identity) {
    const proof = recheck(input, 'command.read', identity); if (proof.denied) return proof;
    const found = find(identity);
    const last = recheck(input, 'command.read', identity); if (last.denied) return last;
    return {state: found ? 'found' : 'not_found', adjudication: found?.value ?? null};
  }
  return Object.freeze({
    async lookupCommandAdmission(input, request) {
      const identity = await validate('lookupCommandAdmission', request);
      return deliver(writer(() => lookup(input, identity)));
    },
    async rejectCommandAdmission(input, request) {
      const value = await validate('rejectCommandAdmission', request), {identity, content} = value;
      if (digest(content) !== identity.request_digest) fail('command_request_invalid');
      if (content.origin !== 'manual' || content.automation_binding !== null) fail('command_permission');
      return deliver(writer(() => {
        const proof = recheck(input, 'command.cancel', identity); if (proof.denied) return proof;
        const k = identity.key, operationDigest = digest(value), owner = ownership(proof, k);
        const prior = rows(db, `SELECT operation_digest,key_id FROM ca_rejection WHERE actor_issuer_id=? AND actor_issuer_epoch=?
          AND actor_principal_id=? AND rejection_operation_id=?`, proof.issuer_id, proof.issuer_epoch, proof.principal_id, value.rejection_operation_id)[0];
        if (prior) {
          if (prior.operation_digest !== operationDigest) fail('command_conflict');
          const found = find(identity); if (!found || found.keyId !== prior.key_id) fail('command_binding');
          return found.value;
        }
        const found = find(identity);
        if (db.prepare('SELECT count(*) FROM ca_rejection').pluck().get() >= 8192 ||
          !found && db.prepare('SELECT count(*) FROM ca_request_key').pluck().get() >= 4096) fail('command_capacity');
        let namespace = rows(db, 'SELECT namespace_id FROM ca_namespace WHERE issuer_id=? AND issuer_epoch=? AND principal_id=? AND request_epoch=?',
          k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch)[0];
        if (!namespace) {
          namespace = {namespace_id: crypto.randomUUID()};
          db.prepare('INSERT INTO ca_namespace VALUES (?,1,?,?,?,?,?,?)').run(namespace.namespace_id, k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch, owner.context_id, owner.body);
        }
        const keyId = found?.keyId ?? crypto.randomUUID(), commitId = crypto.randomUUID(), rejectionId = crypto.randomUUID();
        const kind = found ? 'reject_existing' : 'reject_new';
        const commit = {kind: 'controller_commit', scope, object_id: commitId, revision: '1', operation: kind, identity,
          rejection_operation_id: value.rejection_operation_id, acquisition_ref: time().acquisition};
        const commitRef = {kind: commit.kind, scope, object_id: commitId, revision: '1', digest: digest(commit)};
        const body = {contract_version: version, adjudication_id: crypto.randomUUID(), revision: '1', identity, decision: 'rejected', command_ref: null, commit_ref: commitRef};
        const adjudication = found?.value ?? {...body, adjudication_digest: digest(body)};
        if (!found) {
          db.prepare('INSERT INTO ca_request_key VALUES (?,?,?,?,?,?,?)').run(keyId, namespace.namespace_id, 'createCommand', k.idempotency_key, identity.request_digest, content.device_id, bytes(content));
          db.prepare('INSERT INTO ca_adjudication VALUES (?,?,?, ?,NULL,?,?,?,?)').run(keyId, adjudication.adjudication_id, '1', 'rejected', commitId, kind, adjudication.adjudication_digest, bytes(adjudication));
        }
        db.prepare('INSERT INTO ca_commit VALUES (?,?,?,?,?,?)').run(commitId, keyId, kind, found ? null : keyId, rejectionId, bytes(commit));
        db.prepare('INSERT INTO ca_audit VALUES (?,?,?,?)').run(commitId, keyId, kind, bytes({identity, actor: {issuer_id: proof.issuer_id, issuer_epoch: proof.issuer_epoch, principal_id: proof.principal_id}, decision: adjudication.decision}));
        db.prepare('INSERT INTO ca_notification VALUES (?,?,?,?,?)').run(commitId, keyId, kind, crypto.randomUUID(), bytes({identity, adjudication}));
        db.prepare('INSERT INTO ca_rejection VALUES (?,?,?,?,?,?,?,?,?,?)').run(rejectionId, proof.issuer_id, proof.issuer_epoch, proof.principal_id,
          value.rejection_operation_id, operationDigest, keyId, commitId, bytes(value), bytes({authorization_digest: proof.authorization_digest, scope_digest: proof.scope_digest, token_id: input.token_id}));
        const last = recheck(input, 'command.cancel', identity); if (last.denied) fail(last.denied);
        return adjudication;
      }));
    },
    async submitCommand(input, request) {
      const value = await validate('submitCommand', request);
      return deliver(writer(() => {
        const proof = authenticate(input, 'command.read'); if (proof.denied) return proof;
        const context = rows(db, 'SELECT * FROM request_context WHERE context_id=?', value.context_id)[0];
        if (!context) fail('command_namespace');
        const identity = {key: {target_scope: scope, issuer_id: context.issuer_id, issuer_epoch: context.issuer_epoch, principal_id: context.principal_id,
          request_epoch: context.context_epoch, operation_id: 'createCommand', idempotency_key: value.idempotency_key}, request_digest: digest(commandContent(value))};
        const result = lookup(input, identity); if (result.denied) return result;
        if (result.state !== 'found') fail('command_admission_unavailable');
        return result.adjudication;
      }));
    },
    confirmCommandResult(input, identity, permission, expected) {
      available();
      return deliver(writer(() => {
        const proof = recheck(input, permission, identity); if (proof.denied) return proof;
        const found = find(identity), value = permission === 'command.read' && expected.state ? {state: found ? 'found' : 'not_found', adjudication: found?.value ?? null} : found?.value;
        if (canonical(value) !== canonical(expected)) fail('command_binding'); return value;
      }));
    },
  });
}
