import crypto from 'node:crypto';
import {IdentityError} from './identity-crypto.mjs';
import {canonical, digest} from './auth-clock-value.mjs';

const fail = code => { throw new IdentityError(code); };
const id = value => typeof value === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(value);
const bytes = value => Buffer.from(canonical(value));
const rows = (db, sql, ...args) => {
  const q = db.prepare(sql), names = q.columns().map(c => c.name);
  return q.raw().all(...args).map(values => Object.fromEntries(names.map((n, i) => [n, values[i]])));
};
function decode(body, expected) {
  const value = JSON.parse(body.toString());
  if (!bytes(value).equals(body) || digest(value) !== expected) fail('device_registry_integrity'); return value;
}
const scope = service => ({authority_service_id: service.service_id, database_instance_id: service.database_instance_id});
const available = (db, service) => { if (!db.open || !service || Number(service.schema_revision) < 10) fail('device_migration_required'); };

// 仅由可信本机安装管理调用；参数是待配置元数据，不是能力或设备运行批准。
export function registerDevice(db, service, input) {
  available(db, service);
  if (db.inTransaction) fail('device_outer_transaction');
  if (!input || Object.keys(input).sort().join(',') !== 'device_kind,display_name,request_id' ||
    !id(input.request_id) || !id(input.device_kind) || typeof input.display_name !== 'string' || input.display_name.length < 1 || input.display_name.length > 1024 ||
    /[\u0000-\u001f\u007f]/.test(input.display_name)) fail('device_registration_invalid');
  const request = JSON.parse(canonical(input)), requestDigest = digest(request);
  return db.transaction(() => {
    if (db.prepare('SELECT count(*) FROM identity_receipt').pluck().get() !== 1) fail('device_admin_uninitialized');
    const prior = rows(db, `SELECT r.request_digest,c.receipt_body,c.receipt_digest FROM device_registration r
      JOIN device_registration_commit c USING(tx_id) WHERE r.request_id=?`, request.request_id)[0];
    if (prior) { if (prior.request_digest !== requestDigest) fail('device_registration_conflict'); return decode(prior.receipt_body, prior.receipt_digest); }
    const revision = db.prepare('SELECT revision FROM device_catalog WHERE singleton=1').pluck().get();
    if (revision >= 4096) fail('device_capacity');
    const deviceId = crypto.randomUUID(), recordId = crypto.randomUUID(), txId = crypto.randomUUID();
    const descriptor = {device_id: deviceId, device_kind: request.device_kind, display_name: request.display_name,
      connection_state: 'disconnected', actions: [], triggers: [], state_schema: {schema_id: 'device.unavailable',
        dialect: 'https://json-schema.org/draft/2020-12/schema', document: false, digest: digest(false)}};
    const controlBody = {record_id: recordId, scope: scope(service), device_id: deviceId, revision: '1', control_epoch: crypto.randomUUID(),
      effective_version: '0', reserved_version: '0', holder: null, mode: 'automatic', pending_change: null, gate_state: 'protected',
      in_flight_command_ids: [], unresolved_command_ids: []};
    const control = {...controlBody, record_digest: digest(controlBody)};
    const receipt = {request_id: request.request_id, transaction_id: txId, device_id: deviceId, scope: scope(service),
      catalog_revision: String(revision + 1), descriptor_digest: digest(descriptor), control_ref: {record_id: recordId, revision: '1', digest: control.record_digest}};
    db.prepare('INSERT INTO device_registration VALUES (?,?,?,?,?)').run(request.request_id, requestDigest, deviceId, txId, bytes(request));
    db.prepare('INSERT INTO device_record VALUES (?,?,?,?,?,?,?)').run(deviceId, revision + 1, request.request_id, bytes(descriptor), digest(descriptor), recordId, txId);
    db.prepare('INSERT INTO device_control_history VALUES (?,?,?,?,?,?)').run(recordId, deviceId, '1', control.control_epoch, bytes(control), digest(control));
    db.prepare('INSERT INTO device_registration_commit VALUES (?,?,?,?,?,?,?,?)').run(txId, deviceId, request.request_id, bytes(receipt), digest(receipt),
      bytes({kind: 'local_device_registration', device_id: deviceId, transaction_id: txId}), crypto.randomUUID(), bytes({kind: 'device_registered', receipt}));
    return receipt;
  }).immediate();
}

export function deviceRegistryReader(db, service) {
  const transaction = () => { available(db, service); if (!db.inTransaction) fail('device_transaction_required'); };
  const cursorFor = (revision, sequence) => `v1.${revision}.${sequence}.` + digest({scope: scope(service), kind: 'device_page', revision, sequence}).slice(7);
  return Object.freeze({
    list(cursor) {
      transaction(); const revision = db.prepare('SELECT revision FROM device_catalog WHERE singleton=1').pluck().get(); let after = 0;
      if (cursor !== undefined) {
        const m = typeof cursor === 'string' && /^v1\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.([0-9a-f]{64})$/.exec(cursor);
        if (!m || Number(m[1]) > 4096 || Number(m[2]) < 1 || Number(m[2]) > Number(m[1]) || cursorFor(Number(m[1]), Number(m[2])) !== cursor) fail('device_cursor_invalid');
        if (Number(m[1]) !== revision) fail('device_cursor_stale'); after = Number(m[2]);
      }
      const records = rows(db, 'SELECT sequence,descriptor_body,descriptor_digest FROM device_record WHERE sequence>? ORDER BY sequence LIMIT 65', after);
      const items = []; let size = 0, last = after;
      for (const row of records) {
        if (items.length === 64 || size + row.descriptor_body.length > 49152) break;
        items.push(decode(row.descriptor_body, row.descriptor_digest)); size += row.descriptor_body.length; last = row.sequence;
      }
      return {items, next_cursor: last < revision ? cursorFor(revision, last) : null, catalog_revision: String(revision)};
    },
    control(deviceId) {
      transaction(); if (!id(deviceId)) fail('device_registration_invalid');
      const latest=Number(service.schema_revision)>=26?db.prepare('SELECT r.body_jcs,r.body_digest FROM control_record_revision r JOIN control_record_head h USING(device_id,revision) WHERE device_id=?').raw().get(deviceId):null;
      const record = latest?{body:Buffer.from(latest[0]),digest:latest[1]}:rows(db, `SELECT h.body,h.digest FROM device_record d JOIN device_control_history h ON h.record_id=d.initial_control_id
        AND h.device_id=d.device_id WHERE d.device_id=?`, deviceId)[0];
      if (!record) fail('device_not_found');
      const value = decode(record.body, record.digest), {record_digest, ...body} = value;
      if (digest(body) !== record_digest || canonical(value.scope) !== canonical(scope(service))) fail('device_registry_integrity'); return value;
    },
  });
}
