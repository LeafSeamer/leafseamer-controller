import {randomUUID} from 'node:crypto';
import {canonical, digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {inspectObsCut} from './obs-discovery.mjs';
import {createObsDeviceModule} from './obs-device-module.mjs';

const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/.test(value);
const need = (ok, code) => { if (!ok) throw new IdentityError('obs_resource_' + code); };
const read = (text, expected) => {
  const value = JSON.parse(text);
  need(canonical(value) === text && digest(value) === expected, 'integrity');
  return value;
};
const scopeFor = service => ({authority_service_id: service.service_id, database_instance_id: service.database_instance_id});
const receipt = (service, record) => ({
  resource_ref: {kind: 'resource', ...scopeFor(service), object_id: record.resource_id, revision: '1', digest: digest(record)},
  record
});
const auditFor = (transaction_id, device_id, resource_ref) => ({
  kind: 'obs_local_resource_registered', transaction_id, device_id, resource_ref
});

export function readRegisteredObsResource(db, service, deviceId) {
  need(db.inTransaction && Number(service.schema_revision) >= 98, 'writer');
  const row = db.prepare(`SELECT r.body_jcs,r.body_digest,d.descriptor_digest,c.transaction_id,c.audit_jcs
    FROM obs_local_resource r JOIN obs_local_resource_commit c USING(transaction_id,device_id)
    JOIN device_record d USING(device_id) WHERE r.device_id=?`).raw().get(deviceId);
  need(row, 'unregistered');
  const value = receipt(service, read(row[0], row[1]));
  const expectedDevice = {kind: 'device', ...scopeFor(service), object_id: deviceId, revision: '1', digest: row[2]};
  need(canonical(value.record.device_ref) === canonical(expectedDevice) &&
    row[4] === canonical(auditFor(row[3], deviceId, value.resource_ref)), 'integrity');
  return value;
}

export async function registerObsResource(db, service, input) {
  need(db.open && !db.inTransaction, 'writer');
  need(Number(service.schema_revision) >= 98, 'migration_required');
  need(input && Object.keys(input).sort().join(',') === 'collection_name,device_id,password,port,request_id,scene_uuids', 'input');
  const {request_id, device_id, port, collection_name, scene_uuids, password} = input;
  need(id(request_id) && id(device_id) && Number.isInteger(port) && port >= 1 && port <= 65535 &&
    typeof password === 'string' && Buffer.byteLength(password) > 0 && Buffer.byteLength(password) <= 1024 &&
    typeof collection_name === 'string' && Buffer.byteLength(collection_name) > 0 && Buffer.byteLength(collection_name) <= 1024 &&
    Array.isArray(scene_uuids) && scene_uuids.length === 2 && scene_uuids.every(uuid) && scene_uuids[0] !== scene_uuids[1], 'input');
  const expectedScenes = [...scene_uuids].sort();
  // 凭据只用于本次 WebSocket 认证，历史请求只绑定已核对的端点和目录身份。
  const inputDigest = digest({request_id, device_id, port, collection_name, scene_uuids: expectedScenes});
  const scope = scopeFor(service);
  function select() {
    need(db.prepare('SELECT count(*) FROM identity_receipt').pluck().get() === 1, 'admin_required');
    const prior = db.prepare('SELECT device_id,input_digest FROM obs_local_resource WHERE request_id=?').raw().get(request_id);
    if (prior) {
      need(prior[0] === device_id && prior[1] === inputDigest, 'request_conflict');
      return {prior: readRegisteredObsResource(db, service, device_id)};
    }
    const row = db.prepare('SELECT descriptor_body,descriptor_digest FROM device_record WHERE device_id=?').raw().get(device_id);
    need(row, 'device_required');
    const device = read(row[0].toString('utf8'), row[1]);
    need(device.device_kind === 'obs' && device.device_id === device_id, 'device_kind');
    need(!db.prepare('SELECT 1 FROM obs_local_resource WHERE device_id=?').pluck().get(device_id), 'device_bound');
    need(!db.prepare('SELECT 1 FROM obs_local_resource WHERE endpoint_port=?').pluck().get(port), 'endpoint_bound');
    need(db.prepare('SELECT count(*) FROM obs_local_resource').pluck().get() < 4096, 'capacity');
    return {deviceRef: {kind: 'device', ...scope, object_id: device_id, revision: '1', digest: row[1]}};
  }
  const previous = db.transaction(select).immediate();
  if (previous.prior) return previous.prior;
  const observed = await inspectObsCut({port, password});
  const observedScenes = observed.scenes.map(scene => scene.obs_scene_uuid).sort();
  need(observed.collection_name === collection_name && observedScenes.every((scene, index) => scene === expectedScenes[index]), 'catalog_changed');

  need(db.open && !db.inTransaction, 'writer');
  return db.transaction(() => {
    const selected = select();
    if (selected.prior) return selected.prior;
    need(digest(selected.deviceRef) === digest(previous.deviceRef), 'device_changed');
    const transaction = randomUUID();
    const record = {
      format: 'leafseamer-obs-local-resource/1', resource_id: randomUUID(), device_ref: selected.deviceRef,
      endpoint: {address: '127.0.0.1', port},
      profile: observed.profile, obs_version: observed.obs_version, websocket_version: observed.websocket_version,
      rpc_version: observed.rpc_version, available_requests_digest: observed.available_requests_digest,
      collection_name, scene_uuids: expectedScenes
    };
    const result = receipt(service, record);
    db.prepare('INSERT INTO obs_local_resource VALUES (?,?,?,?,?,?,?,?)').run(device_id, port, record.resource_id,
      request_id, inputDigest, canonical(record), result.resource_ref.digest, transaction);
    db.prepare('INSERT INTO obs_local_resource_commit VALUES (?,?,?)').run(transaction, device_id,
      canonical(auditFor(transaction, device_id, result.resource_ref)));
    return result;
  }).immediate();
}

export async function observeObsResource(db, service, input, secrets) {
  need(db.open && !db.inTransaction, 'writer');
  need(Number(service.schema_revision) >= 98, 'migration_required');
  const fields = input && Object.keys(input).sort().join(',');
  need((fields === 'device_id,password,samples' || (fields === 'device_id,samples,secret_ref' && secrets)) &&
    id(input.device_id) && Number.isInteger(input.samples) && input.samples >= 1 && input.samples <= 8, 'input');
  const {device_id, samples, secret_ref} = input;
  const current = db.transaction(() => readRegisteredObsResource(db, service, device_id)).immediate;
  const resource = current();
  const lifetime = new AbortController();
  const binding = {device_id, device_session_id: randomUUID(), signal: lifetime.signal};
  let cleartext;
  try {
    if (fields === 'device_id,samples,secret_ref') {
      need(secret_ref?.secret_id === resource.resource_ref.object_id, 'secret_binding');
      cleartext = secrets.read(secret_ref);
    }
    const password = cleartext ? new TextDecoder('utf-8', {fatal: true}).decode(cleartext) : input.password;
    const module = createObsDeviceModule({resource: resource.record, password, signal: lifetime.signal});
    cleartext?.fill(0);
    const identity = await module.connectReadOnly(binding);
    const catalog = await module.proposeCatalog({...binding, identity});
    const observations = [];
    for (let i = 0; i < samples; i++) observations.push(await module.captureBaseline(binding));
    need(db.open && !db.inTransaction && current().resource_ref.digest === resource.resource_ref.digest, 'resource_changed');
    return {resource_ref: resource.resource_ref, observation_session_id: binding.device_session_id, identity, catalog, samples: observations};
  } finally { cleartext?.fill(0); lifetime.abort(); }
}

export async function sealObsResourceCredential(db, service, input, secrets) {
  need(input && Object.keys(input).sort().join(',') === 'device_id,password,version' && typeof input.version === 'string' &&
    /^[1-9][0-9]{0,8}(?![\s\S])/.test(input.version), 'input');
  const {device_id, password, version} = input;
  const observed = await observeObsResource(db, service, {device_id, password, samples: 1});
  const secret_ref = {owner_service_id: service.service_id, secret_id: observed.resource_ref.object_id, version, purpose: 'obs_websocket'};
  const bytes = Buffer.from(password, 'utf8');
  try { secrets.write(secret_ref, bytes); }
  finally { bytes.fill(0); }
  return {resource_ref: observed.resource_ref, secret_ref};
}
