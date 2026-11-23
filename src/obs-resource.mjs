import {randomUUID} from 'node:crypto';
import {canonical, digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {inspectObsCut} from './obs-discovery.mjs';

const id = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/.test(value);
const need = (ok, code) => { if (!ok) throw new IdentityError('obs_resource_' + code); };
const read = (text, expected) => {
  const value = JSON.parse(text);
  need(canonical(value) === text && digest(value) === expected, 'integrity');
  return value;
};

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
  const scope = {authority_service_id: service.service_id, database_instance_id: service.database_instance_id};
  const receipt = record => ({
    resource_ref: {kind: 'resource', ...scope, object_id: record.resource_id, revision: '1', digest: digest(record)},
    record
  });
  function select() {
    need(db.prepare('SELECT count(*) FROM identity_receipt').pluck().get() === 1, 'admin_required');
    const prior = db.prepare('SELECT body_jcs,body_digest,input_digest FROM obs_local_resource WHERE request_id=?').raw().get(request_id);
    if (prior) {
      need(prior[2] === inputDigest, 'request_conflict');
      return {prior: receipt(read(prior[0], prior[1]))};
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
    const result = receipt(record);
    db.prepare('INSERT INTO obs_local_resource VALUES (?,?,?,?,?,?,?,?)').run(device_id, port, record.resource_id,
      request_id, inputDigest, canonical(record), result.resource_ref.digest, transaction);
    db.prepare('INSERT INTO obs_local_resource_commit VALUES (?,?,?)').run(transaction, device_id,
      canonical({kind: 'obs_local_resource_registered', transaction_id: transaction, device_id, resource_ref: result.resource_ref}));
    return result;
  }).immediate();
}
