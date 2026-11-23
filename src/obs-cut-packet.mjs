import {canonical,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';

export const obsCutPrimitive = 'obs_program_scene_cut';
export const obsCutPacketBytes = 52;
const opcode = Buffer.from('LSO1');
const fields = ['binding_revision','catalog_revision','collection_generation','collection_ref'];
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/.test(value);
const need = (ok,reason) => { if(!ok)throw new IdentityError('obs_cut_packet_'+reason); };
const exact = (value,keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',')===keys;

function catalogDigest(catalog,binding) {
  need(catalog?.status==='ready'&&catalog.binding_revision==='2'&&catalog.device_id===binding?.device_id&&
    catalog.device_session_id===binding?.device_session_id&&Array.isArray(catalog.entries)&&catalog.entries.length===2,'catalog');
  return Buffer.from(digest(catalog).slice(7),'hex');
}

// 只编码经过确认的逻辑场景引用。报文请求 ID 由实际 WebSocket 出口分配。
export function encodeObsCutPacket(catalog,binding,parameters) {
  const hash = catalogDigest(catalog,binding);
  need(exact(parameters,'scene_ref') && exact(parameters.scene_ref,'binding_revision,catalog_revision,collection_generation,collection_ref,scene_id'),'parameters');
  const ref = parameters.scene_ref;
  need(fields.every(key=>ref[key]===catalog[key]),'stale_reference');
  const target = catalog.entries.find(entry=>entry.scene_id===ref.scene_id);
  need(uuid(target?.obs_scene_uuid),'scene');
  return Buffer.concat([opcode,hash,Buffer.from(target.obs_scene_uuid.replaceAll('-',''),'hex')],obsCutPacketBytes);
}

export function readObsCutPacket(bytes,catalog,binding) {
  const hash = catalogDigest(catalog,binding);
  need(bytes instanceof Uint8Array&&bytes.byteLength===obsCutPacketBytes,'format');
  const packet = Buffer.from(bytes);
  need(packet.subarray(0,opcode.length).equals(opcode),'format');
  need(packet.subarray(opcode.length,opcode.length+hash.length).equals(hash),'stale_reference');
  const hex = packet.subarray(opcode.length+hash.length).toString('hex');
  const scene = [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
  need(catalog.entries.some(entry=>entry.obs_scene_uuid===scene),'scene');
  return scene;
}

export function obsCutDirectoryMatches(catalog,observedScenes) {
  const ordered = entries => [...entries].sort((left,right)=>Buffer.compare(Buffer.from(left.obs_scene_uuid),Buffer.from(right.obs_scene_uuid)));
  const expected = catalog.entries.map(({obs_scene_uuid,display_name})=>({obs_scene_uuid,display_name}));
  return canonical(ordered(expected))===canonical(ordered(observedScenes));
}
