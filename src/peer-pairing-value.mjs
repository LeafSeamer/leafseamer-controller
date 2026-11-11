import crypto from 'node:crypto';
import {canonical, digest, same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-crypto.mjs';
export const pairingNeed=(ok,code)=>{if(!ok)throw new IdentityError('peer_pairing_'+code);};
const need=pairingNeed;
export const pairingFields=(value,names)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names.split(',').sort().join(','),'input');
export const pairingUuid=value=>need(typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value),'input');
export const pairingInteger=value=>{need(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)&&BigInt(value)<(1n<<64n),'input');return BigInt(value);};
const hash=value=>need(typeof value==='string'&&/^sha256:[0-9a-f]{64}$/.test(value),'input');
export function pairingTranscript(input){
 pairingFields(input,'format,pair_attempt_id,parties');need(input.format==='leafseamer.peer-pairing/1','version');pairingUuid(input.pair_attempt_id);
 need(Array.isArray(input.parties)&&input.parties.length===2,'parties');
 for(const p of input.parties){
  pairingFields(p,'service_id,database_instance_id,service_kind,issuer_id,issuer_epoch,binding_id,credential_id,certificate_der_sha256,spki_sha256,trust_bundle_digest,endpoint_config_digest,permissions,object_scope_digest,not_before_ns,expires_ns');
  for(const key of ['service_id','database_instance_id','issuer_id','issuer_epoch','binding_id','credential_id'])pairingUuid(p[key]);
  need(['controller','seamer'].includes(p.service_kind),'kind');
  for(const key of ['certificate_der_sha256','spki_sha256','trust_bundle_digest','endpoint_config_digest','object_scope_digest'])hash(p[key]);
  need(Array.isArray(p.permissions)&&p.permissions.length<=64&&p.permissions.every(v=>typeof v==='string'&&/^[a-z][a-z0-9_.:-]{0,127}$/.test(v))&&
   new Set(p.permissions).size===p.permissions.length&&same(p.permissions,[...p.permissions].sort()),'permissions');
  need(pairingInteger(p.not_before_ns)<pairingInteger(p.expires_ns),'validity');
 }
 const parties=[...input.parties].sort((a,b)=>a.service_id.localeCompare(b.service_id,'en'));
 need(parties[0].service_id!==parties[1].service_id&&parties[0].binding_id!==parties[1].binding_id&&parties[0].spki_sha256!==parties[1].spki_sha256,'parties');
 const value={format:input.format,pair_attempt_id:input.pair_attempt_id,parties};need(Buffer.byteLength(canonical(value))<=16384,'capacity');
 return JSON.parse(canonical(value));
}
export function pairingCertificate(pem){
 const certificate=new crypto.X509Certificate(pem),spki=certificate.publicKey.export({type:'spki',format:'der'});
 const sha=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
 return {certificate_der_sha256:sha(certificate.raw),spki_sha256:sha(spki)};
}
export const pairingReference=value=>({id:value.binding_id,revision:value.revision,digest:value.digest});
export function sealPairing(value){const {digest:_old,...body}=value;return {...body,digest:digest(body)};}
