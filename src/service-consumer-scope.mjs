import {IdentityError} from './identity-error.mjs';
const need=(value,reason)=>{if(!value)throw new IdentityError('service_consumer_'+reason);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(','),'input');
const id=value=>need(typeof value==='string'&&/^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(value),'input');
const uuid=value=>need(typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(value),'input');
const revision=value=>need(typeof value==='string'&&/^[1-9][0-9]{0,19}$(?![\s\S])/.test(value),'input');
const hash=value=>need(typeof value==='string'&&/^sha256:[0-9a-f]{64}$(?![\s\S])/.test(value),'input');
export function normalizeConsumerSlots(input,service){
 need(Array.isArray(input)&&input.length>=1&&input.length<=8,'capacity');const keys=new Set();
 const slots=structuredClone(input);
 for(const slot of slots){
  exact(slot,'publisher_service_id,consumer_service_id,consumer_database_instance_id,consumer_id,purpose,allowed_scope_ref,max_subscriptions,pairing_ref');
  for(const key of ['publisher_service_id','consumer_service_id','consumer_database_instance_id'])uuid(slot[key]);id(slot.consumer_id);
  need(slot.publisher_service_id===service.service_id&&slot.consumer_service_id!==service.service_id&&slot.max_subscriptions===1&&['status_projection','canonical_trigger'].includes(slot.purpose),'scope');
  const ref=slot.allowed_scope_ref;exact(ref,'authority_service_id,database_instance_id,entity_kind,entity_id,entity_epoch,revision,content_digest');
  need(ref.authority_service_id===service.service_id&&ref.database_instance_id===service.database_instance_id&&ref.entity_kind==='subscription_scope','scope');id(ref.entity_id);id(ref.entity_epoch);revision(ref.revision);
  need(typeof ref.content_digest==='string'&&/^[0-9a-f]{64}$(?![\s\S])/.test(ref.content_digest),'input');
  exact(slot.pairing_ref,'id,revision,digest');uuid(slot.pairing_ref.id);revision(slot.pairing_ref.revision);hash(slot.pairing_ref.digest);
  const key=[slot.consumer_service_id,slot.consumer_database_instance_id,slot.consumer_id].join('/');need(!keys.has(key),'duplicate');keys.add(key);
 }
 return slots.sort((a,b)=>{const left=JSON.stringify([a.consumer_service_id,a.consumer_database_instance_id,a.consumer_id]),right=JSON.stringify([b.consumer_service_id,b.consumer_database_instance_id,b.consumer_id]);return left<right?-1:left>right?1:0;});
}
export function checkConsumerPairing(slot,record,service){
 const peer=record.transcript.parties.find(p=>p.service_id===slot.consumer_service_id),local=record.transcript.parties.find(p=>p.service_id===service.service_id);
 need(record.state==='activated'&&record.binding_id===slot.pairing_ref.id&&record.revision===slot.pairing_ref.revision&&record.digest===slot.pairing_ref.digest&&
  record.peer_service_id===slot.consumer_service_id&&peer?.database_instance_id===slot.consumer_database_instance_id&&local?.database_instance_id===service.database_instance_id&&
  peer.permissions.includes('event.internal.subscribe')&&(slot.purpose!=='canonical_trigger'||peer.service_kind==='seamer'),'pairing');
 // 槽批准固定scope引用；这里不把配对的对象范围或未解析scope引用当作完整订阅资格。
 return peer;
}
export function consumerOwner(subject,slot){return {kind:'service',issuer_id:subject.issuer_id,issuer_epoch:subject.issuer_epoch,principal_id:subject.id,
 consumer_service_id:slot.consumer_service_id,consumer_database_instance_id:slot.consumer_database_instance_id,consumer_id:slot.consumer_id,pairing_id:slot.pairing_ref.id};}
export function sameConsumer(a,b){return a.consumer_service_id===b.consumer_service_id&&a.consumer_database_instance_id===b.consumer_database_instance_id&&a.consumer_id===b.consumer_id;}
