import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST;
const {normalizeConsumerSlots,checkConsumerPairing,consumerOwner}=await import(root?pathToFileURL(path.join(root,'dist/service-consumer-scope.mjs')):new URL('../dist/service-consumer-scope.mjs',import.meta.url));
const id=()=>crypto.randomUUID();
function fixture(){
 const service={service_id:id(),database_instance_id:id()},slot={publisher_service_id:service.service_id,consumer_service_id:id(),consumer_database_instance_id:id(),
  consumer_id:'worker.member:events',purpose:'canonical_trigger',max_subscriptions:1,pairing_ref:{id:id(),revision:'4',digest:'sha256:'+'a'.repeat(64)},
  allowed_scope_ref:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id,entity_kind:'subscription_scope',entity_id:'events',entity_epoch:id(),revision:'1',content_digest:'b'.repeat(64)}};
 const record={state:'activated',binding_id:slot.pairing_ref.id,revision:'4',digest:slot.pairing_ref.digest,peer_service_id:slot.consumer_service_id,
  transcript:{parties:[service,{service_id:slot.consumer_service_id,database_instance_id:slot.consumer_database_instance_id,service_kind:'seamer',permissions:['event.internal.subscribe']}]}};
 return {service,slot,record};
}
test('消费者槽固定完整服务和库身份、用途、配对修订及范围原件',()=>{
 const {service,slot,record}=fixture(),copy=normalizeConsumerSlots([slot],service);assert.deepEqual(copy,[slot]);assert.notEqual(copy[0],slot);
 assert.equal(checkConsumerPairing(slot,record,service).service_id,slot.consumer_service_id);
 const subject={id:id(),issuer_id:id(),issuer_epoch:id()};assert.deepEqual(consumerOwner(subject,slot),{kind:'service',issuer_id:subject.issuer_id,issuer_epoch:subject.issuer_epoch,
  principal_id:subject.id,consumer_service_id:slot.consumer_service_id,consumer_database_instance_id:slot.consumer_database_instance_id,consumer_id:slot.consumer_id,pairing_id:slot.pairing_ref.id});
});
test('槽数量和唯一性不能通过改用途或附加字段绕过，scope必须属于当前发布库',()=>{
 const {service,slot}=fixture();
 for(const input of [[],Array(9).fill(slot),[slot,{...slot,purpose:'status_projection'}],[{...slot,max_subscriptions:2}],[{...slot,extra:true}],
  [{...slot,consumer_id:'x\n'}],[{...slot,allowed_scope_ref:{...slot.allowed_scope_ref,database_instance_id:id()}}],
  [{...slot,allowed_scope_ref:{...slot.allowed_scope_ref,content_digest:'sha256:'+'b'.repeat(64)}}]])
  assert.throws(()=>normalizeConsumerSlots(input,service),e=>e.code.startsWith('service_consumer_'));
});
test('配对必须当前且实际批准订阅用途，canonical仅允许Seamer',()=>{
 const {service,slot,record}=fixture();
 for(const change of [r=>r.state='revoked',r=>r.revision='5',r=>r.peer_service_id=id(),r=>r.transcript.parties[1].database_instance_id=id(),
  r=>r.transcript.parties[1].permissions=['events.internal.read'],r=>r.transcript.parties[1].service_kind='controller']){
  const changed=structuredClone(record);change(changed);assert.throws(()=>checkConsumerPairing(slot,changed,service),e=>e.code==='service_consumer_pairing');
 }
});
