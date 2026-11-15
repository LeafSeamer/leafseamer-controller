import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import Database from 'better-sqlite3';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url)),load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {serviceSubscriptionStore}=await load('service-subscription-store.mjs'),{IdentityError}=await load('identity-error.mjs');
const id=()=>crypto.randomUUID(),ref=()=>({id:id(),revision:'1',digest:'sha256:'+'a'.repeat(64)});
function fixture(t){
 const db=new Database(':memory:');t.after(()=>db.close());db.pragma('foreign_keys=ON');db.exec('CREATE TABLE device_event_source(registration_id TEXT PRIMARY KEY)');
 db.exec('CREATE TABLE service_event_subscription ('+fs.readFileSync(path.join(root,'dist/service-subscription.sql'),'utf8').split('CREATE TABLE service_event_subscription (')[1]);
 const registration=id();db.prepare('INSERT INTO device_event_source VALUES(?)').run(registration);
 const service={service_id:id(),database_instance_id:id(),schema_revision:'66'},bootId=id(),owner={kind:'service',issuer_id:id(),issuer_epoch:id(),principal_id:id(),consumer_service_id:id(),consumer_database_instance_id:id(),consumer_id:'events',pairing_id:id()};
 const proof={session:null,principal_kind:'service',owner,subject_ref:ref(),approval_ref:ref(),policy_ref:ref(),pairing_ref:ref(),scope_ref:ref(),service_boot_id:bootId,expires_ns:'1000',acquisition_ref:ref(),source_frontiers:[{source_key:{registration_id:registration},registration_sequence:'2'}]};
 const request={request_id:id(),consumer_id:'events',purpose:'canonical_trigger',scope:{scope_id:id()}},state={allowed:true,upper:1n};
 const current=()=>{if(!state.allowed)throw new IdentityError('service_identity_consumer_unavailable');return structuredClone(proof);};
 const args={db,service,bootId,writer:work=>db.transaction(work).immediate(),time:()=>({upper:state.upper}),authorize:current,currentAuthorization:current},store=serviceSubscriptionStore(args);
 return {db,store,proof,request,state,args,count:table=>db.prepare('SELECT count(*) FROM '+table).pluck().get()};
}
test('持久创建仅返回building，重投查原，关闭保留墓碑且释放同一消费者槽',t=>{
 const f=fixture(t),created=f.store.create('binding',null,f.request),key=created.view.binding.subscription_id;
 assert.equal(created.status,202);assert.equal(created.view.state,'building');assert.equal(created.view.snapshot_ref,null);assert.equal(created.view.binding.connection_generation,'0');
 assert.deepEqual(f.store.create('binding',null,f.request),{status:200,view:created.view});
 assert.throws(()=>f.store.create('binding',null,{...f.request,scope:{scope_id:id()}}),{code:'subscription_conflict'});
 assert.throws(()=>f.store.create('binding',null,{...f.request,request_id:id()}),{code:'subscription_slot_busy'});
 const closed=f.store.access('binding',null,key,{expected_revision:'1'});assert.equal(closed.view.state,'closed');assert.equal(closed.view.revision,'2');
 assert.deepEqual(f.store.access('binding',null,key,{expected_revision:'1'}),closed);assert.deepEqual(f.store.create('binding',null,f.request),closed);
 assert.notEqual(f.store.create('binding',null,{...f.request,request_id:id()}).view.binding.subscription_id,key);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});
test('撤权无需客户端DELETE就关闭释放资格，恢复授权或重启不能复活原订阅',t=>{
 const f=fixture(t),first=f.store.create('binding',null,f.request);f.state.allowed=false;f.store.sweep();
 assert.equal(f.db.prepare('SELECT state FROM service_event_subscription_revision WHERE revision=2').pluck().get(),'revoked');
 assert.throws(()=>f.store.access('binding',null,first.view.binding.subscription_id),{code:'service_identity_consumer_unavailable'});
 f.state.allowed=true;assert.equal(f.store.create('binding',null,f.request).view.state,'revoked');
 const next=f.store.create('binding',null,{...f.request,request_id:id()});const restarted=serviceSubscriptionStore({...f.args,bootId:id()});restarted.sweep();
 assert.equal(restarted.access('binding',null,next.view.binding.subscription_id).view.state,'resync_required');
});
test('订阅、初始修订、pin、head、审计和outbox任一缺写整笔回滚',t=>{
 for(const table of ['service_event_subscription','service_event_subscription_pin','service_event_subscription_revision','service_event_subscription_head','service_event_subscription_audit','service_event_subscription_outbox']){
  const f=fixture(t);f.db.exec('CREATE TRIGGER omit_subscription BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(()=>f.store.create('binding',null,f.request),{code:'subscription_storage'});
  for(const name of ['service_event_subscription','service_event_subscription_pin','service_event_subscription_revision','service_event_subscription_head','service_event_subscription_audit','service_event_subscription_outbox'])assert.equal(f.count(name),0);
  f.db.exec('DROP TRIGGER omit_subscription');assert.equal(f.store.create('binding',null,f.request).status,202);
 }
});
test('原到期界限先关闭为expired，时钟回退和来源恢复均不复活',t=>{
 const f=fixture(t),first=f.store.create('binding',null,f.request);f.state.upper=1000n;f.state.allowed=false;f.store.sweep();
 assert.equal(f.db.prepare('SELECT state FROM service_event_subscription_revision WHERE revision=2').pluck().get(),'expired');
 f.state.upper=1n;f.state.allowed=true;assert.equal(f.store.access('binding',null,first.view.binding.subscription_id).view.state,'expired');
 const next=f.store.create('binding',null,{...f.request,request_id:id()}),failed=serviceSubscriptionStore({...f.args,currentAuthorization(){throw new IdentityError('event_scope_inactive');}});failed.sweep();
 assert.equal(f.store.access('binding',null,next.view.binding.subscription_id).view.state,'resync_required');
});
test('提交末尾授权变化回滚，客户端自报owner和超出当前能力的用途拒绝',t=>{
 const f=fixture(t);let checks=0;const store=serviceSubscriptionStore({...f.args,authorize:()=>{if(++checks===2)throw new IdentityError('service_identity_consumer_changed');return f.proof;}});
 assert.throws(()=>store.create('binding',null,f.request),{code:'service_identity_consumer_changed'});assert.equal(f.count('service_event_subscription'),0);
 assert.throws(()=>f.store.create('binding',null,{...f.request,owner:f.proof.owner}),{code:'subscription_input'});
 assert.throws(()=>f.store.create('binding',null,{...f.request,purpose:'status_projection'}),{code:'subscription_purpose'});
});
