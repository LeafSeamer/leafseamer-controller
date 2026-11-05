import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {decodeLaunchAuthorization} from '../dist/sdk/worker-runtime.mjs';
import {migrateStorage} from '../dist/storage.mjs';
async function ready(t,options={}){
 const x=await setup(t,{revision:23,...options});
 if(options.inject){x.f.close();inspect(x.f.dir,db=>db.exec(options.inject));x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);}
 const a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 x.f.store.configureVirtualDevice({request_id:'resource',device_id:x.registered.device_id});
 const p=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,{profile_id:p.object_id,revision:p.revision});let lost=false;
 // 此单元夹具合成监督连接；业务数据库、人员鉴权与单调时钟均为实际实现。
 const source={scope:{service_id:x.f.store.identity.service_id,database_instance_id:x.f.store.identity.database_instance_id,supervisor_instance_id:core.descriptor.supervisor_instance_id,domain_ref:core.receipt.domain_ref},
  assertCurrent(){if(lost)throw new Error('source_lost');},current(){return {payload:{record:{admission_receipt:core.receipt}}};},lose(){lost=true;}};
 x.f.store.extensionInstallations.bindRuntimeSource(source);
 const kind=options.kind??'activate',plan=await a.sessions.planExtension(token,{request_id:'plan',slot_id:x.installed.slot.record.slot_id,expected_slot_revision:x.installed.slot.slot_ref.revision,
  selection:{kind,source_installation_ref:null,target_installation_ref:x.installed.installation_ref,reuse_content_ref:null,configuration_ref:x.config.configuration_ref}});
 const request={request_id:'activate',slot_id:plan.slot_ref.object_id,expected_slot_revision:plan.slot_ref.revision,target_installation_ref:x.installed.installation_ref,approval_ref:approved.approval_ref,dependency_plan_ref:plan.plan_ref};
 return {...x,a,token,approved,core,source,plan,request,accept:()=>kind==='activate'?a.sessions.activateExtension(token,request):a.sessions.enableExtension(token,request),
  intent:workerIntent(x.f.store,core,x.host.content,approved,[x.registered.device_id])};
}
function close(x){x.a.real.stop();x.f.close();}

async function authorized(t,options={}){
 const x=await ready(t,options);await x.accept();
 const prepared=await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(x.intent))),key={launch_id:x.intent.launch_id,launch_intent_digest:prepared.ref.digest};
 let record=null,onAck=()=>{},lost=()=>{},stopped=false;
 const snapshots=[],grants=[],source={...x.source,
  assertCurrent(){x.source.assertCurrent();if(stopped)throw new Error('source_closed');},
  subscribeLost(fn){lost=fn;return ()=>{};},close(){stopped=true;},
  async putFence(value){snapshots.push(structuredClone(value));await onAck(value);return {revision:value.revision,snapshot_digest:value.digest,journal_committed:true};},
  async queryLaunch(){return record;},
  async registerWorker(intent,grant){assert.deepEqual(intent,x.intent);grants.push(grant);record={state:'registered',creation_attempted:false,retirement_evidence:null};return record;},
  async createWorker(input){grants.push(input.authorization);record={state:'creating',creation_attempted:true,retirement_evidence:null};return record;}
 };
 x.f.store.workerLaunches.authorization.bindSource(source);
 return {...x,key,provider:x.f.store.workerLaunches.authorization,snapshots,grants,setAck(fn){onAck=fn;},setRecord(value){record=value;},lose(){x.source.lose();lost();},stopped:()=>stopped};
}
test('业务短授权绑定原件和完整fence，登记后续签，已尝试CREATE不能再签',{timeout:20000},async t=>{
 const x=await authorized(t),grant=await x.provider.authorize(x.key);
 assert.deepEqual(await decodeLaunchAuthorization(Buffer.from(JSON.stringify(grant))),grant);
 assert.equal(BigInt(grant.lifetime.deadline_tick)-BigInt(grant.lifetime.issued_tick),2000000000n);
 assert.deepEqual(grant.installation_ref,x.approved.record.installation_ref);assert.deepEqual(grant.approval_ref,x.approved.approval_ref);
 assert.deepEqual(grant.lifetime.clock,x.core.receipt.domain_ref);const {authorization_ref,...body}=grant;assert.equal(authorization_ref.digest,hash(body));
 assert.deepEqual(x.snapshots[0].items,[{...x.key,disposition:'allow'}]);
 assert.equal((await x.provider.register(x.key)).state,'registered');
 assert.equal((await x.provider.create(x.key,{load_id:'load',materialization_challenge_id:'challenge',materialization_evidence_id:'evidence'})).state,'creating');
 await assert.rejects(x.provider.authorize(x.key),/creation_attempted/);assert.equal(x.snapshots.length,1);
 close(x);inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get(),3);
  assert.equal(db.prepare('SELECT count(*) FROM worker_fence_snapshot').pluck().get(),1);assert.equal(db.prepare('SELECT count(*) FROM worker_fence_ack').pluck().get(),1);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
  assert.throws(()=>db.exec('DELETE FROM worker_launch_authorization'),/immutable_worker_authorization/);
 });
});
test('fence ACK等待中撤销审批，发送完整deny且不签授权，不释放资源',{timeout:20000},async t=>{
 const x=await authorized(t);x.setAck(()=>{x.setAck(()=>{});x.a.sessions.revokeExtensionApproval(x.token,{request_id:'deny',approval_ref:x.approved.approval_ref,reason:'撤销'});});
 await assert.rejects(x.provider.authorize(x.key),/denied|revoked/);assert.equal(x.snapshots.at(-1).items[0].disposition,'deny');
 await assert.rejects(x.provider.register(x.key),/denied/);close(x);inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM worker_launch_denial').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM extension_resource_owner_head').pluck().get(),1);
 });
});
test('显式撤销不可逆，监督来源失联后不能签发或重新绑定',{timeout:20000},async t=>{
 const x=await authorized(t);await x.provider.authorize(x.key);await x.provider.deny(x.key);await x.provider.synchronize();
 assert.equal(x.snapshots.length,2);assert.equal(x.snapshots[1].items[0].disposition,'deny');await assert.rejects(x.provider.authorize(x.key),/denied/);
 const y=await authorized(t);y.lose();assert.throws(()=>y.provider.authorize(y.key),/unavailable/);assert.throws(()=>y.provider.bindSource(y.source),/unavailable/);
});
test('快照、ACK及授权写入失败均失败关闭且不返回未落盘授权',{timeout:30000},async t=>{
 for(const table of ['worker_fence_snapshot','worker_fence_ack','worker_launch_authorization']){
  const x=await authorized(t,{inject:`CREATE TRIGGER fail_authorization BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_authorization_write'); END`});
  await assert.rejects(x.provider.authorize(x.key),/synthetic_authorization_write/);assert.equal(x.stopped(),true);
  assert.throws(()=>x.provider.authorize(x.key),/unavailable/);close(x);inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get(),0));
 }
});
test('ACK结果不确定关闭连接，不重发allow或签发授权',{timeout:20000},async t=>{
 const x=await authorized(t);x.setAck(()=>{throw new Error('unknown_ack');});await assert.rejects(x.provider.authorize(x.key),/unknown_ack/);
 assert.equal(x.stopped(),true);close(x);inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM worker_fence_snapshot').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM worker_fence_ack').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get(),0);
 });
});
test('静默跳过授权写入不能返回未持久化的grant',{timeout:20000},async t=>{
 const x=await authorized(t,{inject:"CREATE TRIGGER skip_grant BEFORE INSERT ON worker_launch_authorization BEGIN SELECT RAISE(IGNORE); END"});
 await assert.rejects(x.provider.authorize(x.key),/storage_failed/);assert.equal(x.stopped(),true);
 close(x);inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM worker_launch_authorization').pluck().get(),0));
});
test('监督器已经退役的实例进入永久deny，审批仍有效也不能重新allow',{timeout:20000},async t=>{
 const x=await authorized(t);await x.provider.register(x.key);x.setRecord({state:'retired',creation_attempted:true,retirement_evidence:{}});
 await x.provider.synchronize();assert.equal(x.snapshots.at(-1).items[0].disposition,'deny');
 x.setRecord(null);await assert.rejects(x.provider.authorize(x.key),/denied/);assert.equal(x.snapshots.length,2);
});
test('schema22备份升级23只保留受理准备历史，不补造授权或ACK',{timeout:20000},async t=>{
 const x=await ready(t,{revision:22});await x.accept();await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(x.intent)));close(x);
 assert.equal((await migrateStorage(x.f.dir,23)).schema_revision,'23');assert.ok(fs.readdirSync(x.f.dir).some(name=>name.startsWith('controller-before-v23-')));
 x.f.reopen();const key={launch_id:x.intent.launch_id,launch_intent_digest:hash(x.intent)};
 assert.throws(()=>x.f.store.workerLaunches.authorization.authorize(key),/preparation/);x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM extension_activation').pluck().get(),1);
  for(const table of ['worker_fence_snapshot','worker_fence_ack','worker_launch_authorization'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),0);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
 });
});
