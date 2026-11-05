import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
async function ready(t,options={}){
 const x=await setup(t,{revision:22,...options});
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

test('人员受理同事务占用全部资源与推进原槽位，重投只查原且只能绑定一个launch',{timeout:20000},async t=>{
 const x=await ready(t);await assert.rejects(x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(x.intent))),/extension_activation_required/);
 const value=await x.accept();assert.equal(value.record.phase,'accepted');assert.equal(value.record.result,null);assert.equal(value.slot.slot_ref.revision,'3');
 assert.equal(value.slot.record.desired_state,'enabled');assert.equal(value.slot.record.active_installation_id,null);assert.deepEqual(value.slot.record.pending_operation_ref,value.operation_ref);
 assert.equal(value.owners.length,1);assert.equal(value.owners[0].device_ref.object_id,x.registered.device_id);
 assert.deepEqual(await x.accept(),value);assert.deepEqual(x.a.sessions.lookupExtensionActivation(x.token,'activate'),value);
 await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,x.plan.plan_ref),/slot_stale/);
 const prepared=await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(x.intent)));assert.deepEqual(await x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(x.intent))),prepared);
 const second={...x.intent,launch_id:'second',member_id:'second.member',containment_ref:{...x.intent.containment_ref,group_id:'second.group'}};
 await assert.rejects(x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(second))),/launch_used/);
 close(x);inspect(x.f.dir,db=>{
  for(const table of ['extension_activation','extension_resource_owner','extension_resource_owner_head'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),1);
  assert.equal(db.prepare('SELECT activation_operation_id FROM worker_launch_preparation').pluck().get(),value.operation_ref.object_id);
  assert.throws(()=>db.exec('DELETE FROM extension_resource_owner_head'),/owner_release_required/);assert.throws(()=>db.exec('DELETE FROM extension_activation'),/immutable_activation/);
 });
});

test('enable只消费enable计划，跨用途或错审批、目标、槽位与同键冲突拒绝',{timeout:20000},async t=>{
 const x=await ready(t,{kind:'enable'});await assert.rejects(x.a.sessions.activateExtension(x.token,x.request),/plan_binding/);
 for(const mutate of [value=>{value.expected_slot_revision='1';},value=>{value.approval_ref.digest=hash('wrong');},value=>{value.target_installation_ref.digest=hash('wrong');},value=>{value.dependency_plan_ref.digest=hash('wrong');}]){
  const request=structuredClone(x.request);mutate(request);await assert.rejects(x.a.sessions.enableExtension(x.token,request));
 }
 const original=await x.accept();assert.equal(original.record.kind,'enable');await assert.rejects(x.a.sessions.activateExtension(x.token,x.request),/conflict/);
 await assert.rejects(x.f.store.extensionInstallations.stage({request_id:'late.stage',slot_id:x.request.slot_id,expected_slot_revision:'3',intake_ref:x.host.content.intake_ref}),/slot_busy/);
});

test('受理的每个写点失败均回滚，原计划仍可当前查询且不遗留占用',{timeout:30000},async t=>{
 for(const table of ['extension_slot_revision','extension_activation','extension_resource_owner','extension_resource_owner_head','extension_operation']){
  const predicate=table==='extension_slot_revision'?" WHEN NEW.revision=3":table==='extension_operation'?" WHEN NEW.kind IN ('activate','enable')":'';
  const x=await ready(t,{inject:`CREATE TRIGGER fail_activation BEFORE INSERT ON ${table}${predicate} BEGIN SELECT RAISE(ABORT,'synthetic_activation_write'); END`});
  await assert.rejects(x.accept(),/synthetic_activation_write/);assert.equal(x.a.sessions.lookupExtensionActivation(x.token,'activate'),null);
  assert.deepEqual(await x.a.sessions.getCurrentExtensionPlan(x.token,x.plan.plan_ref),x.plan);close(x);
  inspect(x.f.dir,db=>{for(const table of ['extension_activation','extension_resource_owner','extension_resource_owner_head'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),0);
   assert.equal(db.prepare('SELECT revision FROM extension_slot_head').pluck().get(),2);});
 }
});

test('安装来源等待中撤销审批，不能受理；受理后撤销不释放占用或允许准备',{timeout:20000},async t=>{
 let hook=()=>{};const x=await ready(t,{recheck:()=>hook()});
 hook=()=>{hook=()=>{};x.a.sessions.revokeExtensionApproval(x.token,{request_id:'race.deny',approval_ref:x.approved.approval_ref,reason:'受理等待中撤销'});};
 await assert.rejects(x.accept(),/extension_launch_revoked/);assert.equal(x.a.sessions.lookupExtensionActivation(x.token,'activate'),null);
 const y=await ready(t),value=await y.accept();y.a.sessions.revokeExtensionApproval(y.token,{request_id:'deny',approval_ref:y.approved.approval_ref,reason:'受理后撤销'});
 assert.deepEqual(await y.accept(),value);await assert.rejects(y.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(y.intent))),/extension_launch_revoked/);
 close(y);inspect(y.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM extension_resource_owner_head').pluck().get(),1));
});

test('同计划并发重投返回同一受理，来源失联不能新受理，重启不恢复旧启动资格',{timeout:20000},async t=>{
 const x=await ready(t),[a,b]=await Promise.all([x.accept(),x.accept()]);assert.deepEqual(a,b);
 close(x);x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);
 const p=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,{profile_id:p.object_id,revision:p.revision});
 const intent=workerIntent(x.f.store,core,x.host.content,x.approved,[x.registered.device_id]);
 await assert.rejects(x.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent))),/extension_activation_required/);
 const y=await ready(t);y.source.lose();await assert.rejects(y.accept(),/source_lost/);assert.equal(y.a.sessions.lookupExtensionActivation(y.token,'activate'),null);
});

test('schema21显式备份升级22保留候选/计划/槽位历史，不补造受理或资源owner',{timeout:20000},async t=>{
 const x=await ready(t,{revision:21}),identity=x.f.store.identity;assert.throws(()=>x.a.sessions.activateExtension(x.token,x.request),/extension_activation_unavailable/);close(x);
 assert.equal((await migrateStorage(x.f.dir,22)).schema_revision,'22');assert.ok(fs.readdirSync(x.f.dir).some(name=>name.startsWith('controller-before-v22-')));
 x.f.reopen();assert.equal(x.f.store.identity.service_id,identity.service_id);x.f.close();inspect(x.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM extension_activation').pluck().get(),0);assert.equal(db.prepare('SELECT count(*) FROM extension_resource_owner').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM extension_dependency_plan').pluck().get(),1);assert.equal(db.prepare('SELECT count(*) FROM extension_operation').pluck().get(),2);
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').raw().all(),[]);
 });
});

test('两个已批准槽位竞争同一实际资源，只能有一个受理占用',{timeout:20000},async t=>{
 const x=await ready(t),api=x.f.store.extensionInstallations;
 const slot=api.createSlot({request_id:'other.slot',extension_id:x.host.content.manifest.extension_id});
 const installed=await api.stage({request_id:'other.stage',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:x.host.content.intake_ref});
 const configuration=await api.configurations.configure({request_id:'other.config',installation_ref:installed.installation_ref,expected_revision:'0',bytes:Buffer.from('{}')});
 const resolved=await api.roles.resolve({request_id:'other.roles',installation_ref:installed.installation_ref,configuration_ref:configuration.configuration_ref,expected_revision:'0',
  bindings:[{role_id:'device',kind:'device',values:[api.roles.deviceReference(x.registered.device_id)],configuration_ref:configuration.configuration_ref}]});
 const reviewed=await api.reviews.review({request_id:'other.review',installation_ref:installed.installation_ref,configuration_ref:configuration.configuration_ref,role_resolution_ref:resolved.resolution_ref,
  expected_revision:'0',proposed_permissions:resolved.record.permissions});
 const approved=await x.a.sessions.approveExtension(x.token,{request_id:'other.approve',installation_ref:installed.installation_ref,permission_review_ref:reviewed.review_ref,
  configuration_ref:configuration.configuration_ref,approved_permission_ids:['device.request']});
 const makePlan=(request_id,target,config)=>x.a.sessions.planExtension(x.token,{request_id,slot_id:target.slot.record.slot_id,expected_slot_revision:'2',
  selection:{kind:'activate',source_installation_ref:null,target_installation_ref:target.installation_ref,reuse_content_ref:null,configuration_ref:config.configuration_ref}});
 const first=await makePlan('fresh.first',x.installed,x.config),second=await makePlan('fresh.second',installed,configuration);
 x.request.dependency_plan_ref=first.plan_ref;
 const outcomes=await Promise.allSettled([x.accept(),x.a.sessions.activateExtension(x.token,{request_id:'other.activate',slot_id:slot.record.slot_id,expected_slot_revision:'2',
  target_installation_ref:installed.installation_ref,approval_ref:approved.approval_ref,dependency_plan_ref:second.plan_ref})]);
 assert.equal(outcomes.filter(value=>value.status==='fulfilled').length,1);assert.match(outcomes.find(value=>value.status==='rejected').reason.message,/resource_busy/);
 close(x);inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_activation').pluck().get(),1);assert.equal(db.prepare('SELECT count(*) FROM extension_resource_owner_head').pluck().get(),1);});
});

test('数据库完整性约束阻止漏掉资源占用后提交受理',{timeout:20000},async t=>{
 const x=await ready(t,{inject:'CREATE TRIGGER omit_owner BEFORE INSERT ON extension_resource_owner_head BEGIN SELECT RAISE(IGNORE); END'});
 await assert.rejects(x.accept(),/extension_activation_incomplete/);close(x);
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_activation').pluck().get(),0);assert.equal(db.prepare('SELECT revision FROM extension_slot_head').pluck().get(),2);});
});
