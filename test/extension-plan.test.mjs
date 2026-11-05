import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
async function ready(t,options={}){
 const x=await setup(t,{revision:21,...options});
 if(options.inject){x.f.close();inspect(x.f.dir,db=>db.exec(options.inject));x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);}
 const a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 x.f.store.configureVirtualDevice({request_id:'resource',device_id:x.registered.device_id});
 const p=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,options.coreProfile??{profile_id:p.object_id,revision:p.revision});let lost=false;
 // 单元用例合成监督连接；业务数据库、人员鉴权、能力模板及本机单调tick均为实际实现。
 const source={scope:{service_id:x.f.store.identity.service_id,database_instance_id:x.f.store.identity.database_instance_id,supervisor_instance_id:core.descriptor.supervisor_instance_id,domain_ref:core.receipt.domain_ref},
  assertCurrent(){if(lost)throw new Error('source_lost');},current(){return {payload:{record:{admission_receipt:core.receipt}}};},lose(){lost=true;}};
 if(options.bind!==false)x.f.store.extensionInstallations.bindRuntimeSource(source);
 const input={request_id:'plan',slot_id:x.installed.slot.record.slot_id,expected_slot_revision:x.installed.slot.slot_ref.revision,
  selection:{kind:'activate',source_installation_ref:null,target_installation_ref:x.installed.installation_ref,reuse_content_ref:null,configuration_ref:x.config.configuration_ref}};
 return {...x,a,token,approved,core,source,input,plan:()=>a.sessions.planExtension(token,input)};
}
function close(x){x.a.real.stop();x.f.close();}

test('当前人员计划固定完整影响、摘要与监督域，查原不改变运行或创建新实例',{timeout:20000},async t=>{
 const x=await ready(t),plan=await x.plan(),{plan_ref,content_digest,...content}=plan;
 assert.equal(plan_ref.kind,'dependency_plan');assert.equal(plan_ref.digest,hash(content));assert.equal(content_digest,hash(content));
 assert.deepEqual(plan.lifetime.clock,x.core.receipt.domain_ref);assert.equal(BigInt(plan.lifetime.deadline_tick)-BigInt(plan.lifetime.issued_tick),30000000000n);
 assert.equal(plan.impacts.length,2);assert.deepEqual(plan.impacts.map(value=>value.object_ref.kind).sort(),['device','resource']);
 assert.equal(plan.configuration_digest,x.config.configuration_ref.digest);assert.deepEqual(await x.plan(),plan);
 assert.deepEqual(x.a.sessions.lookupExtensionPlan(x.token,'plan'),plan);assert.deepEqual(await x.a.sessions.getCurrentExtensionPlan(x.token,plan_ref),plan);
 assert.deepEqual(x.f.store.workerLaunches.current(),[]);close(x);
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_candidate').pluck().get(),1);assert.equal(db.prepare('SELECT count(*) FROM extension_dependency_plan').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM extension_plan_operation').pluck().get(),1);assert.throws(()=>db.exec('DELETE FROM extension_dependency_plan'),/immutable_dependency_plan/);});
});

test('无监督来源、错槽位或选择、伪造计划引用与同键冲突均拒绝',{timeout:20000},async t=>{
 const x=await ready(t,{bind:false});await assert.rejects(x.plan(),/source_required/);x.f.store.extensionInstallations.bindRuntimeSource(x.source);
 for(const mutation of [value=>{value.expected_slot_revision='1';},value=>{value.selection.configuration_ref.digest=hash('wrong');},value=>{value.selection.kind='upgrade';},value=>{value.selection.reuse_content_ref=value.selection.target_installation_ref;}]){
  const request=structuredClone(x.input);mutation(request);await assert.rejects(x.a.sessions.planExtension(x.token,request));
 }
 const plan=await x.plan();await assert.rejects(x.a.sessions.planExtension(x.token,{...x.input,selection:{...x.input.selection,kind:'enable'}}),/conflict/);
 await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,{...plan.plan_ref,digest:hash('forged')}),/reference/);
 x.host.revoked=true;await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,plan.plan_ref),/source_unavailable/);x.host.revoked=false;
 x.source.lose();await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,plan.plan_ref),/source_lost/);
 assert.deepEqual(await x.plan(),plan); // 历史查询不声称当前有效。
});

test('等待真实安装来源时撤销审批或改变槽位不能提交旧计划',{timeout:20000},async t=>{
 let hook=()=>{};const x=await ready(t,{recheck:()=>hook()});
 hook=()=>{hook=()=>{};x.a.sessions.revokeExtensionApproval(x.token,{request_id:'deny',approval_ref:x.approved.approval_ref,reason:'等待中撤回'});};
 await assert.rejects(x.plan(),/extension_launch_revoked/);assert.equal(x.a.sessions.lookupExtensionPlan(x.token,'plan'),null);
 const y=await ready(t),plan=await y.plan();
 y.f.store.configureVirtualDevice({request_id:'other.resource',device_id:y.f.store.registerDevice({request_id:'other',device_kind:'simulator',display_name:'其他设备'}).device_id});
 await assert.rejects(y.a.sessions.getCurrentExtensionPlan(y.token,plan.plan_ref),/extension_plan_stale/);
 assert.deepEqual(await y.plan(),plan);
});

test('计划审计故障全回滚；现有启动无法由空影响数组绕过',{timeout:20000},async t=>{
 const x=await ready(t,{inject:"CREATE TRIGGER fail_plan BEFORE INSERT ON extension_plan_operation BEGIN SELECT RAISE(ABORT,'synthetic_plan_commit'); END"});
 await assert.rejects(x.plan(),/synthetic_plan_commit/);close(x);inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_dependency_plan').pluck().get(),0);assert.equal(db.prepare('SELECT count(*) FROM extension_plan_operation').pluck().get(),0);});
 const y=await ready(t),intent=workerIntent(y.f.store,y.core,y.host.content,y.approved,[y.registered.device_id]);
 await y.f.store.workerLaunches.prepare(Buffer.from(JSON.stringify(intent)));await assert.rejects(y.plan(),/runtime_provider_required/);
});

test('计划使用真实人员权限，撤销管理权后不能创建新计划或用旧令牌查原',{timeout:20000},async t=>{
 const x=await ready(t),plan=await x.plan(),permissions=x.a.sessions.localPermissions(x.a.auth);
 x.a.sessions.replaceLocalPermissions(x.a.auth,{request_id:crypto.randomUUID(),principal_id:x.a.logged.session.principal_id,expected_revision:permissions.revision,
  permissions:permissions.permissions.filter(value=>!value.startsWith('extension.'))});
 await assert.rejects(x.a.sessions.planExtension(x.token,{...x.input,request_id:'next'}));
 assert.throws(()=>x.a.sessions.lookupExtensionPlan(x.token,'plan'));await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,plan.plan_ref));
});

test('schema20显式备份升级21，不补造旧计划；重启后历史计划不可消费',{timeout:20000},async t=>{
 const legacy=await setup(t,{revision:20}),identity=legacy.f.store.identity;assert.equal(legacy.f.store.extensionInstallations.bindRuntimeSource,undefined);legacy.f.close();
 assert.equal((await migrateStorage(legacy.f.dir,21)).schema_revision,'21');assert.ok(fs.readdirSync(legacy.f.dir).some(name=>name.startsWith('controller-before-v21-')));
 legacy.f.reopen();assert.equal(legacy.f.store.identity.service_id,identity.service_id);legacy.f.close();inspect(legacy.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM extension_dependency_plan').pluck().get(),0));
 const x=await ready(t),plan=await x.plan();close(x);x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);
 const a=await authenticated(t,x.f);await assert.rejects(a.sessions.getCurrentExtensionPlan(a.token(),plan.plan_ref),/stale_boot/);
});

test('计划真实单调截止到期后拒绝当前使用，历史保持原截止且重投不续期',{timeout:45000},async t=>{
 const x=await ready(t),plan=await x.plan();await delay(30050);
 await assert.rejects(x.a.sessions.getCurrentExtensionPlan(x.token,plan.plan_ref),/extension_plan_expired/);
 assert.deepEqual(await x.plan(),plan);
});

test('批准安装的平台必须匹配实际核心监督域，不能等到创建时才拒绝',{timeout:20000},async t=>{
 const x=await ready(t,{coreProfile:{profile_id:'other.platform',revision:'1'}});
 await assert.rejects(x.plan(),/extension_plan_platform_binding/);assert.equal(x.a.sessions.lookupExtensionPlan(x.token,'plan'),null);
});
