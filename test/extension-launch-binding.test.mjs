import test from 'node:test';
import assert from 'node:assert/strict';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
const bytes=value=>Buffer.from(JSON.stringify(value));
const key=intent=>({launch_id:intent.launch_id,launch_intent_digest:hash(intent)});
async function ready(t,options={}){
 const x=await setup(t,options),a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 const receipt=x.host.content.receipt,core=bind(x.f.store,{profile_id:receipt.platform_profile_ref.object_id,revision:receipt.platform_profile_ref.revision});
 const intent=workerIntent(x.f.store,core,x.host.content,approved,[x.registered.device_id]);
 return {...x,a,token,approved,intent};
}
test('当前真实审批与角色绑定进入既有启动准备事务，重复只查原而不授予启动资格',{timeout:20000},async t=>{
 const x=await ready(t),api=x.f.store.workerLaunches,result=await api.prepare(bytes(x.intent));
 assert.deepEqual(result.intent.extension_binding.approval_ref,x.approved.approval_ref);assert.equal(result.current_boot,true);
 assert.deepEqual(await api.prepare(bytes(x.intent)),result);assert.deepEqual(api.query(key(x.intent)),result);
 x.a.sessions.revokeExtensionApproval(x.token,{request_id:'revoke',approval_ref:x.approved.approval_ref,reason:'准备后撤销'});
 assert.deepEqual(await api.prepare(bytes(x.intent)),result); // 原准备结果不是当前批准或LaunchAuthorization。
 await assert.rejects(api.prepare(bytes({...x.intent,launch_id:'another',member_id:'another.member',containment_ref:{...x.intent.containment_ref,group_id:'another.group'}})),/extension_launch_revoked/);
 x.a.real.stop();x.f.close();x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);
 assert.equal(x.f.store.workerLaunches.query(key(x.intent)).current_boot,false);
 await assert.rejects(x.f.store.workerLaunches.prepare(bytes(x.intent)),/worker_launch_stale_boot/);
});
test('错审批、配置、解析、原件、入口或不完整设备范围不能产生启动准备',{timeout:20000},async t=>{
 const x=await ready(t),other=x.f.store.registerDevice({request_id:'other',device_kind:'simulator',display_name:'另一个设备'});
 const mutations=[
  value=>{value.extension_binding.approval_ref={...value.extension_binding.approval_ref,object_id:'missing'};},
  ...['installation_ref','review_ref','role_resolution_ref','configuration_ref','intake_ref','platform_profile_ref'].map(field=>value=>{value.extension_binding[field]={...value.extension_binding[field],digest:hash('wrong')};}),
  ...['host_installation_id','host_trust_epoch','entry_id'].map(field=>value=>{value.extension_binding[field]=field==='host_trust_epoch'?'2':'wrong';}),
  ...['manifest_digest','artifact_set_digest','permissions_digest'].map(field=>value=>{value.extension_binding[field]=hash('wrong');}),
  value=>{value.object_scope.device_ids=[other.device_id];},
  value=>{value.object_scope.device_ids=[x.registered.device_id,other.device_id].sort();}
 ];
 for(const mutate of mutations){const intent=structuredClone(x.intent);mutate(intent);await assert.rejects(x.f.store.workerLaunches.prepare(bytes(intent)));}
 assert.deepEqual(x.f.store.workerLaunches.current(),[]);x.a.real.stop();x.f.close();
 inspect(x.f.dir,db=>{for(const table of ['worker_launch_preparation','worker_launch_device','worker_launch_preparation_commit'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),0);});
});
test('等待当前安装来源期间撤销审批或来源不可用，最终writer不得保存新准备',{timeout:20000},async t=>{
 let onCheck=()=>{};const x=await ready(t,{recheck:()=>onCheck()});
 onCheck=()=>{onCheck=()=>{};x.a.sessions.revokeExtensionApproval(x.token,{request_id:'race-revoke',approval_ref:x.approved.approval_ref,reason:'等待中撤销'});};
 await assert.rejects(x.f.store.workerLaunches.prepare(bytes(x.intent)),/extension_launch_revoked/);assert.deepEqual(x.f.store.workerLaunches.current(),[]);
 const y=await ready(t);y.host.revoked=true;
 await assert.rejects(y.f.store.workerLaunches.prepare(bytes(y.intent)),/extension_launch_source_unavailable/);assert.deepEqual(y.f.store.workerLaunches.current(),[]);
});
