import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {setup} from './fixtures/extension-capabilities.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {bind,workerIntent} from './fixtures/core-binding.mjs';
import {hash,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const bytes=value=>Buffer.from(JSON.stringify(value));
const key=intent=>({launch_id:intent.launch_id,launch_intent_digest:hash(intent)});
async function ready(t,options={}){
 const x=await setup(t,{revision:20,...options});
 if(options.inject){x.f.close();inspect(x.f.dir,db=>db.exec(options.inject));x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);}
 const a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 const profile=x.host.content.receipt.platform_profile_ref,core=bind(x.f.store,{profile_id:profile.object_id,revision:profile.revision});
 // 意图只引用实际角色解析中的完整设备集合。
 const intent=workerIntent(x.f.store,core,x.host.content,approved,x.requestedDevices??[x.registered.device_id]);
 return {...x,a,token,approved,intent,key:key(intent),api:x.f.store.workerLaunches};
}
function configure(x,device=x.registered.device_id){return x.f.store.configureVirtualDevice({request_id:'resource.'+device,device_id:device});}
function close(x){x.a.real.stop();x.f.close();}
function emptyPreparation(x){inspect(x.f.dir,db=>{for(const table of ['worker_launch_preparation','worker_launch_device','worker_launch_preparation_commit','worker_launch_dependencies'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),0);});}

test('缺少实际资源绑定拒绝准备；登记后封存全部动作并同事务保存完整依赖',{timeout:20000},async t=>{
 const x=await ready(t);await assert.rejects(x.api.prepare(bytes(x.intent)),/worker_dependency_resource_provider_unavailable/);
 assert.deepEqual(x.api.current(),[]);const resource=configure(x);assert.deepEqual(configure(x),resource);
 const prepared=await x.api.prepare(bytes(x.intent)),dependencies=x.api.dependencies(x.key);
 assert.deepEqual(dependencies.devices.map(value=>value.object_id),[x.registered.device_id]);assert.deepEqual(dependencies.resources,[resource.resource_ref]);
 assert.deepEqual(dependencies.links[0].action_ids,['get','set']);assert.deepEqual(x.proposed[0].scope.action_ids,['get']);
 assert.equal(dependencies.launch_intent_digest,hash(x.intent));assert.ok(Object.isFrozen(dependencies.links[0]));
 assert.deepEqual(await x.api.prepare(bytes(x.intent)),prepared);
 x.a.sessions.revokeExtensionApproval(x.token,{request_id:'revoke.dependencies',approval_ref:x.approved.approval_ref,reason:'撤回依赖资格'});
 assert.throws(()=>x.api.dependencies(x.key),/extension_launch_revoked/);assert.deepEqual(x.api.query(x.key),prepared);
 close(x);inspect(x.f.dir,db=>{
  for(const table of ['virtual_device_resource','virtual_device_resource_commit','worker_launch_dependencies','worker_launch_preparation_commit'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),1);
  const row=db.prepare('SELECT body_jcs,body_digest FROM worker_launch_dependencies').raw().get();assert.deepEqual(JSON.parse(row[0]),dependencies);assert.equal(row[1],hash(dependencies));
  assert.throws(()=>db.exec('DELETE FROM worker_launch_dependencies'),/immutable_dependency/);
  assert.throws(()=>db.exec('UPDATE virtual_device_resource SET resource_id=resource_id'),/immutable_dependency/);
 });
});

test('未批准动作中的未知资源别名或依赖仍阻止启动准备',{timeout:20000},async t=>{
 for(const [mutate,pattern] of [
  [template=>{template.actions[1].resources=['other'];},/worker_dependency_resource_alias_unavailable/],
  [template=>{template.actions[1].read_set=['other'];},/worker_dependency_resource_alias_unavailable/],
  [template=>{template.actions[1].dependencies=['other'];},/worker_dependency_dependency_provider_unavailable/]
 ]){
  const x=await ready(t,{mutate});configure(x);await assert.rejects(x.api.prepare(bytes(x.intent)),pattern);close(x);emptyPreparation(x);
 }
});

test('多设备角色必须绑定全部资源，缺少任一提供者不得缩小设备集合',{timeout:20000},async t=>{
 const x=await ready(t,{
  prepareHost(host){host.content.manifest.roles[0].maximum=2;},
  prepareBindings(f){const other=f.f.store.registerDevice({request_id:'other',device_kind:'simulator',display_name:'第二设备'});
   f.request.bindings[0].values.push(f.api.roles.deviceReference(other.device_id));
   f.request.bindings[0].values.sort((a,b)=>Buffer.compare(Buffer.from(canonicalize(a)),Buffer.from(canonicalize(b))));
   f.requestedDevices=f.request.bindings[0].values.map(value=>value.object_id).sort();
  }
 });
 configure(x,x.requestedDevices[0]);await assert.rejects(x.api.prepare(bytes(x.intent)),/resource_provider_unavailable/);
 configure(x,x.requestedDevices[1]);await x.api.prepare(bytes(x.intent));
 const dependencies=x.api.dependencies(x.key);assert.deepEqual(dependencies.devices.map(value=>value.object_id),x.requestedDevices);
 assert.equal(new Set(dependencies.resources.map(value=>value.object_id)).size,2);assert.equal(dependencies.links.length,2);
});

test('资源配置和准备依赖的写入故障原子回滚，不遗留可采用记录',{timeout:20000},async t=>{
 for(const table of ['virtual_device_resource_commit','worker_launch_dependencies','worker_launch_preparation_commit']){
  const x=await ready(t,{inject:`CREATE TRIGGER fail_dependency BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_dependency_write'); END`});
  if(table==='virtual_device_resource_commit')assert.throws(()=>configure(x),/synthetic_dependency_write/);
  else {configure(x);await assert.rejects(x.api.prepare(bytes(x.intent)),/synthetic_dependency_write/);}
  close(x);emptyPreparation(x);
  if(table==='virtual_device_resource_commit')inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM virtual_device_resource').pluck().get(),0));
 }
});

test('显式19到20备份迁移保留历史且不补造资源或依赖，旧设备不能事后补齐',{timeout:20000},async t=>{
 const x=await ready(t,{revision:19});assert.throws(()=>configure(x),/migration_required/);
 const original=await x.api.prepare(bytes(x.intent));close(x);
 const result=await migrateStorage(x.f.dir,20);assert.equal(result.steps.length,1);assert.equal(result.schema_revision,'20');
 assert.ok(fs.readdirSync(x.f.dir).some(name=>name.startsWith('controller-before-v20-')));
 x.f.reopen();assert.deepEqual(x.f.store.workerLaunches.query(x.key).intent,original.intent);
 assert.throws(()=>configure(x),/already_prepared/);
 assert.throws(()=>x.f.store.workerLaunches.dependencies(x.key),/worker_launch_stale_boot/);
 x.f.close();inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM worker_launch_dependencies').pluck().get(),0);assert.equal(db.prepare('SELECT dependency_launch_id FROM worker_launch_preparation').pluck().get(),null);});
});

test('物理设备、未知设备及调用方伪造资源字段不能进入固定虚拟后端',{timeout:20000},async t=>{
 const x=await ready(t),physical=x.f.store.registerDevice({request_id:'physical',device_kind:'physical',display_name:'外部设备'});
 assert.throws(()=>configure(x,physical.device_id),/physical_provider_required/);assert.throws(()=>configure(x,'missing'),/device_missing/);
 assert.throws(()=>x.f.store.configureVirtualDevice({request_id:'forged',device_id:x.registered.device_id,resource_id:'forged'}),/worker_dependency_input/);
 configure(x);assert.throws(()=>x.f.store.configureVirtualDevice({request_id:'another',device_id:x.registered.device_id}),/worker_dependency_frozen/);
 assert.throws(()=>x.f.store.configureVirtualDevice({request_id:'resource.'+x.registered.device_id,device_id:physical.device_id}),/worker_dependency_conflict/);
});
