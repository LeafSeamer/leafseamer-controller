import test from 'node:test';
import assert from 'node:assert/strict';
import {migrateStorage} from '../dist/storage.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {inspect,hash} from './fixtures/extension-installation.mjs';
import {setup} from './fixtures/extension-capabilities.mjs';
test('静态模板允许人员批准非空权限；只保留审阅子集且重开核原件，不赋予运行目录资格',{timeout:20000},async t=>{
 const x=await setup(t),a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.request);
 assert.deepEqual(approved.permissions,x.proposed);assert.deepEqual(approved.permissions[0].scope.action_ids,['get']);
 assert.equal(approved.record.permissions_digest,hash(x.proposed));assert.equal(a.sessions.getExtensionApproval(token,approved.approval_ref).status,'approved');
 assert.deepEqual(await a.sessions.approveExtension(token,x.request),approved);a.real.stop();x.f.close();
 inspect(x.f.dir,db=>{const evidence=JSON.parse(db.prepare('SELECT body_jcs FROM extension_approval_capabilities').pluck().get());
  assert.equal(evidence.documents[0].file.digest,x.host.content.inventory.files.find(file=>file.file_id==='capability').digest);
  assert.equal(evidence.documents[0].template.actions[0].footprint,undefined);assert.deepEqual(evidence.intake_ref,x.host.content.intake_ref);
  assert.throws(()=>db.exec("DELETE FROM extension_approval_capabilities"),/extension_approval_history/);
 });
 x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const b=await authenticated(t,x.f);
 assert.equal(b.sessions.getExtensionApproval(b.token(),approved.approval_ref).status,'approved');
});
test('模板原bytes、完整引用、设备类型、角色、动作与平台不匹配拒绝且不落审批记录',{timeout:40000},async t=>{
 for(const options of [
  {response:value=>{value.content.files[0].bytes=Buffer.from('{}');return value;}},
  {response:value=>{value.content.intake_ref={...value.content.intake_ref,revision:'2'};return value;}},
  {mutate:value=>{value.device_kind='different';}},
  {mutate:value=>{value.device_role='other';}},
  {mutate:value=>{value.actions=value.actions.filter(action=>action.action_id!=='get');}},
  {mutate:value=>{for(const action of value.actions)for(const platform of action.platforms)platform.status='unsupported';}},
 ]){
  const x=await setup(t,options),a=await authenticated(t,x.f);
  await assert.rejects(a.sessions.approveExtension(a.token(),x.request),/extension_capability_/);a.real.stop();x.f.close();
  inspect(x.f.dir,db=>{for(const table of ['extension_approval','extension_approval_operation','extension_approval_capabilities'])assert.equal(db.prepare(`SELECT count(*) FROM ${table}`).pluck().get(),0);});
 }
});
test('Schema摘要、外部引用和未知关键字失败时不能以模板声明代替已编译定义',{timeout:30000},async t=>{
 for(const mode of ['digest','external','keyword']){
  const x=await setup(t,{mutate:value=>{const schema=value.state_schema;if(mode==='digest')schema.digest='sha256:'+'a'.repeat(64);
   else{schema.schema_id='bad.schema';schema.document=mode==='external'?{$ref:'https://invalid.example/schema'}:{type:'object',unknownKeyword:true};schema.digest=hash(schema.document);}
  }}),a=await authenticated(t,x.f);
  await assert.rejects(a.sessions.approveExtension(a.token(),x.request),/extension_capability_schema_digest|extension_configuration_external_reference|extension_configuration_schema_compile/);
  assert.equal(a.sessions.lookupExtensionApproval(a.token(),'approve'),null);
 }
});
test('批准、模板证据、操作与审计逐写失败回滚，不留下冻结状态',{timeout:30000},async t=>{
 for(const table of ['extension_approval','extension_approval_capabilities','extension_approval_operation']){
  const x=await setup(t);x.f.close();inspect(x.f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
  x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const a=await authenticated(t,x.f);
  await assert.rejects(a.sessions.approveExtension(a.token(),x.request),/synthetic_failure/);a.real.stop();x.f.close();
  inspect(x.f.dir,db=>{for(const target of ['extension_approval','extension_approval_capabilities','extension_approval_operation'])assert.equal(db.prepare(`SELECT count(*) FROM ${target}`).pluck().get(),0);});
 }
});
test('schema17显式迁移到18保留历史批准，不伪造静态证据',{timeout:20000},async t=>{
 const x=await setup(t,{revision:17}),a=await authenticated(t,x.f),approved=await a.sessions.approveExtension(a.token(),{...x.request,approved_permission_ids:[]});
 a.real.stop();x.f.close();const migrated=await migrateStorage(x.f.dir,18);assert.equal(migrated.schema_revision,'18');assert.equal(migrated.steps.length,1);
 inspect(x.f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_approval_capabilities').pluck().get(),0);
  assert.deepEqual(JSON.parse(db.prepare('SELECT result_jcs FROM extension_approval_operation').pluck().get()),approved);});
 x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const b=await authenticated(t,x.f);
 assert.equal(b.sessions.getExtensionApproval(b.token(),approved.approval_ref).status,'approved');
});
