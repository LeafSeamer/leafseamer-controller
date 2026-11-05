import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {resolveRolePermissions} from '../dist/extension-role-resolution.mjs';
import {decodeArtifactDocument} from '../dist/sdk/artifact-import.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {inspect,hash} from './fixtures/extension-installation.mjs';
import {prepared} from './fixtures/extension-role.mjs';
const ref=(kind,object_id=kind)=>({kind,authority_service_id:'controller.synthetic',database_instance_id:'database.synthetic',object_id,revision:'1',digest:hash(object_id)});
function projection(){
 const kinds={data:'data_object',device:'device',endpoint:'endpoint',filesystem:'filesystem_role',helper:'helper_artifact',policy:'validation_policy',protocol:'protocol_profile',secret:'secret_role',source:'source'};
 const configuration_ref=ref('configuration'),bindings=Object.entries(kinds).map(([role_id,kind])=>({role_id,kind,configuration_ref,
  values:kind==='endpoint'?[{host:'192.0.2.10',port:5000}]:[ref(kind)]}));
 const scopes={device_scope:{device_role:'device',action_ids:['set'],trigger_ids:[]},data_scope:{data_role:'data',access:'read'},
  network_endpoint:{endpoint_role:'endpoint',protocol_profile_role:'protocol',transport:'tcp',min_port:5000,max_port:5000},
  secret_role:{secret_role:'secret',device_role:'device',source_role:'source'},filesystem_root_role:{filesystem_role:'filesystem',access:'cache_write',quota_bytes:'1024'},
  helper_artifact:{helper_role:'helper',launch_policy_role:'policy',helper_file_id:'helper'},panel_method:{authority:'controller',method_ids:['getDevice'],object_roles:['device']},
  protocol_io:{protocol_profile_role:'protocol',endpoint_request_id:'network_endpoint',frame_classes:['query']}};
 const manifest={roles:Object.entries(kinds).map(([role_id,kind])=>({role_id,kind,minimum:1,maximum:1,purpose:'测试角色'})),inventory_digest:hash('inventory'),
  permission_templates:Object.entries(scopes).sort().map(([kind,scope])=>({request_id:kind,kind,purpose:'固定用途',scope}))};
 const inventory={files:[{file_id:'helper',role:'native_helper',digest:hash('helper-bytes')}]};
 return {manifest,inventory,configuration_ref,bindings,scope:{authority:'controller',authority_service_id:'controller.synthetic',database_instance_id:'database.synthetic'},
  current:value=>value.kind==='helper_artifact'?{file_id:'helper',file_digest:hash('helper-bytes'),artifact_set_digest:manifest.inventory_digest}:{}};
}
test('八种角色模板产生固定权限并通过产品Schema，helper绑定原字节和制品集合',async()=>{
 const input=projection(),permissions=resolveRolePermissions(input),body={resolution_id:'resolution.synthetic',authority_service_id:input.scope.authority_service_id,
  database_instance_id:input.scope.database_instance_id,installation_id:'installation.synthetic',manifest_digest:hash(input.manifest),artifact_set_digest:input.manifest.inventory_digest,
  configuration_ref:input.configuration_ref,bindings:input.bindings,permissions};
 assert.equal(permissions.length,8);assert.equal(permissions.find(p=>p.kind==='network_endpoint').scope.port,5000);
 assert.deepEqual(permissions.find(p=>p.kind==='device_scope').scope.devices,[ref('device')]);
 assert.equal(permissions.find(p=>p.kind==='filesystem_root_role').scope.quota_bytes,'1024');
 assert.deepEqual(await decodeArtifactDocument(Buffer.from(canonicalize({...body,resolution_digest:hash(body)})),'RoleResolution'),{...body,resolution_digest:hash(body)});
 input.current=()=>({file_id:'helper',file_digest:hash('different-bytes'),artifact_set_digest:input.manifest.inventory_digest});
 assert.throws(()=>resolveRolePermissions(input),{code:'extension_role_helper_binding'});
});
test('角色拒绝错配置、跨权威、重复对象、未使用声明、非规范端点与协议错绑',()=>{
 const mutations=[
  x=>x.bindings[0].configuration_ref=ref('configuration','other'),
  x=>x.bindings[0].values[0].authority_service_id='other',
  x=>{x.manifest.roles[0].maximum=2;x.bindings[0].values.push({...x.bindings[0].values[0],revision:'2'});},
  x=>x.bindings.push(x.bindings[0]),
  x=>x.manifest.permission_templates=x.manifest.permission_templates.filter(p=>p.kind!=='filesystem_root_role'),
  x=>x.bindings.find(b=>b.kind==='endpoint').values[0].host='EXAMPLE.test',
  x=>x.bindings.find(b=>b.kind==='endpoint').values[0].port=5001,
  x=>x.manifest.permission_templates.find(p=>p.kind==='protocol_io').scope.endpoint_request_id='device_scope',
  x=>x.manifest.permission_templates.find(p=>p.kind==='panel_method').scope.authority='seamer',
  x=>x.manifest.permission_templates.find(p=>p.kind==='device_scope').scope.action_ids=['z','a'],
 ];
 for(const mutate of mutations){const input=projection();mutate(input);assert.throws(()=>resolveRolePermissions(input));}
 const input=projection();input.current=()=>{throw new Error('current_object_missing');};assert.throws(()=>resolveRolePermissions(input),/current_object_missing/);
});
test('实际设备原件参与持久角色解析，幂等、独立修订、CAS与重启历史保持',{timeout:20000},async t=>{
 const {f,api,host,installed,request,registered}=await prepared(t),first=await api.roles.resolve(request);
 assert.equal(first.resolution_ref.digest,first.record.resolution_digest);assert.equal(first.record.permissions[0].scope.devices[0].object_id,registered.device_id);
 assert.deepEqual(await api.roles.resolve(request),first);assert.deepEqual(api.roles.current(installed.installation_ref),first);
 await assert.rejects(api.roles.resolve({...request,expected_revision:'1'}),{code:'extension_role_conflict'});
 await assert.rejects(api.roles.resolve({...request,request_id:'stale'}),{code:'extension_role_stale'});
 const second=await api.roles.resolve({...request,request_id:'second',expected_revision:'1'});assert.equal(second.resolution_ref.revision,'2');assert.notEqual(second.record.resolution_id,first.record.resolution_id);
 f.close();const reopened=f.reopen().extensionInstallations;reopened.bindSource(host);assert.deepEqual(reopened.roles.query('resolve'),first);assert.deepEqual(reopened.roles.current(installed.installation_ref),second);
});
test('当前配置推进、未知设备、错摘要及客户端自报权限不能生成新解析',{timeout:20000},async t=>{
 const {api,installed,request}=await prepared(t);const first=await api.roles.resolve(request);
 for(const change of [{object_id:'missing'},{digest:hash('wrong')},{revision:'2'}]){const bad=structuredClone(request);bad.request_id=crypto.randomUUID();Object.assign(bad.bindings[0].values[0],change);await assert.rejects(api.roles.resolve(bad));}
 await assert.rejects(api.roles.resolve({...request,request_id:'client-permission',permissions:first.record.permissions}),{code:'extension_role_input'});
 await api.configurations.configure({request_id:'new-config',installation_ref:installed.installation_ref,expected_revision:'1',bytes:Buffer.from('{"x":1}')});
 assert.deepEqual(api.roles.query('resolve'),first);assert.throws(()=>api.roles.current(installed.installation_ref),{code:'extension_role_configuration_stale'});
 await assert.rejects(api.roles.resolve({...request,request_id:'new',expected_revision:'1'}),{code:'extension_role_configuration_stale'});
});
test('解析逐写故障整体回滚，来源撤销和等待期间配置推进均不提交',{timeout:20000},async t=>{
 for(const table of ['extension_role_resolution','extension_role_head','extension_role_operation']){
  const {f,host,request}=await prepared(t);f.close();inspect(f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
  const api=f.reopen().extensionInstallations;api.bindSource(host);await assert.rejects(api.roles.resolve(request),/synthetic_failure/);f.close();
  inspect(f.dir,db=>{for(const name of ['extension_role_resolution','extension_role_head','extension_role_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);});
 }
 const revoked=await prepared(t,{recheck:(_f,host)=>{host.revoked=true;}});await assert.rejects(revoked.api.roles.resolve(revoked.request),{code:'extension_role_source_unavailable'});
 const raced=await prepared(t,{recheck:async(f,host)=>{host.checkRoles=false;await f.store.extensionInstallations.configurations.configure({request_id:'raced-config',installation_ref:raced.installed.installation_ref,expected_revision:'1',bytes:Buffer.from('{}')});}});
 await assert.rejects(raced.api.roles.resolve(raced.request),{code:'extension_role_configuration_stale'});assert.equal(raced.api.roles.query('resolve'),null);
});
test('schema14显式迁移到15，已保存配置保持不变',async t=>{
 const {f,api,config}=await prepared(t,{revision:14});assert.equal(api.roles,null);f.close();const migrated=await migrateStorage(f.dir,15);
 assert.equal(migrated.schema_revision,'15');assert.equal(migrated.steps.length,1);assert.deepEqual(f.reopen().extensionInstallations.configurations.query('configuration'),config);
});
