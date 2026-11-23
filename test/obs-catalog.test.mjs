import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import Database from 'better-sqlite3';
import {canonical, digest} from '../dist/auth-clock-value.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {deviceCatalogStore} from '../dist/device-catalog-store.mjs';
import {readDeviceCapabilities,readDeviceSceneCatalog} from '../dist/device-capability-view.mjs';
import {deviceModuleJournal} from '../dist/device-module-store.mjs';
import {obsModuleDefinition as obs} from '../dist/obs-module-profile.mjs';
import {confirmObsSceneCatalog} from '../dist/obs-scene-confirmation.mjs';
import {resolveRolePermissions} from '../dist/extension-role-resolution.mjs';
import {installationDependencies, workerDependencies} from '../dist/worker-dependencies.mjs';
import {decodeCapabilityTemplate} from '../dist/sdk/capability-template.mjs';

const sceneA = 'ebc75716-e090-42b1-b9e5-ee8a1dd15879';
const sceneB = 'c3a343d6-9f64-4862-a151-baf6201a5ae6';
const data = name => readFileSync(new URL('../dist/' + name, import.meta.url));

function fixture(t) {
  const db = new Database(':memory:');
  t.after(() => db.close());
  // 当前原生准入由测试装配提供，从这里执行真实核心依赖、日志、目录与样本代码。
  db.exec(`PRAGMA user_version=99;
    CREATE TABLE device_record(device_id TEXT PRIMARY KEY,descriptor_body BLOB,descriptor_digest TEXT);
    CREATE TABLE obs_local_resource(device_id TEXT PRIMARY KEY,body_jcs TEXT,body_digest TEXT,transaction_id TEXT);
    CREATE TABLE obs_local_resource_commit(transaction_id TEXT,device_id TEXT,audit_jcs TEXT);
    CREATE TABLE extension_configuration(configuration_id TEXT,revision INTEGER,body_jcs TEXT,body_digest TEXT);
    CREATE TABLE extension_approval_capabilities(approval_id TEXT,body_jcs TEXT,body_digest TEXT);
    CREATE TABLE device_module_channel(channel_id TEXT,runtime_id TEXT,binding_jcs TEXT,binding_digest TEXT,audit TEXT);
    CREATE TABLE device_module_frame(channel_id TEXT,direction TEXT,sequence TEXT,message_id TEXT,reply_to TEXT,message_type TEXT,frame_jcs TEXT,frame_digest TEXT,transaction_id TEXT);
    CREATE TABLE device_module_frame_commit(transaction_id TEXT,message_id TEXT,audit TEXT);
    CREATE TABLE device_catalog_approval(approval_id TEXT PRIMARY KEY,channel_id TEXT,device_id TEXT,device_session_id TEXT,connected_message_id TEXT,body_jcs TEXT,body_digest TEXT,audit TEXT);
    CREATE TABLE device_baseline_sample(sample_id TEXT,approval_id TEXT,captured_message_id TEXT,sample_sequence TEXT,body_jcs TEXT,body_digest TEXT,audit TEXT);`);
  const service = {service_id: 'core', database_instance_id: 'database', schema_revision: '99'};
  const scope = {authority_service_id: service.service_id, database_instance_id: service.database_instance_id};
  const ref = (kind, name, body) => ({kind, ...scope, object_id: name, revision: '1', digest: digest(body)});
  const descriptor = {device_id: 'obs', device_kind: 'obs', display_name: 'OBS'};
  const device = ref('device', 'obs', descriptor), entry = {kind:'worker', loader:'node_module', file_id:'module', io_policy_file_id:'policy'};
  const resource = {format:'leafseamer-obs-local-resource/1',resource_id:'resource',device_ref:device,
    endpoint:{address:'127.0.0.1',port:4455}, profile:'obs_isolated_empty_cut/1', collection_name:'known',
    scene_uuids:[sceneA,sceneB].sort()};
  const resourceRef = ref('resource','resource',resource);
  const secretRef = {owner_service_id:service.service_id,secret_id:'resource',version:'1',purpose:'obs_websocket'};
  const config = {configuration:{resource_ref:resourceRef,secret_ref:secretRef}};
  const approval = {approval_ref:ref('approval','approval','approval'),configuration_ref:ref('configuration','config',config)};
  const extension_binding = {...approval,installation_ref:ref('installation','installation','installation'),
    platform_profile_ref:ref('platform_profile','platform','platform')};
  const intent = {member_id:'worker',launch_id:'launch',extension_binding,object_scope:{kind:'devices',device_ids:['obs']}};
  const runtime = {ref:ref('runtime_binding','runtime','runtime'),current_boot:true,withdrawal:null,
    binding:{...service,clock_domain_descriptor:{clock_domain_id:'clock'},launch_intent:intent,admission_receipt:{member_boot_id:'worker-boot'}}};
  const binding = {runtime_binding_ref:runtime.ref,ipc_session_id:'channel',member_boot_id:'worker-boot'};
  const content = {receipt:{manifest_digest:digest('manifest'),artifact_set_digest:digest('artifacts')},intake_ref:ref('intake','intake','intake'),
    manifest:{extension_id:'obs',extension_version:'1',entrypoints:[entry],api_versions:['leafseamer-device-module/2']},
    inventory:{files:[{file_id:'module',role:'module',digest:obs.module},{file_id:'policy',role:'policy',digest:obs.policy}]}};
  const selected = {content,entry,approval,permissions:[],resolution:{bindings:[{role_id:'device',kind:'device',values:[device]}]}};
  const evidence = {format:'leafseamer-static-capability-evidence/1',...content.receipt,intake_ref:content.intake_ref,documents:[{template:obs.template}]};
  db.prepare('INSERT INTO device_record VALUES (?,?,?)').run('obs',Buffer.from(canonical(descriptor)),device.digest);
  db.prepare('INSERT INTO obs_local_resource VALUES (?,?,?,?)').run('obs',canonical(resource),resourceRef.digest,'registration');
  db.prepare('INSERT INTO obs_local_resource_commit VALUES (?,?,?)').run('registration','obs',canonical({
    transaction_id:'registration',device_id:'obs',kind:'obs_local_resource_registered',resource_ref:resourceRef
  }));
  db.prepare('INSERT INTO extension_configuration VALUES (?,?,?,?)').run('config',1,canonical(config),digest(config));
  db.prepare('INSERT INTO extension_approval_capabilities VALUES (?,?,?)').run('approval',canonical(evidence),digest(evidence));
  const current = () => runtime;
  const dependencies = () => installationDependencies(db,service,selected);
  const catalog = deviceCatalogStore({db,current,select:()=>({selected,dependencies:dependencies()})});
  const view = () => ({service,device:'obs',runtime,selected,dependencies:dependencies(),channel:'channel'});
  const journal = deviceModuleJournal(db,current);
  journal.open(binding);
  const clock = openNativeClock();
  let sequence = 0;
  function receive(type,body) {
    const issued = clock.tick(), number = String(++sequence);
    const frame = {version:'device-module/3',type,sequence:number,request_id:'response-'+number,reply_to:'request-'+number,binding,
      issued_tick_ns:String(issued),deadline_tick_ns:String(issued+2000000000n),body:{device_id:'obs',device_session_id:'session',...body}};
    if(type==='CAPTURED')frame.body.captured_tick_ns=String(issued);
    journal.record('w2c',frame);
    catalog.receive(frame);
  }
  return {db,selected,catalog,receive,resourceRef,secretRef,
    dependencies:()=>db.transaction(dependencies).immediate(),
    prepared:()=>db.transaction(()=>workerDependencies(db,service,intent,selected)).immediate(),
    read:()=>db.transaction(()=>readDeviceCapabilities(db,view())).immediate(),
    readScenes:(includeConfirmation)=>readDeviceSceneCatalog(db,view(),includeConfirmation)};
}

test('OBS 固定模板可由当前 SDK 解码且不声明动作或事件', async () => {
  assert.deepEqual(await decodeCapabilityTemplate(data('obs-module-capability.json')),obs.template);
  assert.deepEqual(obs.catalog.action_ids,[]);
  assert.deepEqual(obs.catalog.trigger_ids,[]);
});

test('仅安装包的固定 OBS 模块可绑定无动作与触发权限的设备角色', () => {
  const reference = {kind:'device',authority_service_id:'core',database_instance_id:'database',object_id:'obs',revision:'1',digest:digest('obs')};
  const manifest = {roles:[{role_id:'device',kind:'device',minimum:1,maximum:1}],permission_templates:[],
    entrypoints:[{kind:'worker',loader:'node_module',file_id:'module',io_policy_file_id:'policy'}],
    api_versions:['leafseamer-device-module/2'],ipc_versions:['device-module/3'],capability_template_file_ids:['template']};
  const templateDigest = 'sha256:'+createHash('sha256').update(data('obs-module-capability.json')).digest('hex');
  const inventory = {files:[{file_id:'module',role:'module',digest:obs.module},
    {file_id:'policy',role:'policy',digest:obs.policy},{file_id:'template',role:'schema',digest:templateDigest}]};
  const configuration_ref = {id:'config'};
  const input = {manifest,inventory,configuration_ref,scope:reference,
    bindings:[{role_id:'device',kind:'device',values:[reference],configuration_ref}]};
  const current = () => ({device_kind:'obs'});
  assert.deepEqual(resolveRolePermissions({...input,current}),[]);
  assert.throws(()=>resolveRolePermissions({...input,current:()=>({device_kind:'simulator'})}),{code:'extension_role_unused'});
  for (const file of inventory.files) {
    const saved = file.digest;
    file.digest = digest('different');
    assert.throws(()=>resolveRolePermissions({...input,current}),{code:'extension_role_unused'});
    file.digest = saved;
  }
  manifest.api_versions.push('leafseamer-device-primitives/1');
  assert.throws(()=>resolveRolePermissions({...input,current}),{code:'extension_role_unused'});
});

test('已登记 OBS 资源进入当前依赖、只读目录及采样，断连使原批准失效', t => {
  const f=fixture(t);
  const graph=f.dependencies();
  assert.deepEqual(graph.resources,[f.resourceRef]);
  assert.deepEqual(graph.links[0].obs_binding.secret_ref,f.secretRef);
  assert.deepEqual(f.prepared().links,graph.links);
  f.receive('CONNECTED',{identity:obs.identity,catalog:obs.catalog});
  assert.equal(f.catalog.current('channel','obs','session').scene_catalog,null);
  const scenes=[{obs_scene_uuid:sceneB,display_name:'B'},{obs_scene_uuid:sceneA,display_name:'A'}];
  const baseline = value => f.receive('CAPTURED',{capture_id:'capture-'+value.sample_sequence,value:{scenes,...value}});
  assert.throws(()=>baseline({sample_sequence:'1',program_scene_uuid:'ba76b876-35d6-4476-b28c-0b10cb0cafd3'}),{code:'module_sample_schema'});
  assert.throws(()=>baseline({sample_sequence:'1',program_scene_uuid:sceneA,scenes:[scenes[0],scenes[0]]}),{code:'module_sample_schema'});
  baseline({sample_sequence:'1',program_scene_uuid:sceneA});
  const first=f.catalog.current('channel','obs','session').scene_catalog;
  assert.equal(first.collection_ref,f.catalog.current('channel','obs','session').approval.approval_id);
  assert.equal(first.status,'unconfirmed');
  assert.deepEqual(first.entries.map(({scene_id,...scene})=>scene),scenes);
  assert.equal(new Set(first.entries.map(({scene_id})=>scene_id)).size,2);
  assert.throws(()=>baseline({sample_sequence:'2',program_scene_uuid:sceneA,scenes:[scenes[0],{...scenes[1],display_name:'Renamed'}]}),
    {code:'module_sample_scene_catalog_changed'});
  assert.equal(f.catalog.current('channel','obs','session').sample.value.sample_sequence,'1');
  assert.throws(()=>baseline({sample_sequence:'3',program_scene_uuid:sceneB}),{code:'module_sample_sequence'});
  baseline({sample_sequence:'2',program_scene_uuid:sceneB});
  const current=f.catalog.current('channel','obs','session');
  assert.deepEqual(current.sample.value,{sample_sequence:'2',program_scene_uuid:sceneB,scenes});
  assert.deepEqual(current.scene_catalog,first);
  assert.equal(current.approval.evidence_policy.write_eligible,false);
  assert.equal(current.approval.automation_registration,null);
  assert.deepEqual(f.read().devices[0].actions,[]);
  assert.throws(()=>f.catalog.bindExecution('channel','obs','session'),{code:'execution_binding_qualification'});
  f.receive('DISCONNECTED',{});
  assert.throws(()=>f.catalog.current('channel','obs','session'),{code:'module_session'});
  assert.throws(f.read,{code:'device_capabilities_unavailable'});
  f.receive('CONNECTED',{device_session_id:'reconnected',identity:obs.identity,catalog:obs.catalog});
  f.receive('CAPTURED',{device_session_id:'reconnected',capture_id:'reconnected-first',value:{sample_sequence:'1',program_scene_uuid:sceneA,scenes}});
  const reconnected=f.catalog.current('channel','obs','reconnected').scene_catalog;
  assert.notEqual(reconnected.collection_ref,first.collection_ref);
  assert.notEqual(reconnected.entries[0].scene_id,first.entries[0].scene_id);
  assert.throws(()=>f.catalog.current('channel','obs','session'),{code:'module_session'});
});

test('错配模块、资源、凭据引用和发布的目录均不获批准',t=>{
  const f=fixture(t);
  const module=f.selected.content.inventory.files[0];module.digest=digest('different');
  assert.throws(f.dependencies,{code:'obs_worker_profile'});module.digest=obs.module;
  const binding=f.selected.resolution.bindings[0].values[0],oldDigest=binding.digest;
  binding.digest=digest('different');assert.throws(f.dependencies,{code:'worker_dependency_device_stale'});binding.digest=oldDigest;
  const config={configuration:{resource_ref:f.resourceRef,secret_ref:{...f.secretRef,purpose:'runtime_tls'}}};
  f.selected.approval.configuration_ref.digest=digest(config);
  f.db.prepare('UPDATE extension_configuration SET body_jcs=?,body_digest=?').run(canonical(config),digest(config));
  assert.throws(f.dependencies,{code:'obs_worker_configuration_binding'});
  config.configuration.secret_ref=f.secretRef;
  f.selected.approval.configuration_ref.digest=digest(config);
  f.db.prepare('UPDATE extension_configuration SET body_jcs=?,body_digest=?').run(canonical(config),digest(config));
  f.selected.permissions.push({kind:'device_scope',scope:{action_ids:['SetCurrentProgramScene'],trigger_ids:[]}});
  assert.throws(f.prepared,{code:'worker_dependency_obs_scope'});
  f.selected.permissions.pop();
  const incorrect={...obs.catalog,catalog_revision:'2'};
  assert.throws(()=>f.receive('CONNECTED',{identity:obs.identity,catalog:incorrect}),{code:'module_catalog_proposal'});
  assert.equal(f.db.prepare('SELECT count(*) FROM device_catalog_approval').pluck().get(),0);
});

test('OBS 重新连接同一组 UUID 后需要新的人员确认',t=>{
  const f=fixture(t), sql=data('obs-scene-confirmation.sql').toString('utf8');
  f.db.exec('PRAGMA user_version=100; CREATE TABLE auth_session(session_id TEXT PRIMARY KEY, state TEXT, issuer_id TEXT, issuer_epoch TEXT, principal_id TEXT);');
  f.db.exec(sql.slice(sql.indexOf('CREATE TABLE obs_scene_confirmation')));
  const actor={session_id:'actor-session',issuer_id:'core',issuer_epoch:'issuer',principal_id:'principal',authorization_revision:'1',acquisition_ref:{id:'clock'}};
  f.db.prepare("INSERT INTO auth_session VALUES(?, 'active', ?, ?, ?)").run(actor.session_id,actor.issuer_id,actor.issuer_epoch,actor.principal_id);
  const scenes=[{obs_scene_uuid:sceneB,display_name:'B'},{obs_scene_uuid:sceneA,display_name:'A'}];
  const connect=session=>{
    f.receive('CONNECTED',{device_session_id:session,identity:obs.identity,catalog:obs.catalog});
    f.receive('CAPTURED',{device_session_id:session,capture_id:'capture-'+session,value:{sample_sequence:'1',program_scene_uuid:sceneA,scenes}});
  };
  const read=()=>f.db.transaction(()=>f.readScenes()).immediate();
  const confirm=(request_id,expected_catalog_digest)=>f.db.transaction(()=>confirmObsSceneCatalog(f.db,f.readScenes(false),
    {request_id,expected_catalog_digest},actor)).immediate();
  connect('first');
  const first=read(),initial=digest(first);
  assert.equal(confirm('request',initial).status,'ready');
  assert.throws(()=>f.db.exec("UPDATE obs_scene_confirmation SET request_id='other'"),/immutable_obs_scene_confirmation/);
  f.receive('DISCONNECTED',{device_session_id:'first'});
  assert.throws(read,{code:'device_capabilities_unavailable'});
  connect('reconnected');
  const second=read();
  assert.equal(second.status,'unconfirmed');
  assert.notEqual(second.collection_ref,first.collection_ref);
  assert.throws(()=>confirm('request',initial),{code:'obs_scene_confirmation_stale'});
  assert.throws(()=>confirm('request',digest(second)),{code:'obs_scene_confirmation_conflict'});
  assert.equal(confirm('reconnect',digest(second)).status,'ready');
});
