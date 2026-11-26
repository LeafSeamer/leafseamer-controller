import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import Database from 'better-sqlite3';
import {spawnSync} from 'node:child_process';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));
const {deviceEventScopeStore,eventScopeReference}=await import(pathToFileURL(path.join(root,'dist/device-event-scope.mjs')));
const {canonical,digest}=await import(pathToFileURL(path.join(root,'dist/auth-clock-value.mjs')));
const {deviceSourceProjectionStore}=await import(pathToFileURL(path.join(root,'dist/device-source-projection.mjs')));
const {sealSourceSnapshot}=await import(pathToFileURL(path.join(root,'dist/service-snapshot-content.mjs')));
const {manageLocalEvents}=await import(pathToFileURL(path.join(root,'dist/local-event-management.mjs')));
const {serviceIdentityStore}=await import(pathToFileURL(path.join(root,'dist/service-identity-store.mjs')));
const {contractSelection}=await import(pathToFileURL(path.join(root,'dist/sdk/selection.mjs')));
const {createHttpAdapter}=await import(pathToFileURL(path.join(root,'dist/sdk/http.mjs')));
const id=()=>crypto.randomUUID();
function fixture(t,location=':memory:'){
 const db=new Database(location);t.after(()=>db.close());db.pragma('foreign_keys=ON');
 db.exec('CREATE TABLE service_boot(service_boot_id TEXT PRIMARY KEY); CREATE TABLE device_event_source(registration_id TEXT PRIMARY KEY,device_id TEXT,body_jcs TEXT,body_digest TEXT); CREATE TABLE device_source_event(registration_id TEXT,source_sequence TEXT,record_id TEXT PRIMARY KEY,origin_jcs TEXT,origin_digest TEXT);');
 db.exec('CREATE TABLE device_subscription_scope ('+fs.readFileSync(path.join(root,'dist/device-event-scope.sql'),'utf8').split('CREATE TABLE device_subscription_scope (')[1]);
 const service={service_id:id(),database_instance_id:id(),schema_revision:location===':memory:'?'65':'67'},bootId=id(),device=id(),registration_id=id();db.prepare('INSERT INTO service_boot VALUES(?)').run(bootId);
 const registration={registration_id,revision:'1',source_key:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id,registration_id,source_stream_id:device,source_epoch:id()},
  binding_ref:{revision:'1',target:{kind:'device',device_id:device}},canonical_delivery:'ordered_subscription'};
 db.prepare('INSERT INTO device_event_source VALUES(?,?,?,?)').run(registration_id,device,canonical(registration),digest(registration));
 const value={registration,highest_committed_sequence:'0',fault:null};
 const currentSource=(selected,expected)=>{assert.equal(selected,device);if(expected)assert.equal(expected.object_id,registration.registration_id);return structuredClone(value);};
 const args={db,service,bootId,currentSource},store=deviceEventScopeStore(args),request={request_id:id(),device_ids:[device]};
 return {db,service,bootId,device,registration,value,args,store,request};
}
test('范围固定真实来源原件和完整集合，重复登记只查原，新增事件推进前沿不改范围',t=>{
 const f=fixture(t),created=f.store.register(f.request);assert.deepEqual(f.store.register(f.request),created);
 const body=created.registration;assert.deepEqual(created.scope_ref,eventScopeReference(body));assert.equal(body.selector.window,null);assert.deepEqual(body.selector.entity_ids,[f.registration.registration_id]);
 assert.deepEqual(body.scope.projection_profile_ref,eventScopeReference(body.profile));assert.deepEqual(body.scope.collections[0].selector_ref,eventScopeReference(body.selector));
 assert.deepEqual(f.store.current(created.scope_ref).current_frontiers.map(s=>s.registration_sequence),['0']);
 f.db.prepare('INSERT INTO device_source_event(registration_id,source_sequence,record_id) VALUES(?,?,?)').run(f.registration.registration_id,'1',id());f.value.highest_committed_sequence='1';
 const latest=f.store.current(created.scope_ref);assert.deepEqual(latest.registration,body);assert.equal(latest.current_frontiers[0].registration_sequence,'1');
 assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});
test('拒绝重算摘要引用、缺失正文、缺口、来源变化及故障，撤销和重启不恢复范围',t=>{
 const f=fixture(t),created=f.store.register(f.request),ref=created.scope_ref;
 assert.throws(()=>f.store.current({...ref,content_digest:'b'.repeat(64)}),{code:'event_scope_reference'});
 assert.throws(()=>f.store.register({...f.request,device_ids:[id()]}),{code:'event_scope_conflict'});
 f.value.highest_committed_sequence='2';assert.throws(()=>f.store.current(ref),{code:'event_scope_source_frontier'});f.value.highest_committed_sequence='0';
 f.value.fault={reason:'capture_failed'};assert.throws(()=>f.store.current(ref),{code:'event_scope_source_fault'});f.value.fault=null;
 f.value.registration.source_key.source_epoch=id();assert.throws(()=>f.store.current(ref),{code:'event_scope_source_original'});f.value.registration.source_key.source_epoch=created.registration.sources[0].source_key.source_epoch;
 const restarted=deviceEventScopeStore({...f.args,bootId:id()});assert.throws(()=>restarted.current(ref),{code:'event_scope_inactive'});
 const result=f.store.revoke(ref);assert.deepEqual(f.store.revoke(ref),result);assert.throws(()=>f.store.current(ref),{code:'event_scope_inactive'});assert.deepEqual(f.store.register(f.request),created);
});
test('登记主记录、完整成员和封存缺一回滚，禁止孤立范围提交或封存后增写',t=>{
 for(const table of ['device_subscription_scope','device_subscription_scope_member','device_subscription_scope_seal']){
  const f=fixture(t);f.db.exec('CREATE TRIGGER omit_scope BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(()=>f.store.register(f.request),{code:'event_scope_storage'});
  for(const name of ['device_subscription_scope','device_subscription_scope_member','device_subscription_scope_seal'])assert.equal(f.db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);
  f.db.exec('DROP TRIGGER omit_scope');const created=f.store.register(f.request);assert.equal(f.store.current(created.scope_ref).registration.entity_id,created.registration.entity_id);
  assert.throws(()=>f.db.prepare('DELETE FROM device_subscription_scope_member').run(),/immutable_event_scope/);
  const insertIncomplete=seal=>f.db.transaction(()=>{const body={...created.registration,entity_id:id()},hash=digest(body);
   f.db.prepare('INSERT INTO device_subscription_scope VALUES(?,?,?,?,?,?,?)').run(body.entity_id,id(),digest('incomplete'),f.bootId,canonical(body),hash,body.entity_id);
   if(seal)f.db.prepare('INSERT INTO device_subscription_scope_seal VALUES(?,?)').run(body.entity_id,hash);
  }).immediate();
  assert.throws(()=>insertIncomplete(false),/FOREIGN KEY/);assert.throws(()=>insertIncomplete(true),/scope_members_incomplete/);
  const member=f.db.prepare('SELECT * FROM device_subscription_scope_member').raw().get();assert.throws(()=>f.db.prepare('INSERT INTO device_subscription_scope_member VALUES(?,?,?,?)').run(...member),/scope_sealed/);
  assert.equal(f.db.prepare('SELECT count(*) FROM device_subscription_scope').pluck().get(),1);
 }
});
test('输入不接受过滤器、重复设备或越界数量，缺少来源不能部分登记',t=>{
 const f=fixture(t);for(const request of [{...f.request,filter:{}},{...f.request,device_ids:[]},{...f.request,device_ids:[f.device,f.device]},{...f.request,device_ids:Array.from({length:33},id)}])
  assert.throws(()=>f.store.register(request),{code:'event_scope_input'});
 f.db.prepare('DELETE FROM device_event_source').run();assert.throws(()=>f.store.register(f.request),{code:'event_scope_source_original'});assert.equal(f.db.prepare('SELECT count(*) FROM device_subscription_scope').pluck().get(),0);
});
test('实际生成的Profile、Selector和Scope均符合所采用SDK图，不改变通道模型',t=>{
 const f=fixture(t),{registration}=f.store.register(f.request);
 const script=`import sys,json
from jsonschema import Draft202012Validator,FormatChecker
graph=json.load(open(sys.argv[1],encoding='utf8')); data=json.load(sys.stdin)
for model,key in [('registry__Profile','profile'),('registry__Selector','selector'),('channel__ScopeSpec','scope')]:
 Draft202012Validator({'$ref':'#/$defs/'+model,'$defs':graph['$defs']},format_checker=FormatChecker()).validate(data[key])
print('fixed models validated')`;
 const checked=spawnSync(process.env.LEAFSEAMER_SCHEMA_PYTHON??'python',['-I','-B','-c',script,path.join(root,'dist/sdk/contract/models.schema.json')],{input:JSON.stringify(registration),encoding:'utf8',windowsHide:true});
 assert.equal(checked.status,0,checked.stderr||checked.error?.message);assert.match(checked.stdout,/fixed models validated/);
});
test('本机管理登记人员状态范围并封存实际来源投影，内部摄取范围不能互换',async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-status-scope-'));
 const f=fixture(t,path.join(directory,'events.sqlite'));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 f.db.pragma('user_version=67');
 const projectionSql=fs.readFileSync(path.join(root,'dist/device-source-projection.sql'),'utf8');
 f.db.exec('CREATE TABLE device_source_notification ('+projectionSql.split('CREATE TABLE device_source_notification (')[1]);
 f.db.exec("CREATE TABLE device_source_fault(registration_id TEXT,body_jcs TEXT); CREATE TABLE subject(principal_id TEXT,kind TEXT);");
 const actor={principal_id:id(),session_id:id(),issuer_id:id(),issuer_epoch:id(),recent_before_ns:'200',idle_before_ns:'250',expires_ns:'300'};
 f.db.prepare("INSERT INTO subject VALUES(?,'human')").run(actor.principal_id);
 const auth={credential_id:id()},grant={id:id(),revision:'1',digest:'sha256:'+'a'.repeat(64),state:'active',permissions:[]};
 const sessions=serviceIdentityStore({db:f.db,service:f.service,bootId:f.bootId,writer:work=>f.db.transaction(work).immediate(),
  time:()=>({lower:100n,upper:100n}),authenticated:input=>input===auth?{session:actor,credential:auth}:{denied:'session_invalid'},
  authority:{current:()=>grant},eventScopes:f.store});
 const register=(input=auth)=>manageLocalEvents(sessions,input,'register-status-scope',f.request);
 assert.throws(register,{code:'service_identity_management_denied'});
 grant.permissions=['auth.manage'];
 assert.throws(()=>register({}),{code:'session_invalid'});
 assert.throws(register,{code:'event_scope_projection_missing'});
 const sourceId=f.registration.registration_id,eventId=id(),raw={body:{value:'fixture-private-event-value'}};
 f.db.transaction(()=>{
  f.db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?,?)').run(sourceId,'1',eventId,canonical(raw),digest(raw));
  deviceSourceProjectionStore(f.db).publish(f.registration,[eventId]);
 }).immediate();
 f.value.highest_committed_sequence='1';
 const registered=register();
 assert.deepEqual(register(),registered);
 assert.throws(()=>manageLocalEvents(sessions,auth,'register-event-scope',f.request),{code:'event_scope_conflict'});
 const internal=f.store.register({...f.request,request_id:id()});
 const cut=f.store.snapshotCut(registered.scope_ref);
 assert.deepEqual(cut.registration.profile.owner_kinds,['human']);
 assert.deepEqual(cut.registration.profile.purposes,['status_projection']);
 assert.deepEqual(cut.registration.scope,registered.scope);
 const view={scope:registered.scope,selection:contractSelection,purpose:'status_projection',owner:{kind:'human'},
  binding:{subscription_id:id(),publisher_service_id:f.service.service_id,publisher_database_instance_id:f.service.database_instance_id,
   stream_id:id(),stream_epoch:id(),scope_digest:cut.registration.scope_digest,authorization_revision:'1',connection_generation:'1'}};
 const input={cut,view,snapshotId:id(),domainRef:{clock_domain_id:'clock_'+'b'.repeat(64),descriptor_digest:'sha256:'+'b'.repeat(64)},
  createdAt:'2026-11-15T00:00:00Z',expiresAt:'2026-11-15T00:00:30Z'};
 const sealed=sealSourceSnapshot(input),projection=JSON.parse(sealed.pages[0].body);
 assert.equal(cut.journal_sequence,'2');
 assert.equal(projection.records[0].view.contiguous_sequence,'1');
 assert.equal(sealed.manifest.source_watermarks[0].baseline_sequence,'1');
 assert.equal(JSON.stringify(sealed).includes(raw.body.value),false);
 const wire=createHttpAdapter(contractSelection);
 const base='/api/v1/subscriptions/'+view.binding.subscription_id,query='?expected_connection_generation=1';
 const headers=[['x-leafseamer-contract',contractSelection.contract_id],['x-leafseamer-contract-digest',contractSelection.contract_digest]];
 const page={manifest_digest:sealed.manifest.manifest_digest,content_digest:sealed.pages[0].content_digest,content:projection,delivery_binding:view.binding};
 for(const [route,value] of [[base+'/snapshot',sealed.manifest],[base+'/snapshots/'+input.snapshotId+'/pages/0',page]]){
  const request=wire.prepareRequest('controller','GET',route+query,[...headers,['origin','https://controller.invalid']]);
  const response=wire.prepareResponse(request,'200',[...headers,['content-type','application/json'],['cache-control','no-store']]);
  assert.deepEqual((await wire.decodeResponse(Buffer.from(JSON.stringify(value)),response)).value,value);
 }
 assert.throws(()=>sealSourceSnapshot({...input,view:{...view,owner:{kind:'service'}}}),{code:'snapshot_scope'});
 assert.throws(()=>sealSourceSnapshot({...input,cut:f.store.snapshotCut(internal.scope_ref)}),{code:'snapshot_scope'});
 assert.throws(()=>sealSourceSnapshot({...input,view:{...view,purpose:'canonical_trigger',owner:{kind:'service'}}}),{code:'snapshot_scope'});
 for(const change of [{scope_digest:'0'.repeat(64)},{publisher_database_instance_id:id()}]){
  assert.throws(()=>sealSourceSnapshot({...input,view:{...view,binding:{...view.binding,...change}}}),{code:'snapshot_scope'});
 }
 assert.deepEqual(manageLocalEvents(sessions,auth,'revoke-event-scope',{scope_ref:registered.scope_ref}),{scope_ref:registered.scope_ref,state:'revoked'});
 assert.throws(()=>f.store.snapshotCut(registered.scope_ref),{code:'event_scope_inactive'});
 assert.deepEqual(register(),registered);
 assert.equal(f.store.current(internal.scope_ref).registration.purpose,'canonical_trigger');
 assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
});
