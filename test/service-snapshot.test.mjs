import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import Database from 'better-sqlite3';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url)),load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {serviceSubscriptionStore}=await load('service-subscription-store.mjs'),{canonical,digest}=await load('auth-clock-value.mjs'),{sealSourceSnapshot}=await load('service-snapshot-content.mjs');
const id=()=>crypto.randomUUID(),hash='a'.repeat(64),ref=()=>({id:id(),revision:'1',digest:'sha256:'+hash});
export function snapshotFixture(t,schema=68){
 const db=new Database(':memory:');t.after(()=>db.close());db.pragma('foreign_keys=ON');db.exec('CREATE TABLE device_event_source(registration_id TEXT PRIMARY KEY); CREATE TABLE device_source_notification(sequence INTEGER PRIMARY KEY); INSERT INTO device_source_notification VALUES(7)');
 db.exec('CREATE TABLE service_event_subscription ('+fs.readFileSync(path.join(root,'dist/service-subscription.sql'),'utf8').split('CREATE TABLE service_event_subscription (')[1]);
 db.exec('DROP TRIGGER service_event_subscription_outbox_complete;'+fs.readFileSync(path.join(root,'dist/service-snapshot.sql'),'utf8').split('DROP TRIGGER service_event_subscription_outbox_complete;')[1]);
 if(schema>=69)db.exec('DROP TRIGGER service_snapshot_publish_complete;'+fs.readFileSync(path.join(root,'dist/service-subscription-channel.sql'),'utf8').split('DROP TRIGGER service_snapshot_publish_complete;')[1]);
 const registration=id();db.prepare('INSERT INTO device_event_source VALUES(?)').run(registration);
 if(schema>=70)db.exec('DROP TRIGGER service_snapshot_publish_complete;'+fs.readFileSync(path.join(root,'dist/service-snapshot-baseline.sql'),'utf8').split('DROP TRIGGER service_snapshot_publish_complete;')[1]);
 const service={service_id:id(),database_instance_id:id(),schema_revision:String(schema)},bootId=id(),owner={kind:'service',issuer_id:id(),issuer_epoch:id(),principal_id:id(),consumer_service_id:id(),consumer_database_instance_id:id(),consumer_id:'events',pairing_id:id()};
 const object=kind=>({authority_service_id:service.service_id,database_instance_id:service.database_instance_id,entity_kind:kind,entity_id:id(),entity_epoch:id(),revision:'1',content_digest:hash});
 const scope={scope_id:id(),scope_revision:'1',projection_profile_ref:object('projection_profile'),collections:[{entity_kind:'sources',selector_ref:object('selector'),relation_policy:'authorized_reference',history_policy:'current'}]};
 const proof={session:null,principal_kind:'service',owner,subject_ref:ref(),approval_ref:ref(),policy_ref:ref(),pairing_ref:ref(),scope_ref:object('subscription_scope'),service_boot_id:bootId,expires_ns:'1790001000000000000',acquisition_ref:ref(),source_frontiers:[{source_key:{registration_id:registration},registration_sequence:'2'}]};
 const request={request_id:id(),consumer_id:'events',purpose:'canonical_trigger',scope},state={allowed:true,upper:1790000000000000000n,tick:100n,domain:{clock_domain_id:'clock_'+hash,descriptor_digest:'sha256:'+hash}};
 const source_key={authority_service_id:service.service_id,database_instance_id:service.database_instance_id,registration_id:registration,source_stream_id:id(),source_epoch:id()};
 const view={source_key,binding_ref:object('source_binding'),state:'baseline_required',contiguous_sequence:'2',highest_seen_sequence:'2',baseline_ref:null,gaps:[]};
 const cut={journal_sequence:'7',scope_ref:proof.scope_ref,registration:{scope,selector:{profile_ref:scope.projection_profile_ref,entity_ids:[registration]},profile:{collections:[{entity_kind:'sources',view_schema_ref:{schema_id:'urn:leafseamer:schema:product7',definition:'snapshot__SourceSnapshotView',schema_digest:hash}}]}},
  records:[{entity_kind:'sources',entity_id:registration,entity_epoch:source_key.source_epoch,entity_revision:'2',view}],source_watermarks:[{source_key,binding_ref:view.binding_ref,baseline_sequence:'2',source_state_revision:'2',baseline_ref:null,gap_summary:[]}]};
 const current=()=>state.allowed?structuredClone(proof):{denied:'service_identity_consumer_unavailable'};
 const args={db,service,bootId,writer:work=>db.transaction(work).immediate(),time:()=>({lower:state.upper-1000000n,upper:state.upper}),authorize:current,currentAuthorization:current,domain:()=>({ref:state.domain,tick:String(state.tick)}),sourceCut:()=>structuredClone(cut)};
 const store=serviceSubscriptionStore(args),count=table=>db.prepare('SELECT count(*) FROM '+table).pluck().get();return {db,store,proof,request,state,args,cut,count};
}
const fixture=t=>snapshotFixture(t);
export function buildSnapshot(store){for(let step=0;step<4;step++)store.sweep();}
test('分阶段构建释放事务，保留原切点与原截止，阶段间撤权或到期拒绝发布',t=>{
 const f=fixture(t),key=f.store.create('binding',null,f.request).view.binding.subscription_id;
 for(let step=0;step<3;step++){f.store.sweep();assert.equal(f.db.inTransaction,false);assert.equal(f.store.access('binding',null,key).view.state,'building');assert.equal(f.count('service_snapshot_manifest'),0);}
 const deadline=f.db.prepare('SELECT deadline_tick FROM service_snapshot_build').pluck().get();f.state.tick+=1000000000n;f.cut.records[0].view.contiguous_sequence='3';f.store.sweep();
 assert.equal(f.store.access('binding',null,key).view.state,'snapshot_ready');assert.equal(f.db.prepare('SELECT deadline_tick FROM service_snapshot_build').pluck().get(),deadline);
 assert.equal(JSON.parse(f.db.prepare('SELECT body_jcs FROM service_snapshot_page').pluck().get()).records[0].view.contiguous_sequence,'2');
 assert.equal(f.db.prepare('SELECT deadline_tick FROM service_snapshot_manifest').pluck().get(),'30000000100');
 for(const phase of [1,2,3])for(const revoke of [false,true]){const f=fixture(t),key=f.store.create('binding',null,f.request).view.binding.subscription_id;for(let i=0;i<phase;i++)f.store.sweep();
  if(revoke)f.state.allowed=false;else f.state.tick+=5000000000n;buildSnapshot(f.store);assert.equal(f.count('service_snapshot_manifest'),0);assert.equal(f.count('service_snapshot_end'),1);f.state.allowed=true;assert.notEqual(f.store.access('binding',null,key).view.state,'building');
 }
});
test('同事务发布固定manifest、全页、基线摘要与订阅修订，重复读不确认或延长',t=>{
 const f=fixture(t),first=f.store.create('binding',null,f.request);assert.equal(first.view.state,'building');buildSnapshot(f.store);
 const ready=f.store.access('binding',null,first.view.binding.subscription_id).view;assert.equal(ready.state,'snapshot_ready');assert.equal(ready.revision,'2');assert.equal(ready.ack_payload_digest,'0'.repeat(64));assert.equal(ready.binding.connection_generation,'0');
 const row=f.db.prepare('SELECT body_jcs,body_digest,marker_jcs,marker_digest,deadline_tick FROM service_snapshot_manifest').raw().get(),manifest=JSON.parse(row[0]);
 assert.notEqual(row[1],row[3]);assert.equal(digest(JSON.parse(row[2])).slice(7),row[3]);assert.equal(row[4],'30000000100');assert.equal(manifest.snapshot_cursor,'0');assert.equal(JSON.stringify(manifest).includes('journal'),false);
 assert.equal(f.store.create('binding',null,f.request).view.state,'snapshot_ready');assert.throws(()=>f.store.create('binding',null,{...f.request,request_id:id()}),{code:'subscription_slot_busy'});
 const closed=f.store.access('binding',null,first.view.binding.subscription_id,{expected_revision:'2'});assert.equal(closed.view.revision,'3');assert.equal(closed.view.state,'closed');assert.deepEqual(f.store.access('binding',null,first.view.binding.subscription_id,{expected_revision:'2'}),closed);
 assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
 const page=f.db.prepare('SELECT body_jcs,body_digest FROM service_snapshot_page').raw().get();
 const script=`import sys,json
from jsonschema import Draft202012Validator,FormatChecker
g=json.load(open(sys.argv[1],encoding='utf8')); d=json.load(sys.stdin)
for model,value in d.items(): Draft202012Validator({'$ref':'#/$defs/'+model,'$defs':g['$defs']},format_checker=FormatChecker()).validate(value)
print('snapshot models validated')`;
 const checked=spawnSync(process.env.LEAFSEAMER_SCHEMA_PYTHON??'python',['-I','-B','-c',script,path.join(root,'dist/sdk/contract/models.schema.json')],{input:JSON.stringify({'snapshot__Manifest':manifest,'snapshot__PageResponse':{manifest_digest:row[1],content_digest:page[1],content:JSON.parse(page[0]),delivery_binding:ready.binding},'channel__SubscriptionView':ready}),encoding:'utf8',windowsHide:true});assert.equal(checked.status,0,checked.stderr||checked.error?.message);
});
test('读取中到期、切域、撤权和不完整水位均不发布，原预留不可重试补页',t=>{
 for(const mutate of [f=>{f.state.tick+=5000000000n;},f=>{f.state.domain={...f.state.domain,clock_domain_id:'clock_'+'b'.repeat(64)};},f=>{f.state.allowed=false;},f=>{f.cut.source_watermarks[0].baseline_sequence='3';}]){
  const f=fixture(t),store=serviceSubscriptionStore({...f.args,sourceCut:()=>{mutate(f);return structuredClone(f.cut);}}),key=store.create('binding',null,f.request).view.binding.subscription_id;buildSnapshot(store);
  assert.equal(f.count('service_snapshot_manifest'),0);assert.equal(f.db.prepare('SELECT state FROM service_snapshot_end').pluck().get(),'invalidated');const expected=f.state.allowed?'resync_required':'revoked';f.state.allowed=true;assert.equal(store.access('binding',null,key).view.state,expected);buildSnapshot(store);assert.equal(f.count('service_snapshot_build'),1);
 }
});
test('发布30秒等号、原授权期限、重启均结束可用状态，不恢复旧快照',t=>{
 for(const mutate of [f=>{f.state.tick+=30000000000n;},f=>{f.state.upper=BigInt(f.proof.expires_ns);},f=>{f.args.bootId=id();}]){
  const f=fixture(t),key=f.store.create('binding',null,f.request).view.binding.subscription_id;buildSnapshot(f.store);mutate(f);const store=serviceSubscriptionStore(f.args);buildSnapshot(store);assert.ok(['resync_required','expired'].includes(store.access('binding',null,key).view.state));
  f.state.tick=100n;f.state.upper=1790000000000000000n;assert.notEqual(store.access('binding',null,key).view.state,'snapshot_ready');
 }
});
test('发布每项缺写全部回滚，遗留预留下一次扫描失效，不从新状态重建',t=>{
 for(const table of ['service_snapshot_manifest','service_snapshot_page','service_snapshot_end','service_event_subscription_revision','service_event_subscription_audit','service_event_subscription_outbox']){
  const f=fixture(t),key=f.store.create('binding',null,f.request).view.binding.subscription_id;f.db.exec('CREATE TRIGGER omit_publish BEFORE INSERT ON '+table+' BEGIN SELECT RAISE(IGNORE); END');assert.throws(()=>buildSnapshot(f.store));
  assert.equal(f.count('service_snapshot_manifest'),0);assert.equal(f.count('service_snapshot_page'),0);assert.equal(f.count('service_snapshot_end'),0);assert.equal(f.count('service_event_subscription_revision'),1);f.db.exec('DROP TRIGGER omit_publish');buildSnapshot(f.store);assert.equal(f.store.access('binding',null,key).view.state,'resync_required');assert.equal(f.count('service_snapshot_build'),1);
 }
});
test('内容封存拒绝跨页重复实体和水位不一致；排序与摘要独立于输入顺序',t=>{
 const f=fixture(t),view=f.store.create('binding',null,f.request).view,options={view,cut:f.cut,snapshotId:id(),domainRef:f.state.domain,createdAt:'2026-11-15T00:00:00Z',expiresAt:'2026-11-15T00:00:30Z'};
 const first=sealSourceSnapshot(options);assert.equal(first.pages[0].content_bytes,Buffer.byteLength(first.pages[0].body));assert.equal(first.pages[0].content_digest,digest(JSON.parse(first.pages[0].body)).slice(7));
 f.cut.records.push(f.cut.records[0]);assert.throws(()=>sealSourceSnapshot(options),{code:'snapshot_coverage'});f.cut.records.pop();f.cut.source_watermarks[0].gap_summary=[{loss_extent:'unknown'}];assert.throws(()=>sealSourceSnapshot(options),{code:'snapshot_watermark'});
});
test('多页完整集合按身份排序，每页与信封有界，封存后不能插页',t=>{
 const f=fixture(t),view=f.store.create('binding',null,f.request).view;
 f.cut.records=Array.from({length:32},(_,i)=>{const record=structuredClone(f.cut.records[0]);record.entity_id=String(i).padStart(3,'0');record.view.source_key.registration_id=record.entity_id;
  record.view.gaps=Array.from({length:64},(_,n)=>({gap_id:String(n).padStart(128,'g'),loss_extent:'unknown',first_missing:null,last_missing:null,resolution_state:'open'}));return record;}).reverse();
 f.cut.registration.selector.entity_ids=f.cut.records.map(r=>r.entity_id);f.cut.source_watermarks=f.cut.records.map(r=>({source_key:r.view.source_key,binding_ref:r.view.binding_ref,baseline_sequence:r.view.contiguous_sequence,source_state_revision:r.entity_revision,baseline_ref:null,gap_summary:r.view.gaps}));
 const options={view,cut:f.cut,snapshotId:id(),domainRef:f.state.domain,createdAt:'2026-11-15T00:00:00Z',expiresAt:'2026-11-15T00:00:30Z'},sealed=sealSourceSnapshot(options);assert.ok(sealed.pages.length>1);assert.equal(sealed.manifest.collections[0].count,'32');
 assert.deepEqual(sealed.pages.flatMap(p=>JSON.parse(p.body).records.map(r=>r.entity_id)),[...f.cut.registration.selector.entity_ids].sort());assert.ok(sealed.pages.every(p=>p.content_bytes<=245760));
 f.cut.records.reverse();f.cut.source_watermarks.reverse();assert.deepEqual(sealSourceSnapshot(options),sealed);
 const small=fixture(t);small.store.create('binding',null,small.request);buildSnapshot(small.store);const row=small.db.prepare('SELECT snapshot_id,page_index,body_jcs,body_digest,content_bytes FROM service_snapshot_page').raw().get();
 assert.throws(()=>small.db.prepare('INSERT INTO service_snapshot_page VALUES(?,?,?,?,?)').run(...row),/snapshot_sealed/);
});
test('已发布页缺失或原字节损坏即失步，不重新查询来源补页',t=>{
 for(const corrupt of [db=>{db.exec('DROP TRIGGER service_snapshot_page_no_delete; DELETE FROM service_snapshot_page');},db=>{db.exec("DROP TRIGGER service_snapshot_page_no_update; UPDATE service_snapshot_page SET body_digest='corrupt'");}]){
  const f=fixture(t),key=f.store.create('binding',null,f.request).view.binding.subscription_id;buildSnapshot(f.store);corrupt(f.db);let reads=0;const store=serviceSubscriptionStore({...f.args,sourceCut:()=>{reads++;return f.cut;}});buildSnapshot(store);assert.equal(store.access('binding',null,key).view.state,'resync_required');assert.equal(reads,0);assert.equal(f.count('service_snapshot_build'),1);
 }
});
