import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import Database from 'better-sqlite3';
import {snapshotFixture,buildSnapshot} from './service-snapshot.test.mjs';
import {canonical,digest} from '../dist/auth-clock-value.mjs';
import {contractSelection} from '../dist/sdk/selection.mjs';
import {createDecoder} from '../dist/sdk/runtime/panel-wire/decoder.mjs';
import {createPeerWebsocketServer,openPeerWebsocket} from '../dist/peer-event-websocket.mjs';
import {eventChannelProtocol} from '../dist/service-event-channel.mjs';
import {createSubscriptionEndpoint} from '../dist/service-subscription-http.mjs';
import {certificate} from './https-auth-fixture.mjs';
import {fixture as clockFixture} from './auth-clock-fixture.mjs';

function start(t) {
  const fixture = snapshotFixture(t,71);
  const {store,request} = fixture;
  const created = store.create('binding',null,request).view;
  buildSnapshot(store);
  const channels = store.channels;
  const handle = channels.open('binding',{});
  const {subscription_id,stream_id,stream_epoch,scope_digest,authorization_revision} = created.binding;
  const attach = {schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',connection_attempt_id:randomUUID(),owner:created.owner,
    subscription_id,stream_id,stream_epoch,scope_digest,authorization_revision,expected_connection_generation:'0',replace_existing:false,resume:null};
  const {attached} = channels.attach(handle,attach);
  const confirm = () => channels.applied(handle,{schema_version:attach.schema_version,type:'client.snapshot.applied',binding:attached.binding,snapshot:attached.snapshot_ref});
  return {...fixture,channels,handle,attach,confirm};
}

function notify(fixture,sequence,record) {
  const {db} = fixture;
  db.prepare('INSERT INTO device_source_notification VALUES(?,?,?,?,?,NULL)')
    .run(sequence,'entity.upsert',record.entity_id,canonical(record),digest(record));
}

function sourceEvent(fixture,sequence,persist=true,sourceSequence='3') {
  const {db,cut} = fixture;
  const source_key = cut.records[0].view.source_key;
  const scope = {
    authority_service_id:source_key.authority_service_id,database_instance_id:source_key.database_instance_id
  };
  const origin = {
    source_key,event_id:randomUUID(),source_sequence:sourceSequence,source_time_ref:null,
    binding_ref:{registration_id:source_key.registration_id,revision:'1',owner_service_id:scope.authority_service_id,
      database_instance_id:scope.database_instance_id,provider_id:'provider',provider_boot_id:'boot',
      capture_policy_id:'policy',capture_policy_revision:'1',delivery_semantics:'discrete',
      target:{kind:'device',device_id:'device',trigger_id:'changed',capability_version:'1.0.0'}},
    payload:{schema_ref:{kind:'schema',scope,object_id:'schema',revision:'1',digest:'sha256:'+'a'.repeat(64)},value:{value:7}}
  };
  const hash = digest(origin), event = {origin};
  if(!persist)return {origin,origin_digest:hash};
  db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?)').run(origin.event_id,source_key.registration_id,canonical(origin),hash);
  db.prepare('INSERT INTO device_source_notification VALUES(?,?,?,?,?,?)')
    .run(sequence,'source.event',source_key.registration_id,canonical(event),digest(event),origin.event_id);
  return {origin,origin_digest:hash};
}

test('按固定日志区间分配连续游标，跨连接代际重读保留原摘要',async t=>{
  const f = start(t);
  const record = f.cut.records[0];
  const other = {...record,entity_id:randomUUID()};
  f.db.prepare('INSERT INTO device_event_source VALUES(?)').run(other.entity_id);
  notify(f,8,other);
  const event = sourceEvent(f,9);
  for(let sequence=10;sequence<=25;sequence++) notify(f,sequence,{...record,entity_revision:String(sequence)});
  const confirmed = f.confirm();
  notify(f,26,record);
  assert.deepEqual(f.db.prepare('SELECT start_sequence,end_sequence FROM service_subscription_reconcile').raw().get(),[7,25]);
  assert.throws(()=>f.channels.prepareReconcile(f.handle,'1'),/reconcile_cursor/);
  const first = f.channels.prepareReconcile(f.handle,'0');
  assert.equal(first.length,16);
  assert.deepEqual(first[0].entry,{entry_kind:'source.event',payload:event});
  assert.equal(first[0].payload_digest,digest(first[0].entry).slice(7));
  const decoder = createDecoder(contractSelection), wire = decoder.websocket('controller','internalOpenEvents','server');
  for(const frame of first) assert.deepEqual((await decoder.decode(Buffer.from(JSON.stringify(frame)),wire)).value,frame);
  assert.deepEqual(f.channels.prepareReconcile(f.handle,'0'),first);
  const last = f.channels.prepareReconcile(f.handle,'16');
  assert.equal(last.length,1);
  assert.equal(last[0].cursor,'17');
  assert.equal(last[0].previous_cursor,'16');
  assert.deepEqual(f.channels.prepareReconcile(f.handle,'17'),[]);
  assert.equal(f.count('service_subscription_delivery'),17);
  assert.equal(f.store.access('binding',null,f.attach.subscription_id).view.ack_cursor,'0');
  const replacement = f.channels.open('binding',{});
  f.channels.attach(replacement,{...f.attach,connection_attempt_id:randomUUID(),expected_connection_generation:'1',replace_existing:true,
    resume:{cursor:'0',payload_digest:confirmed.ack_payload_digest,ack_kind:'durable_ingest'}});
  assert.throws(()=>f.channels.prepareReconcile(f.handle,'0'),/subscription_generation/);
  assert.deepEqual(f.channels.prepareReconcile(replacement,'0'),first.map(frame=>({...frame,binding:{...frame.binding,connection_generation:'2'}})));
});

test('确认及窗口同事务，拒绝跳过来源条目与坏摘要，撤权后停止准备',t=>{
  const f = start(t);
  notify(f,8,f.cut.records[0]);
  sourceEvent(f,9);
  f.db.exec('CREATE TEMP TRIGGER omit_window BEFORE INSERT ON service_subscription_reconcile BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(f.confirm,/reconcile_storage/);
  assert.equal(f.count('service_snapshot_baseline'),0);
  f.db.exec('DROP TRIGGER omit_window');
  f.confirm();
  assert.throws(()=>f.db.prepare('INSERT INTO service_subscription_delivery VALUES(?,?,?,?,?,NULL)').run(f.attach.subscription_id,1,9,'{}','fake'),/reconcile_delivery_parent/);
  f.db.prepare("UPDATE device_source_notification SET body_digest='bad' WHERE sequence=9").run();
  assert.throws(()=>f.channels.prepareReconcile(f.handle,'0'),/reconcile_integrity/);
  assert.equal(f.count('service_subscription_delivery'),0);
  f.state.allowed=false;
  assert.throws(()=>f.channels.prepareReconcile(f.handle,'0'));
  assert.equal(f.count('service_subscription_delivery'),0);
});

test('完整信封超过传输上限时整批回滚，游标和基线 ACK 均保留',t=>{
  const f = start(t);
  notify(f,8,f.cut.records[0]);
  // 正文可存入日志，附带连接绑定后的完整帧超过 64 KiB。
  notify(f,9,{...f.cut.records[0],oversized:'a'.repeat(65000)});
  const confirmed = f.confirm();
  assert.throws(()=>f.channels.prepareReconcile(f.handle,'0'),/reconcile_frame_capacity/);
  assert.equal(f.count('service_subscription_delivery'),0);
  assert.deepEqual(f.store.access('binding',null,f.attach.subscription_id).view,confirmed);
});

test('未发送和错误摘要不能推进 ACK，修订写入失败时确认回滚',t=>{
 const f=start(t);
 sourceEvent(f,8);
 const confirmed=f.confirm(),frame=f.channels.nextReconcile(f.handle);
 const premature={entry_kind:'sync.ready',payload:{baseline_snapshot_id:confirmed.snapshot_ref.snapshot_id}};
 assert.throws(()=>f.db.prepare('INSERT INTO service_subscription_delivery VALUES(?,?,NULL,?,?,?)')
  .run(f.attach.subscription_id,2,canonical(premature),digest(premature),confirmed.binding.connection_generation),/reconcile_ready_parent/);
 const ack={schema_version:'event-channel/0.1.0-draft.1',type:'client.ack',binding:frame.binding,
  cursor:frame.cursor,payload_digest:frame.payload_digest,ack_kind:'durable_ingest'};
 assert.throws(()=>f.channels.ack(f.handle,ack),/ack_mapping/);
 f.channels.checkDelivery(f.handle,frame);
 f.channels.transmitted(f.handle,frame);
 assert.equal(f.channels.nextReconcile(f.handle),null);
 assert.throws(()=>f.channels.ack(f.handle,{...ack,payload_digest:'f'.repeat(64)}),/ack_mapping/);
 f.db.exec('CREATE TEMP TRIGGER omit_ack_revision BEFORE INSERT ON service_event_subscription_revision BEGIN SELECT RAISE(IGNORE); END');
 assert.throws(()=>f.channels.ack(f.handle,ack),/subscription_storage/);
 assert.equal(f.count('service_subscription_delivery_ack'),0);
 assert.deepEqual(f.store.access('binding',null,f.attach.subscription_id).view,confirmed);
 f.db.exec('DROP TRIGGER omit_ack_revision');
 const accepted=f.channels.ack(f.handle,ack);
 assert.equal(accepted.ack_cursor,'1');
 assert.deepEqual(f.channels.ack(f.handle,ack),accepted);
 const ready=f.channels.nextReconcile(f.handle);
 assert.equal(ready.type,'server.sync.ready');
 assert.equal(ready.previous_cursor,'1');
 assert.equal(ready.cursor,'2');
});

test('逐条交付只准备待发送帧，确认后再持久化下一条',t=>{
 const f=start(t);
 sourceEvent(f,8);notify(f,9,f.cut.records[0]);f.confirm();
 const first=f.channels.nextReconcile(f.handle);
 assert.equal(first.cursor,'1');assert.equal(f.count('service_subscription_delivery'),1);
 assert.deepEqual(f.channels.nextReconcile(f.handle),first);
 f.channels.checkDelivery(f.handle,first);f.channels.transmitted(f.handle,first);
 assert.equal(f.channels.nextReconcile(f.handle),null);
 assert.equal(f.count('service_subscription_delivery'),1);
 f.channels.ack(f.handle,{schema_version:'event-channel/0.1.0-draft.1',type:'client.ack',binding:first.binding,
  cursor:first.cursor,payload_digest:first.payload_digest,ack_kind:'durable_ingest'});
 const second=f.channels.nextReconcile(f.handle);
 assert.equal(second.cursor,'2');assert.equal(second.previous_cursor,'1');
 assert.equal(f.count('service_subscription_delivery'),2);
});

test('空区间的就绪检查点独占游标，发送前运行域失效会关闭订阅',t=>{
 const f=start(t);
 const baseline=f.confirm(),ready=f.channels.nextReconcile(f.handle);
 assert.deepEqual(ready,{
  schema_version:'event-channel/0.1.0-draft.1',type:'server.sync.ready',binding:baseline.binding,
  baseline_snapshot_id:baseline.snapshot_ref.snapshot_id,cursor:'1',previous_cursor:'0',delivery_mode:'reconcile',
  payload_digest:digest({entry_kind:'sync.ready',payload:{baseline_snapshot_id:baseline.snapshot_ref.snapshot_id}}).slice(7)
 });
 assert.notEqual(ready.payload_digest,baseline.ack_payload_digest);
 f.state.domain={...f.state.domain,descriptor_digest:'sha256:'+'f'.repeat(64)};
 assert.throws(()=>f.channels.checkDelivery(f.handle,ready),/subscription_state/);
 assert.equal(f.count('service_subscription_transmitted'),0);
 assert.equal(f.count('service_subscription_delivery_ack'),0);
});

test('实际 mTLS 实时交付、丢失 ACK 重放及新代际追赶', {skip:!process.env.LEAFSEAMER_RECONCILE_TEST_ROOT,timeout:20000}, async t=>{
 const root=process.env.LEAFSEAMER_RECONCILE_TEST_ROOT;
 const load=name=>import(pathToFileURL(path.join(root,'dist',name)));
 const {initializeStorage,migrateStorage}=await load('storage.mjs');
 const {snapshotIngestStore}=await load('snapshot-ingest-store.mjs');
 const {reconcileInbox}=await load('reconcile-inbox.mjs');
 const {createPeerSubscriptionClient}=await load('peer-subscription-client.mjs');
 const {createPeerSnapshotConfirmation}=await load('peer-snapshot-confirmation.mjs');
 const {authenticationClockStore}=await load('runtime/auth-clock-store.mjs');
 const {startAuthenticationClock}=await load('runtime/auth-clock.mjs');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-reconcile-'));
 const original=initializeStorage(dir);
 migrateStorage(dir,'4');
 const service=migrateStorage(dir,'5');
 const db=new Database(path.join(dir,'seamer.sqlite'));
 t.after(()=>{db.close();assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 assert.equal(service.service_id,original.service_id);
 assert.equal(service.database_instance_id,original.database_instance_id);
 db.pragma('foreign_keys=ON');
 db.pragma('synchronous=FULL');
 const f=snapshotFixture(t,71),{store,proof}=f;
 Object.assign(proof.owner,{consumer_service_id:service.service_id,consumer_database_instance_id:service.database_instance_id});
 const record=f.cut.records[0],binding=sourceEvent(f,8,false).origin.binding_ref;
 record.view.binding_ref={...record.view.binding_ref,entity_id:binding.registration_id,revision:binding.revision,
  entity_epoch:record.view.source_key.source_epoch,content_digest:digest(binding).slice(7)};
 f.cut.source_watermarks[0].binding_ref=record.view.binding_ref;
 // 快照固定在日志 7，事件 8 属于确认时的追赶区间。
 const created=store.create('binding',null,f.request).view;
 buildSnapshot(store);
 const view=store.access('binding',null,created.binding.subscription_id).view;
 assert.equal(view.state,'snapshot_ready');
 const event=sourceEvent(f,8);
 const material=certificate(), endpoint=createSubscriptionEndpoint({store}),incoming=endpoint.channel;
 const websockets=createPeerWebsocketServer({protocol:eventChannelProtocol});
 const http=https.createServer({...material,ca:material.cert,requestCert:true,rejectUnauthorized:true},async(req,res)=>{
  try{
   assert.equal(req.socket.authorized,true);
   const headers=[];for(let i=0;i<req.rawHeaders.length;i+=2)headers.push([req.rawHeaders[i].toLowerCase(),req.rawHeaders[i+1]]);
   const reply=await endpoint.handle({bindingId:'binding',socket:req.socket,method:req.method,path:req.url,headers,body:Buffer.alloc(0)});
   reply.beforeSend();
   res.writeHead(reply.status,Object.fromEntries(reply.headers));
   res.end(reply.body);
  }catch(error){res.destroy(error);}
 });
 const failed=[];
 http.on('upgrade',(request,socket,head)=>websockets.accept(request,socket,head,{
  stable(){assert.equal(socket.authorized,true);},open(){
   const app=incoming.open('binding',socket);
   return {...app,async receive(bytes){try{return await app.receive(bytes);}catch(error){failed.push(error);throw error;}}};
  }
 }));
 http.listen(0,'127.0.0.1');await once(http,'listening');
 const monitor=setInterval(()=>websockets.sweep(),50);
 t.after(async()=>{clearInterval(monitor);await websockets.close();await new Promise(resolve=>http.close(resolve));});
 let suppressCursor='1',checks=0,accepted=0;
 const client=createPeerSubscriptionClient({transport:{
 requestSubscription(_id,{method,path:route,headers}){
  return new Promise((resolve,reject)=>{
   const req=https.request({host:'127.0.0.1',port:http.address().port,path:route,method,headers:Object.fromEntries(headers),
    ...material,ca:material.cert,rejectUnauthorized:true},res=>{
    const chunks=[],pairs=[];
    for(let i=0;i<res.rawHeaders.length;i+=2)pairs.push([res.rawHeaders[i].toLowerCase(),res.rawHeaders[i+1]]);
    res.on('data',chunk=>chunks.push(chunk));res.on('error',reject);
    res.on('end',()=>resolve({status:res.statusCode,headers:pairs,body:Buffer.concat(chunks)}));
   });
   req.on('error',reject);req.end();
  });
 },
 async openSubscriptionChannel(_id,{protocol,onFrame,onClose}){
  const channel=await openPeerWebsocket('wss://127.0.0.1:'+http.address().port+'/internal/events',protocol,
   {...material,ca:material.cert,rejectUnauthorized:true},{stable:socket=>assert.equal(socket.authorized,true),onFrame,onClose});
  return {...channel,send(bytes){
   const frame=JSON.parse(bytes);
   if(frame.type==='client.ack'&&frame.cursor===suppressCursor)return;
   channel.send(bytes);
  }};
 }}});
 const first=await client.attach('binding',view).catch(error=>{throw failed[0]??error;});
 const bootId=randomUUID();
 let selected={subscription:{...view,binding:first.attached.binding},context:{},projection:f.cut};
 const base=snapshotIngestStore({db,service,bootId,isOpen:()=>db.open,receiver:{currentInTransaction:()=>selected}});
 const receipt=base.apply(null);
 db.prepare("INSERT INTO service_boot VALUES(?,?,?,'started')").run(service.service_id,service.database_instance_id,bootId);
 const ledger=authenticationClockStore(db,{service_id:service.service_id,service_boot_id:bootId});
 const {source,provider}=clockFixture(ledger.scope);
 const clock=startAuthenticationClock(source,ledger,provider,{schedule:false});
 let spoofAcquisition=false;
 const inbox=reconcileInbox({db,service,bootId,isOpen:()=>db.open,clock:{pairingSample(){
  const sample=clock.pairingSample();
  return spoofAcquisition?{...sample,acquisition_ref:{...sample.acquisition_ref,digest:'sha256:'+'0'.repeat(64)}}:sample;
 }}});
 const faults=()=>db.prepare('SELECT body_jcs FROM ingest_source_fault ORDER BY fault_key').pluck().all().map(JSON.parse);
 const initialCursor=inbox.receiveCursor(),watermark=sequence=>({...initialCursor,receive_sequence:String(sequence)});
 assert.deepEqual(initialCursor,{scope:receipt.scope,ingest_epoch:initialCursor.ingest_epoch,receive_sequence:'0'});
 assert.match(initialCursor.ingest_epoch,/^[0-9a-f-]{36}$/);
 const confirmation=createPeerSnapshotConfirmation({ingest:base,receiver:{current:()=>selected},client,reconcile:inbox});
 const accept=(frame,check)=>{
  if(frame.type==='server.data'&&frame.cursor==='1'&&frame.delivery_mode==='reconcile'){
   assert.throws(()=>inbox.accept(receipt,{...frame,delivery_mode:'live'},check),/reconcile_inbox_live_without_checkpoint/);
   if(accepted===0){
    spoofAcquisition=true;
    assert.throws(()=>inbox.accept(receipt,frame,check),/reconcile_inbox_clock_acquisition/);
    assert.equal(db.prepare('SELECT count(*) FROM subscription_reconcile_inbox').pluck().get(),0);
    spoofAcquisition=false;
   }
  }
  if(frame.type==='server.sync.ready'){
   const bad={...frame,baseline_snapshot_id:randomUUID()};
   bad.payload_digest=digest({entry_kind:'sync.ready',payload:{baseline_snapshot_id:bad.baseline_snapshot_id}}).slice(7);
   assert.throws(()=>inbox.accept(receipt,bad,check),/reconcile_inbox_binding/);
  }
  inbox.accept(receipt,frame,()=>{check();assert.equal(db.inTransaction,true);checks++;});accepted++;
  return ()=>assert.equal(inbox.confirmed(receipt,frame.cursor,frame.payload_digest),true);
 };
 const until=async predicate=>{for(let i=0;i<100;i++){if(predicate())return;await delay(20);}assert.fail('reconcile_state_timeout');};
 const publisher=()=>store.access('binding',null,view.binding.subscription_id).view;
 await client.snapshotApplied('binding',first,view.snapshot_ref,()=>{},accept);
 await until(()=>accepted===1&&f.count('service_subscription_transmitted')===1);
 const received=db.prepare('SELECT body_jcs,observation_jcs FROM subscription_reconcile_inbox').raw().get();
 assert.deepEqual(JSON.parse(received[0]),{entry_kind:'source.event',payload:event});
 const observation=JSON.parse(received[1]),originalSample=clock.pairingSample();
 assert.equal(observation.receiver_boot_id,bootId);
 assert.deepEqual(observation.runtime_domain_ref,originalSample.runtime_domain_ref);
 assert.deepEqual(observation.acquisition_ref,originalSample.acquisition_ref);
 assert.equal(observation.received_tick_ns,originalSample.tick_ns);
 assert.equal(observation.age_basis,'unproven');
 assert.deepEqual(observation.disposition,{state:'observed_only',age_evidence_ref:null,reason_codes:['source_time_missing','reconciled_delivery']});
 const firstRecord=inbox.sourceEvent(event.origin.source_key,event.origin.event_id);
 assert.deepEqual(firstRecord,{
  origin:event.origin,origin_digest:event.origin_digest,first_observation:observation,first_observation_digest:digest(observation),
  first_delivery:{apply_id:receipt.apply_id,cursor:'1',connection_generation:'1'},receive_cursor:watermark(1)
 });
 assert.equal(publisher().ack_cursor,'0');
 assert.throws(()=>f.db.prepare('UPDATE service_subscription_transmitted SET cursor=2').run(),/immutable_reconcile_transmitted/);
 source.advance(500000000n);
 clock.refresh();
 assert.notDeepEqual(clock.pairingSample().acquisition_ref,observation.acquisition_ref);
 first.close();
 suppressCursor='2';
 const prior=publisher();
 const second=await client.attach('binding',prior,{replace_existing:true,resume:{cursor:'0',payload_digest:prior.ack_payload_digest,ack_kind:'durable_ingest'},beforeSend(){},onReconcile:accept});
 await until(()=>publisher().ack_cursor==='1'&&accepted===3&&f.count('service_subscription_transmitted')===3);
 assert.ok(checks>=3);
 const stored=db.prepare('SELECT body_jcs,observation_jcs FROM subscription_reconcile_inbox ORDER BY cursor').raw().all();
 assert.deepEqual(stored[0],received);
 assert.deepEqual(JSON.parse(stored[1][0]),{entry_kind:'sync.ready',payload:{baseline_snapshot_id:receipt.snapshot_ref.snapshot_id}});
 assert.equal(f.count('service_subscription_delivery_ack'),1);
 assert.deepEqual(inbox.receiveCursor(),watermark(1));
 assert.equal(inbox.ready(receipt,'1',publisher().ack_payload_digest,'2'),false);
 assert.equal((await confirmation.query('binding',second,receipt.apply_id)).transport_ready,false);
 assert.equal(publisher().state,'catching_up');
 assert.equal(base.sourceState(event.origin.source_key).state,'baseline_required');
 second.close();
 const confirmed=publisher();
 suppressCursor='4';
 const third=await client.attach('binding',confirmed,{replace_existing:true,resume:{cursor:'1',payload_digest:confirmed.ack_payload_digest,ack_kind:'durable_ingest'},beforeSend(){},onReconcile:accept});
 assert.equal(third.attached.ack_cursor,'1');
 assert.equal(third.attached.binding.connection_generation,'3');
 await until(()=>publisher().state==='live'&&publisher().ack_cursor==='3');
 assert.equal(accepted,5);
 assert.deepEqual(db.prepare('SELECT body_jcs,observation_jcs FROM subscription_reconcile_inbox ORDER BY cursor LIMIT 2').raw().all(),stored);
 assert.equal(inbox.ready(receipt,'3',publisher().ack_payload_digest,'3'),true);
 const firstLive=sourceEvent(f,9,true,'4');
 await until(()=>accepted===6&&f.count('service_subscription_transmitted')===6);
 assert.equal(publisher().ack_cursor,'3');
 const getRow=cursor=>db.prepare('SELECT body_jcs,observation_jcs FROM subscription_reconcile_inbox WHERE apply_id=? AND cursor=?').raw().get(receipt.apply_id,cursor);
 const liveOriginal=getRow('4');
 assert.deepEqual(JSON.parse(liveOriginal[0]),{entry_kind:'source.event',payload:firstLive});
 assert.equal(JSON.parse(liveOriginal[1]).delivery_mode,'live');
 third.close();
 const offline=sourceEvent(f,10,true,'5');
 suppressCursor=null;
 const fourth=await confirmation.resume('binding',receipt.apply_id,{replace_existing:true});
 assert.equal(fourth.attached.binding.connection_generation,'4');
 assert.equal(fourth.attached.ack_cursor,'3');
 assert.equal(fourth.attached.state,'catching_up');
 await until(()=>publisher().ack_cursor==='6'&&publisher().state==='live');
 assert.deepEqual(getRow('4'),liveOriginal);
 assert.deepEqual(JSON.parse(getRow('5')[0]),{entry_kind:'source.event',payload:offline});
 assert.equal(JSON.parse(getRow('5')[1]).delivery_mode,'reconcile');
 assert.equal((await confirmation.query('binding',fourth,receipt.apply_id)).transport_ready,true);
 assert.deepEqual(inbox.receiveCursor(),watermark(3));
 assert.equal(f.db.prepare('SELECT count(*) FROM service_subscription_delivery WHERE journal_sequence IS NULL').pluck().get(),3);
 const resumedLive=sourceEvent(f,11,true,'6');
 await until(()=>publisher().ack_cursor==='7');
 assert.deepEqual(JSON.parse(getRow('7')[0]),{entry_kind:'source.event',payload:resumedLive});
 assert.equal(JSON.parse(getRow('7')[1]).delivery_mode,'live');
 assert.deepEqual(JSON.parse(getRow('7')[1]).disposition,{state:'observed_only',age_evidence_ref:null,reason_codes:['source_time_missing']});
 assert.equal((await confirmation.query('binding',fourth,receipt.apply_id)).transport_ready,true);
 const wireJump=sourceEvent(f,12,true,'8');
 await until(()=>faults().length===1);
 const [wireFault]=faults();
 assert.equal(wireFault.identity.event_id,wireJump.origin.event_id);
 assert.equal(wireFault.gap.first_missing,'7');
 assert.equal(wireFault.gap.last_missing,'7');
 assert.equal(publisher().ack_cursor,'7');
 assert.equal(inbox.sourceEvent(wireJump.origin.source_key,wireJump.origin.event_id),null);
 assert.deepEqual(inbox.receiveCursor(),watermark(4));
 await assert.rejects(confirmation.query('binding',fourth,receipt.apply_id));
 fourth.close();
 const previousRef=structuredClone(selected.subscription.snapshot_ref);
 selected.subscription.snapshot_ref={...previousRef,snapshot_id:randomUUID()};
 assert.throws(()=>base.apply(null),{code:'snapshot_ingest_baseline_regression'});
 assert.deepEqual(base.confirmationReceipt(receipt.apply_id),receipt);

 store.access('binding',null,view.binding.subscription_id,{expected_revision:publisher().revision});
 f.cut.journal_sequence='12';
 record.entity_revision='3';
 record.view.contiguous_sequence='8';
 record.view.highest_seen_sequence='8';
 f.cut.source_watermarks[0].baseline_sequence='8';
 f.cut.source_watermarks[0].source_state_revision='3';
 const empty=store.create('binding',null,{...f.request,request_id:randomUUID()}).view;
 buildSnapshot(store);
 const emptyView=store.access('binding',null,empty.binding.subscription_id).view;
 assert.equal(emptyView.state,'snapshot_ready');
 const emptyConnection=await client.attach('binding',emptyView);
 selected={subscription:{...emptyView,binding:emptyConnection.attached.binding},context:{},projection:f.cut};
 record.entity_revision='2';
 assert.throws(()=>base.apply(null),{code:'snapshot_ingest_projection_regression'});
 record.entity_revision='3';
 const emptyReceipt=base.apply(null);
 await confirmation.send('binding',emptyConnection,null);
 await until(()=>store.access('binding',null,empty.binding.subscription_id).view.ack_cursor==='1');
 const emptyReady=await confirmation.query('binding',emptyConnection,emptyReceipt.apply_id);
 assert.equal(emptyReady.transport_ready,true);
 assert.equal(emptyReady.view.state,'live');
 assert.equal(base.sourceState(event.origin.source_key).state,'desynchronized');
 assert.deepEqual(base.sourceState(event.origin.source_key).gap_history,[wireFault.gap]);
 const items=db.prepare('SELECT cursor,body_jcs FROM subscription_reconcile_inbox WHERE apply_id=?').raw().all(emptyReceipt.apply_id);
 assert.deepEqual(items,[[1,canonical({entry_kind:'sync.ready',payload:{baseline_snapshot_id:emptyView.snapshot_ref.snapshot_id}})]]);
 const sinceEmpty=()=>store.access('binding',null,empty.binding.subscription_id).view.ack_cursor;
 function receiveEntry(cursor,entry,check=()=>{}){
  return inbox.accept(emptyReceipt,{type:'server.data',delivery_mode:'live',binding:emptyReady.view.binding,
   cursor:String(cursor),previous_cursor:String(cursor-1),entry,payload_digest:digest(entry).slice(7)},check);
 }
 assert.deepEqual(inbox.receiveCursor(),watermark(4));
 const rolledBack={entry_kind:'source.event',payload:sourceEvent(f,13,false,'9')};
 let commitCheck=0;
 assert.throws(()=>receiveEntry(2,rolledBack,()=>{if(++commitCheck===2)throw Error('event_commit_denied');}),/event_commit_denied/);
 assert.equal(inbox.sourceEvent(rolledBack.payload.origin.source_key,rolledBack.payload.origin.event_id),null);
 assert.deepEqual(inbox.receiveCursor(),watermark(4));
 const afterBaseline=sourceEvent(f,13,true,'9');
 await until(()=>sinceEmpty()==='2');
 assert.deepEqual(inbox.sourceEvent(afterBaseline.origin.source_key,afterBaseline.origin.event_id).receive_cursor,watermark(5));
 assert.deepEqual(inbox.receiveCursor(),watermark(5));
 const jumped={entry_kind:'source.event',payload:sourceEvent(f,14,false,'12')};
 assert.throws(()=>receiveEntry(3,jumped,()=>{throw Error('peer_not_current');}),/peer_not_current/);
 assert.throws(()=>receiveEntry(4,jumped),{code:'reconcile_inbox_cursor'});
 assert.throws(()=>receiveEntry(3,{...jumped,payload:{...jumped.payload,origin_digest:event.origin_digest}}),{code:'reconcile_inbox_origin'});
 assert.deepEqual(faults(),[wireFault]);
 let checksBeforeCommit=0;
 assert.throws(()=>receiveEntry(3,jumped,()=>{
  if(++checksBeforeCommit===2)throw Error('peer_changed_before_commit');
 }),/peer_changed_before_commit/);
 assert.deepEqual(faults(),[wireFault]);
 assert.throws(()=>receiveEntry(3,jumped),{code:'reconcile_inbox_source_gap'});
 const gapFault=faults().find(fault=>fault.identity.event_id===jumped.payload.origin.event_id);
 assert.equal(gapFault.identity.expected_sequence,'10');
 assert.equal(gapFault.identity.source_sequence,'12');
 assert.equal(gapFault.gap.first_missing,'10');
 assert.equal(gapFault.gap.last_missing,'11');
 assert.equal(base.sourceState(event.origin.source_key).state,'desynchronized');
 assert.equal(sinceEmpty(),'2');
 assert.equal(inbox.confirmed(emptyReceipt,'3',digest(jumped).slice(7)),false);
 assert.deepEqual(inbox.receiveCursor(),watermark(5));
 source.advance(500000000n);
 clock.refresh();
 const originals=faults();
 assert.throws(()=>receiveEntry(3,jumped),{code:'reconcile_inbox_source_gap'});
 assert.deepEqual(faults(),originals);
 const snapshotBeforeFault=selected.subscription.snapshot_ref;
 selected.subscription.snapshot_ref={...snapshotBeforeFault,snapshot_id:randomUUID()};
 assert.throws(()=>base.apply(null),{code:'snapshot_ingest_baseline_regression'});
 selected.subscription.snapshot_ref=snapshotBeforeFault;
 const gap={gap_id:randomUUID(),loss_extent:'known',first_missing:'10',last_missing:'10',resolution_state:'open'};
 const lost={...record,entity_revision:'5',view:{...record.view,state:'desynchronized',contiguous_sequence:'9',highest_seen_sequence:'10',gaps:[gap]}};
 notify(f,14,lost);
 await until(()=>sinceEmpty()==='3');
 const observedState=base.sourceState(event.origin.source_key);
 assert.equal(observedState.state,'desynchronized');
 assert.equal(observedState.highest_seen_sequence,'12');
 assert.equal(observedState.publisher_projection_revision,'5');
 assert.deepEqual(observedState.gap_history,[wireFault.gap,gap,gapFault.gap]);
 assert.deepEqual(base.confirmationReceipt(emptyReceipt.apply_id),emptyReceipt);
 const repeated={...event.origin,source_sequence:'10'};
 assert.throws(()=>receiveEntry(4,{entry_kind:'source.event',payload:{origin:repeated,origin_digest:digest(repeated)}}),
  {code:'reconcile_inbox_event_identity'});
 assert.equal(sinceEmpty(),'3');
 assert.equal(faults().length,3);
 assert.equal(faults().find(fault=>fault.identity.reason==='event_identity').gap,null);
 assert.equal(base.sourceState(event.origin.source_key).state,'quarantined');
 assert.throws(()=>db.prepare(`INSERT INTO subscription_reconcile_inbox
  SELECT ?,4,?,body_jcs,body_digest,source_key_digest,source_sequence,event_id,observation_jcs,observation_digest,
   receiver_boot_id,receiver_clock_domain_id,acquisition_id,ingest_epoch,7 FROM subscription_reconcile_inbox WHERE apply_id=? AND cursor=1`)
  .run(emptyReceipt.apply_id,emptyReady.view.binding.connection_generation,receipt.apply_id),/reconcile_receive_sequence/);
 assert.throws(()=>db.prepare(`INSERT INTO subscription_reconcile_inbox
  SELECT ?,4,?,body_jcs,body_digest,source_key_digest,source_sequence,event_id,observation_jcs,observation_digest,
   receiver_boot_id,receiver_clock_domain_id,acquisition_id,ingest_epoch,6 FROM subscription_reconcile_inbox WHERE apply_id=? AND cursor=1`)
  .run(emptyReceipt.apply_id,emptyReady.view.binding.connection_generation,receipt.apply_id),{code:'SQLITE_CONSTRAINT_UNIQUE'});
 assert.throws(()=>db.prepare(`INSERT INTO subscription_reconcile_inbox
  SELECT ?,4,?,body_jcs,body_digest,NULL,NULL,NULL,observation_jcs,observation_digest,
   receiver_boot_id,receiver_clock_domain_id,acquisition_id,ingest_epoch,6 FROM subscription_reconcile_inbox WHERE apply_id=? AND cursor=1`)
  .run(emptyReceipt.apply_id,emptyReady.view.binding.connection_generation,receipt.apply_id),{code:'SQLITE_CONSTRAINT_CHECK'});
 assert.deepEqual(inbox.sourceEvent(event.origin.source_key,event.origin.event_id),firstRecord);
 const reopened=new Database(path.join(dir,'seamer.sqlite'),{readonly:true,fileMustExist:true});
 try{
  const recovered=reconcileInbox({db:reopened,service,bootId:randomUUID(),isOpen:()=>reopened.open});
  assert.deepEqual(recovered.sourceEvent(event.origin.source_key,event.origin.event_id),firstRecord);
  assert.deepEqual(recovered.receiveCursor(),watermark(5));
  assert.equal(recovered.sourceEvent({...event.origin.source_key,source_epoch:randomUUID()},event.origin.event_id),null);
 }finally{reopened.close();}
 for(const invalid of [
  {...lost,entity_revision:'4'},
  {...lost,entity_revision:'6',view:{...lost.view,contiguous_sequence:'10'}},
  {...lost,entity_revision:'6',view:{...lost.view,state:'baseline_required'}},
  {...lost,entity_revision:'6',view:{...lost.view,gaps:[]}}
 ]){
  assert.throws(()=>receiveEntry(4,{entry_kind:'entity.upsert',payload:invalid}),{code:'reconcile_inbox_projection_update'});
  assert.equal(sinceEmpty(),'3');
 }
 const closed={...lost,entity_revision:'6',view:{...lost.view,state:'closed'}};
 notify(f,15,closed);
 await until(()=>sinceEmpty()==='4');
 assert.equal(base.sourceState(event.origin.source_key).state,'closed');
 assert.throws(()=>receiveEntry(5,{entry_kind:'source.event',payload:sourceEvent(f,16,false,'10')}),{code:'reconcile_inbox_source_closed'});
 assert.deepEqual(inbox.receiveCursor(),watermark(5));
 selected.subscription.snapshot_ref={...selected.subscription.snapshot_ref,snapshot_id:randomUUID()};
 assert.throws(()=>base.apply(null),{code:'snapshot_ingest_source_closed_or_changed'});
 assert.deepEqual(base.confirmationReceipt(emptyReceipt.apply_id),emptyReceipt);
 f.state.allowed=false;
 store.sweep();
 const state=f.db.prepare(`SELECT r.state FROM service_event_subscription_head h
  JOIN service_event_subscription_revision r USING(subscription_id,revision) WHERE h.subscription_id=?`).pluck().get(empty.binding.subscription_id);
 assert.equal(state,'revoked');
 emptyConnection.close();
});
