import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import path from 'node:path';
import {once} from 'node:events';
import {createRequire} from 'node:module';
import Database from 'better-sqlite3';
import WebSocket from 'ws';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {fixture as clockFixture} from './auth-clock-fixture.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {createAuthenticationHttp} from '../dist/auth-http.mjs';
import {createHumanEventWebsocket} from '../dist/human-event-websocket.mjs';
import {eventChannelProtocol} from '../dist/service-event-channel.mjs';
import {canonical,digest} from '../dist/auth-clock-value.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {sessionStore} from '../dist/session-store.mjs';
import {localPermissionStore} from '../dist/local-permission-store.mjs';
import {deviceEventScopeStore} from '../dist/device-event-scope.mjs';
import {deviceSourceProjectionStore} from '../dist/device-source-projection.mjs';
import {manageLocalEvents} from '../dist/local-event-management.mjs';
import {localPairingPath} from '../dist/local-pairing-admin.mjs';
import {contractSelection as selection} from '../dist/sdk/selection.mjs';

const id=()=>crypto.randomUUID();
const login={login:'status.test',password:'Synthetic-status-password-123'};

test('迁移保留身份，真实 HTTPS 和 WebSocket 人员订阅确认快照、追赶与实时投影', {timeout:90000}, async t=>{
 let cleanup,db,server,clock,humanEvents;
 const sockets=new Set();
 t.after(async()=>{
  for(const socket of sockets)socket.terminate();
  await humanEvents?.close();
  if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  clock?.stop();
  db?.close();
  await cleanup?.();
 });
 const f=await setup({after(fn){cleanup=fn;}},113);
 const enrollment=f.store.enrollment.begin();
 await f.store.enrollment.complete({token_id:enrollment.token_id,secret:enrollment.secret,...login,mode:'standalone'});
 const before=f.store.identity;
 f.close();
 const prior=inspect(f.dir,db=>({
  identity:db.prepare('SELECT * FROM identity_receipt').all(),
  migrations:db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').all()
 }));
 const migration=await migrateStorage(f.dir,114);
 assert.equal(migration.schema_revision,'114');
 assert.equal((await migrateStorage(f.dir,114)).changed,false);
 inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT * FROM identity_receipt').all(),prior.identity);
  assert.deepEqual(db.prepare("SELECT * FROM schema_migration WHERE to_revision!='114' ORDER BY CAST(to_revision AS INTEGER)").all(),prior.migrations);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 const migrated=await migrateStorage(f.dir,115);
 assert.equal(migrated.schema_revision,'115');
 const history=inspect(f.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').all());
 assert.equal((await migrateStorage(f.dir,116)).schema_revision,'116');
 assert.equal((await migrateStorage(f.dir,116)).changed,false);
 inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT * FROM identity_receipt').all(),prior.identity);
  assert.deepEqual(db.prepare("SELECT * FROM schema_migration WHERE to_revision!='116' ORDER BY CAST(to_revision AS INTEGER)").all(),history);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();
 const service=f.store.identity,bootId=f.store.serviceBootId;
 assert.deepEqual({...service,schema_revision:'113'},before);
 db=new Database(path.join(f.dir,'controller.sqlite'));
 db.pragma('foreign_keys=ON');

 // 仅在这个临时库注入装配完毕的设备来源。人员认证、范围与订阅均走产品写入器。
 const device=id(),registration_id=id(),sourceKey={authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
  registration_id,source_stream_id:id(),source_epoch:id()};
 const scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 const registration={registration_id,revision:'1',source_key:sourceKey,binding_ref:{registration_id,revision:'1',
  owner_service_id:service.service_id,database_instance_id:service.database_instance_id,provider_id:'provider',provider_boot_id:'boot',
  capture_policy_id:'policy',capture_policy_revision:'1',delivery_semantics:'discrete',
  target:{kind:'device',device_id:device,trigger_id:'changed',capability_version:'1.0.0'}},
  payload_schema_ref:{kind:'schema',scope,object_id:'schema',revision:'1',digest:'sha256:'+'a'.repeat(64)},
  canonical_delivery:'ordered_subscription'};
 const sourceParent=db.prepare("SELECT sql FROM sqlite_master WHERE name='device_event_source_parent'").pluck().get();
 db.pragma('foreign_keys=OFF');
 db.transaction(()=>{
  db.exec('DROP TRIGGER device_event_source_parent');
  db.prepare('INSERT INTO device_event_source VALUES(?,?,?,?,?,?,?,?,?)').run(registration_id,id(),id(),device,id(),id(),id(),canonical(registration),digest(registration));
  db.exec(sourceParent);
 }).immediate();
 db.pragma('foreign_keys=ON');
 const projections=deviceSourceProjectionStore(db);
 db.transaction(()=>projections.publish(registration)).immediate();
 let sourceSequence='0';
 function appendSourceEvent(sequence,publish=true){
  // 临时库模拟已接收的模块帧，保留真实日志、发布写入器与订阅约束。
  const record_id=id(),transaction=id(),event_id=id(),value={value:Number(sequence)};
  const origin={source_key:sourceKey,event_id,source_sequence:sequence,source_time_ref:null,binding_ref:registration.binding_ref,
   payload:{schema_ref:registration.payload_schema_ref,value}};
  const eventParent=db.prepare("SELECT sql FROM sqlite_master WHERE name='device_source_event_parent'").pluck().get();
  db.pragma('foreign_keys=OFF');
  try{
   db.transaction(()=>{
    db.exec('DROP TRIGGER device_source_event_parent');
    db.prepare('INSERT INTO device_source_event VALUES(?,?,?,?,?,?,?,?,?)')
     .run(record_id,registration_id,event_id,sequence,canonical(origin),digest(origin),id(),canonical({event_id,sequence,payload:value}),transaction);
    db.exec(eventParent);
    db.prepare('INSERT INTO device_source_event_outbox VALUES(?,?,?)')
     .run(record_id,transaction,canonical({record_id,origin,origin_digest:digest(origin)}));
    if(publish)projections.publish(registration,[record_id]);
    else db.prepare("INSERT INTO device_source_notification(entry_kind,registration_id,event_id,body_jcs,body_digest) VALUES('source.event',?,?,?,?)")
     .run(registration_id,record_id,canonical({origin}),digest({origin}));
   }).immediate();
  }finally{db.pragma('foreign_keys=ON');}
  sourceSequence=sequence;
 }
 const eventScopes=deviceEventScopeStore({db,service,bootId,currentSource(selected){
  assert.equal(selected,device);
  return {registration,highest_committed_sequence:sourceSequence,fault:null};
 }});

 const {ca,leaves:[tls]}=peerCertificates();
 let api;
 server=https.createServer(tls,(req,res)=>{
  if(req.url==='/ticket-test'){res.writeHead(200,{'content-type':'text/html'});res.end('<!doctype html><title>Subscription test</title>');return;}
  if(!api.handle(req,res)){res.writeHead(404);res.end();}
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const origin='https://127.0.0.1:'+server.address().port;
 const clockInputs=clockFixture(f.store.authenticationClock.scope,null,{sampleWindowPolicy:'authentication-clock-sample/2'});
 clock=startAuthenticationClock(clockInputs.source,f.store.authenticationClock,clockInputs.provider,{schedule:false});
 const domain={clock_domain_id:'clock_'+'a'.repeat(64),descriptor_digest:'sha256:'+'a'.repeat(64)};
 let tick=1n;
 const authority=localPermissionStore(db,service);
 const sessions=sessionStore(db,service.service_id,clock,authority,true,{service,bootId},null,
  {domain:()=>({ref:domain,tick:String(tick)})},null,null,null,null,null,eventScopes);
 api=createAuthenticationHttp({serviceId:service.service_id,databaseInstanceId:service.database_instance_id,serviceBootId:bootId,
  origin,sessions,localPairing:(auth,operation,request)=>manageLocalEvents(sessions,auth,operation,request)});
 humanEvents=createHumanEventWebsocket({origin,subscriptions:sessions.serviceSubscriptions,stable(){}});
 server.on('upgrade',(req,socket,head)=>{if(!humanEvents.upgrade(req,socket,head))socket.destroy();});

 function send(method,route,body,extra={}){
  const content=body===null?null:Buffer.from(canonical(body));
  return new Promise((resolve,reject)=>{
   const merged={Origin:origin,
    'X-LeafSeamer-Contract':selection.contract_id,'X-LeafSeamer-Contract-Digest':selection.contract_digest,
    ...(content&&{'Content-Type':'application/json','Content-Length':content.length}),...extra};
   const headers=Object.fromEntries(Object.entries(merged).filter(([,value])=>value!==undefined));
   const req=https.request(origin+route,{method,ca,agent:false,headers},res=>{
    const chunks=[];res.on('data',data=>chunks.push(data));
    res.once('end',()=>{const bytes=Buffer.concat(chunks);resolve({status:res.statusCode,headers:res.headers,body:bytes.length?JSON.parse(bytes):null});});
    res.once('error',reject);
   });
   req.once('error',reject);req.end(content);
  });
 }
 async function signIn(){
  const logged=await send('POST','/auth/sessions',login);
  assert.equal(logged.status,201);
  const csrf=logged.headers['x-csrf-token'],cookie=logged.headers['set-cookie'][0].split(';')[0];
  const issued=await send('POST','/auth/service-tokens',{audience:service.service_id,
   requested_scopes:['status.read','request.create'],extension_instance_id:null},{Cookie:cookie,'X-CSRF-Token':csrf});
  assert.equal(issued.status,201);
  return {logged:logged.body.data,csrf,cookie,bearer:'Bearer '+issued.body.data.access_token};
 }
 const person=await signIn(),other=await signIn();
 const endpoint='/api/v1/subscriptions';
 const admin=(operation,request)=>send('POST',localPairingPath,{operation,request},{Cookie:person.cookie,'X-CSRF-Token':person.csrf});
 const scoped=await admin('register-status-scope',{request_id:id(),device_ids:[device]});assert.equal(scoped.status,200);
 const context=async (person,operation='createSubscription',ttl_ms=30000)=>{
  const response=await send('POST','/api/v1/request-contexts',{audience:service.service_id,operations:[operation],ttl_ms,
   max_unique_requests:1,selection},{Authorization:person.bearer});
  assert.equal(response.status,201);
  return response.body.data.context_id;
 };
 const request={context_id:await context(person),idempotency_key:id(),client_instance_id:id(),purpose:'status_projection',scope:scoped.body.scope};
 const create=(body,extra={})=>send('POST',endpoint,body,{Authorization:person.bearer,'X-CSRF-Token':person.csrf,...extra});
 assert.equal((await create(request)).status,403);
 const grant={request_id:id(),scope_ref:scoped.body.scope_ref,principal_id:person.logged.principal_id,expected_revision:'0',enabled:true};
 const enabled=await admin('set-status-scope-reader',grant);assert.equal(enabled.status,200);
 assert.deepEqual((await admin('set-status-scope-reader',grant)).body,enabled.body);
 assert.equal((await create(request,{Origin:'https://foreign.invalid'})).status,403);
 assert.equal((await create(request,{'X-CSRF-Token':'A'.repeat(43)})).status,401);
 const altered={...request,scope:{...request.scope,scope_revision:'2'}};
 assert.equal((await create(altered)).status,403);
 const created=await create(request);assert.equal(created.status,202);
 assert.equal(created.body.owner.session_id,person.logged.session_id);
 assert.equal(created.body.owner.client_instance_id,request.client_instance_id);
 assert.equal(created.body.state,'building');
 assert.equal(created.body.binding.connection_generation,'0');
 const route=endpoint+'/'+created.body.binding.subscription_id;
 const get=async (actor=person)=>send('GET',route,null,{Authorization:actor.bearer});
 assert.equal((await get(other)).status,404);
 assert.throws(()=>sessions.serviceSubscriptions.access('peer',null,created.body.binding.subscription_id),{code:'subscription_not_found'});
 assert.equal((await create(altered)).status,409);
 const replay=await create(request);assert.equal(replay.status,200);assert.deepEqual(replay.body,created.body);
 for(let step=0;step<4;step++)sessions.serviceSubscriptions.sweep();
 const ready=await get();assert.equal(ready.status,200);assert.equal(ready.body.state,'snapshot_ready');
 assert.ok(ready.body.snapshot_ref);

 const ticketInput=async (subscription,ttl)=>({
  context_id:await context(person,'issueWsTicket',ttl),idempotency_key:id(),subscription_id:subscription.binding.subscription_id,
  expected_authorization_revision:subscription.binding.authorization_revision,scope_digest:subscription.binding.scope_digest,
  client_instance_id:subscription.owner.client_instance_id,origin,selection});
 const issue=(input,actor=person)=>send('POST','/api/v1/ws-tickets',input,{Authorization:actor.bearer,'X-CSRF-Token':actor.csrf});
 const ticketPath=origin.replace(/^https:/,'wss:')+'/api/v1/events';
 const protocolsFor=ticket=>[eventChannelProtocol,'leafseamer.ticket.'+ticket];
 function connect(protocols,requestOrigin=origin){
  const socket=new WebSocket(ticketPath,protocols,{ca,origin:requestOrigin,handshakeTimeout:3000,perMessageDeflate:false});
  sockets.add(socket);socket.on('error',()=>{});socket.once('close',()=>sockets.delete(socket));
  return socket;
 }
 function rejectedUpgrade(protocols,requestOrigin=origin){
  return new Promise((resolve,reject)=>{
   const socket=connect(protocols,requestOrigin);
   socket.once('open',()=>{socket.terminate();reject(Error('意外接受 WebSocket 升级'));});
   socket.once('unexpected-response',(_request,res)=>{
    res.resume();res.once('end',()=>{resolve(res.statusCode);socket.terminate();});
   });
   socket.once('error',error=>reject(Error('WebSocket 握手未返回拒绝响应',{cause:error.code})));
  });
 }
 async function open(issued){
  const socket=connect(protocolsFor(issued.ticket));
  const message=once(socket,'message');
  await once(socket,'open');assert.equal(socket.protocol,eventChannelProtocol);
  const [bytes]=await message;
  assert.deepEqual(JSON.parse(bytes),{type:'contract.ready',channel:issued.binding.channel});
  return socket;
 }
 function attachment(subscription,generation,replace_existing=false){
  return {schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:subscription.binding.subscription_id,
   owner:subscription.owner,stream_id:subscription.binding.stream_id,stream_epoch:subscription.binding.stream_epoch,
   scope_digest:subscription.binding.scope_digest,authorization_revision:subscription.binding.authorization_revision,
   expected_connection_generation:generation,replace_existing,resume:null,connection_attempt_id:id()};
 }
 async function attach(socket,input){
  const replied=frame(socket);socket.send(JSON.stringify(input));return replied;
 }
 async function frame(socket){
  const [bytes]=await once(socket,'message',{signal:AbortSignal.timeout(5000)});
  return JSON.parse(bytes);
 }
 const manifest=generation=>send('GET',route+'/snapshot?expected_connection_generation='+generation,null,{Authorization:person.bearer});
 const attempt=attemptId=>send('GET',route+'/connections/'+attemptId,null,{Authorization:person.bearer});
 assert.equal((await manifest('0')).status,412);
 const firstInput=await ticketInput(ready.body);
 assert.equal((await issue(firstInput,other)).status,404);
 assert.equal((await issue({...firstInput,scope_digest:'b'.repeat(64)})).status,412);
 const firstTicket=await issue(firstInput);assert.equal(firstTicket.status,201);
 assert.equal(typeof firstTicket.body.ticket,'string');
 const firstReplay=await issue(firstInput);assert.equal(firstReplay.status,200);
 assert.equal(Object.hasOwn(firstReplay.body,'ticket'),false);
 assert.equal(firstReplay.body.consumed,false);
 assert.equal(await rejectedUpgrade(protocolsFor(firstTicket.body.ticket),'https://outside.invalid'),400);
 assert.equal(await rejectedUpgrade(['leafseamer.contract.wrong',protocolsFor(firstTicket.body.ticket)[1]]),400);
 assert.equal(db.prepare('SELECT count(*) FROM human_event_ticket_consumption').pluck().get(),0);
 const firstSocket=await open(firstTicket.body);
 assert.equal((await issue(firstInput)).body.consumed,true);
 assert.equal(await rejectedUpgrade(protocolsFor(firstTicket.body.ticket)),403);
 const firstAttempt=attachment(ready.body,'0');
 const firstAttached=await attach(firstSocket,firstAttempt);
 assert.equal(firstAttached.type,'server.attached');assert.equal(firstAttached.binding.connection_generation,'1');
 assert.deepEqual((await attempt(firstAttempt.connection_attempt_id)).body.attached,firstAttached);
 const firstManifest=await manifest('1');assert.equal(firstManifest.status,200);
 assert.equal(firstManifest.body.binding.snapshot_id,ready.body.snapshot_ref.snapshot_id);
 const pageRoute=route+'/snapshots/'+firstManifest.body.binding.snapshot_id+'/pages/0?expected_connection_generation=1';
 const page=await send('GET',pageRoute,null,{Authorization:person.bearer,Origin:undefined,'Sec-Fetch-Site':'same-origin'});
 assert.equal(page.status,200);assert.equal(page.body.delivery_binding.connection_generation,'1');
 assert.equal(page.body.content_digest,firstManifest.body.pages[0].content_digest);
 assert.equal(page.headers['cache-control'],'no-store');
 assert.equal((await send('GET',pageRoute,null,{Authorization:other.bearer})).status,404);

 const shortInput=await ticketInput(ready.body,1500),shortTicket=await issue(shortInput);assert.equal(shortTicket.status,201);
 const saved=db.prepare('SELECT binding_jcs FROM human_event_ticket WHERE ticket_id=?').pluck().get(shortTicket.body.binding.channel.binding_id);
 tick=BigInt(JSON.parse(saved).deadline_tick);
 assert.equal(await rejectedUpgrade(protocolsFor(shortTicket.body.ticket)),403);
 assert.equal((await issue(shortInput)).body.consumed,false);
 const wrongTicket=await issue(await ticketInput(ready.body));assert.equal(wrongTicket.status,201);
 const wrongSocket=await open(wrongTicket.body),wrongClosed=once(wrongSocket,'close');
 wrongSocket.send(JSON.stringify({...attachment(ready.body,'1',true),subscription_id:id()}));await wrongClosed;
 const secondTicket=await issue(await ticketInput(ready.body));assert.equal(secondTicket.status,201);
 const secondSocket=await open(secondTicket.body),secondAttempt=attachment(ready.body,'1',true);
 assert.equal((await attach(secondSocket,secondAttempt)).binding.connection_generation,'2');
 assert.equal((await attempt(firstAttempt.connection_attempt_id)).body.current,false);
 assert.equal((await attempt(secondAttempt.connection_attempt_id)).body.current,true);
 assert.equal((await manifest('1')).status,412);
 assert.deepEqual((await manifest('2')).body,firstManifest.body);
 const firstClosed=once(firstSocket,'close');humanEvents.sweep();await firstClosed;

 const secondClosed=once(secondSocket,'close');
 let browserAttached=false;
 if(process.env.LEAFSEAMER_GUI_PLAYWRIGHT&&process.env.LEAFSEAMER_GUI_BROWSER){
  const rendererTicket=await issue(await ticketInput(ready.body));assert.equal(rendererTicket.status,201);
  const {chromium}=createRequire(import.meta.url)(process.env.LEAFSEAMER_GUI_PLAYWRIGHT);
  const spki=crypto.createHash('sha256').update(new crypto.X509Certificate(tls.cert).publicKey.export({type:'spki',format:'der'})).digest('base64');
  const browser=await chromium.launch({executablePath:process.env.LEAFSEAMER_GUI_BROWSER,headless:true,args:['--ignore-certificate-errors-spki-list='+spki]});
  try{
   const page=await browser.newPage();
   assert.equal((await page.goto(origin+'/ticket-test')).status(),200);
   const result=await page.evaluate(async ({ticketPath,protocols,input,route,headers})=>{
    const socket=new WebSocket(ticketPath,protocols);
    const next=()=>new Promise((resolve,reject)=>{
     const timer=setTimeout(()=>reject(Error('WebSocket 帧超时')),5000);
     socket.addEventListener('message',event=>{clearTimeout(timer);resolve(JSON.parse(event.data));},{once:true});
     socket.addEventListener('error',()=>{clearTimeout(timer);reject(Error('WebSocket 连接失败'));},{once:true});
    });
    const ready=await next(),response=next();socket.send(JSON.stringify(input));const attached=await response;
    const generation=attached.binding.connection_generation;
    const fixed=await fetch(route+'/snapshot?expected_connection_generation='+generation,{headers});
    if(fixed.status!==200)throw Error('浏览器快照清单状态 '+fixed.status);
    const manifest=await fixed.json();
    const page=await fetch(route+'/snapshots/'+manifest.binding.snapshot_id+'/pages/0?expected_connection_generation='+generation,{headers});
    if(page.status!==200)throw Error('浏览器快照页面状态 '+page.status);
    socket.close();
    return {ready,attached,protocol:socket.protocol,page:await page.json()};
   },{ticketPath,protocols:protocolsFor(rendererTicket.body.ticket),input:attachment(ready.body,'2',true),route,
    headers:{Authorization:person.bearer,'X-LeafSeamer-Contract':selection.contract_id,'X-LeafSeamer-Contract-Digest':selection.contract_digest}});
   assert.equal(result.protocol,eventChannelProtocol);
   assert.deepEqual(result.ready,{type:'contract.ready',channel:rendererTicket.body.binding.channel});
   assert.equal(result.attached.binding.connection_generation,'3');
   assert.equal(result.page.delivery_binding.connection_generation,'3');
   assert.equal(result.page.content_digest,firstManifest.body.pages[0].content_digest);
   browserAttached=true;t.diagnostic('Edge 原生 WebSocket 与同源快照清单、分页读取通过');
  }finally{await browser.close();}
 }

 const projectionTicket=await issue(await ticketInput(ready.body));assert.equal(projectionTicket.status,201);
 const projectionSocket=await open(projectionTicket.body);
 const generation=browserAttached?'3':'2';
 const fixed=await attach(projectionSocket,attachment(ready.body,generation,true));
 const baselineGeneration=String(Number(generation)+1);
 assert.equal(fixed.binding.connection_generation,baselineGeneration);
 assert.deepEqual((await manifest(baselineGeneration)).body,firstManifest.body);

 appendSourceEvent('1');
 appendSourceEvent('2',false);
 const key=created.body.binding.subscription_id;
 const deliveries=()=>db.prepare('SELECT journal_sequence,body_jcs FROM service_subscription_delivery WHERE subscription_id=? ORDER BY cursor').raw().all(key);
 const start=await attach(projectionSocket,{schema_version:fixed.schema_version,type:'client.snapshot.applied',binding:fixed.binding,snapshot:fixed.snapshot_ref});
 const ack=(message,binding=message.binding)=>({schema_version:fixed.schema_version,type:'client.ack',binding,
  ack_kind:'projection_applied',cursor:message.cursor,payload_digest:message.payload_digest});
 function assertProjection(message,mode,cursor,sequence,binding=fixed.binding){
  assert.equal(message.type,'server.data');assert.equal(message.delivery_mode,mode);assert.equal(message.cursor,cursor);
  assert.equal(message.previous_cursor,String(Number(cursor)-1));assert.deepEqual(message.binding,binding);
  assert.equal(message.entry.entry_kind,'entity.upsert');
  assert.equal(message.entry.payload.entity_id,registration_id);
  assert.equal(message.entry.payload.view.contiguous_sequence,sequence);
  assert.equal(digest(message.entry).slice(7),message.payload_digest);
 }
 assertProjection(start,'reconcile','1','1');
 const catchingUp=(await get()).body;
 assert.equal(catchingUp.state,'catching_up');assert.equal(catchingUp.ack_cursor,'0');
 assert.deepEqual(deliveries().map(([sequence])=>sequence),[3]);
 const tail=db.prepare("SELECT sequence,body_jcs FROM device_source_notification WHERE sequence=4 AND entry_kind='source.event'").get();
 const rawOrigin=JSON.parse(tail.body_jcs).origin;
 const forbidden={entry_kind:'source.event',payload:{origin:rawOrigin,origin_digest:digest(rawOrigin)}};
 assert.throws(()=>db.prepare('INSERT INTO service_subscription_delivery VALUES(?,?,?,?,?,NULL)')
  .run(key,2,tail.sequence,canonical(forbidden),digest(forbidden)),/reconcile_delivery_parent/);
 const checkpoint=await attach(projectionSocket,ack(start));
 assert.equal(checkpoint.type,'server.sync.ready');assert.equal(checkpoint.cursor,'2');
 assert.equal(checkpoint.baseline_snapshot_id,fixed.snapshot_ref.snapshot_id);
 assert.equal((await get()).body.state,'catching_up');
 const awaitCursor=async (cursor,state)=>{
  for(let count=0;count<20;count++){
   const {body}=await get();
   if(body.ack_cursor===cursor){assert.equal(body.state,state);return body;}
  }
  assert.fail('未持久确认游标 '+cursor);
 };
 projectionSocket.send(JSON.stringify(ack(checkpoint)));
 const live=await awaitCursor('2','live');
 db.transaction(()=>projections.publish(registration)).immediate();
 const liveFrame=frame(projectionSocket);humanEvents.sweep();
 const delta=await liveFrame;
 assertProjection(delta,'live','3','2');
 assert.equal((await get()).body.ack_cursor,'2');

 const stopped=once(projectionSocket,'close');
 projectionSocket.close();await stopped;
 const resumeTicket=await issue(await ticketInput(live));assert.equal(resumeTicket.status,201);
 const resumedSocket=await open(resumeTicket.body);
 const replayed=new Promise((resolve,reject)=>{
  const messages=[],timer=setTimeout(()=>reject(Error('WebSocket 恢复帧超时')),5000);
  resumedSocket.on('message',function collect(bytes){
   messages.push(JSON.parse(bytes));
   if(messages.length===2){clearTimeout(timer);resumedSocket.off('message',collect);resolve(messages);}
  });
 });
 resumedSocket.send(JSON.stringify({...attachment(live,baselineGeneration,true),
  resume:{ack_kind:'projection_applied',cursor:live.ack_cursor,payload_digest:live.ack_payload_digest}}));
 const [resumed,replayedDelta]=await replayed;
 assert.equal(resumed.type,'server.attached');assert.equal(resumed.state,'catching_up');
 assert.equal(resumed.binding.connection_generation,String(Number(baselineGeneration)+1));
 assertProjection(replayedDelta,'reconcile','3','2',resumed.binding);
 assert.equal(replayedDelta.payload_digest,delta.payload_digest);
 const newCheckpoint=await attach(resumedSocket,ack(replayedDelta));
 assert.equal(newCheckpoint.type,'server.sync.ready');assert.equal(newCheckpoint.cursor,'4');
 const stale=once(resumedSocket,'close');
 resumedSocket.send(JSON.stringify(ack(newCheckpoint,fixed.binding)));await stale;
 assert.equal((await get()).body.ack_cursor,'3');
 assert.deepEqual(deliveries().map(([sequence,body])=>[sequence,JSON.parse(body).entry_kind]),
  [[3,'entity.upsert'],[null,'sync.ready'],[5,'entity.upsert'],[null,'sync.ready']]);

 const close=(revision,csrf=person.csrf)=>send('DELETE',route+'?expected_revision='+revision,null,
  {Authorization:person.bearer,'X-CSRF-Token':csrf});
 const finalRevision=(await get()).body.revision;
 assert.equal((await close('1')).status,409);
 assert.equal((await close(finalRevision,'A'.repeat(43))).status,401);
 const closed=await close(finalRevision);assert.equal(closed.status,200);assert.equal(closed.body.state,'closed');
 assert.deepEqual((await close(finalRevision)).body,closed.body);
 humanEvents.sweep();await secondClosed;
 assert.deepEqual((await create(request)).body,closed.body);
 assert.equal((await create({...request,idempotency_key:id()})).status,429);

 const another={...request,context_id:await context(person),idempotency_key:id()};
 const second=await create(another);assert.equal(second.status,202);
 const revokedTicket=await issue(await ticketInput(second.body));assert.equal(revokedTicket.status,201);
 const revokedSocket=await open(revokedTicket.body);
 assert.equal((await attach(revokedSocket,attachment(second.body,'0'))).binding.connection_generation,'1');
 const disable={...grant,request_id:id(),expected_revision:'1',enabled:false};
 assert.equal((await admin('set-status-scope-reader',disable)).status,200);
 const revokedClosed=once(revokedSocket,'close');sessions.serviceSubscriptions.sweep();humanEvents.sweep();await revokedClosed;
 const denied=await send('GET',endpoint+'/'+second.body.binding.subscription_id,null,{Authorization:person.bearer});
 assert.equal(denied.status,403);
 assert.equal(db.prepare('SELECT used_count FROM request_context WHERE context_id=?').pluck().get(request.context_id),1);
 assert.deepEqual(db.prepare('SELECT state FROM service_event_subscription_revision ORDER BY rowid').pluck().all(),
  ['building','snapshot_ready','snapshot_ready','snapshot_ready',...(browserAttached?['snapshot_ready']:[]),'snapshot_ready',
   'catching_up','catching_up','live','catching_up','catching_up','closed','building','building','revoked']);
 assert.deepEqual(db.pragma('foreign_key_check').map(row=>row.table).sort(),
  ['device_event_source','device_event_source','device_event_source','device_source_event','device_source_event']);
});
