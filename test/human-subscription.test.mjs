import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import path from 'node:path';
import {once} from 'node:events';
import Database from 'better-sqlite3';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {fixture as clockFixture} from './auth-clock-fixture.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {createAuthenticationHttp} from '../dist/auth-http.mjs';
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

test('113 到 114 保留非空身份及迁移历史，真实 HTTPS 人员订阅按范围授权和生命周期校验', {timeout:90000}, async t=>{
 let cleanup,db,server,clock;
 t.after(async()=>{
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
 f.reopen();
 const service=f.store.identity,bootId=f.store.serviceBootId;
 assert.deepEqual({...service,schema_revision:'113'},before);
 db=new Database(path.join(f.dir,'controller.sqlite'));
 db.pragma('foreign_keys=ON');

 // 仅在这个临时库注入装配完毕的设备来源。人员认证、范围与订阅均走产品写入器。
 const device=id(),registration_id=id(),sourceKey={authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
  registration_id,source_stream_id:id(),source_epoch:id()};
 const registration={registration_id,revision:'1',source_key:sourceKey,binding_ref:{revision:'1',target:{kind:'device',device_id:device}},
  canonical_delivery:'ordered_subscription'};
 const sourceParent=db.prepare("SELECT sql FROM sqlite_master WHERE name='device_event_source_parent'").pluck().get();
 db.pragma('foreign_keys=OFF');
 db.transaction(()=>{
  db.exec('DROP TRIGGER device_event_source_parent');
  db.prepare('INSERT INTO device_event_source VALUES(?,?,?,?,?,?,?,?,?)').run(registration_id,id(),id(),device,id(),id(),id(),canonical(registration),digest(registration));
  db.exec(sourceParent);
 }).immediate();
 db.pragma('foreign_keys=ON');
 db.transaction(()=>deviceSourceProjectionStore(db).publish(registration)).immediate();
 const eventScopes=deviceEventScopeStore({db,service,bootId,currentSource(selected){
  assert.equal(selected,device);
  return {registration,highest_committed_sequence:'0',fault:null};
 }});

 const {ca,leaves:[tls]}=peerCertificates();
 let api;
 server=https.createServer(tls,(req,res)=>{if(!api.handle(req,res)){res.writeHead(404);res.end();}});
 server.listen(0,'127.0.0.1');await once(server,'listening');
 const origin='https://127.0.0.1:'+server.address().port;
 const clockInputs=clockFixture(f.store.authenticationClock.scope,null,{sampleWindowPolicy:'authentication-clock-sample/2'});
 clock=startAuthenticationClock(clockInputs.source,f.store.authenticationClock,clockInputs.provider,{schedule:false});
 const domain={clock_domain_id:'clock_'+'a'.repeat(64),descriptor_digest:'sha256:'+'a'.repeat(64)};
 const authority=localPermissionStore(db,service);
 const sessions=sessionStore(db,service.service_id,clock,authority,true,{service,bootId},null,
  {domain:()=>({ref:domain,tick:'1'})},null,null,null,null,null,eventScopes);
 api=createAuthenticationHttp({serviceId:service.service_id,databaseInstanceId:service.database_instance_id,serviceBootId:bootId,
  origin,sessions,localPairing:(auth,operation,request)=>manageLocalEvents(sessions,auth,operation,request)});

 function send(method,route,body,extra={}){
  const content=body===null?null:Buffer.from(canonical(body));
  return new Promise((resolve,reject)=>{
   const req=https.request(origin+route,{method,ca,agent:false,headers:{Origin:origin,
    'X-LeafSeamer-Contract':selection.contract_id,'X-LeafSeamer-Contract-Digest':selection.contract_digest,
    ...(content&&{'Content-Type':'application/json','Content-Length':content.length}),...extra}},res=>{
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
 const context=async person=>{
  const response=await send('POST','/api/v1/request-contexts',{audience:service.service_id,operations:['createSubscription'],ttl_ms:30000,
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
 const close=(revision,csrf=person.csrf)=>send('DELETE',route+'?expected_revision='+revision,null,
  {Authorization:person.bearer,'X-CSRF-Token':csrf});
 assert.equal((await close('1')).status,409);
 assert.equal((await close(ready.body.revision,'A'.repeat(43))).status,401);
 const closed=await close(ready.body.revision);assert.equal(closed.status,200);assert.equal(closed.body.state,'closed');
 assert.deepEqual((await close(ready.body.revision)).body,closed.body);
 assert.deepEqual((await create(request)).body,closed.body);
 assert.equal((await create({...request,idempotency_key:id()})).status,429);

 const another={...request,context_id:await context(person),idempotency_key:id()};
 const second=await create(another);assert.equal(second.status,202);
 const disable={...grant,request_id:id(),expected_revision:'1',enabled:false};
 assert.equal((await admin('set-status-scope-reader',disable)).status,200);
 sessions.serviceSubscriptions.sweep();
 const denied=await send('GET',endpoint+'/'+second.body.binding.subscription_id,null,{Authorization:person.bearer});
 assert.equal(denied.status,403);
 assert.equal(db.prepare('SELECT used_count FROM request_context WHERE context_id=?').pluck().get(request.context_id),1);
 assert.deepEqual(db.prepare('SELECT state FROM service_event_subscription_revision ORDER BY rowid').pluck().all(),
  ['building','snapshot_ready','closed','building','revoked']);
 assert.deepEqual(db.pragma('foreign_key_check').map(row=>row.table),['device_event_source','device_event_source','device_event_source']);
});
