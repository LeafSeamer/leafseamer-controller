import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import {createBrowserSessionClient,createClient,contractSelection} from '@leafseamer/sdk';
import {createAuthenticationHttp} from '../dist/auth-http.mjs';
import {createIntrospectionEndpoint} from '../dist/introspection-http.mjs';
import {browserFetch} from './https-auth-fixture.mjs';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {startPeerPairingTransport} from '../dist/peer-pairing-transport.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {digest,ref} from '../dist/auth-clock-value.mjs';
const id=()=>crypto.randomUUID();
async function fixture(t,{inject=null,introspection=false}={}){
 const files=[await setup(t,introspection?61:60),await setup(t,introspection?61:60)],certificates=peerCertificates();
 for(const f of files){const e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});}
 if(inject){files[0].close();inspect(files[0].dir,db=>db.exec(inject));files[0].reopen();}
 const peers=[];
 for(let i=0;i<2;i++){
  const f=files[i],auth=await authenticated(t,f,{grant:false,native:{source:openNativeClock(),descriptor:{clock_domain_id:id(),descriptor_digest:digest('synthetic-remote-policy-domain')}},sampleWindowPolicy:'authentication-clock-sample/2'});
  const identity={service_id:f.store.identity.service_id,database_instance_id:f.store.identity.database_instance_id,service_kind:'controller',issuer_id:auth.logged.session.issuer_id,issuer_epoch:auth.logged.session.issuer_epoch,credential_id:id()};
  const endpoint=introspection?createIntrospectionEndpoint({sessions:auth.sessions,serviceId:identity.service_id,serviceBootId:f.store.serviceBootId}):null;
  const transport=await startPeerPairingTransport({pairings:auth.sessions.peerPairings,clock:auth.real,identity,...certificates.leaves[i],ca:certificates.ca,introspection:endpoint});t.after(()=>transport.close());peers.push({...auth,f,identity,transport,material:certificates.leaves[i]});
 }
 const [a,b]=peers;
 for(const [p,other]of [[a,b],[b,a]])p.transport.bindPeers([{identity:other.identity,cert:other.material.cert,origin:other.transport.origin,server_name:'127.0.0.1',trust_bundle_digest:other.transport.configuration.trust_bundle_digest}]);
 const begin=BigInt(a.real.current().lower_ns)-1000000000n,end=begin+120000000000n;
 const parties=peers.map(p=>({...p.transport.configuration,binding_id:id(),permissions:['auth.introspect'],object_scope_digest:digest({identity:true}),not_before_ns:String(begin),expires_ns:String(end)}));
 const transcript={format:'leafseamer.peer-pairing/1',pair_attempt_id:id(),parties},staged=peers.map(p=>p.sessions.peerPairings.stage(p.auth,{request_id:id(),transcript}));
 const reference=v=>({id:v.binding_id,revision:v.revision,digest:v.digest});
 const request={request_id:id(),principal_id:a.logged.session.principal_id,audience:b.identity.service_id,pairing_ref:reference(staged[0]),expected_revision:null,permissions:['auth.manage','auth.read'],not_before_ns:String(begin),expires_ns:String(end)};
 async function activate(){
  await a.transport.prove(staged[0].binding_id);await b.transport.prove(staged[1].binding_id);
  return peers.map((p,i)=>{const record=p.sessions.peerPairings.get(p.auth,staged[i].binding_id);return p.sessions.peerPairings.activate(p.auth,{request_id:id(),binding_id:record.binding_id,expected_revision:record.revision,transcript_digest:record.transcript_digest});});
 }
 const issue=(scopes=['auth.read'])=>a.sessions.issueToken(a.auth,{request_id:id(),audience:request.audience,requested_scopes:scopes});
 return {a,b,request,reference,activate,issue,ca:certificates.ca,staged};
}

test('真实配对后显式远端授权才签发定向人员令牌，减权与注销保持目标记录', {timeout:90000},async t=>{
 const {a,b,request,reference,activate,issue,ca}=await fixture(t),api=a.sessions.remotePermissions;
 assert.equal(api.get(a.auth,request.principal_id,request.audience),null);
 assert.throws(()=>issue(),{code:'remote_authorization_missing'});
 assert.throws(()=>api.replace(a.auth,request),{code:'peer_pairing_activation'});
 const active=await activate();request.pairing_ref=reference(active[0]);
 for(const permissions of [['auth.read\n'],['auth.read','auth.read']])assert.throws(()=>api.replace(a.auth,{...request,permissions}),{code:'remote_authorization_request'});
 assert.throws(()=>api.replace(a.auth,{...request,request_id:request.request_id+'\n'}),{code:'remote_authorization_request'});
 const op=api.replace(a.auth,request);assert.deepEqual(api.replace(a.auth,request),op);assert.equal(op.propagation,'pending');
 assert.throws(()=>api.replace(a.auth,{...request,permissions:['auth.read']}),{code:'remote_authorization_conflict'});
 const grant=api.get(a.auth,request.principal_id,request.audience);assert.deepEqual(ref(grant),op.current_ref);
 let handler;const publicServer=https.createServer({...a.material,minVersion:'TLSv1.3'},(req,res)=>{if(!handler.handle(req,res)){res.writeHead(404);res.end();}});
 await new Promise(resolve=>publicServer.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>{publicServer.close(resolve);publicServer.closeAllConnections();}));
 const origin='https://127.0.0.1:'+publicServer.address().port;
 handler=createAuthenticationHttp({serviceId:a.identity.service_id,databaseInstanceId:a.identity.database_instance_id,serviceBootId:a.f.store.serviceBootId,sessions:a.sessions,origin});
 const browser=browserFetch(ca),client=createBrowserSessionClient({baseUrl:origin,fetchImpl:browser.fetchImpl});
 assert.equal((await client.login({login:'role.test',password:'Synthetic-role-password-123'})).status,'201');
 const remote=await client.issueToken({audience:request.audience,requested_scopes:['auth.read']});
 assert.equal(remote.status,'201');assert.equal(remote.body.data.audience,request.audience);
 const [version,token_id,tokenSecret]=remote.body.data.access_token.split('.');assert.equal(version,'v1');
 assert.equal(a.sessions.verifyToken({token_id,secret:tokenSecret},request.audience).active,true);
 assert.throws(()=>issue(['device.command']),{code:'remote_authorization_denied'});
 const issued=issue(),secret={token_id:issued.token.token_id,secret:issued.secret};
 assert.equal(a.sessions.verifyToken(secret,request.audience).principal_id,request.principal_id);
 assert.throws(()=>a.sessions.verifyToken(secret,a.identity.service_id),{code:'token_invalid'});
 assert.equal(a.sessions.verifyToken(a.token(['auth.read']),a.identity.service_id).active,true);
 const reduced=api.replace(a.auth,{...request,request_id:id(),expected_revision:grant.revision,permissions:['auth.read']});
 assert.equal(reduced.reduced,true);assert.equal(reduced.propagation,'pending');assert.deepEqual(reduced.target_service_ids,[b.identity.service_id]);
 assert.equal(api.get(a.auth,request.principal_id,request.audience).state,'pending');
 assert.throws(()=>a.sessions.verifyToken(secret,request.audience),{code:'token_invalid'});assert.throws(()=>issue(),{code:'remote_authorization_missing'});
 assert.throws(()=>a.sessions.verifyToken({token_id,secret:tokenSecret},request.audience),{code:'token_invalid'});
 const logout=a.sessions.logout(a.auth);assert.ok(logout.propagation.target_service_ids.includes(request.audience));
 a.real.stop();a.f.close();inspect(a.f.dir,db=>{
  assert.equal(db.prepare('SELECT count(*) FROM remote_permission_revision').pluck().get(),2);
  assert.equal(db.prepare('SELECT count(*) FROM remote_permission_outbox').pluck().get(),2);assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.throws(()=>db.prepare('DELETE FROM remote_permission_outbox').run(),/immutable_remote_permission/);
 });
});

test('远端授权通知写入失败与事务末尾失效均回滚；配对撤销立即阻断旧令牌', {timeout:90000},async t=>{
 const failure=id(),f=await fixture(t,{inject:"CREATE TRIGGER test_remote_notification BEFORE INSERT ON remote_permission_outbox WHEN NEW.operation_id='"+failure+"' BEGIN SELECT RAISE(IGNORE); END;"});
 const {a,request,reference,activate,issue}=f,active=await activate();request.pairing_ref=reference(active[0]);
 assert.throws(()=>a.sessions.remotePermissions.replace(a.auth,{...request,request_id:failure}),{code:'remote_authorization_storage'});
 assert.equal(a.sessions.remotePermissions.get(a.auth,request.principal_id,request.audience),null);
 let reads=0;a.state.onRead=()=>{if(++reads===2)a.state.offset=400000000000n;};
 assert.throws(()=>a.sessions.remotePermissions.replace(a.auth,request));a.state.onRead=null;a.state.offset=0n;
 assert.equal(a.sessions.remotePermissions.get(a.auth,request.principal_id,request.audience),null);
 a.sessions.remotePermissions.replace(a.auth,request);const issued=issue(),secret={token_id:issued.token.token_id,secret:issued.secret};
 a.sessions.peerPairings.revoke(a.auth,{request_id:id(),binding_id:active[0].binding_id,expected_revision:active[0].revision});
 assert.throws(()=>a.sessions.verifyToken(secret,request.audience),{code:'peer_pairing_state'});assert.throws(()=>issue(),{code:'peer_pairing_state'});
});

test('59到61逐步迁移保留人员会话，不自动授予远端权限并建立水位基线', {timeout:60000},async t=>{
 const f=await setup(t,59),e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const a=await authenticated(t,f,{grant:false});a.real.stop();f.close();let original;
 inspect(f.dir,db=>{original=db.prepare('SELECT session_id,principal_id,state FROM auth_session').raw().all();});
 const migrated=await migrateStorage(f.dir,60);assert.equal(migrated.schema_revision,'60');f.reopen();assert.equal(f.store.identity.schema_revision,'60');f.close();
 inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT session_id,principal_id,state FROM auth_session').raw().all(),original);assert.equal(db.prepare('SELECT count(*) FROM remote_permission_revision').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
 assert.equal((await migrateStorage(f.dir,61)).schema_revision,'61');f.reopen();assert.equal(f.store.identity.schema_revision,'61');f.close();
 inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT session_id,principal_id,state FROM auth_session').raw().all(),original);assert.equal(db.prepare('SELECT revision FROM issuer_authorization_watermark').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});

test('配对后实际TLS核验返回真实会话近期认证和持久水位，拒绝pending、错audience和未来修订', {timeout:90000},async t=>{
 const failure=id(),f=await fixture(t,{introspection:true,inject:"CREATE TRIGGER test_introspection_rollback BEFORE INSERT ON remote_permission_outbox WHEN NEW.operation_id='"+failure+"' BEGIN SELECT RAISE(IGNORE); END;"});
 const {a,b,request,reference,activate,issue,staged}=f;
 const client=createClient('controller',contractSelection,packet=>b.transport.exchangeIntrospection(staged[1].binding_id,packet));
 const query=body=>client.call('introspect',{headers:{'x-leafseamer-pairing':staged[0].binding_id},body});
 const input={token:'v1.'+id()+'.'+'A'.repeat(43),audience:b.identity.service_id,challenge_id:id(),required_revision:'1'};
 await assert.rejects(query(input));
 const active=await activate();request.pairing_ref=reference(active[0]);a.sessions.remotePermissions.replace(a.auth,request);
 const token=issue();input.token='v1.'+token.token.token_id+'.'+token.secret;
 assert.throws(()=>a.sessions.introspectToken(staged[0].binding_id,{},input),{code:'peer_pairing_tls'});
 const first=await query(input);assert.equal(first.status,'200');const value=first.body.data;assert.equal(value.active,true);
 assert.equal(value.snapshot.challenge_id,input.challenge_id);assert.equal(value.snapshot.audience,b.identity.service_id);assert.equal(value.snapshot.principal_id,a.logged.session.principal_id);
 assert.equal(value.recent_authentication.session_id,a.logged.session.session_id);assert.equal(value.recent_authentication.session_revision,a.logged.session.revision);
 assert.equal(value.recent_authentication.expires_at,new Date(Number(BigInt(a.logged.session.recent_before_ns)/1000000n)).toISOString());
 assert.ok(BigInt(value.snapshot.issuer_revision)>1n);assert.equal(value.snapshot.fresh_for_ms,2000);
 assert.equal((await query({...input,audience:a.identity.service_id})).status,'403');
 assert.equal((await query({...input,required_revision:String(BigInt(value.snapshot.issuer_revision)+1n)})).status,'409');
 const grant=a.sessions.remotePermissions.get(a.auth,request.principal_id,request.audience);
 assert.throws(()=>a.sessions.remotePermissions.replace(a.auth,{...request,request_id:failure,expected_revision:grant.revision,permissions:[]}),{code:'remote_authorization_storage'});
 const next=await query({...input,challenge_id:id()});assert.equal(next.body.data.snapshot.issuer_revision,value.snapshot.issuer_revision);
 assert.notEqual(next.body.data.snapshot.challenge_id,input.challenge_id);assert.notEqual(next.body.data.snapshot.snapshot_id,value.snapshot.snapshot_id);
 assert.deepEqual((await query({...input,token:input.token.slice(0,-1)+(input.token.endsWith('A')?'B':'A')})).body.data,{active:false,snapshot:null,recent_authentication:null});
 a.sessions.logout(a.auth);assert.deepEqual((await query(input)).body.data,{active:false,snapshot:null,recent_authentication:null});
 a.real.stop();a.f.close();inspect(a.f.dir,db=>{
  const current=()=>db.prepare('SELECT CAST(revision AS TEXT) FROM issuer_authorization_watermark').pluck().get();
  const saved=current();assert.ok(BigInt(saved)>BigInt(value.snapshot.issuer_revision));
  assert.throws(()=>db.exec('UPDATE issuer_authorization_watermark SET revision=1'),/issuer_revision_order/);
  assert.throws(()=>db.exec('UPDATE auth_session SET idle_before_ns=idle_before_ns'),/invalid_session_transition/);
  assert.equal(current(),saved);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
