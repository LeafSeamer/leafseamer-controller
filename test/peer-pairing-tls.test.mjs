import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import https from 'node:https';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {startPeerPairingTransport} from '../dist/peer-pairing-transport.mjs';
import {digest,canonical} from '../dist/auth-clock-value.mjs';
import {verifyFirstPairingAuthorization} from '../dist/first-pairing-authorization.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const id=()=>crypto.randomUUID();
async function endpoint(t,f,material,ca){
 const native={source:openNativeClock(),descriptor:{clock_domain_id:id(),descriptor_digest:digest('synthetic-pairing-domain')}};
 const auth=await authenticated(t,f,{grant:false,native,sampleWindowPolicy:'authentication-clock-sample/2'}),identity={service_id:f.store.identity.service_id,
  database_instance_id:f.store.identity.database_instance_id,service_kind:'controller',issuer_id:auth.logged.session.issuer_id,issuer_epoch:auth.logged.session.issuer_epoch,credential_id:id()};
 const transport=await startPeerPairingTransport({pairings:auth.sessions.peerPairings,clock:auth.real,identity,...material,ca});t.after(()=>transport.close());
 return {...auth,identity,transport,api:auth.sessions.peerPairings};
}
function request(origin,path,options){return new Promise((resolve,reject)=>{const r=https.get(origin+path,{agent:false,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,...options},response=>{
 const data=[];response.on('data',part=>data.push(part));response.on('error',reject);response.on('end',()=>resolve({status:response.statusCode,body:Buffer.concat(data).toString()}));});r.on('error',reject);});}
function post(origin,path,input,options){const bytes=Buffer.from(canonical(input));return new Promise((resolve,reject)=>{
 const r=https.request(origin+path,{method:'POST',agent:false,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',rejectUnauthorized:true,...options,
  headers:{'Content-Type':'application/json','Content-Length':bytes.length}},response=>{
  const data=[];response.on('data',part=>data.push(part));response.on('error',reject);response.on('end',()=>resolve({status:response.statusCode,body:Buffer.concat(data).toString()}));});r.on('error',reject);r.end(bytes);
});}
test('首次配对授权绑定真实人员和配置，精确重投且签发失败回滚',{timeout:120000},async t=>{
 const {leaves:[controllerTls,seamerTls,otherTls],ca}=peerCertificates(),f=await setup(t,92);
 const e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const previous=f.store.identity,failed=id();f.close();assert.equal((await migrateStorage(f.dir,93)).schema_revision,'93');
 inspect(f.dir,db=>db.exec("CREATE TRIGGER test_first_pairing_issue_omit BEFORE INSERT ON first_pairing_issue WHEN NEW.binding_id='"+failed+"' BEGIN SELECT RAISE(IGNORE); END;"));
 f.reopen();assert.equal(f.store.identity.service_id,previous.service_id);assert.equal(f.store.identity.database_instance_id,previous.database_instance_id);
 const controller=await endpoint(t,f,controllerTls,ca),issuer=controller.identity;
 const seamerIdentity={service_id:id(),database_instance_id:id(),service_kind:'seamer',issuer_id:issuer.issuer_id,issuer_epoch:issuer.issuer_epoch,credential_id:id()};
 const seamer=await startPeerPairingTransport({pairings:{},clock:controller.real,identity:seamerIdentity,...seamerTls,ca});t.after(()=>seamer.close());
 controller.transport.bindPeers([{identity:seamerIdentity,cert:seamerTls.cert,origin:seamer.origin,server_name:'127.0.0.1',trust_bundle_digest:seamer.configuration.trust_bundle_digest}]);
 const stage=bindingId=>{
  const begin=BigInt(controller.real.current().lower_ns)-1000000000n,end=begin+120000000000n;
  const party=(configuration,binding_id,permissions)=>({...configuration,binding_id,permissions,object_scope_digest:digest({devices:[]}),not_before_ns:String(begin),expires_ns:String(end)});
  return controller.api.stage(controller.auth,{request_id:id(),transcript:{format:'leafseamer.peer-pairing/1',pair_attempt_id:id(),
   parties:[party(controller.transport.configuration,bindingId,[]),party(seamer.configuration,id(),['auth.introspect'])]}});
 };
 const selected=stage(id()),discarded=stage(failed),requestFor=value=>({binding_id:value.binding_id,transcript_digest:value.transcript_digest});
 const request=requestFor(selected),exportFor=(value,auth=controller.auth)=>controller.api.exportFirstPairingAuthorization(auth,value);
 assert.throws(()=>exportFor({...request,transcript_digest:digest('different transcript')}),{code:'peer_pairing_first_authorization_staging'});
 assert.throws(()=>exportFor(request,{...controller.auth,csrf:'wrong'}));
 assert.throws(()=>exportFor(requestFor(discarded)),{code:'peer_pairing_storage'});
 const issued=exportFor(request),bytes=Buffer.from(canonical(issued)),body=issued.authorization;
 assert.deepEqual(verifyFirstPairingAuthorization(bytes,controllerTls.cert),issued);
 assert.deepEqual(exportFor(request),issued);
 assert.equal(body.administrator.principal_id,controller.logged.session.principal_id);
 assert.deepEqual(body.transcript,selected.transcript);
 assert.deepEqual(body.controller_stage_ref,{id:selected.binding_id,revision:'1',digest:selected.digest});
 assert.ok(BigInt(body.expires_ns)<=BigInt(selected.attempt_expires_ns));
 assert.throws(()=>verifyFirstPairingAuthorization(bytes,otherTls.cert),{code:'peer_pairing_first_authorization_certificate'});
 const changed=structuredClone(issued);changed.authorization.administrator.principal_id=id();
 assert.throws(()=>verifyFirstPairingAuthorization(Buffer.from(canonical(changed)),controllerTls.cert),{code:'peer_pairing_first_authorization_signature'});
 controller.state.offset=130000000000n;assert.throws(()=>exportFor(request));controller.state.offset=0n;
 controller.real.stop();f.close();
 inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT binding_id,body_jcs,body_digest FROM first_pairing_issue').raw().all(),[[selected.binding_id,bytes.toString(),digest(issued)]]);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('实际双向TLS完成一次性证明、分别批准和撤销，拒绝未知证书并回滚失败的证明写入', {timeout:120000},async t=>{
 const certificates=peerCertificates(),[am,bm,wrong]=certificates.leaves,first=await setup(t,59),second=await setup(t,59);
 for(const f of [first,second]){const e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});}
 const failedActivation=id();
 first.close();inspect(first.dir,db=>db.exec("CREATE TRIGGER test_activation_ignore BEFORE INSERT ON peer_pairing_operation WHEN NEW.request_id='"+failedActivation+"' BEGIN SELECT RAISE(IGNORE); END;"));first.reopen();
 second.close();inspect(second.dir,db=>db.exec("CREATE TRIGGER test_proof_ignore BEFORE INSERT ON peer_pairing_proof WHEN (SELECT count(*) FROM peer_pairing_challenge)=2 BEGIN SELECT RAISE(IGNORE); END;"));second.reopen();
 // 先完成同步迁移，再启动实时采样，避免测试准备本身阻塞采样事件循环。
 const a=await endpoint(t,first,am,certificates.ca),b=await endpoint(t,second,bm,certificates.ca);
 a.transport.bindPeers([{identity:b.identity,cert:bm.cert,origin:b.transport.origin,server_name:'127.0.0.1',trust_bundle_digest:b.transport.configuration.trust_bundle_digest}]);
 b.transport.bindPeers([{identity:a.identity,cert:am.cert,origin:a.transport.origin,server_name:'127.0.0.1',trust_bundle_digest:a.transport.configuration.trust_bundle_digest}]);
 const samples=[a.real.current(),b.real.current()],begin=samples.map(s=>BigInt(s.lower_ns)).reduce((x,y)=>x<y?x:y)-1000000000n,end=begin+120000000000n;
 const parties=[a,b].map(p=>({...p.transport.configuration,binding_id:id(),permissions:['clock.internal.read'],object_scope_digest:digest({devices:[]}),not_before_ns:String(begin),expires_ns:String(end)}));
 const transcript={format:'leafseamer.peer-pairing/1',pair_attempt_id:id(),parties},ar=a.api.stage(a.auth,{request_id:id(),transcript}),br=b.api.stage(b.auth,{request_id:id(),transcript:{...transcript,parties:[...parties].reverse()}});
 assert.equal(ar.transcript_digest,br.transcript_digest);
 const [at,bt]=await Promise.all([a.transport.status(ar.binding_id),b.transport.status(br.binding_id)]);
 assert.equal(at.state,'staged');assert.equal(bt.state,'staged');assert.equal(at.binding_ref.id,br.binding_id);assert.equal(bt.binding_ref.id,ar.binding_id);
 assert.deepEqual(Object.keys(at).sort(),['binding_ref','format','pair_attempt_id','proof_refs','proofs','state','transcript_digest']);
 const route='/internal/pairings/'+ar.binding_id+'/status';
 assert.deepEqual(await request(a.transport.origin,route,{...wrong,ca:certificates.ca}),{status:403,body:''});
 await assert.rejects(request(a.transport.origin,route,{ca:certificates.ca}));
 assert.deepEqual(await request(a.transport.origin,'/internal/clock-domain',{...bm,ca:certificates.ca}),{status:403,body:''});
 const send=(suffix,input)=>post(b.transport.origin,'/internal/pairings/'+br.binding_id+'/'+suffix,input,{...am,ca:certificates.ca});
 const identity={pair_attempt_id:br.transcript.pair_attempt_id,transcript_digest:br.transcript_digest};
 const challenge1=JSON.parse((await send('challenges',identity)).body),challenge2=JSON.parse((await send('challenges',identity)).body);
 const consume=challenge=>({...identity,challenge_id:challenge.challenge_id,challenge:challenge.challenge});
 assert.equal((await send('proofs',consume(challenge1))).status,403);
 assert.equal((await send('proofs',{...consume(challenge2),challenge:crypto.randomBytes(32).toString('base64url')})).status,403);
 assert.equal((await send('proofs',consume(challenge2))).status,403);
 assert.deepEqual(b.api.get(b.auth,br.binding_id),br);assert.deepEqual((await a.transport.status(ar.binding_id)).proofs,[]);
 const challenge3=JSON.parse((await send('challenges',identity)).body);
 const consumed=await send('proofs',consume(challenge3));assert.equal(consumed.status,200);assert.deepEqual(await send('proofs',consume(challenge3)),consumed);
 // 远端已经提交但发起端尚无本地证明，prove通过实际认证status查回原件。
 const aProof=await a.transport.prove(ar.binding_id);assert.equal(aProof.direction,'outbound');assert.equal(aProof.peer_proof_ref.id,JSON.parse(consumed.body).id);assert.deepEqual(await a.transport.prove(ar.binding_id),aProof);
 assert.equal(a.api.get(a.auth,ar.binding_id).state,'proving');assert.equal(b.api.get(b.auth,br.binding_id).state,'proving');
 const partial=a.api.get(a.auth,ar.binding_id);assert.throws(()=>a.api.activate(a.auth,{request_id:id(),binding_id:ar.binding_id,expected_revision:partial.revision,transcript_digest:ar.transcript_digest}),e=>e.code==='peer_pairing_activation');
 await b.transport.prove(br.binding_id);const readyA=a.api.get(a.auth,ar.binding_id),readyB=b.api.get(b.auth,br.binding_id);assert.equal(readyA.state,'proved');assert.equal(readyB.state,'proved');
 const activationA={request_id:id(),binding_id:ar.binding_id,expected_revision:readyA.revision,transcript_digest:ar.transcript_digest};
 let samplesRead=0;const lateActivation=id();a.state.onPairingRead=()=>{if(++samplesRead===2)a.state.offset=120000000000n;};
 assert.throws(()=>a.api.activate(a.auth,{...activationA,request_id:lateActivation}),e=>e.code==='peer_pairing_expired');
 delete a.state.onPairingRead;a.state.offset=0n;assert.deepEqual(a.api.get(a.auth,ar.binding_id),readyA);
 assert.throws(()=>a.api.activate(a.auth,{...activationA,request_id:failedActivation}),e=>e.code==='peer_pairing_storage');assert.deepEqual(a.api.get(a.auth,ar.binding_id),readyA);
 const activate=(peer,record)=>peer.api.activate(peer.auth,peer===a?activationA:{request_id:id(),binding_id:record.binding_id,expected_revision:record.revision,transcript_digest:record.transcript_digest});
 const activeA=activate(a,readyA);assert.equal(activeA.state,'activated');assert.equal((await a.transport.status(ar.binding_id)).state,'proved');
 assert.deepEqual(a.api.activate(a.auth,activationA),activeA);
 const activeB=activate(b,readyB);assert.equal(activeB.state,'activated');assert.equal((await a.transport.status(ar.binding_id)).state,'activated');
 a.api.revoke(a.auth,{request_id:id(),binding_id:ar.binding_id,expected_revision:activeA.revision});
 assert.deepEqual(a.api.activate(a.auth,activationA),activeA);assert.equal(a.api.get(a.auth,ar.binding_id).state,'revoked');
 await assert.rejects(b.transport.status(br.binding_id),e=>e.code==='peer_pairing_response');
 a.real.stop();b.real.stop();first.close();second.close();
 inspect(second.dir,db=>{
  assert.equal(db.prepare('SELECT state FROM peer_pairing_challenge WHERE challenge_id=?').pluck().get(challenge2.challenge_id),'superseded');
  assert.equal(db.prepare('SELECT state FROM peer_pairing_challenge WHERE challenge_id=?').pluck().get(challenge3.challenge_id),'consumed');
  assert.equal(db.prepare('SELECT count(*) FROM peer_pairing_proof').pluck().get(),2);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 inspect(first.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM peer_pairing_operation WHERE request_id=?').pluck().get(failedActivation),0));
});

test('人员发起原件经真实双向 TLS 读取，未激活、错摘要及释放前变化均拒绝',{timeout:120000},async t=>{
 const {leaves:[am,bm],ca}=peerCertificates(),runtime_domain_ref={id:id()};
 const clock={pairingSample(){const utc=String(BigInt(Date.now())*1000000n);return {lower_ns:utc,upper_ns:utc,tick_ns:String(process.hrtime.bigint()),runtime_domain_ref};}};
 let original,releaseChecks=0,changeBeforeRelease=false,state='staged';
 async function configuredEndpoint(service_kind,material,runInitiator=null){
  const identity={service_id:id(),database_instance_id:id(),service_kind,issuer_id:id(),issuer_epoch:id(),credential_id:id()};
  let localConfiguration,record;
  const pairings={bindConfiguration(value){localConfiguration=value.local;},currentPending(binding){assert.equal(binding,record.binding_id);return {...record,state};}};
  const transport=await startPeerPairingTransport({pairings,clock,identity,...material,ca,runInitiator});t.after(()=>transport.close());
  return {identity,transport,configure(local,peer,transcript){assert.equal(local.endpoint_config_digest,localConfiguration.endpoint_config_digest);
   record={binding_id:local.binding_id,peer_service_id:peer.service_id,transcript,transcript_digest:digest(transcript),expires_ns:local.expires_ns};}};
 }
 const a=await configuredEndpoint('controller',am),b=await configuredEndpoint('seamer',bm,(_binding,_socket,request)=>{
  assert.equal(request.operation_id,original.operation_ref.object_id);
  if(request.operation_digest!==original.operation_ref.digest)return null;
  releaseChecks++;return changeBeforeRelease&&releaseChecks===2?{...original,arm_generation:'2'}:original;
 });
 const describe=(peer,material)=>({identity:peer.identity,cert:material.cert,origin:peer.transport.origin,server_name:'127.0.0.1',trust_bundle_digest:peer.transport.configuration.trust_bundle_digest});
 a.transport.bindPeers([describe(b,bm)]);b.transport.bindPeers([describe(a,am)]);
 const begin=BigInt(clock.pairingSample().lower_ns)-1000000000n,end=begin+120000000000n;
 const parties=[a,b].map(peer=>({...peer.transport.configuration,binding_id:id(),permissions:peer===a?['automation.prepare.read']:[],
  object_scope_digest:digest({devices:[]}),not_before_ns:String(begin),expires_ns:String(end)}));
 const transcript={format:'leafseamer.peer-pairing/1',pair_attempt_id:id(),parties};
 const [ar,br]=parties;a.configure(ar,br,transcript);b.configure(br,ar,transcript);
 const scope=peer=>({authority_service_id:peer.identity.service_id,database_instance_id:peer.identity.database_instance_id});
 const ref=kind=>({kind,scope:scope(b),object_id:id(),revision:'1',digest:digest(kind)}),operation_ref=ref('run_arm_operation');
 original={operation_ref,run_id:id(),definition_id:id(),definition_version:'1',arm_generation:'1',approval_ref:ref('run_approval'),artifact_ref:ref('artifact'),
  target_scope:scope(a),preparation_id:id(),initiator:{issuer_id:a.identity.issuer_id,issuer_epoch:a.identity.issuer_epoch,principal_id:id(),principal_kind:'human'},
  initiator_authorization_ref:{id:operation_ref.object_id,revision:'1',digest:digest('initiator evidence')},
  credential:{issuer_service_id:a.identity.service_id,token_id:id(),session_id:id(),session_revision:'1',credential_id:id(),policy_revision:'1',
   scope_digest:digest('issuer scope'),recent_before_ns:String(end)},eligible_before_ns:String(end)};
 const read=(reference=operation_ref)=>a.transport.readRunInitiator(ar.binding_id,reference);
 await assert.rejects(async()=>read(),{code:'peer_pairing_purpose'});
 const denied=await request(b.transport.origin,'/internal/automation/run-operations/'+operation_ref.object_id,{...am,ca,headers:{
  'X-LeafSeamer-Pairing':br.binding_id,'X-LeafSeamer-Operation-Digest':operation_ref.digest,'X-LeafSeamer-Challenge':id()}});
 assert.deepEqual(denied,{status:403,body:''});assert.equal(releaseChecks,0);
 state='activated';
 assert.deepEqual(await read(),original);assert.equal(releaseChecks,2);
 await assert.rejects(read({...operation_ref,digest:digest('wrong operation digest')}),{code:'peer_pairing_response'});
 releaseChecks=0;changeBeforeRelease=true;await assert.rejects(read(),{code:'peer_pairing_response'});assert.equal(releaseChecks,2);
});
