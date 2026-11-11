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
