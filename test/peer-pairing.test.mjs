import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {digest} from '../dist/auth-clock-value.mjs';
import {pairingTranscript} from '../dist/peer-pairing-value.mjs';
const id=()=>crypto.randomUUID();
async function fixture(t,{inject=null,revision=59}={}){
 const f=await setup(t,revision),enrollment=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:enrollment.token_id,secret:enrollment.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 if(inject){f.close();inspect(f.dir,db=>db.exec(inject));f.reopen();}
 const a=await authenticated(t,f,{grant:false}),now=a.real.current(),party=(service_id,kind)=>({service_id,database_instance_id:id(),service_kind:kind,issuer_id:id(),issuer_epoch:id(),binding_id:id(),credential_id:id(),
  certificate_der_sha256:digest(id()),spki_sha256:digest(id()),trust_bundle_digest:digest('synthetic-ca'),endpoint_config_digest:digest(id()),permissions:['clock.internal.read'],object_scope_digest:digest({devices:[]}),not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
 const local={...party(f.store.identity.service_id,'controller'),database_instance_id:f.store.identity.database_instance_id,issuer_id:a.logged.session.issuer_id,issuer_epoch:a.logged.session.issuer_epoch},peer=party(id(),'seamer');
 const configuration={local,peers:[peer]},request={request_id:id(),transcript:{format:'leafseamer.peer-pairing/1',pair_attempt_id:id(),parties:[local,peer]}};
 a.sessions.peerPairings?.bindConfiguration(configuration);
 return {...f,get store(){return f.store;},...a,local,peer,configuration,request,api:a.sessions.peerPairings};
}
test('配对stage由近期人员授权持久提交，双端投影一致，重放不增修订且不授予active',async t=>{
 const f=await fixture(t),value=f.api.stage(f.auth,f.request);
 assert.equal(value.state,'staged');assert.equal(value.approval_ref,null);assert.deepEqual(value.proof_refs,[]);
 assert.equal(value.transcript_digest,digest(pairingTranscript({...f.request.transcript,parties:[f.peer,f.local]})));
 assert.equal(BigInt(value.attempt_expires_ns)-BigInt(f.real.current().lower_ns),600000000000n);
 assert.deepEqual(f.api.stage(f.auth,f.request),value);assert.deepEqual(f.api.get(f.auth,value.binding_id),value);
 assert.throws(()=>f.api.activate(f.auth,{request_id:id(),binding_id:value.binding_id,expected_revision:'1',transcript_digest:value.transcript_digest}),e=>e.code==='peer_pairing_activation');assert.equal(typeof f.api.authorizeBusiness,'undefined');
 assert.throws(()=>f.api.stage(f.auth,{...f.request,transcript:{...f.request.transcript,pair_attempt_id:id()}}),e=>e.code==='peer_pairing_conflict');
 const rejected=f.api.reject(f.auth,{request_id:id(),binding_id:value.binding_id,expected_revision:'1'});assert.equal(rejected.state,'rejected');
 assert.throws(()=>f.api.currentPending(value.binding_id),e=>e.code==='peer_pairing_state');
});
test('当前配置、人员权限与近期认证均核验；请求不能自报证书或交换服务身份',async t=>{
 const f=await fixture(t);
 for(const patch of [{certificate_der_sha256:digest('wrong')},{issuer_epoch:id()},{service_kind:'controller'}])
  assert.throws(()=>f.api.stage(f.auth,{request_id:id(),transcript:{...f.request.transcript,parties:[f.local,{...f.peer,...patch}]}}),e=>e.code==='peer_pairing_configuration_changed');
 const grant=f.sessions.localPermissions(f.auth);f.sessions.replaceLocalPermissions(f.auth,{request_id:id(),principal_id:f.logged.session.principal_id,expected_revision:grant.revision,permissions:grant.permissions.filter(p=>p!=='auth.manage')});
 assert.throws(()=>f.api.stage(f.auth,f.request),e=>e.code==='peer_pairing_management_denied');
});
test('到期等号关闭attempt，历史重放不重新签发；重启关闭未完成attempt',async t=>{
 const f=await fixture(t),value=f.api.stage(f.auth,f.request);
 f.state.offset=BigInt(value.attempt_expires_ns)-BigInt(f.real.current().upper_ns);
 assert.throws(()=>f.api.currentPending(value.binding_id),e=>e.code==='peer_pairing_expired');
 f.state.offset=0n;f.real.stop();f.close();f.reopen();const next=await authenticated(t,f,{grant:false});next.sessions.peerPairings.bindConfiguration(f.configuration);
 assert.throws(()=>next.sessions.peerPairings.currentPending(value.binding_id),e=>e.code==='peer_pairing_expired');
 const current=next.sessions.peerPairings.get(next.auth,value.binding_id);assert.equal(current.state,'expired');assert.equal(current.revision,'2');
 assert.deepEqual(next.sessions.peerPairings.stage(next.auth,f.request),value);
});
test('配对操作写入被忽略时，revision、head和操作必须一起回滚',async t=>{
 const f=await fixture(t,{inject:"CREATE TRIGGER test_pairing_commit BEFORE INSERT ON peer_pairing_operation BEGIN SELECT RAISE(IGNORE); END;"});
 assert.throws(()=>f.api.stage(f.auth,f.request),e=>e.code==='peer_pairing_storage');f.real.stop();f.close();inspect(f.dir,db=>{
  for(const table of ['peer_pairing_revision','peer_pairing_head','peer_pairing_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('58到59迁移保留既有身份和会话行，追加独立配对表且可重新打开',async t=>{
 const f=await fixture(t,{revision:58});f.real.stop();f.close();let before;
 inspect(f.dir,db=>{before=['identity_issuer','local_principal','auth_session'].map(table=>db.prepare('SELECT * FROM '+table).raw().all());});
 const migration=await migrateStorage(f.dir);assert.equal(migration.schema_revision,'59');inspect(f.dir,db=>{
  assert.deepEqual(['identity_issuer','local_principal','auth_session'].map(table=>db.prepare('SELECT * FROM '+table).raw().all()),before);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);assert.equal(db.prepare('SELECT count(*) FROM peer_pairing_head').pluck().get(),0);
 });f.reopen();assert.equal(f.store.identity.schema_revision,'59');
});
