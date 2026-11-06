import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {ref} from '../dist/auth-clock-value.mjs';
const id=()=>crypto.randomUUID();
async function fixture(t,revision=37){
 const f=await setup(t,revision),e=f.store.enrollment.begin();
 await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const auth=await authenticated(t,f,{grant:false}),s=auth.sessions,now=auth.real.current();
 const principal=s.createServicePrincipal(auth.auth,{request_id:id(),display_name:'定向服务',purpose:'integration'});
 const approved=s.approveServicePrincipal(auth.auth,{request_id:id(),principal_id:principal.id,expected_revision:principal.revision,
  audiences:[f.store.identity.service_id],permissions:['identity.read'],device_ids:[],not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
 const staged=s.createServiceCredential(auth.auth,{request_id:id(),principal_id:principal.id,expected_revision:approved.principal.revision,
  approval_ref:ref(approved.approval),expires_ns:String(BigInt(now.upper_ns)+1800000000000n)});
 const proof=s.proveServiceCredential({credential_id:staged.credential.id,secret:staged.secret,proof_request_id:id()});
 const active=s.activateServiceCredential(auth.auth,{request_id:id(),credential_id:staged.credential.id,expected_revision:'2',approval_ref:ref(approved.approval),proof_ref:ref(proof)});
 const policyRequest={request_id:id(),principal_id:principal.id,subject_ref:ref(approved.principal),approval_ref:ref(approved.approval),audience:f.store.identity.service_id,
  permissions:['identity.read'],device_ids:[],not_before_ns:now.lower_ns,expires_ns:approved.approval.expires_ns};
 const request={credential_id:active.id,secret:staged.secret,request_id:id(),audience:f.store.identity.service_id,permissions:['identity.read'],device_ids:[]};
 return {...f,get store(){return f.store;},...auth,principal:approved.principal,approval:approved.approval,active,staged,policyRequest,request};
}
const tokenInput=t=>({token_id:t.binding.id,secret:t.secret});
test('服务定向token必须同时有实际凭据和独立本地批准，秘密只交付一次且只能读取自身身份',async t=>{
 const f=await fixture(t),s=f.sessions;
 assert.throws(()=>s.issueServiceToken(f.request),e=>e.code==='service_token_policy_required');
 const policy=s.approveLocalServicePolicy(f.auth,f.policyRequest);assert.deepEqual(s.approveLocalServicePolicy(f.auth,f.policyRequest),policy);
 assert.throws(()=>s.approveLocalServicePolicy(f.auth,{...f.policyRequest,request_id:id(),device_ids:[id()]}),e=>e.code==='service_token_scope');
 assert.throws(()=>s.issueServiceToken({...f.request,secret:'A'.repeat(43)}),e=>e.code==='service_identity_credential_invalid');
 assert.throws(()=>s.issueServiceToken({...f.request,audience:id()}),e=>e.code==='service_token_input');
 assert.throws(()=>s.issueServiceToken({...f.request,permissions:['device.command']}),e=>e.code==='service_token_scope');
 const issued=s.issueServiceToken(f.request),replay=s.issueServiceToken(f.request);assert.equal(issued.secret_delivery,'delivered');assert.equal(replay.secret_delivery,'unavailable');
 assert.equal('secret'in replay,false);assert.deepEqual(replay.binding,issued.binding);assert.deepEqual(issued.binding.policy_ref,ref(policy));
 assert.throws(()=>s.issueServiceToken({...f.request,device_ids:[id()]}),e=>e.code==='service_token_conflict');
 const verified=s.verifyServiceToken(tokenInput(issued));assert.equal(verified.principal_kind,'service');assert.equal('session_id'in verified,false);
 assert.equal(s.readServiceIdentity(tokenInput(issued)).id,f.principal.id);
 assert.throws(()=>s.verifyServiceToken({...tokenInput(issued),secret:'A'.repeat(43)}),e=>e.code==='service_token_invalid');
 assert.throws(()=>s.verifyToken(tokenInput(issued),f.store.identity.service_id),e=>e.code==='token_invalid');
 assert.throws(()=>s.verifyServiceToken({token_id:f.active.id,secret:f.staged.secret}),e=>e.code==='service_token_invalid');
 f.real.stop();f.close();inspect(f.dir,db=>{
  const bodies=['service_token_operation','service_receiver_policy','service_access_token'].flatMap(t=>db.prepare('SELECT body_jcs FROM '+t).pluck().all()).join('\n');
  assert.equal(bodies.includes(issued.secret),false);assert.equal(bodies.includes(f.staged.secret),false);assert.equal(bodies.includes('verifier'),false);
  assert.equal(db.prepare('SELECT count(*) FROM service_access_token').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('撤销父凭据立即阻止现存服务token；重新登录管理人员不恢复该token',async t=>{
 const f=await fixture(t),s=f.sessions;s.approveLocalServicePolicy(f.auth,f.policyRequest);const issued=s.issueServiceToken(f.request);
 s.revokeServiceCredential(f.auth,{request_id:id(),credential_id:f.active.id,expected_revision:f.active.revision});
 assert.throws(()=>s.readServiceIdentity(tokenInput(issued)),e=>e.code==='service_token_invalid');
 assert.throws(()=>s.issueServiceToken({...f.request,request_id:id()}),e=>e.code==='service_token_credential_invalid');
 f.real.stop();f.close();f.reopen();const fresh=await authenticated(t,f,{grant:false});
 assert.throws(()=>fresh.sessions.verifyServiceToken(tokenInput(issued)),e=>e.code==='service_token_invalid');
 fresh.real.stop();f.close();inspect(f.dir,db=>assert.equal(db.prepare('SELECT state FROM service_access_token_terminal').pluck().get(),'revoked'));
});
test('本地策略撤销即时拒绝存量token与新签发，不改动主体批准或人员权限',async t=>{
 const f=await fixture(t),s=f.sessions,policy=s.approveLocalServicePolicy(f.auth,f.policyRequest),issued=s.issueServiceToken(f.request);
 const request={request_id:id(),policy_ref:ref(policy)},revoked=s.revokeLocalServicePolicy(f.auth,request);assert.deepEqual(s.revokeLocalServicePolicy(f.auth,request),revoked);
 assert.throws(()=>s.verifyServiceToken(tokenInput(issued)),e=>e.code==='service_token_policy_invalid');
 assert.throws(()=>s.issueServiceToken({...f.request,request_id:id()}),e=>e.code==='service_token_policy_invalid');
 assert.equal(s.getServicePrincipal(f.auth,f.principal.id).state,'active');assert.equal(s.localPermissions(f.auth).state,'active');
});
test('token与本地策略到期都记录永久终态，认证时间回退不重新开放',async t=>{
 const f=await fixture(t),s=f.sessions,policy=s.approveLocalServicePolicy(f.auth,{...f.policyRequest,expires_ns:String(BigInt(f.real.current().upper_ns)+30000000000n)});
 const issued=s.issueServiceToken(f.request);assert.equal(issued.binding.expires_ns,policy.expires_ns);
 f.state.offset=BigInt(issued.binding.expires_ns)-BigInt(f.real.current().upper_ns);
 assert.throws(()=>s.verifyServiceToken(tokenInput(issued)),e=>e.code==='service_token_expired');
 assert.throws(()=>s.issueServiceToken({...f.request,request_id:id()}),e=>e.code==='service_token_policy_invalid');
 f.state.offset=0n;assert.throws(()=>s.verifyServiceToken(tokenInput(issued)),e=>e.code==='service_token_invalid');
 assert.throws(()=>s.issueServiceToken({...f.request,request_id:id()}),e=>e.code==='service_token_policy_invalid');
});
test('每凭据8个活跃token上限包含未取回秘密的签发；重投不另占额度',async t=>{
 const f=await fixture(t),s=f.sessions;s.approveLocalServicePolicy(f.auth,f.policyRequest);const first=s.issueServiceToken(f.request);
 for(let n=1;n<8;n++)s.issueServiceToken({...f.request,request_id:id()});
 assert.throws(()=>s.issueServiceToken({...f.request,request_id:id()}),e=>e.code==='service_token_capacity');
 assert.deepEqual(s.issueServiceToken(f.request).binding,first.binding);
 f.state.offset=61000000000n;const next=s.issueServiceToken({...f.request,request_id:id()});assert.equal(next.secret_delivery,'delivered');
 f.real.stop();f.close();inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM service_access_token').pluck().get(),9);assert.equal(db.prepare('SELECT count(*) FROM service_access_token_terminal').pluck().get(),8);});
});
test('签发最终检查发现到期时不交付秘密，并提交永久终态，原请求只查原',async t=>{
 const f=await fixture(t),s=f.sessions;s.approveLocalServicePolicy(f.auth,f.policyRequest);let reads=0;
 f.state.onRead=()=>{if(++reads===2)f.state.offset=61000000000n;};
 assert.throws(()=>s.issueServiceToken(f.request),e=>e.code==='service_token_expired');delete f.state.onRead;f.state.offset=0n;
 const replay=s.issueServiceToken(f.request);assert.equal(replay.secret_delivery,'unavailable');assert.equal('secret'in replay,false);
 f.real.stop();f.close();inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM service_access_token').pluck().get(),1);
  assert.equal(db.prepare('SELECT state FROM service_access_token_terminal').pluck().get(),'expired');assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});
for(const table of ['service_access_token','service_token_operation'])test('服务token缺写'+table+'不保留秘密验证值或签发结果',async t=>{
 const f=await fixture(t);f.sessions.approveLocalServicePolicy(f.auth,f.policyRequest);f.real.stop();f.close();
 inspect(f.dir,db=>db.exec(`CREATE TRIGGER omit_token BEFORE INSERT ON ${table}${table==='service_token_operation'?" WHEN NEW.kind='issue'":''} BEGIN SELECT RAISE(IGNORE); END;`));
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.throws(()=>a.sessions.issueServiceToken(f.request),e=>e.code==='service_token_storage');a.real.stop();f.close();
 inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM service_access_token').pluck().get(),0);assert.equal(db.prepare("SELECT count(*) FROM service_token_operation WHERE kind='issue'").pluck().get(),0);
  db.exec('DROP TRIGGER omit_token');assert.deepEqual(db.pragma('foreign_key_check'),[]);});
 f.reopen();const b=await authenticated(t,f,{grant:false});assert.equal(b.sessions.issueServiceToken(f.request).secret_delivery,'delivered');assert.equal(b.sessions.issueServiceToken(f.request).secret_delivery,'unavailable');
});
test('schema36到37保留服务凭据原件，迁移后不自动批准接收策略或签发token',async t=>{
 const f=await fixture(t,36);assert.equal(f.sessions.issueServiceToken,undefined);f.real.stop();f.close();let before;
 inspect(f.dir,db=>{before=db.prepare('SELECT * FROM service_credential').raw().all();});await migrateStorage(f.dir,37);
 inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT * FROM service_credential').raw().all(),before);for(const table of ['service_receiver_policy','service_access_token','service_token_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);});
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.throws(()=>a.sessions.issueServiceToken(f.request),e=>e.code==='service_token_policy_required');
 a.sessions.approveLocalServicePolicy(a.auth,f.policyRequest);const issued=a.sessions.issueServiceToken(f.request);assert.equal(a.sessions.readServiceIdentity(tokenInput(issued)).id,f.principal.id);
});
