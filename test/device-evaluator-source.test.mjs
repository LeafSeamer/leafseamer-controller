import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {ref} from '../dist/auth-clock-value.mjs';
const id=()=>crypto.randomUUID();
async function fixture(t,revision=38){
 const f=await setup(t,revision),e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const device=f.store.registerDevice({request_id:'evaluator.device',device_kind:'simulator',display_name:'评估器范围'}).device_id,a=await authenticated(t,f,{grant:false}),s=a.sessions;
 const p=s.createServicePrincipal(a.auth,{request_id:id(),display_name:'内部评估',purpose:'integration'}),now=a.real.current();
 const approved=s.approveServicePrincipal(a.auth,{request_id:id(),principal_id:p.id,expected_revision:p.revision,audiences:[f.store.identity.service_id],permissions:['identity.read'],
  device_ids:[device],not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
 const request={request_id:id(),principal_id:p.id,subject_ref:ref(approved.principal),approval_ref:ref(approved.approval),device_ids:[device],expires_ns:approved.approval.expires_ns};
 return {...f,get store(){return f.store;},...a,device,request};
}
test('评估器内部策略要求实际人员管理权限、精确主体批准与设备范围；不自动构造运行来源',async t=>{
 const f=await fixture(t),s=f.sessions;
 assert.throws(()=>s.approveDeviceEvaluatorPolicy(f.auth,{...f.request,device_ids:[id()]}),e=>e.code==='evaluator_source_scope');
 assert.throws(()=>s.approveDeviceEvaluatorPolicy(f.auth,{...f.request,approval_ref:{...f.request.approval_ref,id:id()}}),e=>e.code==='evaluator_source_binding');
 const p=s.approveDeviceEvaluatorPolicy(f.auth,f.request);assert.deepEqual(s.approveDeviceEvaluatorPolicy(f.auth,f.request),p);
 assert.throws(()=>s.approveDeviceEvaluatorPolicy(f.auth,{...f.request,expires_ns:String(BigInt(f.request.expires_ns)-1n)}),e=>e.code==='evaluator_source_conflict');
 assert.throws(()=>s.beginDeviceEvaluatorChallenge({request_id:id(),policy_ref:ref(p),device_id:f.device}));
 assert.equal(s.getServicePrincipal(f.auth,f.request.principal_id).state,'active');
 const permissions=s.localPermissions(f.auth);s.replaceLocalPermissions(f.auth,{request_id:id(),principal_id:permissions.principal_id,expected_revision:permissions.revision,permissions:permissions.permissions.filter(p=>p!=='auth.manage')});
 assert.throws(()=>s.revokeDeviceEvaluatorPolicy(f.auth,{request_id:id(),policy_ref:ref(p)}),e=>e.code==='service_identity_management_denied');
 f.real.stop();f.close();inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM device_evaluator_policy').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM device_evaluator_challenge').pluck().get(),0);assert.equal(db.prepare('SELECT count(*) FROM device_evaluator_source').pluck().get(),0);});
});
test('评估器策略撤销永久阻止新挑战，重复撤销查原，人员身份仍可用',async t=>{
 const f=await fixture(t),s=f.sessions,p=s.approveDeviceEvaluatorPolicy(f.auth,f.request),request={request_id:id(),policy_ref:ref(p)};
 const revoked=s.revokeDeviceEvaluatorPolicy(f.auth,request);assert.deepEqual(s.revokeDeviceEvaluatorPolicy(f.auth,request),revoked);
 assert.throws(()=>s.beginDeviceEvaluatorChallenge({request_id:id(),policy_ref:ref(p),device_id:f.device}),e=>e.code==='evaluator_source_policy_revoked');
 assert.equal(s.getServicePrincipal(f.auth,f.request.principal_id).state,'active');
});
test('评估器策略到期在挑战前持久关闭，时间回退不复活策略',async t=>{
 const f=await fixture(t),s=f.sessions,p=s.approveDeviceEvaluatorPolicy(f.auth,{...f.request,expires_ns:String(BigInt(f.real.current().upper_ns)+10000000000n)});
 f.state.offset=BigInt(p.expires_ns)-BigInt(f.real.current().upper_ns);
 assert.throws(()=>s.beginDeviceEvaluatorChallenge({request_id:id(),policy_ref:ref(p),device_id:f.device}),e=>e.code==='evaluator_source_policy_expired');
 f.state.offset=0n;assert.throws(()=>s.beginDeviceEvaluatorChallenge({request_id:id(),policy_ref:ref(p),device_id:f.device}),e=>e.code==='evaluator_source_policy_revoked');
});
for(const table of ['device_evaluator_policy','device_evaluator_operation'])test('评估器策略缺写'+table+'整笔回滚',async t=>{
 const f=await fixture(t);f.real.stop();f.close();inspect(f.dir,db=>db.exec(`CREATE TRIGGER evaluator_fault BEFORE INSERT ON ${table} BEGIN SELECT RAISE(IGNORE); END;`));
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.throws(()=>a.sessions.approveDeviceEvaluatorPolicy(a.auth,f.request),e=>e.code==='evaluator_source_storage');a.real.stop();f.close();
 inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM device_evaluator_policy').pluck().get(),0);assert.equal(db.prepare('SELECT count(*) FROM device_evaluator_operation').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});
test('schema37到38保留原服务身份，升级不回填评估器策略或来源',async t=>{
 const f=await fixture(t,37);assert.equal(f.sessions.approveDeviceEvaluatorPolicy,undefined);f.real.stop();f.close();let before;
 inspect(f.dir,db=>{before=db.prepare('SELECT * FROM service_principal_revision').raw().all();});await migrateStorage(f.dir,38);
 inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT * FROM service_principal_revision').raw().all(),before);
  for(const table of ['device_evaluator_policy','device_evaluator_challenge','device_evaluator_source'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);});
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.ok(a.sessions.approveDeviceEvaluatorPolicy(a.auth,f.request).id);
});
