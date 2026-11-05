import test from 'node:test';import assert from 'node:assert/strict';import crypto from 'node:crypto';
import {setup,inspect} from './fixtures/extension-installation.mjs';import {authenticated} from './fixtures/extension-auth.mjs';
import {contractSelection as selection} from '../dist/sdk/index.mjs';
const permissions=['control.read','control.acquire','control.release','control.transfer','control.accept','control.emergency'];
async function fixture(t,{fault=null}={}){const f=await setup(t,26),enroll=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:enroll.token_id,secret:enroll.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 if(fault){f.close();inspect(f.dir,db=>db.exec(`CREATE TRIGGER control_fault BEFORE INSERT ON ${fault.table} BEGIN SELECT RAISE(${fault.mode==='IGNORE'?'IGNORE':"ABORT,'synthetic_control_failure'"}); END`));f.reopen();}
 const a=await authenticated(t,f),old=a.sessions.localPermissions(a.auth);a.sessions.replaceLocalPermissions(a.auth,{request_id:crypto.randomUUID(),principal_id:a.logged.session.principal_id,expected_revision:old.revision,permissions:[...old.permissions,...permissions]});
 const token=a.token([...permissions,'request.create']),device=f.store.registerDevice({request_id:'device',device_kind:'simulator',display_name:'测试设备'}).device_id;
 const context=a.sessions.createRequestContext(token,{audience:f.store.identity.service_id,operations:['acquireControl','releaseControl','offerTransfer','acceptTransfer','cancelTransfer'],selection,ttl_ms:10000,max_unique_requests:8});
 return {...f,a,token,device,context};}
test('人员接管先持久预留版本，屏障缺失保持未决，同键重放不重复受理',async t=>{
 const f=await fixture(t),before=f.a.sessions.getControl(f.token,f.device),request={context_id:f.context.context_id,idempotency_key:'acquire',expected_control:{epoch:before.control_epoch,version:before.effective_version},reason:'测试接管'};
 const accepted=await f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},request);assert.equal(accepted.replay,false);
 await new Promise(resolve=>setImmediate(resolve));const current=f.a.sessions.getControl(f.token,f.device);assert.equal(current.reserved_version,'1');assert.equal(current.effective_version,'0');assert.equal(current.holder,null);assert.equal(current.gate_state,'protected');assert.ok(current.pending_change);
 const op=f.a.sessions.getControlOperation(f.token,accepted.receipt.initial_result_ref.id);assert.equal(op.state,'indeterminate');
 const replay=await f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{...request,force:false});assert.equal(replay.replay,true);assert.deepEqual(replay.receipt,accepted.receipt);
 await assert.rejects(f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{...request,reason:'不同内容'}),/control_conflict/);
 await assert.rejects(f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{...request,idempotency_key:'second',force:true}),/control_conflict/);
 const found=await f.a.sessions.lookupControlRequest(f.token,accepted.receipt.identity);assert.equal(found.status,'found');
 const foreign=structuredClone(accepted.receipt.identity);foreign.key.request_epoch=crypto.randomUUID();
 await assert.rejects(f.a.sessions.lookupControlRequest(f.token,foreign),/control_context/);
 f.close();inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM control_request').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});

for(const table of ['control_record_revision','control_operation_revision','control_request','control_change_commit'])for(const mode of ['ABORT','IGNORE'])test('控制事务'+table+' '+mode+'全体回滚',async t=>{
 const f=await fixture(t,{fault:{table,mode}}),before=f.a.sessions.getControl(f.token,f.device);
 await assert.rejects(f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{context_id:f.context.context_id,idempotency_key:'fault',expected_control:{epoch:before.control_epoch,version:before.effective_version},reason:'事务故障'}));
 f.close();inspect(f.dir,db=>{
  for(const table of ['control_record_revision','control_operation_revision','control_request','control_change_commit','control_barrier_target'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.equal(db.prepare('SELECT used_count FROM request_context WHERE context_id=?').pluck().get(f.context.context_id),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('紧急权限和非空理由分别核验，失败不消耗版本或请求预算',async t=>{
 const f=await fixture(t),token=f.a.token(['request.create','control.read','control.acquire']);
 const c=f.a.sessions.createRequestContext(token,{audience:f.store.identity.service_id,operations:['acquireControl'],selection,ttl_ms:10000,max_unique_requests:8});
 const before=f.a.sessions.getControl(token,f.device),request={context_id:c.context_id,idempotency_key:'force',expected_control:{epoch:before.control_epoch,version:'0'},reason:'强制接管',force:true};
 await assert.rejects(f.a.sessions.changeControl(token,'acquireControl',{device_id:f.device},request),/control_permission/);
 await assert.rejects(f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{...request,context_id:f.context.context_id,reason:'  '}),/control_permission/);
 assert.deepEqual(f.a.sessions.getControl(f.token,f.device),before);
 f.close();inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM control_request').pluck().get(),0);assert.equal(db.prepare('SELECT sum(used_count) FROM request_context').pluck().get(),0);});
});
test('重启保留未决控制及预留版本，不自动恢复闸门或持有人',async t=>{
 const f=await fixture(t),before=f.a.sessions.getControl(f.token,f.device);
 await f.a.sessions.changeControl(f.token,'acquireControl',{device_id:f.device},{context_id:f.context.context_id,idempotency_key:'restart',expected_control:{epoch:before.control_epoch,version:'0'},reason:'重启检查'});
 await new Promise(resolve=>setImmediate(resolve));const original=f.a.sessions.getControl(f.token,f.device);f.close();
 const store=f.reopen(),a=await authenticated(t,{store});const token=a.token(['control.read']);
 assert.deepEqual(a.sessions.getControl(token,f.device),original);assert.equal(original.reserved_version,'1');assert.equal(original.effective_version,'0');assert.equal(original.gate_state,'protected');
});
