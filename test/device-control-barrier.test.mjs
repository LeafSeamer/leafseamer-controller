import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import canonicalize from 'canonicalize';
import {deviceControlBarrier} from '../dist/device-control-barrier.mjs';
import {controlHash as hash} from '../dist/device-control-value.mjs';

test('监督来源缺失按资格拒绝，存储和未知异常保持原错误',t=>{
 const db=new Database(':memory:');t.after(()=>db.close());let thrown;
 const barrier=deviceControlBarrier({db,isOpen:()=>true,authorization:{domain(){throw thrown;}}});
 for(const code of ['worker_authorization_source','supervisor_confirmation_expired']){
  thrown=Object.assign(new Error(code),{code});
  assert.throws(()=>barrier.domain(),e=>e.name==='IdentityError'&&e.code==='control_source_unavailable');
 }
 for(const code of ['SQLITE_CORRUPT','unexpected_provider_error']){
  thrown=Object.assign(new Error(code),{code});assert.throws(()=>barrier.domain(),e=>e===thrown);
 }
});

// 隔离的屏障分支验证；退出原件为合成数据，不作为真实重启或设备验收证据。
function fixture(t,{history=true,accepted=false,retired=true,corrupt=false}={}){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE control_operation_revision(operation_id,revision,body_jcs,body_digest);
 CREATE TABLE control_operation_head(operation_id,revision);
 CREATE TABLE control_barrier_target(operation_id,launch_id,launch_intent_digest,service_boot_id);
 CREATE TABLE control_barrier_evidence(operation_id,body_jcs,body_digest);
 CREATE TABLE ca_adjudication(key_id,decision);CREATE TABLE ca_request_key(key_id,device_id);
 CREATE TABLE worker_launch_preparation(launch_id,intent_digest,service_boot_id);
 CREATE TABLE worker_launch_device(launch_id,device_id);`);
 const target={launch_id:'launch.old',launch_intent_digest:hash('launch'),service_boot_id:'boot.old'};
 const operation={operation_id:'operation.new',device_id:'device',expected_control:{epoch:'epoch',version:'1'},target:{version:'2'},state:'pending'};
 db.prepare('INSERT INTO control_operation_revision VALUES(?,1,?,?)').run(operation.operation_id,canonicalize(operation),hash(operation));
 db.prepare('INSERT INTO control_operation_head VALUES(?,1)').run(operation.operation_id);
 db.prepare('INSERT INTO control_barrier_target VALUES(?,?,?,?)').run(operation.operation_id,...Object.values(target));
 db.prepare('INSERT INTO worker_launch_preparation VALUES(?,?,?)').run(...Object.values(target));
 db.prepare('INSERT INTO worker_launch_device VALUES(?,?)').run(target.launch_id,operation.device_id);
 db.prepare('INSERT INTO ca_request_key VALUES(?,?)').run('request',operation.device_id);
 db.prepare('INSERT INTO ca_adjudication VALUES(?,?)').run('request',accepted?'accepted':'rejected');
 const body={targets:[target],receipts:[{key:{launch_id:target.launch_id,launch_intent_digest:target.launch_intent_digest},
  record:{state:'retired'},retirement:{result:retired?'confirmed_empty':'indeterminate'}}]};
 if(history)db.prepare('INSERT INTO control_barrier_evidence VALUES(?,?,?)').run('operation.old',canonicalize(body),corrupt?hash('other'):hash(body));
 const domain={ref:{clock_domain_id:'domain.new',descriptor_digest:hash('domain')},tick:'1'};
 let open=true;const barrier=deviceControlBarrier({db,bootId:'boot.new',authorization:{domain:()=>domain,
  retireForControl(){assert.fail('不得向当前监督器询问旧boot启动');}},runtime:{invalidate(){assert.fail('不得重绑定旧启动');}},isOpen:()=>open});
 return {db,operation,barrier,domain,close(){open=false;}};
}
test('历史完整退役原件可用于新boot屏障，复制证据无效',async t=>{
 const f=fixture(t),evidence=await f.barrier.protect(f.operation);
 assert.equal(evidence.receipts[0].prior_barrier.operation_id,'operation.old');
 f.db.transaction(()=>f.barrier.verify(f.operation,evidence))();
 assert.throws(()=>f.db.transaction(()=>f.barrier.verify(f.operation,structuredClone(evidence)))(),/control_barrier_proof/);
});
for(const [name,options,code] of [
 ['缺少历史原件',{history:false},'old_exit_unresolved'],
 ['历史退出未确认',{retired:false},'old_exit_unresolved'],
 ['历史摘要损坏',{corrupt:true},'integrity'],
 ['已有接纳命令',{accepted:true},'command_barrier_required']
])test(name+'不会生成完成证明',async t=>{
 const f=fixture(t,options);await assert.rejects(f.barrier.protect(f.operation),new RegExp('control_'+code));
});
test('屏障核验重新检查完整启动集合和当前域',async t=>{
 const f=fixture(t),evidence=await f.barrier.protect(f.operation);
 f.db.prepare('INSERT INTO worker_launch_preparation VALUES(?,?,?)').run('uncovered',hash('uncovered'),'boot.old');
 f.db.prepare('INSERT INTO worker_launch_device VALUES(?,?)').run('uncovered','device');
 assert.throws(()=>f.db.transaction(()=>f.barrier.verify(f.operation,evidence))(),/control_barrier_coverage/);
 f.domain.ref={...f.domain.ref,clock_domain_id:'changed'};
 assert.throws(()=>f.db.transaction(()=>f.barrier.verify(f.operation,evidence))(),/control_barrier_changed/);
});

test('升级后的旧pending没有受理切点时保持未决，不补造切点或复用旧boot退出作为完整证明',async t=>{
 const f=fixture(t),before=f.db.prepare('SELECT * FROM control_operation_revision').raw().all();
 f.db.exec('CREATE TABLE control_command_cut(operation_id,device_id,commit_id,body_jcs,body_digest); PRAGMA user_version=58;');
 await assert.rejects(f.barrier.protect(f.operation),/control_command_cut_missing/);
 assert.deepEqual(f.db.prepare('SELECT * FROM control_operation_revision').raw().all(),before);
 assert.equal(f.db.prepare('SELECT count(*) FROM control_command_cut').pluck().get(),0);
 assert.equal(f.db.prepare('SELECT count(*) FROM control_barrier_evidence').pluck().get(),1);
});
