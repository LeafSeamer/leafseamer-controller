import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {deviceControlRepository} from '../dist/device-control-repository.mjs';
import {deviceRegistryReader} from '../dist/device-registry-store.mjs';
import {currentControlSource,readControlSource,saveControlSources} from '../dist/device-control-source.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {currentDeviceAuthorization,protectControlAuthorization} from '../dist/device-authorization-state.mjs';
const domain={ref:{clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:'sha256:'+'2'.repeat(64)},tick:'100'};
async function fixture(t,revision=32){
 const f=await setup(t,revision),e=f.store.enrollment.begin();
 await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const service=f.store.identity,device=f.store.registerDevice({request_id:'source.device',device_kind:'simulator',display_name:'来源测试'}).device_id;
 f.close();return {...f,service,device};
}
function write(db,f,observed=domain){
 const repo=deviceControlRepository(db,deviceRegistryReader(db,f.service),()=>observed),commit=crypto.randomUUID();
 return db.transaction(()=>{const record=repo.current('record',f.device);repo.touch('record',record,commit);
  repo.commit(commit,'indeterminate',null,1,{synthetic:true});return commit;
 }).immediate();
}
function check(db){db.pragma('foreign_keys=ON');db.pragma('trusted_schema=OFF');}
test('控制物理原件来自同一变更提交，精确保存来源域与自摘要；公开ID不充当物理Ref',async t=>{
 const f=await fixture(t);inspect(f.dir,db=>{check(db);const id=write(db,f);
  const result=db.transaction(()=>currentControlSource(db,f.device))();assert.equal(result.current.ref.id,id);assert.deepEqual(result.current.ref,result.authority.ref);
  const value=result.current.value,{record_digest,...unsigned}=value;
  assert.equal(value.observed_tick_ns,'100');assert.equal(value.clock_domain_id,domain.ref.clock_domain_id);assert.equal(value.revision,'2');
  assert.equal(record_digest,'sha256:'+crypto.createHash('sha256').update(canonicalize(unsigned)).digest('hex'));
  const publicRecord=JSON.parse(db.prepare('SELECT body_jcs FROM control_record_revision').pluck().get());assert.notEqual(value.change_id,publicRecord.record_id);
  assert.throws(()=>currentControlSource(db,f.device),/control_source_writer/);
  assert.throws(()=>db.exec('DELETE FROM control_state_source'),/immutable_control_source/);
  const repo=deviceControlRepository(db,deviceRegistryReader(db,f.service),()=>domain);
  assert.throws(()=>db.transaction(()=>repo.touch('record',repo.current('record',f.device),id)).immediate(),/control_source_commit_closed/);
  assert.throws(()=>write(db,f,{...domain,tick:'99'}),/control_source_clock/);
  assert.equal(db.prepare('SELECT count(*) FROM control_record_revision').pluck().get(),1);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('原件缺写、源域错误或提交失败回滚公开修订、head、原件与审计',async t=>{
 const f=await fixture(t);inspect(f.dir,db=>{check(db);
  for(const [table,action] of [['control_state_source','IGNORE'],['control_state_source',"ABORT,'injected_source'"],['control_change_commit',"ABORT,'injected_commit'"]]){
   db.exec(`CREATE TRIGGER source_fault BEFORE INSERT ON ${table} BEGIN SELECT RAISE(${action}); END`);
   assert.throws(()=>write(db,f));db.exec('DROP TRIGGER source_fault');
   for(const name of ['control_state_source','control_record_revision','control_record_head','control_change_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);
  }
  assert.throws(()=>write(db,f,{...domain,tick:'001'}),/control_source_domain/);
  const repo=deviceControlRepository(db,deviceRegistryReader(db,f.service));
  assert.throws(()=>db.transaction(()=>{const id=crypto.randomUUID();repo.touch('record',repo.current('record',f.device),id);
   db.prepare('INSERT INTO control_change_commit VALUES(?,?,?,?,?,?)').run(id,'indeterminate',1,'{}',id,'{}');
  }).immediate(),/control_source_required/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('schema34控制变更同时追加保护状态，重复读取不增加修订，缺写回滚全部来源',async t=>{
 const f=await fixture(t,34);inspect(f.dir,db=>{check(db);const first=write(db,f);
  const original=db.transaction(()=>currentDeviceAuthorization(db,f.device))();
  assert.equal(original.value.status,'protected');assert.equal(original.ref.revision,'1');
  assert.equal(original.value.context.control_authority_ref.id,first);assert.equal(original.value.context.evaluator_lineage,null);
  const again=db.transaction(()=>protectControlAuthorization(db,currentControlSource(db,f.device).authority.value)).immediate();
  assert.deepEqual(again,original);
  write(db,f,{...domain,tick:'101'});const next=db.transaction(()=>currentDeviceAuthorization(db,f.device))();
  assert.equal(next.ref.revision,'2');assert.deepEqual(next.value.parent_ref,original.ref);assert.deepEqual(next.value.reasons,['control_changed']);
  const tables=['control_record_revision','control_record_head','control_state_source','control_change_commit','device_authorization_state','device_authorization_commit','device_authorization_head'];
  const snapshot=()=>tables.map(name=>db.prepare('SELECT * FROM '+name+' ORDER BY 1').raw().all());
  for(const table of ['device_authorization_state','device_authorization_commit','device_authorization_head']){
   const before=snapshot(),operation=table.endsWith('_head')?'UPDATE':'INSERT';
   db.exec(`CREATE TRIGGER test_omit BEFORE ${operation} ON ${table} BEGIN SELECT RAISE(IGNORE); END;`);
   assert.throws(()=>write(db,f,{...domain,tick:'102'}),/authorization_state_storage|authorization_state_parent/);
   db.exec('DROP TRIGGER test_omit');assert.deepEqual(snapshot(),before);
  }
  assert.throws(()=>db.prepare('UPDATE device_authorization_state SET body_jcs=body_jcs').run(),/immutable_device_authorization/);
  assert.throws(()=>db.prepare('DELETE FROM device_authorization_head').run(),/device_authorization_head_retained/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema34升级35保留保护状态，不从历史启动记录补造当前核心观察',async t=>{
 const f=await fixture(t,34);let before;
 inspect(f.dir,db=>{check(db);write(db,f);before=db.prepare('SELECT * FROM device_authorization_state').raw().all();});
 const migrated=await migrateStorage(f.dir,35);assert.equal(migrated.schema_revision,'35');assert.ok(migrated.backup_ref);
 inspect(f.dir,db=>{check(db);assert.deepEqual(db.prepare('SELECT * FROM device_authorization_state').raw().all(),before);
  assert.equal(db.prepare('SELECT count(*) FROM core_runtime_source').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM core_runtime_source_commit').pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema33升级34不补造历史授权状态；当前来源在新writer内初始化保护态',async t=>{
 const f=await fixture(t,33);let before;
 inspect(f.dir,db=>{check(db);write(db,f);before=db.prepare('SELECT * FROM control_state_source').raw().all();});
 const migrated=await migrateStorage(f.dir,34);assert.equal(migrated.schema_revision,'34');assert.ok(migrated.backup_ref);
 inspect(f.dir,db=>{check(db);assert.deepEqual(db.prepare('SELECT * FROM control_state_source').raw().all(),before);
  assert.equal(db.prepare('SELECT count(*) FROM device_authorization_state').pluck().get(),0);
  const state=db.transaction(()=>protectControlAuthorization(db,currentControlSource(db,f.device).authority.value,{...domain,tick:'150'})).immediate();
  assert.equal(state.ref.revision,'1');assert.equal(state.value.status,'protected');
  assert.equal(JSON.parse(db.prepare('SELECT body_jcs FROM device_authorization_commit').pluck().get()).sampled_tick_ns,'150');
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema32升级33保留控制原件，不补造人员执行来源',async t=>{
 const f=await fixture(t,32);let before;
 inspect(f.dir,db=>{check(db);write(db,f);before=db.prepare('SELECT * FROM control_state_source').raw().all();});
 const migrated=await migrateStorage(f.dir,33);assert.equal(migrated.schema_revision,'33');assert.ok(migrated.backup_ref);
 inspect(f.dir,db=>{check(db);assert.deepEqual(db.prepare('SELECT * FROM control_state_source').raw().all(),before);
  assert.equal(db.prepare('SELECT count(*) FROM execution_manual_authority').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM execution_manual_authority_commit').pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema31升级32保留原控制字节，不补造来源或过去时刻；新变更取得新原件',async t=>{
 const f=await fixture(t,31);let original,oldCommit;
 inspect(f.dir,db=>{check(db);oldCommit=write(db,f);original=db.prepare('SELECT body_jcs FROM control_record_revision').pluck().get();});
 const migrated=await migrateStorage(f.dir,32);assert.equal(migrated.schema_revision,'32');assert.ok(migrated.backup_ref);
 inspect(f.dir,db=>{check(db);assert.equal(db.prepare('SELECT count(*) FROM control_state_source').pluck().get(),0);
  assert.equal(db.prepare('SELECT body_jcs FROM control_record_revision').pluck().get(),original);
  assert.throws(()=>db.transaction(()=>readControlSource(db,f.device,2))(),/control_source_missing/);
  assert.throws(()=>db.transaction(()=>saveControlSources(db,oldCommit,'indeterminate',()=>domain)).immediate(),/control_source_commit_closed/);
  const id=write(db,{...f,service:{...f.service,schema_revision:'32'}});
  const current=db.transaction(()=>currentControlSource(db,f.device))();assert.equal(current.current.ref.id,id);assert.equal(current.current.ref.revision,'3');
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
