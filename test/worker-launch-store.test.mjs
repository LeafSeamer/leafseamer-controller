import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import canonicalize from 'canonicalize';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const bytes=value=>Buffer.from(canonicalize(value));
const key=intent=>({launch_id:intent.launch_id,launch_intent_digest:hash(intent)});
function temporary(t){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-worker-launch-'));
  t.after(()=>{assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});return root;
}
function inspect(root,fn){const db=new Database(path.join(root,'controller.sqlite'));try{return fn(db);}finally{db.close();}}
import {bind} from './fixtures/core-binding.mjs';
async function setup(t,{parent=true,trigger=null,revision=12}={}){
  const root=temporary(t);initializeStorage(root);await migrateStorage(root,revision);
  if(trigger)inspect(root,db=>db.exec(trigger));
  const storage=openStorage(root);t.after(()=>storage.close());
  const capability=storage.enrollment.begin();
  await storage.enrollment.complete({token_id:capability.token_id,secret:capability.secret,login:'synthetic-admin',
    password:'synthetic-worker-password-012345',mode:'standalone'});
  const devices=[1,2].map(n=>storage.registerDevice({request_id:'device-request-'+n,device_kind:'synthetic-device',display_name:'准备测试设备'+n}).device_id).sort();
  const core=parent?bind(storage):null;
  const reference=kind=>({kind,authority_service_id:storage.identity.service_id,database_instance_id:storage.identity.database_instance_id,
    object_id:kind==='platform_profile'?'synthetic-profile':kind,revision:'1',digest:hash(kind)});
  const intent={launch_id:'worker',service_id:storage.identity.service_id,supervisor_instance_id:core?.descriptor.supervisor_instance_id??'supervisor',
    runtime_generation:core?.descriptor.runtime_generation??'generation',member_id:'worker-member',role:'worker',
    artifact_manifest_ref:core?.intent.artifact_manifest_ref??{manifest_id:'synthetic-bundle',revision:'1',digest:hash('bundle')},
    containment_ref:{group_id:'worker-group',generation:'1',backend:'windows_job'},object_scope:{kind:'devices',device_ids:devices},policy_revision:'1',
    extension_binding:{installation_ref:reference('installation'),approval_ref:reference('approval'),review_ref:reference('review'),
      role_resolution_ref:reference('role_resolution'),configuration_ref:reference('configuration'),intake_ref:reference('intake'),
      platform_profile_ref:reference('platform_profile'),host_installation_id:'host',host_trust_epoch:'1',
      manifest_digest:hash('manifest'),artifact_set_digest:hash('artifacts'),entry_id:'simulator',permissions_digest:hash('permissions')}};
  return {root,storage,intent,core};
}

test('实际业务库准备完整worker意图、精确设备集合和审计，幂等查原且重启不复活',async t=>{
  const f=await setup(t),input=bytes(f.intent),pending=f.storage.workerLaunches.prepare(input);input.fill(32);
  const result=await pending;
  assert.deepEqual(result.intent,f.intent);assert.equal(result.current_boot,true);assert.equal(result.ref.digest,hash(f.intent));
  assert(Object.isFrozen(result.intent.extension_binding));
  assert.deepEqual(await f.storage.workerLaunches.prepare(bytes(f.intent)),result);
  assert.deepEqual(f.storage.workerLaunches.query(key(f.intent)),result);assert.deepEqual(f.storage.workerLaunches.current(),[result]);
  await assert.rejects(f.storage.workerLaunches.prepare(bytes({...f.intent,policy_revision:'2'})),e=>e.code==='worker_launch_conflict');
  assert.throws(()=>f.storage.workerLaunches.query({...key(f.intent),launch_intent_digest:hash('other')}),e=>e.code==='worker_launch_conflict');
  f.storage.close();assert.throws(()=>f.storage.workerLaunches.query(key(f.intent)),e=>e.code==='worker_launch_closed');
  inspect(f.root,db=>{
    assert.equal(db.prepare('SELECT count(*) FROM worker_launch_preparation').pluck().get(),1);
    assert.deepEqual(db.prepare('SELECT device_id FROM worker_launch_device ORDER BY device_id').pluck().all(),f.intent.object_scope.device_ids);
    assert.equal(db.prepare('SELECT count(*) FROM worker_launch_preparation_commit').pluck().get(),1);
    assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length,0);
    for(const table of ['worker_launch_preparation','worker_launch_device','worker_launch_preparation_commit'])assert.throws(()=>db.exec('DELETE FROM '+table),/required/);
    assert.throws(()=>db.exec("UPDATE worker_launch_preparation SET state='admitted_closed'"),/immutable/);
  });
  const reopened=openStorage(f.root);try{
    assert.deepEqual(reopened.workerLaunches.query(key(f.intent)),{...result,current_boot:false});
    await assert.rejects(reopened.workerLaunches.prepare(bytes(f.intent)),e=>e.code==='worker_launch_stale_boot');
    assert.throws(()=>reopened.workerLaunches.current(),e=>e.code==='worker_launch_core_required');
    bind(reopened);assert.deepEqual(reopened.workerLaunches.current(),[]);
    await assert.rejects(reopened.workerLaunches.prepare(bytes({...f.intent,launch_id:'another'})),e=>e.code==='worker_launch_binding');
  }finally{reopened.close();}
});

test('准备前核当前核心、权威、域、平台、实际设备及成员组唯一性，失败不建立记录',async t=>{
  const missing=await setup(t,{parent:false});
  await assert.rejects(missing.storage.workerLaunches.prepare(bytes(missing.intent)),e=>e.code==='worker_launch_core_required');missing.storage.close();
  const f=await setup(t);
  for(const change of [value=>{value.supervisor_instance_id='other';},value=>{value.runtime_generation='other';},
    value=>{value.extension_binding.platform_profile_ref.object_id='other';},value=>{value.member_id=f.core.intent.member_id;}]){
    const intent=structuredClone(f.intent);change(intent);await assert.rejects(f.storage.workerLaunches.prepare(bytes(intent)),e=>e.code==='worker_launch_binding');
  }
  await assert.rejects(f.storage.workerLaunches.prepare(bytes({...f.intent,object_scope:{kind:'devices',device_ids:['missing']}})),e=>e.code==='worker_launch_device_missing');
  const foreign=structuredClone(f.intent);foreign.extension_binding.approval_ref.database_instance_id='other';
  await assert.rejects(f.storage.workerLaunches.prepare(bytes(foreign)));assert.deepEqual(f.storage.workerLaunches.current(),[]);
  await f.storage.workerLaunches.prepare(bytes(f.intent));
  await assert.rejects(f.storage.workerLaunches.prepare(bytes({...f.intent,launch_id:'second'})),e=>e.code==='worker_launch_identity_conflict');
  const pending=f.storage.workerLaunches.prepare(bytes({...f.intent,launch_id:'late'}));f.storage.close();
  await assert.rejects(pending,e=>e.code==='worker_launch_closed');
});

test('准备、设备关联或审计写入失败整体回滚，遗漏设备不能提交完整准备',async t=>{
  const triggers=[...['worker_launch_preparation','worker_launch_device','worker_launch_preparation_commit'].map(table=>
    `CREATE TRIGGER synthetic_failure BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_write_failure'); END;`),
    'CREATE TRIGGER synthetic_skip BEFORE INSERT ON worker_launch_device BEGIN SELECT RAISE(IGNORE); END;'];
  for(const trigger of triggers){
    const f=await setup(t,{trigger});await assert.rejects(f.storage.workerLaunches.prepare(bytes(f.intent)),/synthetic_write_failure|worker_launch_incomplete/);
    assert.deepEqual(f.storage.workerLaunches.current(),[]);f.storage.close();
    inspect(f.root,db=>{for(const table of ['worker_launch_preparation','worker_launch_device','worker_launch_preparation_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);});
  }
});

test('schema11显式备份迁移到12，保留核心历史与身份，旧库不隐式增加启动准备',async t=>{
  const f=await setup(t,{revision:11});assert.equal(f.storage.workerLaunches,null);
  const identity=f.storage.identity;f.storage.close();
  const before=inspect(f.root,db=>db.prepare('SELECT * FROM core_runtime_binding').raw().all());
  const upgraded=await migrateStorage(f.root,12);assert.equal(upgraded.schema_revision,'12');assert.equal(upgraded.steps.length,1);
  const backup=new Database(path.join(f.root,upgraded.backup_file),{readonly:true});try{
    assert.equal(backup.pragma('user_version',{simple:true}),11);assert.deepEqual(backup.prepare('SELECT * FROM core_runtime_binding').raw().all(),before);
  }finally{backup.close();}
  assert.equal(upgraded.backup_ref,'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(path.join(f.root,upgraded.backup_file))).digest('hex'));
  assert.deepEqual(await migrateStorage(f.root,12),{schema_revision:'12',changed:false});
  await assert.rejects(migrateStorage(f.root,11),e=>e.code==='migration_downgrade');
  const opened=openStorage(f.root);try{assert.equal(opened.identity.service_id,identity.service_id);assert.equal(opened.identity.database_instance_id,identity.database_instance_id);}finally{opened.close();}
  inspect(f.root,db=>{assert.deepEqual(db.prepare('SELECT * FROM core_runtime_binding').raw().all(),before);assert.equal(db.prepare('SELECT count(*) FROM worker_launch_preparation').pluck().get(),0);});
});
