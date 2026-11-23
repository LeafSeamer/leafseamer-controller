import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import crypto from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from 'canonicalize';
import Database from 'better-sqlite3';
import {initializeStorage, migrateStorage} from '../dist/storage.mjs';
import {initializeProcessHost, startProcessHost, installedCoreDigest, installedTimeProviderDigest, upgradeTimeProviderJournal} from '../dist/process-host.mjs';
import {connectCoreSupervisor,coreRefreshDelayMs} from '../dist/supervisor-control.mjs';
import {timeProviderCaptureStore} from '../dist/time-provider-capture.mjs';
const options = {skip: process.platform !== 'win32', timeout: 60000};
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-control-'));
  t.after(() => { assert.equal(path.dirname(path.resolve(dir)), path.resolve(os.tmpdir())); fs.rmSync(dir, {recursive: true, force: true}); }); return dir;
}
function collect() {
  let buffer = ''; const frames = [];
  return {frames, write(chunk) { buffer += chunk; while (buffer.includes('\n')) { const end = buffer.indexOf('\n'); frames.push(JSON.parse(buffer.slice(0, end))); buffer = buffer.slice(end + 1); } }};
}
async function until(fn) {
  const deadline = performance.now() + 10000;
  while (!fn()) { assert(performance.now() < deadline, '等待真实进程事件超时'); await delay(20); } return fn();
}
function policyFor(identity) {
  return {format: 'leafseamer-core-bootstrap-policy/1', service_id: identity.service_id, database_instance_id: identity.database_instance_id,
    artifact_manifest_ref: {manifest_id: 'local-integration', revision: '1', digest: installedCoreDigest()},
    platform_profile_ref: {profile_id: 'synthetic-windows-profile', revision: '1'}, policy_revision: '1', bootstrap_timeout_ms: 10000, clock_backend_revision: '1'};
}
function inspect(dir, fn) {
  const db = new Database(path.join(dir, 'supervisor-journal.db'), {fileMustExist: true}); try { fn(db); } finally { db.close(); }
}
async function raw(t, mode, setup, provider=false, previous=null, fixturePort=null) {
  const dir = previous?.dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'leafseamer-control-'));
  const children=previous?.children??[];
  if(!previous)t.after(async()=>{
    for(const {child,closed} of children){
      if(child.exitCode===null&&child.signalCode===null) child.kill();
      await closed;
    }
    assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});
  });
  const identity = previous?.identity ?? initializeStorage(dir);
  if(!previous) await initializeProcessHost(dir);
  if(mode==='time-provider-schedule'||mode==='time-provider-schedule-close') await migrateStorage(dir,87);
  if(mode==='time-provider-invalidation'||mode==='time-provider-invalidation-write-fault'){
    await migrateStorage(dir,90);
    if(mode.endsWith('-write-fault')){
      const db=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
      try{db.exec('CREATE TRIGGER omit_reference_protection BEFORE INSERT ON time_provider_reference_protection BEGIN SELECT RAISE(IGNORE); END');}
      finally{db.close();}
    }
  }
  if(mode==='time-provider-authentication') await migrateStorage(dir,81);
  if(mode==='time-provider-anchor'||mode==='time-provider-anchor-write-fault') {
    await migrateStorage(dir,87);
    if(mode==='time-provider-anchor-write-fault') {
      const db=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
      try{db.exec('CREATE TRIGGER omit_reference_anchor BEFORE INSERT ON time_provider_reference_anchor BEGIN SELECT RAISE(IGNORE); END');}
      finally{db.close();}
    }
  }
  if(mode==='time-provider-control'||mode==='time-provider-control-write-fault') {
    await migrateStorage(dir,86);
    if(mode==='time-provider-control-write-fault') {
      const db=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
      try{db.exec('CREATE TRIGGER omit_control BEFORE INSERT ON time_provider_poll_control BEGIN SELECT RAISE(IGNORE); END');}
      finally{db.close();}
    }
  }
  if(['time-provider-capture','time-provider-capture-restart','time-provider-capture-rollback','time-provider-capture-repeat','time-provider-ack-fault'].includes(mode)) {
    await migrateStorage(dir,84);
    if(mode==='time-provider-capture-rollback'){
      const database=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
      try{database.exec('CREATE TRIGGER omit_capture BEFORE INSERT ON time_provider_capture BEGIN SELECT RAISE(IGNORE); END');}
      finally{database.close();}
    }
  }
  if(mode==='time-provider-polls') {
    await migrateStorage(dir,81);
    const before=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
    const migrations=db=>db.prepare("SELECT * FROM schema_migration WHERE to_revision<>'82' ORDER BY CAST(to_revision AS INTEGER)").raw().all();
    const history=db=>['service_boot','core_runtime_binding','time_provider_runtime_binding','authentication_clock_acquisition']
      .map(table=>db.prepare('SELECT * FROM '+table+' ORDER BY rowid').raw().all());
    let prior, originals;
    try{prior=migrations(before);originals=history(before);}
    finally{before.close();}
    await migrateStorage(dir,82);
    const after=new Database(path.join(dir,'controller.sqlite'),{fileMustExist:true});
    try{
      assert.deepEqual(migrations(after),prior);
      assert.deepEqual(history(after),originals);
      assert.deepEqual(after.prepare('SELECT service_id,database_instance_id FROM service_state').raw().get(),[identity.service_id,identity.database_instance_id]);
      assert.deepEqual(after.pragma('foreign_key_check'),[]);
      after.exec("CREATE TRIGGER omit_test_attempt BEFORE INSERT ON time_provider_poll_attempt WHEN NEW.poll_id='poll.rollback' BEGIN SELECT RAISE(IGNORE); END");
    }finally{after.close();}
  }
  if (setup) inspect(dir, setup);
  const output = collect(), status = collect();
  const policy=policyFor(identity), flags=[];
  if(provider){
    if(!previous) await upgradeTimeProviderJournal(dir);
    flags.push('--time-provider-policy',canonicalize({...policy,format:'leafseamer-time-provider-bootstrap-policy/1',
      artifact_manifest_ref:{manifest_id:'reference-time-integration',revision:'1',digest:installedTimeProviderDigest()}}));
  }
  if(fixturePort!==null)flags.push('--fixture-port',String(fixturePort));
  const child = spawn(fileURLToPath(new URL('../dist/native/leafseamer_process_host.exe', import.meta.url)),
    [dir, process.execPath, fileURLToPath(new URL('./fixtures/control-core.mjs', import.meta.url)), 'contained-core-auth', '--bootstrap-policy', canonicalize(policy), '--mode', mode,...flags],
    {stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true});
  const closed = once(child, 'close'); child.stdin.on('error', () => {}); child.stdout.on('data', status.write); child.stderr.on('data', output.write);
  children.push({child,closed});
  return {dir, identity, child, closed, status, output, children};
}

const providerOptions={...options,skip:options.skip||!fs.existsSync(new URL('../dist/runtime/reference-time-provider.exe',import.meta.url))};
test('真实核心经原控制管道核对时间提供者并拒绝错摘要和旧观察', providerOptions,async t=>{
 const run=await raw(t,'time-provider-observation',null,true);
 const observed=await until(()=>run.output.frames.find(f=>f.event==='time-provider-observed'));
 assert.equal(observed.role,'time_provider');
 assert.equal(observed.sameDomain,true);
 assert.equal(observed.sameDescriptor,true);
 assert.equal(observed.processBound,true);
 const started=await until(()=>run.status.frames.find(f=>f.event==='process_contained'));
 assert.equal(observed.providerPid,started.time_provider_pid);
 assert.equal(observed.observedBeforeDeadline,true);
 assert.deepEqual(observed.errors,{copy:'supervisor_time_provider_withdrawn',digest:'supervisor_identity_conflict',
  superseded:'supervisor_time_provider_withdrawn'});
 run.child.stdin.end('stop\n');
 await run.closed;
 assert.equal(run.status.frames.at(-1).active_processes,0);
});

test('时间提供者专用管道拒绝从其他进程认领核心端点', providerOptions, async t=>{
 const run=await raw(t,'time-provider-observation',null,true);
 const {providerBoot}=await until(()=>run.output.frames.find(f=>f.event==='time-provider-observed'));
 const socket=net.createConnection('\\\\.\\pipe\\LeafSeamer.TimeCollector.'+providerBoot+'.core');
 t.after(()=>socket.destroy());
 let received=0;
 socket.on('data',chunk=>{received+=chunk.length;});
 socket.on('error',()=>{});
 const closed=once(socket,'close').catch(()=>{});
 await once(socket,'connect');
 const [exitCode]=await run.closed;
 await closed;
 assert.notEqual(exitCode,0);
 assert.equal(received,0);
 assert.equal(run.status.frames.at(-1).active_processes,0);
 assert.equal(run.status.frames.at(-1).control_failed,true);
});

test('时间提供者拒绝绑定进程提交的错误提供者 PID，即使绑定摘要匹配', providerOptions, async t=>{
 const run=await raw(t,'time-provider-link-bad-binding',null,true);
 await run.closed;
 assert.equal(run.output.frames.some(f=>f.event==='bad-binding-accepted'),false);
 const empty=run.status.frames.at(-1);
 assert.equal(empty.active_processes,0);
 assert.equal(empty.control_failed,true);
 assert.notEqual(empty.time_provider_exit_code,0);
});

test('时间提供者经专用进程管道确认同域认证区间与持久原件', providerOptions, async t=>{
 const run=await raw(t,'time-provider-authentication',null,true);
 const {sample}=await until(()=>run.output.frames.find(f=>f.event==='time-provider-authenticated'));
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  const original=JSON.parse(db.prepare('SELECT body FROM authentication_clock_acquisition WHERE id=?').pluck().get(sample.acquisition_ref.id));
  const binding=JSON.parse(db.prepare('SELECT body_jcs FROM time_provider_runtime_binding').pluck().get());
  assert.equal(sample.acquisition_ref.digest,original.digest);
  assert.deepEqual(sample.runtime_ref,original.runtime_ref);
  assert.deepEqual(sample.policy_ref,original.policy_ref);
  assert.equal(sample.runtime_domain_ref.descriptor_digest,binding.clock_domain_descriptor.descriptor_digest);
  assert.equal(sample.runtime_domain_ref.clock_domain_id,original.clock_domain_id);
  assert.equal(sample.valid_before_tick_ns,original.valid_before_tick_ns);
 }finally{db.close();}
 run.child.stdin.end('stop\n');
 const [exitCode]=await run.closed;
 assert.equal(exitCode,0);
 assert.equal(run.status.frames.at(-1).time_provider_exit_code,0);
});

test('时间提供者采样预约与一次发送尝试持久绑定，失败回滚且重启不可重放', providerOptions, async t=>{
 const legacy=await raw(t,'time-provider-authentication',null,true);
 await until(()=>legacy.output.frames.find(f=>f.event==='time-provider-authenticated'));
 legacy.child.stdin.end('stop\n');
 assert.equal((await legacy.closed)[0],0);
 const initial=await raw(t,'time-provider-polls',null,true,legacy);
 const record=run=>run.output.frames.find(f=>f.event==='time-provider-poll-records');
 const first=await until(()=>record(initial));
 assert(first.rolledBack);
 assert.deepEqual(first.errors,{changed:'time_provider_poll_source_changed',duplicate:'time_provider_poll_already_attempted',
  sameSource:'time_provider_poll_source_busy',alias:'time_provider_poll_source_busy',rollback:'time_provider_poll_attempt_storage',expired:'time_provider_poll_expired',
  afterCommit:'test_source_unavailable',uncertainReplay:'time_provider_poll_already_attempted',capacity:'time_provider_poll_capacity'});
 assert.equal(first.row.reservation.service_boot_id,first.bootId);
 assert.equal(first.row.attempt.poll_ref.digest,first.row.digest);
 assert.equal(first.row.attempt.expires_tick_ns,first.row.reservation.expires_tick_ns);
 initial.child.stdin.end('stop\n');
 assert.equal((await initial.closed)[0],0);
 const reopened=await raw(t,'time-provider-polls-restart',null,true,initial);
 const after=await until(()=>record(reopened));
 assert.notEqual(after.bootId,first.bootId);
 assert.deepEqual(after.row,first.row);
 assert.deepEqual(after.errors,{oldAttempt:'time_provider_poll_identity_conflict',oldReserve:'time_provider_poll_identity_conflict',
  sameSource:'time_provider_poll_source_busy'});
 reopened.child.stdin.end('stop\n');
 assert.equal((await reopened.closed)[0],0);
 const db=new Database(path.join(initial.dir,'controller.sqlite'),{fileMustExist:true});
 const prior=db=>['time_provider_poll_reservation','time_provider_poll_attempt']
  .map(table=>db.prepare('SELECT * FROM '+table+' ORDER BY poll_id').raw().all());
 let original;
 try{
  assert.deepEqual(db.prepare('SELECT poll_id FROM time_provider_poll_attempt ORDER BY poll_id').pluck().all(),['poll.first','poll.uncertain']);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_reservation').pluck().get(),4);
  assert.throws(()=>db.prepare('DELETE FROM time_provider_poll_attempt').run(),/immutable_time_provider_poll_attempt/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  original=prior(db);
 }finally{db.close();}
 await migrateStorage(initial.dir,83);
 const migrated=new Database(path.join(initial.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.deepEqual(prior(migrated),original);
  assert.deepEqual(migrated.pragma('foreign_key_check'),[]);
 }finally{migrated.close();}
});

test('时间提供者经真实管道发出一次授权 UDP 采集，拒绝撤回、重放和过期', providerOptions, async t=>{
 const run=await raw(t,'time-provider-capture',null,true);
 const result=await until(()=>run.output.frames.find(f=>f.event==='time-provider-capture'));
 assert.equal(result.received,1);
 assert.equal(result.attemptedBeforeUDP,true);
 assert.deepEqual(result.archive,{status:'archived',receipt:result.candidate.receipt});
 const sample=result.candidate.candidate;
 assert(BigInt(sample.m1_tick_ns)>=BigInt(result.confirmed.attempted_tick_ns));
 assert(BigInt(sample.m4_tick_ns)<BigInt(result.confirmed.valid_before_tick_ns));
 const sent=Buffer.from(sample.request,'base64url'),reply=Buffer.from(sample.response,'base64url');
 assert.deepEqual(sent.subarray(40,48),reply.subarray(24,32));
 assert.equal(result.busy,'time_provider_poll_busy');
 assert.equal(result.replay,'time_provider_poll_already_attempted');
 assert.deepEqual(result.refused,{status:'unavailable',candidate:null,control:null});
 assert(result.revokedReads>=4);
 assert.equal(result.revokedAttempt,true);
 assert.equal(result.endpoint,'time_provider_poll_endpoint_binding');
 assert.equal(result.changedAttempt,null);
 assert.equal(result.expired,'time_provider_poll_expired');
 assert.equal(result.expiredAttempt,null);
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const database=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 const damagedPath=path.join(run.dir,'capture-damaged-test.sqlite');
 try {
  const [cipher,nonce,tag,text]=database.prepare('SELECT ciphertext,nonce,tag,body_jcs FROM time_provider_capture').raw().get();
  assert.equal(nonce.length,12);assert.equal(tag.length,16);
  assert(!cipher.includes(Buffer.from(sample.request)));assert(!cipher.includes(Buffer.from(sample.response)));
  assert(!text.includes(sample.request));assert(!text.includes(sample.response));
  assert.throws(()=>database.prepare('DELETE FROM time_provider_capture').run(),/immutable_time_provider_capture/);
  assert.deepEqual(database.pragma('foreign_key_check'),[]);
  await database.backup(damagedPath);
 }finally{database.close();}
 const damaged=new Database(damagedPath,{fileMustExist:true});
 try{
  // Only the isolated backup is damaged to exercise GCM authentication.
  damaged.exec('DROP TRIGGER time_provider_capture_no_update');
  const tag=damaged.prepare('SELECT tag FROM time_provider_capture').pluck().get();tag[0]^=1;
  damaged.prepare('UPDATE time_provider_capture SET tag=?').run(tag);
  const key=crypto.createSecretKey(crypto.createHash('sha256').update('isolated archive fixture').digest());
  const archive=timeProviderCaptureStore(damaged,run.identity,{
   currentKey(){throw new Error('read_only_fixture');},
   readKey(scope,id){return {...scope,id,key,writable:false};}
  });
  assert.throws(()=>archive.read(result.archive.receipt.poll_ref),/time_provider_capture_authentication/);
 }finally{damaged.close();}
 const reopened=await raw(t,'time-provider-capture-restart',null,true,run);
 const historical=await until(()=>reopened.output.frames.find(f=>f.event==='time-provider-archive-reopened'));
 assert.equal(historical.restoredDigest,result.archive.receipt.plaintext_digest);
 assert.deepEqual(historical.receipt,result.archive.receipt);
 assert.equal(historical.wrong,'time_provider_capture_integrity');
 assert.equal(historical.replay,'time_provider_poll_identity_conflict');
 assert.equal(historical.reopen,'time_provider_poll_retirement_required');
 assert.equal(historical.received,0);
 reopened.child.stdin.end('stop\n');
 assert.equal((await reopened.closed)[0],0);
 const retained=()=>{
  const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
  try{return ['time_provider_runtime_binding','time_provider_poll_reservation','time_provider_poll_attempt',
   'time_provider_capture','time_provider_poll_release'].map(table=>db.prepare('SELECT * FROM '+table+' ORDER BY rowid').raw().all());}
  finally{db.close();}
 };
 const before=retained();
 await migrateStorage(run.dir,87);
 assert.deepEqual(retained(),before);
});

test('时间提供者确认入库后释放采样槽，同一来源等待原间隔再发包', providerOptions, async t=>{
 const run=await raw(t,'time-provider-capture-repeat',null,true);
 let frame;
 const deadline=performance.now()+26000;
 while(!(frame=run.output.frames.find(f=>f.event==='time-provider-archive-repeat'))){
  assert(performance.now()<deadline,'采样间隔到期后未完成第二次归档');
  await delay(100);
 }
 assert.equal(frame.early,'time_provider_poll_interval');
 assert.equal(frame.received,2);
 assert.equal(frame.first.status,'archived');
 assert.equal(frame.second.status,'archived');
 assert(BigInt(frame.second.receipt.m1_tick_ns)>=BigInt(frame.first.receipt.m4_tick_ns)+16000000000n);
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const database=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try {
  const confirmations=database.prepare('SELECT confirmation_jcs FROM time_provider_poll_release ORDER BY rowid').pluck().all().map(JSON.parse);
  assert.deepEqual(confirmations.map(c=>c.type),['POLL_STORED_ACK','POLL_STORED_ACK']);
  assert.deepEqual(confirmations.map(c=>c.poll_sequence),['1','2']);
  assert.deepEqual(confirmations.map(c=>c.receipt),[frame.first.receipt,frame.second.receipt]);
  assert.equal(database.prepare('SELECT sum(reserved_bytes) FROM time_provider_poll_reservation').pluck().get(),16384);
  assert.deepEqual(database.pragma('foreign_key_check'),[]);
 }finally{database.close();}
});

test('时间提供者跨启动恢复等待新时钟，拒绝重放及未知退避', providerOptions, async t=>{
 const first=await raw(t,'time-provider-capture',null,true);
 const original=await until(()=>first.output.frames.find(f=>f.event==='time-provider-capture'));
 first.child.stdin.end('stop\n');
 assert.equal((await first.closed)[0],0);

 const tables=['time_provider_runtime_binding','time_provider_poll_reservation','time_provider_poll_attempt',
  'time_provider_capture','time_provider_poll_release'];
 const snapshot=()=>{
  const db=new Database(path.join(first.dir,'controller.sqlite'),{fileMustExist:true});
  try{return {
   identity:db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get(),
   history:tables.map(table=>db.prepare('SELECT * FROM '+table+' ORDER BY rowid').raw().all()),
   oldRuntime:JSON.parse(db.prepare('SELECT body_jcs FROM time_provider_runtime_binding ORDER BY rowid LIMIT 1').pluck().get())
  };}
  finally{db.close();}
 };
 const records=snapshot();
 await migrateStorage(first.dir,85);
 const migrated=snapshot();
 assert.deepEqual(migrated,records);

 const next=await raw(t,'time-provider-capture-resume',null,true,first,original.port);
 let frame;
 const deadline=performance.now()+30000;
 while(!(frame=next.output.frames.find(f=>f.event==='time-provider-archive-resumed'))){
  assert.equal(next.child.exitCode,null,JSON.stringify(next.status.frames));
  assert(performance.now()<deadline,'跨启动等待到期后未完成第二次归档');
  await delay(100);
 }
 assert.equal(frame.port,original.port);
 assert.equal(frame.received,1);
 assert.equal(frame.attemptedBeforeUDP,true);
 assert.equal(frame.unrecovered,'time_provider_poll_retirement_required');
 assert.deepEqual(frame.repeated,frame.proof);
 assert.equal(frame.early,'time_provider_poll_interval');
 assert.equal(frame.uncertain.wait_until_tick_ns,null);
 assert.equal(frame.backoff,'time_provider_poll_backoff_unknown');
 assert.equal(frame.replay,'time_provider_poll_identity_conflict');
 assert.equal(frame.archive.status,'archived');
 assert.equal(frame.proof.observation.record.provider_exit.active_processes,0);
 assert.equal(frame.proof.observation.record.core_exit.active_processes,0);
 assert.equal(frame.proof.predecessor_poll_id,'poll.capture');
 assert.equal(frame.uncertain.predecessor_poll_id,'poll.revoked');
 assert.notEqual(frame.proof.receiver_boot_id,records.oldRuntime.service_boot_id);
 const oldDomain=records.oldRuntime.clock_domain_descriptor;
 assert.notEqual(frame.proof.observation.receiving_domain_ref.clock_domain_id,oldDomain.clock_domain_id);
 const elapsed=BigInt(frame.proof.wait_until_tick_ns)-BigInt(frame.proof.observation.received_tick_ns);
 const lower=(elapsed-2n*BigInt(frame.proof.clock_policy.monotonic_quantization_ns))*
  (1000000000n-BigInt(frame.proof.clock_policy.drift_ppb))/1000000000n;
 assert(lower>=16000000000n);
 assert(BigInt(frame.archive.receipt.m1_tick_ns)>=BigInt(frame.proof.wait_until_tick_ns));

 next.child.stdin.end('stop\n');
 assert.equal((await next.closed)[0],0);
 const {history:final}=snapshot();
 for(let i=0;i<tables.length;i++)assert.deepEqual(final[i].slice(0,records.history[i].length),records.history[i]);
 const db=new Database(path.join(next.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.equal(db.pragma('user_version',{simple:true}),85);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_source_recovery').pluck().get(),4);
  assert.throws(()=>db.exec('UPDATE time_provider_source_recovery SET wait_until_tick=NULL'),/immutable_time_provider_source_recovery/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});

test('时间提供者持久退避跨启动保留，第二次 RATE 递增且 DENY 保持停采', {...providerOptions,timeout:95000}, async t=>{
 const first=await raw(t,'time-provider-control',null,true);
 const initial=await until(()=>first.output.frames.find(f=>f.event==='time-provider-control-stored'));
 assert.equal(initial.received,2);
 assert.equal(initial.early,'time_provider_poll_interval');
 assert.equal(initial.denied,'time_provider_poll_backoff_stopped');
 assert.equal(initial.rate.status,'control');
 assert.equal(initial.rate.control.code,0x52415445);
 assert.equal(initial.rate.control.wait_ns,'32000000000');
 assert.equal(initial.stopped.control.code,0x44454e59);
 assert.equal(initial.stopped.control.wait_ns,'0');
 first.child.stdin.end('stop\n');
 assert.equal((await first.closed)[0],0);

 const resume=await raw(t,'time-provider-control-resume',null,true,first,initial.port);
 let frame;
 const deadline=performance.now()+50000;
 while(!(frame=resume.output.frames.find(f=>f.event==='time-provider-control-resumed'))){
  assert.equal(resume.child.exitCode,null,JSON.stringify(resume.status.frames));
  assert(performance.now()<deadline,'持久退避到期后未完成再次采样');
  await delay(100);
 }
 assert.equal(frame.received,1);
 assert.equal(frame.early,'time_provider_poll_interval');
 assert.equal(frame.denied,'time_provider_poll_backoff_stopped');
 assert.equal(frame.stopped.wait_until_tick_ns,null);
 assert.equal(frame.proof.minimum_interval_ns,'32000000000');
 assert.equal(frame.allowed.reservation.effective_poll_interval_ns,'32000000000');
 assert.equal(frame.next.control.wait_ns,'64000000000');
 assert(BigInt(frame.next.control.observed_tick_ns)>=BigInt(frame.proof.wait_until_tick_ns));
 resume.child.stdin.end('stop\n');
 assert.equal((await resume.closed)[0],0);
 const db=new Database(path.join(first.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  const controls=db.prepare('SELECT body_jcs,body_digest FROM time_provider_poll_control ORDER BY rowid').raw().all();
  const acks=db.prepare('SELECT confirmation_jcs FROM time_provider_control_release ORDER BY rowid').pluck().all().map(JSON.parse);
  const results=[initial.rate,initial.stopped,frame.next];
  assert.equal(controls.length,results.length);
  for(let i=0;i<results.length;i++){
   assert.deepEqual(JSON.parse(controls[i][0]).control,results[i].control);
   assert.equal(controls[i][1],results[i].receipt.control_ref.digest);
   assert.equal(acks[i].type,'POLL_CONTROL_STORED_ACK');
   assert.deepEqual(acks[i].receipt,results[i].receipt);
  }
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),0);
  assert.equal(db.prepare('SELECT sum(reserved_bytes) FROM time_provider_poll_reservation').pluck().get(),24576);
  assert.throws(()=>db.exec('UPDATE time_provider_poll_control SET wait_ns=wait_ns'),/immutable_time_provider_poll_control/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});

test('时间提供者持久退避漏写时保持来源和活动槽关闭',providerOptions,async t=>{
 const run=await raw(t,'time-provider-control-write-fault',null,true);
 const frame=await until(()=>run.output.frames.find(f=>f.event==='time-provider-control-write-fault'));
 assert.equal(frame.failed,'time_provider_poll_control_storage');
 assert.equal(frame.replay,'time_provider_poll_already_attempted');
 assert.equal(frame.retry,'time_provider_poll_source_busy');
 assert.equal(frame.capacity,'time_provider_poll_capacity');
 assert.equal(frame.received,1);
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_attempt').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_control').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_control_release').pluck().get(),0);
 }finally{db.close();}
});

test('时间提供者经真实归档发布 UTC 锚点并跨时代解析，缺证据及重启保持关闭', {...providerOptions,timeout:85000},async t=>{
 const run=await raw(t,'time-provider-anchor',null,true);
 let frame;
 const deadline=performance.now()+35000;
 while(!(frame=run.output.frames.find(f=>f.event==='reference-anchor'))){
  assert.equal(run.child.exitCode,null,JSON.stringify(run.status.frames));
  assert(performance.now()<deadline,'未取得实际 UTC 锚点发布事件');
  await delay(100);
 }
 assert.equal(frame.received,2);
 assert.equal(frame.first.status,'archived');
 assert.equal(frame.unqualified,null);
 assert.equal(frame.accepted.status,'archived');
 assert.equal(frame.current?.status,'conditional');
 assert.equal(frame.bundle.bundle_digest,frame.current.bundle_ref.digest);
 assert.equal(frame.bundle.bundle_id,frame.current.anchor_ref.id);
 assert.equal(frame.bundle.exchange.receive_after_tick_ns,frame.accepted.receipt.m4_tick_ns);
 assert.deepEqual(frame.historicBundle,frame.bundle);
 assert.equal(frame.wrongBundle,null);
 assert.equal(frame.bundle.request.request_size,48);assert.equal(frame.bundle.exchange.response_size,48);
 assert.equal(frame.withdrawn,null);
 assert.equal(frame.afterRestore,null);
 assert.deepEqual(frame.rejectedProjections,[null,null,null,null,null]);
 assert.equal(frame.projection?.before_tick_ns,frame.capture.before_tick_ns);
 assert.equal(frame.projection.after_tick_ns,frame.capture.after_tick_ns);
 assert.deepEqual(frame.projection.anchor_ref,frame.current.anchor_ref);
 assert.deepEqual(frame.projection.runtime_domain_ref,frame.current.runtime_domain_ref);
 assert.equal(frame.projection.lower_utc_ns,frame.current.lower_utc_ns);
 assert.equal(BigInt(frame.projection.upper_utc_ns)-BigInt(frame.current.upper_utc_ns),
  BigInt(frame.capture.after_tick_ns)-BigInt(frame.capture.before_tick_ns));
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);

 const restarted=await raw(t,'time-provider-anchor-reopen',null,true,run,frame.port);
 const reopened=await until(()=>restarted.output.frames.find(f=>f.event==='reference-anchor-reopened'));
 assert.equal(reopened.current,null);
 assert.equal(reopened.projection,null);
 assert.equal(reopened.received,0);
 assert.deepEqual(reopened.archived,frame.accepted.receipt);
 restarted.child.stdin.end('stop\n');
 assert.equal((await restarted.closed)[0],0);

 const tables=['time_provider_capture','time_provider_reference_anchor','time_provider_poll_release'];
 const originals=db=>tables.map(table=>db.prepare('SELECT * FROM '+table+' ORDER BY rowid').raw().all());
 let before;
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  const rows=db.prepare('SELECT body_jcs,body_digest FROM time_provider_reference_anchor').raw().all();
  assert.equal(rows.length,1);
  const [text,digest]=rows[0], anchor=JSON.parse(text);
  assert.equal(anchor.anchor_id,frame.current.anchor_ref.id);
  assert.equal(digest,frame.current.anchor_ref.digest);
  assert.deepEqual(anchor.capture_ref,frame.accepted.receipt.capture_ref);
  const stored=JSON.parse(inflateRawSync(Buffer.from(anchor.reference_bundle.body,'base64url')));
  assert.equal(anchor.reference_bundle.digest,frame.bundle.bundle_digest);
  assert.deepEqual(stored.bundle,frame.bundle);
  assert.equal(stored.state.state_digest,frame.bundle.state_ref.digest);
  assert.equal(anchor.packet_summary.request_digest,frame.bundle.request.request_bytes_ref.digest);
  assert.equal(anchor.packet_summary.response_digest,frame.bundle.exchange.response_bytes_ref.digest);
  assert.deepEqual(anchor.t2,{era:'0',seconds:'4294967295',fraction:'4294967295'});
  assert.deepEqual(anchor.t3,{era:'1',seconds:'0',fraction:'1'});
  const boundary=BigInt(frame.eraBoundary), span=BigInt(anchor.m4_tick_ns)-BigInt(anchor.m1_tick_ns);
  assert.equal(BigInt(anchor.lower_utc_ns),boundary-1000n);
  assert.equal(BigInt(anchor.upper_utc_ns),boundary+span+2000n);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),2);
  assert.throws(()=>db.exec('UPDATE time_provider_reference_anchor SET body_jcs=body_jcs'),/immutable_time_provider_reference_anchor/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  before=originals(db);
 }finally{db.close();}
 assert.equal((await migrateStorage(run.dir,88)).schema_revision,'88');
 assert.equal((await migrateStorage(run.dir,89)).schema_revision,'89');
 assert.equal((await migrateStorage(run.dir,90)).schema_revision,'90');
 const after=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.deepEqual(originals(after),before);
  assert.equal(after.prepare('SELECT count(*) FROM time_provider_reference_invalidation').pluck().get(),0);
  assert.equal(after.prepare('SELECT count(*) FROM time_provider_reference_exit_cut').pluck().get(),0);
  assert.deepEqual(after.pragma('foreign_key_check'),[]);
 }
 finally{after.close();}
});

test('时间提供者 UTC 锚点漏写时原件和锚点一起回滚',providerOptions,async t=>{
 const run=await raw(t,'time-provider-anchor-write-fault',null,true);
 const frame=await until(()=>run.output.frames.find(f=>f.event==='reference-anchor-write-fault'));
 assert.deepEqual(frame,{event:'reference-anchor-write-fault',failure:'reference_time_anchor_storage',received:1,
  current:null,archive:null,attempt:true});
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_attempt').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_anchor').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_release').pluck().get(),0);
 }finally{db.close();}
});

test('时间提供者自动采样，经监督退役跨启动等待并在 DENY 后停止', {...providerOptions,timeout:85000},async t=>{
 const first=await raw(t,'time-provider-schedule',null,true);
 const initial=await until(()=>first.output.frames.find(f=>f.event==='reference-schedule-result'));
 assert.equal(initial.received,1);
 assert.equal(initial.status[0].state,'waiting');
 assert.equal(initial.reference?.status,'conditional');
 first.child.stdin.end('stop\n');
 assert.equal((await first.closed)[0],0);
 assert.equal(first.output.frames.find(f=>f.event==='reference-schedule-closed')?.status[0].state,'stopped');

 const next=await raw(t,'time-provider-schedule-restart',null,true,first,initial.port);
 let frame;
 const deadline=performance.now()+27000;
 while(!(frame=next.output.frames.find(f=>f.event==='reference-schedule-result'))){
  assert.equal(next.child.exitCode,null,JSON.stringify(next.status.frames));
  assert(performance.now()<deadline,'自动采样未在跨启动等待后完成');
  await delay(100);
 }
 assert.equal(frame.received,1);
 assert.equal(frame.port,initial.port);
 assert.deepEqual(frame.status,[{source_slot:'source.capture',state:'blocked',reason:'time_provider_poll_backoff_stopped'}]);
 assert.equal(frame.reference,null);
 next.child.stdin.end('stop\n');
 assert.equal((await next.closed)[0],0);
 const db=new Database(path.join(first.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  const polls=db.prepare('SELECT body_jcs FROM time_provider_poll_reservation ORDER BY rowid').pluck().all().map(JSON.parse);
  assert.equal(polls.length,2);
  assert.notEqual(polls[0].poll_id,polls[1].poll_id);
  assert.notEqual(polls[0].service_boot_id,polls[1].service_boot_id);
  const proof=JSON.parse(db.prepare('SELECT body_jcs FROM time_provider_source_recovery').pluck().get());
  assert.equal(proof.predecessor_poll_id,polls[0].poll_id);
  assert(BigInt(polls[1].issued_tick_ns)>=BigInt(proof.wait_until_tick_ns));
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_release').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_control_release').pluck().get(),1);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});

test('时间提供者自动采样等待应答时关闭，保留尝试和未释放槽',providerOptions,async t=>{
 const run=await raw(t,'time-provider-schedule-close',null,true);
 const inFlight=await until(()=>run.output.frames.find(f=>f.event==='reference-schedule-pending'));
 assert.equal(inFlight.received,1);
 assert.equal(inFlight.status[0].state,'collecting');
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0,JSON.stringify(run.status.frames));
 const stopped=run.output.frames.find(f=>f.event==='reference-schedule-closed');
 assert.equal(stopped?.status[0].state,'stopped');
 assert.equal(stopped?.received,1);
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_reservation').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_attempt').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_poll_release').pluck().get(),0);
 }finally{db.close();}
});

test('参考授时撤回持久保存未决采样与保护待办，迟到应答不恢复资格', {...providerOptions,timeout:80000},async t=>{
 const run=await raw(t,'time-provider-invalidation',null,true);
 let frame;
 const deadline=performance.now()+30000;
 while(!(frame=run.output.frames.find(f=>f.event==='reference-invalidation'))){
  assert.equal(run.child.exitCode,null,JSON.stringify(run.status.frames));
  assert(performance.now()<deadline,'未取得参考授时失效记录');
  await delay(100);
 }
 assert.equal(frame.available?.status,'conditional');
 assert.equal(frame.received,2);
 assert.equal(frame.status.state,'unavailable');
 assert.equal(frame.status.cause,'authority_changed');
 assert.equal(frame.status.protection_state,'pending');
 assert.deepEqual(frame.status.exits,{target_count:0,retired_count:0});
 assert.equal(frame.status.durable,true);
 assert.deepEqual(frame.repeated,frame.status);
 assert.equal(frame.afterRestore,null);
 assert.equal(frame.denied,'time_provider_poll_reference_invalidated');
 assert.equal(frame.late.status,'unavailable');
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  const rows=db.prepare('SELECT body_jcs,body_digest FROM time_provider_reference_invalidation').raw().all();
  assert.equal(rows.length,1);
  const [text,digest]=rows[0], invalidation=JSON.parse(text);
  const work=JSON.parse(db.prepare('SELECT body_jcs FROM time_provider_reference_protection').pluck().get());
  assert.equal(digest,frame.status.invalidation_ref.digest);
  assert.deepEqual(invalidation.old_anchor_ref,frame.available.anchor_ref);
  assert.deepEqual(invalidation.domain_ref,frame.available.runtime_domain_ref);
  assert.deepEqual(invalidation.outstanding,[{poll_ref:frame.inflight,attempt_id:frame.attempt}]);
  assert.equal(invalidation.minimum_time_generation,'2');
  assert.deepEqual(work.invalidation_ref,frame.status.invalidation_ref);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_anchor').pluck().get(),1);
  assert.throws(()=>db.exec('UPDATE time_provider_reference_invalidation SET cause=cause'),/immutable_reference_time_invalidation/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});

test('参考授时保护待办漏写时回滚整笔，进程仍拒绝恢复采样',providerOptions,async t=>{
 const run=await raw(t,'time-provider-invalidation-write-fault',null,true);
 const frame=await until(()=>run.output.frames.find(f=>f.event==='reference-invalidation'));
 assert.equal(frame.available?.status,'conditional');
 assert.equal(frame.status.durable,false);
 assert.equal(frame.status.state,'unavailable');
 assert.equal(frame.repeated.operation_id,frame.status.operation_id);
 assert.equal(frame.afterRestore,null);
 assert.equal(frame.denied,'time_provider_poll_reference_invalidated');
 assert.equal(frame.received,1);
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const db=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_invalidation').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_protection').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_exit_cut').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM time_provider_reference_anchor').pluck().get(),1);
 }finally{db.close();}
});

test('时间提供者在确认前断开时保留归档和未释放预约', {
 ...providerOptions, skip:providerOptions.skip||process.env.LEAFSEAMER_TEST_ACK_LOSS!=='1'
},async t=>{
 const run=await raw(t,'time-provider-ack-fault',null,true);
 assert.notEqual((await run.closed)[0],0);
 const database=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  for(const table of ['time_provider_poll_reservation','time_provider_poll_attempt','time_provider_capture']){
   assert.equal(database.prepare('SELECT count(*) FROM '+table).pluck().get(),1);
  }
  assert.equal(database.prepare('SELECT count(*) FROM time_provider_poll_release').pluck().get(),0);
  assert.deepEqual(database.pragma('foreign_key_check'),[]);
 }finally{database.close();}
});

test('时间提供者密文归档漏写仍保留 nonce、发送尝试和未决预约', providerOptions, async t=>{
 const run=await raw(t,'time-provider-capture-rollback',null,true);
 const result=await until(()=>run.output.frames.find(f=>f.event==='time-provider-archive-rollback'));
 assert.deepEqual(result,{event:'time-provider-archive-rollback',failure:'time_provider_capture_storage',
  replay:'time_provider_poll_already_attempted',occupied:'time_provider_poll_source_busy',received:1,attemptedBeforeUDP:true,capture:null,
  keyFailure:'time_provider_capture_key_identity',replacementAttempt:null});
 run.child.stdin.end('stop\n');
 assert.equal((await run.closed)[0],0);
 const database=new Database(path.join(run.dir,'controller.sqlite'),{fileMustExist:true});
 try{
  for(const name of ['time_provider_capture_nonce','time_provider_poll_attempt']){
   assert.equal(database.prepare('SELECT count(*) FROM '+name).pluck().get(),1);
  }
  assert.equal(database.prepare('SELECT count(*) FROM time_provider_poll_reservation').pluck().get(),2);
  assert.equal(database.prepare('SELECT count(*) FROM time_provider_capture').pluck().get(),0);
 }finally{database.close();}
});

test('监督自动刷新按原查询时刻排程，晚到回复不再叠加完整刷新间隔',()=>{
 const issued=10000000000n;
 assert.equal(coreRefreshDelayMs(issued,issued),500);
 assert.equal(coreRefreshDelayMs(issued,issued+450000001n),50);
 assert.equal(coreRefreshDelayMs(issued,issued+500000000n),0);
 assert.equal(coreRefreshDelayMs(issued,issued+1900000000n),0);
});

test('主动核心观察取得本次请求后的真实回复，并发合并不延长旧观察且关闭后拒绝',options,async t=>{
 const run=await raw(t,'core-refresh'),done=await until(()=>run.output.frames.find(f=>f.event==='core-refresh-done'));
 assert.equal(done.fresh,true);assert.equal(done.unchanged,true);
 assert.equal(done.oldError,'supervisor_core_observation');assert.equal(done.closedError,'supervisor_unavailable');
 assert.equal((await run.closed)[0],1);
 const stopped=run.status.frames.at(-1);assert.equal(stopped.event,'process_group_empty');
 assert.equal(stopped.control_failed,true);assert.equal(stopped.active_processes,0);
});

test('真实核心提交完整启动快照，原生持久ACK且拒绝历史deny复活与修订重放', options, async t => {
  const run = await raw(t, 'fence');
  const done = await until(() => run.output.frames.find(f => f.event === 'fence-done')); assert.equal(done.current, 'closed');
  const acknowledgments = run.output.frames.filter(f => f.event === 'fence');
  assert.equal(acknowledgments.length, 5, JSON.stringify(run.output.frames.filter(f => f.event === 'fence-error')));
  assert.deepEqual(run.output.frames.filter(f => f.event === 'fence-error').map(f => f.code),
    ['supervisor_stale_fence', 'supervisor_identity_conflict', 'supervisor_identity_conflict', 'supervisor_identity_conflict']);
  assert(Buffer.byteLength(canonicalize(acknowledgments[0].body)) > 65536);
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    const rows = db.prepare('SELECT snapshot_jcs FROM launch_fence ORDER BY revision').pluck().all().map(JSON.parse);
    assert.deepEqual(rows, [acknowledgments[0].body, acknowledgments[2].body, acknowledgments[3].body]);
    assert.equal(db.prepare('SELECT revision FROM launch_fence_current').pluck().get(), '9007199254740995');
    assert.equal(db.prepare("SELECT count(*) FROM launch_fence_item WHERE disposition='deny'").pluck().get(), 256);
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1);
    assert.throws(() => db.exec('DELETE FROM launch_fence_item'), /immutable/);
    assert.throws(() => db.exec("UPDATE launch_fence_current SET revision='9007199254740994'"), /fence_revision/);
  });
});

test('真实worker登记保存完整新意图且不创建进程，遗漏快照和撤权后不能再取得登记许可', options, async t => {
  const run = await raw(t, 'worker-register');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  assert.equal(result.first.state, 'registered'); assert.equal(result.first.creation_attempted, false); assert.equal(result.first.admission_receipt, null);
  assert.deepEqual(result.first, result.repeated); assert.deepEqual(result.first, result.queried); assert.deepEqual(result.first, result.final);
  assert.deepEqual(result.errors, {expired: 'supervisor_expired', future: 'supervisor_expired', domain: 'supervisor_unauthorized', permissions: 'supervisor_unauthorized',
    approval: 'supervisor_unauthorized', omission: 'supervisor_invalid_binding', unsynchronized: 'supervisor_stale_fence', denied: 'supervisor_unauthorized',
    changed: 'supervisor_identity_conflict', query_conflict: 'supervisor_identity_conflict', reallow: 'supervisor_identity_conflict'});
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    assert.equal(db.prepare('SELECT count(*) FROM worker_launch').pluck().get(), 1);
    assert.deepEqual(JSON.parse(db.prepare('SELECT intent_jcs FROM worker_launch').pluck().get()), result.intent);
    assert.deepEqual(JSON.parse(db.prepare('SELECT authorization_jcs FROM worker_launch').pluck().get()), result.grant);
    assert.equal(db.prepare('SELECT state FROM worker_state').pluck().get(), 'registered');
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
    assert.equal(db.prepare('SELECT revision FROM launch_fence_current').pluck().get(), '2');
    assert.throws(() => db.exec('DELETE FROM worker_launch'), /immutable/);
    assert.throws(() => db.exec("UPDATE worker_state SET state='admitted_closed',creation_attempted=1"), /worker_state_transition|worker_observation_evidence/);
  });
});

test('CREATE重新核授权及当前栅栏，未知安装凭据不能消耗创建权，拒绝后仍可查询原件', options, async t => {
  const run = await raw(t, 'worker-create');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  const expected = {digest: 'unauthorized', missing: 'not_found', expired: 'expired', future: 'expired', domain: 'unauthorized', permissions: 'unauthorized',
    approval: 'unauthorized', installation: 'unauthorized', role: 'unauthorized', authority: 'unauthorized', revision: 'stale_fence',
    conflict: 'identity_conflict', unresolved: 'invalid_binding', repeated: 'invalid_binding', unsynchronized: 'stale_fence', denied: 'unauthorized'};
  assert.deepEqual(Object.fromEntries(Object.entries(result.errors).filter(([key]) => key.startsWith('create_'))),
    Object.fromEntries(Object.entries(expected).map(([key, value]) => ['create_' + key, 'supervisor_' + value])));
  assert.deepEqual(result.first, result.final);
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  assert.equal(run.status.frames.at(-1).active_processes, 0);
  inspect(run.dir, db => {
    assert.deepEqual(db.prepare('SELECT state,creation_attempted,admission_receipt FROM worker_state').raw().get(),
      ['registered', 0, null]);
    assert.deepEqual(JSON.parse(db.prepare('SELECT authorization_jcs FROM worker_launch').pluck().get()), result.grant);
    assert.equal(db.prepare('SELECT count(*) FROM core_observation').pluck().get(), 1);
  });
});

test('已登记worker在撤权及fence失步后按实际独占Job退役，原件持久且终态不能复活', options, async t => {
  const run = await raw(t, 'worker-retire');
  const result = await until(() => run.output.frames.find(f => f.event === 'worker-result'));
  assert.equal(result.retirement.result, 'confirmed_empty'); assert.equal(result.retirement.launch_intake_closed, true);
  assert.deepEqual(result.retirement, result.repeatedRetirement);
  assert.equal(result.final.state, 'retired'); assert.equal(result.final.creation_attempted, false);
  assert.deepEqual(result.final.retirement_evidence, result.retirement);
  assert.equal(result.replacement.state, 'registered');
  assert.deepEqual(Object.fromEntries(Object.entries(result.errors).filter(([key]) => key.startsWith('retire_'))), {
    retire_conflict: 'supervisor_identity_conflict', retire_missing: 'supervisor_not_found', retire_reregister: 'supervisor_stale_fence',
    retire_reregister_synced: 'supervisor_invalid_binding',
    retire_create: 'supervisor_invalid_binding', retire_reallow: 'supervisor_invalid_binding'});
  run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
  inspect(run.dir, db => {
    const row = db.prepare('SELECT request_jcs,observation_jcs,evidence_jcs FROM worker_retirement').raw().get();
    assert.equal(JSON.parse(row[0]).reason, 'revoked');
    assert.deepEqual(JSON.parse(row[2]), result.retirement);
    const observation = JSON.parse(row[1]);
    assert.equal(observation.active_processes, 0); assert.equal(observation.total_processes, 0);
    assert.equal(observation.observation_id, result.retirement.os_observation_refs[0]);
    assert.equal(observation.observed_tick_ns, result.retirement.observed_tick_ns);
    assert.equal(observation.object_name, db.prepare('SELECT object_name FROM worker_group WHERE launch_id=?').pluck().get(result.intent.launch_id));
    const reservation = JSON.parse(db.prepare('SELECT reservation_jcs FROM worker_group WHERE launch_id=?').pluck().get(result.intent.launch_id));
    assert.equal(reservation.object_name, observation.object_name); assert.equal(reservation.group_id, result.intent.containment_ref.group_id);
    assert.equal(db.prepare("SELECT count(*) FROM worker_state WHERE state NOT IN('retired','rejected')").pluck().get(), 1);
    assert.equal(db.prepare('SELECT count(*) FROM worker_group').pluck().get(), 2);
    assert.throws(() => db.exec('DELETE FROM worker_retirement'), /immutable/);
    assert.throws(() => db.exec('DELETE FROM worker_group'), /immutable/);
    assert.throws(() => db.exec("UPDATE worker_state SET state='registered' WHERE state='retired'"), /worker_state_transition|worker_observation_evidence/);
    assert.throws(() => db.exec("UPDATE worker_state SET retirement_evidence='{}' WHERE state='retired'"), /worker_retirement_evidence|worker_state_transition/);
    // 观察原件与终态须一起提交，不能只插入一条孤立证据。
    db.exec("BEGIN; UPDATE worker_state SET state='retiring' WHERE launch_id='worker.next'");
    db.prepare('INSERT INTO worker_retirement SELECT attempt_id,?,?,?,request_jcs,observation_jcs,? FROM worker_retirement LIMIT 1')
      .run('worker.next', 'unpaired.evidence', 'unpaired.observation', '{}');
    assert.throws(() => db.exec('COMMIT'), /FOREIGN KEY/); db.exec('ROLLBACK');
  });
});

test('重算摘要也不能绕过快照范围、全量容量、排序、核心隔离和封闭字段', options, async t => {
  for (const fault of ['scope', 'order', 'duplicate', 'core', 'capacity', 'revision', 'id', 'extra', 'digest']) {
    const run = await raw(t, 'fence-bad-' + fault); assert.equal((await run.closed)[0], 1, fault);
    assert.equal(run.status.frames.at(-1).control_failed, true, fault);
    assert.equal(run.status.frames.at(-1).active_processes, 0, fault);
    inspect(run.dir, db => {
      assert.equal(db.prepare('SELECT count(*) FROM launch_fence').pluck().get(), 0, fault);
      assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1, fault);
    });
  }
});

test('监督日志DDL被额外触发器修改时在创建核心前拒绝', options, async t => {
  const run = await raw(t, 'fence-failure', db => db.exec("CREATE TRIGGER fail_fence BEFORE INSERT ON launch_fence_item BEGIN SELECT RAISE(ABORT,'synthetic_fence_write'); END"));
  // 修改正式DDL会在宿主启动核验时被拒绝；不把此结果当作已进入事务故障测试。
  assert.equal((await run.closed)[0], 1);
  assert.equal(run.output.frames.filter(f => f.event === 'fence').length, 0);
  assert.equal(run.status.frames.at(-1).code, 'process_journal_schema');
  inspect(run.dir, db => { assert.equal(db.prepare('SELECT count(*) FROM launch_fence').pluck().get(), 0); });
});
test('真实核心持续查询已提交回执，超过单次等待窗口仍可服务且不重签准入', options, async t => {
  const dir = temporary(t), identity = initializeStorage(dir); await migrateStorage(dir); await initializeProcessHost(dir); const output = collect();
  const app = await startProcessHost({dataDir: dir, bootstrapPolicy: policyFor(identity), onCoreOutput: output.write}); t.after(() => app.close());
  const listening = await until(() => output.frames.find(f => f.event === 'listening'));
  await delay(2600); assert.equal((await fetch(`http://127.0.0.1:${listening.port}/health/live`)).status, 200);
  const exit = await app.close(); assert.equal(exit.exitCode, 0); assert.equal(exit.control_failed, false);
  inspect(dir, db => { assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1); assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1); });
});
test('真实管道从原生SQLite查回完整原件，未知键与同ID异摘要分别返回null和冲突', options, async t => {
  for (const mode of ['normal', 'missing', 'conflict']) {
    const run = await raw(t, mode), response = await until(() => run.output.frames.find(f => f.event === 'response'));
    assert.equal(response.sequence, '1'); assert.equal(response.reply_to, 'first');
    if (mode === 'missing') assert.equal(response.payload.record, null);
    else if (mode === 'conflict') assert.equal(response.payload.code, 'identity_conflict');
    else assert.equal(response.payload.record.gate_state, 'closed');
    run.child.stdin.end('stop\n'); assert.equal((await run.closed)[0], 0);
    inspect(run.dir, db => {
      if (mode === 'normal') assert.deepEqual(JSON.parse(db.prepare('SELECT receipt_jcs FROM core_admission').pluck().get()), response.payload.record.admission_receipt);
      assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1);
    });
  }
});
test('错范围、通道、序号、方向、重复键和重放关闭实际进程组并保存退出原件', options, async t => {
  for (const mode of ['scope', 'channel', 'sequence', 'reply', 'direction', 'duplicate-key', 'replay', 'disconnect', 'silent']) {
    const run = await raw(t, mode); assert.equal((await run.closed)[0], 1);
    const result = run.status.frames.at(-1); assert.equal(result.event, 'process_group_empty', mode); assert.equal(result.control_failed, true, mode);
    assert.equal(result.active_processes, 0); assert.equal(result.runtime_admitted, false);
    inspect(run.dir, db => { assert.equal(db.prepare('SELECT count(*) FROM core_admission').pluck().get(), 1); assert.equal(db.prepare('SELECT count(*) FROM core_exit').pluck().get(), 1); });
  }
});
test('同一Job中的后代也不能冒充已准入核心连接控制管道', options, async t => {
  const run = await raw(t, 'peer'); assert.equal((await run.closed)[0], 1);
  assert.equal(run.status.frames.at(-1).control_failed, true);
  for (const frame of run.output.frames) if (frame.pid) assert.throws(() => process.kill(frame.pid, 0), {code: 'ESRCH'});
});

function syntheticBinding() {
  const digest = 'sha256:' + '1'.repeat(64), domain = {clock_domain_id: 'clock_' + '1'.repeat(64), descriptor_digest: digest};
  const receipt = {receipt_id: 'receipt', bootstrap_id: 'bootstrap', launch_id: 'launch', launch_intent_digest: digest, member_id: 'member', member_boot_id: 'boot',
    role: 'core', artifact_manifest_ref: {manifest_id: 'artifact', revision: '1', digest}, channel_binding_id: 'bootstrap-channel', domain_ref: domain,
    containment_ref: {group_id: 'group', generation: 'generation', backend: 'windows_job'}, os_observation_ref: 'observation', admitted_tick_ns: '1', gate_state: 'closed'};
  return {binding: {descriptor: {supervisor_instance_id: 'supervisor'}, receipt}, policy: {service_id: 'service', database_instance_id: 'database'}};
}

for(const [scenario,description] of [
 ['observation','先于排队观察并保留已发送查询'],
 ['fence','保留较早的栅栏'],
 ['slow','慢回复后立即安排已到期刷新'],
 ['timer-starved','定时器未执行时仍先发到期确认']
])test('核心确认排队顺序'+description,options,async()=>{
 const fixture=syntheticBinding(),{receipt}=fixture.binding;
 const channelId=crypto.randomBytes(16).toString('hex'),pipe='\\\\.\\pipe\\LeafSeamer.Control.'+channelId;
 let peer,source,release,coreQueries=0;
 const seen=[];
 const server=net.createServer(socket=>{peer=socket;let buffer='';socket.on('error',()=>{});socket.on('data',chunk=>{
  buffer+=chunk;if(!buffer.endsWith('\n'))return;
  const request=JSON.parse(buffer);buffer='';
  const launch=request.payload.launch_id;
  seen.push(launch??request.type);
  const response={...request,message_id:'response-'+request.sequence,reply_to:request.message_id};
  if(request.type==='FENCE_PUT'){
   response.type='FENCE_RESULT';response.payload={revision:request.payload.revision,snapshot_digest:request.payload.digest,journal_committed:true};
  }else{
   const record=launch===receipt.launch_id?{key:request.payload,supervisor_instance_id:'supervisor',state:'admitted_closed',
    creation_attempted:true,gate_state:'closed',retirement_evidence:null,admission_receipt:receipt}:null;
   response.type='LAUNCH_RESULT';response.payload={key:request.payload,record};
  }
  const respond=()=>socket.write(canonicalize(response)+'\n');
  const slowConfirmation=launch===receipt.launch_id&&++coreQueries===2&&scenario==='slow';
  if(launch==='in-flight'||slowConfirmation)release=respond;else respond();
 });});
 await new Promise(resolve=>server.listen(pipe,resolve));
 try{
  source=await connectCoreSupervisor({pipe,channelId,...fixture});
  const lookup=launch=>source.queryLaunch({launch_id:launch,launch_intent_digest:receipt.launch_intent_digest});
  if(scenario==='timer-starved'){
   const previous=source.observeCore();
   // 在同一轮事件循环跨过刷新间隔，既不推进帧序号，也不放宽原确认期限。
   Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,550);
   await lookup('waiting');
   assert.deepEqual(seen,[receipt.launch_id,receipt.launch_id,'waiting']);
   assert.equal(previous.expires_tick_ns,String(BigInt(previous.issued_tick_ns)+5000000000n));
   assert.ok(BigInt(source.observeCore().issued_tick_ns)>BigInt(previous.issued_tick_ns));
   return;
  }
  const inFlight=scenario==='slow'?source.refreshCoreObservation():lookup('in-flight');
  await until(()=>release);
  const previous=source.observeCore();
  const waiting=lookup('waiting');
  let fence;
  if(scenario==='fence'){
   const snapshot={scope:source.scope,revision:'1',items:[]};
   const digest='sha256:'+crypto.createHash('sha256').update(canonicalize(snapshot)).digest('hex');
   fence=source.putFence({...snapshot,digest});
  }
  await delay(scenario==='slow'?650:40);
  const confirmation=scenario==='slow'?undefined:source.refreshCoreObservation();
  assert.deepEqual(seen,[receipt.launch_id,scenario==='slow'?receipt.launch_id:'in-flight']);
  release();
  await Promise.all([inFlight,waiting,fence,confirmation]);
  const expected={
   observation:[receipt.launch_id,'in-flight',receipt.launch_id,'waiting'],
   fence:[receipt.launch_id,'in-flight','waiting','FENCE_PUT',receipt.launch_id],
   slow:[receipt.launch_id,receipt.launch_id,receipt.launch_id,'waiting']
  }[scenario];
  assert.deepEqual(seen.slice(0,expected.length),expected);
  assert.equal(previous.expires_tick_ns,String(BigInt(previous.issued_tick_ns)+5000000000n));
  assert.ok(BigInt(source.observeCore().issued_tick_ns)>BigInt(previous.issued_tick_ns));
 }finally{source?.close();peer?.destroy();await new Promise(resolve=>server.close(resolve));}
});

test('合成监督端的新worker观察保留五秒原截止，刷新不续旧观察且deny立即撤回',options,async()=>{
 const fixture=syntheticBinding();fixture.binding.descriptor.runtime_generation='generation';
 const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
 const ref=kind=>({kind,authority_service_id:'service',database_instance_id:'database',object_id:kind,revision:'1',digest:hash(kind)});
 const intent={launch_id:'worker',service_id:'service',supervisor_instance_id:'supervisor',runtime_generation:'generation',member_id:'worker.member',role:'worker',
  artifact_manifest_ref:fixture.binding.receipt.artifact_manifest_ref,containment_ref:{group_id:'worker.group',generation:'generation',backend:'windows_job'},
  object_scope:{kind:'devices',device_ids:['device']},policy_revision:'1',extension_binding:{installation_ref:ref('installation'),approval_ref:ref('approval'),
   review_ref:ref('review'),role_resolution_ref:ref('role_resolution'),configuration_ref:ref('configuration'),intake_ref:ref('intake'),platform_profile_ref:ref('platform_profile'),
   host_installation_id:'host',host_trust_epoch:'1',manifest_digest:hash('manifest'),artifact_set_digest:hash('artifacts'),entry_id:'simulator',permissions_digest:hash('permissions')}};
 const receipt={...fixture.binding.receipt,receipt_id:'worker.receipt',bootstrap_id:'worker.bootstrap',member_boot_id:'worker.boot',role:'worker',
  launch_id:intent.launch_id,launch_intent_digest:hash(intent),member_id:intent.member_id,containment_ref:intent.containment_ref};
 const channelId=crypto.randomBytes(16).toString('hex'),pipe='\\\\.\\pipe\\LeafSeamer.Control.'+channelId;let peer,source;
 const server=net.createServer(socket=>{peer=socket;let buffer='';socket.on('error',()=>{});socket.on('data',chunk=>{
  buffer+=chunk;if(!buffer.endsWith('\n'))return;const request=JSON.parse(buffer);buffer='';
  const response={...request,message_id:'response-'+request.sequence,reply_to:request.message_id};
  if(request.type==='LAUNCH_QUERY'){response.type='LAUNCH_RESULT';response.payload={key:request.payload,record:{key:request.payload,supervisor_instance_id:'supervisor',
   state:'admitted_closed',creation_attempted:true,gate_state:'closed',retirement_evidence:null,admission_receipt:request.payload.launch_id==='worker'?receipt:fixture.binding.receipt}};}
  else{response.type='FENCE_RESULT';response.payload={revision:request.payload.revision,snapshot_digest:request.payload.digest,journal_committed:true};}
  socket.write(canonicalize(response)+'\n');
 });});
 await new Promise(resolve=>server.listen(pipe,resolve));
 try{
  source=await connectCoreSupervisor({pipe,channelId,...fixture});const old=await source.observeWorker(intent),deadline=old.confirmation_deadline_ns;
  assert.equal(old.source_window_policy,'authority-source-window/2');assert.equal(BigInt(deadline)-BigInt(old.issued_tick_ns),5000000000n);
  await delay(2100);source.assertWorkerObservation(old);const fresh=await source.observeWorker(intent);
  assert.equal(old.confirmation_deadline_ns,deadline);assert.notEqual(fresh.confirmation_deadline_ns,deadline);
  await delay(3000);assert.throws(()=>source.assertWorkerObservation(old),e=>e.code==='supervisor_worker_withdrawn');source.assertWorkerObservation(fresh);
  const body={scope:source.scope,revision:'1',items:[{...fresh.key,disposition:'deny'}]};await source.putFence({...body,digest:hash(body)});
  assert.throws(()=>source.assertWorkerObservation(fresh),e=>e.code==='supervisor_worker_withdrawn');
 }finally{source?.close();peer?.destroy();await new Promise(resolve=>server.close(resolve));}
});

test('核心消费者拒绝借用其它成员、组或观察域的退役结果', options, async () => {
  const hash = value => 'sha256:' + crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
  for (const fault of ['member', 'group', 'domain']) {
    const fixture = syntheticBinding(); fixture.binding.descriptor.runtime_generation = 'generation';
    const ref = kind => ({kind, authority_service_id: 'service', database_instance_id: 'database', object_id: kind, revision: '1', digest: hash(kind)});
    const intent = {launch_id: 'worker', service_id: 'service', supervisor_instance_id: 'supervisor', runtime_generation: 'generation', member_id: 'worker.member',
      role: 'worker', artifact_manifest_ref: fixture.binding.receipt.artifact_manifest_ref, containment_ref: {group_id: 'worker.group', generation: 'generation', backend: 'windows_job'},
      object_scope: {kind: 'devices', device_ids: ['device']}, policy_revision: '1', extension_binding: {
        installation_ref: ref('installation'), approval_ref: ref('approval'), review_ref: ref('review'), role_resolution_ref: ref('role_resolution'),
        configuration_ref: ref('configuration'), intake_ref: ref('intake'), platform_profile_ref: ref('platform_profile'), host_installation_id: 'host', host_trust_epoch: '1',
        manifest_digest: hash('manifest'), artifact_set_digest: hash('artifacts'), entry_id: 'simulator', permissions_digest: hash('permissions')}};
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    let peer;
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = '';
        const response = {...request, message_id: 'response-' + request.sequence, reply_to: request.message_id};
        if (request.type === 'LAUNCH_QUERY') {
          response.type = 'LAUNCH_RESULT'; response.payload = {key: request.payload, record: {key: request.payload, supervisor_instance_id: 'supervisor',
            state: 'admitted_closed', creation_attempted: true, gate_state: 'closed', retirement_evidence: null, admission_receipt: fixture.binding.receipt}};
        } else {
          response.type = 'RETIRE_RESULT'; response.payload = {evidence_id: 'evidence', service_id: 'service', old_domain_ref: request.scope.domain_ref,
            target_scope: 'member_group', target_member_ids: [intent.member_id], containment_ref: {...intent.containment_ref}, launch_intake_closed: true,
            os_observation_refs: ['observation'], result: 'confirmed_empty', evaluator_domain_ref: request.scope.domain_ref, observed_tick_ns: '1'};
          if (fault === 'member') response.payload.target_member_ids = ['another.member'];
          if (fault === 'group') response.payload.containment_ref.group_id = 'another.group';
          if (fault === 'domain') response.payload.evaluator_domain_ref = {...request.scope.domain_ref, descriptor_digest: hash('another.domain')};
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve)); let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture});
      await assert.rejects(source.retireWorker(intent, 'revoked'), e => e.code === 'supervisor_retirement_binding');
      assert.throws(() => source.assertCurrent(), e => e.code === 'supervisor_retirement_binding');
    } finally { source?.close(); peer?.destroy(); await new Promise(resolve => server.close(resolve)); }
  }
});

test('核心核快照ACK原修订和摘要，拒绝结果不冒充监督连接失效', options, async () => {
  for (const mode of ['revision', 'digest', 'reject']) {
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    const fixture = syntheticBinding(); let peer;
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = '';
        const response = {...request, message_id: 'response-' + request.sequence, reply_to: request.message_id};
        if (request.type === 'LAUNCH_QUERY') {
          response.type = 'LAUNCH_RESULT'; response.payload = {key: request.payload, record: {key: request.payload,
            supervisor_instance_id: 'supervisor', state: 'admitted_closed', creation_attempted: true,
            admission_receipt: fixture.binding.receipt, retirement_evidence: null, gate_state: 'closed'}};
        } else {
          response.type = 'FENCE_RESULT'; response.payload = {revision: request.payload.revision, snapshot_digest: request.payload.digest, journal_committed: true};
          if (mode === 'revision') response.payload.revision = '2';
          if (mode === 'digest') response.payload.snapshot_digest = 'sha256:' + '0'.repeat(64);
          if (mode === 'reject') { response.type = 'ERROR'; response.payload = {code: 'stale_fence', retry_action: 'query_only'}; }
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve)); let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture});
      const body = {scope: source.scope, revision: '1', items: []};
      const snapshot = {...body, digest: 'sha256:' + crypto.createHash('sha256').update(canonicalize(body)).digest('hex')};
      await assert.rejects(source.putFence(snapshot), e => e.code === (mode === 'reject' ? 'supervisor_stale_fence' : 'supervisor_fence_binding'));
      if (mode === 'reject') { await delay(550); assert.equal(source.current().payload.record.gate_state, 'closed'); }
      else assert.throws(() => source.assertCurrent(), e => e.code === 'supervisor_fence_binding');
    } finally { source?.close(); peer?.destroy(); await new Promise(resolve => server.close(resolve)); }
  }
});
test('核心物化消费者拒绝同消息内错启动键或观察请求ID，并锁存连接失败', options, async () => {
  for(const fault of ['key','request']){
    const channelId=crypto.randomBytes(16).toString('hex'),pipe='\\\\.\\pipe\\LeafSeamer.Control.'+channelId,fixture=syntheticBinding();let peer,source;
    const server=net.createServer(socket=>{peer=socket;let buffer='';socket.on('error',()=>{});socket.on('data',chunk=>{
      buffer+=chunk;if(!buffer.endsWith('\n'))return;const request=JSON.parse(buffer);buffer='';
      const response={...request,message_id:'response-'+request.sequence,reply_to:request.message_id};
      if(request.type==='LAUNCH_QUERY'){
        response.type='LAUNCH_RESULT';response.payload={key:request.payload,record:{key:request.payload,supervisor_instance_id:'supervisor',state:'admitted_closed',
          creation_attempted:true,admission_receipt:fixture.binding.receipt,retirement_evidence:null,gate_state:'closed'}};
      }else{
        response.type='MATERIALIZATION_RESULT';response.payload={...request.payload,status:'pending',observation:null};
        if(fault==='key')response.payload.key={...request.payload.key,launch_id:'another'};else response.payload.observation_request_id='another';
      }
      socket.write(canonicalize(response)+'\n');
    });});
    await new Promise(resolve=>server.listen(pipe,resolve));
    try{
      source=await connectCoreSupervisor({pipe,channelId,...fixture});
      await assert.rejects(source.prepareWorkerMaterialization({launch_id:'worker',launch_intent_digest:'sha256:'+'1'.repeat(64)}),{code:'supervisor_materialization_binding'});
      assert.throws(()=>source.assertCurrent(),{code:'supervisor_materialization_binding'});
    }finally{source?.close();peer?.destroy();await new Promise(resolve=>server.close(resolve));}
  }
});

test('核心消费者拒绝错误响应绑定，断线及迟到回执不能恢复已关闭来源', options, async t => {
  // 这里仅用合成服务端验证消费者；原生对端PID检查由上述真实宿主用例覆盖。
  for (const mode of ['reply', 'scope', 'sequence', 'receipt', 'disconnect', 'late']) {
    const channelId = crypto.randomBytes(16).toString('hex'), pipe = '\\\\.\\pipe\\LeafSeamer.Control.' + channelId;
    const fixture = syntheticBinding(); let peer = null, count = 0; const timers = [];
    const server = net.createServer(socket => {
      peer = socket; let buffer = ''; socket.on('error', () => {});
      socket.on('data', chunk => {
        buffer += chunk; if (!buffer.endsWith('\n')) return;
        const request = JSON.parse(buffer); buffer = ''; count++;
        const receipt = {...fixture.binding.receipt};
        const response = {...request, type: 'LAUNCH_RESULT', message_id: 'response-' + count, reply_to: request.message_id,
          payload: {key: request.payload, record: {key: request.payload, supervisor_instance_id: 'supervisor', state: 'admitted_closed', creation_attempted: true,
            admission_receipt: receipt, retirement_evidence: null, gate_state: 'closed'}}};
        if (count > 1) {
          if (mode === 'reply') response.reply_to = 'other';
          if (mode === 'scope') response.scope = {...response.scope, service_id: 'other'};
          if (mode === 'sequence') response.sequence = '1';
          if (mode === 'receipt') receipt.member_boot_id = 'other';
          if (mode === 'disconnect') { socket.destroy(); return; }
          if (mode === 'late') { timers.push(setTimeout(() => { if (!socket.destroyed) socket.write(canonicalize(response) + '\n'); }, 2300)); return; }
        }
        socket.write(canonicalize(response) + '\n');
      });
    });
    await new Promise(resolve => server.listen(pipe, resolve));
    let source;
    try {
      source = await connectCoreSupervisor({pipe, channelId, ...fixture}); assert.equal(source.current().payload.record.gate_state, 'closed');
      await new Promise(resolve => source.onLost(resolve)); assert.throws(() => source.current());
      assert.equal(count, 2); await delay(20); assert.throws(() => source.assertCurrent());
    } finally { source?.close(); peer?.destroy(); timers.forEach(clearTimeout); await new Promise(resolve => server.close(resolve)); }
  }
});
