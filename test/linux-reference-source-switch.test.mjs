import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import test from 'node:test';

test('Linux 换源预约须持有原退役证据、新批准和已到期的等待记录',t=>{
  const sql=fs.readFileSync(new URL('../dist/linux-reference-source-switch.sql',import.meta.url),'utf8');
  const db=new DatabaseSync(':memory:');
  t.after(()=>db.close());
  db.exec(`
    CREATE TABLE service_boot(service_boot_id,state);
    CREATE TABLE time_provider_runtime_binding(service_boot_id,launch_id,receipt_id,body_jcs,body_digest);
    CREATE TABLE authentication_clock_acquisition(id,service_boot_id,digest);
    CREATE TABLE time_provider_poll_reservation(poll_id,source_slot,source_digest,service_boot_id,body_digest,body_jcs,issued_tick,acquisition_id);
    CREATE TABLE time_provider_poll_release(poll_id,next_allowed_tick);
    CREATE TABLE time_provider_control_release(poll_id,next_allowed_tick);
    CREATE TABLE time_provider_poll_attempt(poll_id);
    CREATE TABLE time_provider_capture(poll_id);
    CREATE TABLE time_provider_poll_control(poll_id,source_digest,next_allowed_tick,wait_ns);
    CREATE TABLE time_provider_source_recovery(receiver_boot_id,source_digest,predecessor_poll_id,body_jcs,wait_until_tick);
    CREATE TRIGGER time_provider_source_recovery_parent BEFORE INSERT ON time_provider_source_recovery BEGIN SELECT 1; END;
    CREATE TRIGGER time_provider_poll_runtime BEFORE INSERT ON time_provider_poll_reservation BEGIN SELECT 1; END;
    INSERT INTO service_boot VALUES ('old','stopped'),('new','started');
  `);
  const format='leafseamer-time-provider-runtime-binding/2';
  const clock_domain_descriptor={clock_domain_id:'new-clock',descriptor_digest:'new-clock-digest'};
  const addRuntime=db.prepare('INSERT INTO time_provider_runtime_binding VALUES (?,?,?,?,?)');
  addRuntime.run('old','old-launch','old-receipt',JSON.stringify({format,core_receipt_id:'old-core'}),'old-runtime');
  addRuntime.run('new','new-launch','new-receipt',JSON.stringify({format,clock_domain_descriptor}),'new-runtime');
  db.exec("INSERT INTO authentication_clock_acquisition VALUES ('clock-read','new','read-digest')");
  const slot='reference.primary',old='old-source',next='new-source';
  const ns=value=>String(value).padStart(20,'0');
  const oldApproval={source_slot:slot,source_digest:old,minimum_poll_interval_ns:'16000000000'};
  db.prepare('INSERT INTO time_provider_poll_reservation VALUES (?,?,?,?,?,?,?,?)')
    .run('old-poll',slot,old,'old','old-poll-digest',JSON.stringify({authorization:oldApproval}),ns(1),null);
  db.exec("INSERT INTO time_provider_poll_attempt VALUES ('old-poll')");
  db.exec(sql.slice(sql.indexOf('DROP TRIGGER time_provider_source_recovery_parent;')));

  const authorization={...oldApproval,source_digest:next,approval_ref:{digest:'new-approval'}};
  const transition={prior_source_digest:old,source_slot:slot,authorization};
  const proof={predecessor_digest:'old-poll-digest',old_runtime_digest:'old-runtime',transition,observation:{
    receiving_domain_ref:clock_domain_descriptor,record:{format:'leafseamer-linux-reference-retired/1',
      launch_intent:{launch_id:'old-launch'},admission_receipt:{receipt_id:'old-receipt'},core_receipt_id:'old-core'}
  }};
  const due=16000000100n;
  const saveProof=(body=proof,wait=ns(due))=>db.prepare('INSERT INTO time_provider_source_recovery VALUES (?,?,?,?,?)')
    .run('new',next,'old-poll',JSON.stringify(body),wait);
  const reserve=(tick=due,approval=authorization)=>db.prepare('INSERT INTO time_provider_poll_reservation VALUES (?,?,?,?,?,?,?,?)')
    .run('new-poll',slot,next,'new','new-poll-digest',JSON.stringify({runtime_digest:'new-runtime',
      acquisition_ref:{digest:'read-digest'},authorization:approval,effective_poll_interval_ns:'16000000000'}),ns(tick),'clock-read');

  assert.throws(()=>reserve(),/time_provider_poll_runtime_or_source/);
  assert.throws(()=>saveProof(),/time_provider_source_recovery_parent/);
  db.exec('SAVEPOINT unknown');
  saveProof(proof,null);
  assert.throws(()=>reserve(),/time_provider_poll_runtime_or_source/);
  db.exec('ROLLBACK TO unknown; RELEASE unknown');
  db.exec("INSERT INTO time_provider_capture VALUES ('old-poll')");
  assert.throws(()=>saveProof({...proof,transition:{...transition,prior_source_digest:'other-source'}}),/time_provider_source_recovery_parent/);
  saveProof();
  assert.throws(()=>reserve(due-1n),/time_provider_poll_runtime_or_source/);
  assert.throws(()=>reserve(due,{...authorization,approval_ref:{digest:'different-approval'}}),/time_provider_poll_runtime_or_source/);
  assert.equal(reserve().changes,1);
});
