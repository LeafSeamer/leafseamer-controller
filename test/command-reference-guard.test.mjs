import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import {canonical,digest} from '../dist/auth-clock-value.mjs';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

test('Schema 112 显式升级保留服务身份、旧迁移和运行记录',async t=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-reference-guard-'));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 initializeStorage(directory);
 await migrateStorage(directory,112);
 const service=openStorage(directory),{schema_revision,service_id,database_instance_id,control_epoch,request_epoch}=service.identity;
 assert.equal(schema_revision,'112');
 service.close();
 function snapshot(){
  const db=new Database(path.join(directory,'controller.sqlite'),{fileMustExist:true,readonly:true});
  try{
   return {identity:db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch,schema_revision FROM service_state').raw().get(),
    migrations:db.prepare('SELECT * FROM schema_migration WHERE CAST(to_revision AS INTEGER)<=112 ORDER BY CAST(to_revision AS INTEGER)').raw().all(),
    boots:db.prepare('SELECT * FROM service_boot ORDER BY service_boot_id').raw().all(),foreignKeys:db.pragma('foreign_key_check')};
  }finally{db.close();}
 }
 const before=snapshot();
 assert.equal(before.boots.length,1);
 assert.equal((await migrateStorage(directory,113)).schema_revision,'113');
 assert.deepEqual(snapshot(),{...before,identity:[service_id,database_instance_id,control_epoch,request_epoch,'113'],foreignKeys:[]});
 assert.equal((await migrateStorage(directory,113)).changed,false);
});

function journal(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE command_final_admission(transaction_id,command_id,commit_id,body_jcs,body_digest);
  CREATE TABLE command_final_observation(transaction_id,body_jcs);
  CREATE TABLE command_lifecycle_head(command_id,commit_id,revision);
  CREATE TABLE execution_session(ipc_session_id,service_boot_id);
  CREATE TABLE time_provider_reference_anchor(anchor_id,service_boot_id,body_jcs);
  CREATE TABLE execution_frame_record(record_id,transaction_id,ipc_session_id,direction,message_type,device_id,domain_kind,record_digest,frame_jcs,reply_record_id,observed_tick);
  CREATE TABLE execution_write_attempt(attempt_id,record_id,started_tick);
  CREATE TABLE command_guard_request(guard_id,final_transaction_id,record_id,transaction_id,body_jcs,body_digest);
  CREATE TABLE command_guard_ack(guard_id,record_id,transaction_id,write_attempt_id,disposition,body_jcs,body_digest);`);
 const sql=fs.readFileSync(new URL('../dist/command-reference-guard.sql',import.meta.url),'utf8');
 db.exec(sql.slice(sql.indexOf('CREATE TRIGGER command_guard_request_parent')));
 const bodyDigest=digest('final'),requestDigest=digest('request'),replyDigest=digest('reply'),guardDigest=digest('guard');
 const schedule={guard_id:'schedule',guard_digest:digest('schedule')},context={bundle_id:'bundle',bundle_digest:digest('bundle')};
 const base={permit:{content_digest:digest('content')},seal:{binding:{ipc_session_id:'session',device_id:'device'}}};
 const final=scheduled=>({...base,guard:{guard_id:'guard',guard_digest:guardDigest,time_required:scheduled,
  reference_time:scheduled?{context_ref:{id:context.bundle_id,digest:context.bundle_digest}}:null},...(scheduled&&{schedule_guard:schedule})});
 db.prepare('INSERT INTO command_final_admission VALUES(?,?,?,?,?)').run('final','command','commit',canonical(final(true)),bodyDigest);
 db.prepare('INSERT INTO command_final_observation VALUES(?,?)').run('final',canonical({outcome:'committed'}));
 db.prepare('INSERT INTO command_lifecycle_head VALUES(?,?,2)').run('command','commit');
 db.prepare('INSERT INTO execution_session VALUES(?,?)').run('session','boot');
 db.prepare('INSERT INTO time_provider_reference_anchor VALUES(?,?,?)').run(context.bundle_id,'boot',canonical({reference_bundle:{digest:context.bundle_digest}}));
 const frame=db.prepare('INSERT INTO execution_frame_record VALUES(?,?,?,?,?,?,?,?,?,?,?)');
 const request=body=>db.transaction(()=>{
  frame.run('request','install','session','c2w','GUARD_INSTALL','device','command_guard',requestDigest,canonical({body}),null,'01');
  const entry={guard_id:'guard',final_admission_ref:{id:'final',digest:bodyDigest},request_record_ref:{id:'request',digest:requestDigest}};
  db.prepare('INSERT INTO command_guard_request VALUES(?,?,?,?,?,?)').run('guard','final','request','install',canonical(entry),digest(entry));
 })();
 const ack=body=>db.transaction(()=>{
  frame.run('reply','ack','session','w2c','GUARD_ACK','device','command_guard',replyDigest,canonical({body}),'request','03');
  const stored=db.prepare('SELECT body_digest FROM command_guard_request').pluck().get();
  const entry={guard_id:'guard',request_ref:{digest:stored},record_ref:{id:'reply',digest:replyDigest},disposition:'installed'};
  db.prepare('INSERT INTO command_guard_ack VALUES(?,?,?,?,?,?,?)').run('guard','reply','ack','write','installed',canonical(entry),digest(entry));
 })();
 db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run('write','request','02');
 const install=scheduled=>({guard:final(scheduled).guard,content_digest:base.permit.content_digest,
  schedule_guard:scheduled?schedule:null,reference_context:scheduled?context:null});
 return {db,final,request,ack,install,schedule,context,guardDigest};
}

test('定时安装只持久接纳原守卫和同一会话授时，ACK 绑定原排期摘要',t=>{
 const {db,request,ack,install,schedule,context,guardDigest}=journal(t),body=install(true);
 for(const changed of [{schedule_guard:null},{schedule_guard:{...schedule,guard_digest:digest('other')}},
  {reference_context:null},{reference_context:{...context,bundle_digest:digest('other')}}]){
  assert.throws(()=>request({...body,...changed}),/command_guard_request_binding/);
 }
 db.exec("UPDATE time_provider_reference_anchor SET service_boot_id='other-boot'");
 assert.throws(()=>request(body),/command_guard_request_binding/);
 assert.equal(db.prepare('SELECT count(*) FROM execution_frame_record').pluck().get(),0);
 db.exec("UPDATE time_provider_reference_anchor SET service_boot_id='boot'");
 request(body);
 const reply={guard_id:'guard',guard_digest:guardDigest,schedule_guard_digest:schedule.guard_digest};
 assert.throws(()=>ack({...reply,schedule_guard_digest:null}),/command_guard_ack_binding/);
 assert.throws(()=>ack({...reply,schedule_guard_digest:digest('other')}),/command_guard_ack_binding/);
 ack(reply);
 assert.equal(db.prepare('SELECT count(*) FROM command_guard_ack').pluck().get(),1);
});

test('即时守卫及回执继续以显式空排期字段登记',t=>{
 const {db,final,request,ack,install,context,guardDigest}=journal(t),body=install(false);
 db.prepare('UPDATE command_final_admission SET body_jcs=?').run(canonical(final(false)));
 assert.throws(()=>request({...body,reference_context:context}),/command_guard_request_binding/);
 request(body);
 assert.throws(()=>ack({guard_id:'guard',guard_digest:guardDigest}),/command_guard_ack_binding/);
 ack({guard_id:'guard',guard_digest:guardDigest,schedule_guard_digest:null});
});
