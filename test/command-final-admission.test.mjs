import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

test('schema51升级52保留身份，最终受理写集不能脱离公开修订单独提交',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-final-admission-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,51);let store=openStorage(dir);const before=store.identity;store.close();
 assert.equal((await migrateStorage(dir,52)).schema_revision,'52');store=openStorage(dir);
 assert.equal(store.identity.service_id,before.service_id);assert.equal(store.identity.database_instance_id,before.database_instance_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  const targets=db.prepare('PRAGMA foreign_key_list(command_final_admission)').raw().all().map(v=>v[2]);
  for(const table of ['command_device_hold','command_transmission_issue','command_attempt_inventory','command_lifecycle_commit'])assert.ok(targets.includes(table),table);
  assert.throws(()=>db.transaction(()=>db.prepare('INSERT INTO command_transmission_issue VALUES(?,?,?,?,8,?,?)')
   .run('permit','transaction','00000000000000000001','00000000000000000000','{}','sha256:'+'a'.repeat(64)))(),/command_transmission_issue_parent/);
  assert.equal(db.prepare('SELECT count(*) FROM command_transmission_issue').pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
