import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';
test('schema48升级49保存服务身份，命令原件必须具有同库受理来源且不回填记录',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-command-record-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,48);let store=openStorage(dir);const identity=store.identity;store.close();
 assert.equal((await migrateStorage(dir,49)).schema_revision,'49');store=openStorage(dir);
 assert.equal(store.identity.service_id,identity.service_id);assert.equal(store.identity.database_instance_id,identity.database_instance_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  for(const table of ['command_admission_source','command_policy','command_resource_claim','command_context_charge','command_revision'])
   assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.ok(db.prepare('PRAGMA foreign_key_list(ca_command_initial)').raw().all().some(v=>v[2]==='command_admission_source'));
  assert.throws(()=>db.transaction(()=>db.prepare('INSERT INTO command_policy VALUES(?,?,?)').run('orphan','{}','sha256:'+'a'.repeat(64))).immediate(),/FOREIGN KEY/);
  assert.equal(db.prepare('SELECT count(*) FROM command_policy').pluck().get(),0);
 }finally{db.close();}
});

test('schema49升级50保留原受理布局，后继修订不能缺少提交和当前指针',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-command-lifecycle-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,49);let store=openStorage(dir);const before=store.identity;store.close();
 assert.equal((await migrateStorage(dir,50)).schema_revision,'50');store=openStorage(dir);
 assert.equal(store.identity.service_id,before.service_id);assert.equal(store.identity.database_instance_id,before.database_instance_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  for(const table of ['command_lifecycle_revision','command_lifecycle_commit','command_lifecycle_head'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.throws(()=>db.transaction(()=>db.prepare('INSERT INTO command_lifecycle_head VALUES(?,2,?)').run('orphan','missing'))(),/FOREIGN KEY/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
