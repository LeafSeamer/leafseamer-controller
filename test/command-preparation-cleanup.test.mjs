import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

test('schema55升级56保留身份并约束准备清理的终态来源和双向帧关联',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-preparation-cleanup-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,55);let store=openStorage(dir);const identity=store.identity;store.close();
 assert.equal((await migrateStorage(dir,56)).schema_revision,'56');store=openStorage(dir);assert.equal(store.identity.service_id,identity.service_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  const targets=db.prepare('PRAGMA foreign_key_list(execution_dispatch_frame)').raw().all().map(v=>v[2]);
  for(const table of ['command_dispatch_request','command_closure_request','command_closure_ack','command_preparation_cleanup'])assert.ok(targets.includes(table));
  assert.throws(()=>db.prepare('INSERT INTO command_preparation_retirement VALUES(?,?,?,?,?)').run('permit','prepare','command','{}','sha256:'+'a'.repeat(64)),/command_preparation_retirement_binding/);
  assert.equal(db.prepare('SELECT count(*) FROM command_preparation_retirement').pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
