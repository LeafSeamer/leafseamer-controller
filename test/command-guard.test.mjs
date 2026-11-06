import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';
test('schema52升级53保留身份，Guard领域双向绑定共享帧且拒绝孤立写集',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-command-guard-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,52);let store=openStorage(dir);const identity=store.identity;store.close();
 assert.equal((await migrateStorage(dir,53)).schema_revision,'53');store=openStorage(dir);assert.equal(store.identity.service_id,identity.service_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  const targets=db.prepare('PRAGMA foreign_key_list(execution_frame_record)').raw().all().map(v=>v[2]);assert.ok(targets.includes('execution_guard_frame'));
  assert.throws(()=>db.prepare('INSERT INTO command_guard_request VALUES(?,?,?,?,?,?)').run('guard','final','record','tx','{}','sha256:'+'a'.repeat(64)),/command_guard_request_binding/);
  assert.equal(db.prepare('SELECT count(*) FROM command_guard_request').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
