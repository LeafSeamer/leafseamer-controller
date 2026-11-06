import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

test('schema50升级51保留身份，编码领域与共享日志、独立预留双向绑定',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-command-encoding-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,50);let store=openStorage(dir);const before=store.identity;store.close();
 assert.equal((await migrateStorage(dir,51)).schema_revision,'51');store=openStorage(dir);
 assert.equal(store.identity.service_id,before.service_id);assert.equal(store.identity.database_instance_id,before.database_instance_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  for(const table of ['command_encoding_request','command_encoding_reservation','command_encoding_response','execution_encoding_frame'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.ok(db.prepare('PRAGMA foreign_key_list(execution_frame_record)').raw().all().some(v=>v[2]==='execution_encoding_frame'));
  assert.throws(()=>db.transaction(()=>db.prepare('INSERT INTO command_encoding_reservation VALUES(?,?,8,?,?)').run('orphan','missing','{}','sha256:'+'a'.repeat(64)))(),/FOREIGN KEY/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
