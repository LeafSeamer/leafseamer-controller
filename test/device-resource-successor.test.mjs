import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';

test('schema56升级57保留身份和迁移原件，开放屏障及未释放持有仍受数据库约束',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-resource-successor-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,56);
 let store=openStorage(dir);const identity=store.identity;store.close();
 let db=new Database(path.join(dir,'controller.sqlite'));
 const previous=db.prepare('SELECT * FROM schema_migration ORDER BY to_revision').raw().all();db.close();
 assert.equal((await migrateStorage(dir,57)).schema_revision,'57');
 store=openStorage(dir);assert.equal(store.identity.service_id,identity.service_id);assert.equal(store.identity.database_instance_id,identity.database_instance_id);store.close();
 db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  assert.deepEqual(db.prepare("SELECT * FROM schema_migration WHERE to_revision<>'57' ORDER BY to_revision").raw().all(),previous);
  const sql=db.prepare("SELECT sql FROM sqlite_schema WHERE type='index' AND tbl_name='device_initial_open' AND sql IS NOT NULL").pluck().all().join('\n');
  assert.match(sql,/UNIQUE.*binding_id.*barrier_id/s);
  const holds=db.prepare("SELECT sql FROM sqlite_schema WHERE type='trigger' AND tbl_name='command_device_hold'").pluck().all().join('\n');
  assert.match(holds,/command_hold_release/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.equal(db.pragma('integrity_check',{simple:true}),'ok');
 }finally{db.close();}
});
