import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const snapshot=db=>({identity:db.prepare('SELECT * FROM service_state').raw().all(),history:db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all(),frames:db.prepare('SELECT * FROM device_module_frame').raw().all()});
test('63到64显式迁移保留身份历史并建立空来源账本，运行库拒绝迁移',{timeout:60000},async t=>{
 const f=await setup(t,63);await assert.rejects(migrateStorage(f.dir,64),{code:'database_in_use'});f.close();
 const before=inspect(f.dir,snapshot),result=await migrateStorage(f.dir,64);assert.equal(result.schema_revision,'64');assert.equal(result.steps.length,1);assert.ok(fs.existsSync(path.join(f.dir,result.backup_file)));
 inspect(f.dir,db=>{const after=snapshot(db);assert.deepEqual(after.identity[0].filter((_,i)=>i!==6),before.identity[0].filter((_,i)=>i!==6));assert.deepEqual(after.history.slice(0,-1),before.history);assert.deepEqual(after.frames,before.frames);assert.deepEqual(db.pragma('foreign_key_check'),[]);
  for(const table of ['device_event_source','device_source_event','device_source_event_outbox','device_source_batch','device_source_fault'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);});
 f.reopen();assert.equal(f.store.identity.schema_revision,'64');f.close();assert.deepEqual(await migrateStorage(f.dir,64),{schema_revision:'64',changed:false});
});
test('64迁移失败原子回滚到63并保留完整迁移历史',{timeout:60000},async t=>{
 const f=await setup(t,63);f.close();const before=inspect(f.dir,db=>{db.exec('CREATE TABLE device_source_event (conflict TEXT)');return snapshot(db);});
 await assert.rejects(migrateStorage(f.dir,64),{code:'migration_failed'});inspect(f.dir,db=>{assert.deepEqual(snapshot(db),before);assert.equal(db.pragma('user_version',{simple:true}),63);assert.deepEqual(db.pragma('foreign_key_check'),[]);db.exec('DROP TABLE device_source_event');});f.reopen();assert.equal(f.store.identity.schema_revision,'63');
});
