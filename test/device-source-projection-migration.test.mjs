import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
test('66到67显式迁移保持身份与历史，运行库拒绝且旧来源不自动取得投影资格',async t=>{
 const f=await setup(t,66);await assert.rejects(migrateStorage(f.dir,67),{code:'database_in_use'});f.close();
 const before=inspect(f.dir,db=>({history:db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all(),identity:db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get()}));
 assert.equal((await migrateStorage(f.dir,67)).schema_revision,'67');inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all().slice(0,-1),before.history);assert.deepEqual(db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get(),before.identity);
  for(const table of ['device_source_notification','device_source_projection','device_source_projection_head'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });f.reopen();assert.equal(f.store.identity.schema_revision,'67');
});
test('投影表冲突回滚整个67迁移，恢复后可重试',async t=>{
 const f=await setup(t,66);f.close();inspect(f.dir,db=>db.exec('CREATE TABLE device_source_notification(conflict TEXT)'));await assert.rejects(migrateStorage(f.dir,67),{code:'migration_failed'});
 inspect(f.dir,db=>{assert.equal(db.pragma('user_version',{simple:true}),66);assert.equal(db.prepare('SELECT schema_revision FROM service_state').pluck().get(),'66');db.exec('DROP TABLE device_source_notification');});assert.equal((await migrateStorage(f.dir,67)).schema_revision,'67');
});
