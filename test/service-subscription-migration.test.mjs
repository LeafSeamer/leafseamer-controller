import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
test('65到66迁移拒绝运行库，完整保留旧身份与迁移历史，新增订阅表为空',async t=>{
 const f=await setup(t,65);await assert.rejects(migrateStorage(f.dir,66),{code:'database_in_use'});f.close();
 const before=inspect(f.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all());assert.equal((await migrateStorage(f.dir,66)).schema_revision,'66');
 inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all().slice(0,-1),before);assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.equal(db.prepare('SELECT count(*) FROM service_event_subscription').pluck().get(),0);});f.reopen();assert.equal(f.store.identity.schema_revision,'66');
});
test('订阅迁移发生表名冲突时整笔回滚，不能留下66版身份或迁移记录',async t=>{
 const f=await setup(t,65);f.close();inspect(f.dir,db=>db.exec('CREATE TABLE service_event_subscription(conflict TEXT)'));
 await assert.rejects(migrateStorage(f.dir,66),{code:'migration_failed'});inspect(f.dir,db=>{assert.equal(db.pragma('user_version',{simple:true}),65);assert.equal(db.prepare('SELECT schema_revision FROM service_state').pluck().get(),'65');assert.equal(db.prepare('SELECT count(*) FROM schema_migration').pluck().get(),65);db.exec('DROP TABLE service_event_subscription');});
 assert.equal((await migrateStorage(f.dir,66)).schema_revision,'66');
});
