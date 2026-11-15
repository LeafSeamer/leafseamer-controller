import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
test('68到69显式迁移保留身份与历史，运行库拒绝且不补造连接',async t=>{
 const f=await setup(t,68);await assert.rejects(migrateStorage(f.dir,69),{code:'database_in_use'});f.close();const history=inspect(f.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all());
 assert.equal((await migrateStorage(f.dir,69)).schema_revision,'69');inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all().slice(0,-1),history);assert.equal(db.prepare('SELECT count(*) FROM service_subscription_attempt').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});f.reopen();assert.equal(f.store.identity.schema_revision,'69');
});
test('连接表冲突回滚69迁移，原68库及快照表仍完整',async t=>{const f=await setup(t,68);f.close();inspect(f.dir,db=>db.exec('CREATE TABLE service_subscription_attempt(conflict TEXT)'));await assert.rejects(migrateStorage(f.dir,69),{code:'migration_failed'});inspect(f.dir,db=>{assert.equal(db.pragma('user_version',{simple:true}),68);db.exec('DROP TABLE service_subscription_attempt');});f.reopen();assert.equal(f.store.identity.schema_revision,'68');});
