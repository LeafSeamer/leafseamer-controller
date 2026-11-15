import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
test('67到68显式迁移保持身份和历史，运行库拒绝，快照不凭空生成',async t=>{
 const f=await setup(t,67);await assert.rejects(migrateStorage(f.dir,68),{code:'database_in_use'});f.close();
 const before=inspect(f.dir,db=>({history:db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all(),identity:db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get()}));
 assert.equal((await migrateStorage(f.dir,68)).schema_revision,'68');inspect(f.dir,db=>{assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all().slice(0,-1),before.history);assert.deepEqual(db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get(),before.identity);for(const table of ['service_snapshot_build','service_snapshot_end','service_snapshot_manifest','service_snapshot_page'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});f.reopen();assert.equal(f.store.identity.schema_revision,'68');
});
test('快照表冲突回滚整次68迁移，原67库可继续打开',async t=>{
 const f=await setup(t,67);f.close();inspect(f.dir,db=>db.exec('CREATE TABLE service_snapshot_build(conflict TEXT)'));await assert.rejects(migrateStorage(f.dir,68),{code:'migration_failed'});inspect(f.dir,db=>{assert.equal(db.pragma('user_version',{simple:true}),67);db.exec('DROP TABLE service_snapshot_build');});f.reopen();assert.equal(f.store.identity.schema_revision,'67');
});
