import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const snapshot=db=>({identity:db.prepare('SELECT service_id,database_instance_id,control_epoch,request_epoch FROM service_state').raw().get(),history:db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all(),sources:db.prepare('SELECT * FROM device_event_source').raw().all()});
test('64到65显式迁移保留来源与身份历史，运行库不能迁移',async t=>{
 const f=await setup(t,64);await assert.rejects(migrateStorage(f.dir,65),{code:'database_in_use'});f.close();const before=inspect(f.dir,snapshot);
 assert.equal((await migrateStorage(f.dir,65)).schema_revision,'65');inspect(f.dir,db=>{const after=snapshot(db);assert.deepEqual(after.identity,before.identity);assert.deepEqual(after.history.slice(0,-1),before.history);assert.deepEqual(after.sources,before.sources);assert.deepEqual(db.pragma('foreign_key_check'),[]);
  for(const table of ['device_subscription_scope','device_subscription_scope_member','device_subscription_scope_seal','device_subscription_scope_revocation'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);});
 f.reopen();assert.equal(f.store.identity.schema_revision,'65');f.close();assert.deepEqual(await migrateStorage(f.dir,65),{schema_revision:'65',changed:false});
});
test('范围迁移失败恢复完整64版，冲突解除后可重新迁移',async t=>{
 const f=await setup(t,64);f.close();const before=inspect(f.dir,db=>{db.exec('CREATE TABLE device_subscription_scope(conflict TEXT)');return snapshot(db);});
 await assert.rejects(migrateStorage(f.dir,65),{code:'migration_failed'});inspect(f.dir,db=>{assert.deepEqual(snapshot(db),before);assert.equal(db.pragma('user_version',{simple:true}),64);db.exec('DROP TABLE device_subscription_scope');});
 assert.equal((await migrateStorage(f.dir,65)).schema_revision,'65');
});
