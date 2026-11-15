import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const snapshot=db=>({identity:db.prepare('SELECT * FROM service_state').raw().all(),history:db.prepare('SELECT * FROM schema_migration ORDER BY rowid').raw().all(),frames:db.prepare('SELECT * FROM device_module_frame').raw().all()});
test('62到63显式备份迁移保留身份历史且不生成事件原件，运行中拒绝迁移',{timeout:60000},async t=>{
 const f=await setup(t,62);await assert.rejects(migrateStorage(f.dir,63),{code:'database_in_use'});f.close();
 const before=inspect(f.dir,snapshot),migrated=await migrateStorage(f.dir,63);assert.equal(migrated.schema_revision,'63');assert.equal(migrated.steps.length,1);assert.ok(fs.existsSync(path.join(f.dir,migrated.backup_file)));
 inspect(f.dir,db=>{const after=snapshot(db);assert.deepEqual(after.identity[0].filter((_,i)=>i!==6),before.identity[0].filter((_,i)=>i!==6));
  assert.deepEqual(after.history.slice(0,-1),before.history);assert.deepEqual(after.frames,before.frames);assert.deepEqual(db.pragma('foreign_key_check'),[]);
  assert.match(db.prepare("SELECT sql FROM sqlite_schema WHERE name='device_module_frame'").pluck().get(),/EVENT_BATCH/);
  assert.equal(db.prepare("SELECT 1 FROM sqlite_schema WHERE name='device_module_event_parent'").pluck().get(),1);});
 f.reopen();assert.equal(f.store.identity.schema_revision,'63');f.close();assert.deepEqual(await migrateStorage(f.dir,63),{schema_revision:'63',changed:false});
});
test('63迁移中途失败回滚身份和迁移记录，保留原62库',{timeout:60000},async t=>{
 const f=await setup(t,62);f.close();const before=inspect(f.dir,db=>{db.exec('CREATE TABLE device_module_frame_v63 (conflict TEXT)');return snapshot(db);});
 await assert.rejects(migrateStorage(f.dir,63),{code:'migration_failed'});
 inspect(f.dir,db=>{assert.deepEqual(snapshot(db),before);assert.equal(db.pragma('user_version',{simple:true}),62);assert.deepEqual(db.pragma('foreign_key_check'),[]);db.exec('DROP TABLE device_module_frame_v63');});
 f.reopen();assert.equal(f.store.identity.schema_revision,'62');
});
