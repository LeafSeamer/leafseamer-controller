import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {snapshotFixture,buildSnapshot} from './service-snapshot.test.mjs';
const tables=db=>db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").pluck().all();
const contents=db=>Object.fromEntries(tables(db).map(name=>[name,db.prepare('SELECT * FROM "'+name+'" ORDER BY rowid').raw().all()]));
test('70到71显式迁移保留身份、旧行和历史，追赶表初始为空',async t=>{
 const f=await setup(t,70);f.close();const before=inspect(f.dir,contents);
 assert.equal((await migrateStorage(f.dir,71)).schema_revision,'71');
 inspect(f.dir,db=>{
  const after=contents(db);
  for(const [name,rows]of Object.entries(before)){
   if(name==='service_state'){const expected=structuredClone(rows);expected[0][6]='71';assert.deepEqual(after[name],expected);}
   else if(name==='schema_migration')assert.deepEqual(after[name].slice(0,-1),rows);
   else assert.deepEqual(after[name],rows,name);
  }
  assert.deepEqual(after.service_subscription_reconcile,[]);
  assert.deepEqual(after.service_subscription_delivery,[]);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();assert.equal(f.store.identity.schema_revision,'71');
});
test('71追赶表冲突时回滚迁移，原身份和全部旧行仍可读取',async t=>{
 const f=await setup(t,70);f.close();
 inspect(f.dir,db=>db.exec('CREATE TABLE service_subscription_delivery(conflict TEXT)'));
 const before=inspect(f.dir,contents);
 await assert.rejects(migrateStorage(f.dir,71),{code:'migration_failed'});
 inspect(f.dir,db=>{
  assert.equal(db.pragma('user_version',{simple:true}),70);
  assert.deepEqual(contents(db),before);
 });
 f.reopen();assert.equal(f.store.identity.schema_revision,'70');
});
test('69到70显式迁移保留全部旧行和服务身份，普通打开不升级',async t=>{
 const f=await setup(t,69);assert.equal(f.store.identity.schema_revision,'69');await assert.rejects(migrateStorage(f.dir,70),{code:'database_in_use'});f.close();const before=inspect(f.dir,contents);
 assert.equal((await migrateStorage(f.dir,70)).schema_revision,'70');inspect(f.dir,db=>{const after=contents(db);for(const [name,rows]of Object.entries(before)){
  if(name==='schema_migration')assert.deepEqual(after[name].slice(0,-1),rows);else if(name==='service_state'){const expected=structuredClone(rows);expected[0][6]='70';assert.deepEqual(after[name],expected);}else assert.deepEqual(after[name],rows,name);
 }assert.equal(after.service_snapshot_baseline.length,0);assert.deepEqual(db.pragma('foreign_key_check'),[]);});f.reopen();assert.equal(f.store.identity.schema_revision,'70');
});
test('70表冲突回滚元数据重建，保留69身份及全部数据',async t=>{
 const f=await setup(t,69);f.close();inspect(f.dir,db=>db.exec('CREATE TABLE service_snapshot_baseline(conflict TEXT)'));const before=inspect(f.dir,contents);
 await assert.rejects(migrateStorage(f.dir,70),{code:'migration_failed'});inspect(f.dir,db=>{assert.equal(db.pragma('user_version',{simple:true}),69);assert.deepEqual(contents(db),before);db.exec('DROP TABLE service_snapshot_baseline');});f.reopen();assert.equal(f.store.identity.schema_revision,'69');
});
test('非空快照、连接、修订与审计原件升级后逐行相同，不补造ACK',t=>{
 const f=snapshotFixture(t,69),view=f.store.create('binding',null,f.request).view;buildSnapshot(f.store);const c=f.store.channels,h=c.open('binding',{});c.attach(h,{schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:view.binding.subscription_id,owner:view.owner,stream_id:view.binding.stream_id,stream_epoch:view.binding.stream_epoch,scope_digest:view.binding.scope_digest,authorization_revision:'1',expected_connection_generation:'0',replace_existing:false,resume:null,connection_attempt_id:'migration-attempt'});
 const before=contents(f.db),tail='DROP TRIGGER service_snapshot_publish_complete;'+fs.readFileSync(new URL('../dist/service-snapshot-baseline.sql',import.meta.url),'utf8').split('DROP TRIGGER service_snapshot_publish_complete;')[1];
 f.db.pragma('foreign_keys=OFF');f.db.transaction(()=>{f.db.exec(tail);assert.deepEqual(f.db.pragma('foreign_key_check'),[]);}).immediate();f.db.pragma('foreign_keys=ON');const after=contents(f.db);for(const [name,rows]of Object.entries(before))assert.deepEqual(after[name],rows,name);assert.equal(after.service_snapshot_baseline.length,0);
});
test('71 增加实时状态时保留非空 70 基线、订阅修订和确认点',t=>{
 const f=snapshotFixture(t,70),view=f.store.create('binding',null,f.request).view;
 buildSnapshot(f.store);
 const c=f.store.channels,h=c.open('binding',{}),b=view.binding;
 const attached=c.attach(h,{schema_version:'event-channel/0.1.0-draft.1',type:'client.attach',subscription_id:b.subscription_id,owner:view.owner,
  stream_id:b.stream_id,stream_epoch:b.stream_epoch,scope_digest:b.scope_digest,authorization_revision:'1',
  expected_connection_generation:'0',replace_existing:false,resume:null,connection_attempt_id:'migration-live-attempt'}).attached;
 c.applied(h,{schema_version:'event-channel/0.1.0-draft.1',type:'client.snapshot.applied',binding:attached.binding,snapshot:attached.snapshot_ref});
 const before=contents(f.db);
 const marker='CREATE TABLE service_subscription_reconcile (';
 const sql=fs.readFileSync(new URL('../dist/service-subscription-delivery.sql',import.meta.url),'utf8');
 f.db.pragma('foreign_keys=OFF');
 f.db.transaction(()=>{f.db.exec(sql.slice(sql.indexOf(marker)));assert.deepEqual(f.db.pragma('foreign_key_check'),[]);}).immediate();
 f.db.pragma('foreign_keys=ON');
 const after=contents(f.db);
 for(const [name,rows]of Object.entries(before))assert.deepEqual(after[name],rows,name);
 assert.deepEqual(after.service_subscription_follow,[]);
 assert.deepEqual(after.service_subscription_delivery,[]);
});
