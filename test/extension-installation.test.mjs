import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {migrateStorage} from '../dist/storage.mjs';
import {setup,fixture,configure,inspect,hash} from './fixtures/extension-installation.mjs';

test('候选安装保存固定内容和幂等结果，完整Ref及槽位CAS拒绝错绑',async t=>{
  const f=await setup(t),{api,host,slot,request}=configure(f);
  assert.deepEqual(api.createSlot({request_id:'slot.request',extension_id:host.content.manifest.extension_id}),slot);
  assert.throws(()=>api.createSlot({request_id:'slot.request',extension_id:'other'}),{code:'extension_request_conflict'});
  const [result,raced]=await Promise.all([api.stage(request),api.stage(request)]);assert.deepEqual(raced,result);
  assert.equal(result.state,'verified');assert.equal(result.slot.record.revision,'2');assert.equal(result.approval_ref,null);
  assert.deepEqual(api.content(result.installation_ref).manifest,host.content.manifest);assert.equal(Object.isFrozen(result),true);
  assert.throws(()=>api.content({...result.installation_ref,database_instance_id:'other'}),{code:'extension_installation_ref'});
  assert.throws(()=>api.content({...result.installation_ref,digest:hash('other')}),{code:'extension_installation_missing'});
  await assert.rejects(api.stage({...request,intake_ref:{...request.intake_ref,digest:hash('changed')}}),{code:'extension_request_conflict'});
  await assert.rejects(api.stage({...request,request_id:'new.request'}),{code:'extension_slot_stale'});
  f.close();const next=f.reopen().extensionInstallations;assert.deepEqual(next.query(request.request_id),result);
  assert.deepEqual(await next.stage(request),result);assert.equal(next.query('missing'),null);
  assert.deepEqual(next.content(result.installation_ref).inventory,host.content.inventory);
});

test('内容提供者固定身份及目标、清单和库存摘要均须匹配，关闭后迟到结果不能写入',async t=>{
  for(const fault of ['target','host','manifest','inventory','unavailable']){
    const f=await setup(t),{api,host,request}=configure(f);
    if(fault==='target')host.content.receipt.target_authority_service_id='other';
    if(fault==='host')host.content.receipt.host_installation_id='other';
    if(fault==='manifest')host.content.manifest.extension_version='other';
    if(fault==='inventory')host.content.inventory.files[0].digest=hash('other');
    if(fault==='unavailable'){f.close();f.reopen();const invalid={...host,describeIntake:async()=>({status:'unavailable',content:null})};f.store.extensionInstallations.bindSource(invalid);}
    await assert.rejects(f.store.extensionInstallations.stage(request),{code:fault==='unavailable'?'extension_intake_unavailable':'extension_content_binding'});
    assert.equal(f.store.extensionInstallations.query(request.request_id),null);
    assert.throws(()=>api.bindSource(host));
  }
  const f=await setup(t),host=fixture(f.store.identity);let release;
  f.store.extensionInstallations.bindSource({...host,describeIntake:()=>new Promise(resolve=>{release=resolve;})});
  const slot=f.store.extensionInstallations.createSlot({request_id:'slot',extension_id:host.content.manifest.extension_id});
  const pending=f.store.extensionInstallations.stage({request_id:'stage',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:host.content.intake_ref});
  f.close();release({status:'available',content:host.content});await assert.rejects(pending,{code:'extension_store_closed'});
  assert.equal(f.reopen().extensionInstallations.query('stage'),null);
});

test('四个候选写点失败均回滚安装、槽位head与审计；删除原件和head回退均拒绝',async t=>{
  for(const [table,event] of [['extension_slot_revision','INSERT'],['extension_candidate','INSERT'],['extension_slot_head','UPDATE'],['extension_operation','INSERT']]){
    const f=await setup(t),{host,request}=configure(f);f.close();
    inspect(f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE ${event} ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
    const api=f.reopen().extensionInstallations;api.bindSource(host);await assert.rejects(api.stage(request),/synthetic_failure/);f.close();
    inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM extension_candidate').pluck().get(),0);assert.equal(db.prepare('SELECT count(*) FROM extension_operation').pluck().get(),1);
      assert.equal(db.prepare('SELECT revision FROM extension_slot_head').pluck().get(),1);db.exec('DROP TRIGGER injected');});
    const restored=f.reopen().extensionInstallations;restored.bindSource(host);await restored.stage(request);f.close();
    inspect(f.dir,db=>{assert.throws(()=>db.exec('DELETE FROM extension_candidate'),/extension_history_required/);
      assert.throws(()=>db.exec('UPDATE extension_slot_head SET revision=1'),/extension_slot_revision/);});
  }
});

test('schema12显式备份迁移到13且保留身份和旧启动准备结构',async t=>{
  const f=await setup(t,12),identity=f.store.identity;assert.equal(f.store.extensionInstallations,null);f.close();
  const result=await migrateStorage(f.dir,13);assert.equal(result.schema_revision,'13');assert.equal(result.steps.length,1);assert.ok(fs.existsSync(path.join(f.dir,result.backup_file)));
  const store=f.reopen();assert.equal(store.identity.service_id,identity.service_id);assert.equal(store.identity.database_instance_id,identity.database_instance_id);
  assert.equal(typeof store.extensionInstallations.createSlot,'function');f.close();
  assert.deepEqual(await migrateStorage(f.dir,13),{schema_revision:'13',changed:false});
  inspect(f.dir,db=>assert.equal(db.prepare('PRAGMA foreign_key_check').raw().all().length,0));
});
