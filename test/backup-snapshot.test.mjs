import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage,verifyBackupSnapshot,prepareProtectedRecoveryStorage} from '../dist/storage.mjs';
import {currentStorageRevision} from '../dist/storage-revision.mjs';

test('prepares a new protected Controller identity from a verified device inventory',{timeout:240000},async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-backup-verify-'));
  t.after(()=>{
    assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    fs.rmSync(directory,{recursive:true,force:true,maxRetries:5,retryDelay:50});
  });
  initializeStorage(directory);
  await migrateStorage(directory,currentStorageRevision);
  const active=openStorage(directory),identity=active.identity;
  const enrollment=active.enrollment.begin();
  const oldRegistration={request_id:crypto.randomUUID(),device_kind:'simulator',display_name:'恢复联调设备'};
  let registered;
  const file=path.join(directory,'snapshot.sqlite');
  const source=new Database(path.join(directory,'controller.sqlite'),{readonly:true,fileMustExist:true});
  try{
    await active.enrollment.complete({token_id:enrollment.token_id,secret:enrollment.secret,login:'recovery.test',
      password:'synthetic-recovery-password-012345',mode:'standalone'});
    registered=active.registerDevice(oldRegistration);
    active.configureVirtualDevice({device_id:registered.device_id,request_id:crypto.randomUUID()});
    await source.backup(file);
  }finally{source.close();active.close();}
  const snapshot=new Database(file,{fileMustExist:true});
  try{assert.equal(snapshot.pragma('journal_mode=DELETE',{simple:true}),'delete');}finally{snapshot.close();}
  const payload=fs.readFileSync(file);
  const receipt={state:'staged',engine:'3.53.4',backup_operation_id:crypto.randomUUID(),bytes:payload.length,
    sha256:crypto.createHash('sha256').update(payload).digest('hex'),
    scope:Object.fromEntries(['authority','service_id','database_instance_id','control_epoch','request_epoch','schema_revision']
      .map(key=>[key,identity[key]]))};
  const report=verifyBackupSnapshot(file,receipt);
  assert.equal(report.backup_operation_id,receipt.backup_operation_id);
  assert.deepEqual(report.scope,receipt.scope);
  assert.deepEqual(report.command_inventory,{requests:0,commands:0,pending:0,unresolved:0});
  assert.throws(()=>verifyBackupSnapshot(file,{...receipt,sha256:'0'.repeat(64)}),{code:'backup_snapshot_digest'});
  assert.throws(()=>verifyBackupSnapshot(file,{...receipt,scope:{...receipt.scope,control_epoch:crypto.randomUUID()}}),
    {code:'backup_snapshot_scope'});
  assert.deepEqual(fs.readFileSync(file),payload);
  assert.ok(['-wal','-shm','-journal'].every(suffix=>!fs.existsSync(file+suffix)));
  const copied=new Database(file,{fileMustExist:true,readonly:true});
  try{
    assert.deepEqual(copied.prepare('SELECT service_boot_id,state FROM service_boot').raw().all(),[[active.serviceBootId,'started']]);
    assert.equal(copied.prepare('SELECT count(*) FROM identity_receipt').pluck().get(),1);
    assert.equal(copied.prepare('SELECT count(*) FROM virtual_device_resource').pluck().get(),1);
  }finally{copied.close();}

  const target=path.join(directory,'prepared');fs.mkdirSync(target);
  const nextScope={...receipt.scope,database_instance_id:crypto.randomUUID(),control_epoch:crypto.randomUUID(),request_epoch:crypto.randomUUID()};
  const input={sourceFile:file,receipt,targetDirectory:target,nextScope,planDigest:'sha256:'+'a'.repeat(64),dataGenerationId:crypto.randomUUID()};
  await assert.rejects(prepareProtectedRecoveryStorage({...input,nextScope:{...nextScope,control_epoch:identity.control_epoch}}),
    {code:'recovery_storage_scope'});
  const wrongHeader=path.join(directory,'wrong-header.sqlite'),walBytes=Buffer.from(payload);
  walBytes[18]=2;walBytes[19]=2;fs.writeFileSync(wrongHeader,walBytes);
  await assert.rejects(prepareProtectedRecoveryStorage({...input,sourceFile:wrongHeader,
    receipt:{...receipt,sha256:crypto.createHash('sha256').update(walBytes).digest('hex')}}),{code:'backup_snapshot_file'});
  assert.deepEqual(fs.readdirSync(target),[]);
  assert.ok(['-wal','-shm','-journal'].every(suffix=>!fs.existsSync(wrongHeader+suffix)));

  const submitted={...input,receipt:structuredClone(receipt),nextScope:{...nextScope}};
  const preparing=prepareProtectedRecoveryStorage(submitted);
  submitted.receipt.sha256='0'.repeat(64);
  submitted.receipt.scope.database_instance_id=crypto.randomUUID();
  submitted.nextScope.control_epoch=crypto.randomUUID();
  const prepared=await preparing,destination=path.join(target,'controller.sqlite');
  const preparedBytes=fs.readFileSync(destination);
  assert.equal(prepared.format,'leafseamer.controller-protected-recovery-storage/1');
  assert.deepEqual(prepared.next_scope,nextScope);
  assert.equal(prepared.origin.snapshot_sha256,receipt.sha256);
  assert.equal(prepared.origin.plan_digest,input.planDigest);
  assert.deepEqual(prepared.command_inventory,report.command_inventory);
  assert.equal(prepared.device_count,1);
  assert.equal(prepared.device_review_required,true);
  assert.equal(prepared.bytes,preparedBytes.length);
  assert.equal(prepared.sha256,crypto.createHash('sha256').update(preparedBytes).digest('hex'));
  assert.deepEqual(fs.readdirSync(target),['controller.sqlite']);
  await assert.rejects(prepareProtectedRecoveryStorage(input),{code:'recovery_storage_destination'});
  assert.deepEqual(fs.readFileSync(destination),preparedBytes);
  assert.deepEqual(fs.readFileSync(file),payload);
  const newDb=new Database(destination,{fileMustExist:true,readonly:true});
  try{
    for(const table of ['service_boot','identity_receipt','virtual_device_resource','auth_session','control_record_revision','peer_pairing_revision'])
      assert.equal(newDb.prepare('SELECT count(*) FROM '+table).pluck().get(),0,table);
    const descriptor=JSON.parse(newDb.prepare('SELECT descriptor_body FROM device_record').pluck().get());
    assert.equal(descriptor.device_id,registered.device_id);
    assert.equal(descriptor.display_name,oldRegistration.display_name);
    assert.equal(descriptor.connection_state,'disconnected');
    assert.deepEqual(descriptor.actions,[]);
    const control=JSON.parse(newDb.prepare('SELECT body FROM device_control_history').pluck().get());
    assert.equal(control.gate_state,'protected');
    assert.equal(control.holder,null);
    assert.equal(control.scope.database_instance_id,nextScope.database_instance_id);
    const audit=JSON.parse(newDb.prepare('SELECT audit_body FROM device_registration_commit').pluck().get());
    assert.equal(audit.kind,'recovered_device_registration');
    assert.equal(audit.provenance.descriptor_digest,registered.descriptor_digest);
    assert.notEqual(newDb.prepare('SELECT request_id FROM device_registration').pluck().get(),oldRegistration.request_id);
    assert.deepEqual(newDb.prepare('PRAGMA foreign_key_check').raw().all(),[]);
  }finally{newDb.close();}
  const restored=openStorage(target,nextScope);
  try{assert.equal(restored.identity.database_instance_id,nextScope.database_instance_id);}
  finally{restored.close();}
});
