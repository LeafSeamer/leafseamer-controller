import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage,verifyBackupSnapshot} from '../dist/storage.mjs';
import {currentStorageRevision} from '../dist/storage-revision.mjs';

test('validates the current storage layout on the exact standalone backup bytes without booting the copy',{timeout:120000},async t=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-backup-verify-'));
  t.after(()=>{
    assert.equal(path.dirname(path.resolve(directory)),path.resolve(os.tmpdir()));
    fs.rmSync(directory,{recursive:true,force:true,maxRetries:5,retryDelay:50});
  });
  initializeStorage(directory);
  await migrateStorage(directory,currentStorageRevision);
  const active=openStorage(directory),identity=active.identity;
  const file=path.join(directory,'snapshot.sqlite');
  const source=new Database(path.join(directory,'controller.sqlite'),{readonly:true,fileMustExist:true});
  try{
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
  }finally{copied.close();}
});
