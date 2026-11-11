import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import canonicalize from 'canonicalize';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';
import {captureControlCommands,readControlCommandCut,classifyControlCommands} from '../dist/control-command-cut.mjs';
import {controlHash as hash} from '../dist/device-control-value.mjs';

test('57升级58保留既有身份及行，切点不可脱离控制受理提交',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-control-cut-'));
 let db; t.after(()=>{if(db?.open)db.close();assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,57);let store=openStorage(dir);
 const enrollment=store.enrollment.begin();await store.enrollment.complete({token_id:enrollment.token_id,secret:enrollment.secret,
  login:'cut.test',password:'Synthetic-cut-password-123',mode:'standalone'});
 const device=store.registerDevice({request_id:'cut.device',device_kind:'simulator',display_name:'切点验证设备'}).device_id,identity=store.identity;store.close();
 db=new Database(path.join(dir,'controller.sqlite'));
 const original=db.prepare('SELECT * FROM device_record').raw().all();db.close();
 assert.equal((await migrateStorage(dir,58)).schema_revision,'58');store=openStorage(dir);assert.equal(store.identity.service_id,identity.service_id);store.close();
 db=new Database(path.join(dir,'controller.sqlite'));db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
 assert.deepEqual(db.prepare('SELECT * FROM device_record').raw().all(),original);
 const operation={operation_id:crypto.randomUUID(),device_id:device,expected_control:{epoch:identity.control_epoch,version:'0'},target:{version:'1',mode:'manual',holder:null}},commit=crypto.randomUUID();
 // 仅构造数据库写集隔离夹具；不声明真实人员授权或出口退休。
 function stage(){db.prepare('INSERT INTO control_operation_revision VALUES(?,1,?,?,?,?)').run(operation.operation_id,device,canonicalize(operation),hash(operation),commit);
  db.prepare('INSERT INTO control_operation_head VALUES(?,1)').run(operation.operation_id);}
 function seal(){db.prepare('INSERT INTO control_change_commit VALUES(?,?,1,?,?,?)').run(commit,'acquire','{}',crypto.randomUUID(),'{}');}
 assert.throws(()=>db.transaction(()=>{stage();seal();})(),/control_command_cut_incomplete/);
 assert.equal(db.prepare('SELECT count(*) FROM control_operation_revision').pluck().get(),0);
 assert.throws(()=>db.transaction(()=>{stage();captureControlCommands(db,operation,commit,store.bootId);throw new Error('injected_cut_failure');})(),/injected_cut_failure/);
 assert.equal(db.prepare('SELECT count(*) FROM control_command_cut').pluck().get(),0);
 db.transaction(()=>{stage();captureControlCommands(db,operation,commit,null);seal();})();
 const saved=db.transaction(()=>readControlCommandCut(db,operation))();assert.deepEqual(saved.value.commands,[]);assert.equal(saved.value.issued_revision,'0');
 assert.deepEqual(db.transaction(()=>classifyControlCommands(db,operation))(),{cut_ref:saved.ref,commands:[]});
 assert.throws(()=>db.transaction(()=>readControlCommandCut(db,{...operation,target:{...operation.target,version:'2'}}))(),/control_command_cut_integrity/);
 assert.throws(()=>db.prepare('UPDATE control_command_cut SET body_digest=?').run(hash('changed')),/immutable_control_command_cut/);
 assert.throws(()=>db.exec('DELETE FROM control_command_cut'),/immutable_control_command_cut/);
 assert.deepEqual(db.pragma('foreign_key_check'),[]);
});
