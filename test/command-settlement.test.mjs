import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import {initializeStorage,migrateStorage,openStorage} from '../dist/storage.mjs';
import {fixedMemoryCompletion} from '../dist/command-settlement.mjs';
test('固定内存完成必须在原截止前收到完整后继观察，传输入口和关闭确认不能单独证明成功',()=>{
 const input={source:{deadline:{evidence_timeout_ms:1000},policies:{completion:{observation:{value:7}}}},
  report:{transport_entered_tick_ns:'100',disposition:'in_flight',proof:'transport_entered'},observation:{bytes_written:8,response:{value:7,write_sequence:'1'}},
  receivedTick:1000000099n,baseline:{value:{write_sequence:'0'}},coverage:{proof:'transport_entered'}};
 assert.equal(fixedMemoryCompletion(input),true);
 for(const receivedTick of [1000000100n,1000000101n])assert.equal(fixedMemoryCompletion({...input,receivedTick}),false);
 for(const observation of [null,{...input.observation,bytes_written:7},{bytes_written:8,response:{value:8,write_sequence:'1'}},
  {bytes_written:8,response:{value:7,write_sequence:'0'}},{bytes_written:8,response:{value:7,write_sequence:'2'}}])assert.equal(fixedMemoryCompletion({...input,observation}),false);
 assert.equal(fixedMemoryCompletion({...input,coverage:{proof:'send_uncertain'}}),false);
});
test('schema54升级55保留身份，非空关闭帧双向关联且拒绝孤立请求',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-command-settlement-'));
 t.after(()=>{assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 initializeStorage(dir);await migrateStorage(dir,54);let store=openStorage(dir);const identity=store.identity;store.close();
 assert.equal((await migrateStorage(dir,55)).schema_revision,'55');store=openStorage(dir);assert.equal(store.identity.service_id,identity.service_id);store.close();
 const db=new Database(path.join(dir,'controller.sqlite'));try{
  db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');
  const targets=db.prepare('PRAGMA foreign_key_list(execution_dispatch_frame)').raw().all().map(v=>v[2]);
  for(const table of ['command_dispatch_request','command_closure_request','command_closure_ack'])assert.ok(targets.includes(table));
  assert.throws(()=>db.prepare('INSERT INTO command_closure_request VALUES(?,?,?,?,?,?,?)').run('permit','barrier','control','record','tx','{}','sha256:'+'a'.repeat(64)),/command_closure_request_binding/);
  assert.equal(db.prepare('SELECT count(*) FROM command_closure_request').pluck().get(),0);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{db.close();}
});
