import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {memoExecutionRead,withExecutionReadView} from '../dist/execution-read-view.mjs';
function fixture(t){const db=new Database(':memory:');t.after(()=>db.close());db.exec('CREATE TABLE fact(id INTEGER PRIMARY KEY,value TEXT); INSERT INTO fact VALUES(1,\'a\')');return db;}
test('同步writer视图复用原件读取，退出或异常后不跨调用缓存',t=>{
 const db=fixture(t);let reads=0;const read=()=>memoExecutionRead(db,'fact',1,()=>{reads++;return db.prepare('SELECT value FROM fact WHERE id=1').pluck().get();});
 assert.throws(()=>withExecutionReadView(db,read),/execution_read_view_writer/);
 db.transaction(()=>{
  withExecutionReadView(db,()=>{assert.equal(read(),'a');withExecutionReadView(db,()=>assert.equal(read(),'a'));});assert.equal(reads,1);
  withExecutionReadView(db,read);assert.equal(reads,2);
  assert.throws(()=>withExecutionReadView(db,()=>{read();throw new Error('stop');}),/stop/);
  withExecutionReadView(db,read);assert.equal(reads,4);
 }).immediate();
});
test('同事务写入及回滚清除原件视图，缺失和读取失败不缓存',t=>{
 const db=fixture(t);let reads=0;const read=id=>memoExecutionRead(db,'fact',id,()=>{reads++;return db.prepare('SELECT value FROM fact WHERE id=?').pluck().get(id);});
 db.transaction(()=>withExecutionReadView(db,()=>{
  assert.equal(read(1),'a');db.prepare('UPDATE fact SET value=? WHERE id=1').run('b');assert.equal(read(1),'b');
  assert.throws(()=>db.transaction(()=>{db.prepare('UPDATE fact SET value=? WHERE id=1').run('c');assert.equal(read(1),'c');throw new Error('rollback');})(),/rollback/);
  assert.equal(read(1),'b');
  assert.equal(read(2),undefined);assert.equal(read(2),undefined);assert.equal(reads,6);
  for(let i=0;i<2;i++)assert.throws(()=>memoExecutionRead(db,'failure',1,()=>{throw new Error('invalid');}),/invalid/);
 })).immediate();
});

test('写入后嵌套读取独立复用，回滚或退出不能恢复父视图缓存',t=>{
 const db=fixture(t);let reads=0;
 const read=()=>memoExecutionRead(db,'fact',1,()=>{reads++;return db.prepare('SELECT value FROM fact WHERE id=1').pluck().get();});
 db.transaction(()=>withExecutionReadView(db,()=>{
  assert.equal(read(),'a');db.prepare('UPDATE fact SET value=? WHERE id=1').run('b');
  withExecutionReadView(db,()=>{assert.equal(read(),'b');assert.equal(read(),'b');});assert.equal(reads,2);
  assert.throws(()=>db.transaction(()=>{
   db.prepare('UPDATE fact SET value=? WHERE id=1').run('c');
   withExecutionReadView(db,()=>{assert.equal(read(),'c');assert.equal(read(),'c');});
   throw new Error('rollback');
  })(),/rollback/);
  assert.equal(read(),'b');assert.equal(reads,4);
  withExecutionReadView(db,()=>{assert.equal(read(),'b');
   assert.throws(()=>db.transaction(()=>{
    db.prepare('UPDATE fact SET value=? WHERE id=1').run('d');
    withExecutionReadView(db,()=>{assert.equal(read(),'d');assert.equal(read(),'d');throw new Error('rollback');});
   })(),/rollback/);
   assert.equal(read(),'b');
  });
  assert.equal(read(),'b');assert.equal(reads,8);
 })).immediate();
});
