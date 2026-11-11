import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {sqliteRows,sqliteRow} from '../src/sqlite-rows.mjs';

test('复用查询仍读取当前行，写入和回滚不会复用旧权限结果',t=>{
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec("CREATE TABLE permission(id TEXT PRIMARY KEY,value TEXT);INSERT INTO permission VALUES('p','active')");
 let preparations=0;const connection={prepare(sql){preparations++;return db.prepare(sql);}};
 const query='SELECT * FROM permission WHERE id=?';
 assert.deepEqual(sqliteRows(connection,query,'p'),[{id:'p',value:'active'}]);
 db.prepare('UPDATE permission SET value=?').run('revoked');
 assert.deepEqual(sqliteRows(connection,query,'p'),[{id:'p',value:'revoked'}]);
 assert.throws(db.transaction(()=>{db.exec("UPDATE permission SET value='active'");
  assert.equal(sqliteRows(connection,query,'p')[0].value,'active');throw new Error('rollback');}),/rollback/);
 assert.equal(sqliteRows(connection,query,'p')[0].value,'revoked');
 assert.deepEqual(sqliteRows(connection,query,'missing'),[]);
 assert.deepEqual(sqliteRow(connection,query,'p'),{id:'p',value:'revoked'});
 db.exec("UPDATE permission SET value='changed'");
 assert.deepEqual(sqliteRow(connection,query,'p'),{id:'p',value:'changed'});
 assert.equal(sqliteRow(connection,query,'missing'),undefined);assert.equal(preparations,1);
});
test('连接隔离、结构变更和语句淘汰不改变查询结果',t=>{
 const a=new Database(':memory:'),b=new Database(':memory:');t.after(()=>{a.close();b.close();});
 a.exec('CREATE TABLE item(a INTEGER);INSERT INTO item VALUES(1)');b.exec('CREATE TABLE item(b TEXT);INSERT INTO item VALUES(\'b\')');
 assert.deepEqual(sqliteRows(a,'SELECT * FROM item'),[{a:1}]);
 assert.deepEqual(sqliteRows(b,'SELECT * FROM item'),[{b:'b'}]);
 a.exec("ALTER TABLE item ADD COLUMN b TEXT DEFAULT 'new'");
 assert.deepEqual(sqliteRows(a,'SELECT * FROM item'),[{a:1,b:'new'}]);
 assert.deepEqual(sqliteRow(a,'SELECT * FROM item'),{a:1,b:'new'});
 for(let n=0;n<130;n++)assert.deepEqual(sqliteRows(a,`SELECT ${n} AS n`),[{n}]);
 assert.deepEqual(sqliteRows(a,'SELECT * FROM item'),[{a:1,b:'new'}]);
 assert.deepEqual(sqliteRow(a,'SELECT * FROM item'),{a:1,b:'new'});
});
