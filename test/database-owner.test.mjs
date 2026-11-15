import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import Database from 'better-sqlite3';
import {setup} from './fixtures/extension-installation.mjs';
import {openStorage} from '../dist/storage.mjs';
const fixture=fileURLToPath(new URL('./fixtures/database-owner-process.mjs',import.meta.url));
test('67版允许独立只读快照，第二服务和迁移仍拒绝；持有进程退出后占用释放',async t=>{
 const f=await setup(t,67),reader=new Database(path.join(f.dir,'controller.sqlite'),{readonly:true,fileMustExist:true,timeout:0});
 try{assert.equal(reader.pragma('user_version',{simple:true}),67);assert.equal(reader.prepare('SELECT service_id FROM service_state').pluck().get(),f.store.identity.service_id);}finally{reader.close();}
 assert.throws(()=>openStorage(f.dir),{code:'database_in_use'});
 for(const mode of ['open','migrate']){const result=spawnSync(process.execPath,['--disallow-code-generation-from-strings',fixture,mode,f.dir],{encoding:'utf8',windowsHide:true,timeout:15000});assert.equal(result.status,2,result.stderr);assert.match(result.stdout,/database_in_use/);}
 f.close();const child=spawn(process.execPath,['--disallow-code-generation-from-strings',fixture,'hold',f.dir],{stdio:['ignore','pipe','pipe'],windowsHide:true});let error='';child.stderr.on('data',v=>error+=v);const exit=once(child,'exit');t.after(async()=>{if(child.exitCode===null&&child.signalCode===null){child.kill();await exit;}});
 const ready=await Promise.race([once(child.stdout,'data').then(([v])=>String(v)),exit.then(()=>{throw Error(error||'owner_process_exit');})]);assert.match(ready,/ready/);assert.throws(()=>openStorage(f.dir),{code:'database_in_use'});
 child.kill('SIGKILL');await exit;f.reopen();assert.equal(f.store.identity.schema_revision,'67');
});
