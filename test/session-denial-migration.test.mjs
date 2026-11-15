import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
const packageRoot=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST;if(packageRoot)assert.ok(path.isAbsolute(packageRoot));
const {initializeStorage,migrateStorage,openStorage}=await import(packageRoot?pathToFileURL(path.join(packageRoot,'dist/storage.mjs')):new URL('../dist/storage.mjs',import.meta.url));
async function setup(t,revision){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-denial-migration-'));initializeStorage(dir);await migrateStorage(dir,revision);let store=openStorage(dir);
 t.after(()=>{store.close();assert.equal(path.dirname(path.resolve(dir)),path.resolve(os.tmpdir()));fs.rmSync(dir,{recursive:true,force:true});});
 return {dir,get store(){return store;},close(){store.close();},reopen(){store=openStorage(dir);}};
}
test('61到62保留会话撤销原件、目标与outbox，新增回执表不补造成功', {timeout:60000},async t=>{
 const f=await setup(t,61),e=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const auth=await authenticated(t,f,{grant:false}),revoked=auth.sessions.logout(auth.auth);auth.real.stop();f.close();
 let before;inspect(f.dir,db=>{before={sessions:db.prepare('SELECT * FROM auth_session').raw().all(),revoked:db.prepare('SELECT * FROM session_revocation').raw().all(),targets:db.prepare('SELECT * FROM session_revocation_target').raw().all(),outbox:db.prepare('SELECT * FROM session_revocation_outbox').raw().all()};});
 assert.equal((await migrateStorage(f.dir,62)).schema_revision,'62');f.reopen();assert.equal(f.store.identity.schema_revision,'62');f.close();
 inspect(f.dir,db=>{assert.deepEqual({sessions:db.prepare('SELECT * FROM auth_session').raw().all(),revoked:db.prepare('SELECT * FROM session_revocation').raw().all(),targets:db.prepare('SELECT * FROM session_revocation_target').raw().all(),outbox:db.prepare('SELECT * FROM session_revocation_outbox').raw().all()},before);
  assert.equal(db.prepare('SELECT count(*) FROM session_denial_receipt').pluck().get(),0);assert.equal(db.prepare('SELECT operation_id FROM session_revocation').pluck().get(),revoked.operation_ref.id);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});
