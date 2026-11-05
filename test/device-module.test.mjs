import test from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {moduleTransport,moduleFrameBytes} from '../dist/device-module-channel.mjs';
import {createDeviceModule,simulatorCatalog} from '../dist/simulator-module.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {migrateStorage} from '../dist/storage.mjs';
const frame=()=>({version:'device-module/2',type:'CAPTURE',sequence:'1',request_id:'request',reply_to:null,
 binding:{runtime_binding_ref:{kind:'runtime_binding',authority_service_id:'controller',database_instance_id:'database',object_id:'runtime',revision:'1',digest:'sha256:'+'1'.repeat(64)},ipc_session_id:'channel',member_boot_id:'worker'},
 issued_tick_ns:'1',deadline_tick_ns:'100',body:{device_id:'device',device_session_id:'session',capture_id:'capture'}});
test('业务通道接受分片规范帧，拒绝重复键、非规范正文和帧合并',async()=>{
 const stream=new PassThrough();let value;const seen=new Promise(resolve=>{const transport=moduleTransport(stream,{receive(frame){value=frame;resolve();},failed(){}});void transport;});
 const bytes=moduleFrameBytes(frame());stream.write(bytes.subarray(0,12));stream.write(bytes.subarray(12));await seen;assert.equal(value.type,'CAPTURE');stream.destroy();
 for(const invalid of [Buffer.from('{"version":"x",'+bytes.toString().slice(1)),Buffer.from(' '+bytes.toString()),Buffer.concat([bytes,bytes])]){
  const socket=new PassThrough();let received=false;const closed=new Promise(resolve=>moduleTransport(socket,{receive(){received=true;},failed:resolve}));
  socket.write(invalid);await closed;assert.equal(received,false);
 }
});
test('业务帧限制深度、非有限数字和非法Unicode，不把它们转换成合法样本',()=>{
 const capture={...frame(),type:'CAPTURED',reply_to:'request',body:{...frame().body,captured_tick_ns:'2',value:0}};
 for(const value of [Infinity,NaN,'\ud800'])assert.throws(()=>moduleFrameBytes({...capture,body:{...capture.body,value}}));
 let nested=0;for(let i=0;i<50;i++)nested={nested};assert.throws(()=>moduleFrameBytes({...capture,body:{...capture.body,value:nested}}));
});
test('实际模拟器按独立session产生新样本，断开、错设备及撤销拒绝采样',async()=>{
 const abort=new AbortController(),module=createDeviceModule({configuration:{},device_ids:['a','b'],signal:abort.signal});
 const request={device_id:'a',device_session_id:'one',signal:abort.signal};
 assert.deepEqual(await module.connectReadOnly(request),{kind:'virtual',model:'leafseamer.simulator',revision:'1'});
 const identity={kind:'virtual',model:'leafseamer.simulator',revision:'1'};
 assert.deepEqual(await module.proposeCatalog({...request,identity}),simulatorCatalog());
 await assert.rejects(module.proposeCatalog({...request,identity:{...identity,kind:'physical'}}));
 assert.deepEqual(await module.captureBaseline({...request,capture_id:'first'}),{value:0,sample_sequence:'1'});
 assert.deepEqual(await module.captureBaseline({...request,capture_id:'second'}),{value:0,sample_sequence:'2'});
 await assert.rejects(module.captureBaseline({...request,device_session_id:'other'}));
 await module.stopReadOnly(request);await assert.rejects(module.captureBaseline(request));
 await module.connectReadOnly({...request,device_session_id:'two'});abort.abort();await assert.rejects(module.captureBaseline({...request,device_session_id:'two'}));
});
test('schema24显式升级25保留历史与备份，打开旧库不会隐式批准目录',async t=>{
 const f=await setup(t,24);await assert.rejects(f.store.workerLaunches.openModule({}),/worker_module_migration_required/);f.close();
 const before=inspect(f.dir,db=>db.prepare('SELECT migration_id,script_digest FROM schema_migration ORDER BY rowid').raw().all());
 const result=await migrateStorage(f.dir,25);assert.equal(result.schema_revision,'25');assert.ok(fs.existsSync(path.join(f.dir,result.backup_file)));
 inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT migration_id,script_digest FROM schema_migration ORDER BY rowid LIMIT 24').raw().all(),before);
  for(const table of ['device_catalog_approval','device_baseline_sample'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();assert.equal(f.store.identity.schema_revision,'25');
});
test('schema23显式备份迁移到24保留原迁移历史，不补造模块通道或采样',{timeout:10000},async t=>{
 const f=await setup(t,23);await assert.rejects(f.store.workerLaunches.openModule({}),/worker_module_migration_required/);f.close();
 const before=inspect(f.dir,db=>db.prepare('SELECT migration_id,script_digest FROM schema_migration ORDER BY rowid').raw().all());
 const result=await migrateStorage(f.dir,24);assert.equal(result.schema_revision,'24');assert.ok(fs.existsSync(path.join(f.dir,result.backup_file)));
 inspect(f.dir,db=>{
  assert.deepEqual(db.prepare('SELECT migration_id,script_digest FROM schema_migration ORDER BY rowid LIMIT 23').raw().all(),before);
  for(const name of ['device_module_channel','device_module_frame','device_module_frame_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);
 });
 f.reopen();assert.equal(f.store.identity.schema_revision,'24');
});
