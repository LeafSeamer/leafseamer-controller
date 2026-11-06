import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {coreRuntimeSource} from '../dist/core-runtime-source.mjs';
import {IdentityError} from '../dist/identity-crypto.mjs';
import {SupervisorError} from '../dist/supervisor-control.mjs';

// 合成监督观察与时钟；验证持久来源的拒绝分类，不代表真实监督进程验收。
function fixture(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE core_runtime_source(source_id TEXT PRIMARY KEY,service_boot_id TEXT,response_id TEXT,selected_tick TEXT,expires_tick TEXT,body_jcs TEXT,body_digest TEXT);
 CREATE TABLE core_runtime_source_commit(source_id TEXT PRIMARY KEY,body_digest TEXT,audit_jcs TEXT);`);
 const service={service_id:'controller',database_instance_id:'database'},domainRef={clock_domain_id:'domain',descriptor_digest:'sha256:'+'1'.repeat(64)};
 const parent={intent:{launch_id:'core'},receipt:{domain_ref:domainRef}},scope={...service,domain_ref:domainRef};
 let tick=10n,sequence=0,observation,observationError=null,connectionError=null;
 const advance=expires=>{const request={type:'LAUNCH_QUERY',message_id:'query.'+(++sequence),channel_id:'channel',scope,payload:{launch_id:'core'}};
  observation={request,response:{type:'LAUNCH_RESULT',reply_to:request.message_id,message_id:'response.'+sequence,channel_id:'channel',scope,
   payload:{key:request.payload,record:{admission_receipt:parent.receipt}}},issued_tick_ns:String(tick),received_tick_ns:String(tick),expires_tick_ns:String(expires)};};
 advance(20n);
 const source=coreRuntimeSource({db,service,bootId:'boot',core:()=>parent,connected(){if(connectionError)throw connectionError;},observe:()=>observation,
  assertObservation(value){if(observationError)throw observationError;if(tick>=BigInt(value.expires_tick_ns))throw new SupervisorError('supervisor_core_observation');},
  domain:()=>({ref:domainRef,tick:String(tick)})});
 return {source,run:fn=>db.transaction(fn).immediate(),tick:value=>{tick=value;},advance,
  observationError:value=>{observationError=value;},connectionError:value=>{connectionError=value;}};
}
test('旧核心观察到期与检查间竞态只拒绝资格，后续新来源仍可选择',t=>{
 const f=fixture(t),first=f.run(()=>f.source.select());
 f.tick(20n);assert.throws(()=>f.run(()=>f.source.current(first.ref)),e=>e instanceof IdentityError&&e.code==='core_runtime_source_not_current');
 f.advance(40n);const fresh=f.run(()=>f.source.select());assert.notEqual(fresh.ref.id,first.ref.id);
 f.observationError(new SupervisorError('supervisor_core_observation'));
 assert.throws(()=>f.run(()=>f.source.current(fresh.ref)),e=>e instanceof IdentityError&&e.code==='core_runtime_source_not_current');
 assert.throws(()=>f.run(()=>f.source.select()),e=>e instanceof IdentityError&&e.code==='core_runtime_source_not_current');
 f.observationError(null);assert.deepEqual(f.run(()=>f.source.current(fresh.ref)),fresh);
});
test('真实监督通道错误不转换为可恢复的来源失效',t=>{
 const f=fixture(t),first=f.run(()=>f.source.select()),lost=new SupervisorError('supervisor_channel_closed');
 f.connectionError(lost);assert.throws(()=>f.run(()=>f.source.current(first.ref)),e=>e===lost);
 f.connectionError(null);f.observationError(lost);assert.throws(()=>f.run(()=>f.source.current(first.ref)),e=>e===lost);
});
