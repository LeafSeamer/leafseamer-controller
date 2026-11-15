import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const {createDeviceModule,simulatorEventLimits}=await import(pathToFileURL(path.join(root,'dist/simulator-control-module.mjs')));

async function setup(count=1){
 let now=100n,clock=()=>now++;const abort=new AbortController(),ids=Array.from({length:count},(_,i)=>'device-'+i),module=createDeviceModule({configuration:{},device_ids:ids,signal:abort.signal,tick:()=>clock()});
 const inputs=ids.map(id=>({device_id:id,device_session_id:id+'.session',signal:abort.signal,capture_id:id+'.capture'}));for(const input of inputs)await module.connectReadOnly(input);
 const write=async(value,input=inputs[0])=>module.execution.writePrimitive({...input,bytes:await module.execution.encodePrimitive({...input,primitive_id:'simulator_value_set',parameters:{value}})});
 const read=(after_sequence='0',max_events=32,input=inputs[0])=>module.events.read({...input,after_sequence,max_events});
 const ack=(batch,input=inputs[0])=>module.events.acknowledge({...input,through_sequence:batch.batch.through_sequence,batch_digest:batch.batch_digest});
 return {module,inputs,abort,write,read,ack,setClock:fn=>{clock=fn;}};
}
test('实际写入产生精确事件，编码和采样不产生事件；批次原件、确认及空批次重复稳定',async()=>{
 const f=await setup(),input=f.inputs[0];await f.write(1);const start=f.module.events.start(input);assert.equal(start.baseline.write_sequence,'1');assert.equal(start.started_tick_ns,'100');
 await f.module.captureBaseline(input);await f.module.execution.encodePrimitive({...input,primitive_id:'simulator_value_set',parameters:{value:2}});
 for(let i=0;i<2;i++){const empty=f.read();assert.deepEqual(empty.batch.events,[]);f.ack(empty);assert.deepEqual(f.ack(empty),{capture_id:input.capture_id,through_sequence:'0',batch_digest:empty.batch_digest});}
 await f.write(7);await f.write(7);const first=f.read('0',1),event=first.batch.events[0];assert.equal(event.sequence,'1');assert.equal(event.payload.write_sequence,'2');assert.equal(event.payload.value,7);assert.deepEqual(event.capture_interval,{before_tick_ns:'101',after_tick_ns:'102'});
 assert.equal(first.batch_digest,'sha256:'+crypto.createHash('sha256').update(canonicalize(first.batch)).digest('hex'));first.batch.events[0].payload.value=999;
 const repeated=f.read('0',1);assert.equal(repeated.batch.events[0].payload.value,7);assert.equal(repeated.batch.events[0].event_id,event.event_id);await f.write(-3);assert.deepEqual(f.read('0',1).batch,repeated.batch);
 f.ack(repeated);f.ack(repeated);const next=f.read('1');assert.deepEqual(next.batch.events.map(e=>[e.sequence,e.payload.write_sequence,e.payload.value]),[['2','3',7],['3','4',-3]]);assert.equal(new Set([event.event_id,...next.batch.events.map(e=>e.event_id)]).size,3);assert.equal(next.highest_sequence,'3');
 f.ack(next);assert.deepEqual(f.read('3').batch.events,[]);
});
test('未读取、错摘要、越界ACK和错游标不释放事件，设备与捕获代际隔离',async()=>{
 const f=await setup(2),[a,b]=f.inputs;f.module.events.start(a);f.module.events.start(b);await f.write(1);await f.write(2,b);
 assert.throws(()=>f.module.events.acknowledge({...a,through_sequence:'1',batch_digest:'sha256:'+'0'.repeat(64)}),/simulator_event_ack/);
 const batch=f.read();for(const change of [{through_sequence:'2'},{batch_digest:'sha256:'+'0'.repeat(64)}])assert.throws(()=>f.module.events.acknowledge({...a,through_sequence:'1',batch_digest:batch.batch_digest,...change}),/simulator_event_ack/);
 assert.throws(()=>f.module.events.acknowledge({...b,through_sequence:'1',batch_digest:batch.batch_digest}),/simulator_event_ack/);
 assert.throws(()=>f.read('1'),/simulator_event_cursor/);assert.throws(()=>f.read('0',1),/simulator_event_batch_pending/);assert.deepEqual(f.read().batch,batch.batch);
 const closed=f.module.events.stop(a);assert.equal(closed.discarded_events,1);assert.equal(closed.last_sequence,'1');assert.throws(()=>f.module.events.start(a),/simulator_event_capture/);assert.throws(()=>f.read(),/simulator_event_capture/);
 const next={...a,capture_id:'new.capture'};assert.equal(f.module.events.start(next).baseline.write_sequence,'1');assert.deepEqual(f.read('0',32,next).batch.events,[]);assert.equal(f.read('0',32,b).batch.events[0].payload.value,2);
});
test('设备及全模块缓存有界，容量失败前没有设备副作用，ACK不解除失败锁存',async()=>{
 const f=await setup(5);for(const input of f.inputs)f.module.events.start(input);
 for(const input of f.inputs.slice(0,4))for(let i=0;i<simulatorEventLimits.device_events;i++)await f.write(i,input);
 const before=await f.module.captureBaseline(f.inputs[0]);await assert.rejects(f.write(999),/simulator_event_capacity/);assert.equal((await f.module.captureBaseline(f.inputs[0])).write_sequence,before.write_sequence);
 await assert.rejects(f.write(1,f.inputs[4]),/simulator_event_capacity/);assert.equal((await f.module.captureBaseline(f.inputs[4])).write_sequence,'0');
 const failed=f.read();assert.equal(failed.state,'failed');assert.deepEqual(failed.failure,{reason:'capacity',loss_extent:'none',missing_sequence:null});f.ack(failed);await assert.rejects(f.write(999),/simulator_event_failed/);
 assert.equal(f.read('32').batch.events.length,32);const stopped=f.module.events.stop(f.inputs[1]);assert.equal(stopped.discarded_events,128);
 await assert.rejects(f.write(1,f.inputs[4]),/simulator_event_failed/);const next={...f.inputs[4],capture_id:'capacity-restart'};f.module.events.stop(f.inputs[4]);f.module.events.start(next);await f.write(5,next);assert.equal(f.read('0',32,next).batch.events[0].payload.value,5);
});
test('写前时钟失败无副作用，写后时钟失败记录已知缺口且禁止继续，失败不能用ACK消除',async()=>{
 const f=await setup();f.module.events.start(f.inputs[0]);f.setClock(()=>99n);await assert.rejects(f.write(1),/simulator_event_clock/);assert.equal((await f.module.captureBaseline(f.inputs[0])).write_sequence,'0');assert.equal(f.read().failure.loss_extent,'none');
 f.module.events.stop(f.inputs[0]);const input={...f.inputs[0],capture_id:'after-clock-failure'};let calls=0;f.setClock(()=>[200n,201n,199n][calls++]);f.module.events.start(input);await assert.rejects(f.write(2,input),/simulator_event_clock/);
 const actual=await f.module.captureBaseline(input);assert.equal(actual.write_sequence,'1');assert.equal(actual.value,2);const lost=f.read('0',32,input);assert.equal(lost.highest_sequence,'1');assert.deepEqual(lost.batch.events,[]);assert.deepEqual(lost.failure,{reason:'clock',loss_extent:'known',missing_sequence:'1'});f.ack(lost,input);await assert.rejects(f.write(3,input),/simulator_event_failed/);
});
test('断开、旧session及中止不能继续读取旧捕获；未启用事件的原写入行为保留',async()=>{
 const f=await setup();f.module.events.start(f.inputs[0]);await f.write(1);await f.module.stopReadOnly(f.inputs[0]);assert.throws(()=>f.read(),/simulator_session/);
 const next={...f.inputs[0],device_session_id:'next.session',capture_id:'next.capture'};await f.module.connectReadOnly(next);f.module.events.start(next);assert.deepEqual(f.read('0',32,next).batch.events,[]);f.abort.abort();assert.throws(()=>f.read('0',32,next),/simulator_unavailable/);await assert.rejects(f.write(2,next),/simulator_unavailable/);
 const plain=await setup();plain.setClock(()=>{throw new Error('unused');});await plain.write(9);assert.equal((await plain.module.captureBaseline(plain.inputs[0])).value,9);
});
