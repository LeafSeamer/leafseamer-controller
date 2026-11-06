import test from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough,Duplex} from 'node:stream';
import {executionTransport,executionWire,decodeExecutionPayload,executionSessionIdentity} from '../dist/device-execution-channel.mjs';
import {deviceExecutionVersion} from '../dist/sdk/device-execution.mjs';
const frame=n=>({ipc_version:deviceExecutionVersion,type:'CLOSE_GATE',message_id:'close.'+n,reply_to:null,
 ipc_session_id:'ipc',controller_boot_id:'core',worker_boot_id:'worker',seq:String(n),device_id:null,
 body:{close_id:'close.'+n,reason:'test',scope:'controller'},clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:'sha256:'+'2'.repeat(64),journal_mode:'durable'});
const payload=n=>Buffer.from(JSON.stringify(frame(n)));

test('最终写前取消明确返回未进入写调用，保持同一流可用于终端保护',async t=>{
 const writes=[],errors=[],socket=new Duplex({read(){},write(bytes,encoding,callback){writes.push(Buffer.from(bytes));callback();}});
 t.after(()=>socket.destroy());const transport=executionTransport(socket,{incoming:'w2c',receive(){},failed:error=>errors.push(error)});
 const result=await transport.send(payload(1),{beforeWrite:()=>false});assert.deepEqual(result,{wire_length:0,not_started:true});
 assert.equal(writes.length,0);assert.equal(errors.length,0);
 const close={...frame(1),seq:null,journal_mode:'volatile_close'};await transport.send(Buffer.from(JSON.stringify(close)));
 assert.equal(writes.length,1);assert.equal((await decodeExecutionPayload(writes[0].subarray(4),'c2w')).frame.journal_mode,'volatile_close');
});

test('执行session由完整监督身份唯一确定，换域/换boot/换库均不可沿用',()=>{
 const source={authority_service_id:'service',database_instance_id:'database',controller_boot_id:'core',worker_boot_id:'worker',
  clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:'sha256:'+'2'.repeat(64)};
 const identity=executionSessionIdentity(source);assert.ok(Object.isFrozen(identity));assert.deepEqual(executionSessionIdentity({...source}),identity);
 assert.match(identity.ipc_session_id,/^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 for(const key of Object.keys(source)){
  const changed={...source,[key]:key==='clock_domain_id'?'clock_'+'3'.repeat(64):key==='descriptor_digest'?'sha256:'+'4'.repeat(64):source[key]+'_next'};
  assert.notEqual(executionSessionIdentity(changed).ipc_session_id,identity.ipc_session_id);
 }
 for(const changed of [{...source,extra:true},{...source,worker_boot_id:'core'},{...source,controller_boot_id:'core\n'},{...source,clock_domain_id:'clock_bad'}])
  assert.throws(()=>executionSessionIdentity(changed),/execution_identity/);
 source.worker_boot_id='changed';assert.equal(identity.worker_boot_id,'worker');
});

test('最终写前资格核验或持久登记抛错时零字节写出，关闭后不可重试',async()=>{
 for(const reason of ['execution_open_expired','execution_open_storage']){
  const writes=[],errors=[],socket=new Duplex({read(){},write(bytes,encoding,callback){writes.push(Buffer.from(bytes));callback();}});
  const transport=executionTransport(socket,{incoming:'w2c',receive(){},failed:error=>errors.push(error)});
  const failure=new Error(reason);let checked=0;
  await assert.rejects(transport.send(payload(1),{beforeWrite(){checked++;throw failure;}}),error=>error===failure);
  assert.equal(checked,1);assert.equal(writes.length,0);assert.equal(socket.destroyed,true);assert.deepEqual(errors,[failure]);
  await assert.rejects(transport.send(payload(1)),/execution_closed/);assert.equal(writes.length,0);
 }
});
test('执行字节流按长度前缀处理分片和同批多帧，领域处理串行且保留原wire',async t=>{
 const socket=new PassThrough();t.after(()=>socket.destroy());const seen=[];let release,first;
 const gate=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{first=resolve;});
 let done;const complete=new Promise(resolve=>{done=resolve;});
 executionTransport(socket,{incoming:'c2w',failed(){},async receive(value){
  seen.push(value);if(seen.length===1){first();await gate;}else done();
 }});
 const one=executionWire(payload(1)),two=executionWire(payload(2));
 socket.write(one.subarray(0,2));socket.write(Buffer.concat([one.subarray(2),two]));
 await started;assert.equal(seen.length,1);release();await complete;
 assert.deepEqual(seen.map(v=>v.frame.seq),['1','2']);assert.deepEqual(seen[0].wire,one);assert.deepEqual(seen[1].payload,payload(2));
});
test('错长度、重复键、错方向或领域提交失败均关闭，不处理后续帧',async()=>{
 for(const mode of ['length','duplicate','direction','commit']){
  const socket=new PassThrough();let received=0;
  const closed=new Promise(resolve=>executionTransport(socket,{incoming:mode==='direction'?'w2c':'c2w',failed:resolve,
   receive(){received++;throw new Error('synthetic_commit_failure');}}));
  const invalid=mode==='length'?Buffer.from([0,4,0,1]):executionWire(mode==='duplicate'?Buffer.from('{"seq":"2",'+payload(1).toString().slice(1)):payload(1));
  socket.write(Buffer.concat([invalid,executionWire(payload(2))]));await closed;
  assert.equal(received,mode==='commit'?1:0);assert.equal(socket.destroyed,true);
 }
});
test('发送只写一次，复制调用者字节并拒绝重叠写入；失败不重发',async()=>{
 let callback,written,count=0;
 const socket=new Duplex({read(){},write(chunk,encoding,done){count++;written=Buffer.from(chunk);callback=done;}});
 const errors=[];const transport=executionTransport(socket,{incoming:'w2c',receive(){},failed:e=>errors.push(e)});
 const bytes=payload(1),pending=transport.send(bytes);bytes.fill(0);
 await assert.rejects(transport.send(payload(2)),/execution_write_busy/);
 while(!callback)await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(written,executionWire(payload(1)));callback(new Error('synthetic_partial_write'));
 await assert.rejects(pending,/execution_write_uncertain/);assert.equal(count,1);assert.equal(errors.length,1);
 await assert.rejects(transport.send(payload(2)),/execution_closed/);
});
test('执行载荷有独立帧预算，不接受空正文或只读模块帧',async()=>{
 await assert.rejects(decodeExecutionPayload(Buffer.alloc(262145),'c2w'),/execution_frame_size/);
 assert.throws(()=>executionWire(Buffer.alloc(0)),/execution_frame_size/);
 await assert.rejects(decodeExecutionPayload(Buffer.from('{"type":"CAPTURE","version":"device-module/2"}'),'c2w'));
});
