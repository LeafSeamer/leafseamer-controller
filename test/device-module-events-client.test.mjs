import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import canonicalize from 'canonicalize';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));assert.ok(path.isAbsolute(root));
const load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {connectDeviceModule}=await load('device-module-client.mjs'),{moduleTransport}=await load('device-module-channel.mjs'),{openNativeClock}=await load('native-clock.mjs'),{simulatorControlCatalog}=await load('simulator-control-module.mjs');
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
// 独立管道上的合成对端反例；不模拟监督器批准或设备执行资格。
async function fixture(t,change=()=>{},eventSource=null){
 const boot=crypto.randomBytes(16).toString('hex'),clock=openNativeClock(),frames=[],captured=new Map();let failed=false,transport,reads=0;
 const ref={kind:'runtime_binding',authority_service_id:'controller',database_instance_id:'database',object_id:'runtime',revision:'1',digest:hash('runtime')};
 const active={ref,current_boot:true,withdrawal:null,binding:{launch_intent:{object_scope:{device_ids:['device']},extension_binding:{entry_id:'worker'}},admission_receipt:{member_boot_id:boot}}};
 const server=net.createServer(socket=>{transport=moduleTransport(socket,{failed(){},async receive(frame){
  const b=frame.body;let type,body;
  if(frame.type==='LOAD'){type='LOADED';body={entry_id:'worker'};}
  else if(frame.type==='CONNECT'){type='CONNECTED';body={...b,identity:{kind:'virtual',model:'leafseamer.simulator.control',revision:'1'},catalog:simulatorControlCatalog()};}
  else if(frame.type==='EVENT_START'){
   type='EVENT_STARTED';const capture={format:'leafseamer-module-event-capture/1',...b,event_type:'value.written',started_tick_ns:String(clock.tick()),baseline:{value:0}};captured.set(b.capture_id,capture);body={...b,capture};
  }else if(frame.type==='EVENT_READ'){
   type='EVENT_BATCH';const capture=captured.get(b.capture_id),tick=String(clock.tick()),sequence=String(BigInt(b.after_sequence)+1n);
   const batch={format:'leafseamer-module-event-batch/1',capture,after_sequence:b.after_sequence,through_sequence:sequence,events:[{event_id:'event.'+sequence,sequence,event_type:capture.event_type,payload:{value:7},capture_interval:{before_tick_ns:tick,after_tick_ns:tick}}]};
   const result={state:'active',highest_sequence:sequence,failure:null,batch,batch_digest:hash(batch)};body={device_id:b.device_id,device_session_id:b.device_session_id,capture_id:b.capture_id,result};
  }else if(frame.type==='EVENT_ACK'){type='EVENT_ACKED';body=b;}
  else throw new Error('unexpected_test_request');
  const response={...frame,type,body,reply_to:frame.request_id,request_id:crypto.randomUUID()};if(type==='EVENT_BATCH')change(response,++reads,captured);await transport.send(response);
 }});});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen('\\\\.\\pipe\\LeafSeamer.Module.'+boot+'.core',resolve);});
 let client;t.after(async()=>{client?.close();transport?.close();await new Promise(resolve=>server.close(resolve));});
 client=await connectDeviceModule({current:()=>active,invalidate(){failed=true;},configuration:{reference:{kind:'configuration',authority_service_id:'controller',database_instance_id:'database',object_id:'config',revision:'1',digest:hash({})},value:{}},journal:{open(){},record(direction,frame){frames.push({direction,frame});}},catalog:{},events:true,eventSource});
 await client.connectReadOnly('device');await client.startEvents('device');return {client,frames,get failed(){return failed;}};
}
test('事件响应错摘要、描述符或版本不能进入可确认批次',{skip:process.platform!=='win32'},async t=>{
 for(const variant of ['digest','capture','version']){
  const f=await fixture(t,frame=>{if(variant==='digest')frame.body.result.batch_digest=hash('wrong');
   else if(variant==='version')frame.version='device-module/3';
   else{frame.body.result.batch.capture=structuredClone(frame.body.result.batch.capture);frame.body.result.batch.capture.baseline={changed:true};frame.body.result.batch_digest=hash(frame.body.result.batch);}});
  await assert.rejects(f.client.readEvents('device'));assert.equal(f.failed,true);assert.equal(f.frames.filter(v=>v.frame.type==='EVENT_ACK').length,0);
 }
});
test('来源持久化失败关闭实际IPC且不得发送ACK',{skip:process.platform!=='win32'},async t=>{
 const f=await fixture(t,()=>{},{start(){},accept(){throw new Error('source_commit_failed');}});
 await assert.rejects(f.client.readEvents('device'),/source_commit_failed/);assert.equal(f.failed,true);assert.equal(f.frames.filter(v=>v.frame.type==='EVENT_ACK').length,0);
 await assert.rejects(f.client.acknowledgeEvents('device',{through_sequence:'1',batch_digest:hash('batch')}),{code:'module_closed'});
});
test('已读取失败不能恢复为active，跨批次时钟不能倒退',{skip:process.platform!=='win32'},async t=>{
 for(const variant of ['failure','clock']){
  const f=await fixture(t,(frame,n,captures)=>{const r=frame.body.result;if(variant==='failure'&&n===1){r.state='failed';r.failure={reason:'capacity',loss_extent:'none',missing_sequence:null};}
   if(variant==='clock'&&n===2){const start=captures.get(frame.body.capture_id).started_tick_ns;r.batch.events[0].capture_interval={before_tick_ns:start,after_tick_ns:start};r.batch_digest=hash(r.batch);}});
  const first=await f.client.readEvents('device');await f.client.acknowledgeEvents('device',{through_sequence:first.body.result.batch.through_sequence,batch_digest:first.body.result.batch_digest});
  await assert.rejects(f.client.readEvents('device'));assert.equal(f.failed,true);
 }
});
