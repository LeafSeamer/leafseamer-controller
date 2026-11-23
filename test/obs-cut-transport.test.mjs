import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {once} from 'node:events';
import test from 'node:test';
import {WebSocketServer} from 'ws';
import {ObsCutEntryRejected, openObsCutWriterSession} from '../dist/obs-discovery.mjs';

const a='ebc75716-e090-42b1-b9e5-ee8a1dd15879',b='c3a343d6-9f64-4862-a151-baf6201a5ae6';
const availableRequests=JSON.parse(readFileSync(new URL('./fixtures/obs-cut-requests.json',import.meta.url)));
const scenes=[{sceneName:'A',sceneUuid:a},{sceneName:'B',sceneUuid:b}];

async function fixture(t,mode='success'){
 const server=new WebSocketServer({host:'127.0.0.1',port:0}),trace=[];
 t.after(async()=>{for(const client of server.clients)client.terminate();await new Promise(resolve=>server.close(resolve));});
 await once(server,'listening');
 let program=a,setSeen=false;
 server.on('connection',socket=>{
  const emit=(op,d)=>socket.send(JSON.stringify({op,d}));
  const programScene=()=>scenes.find(scene=>scene.sceneUuid===program);
  const array=()=>({scenes,currentProgramSceneName:programScene().sceneName,currentProgramSceneUuid:program});
  const respond={GetVersion:()=>({obsVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,availableRequests}),
   GetSceneCollectionList:()=>({currentSceneCollectionName:'Test',sceneCollections:['Test']}),GetSceneList:array,
   GetCurrentProgramScene:programScene,GetStudioModeEnabled:()=>({studioModeEnabled:false}),
   GetCurrentSceneTransition:()=>({transitionKind:mode==='fade'?'fade_transition':'cut_transition',transitionUuid:a,
    transitionFixed:true,transitionConfigurable:false,transitionDuration:null,transitionSettings:null}),
   GetStreamStatus:()=>({outputActive:false,outputReconnecting:false}),
   GetSceneSceneTransitionOverride:()=>({transitionName:null,transitionDuration:null}),GetSceneItemList:()=>({sceneItems:[]})};
  emit(0,{obsStudioVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,
   authentication:{salt:Buffer.alloc(32,1).toString('base64'),challenge:Buffer.alloc(32,2).toString('base64')}});
  socket.on('message',payload=>{
   const {op,d}=JSON.parse(payload);
   if(op===1){emit(2,{negotiatedRpcVersion:1});return;}
   const {requestType,requestId}=d;
   trace.push({requestType,requestId});
   const ack=(responseData,id=requestId)=>emit(7,{requestType,requestId:id,requestStatus:{result:true,code:100},responseData});
   if(requestType==='SetCurrentProgramScene'){
    assert.deepEqual(d.requestData,{sceneUuid:b});
    setSeen=true;
    if(mode==='disconnect'){socket.terminate();return;}
    if(mode==='bad-ack'){ack(undefined,'wrong');return;}
    if(mode==='collection')emit(5,{eventType:'CurrentSceneCollectionChanging',eventData:{sceneCollectionName:'Other'}});
    if(mode!=='mismatch'){
     program=b;
     emit(5,{eventType:'CurrentProgramSceneChanged',eventData:{sceneUuid:b,sceneName:'B'}});
    }
    ack(undefined);return;
   }
   if(setSeen&&mode==='bad-query'&&requestType==='GetCurrentProgramScene'){ack(programScene(),'wrong');return;}
   assert.ok(respond[requestType],requestType);ack(respond[requestType]());
  });
 });
 const controller=new AbortController(),signal=controller.signal;
 const session=await openObsCutWriterSession({port:server.address().port,password:'synthetic'},signal);
 t.after(()=>session.close());
 let sequence=0n;
 const invoke=enterTransmission=>session.cutScene({sceneUuid:b,enterTransmission,tick:process.hrtime.bigint,
  nextIoSequence:()=>++sequence,evidenceDeadline:process.hrtime.bigint()+5000000000n,signal});
 return {session,trace,invoke,abort:()=>controller.abort()};
}

test('固定 Cut 以一次同步许可发送 UUID，使用该应答之后的新查询记录四帧',async t=>{
 const {invoke,trace}=await fixture(t);
 let sent=0;
 const result=await invoke(()=>{assert.equal(trace.some(v=>v.requestType.startsWith('Set')),false);sent++;});
 assert.equal(sent,1);
 const [send,ack,query,reply]=result.frames;
 assert.deepEqual(result.frames.map(frame=>frame.kind),['set_send','set_ack','query_send','query_result']);
 assert.deepEqual(result.frames.map(frame=>frame.io_seq),['1','2','3','4']);
 assert.equal(send.scene_uuid,b);assert.equal(reply.scene_uuid,b);
 assert.equal(send.protocol_request_id,ack.protocol_request_id);assert.equal(query.protocol_request_id,reply.protocol_request_id);
 assert.notEqual(send.protocol_request_id,query.protocol_request_id);
 const offset=trace.findIndex(value=>value.requestType==='SetCurrentProgramScene');
 assert.deepEqual(trace.slice(offset,offset+2),[{requestType:'SetCurrentProgramScene',requestId:send.protocol_request_id},
  {requestType:'GetCurrentProgramScene',requestId:query.protocol_request_id}]);
 assert.equal(trace.filter(value=>value.requestType==='SetCurrentProgramScene').length,1);
});

test('最终复核拒绝或回调异步时不进入 OBS 出口',async t=>{
 const {invoke,trace,session}=await fixture(t);
 await assert.rejects(invoke(()=>{throw new ObsCutEntryRejected();}),ObsCutEntryRejected);
 assert.equal((await session.sample()).program_scene_uuid,a);
 await assert.rejects(invoke(async()=>{}),{code:'obs_cut_dispatch'});
 assert.equal(trace.some(value=>value.requestType==='SetCurrentProgramScene'),false);
});

test('最终许可回调内撤回会话时不发送也不留下未完成调用',async t=>{
 const {invoke,trace,abort}=await fixture(t);
 await assert.rejects(invoke(abort),{code:'obs_disconnected'});
 assert.equal(trace.some(value=>value.requestType==='SetCurrentProgramScene'),false);
});

for(const mode of ['bad-ack','bad-query','collection','disconnect'])test(`已发送 Cut 遇到 ${mode} 不产生四帧成功或重发`,async t=>{
 const {invoke,trace,session}=await fixture(t,mode);
 await assert.rejects(invoke(()=>{}));
 assert.equal(trace.filter(value=>value.requestType==='SetCurrentProgramScene').length,1);
 assert.throws(()=>session.assertCurrent());
});

test('明确的后置读回不匹配保留实际场景',async t=>{
 const {invoke}=await fixture(t,'mismatch');
 const observation=await invoke(()=>{});
 assert.equal(observation.target_scene_uuid,b);
 assert.equal(observation.frames.at(-1).scene_uuid,a);
});
