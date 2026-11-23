import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {once} from 'node:events';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {WebSocketServer} from 'ws';
import {discoverObsScenes,inspectObsCut} from '../dist/obs-discovery.mjs';

const scene1='ebc75716-e090-42b1-b9e5-ee8a1dd15879',scene2='c3a343d6-9f64-4862-a151-baf6201a5ae6';
const salt=Buffer.alloc(32,1).toString('base64'),challenge=Buffer.alloc(32,2).toString('base64');
const password='synthetic-only-obs-password';
const hash=value=>createHash('sha256').update(value).digest('base64');
const hello={obsStudioVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,authentication:{salt,challenge}};
const results={
 GetVersion:{obsVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,
  availableRequests:['GetVersion','GetSceneCollectionList','GetSceneList','GetCurrentProgramScene','SetCurrentProgramScene']},
 GetSceneCollectionList:{currentSceneCollectionName:'隔离场景',sceneCollections:['隔离场景']},
 GetSceneList:{currentProgramSceneName:'模拟 A',currentProgramSceneUuid:scene1,
  scenes:[{sceneUuid:scene1,sceneName:'模拟 A'},{sceneUuid:scene2,sceneName:'模拟 B'}]},
 GetCurrentProgramScene:{sceneName:'模拟 A',sceneUuid:scene1}
};
async function peer(t,{first=hello,change=null,subscriptions=6}={}){
 const server=new WebSocketServer({port:0,host:'127.0.0.1'}),requests=[];
 await once(server,'listening');
 t.after(()=>new Promise(resolve=>{for(const socket of server.clients)socket.terminate();server.close(resolve);}));
 server.on('connection',socket=>{
  const send=(op,d)=>socket.send(JSON.stringify({op,d}));
  send(0,first);
  socket.on('message',bytes=>{
   const {op,d}=JSON.parse(bytes.toString());
   if(op===1){
    if(d.authentication!==hash(hash(password+salt)+challenge)){socket.close(4009);return;}
    assert.deepEqual(d,{rpcVersion:1,eventSubscriptions:subscriptions,authentication:hash(hash(password+salt)+challenge)});
    send(2,{negotiatedRpcVersion:1});return;
   }
   assert.equal(op,6);assert.deepEqual(Object.keys(d).sort(),['requestId','requestType']);requests.push(d.requestType);
   const value=results[d.requestType];
   assert.ok(value);
   const response={requestId:d.requestId,requestType:d.requestType,requestStatus:{result:true,code:100},responseData:structuredClone(value)};
   change?.({response,requests,send});
   if(socket.readyState===1)send(7,response);
  });
 });
 return {port:server.address().port,requests};
}

test('已构建 Controller 从私有管道执行认证及只读发现，返回场景 UUID 和实际节目场景',async t=>{
 const {port,requests}=await peer(t);
 const file=fileURLToPath(new URL('../dist/cli.mjs',import.meta.url));
 const child=spawn(process.execPath,[file,'inspect-obs'],{stdio:['pipe','pipe','pipe'],windowsHide:true});
 const ended=once(child,'close');t.after(()=>{if(child.exitCode===null)child.kill();});
 let output='',errors='';
 child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>errors+=chunk);
 child.stdin.end(JSON.stringify({port,password}));
 assert.equal((await ended)[0],0,errors);
 assert.doesNotMatch(output+errors,/synthetic-only-obs-password/);
 const result=JSON.parse(output);
 assert.equal(result.event,'obs_discovered');
 assert.equal(result.program_scene_uuid,scene1);
 assert.equal(result.collection_name,'隔离场景');
 assert.deepEqual(result.scenes,[{obs_scene_uuid:scene1,display_name:'模拟 A'},{obs_scene_uuid:scene2,display_name:'模拟 B'}]);
 assert.match(result.available_requests_digest,/^sha256:[a-f0-9]{64}$/);
 assert.deepEqual(requests,['GetVersion','GetSceneCollectionList','GetSceneList','GetCurrentProgramScene','GetSceneCollectionList']);
});

test('不接受未鉴权连接或错误凭据，未发发现请求',async t=>{
 const unauthenticated=await peer(t,{first:{...hello,authentication:undefined}});
 const denied=await peer(t);
 await assert.rejects(discoverObsScenes({port:unauthenticated.port,password}),{code:'obs_authentication_required'});
 await assert.rejects(discoverObsScenes({port:denied.port,password:'wrong synthetic password'}),{code:'obs_authentication'});
 assert.deepEqual(unauthenticated.requests,[]);
 assert.deepEqual(denied.requests,[]);
});

test('连接内集合切换、响应串线或目录重复时拒绝采用',async t=>{
 const variants=[
  [({response,send})=>{if(response.requestType==='GetSceneList')send(5,{eventType:'CurrentSceneCollectionChanging'});},'obs_observation_changed'],
  [({response})=>{if(response.requestType==='GetSceneList')response.requestId='wrong';},'obs_request'],
  [({response})=>{if(response.requestType==='GetSceneList')response.responseData.scenes[1].sceneUuid=scene1;},'obs_scenes'],
  [({response,requests})=>{if(requests.length===5)response.responseData={currentSceneCollectionName:'其他',sceneCollections:['其他']};},'obs_observation_changed']
 ];
 for(const [change,code] of variants){
  const {port}=await peer(t,{change});
  await assert.rejects(discoverObsScenes({port,password}),{code});
 }
});

test('Cut 检查拒绝未经选择的请求表，并在观察期间发现 Studio Mode 切换时失效',async t=>{
 const subscriptions=1|2|4|16|64|128|1024;
 const unexpected=await peer(t,{subscriptions});
 await assert.rejects(inspectObsCut({port:unexpected.port,password}),{code:'obs_cut_profile_version'});
 assert.deepEqual(unexpected.requests,['GetVersion']);

 const changed=await peer(t,{subscriptions,change({send}){
  send(5,{eventType:'StudioModeStateChanged',eventIntent:1024,eventData:{studioModeEnabled:true}});
 }});
 await assert.rejects(inspectObsCut({port:changed.port,password}),{code:'obs_observation_changed'});
 assert.deepEqual(changed.requests,['GetVersion']);
});
