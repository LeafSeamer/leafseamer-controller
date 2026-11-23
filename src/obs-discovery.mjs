import {createHash,randomUUID} from 'node:crypto';
import WebSocket from 'ws';

const protocol='obswebsocket.json';
const budgetMs=5000;
const requests=['GetVersion','GetSceneCollectionList','GetSceneList','GetCurrentProgramScene'];
const invalidate=new Set([
 'CurrentSceneCollectionChanging','CurrentSceneCollectionChanged','SceneCollectionListChanged',
 'SceneCreated','SceneRemoved','SceneNameChanged','SceneListChanged','CurrentProgramSceneChanged'
]);
const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const name=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value)<=1024;
const version=value=>typeof value==='string'&&/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(value)&&value.length<=80;
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const challengeValue=value=>typeof value==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(value)&&Buffer.from(value,'base64').toString('base64')===value;
const hash=value=>createHash('sha256').update(value).digest('base64');

export class ObsDiscoveryError extends Error{
 constructor(code){super(code);this.name='ObsDiscoveryError';this.code='obs_'+code;}
}
const requireValue=(ok,code)=>{if(!ok)throw new ObsDiscoveryError(code);};

function collection(response){
 const {currentSceneCollectionName:current,sceneCollections:collections}=response;
 requireValue(name(current)&&Array.isArray(collections)&&collections.length<=512&&collections.every(name)&&
  new Set(collections).size===collections.length&&collections.includes(current),'collection');
 return {current,collections:[...collections].sort()};
}
function scenes(response,program){
 requireValue(Array.isArray(response.scenes)&&response.scenes.length>0&&response.scenes.length<=512,'scenes');
 const ids=new Set();
 const values=response.scenes.map(scene=>{
  requireValue(record(scene)&&uuid(scene.sceneUuid)&&name(scene.sceneName)&&!ids.has(scene.sceneUuid),'scenes');
  ids.add(scene.sceneUuid);
  return Object.freeze({obs_scene_uuid:scene.sceneUuid,display_name:scene.sceneName});
 });
 requireValue(uuid(program.sceneUuid)&&name(program.sceneName)&&response.currentProgramSceneUuid===program.sceneUuid&&
  response.currentProgramSceneName===program.sceneName&&values.some(scene=>scene.obs_scene_uuid===program.sceneUuid&&scene.display_name===program.sceneName),'program');
 return Object.freeze(values);
}

// 固定本机发现流程。场景名称只供显示，结果不签发 DeviceSession 或写入资格。
export async function discoverObsScenes(input){
 requireValue(record(input)&&Object.keys(input).sort().join(',')==='password,port'&&Number.isInteger(input.port)&&
  input.port>0&&input.port<=65535&&name(input.password),'input');
 let password=input.password,pending=null,failure=null;
 const port=input.port,deadline=performance.now()+budgetMs;
 const socket=new WebSocket('ws://127.0.0.1:'+port,protocol,{
  followRedirects:false,perMessageDeflate:false,maxPayload:262144,maxFragments:16,maxBufferedChunks:16,handshakeTimeout:budgetMs
 });
 const fail=error=>{
  if(failure)return;
  failure=error;
  const waiting=pending;pending=null;
  waiting?.reject(error);
  socket.terminate();
 };
 const timer=setTimeout(()=>fail(new ObsDiscoveryError('timeout')),budgetMs);
 function assertCurrent(){
  if(failure)throw failure;
  requireValue(performance.now()<deadline,'timeout');
 }
 socket.on('error',()=>fail(new ObsDiscoveryError('transport')));
 socket.on('close',code=>fail(new ObsDiscoveryError(code===4009?'authentication':'disconnected')));
 socket.on('message',(bytes,binary)=>{
  try{
   assertCurrent();
   requireValue(socket.protocol===protocol&&!binary&&Buffer.isBuffer(bytes),'frame');
   const frame=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   requireValue(record(frame)&&record(frame.d),'frame');
   if(frame.op===5){
    requireValue(typeof frame.d.eventType==='string','frame');
    requireValue(!invalidate.has(frame.d.eventType),'observation_changed');
    return;
   }
   requireValue(pending?.op===frame.op,'response');
   const waiting=pending;pending=null;
   waiting.resolve(frame.d);
  }catch(error){fail(error instanceof ObsDiscoveryError?error:new ObsDiscoveryError('frame'));}
 });
 function receive(op,outgoing){
  assertCurrent();
  requireValue(pending===null,'response');
  return new Promise((resolve,reject)=>{
   pending={op,resolve,reject};
   if(outgoing!==undefined)socket.send(JSON.stringify(outgoing),error=>{if(error)fail(new ObsDiscoveryError('transport'));});
  });
 }
 async function read(requestType){
  const requestId=randomUUID(),response=await receive(7,{op:6,d:{requestType,requestId}});
  requireValue(response.requestId===requestId&&response.requestType===requestType&&response.requestStatus?.result===true&&
   response.requestStatus.code===100&&record(response.responseData),'request');
  return response.responseData;
 }
 try{
  const hello=await receive(0),proof=hello.authentication;
  requireValue(hello.rpcVersion===1&&version(hello.obsStudioVersion)&&version(hello.obsWebSocketVersion),'version');
  requireValue(record(proof)&&challengeValue(proof.salt)&&challengeValue(proof.challenge),'authentication_required');
  const authentication=hash(hash(password+proof.salt)+proof.challenge);
  password=null;
  const identified=await receive(2,{op:1,d:{rpcVersion:1,authentication,eventSubscriptions:6}});
  requireValue(identified.negotiatedRpcVersion===1,'version');
  const advertised=await read('GetVersion'),available=advertised.availableRequests;
  requireValue(advertised.rpcVersion===1&&advertised.obsVersion===hello.obsStudioVersion&&advertised.obsWebSocketVersion===hello.obsWebSocketVersion&&
   Array.isArray(available)&&available.length<=1024&&available.every(value=>typeof value==='string'&&/^[A-Za-z][A-Za-z0-9]{0,127}$/.test(value))&&
   new Set(available).size===available.length&&requests.every(request=>available.includes(request)),'version');
  const before=collection(await read('GetSceneCollectionList'));
  const directory=await read('GetSceneList');
  const program=await read('GetCurrentProgramScene');
  const after=collection(await read('GetSceneCollectionList'));
  requireValue(before.current===after.current&&JSON.stringify(before.collections)===JSON.stringify(after.collections),'observation_changed');
  const entries=scenes(directory,program);
  assertCurrent();
  return Object.freeze({obs_version:advertised.obsVersion,websocket_version:advertised.obsWebSocketVersion,rpc_version:1,
   available_requests_digest:'sha256:'+createHash('sha256').update(JSON.stringify([...available].sort())).digest('hex'),
   collection_name:after.current,program_scene_uuid:program.sceneUuid,scenes:entries});
 }finally{password=null;clearTimeout(timer);socket.terminate();}
}
