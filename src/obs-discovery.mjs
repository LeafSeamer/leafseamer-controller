import {createHash,randomUUID} from 'node:crypto';
import WebSocket from 'ws';

const protocol='obswebsocket.json';
const budgetMs=5000;
const requests=['GetVersion','GetSceneCollectionList','GetSceneList','GetCurrentProgramScene'];
const cutRequests=['GetStudioModeEnabled','GetCurrentSceneTransition','GetStreamStatus',
 'GetSceneSceneTransitionOverride','GetSceneItemList'];
const cutProfile={
 obs:'32.0.4',websocket:'5.6.3',
 requestsDigest:'sha256:75ec4eb1bf78e9d07e2753a1bafe951c2966e2fa2b222fd60edd6dd8f18811ef'
};
const invalidate=new Set([
 'CurrentSceneCollectionChanging','CurrentSceneCollectionChanged','SceneCollectionListChanged',
 'SceneCreated','SceneRemoved','SceneNameChanged','SceneListChanged','CurrentProgramSceneChanged'
]);
const cutSubscriptions=1|2|4|16|64|128|1024;
const cutInvalidate=new Set(['ExitStarted','StudioModeStateChanged','CurrentSceneTransitionChanged',
 'CurrentSceneTransitionDurationChanged','StreamStateChanged','SceneItemCreated','SceneItemRemoved','SceneItemListReindexed']);
const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const name=value=>typeof value==='string'&&value.length>0&&Buffer.byteLength(value)<=1024;
const version=value=>typeof value==='string'&&/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(value)&&value.length<=80;
const uuid=value=>typeof value==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/.test(value);
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

async function inspectObs(input,cut,signal,onInvalidated){
 requireValue(record(input)&&Object.keys(input).sort().join(',')==='password,port'&&Number.isInteger(input.port)&&
  input.port>0&&input.port<=65535&&name(input.password),'input');
 requireValue(signal===undefined||signal instanceof AbortSignal&&!signal.aborted,'disconnected');
 let password=input.password,pending=null,failure=null,retained=false,sampling=false;
 const port=input.port;
 let deadline=performance.now()+budgetMs;
 const socket=new WebSocket('ws://127.0.0.1:'+port,protocol,{
  followRedirects:false,perMessageDeflate:false,maxPayload:262144,maxFragments:16,maxBufferedChunks:16,handshakeTimeout:budgetMs
 });
 const fail=(error,notify=true)=>{
  if(failure)return;
  failure=error;
  const waiting=pending;pending=null;
  waiting?.reject(error);
  clearTimeout(timer);
  signal?.removeEventListener('abort',close);
  socket.terminate();
  if(notify&&retained)onInvalidated?.(error);
 };
 let timer=setTimeout(()=>fail(new ObsDiscoveryError('timeout')),budgetMs);
 const close=()=>fail(new ObsDiscoveryError('disconnected'),false);
 signal?.addEventListener('abort',close,{once:true});
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
    if(frame.d.eventType==='CurrentProgramSceneChanged'&&retained&&!sampling)return;
    requireValue(!invalidate.has(frame.d.eventType)&&!(cut&&cutInvalidate.has(frame.d.eventType)),'observation_changed');
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
 async function read(requestType,requestData){
  const requestId=randomUUID(),response=await receive(7,{op:6,d:{requestType,requestId,...(requestData&&{requestData})}});
  requireValue(response.requestId===requestId&&response.requestType===requestType&&response.requestStatus?.result===true&&
   response.requestStatus.code===100&&record(response.responseData),'request');
  return response.responseData;
 }
 async function observe(){
  const before=collection(await read('GetSceneCollectionList'));
  const directory=await read('GetSceneList');
  const program=await read('GetCurrentProgramScene');
  const entries=scenes(directory,program);
  if(cut){
   requireValue(entries.length===2,'cut_profile_scene_count');
   const studio=await read('GetStudioModeEnabled');
   requireValue(studio.studioModeEnabled===false,'cut_profile_studio_mode');
   const transition=await read('GetCurrentSceneTransition');
   requireValue(transition.transitionKind==='cut_transition'&&uuid(transition.transitionUuid)&&
    transition.transitionFixed===true&&transition.transitionConfigurable===false&&transition.transitionDuration===null&&
    transition.transitionSettings===null,'cut_profile_transition');
   const stream=await read('GetStreamStatus');
   requireValue(stream.outputActive===false&&stream.outputReconnecting===false,'cut_profile_stream');
   for(const scene of entries){
    const identity={sceneUuid:scene.obs_scene_uuid};
    const override=await read('GetSceneSceneTransitionOverride',identity);
    requireValue(override.transitionName===null&&override.transitionDuration===null,'cut_profile_override');
    const items=await read('GetSceneItemList',identity);
    requireValue(Array.isArray(items.sceneItems)&&items.sceneItems.length===0,'cut_profile_scene_items');
   }
  }
  const after=collection(await read('GetSceneCollectionList'));
  requireValue(before.current===after.current&&JSON.stringify(before.collections)===JSON.stringify(after.collections),'observation_changed');
  assertCurrent();
  return {collection_name:after.current,program_scene_uuid:program.sceneUuid,scenes:entries};
 }
 try{
  const hello=await receive(0),proof=hello.authentication;
  requireValue(hello.rpcVersion===1&&version(hello.obsStudioVersion)&&version(hello.obsWebSocketVersion),'version');
  requireValue(record(proof)&&challengeValue(proof.salt)&&challengeValue(proof.challenge),'authentication_required');
  const authentication=hash(hash(password+proof.salt)+proof.challenge);
  password=null;
  // General + Config + Scenes + Transitions + Outputs + SceneItems + Ui.
  const identified=await receive(2,{op:1,d:{rpcVersion:1,authentication,eventSubscriptions:cut?cutSubscriptions:6}});
  requireValue(identified.negotiatedRpcVersion===1,'version');
  const advertised=await read('GetVersion'),available=advertised.availableRequests;
  requireValue(advertised.rpcVersion===1&&advertised.obsVersion===hello.obsStudioVersion&&advertised.obsWebSocketVersion===hello.obsWebSocketVersion&&
   Array.isArray(available)&&available.length<=1024&&available.every(value=>typeof value==='string'&&/^[A-Za-z][A-Za-z0-9]{0,127}$/.test(value))&&
   new Set(available).size===available.length&&requests.every(request=>available.includes(request)),'version');
  const availableRequestsDigest='sha256:'+createHash('sha256').update(JSON.stringify([...available].sort())).digest('hex');
  if(cut)requireValue(advertised.obsVersion===cutProfile.obs&&advertised.obsWebSocketVersion===cutProfile.websocket&&
   cutRequests.every(request=>available.includes(request))&&available.includes('SetCurrentProgramScene')&&
   availableRequestsDigest===cutProfile.requestsDigest,'cut_profile_version');
  const profile={obs_version:advertised.obsVersion,websocket_version:advertised.obsWebSocketVersion,rpc_version:1,
   available_requests_digest:availableRequestsDigest,...(cut&&{profile:'obs_isolated_empty_cut/1'})};
  const initial=Object.freeze({...profile,...await observe()});
  if(signal===undefined)return initial;
  retained=true;
  clearTimeout(timer);
  deadline=Infinity;
  return Object.freeze({initial,assertCurrent,close,async sample(){
   assertCurrent();
   requireValue(!sampling,'session_busy');
   sampling=true;
   deadline=performance.now()+budgetMs;
   timer=setTimeout(()=>fail(new ObsDiscoveryError('timeout')),budgetMs);
   try{return Object.freeze({...profile,...await observe()});}
   catch(error){fail(error);throw error;}
   finally{sampling=false;clearTimeout(timer);deadline=Infinity;}
  }});
 }finally{password=null;if(!retained)close();}
}

// 场景名称只供显示。两个入口读完即关闭，不签发 DeviceSession 或写权限。
export const discoverObsScenes=input=>inspectObs(input,false);
export const inspectObsCut=input=>inspectObs(input,true);
export function openObsCutSession(input,signal,onInvalidated){
 requireValue(signal instanceof AbortSignal&&(onInvalidated===undefined||typeof onInvalidated==='function'),'session');
 return inspectObs(input,true,signal,onInvalidated);
}
