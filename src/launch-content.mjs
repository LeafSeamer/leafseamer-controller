import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';
import {openMaterializedContent,ContentError} from './materialized-content.mjs';
const format='leafseamer-launch-content/1';
const need=(ok,code)=>{if(!ok)throw new ContentError(code);};
// 文件hash与目录核验在固定worker中执行，避免阻塞核心监督心跳。
export function pinLaunchContent(root,inventory,expectedIdentity){
 need(isMainThread,'content_host');
 return new Promise((resolve,reject)=>{
  const worker=new Worker(new URL('./launch-content.mjs',import.meta.url),{workerData:{format,root,inventory,expectedIdentity}});
  let ready=false,ending=false,failure=null,pending=null,sequence=0,finish;
  const closed=new Promise(resolve=>{finish=resolve;});
  const stop=error=>{
   if(ending)return;ending=true;failure=error;clearTimeout(startup);
   if(pending){clearTimeout(pending.timer);pending.reject(error??new ContentError('content_pin_closed'));pending=null;}
   worker.terminate().catch(()=>{});
  };
  const startup=setTimeout(()=>stop(new ContentError('content_timeout')),3500);
  const handle=Object.freeze({rootIdentity:expectedIdentity,closed,
   assertHeld(){need(ready&&!ending,'content_pin_closed');},
   verify(){
    need(ready&&!ending,'content_pin_closed');need(!pending,'content_verify_pending');const id=++sequence;
    return new Promise((resolve,reject)=>{pending={id,resolve,reject,timer:setTimeout(()=>stop(new ContentError('content_timeout')),3500)};worker.postMessage({type:'verify',id});});
   },
   close(){stop(null);return closed;}
  });
  worker.on('message',message=>{
   if(ending)return;
   if(message?.error){stop(new ContentError(message.error));return;}
   if(!ready){
    if(message?.type!=='ready'||message.root_identity!==expectedIdentity){stop(new ContentError('content_worker_binding'));return;}
    ready=true;clearTimeout(startup);resolve(handle);return;
   }
   if(!pending||message?.type!=='verified'||message.id!==pending.id){stop(new ContentError('content_worker_binding'));return;}
   const call=pending;pending=null;clearTimeout(call.timer);call.resolve();
  });
  worker.on('error',()=>stop(new ContentError('content_worker_failed')));
  worker.on('exit',()=>{
   if(!ending)stop(new ContentError('content_worker_closed'));
   if(!ready)reject(failure??new ContentError('content_pin_closed'));
   finish(Object.freeze({status:'closed',code:failure?.code??null}));
  });
 });
}
if(!isMainThread&&workerData?.format===format){
 let pin;
 const fail=error=>{pin?.close();parentPort.postMessage({error:typeof error?.code==='string'&&/^content_[a-z_]+$/.test(error.code)?error.code:'content_worker_failed'});parentPort.close();};
 try{
  pin=openMaterializedContent().pin(workerData.root,workerData.inventory,{timeoutMs:3000});
  need(pin.rootIdentity===workerData.expectedIdentity,'content_root_identity');
  parentPort.on('message',message=>{
   try{need(message?.type==='verify'&&Number.isSafeInteger(message.id)&&message.id>0,'content_worker_binding');pin.verify({timeoutMs:3000});parentPort.postMessage({type:'verified',id:message.id});}
   catch(error){fail(error);}
  });
  parentPort.on('close',()=>pin.close());parentPort.postMessage({type:'ready',root_identity:pin.rootIdentity});
 }catch(error){fail(error);}
}
