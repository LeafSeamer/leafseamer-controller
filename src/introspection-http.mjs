import crypto from 'node:crypto';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {same} from './auth-clock-value.mjs';

export function createIntrospectionEndpoint({sessions,serviceId,serviceBootId}){
 const adapter=createHttpAdapter(selection);
 return async({bindingId,socket,headers,body})=>{
  const request=adapter.prepareRequest('controller','POST','/internal/auth/introspect',headers);
  const input=(await adapter.decodeRequest(body,request)).value;
  let data,status=200,code;
  try{data=sessions.introspectToken(bindingId,socket,input);}catch(error){
   if(error.code==='introspection_audience'){status=403;code='PERMISSION_DENIED';}
   else if(error.code==='introspection_revision'){status=409;code='REVISION_CONFLICT';}
   else if(error.name==='ClockError'||error.code==='introspection_expired'){status=503;code='CLOCK_UNTRUSTED';}
   else if(error.code==='introspection_migration_required'){status=503;code='WORKER_NOT_READY';}
   else throw error;
  }
  const requestId=crypto.randomUUID(),envelope={request_id:requestId,service_id:serviceId,service_boot_id:serviceBootId,protocol_version:selection.contract_id,selection,
   ...(code?{error:{code,message_key:code.toLowerCase(),request_id:requestId,details:{},existing_command_id:null,existing_operation_id:null,retry_advice:'do_not_retry'}}:{data})};
  const bytes=Buffer.from(JSON.stringify(envelope)),responseHeaders=[['content-type','application/json'],['content-length',String(bytes.length)],['cache-control','no-store'],
   ['x-leafseamer-contract',selection.contract_id],['x-leafseamer-contract-digest',selection.contract_digest]];
  await adapter.decodeResponse(bytes,adapter.prepareResponse(request,String(status),responseHeaders),{yieldNow:()=>Promise.resolve()});
  return {status,body:bytes,headers:responseHeaders,beforeSend(){
   if(status!==200)return;
   const current=sessions.introspectToken(bindingId,socket,input,data.active?String(BigInt(Date.parse(data.snapshot.validity.expires_at))*1000000n):null);
   if(data.active!==current.active)throw new Error('introspection_changed');
   if(data.active){
    const stable=value=>{const {snapshot_id,validity,...rest}=value.snapshot;return {...rest,recent_authentication:value.recent_authentication};};
    if(!same(stable(data),stable(current)))throw new Error('introspection_changed');
   }
  }};
 };
}
