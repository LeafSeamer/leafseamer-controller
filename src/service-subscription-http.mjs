import crypto from 'node:crypto';
import {createHttpAdapter,WireError} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {same} from './auth-clock-value.mjs';
import {serviceEventChannel} from './service-event-channel.mjs';
import {profile} from './sdk/runtime/panel-wire/decoder.mjs';
const snapshotProfile=profile({max_message_bytes:8388608,max_depth:48,max_value_nodes:1048576,max_object_members:65536,max_string_utf8_bytes:8388608,parse_deadline_ms:5000});
export function createSubscriptionEndpoint({store,readReferenceBundle=null,serviceBootId=null}){
 const adapter=createHttpAdapter(selection);
 return Object.freeze({channel:serviceEventChannel(store),sweep:()=>store.sweep(),
  sourceTime:{selection,read:(reference,_peer,binding,socket)=>store.sourceTime(binding,socket,reference)},
  ...(readReferenceBundle&&serviceBootId&&{referenceBundle:{selection,serviceBootId,read:(reference,binding,socket)=>store.referenceBundle(binding,socket,reference,readReferenceBundle)}}),
  async handle({bindingId,socket,method,path,headers,body}){
  const request=adapter.prepareRequest('controller',method,path,headers);
  let result,input;
  const current=()=>{const parameters=request.parameters,path=parameters.path,query=parameters.query;
   if(request.operation_id==='internalQuerySnapshotContext')return {status:200,view:store.channels.context(bindingId,socket,path.subscription_id,input,result?.status===200?result.view:null)};
   if(request.operation_id==='internalGetSnapshot')return {status:200,view:store.channels.snapshot(bindingId,socket,path.subscription_id,query.expected_connection_generation)};
   if(request.operation_id==='internalGetSnapshotPage')return {status:200,view:store.channels.snapshot(bindingId,socket,path.subscription_id,query.expected_connection_generation,{snapshot_id:path.snapshot_id,page_index:path.page_index})};
   if(request.operation_id==='internalGetSubscriptionConnection')return {status:200,view:store.channels.attempt(bindingId,socket,path.subscription_id,path.attempt_id)};
   return store.access(bindingId,socket,path.subscription_id,method==='DELETE'?{expected_revision:query.expected_revision}:null);
  };
  try{input=(await adapter.decodeRequest(body,request))?.value??null;result=method==='POST'&&request.operation_id!=='internalQuerySnapshotContext'?store.create(bindingId,socket,input):current();}
  catch(error){const code=error.code??'',status=error instanceof WireError?400:/subscription_(conflict|revision|slot_busy|generation|state)/.test(code)?409:/subscription_capacity/.test(code)?429:/subscription_input/.test(code)?400:/subscription_not_found/.test(code)?404:
   error.name==='ClockError'||/^(event_scope_|worker_|module_)/.test(code)?503:403;
   const codes={400:'invalid_request',403:'forbidden',404:'not_found_or_invisible',409:'conflict',429:'capacity_exceeded',503:'source_unavailable'};
   result={status,view:{code:codes[status],request_id:crypto.randomUUID(),retry_action:status===409?'read_current':'do_not_retry'}};
  }
  const bytes=Buffer.from(JSON.stringify(result.view)),responseHeaders=[['content-type','application/json'],['content-length',String(bytes.length)],['cache-control','no-store'],['x-leafseamer-contract',selection.contract_id],['x-leafseamer-contract-digest',selection.contract_digest]];
  await adapter.decodeResponse(bytes,adapter.prepareResponse(request,String(result.status),responseHeaders),{yieldNow:()=>Promise.resolve(),...(['internalGetSnapshot','internalGetSnapshotPage'].includes(request.operation_id)?{profile:snapshotProfile}:{})});
  return {status:result.status,headers:responseHeaders,body:bytes,beforeSend(){if(result.status>=300)return;
   const latest=method==='POST'&&request.operation_id!=='internalQuerySnapshotContext'?store.access(bindingId,socket,result.view.binding.subscription_id):current();if(!same(latest.view,result.view))throw new Error('subscription_changed');
  }};
 }});
}
