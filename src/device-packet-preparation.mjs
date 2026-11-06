import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeExecutionPayload,DeviceExecutionError} from './device-execution-channel.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const digest=value=>hash(canonicalize(value));
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const frozen=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))frozen(child);Object.freeze(value);}return value;};
const reference=(id,digest)=>({id,revision:'1',digest});
const projection=ref=>({object_id:ref.id,digest:ref.digest});
const content=({context_id,idempotency_key,correlation_id,...value})=>value;
const maxTick=99999999999999999999n,controlReservation=2*262144+8192;

// 仅由固定worker装配；binding、profile、plan及编码器来自当前已批准模块，不来自设备请求。
// 此对象不分配IPC序号、不签发permit、不调用writePrimitive，也不裁决设备效果。
export function devicePacketPreparation({binding,profile,plan,capability,exit,executor,tick,signal,failed,limits}){
 need(executor?.api_version==='leafseamer-device-primitives/1'&&typeof executor.encodePrimitive==='function'&&typeof tick==='function'&&
  signal instanceof AbortSignal&&typeof failed==='function','encoding_configuration');
 const bound=frozen(structuredClone(binding)),profileRef=frozen(structuredClone(profile)),planRef=frozen(structuredClone(plan)),capabilityRef=frozen(structuredClone(capability));
 need(limits&&typeof limits==='object','encoding_capacity_profile');
 const outlet=frozen(structuredClone(exit)),budget={...limits};
 const transportId=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$(?![\s\S])/.test(value);
 need(transportId(bound.writer_exit_id)&&transportId(bound.device_session_id)&&transportId(outlet.socket_instance_id)&&
  (outlet.protocol_session===null||transportId(outlet.protocol_session)),'encoding_exit_configuration');
 for(const [key,maximum] of Object.entries({max_entries:256,max_cached_bytes:16777216,max_metadata_bytes:67108864,max_encoders:16}))
  need(Number.isSafeInteger(budget[key])&&budget[key]>0&&budget[key]<=maximum,'encoding_capacity_profile');
 const records=new Map(),controlIds=new Map();let terminal=false,bytesReserved=0,metadataReserved=0,encoders=0,lastTick=null;
 function now(){let value;try{value=tick();}catch{need(false,'encoding_clock');}
  need(typeof value==='bigint'&&value>=0n&&value<=maxTick&&(lastTick===null||value>=lastTick),'encoding_clock');lastTick=value;return value;}
 function current(){need(!terminal&&!signal.aborted,'encoding_closed');}
 function dispose(entry){
  if(entry.encoding||entry.consumers)return false;
  entry.bytes?.fill(0);entry.bytes=null;
  if(entry.reserved){bytesReserved-=entry.reserved;entry.reserved=0;}return true;
 }
 function wake(entry){for(const resolve of entry.waiters)resolve();entry.waiters.clear();if(terminal)dispose(entry);}
 function close(error=new DeviceExecutionError('encoding_closed')){
  if(terminal)return;terminal=true;
  for(const entry of records.values()){entry.denied=true;entry.abort.abort();dispose(entry);wake(entry);}
  try{failed(error);}catch{}
 }
 signal.addEventListener('abort',()=>close(),{once:true});
 function fatal(error){close(error);throw error;}
 function record(id){current();const entry=records.get(id);need(entry,'encoding_unknown');return entry;}
 function status(entry){return frozen({prepare_id:entry.prepareId,state:entry.released?'released':entry.denied?'denied':entry.encoding?'encoding':entry.packet?'prepared':'failed',
  encoding_authorization_ref:entry.authorizationRef,packet_ref:entry.packet?{object_id:entry.packet.packet_id,digest:entry.packet.packet_digest}:null});}
 async function incoming(bytes,type){
  current();const decoded=await decodeExecutionPayload(bytes,'c2w');current();const frame=decoded.frame;
  need(frame.type===type&&frame.journal_mode==='durable','encoding_message_type');
  for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','device_id','clock_domain_id','descriptor_digest'])need(frame[key]===bound[key],'encoding_channel_binding');
  return decoded;
 }
 function authorized(frame){
  const body=frame.body,a=body.encoding_authorization,{authorization_digest,...original}=a,t=now();
  need(digest(original)===authorization_digest&&same(a.binding,bound),'encoding_authorization_binding');
  need(a.target.kind==='ordinary'&&a.target.command_ref.id===body.command_id&&a.target.proposed_attempt_id===body.attempt_id&&
   body.device_session_id===bound.device_session_id&&body.request.device_id===bound.device_id&&body.primitive_id===a.primitive_id,'encoding_target');
  need(same(a.primitive_plan_ref,planRef)&&same(a.transport_profile_ref,profileRef)&&same(a.capability_ref,capabilityRef)&&
   same(body.primitive_plan_ref,projection(planRef))&&same(body.transport_profile_ref,projection(profileRef)),'encoding_profile');
  need(body.request.origin!=='manual'||a.requester.kind==='human','encoding_requester');
  need(digest(content(body.request))===a.content_digest&&body.expires_tick_ns===a.expires_tick_ns,'encoding_content');
  need(BigInt(a.created_tick_ns)<=t&&BigInt(a.created_tick_ns)<BigInt(a.expires_tick_ns),'encoding_authorization_time');
  return {authorizationRef:reference(a.authorization_id,a.authorization_digest),expired:t>=BigInt(a.expires_tick_ns)};
 }
 async function run(entry){
  const body=entry.frame.body;
  try{
   current();if(entry.denied)return;const result=await executor.encodePrimitive({device_id:bound.device_id,device_session_id:bound.device_session_id,
    primitive_id:body.primitive_id,parameters:body.request.parameters,signal:entry.abort.signal});
   need(result instanceof Uint8Array&&result.byteLength>0&&result.byteLength<=body.encoding_authorization.max_bytes,'encoding_output');
   if(entry.denied||terminal)return;
   const t=now();if(t>=BigInt(body.expires_tick_ns)){entry.reason='expired';return;}
   const bytes=Uint8Array.from(result),bytesDigest=hash(bytes),packetId=crypto.randomUUID();
   const packet={packet_id:packetId,command_id:body.command_id,attempt_id:body.attempt_id,primitive_id:body.primitive_id,
    writer_exit_id:bound.writer_exit_id,device_session_id:bound.device_session_id,socket_instance_id:outlet.socket_instance_id,
    protocol_session:outlet.protocol_session,wire_packet_id:null,tracking_ids:[],
    immutable_bytes_ref:{object_id:'bytes_'+packetId,digest:bytesDigest},byte_length:bytes.length,sha256:bytesDigest,
    transport_profile_ref:body.transport_profile_ref,primitive_plan_ref:body.primitive_plan_ref};
   entry.bytes=bytes;entry.packet=frozen({...packet,packet_digest:digest(packet)});
  }catch(error){entry.reason='unavailable';if(error?.code==='encoding_clock')close(error);}
  finally{
   entry.encoding=false;encoders--;if(!entry.packet&&!entry.denied)entry.reason??='unavailable';
   if(terminal)dispose(entry);wake(entry);
  }
 }
 async function consume(entry,fn,response){
  // 仅可信发送器/最终出口作为消费者；其Promise必须覆盖所有本机字节引用的生命周期。
  // 逐传输permit消费及设备风险裁决由最终出口负责，借用令牌不代表发送许可。
  current();need(!entry.encoding&&!entry.denied&&!entry.released,'encoding_not_available');
  need(typeof fn==='function','encoding_consumer');need(entry.consumers===0,'encoding_consumer_busy');entry.consumers++;let bytes;
  try{
   if(response){
    const body=entry.packet?{prepare_id:entry.frame.body.prepare_id,packet:entry.packet,bytes_hex:Buffer.from(entry.bytes).toString('hex'),encoding_authorization_ref:entry.authorizationRef}:
     {prepare_id:entry.frame.body.prepare_id,reason:entry.reason,encoding_authorization_ref:entry.authorizationRef};
    return await fn(frozen({type:entry.packet?'PREPARE_PACKET':'PACKET_ENCODING_FAILED',reply_to:entry.frame.message_id,device_id:bound.device_id,body}));
   }
   need(entry.packet&&entry.bytes,'encoding_not_prepared');bytes=Uint8Array.from(entry.bytes);return await fn(bytes);
  }finally{bytes?.fill(0);entry.consumers--;wake(entry);}
 }
 async function cleanup(bytes,type){
  const decoded=await incoming(bytes,type),frame=decoded.frame,body=frame.body,idKey=type==='DENY_ENCODING'?'deny_id':'release_id';
  const {request_digest,...original}=body;
  need(digest(original)===request_digest&&same(body.binding,bound),'encoding_cleanup_binding');
  let entry=records.get(body.prepare_id);
  if(!entry){
   // 当前受信Controller可以撤回尚未入流的准备。只保存精确原ENCODE承诺，
   // 不伪造已见ENCODE、编码失败、活字节预留或释放证明；墓碑计入固定准备容量。
   need(type==='DENY_ENCODING','encoding_unknown');need(!controlIds.has(body[idKey]),'encoding_cleanup_conflict');
   need(BigInt(body.selected_tick_ns)<=now(),'encoding_cleanup_time');
   const metadata=262144+controlReservation;
   need(records.size<budget.max_entries&&metadataReserved+metadata<=budget.max_metadata_bytes,'encoding_metadata_capacity');
   entry={prepareId:body.prepare_id,frame:null,payload:null,authorizationRef:frozen(structuredClone(body.encoding_authorization_ref)),
    encodeMessageId:body.encode_message_id,encodeFrameDigest:body.encode_frame_digest,denySelectedTick:body.selected_tick_ns,
    abort:new AbortController(),encoding:false,consumers:0,waiters:new Set(),bytes:null,packet:null,reserved:0,denied:true,released:false,reason:null,job:Promise.resolve()};
   records.set(body.prepare_id,entry);metadataReserved+=metadata;
  }
  need(same(body.encoding_authorization_ref,entry.authorizationRef)&&body.encode_message_id===entry.encodeMessageId&&body.encode_frame_digest===entry.encodeFrameDigest,'encoding_cleanup_binding');
  // 仅凭未知准备的DENY墓碑不能声称原ENCODE缓存已释放。
  need(type!=='RELEASE_ENCODING'||entry.frame,'encoding_release_origin_required');
  const other=entry[type==='DENY_ENCODING'?'RELEASE_ENCODING':'DENY_ENCODING'];
  need(!other||same(body.revocation_ref,other.frame.body.revocation_ref),'encoding_cleanup_binding');
  const previous=entry[type];
  if(previous){need(previous.payload.equals(decoded.payload),'encoding_cleanup_conflict');return {entry,operation:previous};}
  need(!controlIds.has(body[idKey]),'encoding_cleanup_conflict');const t=now();
  need(BigInt(body.selected_tick_ns)<=t&&(!entry.frame||BigInt(body.selected_tick_ns)>=BigInt(entry.frame.body.encoding_authorization.created_tick_ns)),'encoding_cleanup_time');
  const operation={frame,payload:decoded.payload,ack:null,pending:null};entry[type]=operation;controlIds.set(body[idKey],entry);
  entry.denied=true;entry.abort.abort();return {entry,operation};
 }
 return Object.freeze({
  async prepare(bytes){
   try{
    const {frame,payload}=await incoming(bytes,'ENCODE_PACKET'),previous=records.get(frame.body.prepare_id);
    if(previous){
     if(previous.payload)need(previous.payload.equals(payload),'encoding_prepare_conflict');
     else{
      const {authorizationRef}=authorized(frame);
      need(previous.denied&&frame.message_id===previous.encodeMessageId&&digest(frame)===previous.encodeFrameDigest&&same(authorizationRef,previous.authorizationRef),'encoding_prepare_conflict');
      need(BigInt(frame.body.encoding_authorization.created_tick_ns)<=BigInt(previous.denySelectedTick),'encoding_cleanup_time');
      previous.frame=frame;previous.payload=payload;
     }
     return status(previous);
    }
    const {authorizationRef,expired}=authorized(frame),reserved=frame.body.encoding_authorization.max_bytes*3,metadata=payload.length+controlReservation;
    need(records.size<budget.max_entries&&metadataReserved+metadata<=budget.max_metadata_bytes,'encoding_metadata_capacity');
    const entry={prepareId:frame.body.prepare_id,frame,payload,authorizationRef,encodeMessageId:frame.message_id,encodeFrameDigest:digest(frame),
     abort:new AbortController(),encoding:false,consumers:0,waiters:new Set(),bytes:null,packet:null,reserved:0,denied:false,released:false,reason:null,job:null};
    records.set(frame.body.prepare_id,entry);metadataReserved+=metadata;
    if(expired){entry.reason='expired';entry.job=Promise.resolve();return status(entry);}
    if(encoders>=budget.max_encoders||bytesReserved+reserved>budget.max_cached_bytes){entry.reason='capacity';entry.job=Promise.resolve();return status(entry);}
    entry.encoding=true;entry.reserved=reserved;bytesReserved+=reserved;encoders++;entry.job=Promise.resolve().then(()=>run(entry));return status(entry);
   }catch(error){return fatal(error);}
  },
  async whenPrepared(id){const entry=record(id);await entry.job;current();return status(entry);},
  describe(id){const entry=record(id);need(!entry.encoding&&!entry.denied&&!entry.released&&entry.packet,'encoding_not_prepared');
   return frozen({request:entry.frame.body.request,authorization:entry.frame.body.encoding_authorization,packet:entry.packet});},
  async withResponse(id,send){const entry=record(id);await entry.job;return consume(entry,send,true);},
  async withPacket(id,packetRef,use){const entry=record(id);need(entry.packet&&same(packetRef,{object_id:entry.packet.packet_id,digest:entry.packet.packet_digest}),'encoding_packet_binding');return consume(entry,use,false);},
  async reject(bytes){
   try{const {frame}=await incoming(bytes,'PREPARE_PACKET_REJECTED'),body=frame.body,entry=record(body.prepare_id);
    need(entry.packet&&same(body.packet_ref,{packet_id:entry.packet.packet_id,packet_digest:entry.packet.packet_digest})&&
     same(body.encoding_authorization_ref,entry.authorizationRef),'encoding_rejection_binding');
    need(!entry.rejection||same(entry.rejection,body),'encoding_rejection_conflict');entry.rejection=frozen(structuredClone(body));
    entry.denied=true;entry.abort.abort();
    // 拒绝立即禁止使用，但不冒充带撤回原件的RELEASE_ENCODING确认。
   }catch(error){return fatal(error);}
  },
  async deny(bytes){
   try{const {entry,operation}=await cleanup(bytes,'DENY_ENCODING');if(!operation.ack){const frame=operation.frame,body=frame.body;
    operation.ack=frozen({type:'DENY_ENCODING_ACK',reply_to:frame.message_id,device_id:bound.device_id,body:{deny_ref:reference(body.deny_id,body.request_digest),binding:bound,
     prepare_id:body.prepare_id,deny_message_id:frame.message_id,deny_frame_digest:digest(frame),effective_tick_ns:String(now()),state:'denied',future_use_denied:true}});}
    return operation.ack;
   }catch(error){return fatal(error);}
  },
  async release(bytes){
   try{const {entry,operation}=await cleanup(bytes,'RELEASE_ENCODING');
    if(!operation.pending)operation.pending=(async()=>{
     while(entry.encoding||entry.consumers){await new Promise(resolve=>entry.waiters.add(resolve));current();}
     current();need(dispose(entry),'encoding_consumers');entry.released=true;
     const frame=operation.frame,body=frame.body;
     operation.ack=frozen({type:'RELEASE_ENCODING_ACK',reply_to:frame.message_id,device_id:bound.device_id,body:{release_ref:reference(body.release_id,body.request_digest),binding:bound,
      prepare_id:body.prepare_id,release_message_id:frame.message_id,release_frame_digest:digest(frame),disposed_tick_ns:String(now()),state:'released',encoder_quiescent:true,consumers_quiescent:true,cache_empty:true}});
     return operation.ack;
    })();return await operation.pending;
   }catch(error){return fatal(error);}
  },
  close,
  get usage(){return Object.freeze({entries:records.size,reserved_bytes:bytesReserved,metadata_bytes:metadataReserved,encoders,closed:terminal});}
 });
}
