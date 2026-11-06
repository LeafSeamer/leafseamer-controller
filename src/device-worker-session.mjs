import crypto from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {executionSessionIdentity,executionTransport,decodeExecutionPayload,executionWire,DeviceExecutionError} from './device-execution-channel.mjs';
import {deviceExecutionVersion,deviceExecutionMessages,validateDeviceExecutionFeatures,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const maximum=99999999999999999999n;
const types=new Map(deviceExecutionMessages.map(value=>[value.type,value]));
const freeze=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;};

// 固定worker的单会话内存所有者；不替代Controller的持久FrameRecord/EffectCommit。
// receive只等待领域登记/失效；模块I/O与编码完成应异步提交响应，不能堵住后到的关闭。
// start的HELLO声明必须由已实现的固定worker装配层提供，本对象不自动填充特性声明。
export function deviceWorkerSession({socket,identity,descriptor,devices,receive,failed,signal,limits}){
 need(signal instanceof AbortSignal&&typeof receive==='function'&&typeof failed==='function','worker_session_configuration');
 const {ipc_session_id,...source}=identity??{},bound=executionSessionIdentity(source);
 const domain=freeze(structuredClone(descriptor));
 need(domain?.clock_domain_id===bound.clock_domain_id&&domain.descriptor_digest===bound.descriptor_digest,'worker_session_domain');
 need(ipc_session_id===bound.ipc_session_id&&devices instanceof Map&&devices.size>0&&devices.size<=256,'worker_session_identity');
 const owners=new Map(devices);
 for(const [id,owner] of owners)need(typeof id==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$(?![\s\S])/.test(id)&&typeof owner?.terminate==='function'&&typeof owner.closeScope==='function','worker_session_devices');
 const ranges={max_frames:4096,max_history_bytes:67108864,max_queue_entries:64,max_queue_bytes:16777216,write_timeout_ms:60000};
 need(limits&&Object.keys(limits).sort().join(',')===Object.keys(ranges).sort().join(','),'worker_session_limits');
 for(const [key,max] of Object.entries(ranges))need(Number.isSafeInteger(limits[key])&&limits[key]>0&&limits[key]<=max,'worker_session_limits');
 const budget={...limits},input=new Map(),output=new Map(),queue=[],closes=new Map();
 let transport,phase='new',incoming=0n,outgoing=0n,historyBytes=0,queueBytes=0,pumping=false,writing=null,helloId=null,emergency=null,selectedFeatures=null;
 function fail(error=new DeviceExecutionError('worker_session_closed')){
  if(phase==='closed')return;phase='closed';for(const owner of owners.values())try{owner.terminate();}catch{}
  for(const item of queue.splice(0)){queueBytes-=item.size;item.reject(error);}transport?.close(error);try{failed(error);}catch{}
 }
 signal.addEventListener('abort',()=>fail(),{once:true});
 function available(){need(phase!=='closed'&&!signal.aborted,'worker_session_closed');}
 function envelope(candidate,seq,journal_mode='durable',message_id=crypto.randomUUID()){
  return {ipc_version:deviceExecutionVersion,type:candidate.type,message_id,reply_to:candidate.reply_to,
   ipc_session_id:bound.ipc_session_id,controller_boot_id:bound.controller_boot_id,worker_boot_id:bound.worker_boot_id,
   seq,device_id:candidate.device_id,body:candidate.body,clock_domain_id:bound.clock_domain_id,descriptor_digest:bound.descriptor_digest,journal_mode};
 }
 function binding(frame){
  for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[key]===bound[key],'worker_session_binding');
  need(frame.device_id===null||owners.has(frame.device_id),'worker_session_device');
 }
 function reply(frame,opposite){const allowed=types.get(frame.type).reply_to_types;
  if(allowed.length===0){need(frame.reply_to===null,'worker_session_reply');return;}
  const original=opposite.get(frame.reply_to);need(original&&allowed.includes(original.frame.type),'worker_session_reply');
  if(frame.type==='CLOSE_GATE_ACK')return; // controller范围ACK的device_id固定为null。
  need(frame.device_id===original.frame.device_id,'worker_session_reply_device');
 }
 function reserve(payload){const bytes=payload.length*3+4096;
  need(input.size+output.size<budget.max_frames&&historyBytes+bytes<=budget.max_history_bytes,'worker_session_history_capacity');historyBytes+=bytes;}
 function logical(candidate){need(candidate&&Object.keys(candidate).sort().join(',')==='body,device_id,reply_to,type','worker_session_candidate');
  const copy=freeze(structuredClone(candidate));need(types.get(copy.type)?.direction==='w2c','worker_session_direction');
  need(copy.device_id===null||owners.has(copy.device_id),'worker_session_device');return copy;}
 function enqueue(item,urgent=false){available();
  if(!urgent)need(queue.length<budget.max_queue_entries&&queueBytes+item.size<=budget.max_queue_bytes,'worker_session_queue_capacity');
  const result=new Promise((resolve,reject)=>{item.resolve=resolve;item.reject=reject;});result.catch(()=>{});
  item.urgent=urgent;if(urgent)queue.unshift(item);else queue.push(item);queueBytes+=item.size;void pump();return result;}
 function discardNormal(){for(let i=queue.length-1;i>=0;i--)if(!queue[i].urgent){const [item]=queue.splice(i,1);queueBytes-=item.size;item.reject(new DeviceExecutionError('worker_session_terminal'));}}
 async function transmit(record,item){
  writing=record;let timer;
  try{
   timer=setTimeout(()=>fail(new DeviceExecutionError('worker_session_write_timeout')),budget.write_timeout_ms);
   const result=await transport.send(record.payload,{beforeWrite(){available();
    if(!item.urgent&&phase==='terminal')return false;
    need(!item.urgent||phase==='terminal','worker_session_terminal');
    const checked=item.check?.();need(!checked||typeof checked.then!=='function','worker_session_check_async');record.started=true;
   }});
   if(result.not_started){need(phase==='terminal'&&!record.started,'worker_session_cancelled_write');throw new DeviceExecutionError('worker_session_terminal_before_write');}
   record.complete=true;
  }finally{clearTimeout(timer);writing=null;}
 }
 async function pump(){
  if(pumping)return;pumping=true;
  try{while(queue.length&&phase!=='closed'){
   const item=queue.shift();queueBytes-=item.size;
   try{
    available();let record=item.record;
    if(!record){
     need(phase!=='terminal'&&outgoing<maximum,'worker_session_sequence');
     const check=item.check?.();need(!check||typeof check.then!=='function','worker_session_check_async');
     const frame=envelope(item.candidate,String(outgoing+1n)),payload=Buffer.from(JSON.stringify(frame));
     await decodeExecutionPayload(payload,'w2c');available();
     if(frame.type!=='HELLO')assertDeviceExecutionFeatures(frame,selectedFeatures);
     if(frame.type==='HELLO')need(frame.body.clock_domain_id===bound.clock_domain_id&&frame.body.descriptor_digest===bound.descriptor_digest&&
      canonicalize(frame.body.clock_domain_descriptor)===canonicalize(domain),'worker_session_domain');
     // 尚未登记时可因紧急关闭丢弃；登记后失败由fail永久结束，不能跳号。
     if(phase==='terminal'){item.reject(new DeviceExecutionError('worker_session_terminal'));continue;}
     binding(frame);reply(frame,input);need(!output.has(frame.message_id),'worker_session_message_conflict');reserve(payload);outgoing++;
     record={frame:freeze(frame),payload:Buffer.from(payload),started:false,complete:false,replayQueued:false};output.set(frame.message_id,record);
     if(frame.type==='HELLO')helloId=frame.message_id;
     if(frame.reply_to!==null)input.get(frame.reply_to).responses.push(record);
    }else if(!item.urgent)need(record.complete,'worker_session_replay_incomplete');
    await transmit(record,item);record.replayQueued=false;item.resolve(record.frame);
   }catch(error){item.reject(error);if(!(phase==='terminal'&&error.code==='worker_session_terminal_before_write'))fail(error);}
  }}finally{pumping=false;}
 }
 function replay(record,urgent=false){if(record.replayQueued||writing===record||!record.complete)return;
  record.replayQueued=true;try{void enqueue({record,size:record.payload.length,check:null},urgent);}catch(error){fail(error);}}
 function normalClose(frame){
  const body=frame.body,prior=closes.get(body.close_id);let ack;
  if(prior){need(prior.device_id===frame.device_id&&canonicalize(prior.body)===canonicalize(body),'worker_session_close_conflict');ack=prior.ack;}
  else{
   const selected=body.scope==='controller'?[...owners.keys()].sort():[frame.device_id];
   need((body.scope==='controller'&&frame.device_id===null)||(body.scope==='device'&&owners.has(frame.device_id)),'worker_session_close_scope');
   for(const id of selected){const result=owners.get(id).closeScope(frame);
    need(result?.type==='CLOSE_GATE_ACK'&&result.reply_to===frame.message_id&&result.body.close_id===body.close_id&&
     canonicalize(result.body.closed_device_ids)===canonicalize([id]),'worker_session_close_result');}
   ack=freeze({close_id:body.close_id,closed_device_ids:selected});closes.set(body.close_id,freeze({device_id:frame.device_id,body:structuredClone(body),ack}));
  }
  // 关闭已经同步覆盖全部目标；ACK仍经唯一队列，不阻塞后续关闭接收或冒称持久提交。
  const candidate=logical({type:'CLOSE_GATE_ACK',reply_to:frame.message_id,device_id:null,body:ack});
  void enqueue({candidate,size:Buffer.byteLength(JSON.stringify(candidate))+2048,check:null});
 }
 async function terminalClose(decoded){
  const {frame,payload}=decoded;need(frame.type==='CLOSE_GATE'&&frame.body.scope==='controller'&&frame.seq===null&&frame.device_id===null,'worker_session_terminal_frame');
  if(emergency){need(emergency.payload.equals(payload),'worker_session_terminal_conflict');replay(emergency.response,true);return;}
  need(!input.has(frame.message_id),'worker_session_message_conflict');
  // 预留容量独立于正常队列/历史；所有设备真实close调用完成后才能构造ACK。
  phase='terminal';discardNormal();for(const owner of owners.values()){
   const closed=owner.terminate();need(!closed||typeof closed.then!=='function','worker_session_close_async');}
  const ack=envelope({type:'CLOSE_GATE_ACK',reply_to:frame.message_id,device_id:null,body:{close_id:frame.body.close_id,closed_device_ids:[...owners.keys()].sort()}},null,'volatile_close');
  const bytes=Buffer.from(JSON.stringify(ack));need(payload.length+bytes.length<=524288,'worker_session_protection_capacity');
  await decodeExecutionPayload(bytes,'w2c');available();
  const response={frame:freeze(ack),payload:bytes,started:false,complete:false,replayQueued:false};emergency={payload:Buffer.from(payload),response};
  // 等待正在写的完整帧边界；send的超时/部分写会断流，绝不另开通道。
  void enqueue({record:response,size:bytes.length,check:null},true);
 }
 transport=executionTransport(socket,{incoming:'c2w',failed:fail,async receive(decoded){
  available();const {frame,payload}=decoded;binding(frame);
  if(frame.journal_mode==='volatile_close'){need(phase!=='new','worker_session_handshake');await terminalClose(decoded);return;}
  need(phase!=='terminal','worker_session_terminal');
  const prior=input.get(frame.message_id);
  if(prior){need(prior.payload.equals(payload),'worker_session_message_conflict');for(const response of prior.responses)replay(response);return;}
  need(BigInt(frame.seq)===incoming+1n,'worker_session_sequence');reply(frame,output);
  if(incoming===0n){need(phase==='hello'&&frame.type==='HELLO_ACK'&&frame.reply_to===helloId&&output.get(helloId)?.started,'worker_session_handshake');
   const offered=output.get(helloId).frame.body;
   need(offered.supported_ipc_versions.includes(frame.body.selected_ipc_version)&&frame.body.selected_features.every(value=>offered.supported_features.includes(value)), 'worker_session_features');
   need(frame.body.clock_domain_id===bound.clock_domain_id&&frame.body.descriptor_digest===bound.descriptor_digest&&
    canonicalize(frame.body.clock_domain_descriptor)===canonicalize(domain),'worker_session_domain');
   selectedFeatures=validateDeviceExecutionFeatures(frame.body.selected_features);}
  else {need(phase==='ready','worker_session_handshake');assertDeviceExecutionFeatures(frame,selectedFeatures);}
  reserve(payload);const record={frame,payload:Buffer.from(payload),responses:[]};input.set(frame.message_id,record);incoming++;
  if(frame.type==='CLOSE_GATE')normalClose(frame);
  else await receive(Object.freeze({...decoded,payload:Buffer.from(payload),wire:executionWire(payload)}));available();
  if(incoming===1n&&frame.type==='HELLO_ACK')phase='ready';
 }});
 return Object.freeze({
  async start(body){try{available();need(phase==='new','worker_session_handshake');phase='hello';
   validateDeviceExecutionFeatures(body.supported_features);
   return await enqueue({candidate:logical({type:'HELLO',reply_to:null,device_id:null,body}),size:Buffer.byteLength(JSON.stringify(body))+2048,check:null});
  }catch(error){fail(error);throw error;}},
  send(candidate,check){try{available();need(phase!=='terminal','worker_session_terminal');need(phase==='ready','worker_session_handshake');need(check===undefined||typeof check==='function','worker_session_check');
   const copy=logical(candidate);need(copy.type!=='HELLO','worker_session_handshake');need(copy.type!=='CLOSE_GATE_ACK','worker_session_owned_response');return enqueue({candidate:copy,check,size:Buffer.byteLength(JSON.stringify(copy))+2048});
  }catch(error){if(phase!=='terminal')fail(error);throw error;}},
  close:fail,
  replaceDevice(id,owner){try{available();need(phase!=='terminal'&&owners.has(id)&&typeof owner?.terminate==='function'&&typeof owner.closeScope==='function','worker_session_devices');
   const old=owners.get(id);need(old!==owner,'worker_session_devices');old.terminate();owners.set(id,owner);
  }catch(error){fail(error);throw error;}},
  get state(){return Object.freeze({phase,incoming:String(incoming),outgoing:String(outgoing),history_bytes:historyBytes,queued:queue.length,writing:writing!==null,selected_features:selectedFeatures});}
 });
}
