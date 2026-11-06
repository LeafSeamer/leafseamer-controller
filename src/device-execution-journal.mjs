import {selectCommandGuard,commitCommandGuard,readCommandGuard,currentCommandGuard,acceptCommandGuard} from './command-guard.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeExecutionPayload,executionWire,executionSessionIdentity,DeviceExecutionError} from './device-execution-channel.mjs';
import {deviceExecutionVersion} from './sdk/device-execution.mjs';
import {contractSelection} from './sdk/index.mjs';
import {openNativeClock} from './native-clock.mjs';
import {stageRejectedExecutionFrame,sealRejectedExecutionFrame,executionFrameReceipt} from './device-execution-frames.mjs';
import {selectedHandshake,handshakeAck,commitHandshake,readHandshake,executionTick} from './device-execution-handshake.mjs';
import {prepareInitialFence,currentInitialFence,acceptInitialFenceAck} from './device-execution-control.mjs';
import {prepareInitialOpenDispatch,readInitialOpenDispatch,currentInitialOpenDispatch,acceptInitialOpenAck} from './device-execution-open.mjs';
import {commitInitialReady,currentInitialReady,protectInitialReadies} from './device-initial-ready.mjs';
import {selectCommandEncoding,commitCommandEncoding,readCommandEncoding,currentCommandEncoding,acceptCommandEncoding,selectCommandFinalization} from './command-encoding-store.mjs';
import {commitCommandFinalAdmission,observeCommandFinalAdmission,currentPreparedCommand} from './command-final-admission.mjs';
import {selectCommandDispatch,commitCommandDispatch,readCommandDispatch,startCommandDispatchWrite,acceptCommandDispatchReport,acceptCommandDispatchEvidence} from './command-dispatch.mjs';
import {protectCommandForSettlement,selectCommandClosure,commitCommandClosure,readCommandClosure,currentCommandClosure,acceptCommandClosure,commitCommandSettlement} from './command-settlement.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const hash=bytes=>'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))freeze(item);Object.freeze(value);}return value;};

export function executionJournalHistory(db,sessionId){
 need(typeof sessionId==='string'&&/^[0-9a-f-]{36}$/.test(sessionId),'execution_session_id');
 const row=db.prepare(`SELECT s.binding_jcs,s.binding_digest,e.reason,r.message_id,r.frame_digest,r.transaction_id
  FROM execution_session s LEFT JOIN execution_session_end e USING(ipc_session_id)
  LEFT JOIN execution_rejection r USING(ipc_session_id) WHERE s.ipc_session_id=?`).raw().get(sessionId);
 if(!row)return null;const binding=JSON.parse(row[0]);need(canonicalize(binding)===row[0]&&hash(row[0])===row[1],'execution_history_integrity');
 const receipt=row[3]!==null&&Number(db.pragma('user_version',{simple:true}))>=28?executionFrameReceipt(db,sessionId,row[3]):null;
 const negotiation=Number(db.pragma('user_version',{simple:true}))>=30?readHandshake(db,sessionId)?.receipt??null:null;
 return freeze({binding,ended:row[2]!==null,end_reason:row[2],negotiation,rejection:row[3]===null?null:
  {message_id:row[3],frame_digest:row[4],transaction_id:row[5],disposition:'rejected',reason:'unsupported_message',...(receipt?{journal:receipt}:{})}});
}

// 成功握手与明确拒收分别有专属领域写集，其它消息不得借此产生成功提交。
// 工厂只由核心writer装配，不接受HTTP提供的身份、数据库或领域回调。
export function deviceExecutionJournal({db,current,currentInTransaction,core,isOpen,invalidate,openingSource,encodingSource}){
 const framed=Number(db.pragma('user_version',{simple:true}))>=28;
 let binding=null,terminal=false,busy=false,clock=null,lastTick=null;const readyRequests=new Set();
 function tick(){clock??=openNativeClock();const value=clock.tick();need(lastTick===null||value>=lastTick,'execution_frame_clock');lastTick=value;return value;}
 const available=()=>{need(isOpen()&&db.open,'execution_storage_closed');need(!db.inTransaction,'execution_outer_transaction');};
 function live(){
  available();need(binding&&!terminal,'execution_session_ended');
  const active=current();need(active.current_boot&&!active.withdrawal&&active.ref.object_id===binding.runtime_binding_id,'execution_runtime');
  need(!db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(binding.ipc_session_id),'execution_session_ended');
  return active;
 }
 function end(reason){
  terminal=true;if(!binding)return;
  need(db.open&&!db.inTransaction,'execution_storage_closed');
  db.transaction(()=>{
   protectInitialReadies(db,binding,tick);
   if(!db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(binding.ipc_session_id))
    db.prepare('INSERT INTO execution_session_end VALUES(?,?,?)').run(binding.ipc_session_id,crypto.randomUUID(),reason);
  }).immediate();
 }
 function fail(error){
  // 先锁存本地终止；数据库不可写不能保持旧会话可用，也不能触发重发。
  terminal=true;try{end(error?.code?.startsWith('SQLITE_')?'storage_failed':'protocol_error');}catch{}
  try{invalidate();}catch{}
 }
 function rejection(){
  available();need(binding,'execution_session_missing');
  const row=db.prepare('SELECT message_id,frame_digest,transaction_id FROM execution_rejection WHERE ipc_session_id=?').raw().get(binding.ipc_session_id);
  if(!row)return null;const receipt=framed?executionFrameReceipt(db,binding.ipc_session_id,row[0]):null;
  return Object.freeze({ipc_session_id:binding.ipc_session_id,message_id:row[0],frame_digest:row[1],transaction_id:row[2],disposition:'rejected',reason:'unsupported_message',...(receipt?{journal:receipt}:{})});
 }
 function checkHello(frame){
  need(frame.type==='HELLO'&&frame.seq==='1'&&frame.reply_to===null&&frame.device_id===null&&frame.journal_mode==='durable','execution_handshake_required');
  for(const name of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[name]===binding[name],'execution_frame_binding');
  const active=current();need(frame.body.clock_domain_id===binding.clock_domain_id&&frame.body.descriptor_digest===binding.descriptor_digest&&
   canonicalize(frame.body.clock_domain_descriptor)===canonicalize(active.binding.clock_domain_descriptor),'execution_hello_binding');return active;
 }
 const api={
  open(){
   available();need(!binding&&!terminal,'execution_session_reuse');
   try{
    const active=current(),parent=core(),runtime=active.binding,descriptor=runtime.clock_domain_descriptor;
    need(active.current_boot&&!active.withdrawal&&runtime.gate_state==='closed','execution_runtime');
    need(parent.descriptor.clock_domain_id===descriptor.clock_domain_id&&parent.descriptor.descriptor_digest===descriptor.descriptor_digest,'execution_domain');
    const identity=executionSessionIdentity({authority_service_id:runtime.service_id,database_instance_id:runtime.database_instance_id,
     controller_boot_id:parent.receipt.member_boot_id,worker_boot_id:runtime.admission_receipt.member_boot_id,clock_domain_id:descriptor.clock_domain_id,descriptor_digest:descriptor.descriptor_digest});
    const value={authority:'controller',service_id:runtime.service_id,database_instance_id:runtime.database_instance_id,
     ipc_version:deviceExecutionVersion,contract_selection:contractSelection,ipc_session_id:identity.ipc_session_id,runtime_binding_id:active.ref.object_id,service_boot_id:runtime.service_boot_id,
     controller_boot_id:parent.receipt.member_boot_id,worker_boot_id:runtime.admission_receipt.member_boot_id,
     clock_domain_id:descriptor.clock_domain_id,descriptor_digest:descriptor.descriptor_digest,device_ids:runtime.launch_intent.object_scope.device_ids};
    const transaction=crypto.randomUUID(),body=canonicalize(value);
    db.transaction(()=>{
     db.prepare('INSERT INTO execution_session VALUES(?,?,?,?,?,?,?,?,?,?)').run(value.ipc_session_id,value.runtime_binding_id,value.service_boot_id,
      value.controller_boot_id,value.worker_boot_id,value.clock_domain_id,value.descriptor_digest,body,hash(body),transaction);
     db.prepare('INSERT INTO execution_session_commit VALUES(?,?,?)').run(transaction,value.ipc_session_id,canonicalize({kind:'execution_session_created',binding_digest:hash(body)}));
    }).immediate();
    binding=freeze(structuredClone(value));return binding;
   }catch(error){fail(error);throw error;}
  },
  async negotiate(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{
    live();need(Number(db.pragma('user_version',{simple:true}))>=30,'execution_handshake_migration');
    const {frame,payload}=await decodeExecutionPayload(bytes,'w2c');live();const active=checkHello(frame);
    const old=readHandshake(db,binding.ipc_session_id);if(old){need(old.hello.wire.equals(executionWire(payload)),'execution_replay_conflict');return old.receipt;}
    const selected=selectedHandshake(db,active.binding,frame),ack=handshakeAck(binding,frame,selected);
    await decodeExecutionPayload(Buffer.from(JSON.stringify(ack)),'c2w');live();checkHello(frame);
    db.transaction(()=>{const now=tick();commitHandshake(db,{binding,hello:frame,payload,ack,observedTick:now,committedTick:tick()});}).immediate();
    return readHandshake(db,binding.ipc_session_id).receipt;
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  beginHandshakeWrite(){
   try{live();const stored=readHandshake(db,binding.ipc_session_id);need(stored,'execution_handshake_missing');
    const id=crypto.randomUUID();db.transaction(()=>{
     need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(id,stored.receipt.ack_record_ref.id,executionTick(tick())).changes===1,'execution_handshake_storage');
    }).immediate();
    // 只有可靠提交后才把精确出站字节交给唯一发送器；不从调用者正文重新编码。
    return Object.freeze({attempt_id:id,payload:Buffer.from(stored.ack.wire.subarray(4))});
   }catch(error){fail(error);throw error;}
  },
  finishHandshakeWrite(attemptId,result){
   try{available();need(binding&&['complete','unknown'].includes(result),'execution_write_result');
    const row=db.prepare(`SELECT a.attempt_id FROM execution_write_attempt a JOIN execution_frame_record f USING(record_id)
     WHERE a.attempt_id=? AND f.ipc_session_id=?`).raw().get(attemptId,binding.ipc_session_id);need(row,'execution_write_result');
    if(result==='complete')try{live();}catch{result='unknown';}
    db.transaction(()=>{need(db.prepare('INSERT INTO execution_write_result VALUES(?,?,?)').run(attemptId,result,executionTick(tick())).changes===1,'execution_handshake_storage');}).immediate();
    if(result==='unknown')fail(new DeviceExecutionError('execution_write_unknown'));return Object.freeze({attempt_id:attemptId,result});
   }catch(error){fail(error);throw error;}
  },
  async sendHandshake(transport){
   let write=null,finished=false;
   try{need(typeof transport?.send==='function','execution_write_transport');write=api.beginHandshakeWrite();
    const sent=await transport.send(write.payload,{beforeWrite(){live();}});
    need(sent?.not_started!==true&&sent?.wire_length===write.payload.length+4,'execution_write_unknown');
    const result=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;
    need(result.result==='complete','execution_write_unknown');return result;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}
    fail(error);throw error;}
  },
  prepareInitialFence(device){
   try{live();need(Number(db.pragma('user_version',{simple:true}))>=31&&typeof currentInTransaction==='function','execution_control_migration');
    const negotiation=readHandshake(db,binding.ipc_session_id);need(negotiation,'execution_handshake_missing');
    const result=db.transaction(()=>prepareInitialFence(db,{binding,runtime:currentInTransaction(),device,features:negotiation.receipt.selected_features,tick})).immediate();
    return freeze({fence_id:result.value.fence_id,request_message_id:result.request.frame.message_id,ref:result.ref,confirmation:result.confirmation,confirmation_ref:result.confirmation_ref});
   }catch(error){fail(error);throw error;}
  },
  async receiveInitialFenceAck(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{live();const decoded=await decodeExecutionPayload(bytes,'w2c');live();
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const result=db.transaction(()=>acceptInitialFenceAck(db,{binding,runtime:currentInTransaction(),decoded,features,tick})).immediate();
    return freeze({fence_id:result.value.fence_id,ref:result.ref,confirmation:result.confirmation,confirmation_ref:result.confirmation_ref});
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  async sendInitialFence(transport,id){
   let write=null,finished=false;
   const check=()=>db.transaction(()=>currentInitialFence(db,{binding,runtime:currentInTransaction(),id})).immediate();
   try{live();const stored=check();await decodeExecutionPayload(stored.request.wire.subarray(4),'c2w');live();
    write=db.transaction(()=>{const actual=currentInitialFence(db,{binding,runtime:currentInTransaction(),id}),attempt=crypto.randomUUID();
     need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,actual.request.record.record_id,executionTick(tick())).changes===1,'execution_control_storage');
     return {attempt_id:attempt,payload:actual.request.wire.subarray(4)};
    }).immediate();
    const result=await transport.send(write.payload,{beforeWrite(){live();check();}});
    need(result?.not_started!==true&&result?.wire_length===write.payload.length+4,'execution_write_unknown');
    const committed=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(committed.result==='complete','execution_write_unknown');return committed;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  prepareInitialOpen(reference,{ready=false}={}){
   try{live();const provider=openingSource?.();need(Number(db.pragma('user_version',{simple:true}))>=47&&provider,'execution_open_migration');
    need(typeof ready==='boolean'&&(!ready||Number(db.pragma('user_version',{simple:true}))>=48),'execution_ready_migration');
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const saved=db.transaction(()=>{
     const runtime=currentInTransaction(),id=ready&&db.prepare('SELECT ready_id FROM device_initial_ready WHERE opening_id=?').pluck().get(reference?.id);
     if(id){const current=currentInitialReady(db,{binding,runtime,id,provider,tick});need(canonicalize(current.value.opening_ref)===canonicalize(reference),'execution_open_reference');return current.dispatch;}
     return prepareInitialOpenDispatch(db,{binding,runtime,reference,features,tick,provider});
    }).immediate();
    if(ready)readyRequests.add(reference.id);
    return freeze({opening_id:reference.id,request_message_id:saved.request.frame.message_id,ref:saved.ref,confirmation:saved.confirmation,confirmation_ref:saved.confirmation_ref});
   }catch(error){fail(error);throw error;}
  },
  async receiveInitialOpenAck(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{live();const decoded=await decodeExecutionPayload(bytes,'w2c');live();const provider=openingSource?.();need(provider,'execution_open_migration');
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const result=db.transaction(()=>{
     const runtime=currentInTransaction();
     const prior=Number(db.pragma('user_version',{simple:true}))>=48?db.prepare(`SELECT r.ready_id FROM device_initial_ready r
      JOIN execution_initial_open_dispatch d USING(opening_id) JOIN execution_frame_record f ON f.record_id=d.request_record_id
      WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,decoded.frame.reply_to):null;
     if(prior){const current=currentInitialReady(db,{binding,runtime,id:prior,provider,tick}),saved=current.dispatch;
      need(saved.ack.wire.equals(executionWire(decoded.payload)),'execution_open_replay_conflict');
      return {opening_id:saved.value.opening_ref.id,ref:saved.ref,confirmation:saved.confirmation,confirmation_ref:saved.confirmation_ref,ready:{ref:current.ref,value:current.value}};}
     const saved=acceptInitialOpenAck(db,{binding,runtime,decoded,features,tick,provider});
     const ready=readyRequests.has(saved.value.opening_ref.id)?commitInitialReady(db,{binding,runtime,id:saved.value.opening_ref.id,provider,tick,validatedDispatch:saved}):null;
     return {opening_id:saved.value.opening_ref.id,ref:saved.ref,confirmation:saved.confirmation,confirmation_ref:saved.confirmation_ref,
      ...(ready?{ready:{ref:ready.ref,value:ready.value}}:{})};
    }).immediate();return freeze(result);
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  async sendInitialOpen(transport,id){
   let write=null,finished=false;
   try{live();const stored=db.transaction(()=>readInitialOpenDispatch(db,id)).immediate();
    need(stored,'execution_open_missing');const payload=stored.request.wire.subarray(4);await decodeExecutionPayload(payload,'c2w');
    // 排队和解码均不产生发送资格。在唯一发送器实际写入前，同步核验并持久登记本次尝试。
    const result=await transport.send(payload,{beforeWrite(){live();
     need(!write,'execution_open_write_reuse');
     write=db.transaction(()=>{const actual=currentInitialOpenDispatch(db,{binding,runtime:currentInTransaction(),id,provider:openingSource?.()}),attempt=crypto.randomUUID();
      need(actual.request.wire.equals(stored.request.wire),'execution_open_changed');
      need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,actual.request.record.record_id,executionTick(tick())).changes===1,'execution_open_storage');
      return {attempt_id:attempt};
     }).immediate();
     need(tick()<BigInt(stored.request.frame.body.lease_until_tick_ns),'execution_open_expired');
    }});
    need(write&&result?.not_started!==true&&result?.wire_length===payload.length+4,'execution_write_unknown');
    const committed=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(committed.result==='complete','execution_write_unknown');return committed;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  async prepareCommandEncoding(id){
   try{live();const provider=encodingSource?.();need(provider&&Number(db.pragma('user_version',{simple:true}))>=51,'execution_encoding_migration');
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const candidate=db.transaction(()=>selectCommandEncoding(db,{binding,id,provider,features})).immediate();
    if(candidate.saved)return {...candidate.saved,replay:true};
    await decodeExecutionPayload(Buffer.from(JSON.stringify(candidate.frame)),'c2w');live();
    return {...db.transaction(()=>commitCommandEncoding(db,{binding,candidate,provider,tick})).immediate(),replay:false};
   }catch(error){fail(error);throw error;}
  },
  async sendCommandEncoding(transport,id){
   let write=null,finished=false;
   try{live();const saved=db.transaction(()=>readCommandEncoding(db,id)).immediate(),payload=saved.request.wire.subarray(4);
    await decodeExecutionPayload(payload,'c2w');live();
    const sent=await transport.send(payload,{beforeWrite(){live();need(!write,'execution_encoding_write_reuse');
     write=db.transaction(()=>{const current=currentCommandEncoding(db,{id,provider:encodingSource?.()}),attempt=crypto.randomUUID();
      need(current.request.wire.equals(saved.request.wire),'execution_encoding_changed');
      need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,current.request.record.record_id,executionTick(tick())).changes===1,'execution_encoding_storage');
      return {attempt_id:attempt};
     }).immediate();need(tick()<BigInt(saved.value.authorization.expires_tick_ns),'execution_encoding_expired');
    }});
    need(write&&sent?.not_started!==true&&sent?.wire_length===payload.length+4,'execution_write_unknown');
    const result=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(result.result==='complete','execution_write_unknown');return result;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  async receiveCommandEncoding(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{live();const receivedTick=tick(),decoded=await decodeExecutionPayload(bytes,'w2c');live();
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    return db.transaction(()=>acceptCommandEncoding(db,{binding,decoded,provider:encodingSource?.(),features,tick,receivedTick})).immediate();
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  commandFinalizationInputs(id){
   try{live();return db.transaction(()=>{
    const selected=selectCommandFinalization(db,{id,provider:encodingSource?.(),tick}),e=selected.encoding,r=e.response;
    need(e.value.authorization.binding.ipc_session_id===binding.ipc_session_id,'execution_finalization_binding');
    // 仅供核心检查已读取的输入；没有hold、issue、Seal或Guard，不能交给设备发送器。
    return freeze({command_id:e.value.command_id,prepare_id:id,command_state_ref:selected.actual.command.record.state_ref,
     encoding_ref:e.ref,encoding_response_ref:r.ref,encoding_evidence_ref:{id:r.value.evidence.evidence_id,revision:'1',digest:r.value.evidence.evidence_digest},
     packet_ref:r.value.evidence.packet_ref,bytes_digest:r.value.evidence.bytes_digest,byte_length:r.bytes.length,
     binding_ref:selected.actual.execution.ref,ready_ref:selected.ready.ref,principal_authorization_ref:selected.principal_authorization.ref,
     authorization_binding:selected.principal_authorization.binding,selected_tick_ns:selected.selected_tick_ns,send_window:selected.send_window});
   }).immediate();}catch(error){fail(error);throw error;}
  },
  commandFinalAdmission(id){
   try{live();const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const result=db.transaction(()=>commitCommandFinalAdmission(db,{id,provider:encodingSource?.(),tick,features})).immediate();
    // 该观察发生在T2可靠返回之后；它仍不授予重发或跳过当前资格检查的权利。
    const observation=db.transaction(()=>observeCommandFinalAdmission(db,{commandId:result.saved.source.command_id,binding,tick})).immediate();
    return freeze({...result,observation});
   }catch(error){fail(error);throw error;}
  },
  async prepareCommandGuard(id){
   try{live();const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const candidate=db.transaction(()=>selectCommandGuard(db,{id,binding,provider:encodingSource?.(),tick,features})).immediate();
    if(candidate.saved)return {...candidate.saved,replay:true};
    await decodeExecutionPayload(Buffer.from(JSON.stringify(candidate.frame)),'c2w');live();
    return {...db.transaction(()=>commitCommandGuard(db,{candidate,binding,provider:encodingSource?.(),tick})).immediate(),replay:false};
   }catch(error){fail(error);throw error;}
  },
  async sendCommandGuard(transport,id){
   let write=null,finished=false;
   try{live();const saved=db.transaction(()=>readCommandGuard(db,id)).immediate(),payload=saved.request.wire.subarray(4);
    await decodeExecutionPayload(payload,'c2w');live();
    const sent=await transport.send(payload,{beforeWrite(){live();need(!write,'execution_guard_write_reuse');
     write=db.transaction(()=>{const actual=currentCommandGuard(db,{id,binding,provider:encodingSource?.(),tick}),attempt=crypto.randomUUID();
      need(actual.request.wire.equals(saved.request.wire),'execution_guard_changed');
      need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,actual.request.record.record_id,executionTick(tick())).changes===1,'execution_guard_storage');
      return {attempt_id:attempt};
     }).immediate();need(tick()<BigInt(saved.final.value.seal.send_window.before_tick_ns),'execution_guard_expired');
    }});
    need(write&&sent?.not_started!==true&&sent?.wire_length===payload.length+4,'execution_write_unknown');
    const result=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(result.result==='complete','execution_write_unknown');return result;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  async receiveCommandGuard(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{live();const receivedTick=tick(),decoded=await decodeExecutionPayload(bytes,'w2c');live();
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    return db.transaction(()=>acceptCommandGuard(db,{binding,decoded,provider:encodingSource?.(),tick,features,receivedTick})).immediate();
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  commandGuardHistory(id){
   available();const saved=db.transaction(()=>readCommandGuard(db,id)).immediate();
   need(saved.request.frame.ipc_session_id===binding.ipc_session_id&&saved.ack,'execution_guard_history');
   return freeze({value:saved.value,ref:saved.ref,qualification:null,ack:{value:saved.ack.value,ref:saved.ack.ref,reply:{frame:saved.ack.reply.frame}}});
  },
  async prepareCommandDispatch(id){
   try{live();const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const candidate=db.transaction(()=>selectCommandDispatch(db,{id,binding,provider:encodingSource?.(),tick,features})).immediate();
    if(candidate.saved)return {...candidate.saved,replay:true};
    await decodeExecutionPayload(Buffer.from(JSON.stringify(candidate.frame)),'c2w');live();
    return {...db.transaction(()=>commitCommandDispatch(db,{candidate,binding,provider:encodingSource?.(),tick})).immediate(),replay:false};
   }catch(error){fail(error);throw error;}
  },
  async sendCommandDispatch(transport,id){
   let write=null,finished=false;
   try{live();const saved=db.transaction(()=>readCommandDispatch(db,id)).immediate(),payload=saved.request.wire.subarray(4);
    await decodeExecutionPayload(payload,'c2w');live();
    const sent=await transport.send(payload,{beforeWrite(){live();need(!write,'execution_dispatch_write_reuse');
     write=db.transaction(()=>startCommandDispatchWrite(db,{id,binding,provider:encodingSource?.(),tick})).immediate();
     need(write.payload.equals(payload),'execution_dispatch_changed');need(tick()<BigInt(saved.final.value.seal.send_window.before_tick_ns),'execution_dispatch_expired');
    }});
    need(write&&sent?.not_started!==true&&sent?.wire_length===payload.length+4,'execution_write_unknown');
    const result=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(result.result==='complete','execution_write_unknown');return result;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  async receiveCommandDispatch(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{available();need(binding&&!terminal,'execution_session_ended');const receivedTick=tick(),decoded=await decodeExecutionPayload(bytes,'w2c');available();
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    need(['SEND_REPORT','EVIDENCE_CANDIDATE'].includes(decoded.frame.type),'execution_dispatch_report');
    const accept=decoded.frame.type==='SEND_REPORT'?acceptCommandDispatchReport:acceptCommandDispatchEvidence;
    const saved=db.transaction(()=>accept(db,{binding,decoded,features,tick,receivedTick})).immediate();return api.commandDispatchHistory(saved.value.permit_id);
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  commandDispatchHistory(id){
   available();const saved=db.transaction(()=>readCommandDispatch(db,id)).immediate();need(saved.request.frame.ipc_session_id===binding.ipc_session_id,'execution_dispatch_history');
   return freeze({value:saved.value,ref:saved.ref,write:saved.write,qualification:null,
    report:saved.report?{value:saved.report.value,ref:saved.report.ref,frame:saved.report.reply.frame}:null,
    evidence:saved.evidence?{value:saved.evidence.value,ref:saved.evidence.ref,frame:saved.evidence.reply.frame}:null});
  },
  protectCommandForSettlement(id){
   try{live();return db.transaction(()=>{const permit=db.prepare('SELECT permit_id FROM command_final_admission WHERE command_id=?').pluck().get(id);
    need(permit,'execution_closure_source');return {...protectCommandForSettlement(db,{id:permit,binding,runtime:currentInTransaction(),tick}),permit_id:permit};}).immediate();}
   catch(error){fail(error);throw error;}
  },
  async prepareCommandClosure(id){
   try{live();const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const candidate=db.transaction(()=>selectCommandClosure(db,{id,binding,runtime:currentInTransaction(),features})).immediate();
    if(candidate.saved)return {...candidate.saved,replay:true};
    await decodeExecutionPayload(Buffer.from(JSON.stringify(candidate.frame)),'c2w');live();
    return {...db.transaction(()=>commitCommandClosure(db,{candidate,binding,runtime:currentInTransaction(),tick})).immediate(),replay:false};
   }catch(error){fail(error);throw error;}
  },
  async sendCommandClosure(transport,id){
   let write=null,finished=false;
   try{live();const saved=db.transaction(()=>readCommandClosure(db,id)).immediate(),payload=saved.request.wire.subarray(4);
    await decodeExecutionPayload(payload,'c2w');live();
    const sent=await transport.send(payload,{beforeWrite(){live();need(!write,'execution_closure_write_reuse');
     write=db.transaction(()=>{const actual=currentCommandClosure(db,{id,binding,runtime:currentInTransaction()}),attempt=crypto.randomUUID();
      need(actual.request.wire.equals(saved.request.wire),'execution_closure_changed');
      need(db.prepare('INSERT INTO execution_write_attempt VALUES(?,?,?)').run(attempt,actual.request.record.record_id,executionTick(tick())).changes===1,'execution_closure_storage');
      return {attempt_id:attempt};
     }).immediate();
    }});
    need(write&&sent?.not_started!==true&&sent?.wire_length===payload.length+4,'execution_write_unknown');
    const result=api.finishHandshakeWrite(write.attempt_id,'complete');finished=true;need(result.result==='complete','execution_write_unknown');return result;
   }catch(error){if(write&&!finished)try{api.finishHandshakeWrite(write.attempt_id,'unknown');}catch{}fail(error);throw error;}
  },
  async receiveCommandClosure(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{live();const receivedTick=tick(),decoded=await decodeExecutionPayload(bytes,'w2c');live();
    const features=readHandshake(db,binding.ipc_session_id)?.receipt.selected_features;
    const saved=db.transaction(()=>acceptCommandClosure(db,{binding,decoded,features,tick,receivedTick})).immediate();return api.commandClosureHistory(saved.value.permit_id);
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  commandClosureHistory(id){
   available();const saved=db.transaction(()=>readCommandClosure(db,id)).immediate();need(saved.request.frame.ipc_session_id===binding.ipc_session_id,'execution_closure_history');
   return freeze({value:saved.value,ref:saved.ref,qualification:null,request:{frame:saved.request.frame},
    ack:saved.ack?{value:saved.ack.value,ref:saved.ack.ref,frame:saved.ack.reply.frame}:null});
  },
  settleCommand(id){
   try{available();const saved=db.transaction(()=>commitCommandSettlement(db,{id})).immediate();
    return freeze({record:saved.record,settlement_ref:saved.lifecycle.settlement.ref});
   }catch(error){fail(error);throw error;}
  },
  currentCommandGuard(id){
   try{live();const saved=db.transaction(()=>currentCommandGuard(db,{id,binding,provider:encodingSource?.(),tick,requireAck:true})).immediate();
    return freeze({value:saved.value,ref:saved.ref,qualification:saved.qualification,ack:{value:saved.ack.value,ref:saved.ack.ref,reply:{frame:saved.ack.reply.frame}}});
   }catch(error){fail(error);throw error;}
  },
  currentPreparedCommand(id){
   try{live();const result=db.transaction(()=>currentPreparedCommand(db,{id,binding,provider:encodingSource?.(),tick})).immediate();
    return freeze({command_id:id,final_admission_ref:result.final.ref,resource:result.final.value.resource_after,
     permit_id:result.final.value.permit.permit_id,observation:result.observation,selected_tick_ns:result.selected_tick_ns,
     send_window:result.final.value.seal.send_window});
   }catch(error){fail(error);throw error;}
  },
  adoptInitialReady(openingId){
   try{live();const saved=db.transaction(()=>commitInitialReady(db,{binding,runtime:currentInTransaction(),id:openingId,provider:openingSource?.(),tick})).immediate();
    return freeze({ref:saved.ref,value:saved.value});
   }catch(error){fail(error);throw error;}
  },
  currentReady(id){
   try{live();const saved=db.transaction(()=>currentInitialReady(db,{binding,runtime:currentInTransaction(),id,provider:openingSource?.(),tick})).immediate();
    return freeze({ref:saved.ref,value:saved.value});
   }catch(error){fail(error);throw error;}
  },
  async rejectUnsupported(bytes){
   need(!busy,'execution_receive_busy');busy=true;
   try{
    live();const {frame,payload}=await decodeExecutionPayload(bytes,'w2c');live();
    // 未协商会话只接受首个HELLO。其他帧是协议错误，不制造连续性或业务效果。
    need(frame.type==='HELLO'&&frame.seq==='1'&&frame.reply_to===null&&frame.device_id===null&&frame.journal_mode==='durable','execution_handshake_required');
    for(const name of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[name]===binding[name],'execution_frame_binding');
    const active=current();
    need(frame.body.clock_domain_id===binding.clock_domain_id&&frame.body.descriptor_digest===binding.descriptor_digest&&
     canonicalize(frame.body.clock_domain_descriptor)===canonicalize(active.binding.clock_domain_descriptor),'execution_hello_binding');
    const text=canonicalize(frame),wire=executionWire(payload),transaction=crypto.randomUUID(),observedTick=framed?tick():null;
    db.transaction(()=>{
     const staged=framed?stageRejectedExecutionFrame(db,{binding,frame,wire,transaction,observedTick}):null;
     db.prepare('INSERT INTO execution_rejection VALUES(?,?,?,?,?,?,?,?,?)').run(binding.ipc_session_id,frame.message_id,wire,text,hash(wire),hash(text),hash(canonicalize(frame.body)),transaction,'unsupported_message');
     db.prepare('INSERT INTO execution_rejection_commit VALUES(?,?,?)').run(transaction,binding.ipc_session_id,frame.message_id);
     db.prepare('INSERT INTO execution_session_end VALUES(?,?,?)').run(binding.ipc_session_id,transaction,'unsupported_message');
     if(staged)sealRejectedExecutionFrame(db,staged,tick());
    }).immediate();terminal=true;return rejection();
   }catch(error){fail(error);throw error;}finally{busy=false;}
  },
  lookup(bytes){
   available();need(binding&&bytes instanceof Uint8Array,'execution_lookup');
   const wire=db.prepare('SELECT wire FROM execution_rejection WHERE ipc_session_id=?').pluck().get(binding.ipc_session_id);
   if(!wire)return null;need(wire.equals(executionWire(bytes)),'execution_replay_conflict');return rejection();
  },
  end(){end('closed');},
  get binding(){return binding;}
 };return Object.freeze(api);
}
