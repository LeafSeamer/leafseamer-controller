import {executionSocket,executionTransport,DeviceExecutionError} from './device-execution-channel.mjs';

// 核心内部装配。端点只取已采用成员boot，原生监督器核对两端实际PID。
// 派发写入预约与公开风险状态同事务；发送报告和观察候选分别持久化。
export async function connectDeviceExecution({journal,current,invalidate,onClose}){
 let transport,closed=false,negotiation=null,resolveReady,rejectReady,timer,poll,pending=null,encoding=false,closeFailure=null,closeReason=null;const qualifications=new Map();
 const ready=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});ready.catch(()=>{});
 function close(error=new DeviceExecutionError('execution_client_closed')){
  if(closed)return;closed=true;closeReason=error.code??'execution_client_closed';clearTimeout(timer);clearInterval(poll);for(const q of qualifications.values())clearTimeout(q.timer);qualifications.clear();transport?.close(error);
  try{journal.end();}catch(error){closeFailure={code:error.code??'execution_close_failed',message:error.message};}
  try{invalidate();}catch{}rejectReady(error);try{onClose?.();}catch{}
  if(pending){clearTimeout(pending.timer);pending.reject(error);pending=null;}
 }
 // 客户端只检查连接锁存。每个领域动作由journal在真实写入边界重核运行与授权，
 // 不在同一调用的入口和返回处重复遍历运行原件；独立监视仍持续检查运行退出。
 function check(){if(closed)throw new DeviceExecutionError('execution_client_closed');}
 function watchReady(selected){
  if(qualifications.has(selected.ref.id))return;
  const q={ref:selected.ref,device_id:selected.value.binding.device_id,command_id:null};
  const inspect=()=>{try{if(q.command_id)journal.currentPreparedCommand(q.command_id);else journal.currentReady(q.ref.id);
    if(!closed){q.timer=setTimeout(inspect,100);q.timer.unref();}}catch(error){close(error);}};
  q.timer=setTimeout(inspect,100);q.timer.unref();
  qualifications.set(selected.ref.id,q);
 }
 try{
  const active=current();
  if(active.binding.admission_receipt.member_boot_id!==journal.binding.worker_boot_id)throw new DeviceExecutionError('execution_client_runtime');
  transport=executionTransport(executionSocket(journal.binding.worker_boot_id,'core'),{incoming:'w2c',failed:close,async receive({frame,payload}){
   try{check();if(['FENCE_ACK','OPEN_GATE_ACK'].includes(frame.type)&&negotiation){
     const result=await (frame.type==='FENCE_ACK'?(pending?.closure?journal.receiveCommandClosure(payload):journal.receiveInitialFenceAck(payload)):journal.receiveInitialOpenAck(payload));check();
     if(pending){if(pending.type!==frame.type||pending.message!==frame.reply_to)throw new DeviceExecutionError('execution_control_reply');pending.resolve(result);}return;
    }
    if(['PREPARE_PACKET','PACKET_ENCODING_FAILED'].includes(frame.type)&&negotiation){
     const result=await journal.receiveCommandEncoding(payload);check();
     if(pending){if(pending.type!=='ENCODE_RESULT'||pending.message!==frame.reply_to)throw new DeviceExecutionError('execution_encoding_reply');pending.resolve(result);}return;
    }
    if(frame.type==='GUARD_ACK'&&negotiation){const result=await journal.receiveCommandGuard(payload);check();
     if(pending){if(pending.type!=='GUARD_ACK'||pending.message!==frame.reply_to)throw new DeviceExecutionError('execution_guard_reply');pending.resolve(result);}return;
    }
    if(['SEND_REPORT','EVIDENCE_CANDIDATE'].includes(frame.type)&&negotiation){const result=await journal.receiveCommandDispatch(payload);
     if(pending){if(pending.type!=='DISPATCH_RESULT'||pending.permit_id!==result.value.permit_id)throw new DeviceExecutionError('execution_dispatch_reply');
      if(result.evidence||result.report?.frame.body.socket_callback_observation_ref===null)pending.resolve(result);}return;
    }
    if(['DENY_ENCODING_ACK','RELEASE_ENCODING_ACK'].includes(frame.type)&&negotiation){const result=await journal.receiveCommandCleanup(payload);check();
     if(pending){if(pending.type!==frame.type||pending.message!==frame.reply_to)throw new DeviceExecutionError('execution_cleanup_reply');pending.resolve(result);}return;
    }
    if(frame.type!=='HELLO')throw new DeviceExecutionError('execution_client_unsupported');
    const repeated=negotiation!==null,result=await journal.negotiate(payload);check();
    if(!repeated){await journal.sendHandshake(transport);check();negotiation=result;clearTimeout(timer);resolveReady();}
   }catch(error){close(error);throw error;}
  }});
  timer=setTimeout(()=>close(new DeviceExecutionError('execution_handshake_timeout')),5000);timer.unref();
  // Ready/Prepared监视在同一调用内核验实际运行来源；有设备监视时不再重复遍历。
  // 设备资格撤回后仍由本轮询监视连接，领域写入边界始终独立复核。
  poll=setInterval(()=>{try{check();if(qualifications.size===0)current();}catch(error){close(error);}},100);poll.unref();
  await ready;check();return Object.freeze({binding:journal.binding,negotiation,close,
   async initialFence(device){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');const selected=journal.prepareInitialFence(device);
    if(selected.confirmation){const {request_message_id,...result}=selected;return result;}
    let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
    const call={type:'FENCE_ACK',message:selected.request_message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_control_timeout')),5000)};pending=call;
    try{const [,result]=await Promise.all([journal.sendInitialFence(transport,selected.fence_id),response]);check();return result;}
    catch(error){close(error);throw error;}
    finally{clearTimeout(call.timer);if(pending===call)pending=null;}
   },
   async initialOpen(reference,{ready=false}={}){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');const selected=journal.prepareInitialOpen(reference,{ready});
    if(selected.confirmation){const {request_message_id,...result}=selected;
     if(ready){result.ready=journal.adoptInitialReady(selected.opening_id);watchReady(result.ready);}return result;}
    let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
    const call={type:'OPEN_GATE_ACK',message:selected.request_message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_open_timeout')),5000)};pending=call;
    try{const [,result]=await Promise.all([journal.sendInitialOpen(transport,selected.opening_id),response]);check();if(result.ready)watchReady(result.ready);return result;}
    catch(error){close(error);throw error;}
    finally{clearTimeout(call.timer);if(pending===call)pending=null;}
   },
   async encodeCommand(id){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');encoding=true;let call;
    try{const selected=await journal.prepareCommandEncoding(id);check();
     if(selected.replay){if(!selected.response)throw new DeviceExecutionError('execution_encoding_result_unknown');return selected;}
     let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
     call={type:'ENCODE_RESULT',message:selected.request.frame.message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_encoding_timeout')),5000)};pending=call;
     const [,result]=await Promise.all([journal.sendCommandEncoding(transport,selected.value.prepare_id),response]);check();return result;
    }catch(error){close(error);throw error;}finally{if(call){clearTimeout(call.timer);if(pending===call)pending=null;}encoding=false;}
   },
   async installCommandGuard(id,{qualify=true}={}){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');encoding=true;let call;
    try{const selected=await journal.prepareCommandGuard(id);check();
     if(selected.replay){if(!selected.ack)throw new DeviceExecutionError('execution_guard_result_unknown');return journal.commandGuardHistory(selected.value.guard_id);}
     let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
     call={type:'GUARD_ACK',message:selected.request.frame.message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_guard_timeout')),5000)};pending=call;
     await Promise.all([journal.sendCommandGuard(transport,selected.value.guard_id),response]);check();
     return qualify?journal.currentCommandGuard(selected.value.guard_id):journal.commandGuardHistory(selected.value.guard_id);
    }catch(error){close(error);throw error;}finally{if(call){clearTimeout(call.timer);if(pending===call)pending=null;}encoding=false;}
   },
   async dispatchCommand(id){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');encoding=true;let call;
    try{const selected=await journal.prepareCommandDispatch(id);check();
     if(selected.replay){if(!selected.report)throw new DeviceExecutionError('execution_dispatch_result_unknown');return journal.commandDispatchHistory(selected.value.permit_id);}
     let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
     call={type:'DISPATCH_RESULT',permit_id:selected.value.permit_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_dispatch_timeout')),5000)};pending=call;
     const [,result]=await Promise.all([journal.sendCommandDispatch(transport,selected.value.permit_id),response]);return result;
    }catch(error){close(error);throw error;}finally{if(call){clearTimeout(call.timer);if(pending===call)pending=null;}encoding=false;}
   },
   async closeCommand(id){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');encoding=true;let call;
    try{const protectedReady=journal.protectCommandForSettlement(id),q=qualifications.get(protectedReady.ready_ref.id);
     id=protectedReady.permit_id;
     if(q){clearTimeout(q.timer);qualifications.delete(protectedReady.ready_ref.id);}
     const selected=await journal.prepareCommandClosure(id);check();
     if(selected.replay){if(!selected.ack)throw new DeviceExecutionError('execution_closure_result_unknown');return {...journal.commandClosureHistory(id),settlement:journal.settleCommand(id)};}
     let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
     call={type:'FENCE_ACK',closure:true,message:selected.request.frame.message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_closure_timeout')),5000)};pending=call;
     const [,result]=await Promise.all([journal.sendCommandClosure(transport,id),response]);return {...result,settlement:journal.settleCommand(id)};
    }catch(error){close(error);throw error;}finally{if(call){clearTimeout(call.timer);if(pending===call)pending=null;}encoding=false;}
   },
   async cleanupCommand(id){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');encoding=true;let call,result;
    try{for(const [phase,ack,type] of [['deny_request','deny_ack','DENY_ENCODING_ACK'],['release_request','release_ack','RELEASE_ENCODING_ACK']]){
      const selected=await journal.prepareCommandCleanup(id,phase);check();
      if(selected.replay){if(!selected.steps[ack])throw new DeviceExecutionError('execution_cleanup_result_unknown');result=selected;continue;}
      let resolve,reject;const response=new Promise((yes,no)=>{resolve=yes;reject=no;});response.catch(()=>{});
      call={type,message:selected.steps[phase].frame.message_id,resolve,reject,timer:setTimeout(()=>close(new DeviceExecutionError('execution_cleanup_timeout')),5000)};pending=call;
      [,result]=await Promise.all([journal.sendCommandCleanup(transport,selected.value.permit_id,phase),response]);check();
      clearTimeout(call.timer);if(pending===call)pending=null;call=null;
     }return result;
    }catch(error){close(error);throw error;}finally{if(call){clearTimeout(call.timer);if(pending===call)pending=null;}encoding=false;}
   },
   initialReady(openingId){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');
    try{const selected=journal.adoptInitialReady(openingId);watchReady(selected);return selected;
    }catch(error){close(error);throw error;}
   },
   commandFinalizationInputs(prepareId){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');
    try{return journal.commandFinalizationInputs(prepareId);}catch(error){close(error);throw error;}
   },
   commandFinalAdmission(prepareId){
    check();if(pending||encoding)throw new DeviceExecutionError('execution_control_busy');
    try{const result=journal.commandFinalAdmission(prepareId),q=qualifications.get(result.saved.source.ready_ref.id);
     if(!q)throw new DeviceExecutionError('execution_prepared_monitor');q.command_id=result.saved.source.command_id;return result;
    }catch(error){close(error);throw error;}
   },
   currentPreparedCommand(id){try{check();return journal.currentPreparedCommand(id);}catch(error){close(error);throw error;}},
   currentReady(reference){try{check();const selected=journal.currentReady(reference.id);
    if(selected.ref.digest!==reference.digest||selected.ref.revision!==reference.revision)throw new DeviceExecutionError('execution_ready_reference');return selected;
    }catch(error){close(error);throw error;}},
   // 会话默认闸保持关闭；设备Ready是精确引用，使用前必须通过currentReady核验。
   get state(){return Object.freeze({phase:closed?'closed':'ready',gate_state:'closed',
    ready_devices:[...qualifications.values()].map(({device_id,ref})=>({device_id,ref})),
    close_reason:closeReason,close_failure:closeFailure,selected_features:negotiation.selected_features});}});
 }catch(error){close(error);throw error;}
}
