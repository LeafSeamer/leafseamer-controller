import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeExecutionPayload,DeviceExecutionError} from './device-execution-channel.mjs';
import {authorizationRevoked} from './device-authorization-fence.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const digest=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const frozen=value=>{if(value&&typeof value==='object'){for(const item of Object.values(value))frozen(item);Object.freeze(value);}return value;};
const content=({context_id,idempotency_key,correlation_id,...value})=>value;
const reference=(id,value)=>({id,revision:'1',digest:value});
const max=99999999999999999999n;

// 普通、非面板、无需参考时间的首次发送路径。其余路径须由各自完整处理器接入。
// currentGate由同设备闸所有者同步提供已采用OPEN投影；该所有者负责FENCE/DENY/保护时立即撤下投影。
// nextIoSequence与该所有者共用同一设备序列，不能由请求指定；不接收trusted/passed等布尔许可。
export function deviceTransmissionWriter({binding,preparation,executor,action,currentGate,nextIoSequence,tick,signal,failed,limits}){
 need(executor?.api_version==='leafseamer-device-primitives/1'&&typeof executor.writePrimitive==='function'&&typeof currentGate==='function'&&
  typeof nextIoSequence==='function'&&typeof tick==='function'&&signal instanceof AbortSignal&&typeof failed==='function','transmission_configuration');
 need(limits&&Number.isSafeInteger(limits.max_guards)&&limits.max_guards>0&&limits.max_guards<=4096&&
  Number.isSafeInteger(limits.max_transmissions)&&limits.max_transmissions>0&&limits.max_transmissions<=4096&&
  Number.isSafeInteger(limits.max_metadata_bytes)&&limits.max_metadata_bytes>0&&limits.max_metadata_bytes<=67108864,'transmission_capacity_profile');
 const bound=frozen(structuredClone(binding)),selected=frozen(structuredClone(action)),budget={...limits},abort=new AbortController();
 const guards=new Map(),permitGuards=new Map(),attempts=new Map(),transmissions=new Map(),dispatchIntents=new Map(),issues=new Set(),initialAttempts=new Set();
 let closed=false,writing=false,metadata=0,lastTick=null,lastOrder=0n;
 function stop(error=new DeviceExecutionError('transmission_closed')){if(closed)return;closed=true;abort.abort();try{failed(error);}catch{}}
 signal.addEventListener('abort',()=>stop(),{once:true});
 function current(){need(!closed&&!signal.aborted,'transmission_closed');}
 function now(){let value;try{value=tick();}catch{need(false,'transmission_clock');}
  need(typeof value==='bigint'&&value>=0n&&value<=max&&(lastTick===null||value>=lastTick),'transmission_clock');lastTick=value;return value;}
 function reserve(bytes){need(metadata+bytes<=budget.max_metadata_bytes,'transmission_metadata_capacity');metadata+=bytes;}
 function gate(){
  current();const value=currentGate();need(value&&value.access,'transmission_gate_closed');const a=value.access,{access_digest,...body}=a,t=now();
  need(a.purpose==='ordinary'&&a.protection===null&&a.initial_assessment_ref===null&&same(a.binding,bound)&&digest(body)===access_digest,'transmission_gate_binding');
  need(BigInt(a.selected_tick_ns)<=t&&t<BigInt(a.expires_tick_ns)&&BigInt(a.expires_tick_ns)<=BigInt(value.lease_until_tick_ns),'transmission_gate_expired');
  return {value,t,accessRef:reference(a.access_id,a.access_digest)};
 }
 async function incoming(bytes,type){
  current();const decoded=await decodeExecutionPayload(bytes,'c2w');current();need(decoded.frame.type===type,'transmission_message_type');
  for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','device_id','clock_domain_id','descriptor_digest'])need(decoded.frame[key]===bound[key],'transmission_channel');
  return decoded;
 }
 function checkGuard(frame,live,allowRevoked=false){
  const body=frame.body,g=body.guard,{guard_digest,...unsigned}=g;
  need(digest(unsigned)===guard_digest,'transmission_guard_digest');
  for(const key of ['controller_boot_id','worker_boot_id','ipc_session_id','device_id','clock_domain_id','descriptor_digest'])need(g[key]===bound[key],'transmission_guard_binding');
  need(g.admission_origin==='non_panel'&&g.panel_binding===null&&g.automation_binding===null&&g.time_required===false&&g.reference_time===null&&
   body.schedule_guard===null&&body.reference_context===null&&g.binding.principal_kind==='human'&&g.binding.origin==='manual'&&
   g.binding.audience===bound.scope.authority_service_id&&g.binding.extension_instance_id===null,'transmission_guard_path');
  need(same(g.gate_access_ref,live.accessRef)&&g.authorization_revision===live.value.authorization_revision&&live.t<BigInt(g.authorization_deadline_tick_ns),'transmission_guard_stale');
  need(allowRevoked||!live.value.authorization_denials.some(v=>authorizationRevoked(g.binding,v)),'transmission_authorization_revoked');
  need(!live.value.command_denials.some(v=>v.parent_command_id===g.command_id),'transmission_command_denied');
  return g;
 }
 function checkDispatch(frame,installed){
  const live=gate(),body=frame.body,p=body.permit,g=checkGuard(installed.frame,live,true),a=live.value.access;
  const prepared=preparation.describe(body.prepare_id),authority=prepared.authorization,request=body.request,packet=body.packet,tx=p.transmission;
  const revoked=live.value.authorization_denied_intents.find(v=>v.intent.permit_id===p.permit_id);
  need(!revoked||(same(revoked.intent,tx.intent)&&(!revoked.transmission||same(revoked.transmission,tx))),'transmission_revoked_intent_conflict');
  need(BigInt(tx.issued_revision)>BigInt(live.value.issued_cut_revision)&&!live.value.fenced_permit_ids.includes(p.permit_id),'transmission_fenced');
  need(same(packet,prepared.packet)&&same(content(request),content(prepared.request))&&digest(content(request))===p.content_digest&&
   installed.frame.body.content_digest===p.content_digest,'transmission_content');
  need(request.action_id===selected.action_id&&request.capability_version===selected.capability_version&&body.parameters_schema_digest===selected.parameters_schema_digest&&
   request.origin==='manual'&&request.dispatch.mode==='immediate'&&request.automation_binding===null,'transmission_action');
  need(p.origin==='manual'&&p.admission_origin==='non_panel'&&p.automation_binding===null&&p.panel_binding_digest===null,'transmission_origin');
  need(body.guard_id===g.guard_id&&body.guard_digest===g.guard_digest&&p.guard_id===g.guard_id&&p.guard_digest===g.guard_digest&&p.permit_id===g.permit_id&&p.command_id===g.command_id&&
   p.command_id===packet.command_id&&p.attempt_id===packet.attempt_id&&authority.target.command_ref.id===p.command_id&&authority.target.proposed_attempt_id===p.attempt_id,'transmission_permit_binding');
  for(const key of ['controller_boot_id','worker_boot_id','device_session_id','clock_domain_id','descriptor_digest'])need(p[key]===bound[key],'transmission_permit_binding');
  need(p.control_epoch===a.control_epoch&&p.control_version===a.effective_version&&same(request.expected_control,{epoch:p.control_epoch,version:p.control_version})&&
   p.authorization_revision===g.authorization_revision&&p.gate_revision===live.value.gate_revision&&body.gate_token===live.value.gate_token,'transmission_generation');
  need(same(p.gate_access_ref,live.accessRef)&&same(p.ownership_ref,g.ownership_ref)&&same(p.deadline_policy,request.dispatch),'transmission_authority');
  const requester=authority.requester;need(requester.kind===g.binding.principal_kind&&['issuer_id','issuer_epoch','principal_id'].every(k=>requester[k]===g.binding[k]),'transmission_requester');
  need(tx.kind==='initial'&&tx.ordinal==='0'&&tx.cause==='dispatch'&&tx.initial_permit_id===p.permit_id&&tx.parent_dispatch_intent_id===p.dispatch_intent_id&&
   tx.primitive_id===packet.primitive_id&&same(tx.packet_ref,{packet_id:packet.packet_id,packet_digest:packet.packet_digest})&&same(tx.send_window,body.send_window),'transmission_intent');
  for(const key of ['permit_id','command_id','attempt_id','dispatch_intent_id','worker_boot_id','device_session_id','guard_id','guard_digest','clock_domain_id','descriptor_digest','controller_boot_id','admission_origin','panel_binding_digest','origin'])
   need(tx.intent[key]===p[key],'transmission_intent');
  need(tx.intent.ipc_session_id===bound.ipc_session_id&&tx.intent.device_id===bound.device_id&&tx.intent.automation_binding===null&&tx.intent.automation_binding_digest===null,'transmission_intent');
  need(body.send_window.clock_domain_id===bound.clock_domain_id&&body.send_window.descriptor_digest===bound.descriptor_digest&&
   BigInt(body.send_window.earliest_tick_ns)<=live.t&&live.t<BigInt(body.send_window.latest_tick_ns)&&
   BigInt(body.send_window.latest_tick_ns)<=BigInt(g.authorization_deadline_tick_ns)&&BigInt(body.send_window.latest_tick_ns)<=BigInt(a.expires_tick_ns),'transmission_window');
  return {live,packet,revoked:live.value.authorization_denied_permit_ids.includes(p.permit_id)||live.value.authorization_denials.some(v=>authorizationRevoked(g.binding,v))};
 }
 function report(entry,disposition,proof,observation=null){
  const p=entry.frame.body.permit,tx=p.transmission;
  return frozen({type:'SEND_REPORT',reply_to:null,device_id:bound.device_id,body:{report_id:entry.reportId,permit_id:p.permit_id,
   attempt_id:p.attempt_id,dispatch_intent_id:p.dispatch_intent_id,device_session_id:bound.device_session_id,disposition,proof,protocol_request_id:null,
   transmission_id:tx.transmission_id,packet_ref:tx.packet_ref,ordinal:tx.ordinal,gate_io_seq:entry.order,
   transport_entered_tick_ns:disposition==='in_flight'?entry.enteredTick:null,
   socket_callback_observation_ref:observation?{object_id:observation.observation_id,digest:digest(observation)}:null}});
 }
 function evidence(entry){
  // 只转交同次已完成调用的原始观察；候选不能自行裁决命令成功或释放资源。
  const body=entry.frame.body,p=body.permit,observation=entry.observation;
  need(entry.consumed&&entry.result?.body.disposition==='in_flight'&&observation,'transmission_evidence_source');
  return frozen({type:'EVIDENCE_CANDIDATE',reply_to:null,device_id:bound.device_id,body:{report_id:entry.evidenceId,command_id:p.command_id,
   attempt_id:p.attempt_id,device_session_id:bound.device_session_id,evidence_kind:'module_observation',observation_id:observation.observation_id,
   payload:{format:'leafseamer-primitive-observation/1',binding:bound,send_report_ref:{object_id:entry.reportId,digest:digest(entry.result.body)},
    observation_ref:{object_id:observation.observation_id,digest:digest(observation)},observation}}});
 }
 async function write(entry,installed){
  const body=entry.frame.body,packetRef={object_id:body.packet.packet_id,digest:body.packet.packet_digest};
  function discard(){entry.order=String(nextIoSequence());entry.result=report(entry,'not_sent','discarded_unconsumed');return entry.result;}
  try{
   if(checkDispatch(entry.frame,installed).revoked)return discard();
   return await preparation.withPacket(body.prepare_id,packetRef,async bytes=>{
    const {live,packet,revoked}=checkDispatch(entry.frame,installed);if(revoked)return discard();need(!writing,'transmission_busy');
    need(bytes.length===packet.byte_length&&'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')===packet.sha256,'transmission_packet_bytes');
    const order=nextIoSequence();need(typeof order==='bigint'&&order>lastOrder&&order<=max,'transmission_order');lastOrder=order;
    // 最后复核至许可消费和进入传输之间不await；消费后的任何异常均保留unknown。
    entry.order=String(order);entry.enteredTick=String(live.t);entry.consumed=true;writing=true;
    try{
     const result=await executor.writePrimitive({device_id:bound.device_id,device_session_id:bound.device_session_id,bytes,signal:abort.signal});
     if(closed||signal.aborted)throw new DeviceExecutionError('transmission_closed');
     need(result&&Number.isInteger(result.bytes_written)&&result.bytes_written===packet.byte_length,'transmission_write_uncertain');
     const observation={observation_id:crypto.randomUUID(),permit_id:body.permit.permit_id,transmission_id:body.permit.transmission.transmission_id,
      packet_ref:body.permit.transmission.packet_ref,bytes_written:result.bytes_written,response:structuredClone(result.response),observed_tick_ns:String(now())};
     need(Buffer.byteLength(canonicalize(observation))<=16384,'transmission_observation_capacity');
     entry.observation=frozen(observation);entry.result=report(entry,'in_flight','transport_entered',entry.observation);entry.evidence=evidence(entry);return entry.result;
    }catch(error){entry.evidence=null;entry.result=report(entry,'unknown','send_uncertain');stop(error);return entry.result;}
    finally{writing=false;}
   });
  }catch(error){stop(error);throw error;}finally{entry.finished=true;}
 }
 return Object.freeze({
  async installGuard(bytes){
   try{const {frame,payload}=await incoming(bytes,'GUARD_INSTALL'),id=frame.body.guard.guard_id,prior=guards.get(id);
    if(prior){need(prior.payload.equals(payload),'transmission_guard_conflict');return prior.ack;}
    const live=gate(),g=checkGuard(frame,live);need(!permitGuards.has(g.permit_id)&&guards.size<budget.max_guards,'transmission_guard_capacity');reserve(payload.length+8192);
    const ack=frozen({type:'GUARD_ACK',reply_to:frame.message_id,device_id:bound.device_id,body:{guard_id:g.guard_id,guard_digest:g.guard_digest,
     content_digest:frame.body.content_digest,permit_id:g.permit_id,command_id:g.command_id,installed_authorization_revision:g.authorization_revision,state:'installed',
     panel_binding_digest:null,automation_binding_digest:null,reference_time_digest:null,schedule_guard_digest:null,gate_access_ref:g.gate_access_ref,ownership_ref:g.ownership_ref}});
    const entry={frame,payload,ack};guards.set(id,entry);permitGuards.set(g.permit_id,id);return ack;
   }catch(error){stop(error);throw error;}
  },
  async dispatch(bytes){
   try{const {frame,payload}=await incoming(bytes,'DISPATCH'),p=frame.body.permit,prior=attempts.get(p.permit_id);
    if(prior){need(prior.payload.equals(payload),'transmission_permit_conflict');return await prior.pending;}
    const installed=guards.get(frame.body.guard_id);need(installed,'transmission_guard_required');checkDispatch(frame,installed);
    const initialKey=JSON.stringify([p.command_id,p.attempt_id]);
    need(!writing&&attempts.size<budget.max_transmissions&&!transmissions.has(p.transmission.transmission_id)&&!dispatchIntents.has(p.dispatch_intent_id)&&!issues.has(p.transmission.issued_revision)&&!initialAttempts.has(initialKey),'transmission_capacity_or_reuse');
    reserve(payload.length+45056);const entry={frame,payload,reportId:crypto.randomUUID(),evidenceId:crypto.randomUUID(),order:null,enteredTick:null,consumed:false,finished:false,result:null,observation:null,evidence:null,pending:null};
    attempts.set(p.permit_id,entry);transmissions.set(p.transmission.transmission_id,entry);dispatchIntents.set(p.dispatch_intent_id,entry);issues.add(p.transmission.issued_revision);initialAttempts.add(initialKey);
    entry.pending=write(entry,installed);return await entry.pending;
   }catch(error){stop(error);throw error;}
  },
  query(permitId){const entry=attempts.get(permitId);return entry?frozen({consumed:entry.consumed,pending:!entry.finished,report:entry.result,observation:entry.observation,evidence:entry.evidence}):null;},
  async stored(bytes){
   try{const {frame}=await incoming(bytes,'REPORT_STORED'),body=frame.body;
    const entry=[...attempts.values()].find(value=>value.result?.body.report_id===body.report_id||value.evidence?.body.report_id===body.report_id);
    need(entry,'transmission_report_unknown');entry.receipts??=new Map();const previous=entry.receipts.get(body.report_id);
    need(!previous||same(previous,body),'transmission_report_receipt_conflict');entry.receipts.set(body.report_id,frozen(structuredClone(body)));
    // 送达回执不清除传输账本，也不裁决效果完成或释放。
   }catch(error){stop(error);throw error;}
  },
  // 仅供同设备闸所有者在同步关闭后读取；账本不因报告送达或闸换代而清空。
  fenceSnapshot(){current();return frozen({binding:bound,guards:[...guards.values()].map(v=>v.frame.body.guard),
   transmissions:[...attempts.values()].map(v=>({transmission:v.frame.body.permit.transmission,consumed:v.consumed,report:v.result}))});},
  close:stop,
  get state(){return Object.freeze({closed,writing,guards:guards.size,transmissions:attempts.size,metadata_bytes:metadata});}
 });
}
