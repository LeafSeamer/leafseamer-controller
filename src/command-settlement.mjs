import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {preparedFrame,insertFrame,executionTick} from './device-execution-handshake.mjs';
import {readCommandDispatch,dispatchEffect,dispatchApplied} from './command-dispatch.mjs';
import {readOriginalRecord,readCommandRecord,readReportedCommandRecord,settledCommandProjection} from './command-record-store.mjs';
import {readCommandEncoding} from './command-encoding-store.mjs';
import {readInitialReady,protectInitialReadies} from './device-initial-ready.mjs';
import {readControlSource,currentControlSource} from './device-control-source.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_settlement_'+code);};
const ref=(id,v)=>({id,revision:'1',digest:digest(v)});
const parse=(text,hash)=>{const value=JSON.parse(text);need(canonical(value)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'integrity');return value;};
const written=result=>need(result.changes===1,'storage');
function row(db,sql,...args){const q=db.prepare(sql),names=q.columns().map(v=>v.name),values=q.raw().get(...args);return values&&Object.fromEntries(names.map((n,i)=>[n,values[i]]));}
function source(db,id){
 const dispatch=readCommandDispatch(db,id),v=dispatch.final.value,initial=readOriginalRecord(db,v.command_id),ready=readInitialReady(db,initial.source.ready_ref.id);
 need(dispatch.write&&same(ready.value.binding,v.seal.binding),'source');
 const ids=db.prepare(`SELECT f.permit_id FROM command_final_admission f JOIN command_transmission_issue i USING(permit_id)
  WHERE f.binding_id=? AND i.issued_revision<=? ORDER BY f.permit_id`).pluck().all(initial.source.binding_ref.id,String(v.seal.issued_revision).padStart(20,'0'));
 const dispatches=ids.map(permit=>permit===id?dispatch:readCommandDispatch(db,permit));
 need(dispatches.every(item=>item.report&&same(item.final.value.seal.binding,v.seal.binding)),'cut_sources');
 return {dispatch,initial,ready,dispatches};
}
function checkControl(value,source){
 const p=source.dispatch.final.value.permit,b=source.dispatch.final.value.seal.binding;
 need(value.device_id===b.device_id&&value.gate_state==='protected'&&value.pending_operation_id===null&&value.mode==='manual'&&
  value.control_epoch===p.control_epoch&&value.effective_version===p.control_version&&same(value.holder,source.ready.after.holder)&&
  value.clock_domain_id===b.clock_domain_id&&value.descriptor_digest===b.descriptor_digest,'control');
}
function cutBody(source,barrierId){
 const v=source.dispatch.final.value,p=v.permit,b=v.seal.binding,transmissions=source.dispatches.map(item=>item.final.value.permit.transmission),intents=transmissions.map(t=>t.intent);
 const body={barrier_id:barrierId,operation_id:barrierId+'.operation',control_epoch:p.control_epoch,target_version:p.control_version,
  target_gate_revision:String(BigInt(source.ready.value.gate_after.gate_revision)+1n),issued_cut_revision:v.seal.issued_revision,
  ledger_digest:digest(intents),open_intents:intents,transmission_ledger_digest:digest(transmissions),open_transmission_intents:transmissions,cancel_transmissions:[],cancel_ledger_digest:digest([])};
 const {barrier_id,...cut}=body;
 return {...body,attempt_binding:{cut_id:barrierId+'_cut',cut_digest:digest({type:'FENCE',target_exit_id:b.writer_exit_id,body:cut}),
  target_exit_id:b.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null}};
}
function currentSource(db,{id,binding,runtime}){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=55,'writer');
 const selected=source(db,id),b=selected.dispatch.final.value.seal.binding,control=currentControlSource(db,b.device_id),bound=currentDeviceExecutionBinding(db,runtime,b.device_id,b.ipc_session_id);
 need(b.ipc_session_id===binding.ipc_session_id&&same(bound.value.binding,b)&&same(bound.ref,selected.initial.source.binding_ref)&&
  !db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(b.ipc_session_id),'binding');
 // 截止到当前签发水位的全部同装配传输均须进入关闭清单，已完成历史也不省略。
 const issued=db.prepare('SELECT permit_id FROM command_final_admission WHERE binding_id=? ORDER BY permit_id').pluck().all(selected.initial.source.binding_ref.id);
 need(same(issued,selected.dispatches.map(item=>item.final.value.permit.permit_id)),'cut_inventory');checkControl(control.current.value,selected);return {...selected,control:control.current};
}
export function protectCommandForSettlement(db,{id,binding,runtime,tick}){
 need(db.inTransaction,'writer');const selected=source(db,id),b=selected.dispatch.final.value.seal.binding;
 need(b.ipc_session_id===binding.ipc_session_id,'binding');protectInitialReadies(db,binding,tick);
 return withExecutionReadView(db,()=>{const current=currentSource(db,{id,binding,runtime});return {device_id:b.device_id,ready_ref:current.initial.source.ready_ref};});
}
export function selectCommandClosure(db,{id,binding,runtime,features}){
 return withExecutionReadView(db,()=>{
  const old=db.prepare('SELECT permit_id FROM command_closure_request WHERE permit_id=?').pluck().get(id);if(old)return {saved:readCommandClosure(db,id)};
  const selected=currentSource(db,{id,binding,runtime}),b=selected.dispatch.final.value.seal.binding;
  const previous=db.prepare("SELECT sequence FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence DESC LIMIT 1").pluck().get(binding.ipc_session_id);
  const frame={ipc_version:deviceExecutionVersion,type:'FENCE',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
   controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(previous)+1n),device_id:b.device_id,
   clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:cutBody(selected,crypto.randomUUID())};
  assertDeviceExecutionFeatures(frame,features);return {id,frame};
 });
}
export function commitCommandClosure(db,{candidate,binding,runtime,tick}){
 const selected=withExecutionReadView(db,()=>currentSource(db,{id:candidate.id,binding,runtime}));
 need(same(candidate.frame.body,cutBody(selected,candidate.frame.body.barrier_id)),'changed');
 const item=preparedFrame(binding,candidate.frame,Buffer.from(JSON.stringify(candidate.frame)),'c2w',tick()),value={format:'command-closure-request/1',permit_id:candidate.id,
  dispatch_ref:selected.dispatch.ref,ready_ref:selected.initial.source.ready_ref,control_ref:selected.control.ref,
  record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_closure_request VALUES(?,?,?,?,?,?,?)')
  .run(candidate.id,candidate.frame.body.barrier_id,selected.control.ref.id,item.record.record_id,item.transaction,canonical(value),digest(value)));
 dispatchEffect(db,item,candidate.id,'fence_request',value,tick());return readCommandClosure(db,candidate.id);
}
function expectedAck(saved,coverage,tick){
 const request=saved.request.frame,b=request.body,binding=saved.source.dispatch.final.value.seal.binding;
 need(Array.isArray(coverage)&&coverage.length===b.open_intents.length,'ack_coverage');
 const transmission_coverage=saved.source.dispatches.map((item,index)=>{
  const p=item.final.value.permit,{disposition,proof,intent}=coverage[index]??{};
  need(same(intent,p.transmission.intent)&&((disposition==='in_flight'&&proof==='transport_entered')||
   (disposition==='unknown'&&proof==='send_uncertain')||(disposition==='not_sent'&&['never_received','discarded_unconsumed'].includes(proof))),'ack_disposition');
  const report=item.report?.reply.frame.body;need(report&&report.disposition===disposition&&(disposition!=='not_sent'||proof==='discarded_unconsumed'),'ack_report');
  return {intent:p.transmission,disposition,proof};
 });
 const commands=kind=>[...new Set(coverage.filter(v=>v.disposition===kind).map(v=>v.intent.command_id))].sort(),inFlight=commands('in_flight');
 return {ack:{barrier_id:b.barrier_id,operation_id:b.operation_id,device_id:binding.device_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,
  control_epoch:b.control_epoch,installed_version:b.target_version,discarded_permit_ids:coverage.filter(v=>v.disposition==='not_sent').map(v=>v.intent.permit_id),
  in_flight_command_ids:inFlight,unresolved_command_ids:commands('unknown').filter(id=>!inFlight.includes(id)),all_write_exits_fenced:true,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest},issued_cut_revision:b.issued_cut_revision,ledger_digest:b.ledger_digest,gate_revision:b.target_gate_revision,
  coverage,transmission_coverage,attempt_binding:b.attempt_binding,
  transmission_ledger_digest:b.transmission_ledger_digest,effective_tick_ns:tick,cancel_coverage:[],cancel_ledger_digest:b.cancel_ledger_digest};
}
export function readCommandClosure(db,id){return withExecutionReadView(db,()=>memoExecutionRead(db,'command-closure',id,()=>readClosure(db,id)));}
function readClosure(db,id){
 need(db.inTransaction,'writer');const r=row(db,'SELECT * FROM command_closure_request WHERE permit_id=?',id);need(r,'missing');
 const selected=source(db,id),value=parse(r.body_jcs,r.body_digest),request=dispatchApplied(db,r.record_id,id,'fence_request',value),
  control=readControlSource(db,selected.initial.source.binding.device_id,value.control_ref.revision);
 checkControl(control.value,selected);need(r.control_source_id===control.ref.id&&same(value,{format:'command-closure-request/1',permit_id:id,
  dispatch_ref:selected.dispatch.ref,ready_ref:selected.initial.source.ready_ref,control_ref:control.ref,record_ref:{id:r.record_id,revision:'1',digest:request.record.record_digest}})&&
  same(request.frame.body,cutBody(selected,r.barrier_id))&&request.frame.ipc_session_id===selected.initial.source.binding.ipc_session_id,'request');
 const saved={source:selected,value,ref:ref(id+'.fence_request',value),request,ack:null},a=row(db,'SELECT * FROM command_closure_ack WHERE permit_id=?',id);if(!a)return saved;
 const ack=parse(a.body_jcs,a.body_digest),reply=dispatchApplied(db,a.record_id,id,'fence_ack',ack),b=reply.frame.body,
  attempt=row(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',a.write_attempt_id);
 need(attempt&&attempt.record_id===r.record_id&&reply.replyRecord===r.record_id&&reply.frame.reply_to===request.frame.message_id&&
  reply.frame.ipc_session_id===request.frame.ipc_session_id&&reply.frame.device_id===request.frame.device_id&&
  BigInt(b.effective_tick_ns)>=BigInt(attempt.started_tick)&&BigInt(b.effective_tick_ns)<=reply.observedTick&&
  same(b,expectedAck(saved,b.coverage,b.effective_tick_ns))&&
  same(ack,{format:'command-closure-ack/1',permit_id:id,request_ref:saved.ref,write_attempt_id:a.write_attempt_id,
   record_ref:{id:a.record_id,revision:'1',digest:reply.record.record_digest}}),'ack');
 return {...saved,ack:{value:ack,ref:ref(id+'.fence_ack',ack),reply}};
}
export function currentCommandClosure(db,{id,binding,runtime}){
 return withExecutionReadView(db,()=>{const saved=readCommandClosure(db,id),selected=currentSource(db,{id,binding,runtime});
  need(same(saved.value.control_ref,selected.control.ref)&&same(saved.value.dispatch_ref,selected.dispatch.ref),'changed');return saved;});
}
export function acceptCommandClosure(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 const id=db.prepare(`SELECT c.permit_id FROM command_closure_request c JOIN execution_frame_record f USING(record_id)
  WHERE f.ipc_session_id=? AND f.message_id=?`).pluck().get(binding.ipc_session_id,frame.reply_to);need(id,'reply');
 const saved=readCommandClosure(db,id);if(saved.ack){need(saved.ack.reply.wire.equals(executionWire(payload)),'replay_conflict');return saved;}
 for(const key of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','device_id'])need(frame[key]===saved.request.frame[key],'reply');
 const b=frame.body,attempt=row(db,'SELECT attempt_id,started_tick FROM execution_write_attempt WHERE record_id=?',saved.request.record.record_id);
 need(frame.type==='FENCE_ACK'&&attempt&&BigInt(b.effective_tick_ns)>=BigInt(attempt.started_tick)&&BigInt(b.effective_tick_ns)<=receivedTick&&
  same(b,expectedAck(saved,b.coverage,b.effective_tick_ns)),'reply');
 const item=preparedFrame(binding,frame,payload,'w2c',receivedTick,saved.request.record.record_id),value={format:'command-closure-ack/1',permit_id:id,
  request_ref:saved.ref,write_attempt_id:attempt.attempt_id,record_ref:{id:item.record.record_id,revision:'1',digest:item.record.record_digest}};
 insertFrame(db,item,'command_dispatch');written(db.prepare('INSERT INTO command_closure_ack VALUES(?,?,?,?,?,?)').run(id,item.record.record_id,item.transaction,attempt.attempt_id,canonical(value),digest(value)));
 dispatchEffect(db,item,id,'fence_ack',value,tick());return readCommandClosure(db,id);
}

function evidenceRecord(kind,body){
 const signed={...body,evidence_digest:digest(body)},value={scope:body.scope,command_id:body.command_id,
  source_ref:{id:body.evidence_id,revision:'1',digest:signed.evidence_digest},kind,body:signed};
 return {...value,view_digest:digest(value)};
}
// 输入已由原报告/候选/关闭账本校验；该政策只裁决固定内存的效果与原证据期限。
export function fixedMemoryCompletion({source,report,observation,receivedTick,baseline,coverage}){
 if(!observation||report.transport_entered_tick_ns===null)return false;
 const before=BigInt(report.transport_entered_tick_ns)+BigInt(source.deadline.evidence_timeout_ms)*1000000n;
 return receivedTick<before&&report.disposition==='in_flight'&&report.proof==='transport_entered'&&observation.bytes_written===8&&
  observation.response?.value===source.policies.completion.observation.value&&/^(?:0|[1-9][0-9]{0,19})$/.test(observation.response?.write_sequence)&&
  BigInt(observation.response.write_sequence)===BigInt(baseline.value.write_sequence)+1n&&coverage.proof==='transport_entered';
}
function settlement(db,closed,commit,evidenceRef=undefined){
 need(closed.ack,'closure_required');const {dispatch:d,initial}=closed.source,p=d.final.value.permit,s=initial.source;
 need(d.report,'report_required');const evidenceSource=evidenceRef===null?null:d.evidence;
 if(evidenceRef!==undefined&&evidenceRef!==null)need(evidenceSource&&same(evidenceSource.ref,evidenceRef),'observation_reference');
 const r=d.report.reply.frame.body,o=evidenceSource?.reply.frame.body.payload.observation,
  encoded=readCommandEncoding(db,d.final.value.prepare_id),resourceRow=row(db,'SELECT body_jcs,body_digest FROM device_initial_resource WHERE source_id=?',closed.source.ready.dispatch.plan.resource_source_ref.id);
 need(resourceRow,'resource');const resource=JSON.parse(resourceRow.body_jcs),{digest:resourceDigest,...resourceBody}=resource;
 need(canonical(resource)===resourceRow.body_jcs&&digest(resourceBody)===resourceDigest&&resourceDigest===resourceRow.body_digest&&resourceDigest===closed.source.ready.dispatch.plan.resource_source_ref.digest,'resource');
 const sampleRef=resource.inventory.baseline_ref,sample=row(db,'SELECT body_jcs,body_digest FROM device_baseline_sample WHERE sample_id=?',sampleRef.id);
 need(sample,'sample');const baseline=parse(sample.body_jcs,sample.body_digest);
 need(same(ref(baseline.sample_id,baseline),sampleRef)&&baseline.device_id===s.binding.device_id&&baseline.device_session_id===p.device_session_id,'sample');
 const succeeded=fixedMemoryCompletion({source:s,report:r,observation:o,receivedTick:evidenceSource?.reply.observedTick,baseline,coverage:closed.ack.reply.frame.body.transmission_coverage.find(v=>v.intent.intent.permit_id===p.permit_id)});
 const id=s.command_id,policy=initial.record.policy,closure={format:'fixed-memory-future-writes-closed/1',command_id:id,binding:s.binding,
  final_admission_ref:d.final.ref,cut_ref:closed.ref,ack_ref:closed.ack.ref,transmissions:closed.request.frame.body.open_transmission_intents,automatic_resends:false},
  module={format:'fixed-memory-settlement-proof/1',command_id:id,binding:s.binding,baseline_ref:sampleRef,
   dispatch_ref:d.ref,report_ref:d.report.ref,observation_ref:evidenceSource?.ref??null,closed_ref:ref(id+'.writes-closed',closure),
   evidence_deadline_tick_ns:r.transport_entered_tick_ns===null?null:String(BigInt(r.transport_entered_tick_ns)+BigInt(s.deadline.evidence_timeout_ms)*1000000n),
   module_settled:succeeded},
  decision=evidenceRecord('decision',{evidence_id:id+'.decision',command_id:id,scope:s.metadata.scope,kind:succeeded?'completion':'failure',
   policy_ref:policy.completion_policy_ref,retry_policy_ref:null,attempt_ids:[p.attempt_id],achieved:succeeded?'effect_verified':null,
   effect_status:succeeded?'verified':'possible',resolved_outcome:null}),
  release=succeeded?evidenceRecord('release',{evidence_id:id+'.release',command_id:id,scope:s.metadata.scope,device_id:s.binding.device_id,
   hold_id:d.final.value.ids.hold,cut_ref:closed.ref,kind:'module_settled',policy_ref:policy.release_policy_ref,
   future_writes_closed_ref:ref(id+'.writes-closed',closure),settlement_proof_ref:ref(id+'.module-settled',module)}):null,
  evidence=release?[decision,release]:[decision],previous=readReportedCommandRecord(db,initial,d).record,
  projection=settledCommandProjection(initial,previous,evidence,succeeded),value={format:'command-settlement/1',command_id:id,permit_id:p.permit_id,
   commit_id:commit,revision:'5',previous_state_ref:previous.state_ref,closure_ref:closed.ref,ack_ref:closed.ack.ref,
   future_writes_closed:closure,module_settlement:module,evidence,record_digest:projection.record.record_digest,state_digest:digest(projection.state)};
 return {value,ref:ref(id+'.settlement',value),projection,succeeded};
}
export function commitCommandSettlement(db,{id}){
 need(db.inTransaction,'writer');const closed=readCommandClosure(db,id),command=closed.source.initial.source.command_id,
  old=db.prepare('SELECT commit_id FROM command_settlement WHERE command_id=?').pluck().get(command);
 if(old)return readCommandRecord(db,command);
 const selected=settlement(db,closed,crypto.randomUUID()),{value:v,projection:p}=selected,previous=readCommandRecord(db,command).record;
 need(previous.revision==='4'&&same(previous.state_ref,v.previous_state_ref),'state_order');
 written(db.prepare('INSERT INTO command_settlement VALUES(?,?,?,?,?)').run(command,id,v.commit_id,canonical(v),digest(v)));
 for(const e of v.evidence)written(db.prepare('INSERT INTO command_evidence_record VALUES(?,?,?,?,?,?)').run(e.source_ref.id,command,v.commit_id,e.kind,canonical(e),e.view_digest));
 if(selected.succeeded)written(db.prepare('INSERT INTO command_hold_release VALUES(?,?,?,?)').run(closed.source.dispatch.final.value.ids.hold,command,v.commit_id,v.evidence[1].source_ref.id));
 written(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,?,?,?,?,?,?,?,?)').run(command,5,canonical(p.record),p.record.record_digest,canonical(p.state),digest(p.state),canonical(p.manifest),digest(p.manifest),v.commit_id));
 written(db.prepare('UPDATE command_lifecycle_head SET revision=5,commit_id=? WHERE command_id=? AND revision=4').run(v.commit_id,command));
 const audit=canonical({kind:'command_settled',command_id:command,revision:'5',commit_ref:ref(v.commit_id,v)});
 written(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,?,?,?,?,?,?)').run(v.commit_id,command,5,canonical(v),digest(v),audit,crypto.randomUUID(),audit));
 return readCommandRecord(db,command);
}
export function readSettlementLifecycle(db,initial,head,r){
 const id=initial.source.command_id,s=row(db,'SELECT * FROM command_settlement WHERE command_id=?',id);need(s&&head[0]===5&&s.commit_id===head[1],'state');
 const original=parse(s.body_jcs,s.body_digest),closed=readCommandClosure(db,s.permit_id),expected=settlement(db,closed,s.commit_id,original.module_settlement.observation_ref),{value:v,projection:p}=expected,
  audit=canonical({kind:'command_settled',command_id:id,revision:'5',commit_ref:ref(s.commit_id,v)});
 need(s.body_jcs===canonical(v)&&s.body_digest===digest(v)&&r[0]===canonical(p.record)&&r[1]===p.record.record_digest&&r[2]===canonical(p.state)&&r[3]===digest(p.state)&&
  r[4]===canonical(p.manifest)&&r[5]===digest(p.manifest)&&r[6]===s.body_jcs&&r[7]===s.body_digest&&r[8]===audit&&r[9]===audit&&r[10]===5&&r[11]===id,'state_integrity');
 const evidence=db.prepare('SELECT body_jcs,view_digest FROM command_evidence_record WHERE command_id=? ORDER BY evidence_id').raw().all(id);
 need(evidence.length===v.evidence.length&&evidence.every(([text,hash],i)=>text===canonical(v.evidence[i])&&hash===v.evidence[i].view_digest),'evidence_integrity');
 const released=db.prepare('SELECT hold_id,commit_id,evidence_id FROM command_hold_release WHERE command_id=?').raw().get(id);
 need(expected.succeeded?same(released,[closed.source.dispatch.final.value.ids.hold,s.commit_id,v.evidence[1].source_ref.id]):!released,'release_integrity');
 return {...initial,record:p.record,lifecycle:{commit_ref:ref(s.commit_id,v),final_admission:closed.source.dispatch.final,settlement:expected}};
}
