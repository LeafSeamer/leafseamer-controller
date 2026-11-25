import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {executionTick,insertFrame,preparedFrame} from './device-execution-handshake.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {readReferenceTimeFenceSource} from './reference-time-invalidation.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {sqliteRow} from './sqlite-rows.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('execution_time_fence_'+code);};
const ref=(id,digest)=>({id,revision:'1',digest});
const bytesHash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
function original(text,checksum){
 const value=JSON.parse(text);
 need(canonical(value)===text&&bytesHash(text)===checksum,'integrity');
 return value;
}

function targetSource(db,operation,exit){
 const source=readReferenceTimeFenceSource(db,operation);
 need(source,'source');
 const targetRef=source.targets.find(v=>v.id===exit);
 const row=sqliteRow(db,`SELECT t.*,i.service_boot_id FROM time_provider_reference_exit_target t
  JOIN time_provider_reference_invalidation i USING(operation_id) WHERE t.operation_id=? AND t.exit_id=?`,operation,exit);
 need(row&&same(targetRef,ref(exit,row.body_digest)),'target');
 const target=original(row.body_jcs,row.body_digest);
 need(target.exit_id===exit&&target.ipc_session_id===row.ipc_session_id&&target.device_binding_ref.id===row.binding_id,'target');
 return {source,target,targetRef,serviceBoot:row.service_boot_id,operation};
}
function frameBody(db,selection,barrier_id){
 const {source,target,operation}=selection,{invalidation,issued_cut_revision}=source;
 const {clock_domain_id,descriptor_digest}=invalidation.old_binding.domain,txs=[];
 const issues=db.prepare(`SELECT f.body_jcs,f.body_digest,i.issued_revision FROM command_final_admission f
  JOIN command_transmission_issue i USING(transaction_id,permit_id)
  WHERE f.binding_id=? ORDER BY f.permit_id COLLATE BINARY`).raw().all(target.device_binding_ref.id);
 for(const [text,checksum,issued] of issues){
  const {guard,permit}=original(text,checksum),utc=guard.reference_time?.utc_guard.binding;
  need(guard.time_required===(utc!==undefined&&utc!==null),'ledger');
  if(!utc||!same(utc.domain,invalidation.old_binding.domain)||BigInt(utc.time_generation)>=BigInt(invalidation.next_time_generation))continue;
  const tx=permit.transmission,{intent}=tx,{guard_digest,...guardBody}=guard;
  need(digest(guardBody)===guard_digest&&intent.guard_digest===guard_digest&&intent.guard_id===guard.guard_id&&
   intent.permit_id===guard.permit_id&&intent.command_id===guard.command_id&&intent.device_id===target.device_id&&
   intent.ipc_session_id===target.ipc_session_id&&tx.issued_revision===String(BigInt(issued))&&
   BigInt(issued)<=BigInt(issued_cut_revision),'ledger');
  txs.push(tx);
 }
 need(txs.length<=256,'capacity');
 const open_intents=txs.map(v=>v.intent);
 const body={operation_id:operation,issued_cut_revision,ledger_digest:digest(open_intents),open_intents,clock_domain_id,descriptor_digest,
  open_transmission_intents:txs,transmission_ledger_digest:digest(txs),cancel_transmissions:[],cancel_ledger_digest:digest([]),invalidation};
 const target_exit_id=target.exit_id;
 return {...body,barrier_id,attempt_binding:{cut_id:barrier_id,target_exit_id,attempt_ordinal:'1',previous_barrier_id:null,
  cut_digest:digest({type:'TIME_FENCE',target_exit_id,body})}};
}
function currentSelection(db,binding,runtime,operation,exit){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=112,'writer');
 const selected=targetSource(db,operation,exit),{target,serviceBoot}=selected;
 need(binding.service_boot_id===serviceBoot&&target.ipc_session_id===binding.ipc_session_id&&
  target.runtime_ref.id===runtime.ref.object_id&&target.runtime_ref.digest===runtime.ref.digest&&
  !db.prepare('SELECT 1 FROM time_provider_reference_exit_retired WHERE operation_id=? AND exit_id=?').pluck().get(operation,exit),'target');
 const bound=currentDeviceExecutionBinding(db,runtime,target.device_id,binding.ipc_session_id);
 need(same(bound.ref,target.device_binding_ref)&&bound.value.binding.writer_exit_id===exit,'target');
 return selected;
}
export function selectTimeFence(db,{binding,runtime,input:{operation,exit},features}){
 const selected=currentSelection(db,binding,runtime,operation,exit);
 const prior=db.prepare("SELECT record_id FROM execution_time_fence_frame WHERE operation_id=? AND exit_id=? AND phase='request'").pluck().get(operation,exit);
 if(prior)return {saved:readTimeFence(db,binding,prior)};
 const seq=db.prepare("SELECT max(sequence) FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w'").pluck().get(binding.ipc_session_id);
 need(seq,'handshake');
 const {ipc_session_id,controller_boot_id,worker_boot_id,clock_domain_id,descriptor_digest}=binding;
 const frame={ipc_version:deviceExecutionVersion,type:'TIME_FENCE',message_id:crypto.randomUUID(),reply_to:null,seq:String(BigInt(seq)+1n),
  ipc_session_id,controller_boot_id,worker_boot_id,clock_domain_id,descriptor_digest,device_id:selected.target.device_id,journal_mode:'durable',
  body:frameBody(db,selected,crypto.randomUUID())};
 assertDeviceExecutionFeatures(frame,features);
 return {operation,exit,frame};
}

function domainBody(transaction,recordRef,selected){
 const wire=selected.source.invalidation;
 return {transaction_id:transaction,record_ref:recordRef,target_ref:selected.targetRef,invalidation_ref:ref(wire.invalidation_id,wire.invalidation_digest)};
}
function effectBody(transaction,recordRef,domainDigest,phase,tick){
 const audit={kind:'execution_time_fence_'+phase,domain_digest:domainDigest};
 const effect={record_ref:recordRef,disposition:'applied',domain_commit_refs:[ref(transaction,domainDigest)],
  audit_ref:ref(transaction+'.audit',digest(audit)),reply_record_refs:[],committed_tick_ns:String(tick)};
 return {audit,effect};
}
function append(db,item,selected,phase,tick,attemptId=null){
 const recordRef=ref(item.record.record_id,item.record.record_digest),domain=domainBody(item.transaction,recordRef,selected),checksum=digest(domain);
 const {audit,effect}=effectBody(item.transaction,recordRef,checksum,phase,tick);
 insertFrame(db,item,'time_fence');
 need(db.prepare('INSERT INTO execution_time_fence_frame VALUES(?,?,?,?,?,?,?,?,?,?)').run(recordRef.id,item.transaction,phase,
  selected.operation,selected.targetRef.id,selected.targetRef.digest,item.replyRecord,attemptId,canonical(domain),checksum).changes===1,'storage');
 need(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(recordRef.id,item.transaction,'applied',executionTick(tick),
  canonical(audit),digest(audit),canonical(effect),digest(effect)).changes===1,'storage');
}
export function commitTimeFence(db,{binding,runtime,candidate,tick}){
 const {operation,exit,frame}=candidate,selected=currentSelection(db,binding,runtime,operation,exit);
 need(same(frameBody(db,selected,frame.body.barrier_id),frame.body),'changed');
 const item=preparedFrame(binding,frame,Buffer.from(JSON.stringify(frame)),'c2w',tick());
 append(db,item,selected,'request',tick());
 return readTimeFence(db,binding,item.record.record_id);
}

function savedFrame(db,binding,id,phase,selected){
 const row=sqliteRow(db,`SELECT f.*,x.*,e.disposition,e.committed_tick,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest
  FROM execution_frame_record f JOIN execution_time_fence_frame x USING(record_id,transaction_id)
  JOIN execution_effect_commit e USING(record_id,transaction_id) WHERE f.record_id=?`,id);
 need(row?.phase===phase&&row.operation_id===selected.operation&&row.exit_id===selected.targetRef.id&&row.target_digest===selected.targetRef.digest,'history');
 const frame=original(row.frame_jcs,row.frame_digest),record=JSON.parse(row.record_jcs),{record_digest,...unsigned}=record;
 const recordRef=ref(id,row.record_digest),domain=original(row.domain_jcs,row.domain_digest);
 const {audit,effect}=effectBody(row.transaction_id,recordRef,row.domain_digest,phase,BigInt(row.committed_tick));
 need(row.domain_kind==='time_fence'&&row.ipc_session_id===binding.ipc_session_id&&row.device_id===selected.target.device_id&&
  frame.device_id===row.device_id&&frame.type===(phase==='request'?'TIME_FENCE':'TIME_FENCE_ACK')&&frame.type===row.message_type&&
  frame.seq===String(BigInt(row.sequence))&&frame.message_id===row.message_id&&frame.journal_mode==='durable'&&
  row.direction===(phase==='request'?'c2w':'w2c')&&row.disposition==='applied'&&row.observed_tick<=row.committed_tick,'integrity');
 for(const name of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])
  need(frame[name]===binding[name],'integrity');
 need(executionWire(row.wire.subarray(4)).equals(row.wire)&&bytesHash(row.wire)===row.wire_digest&&same(JSON.parse(row.wire.subarray(4)),frame)&&
  canonical(record)===row.record_jcs&&record_digest===row.record_digest&&digest(unsigned)===record_digest&&
  same(unsigned,{record_id:id,session_ref:ref(binding.ipc_session_id,digest(binding)),direction:row.direction,sequence:frame.seq,
   message_id:frame.message_id,message_type:frame.type,frame_digest:row.frame_digest,wire_digest:row.wire_digest,wire_length:row.wire.length,
   frame_object_ref:ref(id+'.frame',row.frame_digest),wire_object_ref:ref(id+'.wire',row.wire_digest)})&&
  same(domain,domainBody(row.transaction_id,recordRef,selected))&&same(audit,original(row.audit_jcs,row.audit_digest))&&
  same(effect,original(row.effect_jcs,row.effect_digest)),'integrity');
 return {row,recordRef,frame};
}
function checkAck(request,frame,attempt,observed){
 const r=request.frame,b=frame.body,s=r.body;
 need(frame.type==='TIME_FENCE_ACK'&&frame.reply_to===r.message_id&&frame.device_id===r.device_id&&frame.journal_mode==='durable'&&
  attempt?.record_id===request.recordRef.id&&BigInt(b.effective_tick_ns)>=BigInt(attempt.started_tick)&&BigInt(b.effective_tick_ns)<=observed,'reply');
 const {coverage,transmission_coverage}=b;
 need(coverage.length===s.open_intents.length&&transmission_coverage.length===s.open_transmission_intents.length,'coverage');
 for(const [index,v] of transmission_coverage.entries()){
  const {disposition,proof}=v;
  need(same(v.intent,s.open_transmission_intents[index])&&same(coverage[index],{intent:s.open_intents[index],disposition,proof})&&
   (disposition==='unknown'&&proof==='send_uncertain'||disposition==='in_flight'&&proof==='transport_entered'||
    disposition==='not_sent'&&['never_received','discarded_unconsumed'].includes(proof)),'coverage');
 }
 const ids=d=>[...new Set(coverage.filter(v=>v.disposition===d).map(v=>v.intent.command_id))].sort(),inFlight=ids('in_flight');
 need(same(b,{operation_id:s.operation_id,barrier_id:s.barrier_id,issued_cut_revision:s.issued_cut_revision,ledger_digest:s.ledger_digest,
  clock_domain_id:s.clock_domain_id,descriptor_digest:s.descriptor_digest,coverage,transmission_coverage,
  invalidated_permit_ids:coverage.filter(v=>v.disposition==='not_sent').map(v=>v.intent.permit_id),
  in_flight_command_ids:inFlight,unresolved_command_ids:ids('unknown').filter(id=>!inFlight.includes(id)),all_write_exits_fenced:true,
  attempt_binding:s.attempt_binding,transmission_ledger_digest:s.transmission_ledger_digest,effective_tick_ns:b.effective_tick_ns,
  cancel_coverage:[],cancel_ledger_digest:s.cancel_ledger_digest,
  invalidation_ref:ref(s.invalidation.invalidation_id,s.invalidation.invalidation_digest),minimum_time_generation:s.invalidation.next_time_generation}),'reply');
}
export function readTimeFence(db,binding,id){
 need(db.inTransaction,'writer');
 const source=sqliteRow(db,"SELECT operation_id,exit_id FROM execution_time_fence_frame WHERE record_id=? AND phase='request'",id);
 need(source,'history');
 const selected=targetSource(db,source.operation_id,source.exit_id),request=savedFrame(db,binding,id,'request',selected);
 need(request.frame.reply_to===null&&request.row.reply_record_id===null&&
  same(frameBody(db,selected,request.frame.body.barrier_id),request.frame.body),'history');
 const ackId=db.prepare('SELECT record_id FROM execution_time_fence_frame WHERE request_record_id=?').pluck().get(id);
 const ack=ackId?savedFrame(db,binding,ackId,'ack',selected):null;
 if(ack){
  need(ack.row.reply_record_id===id,'reply');
  checkAck(request,ack.frame,sqliteRow(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',ack.row.write_attempt_id),BigInt(ack.row.observed_tick));
 }
 return {request,ack,selected};
}
export function currentTimeFence(db,{binding,runtime,id}){
 const saved=readTimeFence(db,binding,id),{operation,targetRef}=saved.selected;
 const selected=currentSelection(db,binding,runtime,operation,targetRef.id);
 need(!saved.ack&&same(selected,saved.selected),'changed');
 return saved;
}
export function acceptTimeFence(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 const id=db.prepare("SELECT record_id FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' AND message_type='TIME_FENCE' AND message_id=?").pluck().get(binding.ipc_session_id,frame.reply_to);
 need(id,'reply');
 const {request,ack,selected}=readTimeFence(db,binding,id);
 if(ack){need(ack.row.wire.equals(executionWire(payload)),'replay');return {request,ack};}
 const attempt=sqliteRow(db,'SELECT attempt_id,record_id,started_tick FROM execution_write_attempt WHERE record_id=?',id);
 checkAck(request,frame,attempt,receivedTick);
 append(db,preparedFrame(binding,frame,payload,'w2c',receivedTick,id),selected,'ack',tick(),attempt.attempt_id);
 return readTimeFence(db,binding,id);
}
