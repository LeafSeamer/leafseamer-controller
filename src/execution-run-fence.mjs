import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {executionTick,insertFrame,preparedFrame} from './device-execution-handshake.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {runGenerationMatches} from './device-authorization-fence.mjs';
import {captureRunDenySnapshot} from './run-generation-denial.mjs';
import {commandIssueHead} from './command-issue-order.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {sqliteRow} from './sqlite-rows.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('execution_run_fence_'+code);};
const ref=(id,digest)=>({id,revision:'1',digest});
const bytesHash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
function document(text,checksum){
 const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===checksum,'integrity');return value;
}
const sourceSql=`SELECT d.snapshot_revision,d.deny_revision,d.floor,d.rejection_digest,r.operation_id,r.body_jcs,
 d.origin_service_id,d.origin_database_instance_id,d.run_id
 FROM run_generation_denial d JOIN run_approval_rejection r USING(origin_service_id,origin_database_instance_id,approval_id)`;
function denial(values){
 need(values,'source');
 const [revision,denyRevision,floor,checksum,operationId,text,authority_service_id,database_instance_id,run_id]=values;
 document(text,checksum);
 return {revision,denyRevision:String(denyRevision),operationId,checksum,
  selector:{kind:'run_generation',origin_scope:{authority_service_id,database_instance_id},run_id,deny_through_generation:String(BigInt(floor))}};
}
function currentSource(db,binding,runtime,{device_id,origin_scope,run_id}){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=79,'writer');
 const bound=currentDeviceExecutionBinding(db,runtime,device_id,binding.ipc_session_id);
 const controller_scope=bound.value.binding.scope;
 const snapshot=captureRunDenySnapshot(db,controller_scope);
 const entry=snapshot.entries.find(row=>row.selector.run_id===run_id&&same(row.selector.origin_scope,origin_scope));need(entry,'source');
 const source=denial(db.prepare(sourceSql+' WHERE d.origin_service_id=? AND d.origin_database_instance_id=? AND d.run_id=? AND d.deny_revision=?')
  .raw().get(origin_scope.authority_service_id,origin_scope.database_instance_id,run_id,Number(entry.deny_revision)));
 need(same(entry.selector,source.selector),'source');
 const issues=db.prepare(`SELECT f.body_jcs,f.body_digest,i.issued_revision FROM command_final_admission f
  JOIN command_transmission_issue i USING(transaction_id,permit_id) WHERE f.binding_id=? ORDER BY f.permit_id COLLATE BINARY`).raw().all(bound.ref.id);
 const transmissions=[];
 for(const [text,checksum,issued] of issues){
  const {permit}=document(text,checksum),tx=permit.transmission;
  need(tx.intent.origin===permit.origin&&tx.intent.ipc_session_id===binding.ipc_session_id&&tx.intent.device_id===device_id&&
   same(tx.intent.automation_binding,permit.automation_binding)&&tx.issued_revision===String(BigInt(issued)),'ledger');
  if(tx.intent.origin==='automation'&&runGenerationMatches(tx.intent.automation_binding,source.selector))transmissions.push(tx);
 }
 need(transmissions.length<=256,'capacity');
 return {bound,source,transmissions,issued:commandIssueHead(db)};
}
function frameBody({bound,source,transmissions,issued},barrier_id){
 const {scope,writer_exit_id}=bound.value.binding,open_intents=transmissions.map(tx=>tx.intent);
 const body={operation_id:source.operationId,controller_scope:scope,selector:source.selector,selector_digest:digest(source.selector),
  issued_cut_revision:issued,target_deny_revision:source.denyRevision,ledger_digest:digest(open_intents),open_intents,
  transmission_ledger_digest:digest(transmissions),open_transmission_intents:transmissions,cancel_transmissions:[],cancel_ledger_digest:digest([])};
 return {...body,barrier_id,attempt_binding:{cut_id:barrier_id,target_exit_id:writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null,
  cut_digest:digest({type:'RUN_FENCE',target_exit_id:writer_exit_id,body})}};
}
export function selectRunFence(db,{binding,runtime,input,features}){
 const selected=currentSource(db,binding,runtime,input);
 const {source,bound}=selected;
 const existing=db.prepare("SELECT record_id FROM execution_run_fence_frame WHERE device_binding_id=? AND denial_revision=? AND phase='request'").pluck().get(bound.ref.id,source.revision);
 if(existing)return {saved:readRunFence(db,binding,existing)};
 const seq=db.prepare("SELECT max(sequence) FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w'").pluck().get(binding.ipc_session_id);
 need(seq,'handshake');
 const frame={ipc_version:deviceExecutionVersion,type:'RUN_FENCE',message_id:crypto.randomUUID(),reply_to:null,ipc_session_id:binding.ipc_session_id,
  controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:String(BigInt(seq)+1n),device_id:input.device_id,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',body:frameBody(selected,crypto.randomUUID())};
 assertDeviceExecutionFeatures(frame,features);
 return {input,frame,sourceRevision:source.revision,bindingRef:bound.ref};
}

function append(db,item,phase,source,bindingRef,tick,attemptId=null){
 const recordRef=ref(item.record.record_id,item.record.record_digest);
 const domain={transaction_id:item.transaction,record_ref:recordRef,binding_ref:bindingRef,source_revision:String(source.revision),rejection_digest:source.checksum};
 const checksum=digest(domain),audit={kind:'execution_run_fence_'+phase,domain_digest:checksum},auditDigest=digest(audit);
 const effect={record_ref:recordRef,disposition:'applied',domain_commit_refs:[ref(item.transaction,checksum)],
  audit_ref:ref(item.transaction+'.audit',auditDigest),reply_record_refs:[],committed_tick_ns:String(tick)};
 insertFrame(db,item,'run_fence');
 need(db.prepare('INSERT INTO execution_run_fence_frame VALUES(?,?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,phase,source.revision,bindingRef.id,
  item.replyRecord,attemptId,canonical(domain),checksum).changes===1,'storage');
 need(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(tick),
  canonical(audit),auditDigest,canonical(effect),digest(effect)).changes===1,'storage');
}
export function commitRunFence(db,{binding,runtime,candidate,tick}){
 const selected=currentSource(db,binding,runtime,candidate.input);
 need(selected.source.revision===candidate.sourceRevision&&same(selected.bound.ref,candidate.bindingRef)&&
  same(frameBody(selected,candidate.frame.body.barrier_id),candidate.frame.body),'changed');
 const item=preparedFrame(binding,candidate.frame,Buffer.from(JSON.stringify(candidate.frame)),'c2w',tick());
 append(db,item,'request',selected.source,selected.bound.ref,tick());
 return readRunFence(db,binding,item.record.record_id);
}

function original(db,binding,id,phase){
 const row=sqliteRow(db,`SELECT f.*,x.*,b.body_digest AS binding_digest,e.disposition,e.committed_tick,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest
  FROM execution_frame_record f JOIN execution_run_fence_frame x USING(record_id,transaction_id)
  JOIN execution_effect_commit e USING(record_id,transaction_id) JOIN device_execution_binding b ON b.binding_id=x.device_binding_id WHERE f.record_id=?`,id);
 need(row?.ipc_session_id===binding.ipc_session_id&&row.phase===phase,'history');
 const frame=document(row.frame_jcs,row.frame_digest),record=documentRecord(row),body=document(row.domain_jcs,row.domain_digest);
 const audit=document(row.audit_jcs,row.audit_digest),effect=document(row.effect_jcs,row.effect_digest),bindingRef=ref(row.device_binding_id,row.binding_digest);
 const source=denial(db.prepare(sourceSql+' WHERE d.snapshot_revision=?').raw().get(row.denial_revision));
 const recordRef=ref(id,row.record_digest);
 need(row.wire.equals(executionWire(row.wire.subarray(4)))&&bytesHash(row.wire)===row.wire_digest&&same(JSON.parse(row.wire.subarray(4)),frame)&&
  row.domain_kind==='run_fence'&&row.direction===(phase==='request'?'c2w':'w2c')&&row.message_type===(phase==='request'?'RUN_FENCE':'RUN_FENCE_ACK')&&
  row.message_type===frame.type&&row.device_id===frame.device_id&&row.message_id===frame.message_id&&row.sequence===executionTick(BigInt(frame.seq))&&
  row.observed_tick<=row.committed_tick&&row.disposition==='applied','integrity');
 for(const field of ['ipc_version','ipc_session_id','controller_boot_id','worker_boot_id','descriptor_digest','clock_domain_id'])
  need(frame[field]===binding[field],'integrity');
 need(same(record,{record_id:id,session_ref:ref(binding.ipc_session_id,digest(binding)),direction:row.direction,sequence:frame.seq,message_id:frame.message_id,
  message_type:frame.type,frame_digest:row.frame_digest,wire_digest:row.wire_digest,wire_length:row.wire.length,
  frame_object_ref:ref(id+'.frame',row.frame_digest),wire_object_ref:ref(id+'.wire',row.wire_digest),record_digest:row.record_digest})&&
  same(body,{transaction_id:row.transaction_id,record_ref:recordRef,binding_ref:bindingRef,source_revision:String(source.revision),rejection_digest:source.checksum})&&
  same(audit,{kind:'execution_run_fence_'+phase,domain_digest:row.domain_digest})&&
  same(effect,{record_ref:recordRef,disposition:'applied',domain_commit_refs:[ref(row.transaction_id,row.domain_digest)],
   audit_ref:ref(row.transaction_id+'.audit',row.audit_digest),reply_record_refs:[],committed_tick_ns:String(BigInt(row.committed_tick))}),'integrity');
 return {row,frame,recordRef,bindingRef,source};
}
function documentRecord(row){
 const record=JSON.parse(row.record_jcs),{record_digest,...unsigned}=record;
 need(canonical(record)===row.record_jcs&&record_digest===row.record_digest&&digest(unsigned)===record_digest,'integrity');
 return record;
}
function checkAck(request,frame,attempt,observed){
 const r=request.frame,body=r.body,b=frame.body;
 need(frame.type==='RUN_FENCE_ACK'&&frame.reply_to===r.message_id&&frame.device_id===r.device_id&&
  frame.journal_mode==='durable'&&attempt?.record_id===request.recordRef.id&&
  BigInt(b.effective_tick_ns)>=BigInt(attempt.started_tick)&&BigInt(b.effective_tick_ns)<=observed,'reply');
 const {coverage,transmission_coverage}=b;
 need(coverage.length===body.open_intents.length&&transmission_coverage.length===body.open_transmission_intents.length,'coverage');
 for(const [index,tx] of transmission_coverage.entries()){
  const {disposition,proof}=tx;
  need(same(tx.intent,body.open_transmission_intents[index])&&same(coverage[index],{intent:body.open_intents[index],disposition,proof})&&
   (disposition==='unknown'&&proof==='send_uncertain'||disposition==='in_flight'&&proof==='transport_entered'||
    disposition==='not_sent'&&['never_received','discarded_unconsumed'].includes(proof)),'coverage');
 }
 need(same(b,{operation_id:body.operation_id,barrier_id:body.barrier_id,controller_scope:body.controller_scope,selector:body.selector,
  selector_digest:body.selector_digest,issued_cut_revision:body.issued_cut_revision,target_deny_revision:body.target_deny_revision,ledger_digest:body.ledger_digest,
  coverage,transmission_coverage,all_write_exits_fenced:true,attempt_binding:body.attempt_binding,transmission_ledger_digest:body.transmission_ledger_digest,
  effective_tick_ns:b.effective_tick_ns,cancel_coverage:[],cancel_ledger_digest:body.cancel_ledger_digest}),'reply');
}
export function readRunFence(db,binding,id){
 need(db.inTransaction,'writer');
 const request=original(db,binding,id,'request'),{selector,barrier_id}=request.frame.body;
 const device=document(...db.prepare('SELECT body_jcs,body_digest FROM device_execution_binding WHERE binding_id=?').raw().get(request.bindingRef.id));
 need(request.row.reply_record_id===null&&request.frame.reply_to===null&&same(selector,request.source.selector)&&
  same(request.frame.body,frameBody({bound:{value:device},source:request.source,transmissions:request.frame.body.open_transmission_intents,
   issued:request.frame.body.issued_cut_revision},barrier_id)),'integrity');
 const ackId=db.prepare('SELECT record_id FROM execution_run_fence_frame WHERE request_record_id=?').pluck().get(id);
 const ack=ackId?original(db,binding,ackId,'ack'):null;
 if(ack){
  need(ack.row.reply_record_id===id&&same(ack.bindingRef,request.bindingRef)&&same(ack.source,request.source),'reply');
  checkAck(request,ack.frame,sqliteRow(db,'SELECT record_id,started_tick FROM execution_write_attempt WHERE attempt_id=?',ack.row.write_attempt_id),BigInt(ack.row.observed_tick));
 }
 return {request,ack};
}
export function currentRunFence(db,{binding,runtime,id}){
 const saved=readRunFence(db,binding,id),{request}=saved,{selector,barrier_id}=request.frame.body;
 const selected=currentSource(db,binding,runtime,{device_id:request.frame.device_id,origin_scope:selector.origin_scope,run_id:selector.run_id});
 need(!saved.ack&&same(selected.bound.ref,request.bindingRef)&&same(selected.source,request.source)&&
  same(frameBody({...selected,issued:request.frame.body.issued_cut_revision},barrier_id),request.frame.body),'changed');
 return saved;
}
export function acceptRunFence(db,{binding,decoded,features,tick,receivedTick}){
 const {frame,payload}=decoded;assertDeviceExecutionFeatures(frame,features);
 const id=db.prepare("SELECT record_id FROM execution_frame_record WHERE ipc_session_id=? AND direction='c2w' AND message_type='RUN_FENCE' AND message_id=?").pluck().get(binding.ipc_session_id,frame.reply_to);
 need(id,'reply');
 const {request,ack}=readRunFence(db,binding,id);
 if(ack){need(ack.row.wire.equals(executionWire(payload)),'replay');return {request,ack};}
 const attempt=sqliteRow(db,'SELECT attempt_id,record_id,started_tick FROM execution_write_attempt WHERE record_id=?',id);
 checkAck(request,frame,attempt,receivedTick);
 append(db,preparedFrame(binding,frame,payload,'w2c',receivedTick,id),'ack',request.source,request.bindingRef,tick(),attempt.attempt_id);
 return readRunFence(db,binding,id);
}
