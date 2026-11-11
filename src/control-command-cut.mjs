import {controlNeed as need,controlHash as hash,controlSame as same} from './device-control-value.mjs';
import canonicalize from 'canonicalize';
import {readCommandRecord,readCommandRevision,closeQueuedCommand} from './command-record-store.mjs';
import {readCommandFinalAdmission} from './command-final-admission.mjs';
import {readCommandDispatch} from './command-dispatch.mjs';
import {withExecutionReadView} from './execution-read-view.mjs';

const ref=(id,value)=>({id,revision:'1',digest:hash(value)});
const recordRef=record=>({id:record.command_id,revision:record.revision,digest:record.record_digest});
const ids=(db,device)=>db.prepare('SELECT command_id FROM command_admission_source WHERE device_id=? ORDER BY command_id').pluck().all(device);
function transmission(db,saved){
 const row=db.prepare('SELECT transaction_id,body_digest FROM command_final_admission WHERE command_id=?').raw().get(saved.source.command_id);
 if(!row)return null;
 const initial=readCommandRevision(db,saved.source.command_id,'1'),final=readCommandFinalAdmission(db,initial,{id:row[0],revision:'1',digest:row[1]}),value=final.value;
 return {final_ref:final.ref,permit_id:value.permit.permit_id,issued_revision:value.seal.issued_revision,transmission:value.permit.transmission,
  hold_id:value.hold.hold_id};
}
function source(db,operation,commit){
 const commandIds=ids(db,operation.device_id);need(commandIds.length<=4096,'command_cut_capacity');
 const adjudicated=db.prepare("SELECT a.command_id FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=? AND a.decision!='rejected' ORDER BY a.command_id").pluck().all(operation.device_id);
 need(same(commandIds,adjudicated),'command_cut_admissions');
 const commands=commandIds.map(id=>{const saved=readCommandRecord(db,id);return {command_ref:recordRef(saved.record),binding_ref:saved.source.binding_ref,
  binding:saved.source.binding,queued:saved.record.state.phase==='queued'&&saved.record.attempts.length===0,transmission:transmission(db,saved)};});
 const water=db.prepare('SELECT max(issued_revision) FROM command_transmission_issue').pluck().get()??'0';
 return {format:'control-command-cut/1',operation_id:operation.operation_id,device_id:operation.device_id,commit_id:commit,
  expected_control:operation.expected_control,target:operation.target,issued_revision:String(BigInt(water)),commands};
}
// T3与控制版本预留共用writer；捕获全部命令及已签发传输，完成历史也不从切点省略。
export function captureControlCommands(db,operation,commit,bootId){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=58,'command_cut_writer');
 const value=withExecutionReadView(db,()=>source(db,operation,commit)),reference=ref(operation.operation_id+'.commands',value);
 need(db.prepare('INSERT INTO control_command_cut VALUES(?,?,?,?,?)').run(operation.operation_id,operation.device_id,commit,canonicalize(value),reference.digest).changes===1,'command_cut_storage');
 for(const item of value.commands)if(item.queued)closeQueuedCommand(db,item.command_ref.id,{bootId,controlCut:reference});
 return reference;
}
export function readControlCommandCut(db,operation){
 return withExecutionReadView(db,()=>readCut(db,operation));
}
function readCut(db,operation){
 need(db.inTransaction,'command_cut_writer');
 const row=db.prepare('SELECT device_id,commit_id,body_jcs,body_digest FROM control_command_cut WHERE operation_id=?').raw().get(operation.operation_id);
 need(row,'command_cut_missing');const value=JSON.parse(row[2]);
 need(canonicalize(value)===row[2]&&hash(value)===row[3]&&value.format==='control-command-cut/1'&&value.operation_id===operation.operation_id&&
  row[0]===operation.device_id&&value.device_id===row[0]&&value.commit_id===row[1]&&same(value.expected_control,operation.expected_control)&&same(value.target,operation.target),'command_cut_integrity');
 for(const item of value.commands){
  const saved=readCommandRevision(db,item.command_ref.id,item.command_ref.revision);
  need(same(recordRef(saved.record),item.command_ref)&&same(saved.source.binding_ref,item.binding_ref)&&same(saved.source.binding,item.binding)&&
   item.queued===(saved.record.state.phase==='queued'&&saved.record.attempts.length===0)&&same(transmission(db,saved),item.transmission),'command_cut_source');
  if(item.transmission)need(BigInt(item.transmission.issued_revision)<=BigInt(value.issued_revision),'command_cut_watermark');
 }
 return {value,ref:{id:operation.operation_id+'.commands',revision:'1',digest:row[3]}};
}
// 退役只证明旧出口不能再写；它不证明设备效果已消除，未核销hold与累计扣费保持原样。
export function classifyControlCommands(db,operation){
 return withExecutionReadView(db,()=>classify(db,operation));
}
function classify(db,operation){
 const cut=readControlCommandCut(db,operation),commands=[];
 need(same(cut.value.commands.map(v=>v.command_ref.id),ids(db,operation.device_id)),'command_cut_coverage');
 for(const item of cut.value.commands){
  const current=readCommandRecord(db,item.command_ref.id);let disposition='not_issued',reportRef=null;
  if(item.transmission){
   disposition='unknown';
   const exists=db.prepare('SELECT 1 FROM command_dispatch_request WHERE permit_id=?').pluck().get(item.transmission.permit_id);
   if(exists){const dispatch=readCommandDispatch(db,item.transmission.permit_id);
    if(dispatch.report){reportRef=dispatch.report.ref;if(dispatch.report.reply.frame.body.disposition==='in_flight')disposition='in_flight';}
   }
  }else need(current.record.state.phase==='finished'&&current.record.state.effect_status==='not_sent'&&current.record.state.resource_status==='clear','command_cut_queued');
  commands.push({command_ref:recordRef(current.record),permit_id:item.transmission?.permit_id??null,disposition,report_ref:reportRef,
   resource_status:current.record.state.resource_status,resource_evidence_refs:current.record.state.resource_evidence_refs});
 }
 return {cut_ref:cut.ref,commands};
}
