import {digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {readCommandPreparationCleanup} from './command-preparation-cleanup.mjs';
import {readCommandGuard} from './command-guard.mjs';
import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('retired_history_'+code);};
// 历史释放证明只减少当前占用；原许可、命令、持有和累计扣费仍是永久账本。
export function readRetiredPreparation(db,reference){return withExecutionReadView(db,()=>memoExecutionRead(db,'retired-preparation',reference,()=>readRetired(db,reference)));}
function readRetired(db,reference){
 need(db.inTransaction,'writer');
 const id=db.prepare('SELECT permit_id FROM command_preparation_retirement WHERE prepare_id=?').pluck().get(reference?.id?.replace(/\.retirement$/,''));
 need(id,'missing');const saved=readCommandPreparationCleanup(db,id),s=saved.source;
 need(same(saved.ref,reference)&&s.terminal.succeeded&&saved.steps.release_ack,'unreleased');
 const release=db.prepare('SELECT command_id,commit_id,evidence_id FROM command_hold_release WHERE hold_id=?').raw().get(s.final.value.hold.hold_id);
 need(release&&release[0]===s.saved.source.command_id&&release[1]===s.terminal.value.commit_id&&
  s.terminal.value.evidence.some(v=>v.kind==='release'&&v.source_ref.id===release[2]),'hold');
 const guard=readCommandGuard(db,s.final.value.guard.guard_id),dispatch=s.closure.source.dispatch,ready=s.closure.source.ready;
 const outgoing=[s.encoding.request,guard.request,dispatch.request,s.closure.request,saved.steps.deny_request.frame,saved.steps.release_request.frame,ready.dispatch.request];
 return {...saved,outgoing:outgoing.map(v=>({id:v.record.record_id,revision:'1',digest:v.record.record_digest})),
  observation:dispatch.evidence.reply.frame.body.payload.observation.response};
}
export function retiredCommandHistory(db,binding){return withExecutionReadView(db,()=>memoExecutionRead(db,'retired-command-history',binding,()=>{
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=57,'version');
 const ids=db.prepare(`SELECT r.prepare_id,r.body_digest FROM command_preparation_retirement r
  JOIN command_final_admission a USING(permit_id,command_id) JOIN command_transmission_issue i USING(permit_id)
  JOIN device_execution_binding b USING(binding_id) WHERE b.device_id=? AND b.ipc_session_id=? ORDER BY i.issued_revision`).raw().all(binding.device_id,binding.ipc_session_id);
 const records=ids.map(([id,hash])=>readRetiredPreparation(db,{id:id+'.retirement',revision:'1',digest:hash}));
 for(const record of records)need(same(record.value.binding,binding),'binding');
 // 完成但尚未可靠清空缓存的命令不能从资源清单消失。
 const finished=db.prepare(`SELECT s.command_id FROM command_settlement s JOIN command_final_admission a USING(permit_id,command_id)
  JOIN device_execution_binding b USING(binding_id) WHERE b.device_id=? AND b.ipc_session_id=? ORDER BY s.command_id`).pluck().all(binding.device_id,binding.ipc_session_id);
 need(same(finished,records.map(v=>v.value.command_id).sort()),'incomplete');
 const outgoing=new Map();for(const record of records)for(const item of record.outgoing)outgoing.set(item.id,item);
 return {records,refs:records.map(v=>v.ref),commandIds:records.map(v=>v.value.command_id),outgoing,
  latest:records.at(-1)??null,digest:digest(records.map(v=>v.ref))};
}));}
