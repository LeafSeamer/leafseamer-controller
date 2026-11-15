import {canonical,digest,checked,ref,same} from './auth-clock-value.mjs';
import {sessionDenialNotice,sessionDenialReceipt} from './peer-session-denial.mjs';
import {IdentityError} from './identity-error.mjs';
import {pairingUuid,pairingReference} from './peer-pairing-value.mjs';
const need=(ok,code)=>{if(!ok)throw new Error('session_denial_'+code);};
// 可信通知任务消费已有outbox；不创建撤销，不依赖已撤销人员再次登录。
export function sessionDenialStore({db,service,writer,pairings}){
 function notice(operationId,bindingRef){
  const record=pairings().requireActivatedInTransaction(bindingRef),local=record.transcript.parties.find(p=>p.service_id===service.service_id),target=record.transcript.parties.find(p=>p.service_id===record.peer_service_id);
  if(!local.permissions.includes('auth.revoke')||target.service_kind!=='seamer')throw new IdentityError('session_denial_purpose');
  const row=db.prepare('SELECT r.body,r.digest,r.session_id,r.revision_floor,s.state,s.terminal_operation_id,s.revision FROM session_revocation r JOIN session_revocation_outbox o USING(operation_id) JOIN auth_session s ON s.session_id=r.session_id WHERE r.operation_id=? AND o.target_service_id=?').raw().get(operationId,target.service_id);
  need(row,'outbox');const original=checked(JSON.parse(row[0].toString()));
  need(original.format==='session-revocation/1'&&original.id===operationId&&original.session_id===row[2]&&original.revision_floor===String(row[3])&&
   ['revoked','expired'].includes(row[4])&&row[5]===operationId&&String(row[6])===original.revision_floor&&original.digest===row[1]&&canonical(original)===row[0].toString()&&
   original.issuer_id===local.issuer_id&&original.issuer_epoch===local.issuer_epoch&&original.target_service_ids.includes(target.service_id),'source');
  const floor=db.prepare('SELECT revision_floor,operation_id FROM session_revocation_floor WHERE session_id=?').raw().get(original.session_id);
  need(floor&&String(floor[0])===original.revision_floor&&floor[1]===original.id,'source');
  return sessionDenialNotice({format:'leafseamer.session-denial/1',issuer_scope:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id},
   issuer_id:original.issuer_id,issuer_epoch:original.issuer_epoch,operation_ref:ref(original),session_id:original.session_id,revision_floor:original.revision_floor,
   target_scope:{authority_service_id:target.service_id,database_instance_id:target.database_instance_id}});
 }
 const api={
  scan({after=null,limit=16}={}){
   need(Number.isInteger(limit)&&limit>=1&&limit<=64,'page');
   if(after!==null){need(Array.isArray(after)&&after.length===3,'cursor');after.forEach(pairingUuid);}
   return writer(()=>{
    const rows=db.prepare(`SELECT o.operation_id,o.target_service_id,r.binding_id FROM session_revocation_outbox o
     JOIN peer_pairing_revision r ON r.peer_service_id=o.target_service_id
     JOIN peer_pairing_head h ON h.binding_id=r.binding_id AND h.revision=r.revision
     WHERE r.state='activated' AND (o.operation_id,o.target_service_id,r.binding_id)>(?,?,?)
     ORDER BY o.operation_id,o.target_service_id,r.binding_id LIMIT ?`).raw().all(...(after??['','','']),limit);
    return {items:rows.map(([operation_id,target_service_id,binding_id])=>({operation_id,target_service_id,binding_id})),
     next:rows.length===limit?rows.at(-1):null};
   });
  },
  async deliverPending(task,transport){
   const record=pairings().currentPending(task.binding_id),bindingRef=pairingReference(record);
   need(record.peer_service_id===task.target_service_id,'target');
   const prior=writer(()=>{
    const value=notice(task.operation_id,bindingRef),scope=value.target_scope;
    const row=db.prepare('SELECT notice_digest,body_jcs,body_digest FROM session_denial_receipt WHERE operation_id=? AND target_service_id=? AND target_database_instance_id=?').raw().get(task.operation_id,scope.authority_service_id,scope.database_instance_id);
    if(!row)return null;
    const receipt=sessionDenialReceipt(JSON.parse(row[1]),value);
    need(row[0]===digest(value)&&row[1]===canonical(receipt)&&row[2]===digest(receipt),'receipt_integrity');return receipt;
   });
   if(prior)return {state:'acknowledged',receipt:prior};
   return {state:'delivered',receipt:await api.deliver(task.operation_id,bindingRef,transport)};
  },
  prepare(operationId,bindingRef){return writer(()=>notice(operationId,bindingRef));},
  acknowledge(operationId,bindingRef,response){return writer(()=>{
   const value=notice(operationId,bindingRef),receipt=sessionDenialReceipt(response,value),key=[operationId,value.target_scope.authority_service_id,value.target_scope.database_instance_id];
   const old=db.prepare('SELECT body_jcs,body_digest FROM session_denial_receipt WHERE operation_id=? AND target_service_id=? AND target_database_instance_id=?').raw().get(...key);
   if(old){need(old[0]===canonical(receipt)&&old[1]===digest(receipt),'receipt_conflict');return receipt;}
   need(db.prepare('SELECT count(*) FROM session_denial_receipt').pluck().get()<16384,'capacity');
   need(db.prepare('INSERT INTO session_denial_receipt VALUES(?,?,?,?,?,?)').run(...key,digest(value),canonical(receipt),digest(receipt)).changes===1,'write');
   need(same(notice(operationId,bindingRef),value),'changed');return receipt;
  });},
  async deliver(operationId,bindingRef,transport){const value=api.prepare(operationId,bindingRef),receipt=await transport.deliverSessionDenial(bindingRef.id,value);return api.acknowledge(operationId,bindingRef,receipt);}
 };
 return Object.freeze(api);
}
