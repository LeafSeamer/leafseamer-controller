import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {DeviceExecutionError} from './device-execution-channel.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const ref=(id,digest)=>({id,revision:'1',digest});
const counter=value=>{need(typeof value==='bigint'&&value>=0n&&value<=99999999999999999999n,'execution_frame_clock');return String(value).padStart(20,'0');};
function document(text,digest){const value=JSON.parse(text);need(canonicalize(value)===text&&hash(text)===digest,'execution_frame_integrity');return value;}

// 仅由核心领域writer在同一同步事务内调用；尚未连接的领域不能借通用回调写applied。
export function stageRejectedExecutionFrame(db,{binding,frame,wire,transaction,observedTick}){
 need(db.inTransaction,'execution_frame_transaction');
 const id=crypto.randomUUID(),text=canonicalize(frame),frameDigest=hash(text),wireDigest=hash(wire);
 const body={record_id:id,session_ref:ref(binding.ipc_session_id,hash(canonicalize(binding))),direction:'w2c',sequence:frame.seq,
  message_id:frame.message_id,message_type:frame.type,frame_digest:frameDigest,wire_digest:wireDigest,wire_length:wire.length,
  frame_object_ref:ref(id+'.frame',frameDigest),wire_object_ref:ref(id+'.wire',wireDigest)};
 const record={...body,record_digest:hash(canonicalize(body))};
 const domain={ipc_session_id:binding.ipc_session_id,message_id:frame.message_id,frame_digest:frameDigest,transaction_id:transaction,disposition:'rejected',reason:'unsupported_message'};
 const domainText=canonicalize(domain),domainDigest=hash(domainText);
 db.prepare('INSERT INTO execution_frame_record(record_id,ipc_session_id,direction,sequence,message_id,message_type,device_id,reply_record_id,wire,frame_jcs,wire_digest,frame_digest,record_jcs,record_digest,observed_tick,transaction_id,domain_kind) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,binding.ipc_session_id,'w2c',counter(BigInt(frame.seq)),
  frame.message_id,frame.type,frame.device_id,null,wire,text,wireDigest,frameDigest,canonicalize(record),record.record_digest,counter(observedTick),transaction,'hello_rejection');
 db.prepare('INSERT INTO execution_rejection_frame VALUES(?,?,?,?,?,?)').run(id,binding.ipc_session_id,frame.message_id,transaction,domainText,domainDigest);
 return Object.freeze({record,domain,domainDigest,observedTick,transaction});
}
export function sealRejectedExecutionFrame(db,staged,committedTick){
 need(db.inTransaction&&committedTick>=staged.observedTick,'execution_frame_transaction');
 const {record,domain,domainDigest,transaction}=staged;
 const audit={kind:'execution_rejection',ipc_session_id:domain.ipc_session_id,message_id:domain.message_id,frame_digest:domain.frame_digest,reason:domain.reason};
 const auditText=canonicalize(audit),auditDigest=hash(auditText);
 const effect={record_ref:ref(record.record_id,record.record_digest),disposition:'rejected',domain_commit_refs:[ref(transaction,domainDigest)],
  audit_ref:ref(transaction+'.audit',auditDigest),reply_record_refs:[],committed_tick_ns:String(committedTick)};
 const effectText=canonicalize(effect);
 db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(record.record_id,transaction,'rejected',counter(committedTick),auditText,auditDigest,effectText,hash(effectText));
}
export function executionFrameReceipt(db,sessionId,messageId){
 const row=db.prepare(`SELECT f.record_jcs,f.record_digest,f.frame_jcs,f.frame_digest,f.wire,f.wire_digest,f.sequence,f.observed_tick,
  e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,x.domain_jcs,x.domain_digest,f.transaction_id,s.binding_digest
  FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
  JOIN execution_rejection_frame x USING(record_id,transaction_id) JOIN execution_session s ON s.ipc_session_id=f.ipc_session_id
  WHERE f.ipc_session_id=? AND f.direction='w2c' AND f.message_id=?`).raw().get(sessionId,messageId);
 if(!row)return null;
 const [recordText,recordDigest,frameText,frameDigest,wire,wireDigest,sequence,observedTick,effectText,effectDigest,auditText,auditDigest,domainText,domainDigest,transaction,bindingDigest]=row;
 const record=JSON.parse(recordText),{record_digest,...unsigned}=record,frame=document(frameText,frameDigest),effect=document(effectText,effectDigest),
  audit=document(auditText,auditDigest),domain=document(domainText,domainDigest);
 need(canonicalize(record)===recordText&&record_digest===recordDigest&&hash(canonicalize(unsigned))===recordDigest&&
  wire.readUInt32BE(0)===wire.length-4&&hash(wire)===wireDigest&&canonicalize(JSON.parse(wire.subarray(4).toString('utf8')))===frameText,'execution_frame_integrity');
 need(record.session_ref.id===sessionId&&record.session_ref.revision==='1'&&record.session_ref.digest===bindingDigest&&record.direction==='w2c'&&
  record.sequence===frame.seq&&counter(BigInt(record.sequence))===sequence&&record.message_id===messageId&&frame.message_id===messageId&&frame.ipc_session_id===sessionId&&
  record.frame_digest===frameDigest&&record.wire_digest===wireDigest&&record.wire_length===wire.length&&record.message_type===frame.type&&
  canonicalize(record.frame_object_ref)===canonicalize(ref(record.record_id+'.frame',frameDigest))&&canonicalize(record.wire_object_ref)===canonicalize(ref(record.record_id+'.wire',wireDigest)),'execution_frame_integrity');
 need(canonicalize(effect.record_ref)===canonicalize(ref(record.record_id,recordDigest))&&effect.disposition==='rejected'&&effect.reply_record_refs.length===0&&
  canonicalize(effect.domain_commit_refs)===canonicalize([ref(transaction,domainDigest)])&&canonicalize(effect.audit_ref)===canonicalize(ref(transaction+'.audit',auditDigest))&&
  counter(BigInt(effect.committed_tick_ns))>=observedTick&&domain.transaction_id===transaction&&domain.ipc_session_id===sessionId&&domain.message_id===messageId&&
  domain.frame_digest===frameDigest&&domain.disposition==='rejected'&&domain.reason==='unsupported_message'&&audit.kind==='execution_rejection'&&audit.message_id===messageId&&
  audit.ipc_session_id===sessionId&&audit.frame_digest===frameDigest&&audit.reason===domain.reason,'execution_effect_integrity');
 return Object.freeze({record_id:record.record_id,record_digest:recordDigest,effect_digest:effectDigest,direction:record.direction,sequence:record.sequence,disposition:effect.disposition});
}
