import {dispatchRiskFrame} from './command-dispatch.mjs';
import {guardOnlyFrame} from './command-guard.mjs';
import {encodingOnlyFrame} from './command-encoding-store.mjs';
import {readRetiredPreparation} from './command-retired-history.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {digest,same} from './auth-clock-value.mjs';
import {deviceExecutionCapabilities} from './sdk/device-execution.mjs';
import {pendingInitialCommands,readCommandRecord} from './command-record-store.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('initial_denials_'+code);};
const bytesDigest=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const allowed=new Set([...deviceExecutionCapabilities.base,...deviceExecutionCapabilities.manual,
 ...deviceExecutionCapabilities.initial_control,...deviceExecutionCapabilities.without_reference]);
const sealed=value=>({...value,snapshot_digest:digest(value)});

// schema44至52的实际受理器只接受人员manual，尚无运行保护/取消受理写集。
// schema49以后另允许已完整核验的同Ready排队后继；不模拟非空拒绝账本或推断未来版本。
function scope(db,service,current=false){
 need(db.inTransaction,'writer');
 const row=db.prepare('SELECT service_id,database_instance_id,schema_revision FROM service_state').raw().get();
 need(row&&row[0]===service.service_id&&row[1]===service.database_instance_id&&row[2]===service.schema_revision&&
  (current?['44','45','46','47','48','49','50','51','52','53','54','55','56','57','58'].includes(row[2]):Number(row[2])>=44),'schema');
 return {authority_service_id:row[0],database_instance_id:row[1]};
}
function frame(db,id){
 const row=db.prepare(`SELECT f.record_jcs,f.record_digest,f.frame_jcs,f.frame_digest,f.wire,f.wire_digest,
  f.message_type,f.ipc_session_id,f.sequence,s.binding_jcs,s.binding_digest,e.disposition
  FROM execution_frame_record f JOIN execution_session s USING(ipc_session_id)
  JOIN execution_effect_commit e USING(record_id,transaction_id) WHERE f.record_id=? AND f.direction='c2w'`).raw().get(id);
 need(row,'frame_missing');
 const [text,hash,bodyText,bodyHash,wire,wireHash,type,session,sequence,bindingText,bindingHash,disposition]=row;
 const record=JSON.parse(text),{record_digest,...unsigned}=record,value=JSON.parse(bodyText),binding=JSON.parse(bindingText);
 need(canonicalize(record)===text&&record_digest===hash&&digest(unsigned)===hash&&record.record_id===id&&
  canonicalize(value)===bodyText&&digest(value)===bodyHash&&canonicalize(binding)===bindingText&&digest(binding)===bindingHash&&
  wire.length>=5&&wire.readUInt32BE(0)===wire.length-4&&bytesDigest(wire)===wireHash&&
  canonicalize(JSON.parse(wire.subarray(4).toString('utf8')))===bodyText,'integrity');
 need(record.direction==='c2w'&&record.message_type===type&&value.type===type&&value.ipc_session_id===session&&
  record.session_ref.id===session&&record.session_ref.revision==='1'&&record.session_ref.digest===bindingHash&&
  record.sequence===value.seq&&String(BigInt(sequence))===value.seq&&record.message_id===value.message_id&&
  record.frame_digest===bodyHash&&record.wire_digest===wireHash&&record.wire_length===wire.length&&disposition==='applied','binding');
 need(type==='HELLO_ACK'||type==='FENCE','execution_history');
 if(type==='HELLO_ACK')need(value.body.selected_features.every(v=>allowed.has(v)),'features');
 else need(value.body.issued_cut_revision==='0'&&value.body.target_gate_revision==='1'&&value.body.attempt_binding.attempt_ordinal==='1'&&
  value.body.attempt_binding.previous_barrier_id===null&&value.body.open_intents.length===0&&
  value.body.open_transmission_intents.length===0&&value.body.cancel_transmissions.length===0,'fence_history');
 return {reference:{id,revision:'1',digest:hash},binding};
}
export function readInitialDenials(db,service,device,value){
 const expectedScope=scope(db,service);
 const successor=['initial-manual-deny-snapshots/2','initial-manual-deny-snapshots/3'].includes(value?.format);
 if(value?.format==='initial-manual-deny-snapshots/3'){
  need(['57','58'].includes(value.schema_revision)&&Array.isArray(value.retired_preparation_refs)&&value.retired_preparation_refs.length>0,'retired');
  for(const reference of value.retired_preparation_refs){const retired=readRetiredPreparation(db,reference);need(retired.value.binding.device_id===device,'retired');}
 }
 need((successor||value?.format==='initial-manual-deny-snapshots/1')&&['44','45','46','47','48','49','50','51','52','53','54','55','56','57','58'].includes(value.schema_revision)&&same(value.scope,expectedScope)&&
  value.device_id===device&&(successor?Array.isArray(value.pending_admission_refs)&&value.accepted_command_count===value.pending_admission_refs.length:value.accepted_command_count===0)&&Array.isArray(value.outgoing_frame_refs)&&
  value.outgoing_frame_refs.length>0&&value.outgoing_frame_refs.length<=4096,'source');
 if(successor){let last='';for(const ref of value.pending_admission_refs){const saved=readCommandRecord(db,ref.id);
  need(ref.id>last&&same(ref,{id:saved.record.command_id,revision:'1',digest:saved.source.initial_ref.digest})&&saved.source.binding.device_id===device,'admission');last=ref.id;}}
 let previous='';
 for(const reference of value.outgoing_frame_refs){
  need(typeof reference.id==='string'&&reference.id>previous,'order');previous=reference.id;
  const actual=frame(db,reference.id);need(same(actual.reference,reference)&&
   actual.binding.authority==='controller'&&actual.binding.service_id===expectedScope.authority_service_id&&actual.binding.database_instance_id===expectedScope.database_instance_id,'scope');
 }
 need(same(value.run_deny_snapshot,sealed({controller_scope:expectedScope,snapshot_revision:'0',entries:[]}))&&
  same(value.command_deny_snapshot,sealed({scope:expectedScope,device_id:device,snapshot_revision:'0',entries:[]})),'snapshot');
 return value;
}
export function captureInitialDenials(db,service,device,ownOpen=null,ready=null,preparedRef=null,history=null){
 const selectedScope=scope(db,service,true);
 const pending=[49,50,51,52,53,54,55,56,57,58].includes(Number(service.schema_revision))?pendingInitialCommands(db,ready,preparedRef,history?.commandIds):[];
 if(![49,50,51,52,53,54,55,56,57,58].includes(Number(service.schema_revision)))need(!db.prepare('SELECT 1 FROM ca_command_initial LIMIT 1').pluck().get(),'command_history');
 const rows=db.prepare("SELECT record_id,message_type FROM execution_frame_record WHERE direction='c2w' ORDER BY record_id COLLATE BINARY LIMIT 4097").raw().all();
 need(rows.length>0&&rows.length<=4096,'capacity');
 // 只有资源当前性检查已核对的本次OPEN可排除；其他设备或其他业务帧仍严格拒绝。
 if(ownOpen){const actual=db.prepare("SELECT record_digest,device_id FROM execution_frame_record WHERE record_id=? AND domain_kind='initial_open' AND direction='c2w' AND message_type='OPEN_GATE'").raw().get(ownOpen.id);
  need(actual&&ownOpen.revision==='1'&&actual[0]===ownOpen.digest&&actual[1]===device,'open_frame');}
 const encoding=new Set(history?.outgoing.keys()??[]);
 for(const [id]of rows)if(encoding.has(id)){const actual=db.prepare('SELECT record_digest FROM execution_frame_record WHERE record_id=?').pluck().get(id);need(actual===history.outgoing.get(id).digest,'retired_frame');}
 for(const [id,type] of rows)if(type==='ENCODE_PACKET'&&!encoding.has(id)){need(ready,'encoding_ready');encodingOnlyFrame(db,id,ready.value.binding,ready.ref);encoding.add(id);}
 for(const [id,type] of rows)if(type==='GUARD_INSTALL'&&!encoding.has(id)){need(ready,'guard_ready');guardOnlyFrame(db,id,ready.value.binding,preparedRef);encoding.add(id);}
 for(const [id,type] of rows)if(type==='DISPATCH'&&!encoding.has(id)){need(ready,'dispatch_ready');dispatchRiskFrame(db,id,ready.value.binding,preparedRef);encoding.add(id);}
 const value={format:[49,50,51,52,53,54,55,56,57,58].includes(Number(service.schema_revision))?'initial-manual-deny-snapshots/2':'initial-manual-deny-snapshots/1',schema_revision:service.schema_revision,scope:selectedScope,device_id:device,accepted_command_count:pending.length,
  ...([49,50,51,52,53,54,55,56,57,58].includes(Number(service.schema_revision))?{pending_admission_refs:pending}:{}),
  outgoing_frame_refs:rows.filter(([id])=>id!==ownOpen?.id&&!encoding.has(id)).map(([id])=>frame(db,id).reference),
  run_deny_snapshot:sealed({controller_scope:selectedScope,snapshot_revision:'0',entries:[]}),
  command_deny_snapshot:sealed({scope:selectedScope,device_id:device,snapshot_revision:'0',entries:[]})};
 if(history?.records.length){value.format='initial-manual-deny-snapshots/3';value.retired_preparation_refs=history.refs;}
 return readInitialDenials(db,service,device,value);
}
