import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {DeviceExecutionError,executionWire} from './device-execution-channel.mjs';
import {deviceExecutionVersion,deviceExecutionCapabilities,selectDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {fixedWorkerExecutionAvailable} from './device-worker-execution.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(value).digest('hex');
const ref=(id,digest)=>({id,revision:'1',digest});
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
export const executionTick=value=>{need(typeof value==='bigint'&&value>=0n&&value<=99999999999999999999n,'execution_frame_clock');return String(value).padStart(20,'0');};
function document(text,digest){const value=JSON.parse(text);need(canonicalize(value)===text&&hash(text)===digest,'execution_handshake_integrity');return value;}
function row(db,sql,...parameters){const statement=db.prepare(sql),names=statement.columns().map(column=>column.name),values=statement.raw().get(...parameters);
 return values&&Object.fromEntries(names.map((name,index)=>[name,values[index]]));}

// 本模块只为成功握手提供领域写集，不提供任意消息的applied入口。
export function selectedHandshake(db,runtime,hello){
 const extension=runtime.launch_intent.extension_binding;
 const row=db.prepare('SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?').raw().get(extension.installation_ref.object_id);
 need(row,'execution_hello_module');const content=document(...row),manifest=content.manifest,inventory=content.inventory;
 need(hash(canonicalize(manifest))===extension.manifest_digest&&hash(canonicalize(inventory))===extension.artifact_set_digest,'execution_hello_module');
 const entry=manifest.entrypoints.find(value=>value.entry_id===extension.entry_id);
 const file=entry&&inventory.files.find(value=>value.file_id===entry.file_id);
 need(entry?.kind==='worker'&&entry.loader==='node_module'&&file?.role==='module'&&
  hello.body.module_id===manifest.extension_id&&hello.body.module_digest===file.digest,'execution_hello_module');
 // 固定内存模块和已接通的持久OPEN领域才选择普通组；其他入口仍须各自领域原件。
 return selectDeviceExecutionFeatures(hello.body.supported_features,[...deviceExecutionCapabilities.base,
  ...(Number(db.pragma('user_version',{simple:true}))>=31?deviceExecutionCapabilities.initial_control:[]),
  ...(Number(db.pragma('user_version',{simple:true}))>=47&&fixedWorkerExecutionAvailable({inventory},entry)?
   [...deviceExecutionCapabilities.manual,...deviceExecutionCapabilities.without_reference]:[])]);
}
export function handshakeAck(binding,hello,selected){
 return {ipc_version:deviceExecutionVersion,type:'HELLO_ACK',message_id:crypto.randomUUID(),reply_to:hello.message_id,
  ipc_session_id:binding.ipc_session_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,
  seq:'1',device_id:null,clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable',
  body:{selected_ipc_version:deviceExecutionVersion,clock_domain_id:binding.clock_domain_id,gate_state:'closed',selected_features:selected,
   descriptor_digest:binding.descriptor_digest,clock_domain_descriptor:hello.body.clock_domain_descriptor}};
}
export function preparedFrame(binding,frame,payload,direction,observedTick,replyRecord=null){
 const id=crypto.randomUUID(),transaction=crypto.randomUUID(),text=canonicalize(frame),wire=executionWire(payload);
 const body={record_id:id,session_ref:ref(binding.ipc_session_id,hash(canonicalize(binding))),direction,sequence:frame.seq,message_id:frame.message_id,
  message_type:frame.type,frame_digest:hash(text),wire_digest:hash(wire),wire_length:wire.length,
  frame_object_ref:ref(id+'.frame',hash(text)),wire_object_ref:ref(id+'.wire',hash(wire))};
 return {record:{...body,record_digest:hash(canonicalize(body))},transaction,frame,text,wire,observedTick,replyRecord};
}
export function insertFrame(db,item,domain='hello_negotiation'){const {record:r,frame:f}=item;
 need(db.prepare(`INSERT INTO execution_frame_record(record_id,ipc_session_id,direction,sequence,message_id,message_type,device_id,reply_record_id,
  wire,frame_jcs,wire_digest,frame_digest,record_jcs,record_digest,observed_tick,transaction_id,domain_kind) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .run(r.record_id,f.ipc_session_id,r.direction,executionTick(BigInt(f.seq)),f.message_id,f.type,f.device_id,item.replyRecord,item.wire,item.text,
   r.wire_digest,r.frame_digest,canonicalize(r),r.record_digest,executionTick(item.observedTick),item.transaction,domain).changes===1,'execution_handshake_storage');
}
export function commitHandshake(db,{binding,hello,payload,ack,observedTick,committedTick}){
 need(db.inTransaction&&committedTick>=observedTick,'execution_handshake_transaction');
 const incoming=preparedFrame(binding,hello,payload,'w2c',observedTick),outgoing=preparedFrame(binding,ack,Buffer.from(JSON.stringify(ack)),'c2w',observedTick,incoming.record.record_id);
 const id=crypto.randomUUID(),recordRef=item=>ref(item.record.record_id,item.record.record_digest);
 const body={negotiation_id:id,ipc_session_id:binding.ipc_session_id,module_id:hello.body.module_id,module_digest:hello.body.module_digest,
  selected_ipc_version:ack.body.selected_ipc_version,selected_features:ack.body.selected_features,gate_state:'closed',
  hello_record_ref:recordRef(incoming),ack_record_ref:recordRef(outgoing)};
 const bodyText=canonicalize(body),bodyDigest=hash(bodyText),audit={kind:'execution_handshake_closed',negotiation_id:id,body_digest:bodyDigest},auditText=canonicalize(audit),auditDigest=hash(auditText);
 insertFrame(db,incoming);insertFrame(db,outgoing);
 need(db.prepare('INSERT INTO execution_handshake VALUES(?,?,?,?,?,?,?,?,?,?)').run(binding.ipc_session_id,id,incoming.record.record_id,outgoing.record.record_id,
  incoming.transaction,outgoing.transaction,bodyText,bodyDigest,auditText,auditDigest).changes===1,'execution_handshake_storage');
 for(const item of [incoming,outgoing]){
  const domain={transaction_id:item.transaction,negotiation_ref:ref(id,bodyDigest)},domainText=canonicalize(domain),domainDigest=hash(domainText);
  need(db.prepare('INSERT INTO execution_handshake_frame VALUES(?,?,?,?,?)').run(item.record.record_id,item.transaction,id,domainText,domainDigest).changes===1,'execution_handshake_storage');
  const effect={record_ref:recordRef(item),disposition:'applied',domain_commit_refs:[ref(item.transaction,domainDigest)],audit_ref:ref(id+'.audit',auditDigest),
   reply_record_refs:item===incoming?[recordRef(outgoing)]:[],committed_tick_ns:String(committedTick)},effectText=canonicalize(effect);
  need(db.prepare('INSERT INTO execution_effect_commit VALUES(?,?,?,?,?,?,?,?)').run(item.record.record_id,item.transaction,'applied',executionTick(committedTick),
   auditText,auditDigest,effectText,hash(effectText)).changes===1,'execution_handshake_storage');
 }
}
export function readHandshake(db,sessionId){
 const stored=row(db,'SELECT * FROM execution_handshake WHERE ipc_session_id=?',sessionId);if(!stored)return null;
 const body=document(stored.body_jcs,stored.body_digest),audit=document(stored.audit_jcs,stored.audit_digest);
 need(body.ipc_session_id===sessionId&&body.negotiation_id===stored.negotiation_id&&body.gate_state==='closed'&&
  same(audit,{kind:'execution_handshake_closed',negotiation_id:stored.negotiation_id,body_digest:stored.body_digest}),'execution_handshake_integrity');
 const source=row(db,'SELECT binding_jcs,binding_digest FROM execution_session WHERE ipc_session_id=?',sessionId);
 need(source,'execution_handshake_integrity');const binding=document(source.binding_jcs,source.binding_digest),frames=[];
 for(const [id,transaction,direction] of [[stored.hello_record_id,stored.hello_transaction_id,'w2c'],[stored.ack_record_id,stored.ack_transaction_id,'c2w']]){
  const value=row(db,`SELECT f.*,e.effect_jcs,e.effect_digest,e.audit_jcs,e.audit_digest,e.committed_tick,
   x.domain_jcs,x.domain_digest FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
   JOIN execution_handshake_frame x USING(record_id,transaction_id) WHERE f.record_id=?`,id);
  need(value,'execution_handshake_integrity');const frame=document(value.frame_jcs,value.frame_digest),record=JSON.parse(value.record_jcs),{record_digest,...unsigned}=record;
  need(canonicalize(record)===value.record_jcs&&record_digest===value.record_digest&&hash(canonicalize(unsigned))===record_digest&&
   value.ipc_session_id===sessionId&&value.transaction_id===transaction&&value.domain_kind==='hello_negotiation'&&value.direction===direction&&
   value.sequence==='00000000000000000001'&&frame.seq==='1'&&frame.device_id===null&&frame.journal_mode==='durable'&&
   value.wire.readUInt32BE(0)===value.wire.length-4&&hash(value.wire)===value.wire_digest&&same(JSON.parse(value.wire.subarray(4)),frame),'execution_handshake_integrity');
  for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest','ipc_version'])need(frame[key]===binding[key],'execution_handshake_integrity');
  need(same(record,{record_id:id,session_ref:ref(sessionId,source.binding_digest),direction,sequence:'1',message_id:frame.message_id,message_type:frame.type,
   frame_digest:value.frame_digest,wire_digest:value.wire_digest,wire_length:value.wire.length,frame_object_ref:ref(id+'.frame',value.frame_digest),
   wire_object_ref:ref(id+'.wire',value.wire_digest),record_digest}),'execution_handshake_integrity');
  const domain=document(value.domain_jcs,value.domain_digest),effect=document(value.effect_jcs,value.effect_digest);
  need(same(domain,{transaction_id:transaction,negotiation_ref:ref(stored.negotiation_id,stored.body_digest)})&&value.audit_jcs===stored.audit_jcs&&value.audit_digest===stored.audit_digest&&
   same(effect,{record_ref:ref(id,record_digest),disposition:'applied',domain_commit_refs:[ref(transaction,value.domain_digest)],audit_ref:ref(stored.negotiation_id+'.audit',stored.audit_digest),
    reply_record_refs:direction==='w2c'?[body.ack_record_ref]:[],committed_tick_ns:String(BigInt(value.committed_tick))})&&value.committed_tick>=value.observed_tick,'execution_handshake_integrity');
  need(same(direction==='w2c'?body.hello_record_ref:body.ack_record_ref,ref(id,record_digest)),'execution_handshake_integrity');frames.push({frame,wire:Buffer.from(value.wire)});
 }
 const [hello,ack]=frames;
 need(hello.frame.type==='HELLO'&&hello.frame.reply_to===null&&ack.frame.type==='HELLO_ACK'&&ack.frame.reply_to===hello.frame.message_id&&
  body.module_id===hello.frame.body.module_id&&body.module_digest===hello.frame.body.module_digest&&ack.frame.body.gate_state==='closed'&&
  body.selected_ipc_version===ack.frame.body.selected_ipc_version&&same(body.selected_features,ack.frame.body.selected_features)&&
  same(body.selected_features,selectDeviceExecutionFeatures(hello.frame.body.supported_features,body.selected_features)),'execution_handshake_integrity');
 return {receipt:freeze({ref:ref(stored.negotiation_id,stored.body_digest),...body}),hello,ack};
}
