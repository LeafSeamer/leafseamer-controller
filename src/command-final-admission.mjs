import {sqliteRow} from './sqlite-rows.mjs';
import {cacheVerifiedDocument} from './verified-document-cache.mjs';
import crypto from 'node:crypto';
import {withExecutionReadView,memoExecutionRead} from './execution-read-view.mjs';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {selectCommandFinalization,readCommandEncoding} from './command-encoding-store.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
import {preparedCommandProjection,readCommandRecord} from './command-record-store.mjs';
import {deviceExecutionVersion,assertDeviceExecutionFeatures} from './sdk/device-execution.mjs';
import {routes} from './sdk/runtime/panel-wire/preview/routes.mjs';
import {getSchema,validateValue} from './sdk/runtime/panel-wire/preview/registry.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_final_'+code);};
const ref=(id,v)=>({id,revision:'1',digest:digest(v)});
const signed=(v,key)=>({...v,[key]:digest(v)});
const named=(v,id,key,revision='1')=>({id:v[id],revision,digest:v[key]});
const parse=cacheVerifiedDocument((text,hash)=>{const v=JSON.parse(text);need(canonical(v)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'integrity');return v;});
const counter=v=>String(v).padStart(20,'0');
const limits={format:'fixed-memory-transmission-budget/1',profile_id:'leafseamer.simulator.transmission.limits.1',max_transmissions:4096,max_bytes:32768,per_transmission:{attempts:1,transmissions:1,bytes:8}};
const row=sqliteRow;
function principal(db,encoding){
 const saved=row(db,'SELECT authorization_body,authorization_digest FROM access_token WHERE token_id=?',encoding.value.identity_snapshot.identity.token_id);
 need(saved,'authorization');const value=JSON.parse(saved.authorization_body.toString()),{digest:hash,...body}=value;
 need(canonical(value)===saved.authorization_body.toString()&&digest(body)===hash&&saved.authorization_digest===hash&&
  hash===encoding.value.identity_snapshot.identity.authorization_digest,'authorization');
 return value;
}
function materialize({initial,encoding,ready,grant,ids,issue,previous,before,selected,sealed}){
 const source=initial.source,command=source.command_id,b=source.binding,opening=ready.dispatch.plan,access=opening.access,packet=encoding.response.reply.frame.body.packet;
 const expires=encoding.value.authorization.expires_tick_ns,window={not_before_tick_ns:selected,before_tick_ns:expires};
 need(BigInt(encoding.response.value.evidence.received_tick_ns)<=BigInt(selected)&&encoding.response.reply.committedTick<=BigInt(selected)&&
  BigInt(selected)<=BigInt(sealed)&&BigInt(sealed)<BigInt(expires),'deadline');
 need(BigInt(issue)===BigInt(previous)+1n&&BigInt(issue)<=18446744073709551615n&&Number.isSafeInteger(before)&&before>=0&&before<limits.max_transmissions,'budget');
 const state={...initial.record.state,revision:'2',resource_status:'held',attempt_ids:[packet.attempt_id]},stateRef={...ref(command+'_state_2',state),revision:'2'};
 const exit=Object.fromEntries(['device_id','controller_boot_id','worker_boot_id','ipc_session_id','device_session_id','clock_domain_id','descriptor_digest'].map(k=>[k,b[k]]));exit.exit_id=b.writer_exit_id;
 const packetRef={packet_id:packet.packet_id,packet_digest:packet.packet_digest},packetRecordRef={id:packet.packet_id,revision:'1',digest:packet.packet_digest};
 const attempt={attempt_id:packet.attempt_id,command_id:command,ordinal:1,prepared_state_ref:stateRef,exit_ids:[exit.exit_id],packet_refs:[packetRef],encoding_ref:encoding.ref};
 const identity={kind:'ordinary',command_ref:{id:command,revision:'1',digest:source.initial_ref.digest},attempt_ref:ref(packet.attempt_id,attempt),
  cancellation_ref:null,execution_ref:null,requester:{kind:'human',issuer_id:grant.issuer_id,issuer_epoch:grant.issuer_epoch,principal_id:grant.principal_id},origin:'manual',source_ref:source.admission_ref};
 const hold={format:'command-risk-hold/1',hold_id:ids.hold,command_id:command,attempt_id:packet.attempt_id,binding:b,conflict_scope:'whole_device',created_tick_ns:selected,admission_ref:source.admission_ref},holdRef=ref(ids.hold,hold);
 const ownerFields={scope:b.scope,device_id:b.device_id,
  hold_ref:holdRef,identity,control_authority_ref:access.control_authority_ref,control_epoch:access.control_epoch,effective_version:access.effective_version,
  clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,acquired_tick_ns:selected};
 // 回执先封存归属业务字段，不引用Ownership摘要；受理裁决本身不冒充包含新hold的来源回执。
 const ownerReceipt={format:'command-ownership-receipt/1',receipt_id:ids.ownership+'.source',transaction_id:ids.transaction,
  admission_source_ref:encoding.value.authorization.admission_source_ref,adjudication_ref:source.admission_ref,content:ownerFields};
 const ownership=signed({format_version:'hold-ownership/0.1.0-draft.1',ownership_id:ids.ownership,revision:'1',...ownerFields,
  source_receipt_ref:ref(ownerReceipt.receipt_id,ownerReceipt)},'ownership_digest');
 const ownershipRef=named(ownership,'ownership_id','ownership_digest'),accessRef=named(access,'access_id','access_digest',access.revision);
 const authorizationBinding={issuer_id:grant.issuer_id,issuer_epoch:grant.issuer_epoch,audience:grant.audience,principal_kind:'human',principal_id:grant.principal_id,origin:'manual',
  session_id:grant.session_id,credential_id:grant.credential_id,subject_revision:grant.subject_revision,session_revision:grant.session_revision,policy_revision:grant.policy_revision,
  scope_digest:grant.scope_digest,grant_id:null,grant_revision:null,arm_generation:null,extension_instance_id:null,extension_approval_revision:null};
 const guard=signed({guard_id:ids.guard,permit_id:ids.permit,command_id:command,device_id:b.device_id,controller_boot_id:b.controller_boot_id,worker_boot_id:b.worker_boot_id,
  ipc_session_id:b.ipc_session_id,binding:authorizationBinding,authorization_revision:access.authorization_ref.revision,authorization_deadline_tick_ns:expires,
  clock_domain_id:b.clock_domain_id,time_required:false,capacity_reservation_id:ids.budget,descriptor_digest:b.descriptor_digest,
  admission_origin:'non_panel',panel_binding:null,automation_binding:null,reference_time:null,gate_access_ref:accessRef,ownership_ref:ownershipRef},'guard_digest');
 const guardRef=named(guard,'guard_id','guard_digest'),wireWindow={clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,earliest_tick_ns:selected,latest_tick_ns:expires};
 const intent={permit_id:ids.permit,command_id:command,attempt_id:packet.attempt_id,dispatch_intent_id:ids.intent,worker_boot_id:b.worker_boot_id,device_session_id:b.device_session_id,
  guard_id:ids.guard,guard_digest:guard.guard_digest,clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,controller_boot_id:b.controller_boot_id,
  ipc_session_id:b.ipc_session_id,device_id:b.device_id,admission_origin:'non_panel',panel_binding_digest:null,origin:'manual',automation_binding:null,automation_binding_digest:null};
 const permit={permit_id:ids.permit,command_id:command,attempt_id:packet.attempt_id,dispatch_intent_id:ids.intent,controller_boot_id:b.controller_boot_id,worker_boot_id:b.worker_boot_id,
  device_session_id:b.device_session_id,control_epoch:access.control_epoch,control_version:access.effective_version,authorization_revision:access.authorization_ref.revision,
  origin:'manual',grant_revision:null,arm_generation:null,gate_revision:ready.value.gate_after.gate_revision,deadline_policy:source.metadata.dispatch,
  content_digest:source.metadata.request_identity.request_digest,guard_id:ids.guard,guard_digest:guard.guard_digest,clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,
  admission_origin:'non_panel',panel_binding_digest:null,automation_binding:null,
  transmission:{transmission_id:ids.transmission,packet_ref:packetRef,primitive_id:packet.primitive_id,intent,ordinal:'0',kind:'initial',cause:'dispatch',trigger_observation_ref:null,
   parent_dispatch_intent_id:ids.intent,initial_permit_id:ids.permit,issued_revision:issue,send_window:wireWindow},budget_revision:issue,gate_access_ref:accessRef,ownership_ref:ownershipRef};
 const authority=signed({format_version:'permit-authority/0.1.0-draft.1',permit_id:ids.permit,issued_revision:issue,identity,binding:b,hold_ref:holdRef,ownership_ref:ownershipRef,
  control_authority_ref:access.control_authority_ref,control_epoch:access.control_epoch,effective_version:access.effective_version,authorization_ref:access.authorization_ref,guard_ref:guardRef,
  packet_ref:packetRecordRef,ordinal:'0',selected_tick_ns:selected,expires_tick_ns:expires},'authority_digest');
 const charge={format:'command-transmission-charge/1',charge_id:ids.budget,transaction_id:ids.transaction,permit_id:ids.permit,issued_revision:issue,previous_revision:previous,
  command_id:command,device_id:b.device_id,profile:limits,charged:limits.per_transmission,before_count:before,after_count:before+1,selected_tick_ns:selected,window};
 const {state_digest:_before,...resourceBody}=opening.resource;
 need(resourceBody.holds.length===0,'resource');
 const after=signed({...resourceBody,format_version:'command-resource-state/1',state_id:ids.resource,revision:'2',control_state_ref:ready.value.control_after_ref,
  sampled_tick_ns:selected,holds:[{hold_ref:holdRef,ownership_ref:ownershipRef,classification:'active'}]},'state_digest');
 const time={format:'command-transmission-time/1',time_id:ids.time,binding:b,permit_id:ids.permit,issued_revision:issue,original_deadline_ref:initial.record.policy.original_deadline_ref,
  authentication_window:encoding.value.identity_snapshot.authentication_window,reference_time:null,window};
 const sources={origin:encoding.value.authorization.admission_source_ref,capability:encoding.bound.capability_ref,
  encoding:named(encoding.response.value.evidence,'evidence_id','evidence_digest'),authorization:access.authorization_ref,control:access.control_authority_ref,
  gate_commit:ready.ref,gate_access:accessRef,ownership:ownershipRef,permit_authority:named(authority,'permit_id','authority_digest',issue),guard:guardRef,
  budget:ref(ids.budget,charge),time:ref(ids.time,time),resource_before:named(opening.resource,'state_id','state_digest',opening.resource.revision),
  resource_after:named(after,'state_id','state_digest',after.revision),resource_safety:access.resource_safety_ref,gate_safety:access.gate_safety_ref,
  run_deny:{id:opening.id+'.run-deny',revision:opening.resource.run_deny_snapshot.snapshot_revision,digest:opening.resource.run_deny_snapshot.snapshot_digest},
  command_deny:{id:opening.id+'.command-deny',revision:opening.resource.command_deny_snapshot.snapshot_revision,digest:opening.resource.command_deny_snapshot.snapshot_digest}};
 const fields={origin:{command_state_ref:initial.record.state_ref},capability:{encoding_source_ref:sources.encoding},
  encoding:{packet_record_ref:packetRecordRef,packet_ref:packetRef,received_tick_ns:encoding.response.value.evidence.received_tick_ns,expires_tick_ns:expires},
  authorization:{not_before_tick_ns:encoding.value.authorization.created_tick_ns,before_tick_ns:expires},
  control:{pending_operation_id:null,control_epoch:access.control_epoch,effective_version:access.effective_version,mode:'manual',holder:identity.requester},
  gate_commit:{access_ref:accessRef},gate_access:{purpose:'ordinary',restricted_identity:null,control_authority_ref:access.control_authority_ref,control_epoch:access.control_epoch,
   effective_version:access.effective_version,authorization_ref:access.authorization_ref,resource_safety_ref:access.resource_safety_ref,gate_safety_ref:access.gate_safety_ref,
   not_before_tick_ns:access.selected_tick_ns,before_tick_ns:access.expires_tick_ns},
  ownership:{hold_ref:holdRef,control_authority_ref:access.control_authority_ref,control_epoch:access.control_epoch,effective_version:access.effective_version},
  permit_authority:{hold_ref:holdRef,permit_id:ids.permit,issued_revision:issue,ordinal:'0',transmission_id:ids.transmission,ownership_ref:ownershipRef,
   control_authority_ref:access.control_authority_ref,authorization_ref:access.authorization_ref,guard_ref:guardRef,packet_ref:packetRecordRef,control_epoch:access.control_epoch,effective_version:access.effective_version},
  guard:{permit_id:ids.permit,issued_revision:issue,packet_ref:packetRef,gate_access_ref:accessRef,ownership_ref:ownershipRef,protection_assessment_ref:null,...window},
  budget:{permit_id:ids.permit,issued_revision:issue,charge_kind:'new_transmission',charged_permit_id:ids.permit,...window},
  time:{permit_id:ids.permit,issued_revision:issue,clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,...window},
  resource_before:{resource_safety_ref:access.resource_safety_ref,holds:[]},resource_after:{resource_safety_ref:access.resource_safety_ref,holds:after.holds},
  resource_safety:{},gate_safety:{},run_deny:{},command_deny:{}};
 const projections=Object.fromEntries(Object.entries(fields).map(([role,extra])=>{const value={role,source_ref:sources[role],scope:b.scope,transaction_id:ids.transaction,body:{binding:b,identity,...extra}};
  return [role,{...value,ref:ref(ids.transaction+'.'+role,value)}];}));
 const seal=signed({format_version:'final-admission/0.1.0-draft.1',seal_id:ids.seal,revision:'1',transaction_id:ids.transaction,binding:b,identity,command_state_ref:initial.record.state_ref,
  permit_id:ids.permit,transmission_id:ids.transmission,issued_revision:issue,ordinal:'0',transmission_kind:'initial',previous_permit_ref:null,packet_ref:packetRef,
  encoding_packet_ref:packetRecordRef,hold_ref:holdRef,hold_transition:'create',inputs:{...Object.fromEntries(Object.entries(projections).map(([r,p])=>[r,p.ref])),
   ordinary_closure:null,protection_assessment:null,primitive_dependency:null},selected_tick_ns:selected,sealed_tick_ns:sealed,send_window:window},'seal_digest');
 const inventory={format:'command-attempt-inventory/1',command_id:command,revision:'2',state_ref:stateRef,attempt,exit,packet_ref:packetRef,
  encoding_ref:encoding.ref,encoding_response_ref:encoding.response.ref,permit_ref:ref(ids.permit,permit),reports:[],evidence:[]};
 return {format:'command-final-admission/1',transaction_id:ids.transaction,command_id:command,prepare_id:encoding.value.prepare_id,commit_id:ids.commit,ids,
  encoding_ref:encoding.ref,encoding_response_ref:encoding.response.ref,principal_authorization_ref:named(grant,'id','digest',grant.revision),
  hold,ownership_receipt:ownerReceipt,ownership,attempt,inventory,resource_after:after,transmission_charge:charge,guard,permit,permit_authority:authority,time,projections,seal};
}
function validatePayloads(value,encoding,ready,features){
 const b=value.seal.binding,request=encoding.request.frame.body.request;
 const bodies={GUARD_INSTALL:{guard:value.guard,content_digest:value.permit.content_digest,schedule_guard:null,reference_context:null},
  DISPATCH:{permit:value.permit,gate_token:ready.value.gate_after.gate_token,send_window:value.permit.transmission.send_window,request,
   parameters_schema_digest:encoding.bound.action.parameters_schema_digest,guard_id:value.guard.guard_id,guard_digest:value.guard.guard_digest,
   prepare_id:encoding.value.prepare_id,packet:encoding.response.reply.frame.body.packet,resend_request_id:null}};
 for(const [type,body]of Object.entries(bodies)){
  // 这里只校验待签发正文；该对象没有出站日志或发送尝试，不能作为线路帧使用。
  const frame={ipc_version:deviceExecutionVersion,type,message_id:value.transaction_id,reply_to:null,seq:'1',device_id:b.device_id,
   ipc_session_id:b.ipc_session_id,controller_boot_id:b.controller_boot_id,worker_boot_id:b.worker_boot_id,clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest,journal_mode:'durable',body};
  const numbers=new Map(),walk=(v,p)=>{if(typeof v==='number')numbers.set(p,{integer:Number.isInteger(v),safe:Number.isSafeInteger(v)});
   else if(v&&typeof v==='object')for(const [k,x]of Object.entries(v))walk(x,p+'/'+k.replaceAll('~','~0').replaceAll('/','~1'));};walk(frame,'');
  validateValue(getSchema(routes.messages.find(v=>v.type===type).root),frame,numbers);assertDeviceExecutionFeatures(frame,features);
 }
}
export function commitCommandFinalAdmission(db,options){return withExecutionReadView(db,()=>commitFinalAdmission(db,options));}
function commitFinalAdmission(db,{id,provider,tick,features}){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=52,'writer');
 const old=db.prepare('SELECT command_id FROM command_final_admission WHERE prepare_id=?').pluck().get(id);
 if(old)return {saved:readCommandRecord(db,old),replay:true};
 const current=selectCommandFinalization(db,{id,provider,tick}),initial=current.actual.command,encoding=current.encoding;
 need(!db.prepare(`SELECT 1 FROM command_device_hold h WHERE device_id=?
  ${Number(db.pragma('user_version',{simple:true}))>=57?'AND NOT EXISTS(SELECT 1 FROM command_hold_release r WHERE r.hold_id=h.hold_id)':''}`).pluck().get(initial.source.binding.device_id),'resource_busy');
 const before=db.prepare('SELECT count(*) FROM command_transmission_issue').pluck().get(),previous=String(BigInt(db.prepare('SELECT max(issued_revision) FROM command_transmission_issue').pluck().get()??'0'));
 need(before<limits.max_transmissions,'budget');
 const ids=Object.fromEntries(['transaction','commit','hold','ownership','guard','budget','intent','permit','transmission','resource','time','seal'].map(k=>[k,crypto.randomUUID()]));
 const input={initial,encoding,ready:current.ready,grant:current.principal_authorization.value,ids,issue:String(BigInt(previous)+1n),previous,before,selected:current.selected_tick_ns};
 let value=materialize({...input,sealed:String(tick())});
 validatePayloads(value,encoding,current.ready,features);
 const projection=preparedCommandProjection(initial,value.inventory),write=result=>need(result.changes===1,'storage');
 // 当前资格在生成完整正文后重核，随后只进行本T2的同步写入，不跨IPC等待。
 const last=selectCommandFinalization(db,{id,provider,tick});need(same(last.encoding.ref,encoding.ref)&&same(last.actual.command.record.state_ref,initial.record.state_ref),'changed');
 value=materialize({...input,sealed:String(tick())});
 write(db.prepare('INSERT INTO command_final_admission VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(ids.transaction,value.command_id,id,initial.source.binding_ref.id,ids.permit,ids.hold,value.attempt.attempt_id,ids.seal,ids.intent,canonical(value),digest(value),ids.commit));
 write(db.prepare('INSERT INTO command_device_hold VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(ids.hold,ids.transaction,value.command_id,initial.source.binding.device_id,ids.ownership,
  value.ownership_receipt.receipt_id,canonical(value.ownership_receipt),digest(value.ownership_receipt),canonical(value.hold),digest(value.hold),canonical(value.ownership),value.ownership.ownership_digest));
 write(db.prepare('INSERT INTO command_transmission_issue VALUES(?,?,?,?,8,?,?)').run(ids.permit,ids.transaction,counter(value.seal.issued_revision),counter(previous),canonical(value.transmission_charge),digest(value.transmission_charge)));
 write(db.prepare('INSERT INTO command_attempt_inventory VALUES(?,2,?,?,?,?)').run(value.command_id,ids.transaction,value.attempt.attempt_id,canonical(value.inventory),digest(value.inventory)));
 const commit={format:'command-final-admission-commit/1',commit_id:ids.commit,command_id:value.command_id,revision:'2',transaction_ref:ref(ids.transaction,value),
  previous_state_ref:initial.record.state_ref,record_digest:projection.record.record_digest,state_digest:digest(projection.state)};
 const audit=canonical({kind:'command_prepared',command_id:value.command_id,revision:'2',commit_ref:ref(ids.commit,commit)});
 write(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,2,?,?,?,?,?,?,?)').run(value.command_id,canonical(projection.record),projection.record.record_digest,
  canonical(projection.state),digest(projection.state),canonical(projection.manifest),digest(projection.manifest),ids.commit));
 write(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,2,?,?,?,?,?)').run(ids.commit,value.command_id,canonical(commit),digest(commit),audit,crypto.randomUUID(),audit));
 write(db.prepare('INSERT INTO command_lifecycle_head VALUES(?,2,?)').run(value.command_id,ids.commit));
 const saved=readCommandRecord(db,value.command_id);
 need(tick()<BigInt(value.seal.send_window.before_tick_ns),'expired');return {saved,replay:false};
}
// 仅重建固定历史，不查询当前授权，也不返回发送权。当前公开头另由命令reader核验。
export function readCommandFinalAdmission(db,initial,reference){return memoExecutionRead(db,'command-final-admission',reference,()=>readFinalAdmission(db,initial,reference));}
function readFinalAdmission(db,initial,reference){
 need(db.inTransaction,'writer');const r=row(db,'SELECT * FROM command_final_admission WHERE command_id=?',initial.source.command_id);need(r,'missing');
 const value=parse(r.body_jcs,r.body_digest);need(same({id:r.transaction_id,revision:'1',digest:r.body_digest},reference),'reference');
 const encoding=readCommandEncoding(db,r.prepare_id),ready=readInitialReady(db,initial.source.ready_ref.id),grant=principal(db,encoding);
 const issue=row(db,'SELECT * FROM command_transmission_issue WHERE transaction_id=?',r.transaction_id),hold=row(db,'SELECT * FROM command_device_hold WHERE transaction_id=?',r.transaction_id),
  inventory=row(db,'SELECT * FROM command_attempt_inventory WHERE transaction_id=?',r.transaction_id);need(issue&&hold&&inventory,'write_set');
 const before=db.prepare('SELECT count(*) FROM command_transmission_issue WHERE issued_revision<?').pluck().get(issue.issued_revision),previous=db.prepare('SELECT max(issued_revision) FROM command_transmission_issue WHERE issued_revision<?').pluck().get(issue.issued_revision)??'0';
 const expected=materialize({initial,encoding,ready,grant,ids:value.ids,issue:String(BigInt(issue.issued_revision)),previous:String(BigInt(previous)),before,
  selected:value.seal.selected_tick_ns,sealed:value.seal.sealed_tick_ns});
 need(r.body_jcs===canonical(expected)&&r.transaction_id===value.ids.transaction&&r.commit_id===value.ids.commit&&r.command_id===value.command_id&&r.permit_id===value.ids.permit&&
  r.hold_id===value.ids.hold&&r.attempt_id===value.attempt.attempt_id&&r.seal_id===value.ids.seal&&r.dispatch_intent_id===value.ids.intent&&r.binding_id===initial.source.binding_ref.id,'binding');
 need(encoding.response.value.disposition==='prepared'&&same(encoding.value.authorization.binding,initial.source.binding)&&
  encoding.value.command_id===initial.source.command_id&&issue.permit_id===r.permit_id&&issue.previous_revision===counter(previous)&&issue.charged_bytes===8&&
  issue.body_jcs===canonical(value.transmission_charge)&&issue.body_digest===digest(value.transmission_charge)&&
  hold.hold_id===r.hold_id&&hold.ownership_id===value.ownership.ownership_id&&hold.command_id===r.command_id&&hold.device_id===initial.source.binding.device_id&&
  hold.receipt_id===value.ownership_receipt.receipt_id&&hold.receipt_jcs===canonical(value.ownership_receipt)&&hold.receipt_digest===digest(value.ownership_receipt)&&
  hold.hold_jcs===canonical(value.hold)&&hold.hold_digest===digest(value.hold)&&hold.ownership_jcs===canonical(value.ownership)&&hold.ownership_digest===value.ownership.ownership_digest&&
  inventory.command_id===r.command_id&&inventory.revision===2&&inventory.attempt_id===r.attempt_id&&inventory.body_jcs===canonical(value.inventory)&&inventory.body_digest===digest(value.inventory),'write_set');
 return {value,ref:reference,projection:preparedCommandProjection(initial,value.inventory)};
}
export function observeCommandFinalAdmission(db,{commandId,binding,tick,readOnly=false}){
 need(db.inTransaction,'observer_writer');
 const saved=readCommandRecord(db,commandId),final=saved.lifecycle?.final_admission;need(final,'observer_source');
 const value=final.value,b=value.seal.binding;
 need(b.ipc_session_id===binding.ipc_session_id&&b.controller_boot_id===binding.controller_boot_id,'observer_binding');
 const original=row(db,'SELECT receipt_jcs FROM core_runtime_binding WHERE service_boot_id=?',binding.service_boot_id);need(original,'observer_source');
 const receipt=JSON.parse(original.receipt_jcs);need(canonical(receipt)===original.receipt_jcs&&receipt.member_boot_id===b.controller_boot_id,'observer_source');
 const source={format:'command-final-observer/1',service_boot_id:binding.service_boot_id,scope:b.scope,controller_boot_id:b.controller_boot_id,core_receipt:receipt},
  observer=ref(binding.service_boot_id+'.final-observer',source),sealRef=named(value.seal,'seal_id','seal_digest');
 const existing=row(db,'SELECT * FROM command_final_observation WHERE transaction_id=?',value.transaction_id);
 if(existing){const observation=JSON.parse(existing.body_jcs),{observation_digest,...body}=observation;
  need(canonical(observation)===existing.body_jcs&&digest(body)===observation_digest&&observation_digest===existing.body_digest&&
   existing.observer_jcs===canonical(source)&&existing.observer_digest===observer.digest&&existing.service_boot_id===binding.service_boot_id&&
   same(observation,{observation_id:existing.observation_id,transaction_id:value.transaction_id,scope:b.scope,seal_ref:sealRef,permit_id:value.permit.permit_id,
    outcome:'committed',observed_tick_ns:body.observed_tick_ns,observer_ref:observer,observation_digest})&&
   BigInt(body.observed_tick_ns)>=BigInt(value.seal.sealed_tick_ns),'observer_integrity');return observation;
 }
 need(!readOnly,'observer_missing');
 const observed=tick();need(observed>=BigInt(value.seal.sealed_tick_ns),'observer_clock');
 const observation=signed({observation_id:crypto.randomUUID(),transaction_id:value.transaction_id,scope:b.scope,seal_ref:sealRef,permit_id:value.permit.permit_id,
  outcome:'committed',observed_tick_ns:String(observed),observer_ref:observer},'observation_digest');
 need(db.prepare('INSERT INTO command_final_observation VALUES(?,?,?,?,?,?,?)').run(value.transaction_id,observation.observation_id,binding.service_boot_id,
  canonical(source),observer.digest,canonical(observation),observation.observation_digest).changes===1,'observer_storage');
 return observeCommandFinalAdmission(db,{commandId,binding,tick});
}

// T2之后的当前资格与封存历史分离。只能采用原占用、原许可和原窗口，不续期、不重新签发。
export function currentPreparedCommand(db,{id,binding,provider,tick}){
 need(db.inTransaction&&[52,53,54,55,56,57,58].includes(Number(db.pragma('user_version',{simple:true}))),'prepared_writer');
 return withExecutionReadView(db,()=>{
  const saved=readCommandRecord(db,id),final=saved.lifecycle?.final_admission;need(final,'prepared_source');
  const v=final.value,b=v.seal.binding;
  need(b.ipc_session_id===binding.ipc_session_id&&b.controller_boot_id===binding.controller_boot_id&&b.worker_boot_id===binding.worker_boot_id&&
   b.clock_domain_id===binding.clock_domain_id&&b.descriptor_digest===binding.descriptor_digest&&
   !db.prepare('SELECT 1 FROM execution_session_end WHERE ipc_session_id=?').pluck().get(b.ipc_session_id),'prepared_binding');
  const encoding=readCommandEncoding(db,v.prepare_id),actual=provider.currentPrepared(id,encoding.value.identity_snapshot,final.ref),
   observation=observeCommandFinalAdmission(db,{commandId:id,binding,tick,readOnly:true});
  need(same(actual.execution.ready.prepared_resource,{final_admission_ref:final.ref,resource:v.resource_after})&&
   actual.expires_tick_ns===v.seal.send_window.before_tick_ns&&same(actual.command.record.state_ref,saved.record.state_ref)&&
   encoding.response?.value.disposition==='prepared'&&same(encoding.ref,v.encoding_ref)&&same(encoding.response.ref,v.encoding_response_ref),'prepared_changed');
  const now=tick();need(now>=BigInt(observation.observed_tick_ns)&&now>=BigInt(v.seal.sealed_tick_ns)&&
   now>=BigInt(actual.now.tick)&&now<BigInt(v.seal.send_window.before_tick_ns),'prepared_expired');
  // 全部当前资格和原截止复核成功后，才合并该命令的周期监视；历史读取不经过这里。
  provider.notePreparedQualification?.(saved.source.ready_ref,id);
  return {saved,final,encoding,observation,selected_tick_ns:String(now)};
 });
}
