import {digest,same} from './auth-clock-value.mjs';
import {pairingFields as fields,pairingNeed as need,pairingUuid as uuid} from './peer-pairing-value.mjs';
import {actionAdmissionRequest} from './peer-action-binding.mjs';
import {isPreparationDigest as hash} from './peer-run-arm-plan.mjs';

export const automationCommandVersion='leafseamer-automation-command/1';
export const automationCommandRequestLimit=8192;
export const automationCommandResponseLimit=8192;
export const automationCommandPaths=Object.freeze({submit:'/internal/automation/commands',lookup:'/internal/automation/commands/lookup',
 reject:'/internal/automation/commands/reject',result:'/internal/automation/commands/result'});

export function automationCommandRequest(value,scope){
 fields(value,'action,idempotency_key,target');
 actionAdmissionRequest(value.action,scope);uuid(value.idempotency_key);
 const {target}=value;
 fields(target,'device_id,action_id,capability_version');
 uuid(target.device_id);
 need(typeof target.action_id==='string'&&/^[A-Za-z0-9._-]{1,128}$(?![\s\S])/.test(target.action_id)&&
  typeof target.capability_version==='string'&&target.capability_version.length<=128&&
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$(?![\s\S])/.test(target.capability_version),'automation_command_target');
 return value;
}

export function automationCommandIdentity(request,principal){
 const {controller_scope,preparation_id}=request.action.preparation.lookup;
 return {key:{target_scope:controller_scope,issuer_id:principal.issuer_id,issuer_epoch:principal.issuer_epoch,
  principal_id:principal.principal_id,request_epoch:preparation_id,operation_id:'createCommand',idempotency_key:request.idempotency_key},
  request_digest:digest(request)};
}

export function automationCommandAdjudication(value,request){
 fields(value,'contract_version,adjudication_id,revision,identity,decision,command_ref,commit_ref,adjudication_digest');
 const {adjudication_digest,...original}=value,{key}=value.identity,scope=request.action.preparation.lookup.controller_scope;
 fields(key,'target_scope,issuer_id,issuer_epoch,principal_id,request_epoch,operation_id,idempotency_key');
 uuid(value.adjudication_id);uuid(key.issuer_id);uuid(key.issuer_epoch);uuid(key.principal_id);
 need(value.contract_version==='command-admission/0.1.0-draft.1'&&value.revision==='1'&&
  same(value.identity,automationCommandIdentity(request,key))&&digest(original)===adjudication_digest,'automation_command_adjudication');
 function ref(reference,kind){
  fields(reference,'kind,scope,object_id,revision,digest');uuid(reference.object_id);
  need(reference.kind===kind&&same(reference.scope,scope)&&reference.revision==='1'&&hash(reference.digest),'automation_command_reference');
 }
 ref(value.commit_ref,'controller_commit');
 if(value.decision==='accepted')ref(value.command_ref,'command');
 else need(value.decision==='rejected'&&value.command_ref===null,'automation_command_adjudication');
 return value;
}

export function automationCommandTerminal(value,adjudication){
 fields(value,'format,command_ref,record_ref,state_ref,state,completion_achieved');
 const {command_ref,record_ref,state_ref,state,completion_achieved}=value;
 need(value.format==='leafseamer.automation-command-terminal/1'&&adjudication?.decision==='accepted'&&
  same(command_ref,adjudication.command_ref),'automation_command_terminal');
 fields(record_ref,'kind,scope,object_id,revision,digest');
 fields(state_ref,'id,revision,digest');
 fields(state,'attempt_ids,automation_continuation,command_id,completion_evidence_refs,effect_status,outcome,phase,reason_code,resolution_ref,resource_evidence_refs,resource_status,revision,scope,terminal_revision');
 const revision=state.terminal_revision;
 need(typeof revision==='string'&&/^[1-9][0-9]{0,19}$/.test(revision)&&record_ref.kind==='command'&&
  same(record_ref.scope,command_ref.scope)&&record_ref.object_id===command_ref.object_id&&record_ref.revision===revision&&hash(record_ref.digest)&&
  state_ref.id===command_ref.object_id+'_state_'+revision&&state_ref.revision===revision&&state_ref.digest===digest(state)&&
  state.phase==='finished'&&state.command_id===command_ref.object_id&&same(state.scope,command_ref.scope)&&state.revision===revision&&
  ['succeeded','failed','cancelled','unknown','expired','blocked'].includes(state.outcome)&&
  Array.isArray(state.completion_evidence_refs)&&Array.isArray(state.resource_evidence_refs),'automation_command_terminal');
 if(state.outcome==='succeeded'){
  need(completion_achieved==='effect_verified'&&state.effect_status==='verified'&&state.resource_status==='clear'&&
   state.automation_continuation==='eligible'&&state.completion_evidence_refs.length>0&&state.resource_evidence_refs.length>0,'automation_command_terminal_success');
 }else need(completion_achieved===null,'automation_command_terminal');
 for(const evidence of [...state.completion_evidence_refs,...state.resource_evidence_refs]){
  fields(evidence,'id,revision,digest');
  need(typeof evidence.id==='string'&&evidence.id.length>0&&evidence.id.length<=128&&
   typeof evidence.revision==='string'&&/^[1-9][0-9]{0,19}$/.test(evidence.revision)&&hash(evidence.digest),'automation_command_terminal_evidence');
 }
 return value;
}

export function automationCommandReply(value,request,record,challenge,operation){
 fields(value,'version,challenge_id,pair_attempt_id,transcript_digest,body');
 need(value.version===automationCommandVersion&&value.challenge_id===challenge&&value.pair_attempt_id===record.transcript.pair_attempt_id&&
  value.transcript_digest===record.transcript_digest,'automation_command_response');
 const {body}=value;
 if(operation==='result'){
  fields(body,'adjudication,terminal');
  if(body.adjudication!==null)automationCommandAdjudication(body.adjudication,request);
  if(body.terminal!==null)automationCommandTerminal(body.terminal,body.adjudication);
  return body;
 }
 if(operation!=='lookup')return automationCommandAdjudication(body,request);
 fields(body,'state,adjudication');
 if(body.state==='found')automationCommandAdjudication(body.adjudication,request);
 else need(body.state==='not_found'&&body.adjudication===null,'automation_command_response');
 return body;
}
