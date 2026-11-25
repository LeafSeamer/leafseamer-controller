import {digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {installReferenceGuard,checkReferenceDispatch,referenceDispatchCurrent} from './device-reference-guard.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('command_reference_'+code);};
const keys=(value,fields)=>value&&Object.keys(value).sort().join(',')===fields;
const named=(value,id,hash)=>({id:value[id],revision:value.revision,digest:value[hash]});
const sign=(body,field)=>({...body,[field]:digest(body)});
const ref=value=>keys(value,'digest,id,revision')&&Object.values(value).every(item=>typeof item==='string'&&item===item.trim())&&
 /^[A-Za-z0-9_.:-]{1,128}$/.test(value.id)&&/^[1-9][0-9]{0,19}$/.test(value.revision)&&/^sha256:[0-9a-f]{64}$/.test(value.digest);
const min=(...values)=>values.reduce((a,b)=>a<b?a:b);

function iso(ns){
 const tick=BigInt(ns);
 need(tick%1000000n===0n,'window');
 const date=new Date(Number(tick/1000000n));
 need(Number.isFinite(date.getTime())&&BigInt(date.getTime())*1000000n===tick,'window');
 const encoded=date.toISOString();
 need(encoded.length===24,'window');
 return encoded;
}

export function scheduledDispatch(binding,automation,max_queue_ms){
 need(keys(binding,'activation_ref,admission_ref,definition_artifact_ref,execution_ref,format,occurrence_ref,schedule_version,step_id,step_window_ref,window')&&
  binding.format==='leafseamer.schedule-step-binding/1'&&automation&&binding.step_id===automation.step_id&&
  same(binding.execution_ref,{...automation.execution_binding_ref,kind:'execution'})&&
  [binding.occurrence_ref,binding.definition_artifact_ref,binding.activation_ref,binding.admission_ref,binding.step_window_ref].every(ref)&&
  binding.admission_ref.id===binding.occurrence_ref.id&&typeof binding.schedule_version==='string'&&
  /^[1-9][0-9]{0,19}$(?![\s\S])/.test(binding.schedule_version)&&
  keys(binding.window,'not_after_utc_ns,not_before_utc_ns')&&Object.values(binding.window).every(v=>typeof v==='string'&&/^(0|-?[1-9][0-9]{0,29})$/.test(v))&&
  BigInt(binding.window.not_before_utc_ns)<BigInt(binding.window.not_after_utc_ns),'source');
 return {mode:'scheduled',occurrence_id:binding.occurrence_ref.id,not_before:iso(binding.window.not_before_utc_ns),
  not_after:iso(binding.window.not_after_utc_ns),clock_policy_revision:'1',max_queue_ms};
}

export function prepareScheduledGuard({source,snapshot,original,validBefore,selected,authorizedBefore,id}){
 const {metadata:{dispatch,automation_binding:automation},schedule_binding:binding}=source;
 need(same(dispatch,scheduledDispatch(binding,automation,dispatch.max_queue_ms))&&
  original?.bundle&&snapshot,'source');
 const {bundle,state}=original,{domain,time_generation}=bundle.anchor.binding;
 need(state.status==='qualified'&&same(state.binding,bundle.anchor.binding)&&
  same(snapshot.domain,domain)&&snapshot.minimum_time_generation===time_generation&&
  bundle.policy.revision===dispatch.clock_policy_revision&&
  BigInt(original.published_tick_ns??selected)<=BigInt(selected)&&
  BigInt(validBefore)<=BigInt(original.authority_before_tick_ns??validBefore),'generation');
 const deadline=String(min(BigInt(validBefore),BigInt(authorizedBefore),BigInt(source.deadline.queue_deadline_tick_ns)));
 need(BigInt(selected)<BigInt(deadline),'expired');
 const {window,occurrence_ref,definition_artifact_ref,schedule_version,activation_ref,admission_ref,step_window_ref,step_id}=binding;
 const schedule_guard=sign({guard_id:id+'.schedule',revision:'1',origin_service_id:automation.origin_scope.authority_service_id,
  origin_database_instance_id:automation.origin_scope.database_instance_id,occurrence_ref,definition_artifact_ref,schedule_version,activation_ref,
  admission_ref,execution_id:automation.execution_id,step_id,step_window_ref,window,queue_deadline_tick_ns:deadline,local_clock_domain:domain},'guard_digest');
 const utc_guard=sign({guard_id:id+'.utc',revision:'1',model_id:bundle.anchor.model_id,model_revision:bundle.anchor.model_revision,
  binding:bundle.anchor.binding,anchor_ref:named(bundle.anchor,'anchor_id','anchor_digest'),
  assessment_ref:named(bundle.assessment,'assessment_id','assessment_digest'),window,expires_tick_ns:deadline},'guard_digest');
 const context_ref=named(bundle,'bundle_id','bundle_digest');
 const reference_time={context_ref,utc_guard,schedule_ref:named(schedule_guard,'guard_id','guard_digest')};
 const value={reference_time,schedule_guard,reference_context:bundle,valid_before_tick_ns:validBefore,deadline};
 assertScheduledGuardCurrent(value,source,snapshot,selected);
 return value;
}

export function assertScheduledGuardCurrent(value,source,snapshot,now){
 const gate={reference_time_snapshot:snapshot,minimum_time_generation:snapshot.minimum_time_generation};
 const live={t:BigInt(now),value:gate};
 const proof=installReferenceGuard({guard:{time_required:true,automation_binding:source.metadata.automation_binding,reference_time:value.reference_time},
  schedule_guard:value.schedule_guard,reference_context:value.reference_context},live);
 checkReferenceDispatch(proof,source.metadata.dispatch,BigInt(value.deadline));
 need(referenceDispatchCurrent(proof,live),'window');
}
