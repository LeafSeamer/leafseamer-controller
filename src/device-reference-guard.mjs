import {digest,same} from './auth-clock-value.mjs';
import {DeviceExecutionError} from './device-execution-channel.mjs';
import {referenceAnchorInterval,referenceBoundsAt,referenceElapsed,utcCeil} from './reference-time-bundle.mjs';

const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError('transmission_reference_'+code);};
function original(value,idField,digestField){
 const {[digestField]:checksum,...body}=value;
 need(digest(body)===checksum,'digest');
 return {id:value[idField],revision:value.revision,digest:checksum};
}

function assessmentAt(proof,now){
 const bounds=referenceBoundsAt(proof,now),{policy}=proof;
 const {lower,upper,anchorAge,exchangeAge,upstreamAge}=bounds;
 return now>=proof.m4&&anchorAge<BigInt(policy.max_anchor_age_ns)&&exchangeAge<BigInt(policy.max_exchange_age_ns)&&
  upstreamAge<BigInt(policy.max_upstream_age_ns)&&upper-lower<=2n*BigInt(policy.max_half_width_ns)?bounds:null;
}

function currentGeneration(proof,gate){
 const snapshot=gate.reference_time_snapshot;
 return snapshot&&same(snapshot.domain,proof.domain)&&snapshot.minimum_time_generation===proof.generation&&gate.minimum_time_generation===proof.generation;
}

// The fixed execution session supplies these originals from the Controller. This verifies
// their associations and extrapolation in the Worker clock domain before any device I/O.
export function installReferenceGuard({guard,schedule_guard:schedule,reference_context:bundle},live){
 if(!guard.time_required){
  need(guard.reference_time===null&&schedule===null&&bundle===null,'unexpected');
  return null;
 }
 const execution=guard.reference_time,utc=execution.utc_guard;
 const {source,profile,policy,approval,anchor,assessment,request,exchange,error,authentication,era}=bundle;
 const {binding,window}=utc,{domain,time_generation:generation}=binding;
 original(utc,'guard_id','guard_digest');
 need(same(execution.context_ref,original(bundle,'bundle_id','bundle_digest'))&&
  same(utc.anchor_ref,original(anchor,'anchor_id','anchor_digest'))&&
  same(utc.assessment_ref,original(assessment,'assessment_id','assessment_digest'))&&
  same(assessment.anchor_ref,utc.anchor_ref)&&[anchor,assessment,request,exchange,error].every(item=>same(item.binding,binding)),'binding');
 need(same(binding.source_ref,original(source,'source_id','source_digest'))&&same(binding.profile_ref,original(profile,'profile_id','profile_digest'))&&
  same(binding.policy_ref,original(policy,'policy_id','policy_digest'))&&same(binding.approval_ref,original(approval,'approval_id','approval_digest'))&&
  approval.status==='approved'&&approval.authority_service_id===domain.authority_service_id&&same(approval.source_ref,binding.source_ref)&&
  same(approval.profile_ref,binding.profile_ref),'authority');
 const requestRef=original(request,'request_id','request_digest'),exchangeRef=original(exchange,'exchange_id','exchange_digest');
 need(same(anchor.exchange_ref,exchangeRef)&&same(exchange.request_ref,requestRef)&&same(exchange.endpoint_ref,request.endpoint_ref)&&
  same(exchange.correlation_ref,request.correlation_ref)&&authentication.mode===source.authentication&&
  same(authentication.source_ref,binding.source_ref)&&(authentication.mode==='nts')===(authentication.bootstrap_ref!==null)&&
  same(error.error_method_ref,profile.error_method_ref)&&same(era.method_ref,profile.era_method_ref)&&
  same(exchange.authentication_ref,original(authentication,'auth_id','authentication_digest'))&&
  same(exchange.error_ref,original(error,'error_id','error_digest'))&&same(exchange.era_ref,original(era,'era_id','era_digest'))&&
  [error,authentication,era].every(item=>same(item.request_ref,requestRef)&&same(item.response_bytes_ref,exchange.response_bytes_ref)),'evidence');
 const m1=BigInt(anchor.exchange_start_tick_ns),m4=BigInt(anchor.anchor_tick_ns),observed=BigInt(assessment.assessed_tick_ns);
 const expiry=BigInt(utc.expires_tick_ns),start=BigInt(window.not_before_utc_ns),end=BigInt(window.not_after_utc_ns);
 need(m1<=m4&&m4<=observed&&observed<=live.t&&live.t<expiry&&start<end&&
  request.send_before_tick_ns===anchor.exchange_start_tick_ns&&exchange.receive_after_tick_ns===anchor.anchor_tick_ns&&
  m4<BigInt(request.response_deadline_tick_ns)&&exchange.ntp_version===4&&exchange.ntp_mode===4&&exchange.leap===0&&
  exchange.stratum>=1&&exchange.stratum<=15&&request.request_size<=profile.max_packet_bytes&&exchange.response_size<=profile.max_packet_bytes&&
  utcCeil(referenceElapsed(m4-m1,profile).upper,1000000n)<=BigInt(policy.max_exchange_span_ns)&&
  same(anchor.utc_at_anchor,referenceAnchorInterval(exchange.t2,exchange.t3,m1,m4,profile,error)),'anchor');
 const proof={domain,generation,m1,m4,profile,policy,start,end,expiry,queueDeadline:null,schedule,
  lowerAtAnchor:BigInt(anchor.utc_at_anchor.lower_ns),upperAtAnchor:BigInt(anchor.utc_at_anchor.upper_ns),upstreamAtM1:BigInt(error.upstream_age_upper_at_m1_ns)};
 const originalBounds=assessmentAt(proof,observed);
 need(currentGeneration(proof,live.value)&&originalBounds&&assessment.decision==='conditional'&&assessment.reasons.length===0&&
  same(assessment.utc,{lower_ns:String(originalBounds.lower),upper_ns:String(originalBounds.upper)})&&
  assessment.anchor_age_upper_ns===String(originalBounds.anchorAge)&&assessment.exchange_age_upper_ns===String(originalBounds.exchangeAge)&&
  assessment.upstream_age_upper_ns===String(originalBounds.upstreamAge),'assessment');
 if(schedule===null){
  need(execution.schedule_ref===null,'schedule');
 }else{
  const origin=guard.automation_binding,deadline=BigInt(schedule.queue_deadline_tick_ns);
  need(origin&&same(execution.schedule_ref,original(schedule,'guard_id','guard_digest'))&&same(schedule.local_clock_domain,domain)&&same(schedule.window,window)&&
   origin.origin_scope.authority_service_id===schedule.origin_service_id&&origin.origin_scope.database_instance_id===schedule.origin_database_instance_id&&
   origin.execution_id===schedule.execution_id&&origin.step_id===schedule.step_id&&live.t<deadline,'schedule');
  proof.queueDeadline=deadline;
 }
 return proof;
}

function utcNanoseconds(value){
 const millis=Date.parse(value);
 need(Number.isSafeInteger(millis)&&new Date(millis).toISOString()===value,'schedule');
 return BigInt(millis)*1000000n;
}

export function checkReferenceDispatch(proof,permit,before){
 const scheduled=permit.mode==='scheduled';
 need(scheduled===Boolean(proof?.schedule),'dispatch');
 if(!proof)return;
 if(scheduled){
  const {schedule}=proof;
  need(permit.occurrence_id===schedule.occurrence_ref.id&&permit.clock_policy_revision===proof.policy.revision&&
   utcNanoseconds(permit.not_before)===proof.start&&utcNanoseconds(permit.not_after)===proof.end&&before<=proof.queueDeadline,'dispatch');
 }
 need(before<=proof.expiry,'dispatch');
}

export function referenceDispatchCurrent(proof,live){
 if(!proof)return true;
 const {t,value}=live;
 if(!currentGeneration(proof,value)||t>=proof.expiry||(proof.queueDeadline!==null&&t>=proof.queueDeadline))return false;
 const bounds=assessmentAt(proof,t);
 return bounds!==null&&proof.start<=bounds.lower&&bounds.upper<proof.end;
}
