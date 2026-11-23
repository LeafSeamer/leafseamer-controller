import canonicalize from 'canonicalize';
import {createHash} from 'node:crypto';

// 仅测试装配签发受控权威原件；报文、管道、锚点和持久化均走真实运行。
export function referenceBundleAuthority({serviceId,configuration,timeBounds,maxAnchorAge='5000000000',
 maxExchangeAge='5000000000',maxUpstreamAge='10000000000'}){
 const digest=body=>'sha256:'+createHash('sha256').update(body).digest('hex');
 const ref=(id,value='sha256:'+'1'.repeat(64))=>({id,revision:'1',digest:value});
 const seal=(body,field)=>({...body,[field]:digest(canonicalize(body))});
 const objectRef=(value,name,hash)=>ref(value[name],value[hash]);
 const revision='1';
 const sourceDoc=seal({source_id:'source.reference',revision,configured_server_ref:ref('server.loopback'),endpoint_set_ref:ref('endpoints.loopback'),
  effective_config_ref:configuration,authentication:'trusted_network',trust_policy_ref:ref('trust.fixture')},'source_digest');
 const model={revision,model_id:'reference-bound/1',model_revision:revision};
 const profile=seal({profile_id:'profile.reference',...model,collector_artifact_ref:ref('collector'),protocol_artifact_ref:ref('protocol'),
  platform_qualification_ref:ref('platform'),clock_method_ref:ref('clock-method'),error_method_ref:ref('error-method'),era_method_ref:ref('era-method'),
  elapsed_model:'observed-delta-relative/1',elapsed_error_ppm:0,span_quantization_ns:'1000',max_packet_bytes:48,
  time_scale:'posix-utc',leap_policy:'normal-only',smear_policy:'forbidden'},'profile_digest');
 const policyDoc=seal({policy_id:'policy.reference',revision,max_exchange_span_ns:'2000000000',max_anchor_age_ns:maxAnchorAge,
  max_exchange_age_ns:maxExchangeAge,max_upstream_age_ns:maxUpstreamAge,max_half_width_ns:'1000000000'},'policy_digest');
 const source_ref=objectRef(sourceDoc,'source_id','source_digest'),profile_ref=objectRef(profile,'profile_id','profile_digest');
 const approved=seal({approval_id:'approval.current',revision,profile_ref,source_ref,qualification_ref:ref('qualification'),
  authority_service_id:serviceId,status:'approved'},'approval_digest');
 const references={source_ref,profile_ref,policy_ref:objectRef(policyDoc,'policy_id','policy_digest'),approval_ref:objectRef(approved,'approval_id','approval_digest')};
 function originalExchange({runtime,packet,poll_ref,endpoint_ref,runtime_digest,m1_tick_ns}){
  const {clock_domain_id,descriptor_digest}=runtime.clock_domain_descriptor;
  const domain={authority_service_id:runtime.service_id,database_instance_id:runtime.database_instance_id,
   provider_id:runtime.launch_intent.member_id,provider_boot_id:runtime.admission_receipt.member_boot_id,
   runtime_binding_ref:ref(runtime.runtime_binding_id,runtime_digest),clock_domain_id,descriptor_digest,clock_generation:revision};
  const binding={domain,...references,time_generation:revision},response_bytes_ref=ref('bytes.response',packet.response_digest);
  const request=seal({request_id:poll_ref.id,revision,binding,correlation_ref:ref('correlation',digest(packet.request_digest+packet.response_digest)),endpoint_ref,
   send_before_tick_ns:m1_tick_ns,response_deadline_tick_ns:packet.response_deadline_tick_ns,request_bytes_ref:ref('bytes.request',packet.request_digest),
   request_size:packet.request_size},'request_digest');
  const common={revision,request_ref:objectRef(request,'request_id','request_digest'),response_bytes_ref};
  const authentication=seal({auth_id:'authentication',...common,source_ref,mode:'trusted_network',verification_ref:ref('verification'),bootstrap_ref:null,
   peer_binding_ref:ref('peer')},'authentication_digest');
  const error=seal({error_id:'error',...common,binding,error_method_ref:profile.error_method_ref,qualification_ref:ref('error-qualification'),
   t2_error_ns:'1000',t3_error_ns:'1000',upstream_age_upper_at_m1_ns:'1000',provenance_ref:ref('upstream')},'error_digest');
  const era=seal({era_id:'era',...common,method_ref:profile.era_method_ref,independent_time_ref:ref('independent-clock'),allowed_utc:timeBounds},'era_digest');
  return {request,authentication,error,era,proofs:{authentication_ref:objectRef(authentication,'auth_id','authentication_digest'),
   error_ref:objectRef(error,'error_id','error_digest'),era_ref:objectRef(era,'era_id','era_digest')}};
 }
 function referenceBundle({anchor,runtime,packet,assessment}){
  const {request,authentication,error,era,proofs}=originalExchange({...anchor,runtime,packet,endpoint_ref:anchor.authorization.endpoint_ref});
  const request_ref=objectRef(request,'request_id','request_digest'),binding=request.binding;
  const parsed=Object.fromEntries(['response_size','ntp_version','ntp_mode','leap','stratum','precision','root_delay_word','root_dispersion_word','t2','t3']
   .map(name=>[name,packet[name]]));
  const exchange=seal({exchange_id:'exchange',revision,binding,request_ref,correlation_ref:request.correlation_ref,endpoint_ref:request.endpoint_ref,
   response_bytes_ref:authentication.response_bytes_ref,receive_after_tick_ns:anchor.m4_tick_ns,...parsed,...proofs,parser_receipt_ref:anchor.capture_ref},'exchange_digest');
  const exchange_ref=objectRef(exchange,'exchange_id','exchange_digest');
  const derivation={exchange_ref,request_ref,...references,...proofs,formula:'reference-bound/1:observed-delta-relative/1'};
  const standardized=seal({anchor_id:anchor.anchor_id,...model,binding,exchange_ref,anchor_tick_ns:anchor.m4_tick_ns,exchange_start_tick_ns:anchor.m1_tick_ns,
   utc_at_anchor:{lower_ns:anchor.lower_utc_ns,upper_ns:anchor.upper_utc_ns},derivation_digest:digest(canonicalize(derivation))},'anchor_digest');
  const anchor_ref=objectRef(standardized,'anchor_id','anchor_digest');
  const state=seal({state_id:'state',revision,binding,status:'qualified',current_anchor_ref:anchor_ref,invalidation_ref:null},'state_digest');
  const assessed=seal({assessment_id:'assessment',...model,binding,anchor_ref,assessed_tick_ns:assessment.tick_ns,
   utc:{lower_ns:assessment.lower_utc_ns,upper_ns:assessment.upper_utc_ns},exchange_age_upper_ns:assessment.exchange_age_ns,
   anchor_age_upper_ns:assessment.anchor_age_ns,upstream_age_upper_ns:assessment.upstream_age_ns,decision:'conditional',reasons:[]},'assessment_digest');
  return {state,bundle:seal({bundle_id:anchor.anchor_id,revision,state_ref:objectRef(state,'state_id','state_digest'),source:sourceDoc,profile,policy:policyDoc,
   approval:approved,request,authentication,error,era,exchange,anchor:standardized,assessment:assessed},'bundle_digest')};
 }
 return {sourceDoc,references,proofs:input=>originalExchange(input).proofs,readBundleOriginals:referenceBundle};
}
