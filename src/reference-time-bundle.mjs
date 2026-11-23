import {createHash} from 'node:crypto';
import {deflateRawSync,inflateRawSync} from 'node:zlib';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {routes} from './sdk/runtime/panel-wire/preview/routes.mjs';
import {getSchema,validateValue} from './sdk/runtime/panel-wire/preview/registry.mjs';

const route=routes.operations.find(item=>item.authority==='controller'&&item.operation_id==='getReferenceTimeBundle');
const schema=getSchema(route.responses['200']);
const need=ok=>{if(!ok)throw new Error('reference_time_bundle_binding');};
const word=1n<<32n;
const stamp=({era,seconds,fraction})=>((BigInt(era)*word+BigInt(seconds)-2208988800n)*word+BigInt(fraction))*1000000000n;
const tick=value=>BigInt(value);
const bytesDigest=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
const maximumBundleBytes=32768;

function original(value,id,digestField){
  const {[digestField]:actual,...body}=value;
  need(actual===digest(body));
  return {id:value[id],revision:value.revision,digest:actual};
}

// 这些字段来自已通过管道和归档检查的原始数据报。只交付摘要和协议时间头。
export function referencePacketSummary(candidate,deadline){
  const request=Buffer.from(candidate.request,'base64url'),response=Buffer.from(candidate.response,'base64url');
  try{
    const header=response[0];
    return {request_digest:bytesDigest(request),response_digest:bytesDigest(response),
      request_size:request.length,response_size:response.length,response_deadline_tick_ns:deadline,ntp_version:(header>>3)&7,
      ntp_mode:header&7,leap:header>>6,stratum:response[1],precision:response.readInt8(3),
      root_delay_word:String(response.readUInt32BE(4)),root_dispersion_word:String(response.readUInt32BE(8))};
  }finally{request.fill(0);response.fill(0);}
}

export function validateReferenceBundle(input,{anchor,runtime,packet,assessment}){
  const text=canonical(input);
  need(typeof text==='string'&&Buffer.byteLength(text)<=maximumBundleBytes);
  const fixed=JSON.parse(text),{bundle,state}=fixed;
  need(Object.keys(fixed).sort().join(',')==='bundle,state');
  const numbers=new Map();
  for(const group of ['profile','request','exchange'])for(const [key,value] of Object.entries(bundle?.[group]??{})){
    if(Number.isSafeInteger(value))numbers.set(`/data/${group}/${key}`,{integer:true,safe:true});
  }
  validateValue(schema,{contract:'reference-time-service/0.1.0-draft.1',request_id:anchor.anchor_id,service_id:runtime.service_id,
    service_boot_id:runtime.service_boot_id,data:bundle},numbers);
  original(bundle,'bundle_id','bundle_digest');
  need(bundle.bundle_id===anchor.anchor_id&&Object.keys(state).sort().join(',')==='binding,current_anchor_ref,invalidation_ref,revision,state_digest,state_id,status');
  const {source,profile,policy,approval,request,exchange,authentication,error,era}=bundle;
  const p=anchor.approval,e=anchor.evidence;
  const fields={source_ref:original(source,'source_id','source_digest'),profile_ref:original(profile,'profile_id','profile_digest'),
    policy_ref:original(policy,'policy_id','policy_digest'),approval_ref:original(approval,'approval_id','approval_digest')};
  need(fields.source_ref.digest===p.source_digest&&same(fields.profile_ref,p.profile_ref)&&same(fields.policy_ref,p.policy_ref)&&same(fields.approval_ref,p.approval_ref)&&
    same(source.effective_config_ref,p.configuration_ref)&&source.authentication===p.authentication&&approval.status==='approved'&&
    approval.authority_service_id===runtime.service_id&&same(approval.source_ref,fields.source_ref)&&same(approval.profile_ref,fields.profile_ref));
  need(profile.elapsed_error_ppm===p.elapsed_error_ppm&&profile.span_quantization_ns===p.span_quantization_ns&&
    policy.max_exchange_span_ns===p.max_span_ns&&['max_anchor_age_ns','max_exchange_age_ns','max_upstream_age_ns','max_half_width_ns'].every(key=>policy[key]===p[key]));
  const {clock_domain_id,descriptor_digest}=runtime.clock_domain_descriptor;
  const domain={authority_service_id:runtime.service_id,database_instance_id:runtime.database_instance_id,
    provider_id:runtime.launch_intent.member_id,provider_boot_id:runtime.admission_receipt.member_boot_id,
    runtime_binding_ref:{id:runtime.runtime_binding_id,revision:'1',digest:anchor.runtime_digest},clock_domain_id,descriptor_digest,clock_generation:'1'};
  const binding={domain,...fields,time_generation:'1'};
  const requestRef=original(request,'request_id','request_digest'),exchangeRef=original(exchange,'exchange_id','exchange_digest');
  need(same(request.binding,binding)&&same(exchange.binding,binding)&&same(exchange.request_ref,requestRef)&&
    same(exchange.correlation_ref,request.correlation_ref)&&same(exchange.endpoint_ref,request.endpoint_ref)&&
    same(request.endpoint_ref,anchor.authorization.endpoint_ref)&&request.send_before_tick_ns===anchor.m1_tick_ns&&
    request.response_deadline_tick_ns===packet.response_deadline_tick_ns&&exchange.receive_after_tick_ns===anchor.m4_tick_ns&&
    request.request_size===packet.request_size&&exchange.response_size===packet.response_size&&
    request.request_size<=profile.max_packet_bytes&&exchange.response_size<=profile.max_packet_bytes&&
    request.request_bytes_ref.digest===packet.request_digest&&exchange.response_bytes_ref.digest===packet.response_digest&&
    same(exchange.parser_receipt_ref,anchor.capture_ref)&&
    ['ntp_version','ntp_mode','leap','stratum','precision','root_delay_word','root_dispersion_word','t2','t3'].every(key=>same(exchange[key],packet[key])));
  const proofs={authentication_ref:original(authentication,'auth_id','authentication_digest'),error_ref:original(error,'error_id','error_digest'),
    era_ref:original(era,'era_id','era_digest')};
  need(Object.entries(proofs).every(([key,value])=>same(value,e[key])&&same(value,exchange[key]))&&
    [authentication,error,era].every(proof=>same(proof.request_ref,requestRef)&&same(proof.response_bytes_ref,exchange.response_bytes_ref))&&
    authentication.mode===source.authentication&&same(authentication.source_ref,fields.source_ref)&&
    (authentication.mode!=='nts'||authentication.bootstrap_ref!==null)&&same(error.binding,binding)&&
    same(error.error_method_ref,profile.error_method_ref)&&same(era.method_ref,profile.era_method_ref)&&
    error.t2_error_ns===e.t2_error_ns&&error.t3_error_ns===e.t3_error_ns&&error.upstream_age_upper_at_m1_ns===e.upstream_age_at_m1_ns&&
    era.allowed_utc.lower_ns===e.independent_utc_lower_ns&&era.allowed_utc.upper_ns===e.independent_utc_upper_ns&&
    tick(era.allowed_utc.lower_ns)*word<=stamp(exchange.t2)&&stamp(exchange.t3)<=tick(era.allowed_utc.upper_ns)*word);
  const elapsed=(tick(anchor.m4_tick_ns)-tick(anchor.m1_tick_ns))*(1000000n+BigInt(profile.elapsed_error_ppm))+tick(profile.span_quantization_ns)*1000000n;
  need(elapsed<=tick(policy.max_exchange_span_ns)*1000000n);
  const derivation={exchange_ref:exchangeRef,request_ref:requestRef,...fields,...proofs,formula:'reference-bound/1:observed-delta-relative/1'};
  const model={revision:'1',model_id:'reference-bound/1',model_revision:'1',binding};
  const expectedAnchor={anchor_id:anchor.anchor_id,...model,exchange_ref:exchangeRef,anchor_tick_ns:anchor.m4_tick_ns,
    exchange_start_tick_ns:anchor.m1_tick_ns,utc_at_anchor:{lower_ns:anchor.lower_utc_ns,upper_ns:anchor.upper_utc_ns},derivation_digest:digest(derivation)};
  need(same(bundle.anchor,{...expectedAnchor,anchor_digest:digest(expectedAnchor)}));
  const anchorRef=original(bundle.anchor,'anchor_id','anchor_digest');
  const expectedAssessment={assessment_id:bundle.assessment.assessment_id,...model,anchor_ref:anchorRef,assessed_tick_ns:assessment.tick_ns,
    utc:{lower_ns:assessment.lower_utc_ns,upper_ns:assessment.upper_utc_ns},exchange_age_upper_ns:assessment.exchange_age_ns,
    anchor_age_upper_ns:assessment.anchor_age_ns,upstream_age_upper_ns:assessment.upstream_age_ns,decision:'conditional',reasons:[]};
  need(same(bundle.assessment,{...expectedAssessment,assessment_digest:digest(expectedAssessment)})&&
    same(bundle.state_ref,original(state,'state_id','state_digest'))&&same(state.binding,binding)&&state.status==='qualified'&&
    same(state.current_anchor_ref,anchorRef)&&state.invalidation_ref===null);
  return fixed;
}

export function encodeReferenceBundle(value){
  const bytes=Buffer.from(canonical(value));
  need(bytes.length<=maximumBundleBytes);
  return {encoding:'deflate-raw/base64url',digest:value.bundle.bundle_digest,body:deflateRawSync(bytes).toString('base64url')};
}

export function decodeReferenceBundle(value){
  need(value.encoding==='deflate-raw/base64url'&&typeof value.body==='string'&&value.body.length<=16384);
  const compressed=Buffer.from(value.body,'base64url');
  need(compressed.toString('base64url')===value.body);
  const text=inflateRawSync(compressed,{maxOutputLength:maximumBundleBytes}).toString('utf8'),decoded=JSON.parse(text);
  need(canonical(decoded)===text&&decoded.bundle.bundle_digest===value.digest);
  return decoded;
}
