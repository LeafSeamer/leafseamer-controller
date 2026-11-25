import fs from 'node:fs';
import {createHash,createSecretKey,X509Certificate} from 'node:crypto';
import {isIP} from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {clockInteger} from './native-clock.mjs';
import {referenceBundleIssuer,resolveReferenceNtpTimestamp,utcCeil} from './reference-time-bundle.mjs';

const directory='/etc/leafseamer/reference-source';
const sourceSlot='reference.primary';
const pollLease='2000000000',pollInterval='16000000000',reservedBytes=16384;
const ntsPollLease='5000000000',ntsReservedBytes=114688;
const hash=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
const identifier=value=>typeof value==='string'&&/^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const need=(ok,reason)=>{if(!ok)throw new Error('time_provider_poll_'+reason);};
const second=1000000000n,day=86400n*second,word=1n<<32n;
const minimum=(a,b)=>a<b?a:b;
const maximum=(a,b)=>a>b?a:b;
const ref=(id,digest,revision='1')=>({id,digest,revision});
const seal=(body,field)=>({...body,[field]:hash(canonicalize(body))});
const bounded=(value,limit)=>{const n=clockInteger(value);need(n>0n&&n<=limit,'reference_bounds');return n;};
function requireRef(value){
  need(exact(value,'digest,id,revision')&&identifier(value.id)&&/^sha256:[a-f0-9]{64}$/.test(value.digest)&&
    clockInteger(value.revision)>0n,'reference_reference');
}

function numericEndpoint(value){
  const address=typeof value==='string'&&/^(?:\[([0-9a-f:]+)\]|([0-9.]+)):([1-9][0-9]{0,4})$(?![\s\S])/.exec(value);
  return address&&isIP(address[1]??address[2])===(address[1]?6:4)&&Number(address[3])<=65535&&
    (!address[1]||new URL('http://'+value).hostname==='['+address[1]+']'&&!address[1].startsWith('::ffff:'));
}

function dnsName(value){
  return typeof value==='string'&&value.length<=253&&isIP(value)===0&&
    value.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$(?![\s\S])/.test(label));
}

function targetName({name,port},endpoint){
  need(typeof name==='string'&&Number.isInteger(port)&&port>=1&&port<=65535,'installed_source_endpoint');
  const ip=isIP(name);
  if(ip){
    const address=(ip===6?'['+name+']':name)+':'+port;
    need(numericEndpoint(address)&&(endpoint===undefined||address===endpoint),'installed_source_endpoint');
  }else need(dnsName(name),'installed_source_endpoint');
  return name+':'+port;
}

function validateNetwork(network){
  if(network?.authentication==='trusted_network'){
    need(exact(network,'authentication,endpoint')&&numericEndpoint(network.endpoint),'installed_source_endpoint');
    return;
  }
  need(exact(network,'authentication,default_target,key_endpoint,root_der,server_name,targets')&&
    network.authentication==='nts'&&numericEndpoint(network.key_endpoint)&&dnsName(network.server_name)&&
    exact(network.default_target,'name,port')&&Array.isArray(network.targets)&&network.targets.length>=1&&network.targets.length<=16&&
    Array.isArray(network.root_der)&&network.root_der.length>=1&&network.root_der.length<=8&&
    Buffer.byteLength(canonicalize(network))<=12000,'installed_source_endpoint');
  const targets=new Set();
  for(const target of network.targets){
    need(exact(target,'endpoint,name,port')&&numericEndpoint(target.endpoint)&&
      Number(target.endpoint.slice(target.endpoint.lastIndexOf(':')+1))===target.port,'installed_source_endpoint');
    const key=targetName(target,target.endpoint);
    need(!targets.has(key),'installed_source_endpoint');
    targets.add(key);
  }
  need(targets.has(targetName(network.default_target)),'installed_source_endpoint');
  const roots=new Set();
  for(const value of network.root_der){
    need(typeof value==='string'&&value.length>0&&value.length<=12000,'installed_source_root');
    const raw=Buffer.from(value,'base64url');
    need(raw.toString('base64url')===value&&!roots.has(value),'installed_source_root');
    let certificate;
    try{certificate=new X509Certificate(raw);}catch{need(false,'installed_source_root');}
    need(certificate.raw.equals(raw)&&certificate.ca,'installed_source_root');
    roots.add(value);
  }
}

function referenceInstallation(approval,configuration,endpointRef,current){
  const qualified=approval.reference;
  const {authentication}=approval.network,nts=authentication==='nts';
  need(exact(qualified,'elapsed_error_ppm,independent_source_ref,leap_schedule,max_half_width_ns,max_upstream_age_ns,monitoring_ref,platform_qualification_ref,source_provenance_ref,span_quantization_ns,t2_error_ns,t3_error_ns,tref_error_ns,utc_mode')&&
    qualified.utc_mode==='normal_utc_no_smear'&&Number.isInteger(qualified.elapsed_error_ppm)&&
    qualified.elapsed_error_ppm>0&&qualified.elapsed_error_ppm<=1000,'reference_qualification');
  for(const key of ['independent_source_ref','monitoring_ref','platform_qualification_ref','source_provenance_ref'])requireRef(qualified[key]);
  const q=bounded(qualified.span_quantization_ns,1000000n),rho=BigInt(qualified.elapsed_error_ppm);
  const errors=['t2_error_ns','t3_error_ns','tref_error_ns'].map(key=>bounded(qualified[key],second));
  const upstream=bounded(qualified.max_upstream_age_ns,day);
  const halfWidth=bounded(qualified.max_half_width_ns,second);
  const leap=qualified.leap_schedule;
  need(exact(leap,'bulletin_ref,events,valid_from_ns,valid_until_ns')&&Array.isArray(leap.events)&&leap.events.length<=16,'reference_leap_schedule');
  requireRef(leap.bulletin_ref);
  const from=clockInteger(leap.valid_from_ns),until=clockInteger(leap.valid_until_ns);
  let bandStart=from;
  const windows=[];
  for(const event of leap.events){
    need(exact(event,'direction,utc_ns')&&[-1,1].includes(event.direction),'reference_leap_schedule');
    const at=clockInteger(event.utc_ns);
    need(at%second===0n&&at>=from&&at<until&&at-day>=bandStart,'reference_leap_schedule');
    windows.push({lower:bandStart,upper:at-day});
    bandStart=at+day;
  }
  if(bandStart<until)windows.push({lower:bandStart,upper:until});
  need(until>from,'reference_leap_schedule');
  const validFrom=clockInteger(approval.not_before_ns),validUntil=clockInteger(approval.expires_ns);
  const {approval_revision:revision}=approval,qualificationRef=ref('reference.qualification',hash(canonicalize(qualified)),revision);
  const method=id=>ref(id.replace('/','.'),hash(canonicalize({id,version:1})));
  const source=seal({source_id:'reference.source',revision,configured_server_ref:endpointRef,endpoint_set_ref:endpointRef,
    effective_config_ref:configuration,authentication,trust_policy_ref:qualificationRef},'source_digest');
  const profile=seal({profile_id:'reference.profile',revision,model_id:'reference-bound/1',model_revision:'1',
    collector_artifact_ref:ref('reference.collector',approval.provider_digest),protocol_artifact_ref:method(nts?'reference.nts':'reference.ntp-v4'),
    platform_qualification_ref:qualified.platform_qualification_ref,clock_method_ref:method('reference.clock-boottime'),
    error_method_ref:method('qualified-server-envelope/1'),era_method_ref:method('auth-interval-era/1'),
    elapsed_model:'observed-delta-relative/1',elapsed_error_ppm:qualified.elapsed_error_ppm,span_quantization_ns:qualified.span_quantization_ns,
    max_packet_bytes:nts?1232:48,time_scale:'posix-utc',leap_policy:'normal-only',smear_policy:'forbidden'},'profile_digest');
  const policy=seal({policy_id:'reference.policy',revision,max_exchange_span_ns:pollLease,max_anchor_age_ns:'32000000000',
    max_exchange_age_ns:'32000000000',max_upstream_age_ns:String(upstream),max_half_width_ns:String(halfWidth)},'policy_digest');
  const approvalDoc=seal({approval_id:approval.approval_id,revision,source_ref:ref(source.source_id,source.source_digest,revision),
    profile_ref:ref(profile.profile_id,profile.profile_digest,revision),qualification_ref:qualificationRef,
    authority_service_id:approval.scope.service_id,status:'approved'},'approval_digest');
  const issuer=referenceBundleIssuer({source,profile,policy,approval:approvalDoc});
  const {approval_ref,policy_ref,profile_ref,source_ref}=issuer.references;
  let activeWindow=null,deadline=null;
  const elapsed=delta=>utcCeil(delta*(1000000n+rho),1000000n)+q;

  const authority=Object.freeze({
    sourceSlot,
    readApproval(_request,{sample,tick}){
      current();
      const lower=clockInteger(sample.lower_ns),upper=clockInteger(sample.upper_ns);
      need(same(sample.source_ref,qualified.independent_source_ref)&&clockInteger(sample.monotonic_quantization_ns)<=q&&
        BigInt(sample.drift_ppb)*1000n<=rho*(1000000000n-BigInt(sample.drift_ppb)),'reference_clock_source');
      if(!activeWindow){
        const window=windows.find(item=>lower>=item.lower&&upper<item.upper);
        need(window,'reference_leap_window');
        activeWindow={lower:maximum(window.lower,validFrom),upper:minimum(window.upper,validUntil)};
        deadline=tick+maximum(0n,activeWindow.upper-upper-q)*1000000n/(1000000n+rho);
      }
      need(lower>=activeWindow.lower&&upper<activeWindow.upper&&tick<deadline,'reference_leap_window');
      return {format:'leafseamer-reference-approval/1',authentication,time_scale:'UTC',leap_mode:'normal_only',smear:false,
        configuration_ref:configuration,source_digest:source.source_digest,approval_ref,profile_ref,policy_ref,
        elapsed_error_ppm:qualified.elapsed_error_ppm,span_quantization_ns:qualified.span_quantization_ns,
        max_anchor_age_ns:policy.max_anchor_age_ns,max_exchange_age_ns:policy.max_exchange_age_ns,
        max_half_width_ns:policy.max_half_width_ns,max_span_ns:policy.max_exchange_span_ns,max_upstream_age_ns:policy.max_upstream_age_ns,
        valid_before_tick_ns:String(deadline)};
    },
    checkAssessment(value){
      need(BigInt(value.lower_utc_ns)>=activeWindow.lower&&BigInt(value.upper_utc_ns)<activeWindow.upper,'reference_leap_window');
    },
    prepareEvidence(candidate,{capture_ref,runtime_digest},{now},ntsBootstrap){
      const m1=clockInteger(candidate.m1_tick_ns),m4=clockInteger(candidate.m4_tick_ns);
      need(now.tick>=m4&&m4>=m1&&now.tick-m1<2n*second&&elapsed(m4-m1)<=2n*second,'reference_bracket');
      const {sample}=now,lower=clockInteger(sample.lower_ns)-elapsed(now.tick-m1),upper=clockInteger(sample.upper_ns);
      need(upper-lower<=day,'reference_era_window');
      let bootstrap=null;
      if(nts){
        need(ntsBootstrap?.format==='nts-bootstrap/1'&&ntsBootstrap.key_reply_digest===candidate.key_reply_digest&&
          ntsBootstrap.ntp_endpoint===candidate.endpoint&&same(ntsBootstrap.source_ref,qualified.independent_source_ref)&&
          same(ntsBootstrap.policy_ref,sample.policy_ref)&&same(ntsBootstrap.runtime_ref,sample.runtime_ref)&&
          same(ntsBootstrap.runtime_domain_ref,sample.runtime_domain_ref),'reference_nts_bootstrap');
        const {source_ref:authentication_source_ref,...observation}=ntsBootstrap;
        bootstrap=seal({bootstrap_id:capture_ref.id,revision:'1',source_ref,profile_ref,approval_ref,
          endpoint_ref:endpointRef,runtime_digest,capture_ref,authentication_source_ref,...observation},'bootstrap_digest');
      }
      const [e2,e3,eref]=errors;
      const bytes=Buffer.from(candidate.response,'base64url');
      try{
        const t2=resolveReferenceNtpTimestamp(bytes,32,lower,upper,e2).value;
        const t3=resolveReferenceNtpTimestamp(bytes,40,lower,upper,e3).value;
        const tref=resolveReferenceNtpTimestamp(bytes,16,lower-upstream,upper,eref).value;
        need(t3>=t2&&t3-t2<=(elapsed(m4-m1)+e2+e3)*word&&tref-eref*word<=t3+e3*word,'reference_exchange');
        const age=maximum(0n,utcCeil(t3-tref,word)+e3+eref);
        need(age<upstream,'reference_upstream_age');
        const margin=maximum(e2,e3);
        return {qualification:qualified,clock_sample:sample,...(bootstrap&&{bootstrap}),proof:{
          acquisition_ref:sample.acquisition_ref,verification_ref:capture_ref,provenance_ref:qualified.source_provenance_ref,
          ...(bootstrap&&{bootstrap_ref:ref(bootstrap.bootstrap_id,bootstrap.bootstrap_digest)}),
          independent_utc_lower_ns:String(lower-margin),independent_utc_upper_ns:String(upper+margin),
          t2_error_ns:String(e2),t3_error_ns:String(e3),upstream_age_at_m1_ns:String(age)}};
      }finally{bytes.fill(0);}
    },
    readEvidence(input){
      current();
      const {qualification,proof}=input.qualification_original;
      need(same(qualification,qualified),'reference_qualification');
      const {independent_utc_lower_ns,independent_utc_upper_ns,t2_error_ns,t3_error_ns,upstream_age_at_m1_ns}=proof;
      return {format:'leafseamer-reference-evidence/1',exchange_digest:input.exchange_digest,
        ...issuer.exchangeProofs(input,proof).proofs,independent_utc_lower_ns,independent_utc_upper_ns,
        t2_error_ns,t3_error_ns,upstream_age_at_m1_ns,valid_before_tick_ns:String(deadline)};
    },
    readBundleOriginals:issuer.issue
  });
  return {authority,approvalRef:approval_ref,sourceDigest:source.source_digest};
}

function protectedMount(){
  const stat=fs.lstatSync(directory);
  const mounts=fs.readFileSync('/proc/self/mountinfo','utf8').split('\n').map(line=>line.split(' ')).filter(fields=>fields[4]===directory);
  need(stat.isDirectory()&&stat.uid===0&&stat.gid===process.getegid()&&(stat.mode&0o777)===0o750&&
    mounts.length===1&&mounts[0][5].split(',').includes('ro'),'installed_source_mount');
}

function readProtected(name,maximum){
  const fd=fs.openSync(directory+'/'+name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const stat=fs.fstatSync(fd),bytes=Buffer.alloc(stat.size>0&&stat.size<=maximum?stat.size+1:0);
    need(bytes.length>0&&stat.isFile()&&stat.uid===0&&stat.gid===process.getegid()&&(stat.mode&0o777)===0o440,'installed_source_file');
    let offset=0,count;
    while(offset<bytes.length&&(count=fs.readSync(fd,bytes,offset,bytes.length-offset,null))>0)offset+=count;
    need(offset===stat.size,'installed_source_file');
    return bytes.subarray(0,offset);
  }finally{fs.closeSync(fd);}
}

export function readInstalledLinuxReferenceCapture({identity,providerDigest,approvalDigest}){
  const {service_id,database_instance_id}=identity;
  need(process.platform==='linux'&&/^sha256:[a-f0-9]{64}$/.test(approvalDigest),'installed_source');
  protectedMount();
  function currentApproval(){
    const bytes=readProtected('approval.json',16384);
    need(hash(bytes)===approvalDigest,'installed_source_changed');
    return bytes;
  }
  const bytes=currentApproval(),approval=JSON.parse(bytes.toString('utf8'));
  const providesReference=approval?.format==='leafseamer-linux-reference-capture-approval/2';
  need(exact(approval,'approval_id,approval_revision,archive_budget_bytes,capture_key_id,expires_ns,format,network,not_before_ns,provider_digest,'+
    (providesReference?'reference,':'')+'scope')&&bytes.equals(Buffer.from(canonicalize(approval)))&&
    (providesReference||approval.format==='leafseamer-linux-reference-capture-approval/1')&&
    same(approval.scope,{service_id,database_instance_id})&&approval.provider_digest===providerDigest&&
    identifier(approval.approval_id)&&clockInteger(approval.approval_revision)>0n&&identifier(approval.capture_key_id)&&
    Number.isSafeInteger(approval.archive_budget_bytes)&&approval.archive_budget_bytes<=1073741824,'installed_source');
  validateNetwork(approval.network);
  const nts=approval.network.authentication==='nts',reservationBytes=nts?ntsReservedBytes:reservedBytes;
  const network=nts&&providesReference?{...approval.network,bootstrap_evidence:'nts-bootstrap/1'}:approval.network;
  need(Buffer.byteLength(canonicalize(network))<=12000,'installed_source_endpoint');
  need(approval.archive_budget_bytes>=reservationBytes,'installed_source');
  const start=clockInteger(approval.not_before_ns),expires=clockInteger(approval.expires_ns);
  need(expires>start,'installed_source');
  const endpointDigest=hash(canonicalize(network));
  const endpointRef={id:'reference.endpoint',revision:'1',digest:endpointDigest};
  const scope={service_id,database_instance_id,purpose:'reference_time_capture'};
  let withdrawn=false;
  function current(){
    need(!withdrawn,'installed_source_changed');
    try{protectedMount();currentApproval();}
    catch{withdrawn=true;need(false,'installed_source_changed');}
  }
  function keyFor(input,id,writable){
    need(same(input,scope)&&id===approval.capture_key_id,'installed_source_key');
    if(writable)current();
    const material=readProtected('capture.key',32);
    try{need(material.length===32,'installed_source_key');return {...scope,id,key:createSecretKey(material),writable};}
    finally{material.fill(0);}
  }
  const captureProtection=Object.freeze({
    currentKey(input){return keyFor(input,approval.capture_key_id,true);},
    readKey(input,id){return keyFor(input,id,false);}
  });
  captureProtection.currentKey(scope);
  const configuration=ref('reference.configuration',approvalDigest);
  const reference=providesReference?referenceInstallation(approval,configuration,endpointRef,current):null;
  return Object.freeze({
    limits:Object.freeze({max_outstanding:1,max_reserved_bytes:approval.archive_budget_bytes}),schedule:Object.freeze({sourceSlots:Object.freeze([sourceSlot])}),
    readSource(slot,clock){
      current();need(slot===sourceSlot,'installed_source_slot');
      const {lower_ns,upper_ns,tick_ns,valid_before_tick_ns,monotonic_quantization_ns,drift_ppb}=clock.referenceTimeSample();
      const lower=clockInteger(lower_ns),upper=clockInteger(upper_ns),tick=clockInteger(tick_ns),q=clockInteger(monotonic_quantization_ns);
      need(lower>=start&&upper>=lower&&expires>upper+2n*q&&Number.isInteger(drift_ppb)&&drift_ppb>=0&&drift_ppb<=1000000,'installed_source_window');
      const policyDeadline=tick+(expires-upper-2n*q)*1000000000n/(1000000000n+BigInt(drift_ppb));
      const authenticationDeadline=clockInteger(valid_before_tick_ns);
      return {source_slot:slot,source_digest:reference?.sourceDigest??endpointDigest,reserved_bytes:reservationBytes,
        poll_lease_ns:nts?ntsPollLease:pollLease,minimum_poll_interval_ns:pollInterval,
        approval_ref:reference?.approvalRef??ref(approval.approval_id,approvalDigest,approval.approval_revision),
        configuration_ref:configuration,endpoint_ref:{...endpointRef},
        valid_before_tick_ns:String(policyDeadline<authenticationDeadline?policyDeadline:authenticationDeadline)};
    },
    readEndpoint(reference){current();need(same(reference,endpointRef),'installed_source_endpoint');return structuredClone(network);},
    captureProtection,...(reference&&{referenceAuthority:reference.authority,sourceSlot})
  });
}
