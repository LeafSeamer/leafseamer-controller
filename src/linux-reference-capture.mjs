import fs from 'node:fs';
import {createHash,createSecretKey} from 'node:crypto';
import {isIP} from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {clockInteger} from './native-clock.mjs';

const directory='/etc/leafseamer/reference-source';
const sourceSlot='reference.primary';
const pollLease='2000000000',pollInterval='16000000000',reservedBytes=16384;
const hash=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
const identifier=value=>typeof value==='string'&&/^[A-Za-z0-9_.:-]{1,128}$(?![\s\S])/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const need=(ok,reason)=>{if(!ok)throw new Error('time_provider_poll_'+reason);};

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
  need(exact(approval,'approval_id,approval_revision,archive_budget_bytes,capture_key_id,expires_ns,format,network,not_before_ns,provider_digest,scope')&&
    bytes.equals(Buffer.from(canonicalize(approval)))&&approval.format==='leafseamer-linux-reference-capture-approval/1'&&
    same(approval.scope,{service_id,database_instance_id})&&approval.provider_digest===providerDigest&&
    identifier(approval.approval_id)&&clockInteger(approval.approval_revision)>0n&&identifier(approval.capture_key_id)&&
    Number.isSafeInteger(approval.archive_budget_bytes)&&approval.archive_budget_bytes>=reservedBytes&&
    approval.archive_budget_bytes<=1073741824,'installed_source');
  const {network}=approval;
  need(exact(network,'authentication,endpoint')&&network.authentication==='trusted_network'&&typeof network.endpoint==='string','installed_source_endpoint');
  const address=/^(?:\[([0-9a-f:]+)\]|([0-9.]+)):([1-9][0-9]{0,4})$(?![\s\S])/.exec(network.endpoint);
  need(address&&isIP(address[1]??address[2])===(address[1]?6:4)&&Number(address[3])<=65535,'installed_source_endpoint');
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
  return Object.freeze({
    limits:Object.freeze({max_outstanding:1,max_reserved_bytes:approval.archive_budget_bytes}),schedule:Object.freeze({sourceSlots:Object.freeze([sourceSlot])}),
    readSource(slot,clock){
      current();need(slot===sourceSlot,'installed_source_slot');
      const {lower_ns,upper_ns,tick_ns,valid_before_tick_ns,monotonic_quantization_ns,drift_ppb}=clock.referenceTimeSample();
      const lower=clockInteger(lower_ns),upper=clockInteger(upper_ns),tick=clockInteger(tick_ns),q=clockInteger(monotonic_quantization_ns);
      need(lower>=start&&upper>=lower&&expires>upper+2n*q&&Number.isInteger(drift_ppb)&&drift_ppb>=0&&drift_ppb<=1000000,'installed_source_window');
      const policyDeadline=tick+(expires-upper-2n*q)*1000000000n/(1000000000n+BigInt(drift_ppb));
      const authenticationDeadline=clockInteger(valid_before_tick_ns);
      return {source_slot:slot,source_digest:endpointDigest,reserved_bytes:reservedBytes,poll_lease_ns:pollLease,minimum_poll_interval_ns:pollInterval,
        approval_ref:{id:approval.approval_id,revision:approval.approval_revision,digest:approvalDigest},
        configuration_ref:{id:'reference.configuration',revision:'1',digest:approvalDigest},endpoint_ref:{...endpointRef},
        valid_before_tick_ns:String(policyDeadline<authenticationDeadline?policyDeadline:authenticationDeadline)};
    },
    readEndpoint(reference){current();need(same(reference,endpointRef),'installed_source_endpoint');return {...network};},
    captureProtection
  });
}
