import fs from 'node:fs';
import {createConnection} from 'node:net';
import {createHash} from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {BootstrapError} from './core-bootstrap.mjs';
import {decodeBootstrap,decodeProtectedLaunchIntent,bootstrapVersion} from './sdk/bootstrap.mjs';

const location='/etc/leafseamer/bootstrap/reference.sock';
const maximum=16384;
const same=(left,right)=>canonicalize(left)===canonicalize(right);
const fields=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names;
const digest=value=>'sha256:'+createHash('sha256').update(canonicalize(value)).digest('hex');
const integer=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)&&BigInt(value)<=(1n<<64n)-1n;
const check=(ok,code)=>{if(!ok)throw new BootstrapError(code);};

export async function readLinuxReferenceProvider(socket,{core,artifactDigest,assertCurrent,timeoutMs}){
  const line=await new Promise((resolve,reject)=>{
    let buffer=Buffer.alloc(0);
    const finish=(error,value)=>{
      clearTimeout(timer);socket.pause();
      socket.removeListener('data',data).removeListener('error',lost).removeListener('end',lost).removeListener('close',lost);
      if(error)reject(error);else resolve(value);
    };
    const lost=()=>finish(new BootstrapError('bootstrap_linux_reference_channel'));
    const timer=setTimeout(lost,timeoutMs);
    function data(chunk){
      if(buffer.length+chunk.length>maximum+1){lost();return;}
      buffer=Buffer.concat([buffer,chunk]);
      const end=buffer.indexOf(10);
      if(end===buffer.length-1)finish(null,buffer.subarray(0,end));
      else if(end>=0)lost();
    }
    socket.on('data',data).once('end',lost).once('error',lost).once('close',lost);
    if(socket.destroyed||socket.readableEnded)lost();else socket.resume();
  });
  let frame;
  try{frame=JSON.parse(line.toString('utf8'));}catch{throw new BootstrapError('bootstrap_linux_reference_admission');}
  check(fields(frame,'core_receipt_id,format,provider')&&Buffer.from(canonicalize(frame)).equals(line)&&
    frame.format==='leafseamer-linux-reference-admission/1'&&frame.core_receipt_id===core.receipt.receipt_id&&
    fields(frame.provider,'descriptor,intent,process_observation,receipt'),'bootstrap_linux_reference_admission');
  const {descriptor,intent,receipt,process_observation:observed}=frame.provider;
  await decodeProtectedLaunchIntent(Buffer.from(canonicalize(intent)));
  await decodeBootstrap(Buffer.from(canonicalize({version:bootstrapVersion,type:'ADMISSION',payload:receipt})),'ADMISSION');
  check(same(descriptor,core.descriptor)&&intent.role==='time_provider'&&intent.device_ids.length===0&&
    intent.service_id===core.intent.service_id&&intent.supervisor_instance_id===core.intent.supervisor_instance_id&&
    intent.runtime_generation===core.intent.runtime_generation&&intent.policy_revision===core.intent.policy_revision&&
    intent.artifact_manifest_ref.digest===artifactDigest&&intent.containment_ref.backend==='linux_cgroup_v2'&&
    intent.containment_ref.generation===core.intent.runtime_generation&&intent.containment_ref.group_id!==core.intent.containment_ref.group_id&&
    receipt.role===intent.role&&receipt.gate_state==='closed'&&receipt.receipt_id!==core.receipt.receipt_id&&
    receipt.bootstrap_id!==core.receipt.bootstrap_id&&/^[a-f0-9]{32}$/.test(receipt.member_boot_id)&&receipt.member_boot_id!==core.receipt.member_boot_id&&
    receipt.launch_id===intent.launch_id&&receipt.member_id===intent.member_id&&receipt.launch_intent_digest===digest(intent)&&
    same(receipt.artifact_manifest_ref,intent.artifact_manifest_ref)&&same(receipt.containment_ref,intent.containment_ref)&&
    same(receipt.domain_ref,core.receipt.domain_ref)&&fields(observed,'image_device,image_inode,observation_id,observed_tick_ns,provider_pid,start_ticks')&&
    [observed.image_device,observed.image_inode,observed.observed_tick_ns,observed.start_ticks,receipt.admitted_tick_ns].every(integer)&&
    BigInt(observed.observed_tick_ns)<=BigInt(receipt.admitted_tick_ns)&&observed.observation_id===receipt.os_observation_ref&&
    Number.isSafeInteger(observed.provider_pid)&&observed.provider_pid>1,'bootstrap_linux_reference_admission');
  assertCurrent();
  return Object.freeze({provider:frame.provider,socket,assertCurrent});
}

export async function openLinuxReferenceProvider({core,artifactDigest,timeoutMs,assertLive}){
  check(process.platform==='linux'&&/^sha256:[a-f0-9]{64}$/.test(artifactDigest),'bootstrap_linux_reference_options');
  const directory='/etc/leafseamer/bootstrap';
  for(const filename of ['/etc','/etc/leafseamer',directory]){
    const stat=fs.lstatSync(filename);
    check(stat.isDirectory()&&stat.uid===0&&(stat.mode&0o022)===0,'bootstrap_linux_reference_channel');
  }
  const endpoint=()=>{
    const stat=fs.lstatSync(location,{bigint:true});
    check(stat.isSocket()&&stat.uid===0n&&stat.gid===BigInt(process.getegid())&&(stat.mode&0o777n)===0o660n,
      'bootstrap_linux_reference_channel');
    return stat;
  };
  const original=endpoint(),socket=createConnection(location);
  socket.on('error',()=>{});
  try{
    return await readLinuxReferenceProvider(socket,{core,artifactDigest,timeoutMs,assertCurrent(){
      assertLive();const current=endpoint();
      check(!socket.destroyed&&!socket.readableEnded&&current.dev===original.dev&&current.ino===original.ino,'bootstrap_linux_reference_channel');
    }});
  }catch(error){socket.destroy();throw error;}
}
