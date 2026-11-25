import fs from 'node:fs';
import {createConnection} from 'node:net';
import {createHash,randomUUID} from 'node:crypto';
import {once} from 'node:events';
import canonicalize from './runtime/canonicalize.mjs';
import {BootstrapError} from './core-bootstrap.mjs';
import {decodeBootstrap,decodeProtectedLaunchIntent,bootstrapVersion} from './sdk/bootstrap.mjs';

const location='/etc/leafseamer/bootstrap/reference.sock';
const retirementLocation='/etc/leafseamer/bootstrap/ref-retire.sock';
const retirementFormat='leafseamer-linux-reference-retirement/1';
const maximum=16384;
const same=(left,right)=>canonicalize(left)===canonicalize(right);
const fields=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===names;
const digest=value=>'sha256:'+createHash('sha256').update(canonicalize(value)).digest('hex');
const integer=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value)&&BigInt(value)<=(1n<<64n)-1n;
const check=(ok,code)=>{if(!ok)throw new BootstrapError(code);};

function readLine(socket,timeoutMs){
  return new Promise((resolve,reject)=>{
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
}
export async function readLinuxReferenceProvider(socket,{core,artifactDigest,assertCurrent,timeoutMs}){
  const line=await readLine(socket,timeoutMs);
  let frame;
  try{frame=JSON.parse(line.toString('utf8'));}catch{throw new BootstrapError('bootstrap_linux_reference_admission');}
  const retirement=frame?.retirement===retirementFormat;
  check(fields(frame,'core_receipt_id,format,provider'+(retirement?',retirement':''))&&Buffer.from(canonicalize(frame)).equals(line)&&
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
  return Object.freeze({provider:frame.provider,socket,assertCurrent,...(retirement&&{retirement:true})});
}

function bindRetirement(socket,{core,assertCurrent}){
  const lifetime=2000000000n,confirmed=new WeakMap();
  let pending=false;
  return {
    async observeRetirement(original,tick){
      assertCurrent();
      const intent=original?.launch_intent,scope=core.receipt.domain_ref,receiptId=core.receipt.receipt_id;
      const code='bootstrap_linux_reference_retirement';
      check(!pending&&!socket.destroyed&&original?.format==='leafseamer-time-provider-runtime-binding/2'&&
        original.service_id===core.intent.service_id&&intent?.role==='time_provider'&&intent.service_id===original.service_id&&
        intent.runtime_generation!==core.intent.runtime_generation&&original.core_receipt_id!==receiptId,code);
      const key={generation_id:intent.runtime_generation,launch_id:intent.launch_id,launch_intent_digest:digest(intent),
        core_receipt_id:original.core_receipt_id};
      const request={format:retirementFormat,current_core_receipt_id:receiptId,request_id:randomUUID(),key};
      const deadline=tick()+lifetime;
      pending=true;
      try{
        const result=readLine(socket,2000);
        socket.write(canonicalize(request)+'\n',error=>{if(error)socket.destroy();});
        const line=await result;
        const received=tick(),reply=JSON.parse(line.toString('utf8'));
        check(received<deadline&&fields(reply,'current_core_receipt_id,format,record,request_id')&&
          Buffer.from(canonicalize(reply)).equals(line)&&reply.format===retirementFormat&&reply.current_core_receipt_id===receiptId&&
          reply.request_id===request.request_id,code);
        assertCurrent();
        const {record}=reply;
        if(record===null)return null;
        const proof=record?.evidence,validHash=value=>typeof value==='string'&&/^sha256:[a-f0-9]{64}$/.test(value);
        const confirmedEmpty=value=>fields(value,'active_processes')&&value.active_processes===0;
        check(fields(record,'admission_receipt,core_exit,core_receipt_id,endpoint_evidence_digest,evidence,format,generation_id,launch_intent,process_observation,provider_exit,retirement_digest')&&
          record.format==='leafseamer-linux-reference-retired/1'&&record.generation_id===key.generation_id&&record.core_receipt_id===key.core_receipt_id&&
          same(record.admission_receipt,original.admission_receipt)&&same(record.launch_intent,intent)&&same(record.process_observation,original.process_observation)&&
          confirmedEmpty(record.provider_exit)&&confirmedEmpty(record.core_exit)&&
          validHash(record.endpoint_evidence_digest)&&validHash(record.retirement_digest)&&
          fields(proof,'group,group_path,provider_pid,start_ticks')&&proof.provider_pid===original.process_observation.provider_pid&&
          proof.start_ticks===original.process_observation.start_ticks&&fields(proof.group,'device,inode')&&integer(proof.group.device)&&
          integer(proof.group.inode)&&typeof proof.group_path==='string'&&proof.group_path.endsWith('/reference'),code);
        const observed={format:'leafseamer-time-provider-retirement-observation/1',record,
          receiving_domain_ref:structuredClone(scope),received_tick_ns:String(received)};
        confirmed.set(observed,{tick,deadline,text:canonicalize(observed)});
        return observed;
      }catch(error){socket.destroy();throw error;}
      finally{pending=false;}
    },
    assertRetirement(observed){
      assertCurrent();
      const proof=confirmed.get(observed);
      check(proof&&!socket.destroyed&&proof.tick()<proof.deadline&&canonicalize(observed)===proof.text,'bootstrap_linux_reference_retirement');
    }
  };
}

export async function openLinuxReferenceProvider({core,artifactDigest,timeoutMs,assertLive}){
  check(process.platform==='linux'&&/^sha256:[a-f0-9]{64}$/.test(artifactDigest),'bootstrap_linux_reference_options');
  const directory='/etc/leafseamer/bootstrap';
  for(const filename of ['/etc','/etc/leafseamer',directory]){
    const stat=fs.lstatSync(filename);
    check(stat.isDirectory()&&stat.uid===0&&(stat.mode&0o022)===0,'bootstrap_linux_reference_channel');
  }
  const endpoint=(filename=location)=>{
    const stat=fs.lstatSync(filename,{bigint:true});
    check(stat.isSocket()&&stat.uid===0n&&stat.gid===BigInt(process.getegid())&&(stat.mode&0o777n)===0o660n,
      'bootstrap_linux_reference_channel');
    return stat;
  };
  const original=endpoint(),socket=createConnection(location);
  let retired;
  socket.on('error',()=>{});
  try{
    const accepted=await readLinuxReferenceProvider(socket,{core,artifactDigest,timeoutMs,assertCurrent(){
      assertLive();const current=endpoint();
      check(!socket.destroyed&&!socket.readableEnded&&current.dev===original.dev&&current.ino===original.ino,'bootstrap_linux_reference_channel');
    }});
    if(!accepted.retirement)return accepted;
    const bound=endpoint(retirementLocation);
    retired=createConnection(retirementLocation);retired.on('error',()=>{});retired.pause();
    socket.once('close',()=>retired.destroy());
    try{await once(retired,'connect',{signal:AbortSignal.timeout(timeoutMs)});}
    catch{throw new BootstrapError('bootstrap_linux_reference_retirement');}
    const trust=()=>{
      accepted.assertCurrent();
      const live=endpoint(retirementLocation);
      check(!retired.destroyed&&live.dev===bound.dev&&live.ino===bound.ino,'bootstrap_linux_reference_retirement');
    };
    trust();
    return Object.freeze({...accepted,...bindRetirement(retired,{core,assertCurrent:trust})});
  }catch(error){socket.destroy();retired?.destroy();throw error;}
}
