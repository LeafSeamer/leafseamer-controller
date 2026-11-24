import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {Socket,createConnection} from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {BootstrapError,createCoreBootstrapChannel,verifyCoreAssignment,verifyCoreAdmission} from './core-bootstrap.mjs';
import {connectCoreSupervisor} from './supervisor-control.mjs';

const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const check=(ok,code)=>{if(!ok)throw new BootstrapError(code);};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;

function verifyArtifact(policy,serviceKind){
  const file=fs.openSync('/proc/self/exe','r');
  let nodeDigest;
  try{
    const sum=crypto.createHash('sha256'),chunk=Buffer.alloc(65536);
    let length;
    while((length=fs.readSync(file,chunk,0,chunk.length,null))>0)sum.update(chunk.subarray(0,length));
    nodeDigest=sum.digest('hex');
  }finally{fs.closeSync(file);}
  const build=fs.readFileSync(new URL('./build-manifest.json',import.meta.url));
  check(policy.artifact_manifest_ref.digest==='sha256:'+hash(canonicalize({[serviceKind+'_build_sha256']:hash(build),node_sha256:nodeDigest})),
    'bootstrap_artifact');
}

function localGroup(descriptor,serviceKind,compose){
  const generation=descriptor.runtime_generation;
  check(uuid.test(generation)&&fs.statfsSync('/proc').type===0x9fa0,'bootstrap_linux_group');
  const boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(),bound=descriptor.os_boot_identity;
  check(uuid.test(boot)&&bound.status==='verified'&&bound.source==='linux-proc-boot-id'&&
    bound.value===boot&&bound.evidence_ref===boot,'bootstrap_linux_boot');
  const membership=fs.readFileSync('/proc/self/cgroup','utf8');
  const stem='/leafseamer_'+generation.replaceAll('-','')+'_'+serviceKind;
  const groupPath=compose?'':[stem+'/core',stem+'.slice/core'].find(candidate=>membership==='0::'+candidate+'\n');
  if(compose){
    const mounts=fs.readFileSync('/proc/self/mountinfo','utf8').split('\n').map(line=>line.split(' '))
      .filter(fields=>fields[4]==='/sys/fs/cgroup');
    check(process.pid===1&&membership==='0::/\n'&&mounts.length===1&&mounts[0][5]?.split(',').includes('ro'),
      'bootstrap_linux_group');
  }else check(groupPath,'bootstrap_linux_group');
  const filename='/sys/fs/cgroup'+groupPath;
  check(fs.realpathSync.native(filename)===filename&&fs.statfsSync(filename).type===0x63677270,'bootstrap_linux_group');
  const status=fs.lstatSync(filename,{bigint:true});
  check(status.isDirectory(),'bootstrap_linux_group');
  const group={device:String(status.dev),inode:String(status.ino)};
  const identity=compose?{boot_id:boot,generation,service_kind:serviceKind,group}:{boot_id:boot,group_path:groupPath,group};
  return {backend:'linux_cgroup_v2',generation,group_id:'group_'+hash(canonicalize(identity))};
}

export function openLinuxCoreBootstrap(policy,serviceKind,{compose=false,workerControl=false,workerChannelDirectory}={}){
  check(serviceKind==='controller'||serviceKind==='seamer','bootstrap_linux_service');
  check(!workerControl||serviceKind==='controller','bootstrap_linux_control');
  check(workerChannelDirectory===undefined||workerControl&&(!compose||workerChannelDirectory==='/run/leafseamer-worker'),'bootstrap_linux_control');
  check(process.platform==='linux'&&fs.fstatSync(3).isSocket(),'bootstrap_linux_channel');
  verifyArtifact(policy,serviceKind);
  function channelDirectory(){
    const directory=workerChannelDirectory;
    check(typeof directory==='string'&&path.isAbsolute(directory)&&path.normalize(directory)===directory&&
      directory!=='/'&&!directory.endsWith('/')&&!directory.includes('\0')&&Buffer.byteLength(directory)<=60,'bootstrap_linux_worker_channel');
    for(let parent=directory;;parent=path.dirname(parent)){
      const stat=fs.lstatSync(parent,{bigint:true}),sticky=(parent==='/tmp'||parent==='/var/tmp')&&(stat.mode&0o1000n)!==0n;
      check(stat.isDirectory()&&stat.uid===0n&&((stat.mode&0o022n)===0n||sticky),'bootstrap_linux_worker_channel');
      if(parent==='/')return directory;
    }
  }
  if(workerChannelDirectory!==undefined)channelDirectory();
  function openWorkerChannel(memberBootId,purpose){
    check(uuid.test(memberBootId)&&['module','execution'].includes(purpose),'bootstrap_linux_worker_channel');
    const address=path.join(channelDirectory(),memberBootId+'.'+purpose),stat=fs.lstatSync(address,{bigint:true});
    check(stat.isSocket()&&stat.uid===0n&&stat.gid===BigInt(process.getegid())&&(stat.mode&0o777n)===0o660n,'bootstrap_linux_worker_channel');
    return createConnection(address);
  }
  const socket=new Socket({fd:3,readable:true,writable:true});
  const channel=createCoreBootstrapChannel(socket,socket,{timeoutMs:policy.bootstrap_timeout_ms});
  const loss=new AbortController(),{signal}=loss;
  const markLost=()=>loss.abort(new BootstrapError('bootstrap_linux_channel'));
  return Object.freeze({
    async accept({identity,source}){
      let assignment=await channel.assignment();
      const descriptor=assignment.clock_domain_descriptor;
      const namespace=source.capture().raw.namespace_after;
      verifyCoreAssignment(assignment,policy,identity,{clockBackend:'linux_boottime',namespace:'linux_'+namespace.replace(':','_')});
      const containment=localGroup(descriptor,serviceKind,compose);
      const issued=BigInt(assignment.issued_tick_ns),expires=BigInt(assignment.expires_tick_ns);
      function assertLive(){
        check(!signal.aborted&&!socket.destroyed&&!socket.readableEnded,'bootstrap_linux_channel');
        check(canonicalize(localGroup(descriptor,serviceKind,compose))===canonicalize(containment),'bootstrap_linux_group');
        const current=fs.statSync('/proc/self/ns/time',{bigint:true});
        check(String(current.dev)+':'+current.ino===namespace,'bootstrap_linux_clock');
      }
      function assertCurrent(){
        assertLive();
        check(source.capture().continuity==='linux:'+namespace,'bootstrap_linux_clock');
        const now=source.tick();
        check(now>=issued&&now<expires,'bootstrap_expired');
      }
      assertCurrent();
      const receipt=await channel.proveAndReceive(assignment);
      assertCurrent();
      const binding=await verifyCoreAdmission(assignment,receipt,policy,containment);
      assignment=null;
      assertCurrent();
      channel.release();
      socket.once('end',markLost).once('close',markLost).once('error',markLost);
      if(!workerControl){socket.once('data',markLost);socket.resume();return {binding,policy,assertCurrent,assertLive,signal};}
      const supervision=await connectCoreSupervisor({channelId:receipt.channel_binding_id.replaceAll('-',''),binding,policy,
        inherited:{socket,source,assertLive,...(workerChannelDirectory!==undefined&&{openWorkerChannel})}});
      try{assertCurrent();return {binding,policy,assertCurrent,assertLive,signal,supervision};}
      catch(error){supervision.close();throw error;}
    },
    monitor(stop){
      if(signal.aborted)stop();
      else signal.addEventListener('abort',stop,{once:true});
    },
    close(){channel.close();socket.destroy();}
  });
}
