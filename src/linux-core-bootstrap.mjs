import fs from 'node:fs';
import crypto from 'node:crypto';
import {Socket} from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {openNativeClock} from './native-clock.mjs';
import {BootstrapError,createCoreBootstrapChannel,verifyCoreAssignment,verifyCoreAdmission} from './core-bootstrap.mjs';

const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const check=(ok,code)=>{if(!ok)throw new BootstrapError(code);};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;

function verifyArtifact(policy){
  const file=fs.openSync('/proc/self/exe','r');
  let nodeDigest;
  try{
    const sum=crypto.createHash('sha256'),chunk=Buffer.alloc(65536);
    let length;
    while((length=fs.readSync(file,chunk,0,chunk.length,null))>0)sum.update(chunk.subarray(0,length));
    nodeDigest=sum.digest('hex');
  }finally{fs.closeSync(file);}
  const build=fs.readFileSync(new URL('./build-manifest.json',import.meta.url));
  check(policy.artifact_manifest_ref.digest==='sha256:'+hash(canonicalize({controller_build_sha256:hash(build),node_sha256:nodeDigest})),
    'bootstrap_artifact');
}

function localGroup(descriptor){
  const generation=descriptor.runtime_generation;
  check(uuid.test(generation)&&fs.statfsSync('/proc').type===0x9fa0,'bootstrap_linux_group');
  const boot=fs.readFileSync('/proc/sys/kernel/random/boot_id','utf8').trim(),bound=descriptor.os_boot_identity;
  check(uuid.test(boot)&&bound.status==='verified'&&bound.source==='linux-proc-boot-id'&&
    bound.value===boot&&bound.evidence_ref===boot,'bootstrap_linux_boot');
  const membership=fs.readFileSync('/proc/self/cgroup','utf8');
  const stem='/leafseamer_'+generation.replaceAll('-','')+'_controller';
  const groupPath=[stem+'/core',stem+'.slice/core'].find(candidate=>membership==='0::'+candidate+'\n');
  check(groupPath,'bootstrap_linux_group');
  const filename='/sys/fs/cgroup'+groupPath;
  check(fs.realpathSync.native(filename)===filename&&fs.statfsSync(filename).type===0x63677270,'bootstrap_linux_group');
  const status=fs.lstatSync(filename,{bigint:true});
  check(status.isDirectory(),'bootstrap_linux_group');
  const group={device:String(status.dev),inode:String(status.ino)};
  return {backend:'linux_cgroup_v2',generation,group_id:'group_'+hash(canonicalize({boot_id:boot,group_path:groupPath,group}))};
}

export function openLinuxCoreBootstrap(policy){
  check(process.platform==='linux'&&fs.fstatSync(3).isSocket(),'bootstrap_linux_channel');
  verifyArtifact(policy);
  const socket=new Socket({fd:3,readable:true,writable:true});
  const channel=createCoreBootstrapChannel(socket,socket,{timeoutMs:policy.bootstrap_timeout_ms});
  return Object.freeze({
    async accept(identity){
      const source=openNativeClock(),assignment=await channel.assignment(),descriptor=assignment.clock_domain_descriptor;
      const namespace=source.capture().raw.namespace_after;
      verifyCoreAssignment(assignment,policy,identity,{clockBackend:'linux_boottime',namespace:'linux_'+namespace.replace(':','_')});
      const containment=localGroup(descriptor);
      function current(){
        check(source.capture().continuity==='linux:'+namespace,'bootstrap_linux_clock');
        const now=source.tick();
        check(now>=BigInt(assignment.issued_tick_ns)&&now<BigInt(assignment.expires_tick_ns),'bootstrap_expired');
      }
      current();
      const receipt=await channel.proveAndReceive(assignment);
      current();
      const binding=await verifyCoreAdmission(assignment,receipt,policy,containment);
      current();
      check(canonicalize(localGroup(descriptor))===canonicalize(containment),'bootstrap_linux_group');
      channel.release();
      return {binding,policy};
    },
    monitor(stop){
      socket.once('end',stop).once('close',stop).once('error',stop).on('data',stop);
      if(socket.destroyed||socket.readableEnded)stop();
      else socket.resume();
    },
    close(){channel.close();socket.destroy();}
  });
}
