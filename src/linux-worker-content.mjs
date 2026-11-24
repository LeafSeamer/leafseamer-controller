import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {moduleNeed as need} from './sdk/device-module.mjs';
import canonicalize from './runtime/canonicalize.mjs';

const stat=file=>fs.lstatSync(file,{bigint:true});
const identity=info=>`${info.dev}:${info.ino}`;
const mode=info=>info.mode&0o7777n;
const component=/^[A-Za-z0-9_.-]+$(?![\s\S])/;
const directoryName=/^worker-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');

function currentHandoff(materialization,{intent,descriptor},clock){
  const {intake_ref,request,lifetime,observer_clock}=materialization,binding=intent.extension_binding;
  need(canonicalize(intake_ref)===canonicalize(binding.intake_ref)&&request.intake_id===intake_ref.object_id&&
    request.target_authority_service_id===intent.service_id&&request.launch_intent_digest===hash(intent)&&
    request.manifest_digest===binding.manifest_digest&&request.artifact_set_digest===binding.artifact_set_digest&&
    request.host_trust_epoch===binding.host_trust_epoch&&observer_clock.scope==='linux-'+clock.capture().raw.namespace_after&&
    observer_clock.scope.replace('linux-','linux_').replace(':','_')===descriptor.namespace_identity&&
    observer_clock.format==='leafseamer-materialization-clock/1'&&observer_clock.backend==='linux_proc_boottime'&&
    observer_clock.host_installation_id===binding.host_installation_id&&observer_clock.authority_service_id===intake_ref.authority_service_id&&
    observer_clock.database_instance_id===intake_ref.database_instance_id&&lifetime.clock.clock_domain_id===observer_clock.clock_domain_id&&
    lifetime.clock.descriptor_digest===hash(observer_clock),'module_linux_materialization');
  const now=clock.tick(),issued=BigInt(lifetime.issued_tick),deadline=BigInt(lifetime.deadline_tick);
  need(now>=issued&&now<deadline&&deadline-issued===4000000000n,'module_linux_materialization_expired');
}

// 固定Worker在LOAD导入模块前核对安装方交接的根和每个原库存字节。
export function verifyLinuxWorkerContent(materials,admitted,clock){
  currentHandoff(materials.linux_materialization,admitted,clock);
  const selected=materials.linux_materialization.root,root=materials.root_path;
  need(selected&&path.isAbsolute(root)&&path.normalize(root)===root&&selected.path===root&&
    selected.directory===path.dirname(root)&&directoryName.test(path.basename(root))&&
    selected.reader_uid===process.geteuid()&&selected.reader_uid>0&&selected.reader_gid===process.getegid()&&selected.reader_gid>0,
  'module_linux_content');
  const parent=stat(selected.directory),original=stat(root);
  need(parent.isDirectory()&&parent.uid===0n&&mode(parent)===0o711n&&identity(parent)===selected.parent_identity&&
    original.isDirectory()&&original.uid===0n&&original.gid===BigInt(selected.reader_gid)&&mode(original)===0o550n&&
    original.dev===parent.dev&&identity(original)===selected.root_identity,'module_linux_content');
  for(let directory=path.dirname(selected.directory);;directory=path.dirname(directory)){
    const info=stat(directory),sticky=(directory==='/tmp'||directory==='/var/tmp')&&(info.mode&0o1000n)!==0n;
    need(info.isDirectory()&&info.uid===0n&&((info.mode&0o022n)===0n||sticky),'module_linux_content');
    if(directory==='/')break;
  }
  const files=new Map(),directories=new Set();
  for(const file of materials.inventory.files){
    const parts=file.path.split('/');
    need(parts.length<=121&&parts.every(part=>component.test(part)&&part!=='.'&&part!=='..')&&!files.has(file.path),'module_linux_content');
    for(let i=1;i<parts.length;i++)directories.add(parts.slice(0,i).join('/'));
    files.set(file.path,file);
  }
  const buffer=Buffer.alloc(65536);
  function visit(directory,relative=''){
    for(const name of fs.readdirSync(directory)){
      const file=path.join(directory,name),key=relative+name,info=stat(file);
      need(info.uid===0n&&info.gid===original.gid&&info.dev===original.dev,'module_linux_content');
      if(info.isDirectory()){
        need(mode(info)===0o550n&&directories.delete(key),'module_linux_content');
        visit(file,key+'/');
      }else{
        const expected=files.get(key);
        need(expected&&info.isFile()&&info.nlink===1n&&mode(info)===0o440n&&String(info.size)===expected.size_bytes,'module_linux_content');
        const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
        try{
          const held=fs.fstatSync(fd,{bigint:true}),hash=crypto.createHash('sha256');
          need(identity(held)===identity(info)&&held.ctimeNs===info.ctimeNs,'module_linux_content');
          let total=0;
          for(let count;(count=fs.readSync(fd,buffer,0,buffer.length,null))>0;){
            total+=count;need(BigInt(total)<=info.size,'module_linux_content');hash.update(buffer.subarray(0,count));
          }
          need(BigInt(total)===info.size&&'sha256:'+hash.digest('hex')===expected.digest&&stat(file).ctimeNs===info.ctimeNs,'module_linux_content');
        }finally{fs.closeSync(fd);}
        files.delete(key);
      }
    }
  }
  visit(root);
  need(files.size===0&&directories.size===0&&identity(stat(root))===selected.root_identity&&stat(root).ctimeNs===original.ctimeNs,'module_linux_content');
  currentHandoff(materials.linux_materialization,admitted,clock);
}
