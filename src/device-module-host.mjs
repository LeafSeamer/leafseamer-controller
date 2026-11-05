import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import canonicalize from './runtime/canonicalize.mjs';
import {openNativeClock} from './native-clock.mjs';
import {moduleNeed as need,moduleExact as exact,deviceModuleProtocol} from './sdk/device-module.mjs';
import {moduleSocket,moduleTransport,moduleDigestEqual as same} from './device-module-channel.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');

// 仅由固定worker入口装配。root及完整库存来自监督器持续持有的加载材料。
export function hostDeviceModule({admitted,materials,failed}){
 const clock=openNativeClock(),abort=new AbortController(),sessions=new Map(),usedSessions=new Set(),usedCaptures=new Set();
 let transport,implementation=null,binding=null,sequence=1n,stopped=false;
 const stop=()=>{if(stopped)return;stopped=true;abort.abort();transport?.close();failed();};
 const current=frame=>{need(!stopped,'module_closed');const now=clock.tick();need(now>=BigInt(frame.issued_tick_ns)&&now<BigInt(frame.deadline_tick_ns),'module_expired');};
 const timerFor=frame=>setTimeout(stop,Math.max(1,Number((BigInt(frame.deadline_tick_ns)-clock.tick())/1000000n)));
 const entry=materials.manifest.entrypoints.find(e=>e.entry_id===admitted.intent.extension_binding.entry_id);
 need(entry?.kind==='worker'&&entry.loader==='node_module'&&hash(materials.manifest)===admitted.intent.extension_binding.manifest_digest&&
  hash(materials.inventory)===admitted.intent.extension_binding.artifact_set_digest,'module_content_binding');
 function file(fileId,role){const selected=materials.inventory.files.find(f=>f.file_id===fileId);need(selected?.role===role,'module_content_binding');
  const target=path.resolve(materials.root_path,selected.path);need(target.startsWith(path.resolve(materials.root_path)+path.sep),'module_content_path');
  const bytes=fs.readFileSync(target);need(String(bytes.length)===selected.size_bytes&&'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')===selected.digest,'module_content_binding');return target;}
 transport=moduleTransport(moduleSocket(admitted.receipt.member_boot_id,'worker'),{failed:stop,async receive(frame){
  current(frame);need(frame.sequence===String(sequence)&&frame.reply_to===null,'module_order');sequence++;
  need(frame.binding.member_boot_id===admitted.receipt.member_boot_id,'module_binding');
  const timer=timerFor(frame);let type,body;
  try{
   if(!implementation){
    need(frame.type==='LOAD'&&!binding,'module_state');const runtime=frame.body.runtime;
    exact(runtime,['format','runtime_binding_id','service_id','database_instance_id','service_boot_id','launch_intent','clock_domain_descriptor','admission_receipt','gate_state']);
    need(runtime.format==='leafseamer-worker-runtime-binding/1'&&runtime.gate_state==='closed'&&same(runtime.launch_intent,admitted.intent)&&
     same(runtime.admission_receipt,admitted.receipt)&&same(runtime.clock_domain_descriptor,admitted.descriptor)&&hash(runtime)===frame.binding.runtime_binding_ref.digest&&
     runtime.runtime_binding_id===frame.binding.runtime_binding_ref.object_id&&runtime.service_id===frame.binding.runtime_binding_ref.authority_service_id&&
     runtime.database_instance_id===frame.binding.runtime_binding_ref.database_instance_id,'module_binding');
    need(same(frame.body.configuration.reference,admitted.intent.extension_binding.configuration_ref),'module_configuration');
    binding=frame.binding;
    need(materials.manifest.api_versions.includes('leafseamer-device-module/1')&&materials.manifest.ipc_versions.includes(deviceModuleProtocol),'module_version');
    // 文件政策和模块都是批准归档的固定字节；策略对象不自赋联网或设备写许可。
    file(entry.io_policy_file_id,'policy');const selected=await import(pathToFileURL(file(entry.file_id,'module')).href);current(frame);
    need(typeof selected.createDeviceModule==='function','module_interface');
    implementation=await selected.createDeviceModule(Object.freeze({configuration:frame.body.configuration.value,
     device_ids:admitted.intent.object_scope.device_ids,signal:abort.signal,tick:()=>clock.tick()}));current(frame);
    need(implementation?.api_version==='leafseamer-device-module/1'&&['connectReadOnly','captureBaseline','stopReadOnly'].every(k=>typeof implementation[k]==='function'),'module_interface');
    type='LOADED';body={entry_id:entry.entry_id};
   }else{
    need(same(frame.binding,binding),'module_binding');const input=frame.body,device=input.device_id,session=input.device_session_id;
    need(admitted.intent.object_scope.device_ids.includes(device),'module_device');
    if(frame.type==='CONNECT'){
     need(!sessions.has(device)&&!usedSessions.has(session)&&usedSessions.size<4096,'module_session');usedSessions.add(session);
     const identity=await implementation.connectReadOnly({...input,signal:abort.signal});current(frame);sessions.set(device,session);type='CONNECTED';body={...input,identity};
    }else{
     need(sessions.get(device)===session,'module_session');
     if(frame.type==='CAPTURE'){
      need(!usedCaptures.has(input.capture_id)&&usedCaptures.size<4096,'module_capture');usedCaptures.add(input.capture_id);
      const value=await implementation.captureBaseline({...input,signal:abort.signal});current(frame);
      type='CAPTURED';body={...input,value,captured_tick_ns:String(clock.tick())};
     }else{
      need(frame.type==='DISCONNECT','module_direction');sessions.delete(device);await implementation.stopReadOnly({...input,signal:abort.signal});current(frame);type='DISCONNECTED';body=input;
     }
    }
   }
   current(frame);await transport.send({...frame,version:deviceModuleProtocol,type,request_id:crypto.randomUUID(),reply_to:frame.request_id,body});
  }finally{clearTimeout(timer);}
 }});
 return Object.freeze({close:stop});
}
