import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {pathToFileURL} from 'node:url';
import canonicalize from './runtime/canonicalize.mjs';
import {openNativeClock} from './native-clock.mjs';
import {moduleNeed as need,moduleExact as exact,deviceModuleProtocol} from './sdk/device-module.mjs';
import {moduleSocket,moduleTransport,moduleDigestEqual as same} from './device-module-channel.mjs';
import {executionSessionIdentity,executionSocket} from './device-execution-channel.mjs';
import {deviceWorkerSession} from './device-worker-session.mjs';
import {deviceExecutionGate} from './device-execution-gate.mjs';
import {deviceWorkerExecution,fixedWorkerExecutionAvailable} from './device-worker-execution.mjs';
import {deviceExecutionVersion,deviceExecutionCapabilities} from './sdk/device-execution.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');

// 仅由固定worker入口装配。root及完整库存来自监督器持续持有的加载材料。
export function hostDeviceModule({admitted,materials,executionIdentity,failed}){
 const clock=openNativeClock(),abort=new AbortController(),sessions=new Map(),usedSessions=new Set(),usedCaptures=new Set();
 let transport,implementation=null,binding=null,sequence=1n,stopped=false,execution=null,executionSession=null;
 const gates=new Map(),executions=new Map(),executionBindings=new Map();
 const stop=()=>{if(stopped)return;stopped=true;abort.abort();executionSession?.close();transport?.close();failed();};
 const current=frame=>{need(!stopped,'module_closed');const now=clock.tick();need(now>=BigInt(frame.issued_tick_ns)&&now<BigInt(frame.deadline_tick_ns),'module_expired');};
 const timerFor=frame=>setTimeout(stop,Math.max(1,Number((BigInt(frame.deadline_tick_ns)-clock.tick())/1000000n)));
 const entry=materials.manifest.entrypoints.find(e=>e.entry_id===admitted.intent.extension_binding.entry_id);
 need(entry?.kind==='worker'&&entry.loader==='node_module'&&hash(materials.manifest)===admitted.intent.extension_binding.manifest_digest&&
  hash(materials.inventory)===admitted.intent.extension_binding.artifact_set_digest,'module_content_binding');
 function attachExecutionDevice(device,session){
  if(!implementation.execution)return;
  const exit='exit_'+hash({ipc_session_id:execution.ipc_session_id,device_id:device,device_session_id:session}).slice(7);
  const bound={scope:{authority_service_id:execution.authority_service_id,database_instance_id:execution.database_instance_id},
   controller_boot_id:execution.controller_boot_id,worker_boot_id:execution.worker_boot_id,ipc_session_id:execution.ipc_session_id,
   clock_domain_id:execution.clock_domain_id,descriptor_digest:execution.descriptor_digest,writer_exit_id:exit,device_id:device,device_session_id:session};
  executionBindings.set(device,bound);
  const gate=deviceExecutionGate({binding:bound,transmissions:()=>executions.get(device)?.fenceSnapshot(),tick:()=>clock.tick(),signal:abort.signal,failed:stop,limits:{max_entries:4096,max_metadata_bytes:1048576}});
  if(executionSession)executionSession.replaceDevice(device,gate);gates.set(device,gate);
  if(executionSession||!admitted.intent.object_scope.device_ids.every(id=>sessions.has(id)))return;
  executionSession=deviceWorkerSession({socket:executionSocket(admitted.receipt.member_boot_id,'worker'),identity:execution,descriptor:admitted.descriptor,
   devices:gates,signal:abort.signal,failed:stop,limits:{max_frames:4096,max_history_bytes:16777216,max_queue_entries:64,max_queue_bytes:1048576,write_timeout_ms:2000},
   async receive({frame,payload}){
    if(frame.type==='HELLO_ACK')return;
    need(gates.has(frame.device_id),'module_execution_unsupported');
    if(['FENCE','OPEN_GATE','GATE_FENCE','AUTH_FENCE','QUERY_BARRIER','BARRIER_STORED'].includes(frame.type)){
     if(frame.type!=='FENCE')need(executions.has(frame.device_id),'module_execution_unbound');
     const response=await gates.get(frame.device_id).receive(payload);if(response)void executionSession.send(response).catch(stop);
    }else{const owner=executions.get(frame.device_id);need(owner,'module_execution_unbound');await owner.receive({frame,payload});}
   }});
  void executionSession.start({module_id:materials.manifest.extension_id,module_digest:materials.inventory.files.find(f=>f.file_id===entry.file_id).digest,
   clock_domain_id:execution.clock_domain_id,descriptor_digest:execution.descriptor_digest,clock_domain_descriptor:admitted.descriptor,
   supported_ipc_versions:[deviceExecutionVersion],supported_features:[...deviceExecutionCapabilities.base,...deviceExecutionCapabilities.initial_control,
    ...(fixedWorkerExecutionAvailable(materials,entry)?[...deviceExecutionCapabilities.manual,...deviceExecutionCapabilities.without_reference]:[])]}).catch(stop);
 }
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
    const expectedExecution=executionSessionIdentity({authority_service_id:runtime.service_id,database_instance_id:runtime.database_instance_id,
     controller_boot_id:executionIdentity?.controller_boot_id,worker_boot_id:admitted.receipt.member_boot_id,
     clock_domain_id:admitted.descriptor.clock_domain_id,descriptor_digest:admitted.descriptor.descriptor_digest});
    need(same(expectedExecution,executionIdentity),'module_execution_binding');execution=expectedExecution;
    need(same(frame.body.configuration.reference,admitted.intent.extension_binding.configuration_ref),'module_configuration');
    binding=frame.binding;
    need(materials.manifest.api_versions.includes('leafseamer-device-module/2')&&materials.manifest.ipc_versions.includes(deviceModuleProtocol),'module_version');
    // 文件政策和模块都是批准归档的固定字节；策略对象不自赋联网或设备写许可。
    file(entry.io_policy_file_id,'policy');const selected=await import(pathToFileURL(file(entry.file_id,'module')).href);current(frame);
    need(typeof selected.createDeviceModule==='function','module_interface');
    implementation=await selected.createDeviceModule(Object.freeze({configuration:frame.body.configuration.value,
     device_ids:admitted.intent.object_scope.device_ids,signal:abort.signal,tick:()=>clock.tick()}));current(frame);
    need(implementation?.api_version==='leafseamer-device-module/2'&&['connectReadOnly','proposeCatalog','captureBaseline','stopReadOnly'].every(k=>typeof implementation[k]==='function'),'module_interface');
    if(materials.manifest.api_versions.includes('leafseamer-device-primitives/1'))need(implementation.execution?.api_version==='leafseamer-device-primitives/1'&&
     ['encodePrimitive','writePrimitive'].every(key=>typeof implementation.execution[key]==='function'),'module_execution_interface');
    type='LOADED';body={entry_id:entry.entry_id};
   }else{
    need(same(frame.binding,binding),'module_binding');const input=frame.body,device=input.device_id,session=input.device_session_id;
    need(admitted.intent.object_scope.device_ids.includes(device),'module_device');
    if(frame.type==='CONNECT'){
     need(!sessions.has(device)&&!usedSessions.has(session)&&usedSessions.size<4096,'module_session');usedSessions.add(session);
     const identity=Object.freeze(structuredClone(await implementation.connectReadOnly({...input,signal:abort.signal})));current(frame);
     const catalog=await implementation.proposeCatalog({...input,identity,signal:abort.signal});current(frame);
     sessions.set(device,session);attachExecutionDevice(device,session);type='CONNECTED';body={...input,identity,catalog};
    }else{
     need(sessions.get(device)===session,'module_session');
     if(frame.type==='BIND_EXECUTION'){
      need(implementation.execution&&gates.has(device),'module_execution_unavailable');const previous=executions.get(device);
      if(previous)need(same(previous.ref,input.execution.ref)&&hash(input.execution.value)===previous.ref.digest,'module_execution_rebind');
      else executions.set(device,deviceWorkerExecution({execution:input.execution,binding:executionBindings.get(device),runtimeRef:binding.runtime_binding_ref,
       approvalRef:admitted.intent.extension_binding.approval_ref,materials,entry,executor:implementation.execution,gate:gates.get(device),tick:()=>clock.tick(),
       signal:abort.signal,failed:stop,send:candidate=>executionSession.send(candidate)}));
      type='EXECUTION_BOUND';body={device_id:device,device_session_id:session,execution_ref:input.execution.ref};
     }else if(frame.type==='CAPTURE'){
      need(!usedCaptures.has(input.capture_id)&&usedCaptures.size<4096,'module_capture');usedCaptures.add(input.capture_id);
      const value=await implementation.captureBaseline({...input,signal:abort.signal});current(frame);
      type='CAPTURED';body={...input,value,captured_tick_ns:String(clock.tick())};
     }else{
      need(frame.type==='DISCONNECT','module_direction');gates.get(device)?.protect();
      executions.get(device)?.close();executions.delete(device);executionBindings.delete(device);
      sessions.delete(device);await implementation.stopReadOnly({...input,signal:abort.signal});current(frame);type='DISCONNECTED';body=input;
     }
    }
   }
   current(frame);await transport.send({...frame,version:deviceModuleProtocol,type,request_id:crypto.randomUUID(),reply_to:frame.request_id,body});
  }finally{clearTimeout(timer);}
 }});
 // 只向固定worker装配层提供当前身份；不传给第三方模块，也不代表HELLO已协商或闸已开放。
 return Object.freeze({close:stop,executionIdentity(){need(!stopped&&implementation&&execution,'module_execution_unavailable');return execution;}});
}
