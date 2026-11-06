import fs from 'node:fs';
import crypto from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {moduleNeed as need,moduleExact as exact} from './sdk/device-module.mjs';
import {devicePacketPreparation} from './device-packet-preparation.mjs';
import {deviceTransmissionWriter} from './device-transmission-writer.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const fileHash=name=>'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(new URL(name,import.meta.url))).digest('hex');
const moduleDigest=fileHash('./simulator-control-module.mjs'),policyDigest=fileHash('./simulator-control-policy.json');
const template=JSON.parse(fs.readFileSync(new URL('./simulator-control-capability.json',import.meta.url)));
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const reference=(id,value)=>({id,revision:'1',digest:hash(value)});
export function fixedWorkerExecutionAvailable(materials,entry){return materials.inventory.files.find(f=>f.file_id===entry.file_id)?.digest===moduleDigest&&
 materials.inventory.files.find(f=>f.file_id===entry.io_policy_file_id)?.digest===policyDigest;}

// 仅固定host调用。配置取自受监督模块通道的核心持久Binding，命令帧不能更换配置。
export function deviceWorkerExecution({execution,binding,runtimeRef,approvalRef,materials,entry,executor,gate,tick,signal,failed,send}){
 exact(execution,['ref','value']);const value=structuredClone(execution.value),id=value.binding_id,action=template.actions[0];
 exact(value,['format','binding_id','state','write_eligible','binding','runtime_binding_ref','session_ref','catalog_approval_ref','initial_sample_ref',
  'capability_ref','transport_profile','transport_profile_ref','primitive_plan','primitive_plan_ref','exit','action']);
 need(typeof id==='string'&&/^[0-9a-f-]{36}$/.test(id)&&value.format==='leafseamer-device-execution-binding/1'&&
  value.state==='bound_closed'&&value.write_eligible===false&&same(value.binding,binding)&&same(value.runtime_binding_ref,runtimeRef)&&
  same(execution.ref,reference(id,value)),'module_execution_binding');
 need(fixedWorkerExecutionAvailable(materials,entry),'module_execution_profile');
 for(const ref of [value.session_ref,value.catalog_approval_ref,value.initial_sample_ref,value.capability_ref]){
  exact(ref,['id','revision','digest']);need(typeof ref.id==='string'&&ref.id.length>0&&ref.id.length<=128&&ref.revision==='1'&&/^sha256:[0-9a-f]{64}$/.test(ref.digest),'module_execution_reference');
 }
 need(value.session_ref.id===binding.ipc_session_id&&value.capability_ref.id===approvalRef.object_id,'module_execution_reference');
 const profile={format:'leafseamer-memory-transport/1',profile_id:id+'-transport',module_digest:moduleDigest,policy_digest:policyDigest,
  transport:'memory',max_packet_bytes:8,max_in_flight:1,automatic_resends:false,external_resources:[]};
 const plan={format:'leafseamer-memory-primitive-plan/1',plan_id:id+'-plan',primitive_id:'simulator_value_set',action_id:action.action_id,capability_version:action.capability_version,
  parameters_schema_digest:action.parameters_schema.digest,packet:{length:8,prefix_hex:'4c534d31',value_offset:4,value_encoding:'int32_be'},retry:'never'};
 need(same(value.transport_profile,profile)&&same(value.transport_profile_ref,reference(profile.profile_id,profile))&&
  same(value.primitive_plan,plan)&&same(value.primitive_plan_ref,reference(plan.plan_id,plan))&&
  same(value.exit,{socket_instance_id:'memory_'+binding.writer_exit_id.slice(5),protocol_session:null})&&
  same(value.action,{action_id:action.action_id,capability_version:action.capability_version,parameters_schema_digest:action.parameters_schema.digest,result_schema_digest:action.result_schema.digest}),
  'module_execution_profile');
 const lifetime=new AbortController();let retired=false;
 const failure=error=>{if(!retired)failed(error);};
 const forward=candidate=>{need(!retired&&!lifetime.signal.aborted,'module_execution_disconnected');return send(candidate);};
 const retire=()=>{retired=true;lifetime.abort();};signal.addEventListener('abort',retire,{once:true});
 need(!signal.aborted,'module_execution_disconnected');
 const preparation=devicePacketPreparation({binding,profile:value.transport_profile_ref,plan:value.primitive_plan_ref,capability:value.capability_ref,
  exit:value.exit,executor,tick,signal:lifetime.signal,failed:failure,limits:{max_entries:32,max_cached_bytes:1048576,max_metadata_bytes:16777216,max_encoders:4}});
 const writer=deviceTransmissionWriter({binding,preparation,executor,action:value.action,currentGate:gate.currentGate,nextIoSequence:gate.nextIoSequence,
  tick,signal:lifetime.signal,failed:failure,limits:{max_guards:128,max_transmissions:128,max_metadata_bytes:16777216}});
 const later=job=>{void Promise.resolve(job).catch(failure);};
 return Object.freeze({
  // 接收只等待登记/失效；编码和模块写入不阻塞后到的关闭或屏障。
  async receive({frame,payload}){
   switch(frame.type){
    case 'ENCODE_PACKET':{const prepared=await preparation.prepare(payload);later(preparation.withResponse(prepared.prepare_id,forward));break;}
    case 'PREPARE_PACKET_REJECTED':await preparation.reject(payload);break;
    case 'DENY_ENCODING':later(forward(await preparation.deny(payload)));break;
    case 'RELEASE_ENCODING':later(preparation.release(payload).then(forward));break;
    case 'GUARD_INSTALL':later(forward(await writer.installGuard(payload)));break;
    case 'DISPATCH':later(writer.dispatch(payload).then(async report=>{await forward(report);const result=writer.query(frame.body.permit.permit_id);if(result?.evidence)await forward(result.evidence);}));break;
    case 'REPORT_STORED':await writer.stored(payload);break;
    default:need(false,'module_execution_unsupported');
   }
  },
  fenceSnapshot:writer.fenceSnapshot,
  close(){signal.removeEventListener('abort',retire);retire();},
  ref:Object.freeze(structuredClone(execution.ref))
 });
}
