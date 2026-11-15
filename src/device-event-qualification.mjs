import fs from 'node:fs';
import {canonical,digest} from './auth-clock-value.mjs';
import {moduleNeed as need,validateDeviceModuleFrame} from './sdk/device-module.mjs';
import {readDeviceFootprint} from './device-footprint-qualification.mjs';
const review=JSON.parse(fs.readFileSync(new URL('./simulator-event-review.json',import.meta.url),'utf8'));
const same=(a,b)=>canonical(a)===canonical(b);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const counter=value=>typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value);

// 核心对固定制品的捕获语义核验。此结果不是规范摄取或自动化触发许可。
export function qualifyDeviceEventFrame({approved,runtime,frame,started=null}){
 validateDeviceModuleFrame(frame);
 need(['EVENT_STARTED','EVENT_BATCH'].includes(frame.type),'module_event_source_frame');
 const footprint=readDeviceFootprint(approved,runtime),q=approved.qualification;
 need(footprint&&review.format==='leafseamer-fixed-event-review/1'&&
  ['module_digest','protocol_io_policy_digest','template_digest'].every(key=>q[key]===review[key]),'module_event_source_qualification');
 need(same(approved.runtime_binding_ref,runtime.ref)&&same(frame.binding.runtime_binding_ref,runtime.ref)&&
  frame.binding.member_boot_id===runtime.binding.admission_receipt.member_boot_id&&frame.binding.ipc_session_id===approved.channel_id&&
  frame.body.device_id===approved.device_id&&frame.body.device_session_id===approved.device_session_id,'module_event_source_binding');
 const capture=frame.type==='EVENT_STARTED'?frame.body.capture:frame.body.result.batch.capture;
 need(capture.event_type===review.event_type&&exact(capture.baseline,['write_sequence'])&&counter(capture.baseline.write_sequence),'module_event_source_schema');
 if(frame.type==='EVENT_BATCH'){
  need(started,'module_event_source_start');validateDeviceModuleFrame(started);
  need(started.type==='EVENT_STARTED'&&same(started.binding,frame.binding)&&same(started.body.capture,capture)&&
   BigInt(started.sequence)<BigInt(frame.sequence),'module_event_source_start');
  const result=frame.body.result,batch=result.batch;
  need(digest(batch)===result.batch_digest,'module_event_source_digest');
  const baseline=BigInt(capture.baseline.write_sequence);
  need(baseline+BigInt(result.highest_sequence)<=99999999999999999999n,'module_event_source_sequence');
  for(const event of batch.events){
   const payload=event.payload;
   need(exact(payload,['value','write_sequence'])&&Number.isInteger(payload.value)&&!Object.is(payload.value,-0)&&
    payload.value>=review.value_minimum&&payload.value<=review.value_maximum&&counter(payload.write_sequence),'module_event_source_schema');
   need(BigInt(payload.write_sequence)===baseline+BigInt(event.sequence),'module_event_source_sequence');
  }
 }
 return structuredClone({format:'leafseamer-device-event-qualification/1',review_ref:{id:review.review_id,revision:review.revision,digest:digest(review)},
  review,catalog_approval_ref:{id:approved.approval_id,revision:'1',digest:digest(approved)},runtime_binding_ref:runtime.ref,
  channel_id:approved.channel_id,device_id:approved.device_id,device_session_id:approved.device_session_id,capture,
  capture_message_id:(started??frame).request_id,
  clock_domain_descriptor:runtime.binding.clock_domain_descriptor});
}
