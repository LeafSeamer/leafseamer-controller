import fs from 'node:fs';
import {canonical,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
const review=JSON.parse(fs.readFileSync(new URL('./simulator-control-footprint.json',import.meta.url),'utf8'));
const template=JSON.parse(fs.readFileSync(new URL('./simulator-control-capability.json',import.meta.url),'utf8'));
const same=(a,b)=>canonical(a)===canonical(b);
const need=(ok)=>{if(!ok)throw new IdentityError('device_footprint_integrity');};
const reviewRef={id:review.review_id,revision:review.revision,digest:digest(review)};

// 核心固定审阅策略；模块自报complete、模板声明和HTTP输入都不能生成资格。
// 哈希固定在审阅原件中，不能在模块升级时自动以新文件摘要重签旧语义。
export function qualifyDeviceFootprint({runtime,qualification:q,channel_id,device_session_id,catalog}){
 if(q.qualification!=='fixed_memory_control_catalog/1'||q.module_digest!==review.module_digest||
  q.protocol_io_policy_digest!==review.protocol_io_policy_digest||q.template_digest!==review.template_digest)return null;
 need(review.format==='leafseamer-fixed-footprint-review/1'&&review.parameter_scope==='all_allowed_parameters'&&
  review.effect_scope==='entire_virtual_device_and_shared_worker'&&same(review.safe_failure_classes,[])&&digest(template)===review.template_digest);
 need(template.actions.length===1&&template.actions[0].action_id===review.action_id&&same(catalog.action_ids,[review.action_id])&&
  same(catalog.trigger_ids,[])&&same(catalog.state_schema,template.state_schema));
 const scope={authority_service_id:runtime.binding.service_id,database_instance_id:runtime.binding.database_instance_id};
 // 设备物理路径来自核心资源原件；共享worker占用覆盖进程级故障与容量，不推断不同设备独立。
 const device='virtual/'+digest({scope,resource_ref:q.resource_ref}).slice(7),worker='worker/'+digest({scope,runtime_ref:runtime.ref}).slice(7);
 const action=template.actions[0];
 return structuredClone({format:'leafseamer-device-footprint-qualification/1',scope,review_ref:reviewRef,review,
  runtime_binding_ref:runtime.ref,channel_id,device_session_id,qualification:q,catalog_digest:digest(catalog),
  parameter_scope:'all_allowed_parameters',parameter_schema_refs:[{action_id:action.action_id,schema_id:action.parameters_schema.schema_id,digest:action.parameters_schema.digest}],
  alias_rule:'core_virtual_resource_and_runtime/1',action_footprints:[{action_id:action.action_id,manifest_digest:q.manifest_digest,
   semantics_revision:review.semantics_revision,complete:true,reads:[device],writes:[device],failure_writes:[device],resources:[device,worker],safe_failure_classes:[]}]});
}

export function readDeviceFootprint(approved,runtime){
 // 旧原件没有此字段时保持未确认，不能在读取历史时补造批准。
 if(approved.footprint_qualification==null)return null;
 const expected=qualifyDeviceFootprint({runtime,qualification:approved.qualification,channel_id:approved.channel_id,
  device_session_id:approved.device_session_id,catalog:approved.catalog});
 need(expected&&['leafseamer-catalog-approval/2','leafseamer-catalog-approval/3'].includes(approved.format)&&same(approved.footprint_qualification,expected));
 return structuredClone(expected);
}
