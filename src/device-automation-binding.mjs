import fs from 'node:fs';
import {canonical,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {readDeviceFootprint} from './device-footprint-qualification.mjs';
import {validateAutomationModel} from './sdk/automation-program.mjs';
import {readCurrentDeviceCatalog} from './device-capability-view.mjs';
const review=JSON.parse(fs.readFileSync(new URL('./simulator-control-bindings.json',import.meta.url),'utf8'));
const template=JSON.parse(fs.readFileSync(new URL('./simulator-control-capability.json',import.meta.url),'utf8'));
const need=(ok,reason)=>{if(!ok)throw new IdentityError('device_automation_'+reason);};
const same=(a,b)=>canonical(a)===canonical(b);
const ref=(id,value)=>({id,revision:'1',digest:digest(value)});
const schemaRef=value=>({id:value.schema_id,revision:'1',digest:value.digest});

// 仅由目录接纳writer调用。用户和模块只能选择对象，不能提交投影、槽或批准正文。
export function registerDeviceAutomation(approved,runtime){
 const footprint=readDeviceFootprint(approved,runtime);if(!footprint)return null;
 need(review.format==='leafseamer-fixed-binding-review/1'&&review.parameter_scope==='all_allowed_parameters'&&
  review.footprint_review_digest===footprint.review_ref.digest&&digest(template)===approved.qualification.template_digest,'review');
 const action=template.actions[0],prefix='source-'+approved.approval_id;
 const body={format:'leafseamer-device-automation-registration/1',registration_id:prefix,scope:footprint.scope,
  source_kind:'observation',provider_id:runtime.binding.launch_intent.member_id,provider_boot_id:runtime.binding.admission_receipt.member_boot_id,
  device_id:approved.device_id,device_session_id:approved.device_session_id,channel_id:approved.channel_id,runtime_binding_ref:runtime.ref,
  qualification:approved.qualification,catalog_ref:ref(approved.approval_id+'.catalog',approved.catalog),
  footprint_ref:ref(approved.approval_id+'.footprint',footprint),binding_review_ref:{id:review.review_id,revision:review.revision,digest:digest(review)},binding_review:review,
  state_schema_ref:schemaRef(template.state_schema),parameter_schema_ref:schemaRef(action.parameters_schema),result_schema_ref:schemaRef(action.result_schema),
  capability_id:action.action_id,capability_version:action.capability_version,parameter_scope:'all_allowed_parameters'};
 return structuredClone(body);
}

export function readDeviceAutomationRegistration(approved,runtime){
 need(approved.format==='leafseamer-catalog-approval/3'&&approved.automation_registration,'registration_required');
 const expected=registerDeviceAutomation(approved,runtime);need(expected&&same(expected,approved.automation_registration),'registration_stale');
 return expected;
}

export function readDeviceAutomationBindings(db,input,expectedRef=null){
 const {approved,qualified}=readCurrentDeviceCatalog(db,input),registration=readDeviceAutomationRegistration(approved,input.runtime);
 const registrationRef={kind:'source_registration',scope:registration.scope,object_id:registration.registration_id,revision:'1',digest:digest(registration)};
 if(expectedRef!==null)need(same(expectedRef,registrationRef),'registration_stale');
 const contentRef={id:registrationRef.object_id,revision:registrationRef.revision,digest:registrationRef.digest};
 const action=template.actions[0],effect=qualified.action_footprints[0],prefix=registration.registration_id;
 const observation={binding_id:prefix+'.observation',source:'observation',authority_id:registration.scope.authority_service_id,
  registration_ref:contentRef,schema_ref:registration.state_schema_ref,producer_step_id:null,
  projections:review.observation_projections.map(value=>({...value,reads:effect.reads}))};
 const boundAction={binding_id:prefix+'.action',authority_id:registration.scope.authority_service_id,controller_id:registration.scope.authority_service_id,
  device_id:registration.device_id,provider_id:registration.provider_id,capability_id:registration.capability_id,registration_ref:contentRef,
  catalog_ref:registration.catalog_ref,module_ref:{id:registration.qualification.installation_ref.object_id,revision:registration.qualification.installation_ref.revision,digest:registration.qualification.module_digest},
  parameter_schema_ref:registration.parameter_schema_ref,result_schema_ref:registration.result_schema_ref,parameter_slots:review.parameter_slots,
  footprint:{complete:true,evidence_ref:registration.footprint_ref,...Object.fromEntries(['reads','writes','failure_writes','resources','safe_failure_classes'].map(key=>[key,effect[key]])),
   preconditions:effect.reads,target_constraints:effect.resources}};
 validateAutomationModel('InputBinding',observation);validateAutomationModel('ActionBinding',boundAction);
 const binding=(kind,value)=>({kind,binding_id:value.binding_id,content_ref:ref(value.binding_id,value),value});
 return structuredClone({registration_ref:registrationRef,registration,bindings:[binding('input',observation),binding('action',boundAction)],
  schemas:[{binding_id:boundAction.binding_id,schema_ref:boundAction.parameter_schema_ref,document:action.parameters_schema.document}],
  input_schemas:[{schema_ref:observation.schema_ref,document:template.state_schema.document}],
  result_schema:{schema_ref:boundAction.result_schema_ref,document:action.result_schema.document,projections:review.result_projections},
  alias_table:{ref:ref(prefix+'.aliases',[]),entries:[]}});
}
