import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeArtifactDocument} from './sdk/artifact-import.mjs';
import {extensionConfigurationStore} from './extension-configuration-store.mjs';
import {extensionRoleStore} from './extension-role-store.mjs';
import {extensionReviewStore} from './extension-review-store.mjs';
import {extensionApprovalState} from './extension-approval-state.mjs';
import {extensionLaunchBinding} from './extension-launch-binding.mjs';
import {extensionApprovalStore} from './extension-approval-store.mjs';
import {extensionPlanStore} from './extension-plan-store.mjs';
import {extensionActivationStore} from './extension-activation-store.mjs';

export class ExtensionInstallationError extends Error {constructor(code){super(code);this.name='ExtensionInstallationError';this.code=code;}}
const need=(ok,code)=>{if(!ok)throw new ExtensionInstallationError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const digest=value=>typeof value==='string'&&/^sha256:[0-9a-f]{64}(?![\s\S])/.test(value);
const exact=(value,fields)=>value&&Object.keys(value).sort().join(',')===fields.split(',').sort().join(',');
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
const rows=(db,sql,...args)=>{const q=db.prepare(sql),names=q.columns().map(c=>c.name);return q.raw().all(...args).map(row=>Object.fromEntries(names.map((n,i)=>[n,row[i]])));};
function decoded(body,expected){const value=JSON.parse(body);need(canonicalize(value)===body&&hash(value)===expected,'extension_record_integrity');return value;}
function intakeRef(value){need(exact(value,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&value.kind==='intake'&&
  ['authority_service_id','database_instance_id','object_id'].every(k=>id(value[k]))&&value.revision==='1'&&digest(value.digest),'extension_intake_ref');return structuredClone(value);}

// 可信本机装配入口，只产生候选安装；没有HTTP入口、运行批准或任意模块加载。
export function extensionInstallationStore(db,service,isOpen,attachManagement,attachWorkerSource,bootId){
  let source=null,active=0;
  const available=()=>{need(isOpen()&&db.open,'extension_store_closed');need(!db.inTransaction,'extension_outer_transaction');};
  const reference=(kind,object,revision,body)=>({kind,authority_service_id:service.service_id,database_instance_id:service.database_instance_id,object_id:object,revision:String(revision),digest:hash(body)});
  const operation=request=>rows(db,'SELECT * FROM extension_operation WHERE request_id=?',request)[0];
  function original(input,kind){const row=operation(input.request_id);if(!row)return null;need(row.kind===kind&&row.input_digest===hash(input)&&row.input_jcs===canonicalize(input),'extension_request_conflict');return frozen(decoded(row.result_jcs,row.result_digest));}
  const reserve=()=>need(db.prepare('SELECT count(*) FROM extension_operation').pluck().get()<4096,'extension_capacity');
  function save(input,kind,slot,revision,installation,op,result){
    const audit={kind:'extension_'+kind,operation_id:op,request_id:input.request_id,slot_id:slot,installation_id:installation,result_digest:hash(result)};
    const extended=Number(service.schema_revision)>=22;
    db.prepare('INSERT INTO extension_operation VALUES('+Array(extended?13:11).fill('?').join(',')+')').run(input.request_id,op,kind,slot,revision,installation,
      canonicalize(input),hash(input),canonicalize(result),hash(result),canonicalize(audit),...(extended?[kind==='stage'?op:null,null]:[]));return frozen(result);
  }
  const current=slot=>rows(db,'SELECT r.* FROM extension_slot_head h JOIN extension_slot_revision r USING(slot_id,revision) WHERE h.slot_id=?',slot)[0];
  function slotRecord(slot,extension,revision,op){
    const body={slot_id:slot,extension_id:extension,revision:String(revision),active_installation_id:null,
      ...(Number(service.schema_revision)>=22?{desired_state:'disabled',pending_operation_ref:null,pending_installation_ref:null,configuration_ref:null}:{})};
    db.prepare('INSERT INTO extension_slot_revision VALUES(?,?,?,?,?,?)').run(slot,revision,op,extension,canonicalize(body),hash(body));
    return {slot_ref:reference('slot',slot,revision,body),record:body};
  }
  const configurations=Number(service.schema_revision)>=14?extensionConfigurationStore({db,service,available,reference,source:()=>source}):null;
  let currentResolution,currentReview;
  const roles=Number(service.schema_revision)>=15?extensionRoleStore({db,service,available,reference,source:()=>source,attachCurrent:read=>{currentResolution=read;}}):null;
  const reviews=Number(service.schema_revision)>=16?extensionReviewStore({db,service,available,reference,source:()=>source,currentResolution,attachCurrent:read=>{currentReview=read;}}):null;
  let launch=null;
  if(Number(service.schema_revision)>=18){const state=extensionApprovalState({db,service,reference,currentReview,currentResolution});
    launch=extensionLaunchBinding({db,service,available,source:()=>source,currentApproval:state.current,currentResolution,reference});}
  const plans=Number(service.schema_revision)>=21?extensionPlanStore({db,service,bootId,available,reference,launch}):null;
  const lifecycle=Number(service.schema_revision)>=22?extensionActivationStore({db,service,bootId,available,reference,launch,plans}):null;
  if(launch)attachWorkerSource?.(lifecycle?Object.freeze({...launch,current(intent){const chosen=launch.current(intent);lifecycle.forLaunch(intent);return chosen;},activation:lifecycle.forLaunch}):launch);
  if(Number(service.schema_revision)>=17)attachManagement?.(authorize=>Object.freeze({...extensionApprovalStore({db,service,available,reference,source:()=>source,currentReview,currentResolution,authorize}),plans:plans?.management(authorize)??null,lifecycle:lifecycle?.management(authorize)??null}));
  return Object.freeze({
    configurations,roles,reviews,bindRuntimeSource:plans?.bindRuntimeSource,
    bindSource(host){
      available();need(!source&&host&&typeof host.describeIntake==='function','extension_source_binding');
      const identity=host.identity;need(identity&&['host_installation_id','authority_service_id','database_instance_id'].every(k=>id(identity[k])),'extension_source_binding');
      source={identity:Object.fromEntries(['host_installation_id','authority_service_id','database_instance_id'].map(k=>[k,identity[k]])),describe:host.describeIntake.bind(host),
        schema:typeof host.describeConfigurationSchema==='function'?host.describeConfigurationSchema.bind(host):null,
        capabilities:typeof host.describeCapabilityTemplates==='function'?host.describeCapabilityTemplates.bind(host):null,
        loader:typeof host.acquireMaterialization==='function'?host.acquireMaterialization.bind(host):null};
    },
    createSlot(input){
      available();need(exact(input,'request_id,extension_id')&&id(input.request_id)&&id(input.extension_id),'extension_slot_input');const fixed=structuredClone(input);
      return db.transaction(()=>{const prior=original(fixed,'create_slot');if(prior)return prior;reserve();
        const slot=crypto.randomUUID(),op=crypto.randomUUID(),result=slotRecord(slot,fixed.extension_id,1,op);
        db.prepare('INSERT INTO extension_slot_head VALUES(?,1)').run(slot);return save(fixed,'create_slot',slot,1,null,op,result);
      }).immediate();
    },
    async stage(input){
      available();need(exact(input,'request_id,slot_id,expected_slot_revision,intake_ref')&&id(input.request_id)&&id(input.slot_id)&&
        typeof input.expected_slot_revision==='string'&&/^[1-9][0-9]{0,3}(?![\s\S])/.test(input.expected_slot_revision),'extension_stage_input');
      const fixed=structuredClone({...input,intake_ref:intakeRef(input.intake_ref)}),prior=db.transaction(()=>original(fixed,'stage')).immediate();if(prior)return prior;
      need(source&&fixed.intake_ref.authority_service_id===source.identity.authority_service_id&&fixed.intake_ref.database_instance_id===source.identity.database_instance_id,'extension_source_binding');
      need(active<4,'extension_capacity');++active;
      try{
        const response=await source.describe({intake_id:fixed.intake_ref.object_id,target_authority_service_id:service.service_id});available();
        need(response?.status==='available','extension_intake_unavailable');
        const content=structuredClone(response.content);need(exact(content,'format,intake_ref,receipt,manifest,inventory')&&content.format==='leafseamer-intake-content/1','extension_content_binding');
        const receipt=content.receipt;
        need(same(intakeRef(content.intake_ref),fixed.intake_ref)&&hash(receipt)===fixed.intake_ref.digest&&receipt.intake_id===fixed.intake_ref.object_id&&
          receipt.target_authority_service_id===service.service_id&&receipt.host_installation_id===source.identity.host_installation_id,'extension_content_binding');
        const manifest=await decodeArtifactDocument(Buffer.from(canonicalize(content.manifest)),'Manifest');
        const inventory=await decodeArtifactDocument(Buffer.from(canonicalize(content.inventory)),'FileInventory');available();
        need(hash(manifest)===receipt.manifest_digest&&hash(inventory)===receipt.artifact_set_digest&&manifest.inventory_digest===receipt.artifact_set_digest&&
          manifest.kind==='device_module','extension_content_binding');
        // stage保存该次完整观察；后续审批及启动必须重新取得当前资格。
        return db.transaction(()=>{
          const raced=original(fixed,'stage');if(raced)return raced;reserve();const slot=current(fixed.slot_id);need(slot,'extension_slot_missing');
          const currentSlot=decoded(slot.body_jcs,slot.body_digest);need(String(slot.revision)===fixed.expected_slot_revision,'extension_slot_stale');
          need(currentSlot.pending_operation_ref==null&&(currentSlot.desired_state===undefined||currentSlot.desired_state==='disabled'),'extension_slot_busy');
          need(slot.extension_id===manifest.extension_id,'extension_content_binding');need(slot.revision<4096,'extension_capacity');
          const installation=crypto.randomUUID(),op=crypto.randomUUID(),revision=slot.revision+1;
          const originalContent={installation_id:installation,slot_id:slot.slot_id,scope:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id},...content};
          const body=canonicalize(originalContent);need(Buffer.byteLength(body)<=8388608&&
            db.prepare('SELECT coalesce(sum(length(CAST(content_jcs AS BLOB))),0) FROM extension_candidate').pluck().get()+Buffer.byteLength(body)<=67108864,'extension_capacity');
          const slotView=slotRecord(slot.slot_id,slot.extension_id,revision,op),installRef=reference('installation',installation,1,originalContent);
          db.prepare('INSERT INTO extension_candidate VALUES(?,?,?,?,?,?,?)').run(installation,op,slot.slot_id,revision,body,hash(originalContent),'verified');
          db.prepare('UPDATE extension_slot_head SET revision=? WHERE slot_id=?').run(revision,slot.slot_id);
          return save(fixed,'stage',slot.slot_id,revision,installation,op,{installation_ref:installRef,slot:slotView,state:'verified',approval_ref:null,runtime_binding_refs:[]});
        }).immediate();
      }finally{--active;}
    },
    query(requestId){available();need(id(requestId),'extension_request_id');return db.transaction(()=>{const row=operation(requestId);return row?frozen(decoded(row.result_jcs,row.result_digest)):null;}).immediate();},
    content(ref){available();need(exact(ref,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&ref.kind==='installation'&&
      ref.authority_service_id===service.service_id&&ref.database_instance_id===service.database_instance_id&&id(ref.object_id)&&ref.revision==='1'&&digest(ref.digest),'extension_installation_ref');
      return db.transaction(()=>{const row=rows(db,'SELECT * FROM extension_candidate WHERE installation_id=?',ref.object_id)[0];need(row&&row.content_digest===ref.digest,'extension_installation_missing');return frozen(decoded(row.content_jcs,row.content_digest));}).immediate();}
  });
}
