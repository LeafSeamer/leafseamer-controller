import crypto from 'node:crypto';
import canonicalize from 'canonicalize';

export class WorkerDependencyError extends Error {constructor(code){super(code);this.name='WorkerDependencyError';this.code=code;}}
const need=(ok,code)=>{if(!ok)throw new WorkerDependencyError('worker_dependency_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const freeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;};
const reference=(service,kind,object,body)=>({kind,authority_service_id:service.service_id,database_instance_id:service.database_instance_id,object_id:object,revision:'1',digest:hash(body)});
function read(text,digest){const value=JSON.parse(text);need(canonicalize(value)===text&&hash(value)===digest,'integrity');return value;}
function device(db,service,deviceId){
 const row=db.prepare('SELECT descriptor_body,descriptor_digest FROM device_record WHERE device_id=?').raw().get(deviceId);need(row,'device_missing');
 const body=read(row[0].toString('utf8'),row[1]);return {body,ref:reference(service,'device',deviceId,body)};
}
function resource(db,service,deviceId){
 const row=db.prepare('SELECT body_jcs,body_digest FROM virtual_device_resource WHERE device_id=?').raw().get(deviceId);need(row,'resource_provider_unavailable');
 const body=read(row[0],row[1]),current=device(db,service,deviceId);
 need(body.backend==='core_virtual_device/1'&&same(body.device_ref,current.ref)&&current.body.device_kind==='simulator'&&
  same(body.external_resources,[])&&body.resource_id&&body.device_id===deviceId,'resource_binding');
 return {body,ref:reference(service,'resource',body.resource_id,body),device:current.ref};
}

// 与registerDevice相同的可信本机装配边界；普通HTTP不能指定资源身份或伪造物理别名。
// 仅固定内存模拟器可声明无外部资源；物理设备必须接入独立的身份/别名提供者。
export function configureVirtualDevice(db,service,input){
 need(db.open&&!db.inTransaction,'writer');need(Number(service.schema_revision)>=20,'migration_required');
 need(input&&Object.keys(input).sort().join(',')==='device_id,request_id'&&id(input.request_id)&&id(input.device_id),'input');
 const fixed=structuredClone(input),digest=hash(fixed);
 return db.transaction(()=>{
  need(db.prepare('SELECT count(*) FROM identity_receipt').pluck().get()===1,'admin_required');
  const prior=db.prepare('SELECT device_id,input_digest FROM virtual_device_resource WHERE request_id=?').raw().get(fixed.request_id);
  if(prior){need(prior[1]===digest&&prior[0]===fixed.device_id,'conflict');const result=resource(db,service,fixed.device_id);return freeze({resource_ref:result.ref,record:result.body});}
  const selected=device(db,service,fixed.device_id);need(selected.body.device_kind==='simulator','physical_provider_required');
  need(!db.prepare('SELECT 1 FROM virtual_device_resource WHERE device_id=?').pluck().get(fixed.device_id),'frozen');
  need(!db.prepare('SELECT 1 FROM worker_launch_device WHERE device_id=?').pluck().get(fixed.device_id),'already_prepared');
  need(db.prepare('SELECT count(*) FROM virtual_device_resource').pluck().get()<4096,'capacity');
  const transaction=crypto.randomUUID(),body={format:'leafseamer-device-resource/1',resource_id:crypto.randomUUID(),device_id:fixed.device_id,
   device_ref:selected.ref,backend:'core_virtual_device/1',external_resources:[]};
  db.prepare('INSERT INTO virtual_device_resource VALUES(?,?,?,?,?,?,?)').run(fixed.device_id,body.resource_id,fixed.request_id,digest,canonicalize(body),hash(body),transaction);
  db.prepare('INSERT INTO virtual_device_resource_commit VALUES(?,?,?)').run(transaction,fixed.device_id,canonicalize({kind:'virtual_device_resource_configured',transaction_id:transaction,device_id:fixed.device_id,resource_digest:hash(body)}));
  return freeze({resource_ref:reference(service,'resource',body.resource_id,body),record:body});
 }).immediate();
}

// 依赖集合来自当前审批、完整角色解析、已验证模板和核心资源登记；调用方不提交集合。
export function installationDependencies(db,service,selected){
 need(db.inTransaction,'writer');need(selected,'scope');
 need(selected.resolution.bindings.every(value=>value.kind==='device'),'object_provider_unavailable');
 need(selected.permissions.every(value=>value.kind==='device_scope'),'permission_provider_unavailable');
 const raw=db.prepare('SELECT body_jcs,body_digest FROM extension_approval_capabilities WHERE approval_id=?').raw().get(selected.approval.approval_ref.object_id);
 need(raw,'capabilities_missing');const evidence=read(raw[0],raw[1]);
 need(evidence.format==='leafseamer-static-capability-evidence/1'&&same(evidence.intake_ref,selected.content.intake_ref)&&
  evidence.manifest_digest===selected.content.receipt.manifest_digest&&evidence.artifact_set_digest===selected.content.receipt.artifact_set_digest,'capability_binding');
 const byDevice=new Map(),links=[];
 for(const role of selected.resolution.bindings){
  for(const ref of role.values){
   const target=resource(db,service,ref.object_id);need(same(target.device,ref),'device_stale');byDevice.set(ref.object_id,target);
   const matches=evidence.documents.filter(value=>value.template.device_role===role.role_id&&value.template.device_kind==='simulator');
   need(matches.length===1,'footprint_unavailable');const template=matches[0].template;
   // 全部动作均进入最坏足迹，包括本次未批准/未选择的动作。未知资源或依赖不能当空集合。
   for(const action of template.actions){
    need(action.dependencies.length===0,'dependency_provider_unavailable');
    need([...action.resources,...action.read_set,...action.write_set].every(value=>value==='device'),'resource_alias_unavailable');
   }
   links.push({role_id:role.role_id,device_ref:target.device,resource_ref:target.ref,
    action_ids:template.actions.map(value=>value.action_id).sort(),trigger_ids:template.triggers.map(value=>value.trigger_id).sort(),template_digest:hash(template)});
  }
 }
 const devices=[...byDevice.keys()].sort();need(devices.length>=1&&devices.length<=64&&links.length<=256,'capacity');
 const ordered=devices.map(key=>byDevice.get(key));
 return freeze({capability_evidence_digest:raw[1],devices:ordered.map(value=>value.device),resources:ordered.map(value=>value.ref),links:links.sort((a,b)=>canonicalize(a)<canonicalize(b)?-1:1)});
}

export function workerDependencies(db,service,intent,selected){
 need(intent.object_scope.kind==='devices','scope');const graph=installationDependencies(db,service,selected);
 need(same(graph.devices.map(value=>value.object_id),intent.object_scope.device_ids),'incomplete_device_scope');
 const body={format:'leafseamer-worker-dependencies/1',launch_id:intent.launch_id,launch_intent_digest:hash(intent),
  installation_ref:intent.extension_binding.installation_ref,approval_ref:intent.extension_binding.approval_ref,
  role_resolution_ref:intent.extension_binding.role_resolution_ref,configuration_ref:intent.extension_binding.configuration_ref,
  permissions_digest:intent.extension_binding.permissions_digest,...graph};
 need(Buffer.byteLength(canonicalize(body))<=4194304,'capacity');return freeze(body);
}

export function currentWorkerDependencies(db,service,intent,selected){
 const row=db.prepare('SELECT body_jcs,body_digest FROM worker_launch_dependencies WHERE launch_id=?').raw().get(intent.launch_id);need(row,'missing');
 const saved=read(row[0],row[1]);need(same(saved,workerDependencies(db,service,intent,selected)),'stale');return freeze(saved);
}
