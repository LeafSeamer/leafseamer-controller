import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {openNativeClock} from './native-clock.mjs';
import {installationDependencies} from './worker-dependencies.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_plan_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(value,keys)=>value&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
function read(text,digest){const body=JSON.parse(text);need(canonicalize(body)===text&&hash(body)===digest,'integrity');return body;}
const actor=proof=>({principal_id:proof.principal_id,session_id:proof.session_id,credential_id:proof.credential_id,issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch});

// 与真实安装writer、人员鉴权和已认证监督连接共用；计划生成不修改运行或签发许可。
export function extensionPlanStore({db,service,bootId,available,reference,launch}){
 let supervisor=null,native=null,receipt=null,domain=null,pending=0;
 const generation=()=>String(db.prepare('SELECT revision FROM extension_dependency_generation WHERE singleton=1').pluck().get());
 function core(){
  const row=db.prepare("SELECT r.receipt_jcs,r.descriptor_jcs FROM core_runtime_binding r JOIN service_boot b USING(service_boot_id) WHERE r.service_boot_id=? AND b.state='started'").raw().get(bootId);
  need(row,'core_required');return {receipt:JSON.parse(row[0]),descriptor:JSON.parse(row[1])};
 }
 function now(){
  need(supervisor&&native,'source_required');supervisor.assertCurrent();
  const saved=core();need(same(saved.receipt,receipt)&&same(saved.descriptor,domain)&&same(supervisor.current().payload.record.admission_receipt,receipt),'source_changed');
  return {clock:structuredClone(receipt.domain_ref),tick:BigInt(native.tick())};
 }
 function selected(input){
  need(exact(input.selection,'kind,source_installation_ref,target_installation_ref,reuse_content_ref,configuration_ref')&&
   ['activate','enable'].includes(input.selection.kind)&&input.selection.source_installation_ref===null&&input.selection.reuse_content_ref===null,'selection');
  const row=db.prepare('SELECT r.revision,r.body_jcs,r.body_digest FROM extension_slot_head h JOIN extension_slot_revision r USING(slot_id,revision) WHERE h.slot_id=?').raw().get(input.slot_id);
  need(row&&String(row[0])===input.expected_slot_revision,'slot_stale');const slot=read(row[1],row[2]);need(slot.active_installation_id===null&&
   (slot.desired_state===undefined||slot.desired_state==='disabled')&&slot.pending_operation_ref==null,'slot_state');
  const approval=db.prepare('SELECT body_jcs,body_digest FROM extension_approval WHERE installation_id=?').raw().get(input.selection.target_installation_ref?.object_id??'');
  need(approval,'approval_required');const approved=read(approval[0],approval[1]),chosen=launch.select(approved.approval_ref);
  need(chosen.content.slot_id===input.slot_id&&same(chosen.approval.installation_ref,input.selection.target_installation_ref)&&same(chosen.approval.configuration_ref,input.selection.configuration_ref),'selection_binding');
  need(domain&&chosen.content.receipt.platform_profile_ref.object_id===domain.platform_profile_id&&chosen.content.receipt.platform_profile_ref.revision===domain.platform_profile_revision,'platform_binding');
  const graph=installationDependencies(db,service,chosen);
  if(Number(service.schema_revision)>=22)for(const resource of graph.resources)need(!db.prepare('SELECT 1 FROM extension_resource_owner_head WHERE resource_id=?').pluck().get(resource.object_id),'resource_busy');
  // 运行实例的释放与跨服务影响尚需相应提供者；不能把既有启动或未决命令当作空集合。
  need(!db.prepare('SELECT 1 FROM ca_adjudication WHERE decision=\'accepted\' LIMIT 1').pluck().get(),'command_provider_required');
  for(const device of graph.devices)need(!db.prepare('SELECT 1 FROM worker_launch_device WHERE device_id=? LIMIT 1').pluck().get(device.object_id),'runtime_provider_required');
  const impacts=[...graph.devices,...graph.resources].map(object_ref=>({object_ref,consequence:'close',reason_code:'installation_dependency'}));
  impacts.sort((a,b)=>Buffer.compare(Buffer.from(canonicalize(a)),Buffer.from(canonicalize(b))));
  return {chosen,graph,slot_ref:reference('slot',input.slot_id,row[0],slot),dependency_revision:generation(),impacts};
 }
 function view(row){
  if(!row)return null;const body=read(row[0],row[1]),{plan_ref,content_digest,...content}=body;
  need(content_digest===hash(content)&&same(plan_ref,reference('dependency_plan',plan_ref.object_id,1,content)),'integrity');return frozen(body);
 }
 const find=plan=>db.prepare('SELECT body_jcs,body_digest,graph_jcs,graph_digest,service_boot_id FROM extension_dependency_plan WHERE plan_id=?').raw().get(plan);
 function previous(fixed){
  const row=db.prepare('SELECT input_jcs,input_digest,plan_id FROM extension_plan_operation WHERE credential_id=? AND request_id=?').raw().get(fixed.actor.credential_id,fixed.request_id);
  if(!row)return null;need(same(read(row[0],row[1]),fixed),'conflict');return view(find(row[2]));
 }
 function current(ref){
  need(exact(ref,'kind,authority_service_id,database_instance_id,object_id,revision,digest')&&id(ref.object_id),'reference');
  const row=find(ref.object_id),plan=view(row);need(plan&&same(plan.plan_ref,ref),'reference');need(row[4]===bootId,'stale_boot');
  const time=now();need(same(time.clock,plan.lifetime.clock)&&time.tick>=BigInt(plan.lifetime.issued_tick)&&time.tick<BigInt(plan.lifetime.deadline_tick),'expired');
  const input={slot_id:plan.slot_ref.object_id,expected_slot_revision:plan.slot_ref.revision,selection:plan.selection},fresh=selected(input);
  need(fresh.dependency_revision===plan.dependency_revision&&same(fresh.slot_ref,plan.slot_ref)&&same(fresh.impacts,plan.impacts)&&same(fresh.graph,read(row[2],row[3])),'stale');
  need(same(fresh.chosen.content.receipt.platform_profile_ref,plan.platform_profile_ref)&&same(fresh.chosen.content.receipt.validation_policy_ref,plan.policy_ref),'stale');
  return plan;
 }
 return Object.freeze({
  validateForAcceptance(ref){need(db.inTransaction,'writer_required');const plan=current(ref),row=db.prepare('SELECT approval_id,graph_jcs,graph_digest FROM extension_dependency_plan WHERE plan_id=?').raw().get(ref.object_id);
   return {plan,approval_id:row[0],graph:read(row[1],row[2])};},
  assertLifetime(plan){need(db.inTransaction,'writer_required');const time=now();need(same(time.clock,plan.lifetime.clock)&&time.tick>=BigInt(plan.lifetime.issued_tick)&&time.tick<BigInt(plan.lifetime.deadline_tick),'expired');},
  bindRuntimeSource(source){
   available();need(!supervisor&&source&&typeof source.assertCurrent==='function'&&typeof source.current==='function','source');
   source.assertCurrent();const saved=db.transaction(core).immediate();
   need(saved.receipt.role==='core'&&saved.receipt.gate_state==='closed'&&saved.descriptor.clock_backend_id==='windows_interrupt_precise'&&
    same(source.scope,{service_id:service.service_id,database_instance_id:service.database_instance_id,supervisor_instance_id:saved.descriptor.supervisor_instance_id,domain_ref:saved.receipt.domain_ref})&&
    same(source.current().payload.record.admission_receipt,saved.receipt),'source_binding');
   native=openNativeClock();receipt=frozen(saved.receipt);domain=frozen(saved.descriptor);supervisor=source;
  },
  management(authorize){return Object.freeze({
   async create(token,input){
    available();need(exact(input,'request_id,slot_id,expected_slot_revision,selection')&&id(input.request_id)&&id(input.slot_id)&&
     typeof input.expected_slot_revision==='string'&&/^[1-9][0-9]{0,3}(?![\s\S])/.test(input.expected_slot_revision),'input');
    const credential=structuredClone(token),request=structuredClone(input);need(Buffer.byteLength(canonicalize(request))<=16384,'capacity');
    const initial=db.transaction(()=>{const proof=authorize(credential,'extension.manage',true),fixed={...request,actor:actor(proof)},old=previous(fixed);if(old)return {old};
     now();return {fixed,selected:selected(request)};}).immediate();if(initial.old)return initial.old;
    need(pending<2,'capacity');++pending;
    try{
     const observed=await launch.observeSelection(initial.selected.chosen.approval.approval_ref);available();
     return db.transaction(()=>{
      const proof=authorize(credential,'extension.manage',true);need(same(actor(proof),initial.fixed.actor),'actor');const old=previous(initial.fixed);if(old)return old;
      const fresh=selected(request);need(same(fresh,initial.selected)&&same(fresh.chosen,observed),'stale');const time=now();
      need(db.prepare('SELECT count(*) FROM extension_dependency_plan').pluck().get()<4096,'capacity');
      const content={slot_ref:fresh.slot_ref,dependency_revision:fresh.dependency_revision,selection:request.selection,configuration_digest:request.selection.configuration_ref.digest,
       impacts:fresh.impacts,platform_profile_ref:fresh.chosen.content.receipt.platform_profile_ref,policy_ref:fresh.chosen.content.receipt.validation_policy_ref,
       lifetime:{clock:time.clock,issued_tick:String(time.tick),deadline_tick:String(time.tick+30000000000n)}};
      const planId=crypto.randomUUID(),op=crypto.randomUUID(),plan={plan_ref:reference('dependency_plan',planId,1,content),...content,content_digest:hash(content)};
      db.prepare('INSERT INTO extension_dependency_plan VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(planId,request.slot_id,Number(request.expected_slot_revision),bootId,
       fresh.chosen.approval.approval_ref.object_id,Number(fresh.dependency_revision),canonicalize(plan),hash(plan),canonicalize(fresh.graph),hash(fresh.graph),op);
      db.prepare('INSERT INTO extension_plan_operation VALUES(?,?,?,?,?,?,?)').run(op,initial.fixed.actor.credential_id,request.request_id,planId,canonicalize(initial.fixed),hash(initial.fixed),
       canonicalize({kind:'extension_dependency_plan',operation_id:op,plan_id:planId,actor:initial.fixed.actor,authorization_digest:proof.authorization_digest,acquisition_ref:proof.acquisition_ref,plan_digest:plan.content_digest}));
      authorize(credential,'extension.manage',true);current(plan.plan_ref);return frozen(plan);
     }).immediate();
    }finally{--pending;}
   },
   query(token,requestId){available();need(id(requestId),'input');return db.transaction(()=>{const proof=authorize(token,'extension.read',false),row=db.prepare('SELECT plan_id FROM extension_plan_operation WHERE credential_id=? AND request_id=?').pluck().get(proof.credential_id,requestId);return row?view(find(row)):null;}).immediate();},
   async current(token,ref){
    available();const credential=structuredClone(token),fixed=structuredClone(ref);
    const first=db.transaction(()=>{authorize(credential,'extension.read',false);const plan=current(fixed);
     const id=db.prepare('SELECT approval_id FROM extension_dependency_plan WHERE plan_id=?').pluck().get(fixed.object_id);
     const row=db.prepare('SELECT body_jcs,body_digest FROM extension_approval WHERE approval_id=?').raw().get(id);
     return {plan,approval_ref:read(row[0],row[1]).approval_ref};}).immediate();
    need(pending<2,'capacity');++pending;
    try{const observed=await launch.observeSelection(first.approval_ref);available();return db.transaction(()=>{
     authorize(credential,'extension.read',false);const plan=current(fixed);need(same(launch.select(first.approval_ref),observed),'stale');return plan;
    }).immediate();}finally{--pending;}
   }
  });}
 });
}
