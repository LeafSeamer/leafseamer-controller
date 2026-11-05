import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('extension_activation_'+code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const exact=(value,keys)=>value&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(',');
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const frozen=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(frozen);Object.freeze(value);}return value;};
const actor=proof=>({principal_id:proof.principal_id,session_id:proof.session_id,credential_id:proof.credential_id,issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch});
function read(text,digest){const value=JSON.parse(text);need(canonicalize(value)===text&&hash(value)===digest,'integrity');return value;}

// 只受理当前人员确认的计划并占用资源；accepted不等于active_closed或启动授权。
export function extensionActivationStore({db,service,bootId,available,reference,launch,plans}){
 let pending=0;
 function prior(fixed){
  const row=db.prepare('SELECT input_jcs,input_digest,operation_id FROM extension_activation WHERE credential_id=? AND request_id=?').raw().get(fixed.actor.credential_id,fixed.request_id);
  if(!row)return null;need(same(read(row[0],row[1]),fixed),'conflict');return result(row[2]);
 }
 function result(operation){const row=db.prepare('SELECT result_jcs,result_digest FROM extension_operation WHERE operation_id=?').raw().get(operation);need(row,'integrity');return frozen(read(row[0],row[1]));}
 function selection(request,kind){
  const value=plans.validateForAcceptance(request.dependency_plan_ref),{plan}=value;
  need(plan.selection.kind===kind&&plan.slot_ref.object_id===request.slot_id&&plan.slot_ref.revision===request.expected_slot_revision&&
   same(plan.selection.target_installation_ref,request.target_installation_ref)&&value.approval_id===request.approval_ref?.object_id,'plan_binding');
  const chosen=launch.select(request.approval_ref);
  need(same(chosen.approval.installation_ref,request.target_installation_ref)&&same(chosen.approval.configuration_ref,plan.selection.configuration_ref),'approval_binding');
  need(!db.prepare('SELECT 1 FROM extension_activation WHERE installation_id=?').pluck().get(request.target_installation_ref.object_id),'installation_used');
  return {...value,chosen};
 }
 function forLaunch(intent){
  need(db.inTransaction,'writer_required');const binding=intent.extension_binding;
  const row=db.prepare('SELECT operation_id,service_boot_id,body_jcs,body_digest,graph_jcs,graph_digest,slot_id,slot_revision FROM extension_activation WHERE installation_id=?').raw().get(binding.installation_ref.object_id);
  need(row&&row[1]===bootId,'required');const body=read(row[2],row[3]),graph=read(row[4],row[5]);
  need(same(body.approval_ref,binding.approval_ref)&&same(body.target_installation_ref,binding.installation_ref),'binding');
  const slot=db.prepare('SELECT r.body_jcs,r.body_digest FROM extension_slot_head h JOIN extension_slot_revision r USING(slot_id,revision) WHERE h.slot_id=? AND h.revision=?').raw().get(row[6],row[7]);
  need(slot,'slot_changed');const current=read(slot[0],slot[1]);need(current.desired_state==='enabled'&&same(current.pending_operation_ref,body.operation_ref),'slot_changed');
  const held=db.prepare('SELECT o.resource_ref_jcs FROM extension_resource_owner o JOIN extension_resource_owner_head h USING(owner_id,resource_id) WHERE o.operation_id=? ORDER BY o.resource_id COLLATE BINARY').pluck().all(row[0]);
  const expected=[...graph.resources].sort((a,b)=>a.object_id<b.object_id?-1:1);need(same(held.map(value=>JSON.parse(value)),expected),'owner_changed');
  const used=db.prepare('SELECT launch_id,intent_digest FROM worker_launch_preparation WHERE activation_operation_id=?').raw().get(row[0]);
  need(!used||(used[0]===intent.launch_id&&used[1]===hash(intent)),'launch_used');return row[0];
 }
 return Object.freeze({forLaunch,management(authorize){return Object.freeze({
  async accept(token,kind,input){
   available();need(['activate','enable'].includes(kind)&&exact(input,'request_id,slot_id,expected_slot_revision,target_installation_ref,approval_ref,dependency_plan_ref')&&
    id(input.request_id)&&id(input.slot_id)&&typeof input.expected_slot_revision==='string'&&/^[1-9][0-9]{0,3}(?![\s\S])/.test(input.expected_slot_revision),'input');
   const credential=structuredClone(token),request=structuredClone(input);need(Buffer.byteLength(canonicalize(request))<=16384,'capacity');
   const initial=db.transaction(()=>{const proof=authorize(credential,'extension.manage',true),fixed={...request,kind,actor:actor(proof)},old=prior(fixed);if(old)return {old};
    return {fixed,selected:selection(request,kind)};}).immediate();if(initial.old)return initial.old;
   need(pending<2,'capacity');++pending;
   try{const observed=await launch.observeSelection(request.approval_ref);available();return db.transaction(()=>{
    const proof=authorize(credential,'extension.manage',true);need(same(actor(proof),initial.fixed.actor),'actor');const old=prior(initial.fixed);if(old)return old;
    const fresh=selection(request,kind);need(same(fresh,initial.selected)&&same(fresh.chosen,observed),'stale');
    need(db.prepare('SELECT count(*) FROM extension_operation').pluck().get()<4096&&Number(request.expected_slot_revision)<4096,'capacity');
    const op=crypto.randomUUID(),revision=Number(request.expected_slot_revision)+1,content={operation_id:op,kind,slot_id:request.slot_id,target_installation_ref:request.target_installation_ref,
     approval_ref:request.approval_ref,dependency_plan_ref:request.dependency_plan_ref,input_digest:hash(initial.fixed),actor:initial.fixed.actor};
    const opRef=reference('installation_operation',op,1,content),slotBody={slot_id:request.slot_id,extension_id:fresh.chosen.content.manifest.extension_id,revision:String(revision),
     active_installation_id:null,desired_state:'enabled',pending_operation_ref:opRef,pending_installation_ref:request.target_installation_ref,configuration_ref:fresh.plan.selection.configuration_ref};
    const slot={slot_ref:reference('slot',request.slot_id,revision,slotBody),record:slotBody};
    const owners=fresh.graph.resources.map((resource_ref,index)=>({owner_id:crypto.randomUUID(),device_ref:fresh.graph.devices[index],resource_ref}));
    const body={operation_ref:opRef,kind,phase:'accepted',slot_ref:slot.slot_ref,target_installation_ref:request.target_installation_ref,approval_ref:request.approval_ref,
     dependency_plan_ref:request.dependency_plan_ref,graph_digest:hash(fresh.graph),service_boot_id:bootId,resource_owner_ids:owners.map(value=>value.owner_id),result:null};
    const value={operation_ref:opRef,record:body,slot,owners};
    db.prepare('INSERT INTO extension_slot_revision VALUES(?,?,?,?,?,?)').run(request.slot_id,revision,op,slotBody.extension_id,canonicalize(slotBody),hash(slotBody));
    db.prepare('INSERT INTO extension_activation VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(op,initial.fixed.actor.credential_id,request.request_id,request.target_installation_ref.object_id,
     request.slot_id,revision,request.dependency_plan_ref.object_id,request.approval_ref.object_id,bootId,canonicalize(initial.fixed),hash(initial.fixed),canonicalize(body),hash(body),canonicalize(fresh.graph),hash(fresh.graph));
    for(const owner of owners){db.prepare('INSERT INTO extension_resource_owner VALUES(?,?,?,?,?)').run(owner.owner_id,op,owner.resource_ref.object_id,owner.device_ref.object_id,canonicalize(owner.resource_ref));
     db.prepare('INSERT INTO extension_resource_owner_head VALUES(?,?)').run(owner.resource_ref.object_id,owner.owner_id);}
    db.prepare('UPDATE extension_slot_head SET revision=? WHERE slot_id=?').run(revision,request.slot_id);
    const operationRequest='activation.'+op,audit={kind:'extension_'+kind,operation_id:op,request_id:operationRequest,slot_id:request.slot_id,installation_id:request.target_installation_ref.object_id,
     result_digest:hash(value),actor:initial.fixed.actor,authorization_digest:proof.authorization_digest,acquisition_ref:proof.acquisition_ref};
    db.prepare('INSERT INTO extension_operation VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(operationRequest,op,kind,request.slot_id,revision,request.target_installation_ref.object_id,
     canonicalize(initial.fixed),hash(initial.fixed),canonicalize(value),hash(value),canonicalize(audit),null,op);
    authorize(credential,'extension.manage',true);plans.assertLifetime(fresh.plan);return frozen(value);
   }).immediate();}finally{--pending;}
  },
  query(token,requestId){available();need(id(requestId),'input');return db.transaction(()=>{const proof=authorize(token,'extension.read',false),row=db.prepare('SELECT operation_id FROM extension_activation WHERE credential_id=? AND request_id=?').pluck().get(proof.credential_id,requestId);return row?result(row):null;}).immediate();}
 });}});
}
