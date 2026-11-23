import crypto from 'node:crypto';
import {canonical,digest,ref,same,seal} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {pairingReference} from './peer-pairing-value.mjs';
import {proposalReference,proposalTarget,proposalWindowEnd} from './peer-run-approval-proposal.mjs';
import {endorsementScope,assertEndorsementScopeContains} from './run-endorsement-scope.mjs';

const need=(condition,code)=>{if(!condition)throw new IdentityError('run_endorsement_'+code);};
const exact=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===fields;
const uuid=value=>typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const instant=value=>{
 need(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(value)&&BigInt(value)<1n<<64n,'policy_time');
 return BigInt(value);
};
const principal=value=>need(exact(value,'issuer_epoch,issuer_id,principal_id')&&Object.values(value).every(uuid),'principal');
const identity=({issuer_id,issuer_epoch,principal_id})=>({issuer_id,issuer_epoch,principal_id});
const written=result=>need(result.changes===1,'policy_storage');

export function runEndorsementPolicyStore({db,service,management,sourceCurrent,time,deviceAutomationCurrent,pairings,pairingSample}){
 const scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 let readProposal=null,pending=0;
 const select='SELECT policy_id,revision,body_jcs,body_digest,human_id,service_principal_id FROM run_endorsement_policy';
 function read(row){
  if(!row)return null;
  const [id,revision,text,hash,humanId,serviceId]=row,value=JSON.parse(text),{digest:sealed,...body}=value;
  need(canonical(value)===text&&sealed===hash&&digest(body)===hash&&body.id===id&&body.revision===String(revision)&&
   body.human.principal_id===humanId&&body.service_principal.principal_id===serviceId&&same(body.scope,scope),'policy_integrity');
  return value;
 }
 function head(human,servicePrincipal){
  return read(db.prepare(select+' WHERE policy_id=(SELECT policy_id FROM run_endorsement_policy_head WHERE human_id=? AND service_principal_id=?)')
   .raw().get(human,servicePrincipal));
 }
 function registrations(actions){
  need(actions.length===0||typeof deviceAutomationCurrent==='function','catalog_unavailable');
  const devices=new Map();
  return actions.map(action=>{
   const found=devices.get(action.device_id)??deviceAutomationCurrent(action.device_id);
   devices.set(action.device_id,found);
   need(same(found.registration.scope,scope)&&found.registration.device_id===action.device_id&&
    found.registration.capability_id===action.action_id&&found.registration.capability_version===action.capability_version,'catalog_scope');
   return {action,registration_ref:found.registration_ref,parameter_schema_ref:found.registration.parameter_schema_ref};
  });
 }
 function activeHolder(person){
  const row=db.prepare('SELECT s.issuer_id,s.issuer_epoch,s.kind,p.state FROM subject s JOIN local_principal p USING(principal_id) WHERE s.principal_id=?').raw().get(person.principal_id);
  need(row&&same(row,[person.issuer_id,person.issuer_epoch,'human','active']),'policy_human');
 }
 function replace(input,request){
  need(exact(request,'device_actions,expected_policy_ref,expires_ns,human,not_before_ns,parameter_constraints,request_id,service_approval_ref,service_principal')&&uuid(request.request_id),'policy_request');
  const fixed=structuredClone(request);principal(fixed.human);principal(fixed.service_principal);
  const begin=instant(fixed.not_before_ns),end=instant(fixed.expires_ns);need(begin<end,'policy_time');
  const evaluated=endorsementScope(fixed.device_actions,fixed.parameter_constraints,{allowEmpty:true});
  const semantic={...fixed,device_actions:evaluated.device_actions,parameter_constraints:evaluated.parameter_constraints};
  const requestDigest=digest(semantic);
  return management(input,'auth.manage',(actor,now)=>{
   const prior=db.prepare('SELECT request_digest,policy_id FROM run_endorsement_policy_request WHERE actor_id=? AND request_id=?').raw().get(actor.principal_id,fixed.request_id);
   if(prior){need(prior[0]===requestDigest,'policy_conflict');return read(db.prepare(select+' WHERE policy_id=?').raw().get(prior[1]));}
   activeHolder(fixed.human);
   const source=sourceCurrent(fixed.service_principal,fixed.service_approval_ref,now);
   need(begin>=BigInt(source.approval.not_before_ns)&&end<=BigInt(source.approval.expires_ns)&&now.upper<end&&
    evaluated.device_actions.every(action=>source.approval.device_ids.includes(action.device_id)),'policy_scope');
   const old=head(fixed.human.principal_id,fixed.service_principal.principal_id),oldRef=old?ref(old):null;
   need(same(oldRef,fixed.expected_policy_ref),'policy_revision');
   need(db.prepare('SELECT count(*) FROM run_endorsement_policy').pluck().get()<16384,'policy_capacity');
   const evidence=registrations(evaluated.device_actions);
   const value=seal({format:'leafseamer-local-run-endorsement-policy/1',id:crypto.randomUUID(),revision:String(Number(old?.revision??'0')+1),scope,
    human:fixed.human,service_principal:fixed.service_principal,service_approval_ref:fixed.service_approval_ref,pairing_ref:source.approval.automation_origin.pairing_ref,
    not_before_ns:fixed.not_before_ns,expires_ns:fixed.expires_ns,device_actions:evaluated.device_actions,parameter_constraints:evaluated.parameter_constraints,
    registrations:evidence,previous_ref:oldRef,approved_by:identity(actor),acquisition_ref:now.acquisition});
   const text=canonical(value);need(Buffer.byteLength(text)<=1048576,'policy_capacity');
   written(db.prepare('INSERT INTO run_endorsement_policy VALUES(?,?,?,?,?,?)').run(value.id,value.human.principal_id,value.service_principal.principal_id,Number(value.revision),text,value.digest));
   written(db.prepare(`INSERT INTO run_endorsement_policy_head VALUES(?,?,?) ON CONFLICT(human_id,service_principal_id)
    DO UPDATE SET policy_id=excluded.policy_id`).run(value.human.principal_id,value.service_principal.principal_id,value.id));
   written(db.prepare('INSERT INTO run_endorsement_policy_request VALUES(?,?,?,?)').run(actor.principal_id,fixed.request_id,requestDigest,value.id));
   need(same(head(value.human.principal_id,value.service_principal.principal_id),value),'policy_integrity');
   const last=time();sourceCurrent(fixed.service_principal,fixed.service_approval_ref,last);
   need(last.upper<end,'policy_time');
   return value;
  });
 }
 function currentTarget({service_principal,source_service_approval_ref:approvalRef,validity},origin,target,actor,now,current){
  const pairingRef=pairingReference(current);
  need(approvalRef.kind==='service_approval'&&same(approvalRef.scope,scope),'source_approval');
  const source=sourceCurrent(service_principal,{id:approvalRef.object_id,revision:approvalRef.revision,digest:approvalRef.digest},now,current);
  need(same(origin,source.approval.automation_origin.seamer_scope)&&same(pairingRef,source.approval.automation_origin.pairing_ref),'source_approval');
  const allowed=head(actor.principal_id,service_principal.principal_id);
  need(allowed&&same(allowed.human,actor)&&same(allowed.service_principal,service_principal)&&same(allowed.service_approval_ref,ref(source.approval))&&
   same(allowed.pairing_ref,pairingRef),'policy_missing');
  const before=BigInt(Date.parse(validity.not_before))*1000000n,end=proposalWindowEnd({validity});
  need(now.lower>=BigInt(allowed.not_before_ns)&&now.upper<end&&before>=BigInt(allowed.not_before_ns)&&end<=BigInt(allowed.expires_ns),'policy_time');
  const requested=endorsementScope(target.device_actions,target.parameter_constraints);
  assertEndorsementScopeContains(endorsementScope(allowed.device_actions,allowed.parameter_constraints,{allowEmpty:true}),requested);
  const evidence=registrations(requested.device_actions);
  need(evidence.every(item=>allowed.registrations.some(approved=>same(item,approved))),'catalog_changed');
  return {policy_ref:ref(allowed),source_approval_ref:ref(source.approval),registrations:evidence,pairing_ref:pairingRef};
 }
 async function withProposal(request,accept){
  need(readProposal&&typeof pairingSample==='function'&&exact(request,'binding_id,proposal_ref')&&uuid(request.binding_id)&&pending<4,'proposal_unavailable');
  const fixed=structuredClone(request);proposalReference(fixed.proposal_ref);
  const start=pairingSample(),started=BigInt(start.tick_ns);
  const record=pairings().currentPending(fixed.binding_id),pairingRef=pairingReference(record);
  pending++;
  try{
   const saved=await readProposal(fixed.binding_id,fixed.proposal_ref),proposal=saved.proposal,target=proposalTarget(proposal,scope);
   need(same(saved.proposal_ref,fixed.proposal_ref)&&digest(proposal)===saved.proposal_ref.digest,'proposal_changed');
   return accept(saved,(actor,now)=>{
    const current=pairings().requireActivatedInTransaction(pairingRef);
    const evidence=currentTarget(proposal,proposal.scope,target,actor,now,current);
    const last=pairingSample(),tick=BigInt(last.tick_ns);
    need(same(last.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<started+2000000000n&&BigInt(last.upper_ns)<proposalWindowEnd(proposal),'proposal_expired');
    return {...evidence,proposal_ref:saved.proposal_ref,controller_target_digest:digest(target),target};
   });
  }finally{pending--;}
 }
 async function check(input,request){
  const actor=management(input,'grant.manage',identity);
  return withProposal(request,(_saved,verify)=>management(input,'grant.manage',(nowActor,now)=>{
   need(same(actor,identity(nowActor)),'proposal_changed');
   const {target:_target,pairing_ref:_pairing,...evidence}=verify(actor,now);
   return evidence;
  }));
 }
 function requireCurrentEndorsement(body,audit,record,now){
  const target={controller_scope:scope,device_actions:body.device_actions,parameter_constraints:body.parameter_constraints};
  need(digest(target)===body.controller_target_digest&&same(pairingReference(record),audit.pairing_ref),'basis_changed');
  const current=currentTarget({...body,source_service_approval_ref:body.authorization_basis_refs[1]},body.origin_scope,target,body.endorsed_by,now,record);
  need(same(current.policy_ref,audit.target_policy_ref)&&same(current.source_approval_ref,audit.source_approval_ref)&&
   same(current.registrations,audit.registrations),'basis_changed');
 }
 function requireCurrentInitiator(approval,endorsement,actor,now,record){
  activeHolder(actor);
  return currentTarget(approval,approval.scope,{controller_scope:scope,device_actions:endorsement.device_actions,parameter_constraints:endorsement.parameter_constraints},actor,now,record);
 }
 return Object.freeze({replace,check,withProposal,requireCurrentEndorsement,requireCurrentInitiator,bindProposalReader(reader){
  need(!readProposal&&typeof reader==='function','proposal_unavailable');readProposal=reader;
 }});
}
