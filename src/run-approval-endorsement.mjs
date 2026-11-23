import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {proposalReference,proposalWindowEnd} from './peer-run-approval-proposal.mjs';
import {runApprovalReference} from './peer-run-approval.mjs';
import {pairingReference} from './peer-pairing-value.mjs';
import {approvalProtectionNotice,approvalProtectionReceipt,endorsementRevocationNotice,endorsementRevocationReceipt} from './peer-run-approval-protection.mjs';
import {endorsementReference} from './peer-run-approval-endorsement.mjs';
import {currentControlSource} from './device-control-source.mjs';
import {adoptRunGenerationDenial,readRunProtectionWork,scanRunProtectionWork} from './run-generation-denial.mjs';
import {commitRunProtectionCompletion,readRunProtectionCompletion} from './run-approval-protection-completion.mjs';
import {runArmOperationReference} from './peer-run-initiator.mjs';
import {runEligibilityObservationNs} from './peer-run-preparation.mjs';

const operation='endorseRunApproval',path='/api/v1/run-approval-endorsements';
const revokeOperation='revokeRunApprovalEndorsement';
const need=(condition,code)=>{if(!condition)throw new IdentityError('run_endorsement_'+code);};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
const uuid=value=>typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const put=result=>need(result.changes===1,'storage');

export function runApprovalEndorsementStore({db,service,writer,time,authorize,readProposal,authorizePeer,requireCurrentEndorsement,pairings,pairingSample,authorizeProtectionPeer,authorizeArmInitiator,requireCurrentInitiator,protectionTargets}){
 const scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 const canRevoke=Number(service.schema_revision)>=75,canAdopt=Number(service.schema_revision)>=76,canComplete=Number(service.schema_revision)>=80;
 let readApproval=null,readInitiator=null,sendRevocation=null,pendingApprovals=0,pendingProtection=0,pendingInitiators=0;
 const select=`SELECT e.endorsement_id,e.origin_service_id,e.origin_database_instance_id,e.proposal_id,e.context_id,e.request_digest,
  e.body_jcs,e.body_digest,e.audit_jcs,e.audit_digest,s.status_revision,s.state,e.policy_id
  FROM run_approval_endorsement e JOIN run_approval_endorsement_state s USING(endorsement_id)`;
 const reference=(kind,id,revision,hash)=>({kind,scope,object_id:id,revision,digest:hash});
 const identity=(actor,key,operationId=operation)=>digest({scope,actor,request_epoch:service.request_epoch,operation:operationId,idempotency_key:key});
 const selectRevocation=`SELECT operation_id,endorsement_id,context_id,identity_digest,request_digest,body_jcs,body_digest,audit_jcs,audit_digest
  FROM run_approval_endorsement_revocation`;
 function read(row,includeAudit=false){
  need(row,'missing');
  const [id,originService,originDatabase,proposal,context,requestDigest,text,hash,auditText,auditHash,revision,state,policyId]=row;
  const value=JSON.parse(text),audit=JSON.parse(auditText);
  need(canonical(value)===text&&digest(value)===hash&&canonical(audit)===auditText&&digest(audit)===auditHash&&
   same(value.scope,scope)&&value.endorsement_id===id&&value.revision==='1'&&value.proposal_ref.object_id===proposal&&
   same(value.origin_scope,{authority_service_id:originService,database_instance_id:originDatabase})&&same(value.origin_scope,value.proposal_ref.scope)&&
   same(value.created_authentication_ref,reference('authentication',id,'1',auditHash))&&audit.context_id===context&&
   audit.request_digest===requestDigest&&audit.target_policy_ref.id===policyId&&same(audit.actor,value.endorsed_by),'integrity');
  const original={endorsement:value,object_ref:reference('run_approval_endorsement',id,'1',hash),state,status_revision:String(revision)};
  return includeAudit?{original,audit}:original;
 }
 function notice(object,revision,state){
  const value={kind:'run_approval_endorsement_changed',object_ref:object,status_revision:String(revision),state};
  put(db.prepare('INSERT INTO run_approval_endorsement_notice VALUES(?,?,?,?)').run(object.object_id,revision,canonical(value),digest(value)));
 }
 function visibility(proof,value){need(same(proof.actor,value.endorsement.endorsed_by),'missing');}
 function acceptance(value){
  return {endorsement_ref:value.object_ref,status_revision:'1',state:'active'};
 }
 function readRevocation(row,original){
  const [id,endorsementId,contextId,key,requestDigest,text,hash,auditText,auditHash]=row;
  const result=JSON.parse(text),audit=JSON.parse(auditText),value=original.endorsement;
  need(canonical(result)===text&&digest(result)===hash&&canonical(audit)===auditText&&digest(audit)===auditHash&&
   result.operation_id===id&&result.kind==='revoke_endorsement'&&result.request_identity===key&&result.request_digest===requestDigest&&
   same(result.scope,scope)&&result.run_id===value.run_id&&endorsementId===value.endorsement_id&&same(result.endorsement_ref,original.object_ref)&&
   same(result.proposal_ref,value.proposal_ref)&&same(result.targets,[{target_scope:value.origin_scope,purpose:'notify_seamer',state:'pending',receipt_ref:null}])&&
   audit.context_id===contextId&&audit.request_digest===requestDigest,'integrity');
  return {result,actor:audit.actor,ref:reference('run_approval_operation',id,'1',hash)};
 }
 function revocationFor(original){
  const row=canRevoke?db.prepare(selectRevocation+' WHERE endorsement_id=?').raw().get(original.object_ref.object_id):null;
  need((original.state==='active'&&!row)||original.state==='expired'||(original.state==='revoking'&&row),'integrity');
  return row?readRevocation(row,original).ref:null;
 }
 function queuedRevocation(id,original,saved){
  const pending=db.prepare('SELECT target_service_id,target_database_instance_id,body_jcs,body_digest FROM run_approval_endorsement_revocation_outbox WHERE operation_id=?').raw().get(id);
  need(pending,'integrity');const [serviceId,databaseId,text,hash]=pending,value=endorsementRevocationNotice(JSON.parse(text));
  need(canonical(value)===text&&digest(value)===hash&&same(revocationFor(original),saved.ref)&&same(value.revocation_operation_ref,saved.ref)&&
   same(value.endorsement_ref,original.object_ref)&&same(value.proposal_ref,original.endorsement.proposal_ref)&&
   same(value.target_scope,{authority_service_id:serviceId,database_instance_id:databaseId})&&same(value.target_scope,original.endorsement.origin_scope),'integrity');return value;
 }
 function pendingNotice(operationId){
  const row=db.prepare(selectRevocation+' WHERE operation_id=?').raw().get(operationId);need(row,'missing');
  const original=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(row[1]));
  return queuedRevocation(operationId,original,readRevocation(row,original));
 }
 function adoptedRevocation(operationId,notice){
  const row=db.prepare(`SELECT target_service_id,target_database_instance_id,receipt_id,body_jcs,body_digest
   FROM run_approval_endorsement_revocation_receipt WHERE operation_id=?`).raw().get(operationId);
  if(!row)return null;
  const [serviceId,databaseId,id,text,hash]=row,receipt=endorsementRevocationReceipt(JSON.parse(text),notice);
  need(receipt.receipt_id===id&&same(notice.target_scope,{authority_service_id:serviceId,database_instance_id:databaseId})&&
   canonical(receipt)===text&&digest(receipt)===hash,'integrity');return receipt;
 }
 function scanRevocations({after,limit}){
  need((after===null||uuid(after))&&Number.isInteger(limit)&&limit>=1&&limit<=64,'revocation_scan');
  return writer(()=>{
   const keys=db.prepare(`SELECT o.operation_id FROM run_approval_endorsement_revocation_outbox o
    LEFT JOIN run_approval_endorsement_revocation_receipt r USING(operation_id)
    WHERE o.operation_id>? AND r.operation_id IS NULL ORDER BY o.operation_id LIMIT ?`).pluck().all(after??'',limit+1);
   return {items:keys.slice(0,limit),next:keys.length>limit?keys[limit-1]:null};
  });
 }
 async function deliverPendingRevocation(operationId,bindingId=null){
  need(uuid(operationId)&&(bindingId===null||uuid(bindingId))&&sendRevocation,'revocation_delivery');
  const prepared=writer(()=>{
   const notice=pendingNotice(operationId),prior=adoptedRevocation(operationId,notice);
   return prior?{prior}:{notice,record:pairings().requireActivePeerInTransaction(notice.target_scope,'seamer',bindingId)};
  });
  if(prepared.prior)return {state:'acknowledged',receipt:prepared.prior};
  const {notice,record}=prepared;
  const receipt=endorsementRevocationReceipt(await sendRevocation(record.binding_id,notice),notice);
  return writer(()=>{
   const current=pendingNotice(operationId);need(same(current,notice),'revocation_changed');
   const prior=adoptedRevocation(operationId,current);
   if(prior){need(same(prior,receipt),'revocation_receipt_conflict');return {state:'acknowledged',receipt:prior};}
   need(same(pairings().requireActivatedInTransaction(pairingReference(record)),record),'revocation_pairing');
   put(db.prepare('INSERT INTO run_approval_endorsement_revocation_receipt VALUES(?,?,?,?,?,?)')
    .run(operationId,notice.target_scope.authority_service_id,notice.target_scope.database_instance_id,receipt.receipt_id,canonical(receipt),digest(receipt)));
   return {state:'delivered',receipt:adoptedRevocation(operationId,current)};
  });
 }
 function requireOriginalContext(actor,id,operationId){
  const context=db.prepare('SELECT issuer_id,issuer_epoch,principal_id,context_epoch,body,body_digest FROM request_context WHERE context_id=?').raw().get(id);
  need(context&&same(context.slice(0,4),[actor.issuer_id,actor.issuer_epoch,actor.principal_id,service.request_epoch]),'context');
  const original=JSON.parse(context[4].toString());
  need(digest(original)===context[5]&&original.context.operations.includes(operationId),'context');
 }
 function revoke(token,id,request){
  need(uuid(id)&&exact(request,'context_id,endorsement_ref,expected_status_revision,idempotency_key,reason')&&
   uuid(request.context_id)&&uuid(request.idempotency_key)&&['1','2'].includes(request.expected_status_revision)&&
   typeof request.reason==='string'&&request.reason.trim().length>0&&Buffer.byteLength(request.reason)<=4096,'revocation_request');
  const fixed=structuredClone(request);endorsementReference(fixed.endorsement_ref);
  const {endorsement_ref,expected_status_revision,reason,context_id,idempotency_key}=fixed;
  const hash=digest({operation_id:revokeOperation,path:path+'/'+id+'/revoke',request:{endorsement_ref,expected_status_revision,reason}});
  return writer(()=>{
   const actor=authorize(token,null).actor,key=identity(actor,idempotency_key,revokeOperation);
   const original=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(id)),value=original.endorsement;
   const row=db.prepare(selectRevocation+' WHERE identity_digest=?').raw().get(key);
   if(row){
    const access=authorize(token,'grant.read');
    need(row[1]===id&&row[4]===hash,'revocation_conflict');const saved=readRevocation(row,original);
    need(same(access.actor,saved.actor),'missing');return saved.result;
   }
   const auth=authorize(token,'grant.revoke',context_id);
   need(same(auth.actor,actor),'authorization_changed');
   need(same(original.object_ref,endorsement_ref)&&original.status_revision===expected_status_revision&&
    ['active','expired'].includes(original.state)&&!revocationFor(original),'revocation_conflict');
   const target=value.origin_scope,operationId=crypto.randomUUID(),result={scope,operation_id:operationId,kind:'revoke_endorsement',
    request_identity:key,request_digest:hash,run_id:value.run_id,proposal_ref:value.proposal_ref,approval_ref:null,endorsement_ref,
    state:'accepted',targets:[{target_scope:target,purpose:'notify_seamer',state:'pending',receipt_ref:null}],result_ref:null,reason_code:null};
   const audit={actor,context_id,request_digest:hash,reason,authentication:auth.evidence,previous_status_revision:original.status_revision};
   const content=canonical(result),resultHash=digest(result);
   put(db.prepare("UPDATE request_context SET used_count=used_count+1 WHERE context_id=? AND state='active' AND used_count<max_unique_requests").run(context_id));
   put(db.prepare('INSERT INTO run_approval_endorsement_revocation VALUES(?,?,?,?,?,?,?,?,?)')
    .run(operationId,id,context_id,key,hash,content,resultHash,canonical(audit),digest(audit)));
   const message={kind:'run_approval_endorsement_revoked',origin_scope:scope,target_scope:target,proposal_ref:value.proposal_ref,endorsement_ref,
    revocation_operation_ref:reference('run_approval_operation',operationId,'1',resultHash),deny_revision:'2'};
   put(db.prepare('INSERT INTO run_approval_endorsement_revocation_outbox VALUES(?,?,?,?,?)')
    .run(operationId,target.authority_service_id,target.database_instance_id,canonical(message),digest(message)));
   if(original.state==='active'){
    put(db.prepare("UPDATE run_approval_endorsement_state SET status_revision=2,state='revoking' WHERE endorsement_id=? AND state='active'").run(id));
    notice(endorsement_ref,2,'revoking');
   }
   need(same(auth,authorize(token,'grant.revoke',context_id)),'authorization_changed');
   return readRevocation(db.prepare(selectRevocation+' WHERE operation_id=?').raw().get(operationId),original).result;
  });
 }
 function expire(value,now){
  if(value.state==='active'&&now.upper>=proposalWindowEnd(value.endorsement)){
   const id=value.object_ref.object_id;
   put(db.prepare("UPDATE run_approval_endorsement_state SET status_revision=2,state='expired' WHERE endorsement_id=? AND state='active'").run(id));
   notice(value.object_ref,2,'expired');value.state='expired';value.status_revision='2';
  }
 }
 function prior(token,key,requestDigest){
  const row=db.prepare(select+' WHERE request_identity=?').raw().get(key);
  if(!row)return null;
  const stored=read(row);visibility(authorize(token,'grant.read'),stored);
  need(row[5]===requestDigest,'conflict');return acceptance(stored);
 }
 async function endorse(token,request){
  need(exact(request,'binding_id,context_id,idempotency_key,proposal_ref')&&[request.binding_id,request.context_id,request.idempotency_key].every(uuid),'request');
  const fixed=structuredClone(request);proposalReference(fixed.proposal_ref);
  const requestDigest=digest({operation_id:operation,path,request:{binding_id:fixed.binding_id,proposal_ref:fixed.proposal_ref}});
  const prepared=writer(()=>{
   const actor=authorize(token,null).actor,key=identity(actor,fixed.idempotency_key);
   const existing=prior(token,key,requestDigest);
   if(existing)return {existing};
   const auth=authorize(token,'grant.manage',fixed.context_id);
   need(same(actor,auth.actor),'authorization_changed');
   return {auth,key};
  });
  if(prepared.existing)return prepared.existing;
  return readProposal({binding_id:fixed.binding_id,proposal_ref:fixed.proposal_ref},(saved,verify)=>writer(()=>{
   const old=prior(token,prepared.key,requestDigest);if(old)return old;
   const auth=authorize(token,'grant.manage',fixed.context_id);
   need(same(auth,prepared.auth),'authorization_changed');
   const current=verify(auth.actor,time()),proposal=saved.proposal,proposalRef=saved.proposal_ref,target=current.target;
   need(!db.prepare('SELECT 1 FROM run_approval_endorsement WHERE origin_service_id=? AND origin_database_instance_id=? AND proposal_id=?')
    .pluck().get(proposalRef.scope.authority_service_id,proposalRef.scope.database_instance_id,proposalRef.object_id),'proposal_already_endorsed');
   need(db.prepare('SELECT count(*) FROM run_approval_endorsement').pluck().get()<16384,'capacity');
   const id=crypto.randomUUID(),audit={actor:auth.actor,context_id:fixed.context_id,request_digest:requestDigest,
    authentication:auth.evidence,pairing_ref:current.pairing_ref,target_policy_ref:current.policy_ref,
    source_approval_ref:current.source_approval_ref,registrations:current.registrations};
   const auditHash=digest(audit);
   const body={scope,endorsement_id:id,revision:'1',proposal_ref:proposalRef,origin_scope:proposal.scope,run_id:proposal.run_id,
    service_principal:proposal.service_principal,controller_target_digest:current.controller_target_digest,
    device_actions:target.device_actions,parameter_constraints:target.parameter_constraints,validity:proposal.validity,endorsed_by:auth.actor,
    authorization_basis_refs:[reference('run_endorsement_policy',current.policy_ref.id,current.policy_ref.revision,current.policy_ref.digest),
     proposal.source_service_approval_ref],created_authentication_ref:reference('authentication',id,'1',auditHash)};
   const text=canonical(body),auditText=canonical(audit),hash=digest(body);
   need(Buffer.byteLength(text)<=1048576&&Buffer.byteLength(auditText)<=1048576,'capacity');
   put(db.prepare('UPDATE request_context SET used_count=used_count+1 WHERE context_id=? AND state=? AND used_count<max_unique_requests')
    .run(fixed.context_id,'active'));
   put(db.prepare(`INSERT INTO run_approval_endorsement (endorsement_id,origin_service_id,origin_database_instance_id,
    proposal_id,policy_id,context_id,request_identity,request_digest,body_jcs,body_digest,audit_jcs,audit_digest)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(id,proposalRef.scope.authority_service_id,
    proposalRef.scope.database_instance_id,proposalRef.object_id,current.policy_ref.id,fixed.context_id,prepared.key,requestDigest,text,hash,auditText,auditHash));
   put(db.prepare("INSERT INTO run_approval_endorsement_state VALUES(?,1,'active')").run(id));
   const object=reference('run_approval_endorsement',id,'1',hash);notice(object,1,'active');
   need(same(auth,authorize(token,'grant.manage',fixed.context_id))&&same(current,verify(auth.actor,time())),'authorization_changed');
   return acceptance(read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(id)));
  }));
 }
 function readCurrentForPeer(bindingId,socket,request){
   const {record,peer}=authorizePeer(bindingId,socket);
   const {original,audit}=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(request.endorsement_id),true);
   need(original.object_ref.digest===request.endorsement_digest&&same(original.endorsement.origin_scope,
    {authority_service_id:peer.service_id,database_instance_id:peer.database_instance_id}),'missing');
   const now=time();expire(original,now);
   const end=proposalWindowEnd(original.endorsement),pairEnd=BigInt(record.expires_ns),deadline=end<pairEnd?end:pairEnd;
   let eligibility='blocked';
   if(original.state==='active'&&now.upper<deadline&&now.lower>=BigInt(Date.parse(original.endorsement.validity.not_before))*1000000n){
    try{requireCurrentEndorsement(original.endorsement,audit,record,now);eligibility='eligible';}
    catch(error){eligibility=error instanceof IdentityError?'blocked':'unavailable';}
   }
   const last=time();expire(original,last);
   if(original.state==='expired'||last.upper>=deadline||last.lower<BigInt(Date.parse(original.endorsement.validity.not_before))*1000000n)eligibility='blocked';
   need(same(authorizePeer(bindingId,socket).record,record),'authorization_changed');
   const revocation=revocationFor(original);
   return {...original,...(revocation&&{revocation_operation_ref:revocation}),current_eligibility:eligibility,eligible_before_ns:eligibility==='eligible'?String(deadline):null};
 }
 function readControlsForPeer(bindingId,socket,request){
  return writer(()=>{
   const endorsement_read=readCurrentForPeer(bindingId,socket,request);
   if(endorsement_read.current_eligibility!=='eligible')return {endorsement_read,devices:null};
   const ids=[...new Set(endorsement_read.endorsement.device_actions.map(action=>action.device_id))].sort();
   const head=db.prepare('SELECT 1 FROM control_record_head WHERE device_id=?');
   const devices=ids.map(device_id=>{
    if(!head.pluck().get(device_id))return {device_id,control:null};
    const {current}=currentControlSource(db,device_id),{scope:owner,mode,gate_state,control_epoch,effective_version,pending_operation_id}=current.value;
    need(same(owner,scope)&&current.value.device_id===device_id,'control_scope');
    return {device_id,control:{control_ref:current.ref,mode,gate_state,control_epoch,effective_version,pending_operation_id}};
   });
   need(same(readCurrentForPeer(bindingId,socket,request),endorsement_read),'control_changed');
   return {endorsement_read,devices};
  });
 }
 function rejection(reference){
  return db.prepare('SELECT 1 FROM run_approval_rejection WHERE origin_service_id=? AND origin_database_instance_id=? AND approval_id=?')
   .pluck().get(reference.scope.authority_service_id,reference.scope.database_instance_id,reference.object_id);
 }
 function protectionPlan({notice,generations,local_targets}){
   const original=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(notice.endorsement_ref.object_id));
   need(same(original.object_ref,notice.endorsement_ref)&&same(original.endorsement.origin_scope,notice.origin_scope)&&
    (generations.size===1||(canComplete&&generations.size===0)),'protection_original');
   const [run_id,floor]=generations.entries().next().value??[original.endorsement.run_id,null];
   need(uuid(run_id),'protection_original');
   const local=protectionTargets(notice,run_id,{includeDevices:true});
   need(same(local.map(({device_ids,...target})=>target),local_targets),'protection_preparations');
   const device_ids=[...new Set([...original.endorsement.device_actions.map(action=>action.device_id),...local.flatMap(target=>target.device_ids)])].sort();
   need(device_ids.length>0&&device_ids.length<=256,'protection_devices');
   return {origin_scope:notice.origin_scope,run_id,deny_through_generation:floor===null?null:String(BigInt(floor)),device_ids};
 }
 function runProtectionPlan(receiptId){
  need(uuid(receiptId),'protection_request');return writer(()=>protectionPlan(readRunProtectionWork(db,scope,receiptId)));
 }
 function completeRunProtection(receiptId){
  need(uuid(receiptId),'protection_request');
  return writer(()=>{const work=readRunProtectionWork(db,scope,receiptId);return commitRunProtectionCompletion(db,work,protectionPlan(work));});
 }
 async function receiveProtection(bindingId,socket,input,{completion=false}={}){
  need(readApproval&&pendingProtection<4,'protection_unavailable');
  const notice=approvalProtectionNotice(structuredClone(input)),hash=digest(notice),origin=notice.origin_scope;
  const hasTargets=notice.arm_generations.length>0;
  need(!hasTargets||protectionTargets,'protection_unavailable');
  function authorized(){
   const paired=authorizeProtectionPeer(bindingId,socket),peer=paired.peer;
   need(same(scope,notice.target_scope)&&same(origin,{authority_service_id:peer.service_id,database_instance_id:peer.database_instance_id}),'protection_scope');
   return paired.record;
  }
  function prior(){
   const row=db.prepare(`SELECT approval_id,operation_id,request_digest,receipt_id,body_jcs,body_digest FROM run_approval_rejection
    WHERE origin_service_id=? AND origin_database_instance_id=? AND (approval_id=? OR operation_id=?)`).raw()
    .get(origin.authority_service_id,origin.database_instance_id,notice.approval_ref.object_id,notice.revocation_operation_ref.object_id);
   if(!row)return null;
   const [approval,operation,request,id,text,bodyHash]=row;
   need(approval===notice.approval_ref.object_id&&operation===notice.revocation_operation_ref.object_id&&request===hash,'protection_conflict');
   const body=JSON.parse(text);
   need(canonical(body)===text&&digest(body)===bodyHash,'integrity');
   let receipt=body;
   if(body.format==='leafseamer.run-approval-protection-work/1'){
    need(exact(body,'format,local_targets,notice,receipt')&&same(body.notice,notice)&&Array.isArray(body.local_targets),'integrity');
    receipt=body.receipt;
   }else need(!hasTargets,'integrity');
   need(receipt.receipt_id===id,'integrity');approvalProtectionReceipt(receipt,notice);
   return canComplete&&completion?readRunProtectionCompletion(db,notice,receipt,bodyHash)??receipt:receipt;
  }
  const prepared=writer(()=>{const record=authorized();return {record,existing:prior()};});
  if(prepared.existing)return prepared.existing;
  const start=pairingSample(),started=BigInt(start.tick_ns);
  pendingProtection++;
  try{
   const received=await readApproval(bindingId,notice.approval_ref);
   need(same(received.object_ref,notice.approval_ref)&&digest(received.approval)===notice.approval_ref.digest&&
    received.local_eligibility==='blocked'&&['revoking','revoked','expired'].includes(received.state)&&
    same(received.revocation_operation_ref,notice.revocation_operation_ref)&&
    received.approval.controller_endorsement_refs.some(ref=>same(ref,notice.endorsement_ref))&&
    notice.arm_generations.every(item=>item.run_id===received.approval.run_id),'protection_original');
   return writer(()=>{
    function current(){
     const last=pairingSample(),tick=BigInt(last.tick_ns);
     need(same(authorized(),prepared.record)&&same(last.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<started+2000000000n,'protection_expired');
    }
    current();const existing=prior();if(existing)return existing;
    need(db.prepare('SELECT count(*) FROM run_approval_rejection').pluck().get()<16384,'capacity');
    const receipt={format:'leafseamer.run-approval-rejection/1',receipt_id:crypto.randomUUID(),target_scope:scope,approval_ref:notice.approval_ref,
     endorsement_ref:notice.endorsement_ref,revocation_operation_ref:notice.revocation_operation_ref,request_digest:hash,
     identity_state:'denied',protection_state:'pending'};
    const local_targets=protectionTargets?.(notice,received.approval.run_id)??[];
    const body=hasTargets||local_targets.length?{format:'leafseamer.run-approval-protection-work/1',notice,local_targets,receipt}:receipt;
    put(db.prepare('INSERT INTO run_approval_rejection VALUES(?,?,?,?,?,?,?,?)').run(origin.authority_service_id,origin.database_instance_id,
     notice.approval_ref.object_id,notice.revocation_operation_ref.object_id,hash,receipt.receipt_id,canonical(body),digest(body)));
    if(Number(service.schema_revision)>=78)adoptRunGenerationDenial(db,scope,origin,notice.approval_ref.object_id);
    current();return prior();
   });
  }finally{pendingProtection--;}
 }
 async function prepareRunApproval(bindingId,ref){
  need(readApproval&&uuid(bindingId)&&pendingApprovals<4,'approval_unavailable');
  const fixed=runApprovalReference(structuredClone(ref)),start=pairingSample(),started=BigInt(start.tick_ns);
  const observationDeadline=started+runEligibilityObservationNs;
  const record=pairings().currentPending(bindingId),paired=pairingReference(record);
  const peer=record.transcript.parties.find(part=>part.service_id===record.peer_service_id);
  need(record.state==='activated'&&peer?.service_kind==='seamer'&&same(fixed.scope,{authority_service_id:peer.service_id,database_instance_id:peer.database_instance_id}),'approval_pairing');
  pendingApprovals++;
  try{
   const received=structuredClone(await readApproval(bindingId,structuredClone(fixed))),approval=received.approval;
   need(same(received.object_ref,fixed)&&digest(approval)===fixed.digest&&same(approval.scope,fixed.scope)&&
    received.state==='active'&&received.local_eligibility==='eligible','approval_ineligible');
   const target=approval.controller_endorsement_refs.find(ref=>same(ref.scope,scope)),deadline=BigInt(received.eligible_before_ns);
   need(target&&deadline<=proposalWindowEnd(approval)&&deadline<=BigInt(record.expires_ns),'approval_target');
   const before=BigInt(Date.parse(approval.validity.not_before))*1000000n;
   let valid=true;
   function verify(){
    need(db.inTransaction&&valid,'approval_unavailable');
    try{
     const current=pairings().requireActivatedInTransaction(paired);
     need(same(current,record),'approval_pairing');
     if(authorizeProtectionPeer)need(!rejection(fixed),'approval_rejected');
     const {original,audit}=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(target.object_id),true),value=original.endorsement;
     need(original.state==='active'&&same(original.object_ref,target)&&same(approval.proposal_ref,value.proposal_ref)&&same(approval.scope,value.origin_scope)&&
      approval.run_id===value.run_id&&same(approval.service_principal,value.service_principal)&&same(approval.validity,value.validity)&&
      same(approval.source_service_approval_ref,value.authorization_basis_refs[1]),'approval_endorsement');
     const now=time();need(now.lower>=before&&now.upper<deadline,'approval_expired');
     requireCurrentEndorsement(value,audit,current,now);
     const last=pairingSample(),tick=BigInt(last.tick_ns);
     need(same(last.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<observationDeadline&&
      BigInt(last.lower_ns)>=before&&BigInt(last.upper_ns)<deadline,'approval_expired');
     return {approval_ref:structuredClone(fixed),endorsement_ref:structuredClone(target),eligible_before_ns:String(deadline)};
    }catch(error){valid=false;throw error;}
   }
   const eligibility=writer(verify);
   return Object.freeze({get original(){return structuredClone(received);},eligibility,assertCurrentInTransaction:verify});
  }finally{pendingApprovals--;}
 }
 async function prepareRunInitiator(bindingId,ref,expected){
  need(readInitiator&&authorizeArmInitiator&&requireCurrentInitiator&&uuid(bindingId)&&pendingInitiators<4,'initiator_unavailable');
  const fixed=runArmOperationReference(structuredClone(ref)),intent=structuredClone(expected);
  need(exact(intent,'approval_ref,arm_generation,artifact_ref,definition_id,definition_version,preparation_id,run_id'),'initiator_request');
  const start=pairingSample(),started=BigInt(start.tick_ns),record=pairings().currentPending(bindingId),paired=pairingReference(record);
  pendingInitiators++;
  try{
   const [received,approved]=await Promise.allSettled([readInitiator(bindingId,fixed),prepareRunApproval(bindingId,intent.approval_ref)]);
   if(received.status==='rejected')throw received.reason;
   const original=structuredClone(received.value);
   const {operation_ref,target_scope,initiator,initiator_authorization_ref,credential,eligible_before_ns,...selected}=original;
   need(same(operation_ref,fixed)&&same(target_scope,scope)&&same(selected,intent)&&initiator.principal_kind==='human','initiator_scope');
   if(approved.status==='rejected')throw approved.reason;
   const prepared=approved.value,approval=prepared.original.approval;
   need(approval.run_id===intent.run_id&&same(approval.artifact_ref,intent.artifact_ref),'initiator_approval');
   let valid=true,eligibility,issuance;
   function verify(){
    need(db.inTransaction&&valid,'initiator_unavailable');
    try{
     const eligible=prepared.assertCurrentInTransaction(),current=pairings().requireActivatedInTransaction(paired);
     need(same(current,record),'initiator_pairing');
     const {principal_kind:_kind,...actor}=initiator;
     const tokenEnd=authorizeArmInitiator(credential,actor,fixed.scope.authority_service_id);
     const {original:recorded,audit}=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(eligible.endorsement_ref.object_id),true);
     const endorsement=recorded.endorsement;
     const basis=requireCurrentInitiator(approval,endorsement,actor,time(),current);
     const end=[eligible_before_ns,eligible.eligible_before_ns,tokenEnd].map(BigInt).reduce((a,b)=>a<b?a:b),arrival=pairingSample(),tick=BigInt(arrival.tick_ns);
     need(same(arrival.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<started+2000000000n&&
      BigInt(arrival.upper_ns)<end,'initiator_expired');
     const result={operation_ref:fixed,initiator,initiator_authorization_ref,initiator_policy_ref:basis.policy_ref,eligible_before_ns:String(end)};
     const currentIssuance={initiator:result,approval_ref:eligible.approval_ref,endorsement_ref:eligible.endorsement_ref,
      validity:approval.validity,service_principal:approval.service_principal,service_approval_ref:approval.source_service_approval_ref,
      target_policy_ref:audit.target_policy_ref,device_actions:endorsement.device_actions,parameter_constraints:endorsement.parameter_constraints};
     need(!issuance||same(currentIssuance,issuance),'initiator_changed');
     issuance=structuredClone(currentIssuance);return result;
    }catch(error){valid=false;throw error;}
   }
   eligibility=writer(verify);
   return Object.freeze({eligibility,assertCurrentInTransaction:verify,assertIssuanceInTransaction(){
    verify();return structuredClone(issuance);
   }});
  }finally{pendingInitiators--;}
 }
 return Object.freeze({endorse,readForPeer(...args){return writer(()=>readCurrentForPeer(...args));},readControlsForPeer,prepareRunInitiator,bindInitiatorReader(reader){
  need(!readInitiator&&typeof reader==='function','initiator_unavailable');readInitiator=reader;
 },
 prepareRunApproval,...(authorizeProtectionPeer&&{receiveProtection}),
 ...(Number(service.schema_revision)>=79&&protectionTargets&&{runProtectionPlan,scanRunProtection({after,limit}){
  need((after===null||uuid(after))&&Number.isSafeInteger(limit)&&limit>=1&&limit<=64,'protection_scan');
  return writer(()=>scanRunProtectionWork(db,after,limit,{completion:canComplete}));
 }}),...(canComplete&&protectionTargets&&{completeRunProtection}),bindApprovalReader(reader){
  need(!readApproval&&typeof reader==='function','approval_unavailable');readApproval=reader;
 },
  get(token,id){
   need(uuid(id),'request');
   return writer(()=>{
    const auth=authorize(token,'grant.read'),value=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(id));visibility(auth,value);
    expire(value,time());
    need(same(auth,authorize(token,'grant.read')),'authorization_changed');
    const revocation=revocationFor(value);
    return {...value,...(revocation&&{revocation_operation_ref:revocation}),current_eligibility:value.state==='active'?'unavailable':'blocked'};
   });
  },
  lookup(token,request){
   need(exact(request,'context_id,idempotency_key')&&uuid(request.context_id)&&uuid(request.idempotency_key),'request');
   return writer(()=>{
    const auth=authorize(token,'grant.read');
    requireOriginalContext(auth.actor,request.context_id,operation);
    const row=db.prepare(select+' WHERE request_identity=?').raw().get(identity(auth.actor,request.idempotency_key)),value=row?read(row):null;
    if(value)visibility(auth,value);
    need(same(auth,authorize(token,'grant.read')),'authorization_changed');
    return {request_digest:row?.[5]??null,result:value?acceptance(value):null};
   });
  },...(canRevoke&&{revoke,prepareRevocationDelivery(operationId){
   need(uuid(operationId),'request');return writer(()=>pendingNotice(operationId));
  },getRevocation(token,operationId){
   need(uuid(operationId),'request');return writer(()=>{
    const access=authorize(token,'grant.read'),row=db.prepare(selectRevocation+' WHERE operation_id=?').raw().get(operationId);need(row,'missing');
    const original=read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(row[1])),saved=readRevocation(row,original);
    need(same(access.actor,saved.actor),'missing');
    const receipt=canAdopt?adoptedRevocation(operationId,queuedRevocation(operationId,original,saved)):null;
    need(same(access,authorize(token,'grant.read')),'authorization_changed');
    if(!receipt)return saved.result;
    return {...saved.result,state:'applying',targets:[{...saved.result.targets[0],receipt_ref:{kind:'run_endorsement_rejection_receipt',
     scope:receipt.target_scope,object_id:receipt.receipt_id,revision:'1',digest:digest(receipt)}}]};
   });
  },lookupRevocation(token,request){
   need(exact(request,'context_id,idempotency_key')&&uuid(request.context_id)&&uuid(request.idempotency_key),'request');
   return writer(()=>{
    const access=authorize(token,'grant.read');requireOriginalContext(access.actor,request.context_id,revokeOperation);
    const row=db.prepare(selectRevocation+' WHERE identity_digest=?').raw().get(identity(access.actor,request.idempotency_key,revokeOperation));
    const original=row?read(db.prepare(select+' WHERE e.endorsement_id=?').raw().get(row[1])):null,saved=row?readRevocation(row,original):null;
    need(!saved||same(access.actor,saved.actor),'missing');need(same(access,authorize(token,'grant.read')),'authorization_changed');
    return {request_digest:row?.[4]??null,result:saved?.result??null};
   });
  }}),...(canAdopt&&{scanRevocations,deliverPendingRevocation,bindRevocationTransport(send){
   need(!sendRevocation&&typeof send==='function','revocation_delivery');sendRevocation=send;
  }})
 });
}
