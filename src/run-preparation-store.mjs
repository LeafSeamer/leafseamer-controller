import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {currentControlSource} from './device-control-source.mjs';
import {pairingNeed as need,pairingReference} from './peer-pairing-value.mjs';
import {peerScope,proposalWindowEnd} from './peer-run-approval-proposal.mjs';
import {armPlanOriginal,armPreparationRequest,isPreparationDigest as hash} from './peer-run-arm-plan.mjs';
import {armPreparationEligibilityRequest,armPreparationLookup,runEligibilityObservationNs} from './peer-run-preparation.mjs';
import {actionAdmissionBinding,actionAdmissionRequest} from './peer-action-admission.mjs';
import {automationCommandStore} from './automation-command-adjudication.mjs';
import {currentControlReference} from './device-initial-ready.mjs';
import {runGenerationDenied} from './run-generation-denial.mjs';
import {readCommandClosure} from './command-settlement.mjs';
import {readCommandRecord} from './command-record-store.mjs';
import {withExecutionReadView} from './execution-read-view.mjs';

const bodyLimit=1048576;
function reference(kind,scope,object_id,body){return {kind,scope,object_id,revision:'1',digest:digest(body)};}

// 只有受信装配可绑定配对计划读取器。此事务签发持久回执，不改变设备闸门。
export function runPreparationStore({db,service,bootId,writer,time,pairingSample,authorizePeer,prepareInitiator,prepareApproval,automationExecution=null,activePeer=null}){
 const scope=peerScope(service),put=result=>need(result.changes===1,'preparation_storage');
 let readPlan=null,readAction=null,pending=0,pendingEligibility=0,pendingActions=0;
 let lastVerified=null;
 const select=`SELECT p.origin_service_id,p.origin_database_instance_id,p.preparation_id,p.run_id,p.arm_generation,p.request_digest,p.request_jcs,
   g.grant_id,g.body_jcs,g.body_digest,c.commit_id,c.body_jcs,c.body_digest,c.receipt_jcs,c.receipt_digest,c.notice_jcs,c.notice_digest,p.approval_id,g.endorsement_id
  FROM run_preparation p LEFT JOIN run_preparation_grant g ON g.preparation_id=p.preparation_id
   LEFT JOIN run_preparation_commit c ON c.preparation_id=p.preparation_id`;
 function decode(text,checksum){
  need(typeof text==='string'&&hash(checksum),'preparation_integrity');
  const value=JSON.parse(text);need(canonical(value)===text&&digest(value)===checksum,'preparation_integrity');return value;
 }
 function stored(row,includeCommit){
  // 只复用逐列相同的持久原件。每次调用方仍查询原行、当前批准、拒绝水位和设备控制。
  if(lastVerified&&row.length===lastVerified.row.length&&row.every((value,index)=>value===lastVerified.row[index]))
   return includeCommit?lastVerified.result:lastVerified.result.record;
  const [serviceId,databaseId,id,runId,generation,requestDigest,body,grantId,grantBody,grantHash,commitId,commitBody,commitHash,receiptBody,receiptHash,noticeBody,noticeHash,approvalId,endorsementId]=row;
  const request=decode(body,requestDigest),grant=decode(grantBody,grantHash),commit=decode(commitBody,commitHash),receipt=decode(receiptBody,receiptHash),notice=decode(noticeBody,noticeHash);
  const {receipt_digest,...unsigned}=receipt,grantRef=reference('grant',scope,grantId,grant),commitRef=reference('controller_commit',scope,commitId,commit);
  need(same(request.controller_scope,scope)&&same(request.origin_scope,{authority_service_id:serviceId,database_instance_id:databaseId})&&
   request.preparation_id===id&&request.run_id===runId&&request.arm_generation===generation&&grant.grant_id===grantId&&
   request.approval_ref.object_id===approvalId&&same(grant.approval_ref,request.approval_ref)&&grant.endorsement_ref.object_id===endorsementId&&
   grant.run_id===runId&&grant.arm_generation===generation&&same(commit.plan_ref,request.plan_ref)&&
   commit.commit_id===commitId&&commit.preparation_id===id&&commit.request_digest===requestDigest&&same(commit.grant_ref,grantRef)&&
   same(receipt.controller_scope,scope)&&receipt.preparation_id===id&&receipt.request_digest===requestDigest&&
   same(receipt.grant,grant)&&same(receipt.grant_ref,grantRef)&&same(receipt.commit_ref,commitRef)&&digest(unsigned)===receipt_digest&&
   same(notice,{kind:'run_preparation_applied',preparation_id:id,receipt_ref:reference('preparation_receipt',scope,receipt.receipt_id,receipt)}),'preparation_integrity');
  const record={request,request_digest:requestDigest,revision:'2',state:'applied',applied_receipt:receipt,protection_ref:null};
  const result={record,commit};
  if(row.reduce((bytes,value)=>bytes+(typeof value==='string'?Buffer.byteLength(value):0),0)<=bodyLimit)lastVerified={row,result};
  return includeCommit?result:record;
 }
 function find(origin,id,requestDigest,includeCommit=false){
  const row=db.prepare(select+' WHERE p.preparation_id=? AND p.origin_service_id=? AND p.origin_database_instance_id=?').raw().get(id,origin.authority_service_id,origin.database_instance_id);
  if(!row)return null;
  need(row[5]===requestDigest,'preparation_conflict');return stored(row,includeCommit);
 }
 function paired(bindingId,socket,origin,write=false){
  const {record,peer}=authorizePeer(bindingId,socket);
  need(record.state==='activated'&&peer.service_kind==='seamer'&&same(peerScope(peer),origin)&&peer.permissions.includes('automation.prepare.read')&&
   (!write||peer.permissions.includes('automation.prepare')),'preparation_scope');
  return record;
 }
 function actionPair(bindingId,socket,origin){
  if(!activePeer||Number(service.schema_revision)<97)return paired(bindingId,socket,origin,true);
  const record=activePeer(origin,bindingId),peer=record.transcript.parties.find(item=>same(peerScope(item),origin));
  need(peer?.service_kind==='seamer'&&['automation.prepare.read','automation.prepare'].every(value=>peer.permissions.includes(value)),'preparation_scope');
  return record;
 }
 function settledControlReference(current,original,grantRef){
  if(current.value.change_kind!=='gate_protect'||!grantRef)return false;
  return withExecutionReadView(db,()=>{
   const matches=db.prepare(`SELECT s.command_id,c.permit_id FROM command_closure_request c
    JOIN command_settlement s USING(permit_id) WHERE c.control_source_id=? LIMIT 2`).raw().all(current.ref.id);
   if(matches.length!==1)return false;
   const [commandId,permitId]=matches[0],settled=readCommandRecord(db,commandId),closed=readCommandClosure(db,permitId);
   const {metadata}=settled.source;
   return settled.lifecycle?.settlement?.succeeded===true&&metadata.origin==='automation'&&
    metadata.run_binding.grant_id===grantRef.object_id&&metadata.run_binding.grant_revision===grantRef.revision&&
    same(metadata.scope,grantRef.scope)&&same(closed.value.control_ref,current.ref)&&
    same(closed.source.ready.value.control_before_ref,original);
  });
 }
 function controlsCurrent(request,preparedControls=null,grantRef=null){
  const ids=[...new Set(request.grant_intent.device_actions.map(action=>action.device_id))].sort();
  need(same(ids,request.controls.map(control=>control.device_id)),'preparation_controls');
  return request.controls.map(({device_id,expected_control})=>{
   const {current}=currentControlSource(db,device_id),value=current.value;
   need(same(value.scope,scope)&&value.device_id===device_id&&value.mode==='automatic'&&
    value.pending_operation_id===null&&value.holder===null&&same(expected_control,{epoch:value.control_epoch,version:value.effective_version}),
    'preparation_control_changed');
   const original=preparedControls?.find(item=>item.device_id===device_id)?.control_ref;
   if(value.gate_state==='protected'){
    // 只有本RunGrant可查回的已结算关闭切点，可以把保护态与布防原件相连。
    const sameBasis=original&&Number(service.schema_revision)>=96&&settledControlReference(current,original,grantRef);
    return {device_id,control_ref:sameBasis?original:current.ref};
   }
   need(Number(service.schema_revision)>=96&&value.gate_state==='ready'&&original&&
    currentControlReference(db,current,original),'preparation_control_changed');
   return {device_id,control_ref:original};
  });
 }
 function assertRunEligible(origin,approval,runId,generation){
  need(!db.prepare(`SELECT 1 FROM run_approval_rejection WHERE origin_service_id=? AND origin_database_instance_id=? AND approval_id=?`)
   .pluck().get(origin.authority_service_id,origin.database_instance_id,approval.object_id),'preparation_rejected');
  if(Number(service.schema_revision)>=78)need(!runGenerationDenied(db,origin,runId,generation),'preparation_generation_denied');
 }
 async function prepare(bindingId,socket,input){
  const request=armPreparationRequest(structuredClone(input),scope),requestDigest=digest(request);
  const {origin_scope:origin,preparation_id:id,plan_ref,operation_ref,approval_ref,grant_intent:intent}=request;
  const initial=writer(()=>{
   const record=paired(bindingId,socket,origin),existing=find(origin,id,requestDigest);
   need(same(paired(bindingId,socket,origin,!existing),record),'preparation_pairing_changed');
   return {record,existing};
  });
  if(initial.existing)return {created:false,record:structuredClone(initial.existing)};
  need(readPlan&&pending<4,'preparation_unavailable');
  const start=pairingSample(),started=BigInt(start.tick_ns);pending++;
  try{
   const plan=await readPlan(bindingId,structuredClone(plan_ref));
   const original=structuredClone(plan?.original);
   need(same(armPlanOriginal(original,plan_ref,scope),request)&&typeof plan.assertCurrentInTransaction==='function','preparation_plan');
   const expected={approval_ref,arm_generation:request.arm_generation,artifact_ref:request.artifact_ref,definition_id:original.definition_id,
    definition_version:request.definition_version,preparation_id:id,run_id:request.run_id};
   const prepared=await prepareInitiator(bindingId,operation_ref,expected);
   return writer(()=>{
    const before=paired(bindingId,socket,origin),existing=find(origin,id,requestDigest);
    if(existing){
     need(same(paired(bindingId,socket,origin),before),'preparation_pairing_changed');
     return {created:false,record:structuredClone(existing)};
    }
    const verified=()=>{
     need(same(paired(bindingId,socket,origin,true),initial.record)&&same(before,initial.record),'preparation_pairing_changed');
     need(plan.assertCurrentInTransaction()===true,'preparation_plan_changed');
     const actual=prepared.assertIssuanceInTransaction();
     const {not_before,not_after,authorization_policy_revision}=intent.validity;
     const lower=BigInt(Date.parse(not_before))*1000000n,upper=BigInt(Date.parse(not_after))*1000000n;
     const now=time();
     need(same(actual.approval_ref,approval_ref)&&same(actual.initiator.operation_ref,operation_ref)&&
      same(intent.principal,{...actual.service_principal,principal_kind:'service'})&&same(intent.device_actions,actual.device_actions)&&
      same(intent.parameter_constraints,actual.parameter_constraints)&&authorization_policy_revision===actual.target_policy_ref.revision&&
      lower>=BigInt(Date.parse(actual.validity.not_before))*1000000n&&upper<=proposalWindowEnd(actual)&&
      now.lower>=lower&&now.upper<upper&&now.upper<BigInt(actual.initiator.eligible_before_ns),'preparation_authorization');
     assertRunEligible(origin,approval_ref,request.run_id,request.arm_generation);
     const controls=controlsCurrent(request);
     need(same(controls,original.controls),'preparation_control_changed');
     const last=pairingSample(),tick=BigInt(last.tick_ns);
     need(same(last.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<started+2000000000n&&
      BigInt(last.upper_ns)<upper&&BigInt(last.upper_ns)<BigInt(actual.initiator.eligible_before_ns),'preparation_expired');
     return {actual,controls};
    };
    const proof=verified();
    need(!db.prepare(`SELECT 1 FROM run_preparation WHERE preparation_id=? OR
     (origin_service_id=? AND origin_database_instance_id=? AND run_id=? AND arm_generation=?)`).pluck()
     .get(id,origin.authority_service_id,origin.database_instance_id,request.run_id,request.arm_generation),'preparation_conflict');
    const {actual}=proof,grant_id=crypto.randomUUID(),commit_id=crypto.randomUUID();
    const grant={grant_id,revision:'1',origin_scope:origin,run_id:request.run_id,definition_version:request.definition_version,
     arm_generation:request.arm_generation,principal:intent.principal,issuer_id:actual.service_principal.issuer_id,issuer_epoch:actual.service_principal.issuer_epoch,
     device_actions:intent.device_actions,parameter_constraints:intent.parameter_constraints,validity:intent.validity,state:'active',
     approval_ref,endorsement_ref:actual.endorsement_ref};
    const grant_ref=reference('grant',scope,grant_id,grant);
    const commit={commit_id,preparation_id:id,request_digest:requestDigest,grant_ref,pairing_ref:pairingReference(initial.record),plan_ref,proof,
     service_boot_id:bootId,clock_domain_ref:start.runtime_domain_ref};
    const commit_ref=reference('controller_commit',scope,commit_id,commit);
    const unsigned={receipt_id:crypto.randomUUID(),revision:'1',controller_scope:scope,preparation_id:id,request_digest:requestDigest,grant,grant_ref,commit_ref};
    const receipt={...unsigned,receipt_digest:digest(unsigned)};
    const notice={kind:'run_preparation_applied',preparation_id:id,receipt_ref:reference('preparation_receipt',scope,receipt.receipt_id,receipt)};
    const [requestText,grantText,commitText,receiptText,noticeText]=[request,grant,commit,receipt,notice].map(canonical);
    const bytes=[requestText,grantText,commitText,receiptText,noticeText].reduce((sum,text)=>sum+Buffer.byteLength(text),0);
    const [count,existingBytes]=db.prepare('SELECT count(*),coalesce(sum(logical_bytes),0) FROM run_preparation').raw().get();
    need(bytes<=4*bodyLimit&&count<16384&&existingBytes+bytes<=64*bodyLimit,'preparation_capacity');
    put(db.prepare('INSERT INTO run_preparation VALUES(?,?,?,?,?,?,?,?,?)')
     .run(id,origin.authority_service_id,origin.database_instance_id,request.run_id,request.arm_generation,approval_ref.object_id,requestDigest,requestText,bytes));
    put(db.prepare('INSERT INTO run_preparation_grant VALUES(?,?,?,?,?)').run(grant_id,id,actual.endorsement_ref.object_id,grantText,grant_ref.digest));
    put(db.prepare('INSERT INTO run_preparation_commit VALUES(?,?,?,?,?,?,?,?)')
     .run(commit_id,id,commitText,commit_ref.digest,receiptText,digest(receipt),noticeText,digest(notice)));
    need(same(verified(),proof),'preparation_changed');
    return {created:true,record:structuredClone(find(origin,id,requestDigest))};
   });
  }finally{pending--;}
 }
 async function prepareGrantObservation(bindingId,socket,request,forAction=false){
  need(prepareApproval&&pendingEligibility<4,'preparation_unavailable');
  const {origin_scope,preparation_id,request_digest}=request.lookup;
  const start=pairingSample(),started=BigInt(start.tick_ns);
  const observationDeadline=started+runEligibilityObservationNs;
  function ownState(){
   const pair=forAction?actionPair(bindingId,socket,origin_scope):paired(bindingId,socket,origin_scope);
   const original=find(origin_scope,preparation_id,request_digest,true);
   need(original,'preparation_ineligible');
   const {record,commit}=original,receipt=record.applied_receipt,grant=receipt.grant;
   need(bootId&&commit.service_boot_id===bootId&&same(commit.clock_domain_ref,start.runtime_domain_ref)&&
    same(commit.pairing_ref,pairingReference(pair))&&same(receipt.grant_ref,request.grant_ref)&&
    same(reference('preparation_receipt',scope,receipt.receipt_id,receipt),request.receipt_ref),'preparation_ineligible');
   assertRunEligible(origin_scope,grant.approval_ref,grant.run_id,grant.arm_generation);
   need(same(controlsCurrent(record.request,commit.proof.controls,receipt.grant_ref),commit.proof.controls),'preparation_control_changed');
   return {pair,record};
  }
  const initial=writer(ownState);pendingEligibility++;
  try{
   const approved=await prepareApproval(bindingId,initial.record.applied_receipt.grant.approval_ref);
   let valid=true;
   function verifyInTransaction(){
    need(valid&&db.inTransaction,'preparation_ineligible');
    try{
     const current=ownState(),proof=approved.assertCurrentInTransaction(),grant=current.record.applied_receipt.grant;
     need(same(current,initial)&&same(proof.approval_ref,grant.approval_ref)&&same(proof.endorsement_ref,grant.endorsement_ref),'preparation_ineligible');
     const {not_before,not_after}=grant.validity,before=BigInt(Date.parse(not_before))*1000000n;
     const deadline=[proof.eligible_before_ns,current.pair.expires_ns,String(proposalWindowEnd({validity:{not_before,not_after}}))]
      .map(BigInt).reduce((a,b)=>a<b?a:b);
     const now=time(),last=pairingSample(),tick=BigInt(last.tick_ns);
     need(now.lower>=before&&now.upper<deadline&&BigInt(last.lower_ns)>=before&&BigInt(last.upper_ns)<deadline&&
      same(last.runtime_domain_ref,start.runtime_domain_ref)&&tick>=started&&tick<observationDeadline,'preparation_expired');
     return {record:current.record,eligible_before_ns:String(deadline),not_before_ns:String(before)};
    }catch(error){valid=false;throw error;}
   }
   return verifyInTransaction;
  }finally{pendingEligibility--;}
 }
 async function prepareEligibility(bindingId,socket,input){
  const request=armPreparationEligibilityRequest(structuredClone(input),scope);
  const check=await prepareGrantObservation(bindingId,socket,request);
  const verify=()=>writer(()=>{
   const {eligible_before_ns}=check();
   return {request:structuredClone(request),state:'eligible',eligible_before_ns};
  });
  return {body:verify(),beforeSend:verify};
 }
 async function prepareActionAdmission(bindingId,socket,input){
  need(readAction&&pendingActions<4,'action_unavailable');
  const request=actionAdmissionRequest(structuredClone(input),scope);
  const {origin_scope}=request.preparation.lookup;
  const initial=writer(()=>paired(bindingId,socket,origin_scope,true));
  pendingActions++;
  try{
   const [grantResult,actionResult]=await Promise.allSettled([
    prepareGrantObservation(bindingId,socket,request.preparation,true),
    Promise.resolve().then(()=>readAction(bindingId,structuredClone(request)))
   ]);
   if(grantResult.status==='rejected')throw grantResult.reason;
   if(actionResult.status==='rejected')throw actionResult.reason;
   const grant=grantResult.value,observed=actionResult.value;
   const original=structuredClone(observed.original);
   let valid=true,verifiedRecord=null,verifiedBinding=null;
   function assertCurrentInTransaction(){
    need(db.inTransaction&&valid,'action_unavailable');
    try{
     const {record,eligible_before_ns,not_before_ns}=grant();
     need(same(actionPair(bindingId,socket,origin_scope),initial)&&observed.assertCurrentInTransaction()===true,'action_source_changed');
     if(record!==verifiedRecord){
      verifiedBinding=actionAdmissionBinding(original,request,record);
      verifiedRecord=record;
     }
     const binding=verifiedBinding;
     const deadline=[eligible_before_ns,binding.eligible_before_ns].map(BigInt).reduce((a,b)=>a<b?a:b);
     need(time().upper<deadline,'action_expired');
     return {...structuredClone(binding),eligible_before_ns:String(deadline),not_before_ns};
    }catch(error){valid=false;throw error;}
   }
   const binding=writer(assertCurrentInTransaction);
   return Object.freeze({get original(){return structuredClone(binding);},assertCurrentInTransaction});
  }finally{pendingActions--;}
 }
 function protectionTargets(notice,runId,{includeDevices=false}={}){
  need(db.inTransaction,'preparation_transaction');
  const {origin_scope,approval_ref,endorsement_ref}=notice;
  return db.prepare(select+` WHERE p.origin_service_id=? AND p.origin_database_instance_id=? AND p.approval_id=?
   ORDER BY p.preparation_id`).raw().all(origin_scope.authority_service_id,origin_scope.database_instance_id,approval_ref.object_id).map(row=>{
   const {request,request_digest,applied_receipt}=stored(row);
   const {run_id,arm_generation,operation_ref,preparation_id}=request;
   need(run_id===runId&&same(request.approval_ref,approval_ref)&&same(applied_receipt.grant.endorsement_ref,endorsement_ref),'preparation_integrity');
   return {run_id,arm_generation,operation_ref:structuredClone(operation_ref),preparation_id,request_digest,grant_ref:structuredClone(applied_receipt.grant_ref),
    ...(includeDevices?{device_ids:request.grant_intent.device_actions.map(action=>action.device_id)}:{})};
  });
 }
 const automationCommands=Number(service.schema_revision)>=95?automationCommandStore({db,scope,writer,time,prepare:prepareActionAdmission,
  requireExecution:Number(service.schema_revision)>=96,materialize:Number(service.schema_revision)>=97,execution:automationExecution,
  authorize(bindingId,socket,request,purpose){
   const {lookup,grant_ref,receipt_ref}=request.action.preparation,origin=lookup.origin_scope;
   const pair=paired(bindingId,socket,origin,purpose==='submit'),found=find(origin,lookup.preparation_id,lookup.request_digest);
   const peer=pair.transcript.parties.find(item=>same(peerScope(item),origin));
   need(purpose!=='protect'||peer?.permissions.includes('automation.protect'),'automation_command_protection');
   const receipt=found?.applied_receipt;
   need(receipt&&same(receipt.grant_ref,grant_ref)&&same(reference('preparation_receipt',scope,receipt.receipt_id,receipt),receipt_ref)&&
    receipt.grant.device_actions.some(action=>same(action,request.target)),'automation_command_authority');
   return {pairing_ref:pairingReference(pair),principal:receipt.grant.principal};
  }}):null;
 return Object.freeze({prepare,prepareEligibility,prepareActionAdmission,automationCommands,protectionTargets,lookup(bindingId,socket,input){
  const request=armPreparationLookup(structuredClone(input),scope);
  return writer(()=>{
   const binding=paired(bindingId,socket,request.origin_scope);
   const record=find(request.origin_scope,request.preparation_id,request.request_digest);
   need(same(paired(bindingId,socket,request.origin_scope),binding),'preparation_pairing_changed');
   return {state:record?'found':'not_found',record:structuredClone(record)};
  });
 },bindPlanReader(reader){
  need(typeof reader==='function'&&!readPlan,'preparation_unavailable');readPlan=reader;
 },bindActionReader(reader){
  need(typeof reader==='function'&&!readAction,'action_unavailable');readAction=reader;
 }});
}
