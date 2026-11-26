import {randomUUID} from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {pairingNeed as need} from './peer-pairing-value.mjs';
import {automationCommandAdjudication,automationCommandIdentity,automationCommandRequest,automationCommandTerminal} from './peer-automation-command.mjs';
import {readCommandRecord,readCommandResource,readCommandRevision,storeAutomationCommandRecord} from './command-record-store.mjs';

const ref=(kind,scope,object_id,body)=>({kind,scope,object_id,revision:'1',digest:digest(body)});

export function automationCommandStore({db,scope,writer,time,authorize,prepare,requireExecution=false,materialize=false,execution=null}){
 const search=db.prepare(`SELECT body_jcs,body_digest,request_digest,decision,command_id FROM automation_command_adjudication
  WHERE origin_service_id=? AND origin_database_instance_id=? AND (idempotency_key=? OR execution_id=? AND step_id=?)`).raw();
 const insert=db.prepare('INSERT INTO automation_command_adjudication VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)');
 const total=db.prepare('SELECT count(*) FROM automation_command_adjudication').pluck();
 const queued=db.prepare("SELECT count(*) FROM automation_command_adjudication WHERE device_id=? AND decision='accepted'").pluck();
 function address(request){
  const {authority_service_id,database_instance_id}=request.action.preparation.lookup.origin_scope;
  return [authority_service_id,database_instance_id];
 }
 function original(request,identity,resultPairing=null){
  const rows=search.all(...address(request),request.idempotency_key,request.action.execution_ref.object_id,request.action.step_id);
  if(!rows.length)return null;
  need(rows.length===1&&rows[0][2]===identity.request_digest,'automation_command_conflict');
  const [text,hash,,decision,commandId]=rows[0],body=JSON.parse(text),{adjudication,command,commit}=body;
  need(canonical(body)===text&&digest(body)===hash&&same(body.request,request)&&same(adjudication.identity,identity)&&
   adjudication.decision===decision&&same(adjudication.commit_ref,ref('controller_commit',scope,commit.commit_id,commit))&&
   same(commit.identity,identity)&&commit.decision===decision&&
   same(adjudication.command_ref,command===null?null:ref('command',scope,commandId,command))&&
   (command===null?decision==='rejected':decision==='accepted'&&command.command_id===commandId&&same(command.identity,identity)&&same(command.target,request.target)),
   'automation_command_integrity');
  if(command?.format==='leafseamer.automation-command/2'){
   const {execution_basis:basis,authority}=command,origin=basis?.origin,window=basis?.authentication_window;
   if(resultPairing!==null)need(same(basis?.pairing_ref,resultPairing),'automation_command_result_pairing');
   need(basis?.format==='automation-command-execution-basis/1'&&basis.binding.device_id===request.target.device_id&&same(basis.binding.scope,scope)&&
    same(origin?.execution_ref,request.action.execution_ref)&&same(origin?.parameters_ref,request.action.parameters_ref)&&
    same(origin?.grant_ref,request.action.preparation.grant_ref)&&origin.step_id===request.action.step_id&&
    origin.registration_ref?.kind==='source_registration'&&same(origin.registration_ref.scope,scope)&&
    same(origin.action_binding_ref,authority.action_binding_ref)&&same(basis.schedule_binding,authority.schedule_binding)&&origin.run_id===authority.run_id&&
    origin.arm_generation===authority.arm_generation&&origin.definition_version===authority.definition_version&&
    window?.valid_from_ns===authority.not_before_ns&&window.valid_before_ns===authority.eligible_before_ns&&
    same(window.acquisition_ref,command.accepted_acquisition_ref)&&
    same(window.domain_ref,{clock_domain_id:basis.binding.clock_domain_id,descriptor_digest:basis.binding.descriptor_digest})&&
    BigInt(window.selected_tick_ns)<BigInt(window.before_tick_ns),'automation_command_execution_basis');
  }else if(command)need(command.format==='leafseamer.automation-command/1'&&!Object.hasOwn(command,'execution_basis'),'automation_command_integrity');
  return automationCommandAdjudication(adjudication,request);
 }
 function decide(bindingId,socket,request,qualification,decision){
  let activated=null;
  const result=writer(()=>{
   const owner=authorize(bindingId,socket,request,decision==='rejected'?'protect':'submit');
   const identity=automationCommandIdentity(request,owner.principal);
   const previous=original(request,identity);
   if(previous)return {adjudication:previous,created:false};
   need(total.get()<4096&&(materialize||decision==='rejected'||queued.get(request.target.device_id)<8),'automation_command_capacity');
   const authority=qualification?.assertCurrentInTransaction()??null;
   if(decision==='accepted')need(authority&&same(authority.target,request.target)&&same(authority.principal,owner.principal)&&
    same(authority.grant_ref,request.action.preparation.grant_ref),'automation_command_authority');
   const withExecution=decision==='accepted'&&requireExecution;
   if(withExecution)need(execution,'automation_command_execution_unavailable');
   const selected=withExecution?execution.select(authority,owner.pairing_ref):null;
   const now=time(),command=authority===null?null:{format:selected?'leafseamer.automation-command/2':'leafseamer.automation-command/1',command_id:randomUUID(),identity,
    target:request.target,state:'queued',authority,
    accepted_acquisition_ref:selected?.original.authentication_window.acquisition_ref??now.acquisition??null,
    ...(selected&&{execution_basis:selected.original})};
   const command_ref=command===null?null:ref('command',scope,command.command_id,command);
   const commit={format:'leafseamer.automation-adjudication-commit/1',commit_id:randomUUID(),identity,decision,command_ref,
    observed_upper_ns:String(now.upper),acquisition_ref:now.acquisition??null};
   const unsigned={contract_version:'command-admission/0.1.0-draft.1',adjudication_id:randomUUID(),revision:'1',identity,decision,
    command_ref,commit_ref:ref('controller_commit',scope,commit.commit_id,commit)};
   const adjudication={...unsigned,adjudication_digest:digest(unsigned)},body={request,adjudication,command,commit},action=request.action;
   need(insert.run(...address(request),action.execution_ref.object_id,action.step_id,request.idempotency_key,action.preparation.lookup.preparation_id,
    action.preparation.grant_ref.object_id,request.target.device_id,command?.command_id??null,decision,identity.request_digest,
    canonical(body),digest(body)).changes===1,'automation_command_storage');
   if(materialize&&selected)storeAutomationCommandRecord(db,body,selected.execution);
   need(same(authorize(bindingId,socket,request,decision==='rejected'?'protect':'submit'),owner),'automation_command_authority');
   if(authority){
    const latest=qualification.assertCurrentInTransaction();
    need(same(latest,authority)&&time().upper<BigInt(authority.eligible_before_ns),'automation_command_expired');
    if(selected){
     need(same(selected.assertCurrentInTransaction(latest),selected.original),'automation_command_execution_changed');
     if(materialize)activated={id:command.command_id,verify:preparedRef=>selected.currentExecution(qualification.assertCurrentInTransaction(),preparedRef)};
    }
   }
   return {adjudication:original(request,identity),created:true};
  });
  if(activated)execution.activate(activated.id,activated.verify);
  return result;
 }
 const normalize=input=>automationCommandRequest(structuredClone(input),scope);
 function lookup(bindingId,socket,request,purpose){
  return writer(()=>{
   const owner=authorize(bindingId,socket,request,purpose),result=original(request,automationCommandIdentity(request,owner.principal));
   need(same(authorize(bindingId,socket,request,purpose),owner),'automation_command_authority');return result;
  });
 }
 function readOutcome(bindingId,socket,input,includeResource){
  const request=normalize(input);
  return writer(()=>{
   const owner=authorize(bindingId,socket,request,'read');
   const adjudication=original(request,automationCommandIdentity(request,owner.principal),owner.pairing_ref);
   let terminal=null,resource=null;
   if(adjudication?.command_ref&&db.prepare('SELECT 1 FROM command_admission_source WHERE command_id=?').pluck().get(adjudication.command_ref.object_id)){
    const command_ref=adjudication.command_ref,saved=readCommandRecord(db,command_ref.object_id),head=saved.record;
    need(head.origin==='automation'&&same(head.initial_command_ref,command_ref)&&same(saved.adjudication,adjudication),'automation_command_integrity');
    if(head.state.phase==='finished'){
     const revision=head.state.terminal_revision;
     const record=head.revision===revision?head:readCommandRevision(db,command_ref.object_id,revision).record;
     terminal=automationCommandTerminal({format:'leafseamer.automation-command-terminal/1',command_ref,
      record_ref:{...command_ref,revision:record.revision,digest:record.record_digest},state_ref:record.state_ref,state:record.state,
      completion_achieved:record.completion.achieved},adjudication);
    }
    if(includeResource)resource=readCommandResource(db,saved);
   }
   need(same(authorize(bindingId,socket,request,'read'),owner),'automation_command_authority');
   return {adjudication,terminal,...(includeResource&&{resource})};
  });
 }
 return Object.freeze({
  async submit(bindingId,socket,input){
   const request=normalize(input),old=lookup(bindingId,socket,request,'submit');
   if(old)return {adjudication:old,created:false};
   let authority;
   try{authority=await prepare(bindingId,socket,request.action);}
   catch(error){const settled=lookup(bindingId,socket,request,'submit');if(settled)return {adjudication:settled,created:false};throw error;}
   return decide(bindingId,socket,request,authority,'accepted');
  },
  lookup(bindingId,socket,input){
   const adjudication=lookup(bindingId,socket,normalize(input),'read');
   return {state:adjudication===null?'not_found':'found',adjudication};
  },
  ...(materialize&&{result:(bindingId,socket,input)=>readOutcome(bindingId,socket,input,false),
   resource:(bindingId,socket,input)=>readOutcome(bindingId,socket,input,true)}),
  reject(bindingId,socket,input){return decide(bindingId,socket,normalize(input),null,'rejected');}
 });
}
