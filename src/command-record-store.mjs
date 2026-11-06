import {encodingOnlyFrame} from './command-encoding-store.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {IdentityError} from './identity-crypto.mjs';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {routes} from './sdk/runtime/panel-wire/preview/routes.mjs';
import {getSchema,validateValue} from './sdk/runtime/panel-wire/preview/registry.mjs';
import {readInitialReady} from './device-initial-ready.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
import {readDispatchLifecycle} from './command-dispatch.mjs';
import {readSettlementLifecycle} from './command-settlement.mjs';
import {readCommandFinalAdmission} from './command-final-admission.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('command_'+code);};
const bytes=value=>Buffer.from(canonical(value));
const reference=(id,value)=>({id,revision:'1',digest:digest(value)});
const template=JSON.parse(fs.readFileSync(new URL('./simulator-control-capability.json',import.meta.url)));
const capacity={format:'command-capacity/1',profile_id:'leafseamer.simulator.control.limits.1',scope:'development_fixed_memory',
 max_request_keys:4096,max_commands:4096,max_queued_per_device:8,per_command:{commands:1,claims:1,attempts:1,max_packet_bytes:8}};
const readSchema=getSchema(routes.operations.find(v=>v.authority==='controller'&&v.operation_id==='getCommand').responses['200']);
function validate(record){
 const value={view:'current',record},numbers=new Map();
 const walk=(v,p)=>{if(typeof v==='number'){need(Number.isSafeInteger(v),'record_number');numbers.set(p,{integer:true,safe:true});}
  else if(v&&typeof v==='object')for(const [k,x]of Object.entries(v))walk(x,p+'/'+k.replaceAll('~','~0').replaceAll('/','~1'));};
 walk(value,'');validateValue(readSchema,value,numbers);return record;
}
function original(text,hash){const value=JSON.parse(text);need(canonical(value)===text&&'sha256:'+crypto.createHash('sha256').update(text).digest('hex')===hash,'record_integrity');return value;}
const actor=proof=>({principal_id:proof.principal_id,session_id:proof.session_id,authorization_revision:proof.policy_revision,
 issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,local_subject_id:proof.principal_id});
export function commandPolicyInput(value,execution){
 const action=template.actions[0],p=value.parameters,b=execution.value;
 need(execution.catalog.qualification.template_digest===digest(template)&&b.action.action_id===action.action_id&&
  b.action.parameters_schema_digest===action.parameters_schema.digest&&b.action.result_schema_digest===action.result_schema.digest,'capability');
 need(value.action_id===action.action_id&&value.capability_version===action.capability_version,'capability');
 need(p&&Object.keys(p).join(',')==='value'&&Number.isInteger(p.value)&&p.value>=-2147483648&&p.value<=2147483647,'parameters');
 need(value.dispatch.mode==='immediate','reference_time_required');
 need(Array.isArray(value.preconditions)&&value.preconditions.length===0,'preconditions');
 need(action.completion.supported.includes(value.required_completion),'completion');
 need(value.evidence_timeout_ms>0&&value.evidence_timeout_ms<=action.evidence_timeout_ms,'evidence_timeout');
 return {completion:{format:'fixed-memory-completion/1',policy_id:action.completion.evidence_policy_id,capability_ref:b.capability_ref,
   action:b.action,transport_profile_ref:b.transport_profile_ref,levels:action.completion.supported,
   sent:{disposition:'in_flight',proof:'transport_entered',observation_source:'correlated_primitive_observation',bytes_written:8},
   observation:{source:'correlated_module_result',value:p.value,sequence:'strict_successor',binding:'command_attempt_permit'}},
  release:{format:'fixed-memory-release/1',policy_id:'leafseamer.simulator.quiescent_write.1',transport_profile_ref:b.transport_profile_ref,
   automatic_resends:false,external_resources:[],required:'writer_consumption_and_module_completion',failure:'unresolved'},capacity};
}
function publicRecord(source,policy,state,manifest,attempts=[],achieved=null){
 const sref=reference(source.command_id+'_state_'+state.revision,state);sref.revision=state.revision;
 const value={...source.metadata,revision:state.revision,policy,state_ref:sref,state,
  completion:{required:policy.required_completion,achieved,policy_ref:policy.completion_policy_ref,evidence_refs:state.completion_evidence_refs},
  attempts,cancellation:null,evidence_index:{snapshot_ref:reference(source.command_id+'_evidence_'+state.revision,manifest),state_ref:sref,total:String(manifest.members.length)}};
 return validate({...value,record_digest:digest(value)});
}
export function preparedCommandProjection(initial,inventory){
 const a=inventory.attempt,exit=inventory.exit,id=initial.source.command_id;
 const state={...initial.record.state,revision:'2',resource_status:'held',attempt_ids:[a.attempt_id]},sref={...reference(id+'_state_2',state),revision:'2'},
  manifest={command_id:id,revision:'2',members:[]};
 need(inventory.format==='command-attempt-inventory/1'&&inventory.command_id===id&&inventory.revision==='2'&&a.command_id===id&&a.ordinal===1&&
  same(inventory.state_ref,sref)&&same(a.prepared_state_ref,sref)&&same(a.exit_ids,[exit.exit_id])&&same(a.packet_refs,[inventory.packet_ref])&&
  inventory.reports.length===0&&inventory.evidence.length===0,'prepared_inventory');
 const attempts=[{attempt_id:a.attempt_id,ordinal:1,prepared_state_ref:sref,packet_refs:[inventory.packet_ref],outcome:'pending',evidence_refs:[],
  exits:[{exit_ref:reference(exit.exit_id,exit),...Object.fromEntries(['worker_boot_id','ipc_session_id','device_session_id','clock_domain_id','descriptor_digest'].map(k=>[k,exit[k]])),
   send_started_at:null,protocol_request_ids:[]}]}];
 return {state,manifest,record:publicRecord(initial.source,initial.record.policy,state,manifest,attempts)};
}
export function dispatchCommandProjection(initial,final,revision,report=null){
 need(['3','4'].includes(revision)&&(revision==='3'?report===null:report!==null),'dispatch_projection');
 const prepared=final.projection,attempts=structuredClone(prepared.record.attempts);
 if(report?.protocol_request_id!==null&&report?.protocol_request_id!==undefined)attempts[0].exits[0].protocol_request_ids=[report.protocol_request_id];
 // 无可信参考时间映射，传输tick不能转换为UTC；原prepared StateRef固定保留。
 const state={...prepared.state,revision,phase:revision==='3'?'dispatching':'awaiting_evidence',effect_status:'possible'},
  manifest={command_id:initial.source.command_id,revision,members:[]};
 return {state,manifest,record:publicRecord(initial.source,initial.record.policy,state,manifest,attempts)};
}
export function settledCommandProjection(initial,previous,evidence,succeeded){
 const decision=evidence.find(v=>v.kind==='decision'),release=evidence.find(v=>v.kind==='release');
 need(decision&&Boolean(release)===succeeded,'settlement_evidence');
 const attempts=structuredClone(previous.attempts);need(attempts.length===1,'settlement_attempt');
 attempts[0].outcome=succeeded?'succeeded':'unknown';attempts[0].evidence_refs=[decision.source_ref];
 const state={...previous.state,revision:'5',phase:'finished',outcome:succeeded?'succeeded':'unknown',effect_status:succeeded?'verified':'possible',
  resource_status:succeeded?'clear':'unresolved',automation_continuation:succeeded?'eligible':'paused_latched',
  reason_code:succeeded?null:'evidence_unresolved',terminal_revision:'5',completion_evidence_refs:succeeded?[decision.source_ref]:[],resource_evidence_refs:release?[release.source_ref]:[]},
  manifest={command_id:initial.source.command_id,revision:'5',members:evidence.map(v=>({source_ref:v.source_ref,kind:v.kind,view_digest:v.view_digest}))};
 return {state,manifest,record:publicRecord(initial.source,initial.record.policy,state,manifest,attempts,succeeded?'effect_verified':null)};
}
export function prepareCommandRecord({value,content,identity,current,domain,commitRef}){
 const {execution,proof}=current,scope=identity.key.target_scope,policies=commandPolicyInput(value,execution),id=crypto.randomUUID();
 need(execution.ready&&same(domain.ref,{clock_domain_id:execution.value.binding.clock_domain_id,descriptor_digest:execution.value.binding.descriptor_digest}),'clock');
 const tick=BigInt(domain.tick),end=tick+BigInt(value.dispatch.max_queue_ms)*1000000n;
 need(tick<BigInt(execution.ready.value.expires_tick_ns)&&end<=18446744073709551615n,'deadline');
 const accepted={domain:domain.ref,tick_ns:String(tick)},deadline={format:'command-deadline/1',command_id:id,scope,accepted,
  dispatch:value.dispatch,queue_deadline_tick_ns:String(end),evidence_timeout_ms:value.evidence_timeout_ms};
 const initial={command_id:id,scope,revision:'1',request_identity:identity,content,actor:actor(proof),accepted_at:null,
  accepted_monotonic:accepted,binding_ref:execution.ref,ready_ref:execution.ready.ref};
 const initialRef={kind:'command',scope,object_id:id,revision:'1',digest:digest(initial)};
 const abody={contract_version:'command-admission/0.1.0-draft.1',adjudication_id:crypto.randomUUID(),revision:'1',identity,
  decision:'accepted',command_ref:initialRef,commit_ref:commitRef};
 const adjudication={...abody,adjudication_digest:digest(abody)},admissionRef={id:abody.adjudication_id,revision:'1',digest:adjudication.adjudication_digest};
 const policy={command_id:id,scope,device_id:value.device_id,admission_ref:admissionRef,required_completion:value.required_completion,
  completion_policy_ref:reference(id+'_completion_policy',policies.completion),release_policy_ref:reference(id+'_release_policy',policies.release),
  retry_policy_ref:null,max_attempts:1,original_deadline_ref:reference(id+'_deadline',deadline),conflict_scope:'whole_device'};
 const source={format:'command-admission-source/1',command_id:id,initial_ref:initialRef,admission_ref:admissionRef,
  binding_ref:execution.ref,binding:execution.value.binding,ready_ref:execution.ready.ref,context_id:value.context_id,
  token_id:current.token_id,authorization_digest:proof.authorization_digest,scope_digest:proof.scope_digest,policies,deadline,
  metadata:{command_id:id,scope,initial_command_ref:initialRef,request_identity:identity,target:{device_id:value.device_id,action_id:value.action_id,capability_version:value.capability_version},
   actor:initial.actor,origin:'manual',run_binding:null,automation_binding:null,accepted_at:null,dispatch:value.dispatch,control_binding:value.expected_control}};
 const state={command_id:id,scope,revision:'1',phase:'queued',outcome:'pending',effect_status:'not_sent',resource_status:'clear',
  automation_continuation:'eligible',reason_code:null,terminal_revision:null,resolution_ref:null,completion_evidence_refs:[],resource_evidence_refs:[],attempt_ids:[]};
 const manifest={command_id:id,revision:'1',members:[]},claim={format:'command-resource-claim/1',command_id:id,scope,device_id:value.device_id,
  conflict_scope:'whole_device',state:'queued',ownership_ref:null,hold_ref:null};
 return {id,initial,adjudication,source,policy,state,manifest,claim,record:publicRecord(source,policy,state,manifest)};
}
export function storeCommandRecord(db,prepared,keyId,commitId,beforeCount){
 need(db.inTransaction,'writer');const p=prepared,s=p.source,w=result=>need(result.changes===1,'storage');
 w(db.prepare('INSERT INTO ca_command_initial(command_id,key_id,decision,revision,command_digest,command_body,admission_binding_body) VALUES(?,?,\'accepted\',\'1\',?,?,?)')
  .run(p.id,keyId,digest(p.initial),bytes(p.initial),bytes({source_ref:reference(p.id,s)})));
 w(db.prepare('INSERT INTO ca_reservation VALUES(?,?,?,?)').run(keyId,p.id,bytes(reference(capacity.profile_id,capacity)),bytes(capacity.per_command)));
 w(db.prepare('INSERT INTO command_policy VALUES(?,?,?)').run(p.id,canonical(p.policy),digest(p.policy)));
 w(db.prepare('INSERT INTO command_resource_claim VALUES(?,?,?,?)').run(p.id,s.binding.device_id,canonical(p.claim),digest(p.claim)));
 w(db.prepare('UPDATE request_context SET used_count=used_count+1 WHERE context_id=? AND used_count=? AND used_count<max_unique_requests AND state=\'active\'')
  .run(s.context_id,beforeCount));
 w(db.prepare('INSERT INTO command_context_charge VALUES(?,?,?,?)').run(p.id,s.context_id,beforeCount,beforeCount+1));
 w(db.prepare('INSERT INTO command_revision VALUES(?,1,?,?,?,?,?,?,?)').run(p.id,canonical(p.record),p.record.record_digest,canonical(p.state),digest(p.state),canonical(p.manifest),digest(p.manifest),commitId));
 w(db.prepare('INSERT INTO command_admission_source VALUES(?,?,?,?,?,?,?,?,?)').run(p.id,keyId,s.context_id,s.token_id,s.ready_ref.id,s.binding_ref.id,s.binding.device_id,canonical(s),digest(s)));
}
export function readCommandRecord(db,id){return withExecutionReadView(db,()=>{
 const initial=readOriginalRecord(db,id);
 return readLifecycle(db,initial);
 });
}
export function readOriginalRecord(db,id){return memoExecutionRead(db,'command-record-initial',id,()=>readInitialRecord(db,id));}
function readInitialRecord(db,id){
 need(db.inTransaction,'writer');
 const row=db.prepare(`SELECT s.body_jcs,s.body_digest,c.command_body,c.command_digest,c.admission_binding_body,k.content_body,k.request_digest,
  a.adjudication_body,a.adjudication_digest,p.body_jcs,p.body_digest,r.record_jcs,r.record_digest,r.state_jcs,r.state_digest,r.manifest_jcs,r.manifest_digest,
  h.body_jcs,h.body_digest,r.commit_id,a.commit_id,n.commit_body,z.capacity_profile_ref_body,z.dimensions_body
  FROM command_admission_source s JOIN ca_command_initial c USING(command_id,key_id) JOIN ca_request_key k USING(key_id)
  JOIN ca_adjudication a USING(key_id) JOIN command_policy p USING(command_id) JOIN command_resource_claim h USING(command_id)
  JOIN command_revision r USING(command_id) JOIN ca_commit n ON n.commit_id=r.commit_id JOIN ca_reservation z USING(command_id,key_id)
  JOIN ca_audit audit ON audit.commit_id=n.commit_id JOIN ca_notification notice ON notice.commit_id=n.commit_id
  WHERE s.command_id=? AND r.revision=1`).raw().get(id);
 need(row,'record_missing');const [st,sh,ib,ih,ab,cb,ch,at,ah,pt,ph,rt,rh,sst,ssh,mt,mh,ht,hh,commit,admitCommit,ct,cr,dimensions]=row;
 const source=original(st,sh),initial=original(ib.toString(),ih),content=original(cb.toString(),ch),policy=original(pt,ph),state=original(sst,ssh),manifest=original(mt,mh),claim=original(ht,hh),adjudication=JSON.parse(at.toString());
 const {adjudication_digest,...a}=adjudication;
 need(canonical(adjudication)===at.toString()&&adjudication_digest===ah&&digest(a)===ah&&same(a.command_ref,source.initial_ref)&&
  same(source.admission_ref,{id:a.adjudication_id,revision:'1',digest:ah})&&same(a.identity,initial.request_identity)&&same(initial.content,content)&&
  same(JSON.parse(ab.toString()),{source_ref:reference(id,source)})&&source.initial_ref.digest===ih&&source.command_id===id&&initial.command_id===id&&
  commit===admitCommit&&a.commit_ref.digest===digest(JSON.parse(ct.toString())),'record_binding');
 need(same(initial.accepted_monotonic,source.deadline.accepted)&&same(initial.binding_ref,source.binding_ref)&&same(initial.ready_ref,source.ready_ref)&&
  same(initial.actor,source.metadata.actor)&&source.metadata.accepted_at===null&&initial.accepted_at===null&&
  same(source.metadata.request_identity,initial.request_identity)&&same(source.metadata.initial_command_ref,source.initial_ref)&&
  same(source.metadata.control_binding,content.expected_control)&&same(source.metadata.dispatch,content.dispatch)&&
  same(source.metadata.target,{device_id:content.device_id,action_id:content.action_id,capability_version:content.capability_version})&&
  source.metadata.origin==='manual'&&source.metadata.run_binding===null&&source.metadata.automation_binding===null,'record_binding');
 need(same(policy.admission_ref,source.admission_ref)&&same(policy.original_deadline_ref,reference(id+'_deadline',source.deadline))&&
  same(policy.completion_policy_ref,reference(id+'_completion_policy',source.policies.completion))&&same(policy.release_policy_ref,reference(id+'_release_policy',source.policies.release))&&
  policy.required_completion===content.required_completion&&policy.max_attempts===1&&policy.retry_policy_ref===null&&policy.conflict_scope==='whole_device'&&
  same(JSON.parse(cr.toString()),reference(capacity.profile_id,capacity))&&same(JSON.parse(dimensions.toString()),capacity.per_command)&&same(source.policies.capacity,capacity),'record_policy');
 need(state.revision==='1'&&state.phase==='queued'&&state.outcome==='pending'&&state.effect_status==='not_sent'&&state.resource_status==='clear'&&
  state.attempt_ids.length===0&&state.completion_evidence_refs.length===0&&state.resource_evidence_refs.length===0&&
  claim.command_id===id&&claim.state==='queued'&&claim.hold_ref===null&&claim.ownership_ref===null&&claim.device_id===content.device_id&&
  same(manifest,{command_id:id,revision:'1',members:[]}), 'record_state');
 const record=publicRecord(source,policy,state,manifest);need(canonical(record)===rt&&record.record_digest===rh,'record_projection');
 const charge=db.prepare('SELECT context_id,before_count,after_count FROM command_context_charge WHERE command_id=?').raw().get(id);
 need(charge&&charge[0]===source.context_id&&charge[2]===charge[1]+1,'record_charge');
 const ready=readInitialReady(db,source.ready_ref.id),bound=db.prepare('SELECT body_jcs,body_digest FROM device_execution_binding WHERE binding_id=?').raw().get(source.binding_ref.id);
 need(bound,'record_binding');const binding=original(...bound);
 need(same(ready.ref,source.ready_ref)&&same(source.binding,ready.value.binding)&&same(source.binding,binding.binding)&&
  same(source.binding_ref,reference(binding.binding_id,binding))&&same(initial.accepted_monotonic.domain,{clock_domain_id:source.binding.clock_domain_id,descriptor_digest:source.binding.descriptor_digest})&&
  BigInt(initial.accepted_monotonic.tick_ns)>=BigInt(ready.value.selected_tick_ns)&&BigInt(initial.accepted_monotonic.tick_ns)<BigInt(ready.value.expires_tick_ns)&&
  BigInt(source.deadline.queue_deadline_tick_ns)===BigInt(initial.accepted_monotonic.tick_ns)+BigInt(content.dispatch.max_queue_ms)*1000000n,'record_source');
 return {source,record,adjudication,claim};
}
// 初始资格只接无attempt的排队claim；提交后路径须显式匹配唯一T2原件，调用方仍检查占用与全部出站帧。
export function pendingInitialCommands(db,ready,preparedRef=null){
 need(db.inTransaction,'writer');const ids=db.prepare('SELECT command_id FROM ca_command_initial ORDER BY command_id').pluck().all();
 if(!ids.length)return [];
 need([49,50,51,52,53,54,55].includes(Number(db.pragma('user_version',{simple:true})))&&ready,'resource_successor_required');
 return ids.map(id=>{const saved=readCommandRecord(db,id);
  const final=saved.lifecycle?.final_admission;
  const prepared=preparedRef&&final&&same(final.ref,preparedRef)&&saved.record.state.resource_status==='held'&&saved.record.attempts.length===1;
  need((saved.record.state.phase==='queued'||prepared&&saved.lifecycle.dispatch&&['dispatching','awaiting_evidence'].includes(saved.record.state.phase))&&(saved.record.attempts.length===0||prepared)&&same(saved.source.ready_ref,ready.ref)&&same(saved.source.binding,ready.value.binding),'resource_successor');
  return {id,revision:'1',digest:saved.source.initial_ref.digest};});
}
export function commandCapacity(db,device){
 need(db.inTransaction,'writer');
 need(db.prepare('SELECT count(*) FROM ca_request_key').pluck().get()<capacity.max_request_keys&&
  db.prepare('SELECT count(*) FROM ca_command_initial').pluck().get()<capacity.max_commands&&
  db.prepare(Number(db.pragma('user_version',{simple:true}))>=50?
   'SELECT count(*) FROM command_resource_claim c WHERE device_id=? AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=c.command_id)':
   'SELECT count(*) FROM command_resource_claim WHERE device_id=?').pluck().get(device)<capacity.max_queued_per_device,'capacity');
}

function outgoingCut(db,session,through=null){
 const rows=db.prepare(`SELECT record_id,record_digest,message_type,sequence FROM execution_frame_record
  WHERE ipc_session_id=? AND direction='c2w' ORDER BY sequence`).raw().all(session).filter(v=>through===null||BigInt(v[3])<=BigInt(through));
 need(rows.length>0,'queued_closure_requires_execution_ledger');
 const bound=db.prepare('SELECT body_jcs FROM device_execution_binding WHERE ipc_session_id=?').pluck().all(session).map(JSON.parse);
 for(const v of rows){
  if(['HELLO_ACK','FENCE','OPEN_GATE'].includes(v[2]))continue;
  need(v[2]==='ENCODE_PACKET'&&bound.length===1,'queued_closure_requires_execution_ledger');encodingOnlyFrame(db,v[0],bound[0].binding);
 }
 return {through:rows.at(-1)[3],records:rows.map(v=>({id:v[0],digest:v[1],type:v[2],sequence:v[3]}))};
}
function closureOutcome(db,initial,proof){
 const s=initial.source,b=s.binding,record=initial.record;
 need(proof?.format==='queued-command-stop-source/1'&&same(proof.scope,record.scope)&&same(proof.binding,b)&&
  same(proof.initial_command_ref,s.initial_ref)&&same(proof.previous_state_ref,record.state_ref)&&
  same(proof.deadline_ref,record.policy.original_deadline_ref),'closure_binding');
 need(record.state.phase==='queued'&&record.attempts.length===0&&initial.claim.hold_ref===null&&initial.claim.ownership_ref===null,'closure_prestate');
 need(same(outgoingCut(db,b.ipc_session_id,proof.outgoing.through),proof.outgoing),'closure_ledger');
 const boot=db.prepare('SELECT service_id,database_instance_id FROM service_boot WHERE service_boot_id=?').raw().get(proof.observer_boot_id);
 need(boot&&boot[0]===b.scope.authority_service_id&&boot[1]===b.scope.database_instance_id,'closure_observer');
 if(proof.cause==='execution_closed'){
  const ended=db.prepare('SELECT transaction_id,reason FROM execution_session_end WHERE ipc_session_id=?').raw().get(b.ipc_session_id);
  need(ended&&same(proof.end,{transaction_id:ended[0],reason:ended[1]})&&proof.observed===null,'closure_source');return 'blocked';
 }
 need(proof.end===null&&proof.observed&&same(proof.observed.ref,{clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest})&&
  /^(0|[1-9][0-9]{0,19})$/.test(proof.observed.tick),'closure_clock');
 const tick=BigInt(proof.observed.tick);need(tick>=BigInt(s.deadline.accepted.tick_ns),'closure_clock');
 if(proof.cause==='queue_expired'){need(tick>=BigInt(s.deadline.queue_deadline_tick_ns),'closure_deadline');return 'expired';}
 const ready=readInitialReady(db,s.ready_ref.id);need(proof.cause==='ready_expired'&&tick>=BigInt(ready.value.expires_tick_ns),'closure_deadline');return 'blocked';
}
function closedProjection(initial,outcome,reason){
 const state={...initial.record.state,revision:'2',phase:'finished',outcome,automation_continuation:'paused_latched',reason_code:reason,terminal_revision:'2'},
  manifest={command_id:state.command_id,revision:'2',members:[]};
 return {state,manifest,record:publicRecord(initial.source,initial.record.policy,state,manifest)};
}
function readLifecycle(db,initial){
 if(Number(db.pragma('user_version',{simple:true}))<50)return initial;
 // 当前指针逐次读取，不按最大修订降级，也不把当前头放进原件缓存。
 const head=db.prepare('SELECT revision,commit_id FROM command_lifecycle_head WHERE command_id=?').raw().get(initial.source.command_id);
 if(!head)return initial;
 return readLifecycleRevision(db,initial,head);
}
export function readPreparedCommandRecord(db,initial,final){return readLifecycleRevision(db,initial,[2,final.value.commit_id]);}
export function readCommandRevision(db,id,revision){
 const initial=readOriginalRecord(db,id);if(revision==='1')return initial;
 const head=db.prepare('SELECT revision,commit_id FROM command_lifecycle_revision WHERE command_id=? AND CAST(revision AS TEXT)=?').raw().get(id,revision);
 need(head,'not_found');return readLifecycleRevision(db,initial,head);
}
export function readReportedCommandRecord(db,initial,dispatch){return readLifecycleRevision(db,initial,[4,dispatch.report.value.commit_id]);}
function readLifecycleRevision(db,initial,head){
 const row=db.prepare(`SELECT r.record_jcs,r.record_digest,r.state_jcs,r.state_digest,r.manifest_jcs,r.manifest_digest,
  c.body_jcs,c.body_digest,c.audit_jcs,c.notification_jcs,c.revision,c.command_id FROM command_lifecycle_revision r
  JOIN command_lifecycle_commit c USING(command_id,revision,commit_id) WHERE r.command_id=? AND r.revision=? AND r.commit_id=?`)
  .raw().get(initial.source.command_id,...head);
 need(row&&row[10]===head[0]&&row[11]===initial.source.command_id,'lifecycle_head');
 if(head[0]===5)return readSettlementLifecycle(db,initial,head,row);
 if(head[0]>=3)return readDispatchLifecycle(db,initial,head,row);
 need(head[0]===2,'lifecycle_head');
 const body=original(row[6],row[7]),prepared=body.format==='command-final-admission-commit/1';
 need(!prepared||Number(db.pragma('user_version',{simple:true}))>=52,'lifecycle_version');
 const final=prepared?readCommandFinalAdmission(db,initial,body.transaction_ref):null,
  expected=prepared?final.projection:closedProjection(initial,closureOutcome(db,initial,body.proof),body.proof.cause);
 need((prepared||body.format==='command-queued-closure/1')&&body.commit_id===head[1]&&body.command_id===row[11]&&body.revision==='2'&&
  same(body.previous_state_ref,initial.record.state_ref)&&body.record_digest===expected.record.record_digest&&body.state_digest===digest(expected.state)&&
  row[0]===canonical(expected.record)&&row[1]===expected.record.record_digest&&row[2]===canonical(expected.state)&&row[3]===digest(expected.state)&&
  row[4]===canonical(expected.manifest)&&row[5]===digest(expected.manifest)&&
  row[8]===canonical({kind:prepared?'command_prepared':'command_finished',command_id:row[11],revision:'2',commit_ref:reference(head[1],body)})&&row[9]===row[8],'lifecycle_integrity');
 return {...initial,record:expected.record,lifecycle:{commit_ref:reference(head[1],body),...(prepared?{final_admission:final}: {proof:body.proof})}};
}
// 内部同步writer从当前数据库及监督时钟生成关闭依据；HTTP不能提交proof或指定结论。
export function closeQueuedCommand(db,id,{bootId,domain}){
 need(db.inTransaction&&Number(db.pragma('user_version',{simple:true}))>=50,'lifecycle_writer');
 const initial=readOriginalRecord(db,id),current=readLifecycle(db,initial);if(current.record.state.phase!=='queued'||current.record.attempts.length)return current;
 const s=initial.source,b=s.binding,end=db.prepare('SELECT transaction_id,reason FROM execution_session_end WHERE ipc_session_id=?').raw().get(b.ipc_session_id);
 let cause,observed=null;
 if(end)cause='execution_closed';
 else{
  observed=domain();if(!observed)return current;
  need(same(observed.ref,{clock_domain_id:b.clock_domain_id,descriptor_digest:b.descriptor_digest}),'closure_clock');
  const tick=BigInt(observed.tick),ready=readInitialReady(db,s.ready_ref.id);
  if(tick>=BigInt(s.deadline.queue_deadline_tick_ns))cause='queue_expired';
  else if(tick>=BigInt(ready.value.expires_tick_ns))cause='ready_expired';
  else return current;
 }
 const proof={format:'queued-command-stop-source/1',scope:b.scope,binding:b,initial_command_ref:s.initial_ref,previous_state_ref:initial.record.state_ref,
  deadline_ref:initial.record.policy.original_deadline_ref,observer_boot_id:bootId,cause,observed,end:end?{transaction_id:end[0],reason:end[1]}:null,
  outgoing:outgoingCut(db,b.ipc_session_id)};
 const outcome=closureOutcome(db,initial,proof),value=closedProjection(initial,outcome,cause),commit=crypto.randomUUID();
 const body={format:'command-queued-closure/1',commit_id:commit,command_id:id,revision:'2',previous_state_ref:initial.record.state_ref,
  record_digest:value.record.record_digest,state_digest:digest(value.state),proof};
 const audit=canonical({kind:'command_finished',command_id:id,revision:'2',commit_ref:reference(commit,body)}),w=v=>need(v.changes===1,'lifecycle_storage');
 w(db.prepare('INSERT INTO command_lifecycle_revision VALUES(?,2,?,?,?,?,?,?,?)').run(id,canonical(value.record),value.record.record_digest,
  canonical(value.state),digest(value.state),canonical(value.manifest),digest(value.manifest),commit));
 w(db.prepare('INSERT INTO command_lifecycle_commit VALUES(?,?,2,?,?,?,?,?)').run(commit,id,canonical(body),digest(body),audit,crypto.randomUUID(),audit));
 w(db.prepare('INSERT INTO command_lifecycle_head VALUES(?,2,?)').run(id,commit));
 return readLifecycle(db,initial);
}
