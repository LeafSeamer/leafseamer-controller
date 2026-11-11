import {cacheVerifiedDocument} from './verified-document-cache.mjs';
import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {checked,seal,ref,digest,same} from './auth-clock-value.mjs';
import {currentDeviceAuthorization,readDeviceAuthorizationState} from './device-authorization-state.mjs';
import {memoExecutionRead,withExecutionReadView} from './execution-read-view.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('device_evidence_'+code);};
const namedRef=v=>({id:v.evidence_id,revision:v.revision,digest:v.evidence_digest});
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const namedSeal=(v,key)=>({...v,[key]:digest(v)});
const document=cacheVerifiedDocument((text,hash,key='digest')=>{
 const v=JSON.parse(text),{[key]:actual,...body}=v;need(canonicalize(v)===text&&actual===hash&&digest(body)===hash,'integrity');return v;
});
function body(db,sql,...args){const row=db.prepare(sql).raw().get(...args);need(row,'source_missing');
 return memoExecutionRead(db,'device-evidence-source-document',row,()=>{
  const v=JSON.parse(row[0]);need(canonicalize(v)===row[0]&&'sha256:'+crypto.createHash('sha256').update(row[0]).digest('hex')===row[1],'source_integrity');return v;
 });}

// 本机ordinary/manual设备资格的完整适用集合；不复用单条命令的授权使用或RunGrant。
function revocationCut(db,service,selected,execution){
 need(db.inTransaction&&selected.context.mode==='manual'&&selected.context.purpose==='ordinary','scope');
 need(same(execution.value.binding,selected.binding),'runtime_binding');
 const runtime=body(db,'SELECT body_jcs,body_digest FROM worker_runtime_binding WHERE runtime_id=?',execution.value.runtime_binding_ref.object_id);
 const binding=runtime.launch_intent.extension_binding;
 need(runtime.runtime_binding_id===execution.value.runtime_binding_ref.object_id&&digest(runtime)===execution.value.runtime_binding_ref.digest&&
  same(runtime.admission_receipt.domain_ref,{clock_domain_id:selected.binding.clock_domain_id,descriptor_digest:selected.binding.descriptor_digest})&&
  runtime.admission_receipt.member_boot_id===selected.binding.worker_boot_id,'runtime_binding');
 const approval=body(db,'SELECT body_jcs,body_digest FROM extension_approval WHERE approval_id=?',binding.approval_ref.object_id);
 const content=body(db,'SELECT content_jcs,content_digest FROM extension_candidate WHERE installation_id=?',binding.installation_ref.object_id);
 need(same(approval.approval_ref,binding.approval_ref)&&same(approval.installation_ref,binding.installation_ref)&&
  content.installation_id===binding.installation_ref.object_id&&digest(content)===binding.installation_ref.digest&&
  same(content.intake_ref,binding.intake_ref)&&content.receipt.host_trust_epoch===binding.host_trust_epoch&&
  content.receipt.host_installation_id===binding.host_installation_id&&same(content.receipt.platform_profile_ref,binding.platform_profile_ref),'extension_binding');
 const denied=db.prepare('SELECT deny_id,body_jcs,body_digest FROM extension_approval_deny WHERE approval_id=?').raw().all(binding.approval_ref.object_id);
 need(denied.length===0&&!db.prepare('SELECT 1 FROM worker_launch_denial WHERE launch_id=?').pluck().get(runtime.launch_intent.launch_id)&&
  !db.prepare('SELECT 1 FROM worker_runtime_withdrawal WHERE runtime_id=?').pluck().get(runtime.runtime_binding_id),'revoked');
 need(selected.authorization_dependencies.length===2&&selected.authorization_dependencies.every(v=>v.result==='no_matching_denial'),'revoked');
 // local_issuer原件在本库不可改写；跨服务issuer必须由独立提供者接入，不能继承这个集合。
 const issuer=db.prepare('SELECT issuer_id,issuer_epoch,initialization_tx_id FROM identity_issuer').raw().get();need(issuer,'issuer');
 need(selected.authorization_dependencies.every(v=>v.identity.issuer_id===issuer[0]&&v.identity.issuer_epoch===issuer[1]),'issuer');
 return {format:'local-manual-device-revocation-cut/1',scope:selected.binding.scope,binding:selected.binding,context_digest:selected.context_digest,
  source_refs:{holder:selected.source_refs.holder,evaluator:selected.source_refs.evaluator},identity_dependencies:selected.authorization_dependencies,
  extension:{runtime_ref:execution.value.runtime_binding_ref,installation_ref:binding.installation_ref,approval_ref:binding.approval_ref,
   review_ref:binding.review_ref,configuration_ref:binding.configuration_ref,role_resolution_ref:binding.role_resolution_ref,permissions_digest:binding.permissions_digest},
  trust:{local_issuer:{issuer_id:issuer[0],issuer_epoch:issuer[1],initialization_tx_id:issuer[2]},
   host_installation_id:binding.host_installation_id,host_trust_epoch:binding.host_trust_epoch,platform_profile_ref:binding.platform_profile_ref,intake_ref:binding.intake_ref},
  applicability:{grant:'per_command_not_device_gate',cancel:'ordinary_only',remote_issuer:'not_selected'},
  observed_floor_result:'no_matching_denial'};
}
function requirement(selected,m,e,cut,id,tick){
 return namedSeal({format_version:'open-authorization-requirement/0.1.0-draft.1',requirement_id:id,revision:'1',binding:selected.binding,
  purpose:'ordinary',control_mode:'manual',control_state_ref:m.value.control_state_ref,control_authority_ref:m.value.control_authority_ref,holder:m.value.holder,
  evaluator:{runtime_ref:e.value.core_runtime_source_ref,policy_ref:e.value.policy_ref,authority_response_ref:e.ref,scope_proof_ref:e.value.policy_ref,validity_ref:ref(e.value.authentication_window)},
  holder_evidence:{principal:m.value.holder,session_id:m.value.session_id,credential_id:m.value.credential_id,
   challenge_ref:m.value.challenge_ref,response_ref:m.ref,scope_proof_ref:ref(m.value.authorization),validity_ref:ref(m.value.authentication_window)},
  cancel_evidence:null,authorization_state_ref:selected.state_ref,revocation_cut_ref:ref(cut),selected_tick_ns:tick,expires_tick_ns:selected.expires_tick_ns},'requirement_digest');
}
export function selectedDeviceEvidenceDeadline(db,state){
 need(db.inTransaction,'writer');const row=db.prepare(`SELECT e.body_jcs,e.body_digest,c.body_jcs,c.body_digest,h.generation
  FROM device_authorization_evidence_head h JOIN device_authorization_evidence e USING(evidence_id)
  JOIN device_authorization_evidence_commit c ON c.commit_id=h.commit_id WHERE h.state_id=?`).raw().get(state.ref.id);
 if(!row)return null;const evidence=document(row[0],row[1],'evidence_digest'),commit=checked(document(row[2],row[3]));
 need(same(evidence.state_ref,state.ref)&&same(commit.evidence_ref,namedRef(evidence))&&commit.generation===String(row[4])&&
  same(evidence.requirement.authorization_state_ref,state.ref),'head');return evidence.requirement.expires_tick_ns;
}
// 仅核心内部writer使用；原件输入来自实际挑战和当前运行，API调用方不能提供Evidence正文或删减依赖。
export function deviceAuthorizationEvidence({db,service,writer,currentContext,manual,evaluator,executionCurrent,domain,attachCurrent}){
 function read(reference){
  return memoExecutionRead(db,'device-authorization-evidence',reference,()=>readOriginal(reference));
 }
 function readOriginal(reference){
  need(db.inTransaction,'writer');const row=db.prepare(`SELECT e.state_id,e.cut_id,e.request_id,e.request_digest,e.request_jcs,e.body_jcs,e.body_digest,e.commit_id,
   c.body_jcs,c.body_digest,c.audit_jcs,c.notification_jcs,r.body_jcs,r.body_digest FROM device_authorization_evidence e
   JOIN device_authorization_evidence_commit c USING(commit_id) JOIN device_authorization_revocation_cut r ON r.cut_id=e.cut_id WHERE e.evidence_id=?`).raw().get(reference?.id);
  need(row,'missing');const evidence=document(row[5],row[6],'evidence_digest'),commit=checked(document(row[8],row[9])),cut=checked(document(row[12],row[13])),request=JSON.parse(row[4]);
  need(evidence.format_version==='device-authorization-evidence/0.1.0-draft.1'&&commit.format==='device-authorization-evidence-commit/1'&&
   cut.format==='local-manual-device-revocation-cut/1'&&same(namedRef(evidence),reference)&&evidence.state_ref.id===row[0]&&cut.id===row[1]&&commit.id===row[7]&&
   canonicalize(request)===row[4]&&digest(request)===row[3]&&request.request_id===row[2]&&same(commit.request,request)&&
   same(commit.evidence_ref,reference)&&same(commit.state_ref,evidence.state_ref)&&same(evidence.requirement.revocation_cut_ref,ref(cut))&&
   row[10]===canonicalize({kind:'device_authorization_evidence_selected',commit_ref:ref(commit),evidence_ref:reference})&&row[11]===row[10],'integrity');
  const state=readDeviceAuthorizationState(db,evidence.state_ref);
  need(state.value.status==='policy_selected'&&digest(state.value.context)===evidence.context_digest&&
   same(state.recovery.authorization.binding,evidence.requirement.binding)&&same(evidence.requirement.authorization_state_ref,state.ref)&&
   evidence.requirement.requirement_digest===digest((({requirement_digest,...v})=>v)(evidence.requirement))&&
   same(cut.source_refs,{holder:request.manual_source_ref,evaluator:request.evaluator_source_ref})&&same(cut.binding,evidence.requirement.binding)&&
   cut.context_digest===evidence.context_digest,'binding');
  const source=(table,column,reference)=>{const row=db.prepare(`SELECT body_jcs,body_digest FROM ${table} WHERE ${column}=?`).raw().get(reference.id);
   need(row,'source_missing');const value=checked(document(row[0],row[1]));need(same(ref(value),reference),'source_integrity');return {ref:reference,value};};
  const m=source('execution_manual_authority','source_id',request.manual_source_ref),e=source('device_evaluator_source','source_id',request.evaluator_source_ref);
  const windows=[{role:'evaluator',evidence_ref:e.ref,not_before_tick_ns:e.value.selected_tick_ns,before_tick_ns:e.value.expires_tick_ns},
   {role:'holder',evidence_ref:m.ref,not_before_tick_ns:m.value.selected_tick_ns,before_tick_ns:m.value.expires_tick_ns}];
  const expires=String(windows.map(v=>BigInt(v.before_tick_ns)).reduce((a,b)=>a<b?a:b));
  const selected={binding:m.value.binding,state_ref:state.ref,expires_tick_ns:expires};
  need(same(evidence.windows,windows)&&same(cut.identity_dependencies,[e.value.authorization_dependencies,m.value.authorization_dependencies])&&
   same(requirement(selected,m,e,cut,evidence.requirement.requirement_id,commit.selected_tick_ns),evidence.requirement)&&
   windows.every(v=>BigInt(v.not_before_tick_ns)<=BigInt(commit.selected_tick_ns))&&BigInt(commit.selected_tick_ns)<BigInt(expires),'source_binding');
  if(commit.previous_evidence_ref){
   const previous=db.prepare('SELECT e.body_digest,e.state_id,c.body_jcs,c.body_digest FROM device_authorization_evidence e JOIN device_authorization_evidence_commit c USING(commit_id) WHERE e.evidence_id=?').raw().get(commit.previous_evidence_ref.id);
   need(previous&&previous[0]===commit.previous_evidence_ref.digest&&previous[1]===state.ref.id&&commit.previous_evidence_ref.revision==='1','parent');
   const parent=checked(document(previous[2],previous[3]));need(BigInt(parent.generation)+1n===BigInt(commit.generation),'parent');
  }else need(commit.generation==='1','parent');
  return {ref:reference,value:evidence,cut,commit};
 }
 function head(state){const row=db.prepare('SELECT evidence_id,generation,commit_id FROM device_authorization_evidence_head WHERE state_id=?').raw().get(state.ref.id);
  if(!row)return null;const hash=db.prepare('SELECT body_digest FROM device_authorization_evidence WHERE evidence_id=?').pluck().get(row[0]);
  const saved=read({id:row[0],revision:'1',digest:hash});need(saved.commit.id===row[2]&&saved.commit.generation===String(row[1])&&same(saved.value.state_ref,state.ref),'head');return saved;
 }
 function live(saved,selected){
  need(same(saved.value.state_ref,selected.state_ref)&&saved.value.context_digest===selected.context_digest&&same(saved.value.requirement.binding,selected.binding),'changed');
  const now=domain();need(now.ref.clock_domain_id===selected.binding.clock_domain_id&&now.ref.descriptor_digest===selected.binding.descriptor_digest&&
   BigInt(saved.value.requirement.selected_tick_ns)<=BigInt(now.tick)&&BigInt(now.tick)<BigInt(saved.value.requirement.expires_tick_ns),'expired');
 }
 function currentInside(device){
  return withExecutionReadView(db,()=>currentOriginal(device));
 }
 function currentOriginal(device){
  const state=currentDeviceAuthorization(db,device);need(state.value.status==='policy_selected','protected');const saved=head(state);need(saved,'missing');
  const request=saved.commit.request,selected=currentContext({device_id:device,manual_source_ref:request.manual_source_ref,evaluator_source_ref:request.evaluator_source_ref});
  need(!selected.denied,'revoked');live(saved,selected);
  const {id,revision,digest:hash,...stored}=saved.cut;need(same(stored,revocationCut(db,service,selected,executionCurrent(device))),'revocation_changed');return saved;
 }
 attachCurrent?.(currentInside);
 return Object.freeze({
  select(request){need(request&&Object.keys(request).sort().join(',')==='device_id,evaluator_source_ref,expected_evidence_ref,expected_state_ref,manual_source_ref,request_id'&&uuid(request.request_id),'input');
   const fixed=structuredClone(request);return freeze(writer(()=>withExecutionReadView(db,()=>{
    const oldRequest=db.prepare('SELECT evidence_id,body_digest,request_digest FROM device_authorization_evidence WHERE request_id=?').raw().get(fixed.request_id);
    if(oldRequest){need(oldRequest[2]===digest(fixed),'conflict');return read({id:oldRequest[0],revision:'1',digest:oldRequest[1]});}
    const selected=currentContext({device_id:fixed.device_id,manual_source_ref:fixed.manual_source_ref,evaluator_source_ref:fixed.evaluator_source_ref});need(!selected.denied,'revoked');
    const state=currentDeviceAuthorization(db,fixed.device_id);need(state.value.status==='policy_selected'&&same(state.ref,fixed.expected_state_ref)&&same(state.ref,selected.state_ref)&&
     same(state.value.context,selected.context)&&same(state.recovery.authorization.binding,selected.binding),'state');
    const previous=head(state);need(same(previous?.ref??null,fixed.expected_evidence_ref),'selection_conflict');
    if(previous){currentInside(fixed.device_id);live(previous,selected);}else need(BigInt(selected.selected_tick_ns)<BigInt(state.recovery.authorization.expires_tick_ns),'recovery_expired');
    need(db.prepare('SELECT count(*) FROM device_authorization_evidence').pluck().get()<16384,'capacity');
    const m=manual(fixed.manual_source_ref),e=evaluator(fixed.evaluator_source_ref);need(!m.denied&&!e.denied,'revoked');
    const cut=seal({...revocationCut(db,service,selected,executionCurrent(fixed.device_id)),id:crypto.randomUUID(),revision:'1'});
    const r=requirement(selected,m,e,cut,crypto.randomUUID(),selected.selected_tick_ns);
    const evidence=namedSeal({format_version:'device-authorization-evidence/0.1.0-draft.1',evidence_id:crypto.randomUUID(),revision:'1',state_ref:state.ref,
     requirement:r,context_digest:selected.context_digest,windows:selected.windows},'evidence_digest'),reference=namedRef(evidence);
    const generation=Number(previous?.commit.generation??0)+1;need(Number.isSafeInteger(generation),'capacity');
    const commit=seal({format:'device-authorization-evidence-commit/1',id:crypto.randomUUID(),revision:'1',request:fixed,state_ref:state.ref,
     previous_evidence_ref:previous?.ref??null,evidence_ref:reference,generation:String(generation),selected_tick_ns:selected.selected_tick_ns});
    const audit=canonicalize({kind:'device_authorization_evidence_selected',commit_ref:ref(commit),evidence_ref:reference});
    const written=value=>need(value.changes===1,'storage');
    written(db.prepare('INSERT INTO device_authorization_revocation_cut VALUES(?,?,?,?,?)').run(cut.id,state.ref.id,canonicalize(cut),cut.digest,evidence.evidence_id));
    written(db.prepare('INSERT INTO device_authorization_evidence VALUES(?,?,?,?,?,?,?,?,?)').run(evidence.evidence_id,state.ref.id,cut.id,fixed.request_id,digest(fixed),canonicalize(fixed),canonicalize(evidence),evidence.evidence_digest,commit.id));
    written(db.prepare('INSERT INTO device_authorization_evidence_commit VALUES(?,?,?,?,?,?)').run(commit.id,evidence.evidence_id,canonicalize(commit),commit.digest,audit,audit));
    written(previous?db.prepare('UPDATE device_authorization_evidence_head SET evidence_id=?,generation=?,commit_id=? WHERE state_id=? AND evidence_id=?').run(evidence.evidence_id,generation,commit.id,state.ref.id,previous.ref.id):
     db.prepare('INSERT INTO device_authorization_evidence_head VALUES(?,?,?,?)').run(state.ref.id,evidence.evidence_id,generation,commit.id));
    return currentInside(fixed.device_id);
   })));
  },
  current(device){return freeze(writer(()=>currentInside(device)));},
  lookup(reference){return freeze(writer(()=>read(reference)));}
 });
}
