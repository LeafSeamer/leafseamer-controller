import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
import {checked,seal,ref,same,digest} from './auth-clock-value.mjs';
import {controlSeal,controlFrozen} from './device-control-value.mjs';
import {memoExecutionRead} from './execution-read-view.mjs';
import {currentDeviceAuthorization,readDeviceAuthorizationState,selectDeviceRecoveryAuthorization} from './device-authorization-state.mjs';
const need=(v,c)=>{if(!v)throw new IdentityError('device_recovery_'+c);};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const who=v=>({issuer_id:v.issuer_id,issuer_epoch:v.issuer_epoch,principal_id:v.principal_id});
const authorizationRef=v=>({id:v.authorization_id,revision:v.revision,digest:v.authorization_digest});
const written=v=>need(v.changes===1,'storage');
const deliver=v=>{if(v.denied)throw new IdentityError(v.denied);return controlFrozen(v);};
function authorizationFor(receipt,id){
 const selected=receipt.selection,references=[...Object.values(selected.source_refs),selected.context.control_authority_ref,selected.context.evaluator_policy_ref];
 const refs=[...new Map(references.map(v=>[canonicalize(v),v])).values()].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:BigInt(a.revision)<BigInt(b.revision)?-1:BigInt(a.revision)>BigInt(b.revision)?1:a.digest<b.digest?-1:a.digest>b.digest?1:0);
 need(refs.length>0&&refs.length<=16,'evidence');
 return controlSeal({format_version:'device-recovery-authorization/0.1.0-draft.1',authorization_id:id,revision:'1',operation_id:receipt.id,
  request_receipt_ref:ref(receipt),binding:selected.binding,protected_state_ref:selected.state_ref,control_authority_ref:selected.context.control_authority_ref,
  requester:receipt.requester,requester_kind:'human',purpose:'revalidate_device_authorization',proposed_context_digest:selected.context_digest,evidence_refs:refs,
  issued_tick_ns:selected.selected_tick_ns,expires_tick_ns:selected.expires_tick_ns},'authorization_digest');
}

export function readDeviceRecoveryRequest(db,id){
 return memoExecutionRead(db,'device-recovery-request',id,()=>readOriginal(db,id));
}
function readOriginal(db,id){
  const row=db.prepare(`SELECT r.body_jcs,r.body_digest,r.key_digest,r.request_digest,r.device_id,r.principal_id,r.token_id,r.state_id,
   a.authorization_id,a.body_jcs,a.body_digest,a.manual_source_id,a.evaluator_source_id,c.body_jcs,c.body_digest
   FROM device_recovery_request r JOIN device_recovery_authorization a ON a.authorization_id=r.authorization_id AND a.request_id=r.request_id
   JOIN device_recovery_commit c ON c.request_id=r.request_id WHERE r.request_id=?`).raw().get(id);
  need(row,'missing');const receipt=checked(JSON.parse(row[0])),authorization=JSON.parse(row[9]),commit=checked(JSON.parse(row[13]));
  need(canonicalize(receipt)===row[0]&&receipt.digest===row[1]&&receipt.id===id&&digest(receipt.request_identity.key)===row[2]&&
   receipt.request_identity.request_digest===row[3]&&digest(receipt.request)===row[3]&&receipt.request.device_id===row[4]&&
   receipt.requester.principal_id===row[5]&&receipt.token_id===row[6]&&receipt.request.expected_state_ref.id===row[7],'integrity');
  need(receipt.format==='device-authorization-recovery-receipt/1'&&receipt.revision==='1'&&
   same(receipt.request.expected_state_ref,receipt.selection.state_ref)&&digest(receipt.selection.context)===receipt.selection.context_digest&&
   same(receipt.request.manual_source_ref,receipt.selection.source_refs.holder)&&same(receipt.request.evaluator_source_ref,receipt.selection.source_refs.evaluator)&&
   same(authorizationFor(receipt,row[8]),authorization),'integrity');
  need(canonicalize(authorization)===row[9]&&same(controlSeal(authorization,'authorization_digest'),authorization)&&authorization.authorization_digest===row[10]&&
   authorization.authorization_id===row[8]&&same(authorization.request_receipt_ref,ref(receipt))&&authorization.operation_id===receipt.id&&
   authorization.requester_kind==='human'&&same(authorization.requester,receipt.requester)&&authorization.purpose==='revalidate_device_authorization'&&
   same(authorization.protected_state_ref,receipt.request.expected_state_ref)&&authorization.proposed_context_digest===receipt.request.expected_context_digest&&
   receipt.request.manual_source_ref.id===row[11]&&receipt.request.evaluator_source_ref.id===row[12]&&
   same(authorization.binding,receipt.selection.binding)&&same(authorization.control_authority_ref,receipt.selection.context.control_authority_ref),'integrity');
  need(canonicalize(commit)===row[13]&&commit.digest===row[14]&&commit.id===id&&same(commit.receipt_ref,ref(receipt))&&
   same(commit.authorization_ref,authorizationRef(authorization))&&commit.kind==='device_authorization_recovery_accepted','integrity');
  return {receipt,authorization};
 }

// 核心内部的明确人员请求；调用者提供来源引用，不提供授权正文、谱系或有效窗口。
export function deviceAuthorizationRecovery({db,service,writer,time,authorizeToken,currentContext}){
 function authorize(input){
  const p=authorizeToken(input,service.service_id);if(p.denied)return p;
  need(p.principal_kind==='human'&&p.permissions.includes('device.recover')&&p.permissions.includes('device.command'),'permission');
  const recent=db.prepare('SELECT recent_before_ns FROM auth_session WHERE session_id=?').pluck().get(p.session_id);
  need(recent&&time().upper<BigInt(recent),'recent_required');return p;
 }
 const original=id=>readDeviceRecoveryRequest(db,id);
 function sources(request,proof,tokenId){
  const selected=currentContext({device_id:request.device_id,manual_source_ref:request.manual_source_ref,evaluator_source_ref:request.evaluator_source_ref});
  if(selected.denied)return selected;
  const state=currentDeviceAuthorization(db,request.device_id);
  need(state.value.status==='protected'&&same(state.ref,request.expected_state_ref)&&same(selected.state_ref,state.ref),'state');
  need(selected.context_digest===request.expected_context_digest&&same(selected.context.holder,who(proof))&&
   selected.context.holder_lineage.session_id===proof.session_id&&selected.context.holder_lineage.credential_id===proof.credential_id,'context');
  const sourceToken=db.prepare('SELECT token_id FROM execution_manual_authority WHERE source_id=?').pluck().get(request.manual_source_ref.id);
  need(sourceToken===tokenId,'requester_binding');return selected;
 }
 function currentInside(input,id){
  const p=authorize(input);if(p.denied)return p;const saved=original(id);need(same(saved.receipt.requester,who(p)),'requester');
  if(Number(service.schema_revision)>=41)need(!db.prepare('SELECT 1 FROM device_recovery_consumption WHERE authorization_id=?').pluck().get(saved.authorization.authorization_id),'consumed');
  const selected=sources(saved.receipt.request,p,input.token_id);if(selected.denied)return selected;
  const a=saved.authorization;need(same(selected.context,saved.receipt.selection.context)&&same(selected.binding,a.binding)&&
   BigInt(a.issued_tick_ns)<=BigInt(selected.selected_tick_ns)&&BigInt(selected.selected_tick_ns)<BigInt(a.expires_tick_ns),'expired');
  return saved;
 }
 return Object.freeze({
  accept(input,request){
   need(request&&Object.keys(request).sort().join(',')==='device_id,evaluator_source_ref,expected_context_digest,expected_state_ref,manual_source_ref,request_id'&&
    uuid(request.request_id)&&uuid(request.device_id)&&request.expected_state_ref&&request.manual_source_ref&&request.evaluator_source_ref&&
    typeof request.expected_context_digest==='string'&&/^sha256:[0-9a-f]{64}$/.test(request.expected_context_digest),'input');
   return deliver(writer(()=>{
    const p=authorize(input);if(p.denied)return p;const {request_id,...content}=request;
    const key={target_scope:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id},...who(p),request_epoch:service.request_epoch,
     operation_id:'revalidateDeviceAuthorization',idempotency_key:request_id},keyDigest=digest(key),requestDigest=digest(content);
    const prior=db.prepare('SELECT request_id,request_digest FROM device_recovery_request WHERE key_digest=?').raw().get(keyDigest);
    if(prior){need(prior[1]===requestDigest,'conflict');return original(prior[0]);}
    need(db.prepare('SELECT count(*) FROM device_recovery_request').pluck().get()<4096,'capacity');
    const selected=sources(content,p,input.token_id);if(selected.denied)return selected;
    const id=crypto.randomUUID(),aid=crypto.randomUUID(),receipt=seal({format:'device-authorization-recovery-receipt/1',id,revision:'1',
     request_identity:{key,request_digest:requestDigest},request:content,requester:who(p),token_id:input.token_id,selection:selected});
    const authorization=authorizationFor(receipt,aid);
    const commit=seal({format:'device-authorization-recovery-commit/1',id,revision:'1',kind:'device_authorization_recovery_accepted',receipt_ref:ref(receipt),authorization_ref:authorizationRef(authorization)});
    need(Buffer.byteLength(canonicalize(receipt))<=65536,'capacity');
    written(db.prepare('INSERT INTO device_recovery_request VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id,keyDigest,requestDigest,content.device_id,p.principal_id,input.token_id,selected.state_ref.id,canonicalize(receipt),receipt.digest,aid,id));
    written(db.prepare('INSERT INTO device_recovery_authorization VALUES(?,?,?,?,?,?,?,?)').run(aid,id,content.device_id,selected.state_ref.id,content.manual_source_ref.id,content.evaluator_source_ref.id,canonicalize(authorization),authorization.authorization_digest));
    written(db.prepare('INSERT INTO device_recovery_commit VALUES(?,?,?)').run(id,canonicalize(commit),commit.digest));
    const result=currentInside(input,id);need(!result.denied&&same(result,{receipt,authorization}),'readback');return result;
   }));
  },
  current(input,id){need(uuid(id),'input');return deliver(writer(()=>currentInside(input,id)));},
  consume(input,id){need(uuid(id)&&Number(service.schema_revision)>=41,'consumption_unavailable');return deliver(writer(()=>{
   const p=authorize(input);if(p.denied)return p;const saved=original(id);need(same(saved.receipt.requester,who(p)),'requester');
   const used=db.prepare('SELECT body_jcs FROM device_recovery_consumption WHERE authorization_id=?').pluck().get(saved.authorization.authorization_id);
   if(used)return readDeviceAuthorizationState(db,checked(JSON.parse(used)).state_ref);
   const available=currentInside(input,id);if(available.denied)return available;
   const request=saved.receipt.request,selected=currentContext({device_id:request.device_id,manual_source_ref:request.manual_source_ref,evaluator_source_ref:request.evaluator_source_ref});
   if(selected.denied)return selected;
   const adopted=selectDeviceRecoveryAuthorization(db,saved,selected),last=authorize(input);need(!last.denied,'permission');
   const final=currentContext({device_id:request.device_id,manual_source_ref:request.manual_source_ref,evaluator_source_ref:request.evaluator_source_ref});
   need(!final.denied&&same(final.state_ref,adopted.ref)&&same(final.context,selected.context)&&same(final.binding,selected.binding)&&
    BigInt(final.selected_tick_ns)<BigInt(saved.authorization.expires_tick_ns),'consumption_readback');return adopted;
  }));},
  lookup(input,id){need(uuid(id),'input');return deliver(writer(()=>{const p=authorize(input);if(p.denied)return p;const saved=original(id);need(same(saved.receipt.requester,who(p)),'requester');return saved;}));}
 });
}
