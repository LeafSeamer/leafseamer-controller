import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {checked,seal,ref,same,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-crypto.mjs';
import {currentControlSource} from './device-control-source.mjs';
import {currentDeviceAuthorization,protectControlAuthorization} from './device-authorization-state.mjs';
import {selectAuthenticationWindow,currentAuthenticationWindow} from './authentication-window.mjs';
import {collectAuthorizationDependencies,currentAuthorizationDependencies} from './authorization-dependencies.mjs';
import {selectedDeviceEvidenceDeadline} from './device-authorization-evidence.mjs';
import {currentControlReference} from './device-initial-ready.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('manual_authority_'+code);};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const maximum=99999999999999999999n;
// 当前人员来源只在本机身份writer内采集；不把该短期原件当成设备授权State或OPEN许可。
export function manualExecutionAuthority({db,service,writer,authorizeToken,currentRecordedToken,authority,executionCurrent,domain,coreSource,attachCurrent}){
 function sources(device,proof){
  need(!proof.denied&&proof.principal_kind==='human'&&proof.permissions.includes('device.command'),'permission');
  const control=currentControlSource(db,device),value=control.current.value,holder={issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,principal_id:proof.principal_id};
  need(value.mode==='manual'&&value.pending_operation_id===null&&same(value.holder,{kind:'human',...holder}),'holder');
  const policy=authority.current(proof.principal_id);need(policy.state==='active'&&policy.permissions.includes('device.command')&&
   policy.issuer_id===holder.issuer_id&&policy.issuer_epoch===holder.issuer_epoch,'policy');
  let execution;try{execution=executionCurrent(device);}catch(error){if(error?.code?.startsWith('SQLITE_'))throw error;
   const rejected=new IdentityError('manual_authority_execution');rejected.cause=error;throw rejected;}
  const binding=execution.value.binding,now=domain();
  need(same(binding.scope,{authority_service_id:service.service_id,database_instance_id:service.database_instance_id})&&
   binding.clock_domain_id===now.ref.clock_domain_id&&binding.descriptor_digest===now.ref.descriptor_digest&&
   value.clock_domain_id===binding.clock_domain_id&&value.descriptor_digest===binding.descriptor_digest,'domain');
  need(/^(0|[1-9][0-9]{0,19})$/.test(now.tick),'clock');
  return {control,policy,execution,binding,now,holder};
 }
 function original(reference){
  need(reference&&typeof reference.id==='string'&&reference.revision==='1','reference');
  const row=db.prepare(`SELECT s.body_jcs,s.body_digest,c.body_digest,c.audit_jcs,c.notification_jcs,
   s.device_id,s.binding_id,s.control_source_id,s.token_id,s.policy_id,s.acquisition_id,s.selected_tick,s.expires_tick FROM execution_manual_authority s
   JOIN execution_manual_authority_commit c USING(source_id) WHERE source_id=?`).raw().get(reference.id);
  need(row,'missing');const value=checked(JSON.parse(row[0]));
  need(canonicalize(value)===row[0]&&value.digest===row[1]&&row[1]===row[2]&&same(ref(value),reference)&&
   row[3]===canonicalize({kind:'manual_execution_source',source_ref:reference})&&row[4]===row[3]&&
   value.binding.device_id===row[5]&&value.binding_ref.id===row[6]&&value.control_state_ref.id===row[7]&&value.token_id===row[8]&&
   value.policy_ref.id===row[9]&&value.authentication_acquisition_ref.id===row[10]&&
   value.selected_tick_ns.padStart(20,'0')===row[11]&&value.expires_tick_ns.padStart(20,'0')===row[12],'integrity');return value;
 }
 function challenge(reference){
  need(reference&&reference.revision==='1','challenge_reference');
  const row=db.prepare(`SELECT c.body_jcs,c.body_digest,c.token_id,c.device_id,c.binding_id,c.control_source_id,c.core_source_id,k.audit_jcs,c.request_id
   FROM manual_execution_challenge c JOIN manual_execution_challenge_commit k USING(challenge_id) WHERE c.challenge_id=?`).raw().get(reference.id);
  need(row,'challenge_missing');const v=checked(JSON.parse(row[0]));
  need(v.format==='manual-execution-challenge/1'&&canonicalize(v)===row[0]&&v.digest===row[1]&&same(ref(v),reference)&&v.token_id===row[2]&&v.binding.device_id===row[3]&&
   v.binding_ref.id===row[4]&&v.control_state_ref.id===row[5]&&v.core_runtime_source_ref.id===row[6]&&
   row[7]===canonicalize({kind:'manual_execution_challenge',challenge_ref:reference})&&v.request_id===row[8]&&
   typeof v.nonce==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v.nonce)&&Buffer.from(v.nonce,'base64url').toString('base64url')===v.nonce,
   'challenge_integrity');return v;
 }
 function checkChallenge(v,actual,proof){
  need(same(v.binding,actual.binding)&&same(v.binding_ref,actual.execution.ref)&&currentControlReference(db,actual.control.current,v.control_state_ref)&&
   same(v.control_authority_ref,actual.control.authority.ref)&&same(v.holder,actual.holder)&&same(v.policy_ref,ref(actual.policy))&&
   v.session_id===proof.session_id&&v.credential_id===proof.credential_id&&v.authorization_digest===proof.authorization_digest,'challenge_binding');
  need(BigInt(v.issued_tick_ns)<=BigInt(actual.now.tick)&&BigInt(actual.now.tick)<BigInt(v.expires_tick_ns),'challenge_expired');
  const runtime=coreSource.currentCoreSource(v.core_runtime_source_ref);need(same(runtime.value.domain_ref,actual.now.ref),'challenge_domain');return runtime;
 }
 function currentInside(reference){
  const value=original(reference),proof=currentRecordedToken(value.token_id,service.service_id);if(proof.denied)return proof;
  const actual=sources(value.binding.device_id,proof),tick=BigInt(actual.now.tick);
  if(Number(service.schema_revision)>=34&&Number(service.schema_revision)<41)need(same(currentDeviceAuthorization(db,value.binding.device_id).ref,value.authorization_state_ref),'state');
  need(same(actual.execution.ref,value.binding_ref)&&same(actual.control.authority.ref,value.control_authority_ref)&&
   currentControlReference(db,actual.control.current,value.control_state_ref)&&same(ref(actual.policy),value.policy_ref)&&same(actual.binding,value.binding)&&
   proof.authorization_digest===value.authorization.digest&&proof.session_id===value.session_id&&proof.credential_id===value.credential_id,'changed');
  need(BigInt(value.selected_tick_ns)<=tick&&tick<BigInt(value.expires_tick_ns),'expired');
  const runtime=Number(service.schema_revision)>=35?coreSource.currentCoreSource(value.core_runtime_source_ref):null;
  let ch=null;
  if(Number(service.schema_revision)>=42){
   need(value.challenge_ref,'challenge_required');ch=challenge(value.challenge_ref);checkChallenge(ch,actual,proof);
   const response=db.prepare('SELECT challenge_id,request_id,request_digest FROM manual_execution_challenge_response WHERE source_id=?').raw().get(value.id);
   need(response&&response[0]===ch.id&&response[1]===value.challenge_response_id&&response[2]===value.challenge_response_digest&&
    value.challenge_response_digest===digest({request_id:response[1],challenge_ref:ref(ch),nonce:ch.nonce})&&
    value.token_id===ch.token_id&&same(value.core_runtime_source_ref,ch.core_runtime_source_ref),'challenge_response');
  }
  if(Number(service.schema_revision)>=38){
   need(value.authentication_window&&value.expires_tick_ns===value.authentication_window.before_tick_ns,'window');
   const cap=[BigInt(value.selected_tick_ns)+2000000000n,BigInt(runtime.value.expires_tick_ns),...(ch?[BigInt(ch.expires_tick_ns)]:[])].reduce((a,b)=>a<b?a:b);
   currentAuthenticationWindow({db,service,coreRuntime:runtime,domain:actual.now.ref,acquisitionRef:value.authentication_acquisition_ref,selectedTick:value.selected_tick_ns,
    validFrom:[proof.session_not_before_ns,value.authorization.not_before_ns].reduce((a,b)=>BigInt(a)>BigInt(b)?a:b),validBefore:proof.expires_ns,capTick:String(cap)},value.authentication_window,actual.now.tick);
  }if(Number(service.schema_revision)>=39)currentAuthorizationDependencies(db,service,'manual',value);return value;
 }
 attachCurrent?.(reference=>{need(db.inTransaction,'writer');const value=currentInside(reference);return value.denied?value:{ref:reference,value};});
 const api={
  begin(input,device,requestId){need(Number(service.schema_revision)>=42&&typeof requestId==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestId),'challenge_input');
   const result=writer(()=>{
    const proof=authorizeToken(input,service.service_id);if(proof.denied)return proof;const actual=sources(device,proof);
    const prior=db.prepare('SELECT challenge_id,body_digest FROM manual_execution_challenge WHERE token_id=? AND request_id=?').raw().get(input.token_id,requestId);
    if(prior){const v=challenge({id:prior[0],revision:'1',digest:prior[1]});need(v.binding.device_id===device,'challenge_conflict');checkChallenge(v,actual,proof);return v;}
    need(db.prepare('SELECT count(*) FROM manual_execution_challenge').pluck().get()<4096,'challenge_capacity');
    const runtime=coreSource.selectCoreSource(),expires=[BigInt(actual.now.tick)+2000000000n,BigInt(runtime.value.expires_tick_ns)].reduce((a,b)=>a<b?a:b);
    need(BigInt(actual.now.tick)<expires&&expires<=maximum,'clock');
    const v=seal({format:'manual-execution-challenge/1',id:crypto.randomUUID(),revision:'1',request_id:requestId,nonce:crypto.randomBytes(32).toString('base64url'),
     binding:actual.binding,binding_ref:actual.execution.ref,control_state_ref:actual.control.current.ref,control_authority_ref:actual.control.authority.ref,
     holder:actual.holder,token_id:input.token_id,session_id:proof.session_id,credential_id:proof.credential_id,authorization_digest:proof.authorization_digest,
     policy_ref:ref(actual.policy),core_runtime_source_ref:runtime.ref,issued_tick_ns:actual.now.tick,expires_tick_ns:String(expires)});
    need(db.prepare('INSERT INTO manual_execution_challenge VALUES(?,?,?,?,?,?,?,?,?,?)').run(v.id,input.token_id,requestId,device,v.binding_ref.id,v.control_state_ref.id,runtime.ref.id,canonicalize(v),v.digest,v.id).changes===1,'challenge_storage');
    need(db.prepare('INSERT INTO manual_execution_challenge_commit VALUES(?,?)').run(v.id,canonicalize({kind:'manual_execution_challenge',challenge_ref:ref(v)})).changes===1,'challenge_storage');
    challenge(ref(v));const last=authorizeToken(input,service.service_id);need(!last.denied,'permission');checkChallenge(v,sources(device,last),last);return v;
   });if(result.denied)throw new IdentityError(result.denied);return freeze(result);
  },
  complete(input,request){
   need(Number(service.schema_revision)>=42&&request&&Object.keys(request).sort().join(',')==='challenge_ref,nonce,request_id'&&typeof request.request_id==='string'&&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.request_id),'challenge_input');
   return api.select(input,null,request);
  },
  select(input,device,response=null){need(Number(service.schema_revision)<42||response,'challenge_required');const result=writer(()=>{
   const ch=response?challenge(response.challenge_ref):null;if(ch){need(response.nonce===ch.nonce&&input.token_id===ch.token_id,'challenge_response');device=ch.binding.device_id;}
   const proof=authorizeToken(input,service.service_id);if(proof.denied)return proof;const actual=sources(device,proof),selected=BigInt(actual.now.tick);
   let authorizationState=null;
   const coreRuntime=ch?checkChallenge(ch,actual,proof):Number(service.schema_revision)>=35?coreSource.selectCoreSource():null;
   if(ch){const old=db.prepare('SELECT source_id,request_digest FROM manual_execution_challenge_response WHERE challenge_id=?').raw().get(ch.id);
    if(old){need(old[1]===digest(response),'challenge_conflict');const saved=db.prepare('SELECT body_digest FROM execution_manual_authority WHERE source_id=?').pluck().get(old[0]);
     need(saved,'challenge_integrity');const reference={id:old[0],revision:'1',digest:saved},value=currentInside(reference);return value.denied?value:{ref:reference,value};}}
   const expires=[selected+2000000000n,...(coreRuntime?[BigInt(coreRuntime.value.expires_tick_ns)]:[]),...(ch?[BigInt(ch.expires_tick_ns)]:[])].reduce((a,b)=>a<b?a:b);
   need(selected+2000000000n<=maximum,'clock');
   need(db.prepare('SELECT count(*) FROM execution_manual_authority').pluck().get()<4096,'capacity');
   const row=db.prepare('SELECT authorization_body,authorization_digest FROM access_token WHERE token_id=?').raw().get(input.token_id);
   need(row,'token');const authorization=checked(JSON.parse(row[0].toString()));
   need(canonicalize(authorization)===row[0].toString()&&authorization.digest===row[1]&&row[1]===proof.authorization_digest,'integrity');
   if(Number(service.schema_revision)>=34){
    const old=Number(service.schema_revision)>=41?currentDeviceAuthorization(db,device,{optional:true}):null;
    if(old?.value.status==='policy_selected'&&same(old.value.context.control_authority_ref,actual.control.authority.ref)){
     const h=old.value.context.holder_lineage,a=old.recovery.authorization;
     // 已采用Evidence取实际当前选择的截止；没有Evidence时仍受首次恢复窗口约束。
     const before=Number(service.schema_revision)>=43?selectedDeviceEvidenceDeadline(db,old)??a.expires_tick_ns:a.expires_tick_ns;
     const reason=!same(a.binding,actual.binding)?'runtime_changed':BigInt(actual.now.tick)>=BigInt(before)?'evidence_expired':
      !h||h.session_id!==proof.session_id||h.credential_id!==proof.credential_id||h.subject_revision!==String(authorization.subject_revision)||
      h.policy_revision!==authorization.policy_revision||h.scope_digest!==authorization.scope_digest?'credential_changed':null;
     authorizationState=reason?protectControlAuthorization(db,actual.control.authority.value,actual.now,reason):old;
    }else authorizationState=protectControlAuthorization(db,actual.control.authority.value,actual.now);
   }
   const window=Number(service.schema_revision)>=38?selectAuthenticationWindow({db,service,coreRuntime,domain:actual.now.ref,acquisitionRef:proof.acquisition_ref,
    selectedTick:String(selected),validFrom:[proof.session_not_before_ns,authorization.not_before_ns].reduce((a,b)=>BigInt(a)>BigInt(b)?a:b),validBefore:proof.expires_ns,capTick:String(expires)}):null;
   const base={format:'manual-execution-authority-source/1',id:crypto.randomUUID(),revision:'1',binding:actual.binding,binding_ref:actual.execution.ref,
    control_state_ref:actual.control.current.ref,control_authority_ref:actual.control.authority.ref,holder:actual.holder,policy_ref:ref(actual.policy),
    token_id:input.token_id,session_id:proof.session_id,credential_id:proof.credential_id,authorization,authentication_acquisition_ref:proof.acquisition_ref,
    selected_tick_ns:String(selected),expires_tick_ns:window?.before_tick_ns??String(expires),...(window?{authentication_window:window}:{}),...(authorizationState?{authorization_state_ref:authorizationState.ref}:{}),
    ...(coreRuntime?{core_runtime_source_ref:coreRuntime.ref}:{}),...(ch?{challenge_ref:ref(ch),challenge_response_id:response.request_id,challenge_response_digest:digest(response)}:{})};
   const value=seal({...base,...(Number(service.schema_revision)>=39?{authorization_dependencies:collectAuthorizationDependencies(db,service,'manual',base)}:{})}),reference=ref(value),audit=canonicalize({kind:'manual_execution_source',source_ref:reference});
   if(ch)need(db.prepare('INSERT INTO manual_execution_challenge_response VALUES(?,?,?,?)').run(ch.id,value.id,response.request_id,digest(response)).changes===1,'challenge_storage');
   need(db.prepare('INSERT INTO execution_manual_authority VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(value.id,device,value.binding_ref.id,value.control_state_ref.id,value.token_id,
    value.policy_ref.id,value.authentication_acquisition_ref.id,value.selected_tick_ns.padStart(20,'0'),value.expires_tick_ns.padStart(20,'0'),canonicalize(value),value.digest,value.id).changes===1,'storage');
   need(db.prepare('INSERT INTO execution_manual_authority_commit VALUES(?,?,?,?,?)').run(value.id,value.digest,audit,crypto.randomUUID(),audit).changes===1,'storage');
   const last=currentInside(reference);return last.denied?last:{ref:reference,value};
  });if(result.denied)throw new IdentityError(result.denied);return freeze(result);},
  current(reference){const result=writer(()=>{const value=currentInside(reference);return value.denied?value:{ref:structuredClone(reference),value};});
   if(result.denied)throw new IdentityError(result.denied);return freeze(result);}
 };return Object.freeze(api);
}
