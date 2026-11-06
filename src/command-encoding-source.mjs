import {IdentityError} from './identity-crypto.mjs';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {readCommandRecord,commandPolicyInput} from './command-record-store.mjs';
import {selectAuthenticationWindow,currentAuthenticationWindow} from './authentication-window.mjs';
const need=(value,code)=>{if(!value)throw new IdentityError('command_encoding_'+code);};
const reference=(id,value)=>({id,revision:'1',digest:digest(value)});

// 仅核心装配持有此提供者。命令ID定位同库已受理来源，不能从HTTP提交身份快照或授权正文。
export function commandEncodingSource({db,service,currentRecordedToken,devices,executionCurrent,coreSource}){
 function collect(id,preparedRef=null){
  need(db.inTransaction,'writer');const command=readCommandRecord(db,id),s=command.source,m=s.metadata;
  need((command.record.state.phase==='queued'||preparedRef&&command.lifecycle?.dispatch&&['dispatching','awaiting_evidence'].includes(command.record.state.phase))&&(preparedRef?command.record.attempts.length===1&&command.record.state.resource_status==='held'&&same(command.lifecycle?.final_admission?.ref,preparedRef):command.record.attempts.length===0),'state');
  const proof=currentRecordedToken(s.token_id,service.service_id);
  need(!proof.denied&&proof.principal_kind==='human'&&proof.permissions.includes('device.command'),'permission');
  const actor={issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,principal_id:proof.principal_id};
  need(same(actor,{issuer_id:m.actor.issuer_id,issuer_epoch:m.actor.issuer_epoch,principal_id:m.actor.principal_id})&&
   proof.session_id===m.actor.session_id&&proof.policy_revision===m.actor.authorization_revision&&
   proof.authorization_digest===s.authorization_digest&&proof.scope_digest===s.scope_digest,'identity');
  const control=devices.control(s.binding.device_id);
  need(control.mode==='manual'&&control.gate_state==='ready'&&control.pending_change===null&&same(control.holder,actor)&&
   same(m.control_binding,{epoch:control.control_epoch,version:control.effective_version}),'control');
  const execution=executionCurrent(s.binding.device_id,{requireReady:true,preparedRef});
  need(same(execution.ref,s.binding_ref)&&same(execution.value.binding,s.binding)&&same(execution.ready.ref,s.ready_ref),'binding');
  const row=db.prepare('SELECT k.content_body,k.request_digest FROM ca_request_key k JOIN command_admission_source s USING(key_id) WHERE s.command_id=?').raw().get(id);
  need(row,'request');const content=JSON.parse(row[0].toString());
  need(canonical(content)===row[0].toString()&&digest(content)===row[1]&&row[1]===m.request_identity.request_digest,'request');
  const request={context_id:s.context_id,idempotency_key:m.request_identity.key.idempotency_key,...content};
  commandPolicyInput(request,execution);
  const now=coreSource.domain();need(same(now.ref,s.deadline.accepted.domain)&&BigInt(now.tick)<BigInt(s.deadline.queue_deadline_tick_ns),'deadline');
  const identity={token_id:s.token_id,actor,session_id:proof.session_id,credential_id:proof.credential_id,audience:proof.audience,
   permissions:proof.permissions,authorization_digest:proof.authorization_digest,scope_digest:proof.scope_digest,policy_revision:proof.policy_revision,
   authorization_revision:proof.authorization_revision,expires_ns:proof.expires_ns,session_not_before_ns:proof.session_not_before_ns,
   binding_ref:execution.ref,ready_ref:execution.ready.ref};
  return {command,request,execution,proof,now,identity};
 }
 function windowInput(actual,core,acquisition,selected,cap){return {db,service,coreRuntime:core,domain:actual.now.ref,acquisitionRef:acquisition,
  selectedTick:selected,validFrom:actual.proof.session_not_before_ns,validBefore:actual.proof.expires_ns,capTick:cap};}
 function current(id,snapshot,preparedRef=null){
   const actual=collect(id,preparedRef);need(snapshot.format==='command-encoding-identity/1'&&snapshot.command_id===id&&same(snapshot.identity,actual.identity),'changed');
   const core=coreSource.currentCoreSource(snapshot.core_source_ref),window=snapshot.authentication_window;
   currentAuthenticationWindow(windowInput(actual,core,window.acquisition_ref,window.selected_tick_ns,window.cap_tick_ns),window,actual.now.tick);
   need(BigInt(window.before_tick_ns)<=BigInt(actual.command.source.deadline.queue_deadline_tick_ns)&&
    BigInt(window.before_tick_ns)<=BigInt(actual.execution.ready.value.expires_tick_ns),'deadline');
   return {...actual,snapshot,snapshot_ref:reference(id+'.encoding-identity',snapshot),expires_tick_ns:window.before_tick_ns};
  }
 return Object.freeze({
  select(id){
   const actual=collect(id),core=coreSource.selectCoreSource();
   const cap=String([BigInt(actual.command.source.deadline.queue_deadline_tick_ns),BigInt(actual.execution.ready.value.expires_tick_ns),BigInt(core.value.expires_tick_ns)].reduce((a,b)=>a<b?a:b));
   const window=selectAuthenticationWindow(windowInput(actual,core,actual.proof.acquisition_ref,actual.now.tick,cap));
   const snapshot={format:'command-encoding-identity/1',command_id:id,identity:actual.identity,core_source_ref:core.ref,authentication_window:window};
   return {...actual,snapshot,snapshot_ref:reference(id+'.encoding-identity',snapshot),expires_tick_ns:window.before_tick_ns};
  },
  current(id,snapshot){return current(id,snapshot);},
  currentPrepared(id,snapshot,preparedRef){need(preparedRef,'prepared_source');return current(id,snapshot,preparedRef);},
 });
}
