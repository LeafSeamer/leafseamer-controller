import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {decodeExecutionPayload,DeviceExecutionError} from './device-execution-channel.mjs';
import {authorizationRevoked} from './device-authorization-fence.mjs';
const need=(ok,code)=>{if(!ok)throw new DeviceExecutionError(code);};
const digest=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const freeze=value=>{if(value&&typeof value==='object'){for(const v of Object.values(value))freeze(v);Object.freeze(value);}return value;};
const maximum=99999999999999999999n;

// 固定worker内每设备唯一所有者。会话接收器负责全设备共用的seq及原帧日志；
// 本对象只处理设备闸，不签发Controller的持久授权、Ready或资源释放证明。
// 当前支持普通首次传输的控制屏障与ordinary开放；取消、重传和拒绝快照须另行接入。
export function deviceExecutionGate({binding,transmissions,tick,signal,failed,limits}){
 need(typeof tick==='function'&&signal instanceof AbortSignal&&typeof failed==='function','gate_configuration');
 need(transmissions===undefined||typeof transmissions==='function','gate_configuration');
 need(limits&&Number.isSafeInteger(limits.max_entries)&&limits.max_entries>0&&limits.max_entries<=4096&&
  Number.isSafeInteger(limits.max_metadata_bytes)&&limits.max_metadata_bytes>0&&limits.max_metadata_bytes<=67108864,'gate_capacity_profile');
 const bound=freeze(structuredClone(binding)),budget={...limits},history=new Map(),tokens=new Set(),fenceTokens=new Set(),cuts=new Map(),fencedPermits=new Set(),stored=new Map();
 const denials=new Map(),authorizationPermits=new Map(),runDenials=new Map();let authorizationRevision=0n,runSnapshot=null,commandSnapshot=null;
 let terminal=false,active=null,barrier=null,control=null,revision=0n,order=0n,lastTick=null,metadata=0,closedOnce=false,openedOnce=false,issuedCut=0n,latestCut=null;
 function withdraw(){active=null;barrier=null;}
 function stop(error=new DeviceExecutionError('gate_closed')){if(terminal)return;terminal=true;withdraw();try{failed(error);}catch{}}
 signal.addEventListener('abort',()=>stop(),{once:true});
 function current(){need(!terminal&&!signal.aborted,'gate_closed');}
 function now(){let t;try{t=tick();}catch{need(false,'gate_clock');}
  need(typeof t==='bigint'&&t>=0n&&t<=maximum&&(lastTick===null||t>=lastTick),'gate_clock');lastTick=t;return t;}
 function next(){need(order<maximum,'gate_order_exhausted');return ++order;}
 function remember(key,body,ack){const size=Buffer.byteLength(canonicalize(body))+Buffer.byteLength(canonicalize(ack));
  need(history.size<budget.max_entries&&metadata+size<=budget.max_metadata_bytes,'gate_history_capacity');
  const record=freeze({body:structuredClone(body),ack});history.set(key,record);metadata+=size;return record.ack;}
 function previous(key,body,frame){const item=history.get(key);if(!item)return null;
  need(same(item.body,body),'gate_identity_conflict');return freeze({...item.ack,reply_to:frame.message_id});}
 function candidate(frame,type,body){return freeze({type,reply_to:frame.message_id,device_id:type==='CLOSE_GATE_ACK'?null:bound.device_id,body});}
 function self(value,field,code){const {[field]:hash,...body}=value;need(digest(body)===hash,code);}
 const runKey=selector=>canonicalize([selector.origin_scope.authority_service_id,selector.origin_scope.database_instance_id,selector.run_id]);
 function runMatches(intent,selector){const origin=intent.automation_binding;
  return intent.origin==='automation'&&origin&&same(origin.origin_scope,selector.origin_scope)&&origin.run_id===selector.run_id&&BigInt(origin.arm_generation)<=BigInt(selector.deny_through_generation);}
 function runProgress(entry,old){if(!old)return;
  need(BigInt(entry.deny_revision)>=BigInt(old.deny_revision)&&BigInt(entry.selector.deny_through_generation)>=BigInt(old.selector.deny_through_generation),'gate_run_deny_floor');
  if(entry.deny_revision===old.deny_revision)need(same(entry,old),'gate_deny_snapshot_conflict');
 }
 function denySnapshot(snapshot,prior,kind){
  const key=kind==='run'?entry=>canonicalize([entry.selector.origin_scope.authority_service_id,entry.selector.origin_scope.database_instance_id,entry.selector.run_id]):entry=>entry.parent_command_id;
  const entries=new Map();let last=null;
  for(const entry of snapshot.entries){
   const id=key(entry);need(last===null||last<id,'gate_deny_snapshot_order');last=id;
   need(BigInt(entry.deny_revision)>0n&&BigInt(entry.deny_revision)<=BigInt(snapshot.snapshot_revision),'gate_deny_snapshot_revision');entries.set(id,entry);
  }
  if(prior){
   need(BigInt(snapshot.snapshot_revision)>=BigInt(prior.snapshot_revision),'gate_deny_snapshot_revision');
   if(snapshot.snapshot_revision===prior.snapshot_revision)need(same(snapshot,prior),'gate_deny_snapshot_conflict');
   for(const old of prior.entries){const entry=entries.get(key(old));need(entry,'gate_deny_snapshot_omitted');
    need(BigInt(entry.deny_revision)>=BigInt(old.deny_revision),'gate_deny_snapshot_revision');
    if(entry.deny_revision===old.deny_revision)need(same(entry,old),'gate_deny_snapshot_conflict');
    if(kind==='run')need(BigInt(entry.selector.deny_through_generation)>=BigInt(old.selector.deny_through_generation),'gate_run_deny_floor');
    else need(entry.cancellation_id===old.cancellation_id&&(old.stage!=='all'||entry.stage==='all'),'gate_command_deny_binding');
   }
  }
  return freeze(structuredClone(snapshot));
 }
 function live(){current();const t=now();if(active&&(t>=BigInt(active.lease_until_tick_ns)||t>=BigInt(active.access.expires_tick_ns)))withdraw();return active;}
 function unavailable(frame,reason){return candidate(frame,'BARRIER_UNAVAILABLE',{...frame.body,reason});}
 function barrierRecord(frame){const b=frame.body,item=history.get('fence:'+b.barrier_id);
  need(b.attempt_binding.target_exit_id===bound.writer_exit_id,'gate_fence_attempt');
  if(item)need(item.body.operation_id===b.operation_id&&same(item.body.attempt_binding,b.attempt_binding),'gate_identity_conflict');return item;}
 function queryBarrier(frame){const item=barrierRecord(frame);return item?.ack?freeze({...item.ack,reply_to:frame.message_id}):unavailable(frame,item?'cache_miss':'unknown_barrier');}
 function storeBarrier(frame){const b=frame.body,item=barrierRecord(frame),old=stored.get(b.barrier_id);
  need(item,'gate_barrier_unknown');if(old){need(same(old,b),'gate_identity_conflict');return null;}
  need(item.ack&&digest(item.ack.body)===b.ack_digest,'gate_ack_digest');
  remember('stored:'+b.barrier_id,b,null);stored.set(b.barrier_id,freeze(structuredClone(b)));
  history.set('fence:'+b.barrier_id,freeze({body:item.body,ack:null}));return null;
 }
 function coverage(b,selector=null){
  need(b.cancel_transmissions.length===0,'gate_control_fence_unsupported');
  const ordered=(items,id)=>items.every((v,i)=>i===0||id(items[i-1])<id(v));
  need(ordered(b.open_intents,v=>v.permit_id)&&ordered(b.open_transmission_intents,v=>v.intent.permit_id),'gate_ledger_order');
  need(b.ledger_digest===digest(b.open_intents)&&b.transmission_ledger_digest===digest(b.open_transmission_intents)&&b.cancel_ledger_digest===digest([]),'gate_ledger_digest');
  const snapshot=transmissions?.();
  if(!snapshot){need(control===null&&!openedOnce&&b.open_intents.length===0&&b.open_transmission_intents.length===0,'gate_control_fence_unsupported');return {coverage:[],transmission_coverage:[]};}
  need(same(snapshot.binding,bound),'gate_transmission_binding');
  const selected=snapshot.transmissions.filter(v=>{if(!selector)return true;if(selector.kind==='run_generation')return runMatches(v.transmission.intent,selector);const guard=snapshot.guards.find(g=>g.guard_id===v.transmission.intent.guard_id);
   need(guard,'gate_guard_binding');return authorizationRevoked(guard.binding,selector);});
  const local=new Map(selected.map(v=>[v.transmission.transmission_id,v])),anchors=new Map(),ids=new Set(),issues=new Set();
  for(const intent of b.open_intents){
   for(const key of ['controller_boot_id','worker_boot_id','ipc_session_id','device_id','device_session_id','clock_domain_id','descriptor_digest'])need(intent[key]===bound[key],'gate_intent_binding');
   need(intent.admission_origin==='non_panel'&&intent.panel_binding_digest===null,'gate_control_fence_unsupported');
   if(intent.origin==='automation')need(intent.automation_binding&&digest(intent.automation_binding)===intent.automation_binding_digest,'gate_automation_binding');
   else need(intent.origin==='manual'&&intent.automation_binding===null&&intent.automation_binding_digest===null,'gate_control_fence_unsupported');
   const guard=snapshot.guards.find(v=>v.permit_id===intent.permit_id||v.guard_id===intent.guard_id);
   if(guard)need(guard.permit_id===intent.permit_id&&guard.guard_id===intent.guard_id&&guard.guard_digest===intent.guard_digest&&guard.command_id===intent.command_id,'gate_guard_binding');
   if(guard)need(same(guard.automation_binding,intent.automation_binding),'gate_guard_binding');
   if(selector?.kind==='run_generation')need(runMatches(intent,selector),'gate_selector_binding');
   else if(guard&&selector)need(authorizationRevoked(guard.binding,selector),'gate_selector_binding');
   anchors.set(intent.permit_id,intent);
  }
  const transmission_coverage=b.open_transmission_intents.map(tx=>{
   need(tx.kind==='initial'&&tx.ordinal==='0'&&tx.cause==='dispatch'&&tx.trigger_observation_ref===null,'gate_control_fence_unsupported');
   need(same(anchors.get(tx.intent.permit_id),tx.intent)&&tx.initial_permit_id===tx.intent.permit_id&&tx.parent_dispatch_intent_id===tx.intent.dispatch_intent_id,'gate_transmission_anchor');
   need(!ids.has(tx.transmission_id)&&!issues.has(tx.issued_revision)&&BigInt(tx.issued_revision)<=BigInt(b.issued_cut_revision),'gate_transmission_revision');
   ids.add(tx.transmission_id);issues.add(tx.issued_revision);
   need(tx.send_window.clock_domain_id===bound.clock_domain_id&&tx.send_window.descriptor_digest===bound.descriptor_digest,'gate_transmission_binding');
   const received=snapshot.transmissions.find(v=>v.transmission.transmission_id===tx.transmission_id||v.transmission.intent.permit_id===tx.intent.permit_id);
   if(received)need(same(received.transmission,tx)&&local.has(tx.transmission_id),'gate_transmission_conflict');
   const known=local.get(tx.transmission_id);
   if(known)need(same(known.transmission,tx),'gate_transmission_conflict');
   const disposition=!known||!known.consumed?'not_sent':known.report?.body.disposition==='in_flight'?'in_flight':'unknown';
   return {intent:tx,disposition,proof:disposition==='in_flight'?'transport_entered':disposition==='unknown'?'send_uncertain':known?'discarded_unconsumed':'never_received'};
  });
  for(const known of local.values())need(ids.has(known.transmission.transmission_id),'gate_transmission_omitted');
  // 当前路径每个业务锚只有一次initial；缺少对应传输时不推断完整未发。
  return {transmission_coverage,coverage:b.open_intents.map(intent=>{const tx=transmission_coverage.find(v=>v.intent.intent.permit_id===intent.permit_id);
   return {intent,disposition:tx?.disposition??'unknown',proof:tx?.proof??'send_uncertain'};})};
 }
 function fence(frame){
  const b=frame.body,key='fence:'+b.barrier_id,old=history.get(key);
  if(old){need(same(old.body,b),'gate_identity_conflict');return old.ack?freeze({...old.ack,reply_to:frame.message_id}):candidate(frame,'BARRIER_UNAVAILABLE',{
   barrier_id:b.barrier_id,operation_id:b.operation_id,attempt_binding:b.attempt_binding,reason:'cache_miss'});}
  const a=b.attempt_binding,{barrier_id,attempt_binding,...body}=b,cut=cuts.get(a.cut_id);
  need(a.target_exit_id===bound.writer_exit_id&&a.cut_digest===digest({type:'FENCE',target_exit_id:bound.writer_exit_id,body}),'gate_cut_digest');
  if(cut){need(cut.type==='FENCE'&&latestCut===a.cut_id&&!cut.opened&&cut.digest===a.cut_digest&&a.previous_barrier_id===cut.id&&BigInt(a.attempt_ordinal)===cut.ordinal+1n,'gate_fence_attempt');
   need(BigInt(b.target_gate_revision)===revision,'gate_revision');
  }else{need(a.attempt_ordinal==='1'&&a.previous_barrier_id===null,'gate_fence_attempt');need(BigInt(b.target_gate_revision)>revision,'gate_revision');}
  need(BigInt(b.issued_cut_revision)>=issuedCut,'gate_cut_revision');
  // 同设备顺序先撤下资格，再同步读消费账本；不等待模块I/O退出。
  const t=now();withdraw();next();const covered=coverage(b);
  need(new Set([...fencedPermits,...b.open_intents.map(v=>v.permit_id)]).size<=4096,'gate_permit_capacity');
  for(const intent of b.open_intents)fencedPermits.add(intent.permit_id);issuedCut=BigInt(b.issued_cut_revision);
  control=freeze({epoch:b.control_epoch,version:b.target_version});revision=BigInt(b.target_gate_revision);
  barrier=freeze({id:b.barrier_id,revision:b.target_gate_revision,renewal:null,cut_id:a.cut_id});latestCut=a.cut_id;
  cuts.set(a.cut_id,{type:'FENCE',id:b.barrier_id,digest:a.cut_digest,ordinal:BigInt(a.attempt_ordinal),opened:false});
  const commandIds=disposition=>[...new Set(covered.coverage.filter(v=>v.disposition===disposition).map(v=>v.intent.command_id))].sort();
  const inFlight=commandIds('in_flight');
  const ack={barrier_id:b.barrier_id,operation_id:b.operation_id,device_id:bound.device_id,controller_boot_id:bound.controller_boot_id,worker_boot_id:bound.worker_boot_id,
   control_epoch:b.control_epoch,installed_version:b.target_version,discarded_permit_ids:covered.coverage.filter(v=>v.disposition==='not_sent').map(v=>v.intent.permit_id),
   in_flight_command_ids:inFlight,unresolved_command_ids:commandIds('unknown').filter(id=>!inFlight.includes(id)),all_write_exits_fenced:true,
   clock_domain_id:bound.clock_domain_id,descriptor_digest:bound.descriptor_digest};
  return remember(key,b,candidate(frame,'FENCE_ACK',{ack,issued_cut_revision:b.issued_cut_revision,ledger_digest:b.ledger_digest,gate_revision:b.target_gate_revision,
   ...covered,attempt_binding:b.attempt_binding,transmission_ledger_digest:b.transmission_ledger_digest,effective_tick_ns:String(t),cancel_coverage:[],cancel_ledger_digest:b.cancel_ledger_digest}));
 }
 function authorizationFence(frame){
  const b=frame.body,key='fence:'+b.barrier_id,old=history.get(key);
  if(old){need(same(old.body,b),'gate_identity_conflict');return old.ack?freeze({...old.ack,reply_to:frame.message_id}):candidate(frame,'BARRIER_UNAVAILABLE',{
   operation_id:b.operation_id,barrier_id:b.barrier_id,attempt_binding:b.attempt_binding,reason:'cache_miss'});}
  need(['session','principal','credential','grant','extension','trust'].includes(b.selector.kind),'authorization_selector_unsupported');
  need(b.selector_digest===digest(b.selector),'gate_selector_digest');
  const a=b.attempt_binding,{barrier_id,attempt_binding,...body}=b,cut=cuts.get(a.cut_id),target=BigInt(b.target_authorization_revision);
  need(a.target_exit_id===bound.writer_exit_id&&a.cut_digest===digest({type:'AUTH_FENCE',target_exit_id:bound.writer_exit_id,body}),'gate_cut_digest');
  if(cut)need(cut.type==='AUTH_FENCE'&&cut.digest===a.cut_digest&&cut.id===a.previous_barrier_id&&BigInt(a.attempt_ordinal)===cut.ordinal+1n&&target===authorizationRevision,'gate_fence_attempt');
  else need(a.attempt_ordinal==='1'&&a.previous_barrier_id===null&&target>authorizationRevision,'gate_fence_attempt');
  const {revision_floor,...identity}=b.selector,selectorKey=canonicalize(identity),prior=denials.get(selectorKey);
  need(!prior||BigInt(revision_floor)>=BigInt(prior.revision_floor),'gate_authorization_floor');
  need(denials.has(selectorKey)||denials.size<4096,'gate_authorization_capacity');
  const t=now();next();const covered=coverage(b,b.selector);
  need(new Set([...authorizationPermits.keys(),...b.open_intents.map(v=>v.permit_id)]).size<=4096,'gate_authorization_capacity');
  for(const intent of b.open_intents){const prior=authorizationPermits.get(intent.permit_id),tx=b.open_transmission_intents.find(v=>v.intent.permit_id===intent.permit_id)??null;
   if(prior)need(same(prior.intent,intent)&&(!prior.transmission||!tx||same(prior.transmission,tx)),'gate_revoked_intent_conflict');
   authorizationPermits.set(intent.permit_id,freeze({intent:structuredClone(intent),transmission:structuredClone(tx??prior?.transmission??null)}));}
  // 精确撤回不撤下其他身份的开放资格，也不更换控制持有人/版本。
  denials.set(selectorKey,freeze(structuredClone(b.selector)));
  authorizationRevision=target;cuts.set(a.cut_id,{type:'AUTH_FENCE',id:b.barrier_id,digest:a.cut_digest,ordinal:BigInt(a.attempt_ordinal)});
  const ids=d=>[...new Set(covered.coverage.filter(v=>v.disposition===d).map(v=>v.intent.command_id))].sort(),inFlight=ids('in_flight');
  return remember(key,b,candidate(frame,'AUTH_FENCE_ACK',{operation_id:b.operation_id,barrier_id:b.barrier_id,selector:b.selector,target_authorization_revision:b.target_authorization_revision,
   issued_cut_revision:b.issued_cut_revision,ledger_digest:b.ledger_digest,...covered,invalidated_permit_ids:covered.coverage.filter(v=>v.disposition==='not_sent').map(v=>v.intent.permit_id),
   in_flight_command_ids:inFlight,unresolved_command_ids:ids('unknown').filter(id=>!inFlight.includes(id)),all_write_exits_fenced:true,applied_authorization_revision:b.target_authorization_revision,
   selector_digest:b.selector_digest,attempt_binding:a,transmission_ledger_digest:b.transmission_ledger_digest,effective_tick_ns:String(t),cancel_coverage:[],cancel_ledger_digest:b.cancel_ledger_digest}));
 }
 function runFence(frame){
  const b=frame.body,key='fence:'+b.barrier_id,old=history.get(key);
  if(old){need(same(old.body,b),'gate_identity_conflict');return old.ack?freeze({...old.ack,reply_to:frame.message_id}):candidate(frame,'BARRIER_UNAVAILABLE',{
   operation_id:b.operation_id,barrier_id:b.barrier_id,attempt_binding:b.attempt_binding,reason:'cache_miss'});}
  need(same(b.controller_scope,bound.scope)&&b.selector_digest===digest(b.selector),'gate_run_selector');
  const a=b.attempt_binding,{barrier_id,attempt_binding,...body}=b,cut=cuts.get(a.cut_id);
  need(a.target_exit_id===bound.writer_exit_id&&a.cut_digest===digest({type:'RUN_FENCE',target_exit_id:bound.writer_exit_id,body}),'gate_cut_digest');
  if(cut)need(cut.type==='RUN_FENCE'&&cut.digest===a.cut_digest&&cut.id===a.previous_barrier_id&&BigInt(a.attempt_ordinal)===cut.ordinal+1n,'gate_fence_attempt');
  else need(a.attempt_ordinal==='1'&&a.previous_barrier_id===null,'gate_fence_attempt');
  const id=runKey(b.selector),entry={selector:b.selector,deny_revision:b.target_deny_revision};
  need(BigInt(entry.deny_revision)>0n&&(runDenials.has(id)||runDenials.size<4096),'gate_run_deny_capacity');runProgress(entry,runDenials.get(id));
  // 与普通发送共用顺序；按来源运行匹配，不改人工持有人、不等待在途模块返回。
  const t=now();next();const covered=coverage(b,b.selector);
  runDenials.set(id,freeze(structuredClone(entry)));cuts.set(a.cut_id,{type:'RUN_FENCE',id:b.barrier_id,digest:a.cut_digest,ordinal:BigInt(a.attempt_ordinal)});
  return remember(key,b,candidate(frame,'RUN_FENCE_ACK',{operation_id:b.operation_id,barrier_id:b.barrier_id,controller_scope:b.controller_scope,
   selector:b.selector,selector_digest:b.selector_digest,issued_cut_revision:b.issued_cut_revision,target_deny_revision:b.target_deny_revision,
   ledger_digest:b.ledger_digest,...covered,all_write_exits_fenced:true,attempt_binding:a,transmission_ledger_digest:b.transmission_ledger_digest,
   effective_tick_ns:String(t),cancel_coverage:[],cancel_ledger_digest:b.cancel_ledger_digest}));
 }
 function renew(frame){
  const b=frame.body,key='renew:'+b.request_id,old=previous(key,b,frame);if(old)return old;
  self(b,'request_digest','gate_fence_digest');const t=now();
  need(same(b.binding,bound)&&control!==null&&closedOnce&&!live(),'gate_fence_binding');
  need(BigInt(b.target_gate_revision)>revision&&!tokens.has(b.gate_token)&&!fenceTokens.has(b.gate_token),'gate_revision');
  need(BigInt(b.selected_tick_ns)<=t&&t<BigInt(b.expires_tick_ns)&&BigInt(b.expires_tick_ns)<=BigInt(b.lease_until_tick_ns),'gate_fence_expired');
  // close_ack_ref/before_gate_ref指向Controller持久原件；worker不伪造其数据库存在性证明。
  need(!openedOnce||b.before_gate_ref!==null,'gate_predecessor');
  withdraw();next();revision=BigInt(b.target_gate_revision);fenceTokens.add(b.gate_token);barrier=freeze({id:b.request_id,revision:b.target_gate_revision,renewal:structuredClone(b)});
  return remember(key,b,candidate(frame,'GATE_FENCE_ACK',{request_id:b.request_id,request_digest:b.request_digest,binding:bound,gate_revision:b.target_gate_revision,
   gate_token:b.gate_token,effective_tick_ns:String(t),state:'fenced'}));
 }
 function open(frame){
  const b=frame.body,a=b.gate_access,key='open:'+JSON.stringify([a.access_id,a.revision]),old=previous(key,b,frame);if(old)return old;
  const t=now();need(!live()&&control&&barrier&&b.barrier_id===barrier.id&&b.gate_revision===barrier.revision&&!tokens.has(b.gate_token),'gate_open_barrier');
  need(BigInt(b.authorization_revision)>=authorizationRevision,'gate_authorization_revision');
  need(b.device_session_id===bound.device_session_id&&b.clock_domain_id===bound.clock_domain_id&&b.descriptor_digest===bound.descriptor_digest&&
   b.control_epoch===control.epoch&&b.control_version===control.version,'gate_open_control');
  self(a,'access_digest','gate_access_digest');need(a.purpose==='ordinary'&&a.protection===null&&a.initial_assessment_ref===null&&b.protection_assessment===null&&
   same(a.binding,bound)&&a.control_epoch===control.epoch&&a.effective_version===control.version,'gate_access_binding');
  need(BigInt(a.selected_tick_ns)<=t&&t<BigInt(a.expires_tick_ns)&&BigInt(a.expires_tick_ns)<=BigInt(b.lease_until_tick_ns),'gate_open_expired');
  if(barrier.renewal){const r=barrier.renewal;need(t<BigInt(r.expires_tick_ns)&&b.gate_token===r.gate_token&&b.lease_until_tick_ns===r.lease_until_tick_ns&&
   same(a.control_authority_ref,r.control_authority_ref),'gate_open_renewal');}
  const run=b.run_deny_snapshot,command=b.command_deny_snapshot,time=b.reference_time_snapshot;
  self(run,'snapshot_digest','gate_run_snapshot_digest');self(command,'snapshot_digest','gate_command_snapshot_digest');
  if(time!==null)self(time,'snapshot_digest','gate_time_snapshot_digest');
  need(same(run.controller_scope,bound.scope)&&same(command.scope,bound.scope)&&command.device_id===bound.device_id,'gate_snapshot_binding');
  const nextRun=denySnapshot(run,runSnapshot,'run'),nextCommand=denySnapshot(command,commandSnapshot,'command');
  const installedRuns=new Map(nextRun.entries.map(entry=>[runKey(entry.selector),entry]));
  for(const [key,old] of runDenials){const entry=installedRuns.get(key);need(entry,'gate_deny_snapshot_omitted');runProgress(entry,old);}
  need(time===null||(time.domain.authority_service_id===bound.scope.authority_service_id&&time.domain.database_instance_id===bound.scope.database_instance_id&&
   time.domain.clock_domain_id===bound.clock_domain_id&&time.domain.descriptor_digest===bound.descriptor_digest),'gate_time_domain');
  next();tokens.add(b.gate_token);openedOnce=true;runSnapshot=nextRun;commandSnapshot=nextCommand;
  for(const [key,entry] of installedRuns)runDenials.set(key,entry);
  authorizationRevision=BigInt(b.authorization_revision);
  if(barrier.cut_id)cuts.get(barrier.cut_id).opened=true;
  active=freeze({access:structuredClone(a),gate_token:b.gate_token,gate_revision:b.gate_revision,authorization_revision:b.authorization_revision,lease_until_tick_ns:b.lease_until_tick_ns,
   issued_cut_revision:String(issuedCut),fenced_permit_ids:[...fencedPermits]});
  return remember(key,b,candidate(frame,'OPEN_GATE_ACK',{gate_token:b.gate_token,gate_revision:b.gate_revision,state:'open',run_deny_snapshot_revision:run.snapshot_revision,
   run_deny_snapshot_digest:run.snapshot_digest,command_deny_snapshot_revision:command.snapshot_revision,command_deny_snapshot_digest:command.snapshot_digest,
   reference_time_snapshot_ref:time===null?null:{id:time.snapshot_id,revision:time.snapshot_revision,digest:time.snapshot_digest},gate_access_ref:{id:a.access_id,revision:a.revision,digest:a.access_digest}}));
 }
 function close(frame){const b=frame.body,key='close:'+b.close_id,old=previous(key,b,frame);if(old)return old;
  need(frame.journal_mode==='durable'&&((b.scope==='device'&&frame.device_id===bound.device_id)||(b.scope==='controller'&&frame.device_id===null)),'gate_close_scope');
  withdraw();next();closedOnce=true;return remember(key,b,candidate(frame,'CLOSE_GATE_ACK',{close_id:b.close_id,closed_device_ids:[bound.device_id]}));}
 return Object.freeze({
  async receive(bytes){try{current();const {frame}=await decodeExecutionPayload(bytes,'c2w');current();
   for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','device_id','clock_domain_id','descriptor_digest'])need(frame[key]===bound[key],'gate_channel');
   need(frame.journal_mode==='durable','gate_journal_mode');
   switch(frame.type){case 'FENCE':return fence(frame);case 'AUTH_FENCE':return authorizationFence(frame);case 'RUN_FENCE':return runFence(frame);case 'QUERY_BARRIER':return queryBarrier(frame);case 'BARRIER_STORED':return storeBarrier(frame);case 'GATE_FENCE':return renew(frame);case 'OPEN_GATE':return open(frame);case 'CLOSE_GATE':return close(frame);default:need(false,'gate_message_unsupported');}
  }catch(error){stop(error);throw error;}},
  currentGate(){try{const value=live();return value?freeze({...value,authorization_denials:[...denials.values()],authorization_denied_permit_ids:[...authorizationPermits.keys()],
   authorization_denied_intents:[...authorizationPermits.values()],run_denials:[...runDenials.values()],command_denials:commandSnapshot.entries,
   run_deny_snapshot_ref:{revision:runSnapshot.snapshot_revision,digest:runSnapshot.snapshot_digest},
   command_deny_snapshot_ref:{revision:commandSnapshot.snapshot_revision,digest:commandSnapshot.snapshot_digest}}):null;}catch(error){stop(error);throw error;}},
  // 固定会话已严格解码原wire；同步关闭供其完整设备集合仲裁，不能在设备之间await。
  closeScope(frame){try{current();need(frame?.type==='CLOSE_GATE'&&frame.journal_mode==='durable'&&frame.reply_to===null,'gate_close_scope');
   for(const key of ['ipc_session_id','controller_boot_id','worker_boot_id','clock_domain_id','descriptor_digest'])need(frame[key]===bound[key],'gate_channel');
   const b=frame.body;need(b&&Object.keys(b).sort().join(',')==='close_id,reason,scope'&&typeof b.close_id==='string'&&b.close_id.length>0&&b.close_id.length<=128&&
    typeof b.reason==='string'&&b.reason.length>0&&b.reason.length<=128,'gate_close_scope');
   return close(frame);
  }catch(error){stop(error);throw error;}},
  nextIoSequence(){try{need(live(),'gate_not_open');return next();}catch(error){stop(error);throw error;}},
  // 本地保护撤下开放与屏障；不生成远端ACK，不宣称传输已排空。
  protect(){try{current();withdraw();next();}catch(error){stop(error);throw error;}},
  // 会话所有者已进入终端保护时只撤资格；不以故障回调递归断开待发送的关闭ACK。
  terminate(){terminal=true;withdraw();},
  close:stop,
  get state(){let value=null;if(!terminal){try{value=live();}catch(error){stop(error);}}
   return freeze({terminal,open:value!==null,revision:String(revision),io_sequence:String(order),history_entries:history.size,metadata_bytes:metadata});}
 });
}
