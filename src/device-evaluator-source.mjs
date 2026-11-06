import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {seal,ref,same,checked,digest} from './auth-clock-value.mjs';
import {IdentityError} from './identity-crypto.mjs';
import {selectAuthenticationWindow,currentAuthenticationWindow} from './authentication-window.mjs';
import {collectAuthorizationDependencies,currentAuthorizationDependencies} from './authorization-dependencies.mjs';
const need=(v,c)=>{if(!v)throw new IdentityError('evaluator_source_'+c);};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const fields=(v,n)=>need(v&&typeof v==='object'&&Object.keys(v).sort().join(',')===n.split(',').sort().join(','),'input');
const unpack=(text,hash)=>{const v=checked(JSON.parse(text));need(canonicalize(v)===text&&v.digest===hash,'integrity');return v;};
const written=r=>need(r.changes===1,'storage');
const deliver=v=>{if(v.denied)throw new IdentityError(v.denied);return v;};
// 内部评估器取证；身份认证与核心单调观察分别复核，本原件不充当OPEN Requirement。
export function deviceEvaluatorSource({db,service,writer,time,management,principal,approval,credential,allowed,expired,authenticateCredential,coreSource,attachCurrent}){
 const attempts=new Map();let globalStart=0n,globalCount=0;
 function throttle(id){const tick=process.hrtime.bigint(),minute=60000000000n;if(tick-globalStart>=minute){globalStart=tick;globalCount=0;}
  for(const [k,v] of attempts)if(tick-v.start>=minute)attempts.delete(k);need(globalCount<60&&attempts.size<4096,'throttled');globalCount++;
  const b=attempts.get(id)??{start:tick,count:0};need(b.count<16,'throttled');b.count++;attempts.set(id,b);}
 function supervised(read){try{return read();}catch(error){
  if(error instanceof IdentityError||typeof error?.code!=='string'||error.code.startsWith('SQLITE_'))throw error;
  need(false,'runtime_unavailable');
 }}
 function operation(id,key,request,kind,result,now,actor=null){
  need(db.prepare('SELECT count(*) FROM device_evaluator_operation').pluck().get()<16384,'capacity');
  const v=seal({format:'device-evaluator-operation/1',id,revision:'1',actor,kind,key,request_id:request.request_id,request_digest:digest(request),result,acquisition_ref:now.acquisition});
  written(db.prepare('INSERT INTO device_evaluator_operation VALUES(?,?,?,?,?,?,?,?)').run(id,key,request.request_id,kind,v.request_digest,now.acquisition.id,canonicalize(v),v.digest));return result;
 }
 function prior(key,request,kind){const row=db.prepare('SELECT kind,request_digest,body_jcs,body_digest FROM device_evaluator_operation WHERE actor_key=? AND request_id=?').raw().get(key,request.request_id);
  if(!row)return null;need(row[0]===kind&&row[1]===digest(request),'conflict');return unpack(row[2],row[3]).result;}
 function policy(reference){const row=db.prepare('SELECT body_jcs,body_digest,principal_id,approval_id FROM device_evaluator_policy WHERE policy_id=?').raw().get(reference?.id);
  need(row,'policy_missing');const v=unpack(row[0],row[1]);need(same(ref(v),reference)&&v.principal_id===row[2]&&v.approval_ref.id===row[3]&&v.service_id===service.service_id&&v.database_instance_id===service.database_instance_id,'integrity');return v;}
 function activePolicy(reference,now){const p=policy(reference);need(!db.prepare('SELECT 1 FROM device_evaluator_policy_revocation WHERE policy_id=?').pluck().get(p.id),'policy_revoked');
  const s=principal(p.principal_id),a=approval(s);need(same(ref(s),p.subject_ref)&&same(ref(a),p.approval_ref),'policy_changed');
  if(now.upper>=BigInt(p.expires_ns)){
   const op=crypto.randomUUID(),r=seal({format:'device-evaluator-policy-revocation/1',id:crypto.randomUUID(),revision:'1',policy_ref:ref(p),reason:'expired',actor:null,acquisition_ref:now.acquisition});
   written(db.prepare('INSERT INTO device_evaluator_policy_revocation VALUES(?,?,?,?,?)').run(r.id,p.id,canonicalize(r),r.digest,op));
   operation(op,'system:'+p.id,{request_id:op,policy_ref:ref(p)},'expire',r,now);return {denied:'evaluator_source_policy_expired'};
  }
  need(now.lower>=BigInt(p.not_before_ns)&&now.lower>=BigInt(a.not_before_ns)&&now.upper<BigInt(a.expires_ns),'policy_validity');return {p,s,a};
 }
 function challenge(reference){const row=db.prepare('SELECT body_jcs,body_digest,policy_id,core_source_id,device_id FROM device_evaluator_challenge WHERE challenge_id=?').raw().get(reference?.id);
  need(row,'challenge_missing');const v=unpack(row[0],row[1]);need(same(ref(v),reference)&&v.policy_ref.id===row[2]&&v.core_runtime_source_ref.id===row[3]&&v.device_id===row[4],'integrity');return v;}
 function currentChallenge(v){need(coreSource,'runtime_unavailable');const now=supervised(()=>coreSource.domain());
  need(same(v.domain_ref,now.ref)&&BigInt(v.issued_tick_ns)<=BigInt(now.tick)&&BigInt(now.tick)<BigInt(v.expires_tick_ns),'challenge_expired');
  const runtime=supervised(()=>coreSource.currentCoreSource(v.core_runtime_source_ref));need(same(runtime.value.domain_ref,now.ref),'runtime_domain');return {runtime,now};}
 function original(reference){const row=db.prepare('SELECT s.body_jcs,s.body_digest,s.challenge_id,s.credential_id,s.request_digest,o.body_jcs,o.body_digest FROM device_evaluator_source s JOIN device_evaluator_operation o USING(operation_id) WHERE source_id=?').raw().get(reference?.id);
  need(row,'source_missing');const v=unpack(row[0],row[1]),op=unpack(row[5],row[6]);need(same(ref(v),reference)&&v.challenge_ref.id===row[2]&&v.credential_ref.id===row[3]&&v.response_digest===row[4]&&op.kind==='source'&&same(op.result,{ref:reference,value:v}),'integrity');return v;}
 function currentInside(reference){const v=original(reference),ch=challenge(v.challenge_ref),actual=currentChallenge(ch),now=time(),p=activePolicy(v.policy_ref,now);if(p.denied)return p;
  const c=credential(v.credential_ref.id);if(expired(c,now))return {denied:'evaluator_source_credential_expired'};
  const parent=allowed(c,now);need(c.state==='active'&&same(ref(c),v.credential_ref)&&same(ref(parent.subject),v.subject_ref)&&same(ref(parent.a),v.approval_ref)&&p.p.device_ids.includes(v.device_id),'identity_changed');
  need(v.authentication_window&&v.expires_tick_ns===v.authentication_window.before_tick_ns,'window_missing');
  currentAuthenticationWindow({db,service,coreRuntime:actual.runtime,domain:actual.now.ref,acquisitionRef:v.authentication_acquisition_ref,
   selectedTick:v.selected_tick_ns,validFrom:[c.not_before_ns,p.p.not_before_ns,parent.a.not_before_ns].reduce((a,b)=>BigInt(a)>BigInt(b)?a:b),
   validBefore:[c.expires_ns,p.p.expires_ns,parent.a.expires_ns].reduce((a,b)=>BigInt(a)<BigInt(b)?a:b),capTick:ch.expires_tick_ns},v.authentication_window,actual.now.tick);
  need(same(v.domain_ref,actual.now.ref)&&BigInt(v.selected_tick_ns)<=BigInt(actual.now.tick)&&BigInt(actual.now.tick)<BigInt(v.expires_tick_ns)&&
   same(v.core_runtime_source_ref,ch.core_runtime_source_ref)&&same(v.policy_ref,ch.policy_ref),'expired');
  if(Number(service.schema_revision)>=39)currentAuthorizationDependencies(db,service,'evaluator',v);return {ref:reference,value:v};
 }
 attachCurrent?.(reference=>{need(db.inTransaction,'writer');return currentInside(reference);});
 return Object.freeze({
  approveDeviceEvaluatorPolicy(input,request){fields(request,'request_id,principal_id,subject_ref,approval_ref,device_ids,expires_ns');need(uuid(request.request_id)&&uuid(request.principal_id)&&
   Array.isArray(request.device_ids)&&request.device_ids.length>0&&request.device_ids.length<=128&&request.device_ids.every(uuid)&&new Set(request.device_ids).size===request.device_ids.length&&
   typeof request.expires_ns==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(request.expires_ns),'input');request={...request,device_ids:[...request.device_ids].sort()};
   return management(input,'auth.manage',(actor,now)=>{const key='human:'+actor.principal_id,old=prior(key,request,'policy');if(old)return old;
    const s=principal(request.principal_id),a=approval(s);need(same(ref(s),request.subject_ref)&&same(ref(a),request.approval_ref)&&a.audiences.includes(service.service_id),'binding');
    need(request.device_ids.every(id=>a.device_ids.includes(id)&&db.prepare('SELECT 1 FROM device_record WHERE device_id=?').pluck().get(id)),'scope');
    need(now.lower>=BigInt(a.not_before_ns)&&now.upper<BigInt(request.expires_ns)&&BigInt(request.expires_ns)<=BigInt(a.expires_ns),'validity');
    need(!db.prepare('SELECT 1 FROM device_evaluator_policy WHERE principal_id=?').pluck().get(s.id),'policy_change_unavailable');
    const op=crypto.randomUUID(),v=seal({format:'device-evaluator-policy/1',id:crypto.randomUUID(),revision:'1',service_id:service.service_id,database_instance_id:service.database_instance_id,
     principal_id:s.id,subject_ref:ref(s),approval_ref:ref(a),purpose:'ordinary_evaluation',device_ids:request.device_ids,not_before_ns:String(now.lower),expires_ns:request.expires_ns,actor,acquisition_ref:now.acquisition});
    written(db.prepare('INSERT INTO device_evaluator_policy VALUES(?,?,?,?,?,?)').run(v.id,s.id,a.id,canonicalize(v),v.digest,op));need(same(policy(ref(v)),v),'integrity');return operation(op,key,request,'policy',v,now,actor);
   });
  },
  revokeDeviceEvaluatorPolicy(input,request){fields(request,'request_id,policy_ref');need(uuid(request.request_id),'input');return management(input,'auth.manage',(actor,now)=>{
   const key='human:'+actor.principal_id,old=prior(key,request,'revoke');if(old)return old;const p=policy(request.policy_ref),row=db.prepare('SELECT body_jcs,body_digest FROM device_evaluator_policy_revocation WHERE policy_id=?').raw().get(p.id),op=crypto.randomUUID();
   const v=row?unpack(...row):seal({format:'device-evaluator-policy-revocation/1',id:crypto.randomUUID(),revision:'1',policy_ref:ref(p),reason:'revoked',actor,acquisition_ref:now.acquisition});
   if(!row)written(db.prepare('INSERT INTO device_evaluator_policy_revocation VALUES(?,?,?,?,?)').run(v.id,p.id,canonicalize(v),v.digest,op));return operation(op,key,request,'revoke',v,now,actor);
  });},
  beginDeviceEvaluatorChallenge(request){fields(request,'request_id,policy_ref,device_id');need(uuid(request.request_id)&&uuid(request.device_id),'input');return deliver(writer(()=>{
   need(coreSource,'runtime_unavailable');const now=time(),p=activePolicy(request.policy_ref,now);if(p.denied)return p;need(p.p.device_ids.includes(request.device_id),'scope');
   const old=prior('core',request,'challenge');if(old){currentChallenge(old);return old;}
   need(db.prepare('SELECT count(*) FROM device_evaluator_challenge').pluck().get()<4096,'capacity');const runtime=supervised(()=>coreSource.selectCoreSource()),domain=supervised(()=>coreSource.domain()),op=crypto.randomUUID();
   const end=[BigInt(runtime.value.expires_tick_ns),BigInt(domain.tick)+2000000000n].reduce((a,b)=>a<b?a:b);need(BigInt(domain.tick)<end,'challenge_expired');
   const v=seal({format:'device-evaluator-challenge/1',id:crypto.randomUUID(),revision:'1',policy_ref:ref(p.p),device_id:request.device_id,core_runtime_source_ref:runtime.ref,
    domain_ref:domain.ref,nonce:crypto.randomBytes(32).toString('base64url'),issued_tick_ns:domain.tick,expires_tick_ns:String(end)});
   written(db.prepare('INSERT INTO device_evaluator_challenge VALUES(?,?,?,?,?,?,?)').run(v.id,p.p.id,runtime.ref.id,v.device_id,canonicalize(v),v.digest,op));
   currentChallenge(v);return operation(op,'core',request,'challenge',v,now);
  }));},
  completeDeviceEvaluatorChallenge(input){fields(input,'request_id,challenge_ref,nonce,credential_id,secret');need(uuid(input.request_id)&&uuid(input.credential_id),'input');throttle(input.credential_id);return deliver(writer(()=>{
   const c=authenticateCredential(input.credential_id,input.secret),now=time();if(expired(c,now))return {denied:'evaluator_source_credential_expired'};need(c.state==='active','credential_state');
   const ch=challenge(input.challenge_ref),actual=currentChallenge(ch),p=activePolicy(ch.policy_ref,now);if(p.denied)return p;const parent=allowed(c,now);
   need(input.nonce===ch.nonce&&same(ref(parent.subject),p.p.subject_ref)&&same(ref(parent.a),p.p.approval_ref)&&p.p.device_ids.includes(ch.device_id),'response_binding');
   const {secret:_secret,...request}=input,old=db.prepare('SELECT source_id,body_digest,request_digest FROM device_evaluator_source WHERE challenge_id=?').raw().get(ch.id);
   if(old){need(old[2]===digest(request),'conflict');return currentInside({id:old[0],revision:'1',digest:old[1]});}
   const validFrom=[c.not_before_ns,p.p.not_before_ns,parent.a.not_before_ns].reduce((a,b)=>BigInt(a)>BigInt(b)?a:b),
    validBefore=[c.expires_ns,p.p.expires_ns,parent.a.expires_ns].reduce((a,b)=>BigInt(a)<BigInt(b)?a:b);
   const selected=supervised(()=>coreSource.domain());
   const window=selectAuthenticationWindow({db,service,coreRuntime:actual.runtime,domain:selected.ref,acquisitionRef:now.acquisition,selectedTick:selected.tick,
    validFrom,validBefore,capTick:ch.expires_tick_ns});
   const op=crypto.randomUUID(),base={format:'device-evaluator-source/2',id:crypto.randomUUID(),revision:'1',device_id:ch.device_id,policy_ref:ref(p.p),subject_ref:ref(parent.subject),approval_ref:ref(parent.a),
    credential_ref:ref(c),issuer_id:parent.subject.issuer_id,issuer_epoch:parent.subject.issuer_epoch,principal_id:parent.subject.id,challenge_ref:ref(ch),response_id:input.request_id,response_digest:digest(request),
    authentication_acquisition_ref:now.acquisition,authentication_valid_from_ns:validFrom,authentication_valid_before_ns:validBefore,authentication_window:window,
    core_runtime_source_ref:ch.core_runtime_source_ref,domain_ref:selected.ref,selected_tick_ns:selected.tick,expires_tick_ns:window.before_tick_ns};
   const v=seal({...base,...(Number(service.schema_revision)>=39?{authorization_dependencies:collectAuthorizationDependencies(db,service,'evaluator',base)}:{})});
   written(db.prepare('INSERT INTO device_evaluator_source VALUES(?,?,?,?,?,?,?,?)').run(v.id,ch.id,c.id,v.response_digest,canonicalize(v),v.digest,now.acquisition.id,op));
   operation(op,'credential:'+c.id,request,'source',{ref:ref(v),value:v},now);return currentInside(ref(v));
  }));},
  currentDeviceEvaluatorSource(reference){return deliver(writer(()=>currentInside(reference)));}
 });
}
