import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError,createOpaqueSecret,verifyOpaqueSecret} from './identity-crypto.mjs';
import {seal,ref,checked,same,digest} from './auth-clock-value.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('service_token_'+code);};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const fields=(v,names)=>need(v&&typeof v==='object'&&Object.keys(v).sort().join(',')===names.split(',').sort().join(','),'input');
const integer=v=>{need(typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<(1n<<64n),'input');return BigInt(v);};
const written=r=>need(r.changes===1,'storage');
const unpack=(text,hash)=>{const v=checked(JSON.parse(text));need(canonicalize(v)===text&&v.digest===hash,'integrity');return v;};
const deliver=v=>{if(v.denied)throw new IdentityError(v.denied);return v;};
const scope=request=>{
 need(Array.isArray(request.permissions)&&request.permissions.length===1&&request.permissions[0]==='identity.read'&&
  Array.isArray(request.device_ids)&&request.device_ids.length<=128&&request.device_ids.every(uuid)&&new Set(request.device_ids).size===request.device_ids.length,'scope');
 return {...request,device_ids:[...request.device_ids].sort()};
};
// 本机接收方授权与签发批准分别保存。当前唯一消费路径是服务读取自身身份。
export function serviceAccessTokenStore({db,service,writer,time,management,principal,approval,credential,allowed,expired,authenticateCredential}){
 const invalid=crypto.randomBytes(32),buckets=new Map();let globalStart=0n,globalCount=0;
 function throttle(id){const tick=process.hrtime.bigint(),minute=60000000000n;
  if(tick-globalStart>=minute){globalStart=tick;globalCount=0;}for(const [k,v] of buckets)if(tick-v.start>=minute)buckets.delete(k);
  need(globalCount<60&&buckets.size<4096,'throttled');globalCount++;const b=buckets.get(id)??{start:tick,count:0};need(b.count<16,'throttled');b.count++;buckets.set(id,b);
 }
 function commit(id,key,request,kind,result,now,actor=null){
  need(db.prepare('SELECT count(*) FROM service_token_operation').pluck().get()<16384,'capacity');
  const v=seal({format:'local-service-token-operation/1',id,revision:'1',kind,key,request_id:request.request_id,request_digest:digest(request),actor,result,acquisition_ref:now.acquisition});
  written(db.prepare('INSERT INTO service_token_operation VALUES(?,?,?,?,?,?,?,?)').run(id,key,request.request_id,kind,v.request_digest,now.acquisition.id,canonicalize(v),v.digest));
  need(same(unpack(...db.prepare('SELECT body_jcs,body_digest FROM service_token_operation WHERE operation_id=?').raw().get(id)),v),'integrity');return result;
 }
 function prior(key,request,kind){const row=db.prepare('SELECT kind,request_digest,body_jcs,body_digest FROM service_token_operation WHERE actor_key=? AND request_id=?').raw().get(key,request.request_id);
  if(!row)return null;need(row[0]===kind&&row[1]===digest(request),'conflict');return unpack(row[2],row[3]).result;}
 function policy(id){const row=db.prepare('SELECT body_jcs,body_digest,principal_id,service_id,approval_id FROM service_receiver_policy WHERE policy_id=?').raw().get(id);
  need(row,'policy_required');const p=unpack(row[0],row[1]);need(p.id===id&&p.principal_id===row[2]&&p.audience===row[3]&&p.approval_ref.id===row[4]&&p.audience===service.service_id,'integrity');return p;}
 function currentPolicy(subject,a,now){const row=db.prepare('SELECT policy_id FROM service_receiver_policy WHERE principal_id=?').pluck().get(subject.id);need(row,'policy_required');const p=policy(row);
  if(db.prepare('SELECT 1 FROM service_receiver_policy_revocation WHERE policy_id=?').pluck().get(p.id))return null;
  if(now.upper>=BigInt(p.expires_ns)){
   const op=crypto.randomUUID(),v=seal({format:'local-service-policy-revocation/1',id:crypto.randomUUID(),revision:'1',policy_ref:ref(p),reason:'expired',revoked_by:null,acquisition_ref:now.acquisition});
   written(db.prepare('INSERT INTO service_receiver_policy_revocation VALUES(?,?,?,?,?)').run(v.id,p.id,canonicalize(v),v.digest,op));
   commit(op,'system:policy:'+p.id,{request_id:op,policy_ref:ref(p)},'expired',v,now);return null;
  }
  need(same(p.approval_ref,ref(a))&&same(p.subject_ref,ref(subject))&&now.lower>=BigInt(p.not_before_ns),'policy_invalid');return p;}
 function read(id){const row=db.prepare('SELECT body_jcs,body_digest,credential_id,policy_id,audience,expires_ns,request_id,request_digest FROM service_access_token WHERE token_id=?').raw().get(id);
  need(row,'invalid');const v=unpack(row[0],row[1]);need(v.id===id&&v.credential_ref.id===row[2]&&v.policy_ref.id===row[3]&&v.audience===row[4]&&v.expires_ns===row[5]&&v.request_id===row[6]&&v.request_digest===row[7],'integrity');return v;}
 function terminal(v,state,now){const old=db.prepare('SELECT body_jcs,body_digest FROM service_access_token_terminal WHERE token_id=?').raw().get(v.id);if(old)return unpack(...old);
  const op=crypto.randomUUID(),result=seal({format:'local-service-token-terminal/1',id:v.id,revision:'2',binding_ref:ref(v),state,acquisition_ref:now.acquisition});
  written(db.prepare('INSERT INTO service_access_token_terminal VALUES(?,?,?,?,?)').run(v.id,state,canonicalize(result),result.digest,op));
  commit(op,'system:'+v.id,{request_id:op,token_ref:ref(v)},state,result,now);return result;
 }
 function current(v,now){
  if(db.prepare('SELECT 1 FROM service_access_token_terminal WHERE token_id=?').pluck().get(v.id))return {denied:'service_token_invalid'};
  if(now.upper>=BigInt(v.expires_ns)){terminal(v,'expired',now);return {denied:'service_token_expired'};}
  const c=credential(v.credential_ref.id);if(expired(c,now)||c.state!=='active'||!same(ref(c),v.credential_ref)){terminal(v,'revoked',now);return {denied:'service_token_invalid'};}
  const {subject,a}=allowed(c,now),p=currentPolicy(subject,a,now);if(!p){terminal(v,'revoked',now);return {denied:'service_token_policy_invalid'};}
  need(same(ref(subject),v.subject_ref)&&same(ref(a),v.approval_ref)&&same(ref(p),v.policy_ref)&&now.lower>=BigInt(v.not_before_ns),'authority_changed');
  need(v.permissions.every(x=>a.permissions.includes(x)&&p.permissions.includes(x))&&v.device_ids.every(x=>a.device_ids.includes(x)&&p.device_ids.includes(x)),'scope');
  return {active:true,principal_kind:'service',issuer_id:subject.issuer_id,issuer_epoch:subject.issuer_epoch,principal_id:subject.id,
   credential_ref:ref(c),subject_ref:ref(subject),approval_ref:ref(a),policy_ref:ref(p),binding_ref:ref(v),audience:v.audience,
   permissions:v.permissions,device_ids:v.device_ids,not_before_ns:v.not_before_ns,expires_ns:v.expires_ns,acquisition_ref:now.acquisition};
 }
 function verify(input){fields(input,'token_id,secret');need(uuid(input.token_id),'invalid');throttle(input.token_id);
  const row=db.prepare('SELECT verifier,verifier_profile FROM service_access_token WHERE token_id=?').raw().get(input.token_id);let ok=false;
  try{ok=verifyOpaqueSecret('access_token',input.secret,row?.[0]??invalid);}catch{}need(row&&row[1]==='opaque-verifier/1'&&ok,'invalid');
  const v=read(input.token_id);need(v.audience===service.service_id,'audience');const found=current(v,time());if(found.denied)return found;return current(v,time());
 }
 return Object.freeze({
  approveLocalServicePolicy(input,request){fields(request,'request_id,principal_id,subject_ref,approval_ref,audience,permissions,device_ids,not_before_ns,expires_ns');
   request=scope(request);need(uuid(request.request_id)&&uuid(request.principal_id)&&request.audience===service.service_id,'input');const start=integer(request.not_before_ns),end=integer(request.expires_ns);need(end>start,'input');
   return management(input,'auth.manage',(actor,now)=>{const key='human:'+actor.principal_id,old=prior(key,request,'policy');if(old)return old;
    const s=principal(request.principal_id),a=approval(s);need(same(request.subject_ref,ref(s))&&same(request.approval_ref,ref(a)),'revision');
    need(a.audiences.includes(request.audience)&&request.permissions.every(p=>a.permissions.includes(p))&&request.device_ids.every(d=>a.device_ids.includes(d)),'scope');
    need(start>=BigInt(a.not_before_ns)&&end<=BigInt(a.expires_ns)&&now.upper<end,'validity');
    need(!db.prepare('SELECT 1 FROM service_receiver_policy WHERE principal_id=?').pluck().get(s.id),'policy_change_unavailable');
    const op=crypto.randomUUID(),v=seal({format:'local-service-receiver-policy/1',id:crypto.randomUUID(),revision:'1',principal_id:s.id,subject_ref:ref(s),approval_ref:ref(a),
     audience:request.audience,permissions:request.permissions,device_ids:request.device_ids,not_before_ns:request.not_before_ns,expires_ns:request.expires_ns,approved_by:actor,acquisition_ref:now.acquisition});
    written(db.prepare('INSERT INTO service_receiver_policy VALUES(?,?,?,?,?,?,?)').run(v.id,s.id,service.service_id,a.id,canonicalize(v),v.digest,op));need(same(policy(v.id),v),'integrity');
    return commit(op,key,request,'policy',v,now,actor);
   });
  },
  revokeLocalServicePolicy(input,request){fields(request,'request_id,policy_ref');need(uuid(request.request_id),'input');return management(input,'auth.manage',(actor,now)=>{
   const key='human:'+actor.principal_id,old=prior(key,request,'policy_revoke');if(old)return old;const p=policy(request.policy_ref.id);need(same(ref(p),request.policy_ref),'revision');
   const row=db.prepare('SELECT body_jcs,body_digest FROM service_receiver_policy_revocation WHERE policy_id=?').raw().get(p.id),op=crypto.randomUUID();
   const result=row?unpack(...row):seal({format:'local-service-policy-revocation/1',id:crypto.randomUUID(),revision:'1',policy_ref:ref(p),revoked_by:actor,acquisition_ref:now.acquisition});
   if(!row)written(db.prepare('INSERT INTO service_receiver_policy_revocation VALUES(?,?,?,?,?)').run(result.id,p.id,canonicalize(result),result.digest,op));
   return commit(op,key,request,'policy_revoke',result,now,actor);
  });},
  issueServiceToken(input){fields(input,'credential_id,secret,request_id,audience,permissions,device_ids');need(uuid(input.credential_id)&&uuid(input.request_id)&&input.audience===service.service_id,'input');
   const {secret:_secret,...request}=scope(input);throttle(input.credential_id);const generated=createOpaqueSecret('access_token');let delivered=false;
   const result=deliver(writer(()=>{const c=authenticateCredential(input.credential_id,input.secret),now=time();if(expired(c,now)||c.state!=='active')return {denied:'service_token_credential_invalid'};
    const key='credential:'+c.id,old=prior(key,request,'issue');if(old)return old;
    const {subject,a}=allowed(c,now),p=currentPolicy(subject,a,now);if(!p)return {denied:'service_token_policy_invalid'};
    need(request.permissions.every(x=>a.permissions.includes(x)&&p.permissions.includes(x))&&request.device_ids.every(x=>a.device_ids.includes(x)&&p.device_ids.includes(x)),'scope');
    const rows=db.prepare('SELECT token_id FROM service_access_token WHERE credential_id=?').pluck().all(c.id);let active=0;
    for(const id of rows){const v=read(id);if(!db.prepare('SELECT 1 FROM service_access_token_terminal WHERE token_id=?').pluck().get(id)){if(now.upper>=BigInt(v.expires_ns))terminal(v,'expired',now);else active++;}}
    if(active>=8)return {denied:'service_token_capacity'};need(db.prepare('SELECT count(*) FROM service_access_token').pluck().get()<4096,'capacity');
    const end=[now.lower+60000000000n,BigInt(c.expires_ns),BigInt(a.expires_ns),BigInt(p.expires_ns)].reduce((a,b)=>a<b?a:b);need(now.upper<end,'validity');
    const op=crypto.randomUUID(),v=seal({format:'local-service-token-binding/1',id:crypto.randomUUID(),revision:'1',credential_ref:ref(c),subject_ref:ref(subject),approval_ref:ref(a),policy_ref:ref(p),
     audience:service.service_id,permissions:request.permissions,device_ids:request.device_ids,request_id:request.request_id,request_digest:digest(request),
     not_before_ns:String(now.lower),expires_ns:String(end),acquisition_ref:now.acquisition});
    written(db.prepare('INSERT INTO service_access_token VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(v.id,c.id,p.id,service.service_id,request.request_id,v.request_digest,generated.verifier,'opaque-verifier/1',v.expires_ns,canonicalize(v),v.digest,now.acquisition.id,op));
    need(same(read(v.id),v),'integrity');const last=current(v,time());
    const result=commit(op,key,request,'issue',{binding:v,secret_delivery:'unavailable'},now);
    if(last.denied)return last;delivered=true;return result;
   }));return delivered?{...result,secret_delivery:'delivered',secret:generated.secret}:result;
  },
  verifyServiceToken(input){return deliver(writer(()=>verify(input)));},
  readServiceIdentity(input){return deliver(writer(()=>{const proof=verify(input);if(proof.denied)return proof;need(proof.permissions.includes('identity.read'),'permission');return principal(proof.principal_id);}));}
 });
}
