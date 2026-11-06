import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {IdentityError,createOpaqueSecret,verifyOpaqueSecret} from './identity-crypto.mjs';
import {seal as sealBody,ref,checked,same,digest} from './auth-clock-value.mjs';
import {serviceAccessTokenStore} from './service-access-token-store.mjs';
import {deviceEvaluatorSource} from './device-evaluator-source.mjs';
const seal=({digest:_previous,...body})=>sealBody(body);
const need=(ok,code)=>{if(!ok)throw new IdentityError('service_identity_'+code);};
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const fields=(v,names)=>need(v&&typeof v==='object'&&Object.keys(v).sort().join(',')===names.split(',').sort().join(','),'input');
const integer=v=>{need(typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<(1n<<64n),'input');return BigInt(v);};
const written=r=>need(r.changes===1,'storage');
const unpack=(text,hash)=>{const v=checked(JSON.parse(text));need(canonicalize(v)===text&&v.digest===hash,'integrity');return v;};
const deliver=v=>{if(v.denied)throw new IdentityError(v.denied);return v;};
// 核心内部人员管理入口。服务主体不建立人员会话，凭据激活不授予设备执行许可。
export function serviceIdentityStore({db,service,writer,time,authenticated,authority,coreSource=null,attachEvaluatorCurrent}){
 const invalidVerifier=crypto.randomBytes(32),attempts=new Map();let globalStart=0n,globalCount=0;
 function management(input,permission,work){return deliver(writer(()=>{
  const now=time(),found=authenticated(input,now);if(found.denied)return found;
  const grant=authority.current(found.session.principal_id);
  need(db.prepare("SELECT 1 FROM subject WHERE principal_id=? AND kind='human'").pluck().get(found.session.principal_id)&&
   grant.state==='active'&&grant.permissions.includes(permission)&&(permission!=='auth.manage'||now.upper<BigInt(found.session.recent_before_ns)),'management_denied');
  const actor={principal_id:found.session.principal_id,issuer_id:found.session.issuer_id,issuer_epoch:found.session.issuer_epoch,
   session_id:found.session.session_id,credential_id:found.credential.credential_id,policy_ref:ref(grant)};
  const result=work(actor,now),last=time();need((permission!=='auth.manage'||last.upper<BigInt(found.session.recent_before_ns))&&
   last.upper<BigInt(found.session.idle_before_ns)&&last.upper<BigInt(found.session.expires_ns)&&same(ref(authority.current(actor.principal_id)),actor.policy_ref),'management_changed');return result;
 }));}
 function principal(id){
  need(uuid(id),'input');const row=db.prepare(`SELECT r.body_jcs,r.body_digest,r.state,r.revision,s.issuer_id,s.issuer_epoch,s.kind
   FROM service_principal_head h JOIN service_principal_revision r USING(principal_id,revision)
   JOIN subject s USING(principal_id) WHERE h.principal_id=?`).raw().get(id);
  need(row,'not_found');const value=unpack(row[0],row[1]);
  need(value.id===id&&value.kind==='service'&&value.format==='local-service-principal/1'&&value.state===row[2]&&value.revision===String(row[3])&&value.issuer_id===row[4]&&value.issuer_epoch===row[5]&&row[6]==='service','integrity');return value;
 }
 function credential(id){
  need(uuid(id),'input');const row=db.prepare(`SELECT r.body_jcs,r.body_digest,r.state,r.revision,c.principal_id,c.approval_id,c.expires_ns,c.stage_deadline_ns
   FROM service_credential_head h JOIN service_credential_revision r USING(credential_id,revision) JOIN service_credential c USING(credential_id) WHERE h.credential_id=?`).raw().get(id);
  need(row,'not_found');const value=unpack(row[0],row[1]);
  need(value.id===id&&value.state===row[2]&&value.revision===String(row[3])&&value.principal_id===row[4]&&value.approval_ref.id===row[5]&&
   value.expires_ns===row[6]&&value.stage_deadline_ns===row[7],'integrity');return value;
 }
 function approval(subject){
  need(subject.state==='active'&&subject.approval_ref,'approval_required');
  const row=db.prepare('SELECT body_jcs,body_digest FROM service_approval WHERE approval_id=? AND principal_id=?').raw().get(subject.approval_ref.id,subject.id);
  need(row,'approval_required');const value=unpack(...row);need(same(ref(value),subject.approval_ref),'integrity');return value;
 }
 function capacity(){need(db.prepare('SELECT count(*) FROM service_identity_operation').pluck().get()<16384,'capacity');}
 function prior(actor,request,kind){
  need(uuid(request.request_id),'input');const row=db.prepare('SELECT kind,request_digest,body_jcs,body_digest FROM service_identity_operation WHERE actor_id=? AND request_id=?').raw().get(actor.principal_id,request.request_id);
  if(!row)return null;need(row[0]===kind&&row[1]===digest(request),'conflict');return unpack(row[2],row[3]).result;
 }
 function commit(id,actor,request,kind,result,now){
  capacity();const value=seal({format:'local-service-identity-operation/1',id,revision:'1',kind,actor,request_id:request.request_id,
   request_digest:digest(request),result,acquisition_ref:now.acquisition});
  written(db.prepare('INSERT INTO service_identity_operation VALUES(?,?,?,?,?,?,?,?)').run(id,actor?.principal_id??null,request.request_id,kind,value.request_digest,now.acquisition.id,canonicalize(value),value.digest));return result;
 }
 function savePrincipal(value,operation,old=null){
  written(db.prepare('INSERT INTO service_principal_revision VALUES(?,?,?,?,?,?)').run(value.id,Number(value.revision),value.state,canonicalize(value),value.digest,operation));
  written(old?db.prepare('UPDATE service_principal_head SET revision=? WHERE principal_id=? AND revision=?').run(Number(value.revision),value.id,Number(old.revision)):
   db.prepare('INSERT INTO service_principal_head VALUES(?,?)').run(value.id,Number(value.revision)));
  need(same(principal(value.id),value),'integrity');
 }
 function saveCredential(value,operation,old=null){
  written(db.prepare('INSERT INTO service_credential_revision VALUES(?,?,?,?,?,?)').run(value.id,Number(value.revision),value.state,canonicalize(value),value.digest,operation));
  written(old?db.prepare('UPDATE service_credential_head SET revision=? WHERE credential_id=? AND revision=?').run(Number(value.revision),value.id,Number(old.revision)):
   db.prepare('INSERT INTO service_credential_head VALUES(?,?)').run(value.id,Number(value.revision)));
  need(same(credential(value.id),value),'integrity');
 }
 function expired(value,now){
  if(['expired','revoked'].includes(value.state))return true;
  const deadline=['staged','proven'].includes(value.state)?BigInt(value.stage_deadline_ns):BigInt(value.expires_ns);
  if(now.upper<deadline)return false;
  const id=crypto.randomUUID(),next=seal({...value,revision:String(Number(value.revision)+1),state:'expired'});
  saveCredential(next,id,value);commit(id,null,{request_id:id,credential_ref:ref(value)},'expire',next,now);return true;
 }
 function allowed(value,now){const subject=principal(value.principal_id),a=approval(subject);
  need(same(value.approval_ref,ref(a))&&now.lower>=BigInt(a.not_before_ns)&&now.lower>=BigInt(value.not_before_ns)&&now.upper<BigInt(a.expires_ns),'approval_required');return {subject,a};}
 function authenticateCredential(id,secret){const row=db.prepare('SELECT verifier,verifier_profile FROM service_credential WHERE credential_id=?').raw().get(id);
  let valid=false;try{valid=verifyOpaqueSecret('service_credential',secret,row?.[0]??invalidVerifier);}catch{}need(row&&row[1]==='opaque-verifier/1'&&valid,'credential_invalid');return credential(id);}
 function throttle(id){
  const tick=process.hrtime.bigint(),minute=60000000000n;if(tick-globalStart>=minute){globalStart=tick;globalCount=0;}
  for(const [key,v] of attempts)if(tick-v.start>=minute)attempts.delete(key);
  need(globalCount<60&&attempts.size<4096,'throttled');++globalCount;const bucket=attempts.get(id)??{start:tick,count:0};
  need(bucket.count<5,'throttled');++bucket.count;attempts.set(id,bucket);
 }
 return Object.freeze({
  ...(Number(service.schema_revision)>=38?deviceEvaluatorSource({db,service,writer,time,management,principal,approval,credential,allowed,expired,authenticateCredential,coreSource,attachCurrent:attachEvaluatorCurrent}):{}),
  ...(Number(service.schema_revision)>=37?serviceAccessTokenStore({db,service,writer,time,management,principal,approval,credential,allowed,expired,authenticateCredential}):{}),
  createServicePrincipal(input,request){fields(request,'request_id,display_name,purpose');
   need(typeof request.display_name==='string'&&request.display_name.length>=1&&request.display_name.length<=256&&!/[\x00-\x1f\x7f]/.test(request.display_name)&&
    typeof request.purpose==='string'&&/^[a-z][a-z0-9_.-]{0,63}$/.test(request.purpose),'input');
   return management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'create');if(old)return old;
    need(db.prepare('SELECT count(*) FROM service_principal_head').pluck().get()<128,'capacity');
    const issuer=db.prepare('SELECT issuer_id,issuer_epoch FROM identity_issuer').raw().get();need(issuer,'issuer');
    const id=crypto.randomUUID(),op=crypto.randomUUID(),value=seal({format:'local-service-principal/1',id,revision:'1',issuer_id:issuer[0],issuer_epoch:issuer[1],
     kind:'service',display_name:request.display_name,purpose:request.purpose,state:'disabled',approval_ref:null});
    written(db.prepare("INSERT INTO subject VALUES(?,?,?,?,'service')").run(crypto.randomUUID(),...issuer,id));savePrincipal(value,op);
    return commit(op,actor,request,'create',value,now);
   });
  },
  getServicePrincipal(input,id){return management(input,'auth.read',()=>principal(id));},
  revokeServicePrincipal(input,request){fields(request,'request_id,principal_id,expected_revision');need(Number(service.schema_revision)>=39,'principal_revocation_migration');
   return management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'revoke');if(old)return old;const subject=principal(request.principal_id);
    need(subject.revision===request.expected_revision,'revision');const op=crypto.randomUUID(),revoked=[];
    if(subject.state==='revoked')return commit(op,actor,request,'revoke',{principal:subject,revoked_credential_refs:revoked},now);
    const rows=db.prepare('SELECT credential_id FROM service_credential WHERE principal_id=? ORDER BY credential_id LIMIT 4097').pluck().all(subject.id);
    need(rows.length<=4096,'capacity');
    for(const id of rows){const value=credential(id);if(['expired','revoked'].includes(value.state))continue;
     const next=seal({...value,revision:String(Number(value.revision)+1),state:'revoked'});saveCredential(next,op,value);revoked.push(ref(next));
    }
    const next=seal({...subject,revision:String(Number(subject.revision)+1),state:'revoked'});savePrincipal(next,op,subject);
    return commit(op,actor,request,'revoke',{principal:next,revoked_credential_refs:revoked},now);
   });
  },
  approveServicePrincipal(input,request){fields(request,'request_id,principal_id,expected_revision,audiences,permissions,device_ids,not_before_ns,expires_ns');
   const before=integer(request.not_before_ns),end=integer(request.expires_ns);need(end>before&&Array.isArray(request.audiences)&&
    request.audiences.length===1&&request.audiences[0]===service.service_id&&Array.isArray(request.permissions)&&request.permissions.length>0&&request.permissions.length<=64&&
    request.permissions.every(p=>typeof p==='string'&&/^[a-z][a-z0-9_.]{0,63}$/.test(p))&&new Set(request.permissions).size===request.permissions.length&&
    Array.isArray(request.device_ids)&&request.device_ids.length<=128&&request.device_ids.every(uuid)&&new Set(request.device_ids).size===request.device_ids.length,'input');
   request={...request,permissions:[...request.permissions].sort(),device_ids:[...request.device_ids].sort()};
   return management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'approve');if(old)return old;
    const subject=principal(request.principal_id);need(subject.revision===request.expected_revision,'revision');need(subject.state==='disabled'&&!subject.approval_ref,'approval_change_unavailable');
    need(now.upper<end,'expired');for(const id of request.device_ids)need(db.prepare('SELECT 1 FROM device_record WHERE device_id=?').pluck().get(id),'scope');
    const op=crypto.randomUUID(),value=seal({format:'local-service-approval/1',id:crypto.randomUUID(),revision:'1',principal_id:subject.id,
     issuer_id:subject.issuer_id,issuer_epoch:subject.issuer_epoch,audiences:request.audiences,permissions:request.permissions,device_ids:request.device_ids,
     not_before_ns:request.not_before_ns,expires_ns:request.expires_ns,approved_by:actor,acquisition_ref:now.acquisition});
    written(db.prepare('INSERT INTO service_approval VALUES(?,?,?,?,?)').run(value.id,subject.id,canonicalize(value),value.digest,op));
    const next=seal({...subject,revision:'2',state:'active',approval_ref:ref(value)});savePrincipal(next,op,subject);return commit(op,actor,request,'approve',{principal:next,approval:value},now);
   });
  },
  createServiceCredential(input,request){fields(request,'request_id,principal_id,expected_revision,approval_ref,expires_ns');const end=integer(request.expires_ns);
   const secret=createOpaqueSecret('service_credential');let delivered=false;
   const result=management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'credential');if(old)return old;
    const subject=principal(request.principal_id),a=approval(subject);need(subject.revision===request.expected_revision&&same(ref(a),request.approval_ref),'revision');
    need(now.lower>=BigInt(a.not_before_ns)&&now.upper<end&&end<=BigInt(a.expires_ns),'expired');
    const existing=db.prepare(`SELECT r.body_jcs,r.body_digest FROM service_credential c JOIN service_credential_head h USING(credential_id)
     JOIN service_credential_revision r USING(credential_id,revision) WHERE c.principal_id=?`).raw().all(subject.id);
    for(const row of existing){const oldCredential=unpack(...row);need(expired(oldCredential,now),'rotation_unavailable');}
    need(db.prepare('SELECT count(*) FROM service_credential').pluck().get()<4096,'capacity');
    const id=crypto.randomUUID(),op=crypto.randomUUID(),stage=now.lower+600000000000n,deadline=stage<end?stage:end;
    const value=seal({format:'local-service-credential/1',id,revision:'1',principal_id:subject.id,approval_ref:ref(a),state:'staged',
     not_before_ns:String(now.lower),expires_ns:String(end),stage_deadline_ns:String(deadline),proof_ref:null,activation_operation_id:null});
    written(db.prepare('INSERT INTO service_credential VALUES(?,?,?,?,?,?,?,?)').run(id,subject.id,a.id,secret.verifier,'opaque-verifier/1',value.expires_ns,value.stage_deadline_ns,op));
    saveCredential(value,op);delivered=true;return commit(op,actor,request,'credential',{credential:value,secret_delivery:'unavailable'},now);
   });
   return delivered?{...result,secret_delivery:'delivered',secret:secret.secret}:result;
  },
  proveServiceCredential(input){fields(input,'credential_id,secret,proof_request_id');need(uuid(input.credential_id)&&uuid(input.proof_request_id),'input');throttle(input.credential_id);
   return deliver(writer(()=>{const row=db.prepare('SELECT verifier,verifier_profile FROM service_credential WHERE credential_id=?').raw().get(input.credential_id);
    let valid=false;try{valid=verifyOpaqueSecret('service_credential',input.secret,row?.[0]??invalidVerifier);}catch{}need(row&&row[1]==='opaque-verifier/1'&&valid,'credential_invalid');
    const now=time(),value=credential(input.credential_id);if(expired(value,now))return {denied:value.state==='revoked'?'service_identity_credential_invalid':'service_identity_credential_expired'};allowed(value,now);
    need(['staged','proven'].includes(value.state),'credential_state');if(value.proof_ref){const row=db.prepare('SELECT body_jcs,body_digest FROM service_credential_proof WHERE credential_id=?').raw().get(value.id);
     need(row,'integrity');const proof=unpack(...row);need(same(ref(proof),value.proof_ref),'integrity');return proof;}
    const op=crypto.randomUUID(),proof=seal({format:'local-service-credential-proof/1',id:crypto.randomUUID(),revision:'1',credential_ref:ref(value),
     proof_request_id:input.proof_request_id,acquisition_ref:now.acquisition,observed_upper_ns:String(now.upper)});
    written(db.prepare('INSERT INTO service_credential_proof VALUES(?,?,?,?,?)').run(proof.id,value.id,canonicalize(proof),proof.digest,op));
    saveCredential(seal({...value,revision:'2',state:'proven',proof_ref:ref(proof)}),op,value);
    return commit(op,null,{request_id:input.proof_request_id,credential_ref:ref(value)},'proof',proof,now);
   }));
  },
  activateServiceCredential(input,request){fields(request,'request_id,credential_id,expected_revision,approval_ref,proof_ref');
   return management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'activate');if(old)return old;const value=credential(request.credential_id);
    if(expired(value,now))return {denied:value.state==='revoked'?'service_identity_credential_invalid':'service_identity_credential_expired'};allowed(value,now);
    need(value.revision===request.expected_revision&&same(value.approval_ref,request.approval_ref),'revision');
    need(value.state==='proven'&&same(value.proof_ref,request.proof_ref),'proof_required');
    const proof=db.prepare('SELECT body_jcs,body_digest FROM service_credential_proof WHERE credential_id=?').raw().get(value.id);
    need(proof&&same(ref(unpack(...proof)),value.proof_ref),'proof_required');const op=crypto.randomUUID(),next=seal({...value,revision:'3',state:'active',activation_operation_id:op});
    saveCredential(next,op,value);return commit(op,actor,request,'activate',next,now);
   });
  },
  getServiceCredential(input,id){return management(input,'auth.read',(_actor,now)=>{const value=credential(id);expired(value,now);return credential(id);});},
  revokeServiceCredential(input,request){fields(request,'request_id,credential_id,expected_revision');
   return management(input,'auth.manage',(actor,now)=>{const old=prior(actor,request,'revoke');if(old)return old;const value=credential(request.credential_id);
    need(value.revision===request.expected_revision,'revision');if(['expired','revoked'].includes(value.state))return commit(crypto.randomUUID(),actor,request,'revoke',value,now);
    const op=crypto.randomUUID(),next=seal({...value,revision:String(Number(value.revision)+1),state:'revoked'});saveCredential(next,op,value);
    return commit(op,actor,request,'revoke',next,now);
   });
  }
 });
}
