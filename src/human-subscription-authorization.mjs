import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';

const need=(ok,code)=>{if(!ok)throw new IdentityError('subscription_'+code);};
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)&&value.trim()===value;
const ownerFields=value=>({issuer_id:value.issuer_id,issuer_epoch:value.issuer_epoch,principal_id:value.principal_id,session_id:value.session_id});
const owner=(proof,client_instance_id)=>({kind:'human',...ownerFields(proof),client_instance_id});
const limit=65536;

export function humanSubscriptionAuthority({db,service,time,authority,eventScopes,authorizeToken,tokenWithCsrf,contextCurrent}){
 const reader=db.prepare('SELECT body_jcs,body_digest FROM status_scope_reader WHERE scope_id=? AND principal_id=? ORDER BY revision DESC LIMIT 1').raw();
 const byRequest=db.prepare('SELECT body_jcs,body_digest FROM status_scope_reader WHERE request_id=?').raw();
 function unpack(row){
  const value=JSON.parse(row[0]);need(canonical(value)===row[0]&&digest(value)===row[1],'integrity');return value;
 }
 function activeReader(scope_ref,principal_id){
  const row=reader.get(scope_ref.entity_id,principal_id);
  need(row,'forbidden');const entry=unpack(row);
  need(entry.state==='active'&&same(entry.scope_ref,scope_ref),'forbidden');
  return row[1];
 }
 function current(saved){
  const actor=saved.owner;
  const session=db.prepare(`SELECT s.session_id,s.issuer_id,s.issuer_epoch,s.principal_id,s.state,s.expires_ns,s.idle_before_ns
   FROM auth_session s JOIN local_principal p USING(principal_id) WHERE s.session_id=? AND p.state='active'`).get(actor.session_id);
  need(session?.state==='active'&&same(ownerFields(session),ownerFields(actor)),'revoked');
  const grant=authority.current(actor.principal_id);
  need(grant.state==='active'&&grant.digest===saved.policy_digest&&grant.permissions.includes('status.read'),'revoked');
  need(activeReader(saved.scope_ref,actor.principal_id)===saved.reader_digest,'revoked');
  const selected=eventScopes.currentInTransaction(saved.scope_ref);
  need(selected.registration.purpose==='status_projection'&&selected.registration.profile.owner_kinds.includes('human'),'forbidden');
  const now=time(),expires=[session.expires_ns,session.idle_before_ns].map(BigInt).reduce((a,b)=>a<b?a:b);
  need(now.upper<expires,'expired');
  return {authorization:saved,expires_ns:String(expires),source_frontiers:selected.current_frontiers,acquisition_ref:now.acquisition};
 }
 return Object.freeze({
  owner,
  current,
  authenticate(token,csrf,write){
   const proof=write?tokenWithCsrf(token,csrf):authorizeToken(token,service.service_id);
   if(proof.denied)return proof;
   need(proof.principal_kind==='human'&&proof.permissions.includes('status.read'),'forbidden');
   return proof;
  },
  createProof(proof,request){
   const {scope_ref}=eventScopes.matchStatusInTransaction(request.scope),grant=authority.current(proof.principal_id);
   need(grant.revision===proof.policy_revision,'revoked');
   return current({owner:owner(proof,request.client_instance_id),scope_ref,policy_digest:grant.digest,
    reader_digest:activeReader(scope_ref,proof.principal_id)});
  },
  consumeContext(token,context_id){
   const context=contextCurrent(token,context_id,'createSubscription');
   if(context.denied)return context;
   const updated=db.prepare("UPDATE request_context SET used_count=used_count+1 WHERE context_id=? AND state='active' AND used_count<max_unique_requests").run(context_id);
   need(updated.changes===1,'capacity');return context;
  },
  setReader(actor,request){
   need(request&&Object.keys(request).sort().join(',')==='enabled,expected_revision,principal_id,request_id,scope_ref'&&
    uuid(request.request_id)&&uuid(request.principal_id)&&typeof request.enabled==='boolean'&&
    typeof request.expected_revision==='string'&&/^(0|[1-9][0-9]{0,4})$/.test(request.expected_revision)&&Number(request.expected_revision)<limit,'input');
   const requestDigest=digest(request),old=byRequest.get(request.request_id);
   if(old){
    const original=unpack(old);need(original.request_digest===requestDigest&&original.actor.principal_id===actor.principal_id&&
     original.actor.issuer_id===actor.issuer_id&&original.actor.issuer_epoch===actor.issuer_epoch,'conflict');
    return original;
   }
   const selected=eventScopes.currentInTransaction(request.scope_ref);
   need(selected.registration.purpose==='status_projection'&&selected.registration.profile.owner_kinds.includes('human'),'forbidden');
   const principal=db.prepare("SELECT 1 FROM local_principal p JOIN subject s USING(principal_id) WHERE p.principal_id=? AND s.kind='human' AND p.state='active'").pluck().get(request.principal_id);
   need(principal,'not_found');
   const prior=reader.get(request.scope_ref.entity_id,request.principal_id),state=request.enabled?'active':'revoked',number=Number(request.expected_revision)+1;
   const previous=prior?unpack(prior):null;
   need((previous?.revision??'0')===request.expected_revision&&state!==(previous?.state??'revoked'),'revision');
   need(db.prepare('SELECT count(*) FROM status_scope_reader').pluck().get()<16384,'capacity');
   const value={scope_ref:request.scope_ref,principal_id:request.principal_id,request_id:request.request_id,request_digest:requestDigest,
    revision:String(number),state,actor:{issuer_id:actor.issuer_id,issuer_epoch:actor.issuer_epoch,principal_id:actor.principal_id}};
   const inserted=db.prepare('INSERT INTO status_scope_reader VALUES(?,?,?,?,?,?,?)').run(request.scope_ref.entity_id,request.principal_id,number,
    request.request_id,state,canonical(value),digest(value));
   need(inserted.changes===1,'storage');return value;
  }
 });
}
