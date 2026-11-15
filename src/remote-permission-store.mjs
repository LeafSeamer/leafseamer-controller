import crypto from 'node:crypto';
import {IdentityError} from './identity-error.mjs';
import {canonical,checked,digest,fields,ref,same,seal} from './auth-clock-value.mjs';
import {clockInteger} from './native-clock.mjs';

const need=(ok,reason)=>{if(!ok)throw new IdentityError('remote_authorization_'+reason);};
const uuid=value=>typeof value==='string'&&value.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const scopes=value=>Array.isArray(value)&&value.length<=64&&new Set(value).size===value.length&&value.every(p=>typeof p==='string'&&p.trim()===p&&p.length<=128&&/^[a-z][a-z0-9_.:-]*$/.test(p));
const key=value=>String(value).padStart(20,'0');
const put=result=>need(result.changes===1,'storage');

// 签发方的定向权限上限；接收方仍须独立核验自身授权，不能把本记录当作目标批准。
export function remotePermissionStore({db,service,writer,time,authenticated,authority,pairing}){
 const transaction=()=>need(db.open&&db.inTransaction,'transaction');
 function current(principal,audience){
  transaction();need(uuid(principal)&&uuid(audience)&&audience!==service.service_id,'target');
  const row=db.prepare('SELECT r.body_jcs,r.digest,r.revision,r.id,r.state FROM remote_permission_revision r JOIN remote_permission_head h USING(principal_id,audience,revision) WHERE principal_id=? AND audience=?').raw().get(principal,audience);
  if(!row)return null;const value=checked(JSON.parse(row[0]));
  need(canonical(value)===row[0]&&value.digest===row[1]&&key(value.revision)===row[2]&&value.id===row[3]&&value.state===row[4]&&value.principal_id===principal&&value.audience===audience&&value.service_id===service.service_id&&value.database_instance_id===service.database_instance_id,'integrity');return value;
 }
 function target(reference,audience){
  const value=pairing(reference);need(value.peer_service_id===audience,'pairing_target');return value;
 }
 function manager(input,work){return writer(()=>{
  const now=time(),actor=authenticated(input,now);need(!actor.denied,'management');
  const grant=JSON.parse(canonical(authority.current(actor.session.principal_id)));
  const human=()=>!!db.prepare("SELECT 1 FROM subject WHERE principal_id=? AND kind='human'").pluck().get(actor.session.principal_id);
  need(human()&&grant.state==='active'&&grant.issuer_id===actor.session.issuer_id&&grant.issuer_epoch===actor.session.issuer_epoch&&grant.permissions.includes('auth.manage')&&now.upper<BigInt(actor.session.recent_before_ns),'management');
  const result=work(actor,now),last=time(),again=authenticated(input,last);
  need(!again.denied&&human()&&['principal_id','session_id','issuer_id','issuer_epoch'].every(k=>again.session[k]===actor.session[k])&&
   same(authority.current(actor.session.principal_id),grant)&&last.upper<BigInt(actor.session.recent_before_ns)&&last.upper<BigInt(again.session.recent_before_ns),'management_changed');return result;
 });}
 function resolve(binding){
  transaction();const value=current(binding.principal_id,binding.audience);need(value&&value.state==='active','missing');
  const now=time(),peer=target(value.pairing_ref,binding.audience);
  need(now.lower>=BigInt(value.not_before_ns)&&now.upper<BigInt(value.expires_ns)&&peer.state==='activated','expired');
  const parent=db.prepare(`SELECT s.revision,s.not_before_ns,s.expires_ns,p.revision FROM auth_session s JOIN local_principal p ON p.principal_id=s.principal_id
   JOIN session_refresh_credential c ON c.session_id=s.session_id JOIN subject u ON u.principal_id=p.principal_id
   WHERE s.session_id=? AND c.credential_id=? AND s.principal_id=? AND s.issuer_id=? AND s.issuer_epoch=?
   AND s.state='active' AND p.state='active' AND c.state!='revoked' AND u.kind='human'`).raw().get(binding.session_id,binding.credential_id,binding.principal_id,binding.issuer_id,binding.issuer_epoch);
  need(parent&&String(parent[0])===binding.session_revision&&value.issuer_id===binding.issuer_id&&value.issuer_epoch===binding.issuer_epoch,'parent');
  need(scopes(binding.requested_scopes)&&binding.requested_scopes.length>0&&binding.requested_scopes.every(p=>value.permissions.includes(p)),'denied');
  const {requested_scopes,...identity}=binding;
  return seal({id:value.id,revision:value.revision,...identity,subject_revision:parent[3],policy_revision:value.revision,permissions:[...requested_scopes].sort(),
   scope_digest:digest({service_id:service.service_id,database_instance_id:service.database_instance_id,audience:binding.audience,grant_ref:ref(value),pairing_ref:value.pairing_ref}),
   not_before_ns:String(BigInt(parent[1])>BigInt(value.not_before_ns)?BigInt(parent[1]):BigInt(value.not_before_ns)),
   expires_ns:String(BigInt(parent[2])<BigInt(value.expires_ns)?BigInt(parent[2]):BigInt(value.expires_ns))});
 }
 const api=Object.freeze({
  get(input,principal,audience){return manager(input,()=>current(principal,audience));},
  replace(input,request){
   fields(request,['request_id','principal_id','audience','pairing_ref','expected_revision','permissions','not_before_ns','expires_ns']);
   need(uuid(request.request_id)&&uuid(request.principal_id)&&uuid(request.audience)&&request.audience!==service.service_id&&scopes(request.permissions),'request');
   need(request.expected_revision===null||clockInteger(request.expected_revision)>0n,'revision');
   need(clockInteger(request.not_before_ns)<clockInteger(request.expires_ns),'validity');
   request=JSON.parse(canonical({...request,permissions:[...request.permissions].sort()}));
   return manager(input,(actor,now)=>{
    const prior=db.prepare('SELECT actor_principal_id,request_digest,body_jcs FROM remote_permission_operation WHERE operation_id=?').raw().get(request.request_id);
    if(prior){need(prior[0]===actor.session.principal_id&&prior[1]===digest(request),'conflict');return JSON.parse(prior[2]);}
    const old=current(request.principal_id,request.audience);need((old?.revision??null)===request.expected_revision,'revision');
    need(!old||old.state==='active','pending');
    const peer=target(request.pairing_ref,request.audience),subject=db.prepare("SELECT issuer_id,issuer_epoch FROM subject JOIN local_principal USING(principal_id) WHERE principal_id=? AND kind='human' AND state='active'").raw().get(request.principal_id);
    need(subject&&subject[0]===actor.session.issuer_id&&subject[1]===actor.session.issuer_epoch,'principal');
    need(now.lower>=BigInt(request.not_before_ns)&&now.upper<BigInt(request.expires_ns)&&BigInt(request.not_before_ns)>=BigInt(peer.not_before_ns)&&BigInt(request.expires_ns)<=BigInt(peer.expires_ns),'validity');
    need(db.prepare('SELECT count(*) FROM remote_permission_revision').pluck().get()<16384,'capacity');
    const revision=String(BigInt(old?.revision??'0')+1n);clockInteger(revision);
    const reduced=!!old&&(old.permissions.some(p=>!request.permissions.includes(p))||!same(old.pairing_ref,request.pairing_ref)||BigInt(request.not_before_ns)>BigInt(old.not_before_ns)||BigInt(request.expires_ns)<BigInt(old.expires_ns));
    const value=seal({format:'issuer-remote-permission/1',id:crypto.randomUUID(),revision,service_id:service.service_id,database_instance_id:service.database_instance_id,
     issuer_id:subject[0],issuer_epoch:subject[1],principal_id:request.principal_id,audience:request.audience,pairing_ref:request.pairing_ref,permissions:request.permissions,
     not_before_ns:request.not_before_ns,expires_ns:request.expires_ns,state:reduced?'pending':'active',operation_id:request.request_id});
    const operation=seal({format:'issuer-remote-permission-operation/1',id:request.request_id,revision:'1',principal_id:value.principal_id,audience:value.audience,
     previous_ref:old?ref(old):null,current_ref:ref(value),reduced,propagation:'pending',target_service_ids:[value.audience],acquisition_ref:now.acquisition});
    put(db.prepare('INSERT INTO remote_permission_revision VALUES(?,?,?,?,?,?,?,?)').run(value.principal_id,value.audience,key(value.revision),value.id,value.state,value.digest,canonical(value),request.request_id));
    put(old?db.prepare('UPDATE remote_permission_head SET revision=? WHERE principal_id=? AND audience=? AND revision=?').run(key(value.revision),value.principal_id,value.audience,key(old.revision)):
     db.prepare('INSERT INTO remote_permission_head VALUES(?,?,?)').run(value.principal_id,value.audience,key(value.revision)));
    db.prepare("UPDATE access_token SET state='revoked' WHERE state='active' AND audience=? AND session_id IN(SELECT session_id FROM auth_session WHERE principal_id=?)").run(value.audience,value.principal_id);
    put(db.prepare('INSERT INTO remote_permission_operation VALUES(?,?,?,?,?,?,?,?)').run(request.request_id,actor.session.principal_id,digest(request),value.principal_id,value.audience,key(value.revision),now.acquisition.id,canonical(operation)));
    put(db.prepare('INSERT INTO remote_permission_outbox VALUES(?,?)').run(operation.id,value.audience));
    const last=time();target(request.pairing_ref,request.audience);need(last.lower>=BigInt(value.not_before_ns)&&last.upper<BigInt(value.expires_ns),'expired');return operation;
   });
  }
 });
 return Object.freeze({resolve,api});
}
