import {checked,ref,same,digest} from './auth-clock-value.mjs';
import canonicalize from 'canonicalize';
import {IdentityError} from './identity-crypto.mjs';
const need=(v,c)=>{if(!v)throw new IdentityError('authorization_dependencies_'+c);};
const decode=(bytes,hash=null)=>{const text=bytes.toString(),v=checked(JSON.parse(text));need(canonicalize(v)===text&&(hash===null||hash===v.digest),'integrity');return v;};
const rows=(db,sql,...args)=>{const q=db.prepare(sql),keys=q.columns().map(c=>c.name);return q.raw().all(...args).map(v=>Object.fromEntries(keys.map((k,i)=>[k,v[i]])));};
const one=(db,sql,...args)=>{const result=rows(db,sql,...args);need(result.length===1,'missing');return result[0];};
// 本机已实现的两类来源适配器。成员排序只供确定性比较，不声称是事件发生顺序。
export function collectAuthorizationDependencies(db,service,role,source){
 need(db.inTransaction,'writer');need(['manual','evaluator'].includes(role),'role');
 const identity=role==='manual'?source.holder:{issuer_id:source.issuer_id,issuer_epoch:source.issuer_epoch,principal_id:source.principal_id};
 need(identity&&typeof identity.principal_id==='string','binding');
 const issuer=one(db,'SELECT issuer_id,issuer_epoch FROM identity_issuer');need(issuer.issuer_id===identity.issuer_id&&issuer.issuer_epoch===identity.issuer_epoch,'local_issuer');
 const subject=one(db,'SELECT issuer_id,issuer_epoch,principal_id,kind FROM subject WHERE principal_id=?',identity.principal_id);
 need(subject.issuer_id===issuer.issuer_id&&subject.issuer_epoch===issuer.issuer_epoch&&subject.kind===(role==='manual'?'human':'service'),'binding');
 const records=[{kind:'issuer',value:issuer},{kind:'subject',value:subject}],events=[],denied=[];
 const reject=(condition,kind)=>{if(condition)denied.push(kind);};
 const operation=(table,id)=>{const op=one(db,`SELECT operation_id,body_jcs,body_digest FROM ${table} WHERE operation_id=?`,id),v=decode(op.body_jcs,op.body_digest);need(v.id===op.operation_id,'integrity');return ref(v);};
 const history=(table,keyColumn,key)=>{
  const found=rows(db,`SELECT revision,state,body_jcs,body_digest,operation_id FROM ${table} WHERE ${keyColumn}=? ORDER BY revision LIMIT 4097`,key);need(found.length>0&&found.length<=4096,'capacity');
  return found.map((r,i)=>{const v=decode(r.body_jcs,r.body_digest);need(v.id===key&&v.revision===String(r.revision)&&v.state===r.state&&r.revision===i+1,'history');
   return {value:v,operation_ref:operation('service_identity_operation',r.operation_id)};});
 };
 if(role==='manual'){
  const p=one(db,'SELECT principal_id,state,revision FROM local_principal WHERE principal_id=?',identity.principal_id);
  const s=one(db,'SELECT session_id,principal_id,issuer_id,issuer_epoch,state,revision,terminal_operation_id FROM auth_session WHERE session_id=?',source.session_id);
  const c=one(db,'SELECT credential_id,session_id,state,consumed_tx_id FROM session_refresh_credential WHERE credential_id=?',source.credential_id);
  const t=one(db,'SELECT token_id,session_id,credential_id,audience,state,authorization_digest FROM access_token WHERE token_id=?',source.token_id);
  need(s.principal_id===p.principal_id&&s.issuer_id===issuer.issuer_id&&s.issuer_epoch===issuer.issuer_epoch&&c.session_id===s.session_id&&
   t.session_id===s.session_id&&t.credential_id===c.credential_id&&t.audience===service.service_id&&t.authorization_digest===source.authorization.digest,'binding');
  records.push({kind:'principal',value:p},{kind:'session',value:s},{kind:'credential',value:c},{kind:'access_token',value:t});
  reject(p.state!=='active','principal');reject(s.state!=='active','session');reject(c.state==='revoked','credential');reject(t.state!=='active','access_token');
  const current=one(db,'SELECT r.id,r.revision,r.state,r.digest,r.body FROM local_permission_head h JOIN local_permission_revision r ON r.id=h.id WHERE h.principal_id=?',p.principal_id),policy=decode(current.body,current.digest);
  need(policy.principal_id===p.principal_id&&policy.id===current.id&&policy.revision===String(BigInt(current.revision))&&policy.state===current.state,'integrity');
  records.push({kind:'policy',value:{ref:ref(policy),state:policy.state}});reject(policy.state!=='active'||!same(ref(policy),source.policy_ref),'policy');
  const revocations=rows(db,'SELECT r.operation_id,r.revision_floor,r.digest,r.body,f.revision_floor AS floor_revision,f.operation_id AS floor_operation FROM session_revocation r LEFT JOIN session_revocation_floor f ON f.session_id=r.session_id WHERE r.session_id=?',s.session_id);
  need(revocations.length<=1,'integrity');for(const r of revocations){const v=decode(r.body,r.digest);need(v.id===r.operation_id&&v.session_id===s.session_id&&v.revision_floor===String(r.revision_floor)&&r.floor_revision===r.revision_floor&&r.floor_operation===r.operation_id,'integrity');
   events.push({kind:'session',target_id:s.session_id,revision_floor:v.revision_floor,event_ref:ref(v)});reject(BigInt(source.authorization.session_revision)<BigInt(v.revision_floor),'session_floor');}
  const floor=rows(db,'SELECT operation_id FROM session_revocation_floor WHERE session_id=?',s.session_id);need(floor.length===revocations.length,'integrity');
  const changes=rows(db,'SELECT operation_id,revision,grant_id,body FROM local_permission_operation WHERE principal_id=? ORDER BY revision LIMIT 4097',p.principal_id);need(changes.length<=4096,'capacity');
  for(const r of changes){const v=decode(r.body);need(v.id===r.operation_id&&v.principal_id===p.principal_id&&v.current_ref.id===r.grant_id&&v.current_ref.revision===String(BigInt(r.revision)),'integrity');
   if(v.reduced){events.push({kind:'policy',target_id:p.principal_id,revision_floor:v.current_ref.revision,event_ref:ref(v)});reject(BigInt(source.policy_ref.revision)<BigInt(v.current_ref.revision),'policy_floor');}}
 }else{
  const principalHistory=history('service_principal_revision','principal_id',identity.principal_id),p=principalHistory.at(-1).value;
  const ph=one(db,'SELECT revision FROM service_principal_head WHERE principal_id=?',p.id);need(String(ph.revision)===p.revision,'head');
  const credentialHistory=history('service_credential_revision','credential_id',source.credential_ref.id),c=credentialHistory.at(-1).value;
  const ch=one(db,'SELECT revision FROM service_credential_head WHERE credential_id=?',c.id);need(String(ch.revision)===c.revision,'head');
  need(c.principal_id===p.id&&p.issuer_id===issuer.issuer_id&&p.issuer_epoch===issuer.issuer_epoch&&same(c.approval_ref,source.approval_ref),'binding');
  records.push({kind:'principal',value:{ref:ref(p),state:p.state}},{kind:'credential',value:{ref:ref(c),state:c.state}});
  reject(p.state!=='active'||!same(ref(p),source.subject_ref),'principal');reject(c.state!=='active'||!same(ref(c),source.credential_ref),'credential');
  for(const [kind,items] of [['principal',principalHistory],['credential',credentialHistory]])for(const {value,operation_ref} of items){
   if(['revoked','expired'].includes(value.state))events.push({kind,target_id:value.id,state:value.state,event_ref:ref(value),operation_ref});
  }
  const a=one(db,'SELECT principal_id,body_jcs,body_digest,operation_id FROM service_approval WHERE approval_id=?',source.approval_ref.id),approval=decode(a.body_jcs,a.body_digest);
  need(a.principal_id===p.id&&approval.principal_id===p.id&&same(ref(approval),source.approval_ref)&&same(p.approval_ref,source.approval_ref),'binding');
  records.push({kind:'approval',value:{ref:ref(approval),operation_ref:operation('service_identity_operation',a.operation_id)}});
  const pr=one(db,'SELECT principal_id,approval_id,body_jcs,body_digest,operation_id FROM device_evaluator_policy WHERE policy_id=?',source.policy_ref.id),policy=decode(pr.body_jcs,pr.body_digest);
  need(pr.principal_id===p.id&&pr.approval_id===approval.id&&same(ref(policy),source.policy_ref)&&policy.service_id===service.service_id&&policy.database_instance_id===service.database_instance_id,'binding');
  records.push({kind:'policy',value:{ref:ref(policy),operation_ref:operation('device_evaluator_operation',pr.operation_id)}});
  const revocations=rows(db,'SELECT revocation_id,body_jcs,body_digest,operation_id FROM device_evaluator_policy_revocation WHERE policy_id=?',policy.id);need(revocations.length<=1,'integrity');
  for(const r of revocations){const v=decode(r.body_jcs,r.body_digest);need(v.id===r.revocation_id&&same(v.policy_ref,ref(policy)),'integrity');events.push({kind:'policy',target_id:policy.id,event_ref:ref(v),operation_ref:operation('device_evaluator_operation',r.operation_id)});}
  reject(revocations.length!==0,'policy');
 }
 records.sort((a,b)=>a.kind<b.kind?-1:a.kind>b.kind?1:0);events.sort((a,b)=>{const x=canonicalize(a),y=canonicalize(b);return x<y?-1:x>y?1:0;});
 const body={format:'local-device-authorization-dependencies/1',scope:{authority_service_id:service.service_id,database_instance_id:service.database_instance_id},
  role,device_id:role==='manual'?source.binding.device_id:source.device_id,identity,records,events,denied:[...new Set(denied)].sort(),
  result:denied.length?'denied':'no_matching_denial'};
 need(Buffer.byteLength(canonicalize(body))<=32768,'capacity');return {...body,digest:digest(body)};
}
export function currentAuthorizationDependencies(db,service,role,source){
 need(source.authorization_dependencies,'missing');const current=collectAuthorizationDependencies(db,service,role,source);
 need(same(current,source.authorization_dependencies),'changed');need(current.result==='no_matching_denial','denied');return current;
}
