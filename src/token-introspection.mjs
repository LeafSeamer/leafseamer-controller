import crypto from 'node:crypto';
import {IdentityError} from './identity-error.mjs';
import {clockInteger} from './native-clock.mjs';
import {same} from './auth-clock-value.mjs';
const need=(ok,code)=>{if(!ok)throw new IdentityError('introspection_'+code);};
const inactive=()=>({active:false,snapshot:null,recent_authentication:null});
const minimum=(...values)=>values.reduce((a,b)=>a<b?a:b);
const timestamp=(ns,ceil=false)=>new Date(Number((ns+(ceil?999999n:0n))/1000000n)).toISOString();
const denied=new Set(['token_invalid','token_expired','token_time_invalid','remote_authorization_missing','remote_authorization_denied','remote_authorization_expired','remote_authorization_parent']);

// 仅由指定签发方同库会话服务装配；对端必须是当前TLS连接，不能用请求正文充当服务身份。
export function tokenIntrospection({db,service,writer,time,authorizeToken,pairings}){
 return (bindingId,socket,request,expiresBefore=null)=>writer(()=>{
  const allowed=pairings().authorizeIntrospectionInTransaction(bindingId,socket),audience=allowed.peer.service_id;
  need(request.audience===audience,'audience');
  const watermark=()=>{const row=db.prepare('SELECT issuer_id,issuer_epoch,CAST(revision AS TEXT) FROM issuer_authorization_watermark WHERE singleton=1').raw().get();need(row,'issuer');return row;};
  const required=clockInteger(request.required_revision),initial=watermark();
  need(required<=BigInt(initial[2]),'revision');
  const match=/^v1\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(request.token);if(!match||match[0]!==request.token)return inactive();
  let proof;
  try{proof=authorizeToken({token_id:match[1],secret:match[2]},audience);}catch(error){if(denied.has(error.code))return inactive();throw error;}
  if(proof.denied)return inactive();
  const session=db.prepare('SELECT revision,not_before_ns,recent_before_ns FROM auth_session WHERE session_id=? AND principal_id=?').raw().get(proof.session_id,proof.principal_id);
  const subject=db.prepare("SELECT revision FROM local_principal WHERE principal_id=? AND state='active'").pluck().get(proof.principal_id);
  const now=time(),issuer=watermark();need(session&&subject&&proof.issuer_id===issuer[0]&&proof.issuer_epoch===issuer[1],'identity');
  const expiry=minimum(BigInt(proof.expires_ns),BigInt(proof.session_expires_ns),BigInt(proof.session_idle_before_ns),now.lower+2000000000n,
   expiresBefore===null?(1n<<64n)-1n:clockInteger(expiresBefore))/1000000n*1000000n;
  need(now.upper<expiry&&(now.lower+999999n)/1000000n*1000000n<expiry,'expired');
  const result={active:true,snapshot:{snapshot_id:crypto.randomUUID(),issuer_id:issuer[0],issuer_epoch:issuer[1],issuer_revision:String(issuer[2]),audience,
   principal_kind:'human',principal_id:proof.principal_id,session_id:proof.session_id,credential_id:proof.credential_id,subject_revision:String(subject),session_revision:String(session[0]),
   policy_revision:proof.policy_revision,permissions:proof.permissions,scope_digest:proof.scope_digest,challenge_id:request.challenge_id,
   validity:{not_before:timestamp(now.lower,true),expires_at:timestamp(expiry)},fresh_for_ms:2000,state:'active'},
   recent_authentication:{format:'issuer-recent-authentication/1',session_id:proof.session_id,session_revision:String(session[0]),not_before:timestamp(BigInt(session[1]),true),expires_at:timestamp(BigInt(session[2]))}};
  const last=time(),current=pairings().authorizeIntrospectionInTransaction(bindingId,socket);
  need(last.upper<expiry&&same(current.record,allowed.record)&&same(watermark(),issuer),'changed');return result;
 });
}
