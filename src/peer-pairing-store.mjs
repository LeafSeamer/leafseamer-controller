import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {canonical, digest, same,seal,ref} from './auth-clock-value.mjs';
import {createOpaqueSecret,verifyOpaqueSecret} from './identity-crypto.mjs';
import {pairingNeed as need,pairingFields as fields,pairingUuid as uuid,pairingInteger as integer,pairingTranscript,sealPairing,pairingCertificate} from './peer-pairing-value.mjs';

// 本机受信装配提供配置；普通请求只能引用预登记的配置摘要，不能导入CA或指定回调地址。
export function peerPairingStore({db,service,bootId,writer,time,authenticated,authority}){
 let configuration=null;
 const write=result=>need(result.changes===1,'storage');
 function read(id,revision=null){
  uuid(id);const row=revision===null?db.prepare('SELECT r.body_jcs,r.body_digest FROM peer_pairing_revision r JOIN peer_pairing_head h USING(binding_id,revision) WHERE binding_id=?').raw().get(id):
   db.prepare('SELECT body_jcs,body_digest FROM peer_pairing_revision WHERE binding_id=? AND revision=?').raw().get(id,Number(revision));
  need(row,'not_found');const value=JSON.parse(row[0]);need(canonical(value)===row[0]&&sealPairing(value).digest===row[1]&&value.digest===row[1]&&value.binding_id===id,'integrity');return value;
 }
 function save(value,previous=null){
  value=sealPairing(value);write(db.prepare('INSERT INTO peer_pairing_revision VALUES(?,?,?,?,?,?,?,?,?)').run(value.binding_id,Number(value.revision),value.transcript.pair_attempt_id,
   value.peer_service_id,value.service_boot_id,value.state,value.transcript_digest,canonical(value),value.digest));
  write(previous?db.prepare('UPDATE peer_pairing_head SET revision=? WHERE binding_id=? AND revision=?').run(Number(value.revision),value.binding_id,Number(previous.revision)):
   db.prepare('INSERT INTO peer_pairing_head VALUES(?,?)').run(value.binding_id,Number(value.revision)));
  need(same(read(value.binding_id),value),'integrity');return value;
 }
 function manager(input,work,finish=()=>{}){return writer(()=>{
  const now=time(),found=authenticated(input,now);need(!found.denied,'management_denied');const grant=authority.current(found.session.principal_id);
  need(db.prepare("SELECT 1 FROM subject WHERE principal_id=? AND kind='human'").pluck().get(found.session.principal_id)&&grant.state==='active'&&
   grant.issuer_id===found.session.issuer_id&&grant.issuer_epoch===found.session.issuer_epoch&&grant.permissions.includes('auth.manage')&&now.upper<BigInt(found.session.recent_before_ns),'management_denied');
  const result=work(found,now),last=time(),current=authenticated(input,last);need(!current.denied&&same(authority.current(found.session.principal_id),grant)&&last.upper<BigInt(found.session.recent_before_ns),'management_changed');finish(result,last);return result;
 });}
 function prior(input,actor){uuid(input.request_id);const row=db.prepare('SELECT principal_id,request_digest,binding_id,revision FROM peer_pairing_operation WHERE request_id=?').raw().get(input.request_id);
  if(!row)return null;need(row[0]===actor.session.principal_id&&row[1]===digest(input),'conflict');return read(row[2],row[3]);}
 function commit(input,actor,now,value){write(db.prepare('INSERT INTO peer_pairing_operation VALUES(?,?,?,?,?,?)').run(input.request_id,actor.session.principal_id,digest(input),value.binding_id,Number(value.revision),now.acquisition.id));return value;}
 function configured(transcript){
  need(configuration,'configuration_missing');const local=transcript.parties.find(p=>p.service_id===service.service_id),peer=transcript.parties.find(p=>p.service_id!==service.service_id);
  need(local&&peer&&local.database_instance_id===service.database_instance_id&&local.service_kind==='controller','local_identity');
  const issuer=db.prepare('SELECT issuer_id,issuer_epoch FROM identity_issuer').raw().get();need(issuer&&local.issuer_id===issuer[0]&&local.issuer_epoch===issuer[1],'local_identity');
  const match=(party,config)=>config&&['service_id','database_instance_id','service_kind','issuer_id','issuer_epoch','credential_id','certificate_der_sha256','spki_sha256','trust_bundle_digest','endpoint_config_digest'].every(k=>party[k]===config[k]);
  need(match(local,configuration.local)&&match(peer,configuration.peers.find(p=>p.service_id===peer.service_id)),'configuration_changed');return {local,peer};
 }
 function timing(value,now){
  need(now.lower>=BigInt(value.not_before_ns)&&now.upper<BigInt(value.expires_ns),'expired');
  if(value.state!=='activated')need(value.service_boot_id===bootId&&same(value.runtime_domain_ref,now.runtime_domain_ref)&&now.tick<BigInt(value.attempt_deadline_tick_ns),'expired');
 }
 function expirePending(now){
  for(const [id]of db.prepare("SELECT binding_id FROM peer_pairing_revision r JOIN peer_pairing_head h USING(binding_id,revision) WHERE state IN ('staged','proving','proved')").raw().all()){
   const value=read(id);
   if(value.service_boot_id!==bootId||!same(value.runtime_domain_ref,now.runtime_domain_ref)||now.upper>=BigInt(value.attempt_expires_ns)||now.tick>=BigInt(value.attempt_deadline_tick_ns))
    save({...value,revision:String(BigInt(value.revision)+1n),state:'expired'},value);
  }
 }
 function currentPeer(id){const value=read(id);configured(value.transcript);need(['staged','proving','proved','activated'].includes(value.state),'state');const now=time();timing(value,now);
  if(value.state!=='activated')need(now.upper<BigInt(value.attempt_expires_ns),'expired');return {value,now};}
 function channel(value,socket){
  need(socket instanceof TLSSocket&&socket.authorized&&socket.getProtocol()==='TLSv1.3'&&!socket.isSessionReused(),'tls');
  const peer=value.transcript.parties.find(p=>p.service_id===value.peer_service_id),actual=socket.getPeerX509Certificate();
  need(actual&&same(pairingCertificate(actual.raw),{certificate_der_sha256:peer.certificate_der_sha256,spki_sha256:peer.spki_sha256}),'certificate_binding');return peer;
 }
 function proofs(binding){return db.prepare('SELECT body_jcs,body_digest FROM peer_pairing_proof WHERE binding_id=? ORDER BY direction').raw().all(binding).map(([text,hash])=>{
  const value=JSON.parse(text),{digest:old,...body}=value;need(canonical(value)===text&&old===hash&&digest(body)===hash,'integrity');return value;});}
 function saveProof(value,direction,details,now){
  const proof=seal({format:'leafseamer.peer-pairing-proof/1',id:crypto.randomUUID(),revision:'1',binding_id:value.binding_id,pair_attempt_id:value.transcript.pair_attempt_id,
   transcript_digest:value.transcript_digest,direction,service_boot_id:bootId,peer_service_id:value.peer_service_id,acquisition_ref:now.acquisition,...details});
  write(db.prepare('INSERT INTO peer_pairing_proof VALUES(?,?,?,?,?)').run(proof.id,value.binding_id,direction,canonical(proof),proof.digest));
  const all=proofs(value.binding_id);save({...value,revision:String(BigInt(value.revision)+1n),proof_refs:all.map(p=>({direction:p.direction,ref:ref(p)})),state:all.length===2?'proved':'proving'},value);currentPeer(value.binding_id);return proof;
 }
 return Object.freeze({
  bindConfiguration(value){need(!configuration,'configuration_bound');fields(value,'local,peers');need(Array.isArray(value.peers)&&value.peers.length<=64,'configuration');
   const fixed=JSON.parse(canonical(value));need(fixed.local.service_id===service.service_id&&new Set(fixed.peers.map(p=>p.service_id)).size===fixed.peers.length,'configuration');configuration=fixed;},
  stage(input,request){fields(request,'request_id,transcript');const transcript=pairingTranscript(request.transcript);return manager(input,(actor,now)=>{
   const old=prior(request,actor);if(old)return old;const {local,peer}=configured(transcript);
   expirePending(now);
   need(!db.prepare('SELECT 1 FROM peer_pairing_head WHERE binding_id=?').pluck().get(local.binding_id),'binding_exists');
   need(!db.prepare('SELECT 1 FROM peer_pairing_revision WHERE attempt_id=?').pluck().get(transcript.pair_attempt_id),'attempt_exists');
   need(db.prepare("SELECT count(*) FROM peer_pairing_revision r JOIN peer_pairing_head h USING(binding_id,revision) WHERE state IN ('staged','proving','proved')").pluck().get()<16,'capacity');
   const begin=[local,peer].map(p=>BigInt(p.not_before_ns)).reduce((a,b)=>a>b?a:b),end=[local,peer].map(p=>BigInt(p.expires_ns)).reduce((a,b)=>a<b?a:b);
   need(now.lower>=begin&&now.upper<end,'validity');const attemptEnd=end<now.lower+600000000000n?end:now.lower+600000000000n;
   const value=save({format:'leafseamer.peer-pairing-record/1',binding_id:local.binding_id,revision:'1',peer_service_id:peer.service_id,service_boot_id:bootId,state:'staged',
    transcript,transcript_digest:digest(transcript),not_before_ns:String(begin),expires_ns:String(end),attempt_expires_ns:String(attemptEnd),
    runtime_domain_ref:now.runtime_domain_ref,attempt_deadline_tick_ns:String(now.tick+(attemptEnd-now.upper)),proof_refs:[],approval_ref:null});
   return commit(request,actor,now,value);
  });},
  get(input,id){return manager(input,(_actor,now)=>{expirePending(now);return read(id);});},
  reject(input,request){fields(request,'request_id,binding_id,expected_revision');uuid(request.binding_id);integer(request.expected_revision);return manager(input,(actor,now)=>{
   const old=prior(request,actor);if(old)return old;const current=read(request.binding_id);need(current.revision===request.expected_revision,'stale');
   need(['staged','proving','proved'].includes(current.state),'terminal');const value=save({...current,revision:String(BigInt(current.revision)+1n),state:'rejected'},current);return commit(request,actor,now,value);
  });},
  currentPending(id){return writer(()=>currentPeer(id).value);},
  peerProofs(id,socket){return writer(()=>{const {value}=currentPeer(id);channel(value,socket);return proofs(id);});},
  challenge(id,socket,request){fields(request,'pair_attempt_id,transcript_digest');return writer(()=>{
   const {value,now}=currentPeer(id);channel(value,socket);need(value.state!=='activated'&&value.transcript.pair_attempt_id===request.pair_attempt_id&&value.transcript_digest===request.transcript_digest,'binding');
   need(!proofs(id).some(p=>p.direction==='inbound'),'already_proven');
   need(db.prepare('SELECT count(*) FROM peer_pairing_challenge WHERE binding_id=?').pluck().get(id)<64&&db.prepare('SELECT count(*) FROM peer_pairing_challenge').pluck().get()<4096,'capacity');
   db.prepare("UPDATE peer_pairing_challenge SET state='superseded' WHERE binding_id=? AND state='pending'").run(id);
   const material=createOpaqueSecret('pairing_challenge'),challenge_id=crypto.randomUUID(),end=BigInt(value.attempt_expires_ns)<now.lower+60000000000n?BigInt(value.attempt_expires_ns):now.lower+60000000000n;
   need(end>now.upper,'expired');const before=now.tick+(end-now.upper);
   write(db.prepare("INSERT INTO peer_pairing_challenge VALUES(?,?,?,?,?,'pending')").run(challenge_id,id,material.verifier,String(before),String(end)));
   return {format:'leafseamer.peer-pairing-challenge/1',challenge_id,challenge:material.secret,pair_attempt_id:request.pair_attempt_id,transcript_digest:request.transcript_digest};
  });},
  consumeProof(id,socket,request){fields(request,'challenge_id,challenge,pair_attempt_id,transcript_digest');uuid(request.challenge_id);return writer(()=>{
   const {value,now}=currentPeer(id);channel(value,socket);need(value.transcript.pair_attempt_id===request.pair_attempt_id&&value.transcript_digest===request.transcript_digest,'binding');
   const row=db.prepare('SELECT verifier,expires_tick_ns,expires_ns,state FROM peer_pairing_challenge WHERE challenge_id=? AND binding_id=?').raw().get(request.challenge_id,id);
   need(row&&verifyOpaqueSecret('pairing_challenge',request.challenge,row[0]),'challenge');
   if(row[3]==='consumed'){const old=proofs(id).find(p=>p.direction==='inbound');need(old&&old.challenge_id===request.challenge_id,'integrity');return old;}
   need(value.state!=='activated'&&row[3]==='pending'&&now.tick<BigInt(row[1])&&now.upper<BigInt(row[2]),'challenge_expired');
   write(db.prepare("UPDATE peer_pairing_challenge SET state='consumed' WHERE challenge_id=? AND state='pending'").run(request.challenge_id));
   return saveProof(value,'inbound',{challenge_id:request.challenge_id,peer_proof_ref:null},now);
  });},
  recordOutbound(id,socket,proof){return writer(()=>{
   const {value,now}=currentPeer(id),peer=channel(value,socket);fields(proof,'format,id,revision,digest,binding_id,pair_attempt_id,transcript_digest,direction,service_boot_id,peer_service_id,acquisition_ref,challenge_id,peer_proof_ref');
   const {digest:hash,...body}=proof;uuid(proof.id);uuid(proof.challenge_id);
   need(hash===digest(body)&&proof.format==='leafseamer.peer-pairing-proof/1'&&proof.revision==='1'&&proof.direction==='inbound'&&proof.peer_proof_ref===null&&proof.binding_id===peer.binding_id&&proof.peer_service_id===service.service_id&&
    proof.pair_attempt_id===value.transcript.pair_attempt_id&&proof.transcript_digest===value.transcript_digest,'proof_binding');
   const old=proofs(id).find(p=>p.direction==='outbound');if(old){need(same(old.peer_proof_ref,ref(proof)),'proof_conflict');return old;}
   need(value.state!=='activated','state');return saveProof(value,'outbound',{challenge_id:proof.challenge_id,peer_proof_ref:ref(proof)},now);
  });},
  activate(input,request){fields(request,'request_id,binding_id,expected_revision,transcript_digest');let fresh=false;return manager(input,(actor,now)=>{
   const old=prior(request,actor);if(old)return old;const value=read(request.binding_id);configured(value.transcript);timing(value,now);
   need(value.state==='proved'&&value.revision===request.expected_revision&&value.transcript_digest===request.transcript_digest&&now.upper<BigInt(value.attempt_expires_ns),'activation');
   const all=proofs(value.binding_id);need(all.length===2&&same(value.proof_refs,all.map(p=>({direction:p.direction,ref:ref(p)}))),'proof_required');
   const approval={request_id:request.request_id,principal_id:actor.session.principal_id,authorization_ref:ref(authority.current(actor.session.principal_id)),acquisition_ref:now.acquisition};
   const result=save({...value,revision:String(BigInt(value.revision)+1n),state:'activated',approval_ref:{id:request.request_id,revision:'1',digest:digest(approval)},approval},value);
   fresh=true;return commit(request,actor,now,result);
  },(result,last)=>{
   // 幂等查回原件不重新激活；新激活必须在事务末尾仍处于原attempt窗口。
   if(fresh){timing({...result,state:'proved'},last);need(last.upper<BigInt(result.attempt_expires_ns),'expired');}
  });},
  revoke(input,request){fields(request,'request_id,binding_id,expected_revision');return manager(input,(actor,now)=>{
   const old=prior(request,actor);if(old)return old;const value=read(request.binding_id);need(value.state==='activated'&&value.revision===request.expected_revision,'stale');
   return commit(request,actor,now,save({...value,revision:String(BigInt(value.revision)+1n),state:'revoked'},value));
  });},
 });
}
