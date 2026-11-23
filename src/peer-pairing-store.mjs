import crypto from 'node:crypto';
import {TLSSocket} from 'node:tls';
import {canonical, digest, same,seal,ref} from './auth-clock-value.mjs';
import {createOpaqueSecret,verifyOpaqueSecret} from './opaque-secret.mjs';
import {pairingNeed as need,pairingFields as fields,pairingUuid as uuid,pairingInteger as integer,pairingTranscript,sealPairing,pairingCertificate} from './peer-pairing-value.mjs';
import {firstPairingFormat,verifyFirstPairingAuthorization} from './first-pairing-authorization.mjs';

// 本机受信装配提供配置；普通请求只能引用预登记的配置摘要，不能导入CA或指定回调地址。
export function peerPairingStore({db,service,bootId,writer,time,authenticated,authority,firstPairing=null,
 issuerIdentity=()=>db.prepare('SELECT issuer_id,issuer_epoch FROM identity_issuer').raw().get(),
 humanPrincipal=id=>!!db.prepare("SELECT 1 FROM subject WHERE principal_id=? AND kind='human'").pluck().get(id)}){
 let configuration=null,firstPairingSigner=null;const revocationChecks=new Map();
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
 function manager(input,work,finish=()=>{},finalScope=()=>null){return writer(()=>{
  const now=time(),found=authenticated(input,now);need(!found.denied,'management_denied');const grant=JSON.parse(canonical(authority.current(found.session.principal_id)));
  need(humanPrincipal(found.session.principal_id)===true&&grant.state==='active'&&
   grant.issuer_id===found.session.issuer_id&&grant.issuer_epoch===found.session.issuer_epoch&&grant.permissions.includes('auth.manage')&&now.upper<BigInt(found.session.recent_before_ns),'management_denied');
  const result=work(found,now),last=time(),current=authenticated(input,last,finalScope());need(!current.denied&&
   ['principal_id','issuer_id','issuer_epoch','session_id'].every(key=>current.session[key]===found.session[key])&&humanPrincipal(current.session.principal_id)===true&&
   same(authority.current(found.session.principal_id),grant)&&last.upper<BigInt(found.session.recent_before_ns)&&last.upper<BigInt(current.session.recent_before_ns),'management_changed');finish(result,last);return result;
 });}
 function prior(input,principalId){uuid(input.request_id);const row=db.prepare('SELECT principal_id,request_digest,binding_id,revision FROM peer_pairing_operation WHERE request_id=?').raw().get(input.request_id);
  if(!row)return null;need(row[0]===principalId&&row[1]===digest(input),'conflict');return read(row[2],row[3]);}
 function commit(input,principalId,now,value){write(db.prepare('INSERT INTO peer_pairing_operation VALUES(?,?,?,?,?,?)').run(input.request_id,principalId,digest(input),value.binding_id,Number(value.revision),now.acquisition.id));return value;}
 function configured(transcript){
  need(configuration,'configuration_missing');const local=transcript.parties.find(p=>p.service_id===service.service_id),peer=transcript.parties.find(p=>p.service_id!==service.service_id);
  need(local&&peer&&local.database_instance_id===service.database_instance_id&&local.service_kind===service.authority,'local_identity');
  const issuer=issuerIdentity();need(issuer&&local.issuer_id===issuer[0]&&local.issuer_epoch===issuer[1],'local_identity');
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
 function stageRecord(transcript,now,before=null){
   const {local,peer}=configured(transcript);
   expirePending(now);
   need(!db.prepare('SELECT 1 FROM peer_pairing_head WHERE binding_id=?').pluck().get(local.binding_id),'binding_exists');
   need(!db.prepare('SELECT 1 FROM peer_pairing_revision WHERE attempt_id=?').pluck().get(transcript.pair_attempt_id),'attempt_exists');
   need(db.prepare("SELECT count(*) FROM peer_pairing_revision r JOIN peer_pairing_head h USING(binding_id,revision) WHERE state IN ('staged','proving','proved')").pluck().get()<16,'capacity');
   const begin=[local,peer].map(p=>BigInt(p.not_before_ns)).reduce((a,b)=>a>b?a:b),end=[local,peer].map(p=>BigInt(p.expires_ns)).reduce((a,b)=>a<b?a:b);
   const attemptEnd=[end,now.lower+600000000000n,before??end].reduce((a,b)=>a<b?a:b);
   need(now.lower>=begin&&now.upper<attemptEnd,'validity');
   return save({format:'leafseamer.peer-pairing-record/1',binding_id:local.binding_id,revision:'1',peer_service_id:peer.service_id,service_boot_id:bootId,state:'staged',
    transcript,transcript_digest:digest(transcript),not_before_ns:String(begin),expires_ns:String(end),attempt_expires_ns:String(attemptEnd),
    runtime_domain_ref:now.runtime_domain_ref,attempt_deadline_tick_ns:String(now.tick+(attemptEnd-now.upper)),proof_refs:[],approval_ref:null});
 }
 function ready(value,now){
   configured(value.transcript);timing(value,now);
   need(value.state==='proved'&&now.upper<BigInt(value.attempt_expires_ns),'activation');
   const all=proofs(value.binding_id);need(all.length===2&&same(value.proof_refs,all.map(p=>({direction:p.direction,ref:ref(p)}))),'proof_required');return all;
 }
 function activateRecord(value,approval){
   return save({...value,revision:String(BigInt(value.revision)+1n),state:'activated',approval_ref:{id:approval.request_id,revision:'1',digest:digest(approval)},approval},value);
 }
 return Object.freeze({
  bindConfiguration(value,signer=null){need(!configuration,'configuration_bound');fields(value,'local,peers');need(Array.isArray(value.peers)&&value.peers.length<=64,'configuration');
   const fixed=JSON.parse(canonical(value));need(fixed.local.service_id===service.service_id&&new Set(fixed.peers.map(p=>p.service_id)).size===fixed.peers.length,'configuration');
   if(signer!==null)need(service.authority==='controller'&&typeof signer.sign==='function'&&typeof signer.check==='function'&&
    Object.entries(pairingCertificate(signer.certificate.raw)).every(([k,v])=>fixed.local[k]===v),'first_authorization_signer');
   configuration=fixed;firstPairingSigner=signer;
  },
  stage(input,request){fields(request,'request_id,transcript');const transcript=pairingTranscript(request.transcript);return manager(input,(actor,now)=>{
   const principal=actor.session.principal_id,old=prior(request,principal);if(old)return old;
   return commit(request,principal,now,stageRecord(transcript,now));
  });},
  ...(firstPairing&&service.authority==='seamer'&&{
   stageFirstPairing(id){return writer(()=>{
    const now=time(),selected=firstPairing.select(id,now),{authorization,envelopeDigest,localBinding}=selected;
    const principal=authorization.administrator.principal_id,request={request_id:id,authorization_digest:envelopeDigest};
    const old=prior(request,principal);
    if(old){const {value}=currentPeer(localBinding);need(old.binding_id===localBinding&&same(old.transcript,authorization.transcript),'first_authorization_staging');return value;}
    expirePending(now);firstPairing.assertNoPending();firstPairing.remember(authorization.administrator);
    const stage=stageRecord(authorization.transcript,now,BigInt(authorization.expires_ns));
    commit(request,principal,now,stage);
    const last=time();firstPairing.select(id,last);timing(stage,last);need(last.upper<BigInt(stage.attempt_expires_ns),'expired');return stage;
   });},
   readFirstPairingCompletion(id){return writer(()=>firstPairing.completed(id));},
   activateFirstPairing(id,remote){return writer(()=>{
    const replay=firstPairing.completed(id);if(replay)return replay;
    const now=time(),selected=firstPairing.select(id,now),{authorization,envelopeDigest,localBinding}=selected,
     principal=authorization.administrator.principal_id,stage=prior({request_id:id,authorization_digest:envelopeDigest},principal);
    need(stage?.binding_id===localBinding&&same(stage.transcript,authorization.transcript),'first_authorization_staging');
    const current=read(localBinding),all=ready(current,now),{peer}=configured(current.transcript);
    const inbound=all.find(proof=>proof.direction==='inbound'),outbound=all.find(proof=>proof.direction==='outbound');
    const remoteIn=remote.proofs?.find(proof=>proof.direction==='inbound'),remoteOut=remote.proofs?.find(proof=>proof.direction==='outbound');
    need(remote.state==='activated'&&remote.binding_ref?.id===peer.binding_id&&remote.pair_attempt_id===authorization.transcript.pair_attempt_id&&
     remote.transcript_digest===authorization.transcript_digest&&remoteIn&&remoteOut&&same(ref(remoteIn),outbound.peer_proof_ref)&&
     same(remoteOut.peer_proof_ref,ref(inbound)),'first_authorization_remote');
    const last=time();firstPairing.select(id,last);timing(current,last);need(last.upper<BigInt(current.attempt_expires_ns),'expired');
    const approval={request_id:crypto.randomUUID(),principal_id:principal,authorization_ref:{id,revision:'1',digest:envelopeDigest},
     acquisition_ref:last.acquisition,controller_binding_ref:remote.binding_ref};
    const active=activateRecord(current,approval);
    commit({request_id:approval.request_id,authorization_id:id,controller_binding_ref:remote.binding_ref},principal,last,active);
    return firstPairing.complete(selected,active,last);
   });}
  }),
  exportFirstPairingAuthorization(input,request){
   fields(request,'binding_id,transcript_digest');uuid(request.binding_id);
   need(service.authority==='controller'&&Number(service.schema_revision)>=93&&firstPairingSigner,'first_authorization_unavailable');
   return manager(input,(actor,now)=>{
    const current=read(request.binding_id),stage=read(request.binding_id,'1'),{peer}=configured(stage.transcript),session=actor.session;
    timing(current,now);
    need(['staged','proving','proved'].includes(current.state)&&stage.state==='staged'&&peer.service_kind==='seamer'&&
     stage.transcript_digest===request.transcript_digest&&current.transcript_digest===stage.transcript_digest,'first_authorization_staging');
    const certificateBefore=firstPairingSigner.check(peer.service_id);
    const owner=db.prepare('SELECT principal_id FROM peer_pairing_operation WHERE binding_id=? AND revision=1').pluck().get(stage.binding_id);
    need(owner===session.principal_id,'first_authorization_administrator');
    const existing=db.prepare('SELECT body_jcs,body_digest FROM first_pairing_issue WHERE binding_id=?').raw().get(stage.binding_id);
    if(existing){
     const saved=verifyFirstPairingAuthorization(Buffer.from(existing[0]),firstPairingSigner.certificate);
     need(existing[1]===digest(saved)&&saved.authorization.controller_stage_ref.digest===stage.digest&&
      saved.authorization.administrator.principal_id===owner,'first_authorization_integrity');
     return saved;
    }
    need(current.state==='staged','first_authorization_staging');
    const before=[stage.attempt_expires_ns,session.recent_before_ns,session.expires_ns,session.idle_before_ns,certificateBefore]
     .map(BigInt).reduce((a,b)=>a<b?a:b);
    need(now.upper<before,'first_authorization_expired');
    const body={format:firstPairingFormat,authorization_id:crypto.randomUUID(),transcript:stage.transcript,transcript_digest:stage.transcript_digest,
     controller_stage_ref:{id:stage.binding_id,revision:'1',digest:stage.digest},administrator:{principal_kind:'human',principal_id:owner,
      issuer_id:session.issuer_id,issuer_epoch:session.issuer_epoch},not_before_ns:String(now.lower),expires_ns:String(before)};
    const text=canonical(firstPairingSigner.sign(body));
    const issued=verifyFirstPairingAuthorization(Buffer.from(text),firstPairingSigner.certificate);
    need(same(issued.authorization,body),'first_authorization_integrity');
    write(db.prepare('INSERT INTO first_pairing_issue VALUES(?,1,?,?,?,?,?)').run(stage.binding_id,body.authorization_id,owner,now.acquisition.id,text,digest(issued)));
    return issued;
   },(result,last)=>{
    need(last.lower>=BigInt(result.authorization.not_before_ns)&&last.upper<BigInt(result.authorization.expires_ns),'first_authorization_expired');
    const current=read(request.binding_id);timing(current,last);firstPairingSigner.check(current.peer_service_id);
   });
  },
  get(input,id){return manager(input,(_actor,now)=>{expirePending(now);return read(id);});},
  reject(input,request){fields(request,'request_id,binding_id,expected_revision');uuid(request.binding_id);integer(request.expected_revision);return manager(input,(actor,now)=>{
   const principal=actor.session.principal_id,old=prior(request,principal);if(old)return old;const current=read(request.binding_id);need(current.revision===request.expected_revision,'stale');
   need(['staged','proving','proved'].includes(current.state),'terminal');const value=save({...current,revision:String(BigInt(current.revision)+1n),state:'rejected'},current);return commit(request,principal,now,value);
  });},
  currentPending(id){return writer(()=>currentPeer(id).value);},
  requireActivatedInTransaction(reference){
   need(db.open&&db.inTransaction,'transaction');fields(reference,'id,revision,digest');
   const {value}=currentPeer(reference.id);need(value.state==='activated'&&value.revision===reference.revision&&value.digest===reference.digest,'activation');return value;
  },
  requireActivePeerInTransaction(scope,kind,bindingId=null){
   need(db.open&&db.inTransaction,'transaction');fields(scope,'authority_service_id,database_instance_id');
   uuid(scope.authority_service_id);uuid(scope.database_instance_id);if(bindingId!==null)uuid(bindingId);
   const now=time(),candidates=db.prepare(`SELECT r.binding_id FROM peer_pairing_head h JOIN peer_pairing_revision r USING(binding_id,revision)
    WHERE r.peer_service_id=? AND r.state='activated' AND (? IS NULL OR r.binding_id=?)`).pluck().all(scope.authority_service_id,bindingId,bindingId);
   const matches=candidates.map(id=>read(id)).filter(value=>{
    const peer=value.transcript.parties.find(party=>party.service_id===value.peer_service_id);
    return peer?.service_kind===kind&&peer.database_instance_id===scope.database_instance_id&&now.lower>=BigInt(value.not_before_ns)&&now.upper<BigInt(value.expires_ns);
   });
   need(matches.length===1,'activation');const value=matches[0];configured(value.transcript);return value;
  },
  identityForRevocationInTransaction(reference,scope){
   need(db.open&&db.inTransaction,'transaction');fields(reference,'id,revision,digest');const transition=revocationChecks.get(scope);need(transition,'revocation_scope');
   if(reference.id!==transition.before.binding_id){const {value}=currentPeer(reference.id);need(value.state==='activated'&&value.revision===reference.revision&&value.digest===reference.digest,'activation');return value;}
   // 仅当前revoke的提交末尾可沿原身份完成自身撤销；不是新的active配对或可缓存资格。
   const before=transition.before,after=read(reference.id);need(before.revision===reference.revision&&before.digest===reference.digest&&same(after,transition.after),'revocation_scope');
   configured(before.transcript);timing(before,time());return before;
  },
  authorizeIntrospectionInTransaction(id,socket){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.permissions.includes('auth.introspect'),'purpose');return {record:value,peer};
  },
  authorizeSubscriptionInTransaction(id,socket){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.permissions.includes('event.internal.subscribe'),'purpose');return {record:value,peer};
  },
  authorizeAutomationApprovalInTransaction(id,socket){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.service_kind==='seamer'&&peer.permissions.includes('automation.prepare.read'),'purpose');return {record:value,peer};
  },
  authorizeRunRecordInTransaction(id,socket){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.service_kind==='controller'&&peer.permissions.includes('automation.prepare.read'),'purpose');return {record:value,peer};
  },
  authorizeRunProtectionInTransaction(id,socket,peerKind='seamer'){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.service_kind===peerKind&&peer.permissions.includes('automation.protect'),'purpose');return {record:value,peer};
  },
  authorizeRevocationInTransaction(id,socket){
   need(db.open&&db.inTransaction,'transaction');const {value}=currentPeer(id),peer=channel(value,socket);
   need(value.state==='activated'&&peer.permissions.includes('auth.revoke'),'purpose');return {record:value,peer};
  },
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
   const principal=actor.session.principal_id,old=prior(request,principal);if(old)return old;const value=read(request.binding_id);
   ready(value,now);need(value.revision===request.expected_revision&&value.transcript_digest===request.transcript_digest&&
    !firstPairing?.reserved(value.binding_id),'activation');
   const approval={request_id:request.request_id,principal_id:principal,authorization_ref:ref(authority.current(principal)),acquisition_ref:now.acquisition};
   const result=activateRecord(value,approval);
   fresh=true;return commit(request,principal,now,result);
  },(result,last)=>{
   // 幂等查回原件不重新激活；新激活必须在事务末尾仍处于原attempt窗口。
   if(fresh){timing({...result,state:'proved'},last);need(last.upper<BigInt(result.attempt_expires_ns),'expired');}
  });},
  revoke(input,request){fields(request,'request_id,binding_id,expected_revision');let scope=null;
   try{return manager(input,(actor,now)=>{
    const principal=actor.session.principal_id,old=prior(request,principal);if(old)return old;const value=read(request.binding_id);need(value.state==='activated'&&value.revision===request.expected_revision,'stale');
    const result=commit(request,principal,now,save({...value,revision:String(BigInt(value.revision)+1n),state:'revoked'},value));
    scope=Object.freeze({});revocationChecks.set(scope,{before:value,after:result});return result;
   },()=>{},()=>scope);}finally{if(scope)revocationChecks.delete(scope);}
  },
 });
}
