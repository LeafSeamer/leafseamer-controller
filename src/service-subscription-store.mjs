import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {contractSelection} from './sdk/selection.mjs';
import {IdentityError} from './identity-error.mjs';
import {serviceSnapshotStore} from './service-snapshot-store.mjs';
import {subscriptionChannels} from './service-subscription-channel.mjs';
import {withExecutionReadView} from './execution-read-view.mjs';
import {readDeviceSourceTime} from './device-event-source.mjs';
const activeStates=['building','snapshot_ready','catching_up','live'];
const need=(ok,reason)=>{if(!ok)throw new IdentityError('subscription_'+reason);};
const fields=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys.split(',').sort().join(','),'input');
const id=value=>need(typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$(?![\s\S])/.test(value),'input');
const written=r=>need(r.changes===1,'storage');
const unpack=(body,hash)=>{const value=JSON.parse(body);need(canonical(value)===body&&digest(value)===hash,'integrity');return value;};
const authorization=proof=>Object.fromEntries(['owner','subject_ref','approval_ref','policy_ref','pairing_ref','scope_ref'].map(key=>[key,proof[key]]));
const query=request=>({consumer_id:request.consumer_id,purpose:request.purpose,scope:request.scope});
const denied=result=>{if(result.denied)throw new IdentityError(result.denied);return result;};
export function serviceSubscriptionStore({db,service,bootId,writer,time,authorize,currentAuthorization,humanAuthority=null,domain=null,sourceCut=null,durationSample=null,scopeCurrent=null}){
 const write=writer;writer=work=>write(()=>withExecutionReadView(db,work));
 const sourceCheck=work=>{try{return work();}catch(error){if(['WorkerLaunchError','WorkerRuntimeError','DeviceModuleError'].includes(error.name))throw Object.assign(new IdentityError('event_scope_unavailable'),{cause:error});throw error;}};
 function read(key){const row=db.prepare('SELECT s.creation_jcs,s.creation_digest,r.body_jcs,r.body_digest FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision) WHERE s.subscription_id=?').raw().get(key);
  need(row,'not_found');return {creation:unpack(row[0],row[1]),view:unpack(row[2],row[3])};}
 function revision(view,action,reason=null){const operation=crypto.randomUUID(),key=view.binding.subscription_id,number=Number(view.revision),body=canonical(view),hash=digest(view);
  written(db.prepare('INSERT INTO service_event_subscription_revision VALUES(?,?,?,?,?,?)').run(key,number,view.state,body,hash,operation));
  written(number===1?db.prepare('INSERT INTO service_event_subscription_head VALUES(?,?)').run(key,number):db.prepare('UPDATE service_event_subscription_head SET revision=? WHERE subscription_id=? AND revision=?').run(number,key,number-1));
  const record=canonical({subscription_id:key,revision:view.revision,action,view_digest:hash,...(reason!==null&&{reason_code:reason})});
  written(db.prepare('INSERT INTO service_event_subscription_audit VALUES(?,?)').run(operation,record));
  written(db.prepare('INSERT INTO service_event_subscription_outbox VALUES(?,?,?,?)').run(operation,key,number,record));
 }
 function terminate(saved,state,reason=null){if(!activeStates.includes(saved.view.state))return saved.view;const view={...saved.view,revision:String(Number(saved.view.revision)+1),state};revision(view,state,reason);return view;}
 function checkCurrent(saved){
  need(saved.creation.service_boot_id===bootId,'boot');need(time().upper<BigInt(saved.creation.expires_ns),'expired');
  const original=saved.creation.authorization;
  if(saved.view.owner.kind==='human'){
   need(humanAuthority,'forbidden');return sourceCheck(()=>humanAuthority.current(original));
  }
  const proof=sourceCheck(()=>currentAuthorization(original));
  need(!proof.denied&&same(authorization(proof),original),'authorization_changed');return proof;
 }
 const snapshots=Number(service.schema_revision)>=68?serviceSnapshotStore({db,bootId,writer,time,domain,sourceCut,read,revision,terminate,checkCurrent}):null;
 function sweep(){
  const rows=db.prepare("SELECT subscription_id FROM service_event_subscription_revision r JOIN service_event_subscription_head h USING(subscription_id,revision) WHERE r.state IN('building','snapshot_ready','catching_up','live')").pluck().all();
  for(const key of rows){const saved=read(key);if(saved.creation.service_boot_id!==bootId){terminate(saved,'resync_required');continue;}
   try{checkCurrent(saved);}
   catch(error){
    const code=error.code??error.name;
    if(code==='subscription_expired')terminate(saved,'expired',code);
    else if(/^(event_scope_|worker_|module_)/.test(code)||error.name==='ClockError')terminate(saved,'resync_required',code);
    else if(error instanceof IdentityError)terminate(saved,'revoked',code);
    else throw error;
   }
  }snapshots?.sweep();
 }
 function check(binding,socket,request){const proof=sourceCheck(()=>authorize(binding,socket,query(request)));if(proof.denied)return proof;need(proof.session===null&&proof.principal_kind==='service','identity');return proof;}
 function capacity(purpose,slotKey){
  need(!db.prepare("SELECT 1 FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision) WHERE s.purpose=? AND s.slot_key=? AND r.state IN('building','snapshot_ready','catching_up','live')").pluck().get(purpose,slotKey),'slot_busy');
  need(db.prepare('SELECT count(*) FROM service_event_subscription WHERE purpose=?').pluck().get(purpose)<1024&&
   db.prepare("SELECT count(*) FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision) WHERE s.purpose=? AND r.state IN('building','snapshot_ready','catching_up','live')").pluck().get(purpose)<64,'capacity');
 }
 function originalRequest(ownerKey,purpose,requestId,request){
  const old=db.prepare('SELECT subscription_id,request_digest FROM service_event_subscription WHERE owner_key=? AND purpose=? AND request_id=?').raw().get(ownerKey,purpose,requestId);
  if(!old)return null;
  need(old[1]===digest(request),'conflict');return read(old[0]);
 }
 function createRevision({request,requestId,proof,ownerKey,slotKey,auth,authorizationRevision}){
  const key=crypto.randomUUID(),view={schema_version:'event-channel/0.1.0-draft.1',type:'event.subscription',binding:{subscription_id:key,publisher_service_id:service.service_id,publisher_database_instance_id:service.database_instance_id,
   stream_id:crypto.randomUUID(),stream_epoch:crypto.randomUUID(),scope_digest:digest(request.scope).slice(7),authorization_revision:authorizationRevision,connection_generation:'0'},revision:'1',owner:auth.owner,purpose:request.purpose,state:'building',ack_cursor:'0',ack_payload_digest:'0'.repeat(64),snapshot_ref:null,selection:contractSelection,scope:request.scope};
  const creation={format:'leafseamer-service-subscription/1',subscription_id:key,service_boot_id:bootId,request,authorization:auth,expires_ns:proof.expires_ns,source_frontiers:proof.source_frontiers,acquisition_ref:proof.acquisition_ref};
  written(db.prepare('INSERT INTO service_event_subscription VALUES(?,?,?,?,?,?,?,?,?,1)').run(key,ownerKey,slotKey,request.purpose,requestId,digest(request),canonical(creation),digest(creation),proof.expires_ns));
  for(const source of proof.source_frontiers)written(db.prepare('INSERT INTO service_event_subscription_pin VALUES(?,?,?)').run(key,source.source_key.registration_id,source.registration_sequence));
  revision(view,'created');return view;
 }
 function expectedRevision(value){need(typeof value==='string'&&/^[1-9][0-9]{0,4}$/.test(value)&&Number(value)<=65536,'revision');}
 const human=humanAuthority&&Object.freeze({
  create(token,csrf,input){
   fields(input,'context_id,idempotency_key,client_instance_id,purpose,scope');
   for(const value of [input.context_id,input.idempotency_key,input.client_instance_id])id(value);
   need(input.purpose==='status_projection','purpose');const request=structuredClone(input);
   return denied(writer(()=>{
    sweep();const actor=humanAuthority.authenticate(token,csrf,true);if(actor.denied)return actor;
    const owner=humanAuthority.owner(actor,request.client_instance_id),ownerKey=digest(owner),requestId=digest([request.context_id,request.idempotency_key]);
    const old=originalRequest(ownerKey,request.purpose,requestId,request);
    if(old){sourceCheck(()=>humanAuthority.current(old.creation.authorization));return {status:200,view:old.view};}
    const proof=sourceCheck(()=>humanAuthority.createProof(actor,request)),slotKey=digest([actor.session_id,request.scope.scope_id]);
    capacity(request.purpose,slotKey);
    const context=humanAuthority.consumeContext(token,request.context_id);if(context.denied)return context;
    const view=createRevision({request,requestId,proof,ownerKey,slotKey,auth:proof.authorization,authorizationRevision:actor.policy_revision});
    const last=humanAuthority.authenticate(token,csrf,true);
    need(!last.denied&&same(humanAuthority.owner(last,request.client_instance_id),owner)&&last.policy_revision===actor.policy_revision,'authorization_changed');
    sourceCheck(()=>humanAuthority.current(proof.authorization));return {status:202,view};
   }));
  },
  access(token,key,close=null){
   id(key);if(close!==null){fields(close,'expected_revision,csrf');expectedRevision(close.expected_revision);}
   return denied(writer(()=>{
    sweep();const proof=humanAuthority.authenticate(token,close?.csrf,close!==null);if(proof.denied)return proof;
    const saved=read(key),owner=saved.view.owner;
    need(owner.kind==='human'&&same(humanAuthority.owner(proof,owner.client_instance_id),owner),'not_found');
    sourceCheck(()=>humanAuthority.current(saved.creation.authorization));
    if(close===null)return {status:200,view:saved.view};
    if(saved.view.state==='closed'&&[saved.view.revision,String(Number(saved.view.revision)-1)].includes(close.expected_revision))return {status:200,view:saved.view};
    need(activeStates.includes(saved.view.state),'gone');
    need(saved.view.revision===close.expected_revision,'revision');
    return {status:200,view:terminate(saved,'closed')};
   }));
  }
 });
 function permitsSource(binding,socket,evidence){
  const keys=db.prepare(`SELECT p.subscription_id FROM service_event_subscription_pin p
   JOIN service_event_subscription s USING(subscription_id) JOIN service_event_subscription_head h USING(subscription_id)
   JOIN service_event_subscription_revision r USING(subscription_id,revision)
   WHERE p.registration_id=? AND r.state IN ('building','snapshot_ready','catching_up','live')
   AND json_extract(s.creation_jcs,'$.authorization.pairing_ref.id')=?`).pluck().all(evidence.source_key.registration_id,binding);
  for(const key of keys){
   const saved=read(key);
   try{
    if(saved.creation.service_boot_id!==bootId||time().upper>=BigInt(saved.creation.expires_ns))continue;
    const proof=check(binding,socket,saved.creation.request);
    if(!proof.denied&&same(authorization(proof),saved.creation.authorization)&&
     proof.source_frontiers.some(source=>same(source.source_key,evidence.source_key)&&same(source.binding_ref,evidence.binding_ref)))return true;
   }catch(error){if(!(error instanceof IdentityError))throw error;}
  }
  return false;
 }
 const channels=Number(service.schema_revision)>=69?subscriptionChannels({db,service,bootId,writer,sweep,read,revision,check,snapshots,durationSample,scopeCurrent:typeof scopeCurrent==='function'?ref=>sourceCheck(()=>scopeCurrent(ref)):null}):null;
 return Object.freeze({
  channels,human,
  sourceTime(binding,socket,reference){
   if(Number(service.schema_revision)<94)return null;
   return writer(()=>{
    const evidence=readDeviceSourceTime(db,reference);
    return evidence&&permitsSource(binding,socket,evidence)?evidence:null;
   });
  },
  referenceBundle(binding,socket,reference,load){
   if(Number(service.schema_revision)<94||reference.revision!=='1')return null;
   return writer(()=>{
    const candidates=db.prepare(`SELECT min(e.record_id),e.registration_id FROM device_source_event e
     JOIN device_source_event_outbox o USING(record_id,transaction_id)
     WHERE json_extract(o.body_jcs,'$.source_time_evidence.reference_context_ref.id')=?
       AND json_extract(o.body_jcs,'$.source_time_evidence.reference_context_ref.digest')=?
     GROUP BY e.registration_id`).raw().all(reference.id,reference.digest);
    for(const [record] of candidates){
     const selected=db.prepare("SELECT json_extract(origin_jcs,'$.source_time_ref.digest') FROM device_source_event WHERE record_id=?").pluck().get(record);
     const evidence=readDeviceSourceTime(db,{id:record,revision:'1',digest:selected});
     if(evidence&&same(evidence.reference_context_ref,reference)&&permitsSource(binding,socket,evidence))return load(reference);
    }
    return null;
   });
  },
  sweep:()=>{writer(sweep);snapshots?.buildPending();},
  create(binding,socket,input){fields(input,'request_id,consumer_id,purpose,scope');id(input.request_id);id(input.consumer_id);need(input.purpose==='canonical_trigger','purpose');const request=structuredClone(input);
   return denied(writer(()=>{sweep();const proof=check(binding,socket,request);if(proof.denied)return proof;
    const ownerKey=digest(proof.owner),slotKey=digest([proof.owner.consumer_service_id,proof.owner.consumer_database_instance_id,proof.owner.consumer_id]);
    const old=originalRequest(ownerKey,request.purpose,request.request_id,request);
    if(old)return {status:200,view:old.view};
    capacity(request.purpose,slotKey);
    const auth=authorization(proof),view=createRevision({request,requestId:request.request_id,proof,ownerKey,slotKey,auth,authorizationRevision:'1'});
    const last=check(binding,socket,request);need(!last.denied&&same(authorization(last),auth),'authorization_changed');return {status:202,view};
   }));
  },
  access(binding,socket,key,close=null){id(key);if(close!==null){fields(close,'expected_revision');expectedRevision(close.expected_revision);}
   return denied(writer(()=>{sweep();const saved=read(key);need(saved.view.owner.kind==='service','not_found');
    const proof=check(binding,socket,saved.creation.request);if(proof.denied)return proof;need(same(proof.owner,saved.view.owner),'not_found');
    if(close!==null){if(saved.view.state==='closed'&&Number(close.expected_revision)===Number(saved.view.revision)-1)return {status:200,view:saved.view};need(saved.view.revision===close.expected_revision,'revision');
     return {status:200,view:terminate(saved,'closed')};}return {status:200,view:saved.view};
   }));
  }
 });
}
