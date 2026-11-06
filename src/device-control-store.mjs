import crypto from 'node:crypto';
import canonicalize from 'canonicalize';
import {createHttpAdapter} from './sdk/http.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {deviceControlRepository} from './device-control-repository.mjs';
import {controlNeed as need,controlHash as hash,controlSame as same,controlActor as actor,controlVersion as version,
 controlRef as ref,controlNext as next,controlSeal as seal,controlFrozen as frozen} from './device-control-value.mjs';
const permissions={acquireControl:'control.acquire',releaseControl:'control.release',offerTransfer:'control.transfer',acceptTransfer:'control.accept',cancelTransfer:'control.transfer'};
const uuid=()=>crypto.randomUUID();

// 人员控制请求使用同库真实令牌、上下文和授权；屏障仅由核心内部提供者处理。
export function deviceControlStore({db,service,bootId,writer,time,authorizeToken,contextCurrent,authority,devices,barriers}){
 const adapter=createHttpAdapter(selection),repository=deviceControlRepository(db,devices,()=>barriers.domain()),scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 let stopped=false;const running=new Set();
 const available=()=>need(!stopped&&Number(service.schema_revision)>=26,'unavailable');
 function authorize(token,permission='control.read'){
  const proof=authorizeToken(token,service.service_id);need(!proof.denied,'permission');need(proof.principal_kind==='human'&&proof.permissions.includes(permission),'permission');return proof;
 }
 function principal(value,permission){
  const row=db.prepare('SELECT s.kind,s.issuer_id,s.issuer_epoch,p.state FROM subject s JOIN local_principal p USING(principal_id) WHERE s.principal_id=?').raw().get(value.principal_id);
  need(row&&row[0]==='human'&&row[1]===value.issuer_id&&row[2]===value.issuer_epoch&&row[3]==='active','target_permission');
  const grant=authority.current(value.principal_id);need(grant.state==='active'&&grant.issuer_id===value.issuer_id&&grant.issuer_epoch===value.issuer_epoch&&grant.permissions.includes(permission),'target_permission');
 }
 function context(token,id,proof,operation,fresh){
  const row=db.prepare('SELECT body,body_digest FROM request_context WHERE context_id=?').raw().get(id);need(row,'context');
  const original=JSON.parse(row[0].toString()),c=original.context;
  need(hash(original)===row[1]&&c.service_id===service.service_id&&same(selection,c.selection)&&same(actor(c),actor(proof)),'context');
  if(fresh){const current=contextCurrent(token,id,operation);need(!current.denied,'context');}
  return c;
 }
 async function decode(operation,parameters,input){
  available();let path=adapter.describe('controller',operation).path;
  for(const [key,value] of Object.entries(parameters))path=path.replace('{'+key+'}',encodeURIComponent(value));
  try{const request=adapter.prepareRequest('controller','POST',path,[['Content-Type','application/json'],['X-LeafSeamer-Contract',selection.contract_id],['X-LeafSeamer-Contract-Digest',selection.contract_digest]]);
   const bytes=Buffer.from(JSON.stringify(input));need(bytes.length<=16384,'input');return (await adapter.decodeRequest(bytes,request)).value;
  }catch{need(false,'input');}
 }
 function offerCurrent(device,id){const value=repository.current('offer',id);need(value.device_id===device,'not_found');return value;}
 function offerLive(offer){const domain=barriers.domain();return same({clock_domain_id:offer.lifetime.clock_domain_id,descriptor_digest:offer.lifetime.descriptor_digest},domain.ref)&&
  BigInt(offer.lifetime.issued_tick_ns)<=BigInt(domain.tick)&&BigInt(domain.tick)<BigInt(offer.lifetime.expires_tick_ns);}
 function expire(offer){
  if(offer.state!=='offered'||offerLive(offer))return offer;
  repository.capacity();const id=uuid();offer.state='expired';offer.closed_reason='clock_domain_changed_or_expired';
  const value=repository.touch('offer',offer,id);repository.commit(id,'expire_offer',null,1,time().acquisition);return value;
 }
 function bindTargets(operation){
  const targets=db.prepare('SELECT p.launch_id,p.intent_digest,p.service_boot_id FROM worker_launch_preparation p JOIN worker_launch_device d USING(launch_id) WHERE d.device_id=? ORDER BY p.launch_id').raw().all(operation.device_id);
  need(targets.length<=256,'capacity');
  for(const target of targets)need(db.prepare('INSERT INTO control_barrier_target VALUES(?,?,?,?)').run(operation.operation_id,...target).changes===1,'storage');
 }
 async function process(id){
  if(stopped||running.has(id))return;running.add(id);
  try{
   const request=writer(()=>{const op=repository.current('operation',id);if(!['pending','indeterminate'].includes(op.state))return null;return op;});if(!request)return;
   let evidence=null;try{evidence=await barriers.protect(request);}catch{}
   if(stopped)return;
   writer(()=>{
    repository.capacity();
    const operation=repository.current('operation',id),record=repository.current('record',operation.device_id);
    need(['pending','indeterminate'].includes(operation.state)&&record.pending_change?.operation_id===id&&same(version(record),operation.expected_control),'conflict');
    const commit=uuid();let eligible=true;
    try{principal(operation.target.holder??operation.requester,operation.kind==='transfer'?'control.accept':operation.kind==='release'?'control.release':'control.acquire');}catch{eligible=false;}
    if(!eligible){operation.state='rejected';operation.failure_code='target_authorization_revoked';record.pending_change=null;}
    else if(!evidence){operation.state='indeterminate';operation.failure_code='barrier_unconfirmed';}
    else{
     barriers.verify(operation,evidence);operation.state='effective';operation.failure_code=null;
     record.effective_version=operation.target.version;record.mode=operation.target.mode;record.holder=operation.target.holder;record.pending_change=null;
     need(db.prepare('INSERT INTO control_barrier_evidence VALUES(?,?,?,?)').run(id,canonicalize(evidence),hash(evidence),commit).changes===1,'storage');
     operation.barrier_selection_ref={id:evidence.selection_id,revision:'1',digest:hash(evidence)};
    }
    record.gate_state='protected';const control=repository.touch('record',record,commit);
    if(operation.state==='effective')operation.effective_control_ref=ref(control,'record_id','record_digest');
    repository.touch('operation',operation,commit);repository.commit(commit,operation.state,operation.requester,2,time().acquisition);
   });
  }catch{ /* 未能提交时保留原pending/indeterminate；不得转成生效或清理版本。 */ }
  finally{running.delete(id);}
 }
 return Object.freeze({
  async invoke(token,method,parameters,input){
   need(Object.hasOwn(permissions,method),'input');const body=await decode(method,parameters,input),credential=structuredClone(token),fixed=structuredClone(parameters);
   const result=writer(()=>{
    const proof=authorize(credential),who=actor(proof),c=context(credential,body.context_id,proof,method,false);
    const {context_id,idempotency_key,...normalized}=body;if(method==='acquireControl')normalized.force??=false;
    const content={operation_id:method,scope,device_id:fixed.device_id,transfer_id:fixed.transfer_id??null,input:normalized};
    const identity={key:{target_scope:scope,...who,request_epoch:c.context_epoch,operation_id:method,idempotency_key},request_digest:hash(content)};
    const old=repository.prior(identity);if(old)return {receipt:old,replay:true};
    authorize(credential,permissions[method]);context(credential,body.context_id,proof,method,true);repository.capacity();
    const record=repository.current('record',fixed.device_id),commit=uuid();let offer=null,operation=null,resultKind,resultRef,members=2;
    if(method==='cancelTransfer'){
     offer=offerCurrent(fixed.device_id,fixed.transfer_id);need(same(offer.from_principal,who),'permission');
     need(same(body.expected_offer,ref(offer,'transfer_id','offer_digest'))&&offer.state==='offered'&&offerLive(offer),'conflict');
     offer.state='cancelled';offer.closed_reason='cancelled_by_owner';offer=repository.touch('offer',offer,commit);resultKind='transfer_offer';resultRef=ref(offer,'transfer_id','offer_digest');
    }else{
     need(same(body.expected_control,version(record))&&!record.pending_change,'conflict');
     if(method==='offerTransfer'){
      need(record.mode==='manual'&&same(record.holder,who),'permission');need(!same(body.target_principal,who),'input');principal(body.target_principal,'control.accept');
      const domain=barriers.domain(),expiry=BigInt(domain.tick)+BigInt(body.offer_ttl_ms)*1000000n;need(expiry<=99999999999999999999n,'capacity');
      offer=seal({transfer_id:uuid(),scope,device_id:record.device_id,revision:'1',from_principal:who,target_principal:body.target_principal,expected_control:version(record),
       lifetime:{...domain.ref,issued_tick_ns:domain.tick,expires_tick_ns:String(expiry)},reason:body.reason,state:'offered',accepted_operation_id:null,closed_reason:null},'offer_digest');
      repository.append('offer',offer,commit);resultKind='transfer_offer';resultRef=ref(offer,'transfer_id','offer_digest');
     }else{
      let kind,holder;
      if(method==='acquireControl'){
       need(!same(record.holder,who),'conflict');if(normalized.force)need(proof.permissions.includes('control.emergency')&&body.reason.trim().length>0,'permission');
       if(record.mode==='manual')need(normalized.force&&proof.permissions.includes('control.emergency'),'permission');kind='acquire';holder=who;
      }else if(method==='releaseControl'){need(record.mode==='manual'&&same(record.holder,who),'permission');kind='release';holder=null;}
      else{
       offer=offerCurrent(fixed.device_id,fixed.transfer_id);need(offer.state==='offered'&&offerLive(offer)&&same(offer.expected_control,version(record)),'conflict');
       need(same(offer.target_principal,who)&&same(offer.from_principal,record.holder),'permission');principal(offer.from_principal,'control.transfer');kind='transfer';holder=who;
      }
      record.reserved_version=next(record.reserved_version);const target={version:record.reserved_version,mode:holder?'manual':'automatic',holder};
      operation=seal({operation_id:uuid(),scope,device_id:record.device_id,revision:'1',identity,kind,requester:who,expected_control:version(record),target,state:'pending',
       barrier_selection_ref:null,effective_control_ref:null,failure_code:null},'operation_digest');repository.append('operation',operation,commit);
      record.pending_change={operation_id:operation.operation_id,target,requested_by:who,reason:body.reason};record.gate_state='fencing';repository.touch('record',record,commit);bindTargets(operation);members=3;
      if(offer){offer.state='accepted';offer.accepted_operation_id=operation.operation_id;repository.touch('offer',offer,commit);members++;}
      resultKind='control_operation';resultRef=ref(operation,'operation_id','operation_digest');
     }
    }
    const receipt={identity,result_kind:resultKind,initial_result_ref:resultRef};
    need(db.prepare('UPDATE request_context SET used_count=used_count+1 WHERE context_id=? AND used_count<max_unique_requests').run(body.context_id).changes===1,'capacity');
    repository.request(identity,body.context_id,record.device_id,receipt,commit);repository.commit(commit,operation?.kind??(method==='offerTransfer'?'offer':'cancel_offer'),who,members,time().acquisition);
    authorize(credential,permissions[method]);return {receipt,replay:false};
   });
   if(result.receipt.result_kind==='control_operation')void process(result.receipt.initial_result_ref.id);
   return frozen(result);
  },
  getOperation(token,id){available();return frozen(writer(()=>{authorize(token);const result=repository.current('operation',id);authorize(token);return result;}));},
  getTransfer(token,device,id){available();return frozen(writer(()=>{authorize(token);const result=expire(offerCurrent(device,id));authorize(token);return result;}));},
  async lookup(token,input){const identity=await decode('lookupControlRequest',{},input);return frozen(writer(()=>{
   const proof=authorize(token);need(same(identity.key.target_scope,scope)&&same(actor(identity.key),actor(proof)),'permission');
   const owner=db.prepare('SELECT context_id FROM request_context WHERE service_id=? AND database_instance_id=? AND issuer_id=? AND issuer_epoch=? AND principal_id=? AND context_epoch=? ORDER BY context_id LIMIT 1').pluck()
    .get(service.service_id,service.database_instance_id,proof.issuer_id,proof.issuer_epoch,proof.principal_id,identity.key.request_epoch);
   need(owner,'context');context(token,owner,proof,identity.key.operation_id,false);const receipt=repository.prior(identity);
   authorize(token);return {status:receipt?'found':'not_found',receipt};
  }));},
  process,
  close(){stopped=true;}
 });
}
