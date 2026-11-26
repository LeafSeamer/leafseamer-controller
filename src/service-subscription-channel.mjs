import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {contractSelection as selection} from './sdk/selection.mjs';
import {snapshotContext,checkSnapshotContext} from './service-snapshot-context.mjs';
import {subscriptionReconcile} from './service-subscription-reconcile.mjs';
const need=(ok,why)=>{if(!ok)throw new IdentityError('subscription_'+why);};
const written=result=>need(result.changes===1,'storage');
const activeStates=['building','snapshot_ready','catching_up','live'];
const flowing=state=>state==='catching_up'||state==='live';
const deliveryMode=view=>view.state==='live'?'live':'reconcile';
export function subscriptionChannels({db,service,bootId,writer,sweep,read,revision,check,snapshots,checkHuman,durationSample,scopeCurrent}){
 const channels=new WeakMap(),live=new Map();
 const reconcile=Number(service.schema_revision)>=71?subscriptionReconcile(db):null;
 function entry(handle){const channel=channels.get(handle);need(channel&&live.has(channel.id),'connection');return channel;}
 function head(key){return db.prepare('SELECT a.attempt_id,a.connection_id,a.generation,a.response_jcs FROM service_subscription_attempt a JOIN service_subscription_connection h USING(subscription_id,attempt_id) WHERE a.subscription_id=?').raw().get(key);}
 function current(row){
  const channel=row&&live.get(row[1]);
  return !!channel&&!(channel.human&&channel.socket.destroyed)&&!db.prepare('SELECT 1 FROM service_subscription_disconnect WHERE connection_id=?').pluck().get(row[1]);
 }
 function authorized(channel,saved,active=true){
  if(channel.human){need(!channel.socket.destroyed&&saved.view.owner.kind==='human','connection');checkHuman(channel.human,saved);return;}
  need(saved.view.owner.kind==='service','not_found');
  const proof=check(channel.binding,channel.socket,saved.creation.request);
  need(!proof.denied&&same(proof.owner,saved.view.owner),'not_found');if(active)need(activeStates.includes(saved.view.state),'state');return proof;
 }
 function open(channel){
  need([...live.values()].filter(value=>!!value.human===!!channel.human).length<16&&!live.has(channel.id),'capacity');
  const handle=Object.freeze({});channels.set(handle,channel);live.set(channel.id,channel);return handle;
 }
 function attached(saved){return {schema_version:'event-channel/0.1.0-draft.1',type:'server.attached',binding:saved.view.binding,state:saved.view.state,snapshot_ref:saved.view.snapshot_ref,ack_cursor:saved.view.ack_cursor,ack_payload_digest:saved.view.ack_payload_digest};}
 function release(channel){need(channel.subscription,'connection');const saved=read(channel.subscription);authorized(channel,saved);const row=head(channel.subscription);need(current(row)&&row[1]===channel.id&&row[2]===saved.view.binding.connection_generation,'generation');return saved;}
 function deliveryFrame(view,value){
  if(value.entry.entry_kind==='sync.ready'){
   const {cursor,previous_cursor,payload_digest,entry}=value;
   need(entry.payload.baseline_snapshot_id===view.snapshot_ref.snapshot_id,'delivery_mapping');
   return {schema_version:'event-channel/0.1.0-draft.1',type:'server.sync.ready',binding:view.binding,
    baseline_snapshot_id:entry.payload.baseline_snapshot_id,cursor,previous_cursor,payload_digest,delivery_mode:'reconcile'};
  }
  const frame={format_version:'snapshot-projection/0.2.0-draft.1',type:'server.data',binding:view.binding,delivery_mode:deliveryMode(view),...value};
  need(Buffer.byteLength(JSON.stringify(frame))<=65536,'reconcile_frame_capacity');
  return frame;
 }
 function nextToSend(channel,saved,frame){
  const view=saved.view;
  const entry=frame.type==='server.sync.ready'
   ? {entry_kind:'sync.ready',payload:{baseline_snapshot_id:frame.baseline_snapshot_id}}
   : frame.entry;
  need(flowing(view.state)&&frame.delivery_mode===deliveryMode(view)&&same(view.binding,frame.binding)&&frame.previous_cursor===view.ack_cursor&&
   frame.cursor===String(BigInt(view.ack_cursor)+1n)&&digest(entry).slice(7)===frame.payload_digest,'delivery_binding');
  const hash=db.prepare('SELECT body_digest FROM service_subscription_delivery WHERE subscription_id=? AND cursor=?').pluck().get(channel.subscription,frame.cursor);
  need(hash==='sha256:'+frame.payload_digest,'delivery_mapping');
 }
 return Object.freeze({
  deliversReconcile:reconcile!==null,
  context(binding,socket,key,input,original=null){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved);const latest=head(key);
   need(input.expected_connection_generation!=='0'&&input.expected_connection_generation===saved.view.binding.connection_generation&&current(latest)&&latest[2]===input.expected_connection_generation,'generation');need(saved.view.state==='snapshot_ready','state');
   need(typeof durationSample==='function'&&typeof scopeCurrent==='function','context_unavailable');
   const registration=scopeCurrent(saved.creation.authorization.scope_ref).registration,snapshot=snapshots.lease(saved),clock=durationSample();
   const value=snapshotContext({saved,input,bootId,registration,snapshot,clock});return original?checkSnapshotContext(original,value):value;
  });},
  open(binding,socket){return open({id:crypto.randomUUID(),binding,socket,subscription:null});},
  openHuman(grant,socket){need(checkHuman,'connection');return open({id:grant.original.binding.channel.binding_id,human:grant,socket,subscription:null});},
  attach(handle,input){const channel=entry(handle);writer(sweep);return writer(()=>{const saved=read(input.subscription_id);authorized(channel,saved);const binding=saved.view.binding;
   need(same(input.owner,saved.view.owner)&&['stream_id','stream_epoch','scope_digest','authorization_revision'].every(key=>input[key]===binding[key]),'binding');
   if(input.resume===null)need(['building','snapshot_ready'].includes(saved.view.state),'resume_unavailable');
   else{
    need(Number(service.schema_revision)>=70&&flowing(saved.view.state)&&saved.view.purpose==='canonical_trigger','resume_unavailable');
    const resume=input.resume;need(resume&&Object.keys(resume).sort().join(',')==='ack_kind,cursor,payload_digest'&&resume.ack_kind==='durable_ingest'&&resume.cursor===saved.view.ack_cursor&&resume.payload_digest===saved.view.ack_payload_digest,'resume_binding');
    const baseline=db.prepare('SELECT snapshot_id,snapshot_cursor,manifest_digest,marker_digest,journal_sequence FROM service_snapshot_baseline WHERE subscription_id=?').raw().get(input.subscription_id),content=snapshots.baseline(saved,false);
    need(baseline&&baseline[0]===saved.view.snapshot_ref.snapshot_id&&baseline[2]===saved.view.snapshot_ref.manifest_digest&&baseline[3]===content.marker_digest&&baseline[4]===content.journal_sequence,'resume_mapping');
    if(resume.cursor===baseline[1])need(resume.payload_digest===baseline[3],'resume_mapping');
    else{
     need(reconcile,'resume_mapping');
     const hash=db.prepare('SELECT d.body_digest FROM service_subscription_delivery_ack a JOIN service_subscription_delivery d USING(subscription_id,cursor) WHERE a.subscription_id=? AND a.cursor=?').pluck().get(input.subscription_id,resume.cursor);
     need(hash==='sha256:'+resume.payload_digest,'resume_mapping');
    }
   }
   need(!channel.subscription||channel.subscription===input.subscription_id,'connection');
   const old=db.prepare('SELECT request_digest,connection_id,response_jcs FROM service_subscription_attempt WHERE subscription_id=? AND attempt_id=?').raw().get(input.subscription_id,input.connection_attempt_id),prior=head(input.subscription_id);
   let response;
   if(old){need(old[0]===digest(input)&&old[1]===channel.id&&current(prior)&&prior[0]===input.connection_attempt_id,'conflict');response=JSON.parse(old[2]);}
   else{
    need(!channel.subscription,'conflict');
    need(input.expected_connection_generation===binding.connection_generation&&(!current(prior)||input.replace_existing),'conflict');
    need(db.prepare('SELECT count(*) FROM service_subscription_attempt JOIN service_event_subscription USING(subscription_id) WHERE purpose=?').pluck().get(saved.view.purpose)<16384&&
     db.prepare('SELECT count(*) FROM service_subscription_attempt WHERE subscription_id=?').pluck().get(input.subscription_id)<1024,'capacity');
    const generation=String(BigInt(binding.connection_generation)+1n);need(BigInt(generation)<=18446744073709551615n,'capacity');
    const view={...saved.view,state:input.resume===null?saved.view.state:'catching_up',revision:String(Number(saved.view.revision)+1),binding:{...binding,connection_generation:generation}};response=attached({view});
    written(db.prepare('INSERT INTO service_subscription_attempt VALUES(?,?,?,?,?,?,?,?)').run(input.subscription_id,input.connection_attempt_id,channel.id,generation,digest(input),canonical(response),Number(view.revision),bootId));
    revision(view,'attached');
    written(prior?db.prepare('UPDATE service_subscription_connection SET attempt_id=? WHERE subscription_id=? AND attempt_id=?').run(input.connection_attempt_id,input.subscription_id,prior[0]):db.prepare('INSERT INTO service_subscription_connection VALUES(?,?)').run(input.subscription_id,input.connection_attempt_id));
    if(input.resume!==null)reconcile?.follow(input.subscription_id,generation);
   }
   authorized(channel,read(input.subscription_id));channel.subscription=input.subscription_id;
   const channelView=channel.human?.original.binding.channel??{binding_id:channel.id,selection,publisher_service_id:service.service_id,publisher_database_instance_id:service.database_instance_id,service_boot_id:bootId,owner:saved.view.owner,subscription_id:null,transport:'service_mtls'};
   return {ready:{type:'contract.ready',channel:channelView},attached:response};
  });},
  applied(handle,input){need(Number(service.schema_revision)>=70,'baseline_unavailable');const channel=entry(handle);writer(sweep);return writer(()=>{
   const saved=release(channel);need(same(input.binding,saved.view.binding)&&same(input.snapshot,saved.view.snapshot_ref),'binding');
   need(input.type==='client.snapshot.applied'&&input.schema_version==='event-channel/0.1.0-draft.1'&&Object.keys(input).sort().join(',')==='binding,schema_version,snapshot,type','input');
   const prior=db.prepare('SELECT snapshot_id,manifest_digest,connection_generation,marker_digest FROM service_snapshot_baseline WHERE subscription_id=?').raw().get(channel.subscription);
   if(prior){need(flowing(saved.view.state)&&prior[0]===input.snapshot.snapshot_id&&prior[1]===input.snapshot.manifest_digest&&prior[2]===input.binding.connection_generation,'conflict');return saved.view;}
   need(saved.view.state==='snapshot_ready'&&saved.view.purpose==='canonical_trigger','state');const baseline=snapshots.baseline(saved),number=Number(saved.view.revision)+1;
   written(db.prepare('INSERT INTO service_snapshot_baseline VALUES(?,?,?,?,?,?,?,?)').run(channel.subscription,input.snapshot.snapshot_id,input.snapshot.snapshot_cursor,input.snapshot.manifest_digest,baseline.marker_digest,baseline.journal_sequence,input.binding.connection_generation,number));
   reconcile?.reserve(channel.subscription,baseline.journal_sequence);
   reconcile?.follow(channel.subscription,saved.view.binding.connection_generation);
   const view={...saved.view,revision:String(number),state:'catching_up',ack_cursor:input.snapshot.snapshot_cursor,ack_payload_digest:baseline.marker_digest};revision(view,'snapshot_applied');
   release(channel);snapshots.baseline(saved);return view;
  });},
  prepareReconcile(handle,afterCursor){
   need(reconcile,'reconcile_unavailable');
   const channel=entry(handle);
   writer(sweep);
   return writer(()=>{
    const saved=release(channel);
    need(flowing(saved.view.state)&&saved.view.purpose==='canonical_trigger','state');
    const entries=reconcile.prepare(channel.subscription,afterCursor,saved.view.binding.connection_generation,deliveryMode(saved.view));
    release(channel);
    return entries.map(value=>deliveryFrame(saved.view,value));
   });
  },
  nextReconcile(handle){
   if(!reconcile)return null;
   const channel=entry(handle);writer(sweep);
   return writer(()=>{
    const saved=release(channel),view=saved.view;
    if(view.purpose!=='canonical_trigger'||!flowing(view.state))return null;
    const next=String(BigInt(view.ack_cursor)+1n);
    if(db.prepare('SELECT 1 FROM service_subscription_transmitted WHERE subscription_id=? AND connection_generation=? AND cursor=?')
     .pluck().get(channel.subscription,view.binding.connection_generation,next))return null;
    // WebSocket 每次仅发送下一条并等待持久 ACK，准备时沿用同一上限。
    const [nextFrame]=reconcile.prepare(channel.subscription,view.ack_cursor,view.binding.connection_generation,deliveryMode(view),1);
    const value=nextFrame??(view.state==='catching_up'?
     reconcile.checkpoint(channel.subscription,view.ack_cursor,view.snapshot_ref.snapshot_id,view.binding.connection_generation):null);
    release(channel);
    return value?deliveryFrame(view,value):null;
   });
  },
  hasLiveWork(handle){
   if(!reconcile)return false;
   const channel=entry(handle),key=channel.subscription;
   return !!db.prepare(`SELECT 1 FROM service_event_subscription_head h JOIN service_event_subscription_revision r USING(subscription_id,revision)
    JOIN service_subscription_reconcile w USING(subscription_id)
    WHERE h.subscription_id=? AND r.state='live'
     AND NOT EXISTS(SELECT 1 FROM service_subscription_transmitted s WHERE s.subscription_id=h.subscription_id
      AND s.connection_generation=json_extract(r.body_jcs,'$.binding.connection_generation') AND s.cursor=CAST(json_extract(r.body_jcs,'$.ack_cursor') AS INTEGER)+1)
     AND (EXISTS(SELECT 1 FROM service_subscription_delivery d WHERE d.subscription_id=h.subscription_id AND d.cursor>CAST(json_extract(r.body_jcs,'$.ack_cursor') AS INTEGER))
       OR EXISTS(SELECT 1 FROM device_source_notification n JOIN service_event_subscription_pin p ON p.registration_id=n.registration_id
        WHERE p.subscription_id=h.subscription_id AND n.sequence>coalesce((SELECT max(d.journal_sequence) FROM service_subscription_delivery d
          WHERE d.subscription_id=h.subscription_id),w.start_sequence)))`).pluck().get(key);
  },
  checkDelivery(handle,frame){
   need(reconcile,'reconcile_unavailable');
   const channel=entry(handle);writer(sweep);
   return writer(()=>nextToSend(channel,release(channel),frame));
  },
  transmitted(handle,frame){
   need(reconcile,'reconcile_unavailable');
   const channel=entry(handle);writer(sweep);
   return writer(()=>{
    nextToSend(channel,release(channel),frame);
    written(db.prepare('INSERT INTO service_subscription_transmitted VALUES(?,?,?)')
     .run(channel.subscription,frame.binding.connection_generation,frame.cursor));
    release(channel);
   });
  },
  ack(handle,input){
   need(reconcile,'reconcile_unavailable');
   const channel=entry(handle);writer(sweep);
   return writer(()=>{
    const {view}=release(channel);
    need(input.type==='client.ack'&&input.schema_version==='event-channel/0.1.0-draft.1'&&input.ack_kind==='durable_ingest'&&
     view.purpose==='canonical_trigger'&&flowing(view.state)&&same(view.binding,input.binding),'ack_binding');
    const sent=db.prepare(`SELECT d.body_digest,d.checkpoint_generation FROM service_subscription_transmitted s
     JOIN service_subscription_delivery d USING(subscription_id,cursor)
     WHERE s.subscription_id=? AND s.connection_generation=? AND s.cursor=?`).raw().get(channel.subscription,view.binding.connection_generation,input.cursor);
    const [hash,checkpointGeneration]=sent??[];
    need(hash==='sha256:'+input.payload_digest,'ack_mapping');
    if(input.cursor===view.ack_cursor){
     need(input.payload_digest===view.ack_payload_digest,'ack_mapping');
     return view;
    }
    need(input.cursor===String(BigInt(view.ack_cursor)+1n),'ack_cursor');
    const number=Number(view.revision)+1;
    written(db.prepare('INSERT INTO service_subscription_delivery_ack VALUES(?,?,?,?)')
     .run(channel.subscription,input.cursor,view.binding.connection_generation,number));
    const state=checkpointGeneration===view.binding.connection_generation?'live':view.state;
    const next={...view,state,revision:String(number),ack_cursor:input.cursor,ack_payload_digest:input.payload_digest};
    revision(next,state!==view.state?'live_ready':state==='live'?'live_ack':'reconcile_ack');
    release(channel);
    return next;
   });
  },
  check(handle){const channel=entry(handle);if(!channel.human)writer(sweep);return writer(()=>release(channel).view);},
  // 仅用于紧随全局失效扫描的连接回收，不是内容释放门。
  poll(handle){const channel=entry(handle);return writer(()=>{need(channel.subscription,'connection');const saved=read(channel.subscription),row=head(channel.subscription);need(activeStates.includes(saved.view.state)&&current(row)&&row[1]===channel.id,'generation');return saved.view.state==='live';});},
  close(handle){const channel=channels.get(handle);if(!channel||!live.delete(channel.id))return;
   if(channel.subscription)writer(()=>{if(db.prepare('SELECT 1 FROM service_subscription_attempt WHERE connection_id=?').pluck().get(channel.id)&&!db.prepare('SELECT 1 FROM service_subscription_disconnect WHERE connection_id=?').pluck().get(channel.id))written(db.prepare('INSERT INTO service_subscription_disconnect VALUES(?)').run(channel.id));});
  },
  attempt(binding,socket,key,attemptId){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved,false);const row=db.prepare('SELECT connection_id,response_jcs FROM service_subscription_attempt WHERE subscription_id=? AND attempt_id=?').raw().get(key,attemptId);need(row,'not_found');const latest=head(key);return {subscription_id:key,connection_attempt_id:attemptId,attached:JSON.parse(row[1]),current:activeStates.includes(saved.view.state)&&current(latest)&&latest[0]===attemptId};});},
  humanAttempt(saved,attemptId){
   const key=saved.view.binding.subscription_id,latest=head(key);
   const row=db.prepare('SELECT response_jcs FROM service_subscription_attempt WHERE subscription_id=? AND attempt_id=?').pluck().get(key,attemptId);need(row,'not_found');
   let accepted=false;
   if(activeStates.includes(saved.view.state)&&current(latest)&&latest[0]===attemptId){
    try{authorized(live.get(latest[1]),saved);accepted=true;}
    catch(error){if(!(error instanceof IdentityError)&&error.name!=='ClockError')throw error;}
   }
   return {subscription_id:key,connection_attempt_id:attemptId,attached:JSON.parse(row),current:accepted};
  },
  humanSnapshot(saved,generation,page=null){
   const latest=head(saved.view.binding.subscription_id);
   need(generation!=='0'&&current(latest)&&latest[2]===generation&&saved.view.binding.connection_generation===generation,'generation');
   authorized(live.get(latest[1]),saved);need(saved.view.state==='snapshot_ready','state');return snapshots.content(saved,page);
  },
  snapshot(binding,socket,key,generation,page=null){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved);const latest=head(key);need(generation!=='0'&&generation===saved.view.binding.connection_generation&&current(latest)&&latest[2]===generation,'generation');need(saved.view.state==='snapshot_ready','state');return snapshots.content(saved,page);});}
 });
}
