import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {contractSelection as selection} from './sdk/selection.mjs';
import {snapshotContext,checkSnapshotContext} from './service-snapshot-context.mjs';
const need=(ok,why)=>{if(!ok)throw new IdentityError('subscription_'+why);};
const written=result=>need(result.changes===1,'storage');
export function subscriptionChannels({db,service,bootId,writer,sweep,read,revision,check,snapshots,durationSample,scopeCurrent}){
 const channels=new WeakMap(),live=new Map();
 function entry(handle){const channel=channels.get(handle);need(channel&&live.has(channel.id),'connection');return channel;}
 function head(key){return db.prepare('SELECT a.attempt_id,a.connection_id,a.generation,a.response_jcs FROM service_subscription_attempt a JOIN service_subscription_connection h USING(subscription_id,attempt_id) WHERE a.subscription_id=?').raw().get(key);}
 function current(row){return !!row&&live.has(row[1])&&!db.prepare('SELECT 1 FROM service_subscription_disconnect WHERE connection_id=?').pluck().get(row[1]);}
 function authorized(channel,saved,active=true){const proof=check(channel.binding,channel.socket,saved.creation.request);need(!proof.denied&&same(proof.owner,saved.view.owner),'not_found');if(active)need(['building','snapshot_ready','catching_up'].includes(saved.view.state),'state');return proof;}
 function attached(saved){return {schema_version:'event-channel/0.1.0-draft.1',type:'server.attached',binding:saved.view.binding,state:saved.view.state,snapshot_ref:saved.view.snapshot_ref,ack_cursor:saved.view.ack_cursor,ack_payload_digest:saved.view.ack_payload_digest};}
 function release(channel){need(channel.subscription,'connection');const saved=read(channel.subscription);authorized(channel,saved);const row=head(channel.subscription);need(current(row)&&row[1]===channel.id&&row[2]===saved.view.binding.connection_generation,'generation');return saved;}
 return Object.freeze({
  context(binding,socket,key,input,original=null){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved);const latest=head(key);
   need(input.expected_connection_generation!=='0'&&input.expected_connection_generation===saved.view.binding.connection_generation&&current(latest)&&latest[2]===input.expected_connection_generation,'generation');need(saved.view.state==='snapshot_ready','state');
   need(typeof durationSample==='function'&&typeof scopeCurrent==='function','context_unavailable');
   const registration=scopeCurrent(saved.creation.authorization.scope_ref).registration,snapshot=snapshots.lease(saved),clock=durationSample();
   const value=snapshotContext({saved,input,bootId,registration,snapshot,clock});return original?checkSnapshotContext(original,value):value;
  });},
  open(binding,socket){const handle=Object.freeze({}),channel={id:crypto.randomUUID(),binding,socket,subscription:null};need(live.size<16,'capacity');channels.set(handle,channel);live.set(channel.id,channel);return handle;},
  attach(handle,input){const channel=entry(handle);writer(sweep);return writer(()=>{const saved=read(input.subscription_id);authorized(channel,saved);const binding=saved.view.binding;
   need(same(input.owner,saved.view.owner)&&['stream_id','stream_epoch','scope_digest','authorization_revision'].every(key=>input[key]===binding[key]),'binding');
   need(input.resume===null&&['building','snapshot_ready'].includes(saved.view.state),'resume_unavailable');need(!channel.subscription||channel.subscription===input.subscription_id,'connection');
   const old=db.prepare('SELECT request_digest,connection_id,response_jcs FROM service_subscription_attempt WHERE subscription_id=? AND attempt_id=?').raw().get(input.subscription_id,input.connection_attempt_id),prior=head(input.subscription_id);
   let response;
   if(old){need(old[0]===digest(input)&&old[1]===channel.id&&current(prior)&&prior[0]===input.connection_attempt_id,'conflict');response=JSON.parse(old[2]);}
   else{
    need(!channel.subscription,'conflict');
    need(input.expected_connection_generation===binding.connection_generation&&(!current(prior)||input.replace_existing),'conflict');
    need(db.prepare('SELECT count(*) FROM service_subscription_attempt').pluck().get()<16384&&db.prepare('SELECT count(*) FROM service_subscription_attempt WHERE subscription_id=?').pluck().get(input.subscription_id)<1024,'capacity');
    const generation=String(BigInt(binding.connection_generation)+1n);need(BigInt(generation)<=18446744073709551615n,'capacity');
    const view={...saved.view,revision:String(Number(saved.view.revision)+1),binding:{...binding,connection_generation:generation}};response=attached({view});
    written(db.prepare('INSERT INTO service_subscription_attempt VALUES(?,?,?,?,?,?,?,?)').run(input.subscription_id,input.connection_attempt_id,channel.id,generation,digest(input),canonical(response),Number(view.revision),bootId));
    revision(view,'attached');
    written(prior?db.prepare('UPDATE service_subscription_connection SET attempt_id=? WHERE subscription_id=? AND attempt_id=?').run(input.connection_attempt_id,input.subscription_id,prior[0]):db.prepare('INSERT INTO service_subscription_connection VALUES(?,?)').run(input.subscription_id,input.connection_attempt_id));
   }
   authorized(channel,read(input.subscription_id));channel.subscription=input.subscription_id;
   return {ready:{type:'contract.ready',channel:{binding_id:channel.id,selection,publisher_service_id:service.service_id,publisher_database_instance_id:service.database_instance_id,service_boot_id:bootId,owner:saved.view.owner,subscription_id:null,transport:'service_mtls'}},attached:response};
  });},
  applied(handle,input){need(Number(service.schema_revision)>=70,'baseline_unavailable');const channel=entry(handle);writer(sweep);return writer(()=>{
   const saved=release(channel);need(same(input.binding,saved.view.binding)&&same(input.snapshot,saved.view.snapshot_ref),'binding');
   need(input.type==='client.snapshot.applied'&&input.schema_version==='event-channel/0.1.0-draft.1'&&Object.keys(input).sort().join(',')==='binding,schema_version,snapshot,type','input');
   const prior=db.prepare('SELECT snapshot_id,manifest_digest,connection_generation,marker_digest FROM service_snapshot_baseline WHERE subscription_id=?').raw().get(channel.subscription);
   if(prior){need(saved.view.state==='catching_up'&&prior[0]===input.snapshot.snapshot_id&&prior[1]===input.snapshot.manifest_digest&&prior[2]===input.binding.connection_generation&&prior[3]===saved.view.ack_payload_digest,'conflict');return saved.view;}
   need(saved.view.state==='snapshot_ready'&&saved.view.purpose==='canonical_trigger','state');const baseline=snapshots.baseline(saved),number=Number(saved.view.revision)+1;
   written(db.prepare('INSERT INTO service_snapshot_baseline VALUES(?,?,?,?,?,?,?,?)').run(channel.subscription,input.snapshot.snapshot_id,input.snapshot.snapshot_cursor,input.snapshot.manifest_digest,baseline.marker_digest,baseline.journal_sequence,input.binding.connection_generation,number));
   const view={...saved.view,revision:String(number),state:'catching_up',ack_cursor:input.snapshot.snapshot_cursor,ack_payload_digest:baseline.marker_digest};revision(view,'snapshot_applied');
   release(channel);snapshots.baseline(saved);return view;
  });},
  check(handle){const channel=entry(handle);writer(sweep);return writer(()=>release(channel).view);},
  // 仅用于紧随全局失效扫描的连接回收，不是内容释放门。
  poll(handle){const channel=entry(handle);return writer(()=>{need(channel.subscription,'connection');const saved=read(channel.subscription),row=head(channel.subscription);need(['building','snapshot_ready','catching_up'].includes(saved.view.state)&&current(row)&&row[1]===channel.id,'generation');});},
  close(handle){const channel=channels.get(handle);if(!channel||!live.delete(channel.id))return;
   if(channel.subscription)writer(()=>{if(db.prepare('SELECT 1 FROM service_subscription_attempt WHERE connection_id=?').pluck().get(channel.id)&&!db.prepare('SELECT 1 FROM service_subscription_disconnect WHERE connection_id=?').pluck().get(channel.id))written(db.prepare('INSERT INTO service_subscription_disconnect VALUES(?)').run(channel.id));});
  },
  attempt(binding,socket,key,attemptId){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved,false);const row=db.prepare('SELECT connection_id,response_jcs FROM service_subscription_attempt WHERE subscription_id=? AND attempt_id=?').raw().get(key,attemptId);need(row,'not_found');const latest=head(key);return {subscription_id:key,connection_attempt_id:attemptId,attached:JSON.parse(row[1]),current:['building','snapshot_ready','catching_up'].includes(saved.view.state)&&current(latest)&&latest[0]===attemptId};});},
  snapshot(binding,socket,key,generation,page=null){writer(sweep);return writer(()=>{const saved=read(key);authorized({binding,socket},saved);const latest=head(key);need(generation!=='0'&&generation===saved.view.binding.connection_generation&&current(latest)&&latest[2]===generation,'generation');need(saved.view.state==='snapshot_ready','state');return snapshots.content(saved,page);});}
 });
}
