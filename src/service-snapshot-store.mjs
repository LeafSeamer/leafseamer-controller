import crypto from 'node:crypto';
import {canonical,digest,same} from './auth-clock-value.mjs';
import {IdentityError} from './identity-error.mjs';
import {sealSourceSnapshot,snapshotBudget} from './service-snapshot-content.mjs';
const need=(ok,reason)=>{if(!ok)throw new IdentityError('snapshot_'+reason);};
const written=r=>need(r.changes===1,'storage');
const date=ns=>new Date(Number(ns/1000000n)).toISOString();
const known=e=>e instanceof IdentityError||['ClockError','WorkerLaunchError','WorkerRuntimeError','DeviceModuleError'].includes(e.name);
export function serviceSnapshotStore({db,bootId,writer,time,domain,sourceCut,read,revision,terminate,checkCurrent}){
 let busy=false,pending=null;
 function domainNow(){need(typeof domain==='function','domain_unavailable');const current=domain();need(current&&typeof current.tick==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(current.tick)&&current.ref,'domain');return current;}
 function invalidate(key,reason){const old=db.prepare('SELECT 1 FROM service_snapshot_end WHERE snapshot_id=?').pluck().get(key);if(!old)written(db.prepare('INSERT INTO service_snapshot_end VALUES(?,?,?,NULL)').run(key,'invalidated',reason));}
 function reserve(key){const saved=read(key);need(saved.view.state==='building','state');checkCurrent(saved);const current=domainNow();
  const owner=digest(saved.view.owner),active=db.prepare('SELECT owner_key,reserved_bytes FROM service_snapshot_build WHERE snapshot_id NOT IN(SELECT snapshot_id FROM service_snapshot_end)').raw().all();
  const used=db.prepare('SELECT coalesce(sum(stored_bytes),0) FROM service_snapshot_manifest').pluck().get();
  if(active.length>=4||active.some(row=>row[0]===owner)||used+active.reduce((n,row)=>n+row[1],0)+snapshotBudget.total>67108864)return null;
  const snapshotId=crypto.randomUUID(),pin=String(db.prepare('SELECT coalesce(max(sequence),0) FROM device_source_notification').pluck().get()),deadline=String(BigInt(current.tick)+snapshotBudget.build);
  written(db.prepare('INSERT INTO service_snapshot_build VALUES(?,?,?,?,?,?,?,?,?)').run(snapshotId,key,owner,bootId,canonical(current.ref),current.tick,deadline,pin,snapshotBudget.total));
  return {snapshotId,key,saved,domain:current.ref,started:current.tick,deadline,pin};
 }
 function gate(build){const saved=read(build.key);need(saved.view.state==='building'&&same(saved.creation,build.saved.creation)&&saved.creation.service_boot_id===bootId,'state');checkCurrent(saved);
  const current=domainNow();need(same(current.ref,build.domain)&&BigInt(current.tick)>=BigInt(build.started)&&BigInt(current.tick)<BigInt(build.deadline),'deadline');
  const pin=db.prepare('SELECT journal_pin FROM service_snapshot_build WHERE snapshot_id=? AND boot_id=?').pluck().get(build.snapshotId,bootId);need(pin===build.pin&&!db.prepare('SELECT 1 FROM service_snapshot_end WHERE snapshot_id=?').pluck().get(build.snapshotId),'reservation');
  return {current,now:time(),saved};
 }
 function seal(build,cut){
  const {now,current}=writer(()=>gate(build));need(BigInt(cut.journal_sequence)>=BigInt(build.pin),'journal');
   need(same(cut.scope_ref,build.saved.creation.authorization.scope_ref),'scope');
   const authEnd=BigInt(build.saved.creation.expires_ns),displayEnd=now.lower+snapshotBudget.apply;
   build.applyDeadline=String(BigInt(current.tick)+snapshotBudget.apply);
   return sealSourceSnapshot({view:build.saved.view,cut,snapshotId:build.snapshotId,domainRef:build.domain,createdAt:date(now.lower),expiresAt:date(displayEnd<authEnd?displayEnd:authEnd)});
 }
 function publish(build,cut,sealed){
  return writer(()=>{const {current,saved}=gate(build);
   const nextRevision=Number(saved.view.revision)+1;
   written(db.prepare('INSERT INTO service_snapshot_manifest VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').run(build.snapshotId,build.key,nextRevision,sealed.manifestBody,sealed.manifest.manifest_digest,sealed.pages.length,sealed.storedBytes,cut.journal_sequence,current.tick,build.applyDeadline,sealed.markerBody,sealed.markerDigest));
   for(const page of sealed.pages)written(db.prepare('INSERT INTO service_snapshot_page VALUES(?,?,?,?,?)').run(build.snapshotId,page.page_index,page.body,page.content_digest,page.content_bytes));
   revision({...saved.view,revision:String(nextRevision),state:'snapshot_ready',snapshot_ref:sealed.snapshotRef},'snapshot_published');
   written(db.prepare('INSERT INTO service_snapshot_end VALUES(?,?,NULL,?)').run(build.snapshotId,'published',build.snapshotId));
   // 序列化和所有写入也消耗原五秒预算；不因封存而重置。
   const last=domainNow();checkCurrent(read(build.key));need(same(last.ref,build.domain)&&BigInt(last.tick)>=BigInt(current.tick)&&BigInt(last.tick)<BigInt(build.deadline),'deadline');
   return sealed.snapshotRef;
  });
 }
 function publishedCurrent(saved,requireDeadline=true){
  const key=saved.view.snapshot_ref?.snapshot_id,row=db.prepare('SELECT b.boot_id,b.domain_jcs,m.published_tick,m.deadline_tick,m.body_jcs,m.body_digest,m.page_count,m.marker_jcs,m.marker_digest FROM service_snapshot_build b JOIN service_snapshot_manifest m USING(snapshot_id) JOIN service_snapshot_end e USING(snapshot_id) WHERE b.snapshot_id=? AND e.state=\'published\'').raw().get(key);
  need(row&&row[0]===bootId,'missing');const current=domainNow();need(same(current.ref,JSON.parse(row[1]))&&BigInt(current.tick)>=BigInt(row[2])&&(!requireDeadline||BigInt(current.tick)<BigInt(row[3])),'deadline');
  const manifest=JSON.parse(row[4]),{manifest_digest,...unsigned}=manifest;need(canonical(manifest)===row[4]&&digest(unsigned).slice(7)===row[5]&&manifest_digest===row[5]&&saved.view.snapshot_ref.manifest_digest===row[5],'integrity');
  const pages=db.prepare('SELECT page_index,body_jcs,body_digest,content_bytes FROM service_snapshot_page WHERE snapshot_id=? ORDER BY page_index').raw().all(key);need(pages.length===row[6],'integrity');
  for(const [index,body,hash,bytes]of pages){const value=JSON.parse(body);need(canonical(value)===body&&digest(value).slice(7)===hash&&Buffer.byteLength(body)===bytes&&manifest.pages[index]?.content_digest===hash&&manifest.pages[index]?.content_bytes===bytes,'integrity');}
  need(digest(JSON.parse(row[7])).slice(7)===row[8]&&same(JSON.parse(row[7]),{entry_kind:'snapshot.baseline',payload:saved.view.snapshot_ref}),'integrity');
 }
 return Object.freeze({
  baseline(saved,requireDeadline=true){publishedCurrent(saved,requireDeadline);const row=db.prepare('SELECT journal_sequence,marker_digest FROM service_snapshot_manifest WHERE snapshot_id=?').raw().get(saved.view.snapshot_ref.snapshot_id);return {journal_sequence:row[0],marker_digest:row[1]};},
  lease(saved){publishedCurrent(saved);const row=db.prepare('SELECT b.domain_jcs,m.deadline_tick FROM service_snapshot_build b JOIN service_snapshot_manifest m USING(snapshot_id) WHERE b.snapshot_id=?').raw().get(saved.view.snapshot_ref.snapshot_id);return {domain:JSON.parse(row[0]),deadline:row[1]};},
  content(saved,page=null){publishedCurrent(saved);const key=saved.view.snapshot_ref.snapshot_id;
   const manifest=JSON.parse(db.prepare('SELECT body_jcs FROM service_snapshot_manifest WHERE snapshot_id=?').pluck().get(key));
   if(page===null)return manifest;need(page.snapshot_id===key&&Number.isInteger(page.page_index),'page');
   const row=db.prepare('SELECT body_jcs,body_digest FROM service_snapshot_page WHERE snapshot_id=? AND page_index=?').raw().get(key,page.page_index);need(row,'page');
   return {manifest_digest:manifest.manifest_digest,content_digest:row[1],content:JSON.parse(row[0]),delivery_binding:saved.view.binding};
  },
  // 仅由共享writer调用；进程中断留下的预留绝不重新采集补页。
  sweep(){for(const [snapshot,key]of db.prepare('SELECT snapshot_id,subscription_id FROM service_snapshot_build WHERE snapshot_id NOT IN(SELECT snapshot_id FROM service_snapshot_end)').raw().all()){if(snapshot===pending?.build.snapshotId)continue;invalidate(snapshot,'abandoned');terminate(read(key),'resync_required');}
   for(const key of db.prepare("SELECT subscription_id FROM service_event_subscription_revision JOIN service_event_subscription_head USING(subscription_id,revision) WHERE state IN('snapshot_ready','catching_up','live')").pluck().all()){
    const saved=read(key);try{publishedCurrent(saved,saved.view.state==='snapshot_ready');}catch(error){if(!known(error)&&!(error instanceof SyntaxError))throw error;terminate(saved,'resync_required',error.code??error.name);}
   }
  },
  // 每次调度只推进一个阶段；阶段之间释放writer与读取连接，保留原预留截止。
  buildPending(){if(busy)return;busy=true;let build=pending?.build,key=build?.key;try{
   if(!pending){key=writer(()=>db.prepare("SELECT s.subscription_id FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision) WHERE r.state='building' AND NOT EXISTS(SELECT 1 FROM service_snapshot_build b WHERE b.subscription_id=s.subscription_id) ORDER BY s.rowid LIMIT 1").pluck().get());if(!key)return;
    build=writer(()=>reserve(key));if(build)pending={build,phase:'read'};return;}
   if(pending.phase==='read'){writer(()=>gate(build));pending.cut=sourceCut(build.saved.creation.authorization.scope_ref);pending.phase='seal';return;}
   if(pending.phase==='seal'){pending.sealed=seal(build,pending.cut);pending.phase='publish';return;}
   publish(build,pending.cut,pending.sealed);pending=null;
  }catch(error){pending=null;if(!known(error)||error.code==='snapshot_storage'||error.code==='subscription_storage')throw error;if(key)writer(()=>{if(build)invalidate(build.snapshotId,error.code??error.name);terminate(read(key),'resync_required');});
  }finally{busy=false;}}
 });
}
