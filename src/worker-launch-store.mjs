import {sqliteRows} from './sqlite-rows.mjs';
import {cacheVerifiedDocument} from './verified-document-cache.mjs';
import crypto from 'node:crypto';
import {workerDependencies,currentWorkerDependencies} from './worker-dependencies.mjs';
import {workerRuntimeStore} from './worker-runtime-store.mjs';
import {workerAuthorizationStore} from './worker-authorization-store.mjs';
import {connectDeviceModule} from './device-module-client.mjs';
import {isObsModuleEntry} from './obs-module-profile.mjs';
import {encodeObsCutPacket} from './obs-cut-packet.mjs';
import {readRegisteredObsResource} from './obs-resource.mjs';
import {deviceModuleJournal} from './device-module-store.mjs';
import {deviceCatalogStore} from './device-catalog-store.mjs';
import {deviceEventSourceStore} from './device-event-source.mjs';
import {deviceEventScopeStore} from './device-event-scope.mjs';
import {deviceEventSourceRef} from './peer-device-events.mjs';
import {deviceControlBarrier} from './device-control-barrier.mjs';
import {deviceExecutionJournal,executionJournalHistory} from './device-execution-journal.mjs';
import {connectDeviceExecution} from './device-execution-client.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {readDeviceCapabilities,readDeviceSceneCatalog} from './device-capability-view.mjs';
import {readDeviceAutomationBindings} from './device-automation-binding.mjs';
import {currentInitialReady} from './device-initial-ready.mjs';
import {currentControlSource} from './device-control-source.mjs';
import canonicalize from 'canonicalize';
import {decodeWorkerIntent} from './sdk/worker-runtime.mjs';
import {deviceExecutionCapabilities} from './sdk/device-execution.mjs';
import {readRunProtectionExits} from './run-protection-exits.mjs';

export class WorkerLaunchError extends Error { constructor(code) { super(code); this.name='WorkerLaunchError'; this.code=code; } }
const need=(ok,code)=>{if(!ok)throw new WorkerLaunchError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const deepFreeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))deepFreeze(child);Object.freeze(value);}return value;};
const rows=sqliteRows;
const readLaunchIntent=cacheVerifiedDocument((text,digest)=>{
  const value=JSON.parse(text);
  need(canonicalize(value)===text&&hash(value)===digest,'worker_launch_integrity');
  return value;
},{immutable:true});
const readCoreOriginal=cacheVerifiedDocument(text=>{
  const value=JSON.parse(text);
  need(canonicalize(value)===text,'worker_launch_integrity');
  return value;
},{immutable:true});

// 启动意图准备属于核心内部writer，不是安装审批或LaunchAuthorization提供者。
export function workerLaunchStore(db,service,bootId,isOpen,extensionSource,attachStop,openingSource,encodingSource,projectReferenceCapture){
  const commandTasks=new Map(),guardTasks=new Map(),dispatchTasks=new Map(),settlementTasks=new Map(),cleanupTasks=new Map(),finalAdmissionTasks=new Map(),encodingTails=new Map();
  let pending=0,acquiring=0,runtime=null,authorization=null;const modules=new Map(),contentPins=new Set(),executionJournals=new Set(),executionClients=new Map();attachStop?.(()=>{for(const client of executionClients.values())client?.close();for(const journal of executionJournals)try{journal.end();}catch{}for(const module of modules.values())module?.close();runtime?.close();authorization?.close();for(const pin of contentPins)pin.close();});
  const available=()=>{need(isOpen()&&db.open,'worker_launch_closed');need(!db.inTransaction,'worker_launch_outer_transaction');};
  const fields='launch_id,intent_digest,preparation_id,transaction_id,service_boot_id,intent_jcs';
  function view(row){
    if(!row)return null;
    const intent=readLaunchIntent(row.intent_jcs,row.intent_digest);
    return deepFreeze({preparation_id:row.preparation_id,transaction_id:row.transaction_id,service_boot_id:row.service_boot_id,
      intent,ref:{kind:'launch_intent',authority_service_id:service.service_id,database_instance_id:service.database_instance_id,
        object_id:row.launch_id,revision:'1',digest:row.intent_digest},current_boot:row.service_boot_id===bootId});
  }
  function key(value){
    need(value&&Object.keys(value).sort().join(',')==='launch_id,launch_intent_digest'&&id(value.launch_id)&&
      typeof value.launch_intent_digest==='string'&&/^sha256:[0-9a-f]{64}(?![\s\S])/.test(value.launch_intent_digest),'worker_launch_key');
    return {...value};
  }
  const find=launch=>rows(db,'SELECT '+fields+' FROM worker_launch_preparation WHERE launch_id=?',launch)[0];
  function core(){
    const row=rows(db,`SELECT r.* FROM core_runtime_binding r JOIN service_boot b USING(service_boot_id)
      WHERE r.service_boot_id=? AND b.state='started' AND b.service_id=? AND b.database_instance_id=?`,bootId,service.service_id,service.database_instance_id)[0];
    need(row,'worker_launch_core_required');
    const result=Object.fromEntries(['intent','descriptor','receipt','policy'].map(name=>{
      return [name,readCoreOriginal(row[name+'_jcs'])];
    }));
    need(result.intent.role==='core'&&result.receipt.role==='core'&&result.receipt.gate_state==='closed'&&
      result.intent.service_id===service.service_id&&result.policy.service_id===service.service_id&&
      result.policy.database_instance_id===service.database_instance_id,'worker_launch_core_required');
    return result;
  }
  runtime=Number(service.schema_revision)>=19?workerRuntimeStore({db,service,bootId,isOpen,core,extension:extensionSource,verifyDependencies:Number(service.schema_revision)>=20?(intent,selected)=>currentWorkerDependencies(db,service,intent,selected):null,prepared(value){const selected=key(value),row=find(selected.launch_id);if(row)need(row.intent_digest===selected.launch_intent_digest,'worker_launch_conflict');return view(row);}}):null;
  authorization=Number(service.schema_revision)>=23?workerAuthorizationStore({db,service,bootId,isOpen,core,extension:extensionSource,
    verifyDependencies:(intent,selected)=>currentWorkerDependencies(db,service,intent,selected),
    prepared(value){const selected=key(value),row=find(selected.launch_id);if(row)need(row.intent_digest===selected.launch_intent_digest,'worker_launch_conflict');return view(row);},
    all(){return rows(db,'SELECT '+fields+' FROM worker_launch_preparation WHERE service_boot_id=? ORDER BY launch_id COLLATE BINARY',bootId).map(view);}}):null;
  const controlBarrier=Number(service.schema_revision)>=26?deviceControlBarrier({db,bootId,authorization,runtime,isOpen}):null;
  function openJournal(selected){
    const journal=deviceExecutionJournal({db,core,isOpen,current:()=>runtime.current(selected),currentInTransaction:()=>runtime.currentInTransaction(selected),invalidate:()=>runtime.invalidate(selected),openingSource,encodingSource:()=>{
      const provider=encodingSource?.();return provider&&{...provider,
        notePreparedQualification(reference,id){executionClients.get(selected.launch_id)?.notePreparedQualification(reference,id);}};
    }});
    journal.open();executionJournals.add(journal);return journal;
  }
  function currentDeviceModule(device){
      need(isOpen()&&db.open&&db.inTransaction&&Number(service.schema_revision)>=25,'device_capabilities_unavailable');
      const candidates=rows(db,`SELECT r.launch_id,p.intent_digest FROM worker_runtime_binding r
       JOIN worker_launch_preparation p USING(launch_id) JOIN worker_launch_device d USING(launch_id)
       LEFT JOIN worker_runtime_withdrawal w USING(runtime_id) WHERE d.device_id=? AND r.service_boot_id=? AND w.runtime_id IS NULL LIMIT 5`,device,bootId);
      need(candidates.length===1,'device_capabilities_unavailable');const candidate=candidates[0],module=modules.get(candidate.launch_id);
      need(module,'device_capabilities_unavailable');const active=runtime.currentInTransaction({launch_id:candidate.launch_id,launch_intent_digest:candidate.intent_digest});
      return {active,module};
  }
  function currentDeviceCatalogInput(device){
      const {active,module}=currentDeviceModule(device);
      const selected=extensionSource.current(active.binding.launch_intent),dependencies=currentWorkerDependencies(db,service,active.binding.launch_intent,selected);
      return {service,device,runtime:active,selected,dependencies,channel:module.binding.ipc_session_id};
  }
  function readDeviceEventsCurrent(device,expectedSourceRef=null,after='0',limit=32){
    need(isOpen()&&db.open&&db.inTransaction&&Number(service.schema_revision)>=64,'device_events_writer');
    const {module}=currentDeviceModule(device);
    const value=module.publishedEvents(device,after,limit);
    need(expectedSourceRef===null||hash(deviceEventSourceRef(value.registration))===hash(expectedSourceRef),'device_events_source_changed');return value;
  }
  function readDeviceEvents(...args){available();return db.transaction(()=>readDeviceEventsCurrent(...args)).immediate();}
  const eventScopes=Number(service.schema_revision)>=65?deviceEventScopeStore({db,service,bootId,currentSource:readDeviceEventsCurrent}):null;
  async function applyRunProtection(plan,assertCurrent=()=>{}){
    available();assertCurrent();
    const fixed=structuredClone(plan),{origin_scope,run_id,device_ids}=fixed;
    need(Array.isArray(device_ids)&&device_ids.length>0&&device_ids.length<=256&&device_ids.every(id)&&new Set(device_ids).size===device_ids.length&&
      typeof fixed.deny_through_generation==='string'&&/^[1-9][0-9]{0,19}(?![\s\S])/.test(fixed.deny_through_generation),'run_protection_targets');
    for(const device_id of device_ids){
      assertCurrent();available();
      const original=db.transaction(()=>readRunProtectionExits(db,device_id,fixed)).immediate();
      if(original.state==='acknowledged')continue;
      const owners=db.prepare(`SELECT DISTINCT r.launch_id,s.ipc_session_id FROM execution_session s
       JOIN worker_runtime_binding r USING(runtime_id) JOIN worker_launch_device d USING(launch_id)
       WHERE d.device_id=? AND s.service_boot_id=?
        AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id)
        AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
       ORDER BY r.launch_id`).raw().all(device_id,bootId);
      for(const [launch,session] of owners){
        if(original.exits.find(exit=>exit.launch_id===launch)?.state!=='pending')continue;
        const client=executionClients.get(launch),module=modules.get(launch);
        if(client?.binding.ipc_session_id!==session||!module||client.state.phase!=='ready'||
         !deviceExecutionCapabilities.automation.every(feature=>client.negotiation.selected_features.includes(feature)))continue;
        const configured=db.prepare(`SELECT 1 FROM device_execution_binding b JOIN device_module_frame f
          ON json_extract(f.frame_jcs,'$.body.execution_ref.id')=b.binding_id
          WHERE b.ipc_session_id=? AND b.device_id=? AND f.channel_id=? AND f.direction='w2c' AND f.message_type='EXECUTION_BOUND' LIMIT 1`)
          .pluck().get(session,device_id,module.binding.ipc_session_id);
        if(!configured)continue;
        assertCurrent();
        try{
          await client.applyRunFence({device_id,origin_scope,run_id});
        }catch(error){
          if(error.code?.startsWith('SQLITE_'))throw error;
          // 保留原批准与落库确认；忙、退出或隔离失败留给下一次扫描。
        }
      }
    }
    assertCurrent();available();
    const targets=db.transaction(()=>device_ids.map(deviceId=>readRunProtectionExits(db,deviceId,fixed))).immediate();
    return {state:targets.every(target=>target.state==='acknowledged')?'acknowledged':'pending',targets};
  }
  return Object.freeze({runtime,authorization,controlBarrier,eventScopes,
    ...(Number(service.schema_revision)>=79&&{applyRunProtection}),
    queueCommandEncoding(id){
      if(commandTasks.has(id))return;
      // 受理响应先完成本轮微任务；后台执行从下一事件轮开始，避免占用响应校验预算。
      const task=new Promise(resolve=>setImmediate(resolve)).then(()=>{
        available();need(Number(service.schema_revision)>=51,'execution_encoding_migration');
        const candidate=db.prepare(`SELECT r.launch_id FROM command_admission_source c JOIN device_execution_binding b USING(binding_id)
          JOIN execution_session s USING(ipc_session_id) JOIN worker_runtime_binding r USING(runtime_id)
          WHERE c.command_id=? AND s.service_boot_id=?`).pluck().get(id,bootId);
        need(candidate,'execution_encoding_source');
        const client=executionClients.get(candidate);need(client,'execution_encoding_source');
        // 同一Execution会话只有一个有序控制出口；多个已受理命令不能互相抢占它。
        const preceding=encodingTails.get(candidate)??Promise.resolve();
        const encoded=preceding.catch(()=>{}).then(()=>client.encodeCommand(id));
        const admitted=encoded.then(result=>Number(service.schema_revision)>=52&&result.response?.value.disposition==='prepared'?
          client.commandFinalAdmission(result.value.prepare_id):null);
        finalAdmissionTasks.set(id,admitted);admitted.catch(()=>{});
        // 自动派发只消费已安装回执；发送器在实际写入边界独立重核当前资格。
        const guarded=admitted.then(result=>Number(service.schema_revision)>=53&&result?client.installCommandGuard(id,{qualify:Number(service.schema_revision)<57}):null);
        guardTasks.set(id,guarded);guarded.catch(()=>{});
        const dispatched=guarded.then(result=>Number(service.schema_revision)>=54&&result?client.dispatchCommand(id):null);
        dispatchTasks.set(id,dispatched);dispatched.catch(()=>{});
        const settled=dispatched.then(result=>Number(service.schema_revision)>=55&&result?client.closeCommand(id):null);
        settlementTasks.set(id,settled);settled.catch(()=>{});
        const cleaned=settled.then(result=>Number(service.schema_revision)>=56&&result?client.cleanupCommand(id):null);
        cleanupTasks.set(id,cleaned);cleaned.catch(()=>{});encodingTails.set(candidate,cleaned);return encoded;
      });
      commandTasks.set(id,task);task.catch(()=>{});
    },
    whenCommandEncoded(id){available();const task=commandTasks.get(id);need(task,'execution_encoding_not_queued');return task;},
    whenCommandGuarded(id){available();const task=guardTasks.get(id)??commandTasks.get(id)?.then(()=>guardTasks.get(id));need(task,'execution_guard_not_queued');return task;},
    whenCommandDispatched(id){available();const task=dispatchTasks.get(id)??commandTasks.get(id)?.then(()=>dispatchTasks.get(id));need(task,'execution_dispatch_not_queued');return task;},
    whenCommandSettled(id){available();const task=settlementTasks.get(id)??commandTasks.get(id)?.then(()=>settlementTasks.get(id));need(task,'execution_settlement_not_queued');return task;},
    whenCommandCleaned(id){available();const task=cleanupTasks.get(id)??commandTasks.get(id)?.then(()=>cleanupTasks.get(id));need(task,'execution_cleanup_not_queued');return task;},
    whenCommandFinalized(id){available();const task=finalAdmissionTasks.get(id)??commandTasks.get(id)?.then(()=>finalAdmissionTasks.get(id));need(task,'execution_finalization_not_queued');return task;},
    deviceCapabilitiesCurrent(device){return readDeviceCapabilities(db,currentDeviceCatalogInput(device));},
    deviceSceneCatalogCurrent(device,includeConfirmation){return readDeviceSceneCatalog(db,currentDeviceCatalogInput(device),includeConfirmation);},
    prepareObsCutPacket(device,parameters){
      const prepare=()=>{
        const catalog=readDeviceSceneCatalog(db,currentDeviceCatalogInput(device));
        return encodeObsCutPacket(catalog,{device_id:device,device_session_id:catalog.device_session_id},parameters);
      };
      return db.inTransaction?prepare():db.transaction(prepare).immediate();
    },
    deviceAutomation(device,expectedRegistrationRef=null){available();return db.transaction(()=>readDeviceAutomationBindings(db,currentDeviceCatalogInput(device),expectedRegistrationRef)).immediate();},
    deviceAutomationCurrent(device,expectedRegistrationRef=null){return readDeviceAutomationBindings(db,currentDeviceCatalogInput(device),expectedRegistrationRef);},
    deviceEvents:readDeviceEvents,
    commandExecutionCurrent(device,{requireReady=false,preparedRef=null}={}){
      need(isOpen()&&db.open&&db.inTransaction&&Number(service.schema_revision)>=30,'command_execution_source');
      const candidates=rows(db,`SELECT r.launch_id,p.intent_digest,s.ipc_session_id FROM execution_session s
       JOIN worker_runtime_binding r USING(runtime_id) JOIN worker_launch_preparation p USING(launch_id)
       JOIN worker_launch_device d USING(launch_id) LEFT JOIN execution_session_end e USING(ipc_session_id)
       LEFT JOIN worker_runtime_withdrawal w USING(runtime_id)
       WHERE d.device_id=? AND r.service_boot_id=? AND e.ipc_session_id IS NULL AND w.runtime_id IS NULL LIMIT 5`,device,bootId);
      need(candidates.length===1,'command_execution_source');const candidate=candidates[0],client=executionClients.get(candidate.launch_id),module=modules.get(candidate.launch_id);
      need(client&&module&&client.binding.ipc_session_id===candidate.ipc_session_id&&client.state.phase==='ready','command_execution_source');
      const active=runtime.currentInTransaction({launch_id:candidate.launch_id,launch_intent_digest:candidate.intent_digest});
      const bound=currentDeviceExecutionBinding(db,active,device,candidate.ipc_session_id);
      need(module.binding.ipc_session_id===bound.catalog.channel_id,'command_execution_source');
      let ready=null;
      if(requireReady){
        need(Number(service.schema_revision)>=48&&controlBarrier,'command_execution_ready');
        const control=currentControlSource(db,device);
        const readyId=db.prepare('SELECT ready_id FROM device_initial_ready WHERE control_source_id=?').pluck().get(control.current.ref.id);
        need(readyId,'command_execution_ready');
        // 在调用者的writer内检查原件和全部当前来源。不能调用会另开事务的client.currentReady，
        // 也不能把客户端缓存的ready_devices或会话默认闸当成设备发送资格。
        const selected=currentInitialReady(db,{binding:client.binding,runtime:active,id:readyId,provider:openingSource?.(),
          tick:()=>BigInt(controlBarrier.domain().tick),preparedRef});
        need(same(selected.value.binding,bound.value.binding),'command_execution_ready');
        client.noteReadyQualification(selected.ref);
        ready={ref:selected.ref,value:selected.value,...(selected.prepared_resource?{prepared_resource:selected.prepared_resource}:{})};
      }
      return deepFreeze({...bound,negotiation:client.negotiation,channel_state:client.state,ready});
    },
    queryExecutionJournal(sessionId){available();need(Number(service.schema_revision)>=27,'execution_migration_required');return executionJournalHistory(db,sessionId);},
    openExecutionJournal(value){
      available();need(Number(service.schema_revision)>=27,'execution_migration_required');const selected=key(value);
      return openJournal(selected);
    },
    async openExecution(value){
      available();need(Number(service.schema_revision)>=30,'execution_handshake_migration');const selected=key(value);
      need(!executionClients.has(selected.launch_id)&&executionClients.size<4,'execution_client_capacity');
      const journal=openJournal(selected);executionClients.set(selected.launch_id,null);let client;
      try{client=await connectDeviceExecution({journal,current:()=>runtime.current(selected),invalidate:()=>runtime.invalidate(selected),
        onClose:()=>executionClients.delete(selected.launch_id)});available();runtime.current(selected);executionClients.set(selected.launch_id,client);return client;
      }catch(error){executionClients.delete(selected.launch_id);client?.close();throw error;}
    },
    async openModule(value,{events=false}={}){
      available();need(Number(service.schema_revision)>=25,'worker_module_migration_required');const selected=key(value),active=runtime.current(selected);need(!modules.has(selected.launch_id)&&modules.size<4,'worker_module_capacity');
      need(typeof events==='boolean'&&(!events||Number(service.schema_revision)>=63),'worker_module_event_migration_required');
      const reference=active.binding.launch_intent.extension_binding.configuration_ref;
      const row=db.prepare('SELECT body_jcs,body_digest FROM extension_configuration WHERE configuration_id=? AND revision=?').raw().get(reference.object_id,Number(reference.revision));
      need(row&&row[1]===reference.digest,'worker_module_configuration');const body=JSON.parse(row[0]);need(canonicalize(body)===row[0]&&hash(body)===row[1],'worker_module_configuration');
      modules.set(selected.launch_id,null);
      const current=()=>db.inTransaction?runtime.currentInTransaction(selected):runtime.current(selected);
      const catalog=deviceCatalogStore({db,current,select(intent){const selected=extensionSource.current(intent);return {selected,dependencies:currentWorkerDependencies(db,service,intent,selected)};}});
      const journal=deviceModuleJournal(db,current),eventSource=events&&Number(service.schema_revision)>=64?deviceEventSourceStore({db,current,catalog,projectReferenceCapture}):null;
      let module;
      try{
        const configuration=db.transaction(()=>{
          const checked=current(),intent=checked.binding.launch_intent,chosen=extensionSource.current(intent);
          if(!isObsModuleEntry(chosen.content,chosen.entry))return {reference,value:body.configuration};
          const graph=currentWorkerDependencies(db,service,intent,chosen),link=graph.links[0],obs=link?.obs_binding;
          need(!events&&graph.links.length===1&&obs,'worker_module_obs_scope');
          const registered=readRegisteredObsResource(db,service,link.device_ref.object_id);
          need(same(registered.resource_ref,obs.resource_ref)&&same(body.configuration,{resource_ref:obs.resource_ref,secret_ref:obs.secret_ref}),'worker_module_obs_binding');
          return {reference,value:{...body.configuration,resource_record:registered.record}};
        }).immediate();
        module=await connectDeviceModule({events,eventSource,current,invalidate:()=>runtime.invalidate(selected),configuration,
        journal:{open:journal.open,record(direction,frame){journal.record(direction,frame);if(direction==='w2c')catalog.receive(frame);}},catalog,
        onClose:()=>{try{eventSource?.close();}finally{modules.delete(selected.launch_id);}}});
        available();current();modules.set(selected.launch_id,module);return module;
      }catch(error){modules.delete(selected.launch_id);module?.close();try{runtime.invalidate(selected);}catch{}throw error;}
    },
    async prepare(input){
      available();need(Buffer.isBuffer(input)&&input.length<=262144,'worker_launch_input');
      const bytes=Buffer.from(input);
      const intent=await decodeWorkerIntent(bytes,{authority:'controller',service_id:service.service_id,database_instance_id:service.database_instance_id});
      const body=canonicalize(intent),digest=hash(intent);available();
      const existing=db.transaction(()=>{const row=find(intent.launch_id);if(!row)return null;
        need(row.intent_digest===digest,'worker_launch_conflict');need(row.service_boot_id===bootId,'worker_launch_stale_boot');return view(row);}).immediate();
      if(existing)return existing;need(pending<4,'worker_launch_capacity');++pending;
      try{
      let observed=null;
      if(Number(service.schema_revision)>=18){need(extensionSource,'worker_launch_approval_source');observed=await extensionSource.observe(intent);available();}
      return db.transaction(()=>{
        const prior=find(intent.launch_id);
        if(prior){need(prior.intent_digest===digest,'worker_launch_conflict');need(prior.service_boot_id===bootId,'worker_launch_stale_boot');return view(prior);}
        const selected=observed?extensionSource.current(intent):null;
        if(observed)need(same(selected,observed),'worker_launch_approval_stale');
        const dependencies=Number(service.schema_revision)>=20?workerDependencies(db,service,intent,selected):null;
        const activation=Number(service.schema_revision)>=22?extensionSource.activation(intent):null;
        const parent=core(),domain=parent.descriptor;
        need(intent.supervisor_instance_id===domain.supervisor_instance_id&&intent.runtime_generation===domain.runtime_generation&&
          intent.policy_revision===parent.policy.policy_revision&&same(intent.artifact_manifest_ref,parent.intent.artifact_manifest_ref)&&
          intent.containment_ref.backend==='windows_job'&&intent.containment_ref.group_id!==parent.intent.containment_ref.group_id&&
          intent.member_id!==parent.intent.member_id&&intent.launch_id!==parent.intent.launch_id,'worker_launch_binding');
        const profile=intent.extension_binding.platform_profile_ref;
        need(profile.object_id===domain.platform_profile_id&&profile.revision===domain.platform_profile_revision,'worker_launch_binding');
        need(db.prepare('SELECT count(*) FROM worker_launch_preparation').pluck().get()<4096&&
          db.prepare('SELECT count(*) FROM worker_launch_preparation WHERE service_boot_id=?').pluck().get(bootId)<256,'worker_launch_capacity');
        for(const device of intent.object_scope.device_ids)need(db.prepare('SELECT 1 FROM device_record WHERE device_id=?').pluck().get(device),'worker_launch_device_missing');
        need(!db.prepare(`SELECT 1 FROM worker_launch_preparation WHERE supervisor_instance_id=? AND
          (member_id=? OR (group_id=? AND group_generation=?))`).pluck().get(intent.supervisor_instance_id,intent.member_id,intent.containment_ref.group_id,intent.containment_ref.generation),'worker_launch_identity_conflict');
        const preparation=crypto.randomUUID(),transaction=crypto.randomUUID();
        if(activation?.replacement){
          const r=activation.replacement;
          need(db.prepare('INSERT INTO obs_worker_launch_replacement VALUES(?,?,?,?,?,?)')
            .run(r.launch_id,r.activation_operation_id,r.previous_launch_id,r.control_operation_id,canonicalize(r),hash(r)).changes===1,
            'worker_launch_replacement_storage');
        }
        db.prepare('INSERT INTO worker_launch_preparation VALUES('+Array(activation?14:dependencies?13:12).fill('?').join(',')+')').run(intent.launch_id,preparation,transaction,bootId,
          intent.supervisor_instance_id,intent.runtime_generation,intent.member_id,intent.containment_ref.group_id,intent.containment_ref.generation,
          digest,body,'prepared',...(dependencies?[intent.launch_id]:[]),...(activation?[activation.id]:[]));
        if(dependencies)db.prepare('INSERT INTO worker_launch_dependencies VALUES(?,?,?)').run(intent.launch_id,canonicalize(dependencies),hash(dependencies));
        for(const device of intent.object_scope.device_ids)db.prepare('INSERT INTO worker_launch_device VALUES(?,?)').run(intent.launch_id,device);
        const audit=canonicalize({kind:'worker_launch_prepared',transaction_id:transaction,preparation_id:preparation,
          service_boot_id:bootId,launch_id:intent.launch_id,intent_digest:digest});
        db.prepare('INSERT INTO worker_launch_preparation_commit VALUES(?,?,?,?,?)').run(transaction,intent.launch_id,preparation,digest,audit);
        return view(find(intent.launch_id));
      }).immediate();
      }finally{--pending;}
    },
    async acquireContent(value){
      available();const selected=key(value);need(extensionSource&&Number(service.schema_revision)>=18,'worker_launch_approval_source');
      const prepared=db.transaction(()=>{const row=find(selected.launch_id);need(row&&row.intent_digest===selected.launch_intent_digest,'worker_launch_conflict');
        need(row.service_boot_id===bootId,'worker_launch_stale_boot');core();const result=view(row);if(Number(service.schema_revision)>=20)currentWorkerDependencies(db,service,result.intent,extensionSource.current(result.intent));return result;}).immediate();
      need(acquiring+contentPins.size<4,'worker_launch_capacity');++acquiring;let pin;
      try{pin=await extensionSource.acquire(prepared.intent);available();contentPins.add(pin);pin.closed.then(()=>contentPins.delete(pin));return pin;}
      catch(error){if(pin)await pin.close();throw error;}finally{--acquiring;}
    },
    dependencies(value){available();need(Number(service.schema_revision)>=20,'worker_dependency_migration_required');const selected=key(value);return db.transaction(()=>{
      const row=find(selected.launch_id);need(row&&row.intent_digest===selected.launch_intent_digest,'worker_launch_conflict');need(row.service_boot_id===bootId,'worker_launch_stale_boot');
      core();const result=view(row);return currentWorkerDependencies(db,service,result.intent,extensionSource.current(result.intent));
    }).immediate();},
    query(value){available();const selected=key(value);return db.transaction(()=>{
      const row=find(selected.launch_id);if(row)need(row.intent_digest===selected.launch_intent_digest,'worker_launch_conflict');return view(row);
    }).immediate();},
    current(){available();return db.transaction(()=>{
      core();return Object.freeze(rows(db,'SELECT '+fields+' FROM worker_launch_preparation WHERE service_boot_id=? ORDER BY launch_id COLLATE BINARY',bootId).map(view));
    }).immediate();}
  });
}
