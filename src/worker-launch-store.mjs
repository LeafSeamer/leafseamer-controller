import crypto from 'node:crypto';
import {workerDependencies,currentWorkerDependencies} from './worker-dependencies.mjs';
import {workerRuntimeStore} from './worker-runtime-store.mjs';
import {workerAuthorizationStore} from './worker-authorization-store.mjs';
import {connectDeviceModule} from './device-module-client.mjs';
import {deviceModuleJournal} from './device-module-store.mjs';
import {deviceCatalogStore} from './device-catalog-store.mjs';
import {deviceControlBarrier} from './device-control-barrier.mjs';
import {deviceExecutionJournal,executionJournalHistory} from './device-execution-journal.mjs';
import {connectDeviceExecution} from './device-execution-client.mjs';
import {currentDeviceExecutionBinding} from './device-execution-binding.mjs';
import {currentInitialReady} from './device-initial-ready.mjs';
import {currentControlSource} from './device-control-source.mjs';
import canonicalize from 'canonicalize';
import {decodeWorkerIntent} from './sdk/worker-runtime.mjs';

export class WorkerLaunchError extends Error { constructor(code) { super(code); this.name='WorkerLaunchError'; this.code=code; } }
const need=(ok,code)=>{if(!ok)throw new WorkerLaunchError(code);};
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const same=(a,b)=>canonicalize(a)===canonicalize(b);
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const deepFreeze=value=>{if(value&&typeof value==='object'){for(const child of Object.values(value))deepFreeze(child);Object.freeze(value);}return value;};
const rows=(db,sql,...args)=>{const query=db.prepare(sql),names=query.columns().map(column=>column.name);
  return query.raw().all(...args).map(values=>Object.fromEntries(names.map((name,index)=>[name,values[index]])));};

// 启动意图准备属于核心内部writer，不是安装审批或LaunchAuthorization提供者。
export function workerLaunchStore(db,service,bootId,isOpen,extensionSource,attachStop,openingSource,encodingSource){
  const commandTasks=new Map(),guardTasks=new Map(),dispatchTasks=new Map(),settlementTasks=new Map(),finalAdmissionTasks=new Map(),encodingTails=new Map();
  let pending=0,acquiring=0,runtime=null,authorization=null;const modules=new Map(),contentPins=new Set(),executionJournals=new Set(),executionClients=new Map();attachStop?.(()=>{for(const client of executionClients.values())client?.close();for(const journal of executionJournals)try{journal.end();}catch{}for(const module of modules.values())module?.close();runtime?.close();authorization?.close();for(const pin of contentPins)pin.close();});
  const available=()=>{need(isOpen()&&db.open,'worker_launch_closed');need(!db.inTransaction,'worker_launch_outer_transaction');};
  const fields='launch_id,intent_digest,preparation_id,transaction_id,service_boot_id,intent_jcs';
  function view(row){
    if(!row)return null;
    const intent=JSON.parse(row.intent_jcs);
    need(canonicalize(intent)===row.intent_jcs&&hash(intent)===row.intent_digest,'worker_launch_integrity');
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
      const value=JSON.parse(row[name+'_jcs']);need(canonicalize(value)===row[name+'_jcs'],'worker_launch_integrity');return [name,value];
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
    const journal=deviceExecutionJournal({db,core,isOpen,current:()=>runtime.current(selected),currentInTransaction:()=>runtime.currentInTransaction(selected),invalidate:()=>runtime.invalidate(selected),openingSource,encodingSource});
    journal.open();executionJournals.add(journal);return journal;
  }
  return Object.freeze({runtime,authorization,controlBarrier,
    queueCommandEncoding(id){
      if(commandTasks.has(id))return;
      // 受理响应先完成本轮微任务；后台执行从下一事件轮开始，避免占用响应校验预算。
      const task=new Promise(resolve=>setImmediate(resolve)).then(()=>{
        available();need(Number(service.schema_revision)>=51,'execution_encoding_migration');
        const candidate=db.prepare(`SELECT r.launch_id FROM command_admission_source c JOIN device_execution_binding b USING(binding_id)
          JOIN execution_session s USING(ipc_session_id) JOIN worker_runtime_binding r USING(runtime_id)
          WHERE c.command_id=? AND s.service_boot_id=?`).pluck().get(id,bootId);
        const client=executionClients.get(candidate);need(client,'execution_encoding_source');
        // 同一Execution会话只有一个有序控制出口；多个已受理命令不能互相抢占它。
        const preceding=encodingTails.get(candidate)??Promise.resolve();
        const encoded=preceding.catch(()=>{}).then(()=>client.encodeCommand(id));
        const admitted=encoded.then(result=>Number(service.schema_revision)>=52&&result.response?.value.disposition==='prepared'?
          client.commandFinalAdmission(result.value.prepare_id):null);
        finalAdmissionTasks.set(id,admitted);admitted.catch(()=>{});
        const guarded=admitted.then(result=>Number(service.schema_revision)>=53&&result?client.installCommandGuard(id):null);
        guardTasks.set(id,guarded);guarded.catch(()=>{});
        const dispatched=guarded.then(result=>Number(service.schema_revision)>=54&&result?client.dispatchCommand(id):null);
        dispatchTasks.set(id,dispatched);dispatched.catch(()=>{});
        const settled=dispatched.then(result=>Number(service.schema_revision)>=55&&result?client.closeCommand(id):null);
        settlementTasks.set(id,settled);settled.catch(()=>{});encodingTails.set(candidate,settled);return encoded;
      });
      commandTasks.set(id,task);task.catch(()=>{});
    },
    whenCommandEncoded(id){available();const task=commandTasks.get(id);need(task,'execution_encoding_not_queued');return task;},
    whenCommandGuarded(id){available();const task=guardTasks.get(id)??commandTasks.get(id)?.then(()=>guardTasks.get(id));need(task,'execution_guard_not_queued');return task;},
    whenCommandDispatched(id){available();const task=dispatchTasks.get(id)??commandTasks.get(id)?.then(()=>dispatchTasks.get(id));need(task,'execution_dispatch_not_queued');return task;},
    whenCommandSettled(id){available();const task=settlementTasks.get(id)??commandTasks.get(id)?.then(()=>settlementTasks.get(id));need(task,'execution_settlement_not_queued');return task;},
    whenCommandFinalized(id){available();const task=finalAdmissionTasks.get(id)??commandTasks.get(id)?.then(()=>finalAdmissionTasks.get(id));need(task,'execution_finalization_not_queued');return task;},
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
    async openModule(value){
      available();need(Number(service.schema_revision)>=25,'worker_module_migration_required');const selected=key(value),active=runtime.current(selected);need(!modules.has(selected.launch_id)&&modules.size<4,'worker_module_capacity');
      const reference=active.binding.launch_intent.extension_binding.configuration_ref;
      const row=db.prepare('SELECT body_jcs,body_digest FROM extension_configuration WHERE configuration_id=? AND revision=?').raw().get(reference.object_id,Number(reference.revision));
      need(row&&row[1]===reference.digest,'worker_module_configuration');const body=JSON.parse(row[0]);need(canonicalize(body)===row[0]&&hash(body)===row[1],'worker_module_configuration');
      modules.set(selected.launch_id,null);
      const current=()=>runtime.current(selected);
      const catalog=deviceCatalogStore({db,current,select(intent){const selected=extensionSource.current(intent);return {selected,dependencies:currentWorkerDependencies(db,service,intent,selected)};}});
      const journal=deviceModuleJournal(db,current);
      let module;
      try{module=await connectDeviceModule({current,invalidate:()=>runtime.invalidate(selected),configuration:{reference,value:body.configuration},
        journal:{open:journal.open,record(direction,frame){journal.record(direction,frame);if(direction==='w2c')catalog.receive(frame);}},catalog,
        onClose:()=>modules.delete(selected.launch_id)});
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
        db.prepare('INSERT INTO worker_launch_preparation VALUES('+Array(activation?14:dependencies?13:12).fill('?').join(',')+')').run(intent.launch_id,preparation,transaction,bootId,
          intent.supervisor_instance_id,intent.runtime_generation,intent.member_id,intent.containment_ref.group_id,intent.containment_ref.generation,
          digest,body,'prepared',...(dependencies?[intent.launch_id]:[]),...(activation?[activation]:[]));
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
