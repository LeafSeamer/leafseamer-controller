import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {Duplex} from 'node:stream';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from 'canonicalize';
import {deviceWorkerSession} from '../dist/device-worker-session.mjs';
import {deviceExecutionGate} from '../dist/device-execution-gate.mjs';
import {executionSessionIdentity,executionWire,decodeExecutionPayload} from '../dist/device-execution-channel.mjs';
import {deviceExecutionVersion,deviceExecutionCapabilities} from '../dist/sdk/device-execution.mjs';
const raw=value=>Buffer.from(JSON.stringify(value));
const hash=value=>'sha256:'+crypto.createHash('sha256').update(canonicalize(value)).digest('hex');
const models=JSON.parse(fs.readFileSync(new URL('../dist/sdk/contract/models.schema.json',import.meta.url)));
// 握手远端/特性来源是合成输入，不把会话组件测试当作全部业务处理器已实现。
const features=models.$defs.command__S9__HELLO_ACKBody.properties.selected_features.items.enum;
async function until(predicate){const deadline=performance.now()+3000;while(!predicate()){assert.ok(performance.now()<deadline,'会话检查等待超时');await delay(1);}}
async function fixture(t,options={}){
 const body={descriptor_version:'clock-domain/1',domain_kind:'supervised_runtime',authority_service_id:'controller',runtime_generation:'generation',supervisor_instance_id:'supervisor',
  clock_backend_id:'windows_interrupt_precise',clock_backend_revision:'1',tick_unit:'ns',suspend_accounting:'included',namespace_identity:'windows-global',
  os_boot_identity:{status:'unavailable'},platform_profile_id:'profile',platform_profile_revision:'1'};
 const descriptor={...body,descriptor_digest:hash(body),clock_domain_id:'clock_'+hash(body).slice(7)};
 const identity=executionSessionIdentity({authority_service_id:'controller',database_instance_id:'database',controller_boot_id:'core',worker_boot_id:'worker',
  clock_domain_id:descriptor.clock_domain_id,descriptor_digest:descriptor.descriptor_digest});
 const abort=new AbortController(),devices=new Map(),errors=[],seen=[],writes=[],callbacks=[];let blocked=false,session;
 for(const id of ['a','b'])devices.set(id,deviceExecutionGate({binding:{scope:{authority_service_id:'controller',database_instance_id:'database'},
  controller_boot_id:'core',worker_boot_id:'worker',writer_exit_id:'exit_'+id,ipc_session_id:identity.ipc_session_id,device_id:id,device_session_id:'device_'+id,
  clock_domain_id:identity.clock_domain_id,descriptor_digest:identity.descriptor_digest},tick:()=>10n,signal:abort.signal,failed(error){session?.close(error);},limits:{max_entries:16,max_metadata_bytes:1048576}}));
 const socket=new Duplex({read(){},write(bytes,encoding,callback){writes.push(Buffer.from(bytes));if(blocked)callbacks.push(callback);else callback();}});
 t.after(()=>{session?.close();socket.destroy();for(const callback of callbacks.splice(0))callback();});
 const candidate=frame=>({type:'CLOSE_GATE_ACK',reply_to:frame.message_id,device_id:null,body:{close_id:frame.body.close_id,closed_device_ids:[frame.device_id]}});
 session=deviceWorkerSession({socket,identity,descriptor,devices,signal:abort.signal,failed:error=>errors.push(error),limits:{max_frames:64,max_history_bytes:1048576,max_queue_entries:8,max_queue_bytes:1048576,write_timeout_ms:1000,...options.limits},
  async receive(decoded){seen.push(decoded.frame);
   if(options.openThroughSession&&decoded.frame.type==='OPEN_GATE')await session.send(await devices.get(decoded.frame.device_id).receive(decoded.payload));}});
 function frame(type,id,seq,device,body,reply_to=null,journal_mode='durable'){
  return {ipc_version:deviceExecutionVersion,type,message_id:id,reply_to,ipc_session_id:identity.ipc_session_id,controller_boot_id:'core',worker_boot_id:'worker',
   seq,device_id:device,body,clock_domain_id:identity.clock_domain_id,descriptor_digest:identity.descriptor_digest,journal_mode};
 }
 const hello=await session.start({module_id:'synthetic_module',module_digest:hash('module'),clock_domain_id:identity.clock_domain_id,supported_ipc_versions:[deviceExecutionVersion],
  supported_features:options.features??features,descriptor_digest:identity.descriptor_digest,clock_domain_descriptor:descriptor});
 const ack=frame('HELLO_ACK','hello_ack','1',null,{selected_ipc_version:deviceExecutionVersion,clock_domain_id:identity.clock_domain_id,gate_state:'closed',selected_features:options.selected??options.features??features,
  descriptor_digest:identity.descriptor_digest,clock_domain_descriptor:descriptor},hello.message_id);
 function push(value){socket.push(executionWire(value instanceof Uint8Array?value:raw(value)));}
 if(options.ack!==false){push(ack);await until(()=>session.state.phase==='ready'||session.state.phase==='closed');assert.equal(session.state.phase,'ready');}
 return {session,devices,errors,seen,writes,callbacks,abort,ack,frame,push,candidate,identity,descriptor,
  close(id,seq,device='a'){return frame('CLOSE_GATE',id,seq,device,{close_id:id,reason:'test',scope:'device'});},
  closeAll(id,seq){return frame('CLOSE_GATE',id,seq,null,{close_id:id,reason:'test',scope:'controller'});},
  query(id,seq){return frame('QUERY_BARRIER',id,seq,'a',{barrier_id:id,operation_id:'operation',attempt_binding:{cut_id:'cut',cut_digest:hash('cut'),target_exit_id:'exit_a',attempt_ordinal:'1',previous_barrier_id:null}});},
  queryReply(request){return {type:'BARRIER_UNAVAILABLE',reply_to:request.message_id,device_id:request.device_id,body:{...request.body,reason:'unknown_barrier'}};},
  emergency(id='emergency'){return frame('CLOSE_GATE',id,null,null,{close_id:id,reason:'storage_failed',scope:'controller'},null,'volatile_close');},
  block(){blocked=true;},release(){blocked=false;for(const callback of callbacks.splice(0))callback();}};
}

async function openDevice(f,id,renew=false,options={}){
 const ref=id=>({id,revision:'1',digest:hash(id)}),scope={authority_service_id:'controller',database_instance_id:'database'},binding={scope,controller_boot_id:'core',worker_boot_id:'worker',
  writer_exit_id:'exit_'+id,ipc_session_id:f.identity.ipc_session_id,device_id:id,device_session_id:'device_'+id,clock_domain_id:f.identity.clock_domain_id,descriptor_digest:f.identity.descriptor_digest};
 const revision=renew?'2':'1',barrier=(renew?'renew_':'barrier_')+id,token='token_'+id+'_'+revision,owner=f.devices.get(id);
 if(renew){const body={request_id:barrier,binding,control_authority_ref:ref('control_'+id),before_gate_ref:ref('before_'+id),close_ack_ref:ref('close_'+id),
   target_gate_revision:revision,gate_token:token,selected_tick_ns:'1',expires_tick_ns:'80',lease_until_tick_ns:'100'};
  await owner.receive(raw(f.frame('GATE_FENCE',barrier,'1',id,{...body,request_digest:hash(body)})));
 }else{
  const body={operation_id:'operation_'+id,control_epoch:'epoch',target_version:'1',target_gate_revision:revision,issued_cut_revision:'0',
   ledger_digest:hash([]),open_intents:[],transmission_ledger_digest:hash([]),open_transmission_intents:[],cancel_transmissions:[],cancel_ledger_digest:hash([])};
  await owner.receive(raw(f.frame('FENCE',barrier,'1',id,{...body,barrier_id:barrier,attempt_binding:{cut_id:'cut_'+id,
   cut_digest:hash({type:'FENCE',target_exit_id:binding.writer_exit_id,body}),target_exit_id:binding.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null}})));
 }
 const access={format_version:'gate-access/0.1.0-draft.1',access_id:'access_'+id+'_'+revision,revision:'1',purpose:'ordinary',binding,control_authority_ref:ref('control_'+id),
  control_epoch:'epoch',effective_version:'1',authorization_ref:ref('authorization'),resource_safety_ref:ref('resource'),gate_safety_ref:ref('gate'),protection:null,initial_assessment_ref:null,
  selected_tick_ns:'1',expires_tick_ns:'90'},run={controller_scope:scope,snapshot_revision:'0',entries:[]},command={scope,device_id:id,snapshot_revision:'0',entries:[]},
  time={snapshot_id:'time_'+id,domain:{...scope,provider_id:'provider',provider_boot_id:'provider_boot',runtime_binding_ref:ref('runtime'),clock_domain_id:binding.clock_domain_id,
   descriptor_digest:binding.descriptor_digest,clock_generation:'1'},snapshot_revision:'1',minimum_time_generation:'1',state_ref:ref('time_state')};
 const opening=f.frame('OPEN_GATE','open_'+id+'_'+revision,options.seq??'1',id,{barrier_id:barrier,gate_token:token,device_session_id:binding.device_session_id,control_epoch:'epoch',control_version:'1',
  gate_revision:revision,authorization_revision:'1',clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,lease_until_tick_ns:'100',
  run_deny_snapshot:{...run,snapshot_digest:hash(run)},command_deny_snapshot:{...command,snapshot_digest:hash(command)},reference_time_snapshot:options.absent?null:{...time,snapshot_digest:hash(time)},
  gate_access:{...access,access_digest:hash(access)},protection_assessment:null});
 if(options.frameOnly)return opening;
 await owner.receive(raw(opening));
 assert.equal(owner.state.open,true);
}

test('无参考时间OPEN经协商会话进入实际闸，ACK保留null且未协商时不进入领域处理',async t=>{
 const manual=[...deviceExecutionCapabilities.base,...deviceExecutionCapabilities.manual],absent=deviceExecutionCapabilities.without_reference;
 const f=await fixture(t,{features:[...manual,...absent],openThroughSession:true});
 const opening=await openDevice(f,'a',false,{absent:true,frameOnly:true,seq:'2'});
 f.push(opening);await until(()=>f.writes.length===2||f.session.state.phase==='closed');
 assert.equal(f.session.state.phase,'ready');assert.equal(f.devices.get('a').state.open,true);
 const ack=(await decodeExecutionPayload(f.writes[1].subarray(4),'w2c')).frame;
 assert.equal(ack.type,'OPEN_GATE_ACK');assert.equal(ack.reply_to,opening.message_id);assert.equal(ack.body.reference_time_snapshot_ref,null);
 f.push(opening);await until(()=>f.writes.length===3);assert.deepEqual(f.writes[2],f.writes[1]);
 assert.equal(f.seen.filter(v=>v.type==='OPEN_GATE').length,1);
 for(const selected of [manual,[...manual,...absent,...deviceExecutionCapabilities.reference]]){
  const denied=await fixture(t,{features:[...new Set(selected)],openThroughSession:true});
  denied.push(await openDevice(denied,'a',false,{absent:true,frameOnly:true,seq:'2'}));
  await until(()=>denied.session.state.phase==='closed');assert.equal(denied.writes.length,1);
  assert.equal(denied.seen.filter(v=>v.type==='OPEN_GATE').length,0);assert.equal(denied.devices.get('a').state.open,false);
  assert.match(denied.errors[0].reason??denied.errors[0].message,/execution_feature_missing|execution_reference_snapshot_required/);
 }
});

test('基础能力握手保持关闭，未协商业务在领域回调前被拒绝',async t=>{
 const f=await fixture(t,{features:deviceExecutionCapabilities.base});
 assert.deepEqual(f.session.state.selected_features,deviceExecutionCapabilities.base);
 assert.ok(Object.isFrozen(f.session.state.selected_features));
 assert.ok([...f.devices.values()].every(owner=>!owner.state.open));
 f.push(f.closeAll('base_close','2'));await until(()=>f.writes.length===2);
 assert.equal(f.session.state.phase,'ready');assert.equal(f.seen.length,1);
 f.push(f.query('unselected','3'));await until(()=>f.session.state.phase==='closed');
 assert.match(f.errors[0].reason??f.errors[0].message,/execution_feature_missing/);
 assert.equal(f.seen.length,1);assert.equal(f.writes.length,2);
 const outbound=await fixture(t,{features:deviceExecutionCapabilities.base});
 await assert.rejects(outbound.session.send({type:'EVIDENCE_CANDIDATE',reply_to:null,device_id:'a',body:{
  report_id:'report',command_id:'command',attempt_id:'attempt',device_session_id:'device_a',
  evidence_kind:'module_observation',observation_id:'observation',payload:{}}}));
 assert.equal(outbound.writes.length,1);assert.equal(outbound.session.state.phase,'closed');
});

test('ACK不能选取Worker未宣告的能力',async t=>{
 const f=await fixture(t,{features:deviceExecutionCapabilities.base,selected:features,ack:false});f.push(f.ack);
 await until(()=>f.session.state.phase==='closed');assert.equal(f.seen.length,0);
 assert.equal(f.errors[0].code,'worker_session_features');assert.equal(f.writes.length,1);
});

test('设备重连替换真实闸所有者，旧开放永久失效且新关闭到达新所有者',async t=>{
 const f=await fixture(t);await openDevice(f,'a');const old=f.devices.get('a');
 const next=deviceExecutionGate({binding:{scope:{authority_service_id:'controller',database_instance_id:'database'},
  controller_boot_id:'core',worker_boot_id:'worker',writer_exit_id:'exit_new_a',ipc_session_id:f.identity.ipc_session_id,device_id:'a',device_session_id:'reconnected_a',
  clock_domain_id:f.identity.clock_domain_id,descriptor_digest:f.identity.descriptor_digest},tick:()=>10n,signal:f.abort.signal,failed:error=>f.session.close(error),limits:{max_entries:16,max_metadata_bytes:1048576}});
 f.session.replaceDevice('a',next);assert.equal(old.state.terminal,true);assert.equal(old.state.open,false);assert.equal(next.state.open,false);
 f.push(f.close('new_owner_close','2'));await until(()=>f.writes.length===2);
 assert.equal(next.state.io_sequence,'1');assert.equal(f.session.state.phase,'ready');
 assert.deepEqual((await decodeExecutionPayload(f.writes[1].subarray(4),'w2c')).frame.body.closed_device_ids,['a']);
});

test('正常Controller关闭覆盖所有已登记设备，历史新信封只回原确认且不关闭后来新闸',async t=>{
 const f=await fixture(t);await openDevice(f,'a');await openDevice(f,'b');const close=f.closeAll('all','2');f.push(close);
 await until(()=>f.writes.length===2);const ack=(await decodeExecutionPayload(f.writes[1].subarray(4),'w2c')).frame;
 assert.deepEqual(ack.body.closed_device_ids,['a','b']);assert.equal(ack.reply_to,'all');assert.equal(ack.seq,'2');assert.equal(ack.journal_mode,'durable');
 for(const owner of f.devices.values()){assert.equal(owner.state.open,false);assert.equal(owner.state.terminal,false);assert.equal(owner.state.io_sequence,'3');}
 assert.equal(f.session.state.phase,'ready');assert.equal(f.seen.length,1);
 await openDevice(f,'a',true);await openDevice(f,'b',true);
 const replay={...close,message_id:'all_replay',seq:'3'};f.push(replay);await until(()=>f.writes.length===3);
 const historical=(await decodeExecutionPayload(f.writes[2].subarray(4),'w2c')).frame;
 assert.equal(historical.reply_to,'all_replay');assert.equal(historical.seq,'3');assert.deepEqual(historical.body,ack.body);
 for(const owner of f.devices.values()){assert.equal(owner.state.open,true);assert.equal(owner.state.io_sequence,'5');}
 f.push(close);await until(()=>f.writes.length===4);assert.deepEqual(f.writes[3],f.writes[1]);assert.equal(f.session.state.outgoing,'3');
 for(const owner of f.devices.values())assert.equal(owner.state.open,true);
});

test('单设备关闭范围精确，close_id不能以新信封换范围或正文',async t=>{
 const f=await fixture(t);await openDevice(f,'a');await openDevice(f,'b');const close=f.close('one','2','a');f.push(close);await until(()=>f.writes.length===2);
 assert.equal(f.devices.get('a').state.open,false);assert.equal(f.devices.get('b').state.open,true);
 assert.deepEqual((await decodeExecutionPayload(f.writes[1].subarray(4),'w2c')).frame.body.closed_device_ids,['a']);
 const changed={...close,message_id:'changed',seq:'3',device_id:null,body:{...close.body,scope:'controller'}};
 f.push(changed);await until(()=>f.session.state.phase==='closed');assert.equal(f.writes.length,2);assert.match(f.errors[0].code,/close_conflict/);
 const other=await fixture(t),original=other.closeAll('same','2');other.push(original);await until(()=>other.writes.length===2);
 other.push({...original,message_id:'new_message',seq:'3',body:{...original.body,reason:'different'}});await until(()=>other.session.state.phase==='closed');
 assert.match(other.errors[0].code,/close_conflict/);assert.equal(other.writes.length,2);
});

test('一个设备关闭失败不确认部分集合，普通领域发送器不能伪造关闭ACK',async t=>{
 const f=await fixture(t);await openDevice(f,'a');await openDevice(f,'b');f.devices.get('b').terminate();f.push(f.closeAll('all','2'));
 await until(()=>f.session.state.phase==='closed');assert.equal(f.writes.length,1);for(const owner of f.devices.values())assert.equal(owner.state.terminal,true);
 const forged=await fixture(t);assert.throws(()=>forged.session.send(forged.candidate(forged.close('fake','2'))),/worker_session_owned_response/);
 assert.equal(forged.writes.length,1);assert.equal(forged.session.state.phase,'closed');
});

test('同一worker多设备共用方向水位，回复精确关联原请求且只有一个写出口',async t=>{
 const f=await fixture(t);f.push(f.close('a_close','2','a'));f.push(f.close('b_close','3','b'));
 await until(()=>f.writes.length===3);
 assert.deepEqual(f.seen.map(frame=>frame.seq),['1']);assert.equal(f.session.state.incoming,'3');
 const output=await Promise.all(f.writes.map(wire=>decodeExecutionPayload(wire.subarray(4),'w2c')));
 assert.deepEqual(output.map(value=>value.frame.seq),['1','2','3']);assert.deepEqual(output.slice(1).map(value=>value.frame.reply_to),['a_close','b_close']);
 assert.equal(f.devices.get('a').state.io_sequence,'1');assert.equal(f.devices.get('b').state.io_sequence,'1');assert.equal(f.errors.length,0);
});

test('同一原wire只查原效果并重交原ACK，异字节同ID与同号异ID关闭会话',async t=>{
 const f=await fixture(t),frame=f.close('one','2');f.push(frame);await until(()=>f.writes.length===2);
 f.push(frame);await until(()=>f.writes.length===3);assert.deepEqual(f.writes[2],f.writes[1]);assert.equal(f.devices.get('a').state.io_sequence,'1');assert.equal(f.session.state.outgoing,'2');
 f.push(Buffer.from(JSON.stringify(frame,null,1)));await until(()=>f.session.state.phase==='closed');assert.match(f.errors[0].code,/message_conflict/);
 const other=await fixture(t);other.push(other.close('first','2'));await until(()=>other.session.state.incoming==='2');other.push(other.close('different','2'));
 await until(()=>other.session.state.phase==='closed');assert.match(other.errors[0].code,/sequence/);
});

test('握手核对真实绑定、回应对象、完整时钟原件和特性选择',async t=>{
 for(const change of [value=>{value.worker_boot_id='other';},value=>{value.reply_to='missing';},value=>{value.seq='2';},
  value=>{value.body.clock_domain_descriptor.runtime_generation='other';},value=>{value.body.selected_features.push('unsupported_extra');}]){
  const f=await fixture(t,{ack:false}),ack=structuredClone(f.ack);change(ack);f.push(ack);await until(()=>f.session.state.phase==='closed');
  assert.equal(f.seen.length,0);assert.equal(f.writes.length,1);assert.equal(f.errors.length,1);
 }
});

test('发送前复核拒绝不分配序号，预约后失效不发字节且永久停止后续正常发送',async t=>{
 for(const late of [false,true]){
  const f=await fixture(t),request=f.query('one','2');f.push(request);await until(()=>f.session.state.incoming==='2');let checks=0;
  await assert.rejects(f.session.send(f.queryReply(request),()=>{if(++checks===(late?2:1))throw new Error('selected_state_changed');}),/selected_state_changed/);
  assert.equal(f.session.state.phase,'closed');assert.equal(f.session.state.outgoing,late?'2':'1');assert.equal(f.writes.length,1);
  assert.throws(()=>f.session.send(f.candidate(request)),/worker_session_closed/);
 }
});

test('紧急关闭撤下所有设备并丢弃未预约候选，在同一流完整帧边界发送null序号ACK',async t=>{
 const f=await fixture(t);f.block();f.push(f.close('first','2'));await until(()=>f.callbacks.length===1);
 f.push(f.close('second','3','b'));await until(()=>f.session.state.queued===1);
 const close=f.emergency();f.push(close);await until(()=>f.session.state.phase==='terminal');
 assert.equal(f.devices.get('a').state.terminal,true);assert.equal(f.devices.get('b').state.terminal,true);
 assert.equal(f.writes.length,2);assert.equal(f.session.state.outgoing,'2');
 assert.throws(()=>f.session.send(f.candidate(f.close('late_result','2'))),/worker_session_terminal/);assert.equal(f.session.state.phase,'terminal');
 f.release();await until(()=>f.writes.length===3);const ack=(await decodeExecutionPayload(f.writes[2].subarray(4),'w2c')).frame;
 assert.equal(ack.seq,null);assert.equal(ack.journal_mode,'volatile_close');assert.deepEqual(ack.body.closed_device_ids,['a','b']);assert.equal(ack.reply_to,close.message_id);
 assert.equal(f.session.state.queued,0);assert.equal(f.session.state.outgoing,'2');
 await until(()=>!f.session.state.writing);f.push(close);await until(()=>f.writes.length===4);assert.deepEqual(f.writes[3],f.writes[2]);
 assert.equal(f.session.state.incoming,'3');assert.equal(f.session.state.outgoing,'2');assert.equal(f.errors.length,0);
});

test('写入阻塞超时断流，紧急ACK不能插入未完成前缀；历史容量耗尽不驱逐旧帧',async t=>{
 const f=await fixture(t,{limits:{write_timeout_ms:40}});f.block();f.push(f.close('first','2'));await until(()=>f.callbacks.length===1);
 f.push(f.emergency());await until(()=>f.session.state.phase==='closed');assert.equal(f.writes.length,2);assert.equal(f.errors.length,1);assert.equal(f.errors[0].code,'worker_session_write_timeout');
 const full=await fixture(t,{limits:{max_frames:2}});full.push(full.close('overflow','2'));await until(()=>full.session.state.phase==='closed');
 assert.equal(full.writes.length,1);assert.equal(full.session.state.incoming,'1');assert.match(full.errors[0].code,/history_capacity/);
 const protectedCapacity=await fixture(t,{limits:{max_frames:2}});protectedCapacity.push(protectedCapacity.emergency());await until(()=>protectedCapacity.writes.length===2);
 assert.equal(protectedCapacity.session.state.phase,'terminal');assert.equal(protectedCapacity.session.state.incoming,'1');assert.equal(protectedCapacity.session.state.outgoing,'1');
 assert.equal((await decodeExecutionPayload(protectedCapacity.writes[1].subarray(4),'w2c')).frame.seq,null);assert.equal(protectedCapacity.errors.length,0);
});
