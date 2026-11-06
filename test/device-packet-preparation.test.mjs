import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {devicePacketPreparation} from '../dist/device-packet-preparation.mjs';
import {deviceTransmissionWriter} from '../dist/device-transmission-writer.mjs';
import {deviceExecutionGate} from '../dist/device-execution-gate.mjs';
import {authorizationRevoked} from '../dist/device-authorization-fence.mjs';
import {createDeviceModule} from '../dist/simulator-control-module.mjs';
import {decodeExecutionPayload} from '../dist/device-execution-channel.mjs';
import {deviceExecutionVersion} from '../dist/sdk/device-execution.mjs';
const hash=value=>'sha256:'+crypto.createHash('sha256').update(typeof value==='string'?value:canonicalize(value)).digest('hex');
const raw=value=>Buffer.from(JSON.stringify(value));
const ref=id=>({id,revision:'1',digest:hash(id)});
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
const turn=()=>new Promise(resolve=>setImmediate(resolve));
function signCut(frame){const {barrier_id,attempt_binding,...body}=frame.body;
 frame.body.attempt_binding.cut_digest=hash({type:frame.type,target_exit_id:attempt_binding.target_exit_id,body});return frame;}
async function fixture(options={}){
 const abort=new AbortController(),module=createDeviceModule({configuration:{},device_ids:['device'],signal:abort.signal});
 const device={device_id:'device',device_session_id:'device_session',signal:abort.signal};await module.connectReadOnly(device);
 const binding={scope:{authority_service_id:'controller',database_instance_id:'database'},controller_boot_id:'core.boot',worker_boot_id:'worker.boot',
  writer_exit_id:'exit',ipc_session_id:'ipc',device_id:'device',device_session_id:'device_session',clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:'sha256:'+'2'.repeat(64)};
 const profile=ref('profile'),plan=ref('plan'),capability=ref('capability'),errors=[];let tick=10n,calls=0;
 const executor={api_version:'leafseamer-device-primitives/1',async encodePrimitive(input){calls++;return options.encode?options.encode(input,module):module.execution.encodePrimitive(input);}};
 const cache=devicePacketPreparation({binding,profile,plan,capability,exit:{socket_instance_id:'socket',protocol_session:null},executor,tick:()=>tick,signal:abort.signal,failed:error=>errors.push(error),
  limits:options.limits??{max_entries:256,max_cached_bytes:1048576,max_metadata_bytes:16777216,max_encoders:4}});
 function encode(id='prepare',value=42){
  const request={context_id:'context',idempotency_key:'key.'+id,device_id:'device',action_id:'leafseamer.simulator.value.set',capability_version:'1.0.0',parameters:{value},
   expected_control:{epoch:'epoch',version:'1'},origin:'manual',automation_binding:null,required_completion:'effect_verified',preconditions:[],dispatch:{mode:'immediate',max_queue_ms:1000},evidence_timeout_ms:1000};
  const {context_id,idempotency_key,...content}=request;
  const authority={format_version:'encoding-authorization/0.1.0-draft.1',authorization_id:'authorization.'+id,revision:'1',binding,
   target:{kind:'ordinary',command_ref:ref('command_'+id),proposed_attempt_id:'attempt_'+id,cancellation_ref:null,execution_ref:null},
   requester:{kind:'human',issuer_id:'issuer',issuer_epoch:'issuer.1',principal_id:'person'},admission_source_ref:ref('admission.'+id),authorization_snapshot_ref:ref('authorization.snapshot'),
   capability_ref:capability,primitive_id:'simulator_value_set',primitive_plan_ref:plan,transport_profile_ref:profile,content_digest:hash(content),
   encoding_reservation_ref:ref('reservation.'+id),max_bytes:8,created_tick_ns:'1',expires_tick_ns:'100'};
  return envelope('ENCODE_PACKET','encode.'+id,{prepare_id:id,command_id:authority.target.command_ref.id,attempt_id:authority.target.proposed_attempt_id,primitive_id:authority.primitive_id,
   device_session_id:'device_session',request,primitive_plan_ref:{object_id:plan.id,digest:plan.digest},transport_profile_ref:{object_id:profile.id,digest:profile.digest},expires_tick_ns:'100',
   encoding_authorization:{...authority,authorization_digest:hash(authority)}});
 }
 function envelope(type,id,body){return {ipc_version:deviceExecutionVersion,type,message_id:id,reply_to:null,
  ipc_session_id:binding.ipc_session_id,controller_boot_id:binding.controller_boot_id,worker_boot_id:binding.worker_boot_id,seq:'1',device_id:'device',body,
  clock_domain_id:binding.clock_domain_id,descriptor_digest:binding.descriptor_digest,journal_mode:'durable'};}
 function cleanup(frame,type='RELEASE_ENCODING'){
  const a=frame.body.encoding_authorization,id=type==='RELEASE_ENCODING'?'release_id':'deny_id';
  const body={[id]:type+'.'+frame.body.prepare_id,revision:'1',binding,prepare_id:frame.body.prepare_id,encoding_authorization_ref:{id:a.authorization_id,revision:'1',digest:a.authorization_digest},
   encode_message_id:frame.message_id,encode_frame_digest:hash(frame),revocation_ref:ref('revocation'),selected_tick_ns:String(tick)};
  return envelope(type,type+'.message.'+frame.body.prepare_id,{...body,request_digest:hash(body)});
 }
 async function response(candidate){return (await decodeExecutionPayload(raw({...envelope(candidate.type,'reply',candidate.body),device_id:candidate.device_id,reply_to:candidate.reply_to}),'w2c')).frame;}
 return {cache,module,device,abort,binding,errors,encode,cleanup,response,envelope,clock:()=>tick,tick:value=>{tick=value;},calls:()=>calls};
}

async function sending(options={}){
 const f=await fixture(),encoded=f.encode();await f.cache.prepare(raw(encoded));await f.cache.whenPrepared('prepare');
 const accessBody={format_version:'gate-access/0.1.0-draft.1',access_id:'access',revision:'1',purpose:'ordinary',binding:f.binding,
  control_authority_ref:ref('control'),control_epoch:'epoch',effective_version:'1',authorization_ref:ref('authorization'),resource_safety_ref:ref('resource'),gate_safety_ref:ref('gate'),
  protection:null,initial_assessment_ref:null,selected_tick_ns:'1',expires_tick_ns:'100'};
 let writer;
 const gateOwner=deviceExecutionGate({binding:f.binding,transmissions:()=>{const value=writer?.fenceSnapshot();return value&&options.transmissions?options.transmissions(value):value;},tick:f.clock,signal:f.abort.signal,failed:error=>f.errors.push(error),limits:options.gateLimits??{max_entries:32,max_metadata_bytes:1048576}});
 const fence=f.envelope('FENCE','fence_message',{barrier_id:'barrier',operation_id:'operation',control_epoch:'epoch',target_version:'1',target_gate_revision:'1',issued_cut_revision:'0',
  ledger_digest:hash([]),open_intents:[],attempt_binding:{cut_id:'cut',cut_digest:hash('cut'),target_exit_id:f.binding.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null},
  transmission_ledger_digest:hash([]),open_transmission_intents:[],cancel_transmissions:[],cancel_ledger_digest:hash([])});
 signCut(fence);
 const run={controller_scope:f.binding.scope,snapshot_revision:'0',entries:[]},commands={scope:f.binding.scope,device_id:'device',snapshot_revision:'0',entries:[]};
 const time={snapshot_id:'time_snapshot',domain:{...f.binding.scope,provider_id:'provider',provider_boot_id:'provider_boot',runtime_binding_ref:ref('runtime'),
  clock_domain_id:f.binding.clock_domain_id,descriptor_digest:f.binding.descriptor_digest,clock_generation:'1'},snapshot_revision:'1',minimum_time_generation:'1',state_ref:ref('time_state')};
 const open=f.envelope('OPEN_GATE','open_message',{barrier_id:'barrier',gate_token:'token',device_session_id:f.binding.device_session_id,control_epoch:'epoch',control_version:'1',gate_revision:'1',
  authorization_revision:'1',clock_domain_id:f.binding.clock_domain_id,lease_until_tick_ns:'100',descriptor_digest:f.binding.descriptor_digest,
  run_deny_snapshot:{...run,snapshot_digest:hash(run)},command_deny_snapshot:{...commands,snapshot_digest:hash(commands)},reference_time_snapshot:{...time,snapshot_digest:hash(time)},
  gate_access:{...accessBody,access_digest:hash(accessBody)},protection_assessment:null});
 options.snapshots?.(open.body,encoded.body.command_id);
 await f.response(await gateOwner.receive(raw(fence)));await f.response(await gateOwner.receive(raw(open)));
 let gateOverride,writes=0;
 const ownership=ref('ownership'),accessRef={id:'access',revision:'1',digest:hash(accessBody)};
 const authorization={issuer_id:'issuer',issuer_epoch:'issuer.1',audience:'controller',principal_kind:'human',principal_id:'person',origin:'manual',session_id:'session',credential_id:'credential',
  subject_revision:'1',session_revision:'1',policy_revision:'1',scope_digest:hash('scope'),grant_id:null,grant_revision:null,arm_generation:null,extension_instance_id:null,extension_approval_revision:null};
 const guardBody={guard_id:'guard',permit_id:'permit',command_id:encoded.body.command_id,device_id:'device',controller_boot_id:f.binding.controller_boot_id,
  worker_boot_id:f.binding.worker_boot_id,ipc_session_id:f.binding.ipc_session_id,binding:authorization,authorization_revision:'1',authorization_deadline_tick_ns:'90',
  clock_domain_id:f.binding.clock_domain_id,time_required:false,capacity_reservation_id:'reservation',descriptor_digest:f.binding.descriptor_digest,
  admission_origin:'non_panel',panel_binding:null,automation_binding:null,reference_time:null,gate_access_ref:accessRef,ownership_ref:ownership};
 const guard={...guardBody,guard_digest:hash(guardBody)},contentDigest=encoded.body.encoding_authorization.content_digest;
 const install=f.envelope('GUARD_INSTALL','guard_message',{guard,content_digest:contentDigest,schedule_guard:null,reference_context:null});
 const packet=f.cache.describe('prepare').packet,packetRef={packet_id:packet.packet_id,packet_digest:packet.packet_digest};
 const window={clock_domain_id:f.binding.clock_domain_id,descriptor_digest:f.binding.descriptor_digest,earliest_tick_ns:'1',latest_tick_ns:'80'};
 const intent={permit_id:'permit',command_id:packet.command_id,attempt_id:packet.attempt_id,dispatch_intent_id:'dispatch_intent',worker_boot_id:f.binding.worker_boot_id,
  device_session_id:f.binding.device_session_id,guard_id:guard.guard_id,guard_digest:guard.guard_digest,clock_domain_id:f.binding.clock_domain_id,descriptor_digest:f.binding.descriptor_digest,
  controller_boot_id:f.binding.controller_boot_id,ipc_session_id:f.binding.ipc_session_id,device_id:'device',admission_origin:'non_panel',panel_binding_digest:null,origin:'manual',automation_binding:null,automation_binding_digest:null};
 const permit={permit_id:'permit',command_id:packet.command_id,attempt_id:packet.attempt_id,dispatch_intent_id:'dispatch_intent',controller_boot_id:f.binding.controller_boot_id,
  worker_boot_id:f.binding.worker_boot_id,device_session_id:f.binding.device_session_id,control_epoch:'epoch',control_version:'1',authorization_revision:'1',origin:'manual',grant_revision:null,arm_generation:null,
  gate_revision:'1',deadline_policy:encoded.body.request.dispatch,content_digest:contentDigest,guard_id:guard.guard_id,guard_digest:guard.guard_digest,
  clock_domain_id:f.binding.clock_domain_id,descriptor_digest:f.binding.descriptor_digest,admission_origin:'non_panel',panel_binding_digest:null,automation_binding:null,
  transmission:{transmission_id:'transmission',packet_ref:packetRef,primitive_id:packet.primitive_id,intent,ordinal:'0',kind:'initial',cause:'dispatch',trigger_observation_ref:null,
   parent_dispatch_intent_id:'dispatch_intent',initial_permit_id:'permit',issued_revision:'1',send_window:window},budget_revision:'1',gate_access_ref:accessRef,ownership_ref:ownership};
 const template=JSON.parse(fs.readFileSync(new URL('../dist/simulator-control-capability.json',import.meta.url))),a=template.actions[0];
 const dispatch=f.envelope('DISPATCH','dispatch_message',{permit,gate_token:'token',send_window:window,request:encoded.body.request,parameters_schema_digest:a.parameters_schema.digest,
  guard_id:guard.guard_id,guard_digest:guard.guard_digest,prepare_id:'prepare',packet,resend_request_id:null});
 const executor={api_version:'leafseamer-device-primitives/1',async writePrimitive(input){writes++;return options.write?options.write(input,f.module):f.module.execution.writePrimitive(input);}};
 // 控制/授权输入仍为合成原件；门控状态、共用I/O序列及实际模块写入均使用交付实现。
 writer=deviceTransmissionWriter({binding:f.binding,preparation:options.preparation?options.preparation(f.cache):f.cache,executor,action:{action_id:a.action_id,capability_version:a.capability_version,parameters_schema_digest:a.parameters_schema.digest},
  currentGate:()=>{const value=gateOverride===undefined?gateOwner.currentGate():gateOverride;return options.gate?options.gate(value):value;},nextIoSequence:gateOwner.nextIoSequence,tick:f.clock,signal:f.abort.signal,failed:error=>{gateOwner.close(error);f.errors.push(error);},
  limits:{max_guards:16,max_transmissions:16,max_metadata_bytes:1048576}});
 return {...f,encoded,install,dispatch,writer,gateOwner,fence,open,writes:()=>writes,gate:value=>{if(value===null)gateOwner.protect();else gateOverride=value;},gateValue:()=>structuredClone(gateOwner.currentGate())};
}

function closing(f,id='close') {return f.envelope('CLOSE_GATE',id+'_message',{close_id:id,reason:'protection',scope:'device'});}
test('准备拒绝立即禁止取包，报告送达只登记原报告且不能抹掉屏障账本',async()=>{
 const f=await sending();await f.writer.installGuard(raw(f.install));const report=await f.writer.dispatch(raw(f.dispatch));
 const receipt=f.envelope('REPORT_STORED','stored',{report_id:report.body.report_id,record_revision:'1'});
 await f.writer.stored(raw(receipt));await f.writer.stored(raw(receipt));
 assert.equal(f.writer.fenceSnapshot().transmissions.length,1);assert.equal(f.writes(),1);
 const packet=f.cache.describe('prepare').packet;
 const rejection=f.envelope('PREPARE_PACKET_REJECTED','reject',{prepare_id:'prepare',packet_ref:{packet_id:packet.packet_id,packet_digest:packet.packet_digest},
  reason:'protected',encoding_authorization_ref:{id:f.encoded.body.encoding_authorization.authorization_id,revision:'1',digest:f.encoded.body.encoding_authorization.authorization_digest}});
 rejection.reply_to='prepared_response';
 await f.cache.reject(raw(rejection));assert.throws(()=>f.cache.describe('prepare'),/encoding_not_prepared/);
 await assert.rejects(f.writer.stored(raw({...receipt,body:{...receipt.body,record_revision:'2'}})),/transmission_report_receipt_conflict/);
});

test('无参考时间OPEN返回null确认，普通即时写仍须完整Guard和单次许可',async()=>{
 const f=await sending({snapshots:frame=>{frame.reference_time_snapshot=null;}});
 const repeated=await f.response(await f.gateOwner.receive(raw(f.open)));
 assert.equal(repeated.body.reference_time_snapshot_ref,null);
 await f.writer.installGuard(raw(f.install));
 const report=await f.writer.dispatch(raw(f.dispatch));assert.equal(report.body.disposition,'in_flight');assert.equal(f.writes(),1);
 assert.deepEqual(await f.writer.dispatch(raw(f.dispatch)),report);assert.equal(f.writes(),1);
 const sample=await f.module.captureBaseline({device_id:'device',device_session_id:f.binding.device_session_id,signal:f.abort.signal});
 assert.equal(sample.write_sequence,'1');
});
function controlFence(f,items=[f.dispatch.body.permit.transmission]){
 const frame=structuredClone(f.fence);frame.message_id='control_fence_message';
 Object.assign(frame.body,{barrier_id:'control_barrier',operation_id:'control_operation',target_gate_revision:'2',issued_cut_revision:'1',
  open_intents:items.map(v=>v.intent),open_transmission_intents:items,ledger_digest:hash(items.map(v=>v.intent)),transmission_ledger_digest:hash(items)});
 frame.body.attempt_binding.cut_id='control_cut';return signCut(frame);
}
function reopenAfterFence(f,cut){
 const frame=structuredClone(f.open);frame.message_id='reopen_message';
 Object.assign(frame.body,{barrier_id:cut.body.barrier_id,gate_revision:cut.body.target_gate_revision,gate_token:'reopen_token'});
 const {access_digest,...a}=frame.body.gate_access;a.access_id='reopen_access';frame.body.gate_access={...a,access_digest:hash(a)};return frame;
}
function barrierQuery(f,cut,id='query') {return f.envelope('QUERY_BARRIER',id,{operation_id:cut.body.operation_id,barrier_id:cut.body.barrier_id,attempt_binding:cut.body.attempt_binding});}
function authFence(f,selector={kind:'principal',issuer_id:'issuer',issuer_epoch:'issuer.1',target_id:'person',revision_floor:'2'},items=[f.dispatch.body.permit.transmission]){
 return signCut(f.envelope('AUTH_FENCE','auth_message',{operation_id:'auth_operation',barrier_id:'auth_barrier',selector,selector_digest:hash(selector),target_authorization_revision:'2',
  issued_cut_revision:'1',ledger_digest:hash(items.map(v=>v.intent)),open_intents:items.map(v=>v.intent),transmission_ledger_digest:hash(items),open_transmission_intents:items,
  cancel_transmissions:[],cancel_ledger_digest:hash([]),attempt_binding:{cut_id:'auth_cut',cut_digest:hash('cut'),target_exit_id:f.binding.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null}}));
}
function renewal(f){
 const body={request_id:'renewal',binding:f.binding,control_authority_ref:f.open.body.gate_access.control_authority_ref,before_gate_ref:ref('previous_gate'),close_ack_ref:ref('close_ack'),
  target_gate_revision:'2',gate_token:'second_token',selected_tick_ns:'10',expires_tick_ns:'70',lease_until_tick_ns:'100'};
 const fence=f.envelope('GATE_FENCE','renewal_message',{...body,request_digest:hash(body)}),open=structuredClone(f.open);
 Object.assign(open,{message_id:'second_open_message'});Object.assign(open.body,{barrier_id:'renewal',gate_token:'second_token',gate_revision:'2'});
 const {access_digest,...access}=open.body.gate_access;access.access_id='second_access';open.body.gate_access={...access,access_digest:hash(access)};
 return {fence,open};
}

function signSnapshot(value){const {snapshot_digest,...body}=value;return {...body,snapshot_digest:hash(body)};}
function runFence(f,items=[],floor='2',revision='1'){
 const selector={kind:'run_generation',origin_scope:{authority_service_id:'seamer',database_instance_id:'origin_database'},run_id:'run',deny_through_generation:floor};
 return signCut(f.envelope('RUN_FENCE','run_message',{operation_id:'run_operation',barrier_id:'run_barrier',controller_scope:f.binding.scope,selector,selector_digest:hash(selector),
  issued_cut_revision:'1',target_deny_revision:revision,ledger_digest:hash(items.map(v=>v.intent)),open_intents:items.map(v=>v.intent),
  transmission_ledger_digest:hash(items),open_transmission_intents:items,cancel_transmissions:[],cancel_ledger_digest:hash([]),
  attempt_binding:{cut_id:'run_cut',cut_digest:hash('cut'),target_exit_id:f.binding.writer_exit_id,attempt_ordinal:'1',previous_barrier_id:null}}));
}
function automationTransmission(f){
 const tx=structuredClone(f.dispatch.body.permit.transmission),origin_scope={authority_service_id:'seamer',database_instance_id:'origin_database'};
 const binding={origin_scope,run_id:'run',definition_version:'1',arm_generation:'2',execution_id:'execution',
  execution_binding_ref:{kind:'execution_binding',scope:origin_scope,object_id:'execution',revision:'1',digest:hash('execution')},
  step_id:'step',logical_action_id:'action',binding_version:'continuation-execution/0.1.0-draft.1',authorization_mode:'preparation',continuation:null};
 Object.assign(tx.intent,{origin:'automation',automation_binding:binding,automation_binding_digest:hash(binding)});return tx;
}

test('RUN_FENCE安装来源运行下界且不撤销无关人工Guard，查询与STORED保留原确认',async()=>{
 const f=await sending();await f.writer.installGuard(raw(f.install));const before=f.gateValue(),cut=runFence(f),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);
 assert.deepEqual(ack.body.coverage,[]);assert.equal(f.gateValue().run_denials[0].selector.deny_through_generation,'2');
 assert.deepEqual(f.gateValue().access,before.access);assert.equal(f.gateValue().gate_revision,before.gate_revision);
 assert.equal((await f.writer.dispatch(raw(f.dispatch))).body.disposition,'in_flight');assert.equal(f.writes(),1);
 assert.deepEqual((await f.gateOwner.receive(raw(barrierQuery(f,cut)))).body,ack.body);
 await f.gateOwner.receive(raw(f.envelope('BARRIER_STORED','run_stored',{...barrierQuery(f,cut).body,ack_digest:hash(ack.body),record_revision:'1'})));
 assert.equal((await f.gateOwner.receive(raw(barrierQuery(f,cut)))).body.reason,'cache_miss');assert.equal(f.gateValue().run_denials.length,1);
});

test('RUN_FENCE完整automation原件按来源和布防代次匹配，未收到不制造在途',async()=>{
 const f=await sending(),tx=automationTransmission(f),ack=await f.gateOwner.receive(raw(runFence(f,[tx])));await f.response(ack);
 assert.equal(ack.body.transmission_coverage[0].disposition,'not_sent');assert.equal(ack.body.transmission_coverage[0].proof,'never_received');
 for(const mutate of [tx=>{tx.intent.automation_binding.run_id='other';},tx=>{tx.intent.automation_binding.origin_scope.database_instance_id='other';},
  tx=>{tx.intent.automation_binding.arm_generation='3';},tx=>{tx.intent.automation_binding_digest=hash('wrong');}]){
  const other=await sending(),tx=automationTransmission(other);mutate(tx);
  if(tx.intent.automation_binding_digest!==hash('wrong'))tx.intent.automation_binding_digest=hash(tx.intent.automation_binding);
  await assert.rejects(other.gateOwner.receive(raw(runFence(other,[tx]))),/gate_(selector|automation)_binding/);assert.equal(other.gateOwner.state.open,false);
 }
 const manual=await sending();await manual.writer.installGuard(raw(manual.install));await manual.writer.dispatch(raw(manual.dispatch));
 await assert.rejects(manual.gateOwner.receive(raw(runFence(manual,[automationTransmission(manual)]))),/gate_guard_binding/);
 assert.equal(manual.writer.query('permit').report.body.disposition,'in_flight');assert.equal(manual.writes(),1);
});

test('RUN_FENCE不遗漏已知automation传输，原未知确认不因迟到观察改写',async()=>{
 // 此用例的automation账本是合成输入，未声称真实自动化派发已接通。
 let injected=null;const f=await sending({transmissions:value=>injected??value}),tx=automationTransmission(f),guard={...f.install.body.guard,automation_binding:tx.intent.automation_binding};
 injected={binding:f.binding,guards:[guard],transmissions:[{transmission:tx,consumed:true,report:null}]};
 const cut=runFence(f,[tx]),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);assert.equal(ack.body.coverage[0].disposition,'unknown');
 injected.transmissions[0].report={body:{disposition:'in_flight'}};
 assert.equal((await f.gateOwner.receive(raw(cut))).body.coverage[0].disposition,'unknown');
 const next=structuredClone(cut);next.message_id='run_retry';next.body.barrier_id='run_retry_barrier';
 Object.assign(next.body.attempt_binding,{attempt_ordinal:'2',previous_barrier_id:cut.body.barrier_id});f.tick(12n);
 const stronger=await f.gateOwner.receive(raw(next));await f.response(stronger);assert.equal(stronger.body.coverage[0].disposition,'in_flight');assert.equal(stronger.body.effective_tick_ns,'12');
 const missing=structuredClone(next);missing.message_id='run_missing';missing.body.barrier_id='run_missing';missing.body.open_intents=[];missing.body.open_transmission_intents=[];
 missing.body.ledger_digest=hash([]);missing.body.transmission_ledger_digest=hash([]);Object.assign(missing.body.attempt_binding,{cut_id:'missing_cut',attempt_ordinal:'1',previous_barrier_id:null});signCut(missing);
 await assert.rejects(f.gateOwner.receive(raw(missing)),/gate_transmission_omitted/);
});

test('RUN_FENCE晚于快照时旧OPEN不得漏项，更新完整快照后仍保留拒绝',async()=>{
 for(const complete of [false,true]){
  const f=await sending(),cut=runFence(f);await f.gateOwner.receive(raw(cut));await f.gateOwner.receive(raw(closing(f)));const next=renewal(f);
  if(complete)next.open.body.run_deny_snapshot=signSnapshot({controller_scope:f.binding.scope,snapshot_revision:'1',entries:[{selector:cut.body.selector,deny_revision:'1'}]});
  await f.gateOwner.receive(raw(next.fence));
  if(!complete)await assert.rejects(f.gateOwner.receive(raw(next.open)),/gate_deny_snapshot_omitted/);
  else{await f.response(await f.gateOwner.receive(raw(next.open)));assert.equal(f.gateValue().run_denials[0].selector.deny_through_generation,'2');}
 }
});

test('运行拒绝同修订不能改下界，新cut不能倒退，历史原ACK不撤销更强下界',async()=>{
 const f=await sending(),first=runFence(f),ack=await f.gateOwner.receive(raw(first)),next=runFence(f,[],'3','2');
 next.message_id='new_run_message';next.body.barrier_id='new_run_barrier';next.body.attempt_binding.cut_id='new_run_cut';signCut(next);await f.gateOwner.receive(raw(next));
 assert.deepEqual((await f.gateOwner.receive(raw(first))).body,ack.body);assert.equal(f.gateValue().run_denials[0].selector.deny_through_generation,'3');
 for(const [floor,revision] of [['1','2'],['3','1']]){
  const other=await sending();await other.gateOwner.receive(raw(runFence(other)));const bad=runFence(other,[],floor,revision);
  bad.message_id='bad';bad.body.barrier_id='bad';bad.body.attempt_binding.cut_id='bad';signCut(bad);
  await assert.rejects(other.gateOwner.receive(raw(bad)),/gate_(run_deny_floor|deny_snapshot_conflict)/);assert.equal(other.gateOwner.state.open,false);
 }
});

function nonemptySnapshots(body,parent='other_command',stage='ordinary'){
 body.run_deny_snapshot=signSnapshot({...body.run_deny_snapshot,snapshot_revision:'1',entries:[{selector:{kind:'run_generation',
  origin_scope:{authority_service_id:'seamer',database_instance_id:'origin_database'},run_id:'old_run',deny_through_generation:'2'},deny_revision:'1'}]});
 body.command_deny_snapshot=signSnapshot({...body.command_deny_snapshot,snapshot_revision:'1',entries:[{cancellation_id:'cancellation',parent_command_id:parent,stage,deny_revision:'1',cut_ref:ref('cancel_cut')}]});
}

test('完整非空拒绝快照随开放安装，独立人工命令保留发送资格',async()=>{
 const f=await sending({snapshots:body=>nonemptySnapshots(body)}),live=f.gateValue();
 assert.equal(live.run_denials.length,1);assert.equal(live.command_denials.length,1);
 assert.equal(live.command_deny_snapshot_ref.digest,f.open.body.command_deny_snapshot.snapshot_digest);
 await f.writer.installGuard(raw(f.install));const report=await f.writer.dispatch(raw(f.dispatch));
 assert.equal(report.body.disposition,'in_flight');assert.equal(f.writes(),1);
});

test('ordinary和all拒绝快照均阻止父命令安装新Guard，不扩大为独立命令拒绝',async()=>{
 for(const stage of ['ordinary','all']){
  const f=await sending({snapshots:(body,command)=>nonemptySnapshots(body,command,stage)});
  await assert.rejects(f.writer.installGuard(raw(f.install)),/transmission_command_denied/);assert.equal(f.writes(),0);
 }
});

test('换闸不能删拒绝项、回退运行代次或取消stage，也不能同修订替换原件',async()=>{
 const cases=[
  b=>{b.run_deny_snapshot.entries=[];},
  b=>{b.command_deny_snapshot.entries=[];},
  b=>{b.run_deny_snapshot.entries[0].selector.deny_through_generation='1';b.run_deny_snapshot.entries[0].deny_revision='2';},
  b=>{b.command_deny_snapshot.entries[0].stage='ordinary';b.command_deny_snapshot.entries[0].deny_revision='2';},
  b=>{b.command_deny_snapshot.entries[0].cancellation_id='replacement';b.command_deny_snapshot.entries[0].deny_revision='2';},
  b=>{b.command_deny_snapshot.entries[0].cut_ref=ref('changed_cut');},
  b=>{b.run_deny_snapshot.snapshot_revision='0';}
 ];
 for(const mutate of cases){
  const f=await sending({snapshots:body=>nonemptySnapshots(body,'other_command','all')});await f.gateOwner.receive(raw(closing(f)));
  const next=renewal(f);next.open.body.run_deny_snapshot.snapshot_revision='2';next.open.body.command_deny_snapshot.snapshot_revision='2';mutate(next.open.body);
  for(const key of ['run_deny_snapshot','command_deny_snapshot'])next.open.body[key]=signSnapshot(next.open.body[key]);
  await f.gateOwner.receive(raw(next.fence));await assert.rejects(f.gateOwner.receive(raw(next.open)),/gate_(deny_snapshot|run_deny_floor|command_deny_binding)/);
  assert.equal(f.gateOwner.state.open,false);assert.equal(f.writes(),0);
 }
});

test('快照可增加更强拒绝但不能重复父命令；旧OPEN查原不抹除新快照',async()=>{
 const f=await sending({snapshots:body=>nonemptySnapshots(body)});await f.gateOwner.receive(raw(closing(f)));const next=renewal(f);
 const run=next.open.body.run_deny_snapshot,command=next.open.body.command_deny_snapshot;
 run.snapshot_revision='2';run.entries[0].deny_revision='2';run.entries[0].selector.deny_through_generation='3';
 command.snapshot_revision='2';command.entries[0].deny_revision='2';command.entries[0].stage='all';command.entries[0].cut_ref=ref('all_cut');
 next.open.body.run_deny_snapshot=signSnapshot(run);next.open.body.command_deny_snapshot=signSnapshot(command);
 await f.gateOwner.receive(raw(next.fence));await f.response(await f.gateOwner.receive(raw(next.open)));
 await f.response(await f.gateOwner.receive(raw({...f.open,message_id:'old_open_query'})));
 assert.equal(f.gateValue().run_denials[0].selector.deny_through_generation,'3');assert.equal(f.gateValue().command_denials[0].stage,'all');
 await assert.rejects(sending({snapshots:body=>{nonemptySnapshots(body);body.command_deny_snapshot.entries.push(structuredClone(body.command_deny_snapshot.entries[0]));body.command_deny_snapshot=signSnapshot(body.command_deny_snapshot);}}),/gate_deny_snapshot_order/);
});

test('真实门控关闭后旧OPEN和FENCE只查历史；完整换闸开放后旧close不再关闭新闸',async()=>{
 const f=await sending(),close=closing(f),original=await f.gateOwner.receive(raw(close));await f.response(original);
 assert.equal(f.gateOwner.currentGate(),null);assert.equal(f.gateOwner.state.io_sequence,'3');
 for(const frame of [f.open,f.fence])await f.response(await f.gateOwner.receive(raw({...frame,message_id:'replay_'+frame.message_id,seq:'9'})));
 assert.equal(f.gateOwner.currentGate(),null);assert.equal(f.gateOwner.state.io_sequence,'3');
 const next=renewal(f);await f.response(await f.gateOwner.receive(raw(next.fence)));await f.response(await f.gateOwner.receive(raw(next.open)));
 assert.equal(f.gateOwner.currentGate().gate_revision,'2');assert.equal(f.gateOwner.state.io_sequence,'5');
 const cached=await f.gateOwner.receive(raw({...close,message_id:'close_replay',seq:'10'}));assert.deepEqual(cached.body,original.body);assert.equal(cached.reply_to,'close_replay');
 assert.equal(f.gateOwner.currentGate().gate_revision,'2');assert.equal(f.gateOwner.state.io_sequence,'5');
 await f.writer.installGuard(raw(f.install)).then(()=>assert.fail(),error=>assert.match(error.message,/transmission_guard_stale/));assert.equal(f.writes(),0);
});

test('租期/Access截止等号撤下屏障，旧OPEN不续租；时钟倒退与中止终止所有者',async()=>{
 const f=await sending();f.tick(100n);assert.equal(f.gateOwner.currentGate(),null);await f.gateOwner.receive(raw(f.open));assert.equal(f.gateOwner.currentGate(),null);
 const changed=structuredClone(f.open);changed.message_id='late';const {access_digest,...access}=changed.body.gate_access;
 access.access_id='late_access';access.expires_tick_ns='200';changed.body.gate_access={...access,access_digest:hash(access)};changed.body.lease_until_tick_ns='200';
 await assert.rejects(f.gateOwner.receive(raw(changed)),/gate_open_barrier/);assert.equal(f.gateOwner.state.terminal,true);
 const backwards=await sending();backwards.tick(9n);assert.throws(()=>backwards.gateOwner.currentGate(),/gate_clock/);assert.equal(backwards.gateOwner.state.terminal,true);
 const aborted=await sending();aborted.abort.abort();assert.throws(()=>aborted.gateOwner.currentGate(),/gate_closed/);
});

test('门控身份冲突和容量耗尽均先关闭，历史缓存不驱逐',async()=>{
 const f=await sending(),close=closing(f);await f.gateOwner.receive(raw(close));close.body.reason='changed';
 await assert.rejects(f.gateOwner.receive(raw(close)),/gate_identity_conflict/);assert.equal(f.gateOwner.state.terminal,true);
 const full=await sending({gateLimits:{max_entries:2,max_metadata_bytes:1048576}});
 await assert.rejects(full.gateOwner.receive(raw(closing(full))),/gate_history_capacity/);assert.equal(full.gateOwner.state.terminal,true);assert.equal(full.gateOwner.state.history_entries,2);
});

test('换闸摘要/期限和开放快照/控制不符拒绝，已发送账本不伪造空覆盖',async()=>{
 for(const mutate of [v=>{v.fence.body.request_digest=hash('bad');},v=>{v.open.body.control_version='2';},
  v=>{v.open.body.run_deny_snapshot.snapshot_digest=hash('bad');},v=>{v.open.body.reference_time_snapshot.domain.clock_domain_id='clock_'+'9'.repeat(64);
   const {snapshot_digest,...body}=v.open.body.reference_time_snapshot;v.open.body.reference_time_snapshot.snapshot_digest=hash(body);}]){
  const f=await sending();await f.gateOwner.receive(raw(closing(f)));const next=renewal(f);mutate(next);
  await assert.rejects((async()=>{await f.gateOwner.receive(raw(next.fence));await f.gateOwner.receive(raw(next.open));})());assert.equal(f.gateOwner.state.terminal,true);assert.equal(f.writes(),0);
 }
 const late=await sending();await late.gateOwner.receive(raw(closing(late)));const next=renewal(late);await late.gateOwner.receive(raw(next.fence));late.tick(70n);
 await assert.rejects(late.gateOwner.receive(raw(next.open)),/gate_open_renewal/);assert.equal(late.writes(),0);
 const used=await sending();await used.writer.installGuard(raw(used.install));await used.writer.dispatch(raw(used.dispatch));
 const second=controlFence(used,[]);
 await assert.rejects(used.gateOwner.receive(raw(second)),/gate_transmission_omitted/);assert.equal(used.writes(),1);
});

test('设备关闭与发送共用顺序，关闭ACK不冒充已进入模块的写入排空',async()=>{
 const started=deferred(),finish=deferred(),f=await sending({async write(input,module){const result=await module.execution.writePrimitive(input);started.resolve();await finish.promise;return result;}});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));await started.promise;
 assert.equal(f.gateOwner.state.io_sequence,'3');const ack=await f.gateOwner.receive(raw(closing(f)));await f.response(ack);
 assert.equal(f.gateOwner.state.io_sequence,'4');assert.equal(f.gateOwner.currentGate(),null);assert.equal(f.writer.query('permit').pending,true);
 finish.resolve();const report=await pending;assert.equal(report.body.gate_io_seq,'3');assert.equal(report.body.disposition,'in_flight');assert.equal(f.writes(),1);
 assert.equal((await f.module.captureBaseline(f.device)).value,42);assert.equal(f.writer.query('permit').pending,false);
});

test('未开放的换闸token也不能跨新屏障复用；非空首次账本不生成空ACK',async()=>{
 const f=await sending();await f.gateOwner.receive(raw(closing(f)));const next=renewal(f);await f.gateOwner.receive(raw(next.fence));
 await f.gateOwner.receive(raw(closing(f,'second_close')));const another=structuredClone(next.fence);
 another.message_id='third_fence';another.body.request_id='third_fence';another.body.target_gate_revision='3';
 const {request_digest,...unsigned}=another.body;another.body.request_digest=hash(unsigned);
 await assert.rejects(f.gateOwner.receive(raw(another)),/gate_revision/);assert.equal(f.gateOwner.state.terminal,true);
 const uninitialized=deviceExecutionGate({binding:f.binding,tick:f.clock,signal:f.abort.signal,failed:()=>{},limits:{max_entries:4,max_metadata_bytes:1048576}});
 const frame=structuredClone(f.fence);frame.body.open_transmission_intents=[f.dispatch.body.permit.transmission];frame.body.transmission_ledger_digest=hash(frame.body.open_transmission_intents);
 signCut(frame);
 await assert.rejects(uninitialized.receive(raw(frame)),/gate_control_fence_unsupported/);assert.equal(uninitialized.state.history_entries,0);
});

test('非空控制屏障保留真实发送事实；未收到的许可明确未发，旧发送只查原',async()=>{
 for(const sent of [false,true]){
  const f=await sending();await f.writer.installGuard(raw(f.install));let report;
  if(sent)report=await f.writer.dispatch(raw(f.dispatch));const cut=controlFence(f),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);
  assert.equal(f.gateOwner.currentGate(),null);assert.equal(ack.body.transmission_coverage.length,1);
  assert.deepEqual(ack.body.transmission_coverage[0].intent,f.dispatch.body.permit.transmission);
  assert.equal(ack.body.coverage[0].disposition,sent?'in_flight':'not_sent');assert.equal(ack.body.coverage[0].proof,sent?'transport_entered':'never_received');
  assert.deepEqual(ack.body.ack.in_flight_command_ids,sent?['command_prepare']:[]);assert.deepEqual(ack.body.ack.discarded_permit_ids,sent?[]:['permit']);
  await f.response(await f.gateOwner.receive(raw(reopenAfterFence(f,cut))));
  if(sent)assert.deepEqual(await f.writer.dispatch(raw(f.dispatch)),report);
  else await assert.rejects(f.writer.dispatch(raw(f.dispatch)),/transmission_guard_stale/);
  assert.equal(f.writes(),sent?1:0);
 }
});

test('在途写不阻塞FENCE，原未知ACK不被迟到结果改写，新cut可保留更强发送事实',async()=>{
 const started=deferred(),finish=deferred(),f=await sending({async write(input,module){const result=await module.execution.writePrimitive(input);started.resolve();await finish.promise;return result;}});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));await started.promise;
 const cut=controlFence(f),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);
 assert.equal(ack.body.coverage[0].disposition,'unknown');assert.deepEqual(ack.body.ack.unresolved_command_ids,['command_prepare']);
 assert.equal(f.writer.query('permit').pending,true);assert.equal(f.gateOwner.state.io_sequence,'4');
 finish.resolve();assert.equal((await pending).body.disposition,'in_flight');f.tick(11n);
 const replay=await f.gateOwner.receive(raw({...cut,message_id:'cut_replay'}));assert.deepEqual(replay.body,ack.body);
 const next=structuredClone(cut);next.message_id='next_cut_message';next.body.barrier_id='next_barrier';next.body.operation_id='next_operation';
 next.body.target_gate_revision='3';next.body.attempt_binding.cut_id='next_cut';signCut(next);
 const stronger=await f.gateOwner.receive(raw(next));await f.response(stronger);assert.equal(stronger.body.coverage[0].disposition,'in_flight');
 assert.equal(stronger.body.effective_tick_ns,'11');assert.equal(f.writes(),1);
});

test('已登记但未消费的许可被屏障丢弃，延后返回的字节不能再进入写出口',async()=>{
 const entered=deferred(),release=deferred(),f=await sending({preparation:cache=>({describe:cache.describe,
  async withPacket(...args){entered.resolve();await release.promise;return cache.withPacket(...args);}})});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));const rejected=assert.rejects(pending,/transmission_gate_closed/);await entered.promise;
 assert.equal(f.writer.query('permit').consumed,false);const ack=await f.gateOwner.receive(raw(controlFence(f)));await f.response(ack);
 assert.equal(ack.body.coverage[0].disposition,'not_sent');assert.equal(ack.body.coverage[0].proof,'discarded_unconsumed');
 release.resolve();await rejected;assert.equal(f.writes(),0);assert.equal(f.writer.query('permit').consumed,false);
});

test('同一命令部分锚缺少完整传输时保留unknown，汇总不覆盖其他锚的已发事实',async()=>{
 const f=await sending();await f.writer.installGuard(raw(f.install));await f.writer.dispatch(raw(f.dispatch));const cut=controlFence(f);
 const extra=structuredClone(cut.body.open_intents[0]);Object.assign(extra,{permit_id:'permit_z',guard_id:'guard_z',guard_digest:hash('guard_z'),attempt_id:'attempt_z',dispatch_intent_id:'intent_z'});
 cut.body.open_intents.push(extra);cut.body.ledger_digest=hash(cut.body.open_intents);signCut(cut);
 const ack=await f.gateOwner.receive(raw(cut));await f.response(ack);assert.equal(ack.body.coverage[1].disposition,'unknown');
 assert.deepEqual(ack.body.ack.in_flight_command_ids,['command_prepare']);assert.deepEqual(ack.body.ack.unresolved_command_ids,[]);
});

test('屏障查询只回原ACK；持久确认仅释放缓存，同cut后继尝试有真实新生效时间',async()=>{
 const f=await sending(),cut=controlFence(f),ack=await f.gateOwner.receive(raw(cut));
 const query=barrierQuery(f,cut);const found=await f.gateOwner.receive(raw(query));await f.response(found);assert.deepEqual(found.body,ack.body);assert.equal(found.reply_to,'query');
 const receipt=f.envelope('BARRIER_STORED','stored',{...query.body,ack_digest:hash(ack.body),record_revision:'1'});
 assert.equal(await f.gateOwner.receive(raw(receipt)),null);assert.equal(await f.gateOwner.receive(raw(receipt)),null);
 const missing=await f.gateOwner.receive(raw(query));await f.response(missing);assert.equal(missing.type,'BARRIER_UNAVAILABLE');assert.equal(missing.body.reason,'cache_miss');
 assert.equal((await f.gateOwner.receive(raw(cut))).body.reason,'cache_miss');assert.equal(f.gateOwner.state.io_sequence,'3');
 const unknown=structuredClone(query);unknown.body.barrier_id='unknown_barrier';unknown.body.attempt_binding.cut_id='unknown_cut';
 const absent=await f.gateOwner.receive(raw(unknown));await f.response(absent);assert.equal(absent.body.reason,'unknown_barrier');assert.equal(absent.body.coverage,undefined);
 f.tick(12n);const retry=structuredClone(cut);retry.message_id='retry_message';retry.body.barrier_id='retry_barrier';
 Object.assign(retry.body.attempt_binding,{attempt_ordinal:'2',previous_barrier_id:cut.body.barrier_id});
 const again=await f.gateOwner.receive(raw(retry));await f.response(again);assert.equal(again.body.effective_tick_ns,'12');assert.equal(again.body.coverage[0].disposition,'not_sent');
 await f.gateOwner.receive(raw(reopenAfterFence(f,retry)));const before=f.gateOwner.state.io_sequence;
 await f.gateOwner.receive(raw(receipt));await f.gateOwner.receive(raw(query));assert.equal(f.gateOwner.currentGate().gate_revision,'2');assert.equal(f.gateOwner.state.io_sequence,before);
 const forbidden=structuredClone(retry);forbidden.body.barrier_id='retry_after_open';forbidden.body.attempt_binding.attempt_ordinal='3';forbidden.body.attempt_binding.previous_barrier_id=retry.body.barrier_id;
 await assert.rejects(f.gateOwner.receive(raw(forbidden)),/gate_fence_attempt/);
});

test('屏障拒绝摘要、关联、顺序、漏项与跨出口清单，不生成完整覆盖',async()=>{
 const mutations=[
  c=>{c.body.attempt_binding.cut_digest=hash('bad');},
  c=>{c.body.open_intents[0].device_session_id='foreign';c.body.open_transmission_intents[0].intent.device_session_id='foreign';},
  c=>{c.body.open_transmission_intents[0].packet_ref.packet_digest=hash('other');},
  c=>{c.body.open_transmission_intents[0].issued_revision='2';},
  c=>{c.body.open_intents.push(structuredClone(c.body.open_intents[0]));},
  c=>{c.body.open_transmission_intents=[];c.body.open_intents=[];},
  c=>{c.body.open_intents[0].guard_digest=hash('other');c.body.open_transmission_intents[0].intent.guard_digest=hash('other');}
 ];
 for(let i=0;i<mutations.length;i++){
  const f=await sending();await f.writer.installGuard(raw(f.install));await f.writer.dispatch(raw(f.dispatch));
  const cut=controlFence(f);mutations[i](cut);if(i!==0){cut.body.ledger_digest=hash(cut.body.open_intents);cut.body.transmission_ledger_digest=hash(cut.body.open_transmission_intents);signCut(cut);}
  await assert.rejects(f.gateOwner.receive(raw(cut)));assert.equal(f.gateOwner.state.terminal,true);assert.equal(f.writes(),1);assert.equal(f.writer.query('permit').report.body.disposition,'in_flight');
 }
 const f=await sending(),cut=controlFence(f),ack=await f.gateOwner.receive(raw(cut));
 await assert.rejects(f.gateOwner.receive(raw(f.envelope('BARRIER_STORED','bad_receipt',{...barrierQuery(f,cut).body,ack_digest:hash('bad'),record_revision:'1'}))),/gate_ack_digest/);
 assert.equal(ack.body.coverage[0].disposition,'not_sent');
});

test('重新开放也不能用新Guard复活已冻结签发水位内的许可',async()=>{
 const f=await sending(),cut=controlFence(f);await f.gateOwner.receive(raw(cut));const open=reopenAfterFence(f,cut);await f.gateOwner.receive(raw(open));
 const a=open.body.gate_access,accessRef={id:a.access_id,revision:a.revision,digest:a.access_digest};
 const install=structuredClone(f.install),{guard_digest,...g}=install.body.guard;g.guard_id='new_guard';g.permit_id='new_permit';g.gate_access_ref=accessRef;install.body.guard={...g,guard_digest:hash(g)};
 await f.writer.installGuard(raw(install));const dispatch=structuredClone(f.dispatch),p=dispatch.body.permit,tx=p.transmission;
 Object.assign(dispatch.body,{gate_token:open.body.gate_token,guard_id:g.guard_id,guard_digest:hash(g)});
 Object.assign(p,{permit_id:g.permit_id,guard_id:g.guard_id,guard_digest:hash(g),gate_access_ref:accessRef,gate_revision:'2'});
 Object.assign(tx,{initial_permit_id:g.permit_id,transmission_id:'new_transmission'});Object.assign(tx.intent,{permit_id:g.permit_id,guard_id:g.guard_id,guard_digest:hash(g)});
 await assert.rejects(f.writer.dispatch(raw(dispatch)),/transmission_fenced/);assert.equal(f.writes(),0);
});

test('授权撤回先于发送时精确拒绝旧许可，返回not_sent且不冒充准备释放',async()=>{
 const f=await sending();await f.writer.installGuard(raw(f.install));const before=f.gateValue(),cut=authFence(f),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);
 assert.equal(ack.body.applied_authorization_revision,'2');assert.equal(ack.body.coverage[0].disposition,'not_sent');assert.deepEqual(ack.body.invalidated_permit_ids,['permit']);
 assert.equal(f.gateValue().access.control_epoch,before.access.control_epoch);assert.equal(f.gateValue().access.effective_version,before.access.effective_version);
 assert.equal(f.gateOwner.state.open,true);assert.ok(f.cache.describe('prepare').packet);
 const report=await f.writer.dispatch(raw(f.dispatch));await f.response(report);assert.equal(report.body.disposition,'not_sent');assert.equal(report.body.proof,'discarded_unconsumed');
 assert.equal(f.writer.query('permit').consumed,false);assert.equal(f.writer.state.closed,false);assert.equal(f.gateOwner.state.open,true);assert.equal(f.writes(),0);
 assert.deepEqual(await f.writer.dispatch(raw(f.dispatch)),report);assert.ok(f.cache.describe('prepare').packet);
 const query=await f.gateOwner.receive(raw(barrierQuery(f,cut)));await f.response(query);assert.deepEqual(query.body,ack.body);
});

test('授权选择器不匹配时不关闭独立身份，也不要求其发送记录进入撤回清单',async()=>{
 for(const sent of [false,true]){
  const f=await sending();await f.writer.installGuard(raw(f.install));if(sent)await f.writer.dispatch(raw(f.dispatch));
  const selector={kind:'principal',issuer_id:'issuer',issuer_epoch:'issuer.1',target_id:'another_person',revision_floor:'2'},ack=await f.gateOwner.receive(raw(authFence(f,selector,[])));
  await f.response(ack);assert.deepEqual(ack.body.coverage,[]);assert.equal(f.gateOwner.state.open,true);
  assert.equal((await f.writer.dispatch(raw(f.dispatch))).body.disposition,'in_flight');assert.equal(f.writes(),1);
 }
});

test('许可已登记但最终字节出口尚未进入时，AUTH_FENCE仍阻止写入且不关闭独立闸',async()=>{
 const selected=deferred(),release=deferred(),f=await sending({preparation:cache=>({describe:cache.describe,
  async withPacket(...args){selected.resolve();await release.promise;return cache.withPacket(...args);}})});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));await selected.promise;
 const ack=await f.gateOwner.receive(raw(authFence(f)));await f.response(ack);assert.equal(ack.body.coverage[0].proof,'discarded_unconsumed');
 release.resolve();const report=await pending;await f.response(report);assert.equal(report.body.disposition,'not_sent');assert.equal(f.writes(),0);
 assert.equal(f.writer.query('permit').consumed,false);assert.equal(f.writer.state.closed,false);assert.equal(f.gateOwner.state.open,true);
});

test('撤回清单中的许可不能改签发修订或业务意图后换取not_sent报告',async()=>{
 for(const mutate of [f=>{f.dispatch.body.permit.transmission.issued_revision='2';},f=>{
  f.dispatch.body.permit.dispatch_intent_id='other_intent';f.dispatch.body.permit.transmission.parent_dispatch_intent_id='other_intent';f.dispatch.body.permit.transmission.intent.dispatch_intent_id='other_intent';}]){
  const f=await sending();await f.writer.installGuard(raw(f.install));await f.gateOwner.receive(raw(authFence(f)));mutate(f);
  await assert.rejects(f.writer.dispatch(raw(f.dispatch)),/transmission_revoked_intent_conflict/);assert.equal(f.writes(),0);assert.equal(f.writer.query('permit'),null);
 }
});

test('AUTH_FENCE不等待在途写，原未知ACK保持不变，后继尝试可保留迟到已发证据',async()=>{
 const start=deferred(),finish=deferred(),f=await sending({async write(input,module){const result=await module.execution.writePrimitive(input);start.resolve();await finish.promise;return result;}});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));await start.promise;
 const cut=authFence(f),ack=await f.gateOwner.receive(raw(cut));await f.response(ack);assert.equal(ack.body.coverage[0].disposition,'unknown');
 assert.equal(f.writer.query('permit').pending,true);assert.equal(f.gateOwner.state.open,true);finish.resolve();assert.equal((await pending).body.disposition,'in_flight');
 f.tick(11n);const retry=structuredClone(cut);retry.message_id='auth_retry';retry.body.barrier_id='auth_second';retry.body.attempt_binding.attempt_ordinal='2';retry.body.attempt_binding.previous_barrier_id='auth_barrier';
 const stronger=await f.gateOwner.receive(raw(retry));await f.response(stronger);assert.equal(stronger.body.coverage[0].disposition,'in_flight');assert.equal(stronger.body.effective_tick_ns,'11');
 assert.deepEqual((await f.gateOwner.receive(raw(barrierQuery(f,cut)))).body,ack.body);assert.equal(f.writes(),1);
});

test('授权屏障拒绝遗漏匹配发送及伪装其他身份的已知传输，摘要和下界不可回退',async()=>{
 const missing=await sending();await missing.writer.installGuard(raw(missing.install));await missing.writer.dispatch(raw(missing.dispatch));
 await assert.rejects(missing.gateOwner.receive(raw(authFence(missing,undefined,[]))),/gate_transmission_omitted/);
 const f=await sending();await f.writer.installGuard(raw(f.install));await f.writer.dispatch(raw(f.dispatch));
 const tx=structuredClone(f.dispatch.body.permit.transmission);Object.assign(tx.intent,{permit_id:'other_permit',guard_id:'other_guard',guard_digest:hash('other_guard')});tx.initial_permit_id='other_permit';
 const selector={kind:'principal',issuer_id:'issuer',issuer_epoch:'issuer.1',target_id:'another_person',revision_floor:'2'};
 await assert.rejects(f.gateOwner.receive(raw(authFence(f,selector,[tx]))),/gate_transmission_conflict/);
 const bad=await sending(),cut=authFence(bad);cut.body.selector_digest=hash('bad');signCut(cut);await assert.rejects(bad.gateOwner.receive(raw(cut)),/gate_selector_digest/);
 const lower=await sending();await lower.gateOwner.receive(raw(authFence(lower)));const changed=authFence(lower);Object.assign(changed.body,{barrier_id:'lower',operation_id:'lower',target_authorization_revision:'3'});
 changed.body.selector.revision_floor='1';changed.body.selector_digest=hash(changed.body.selector);changed.body.attempt_binding.cut_id='lower';signCut(changed);
 await assert.rejects(lower.gateOwner.receive(raw(changed)),/gate_authorization_floor/);
});

test('新OPEN不能绕过已安装授权修订，较高授权修订仍须完整换闸',async()=>{
 for(const revision of ['1','2']){
  const f=await sending();await f.gateOwner.receive(raw(authFence(f)));await f.gateOwner.receive(raw(closing(f)));const next=renewal(f);await f.gateOwner.receive(raw(next.fence));
  next.open.body.authorization_revision=revision;
  if(revision==='1')await assert.rejects(f.gateOwner.receive(raw(next.open)),/gate_authorization_revision/);
  else{await f.response(await f.gateOwner.receive(raw(next.open)));assert.equal(f.gateValue().authorization_denials.length,1);assert.deepEqual(f.gateValue().authorization_denied_permit_ids,['permit']);}
 }
});

test('标准授权选择器按原绑定修订取下界，credential及issuer域撤回不可用新修订解除',async()=>{
 const f=await sending(),base=f.install.body.guard.binding;
 for(const [kind,key,revision] of [['principal','principal_id','subject_revision'],['session','session_id','session_revision'],['grant','grant_id','grant_revision'],['extension','extension_instance_id','extension_approval_revision']]){
  const binding={...base,[key]:'target',[revision]:'1'},selector={kind,issuer_id:'issuer',issuer_epoch:'issuer.1',target_id:'target',revision_floor:'2'};
  assert.equal(authorizationRevoked(binding,selector),true);assert.equal(authorizationRevoked({...binding,[revision]:'2'},selector),false);
  assert.equal(authorizationRevoked({...binding,issuer_epoch:'another'},selector),false);
 }
 for(const kind of ['credential','trust']){
  const selector={kind,issuer_id:'issuer',issuer_epoch:'issuer.1',target_id:kind==='credential'?base.credential_id:'issuer_trust',revision_floor:'999'};
  assert.equal(authorizationRevoked({...base,subject_revision:'1000',session_revision:'1000',policy_revision:'1000'},selector),true);
  if(kind==='credential')assert.equal(authorizationRevoked({...base,credential_id:'replacement'},selector),false);
 }
});

test('Guard安装后许可只消费一次，真实内存写入返回传输事实；重复请求只查原',async()=>{
 const f=await sending(),ack=await f.writer.installGuard(raw(f.install));await f.response(ack);
 const report=await f.writer.dispatch(raw(f.dispatch));await f.response(report);
 assert.equal(report.body.disposition,'in_flight');assert.equal(report.body.proof,'transport_entered');assert.equal(f.writes(),1);
 assert.equal((await f.module.captureBaseline(f.device)).value,42);
 assert.deepEqual(await f.writer.dispatch(raw(f.dispatch)),report);assert.equal(f.writes(),1);
 const state=f.writer.query('permit');assert.equal(state.consumed,true);assert.equal(state.pending,false);
 assert.equal(state.observation.response.write_sequence,'1');assert.equal(report.body.socket_callback_observation_ref.digest,hash(state.observation));
 await f.response(state.evidence);assert.equal(state.evidence.type,'EVIDENCE_CANDIDATE');assert.equal(state.evidence.reply_to,null);
 assert.equal(state.evidence.body.evidence_kind,'module_observation');assert.notEqual(state.evidence.body.report_id,report.body.report_id);
 assert.equal(state.evidence.body.command_id,f.dispatch.body.permit.command_id);assert.equal(state.evidence.body.observation_id,state.observation.observation_id);
 assert.deepEqual(state.evidence.body.payload.binding,f.binding);assert.deepEqual(state.evidence.body.payload.observation,state.observation);
 assert.deepEqual(state.evidence.body.payload.send_report_ref,{object_id:report.body.report_id,digest:hash(report.body)});
 assert.deepEqual(state.evidence.body.payload.observation_ref,report.body.socket_callback_observation_ref);
 assert.equal(state.evidence.body.payload.observation.response.value,42);assert.equal(Object.isFrozen(state.evidence.body.payload.observation.response),true);
 f.gate(null);assert.deepEqual(await f.writer.installGuard(raw(f.install)),ack);assert.deepEqual(await f.writer.dispatch(raw(f.dispatch)),report);assert.equal(f.writes(),1);
 assert.deepEqual(f.writer.query('permit').evidence,state.evidence);
});

test('Guard缺失、范围/参数/意图不符或最终门控失效均零写入',async()=>{
 const missing=await sending();await assert.rejects(missing.writer.dispatch(raw(missing.dispatch)),/transmission_guard_required/);assert.equal(missing.writes(),0);
 for(const mutate of [f=>{f.dispatch.body.parameters_schema_digest=hash('other');},f=>{f.dispatch.body.permit.transmission.intent.attempt_id='other';},
  f=>{f.dispatch.body.request.parameters.value=10;},f=>{f.dispatch.body.permit.control_version='2';},f=>{f.gate(null);},f=>{f.tick(80n);},
  f=>{const next=f.gateValue();next.authorization_revision='2';f.gate(next);}]){
  const f=await sending();await f.writer.installGuard(raw(f.install));mutate(f);await assert.rejects(f.writer.dispatch(raw(f.dispatch)));
  assert.equal(f.writes(),0);assert.equal((await f.module.captureBaseline(f.device)).write_sequence,'0');
 }
 let reads=0;const raced=await sending({gate:value=>++reads>=3?null:value});await raced.writer.installGuard(raw(raced.install));
 await assert.rejects(raced.writer.dispatch(raw(raced.dispatch)),/transmission_gate_closed/);assert.equal(raced.writes(),0);
 assert.equal(raced.writer.query('permit').consumed,false);assert.equal(raced.writer.query('permit').pending,false);
});

test('消费许可后传输抛错或部分写只记unknown，绝不重发或宣布not_sent',async()=>{
 for(const mode of ['throw','partial']){
  const f=await sending({async write(input,module){await module.execution.writePrimitive(input);if(mode==='throw')throw new Error('synthetic_lost_response');return {bytes_written:4,response:null};}});
  await f.writer.installGuard(raw(f.install));const report=await f.writer.dispatch(raw(f.dispatch));await f.response(report);
  assert.equal(report.body.disposition,'unknown');assert.equal(report.body.proof,'send_uncertain');assert.equal(report.body.transport_entered_tick_ns,null);
  assert.equal(f.writer.query('permit').consumed,true);assert.equal(f.writes(),1);assert.equal((await f.module.captureBaseline(f.device)).value,42);
  assert.equal(f.writer.query('permit').evidence,null);
  await assert.rejects(f.writer.dispatch(raw(f.dispatch)),/transmission_closed/);assert.equal(f.writes(),1);
 }
});

test('传输进行中关闭不伪造退出，返回后仍为unknown；重复许可冲突关闭会话',async()=>{
 const started=deferred(),finish=deferred(),f=await sending({async write(input,module){const observed=await module.execution.writePrimitive(input);started.resolve();await finish.promise;return observed;}});
 await f.writer.installGuard(raw(f.install));const pending=f.writer.dispatch(raw(f.dispatch));await started.promise;
 assert.equal(f.writer.query('permit').consumed,true);assert.equal(f.writer.query('permit').pending,true);
 assert.equal(f.writer.query('permit').evidence,null);
 f.writer.close();assert.equal(f.writer.state.writing,true);finish.resolve();const report=await pending;
 assert.equal(report.body.disposition,'unknown');assert.equal(f.writer.state.writing,false);assert.equal(f.writes(),1);
 assert.equal(f.writer.query('permit').evidence,null);
 const other=await sending();await other.writer.installGuard(raw(other.install));await other.writer.dispatch(raw(other.dispatch));
 await assert.rejects(other.writer.dispatch(Buffer.from(JSON.stringify(other.dispatch,null,1))),/transmission_permit_conflict/);assert.equal(other.writes(),1);
});

test('传输等待期间重投同一许可最终取得同一报告且只有一次模块调用',async()=>{
 const started=deferred(),finish=deferred(),f=await sending({async write(input,module){const result=await module.execution.writePrimitive(input);started.resolve();await finish.promise;return result;}});
 await f.writer.installGuard(raw(f.install));const first=f.writer.dispatch(raw(f.dispatch));await started.promise;
 const duplicate=f.writer.dispatch(raw(f.dispatch));finish.resolve();const results=await Promise.all([first,duplicate]);
 assert.deepEqual(results[0],results[1]);assert.equal(f.writes(),1);assert.equal(f.writer.query('permit').consumed,true);
});

test('更换permit和Guard不能把同一attempt再次作为initial发送',async()=>{
 const f=await sending();await f.writer.installGuard(raw(f.install));await f.writer.dispatch(raw(f.dispatch));
 const install=structuredClone(f.install),g=install.body.guard;g.guard_id='second_guard';g.permit_id='second_permit';
 const {guard_digest,...unsigned}=g;g.guard_digest=hash(unsigned);install.message_id='second_guard_message';
 await f.writer.installGuard(raw(install));
 const dispatch=structuredClone(f.dispatch),p=dispatch.body.permit,tx=p.transmission;dispatch.message_id='second_dispatch_message';
 dispatch.body.guard_id=g.guard_id;dispatch.body.guard_digest=g.guard_digest;
 p.permit_id=g.permit_id;p.guard_id=g.guard_id;p.guard_digest=g.guard_digest;p.dispatch_intent_id='second_intent';p.budget_revision='2';
 tx.transmission_id='second_transmission';tx.initial_permit_id=p.permit_id;tx.parent_dispatch_intent_id=p.dispatch_intent_id;tx.issued_revision='2';
 Object.assign(tx.intent,{permit_id:p.permit_id,guard_id:p.guard_id,guard_digest:p.guard_digest,dispatch_intent_id:p.dispatch_intent_id});
 await assert.rejects(f.writer.dispatch(raw(dispatch)),/transmission_capacity_or_reuse/);assert.equal(f.writes(),1);
 assert.equal((await f.module.captureBaseline(f.device)).write_sequence,'1');
});

test('模块编码实际字节绑定原命令和授权，只读准备不调用设备写，原请求复用不重编码',async()=>{
 const f=await fixture(),frame=f.encode();await f.cache.prepare(raw(frame));const prepared=await f.cache.whenPrepared('prepare');
 assert.equal(prepared.state,'prepared');assert.equal(f.calls(),1);
 let packet;await f.cache.withResponse('prepare',async candidate=>{
  const reply=await f.response(candidate);packet=reply.body.packet;assert.equal(reply.type,'PREPARE_PACKET');
  assert.equal(reply.body.bytes_hex,'4c534d310000002a');assert.equal(packet.command_id,frame.body.command_id);
  assert.deepEqual(reply.body.encoding_authorization_ref,prepared.encoding_authorization_ref);
  const {packet_digest,...body}=packet;assert.equal(hash(body),packet_digest);
  assert.equal(packet.sha256,'sha256:'+crypto.createHash('sha256').update(Buffer.from(reply.body.bytes_hex,'hex')).digest('hex'));
 });
 assert.equal((await f.module.captureBaseline(f.device)).write_sequence,'0');
 await f.cache.prepare(raw(frame));assert.equal(f.calls(),1);
 // 此处直接以真实内存模块模拟消费者；不冒充Guard/permit或端到端命令验收。
 await f.cache.withPacket('prepare',prepared.packet_ref,bytes=>f.module.execution.writePrimitive({...f.device,bytes}));
 assert.equal((await f.module.captureBaseline(f.device)).value,42);
 const release=f.cleanup(frame),ack=await f.cache.release(raw(release));await f.response(ack);f.tick(30n);
 assert.deepEqual(await f.cache.release(raw(release)),ack);assert.equal(f.cache.usage.reserved_bytes,0);assert.ok(f.cache.usage.metadata_bytes>0);
 await assert.rejects(f.cache.withPacket('prepare',prepared.packet_ref,()=>assert.fail()),/encoding_not_available/);
});

test('DENY先于ENCODE安装精确墓碑，迟到原请求只补历史且永久不启动编码',async()=>{
 const f=await fixture(),frame=f.encode(),deny=f.cleanup(frame,'DENY_ENCODING');
 const ack=await f.cache.deny(raw(deny));await f.response(ack);assert.equal(ack.body.future_use_denied,true);
 assert.equal(f.cache.usage.entries,1);assert.equal(f.cache.usage.reserved_bytes,0);assert.equal(f.cache.usage.encoders,0);assert.equal(f.calls(),0);
 assert.equal((await f.cache.whenPrepared('prepare')).state,'denied');const metadata=f.cache.usage.metadata_bytes;
 f.tick(150n);assert.equal((await f.cache.prepare(raw(frame))).state,'denied');assert.equal(f.calls(),0);assert.equal(f.cache.usage.metadata_bytes,metadata);
 assert.deepEqual(await f.cache.deny(raw(deny)),ack);await assert.rejects(f.cache.withResponse('prepare',()=>assert.fail()),/encoding_not_available/);
 const released=await f.cache.release(raw(f.cleanup(frame)));await f.response(released);assert.equal(released.body.cache_empty,true);
 assert.equal((await f.cache.prepare(raw(frame))).state,'released');assert.equal(f.calls(),0);assert.equal(f.cache.usage.reserved_bytes,0);
 assert.equal((await f.module.captureBaseline(f.device)).write_sequence,'0');
});

test('未知准备的拒绝ACK不构成原编码缓存释放证明，缺少原ENCODE时不返回释放成功',async()=>{
 const f=await fixture(),frame=f.encode();await f.cache.deny(raw(f.cleanup(frame,'DENY_ENCODING')));
 await assert.rejects(f.cache.release(raw(f.cleanup(frame))),/encoding_release_origin_required/);assert.equal(f.cache.usage.closed,true);assert.equal(f.calls(),0);
 const absent=await fixture();await assert.rejects(absent.cache.release(raw(absent.cleanup(absent.encode()))),/encoding_unknown/);
 assert.equal(absent.cache.usage.entries,0);assert.equal(absent.calls(),0);
});

test('先行拒绝绑定原ENCODE信封、授权和选择时刻，改原件或改承诺均不能复活',async()=>{
 for(const mutate of [frame=>{frame.message_id='changed';},frame=>{frame.seq='2';},frame=>{
  frame.body.request.parameters.value=43;const {context_id,idempotency_key,...content}=frame.body.request;
  const a=frame.body.encoding_authorization;a.content_digest=hash(content);const {authorization_digest,...body}=a;a.authorization_digest=hash(body);
 }]){
  const f=await fixture(),frame=f.encode();await f.cache.deny(raw(f.cleanup(frame,'DENY_ENCODING')));mutate(frame);
  await assert.rejects(f.cache.prepare(raw(frame)),/encoding_prepare_conflict/);assert.equal(f.calls(),0);assert.equal(f.cache.usage.closed,true);
 }
 const f=await fixture(),frame=f.encode(),deny=f.cleanup(frame,'DENY_ENCODING');deny.body.selected_tick_ns='0';
 const {request_digest,...body}=deny.body;deny.body.request_digest=hash(body);await f.cache.deny(raw(deny));
 await assert.rejects(f.cache.prepare(raw(frame)),/encoding_cleanup_time/);assert.equal(f.calls(),0);
});

test('未知准备墓碑占永久元数据容量，收到原件及释放后仍不能复用这部分预算',async()=>{
 const f=await fixture({limits:{max_entries:2,max_cached_bytes:24,max_metadata_bytes:800000,max_encoders:1}}),first=f.encode('first');
 await f.cache.deny(raw(f.cleanup(first,'DENY_ENCODING')));const metadata=f.cache.usage.metadata_bytes;
 await f.cache.prepare(raw(first));await f.cache.release(raw(f.cleanup(first)));assert.equal(f.cache.usage.metadata_bytes,metadata);assert.equal(f.cache.usage.reserved_bytes,0);
 await assert.rejects(f.cache.deny(raw(f.cleanup(f.encode('second'),'DENY_ENCODING'))),/encoding_metadata_capacity/);
 assert.equal(f.cache.usage.entries,1);assert.equal(f.calls(),0);assert.equal(f.cache.usage.closed,true);
});

test('DENY与RELEASE必须引用同一准备撤回原件，重算摘要不能替换撤回来源',async()=>{
 const f=await fixture(),frame=f.encode();await f.cache.prepare(raw(frame));await f.cache.whenPrepared('prepare');await f.cache.deny(raw(f.cleanup(frame,'DENY_ENCODING')));
 const release=f.cleanup(frame);release.body.revocation_ref=ref('different_revocation');const {request_digest,...body}=release.body;release.body.request_digest=hash(body);
 await assert.rejects(f.cache.release(raw(release)),/encoding_cleanup_binding/);assert.equal(f.cache.usage.closed,true);
});

test('DENY先阻止未来借用，RELEASE等待真实消费者退出；不提前清空或退款',async()=>{
 const f=await fixture(),frame=f.encode();await f.cache.prepare(raw(frame));const prepared=await f.cache.whenPrepared('prepare'),entered=deferred(),finish=deferred();let held;
 const consumer=f.cache.withPacket('prepare',prepared.packet_ref,async bytes=>{held=bytes;entered.resolve();await finish.promise;});await entered.promise;
 await assert.rejects(f.cache.withResponse('prepare',()=>assert.fail()),/encoding_consumer_busy/);
 const deny=f.cleanup(frame,'DENY_ENCODING'),denied=await f.cache.deny(raw(deny));await f.response(denied);
 assert.equal(denied.body.future_use_denied,true);assert.ok(f.cache.usage.reserved_bytes>0);assert.equal(held[0],76);
 await assert.rejects(f.cache.withPacket('prepare',prepared.packet_ref,()=>assert.fail()),/encoding_not_available/);
 let released=false;const pending=f.cache.release(raw(f.cleanup(frame))).then(value=>{released=true;return value;});
 await turn();assert.equal(released,false);assert.ok(f.cache.usage.reserved_bytes>0);finish.resolve();await consumer;const ack=await pending;
 assert.equal(held.every(v=>v===0),true);assert.equal(ack.body.cache_empty,true);assert.equal(f.cache.usage.reserved_bytes,0);await f.response(ack);
});

test('取消编码只发出中止信号，释放ACK等待编码器实际返回且不接纳迟到字节',async()=>{
 const started=deferred(),finish=deferred();let exited=false;
 const f=await fixture({async encode(input){started.resolve();await finish.promise;exited=true;return new Uint8Array([76,83,77,49,0,0,0,7]);}}),frame=f.encode();
 await f.cache.prepare(raw(frame));await started.promise;
 const deny=await f.cache.deny(raw(f.cleanup(frame,'DENY_ENCODING')));assert.equal(deny.body.state,'denied');
 let acked=false;const pending=f.cache.release(raw(f.cleanup(frame))).then(ack=>{acked=true;return ack;});
 await turn();assert.equal(exited,false);assert.equal(acked,false);assert.equal(f.cache.usage.encoders,1);assert.ok(f.cache.usage.reserved_bytes>0);
 finish.resolve();const ack=await pending;assert.equal(exited,true);assert.equal(ack.body.encoder_quiescent,true);
 assert.equal((await f.cache.whenPrepared('prepare')).packet_ref,null);assert.equal((await f.module.captureBaseline(f.device)).write_sequence,'0');
 assert.equal(f.cache.usage.reserved_bytes,0);
});

test('容量失败保留原结果，释放只回收活字节，prepare身份和元数据不复用',async()=>{
 const f=await fixture({limits:{max_entries:3,max_cached_bytes:24,max_metadata_bytes:4000000,max_encoders:1}}),one=f.encode('one'),two=f.encode('two');
 await f.cache.prepare(raw(one));await f.cache.whenPrepared('one');await f.cache.prepare(raw(two));
 await f.cache.withResponse('two',async candidate=>{assert.equal((await f.response(candidate)).body.reason,'capacity');});
 assert.equal(f.calls(),1);await f.cache.release(raw(f.cleanup(one)));await f.cache.prepare(raw(two));assert.equal(f.calls(),1);
 const three=f.encode('three');await f.cache.prepare(raw(three));await f.cache.whenPrepared('three');assert.equal(f.calls(),2);
 assert.equal(f.cache.usage.entries,3);await assert.rejects(f.cache.prepare(raw(f.encode('four'))),/encoding_metadata_capacity/);
 assert.equal(f.cache.usage.closed,true);assert.equal(f.errors.length,1);
});

test('当前身份、完整授权及原字节冲突关闭缓存，不信任重算摘要后的越权字段',async()=>{
 for(const mutate of [frame=>{frame.worker_boot_id='other';},frame=>{frame.body.encoding_authorization.authorization_digest=hash('wrong');},
  frame=>{const a=frame.body.encoding_authorization;a.target.proposed_attempt_id='other';const {authorization_digest,...body}=a;a.authorization_digest=hash(body);},
  frame=>{const a=frame.body.encoding_authorization;a.requester.kind='service';const {authorization_digest,...body}=a;a.authorization_digest=hash(body);}]){
  const f=await fixture(),frame=f.encode();mutate(frame);await assert.rejects(f.cache.prepare(raw(frame)));assert.equal(f.calls(),0);assert.equal(f.cache.usage.closed,true);
 }
 const f=await fixture(),frame=f.encode();await f.cache.prepare(raw(frame));await f.cache.whenPrepared('prepare');
 await assert.rejects(f.cache.prepare(Buffer.from(JSON.stringify(frame,null,1))),/encoding_prepare_conflict/);assert.equal(f.calls(),1);assert.equal(f.cache.usage.closed,true);
});

test('编码在截止等号完成不能形成packet；过期仍可释放，时钟倒退永久关闭',async()=>{
 const gate=deferred(),f=await fixture({async encode(){await gate.promise;return new Uint8Array(8);}}),frame=f.encode();
 await f.cache.prepare(raw(frame));f.tick(100n);gate.resolve();assert.equal((await f.cache.whenPrepared('prepare')).state,'failed');
 await f.cache.withResponse('prepare',async candidate=>{assert.equal((await f.response(candidate)).body.reason,'expired');});
 f.tick(150n);await f.cache.release(raw(f.cleanup(frame)));assert.equal(f.cache.usage.reserved_bytes,0);
 const other=await fixture();await other.cache.prepare(raw(other.encode()));await other.cache.whenPrepared('prepare');other.tick(1n);
 await assert.rejects(other.cache.deny(raw(other.cleanup(other.encode(),'DENY_ENCODING'))),/encoding_clock/);assert.equal(other.cache.usage.closed,true);
});

test('到达时已过期只保存失败，失败编码不重试，错误清理身份不能制造释放证明',async()=>{
 const expired=await fixture(),late=expired.encode();expired.tick(100n);
 assert.equal((await expired.cache.prepare(raw(late))).state,'failed');assert.equal(expired.calls(),0);
 await expired.cache.withResponse('prepare',async candidate=>{assert.equal((await expired.response(candidate)).body.reason,'expired');});
 await expired.cache.release(raw(expired.cleanup(late)));assert.equal(expired.cache.usage.closed,false);
 const f=await fixture({async encode(){throw new Error('synthetic_encoder_failed');}}),frame=f.encode();await f.cache.prepare(raw(frame));await f.cache.whenPrepared('prepare');
 await f.cache.withResponse('prepare',async candidate=>{assert.equal((await f.response(candidate)).body.reason,'unavailable');});
 await f.cache.prepare(raw(frame));assert.equal(f.calls(),1);
 const changed=f.cleanup(frame);changed.body.encode_frame_digest=hash('other');const {request_digest,...body}=changed.body;changed.body.request_digest=hash(body);
 await assert.rejects(f.cache.release(raw(changed)),/encoding_cleanup_binding/);assert.equal(f.cache.usage.closed,true);
});

test('会话终止不重试已开始的编码或消费者，仍等待真实返回后丢弃活字节',async()=>{
 const started=deferred(),finish=deferred(),f=await fixture({async encode(){started.resolve();await finish.promise;return new Uint8Array(8);}}),frame=f.encode();
 await f.cache.prepare(raw(frame));await started.promise;const release=f.cache.release(raw(f.cleanup(frame)));await turn();
 f.abort.abort();await assert.rejects(release,/encoding_closed/);
 assert.equal(f.cache.usage.encoders,1);assert.ok(f.cache.usage.reserved_bytes>0);finish.resolve();await turn();
 assert.equal(f.cache.usage.encoders,0);assert.equal(f.cache.usage.reserved_bytes,0);assert.equal(f.calls(),1);assert.equal(f.errors.length,1);
 await assert.rejects(f.cache.prepare(raw(frame)),/encoding_closed/);
});
