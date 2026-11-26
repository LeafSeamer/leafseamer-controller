import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import test from 'node:test';
import Database from 'better-sqlite3';
import {canonical,digest,seal} from '../dist/auth-clock-value.mjs';
import {deviceControlRepository} from '../dist/device-control-repository.mjs';
import {currentControlSource} from '../dist/device-control-source.mjs';
import {deviceRegistryReader} from '../dist/device-registry-store.mjs';
import {runApprovalEndorsementStore} from '../dist/run-approval-endorsement.mjs';
import {captureRunDenySnapshot} from '../dist/run-generation-denial.mjs';
import {runPreparationStore} from '../dist/run-preparation-store.mjs';
import {startPeerPairingTransport} from '../dist/peer-pairing-transport.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {automationCommandExecutionSource} from '../dist/command-encoding-source.mjs';
import {readCommandPrincipalAuthorization} from '../dist/command-encoding-store.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {fixture as authenticationFixture} from './auth-clock-fixture.mjs';
import {inspect,setup} from './fixtures/extension-installation.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';

const id=()=>crypto.randomUUID();
const tables=['run_preparation','run_preparation_grant','run_preparation_commit'];
const rows=(db,table)=>db.prepare(`SELECT * FROM ${table} ORDER BY 1`).raw().all();
const ref=(kind,scope,object_id,body)=>({kind,scope,object_id,revision:'1',digest:digest(body)});
const iso=ns=>new Date(Number(ns/1000000n)).toISOString();

test('最终准入的服务授权从原 RunGrant、配对与批准重建，拒绝换代或替换配对',t=>{
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE automation_command_adjudication(command_id,decision,preparation_id,grant_id,body_jcs,body_digest);
  CREATE TABLE run_preparation_grant(preparation_id,grant_id,body_jcs,body_digest);
  CREATE TABLE run_preparation_commit(preparation_id,body_jcs,body_digest);
  CREATE TABLE peer_pairing_revision(binding_id,revision,state,body_jcs,body_digest);
  CREATE TABLE service_approval(approval_id,principal_id,body_jcs,body_digest);
  CREATE TABLE service_principal_revision(principal_id,state,body_jcs,body_digest);`);
 const scope={authority_service_id:id(),database_instance_id:id()},origin={authority_service_id:id(),database_instance_id:id()};
 const actor={issuer_id:id(),issuer_epoch:id(),principal_id:id()},target={device_id:id(),action_id:'set',capability_version:'1.0.0'};
 const device_scope={format:'leafseamer.device-binding-scope/1',...scope,device_ids:[target.device_id]},scopeDigest=digest(device_scope);
 const peer={service_kind:'seamer',service_id:origin.authority_service_id,database_instance_id:origin.database_instance_id,
  issuer_id:actor.issuer_id,issuer_epoch:actor.issuer_epoch,credential_id:id(),permissions:['automation.prepare'],object_scope_digest:scopeDigest};
 const pair=seal({binding_id:id(),revision:'4',state:'activated',transcript:{parties:[peer]}});
 const pairRef={id:pair.binding_id,revision:pair.revision,digest:pair.digest};
 const approval=seal({id:id(),revision:'1',principal_id:actor.principal_id,audiences:[scope.authority_service_id],permissions:['automation.prepare'],
  device_ids:[target.device_id],automation_origin:{seamer_scope:origin,pairing_ref:pairRef,device_scope}});
 const approvalRef={id:approval.id,revision:approval.revision,digest:approval.digest};
 const subject=seal({id:actor.principal_id,revision:'2',issuer_id:actor.issuer_id,issuer_epoch:actor.issuer_epoch,purpose:'automation',approval_ref:approvalRef});
 const grant= {grant_id:id(),revision:'1',origin_scope:origin,run_id:id(),definition_version:'2',arm_generation:'3',principal:{...actor,principal_kind:'service'},
  state:'active',device_actions:[target],validity:{authorization_policy_revision:'7'}};
 const grantRef=ref('grant',scope,grant.grant_id,grant),preparationId=id(),commandId=id();
 const preparation={grant_ref:grantRef,pairing_ref:pairRef,proof:{actual:{service_approval_ref:{kind:'service_approval',scope,object_id:approval.id,
  revision:approval.revision,digest:approval.digest},target_policy_ref:{id:id(),revision:'7',digest:digest('policy')}}}};
 const command={authority:{grant_ref:grantRef},execution_basis:{pairing_ref:pairRef}},adjudication={command};
 db.prepare('INSERT INTO automation_command_adjudication VALUES(?,?,?,?,?,?)').run(commandId,'accepted',preparationId,grant.grant_id,canonical(adjudication),digest(adjudication));
 db.prepare('INSERT INTO run_preparation_grant VALUES(?,?,?,?)').run(preparationId,grant.grant_id,canonical(grant),digest(grant));
 db.prepare('INSERT INTO run_preparation_commit VALUES(?,?,?)').run(preparationId,canonical(preparation),digest(preparation));
 db.prepare('INSERT INTO peer_pairing_revision VALUES(?,?,?,?,?)').run(pair.binding_id,4,'activated',canonical(pair),pair.digest);
 db.prepare('INSERT INTO service_approval VALUES(?,?,?,?)').run(approval.id,actor.principal_id,canonical(approval),approval.digest);
 db.prepare('INSERT INTO service_principal_revision VALUES(?,?,?,?)').run(subject.id,'active',canonical(subject),subject.digest);
 const source={command_id:commandId,binding:{scope,device_id:target.device_id},metadata:{origin:'automation',actor,target,
  automation_binding:{origin_scope:origin},run_binding:{grant_id:grant.grant_id,grant_revision:grant.revision,run_id:grant.run_id,
   definition_version:grant.definition_version,arm_generation:grant.arm_generation}}};
 const read=value=>db.transaction(()=>readCommandPrincipalAuthorization(db,value)).deferred();
 assert.deepEqual(read(source),{ref:{id:grant.grant_id,revision:'1',digest:grantRef.digest},binding:{...actor,audience:scope.authority_service_id,
  principal_kind:'service',origin:'automation',credential_id:peer.credential_id,subject_revision:'2',policy_revision:'7',scope_digest:scopeDigest,
  session_id:null,session_revision:null,grant_id:grant.grant_id,grant_revision:'1',arm_generation:'3',extension_instance_id:null,extension_approval_revision:null}});
 const different=structuredClone(source);different.metadata.run_binding.arm_generation='4';
 assert.throws(()=>read(different),{code:'execution_encoding_finalization_authorization'});
 command.execution_basis.pairing_ref={...pairRef,id:id()};
 db.prepare('UPDATE automation_command_adjudication SET body_jcs=?,body_digest=?').run(canonical(adjudication),digest(adjudication));
 assert.throws(()=>read(source),{code:'execution_encoding_finalization_authorization'});
});

test('自动命令的设备资格固定原 Ready、参数策略和授权窗口',async t=>{
 const f=await setup(t,97),service=f.store.identity,scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 const clockScope=f.store.authenticationClock.scope,base=authenticationFixture(clockScope);
 const domain={clock_domain_id:'clock_'+'c'.repeat(64),descriptor_digest:'sha256:'+'c'.repeat(64)};
 const fixed=authenticationFixture(clockScope,{source:base.source,descriptor:domain});
 const clock=startAuthenticationClock(fixed.source,f.store.authenticationClock,fixed.provider,{schedule:false});
 t.after(()=>clock.stop());
 const template=JSON.parse(fs.readFileSync(new URL('../dist/simulator-control-capability.json',import.meta.url),'utf8')),action=template.actions[0];
 const device=id(),binding={...domain,scope,device_id:device,device_session_id:id()},tick=base.source.tick();
 const execution={ref:ref('execution_device',scope,id(),binding),value:{binding,action:{action_id:action.action_id,capability_version:action.capability_version,
  parameters_schema_digest:action.parameters_schema.digest,result_schema_digest:action.result_schema.digest},capability_ref:{id:id(),revision:'1',digest:digest(template)},
  transport_profile_ref:{id:id(),revision:'1',digest:digest('transport')}},catalog:{qualification:{template_digest:digest(template)}},
  negotiation:{selected_features:['automation_origin_binding','run_generation_fence','run_deny_snapshot']},
  ready:{ref:ref('ready',scope,id(),'ready'),value:{binding,gate_after:{phase:'ready'},selected_tick_ns:String(tick-1n),expires_tick_ns:String(tick+700000000n),
   eligibility_refs:{control_authority:{id:id(),revision:'1',digest:digest('control')},authorization:{id:id(),revision:'1',digest:digest('authorization')}}}}};
 const origin={authority_service_id:id(),database_instance_id:id()},transcript={id:id(),revision:'1',digest:digest('paired')};
 const verified={target:{device_id:device,action_id:action.action_id,capability_version:action.capability_version},
  principal:{principal_kind:'service',issuer_id:id(),issuer_epoch:id(),principal_id:id()},
  execution_ref:ref('execution',origin,id(),'execution'),parameters_ref:ref('action_parameters',origin,'first',{value:13}),
  step_id:'first',action_binding_ref:{id:'binding.set',revision:'1',digest:digest('action binding')},
  grant_ref:ref('grant',scope,id(),'grant'),run_id:id(),arm_generation:'1',definition_version:'1',parameters:{value:13},
  parameter_schema_ref:{id:action.parameters_schema.schema_id,revision:'1',digest:action.parameters_schema.digest},
  not_before_ns:String(BigInt(clock.current().lower_ns)-1000000n),eligible_before_ns:String(BigInt(clock.current().upper_ns)+400000000n)};
 const control={mode:'automatic',holder:null,pending_change:null,gate_state:'ready',control_epoch:id(),effective_version:'1'};
 const registration={registration_ref:ref('source_registration',scope,id(),'registered action'),registration:{device_session_id:binding.device_session_id,capability_version:action.capability_version},
  bindings:[{kind:'action',content_ref:verified.action_binding_ref,value:{device_id:device,capability_id:action.action_id,parameter_schema_ref:verified.parameter_schema_ref}}]};
 const core={ref:{id:id(),revision:'1',digest:digest('core')},value:{domain_ref:domain,expires_tick_ns:String(tick+600000000n),service_boot_id:f.store.serviceBootId}};
 const preparedRef={id:id(),revision:'1',digest:digest('final admission')};
 let readyAvailable=true;
 inspect(f.dir,db=>{
  const write=work=>db.transaction(work).immediate();
  const gate=automationCommandExecutionSource({db,service,devices:{control(id){assert.equal(id,device);return control;}},
   executionCurrent(id,options){assert.equal(id,device);
    assert.deepEqual(options,{requireReady:true,...(options.preparedRef&&{preparedRef})});
    if(!readyAvailable)throw Object.assign(Error('ready lost'),{name:'WorkerLaunchError'});return execution;},
   deviceAutomationCurrent(id){assert.equal(id,device);return registration;},
   coreSource:{domain:()=>({ref:domain,tick:String(base.source.tick())}),selectCoreSource:()=>core,currentCoreSource(ref){assert.deepEqual(ref,core.ref);return core;}},
   time:()=>({acquisition:clock.current().acquisition_ref})});
  const selected=write(()=>gate.select(verified,transcript));
  assert.deepEqual(selected.original.ready_ref,execution.ready.ref);
  assert.deepEqual(selected.original.origin.action_binding_ref,verified.action_binding_ref);
  assert.deepEqual(selected.original.origin.registration_ref,registration.registration_ref);
  assert.equal(selected.original.action_policy.required_completion,'effect_verified');
  const window=selected.original.authentication_window;
  assert.equal(window.valid_before_ns,verified.eligible_before_ns);assert.ok(BigInt(window.before_tick_ns)<tick+600000000n);
  assert.deepEqual(write(()=>selected.assertCurrentInTransaction(verified)),selected.original);
  assert.deepEqual(write(()=>selected.currentExecution(verified,preparedRef)),execution);
  assert.throws(()=>write(()=>selected.assertCurrentInTransaction({...verified,eligible_before_ns:String(BigInt(verified.eligible_before_ns)+1000n)})),{code:'command_encoding_automation_changed'});
  assert.throws(()=>write(()=>gate.select({...verified,parameter_schema_ref:{...verified.parameter_schema_ref,digest:digest('wrong schema')}},transcript)),{code:'command_encoding_automation_registration'});
  assert.throws(()=>write(()=>gate.select({...verified,action_binding_ref:{...verified.action_binding_ref,digest:digest('old registration')}},transcript)),{code:'command_encoding_automation_registration'});
  readyAvailable=false;
  assert.throws(()=>write(()=>selected.assertCurrentInTransaction(verified)),{code:'command_encoding_automation_ready'});
  readyAvailable=true;
  base.source.advance(BigInt(window.before_tick_ns)-tick);
  assert.throws(()=>write(()=>selected.currentExecution(verified,preparedRef)),{code:'authentication_window_expired'});
 });
});

test('显式接入 Controller 准备受理，核验同一计划与控制原件，原子签发并可重开查原',{timeout:120000},async t=>{
 let db;t.after(()=>{if(db?.open)db.close();});
 const f=await setup(t,76),enrollment=f.store.enrollment.begin();
 await f.store.enrollment.complete({token_id:enrollment.token_id,secret:enrollment.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const auth=await authenticated(t,f,{grant:false}),service=f.store.identity;
 const permissions=auth.sessions.localPermissions(auth.auth);
 auth.sessions.replaceLocalPermissions(auth.auth,{request_id:id(),principal_id:auth.logged.session.principal_id,
  expected_revision:permissions.revision,permissions:[...permissions.permissions,'grant.manage']});
 const context=auth.sessions.createEndorsementContext(auth.token(['request.create','grant.manage']),{ttl_ms:30000,max_unique_requests:1});
 const serviceSubject=auth.sessions.createServicePrincipal(auth.auth,{request_id:id(),display_name:'准备主体',purpose:'automation'});
 const device=f.store.registerDevice({request_id:id(),device_kind:'simulator',display_name:'准备目标'}).device_id;
 const additionalDevice=f.store.registerDevice({request_id:id(),device_kind:'simulator',display_name:'尚未准备的批准目标'}).device_id;
 assert.equal(auth.sessions.runPreparations,null);auth.real.stop();f.close();

 const oldTables=['service_state','schema_migration','device_record','request_context','service_principal_head'];
 const old=inspect(f.dir,db=>oldTables.map(table=>rows(db,table)));
 inspect(f.dir,db=>db.exec('CREATE TABLE run_preparation_commit(conflict TEXT)'));
 await assert.rejects(migrateStorage(f.dir,77),{code:'migration_failed'});
 inspect(f.dir,db=>{
  assert.equal(db.pragma('user_version',{simple:true}),76);assert.deepEqual(oldTables.map(table=>rows(db,table)),old);
  assert.equal(db.prepare("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('run_preparation','run_preparation_grant')").pluck().get(),0);
  db.exec('DROP TABLE run_preparation_commit');
 });
 assert.equal((await migrateStorage(f.dir,77)).schema_revision,'77');
 inspect(f.dir,db=>{
  assert.deepEqual(oldTables.slice(2).map(table=>rows(db,table)),old.slice(2));
  assert.deepEqual(rows(db,'schema_migration').filter(row=>row[2]!=='77'),old[1]);
 });
 const migrated=f.reopen();
 assert.deepEqual(migrated.identity,{...service,schema_revision:'77'});f.close();
 let activeService=migrated.identity;
 const open=()=>{const db=new Database(path.join(f.dir,'controller.sqlite'));db.pragma('foreign_keys=ON');return db;};
 db=open();
 assert.deepEqual(db.prepare('SELECT state,closed_reason FROM request_context WHERE context_id=?').raw().get(context.context_id),['closed','restarted']);

 const writer=work=>db.transaction(work).immediate(),controller_scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id};
 const origin_scope={authority_service_id:id(),database_instance_id:id()},bindingId=id();
 const policyId=id(),endorsementId=id(),proposalId=id(),unarmedRunId=id();
 const service_principal={issuer_id:serviceSubject.issuer_id,issuer_epoch:serviceSubject.issuer_epoch,principal_id:serviceSubject.id};
 const issuerIdentity={issuer_id:auth.logged.session.issuer_id,issuer_epoch:auth.logged.session.issuer_epoch,principal_id:auth.logged.session.principal_id};
 const endorsementRequestDigest=digest('request');
 const endorsementAudit={context_id:context.context_id,request_digest:endorsementRequestDigest,target_policy_ref:{id:policyId},actor:issuerIdentity};
 const endorsement={scope:controller_scope,origin_scope,endorsement_id:endorsementId,revision:'1',run_id:unarmedRunId,proposal_ref:ref('run_approval_proposal',origin_scope,proposalId,'proposal'),
  created_authentication_ref:ref('authentication',controller_scope,endorsementId,endorsementAudit),endorsed_by:issuerIdentity,
  device_actions:[device,additionalDevice].map(device_id=>({device_id,action_id:'set',capability_version:'1.0.0'}))};
 const endorsement_ref=ref('run_approval_endorsement',controller_scope,endorsementId,endorsement);
 writer(()=>{
  // 锁定 Controller 的已有实体与背书关系。远端计划和授权结果由下方受控提供者送入。
  db.prepare('INSERT INTO run_endorsement_policy VALUES(?,?,?,?,?,?)').run(policyId,issuerIdentity.principal_id,serviceSubject.id,1,'{}',digest({}));
  db.prepare('INSERT INTO run_approval_endorsement VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
   .run(endorsementId,origin_scope.authority_service_id,origin_scope.database_instance_id,proposalId,policyId,context.context_id,
    digest('request identity'),endorsementRequestDigest,canonical(endorsement),digest(endorsement),canonical(endorsementAudit),digest(endorsementAudit));
  db.prepare("INSERT INTO run_approval_endorsement_state VALUES(?,1,'active')").run(endorsementId);
  const domain={ref:{clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:digest('control clock')},tick:'100'};
  const repository=deviceControlRepository(db,deviceRegistryReader(db,migrated.identity),()=>domain),commit=id();
  repository.touch('record',repository.current('record',device),commit);repository.commit(commit,'indeterminate',null,1,{synthetic:true});
 });
 let control=writer(()=>currentControlSource(db,device).current);
 const start=BigInt(Date.now()-5000)*1000000n,end=start+120000000000n;
 let now={lower:start+1000000n,upper:start+2000000n},tick=5n,delayPlan=false;
 const pairingSample=()=>({runtime_domain_ref:{id:'preparation test'},tick_ns:String(tick),lower_ns:String(now.lower),upper_ns:String(now.upper)});
 const binding={binding_id:bindingId,revision:'4',digest:digest('paired transcript'),state:'activated'};
 let permissionsForPeer=['automation.prepare','automation.prepare.read'];
 const planById=new Map(),proofByOperation=new Map(),approvals=new Map();
 let reads=0,checks=0,failAt=Infinity,observeRecoveryInitiator=null,overrideRecoveryExecution=null;
 function choose(origin,variant=()=>{}){
  const operation_id=id(),preparation_id=id(),run_id=origin?.run_id??id(),definition_id=id(),controls=[{device_id:device,control_ref:control.ref}];
  const approval={approval_id:id(),run_id,controller_endorsement_refs:[endorsement_ref]};
  const approval_ref=origin?.approval_ref??ref('run_approval',origin_scope,approval.approval_id,approval),operation_ref=ref('run_arm_operation',origin_scope,operation_id,'arm');
  if(!origin?.approval_ref)approvals.set(approval.approval_id,approval);
  const planned={operation_id,preparation_id,controller_scope,origin_scope,run_id,definition_version:'1',arm_generation:origin?.arm_generation??'1',mode:'arm',execution_id:null,
   operation_ref,artifact_ref:ref('artifact',origin_scope,id(),'artifact'),approval_ref,authorization_digest:digest('authorization'),source_digest:digest('source'),
   controls:[{device_id:device,expected_control:{epoch:control.value.control_epoch,version:control.value.effective_version}}],baseline_grant_ref:null,
   grant_intent:{principal:{...service_principal,principal_kind:'service'},device_actions:[{device_id:device,action_id:'set',capability_version:'1.0.0'}],
    parameter_constraints:[],validity:{not_before:iso(start),not_after:iso(end),authorization_policy_revision:'1'}}};
  const original={format:'leafseamer.run-arm-plan/1',definition_id,preparation:planned,controls};
  const {authorization_policy_revision,...validity}=planned.grant_intent.validity;
  const proof={initiator:{operation_ref,initiator:{...issuerIdentity,principal_kind:'human'},eligible_before_ns:String(end)},approval_ref,
   endorsement_ref,validity,service_principal,
   target_policy_ref:{id:policyId,revision:authorization_policy_revision,digest:digest('policy')},device_actions:planned.grant_intent.device_actions,parameter_constraints:[]};
  variant(original,proof);
  planById.set(preparation_id,original);proofByOperation.set(operation_id,proof);
  return {...planned,plan_ref:ref(planned.mode==='recovery'?'recovery_plan':'arm_plan',origin_scope,preparation_id,original)};
 }
 const authorizePeer=(supplied,socket)=>{
  assert.equal(supplied,bindingId);assert.equal(db.inTransaction,true);
  if(socket!=='paired TLS'){assert.equal(socket.authorized,true);assert.equal(socket.getProtocol(),'TLSv1.3');}
  return {record:binding,peer:{service_kind:'seamer',service_id:origin_scope.authority_service_id,database_instance_id:origin_scope.database_instance_id,permissions:permissionsForPeer}};
 };
 const prepareInitiator=async(binding,ref,expected)=>{
  assert.equal(binding,bindingId);assert.equal(db.inTransaction,false);
  const original=planById.get(expected.preparation_id);
  assert.equal(expected.definition_id,original.definition_id);assert.equal(expected.run_id,original.preparation.run_id);
  assert.deepEqual(expected.approval_ref,original.preparation.approval_ref);
  if(ref.kind==='recovery_operation'){
   const observed=await observeRecoveryInitiator(ref);
   if(observed.execution_id!==expected.execution_id)throw Error('recovery execution changed');
  }
  return {assertIssuanceInTransaction(){assert.equal(db.inTransaction,true);return proofByOperation.get(ref.object_id);}};
 };
 let approvalCurrent=true;
 const prepareApproval=async(binding,reference)=>{
  assert.equal(binding,bindingId);assert.equal(db.inTransaction,false);
  const actual=[...proofByOperation.values()].find(proof=>proof.approval_ref.object_id===reference.object_id);
  assert.deepEqual(actual.approval_ref,reference);
  return {assertCurrentInTransaction(){
   assert.ok(db.inTransaction);if(!approvalCurrent)throw Error('approval withdrawn');
   return {approval_ref:reference,endorsement_ref:actual.endorsement_ref,eligible_before_ns:String(end)};
  }};
 };
 let automationExecution=null;
 const construct=(bootId=migrated.serviceBootId)=>runPreparationStore({db,service:activeService,bootId,writer,time:()=>now,pairingSample,automationExecution,
  authorizePeer,prepareInitiator,prepareApproval});
 const store=construct(),main=choose();
 const send=(request=main)=>store.prepare(bindingId,'paired TLS',request);
 const query=(request=main)=>({controller_scope,origin_scope,preparation_id:request.preparation_id,request_digest:digest(request)});
 const counts=()=>tables.map(table=>rows(db,table).length);
 await assert.rejects(send(),{code:'peer_pairing_preparation_unavailable'});
 store.bindPlanReader(async(binding,{object_id})=>{
  assert.equal(binding,bindingId);assert.equal(db.inTransaction,false);reads++;
  if(delayPlan)tick+=2000000000n;
  return {original:planById.get(object_id),assertCurrentInTransaction(){
   assert.equal(db.inTransaction,true);if(++checks===failAt)throw Error('plan evidence withdrawn');return true;
  }};
 });
 permissionsForPeer=['automation.prepare.read'];
 await assert.rejects(send(),{code:'peer_pairing_preparation_scope'});assert.equal(reads,0);
 permissionsForPeer=['automation.prepare','automation.prepare.read'];
 await assert.rejects(send({...main,source_digest:digest('other source')}),{code:'peer_pairing_preparation_plan'});
 const wrongControl=choose(null,original=>{original.controls=[{device_id:device,control_ref:{...control.ref,digest:digest('wrong source')}}];});
 await assert.rejects(send(wrongControl),{code:'peer_pairing_preparation_control_changed'});
 const wrongPolicy=choose(null,original=>{original.preparation.grant_intent.validity.authorization_policy_revision='2';});
 await assert.rejects(send(wrongPolicy),{code:'peer_pairing_preparation_authorization'});
 delayPlan=true;await assert.rejects(send(),{code:'peer_pairing_preparation_expired'});delayPlan=false;
 for(const table of tables){
  db.exec(`CREATE TEMP TRIGGER omit_prepare BEFORE INSERT ON ${table} BEGIN SELECT RAISE(IGNORE); END`);
  await assert.rejects(send(),{code:'peer_pairing_preparation_storage'});
  db.exec('DROP TRIGGER omit_prepare');assert.deepEqual(counts(),[0,0,0]);
 }
 failAt=checks+2;await assert.rejects(send(),/plan evidence withdrawn/);failAt=Infinity;
 assert.deepEqual(counts(),[0,0,0]);assert.deepEqual(store.lookup(bindingId,'paired TLS',query()),{state:'not_found',record:null});
 const [one,two]=await Promise.all([send(),send()]);
 assert.deepEqual(one.record,two.record);assert.equal(Number(one.created)+Number(two.created),1);assert.deepEqual(counts(),[1,1,1]);
 const receipt=one.record.applied_receipt,{receipt_digest,...unsigned}=receipt;
 assert.equal(receipt_digest,digest(unsigned));assert.equal(receipt.grant_ref.digest,digest(receipt.grant));
 assert.deepEqual(receipt.grant.approval_ref,main.approval_ref);assert.equal(receipt.grant.endorsement_ref.object_id,endorsementId);
 assert.equal(receipt.grant.issuer_id,serviceSubject.issuer_id);
 assert.equal(receipt.grant.issuer_epoch,serviceSubject.issuer_epoch);
 const lookupStored=()=>store.lookup(bindingId,'paired TLS',query()).record;
 const detached=lookupStored();detached.applied_receipt.grant.issuer_id=id();
 assert.deepEqual(lookupStored(),one.record);
 const trigger=db.prepare("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='run_preparation_grant_no_update'").pluck().get();
 const originalGrant=db.prepare('SELECT body_jcs FROM run_preparation_grant WHERE preparation_id=?').pluck().get(main.preparation_id);
 const updateGrant=db.prepare('UPDATE run_preparation_grant SET body_jcs=? WHERE preparation_id=?');
 db.exec('DROP TRIGGER run_preparation_grant_no_update');
 try{
  assert.equal(updateGrant.run(originalGrant+' ',main.preparation_id).changes,1);
  assert.throws(lookupStored,{code:'peer_pairing_preparation_integrity'});
 }finally{
  updateGrant.run(originalGrant,main.preparation_id);db.exec(trigger);
 }
 assert.deepEqual(lookupStored(),one.record);
 assert.deepEqual(writer(()=>currentControlSource(db,device).current),control);
 const alias=choose(main);await assert.rejects(send(alias),{code:'peer_pairing_preparation_conflict'});
 await assert.rejects(send({...main,authorization_digest:digest('changed')}),{code:'peer_pairing_preparation_conflict'});
 const denied=choose();
 writer(()=>db.prepare('INSERT INTO run_approval_rejection VALUES(?,?,?,?,?,?,?,?)')
  .run(origin_scope.authority_service_id,origin_scope.database_instance_id,denied.approval_ref.object_id,id(),digest('rejection'),id(),canonical({}),digest({})));
 await assert.rejects(send(denied),{code:'peer_pairing_preparation_rejected'});
 now={lower:end,upper:end};
 permissionsForPeer=['automation.prepare.read'];
 const noNewReads=reads;assert.deepEqual(await send(),{created:false,record:one.record});assert.equal(reads,noNewReads);
 permissionsForPeer=[];assert.throws(()=>store.lookup(bindingId,'paired TLS',query()),{code:'peer_pairing_preparation_scope'});
 permissionsForPeer=['automation.prepare.read'];db.close();db=open();
 assert.deepEqual(construct().lookup(bindingId,'paired TLS',query()),{state:'found',record:one.record});
 assert.deepEqual(counts(),[1,1,1]);assert.deepEqual(db.pragma('foreign_key_check'),[]);

 now={lower:start+1000000n,upper:start+2000000n};permissionsForPeer=['automation.prepare','automation.prepare.read','automation.protect'];
 const {leaves:[seamerMaterial,controllerMaterial],ca}=peerCertificates(),runtime_domain_ref={id:id()};
 let observationOffset=0n;
 const clock={pairingSample(){const sample=String(BigInt(Date.now())*1000000n);return {lower_ns:sample,upper_ns:sample,
  tick_ns:String(process.hrtime.bigint()+observationOffset),runtime_domain_ref};}};
 async function endpoint(scope,service_kind,material,options){
  const identity={service_id:scope.authority_service_id,database_instance_id:scope.database_instance_id,service_kind,
   issuer_id:serviceSubject.issuer_id,issuer_epoch:serviceSubject.issuer_epoch,credential_id:id()};
  let record;
  const pairings={bindConfiguration(){},currentPending(key){assert.equal(key,record.binding_id);return record;},
   requireActivatedInTransaction(reference){assert.ok(db.inTransaction);assert.equal(reference.id,record.binding_id);return record;}};
  const transport=await startPeerPairingTransport({pairings,clock,identity,...material,ca,...options});
  return {transport,bindRecord(value){record=value;},peer:{identity,cert:material.cert,origin:transport.origin,
   server_name:'127.0.0.1',trust_bundle_digest:transport.configuration.trust_bundle_digest}};
 }
 let networkStore=construct(),loseResponseFor=null,loseCommandFor=null,actionReadHandler=null;
 const revocations=new Map();
 function protectionStore(){
  const store=runApprovalEndorsementStore({db,service:activeService,writer,pairingSample,
   authorizeProtectionPeer:authorizePeer,protectionTargets:networkStore.protectionTargets});
  store.bindApprovalReader(async(binding,reference)=>{
   assert.equal(binding,bindingId);assert.equal(db.inTransaction,false);
   return revocations.get(reference.object_id);
  });
  return store;
 }
 let protection=protectionStore();
 const controller=await endpoint(controller_scope,'controller',controllerMaterial,{runApprovalProtection:(...args)=>protection.receiveProtection(...args),
  automationCommands:{
   async submit(key,socket,request){
    const result=await networkStore.automationCommands.submit(key,socket,request);
    if(request.idempotency_key===loseCommandFor)socket.destroy();
    return result;
   },
   lookup:(...args)=>networkStore.automationCommands.lookup(...args),
   result:(...args)=>networkStore.automationCommands.result(...args),
   resource:(...args)=>networkStore.automationCommands.resource(...args),
   reject:(...args)=>networkStore.automationCommands.reject(...args)
  },runPreparations:{
  lookup:(...args)=>networkStore.lookup(...args),prepareEligibility:(...args)=>networkStore.prepareEligibility(...args),async prepare(key,socket,input,options){
   const result=await networkStore.prepare(key,socket,input,options);
   if(input.preparation_id===loseResponseFor)socket.destroy();
   return result;
  }
 }});t.after(()=>controller.transport.close());
 function planReply(request,kind){
  const original=planById.get(request.preparation_id),plan_ref=ref(kind,origin_scope,request.preparation_id,original);
  assert.equal(request.plan_digest,plan_ref.digest);
  const body={plan_ref,original,eligible_before_ns:String(end)};
  return {body,beforeSend:()=>body};
 }
 const seamer=await endpoint(origin_scope,'seamer',seamerMaterial,{runActionBinding:(...args)=>actionReadHandler(...args),
  runArmPlan(_binding,_socket,request){return planReply(request,'arm_plan');},
  runRecoveryPlan(_binding,_socket,request){return planReply(request,'recovery_plan');},runRecoveryInitiator(_binding,_socket,request){
   const {definition_id,preparation}=Array.from(planById.values()).find(value=>value.preparation.operation_id===request.operation_id);
   const {operation_ref,run_id,definition_version,arm_generation,approval_ref,artifact_ref,preparation_id,execution_id}=preparation;
   const {initiator}=proofByOperation.get(request.operation_id).initiator;
   return {operation_ref,run_id,definition_id,definition_version,arm_generation,approval_ref,artifact_ref,target_scope:controller_scope,
    preparation_id,execution_id:overrideRecoveryExecution??execution_id,initiator,
    initiator_authorization_ref:{id:request.operation_id,revision:'1',digest:digest('recovery authorization')},
    credential:{issuer_service_id:controller_scope.authority_service_id,token_id:request.operation_id,session_id:request.operation_id,
     session_revision:'1',credential_id:request.operation_id,policy_revision:'1',scope_digest:digest('issuer scope'),recent_before_ns:String(end)},
    eligible_before_ns:String(end)};
 }});t.after(()=>seamer.transport.close());
 controller.transport.bindPeers([seamer.peer]);seamer.transport.bindPeers([controller.peer]);
 const originBinding=id();
 const a={...seamer.transport.configuration,binding_id:originBinding,permissions:permissionsForPeer};
 const b={...controller.transport.configuration,binding_id:bindingId,permissions:['automation.prepare.read']};
 const transcript={pair_attempt_id:id(),parties:[a,b]},pair={state:'activated',revision:'4',digest:binding.digest,expires_ns:String(end),
  transcript,transcript_digest:digest(transcript)};
 Object.assign(binding,pair,{peer_service_id:a.service_id});controller.bindRecord(binding);
 seamer.bindRecord({...pair,binding_id:originBinding,peer_service_id:b.service_id});
 networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);
 observeRecoveryInitiator=ref=>controller.transport.readRunRecoveryInitiator(bindingId,ref);
 const submit=input=>seamer.transport.submitRunPreparation(originBinding,input);
 const lookup=input=>seamer.transport.lookupRunPreparation(originBinding,query(input));
 function revocation(request,grants=[]){
  const {approval_ref,operation_ref,preparation_id,run_id,arm_generation}=request,approval=approvals.get(approval_ref.object_id);
  const revocation_operation_ref=ref('run_approval_operation',origin_scope,id(),'revoke');
  revocations.set(approval_ref.object_id,{approval,object_ref:approval_ref,revocation_operation_ref,state:'revoking',local_eligibility:'blocked'});
  return {kind:'run_approval_revocation',origin_scope,target_scope:controller_scope,revocation_operation_ref,approval_ref,
   endorsement_ref:approval.controller_endorsement_refs[0],preparations:[{operation_ref,preparation_id,run_id,arm_generation,request_digest:digest(request)}],
   grants,arm_generations:[{run_id,arm_generation}]};
 }
 const revoke=notice=>seamer.transport.deliverRunApprovalProtection(originBinding,notice);
 function captured(notice){
  const [text,checksum]=db.prepare('SELECT body_jcs,body_digest FROM run_approval_rejection WHERE approval_id=?').raw().get(notice.approval_ref.object_id);
  const body=JSON.parse(text);assert.equal(digest(body),checksum);assert.deepEqual(body.notice,notice);return body;
 }
 const lost=choose();loseResponseFor=lost.preparation_id;
 assert.deepEqual(await lookup(lost),{state:'not_found',record:null});
 await assert.rejects(submit(lost),{code:'ECONNRESET'});assert.deepEqual(counts(),[2,2,2]);
 const lostNotice=revocation(lost),deniedLost=await revoke(lostNotice);
 assert.equal(deniedLost.protection_state,'pending');
 const recovered=await lookup(lost);
 assert.equal(recovered.state,'found');assert.deepEqual(recovered.record.request,lost);
 const historical=recovered.record.applied_receipt;
 assert.equal(historical.grant_ref.digest,digest(historical.grant));
 assert.deepEqual(captured(lostNotice).local_targets,[{...lostNotice.preparations[0],grant_ref:historical.grant_ref}]);
 const late=choose(),lateNotice=revocation(late),wrongRun={...lateNotice,preparations:[],arm_generations:[{run_id:id(),arm_generation:'1'}]};
 await assert.rejects(revoke(wrongRun),{code:'peer_pairing_response'});
 db.exec('CREATE TEMP TRIGGER omit_rejection BEFORE INSERT ON run_approval_rejection BEGIN SELECT RAISE(IGNORE); END');
 await assert.rejects(revoke(lateNotice),{code:'peer_pairing_response'});
 assert.equal(db.prepare('SELECT 1 FROM run_approval_rejection WHERE approval_id=?').pluck().get(late.approval_ref.object_id),undefined);
 db.exec('DROP TRIGGER omit_rejection');
 const deniedLate=await revoke(lateNotice);
 assert.equal(deniedLate.identity_state,'denied');assert.equal(deniedLate.protection_state,'pending');
 assert.deepEqual(captured(lateNotice).local_targets,[]);
 await assert.rejects(submit(late),{code:'peer_pairing_response'});
 await assert.rejects(networkStore.prepare(bindingId,'paired TLS',late),{code:'peer_pairing_preparation_rejected'});
 assert.deepEqual(await lookup(late),{state:'not_found',record:null});
 loseResponseFor=null;
 assert.deepEqual(await submit(lost),{created:false,record:recovered.record});
 await assert.rejects(submit({...lost,authorization_digest:digest('different authorization')}),{code:'peer_pairing_preparation_conflict'});
 const normal=choose(),result=await submit(normal);
 assert.equal(result.created,true);assert.deepEqual(await lookup(normal),{state:'found',record:result.record});
 const receiptForEligibility=result.record.applied_receipt;
 const eligibility={lookup:query(normal),grant_ref:receiptForEligibility.grant_ref,
  receipt_ref:ref('preparation_receipt',controller_scope,receiptForEligibility.receipt_id,receiptForEligibility)};
 const observe=(input=eligibility)=>seamer.transport.prepareRunPreparationEligibility(originBinding,input);
 const live=await observe();assert.deepEqual(live.original,{request:eligibility,state:'eligible',eligible_before_ns:String(end)});
 assert.equal(writer(live.assertCurrentInTransaction),true);
 const scheduled={...eligibility,schedule_device_ids:[device]};
 await assert.rejects(observe(scheduled),{code:'peer_pairing_response'});
 const withoutScheduleTargets=networkStore;
 let targetRevision='1',targetReady=true;
 automationExecution={observeScheduleTarget(id){
  assert.equal(db.inTransaction,true);assert.equal(id,device);
  if(!targetReady)throw Error('scheduled gate unavailable');
  return {ready_ref:{id:device,revision:targetRevision}};
 }};
 networkStore=construct();
 try{
  const observed=await observe(scheduled);
  assert.deepEqual(observed.original,{request:scheduled,state:'eligible',eligible_before_ns:String(end)});
  assert.equal(writer(observed.assertCurrentInTransaction),true);
  await assert.rejects(observe({...scheduled,schedule_device_ids:[id()]}),{code:'peer_pairing_response'});
  await assert.rejects(observe({...scheduled,schedule_device_ids:[device,device]}),{code:'peer_pairing_preparation_schedule_devices'});
  const gateChanged=await networkStore.prepareEligibility(bindingId,'paired TLS',scheduled);
  targetRevision='2';
  assert.throws(gateChanged.beforeSend,{code:'peer_pairing_preparation_schedule_changed'});
  targetReady=false;
  await assert.rejects(observe(scheduled),{code:'peer_pairing_response'});
  assert.deepEqual((await observe()).original.request,eligibility);
 }finally{networkStore=withoutScheduleTargets;automationExecution=null;}
 const fixedWindow=await observe();
 observationOffset=2000000000n;
 assert.equal(writer(fixedWindow.assertCurrentInTransaction),true);
 observationOffset=5000000000n;
 assert.throws(()=>writer(fixedWindow.assertCurrentInTransaction),{code:'peer_pairing_preparation_expired'});
 observationOffset=0n;
 const localWindow=await networkStore.prepareEligibility(bindingId,'paired TLS',eligibility);
 const localStart=tick;
 tick=localStart+2000000000n;
 assert.deepEqual(localWindow.beforeSend(),localWindow.body);
 tick=localStart+5000000000n;
 assert.throws(localWindow.beforeSend,{code:'peer_pairing_preparation_expired'});
 tick=localStart;
 const execution_id=id(),step_id='first',ready_id=id(),origin_digest=digest('original source event'),
  parameter_schema_ref={id:'fixture-parameter-schema',revision:'1',digest:digest('fixture schema')};
 const step_plan={execution_id,step_id,payload:{kind:'action',binding:{grant_ref:eligibility.grant_ref,parameter_schema_ref,
  target:{controller_scope,device_action:normal.grant_intent.device_actions[0]}}}};
 const execution={format:'leafseamer.trigger-execution/1',runtime_revision:'3',scope:origin_scope,execution_id,run_id:normal.run_id,
  artifact_ref:normal.artifact_ref,origin_kind:'trigger',origin_digest,arm_generation:normal.arm_generation,
  approved_before_ns:String(end),steps:[{step_id,plan_digest:digest(step_plan)}],
  grant_basis:[{...eligibility,eligible_before_ns:String(end)}]};
 const execution_ref=ref('execution',origin_scope,execution_id,execution);
 const ready={format:'leafseamer.step-ready/1',ready_id,execution_ref,step_id,step_plan_digest:digest(step_plan)};
 const step_ready={ref:ref('step_ready',origin_scope,ready_id,ready),body:ready};
 const frozen={format:'leafseamer.action-parameters/1',execution_ref,step_id,step_ready_ref:step_ready.ref,step_plan_digest:digest(step_plan),
  origin_digest,grant_ref:eligibility.grant_ref,delay_window_refs:[],parameter_schema_ref,eligible_before_ns:String(end),
  parameters:{value:13},parameters_digest:digest({value:13})};
 const parameters={ref:ref('action_parameters',origin_scope,step_id,frozen),body:frozen};
 const command={preparation:eligibility,execution_ref,step_id,parameters_ref:parameters.ref};
 const originalAction={execution,step_plan,step_ready,parameters,eligible_before_ns:String(end)};
 const prepareAction=(request=command)=>networkStore.prepareActionAdmission(bindingId,'paired TLS',request);
 await assert.rejects(prepareAction(),{code:'peer_pairing_action_unavailable'});
 let currentAction=originalAction,actionSourceCurrent=true;
 actionReadHandler=(selected,socket,request)=>{
  assert.equal(selected,originBinding);assert.equal(socket.authorized,true);assert.equal(db.inTransaction,false);
  assert.equal(request.step_id,step_id);
  const body=structuredClone(currentAction);
  return {body,beforeSend(){assert.ok(actionSourceCurrent);return body;}};
 };
 networkStore.bindActionReader(controller.transport.prepareRunActionBinding);
 const admitted=await prepareAction();
 assert.deepEqual(admitted.original.target,normal.grant_intent.device_actions[0]);
 assert.deepEqual(admitted.original.parameters,{value:13});
 assert.deepEqual(admitted.original.principal,receiptForEligibility.grant.principal);
 assert.deepEqual(admitted.original.grant_ref,receiptForEligibility.grant_ref);
 assert.deepEqual(writer(admitted.assertCurrentInTransaction),admitted.original);
 const fixedActionWindow=await controller.transport.prepareRunActionBinding(bindingId,command);
 observationOffset=2000000000n;
 assert.equal(writer(fixedActionWindow.assertCurrentInTransaction),true);
 observationOffset=5000000000n;
 assert.throws(()=>writer(fixedActionWindow.assertCurrentInTransaction),{code:'peer_pairing_preparation_expired'});
 observationOffset=0n;
 currentAction={...originalAction,step_plan:{...step_plan,payload:{...step_plan.payload,binding:{...step_plan.payload.binding,
  target:{controller_scope,device_action:{...normal.grant_intent.device_actions[0],device_id:additionalDevice}}}}}};
 await assert.rejects(prepareAction(),{code:'peer_pairing_action_plan'});
 currentAction=originalAction;
 const modified={...frozen,parameters:{value:99},parameters_digest:digest({value:99})};
 currentAction={...originalAction,parameters:{...parameters,body:modified}};
 await assert.rejects(prepareAction(),{code:'peer_pairing_response'});
 currentAction=originalAction;
 actionSourceCurrent=false;await assert.rejects(prepareAction(),{code:'peer_pairing_response'});
 actionSourceCurrent=true;
 const rawAction=Buffer.from(canonical(command));
 function readWithHeaders(headers,body=rawAction,client=controllerMaterial){
  return new Promise((resolve,reject)=>{
   const request=https.request(seamer.transport.origin+'/internal/automation/action-bindings',{method:'POST',agent:false,
    ...client,ca,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',headers:{'X-LeafSeamer-Pairing':originBinding,'X-LeafSeamer-Challenge':id(),
     'Content-Type':'application/json','Content-Length':body.length,...headers}},response=>{
    response.resume();response.on('end',()=>resolve(response.statusCode));response.on('error',reject);
   });request.on('error',reject);request.end(body);
  });
 }
 const version={'X-LeafSeamer-Action-Binding-Version':'leafseamer-action-binding/1'};
 assert.equal(await readWithHeaders({}),403);
 assert.equal(await readWithHeaders({...version,Authorization:'Bearer fixture'}),403);
 assert.equal(await readWithHeaders(version,Buffer.concat([rawAction,Buffer.from(' ')])),403);
 await assert.rejects(readWithHeaders(version,rawAction,{}));
 await assert.rejects(observe({...eligibility,grant_ref:{...eligibility.grant_ref,digest:digest('wrong grant')}}),{code:'peer_pairing_response'});
 await assert.rejects(construct(id()).prepareEligibility(bindingId,'paired TLS',eligibility),{code:'peer_pairing_preparation_ineligible'});
 const pendingProof=await networkStore.prepareEligibility(bindingId,'paired TLS',eligibility);
 approvalCurrent=false;assert.throws(pendingProof.beforeSend,/approval withdrawn/);
 await assert.rejects(observe(),{code:'peer_pairing_response'});approvalCurrent=true;
 assert.throws(pendingProof.beforeSend,{code:'peer_pairing_preparation_ineligible'});
 now={lower:end,upper:end};await assert.rejects(observe(),{code:'peer_pairing_response'});
 now={lower:start+1000000n,upper:start+2000000n};
 const normalNotice=revocation(normal,[{preparation_id:normal.preparation_id,grant_ref:receiptForEligibility.grant_ref}]);
 assert.equal((await revoke(normalNotice)).protection_state,'pending');
 assert.throws(()=>writer(admitted.assertCurrentInTransaction),{code:'peer_pairing_preparation_rejected'});
 await assert.rejects(observe(),{code:'peer_pairing_response'});
 assert.deepEqual(await lookup(normal),{state:'found',record:result.record});

 const oldInput=Buffer.from(canonical(choose()));
 const status=await new Promise((resolve,reject)=>{
  const request=https.request(controller.transport.origin+'/internal/automation/preparations',{method:'POST',agent:false,
   ...seamerMaterial,ca,minVersion:'TLSv1.3',maxVersion:'TLSv1.3',headers:{'X-LeafSeamer-Pairing':bindingId,'X-LeafSeamer-Challenge':id(),
    'X-LeafSeamer-Preparation-Version':'automation-preparation/0.1.0-draft.1','Content-Type':'application/json','Content-Length':oldInput.length}},response=>{
   response.resume();response.on('end',()=>resolve(response.statusCode));response.on('error',reject);
  });request.on('error',reject);request.end(oldInput);
 });
 assert.equal(status,403);assert.deepEqual(counts(),[3,3,3]);
 assert.deepEqual(writer(()=>currentControlSource(db,device).current),control);
 db.close();db=open();networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);
 protection=protectionStore();revocations.delete(lostNotice.approval_ref.object_id);
 assert.deepEqual(await revoke(lostNotice),deniedLost);
 assert.deepEqual(await lookup(lost),recovered);
 const mainEligibility={lookup:query(main),grant_ref:receipt.grant_ref,
  receipt_ref:ref('preparation_receipt',controller_scope,receipt.receipt_id,receipt)};
 assert.equal((await observe(mainEligibility)).original.state,'eligible');
 writer(()=>{
  const domain={ref:{clock_domain_id:'clock_'+'1'.repeat(64),descriptor_digest:digest('control clock')},tick:'101'};
  const repository=deviceControlRepository(db,deviceRegistryReader(db,migrated.identity),()=>domain),commit=id();
  repository.touch('record',repository.current('record',device),commit);repository.commit(commit,'indeterminate',null,1,{synthetic:true});
 });
 await assert.rejects(observe(mainEligibility),{code:'peer_pairing_response'});
 assert.deepEqual(await lookup(lost),recovered);
 const mainNotice=revocation(main),legacy={...mainNotice,preparations:[],grants:[],arm_generations:[]};
 assert.equal((await revoke(legacy)).protection_state,'pending');
 assert.deepEqual(captured(legacy).local_targets,[{...mainNotice.preparations[0],grant_ref:receipt.grant_ref}]);
 assert.deepEqual(db.pragma('foreign_key_check'),[]);

 const protectedTables=['run_approval_rejection',...tables],originals=protectedTables.map(table=>rows(db,table)),migrations=rows(db,'schema_migration');
 db.exec('CREATE TABLE run_generation_denial(conflict TEXT)');db.close();
 await assert.rejects(migrateStorage(f.dir,78),{code:'migration_failed'});
 db=open();assert.equal(db.pragma('user_version',{simple:true}),77);assert.deepEqual(rows(db,'schema_migration'),migrations);
 assert.deepEqual(protectedTables.map(table=>rows(db,table)),originals);
 db.exec('DROP TABLE run_generation_denial');db.close();
 assert.equal((await migrateStorage(f.dir,78)).schema_revision,'78');
 const upgraded=f.reopen();activeService=upgraded.identity;
 assert.deepEqual(activeService,{...migrated.identity,schema_revision:'78'});f.close();db=open();
 assert.deepEqual(protectedTables.map(table=>rows(db,table)),originals);
 assert.deepEqual(rows(db,'schema_migration').filter(row=>row[2]!=='78'),migrations);
 control=writer(()=>currentControlSource(db,device).current);
 networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);protection=protectionStore();
 const snapshot=revision=>writer(()=>captureRunDenySnapshot(db,controller_scope,revision));
 const restored=snapshot();assert.equal(restored.snapshot_revision,'4');
 assert.deepEqual(new Set(restored.entries.map(entry=>entry.selector.run_id)),new Set([main.run_id,normal.run_id,late.run_id,lost.run_id]));
 assert.ok(restored.entries.every(entry=>entry.selector.deny_through_generation==='1'&&entry.deny_revision==='1'));
 assert.deepEqual(await revoke(lostNotice),deniedLost);assert.deepEqual(snapshot(),restored);
 const lateReplacement=choose({run_id:late.run_id});
 await assert.rejects(submit(lateReplacement),{code:'peer_pairing_response'});
 await assert.rejects(networkStore.prepare(bindingId,'paired TLS',lateReplacement),{code:'peer_pairing_preparation_generation_denied'});
 const second=choose({run_id:late.run_id,arm_generation:'2'}),issued=await submit(second),secondReceipt=issued.record.applied_receipt;
 const earlierQualification={lookup:query(second),grant_ref:secondReceipt.grant_ref,
  receipt_ref:ref('preparation_receipt',controller_scope,secondReceipt.receipt_id,secondReceipt)};
 assert.equal((await observe(earlierQualification)).original.state,'eligible');
 const third=choose({run_id:late.run_id,arm_generation:'3'}),raise=revocation(third);
 db.exec('CREATE TEMP TRIGGER omit_floor BEFORE INSERT ON run_generation_denial BEGIN SELECT RAISE(IGNORE); END');
 await assert.rejects(revoke(raise),{code:'peer_pairing_response'});
 assert.equal(db.prepare('SELECT 1 FROM run_approval_rejection WHERE approval_id=?').pluck().get(third.approval_ref.object_id),undefined);
 assert.deepEqual(snapshot(),restored);db.exec('DROP TRIGGER omit_floor');
 assert.equal((await revoke(raise)).protection_state,'pending');
 const raised=snapshot();assert.equal(raised.snapshot_revision,'5');
 assert.deepEqual(raised.entries.find(entry=>entry.selector.run_id===late.run_id),{selector:{kind:'run_generation',origin_scope,run_id:late.run_id,deny_through_generation:'3'},deny_revision:'2'});
 assert.deepEqual(snapshot(4),restored);
 await assert.rejects(observe(earlierQualification),{code:'peer_pairing_response'});
 assert.deepEqual(await lookup(second),{state:'found',record:issued.record});
 assert.equal((await revoke(revocation(lateReplacement))).protection_state,'pending');assert.deepEqual(snapshot(),raised);
 assert.equal((await submit(choose({run_id:late.run_id,arm_generation:'4'}))).created,true);
 assert.throws(()=>db.exec('DELETE FROM run_generation_denial'),/immutable_run_generation_denial/);
 assert.deepEqual(db.pragma('foreign_key_check'),[]);
 db.close();assert.equal((await migrateStorage(f.dir,79)).schema_revision,'79');db=open();
 activeService={...activeService,schema_revision:'79'};
 networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);protection=protectionStore();
 const firstPage=protection.scanRunProtection({after:null,limit:1});
 assert.equal(firstPage.items.length,1);assert.equal(firstPage.next,firstPage.items[0]);
 const nextPage=protection.scanRunProtection({after:firstPage.next,limit:16});
 assert.equal(nextPage.next,null);assert.ok(nextPage.items.includes(deniedLost.receipt_id)||firstPage.items.includes(deniedLost.receipt_id));
 assert.deepEqual(protection.runProtectionPlan(deniedLost.receipt_id),{
  origin_scope,run_id:lost.run_id,deny_through_generation:'1',device_ids:[device,additionalDevice].sort()});
 assert.deepEqual(protection.runProtectionPlan(deniedLate.receipt_id),{
  origin_scope,run_id:late.run_id,deny_through_generation:'1',device_ids:[device,additionalDevice].sort()});

 const unarmed=choose({run_id:unarmedRunId});
 const unarmedNotice={...revocation(unarmed),arm_generations:[],preparations:[],grants:[]};
 const deniedUnarmed=await revoke(unarmedNotice);
 const readUnarmed=()=>db.prepare('SELECT body_jcs,body_digest FROM run_approval_rejection WHERE receipt_id=?').raw().get(deniedUnarmed.receipt_id);
 const plain=readUnarmed();
 assert.deepEqual(plain,[canonical(deniedUnarmed),digest(deniedUnarmed)]);
 assert.ok(!protection.scanRunProtection({after:null,limit:16}).items.includes(deniedUnarmed.receipt_id));
 db.close();assert.equal((await migrateStorage(f.dir,80)).schema_revision,'80');db=open();
 activeService={...activeService,schema_revision:'80'};
 networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);protection=protectionStore();
 const readOptIn=notice=>seamer.transport.deliverRunApprovalProtection(originBinding,notice,{completion:true});
 const observeProtection=notice=>seamer.transport.observeRunApprovalProtection(originBinding,notice);
 async function assertObservation(notice,state,completion=null){
  const value=await observeProtection(notice);
  assert.deepEqual(value,{format:'leafseamer.run-approval-protection-observation/1',challenge_id:value.challenge_id,
   request_digest:digest(notice),state,completion});
  return value;
 }
 const plan={origin_scope,run_id:unarmedRunId,deny_through_generation:null,device_ids:[device,additionalDevice].sort()};
 assert.ok(protection.scanRunProtection({after:null,limit:16}).items.includes(deniedUnarmed.receipt_id));
 assert.deepEqual(protection.runProtectionPlan(deniedUnarmed.receipt_id),plan);
 assert.equal(protection.runProtectionPlan(deniedLost.receipt_id).deny_through_generation,'1');
 assert.deepEqual(await readOptIn(unarmedNotice),deniedUnarmed);
 await assertObservation(unarmedNotice,'pending');
 await assertObservation(lostNotice,'pending');
 const beforeObservation=rows(db,'run_approval_rejection');
 await assertObservation(revocation(choose()),'not_found');
 assert.deepEqual(rows(db,'run_approval_rejection'),beforeObservation);
 await assert.rejects(observeProtection({...unarmedNotice,revocation_operation_ref:{...unarmedNotice.revocation_operation_ref,object_id:id()}}),
  {code:'peer_pairing_response'});
 await assert.rejects(submit(unarmed),{code:'peer_pairing_response'});
 const fenceTables=['run_generation_denial','execution_run_fence_frame'],beforeCompletion=fenceTables.map(table=>rows(db,table));
 const completed=protection.completeRunProtection(deniedUnarmed.receipt_id);
 assert.equal(completed.state,'delivered');
 const {receipt:finalReceipt}=completed;
 assert.deepEqual(finalReceipt,{format:'leafseamer.run-approval-protection/1',receipt_id:finalReceipt.receipt_id,rejection:deniedUnarmed,
  run_id:plan.run_id,deny_through_generation:null,device_ids:plan.device_ids,proof_digest:finalReceipt.proof_digest,protection_state:'applied'});
 const evidence={format:'leafseamer.run-approval-protection-no-preparation/1',plan,rejection_digest:plain[1],
  targets:plan.device_ids.map(device_id=>({device_id,state:'never_prepared'}))};
 assert.equal(finalReceipt.proof_digest,digest(evidence));
 const observed=await assertObservation(unarmedNotice,'verified',finalReceipt);
 assert.deepEqual(fenceTables.map(table=>rows(db,table)),beforeCompletion);
 assert.deepEqual(readUnarmed(),plain);
 assert.ok(!protection.scanRunProtection({after:null,limit:16}).items.includes(deniedUnarmed.receipt_id));
 db.close();db=open();
 networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);protection=protectionStore();
 assert.deepEqual(await readOptIn(unarmedNotice),finalReceipt);
 const reopenedObservation=await assertObservation(unarmedNotice,'verified',finalReceipt);
 assert.notEqual(reopenedObservation.challenge_id,observed.challenge_id);
 assert.deepEqual(await revoke(unarmedNotice),deniedUnarmed);
 assert.deepEqual(protection.completeRunProtection(deniedUnarmed.receipt_id),{state:'acknowledged',receipt:finalReceipt});
 await assert.rejects(submit(unarmed),{code:'peer_pairing_response'});
 assert.deepEqual(db.pragma('foreign_key_check'),[]);

 db.close();assert.equal((await migrateStorage(f.dir,94)).schema_revision,'94');db=open();
 const earlier=protectedTables.map(table=>rows(db,table)),migrationHistory=rows(db,'schema_migration');
 db.exec('CREATE TABLE automation_command_adjudication(conflict TEXT)');db.close();
 await assert.rejects(migrateStorage(f.dir,95),{code:'migration_failed'});
 db=open();assert.equal(db.pragma('user_version',{simple:true}),94);
 assert.deepEqual(rows(db,'schema_migration'),migrationHistory);
 db.exec('DROP TABLE automation_command_adjudication');db.close();
 assert.equal((await migrateStorage(f.dir,95)).schema_revision,'95');db=open();
 assert.deepEqual(protectedTables.map(table=>rows(db,table)),earlier);
 assert.deepEqual(rows(db,'schema_migration').filter(row=>row[2]!=='95'),migrationHistory);
 activeService={...activeService,schema_revision:'95'};
 networkStore=construct();networkStore.bindPlanReader(controller.transport.prepareRunArmPlan);
 networkStore.bindActionReader(controller.transport.prepareRunActionBinding);
 protection=protectionStore();control=writer(()=>currentControlSource(db,device).current);
 const queuedRun=choose(),queuedPrepare=await submit(queuedRun),queuedReceipt=queuedPrepare.record.applied_receipt;
 const approvedAction={lookup:query(queuedRun),grant_ref:queuedReceipt.grant_ref,
  receipt_ref:ref('preparation_receipt',controller_scope,queuedReceipt.receipt_id,queuedReceipt)};
 function commandForStep(){
  const execution_id=id();
  const plan={...step_plan,execution_id,payload:{...step_plan.payload,binding:{...step_plan.payload.binding,grant_ref:approvedAction.grant_ref,
   action_binding_ref:{id:'binding.set',revision:'1',digest:digest('action binding')}}}};
  const sealed={...execution,execution_id,run_id:queuedRun.run_id,artifact_ref:queuedRun.artifact_ref,arm_generation:queuedRun.arm_generation,
   steps:[{step_id,plan_digest:digest(plan)}],grant_basis:[{...approvedAction,eligible_before_ns:String(end)}]};
  const executionRef=ref('execution',origin_scope,execution_id,sealed);
  const bodyReady={...ready,ready_id:id(),execution_ref:executionRef,step_plan_digest:digest(plan)};
  const readyRecord={ref:ref('step_ready',origin_scope,bodyReady.ready_id,bodyReady),body:bodyReady};
  const value={...frozen,execution_ref:executionRef,step_ready_ref:readyRecord.ref,step_plan_digest:digest(plan),grant_ref:approvedAction.grant_ref};
  const parametersRef=ref('action_parameters',origin_scope,step_id,value);
  const request={action:{preparation:approvedAction,execution_ref:executionRef,step_id,parameters_ref:parametersRef},
   target:queuedRun.grant_intent.device_actions[0],idempotency_key:id()};
  const source={execution:sealed,step_plan:plan,step_ready:readyRecord,parameters:{ref:parametersRef,body:value},eligible_before_ns:String(end)};
  return {request,source};
 }
 const postCommand=request=>seamer.transport.submitAutomationCommand(originBinding,request);
 const lookupCommand=request=>seamer.transport.lookupAutomationCommand(originBinding,request);
 const rejectCommand=request=>seamer.transport.rejectAutomationCommand(originBinding,request);
 const queued=commandForStep();currentAction=queued.source;
 assert.deepEqual(await lookupCommand(queued.request),{state:'not_found',adjudication:null});
 db.exec('CREATE TEMP TRIGGER omit_auto BEFORE INSERT ON automation_command_adjudication BEGIN SELECT RAISE(IGNORE); END');
 await assert.rejects(postCommand(queued.request),{code:'peer_pairing_response'});
 assert.deepEqual(await lookupCommand(queued.request),{state:'not_found',adjudication:null});db.exec('DROP TRIGGER omit_auto');
 loseCommandFor=queued.request.idempotency_key;
 await assert.rejects(postCommand(queued.request));loseCommandFor=null;
 const accepted=await lookupCommand(queued.request);
 assert.equal(accepted.state,'found');assert.equal(accepted.adjudication.decision,'accepted');
 const persisted=JSON.parse(db.prepare('SELECT body_jcs FROM automation_command_adjudication WHERE decision=\'accepted\'').pluck().get());
 assert.equal(persisted.command.state,'queued');assert.deepEqual(persisted.command.authority.parameters,{value:13});
 assert.equal(accepted.adjudication.command_ref.digest,digest(persisted.command));
 assert.deepEqual(await postCommand(queued.request),accepted.adjudication);
 await assert.rejects(postCommand({...queued.request,idempotency_key:id()}),{code:'peer_pairing_automation_command_conflict'});
 await assert.rejects(lookupCommand({...queued.request,action:{...queued.request.action,
  parameters_ref:{...queued.request.action.parameters_ref,digest:digest('other content')}}}),{code:'peer_pairing_automation_command_conflict'});
 const lateCommand=commandForStep();currentAction=lateCommand.source;
 const rejected=await rejectCommand(lateCommand.request);
 assert.equal(rejected.decision,'rejected');assert.equal(rejected.command_ref,null);
 assert.deepEqual(await postCommand(lateCommand.request),rejected);
 assert.deepEqual(await rejectCommand(queued.request),accepted.adjudication);
 const concurrent=commandForStep();currentAction=concurrent.source;
 const priorActionReader=actionReadHandler,entered=Promise.withResolvers(),release=Promise.withResolvers();
 actionReadHandler=async(...args)=>{
  const current=priorActionReader(...args);
  entered.resolve();
  await release.promise;
  return current;
 };
 const inFlight=postCommand(concurrent.request);
 inFlight.catch(()=>{});
 let firstDecision;
 try{
  await Promise.race([entered.promise,inFlight]);
  firstDecision=await rejectCommand(concurrent.request);
 }finally{release.resolve();actionReadHandler=priorActionReader;}
 assert.equal(firstDecision.decision,'rejected');
 assert.deepEqual(await inFlight,firstDecision);
 db.close();assert.equal((await migrateStorage(f.dir,96)).schema_revision,'96');db=open();
 activeService={...activeService,schema_revision:'96'};
 networkStore=construct();networkStore.bindActionReader(controller.transport.prepareRunActionBinding);
 assert.deepEqual(await lookupCommand(queued.request),accepted);
 const runtimeCandidate=commandForStep();currentAction=runtimeCandidate.source;
 await assert.rejects(postCommand(runtimeCandidate.request),{code:'peer_pairing_response'});
 assert.deepEqual(await lookupCommand(runtimeCandidate.request),{state:'not_found',adjudication:null});
 let lostReady=true;
 automationExecution={select(authority,pairing_ref){
  assert.ok(db.inTransaction);assert.deepEqual(authority.execution_ref,runtimeCandidate.request.action.execution_ref);
  assert.equal(authority.not_before_ns,String(start));assert.deepEqual(authority.parameters,{value:13});
  const {execution_ref,parameters_ref,grant_ref,step_id,action_binding_ref,run_id,arm_generation,definition_version}=authority;
  const coreDomain={clock_domain_id:'fixture-clock',descriptor_digest:digest('fixture domain')};
  const original={format:'automation-command-execution-basis/1',binding:{device_id:device,scope:controller_scope,...coreDomain},
   ready_ref:{id:id(),revision:'1',digest:digest('worker ready')},pairing_ref,
   origin:{execution_ref,parameters_ref,grant_ref,step_id,action_binding_ref,run_id,arm_generation,definition_version,
    registration_ref:ref('source_registration',controller_scope,id(),'catalog registration')},
   authentication_window:{valid_from_ns:authority.not_before_ns,valid_before_ns:authority.eligible_before_ns,
    acquisition_ref:{id:id(),revision:'1',digest:digest('clock acquisition')},domain_ref:coreDomain,selected_tick_ns:'1',before_tick_ns:'1000'}};
  return {original,assertCurrentInTransaction(latest){
   assert.ok(db.inTransaction);assert.deepEqual(latest,authority);
   if(lostReady)return null;
   return original;
  }};
 }};
 networkStore=construct();networkStore.bindActionReader(controller.transport.prepareRunActionBinding);
 await assert.rejects(postCommand(runtimeCandidate.request),{code:'peer_pairing_response'});
 assert.deepEqual(await lookupCommand(runtimeCandidate.request),{state:'not_found',adjudication:null});
 lostReady=false;
 const qualified=await postCommand(runtimeCandidate.request);
 const qualifiedOriginal=JSON.parse(db.prepare('SELECT body_jcs FROM automation_command_adjudication WHERE command_id=?').pluck().get(qualified.command_ref.object_id));
 assert.equal(qualifiedOriginal.command.format,'leafseamer.automation-command/2');
 assert.equal(qualified.command_ref.digest,digest(qualifiedOriginal.command));
 assert.deepEqual(qualifiedOriginal.command.execution_basis.origin.parameters_ref,runtimeCandidate.request.action.parameters_ref);
 assert.deepEqual(await postCommand(runtimeCandidate.request),qualified);
 protection=protectionStore();
 const withdrawn=commandForStep();currentAction=withdrawn.source;
 assert.equal((await revoke(revocation(queuedRun))).protection_state,'pending');
 await assert.rejects(postCommand(withdrawn.request),{code:'peer_pairing_response'});
 assert.deepEqual(await lookupCommand(withdrawn.request),{state:'not_found',adjudication:null});
 db.close();db=open();networkStore=construct(id());
 assert.deepEqual(await lookupCommand(queued.request),accepted);
 assert.deepEqual(await lookupCommand(lateCommand.request),{state:'found',adjudication:rejected});
 assert.deepEqual(await lookupCommand(concurrent.request),{state:'found',adjudication:firstDecision});
 assert.deepEqual(await lookupCommand(runtimeCandidate.request),{state:'found',adjudication:qualified});
 assert.equal(db.prepare('SELECT count(*) FROM automation_command_adjudication').pluck().get(),4);
 assert.equal(db.prepare('SELECT count(*) FROM ca_command_initial').pluck().get(),0);
 assert.throws(()=>db.exec('DELETE FROM automation_command_adjudication'),/immutable_automation_command_adjudication/);
 assert.deepEqual(db.pragma('foreign_key_check'),[]);
 db.close();assert.equal((await migrateStorage(f.dir,97)).schema_revision,'97');db=open();
 activeService={...activeService,schema_revision:'97'};networkStore=construct(id());
 const readResult=input=>seamer.transport.readAutomationCommandResult(originBinding,input);
 const readResource=input=>seamer.transport.readAutomationCommandResource(originBinding,input);
 assert.deepEqual(await readResult(runtimeCandidate.request),{adjudication:qualified,terminal:null});
 assert.deepEqual(await readResult(lateCommand.request),{adjudication:rejected,terminal:null});
 assert.deepEqual(await readResult(withdrawn.request),{adjudication:null,terminal:null});
 for(const [request,adjudication] of [[runtimeCandidate.request,qualified],[lateCommand.request,rejected],[withdrawn.request,null]]){
  assert.deepEqual(await readResource(request),{adjudication,terminal:null,resource:null});
 }
 await assert.rejects(readResource({...runtimeCandidate.request,idempotency_key:id()}),{code:'peer_pairing_automation_command_conflict'});
 const oldPairingDigest=binding.digest;
 binding.digest=digest('replacement pairing');
 try{
  await assert.rejects(readResult(runtimeCandidate.request),{code:'peer_pairing_response'});
  await assert.rejects(readResource(runtimeCandidate.request),{code:'peer_pairing_response'});
 }
 finally{binding.digest=oldPairingDigest;}
 function recoveryRequest(generation,baseline=receipt.grant_ref){
  return choose({run_id:main.run_id,arm_generation:generation},(original,proof)=>{
   const preparation=original.preparation;
   original.format='leafseamer.run-recovery-plan/1';
   preparation.mode='recovery';preparation.execution_id=id();preparation.artifact_ref=main.artifact_ref;
   preparation.baseline_grant_ref=baseline;
   preparation.operation_ref=ref('recovery_operation',origin_scope,preparation.operation_id,'consumed recovery preview');
   proof.initiator.operation_ref=preparation.operation_ref;
   proof.initiator.execution_id=preparation.execution_id;
  });
 }
 networkStore.bindPlanReader(controller.transport.prepareRunRecoveryPlan);
 const recovery=recoveryRequest('2'),submitRecovery=input=>seamer.transport.submitRecoveryPreparation(originBinding,input);
 const lookupRecovery=()=>seamer.transport.lookupRecoveryPreparation(originBinding,query(recovery));
 const beforeRecovery=counts();
 await assert.rejects(submitRecovery(recoveryRequest('1')),{code:'peer_pairing_response'});
 await assert.rejects(submitRecovery(recoveryRequest('2',{...receipt.grant_ref,digest:digest('wrong old grant')})),{code:'peer_pairing_response'});
 await assert.rejects(seamer.transport.submitRunPreparation(originBinding,recovery),{code:'peer_pairing_preparation_request'});
 overrideRecoveryExecution=id();
 await assert.rejects(submitRecovery(recovery),{code:'peer_pairing_response'});
 overrideRecoveryExecution=null;
 assert.deepEqual(counts(),beforeRecovery);
 assert.deepEqual(await lookupRecovery(),{state:'not_found',record:null});
 loseResponseFor=recovery.preparation_id;
 await assert.rejects(submitRecovery(recovery));
 loseResponseFor=null;
 const recoveredPreparation=await lookupRecovery();
 assert.equal(recoveredPreparation.state,'found');
 assert.deepEqual(recoveredPreparation.record.request,recovery);
 assert.equal(recoveredPreparation.record.applied_receipt.grant.arm_generation,'2');
 assert.deepEqual(await submitRecovery(recovery),{created:false,record:recoveredPreparation.record});
 assert.deepEqual(counts(),beforeRecovery.map(count=>count+1));
 const recoveredReceipt=recoveredPreparation.record.applied_receipt,recoveryProof={lookup:query(recovery),grant_ref:recoveredReceipt.grant_ref,
  receipt_ref:ref('preparation_receipt',controller_scope,recoveredReceipt.receipt_id,recoveredReceipt)};
 await assert.rejects(seamer.transport.lookupRunPreparation(originBinding,query(recovery)),{code:'peer_pairing_response'});
 await assert.rejects(observe(recoveryProof),{code:'peer_pairing_response'});
 assert.equal((await seamer.transport.prepareRecoveryPreparationEligibility(originBinding,recoveryProof)).original.state,'eligible');
 networkStore.bindActionReader(controller.transport.prepareRunActionBinding);
 await assert.rejects(networkStore.prepareActionAdmission(bindingId,'paired TLS',
  {...runtimeCandidate.request.action,preparation:recoveryProof}),{code:'peer_pairing_preparation_ineligible'});
 function recoveryAction({decision='execute_new',operation=recovery.operation_ref,originalParameters=true,parametersValue=13,
  movePlan=false,oldGrant=recovery.baseline_grant_ref,peerBinding=originBinding}={}){
  const {execution_id,run_id,arm_generation,artifact_ref,definition_version}=recovery;
  const source_execution_id=id(),source_execution_ref=ref('execution',origin_scope,source_execution_id,'original execution');
  const source_step_plan={...structuredClone(step_plan),execution_id:source_execution_id};
  source_step_plan.payload.binding.grant_ref=oldGrant;
  const sourceBody={...structuredClone(frozen),execution_ref:source_execution_ref,step_plan_digest:digest(source_step_plan),grant_ref:oldGrant};
  const source_parameters=originalParameters?{ref:ref('action_parameters',origin_scope,step_id,sourceBody),body:sourceBody}:null;
  const reservation_ref=ref('execution',origin_scope,execution_id,'reserved execution');
  const members=[{...recoveryProof,pairing_ref:{id:peerBinding,revision:'4',digest:digest('Seamer local pairing')},endorsement_ref:recoveredReceipt.grant.endorsement_ref}];
  const definition={format:'leafseamer.recovery-execution-binding/1',operation_ref:operation,execution_ref:reservation_ref,
   approval_ref:recovery.approval_ref,arm_generation,run_revision:'8',grants:members,dispatch_eligible:false,service_boot_id:id()};
  const binding_ref=ref('recovery_execution_binding',origin_scope,execution_id,definition);
  const startRecord={format:'leafseamer.recovery-start/1',state:'start_recorded',operation_ref:operation,execution_ref:reservation_ref,binding_ref,
   approval_ref:recovery.approval_ref,arm_generation,previous_run_revision:'8',run_revision:'9',dispatch_eligible:false,service_boot_id:definition.service_boot_id,
   steps:[{step_id,source_execution_id,plan_digest:digest(source_step_plan),decision,grant_ref:recoveryProof.grant_ref,
    parameters_digest:source_parameters?.ref.digest??digest(source_step_plan.payload)}]};
  const start_ref=ref('recovery_start',origin_scope,operation.object_id,startRecord);
  const plan={...structuredClone(source_step_plan),execution_id};
  plan.payload.binding.grant_ref=recoveryProof.grant_ref;
  if(movePlan)plan.payload.binding.action_binding_ref={...plan.payload.binding.action_binding_ref,digest:digest('different binding')};
  const sealed={format:'leafseamer.recovery-action-execution/1',origin_kind:'recovery',execution_id,run_id,arm_generation,artifact_ref,definition_version,
   scope:origin_scope,reservation_ref,binding_ref,start_ref,service_boot_id:definition.service_boot_id,origin_digest:start_ref.digest,
   steps:[{step_id,plan_digest:digest(plan)}],grant_basis:members.map(member=>({...member,eligible_before_ns:String(end)})),approved_before_ns:String(end)};
  const execution_ref={...ref('execution',origin_scope,execution_id,sealed),revision:'2'};
  const bodyReady={...ready,ready_id:id(),execution_ref,step_plan_digest:digest(plan)};
  const step_ready={ref:ref('step_ready',origin_scope,bodyReady.ready_id,bodyReady),body:bodyReady};
  const body={...frozen,execution_ref,step_ready_ref:step_ready.ref,step_plan_digest:digest(plan),origin_digest:start_ref.digest,
   grant_ref:recoveryProof.grant_ref,parameters:{value:parametersValue},parameters_digest:digest({value:parametersValue})};
  const parameters_ref=ref('action_parameters',origin_scope,step_id,body);
  return {request:{action:{preparation:recoveryProof,execution_ref,step_id,parameters_ref},
   target:recovery.grant_intent.device_actions[0],idempotency_key:id()},source:{
   execution:sealed,step_plan:plan,step_ready,parameters:{ref:parameters_ref,body},eligible_before_ns:String(end),
   recovery:{binding:definition,start:startRecord,source_step_plan,source_parameters}}};
 }
 const resumed=recoveryAction();
 currentAction=resumed.source;
 const admitRecovery=action=>networkStore.prepareActionAdmission(bindingId,'paired TLS',action);
 const qualification=await admitRecovery(resumed.request.action);
 assert.deepEqual(qualification.original.execution_ref,resumed.request.action.execution_ref);
 assert.deepEqual(qualification.original.parameters,{value:13});
 assert.deepEqual(qualification.original.grant_ref,recoveryProof.grant_ref);
 assert.deepEqual(writer(qualification.assertCurrentInTransaction),qualification.original);
 assert.equal(await readWithHeaders(version,Buffer.from(canonical(resumed.request.action))),403);
 const foreign={...resumed.request,action:{...resumed.request.action,execution_ref:{...resumed.request.action.execution_ref,object_id:id()}}};
 await assert.rejects(admitRecovery(foreign.action),{code:'peer_pairing_preparation_ineligible'});
 await assert.rejects(lookupCommand(foreign),{code:'peer_pairing_response'});
 await assert.rejects(rejectCommand(foreign),{code:'peer_pairing_response'});
 for(const [options,code] of [
  [{decision:'retain_success'},'action_recovery_step'],
  [{operation:{...recovery.operation_ref,digest:digest('different recovery operation')}},'action_recovery_start'],
  [{parametersValue:17},'action_recovery_parameters'],
  [{peerBinding:id()},'action_recovery_grant'],
  [{oldGrant:recoveryProof.grant_ref},'action_recovery_step'],
  [{movePlan:true},'action_recovery_step']
 ]){
  const candidate=recoveryAction(options);currentAction=candidate.source;
  await assert.rejects(admitRecovery(candidate.request.action),{code:'peer_pairing_'+code});
 }
 const unprepared=recoveryAction({originalParameters:false});
 currentAction=unprepared.source;
 assert.deepEqual((await admitRecovery(unprepared.request.action)).original.parameters,{value:13});
 approvalCurrent=false;
 assert.throws(()=>writer(qualification.assertCurrentInTransaction),/approval withdrawn/);
 approvalCurrent=true;
 assert.throws(()=>writer(qualification.assertCurrentInTransaction),{code:'peer_pairing_action_unavailable'});
 assert.deepEqual(writer(()=>currentControlSource(db,device).current),control);
 db.close();db=open();networkStore=construct(id());
 assert.deepEqual(await lookupRecovery(),recoveredPreparation);
 await assert.rejects(seamer.transport.prepareRecoveryPreparationEligibility(originBinding,recoveryProof),{code:'peer_pairing_response'});
 assert.equal(db.prepare('SELECT count(*) FROM ca_command_initial').pluck().get(),0);
});
