import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';
import Database from 'better-sqlite3';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {registered} from './fixtures/device-bindings.mjs';
import {migrateStorage} from '../dist/storage.mjs';

const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url));
const load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const [{runEndorsementPolicyStore},{endorsementScope,assertEndorsementScopeContains,assertEndorsementParameters},{digest,ref,seal},{runApprovalEndorsementStore},{startOutboxDelivery}]=await Promise.all(
 ['run-endorsement-policy.mjs','run-endorsement-scope.mjs','auth-clock-value.mjs','run-approval-endorsement.mjs','session-denial-delivery.mjs'].map(load));
const id=()=>crypto.randomUUID();
const action={device_id:id(),action_id:'simulator.value.set',capability_version:'1.0.0'};
const clause=(rule,parameter_pointer='/value',selected=action)=>({...selected,parameter_pointer,rule});
const range=(minimum,maximum)=>({kind:'range',minimum,maximum});
const oneOf=(...values)=>({kind:'one_of',values});
const equals=value=>({kind:'equals',value});
const check=(policy,request)=>assertEndorsementScopeContains(endorsementScope([action],policy),endorsementScope([action],request));

test('目标策略按精确动作与参数路径证明包含关系，条件采用交集',()=>{
 assert.doesNotThrow(()=>check([clause(range(0,10)),clause(oneOf(1,3,5))],[clause(range(2,4)),clause(oneOf(1,3,7))]));
 assert.doesNotThrow(()=>check([clause(oneOf(3))],[clause(range(3,3))]));
 assert.doesNotThrow(()=>check([clause(range(0,10))],[clause(range(2,5))]));
 for(const request of [[],[clause(range(-1,5))],[clause(equals('3'))],[clause(equals(3),'/value/child')]]){
  assert.throws(()=>check([clause(range(0,10))],request),{code:'run_endorsement_constraint_denied'});
 }
 assert.throws(()=>check([],[clause(range(1,2)),clause(range(3,4))]),{code:'run_endorsement_constraint_empty'});
 assert.throws(()=>check([],[clause(equals({child:1})),clause(equals(2),'/value/child')]),{code:'run_endorsement_constraint_overlap'});
 assert.throws(()=>assertEndorsementScopeContains(endorsementScope([action],[]),
  endorsementScope([{...action,capability_version:'2.0.0'}],[])),{code:'run_endorsement_action_denied'});
});

test('Controller按原RunGrant约束重新核验封存参数',()=>{
 const pointer='/values/0/left~1right';
 const approved=endorsementScope([action],[clause(range(1,5),pointer),clause(oneOf(1,3,7),pointer)]);
 assert.doesNotThrow(()=>assertEndorsementParameters(approved,action,{values:[{'left/right':3}]}));
 for(const parameters of [{values:[{'left/right':7}]},{values:[{'left/right':'3'}]},{values:[]},{}]){
  assert.throws(()=>assertEndorsementParameters(approved,action,parameters),{code:'run_endorsement_constraint_denied'});
 }
 assert.throws(()=>assertEndorsementParameters(approved,{...action,device_id:id()},{values:[{'left/right':3}]}),
  {code:'run_endorsement_action_denied'});
});

test('显式迁移保留身份，当前策略控制正式认可，事务失败可重试，过期原件仍可查', {timeout:60000},async t=>{
 const fixture=await setup(t,71),first=fixture.store.enrollment.begin();
 await fixture.store.enrollment.complete({token_id:first.token_id,secret:first.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 const auth=await authenticated(t,fixture,{grant:false}),holder=auth.logged.session;
 assert.equal(auth.sessions.localPermissions(auth.auth).permissions.includes('grant.manage'),false);
 const human={issuer_id:holder.issuer_id,issuer_epoch:holder.issuer_epoch,principal_id:holder.principal_id};
 const servicePrincipal=auth.sessions.createServicePrincipal(auth.auth,{request_id:id(),display_name:'认可策略测试',purpose:'automation'});
 const service_principal={issuer_id:servicePrincipal.issuer_id,issuer_epoch:servicePrincipal.issuer_epoch,principal_id:servicePrincipal.id};
 const service=fixture.store.identity,device=fixture.store.registerDevice({request_id:id(),device_kind:'simulator',display_name:'认可目标'}).device_id;
 const catalog=registered(t,{service,device}),bundle=catalog.bindings(),selected=bundle.registration;
 const deviceAction={device_id:device,action_id:selected.capability_id,capability_version:selected.capability_version};
 const scope={authority_service_id:service.service_id,database_instance_id:service.database_instance_id},seamer={authority_service_id:id(),database_instance_id:id()};
 const pair={binding_id:id(),revision:'4',digest:digest('pair')},pairing_ref={id:pair.binding_id,revision:pair.revision,digest:pair.digest};
 const begin=1700000000000000000n,end=begin+120000000000n,now={lower:begin+1000000n,upper:begin+2000000n,acquisition:{id:id(),revision:'1',digest:digest('clock')}};
 const source=seal({id:id(),revision:'1',automation_origin:{pairing_ref,seamer_scope:seamer},not_before_ns:String(begin),expires_ns:String(end),device_ids:[device]});
 auth.real.stop();fixture.close();
 const before=inspect(fixture.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all());
 inspect(fixture.dir,db=>db.exec('CREATE TABLE run_endorsement_policy(conflict TEXT)'));
 await assert.rejects(migrateStorage(fixture.dir,72),{code:'migration_failed'});
 inspect(fixture.dir,db=>{
  assert.equal(db.pragma('user_version',{simple:true}),71);
  assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all(),before);
  db.exec('DROP TABLE run_endorsement_policy');
 });
 assert.equal((await migrateStorage(fixture.dir,72)).schema_revision,'72');
 const policyMigrations=inspect(fixture.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all());
 assert.deepEqual(policyMigrations.slice(0,-1),before);
 assert.equal((await migrateStorage(fixture.dir,73)).schema_revision,'73');
 const endorsementMigrations=inspect(fixture.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all());
 assert.deepEqual(endorsementMigrations.slice(0,-1),policyMigrations);
 assert.equal((await migrateStorage(fixture.dir,74)).schema_revision,'74');
 const rejectionMigrations=inspect(fixture.dir,db=>db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all());
 inspect(fixture.dir,db=>db.exec('CREATE TABLE run_approval_endorsement_revocation_outbox(conflict TEXT)'));
 await assert.rejects(migrateStorage(fixture.dir,75),{code:'migration_failed'});
 inspect(fixture.dir,db=>{
  assert.equal(db.pragma('user_version',{simple:true}),74);
  assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all(),rejectionMigrations);
  db.exec('DROP TABLE run_approval_endorsement_revocation_outbox');
 });
 assert.equal((await migrateStorage(fixture.dir,75)).schema_revision,'75');
 fixture.reopen();
 const endorsementAuth=await authenticated(t,fixture,{grant:false});
 const permissions=endorsementAuth.sessions.localPermissions(endorsementAuth.auth);
 const contextOptions={ttl_ms:30000,max_unique_requests:1};
 assert.throws(()=>endorsementAuth.sessions.createEndorsementContext(endorsementAuth.token(['request.create']),contextOptions),
  {code:'request_context_permission'});
 endorsementAuth.sessions.replaceLocalPermissions(endorsementAuth.auth,{request_id:id(),principal_id:human.principal_id,
  expected_revision:permissions.revision,permissions:[...permissions.permissions,'grant.manage','grant.read','grant.revoke']});
 const token=endorsementAuth.token(['request.create','grant.manage','grant.read']);
 const context=endorsementAuth.sessions.createEndorsementContext(token,contextOptions);
 const secondContext=endorsementAuth.sessions.createEndorsementContext(token,contextOptions);
 assert.throws(()=>endorsementAuth.sessions.createEndorsementRevocationContext(token,contextOptions),{code:'request_context_permission'});
 const revoker=endorsementAuth.token(['request.create','grant.revoke','grant.read']);
 const revokeContext=endorsementAuth.sessions.createEndorsementRevocationContext(revoker,contextOptions);
 assert.deepEqual(context.operations,['endorseRunApproval']);
 assert.throws(()=>endorsementAuth.sessions.createRequestContext(token,{...contextOptions,audience:service.service_id,
  selection:context.selection,operations:context.operations}),{code:'request_context_operation'});
 endorsementAuth.real.stop();fixture.close();
 const filename=path.join(fixture.dir,'controller.sqlite');
 function openFixture(){const db=new Database(filename);db.pragma('foreign_keys=ON');db.pragma('recursive_triggers=ON');return db;}
 let db=openFixture();
 try{
  const after=db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all();
  assert.deepEqual(after.slice(0,-1),rejectionMigrations);
  let activeSource=true,observed=bundle,readResult=null,hasGrant=true;
  const state={...service,schema_revision:'75'};
  const store=runEndorsementPolicyStore({db,service:state,
   management(_input,permission,work){if(permission==='grant.manage'&&!hasGrant)throw Object.assign(Error('denied'),{code:'denied'});return db.transaction(()=>work(human,now)).immediate();},
   sourceCurrent(principal,approvalRef){assert.ok(db.inTransaction);assert.deepEqual(principal,service_principal);assert.deepEqual(approvalRef,ref(source));assert.ok(activeSource,'source_revoked');return {approval:source};},
   time:()=>now,
   deviceAutomationCurrent(id){assert.equal(id,device);return observed;},
   pairings:()=>({currentPending:()=>pair,requireActivatedInTransaction(reference){assert.ok(db.inTransaction);assert.deepEqual(reference,pairing_ref);return pair;}}),
   pairingSample:()=>({runtime_domain_ref:{id:'clock'},tick_ns:'6000000',upper_ns:String(now.upper)})
  });
  store.bindProposalReader(async()=>{assert.equal(db.inTransaction,false);return readResult;});
  const request={request_id:id(),human,service_principal,service_approval_ref:ref(source),expected_policy_ref:null,not_before_ns:String(begin),expires_ns:String(end),
   device_actions:[deviceAction],parameter_constraints:[clause(range(0,20),'/value',deviceAction)]};
  const policy=store.replace(null,request);
  assert.equal(policy.revision,'1');assert.deepEqual(store.replace(null,request),policy);
  assert.throws(()=>store.replace(null,{...request,parameter_constraints:[]}),{code:'run_endorsement_policy_conflict'});
  assert.throws(()=>db.prepare('UPDATE run_endorsement_policy SET body_digest=?').run(digest('other')),/immutable_run_endorsement_policy/);
  let proposalId=id();const runId=id(),iso=value=>new Date(Number(value/1000000n)).toISOString();
  const setTarget=rules=>{
   const proposal={proposal_id:proposalId,run_id:runId,scope:seamer,service_principal,validity:{not_before:iso(begin),not_after:iso(end)},
    source_service_approval_ref:{kind:'service_approval',scope,object_id:source.id,revision:'1',digest:source.digest},
    controller_targets:[{controller_scope:scope,device_actions:[deviceAction],parameter_constraints:rules}]};
   readResult={proposal,proposal_ref:{kind:'run_approval_proposal',scope:seamer,object_id:proposalId,revision:'1',digest:digest(proposal)}};
   return {binding_id:pair.binding_id,proposal_ref:readResult.proposal_ref};
  };
  const peerRequest=setTarget([clause(equals(12),'/value',deviceAction)]);
  const ready=await store.check(null,peerRequest);
  assert.deepEqual(ready.policy_ref,ref(policy));assert.deepEqual(ready.registrations[0].registration_ref,bundle.registration_ref);
  await assert.rejects(store.check(null,setTarget([])),{code:'run_endorsement_constraint_denied'});
  await assert.rejects(store.check(null,setTarget([clause(equals(21),'/value',deviceAction)])),{code:'run_endorsement_constraint_denied'});
  assert.equal(setTarget([clause(equals(12),'/value',deviceAction)]).proposal_ref.digest,peerRequest.proposal_ref.digest);
  hasGrant=false;await assert.rejects(store.check(null,peerRequest),{code:'denied'});hasGrant=true;
  activeSource=false;await assert.rejects(store.check(null,peerRequest),/source_revoked/);activeSource=true;
  observed={...bundle,registration_ref:{...bundle.registration_ref,digest:digest('catalog changed')}};
  await assert.rejects(store.check(null,peerRequest),{code:'run_endorsement_catalog_changed'});observed=bundle;
  let reader=human,writeAllowed=true,originPeer=seamer;
  const fullPair={...pair,state:'activated',expires_ns:String(end),peer_service_id:seamer.authority_service_id,
   transcript:{parties:[{service_kind:'seamer',service_id:seamer.authority_service_id,database_instance_id:seamer.database_instance_id}]}};
  let approvalTick=6000000n,initiatorTokenCurrent=true;
  const openEndorsements=revision=>runApprovalEndorsementStore({db,service:{...state,schema_revision:revision},writer:work=>db.transaction(work).immediate(),time:()=>now,
   requireCurrentEndorsement:store.requireCurrentEndorsement,
   requireCurrentInitiator:store.requireCurrentInitiator,
   authorizeArmInitiator(_credential,_actor,audience){assert.ok(db.inTransaction);assert.equal(audience,seamer.authority_service_id);
    if(!initiatorTokenCurrent)throw Object.assign(Error('issuer revoked token'),{code:'run_initiator_authorization'});return end;},
   pairings:()=>({currentPending:()=>fullPair,requireActivatedInTransaction(reference){assert.ok(db.inTransaction);assert.deepEqual(reference,pairing_ref);return fullPair;},
    requireActivePeerInTransaction(scope,kind,bindingId){assert.ok(db.inTransaction);assert.deepEqual(scope,seamer);assert.equal(kind,'seamer');
     assert.ok(bindingId===null||bindingId===pair.binding_id);return fullPair;}}),
   pairingSample:()=>({runtime_domain_ref:{id:'clock'},tick_ns:String(approvalTick),lower_ns:String(now.lower),upper_ns:String(now.upper)}),
   authorizePeer(bindingId,socket){assert.ok(db.inTransaction);assert.equal(bindingId,pair.binding_id);assert.equal(socket,'tls');
    return {record:{...pair,expires_ns:String(end)},peer:{service_id:originPeer.authority_service_id,database_instance_id:originPeer.database_instance_id}};
   },
   authorizeProtectionPeer(bindingId,socket){assert.ok(db.inTransaction);assert.equal(bindingId,pair.binding_id);assert.equal(socket,'tls');
    return {record:fullPair,peer:{service_id:originPeer.authority_service_id,database_instance_id:originPeer.database_instance_id}};
   },
   readProposal:store.withProposal,authorize(credential,permission,contextId){
    assert.ok(db.inTransaction);assert.ok(credential===token||credential===revoker);
    if(permission==='grant.manage'){
     if(!writeAllowed)throw Object.assign(Error('context closed'),{code:'request_context_closed'});
     assert.ok([context.context_id,secondContext.context_id].includes(contextId));
    }
    if(permission==='grant.revoke'){
     if(credential!==revoker)throw Object.assign(Error('missing grant.revoke'),{code:'run_endorsement_permission'});
     assert.equal(contextId,revokeContext.context_id);
    }
    return {actor:permission==='grant.read'?reader:human,evidence:{authorization_digest:digest('endorsement authorization')}};
   }});
  const endorsements=openEndorsements('75');
  const submission={...peerRequest,context_id:context.context_id,idempotency_key:id()};
  const lookup={context_id:context.context_id,idempotency_key:submission.idempotency_key};
  const used=()=>db.prepare('SELECT used_count FROM request_context WHERE context_id=?').pluck().get(context.context_id);
  db.exec('CREATE TEMP TRIGGER omit_notice BEFORE INSERT ON run_approval_endorsement_notice BEGIN SELECT RAISE(IGNORE); END');
  await assert.rejects(endorsements.endorse(token,submission),{code:'run_endorsement_storage'});
  assert.equal(used(),0);
  assert.deepEqual(endorsements.lookup(token,lookup),{request_digest:null,result:null});
  db.exec('DROP TRIGGER omit_notice');
  const receipt=await endorsements.endorse(token,submission),endorsementId=receipt.endorsement_ref.object_id;
  const stored=endorsements.get(token,endorsementId);
  assert.equal(stored.endorsement.run_id,runId);
  assert.equal(digest(stored.endorsement),receipt.endorsement_ref.digest);
  assert.equal(stored.endorsement.controller_target_digest,ready.controller_target_digest);
  assert.deepEqual(stored.endorsement.parameter_constraints,[clause(equals(12),'/value',deviceAction)]);
  const artifactRef={kind:'artifact',scope:seamer,object_id:id(),revision:'1',digest:digest('program artifact')};
  const approval={scope:seamer,approval_id:id(),revision:'1',proposal_ref:peerRequest.proposal_ref,run_id:runId,service_principal,artifact_ref:artifactRef,
   validity:readResult.proposal.validity,source_service_approval_ref:readResult.proposal.source_service_approval_ref,controller_endorsement_refs:[receipt.endorsement_ref]};
  function reply(body){return {approval:body,object_ref:{kind:'run_approval',scope:seamer,object_id:body.approval_id,revision:'1',digest:digest(body)},
   state:'active',local_eligibility:'eligible',eligible_before_ns:String(end)};}
  let remoteApproval=reply(approval);
  endorsements.bindApprovalReader(async(bindingId,reference)=>{assert.equal(db.inTransaction,false);assert.equal(bindingId,pair.binding_id);
   assert.deepEqual(reference,remoteApproval.object_ref);return remoteApproval;});
  const qualify=()=>endorsements.prepareRunApproval(pair.binding_id,remoteApproval.object_ref);
  const qualified=await qualify();
  assert.deepEqual(qualified.eligibility,{approval_ref:remoteApproval.object_ref,endorsement_ref:receipt.endorsement_ref,eligible_before_ns:String(end)});
  assert.deepEqual(db.transaction(qualified.assertCurrentInTransaction).immediate(),qualified.eligibility);
  const armRef={kind:'run_arm_operation',scope:seamer,object_id:id(),revision:'1',digest:digest('arm operation')};
  const intent={run_id:runId,definition_id:id(),definition_version:'1',arm_generation:'1',preparation_id:id(),approval_ref:remoteApproval.object_ref,artifact_ref:artifactRef};
  const issued={...intent,operation_ref:armRef,target_scope:scope,initiator:{...human,principal_kind:'human'},
   initiator_authorization_ref:{id:armRef.object_id,revision:'1',digest:digest('arm authorization')},credential:{},eligible_before_ns:String(end)};
  let armOriginal=issued;
  endorsements.bindInitiatorReader(async(bindingId,reference)=>{assert.equal(db.inTransaction,false);assert.equal(bindingId,pair.binding_id);assert.deepEqual(reference,armRef);return armOriginal;});
  const qualifyInitiator=(expected=intent)=>endorsements.prepareRunInitiator(pair.binding_id,armRef,expected);
  const qualifiedInitiator=await qualifyInitiator();
  assert.deepEqual(qualifiedInitiator.eligibility.initiator_policy_ref,ref(policy));
  assert.deepEqual(db.transaction(qualifiedInitiator.assertCurrentInTransaction).immediate(),qualifiedInitiator.eligibility);
  assert.deepEqual(db.transaction(qualifiedInitiator.assertIssuanceInTransaction).immediate(),{
   initiator:qualifiedInitiator.eligibility,approval_ref:remoteApproval.object_ref,endorsement_ref:receipt.endorsement_ref,
   validity:approval.validity,service_principal,service_approval_ref:approval.source_service_approval_ref,target_policy_ref:ref(policy),
   device_actions:stored.endorsement.device_actions,parameter_constraints:stored.endorsement.parameter_constraints});
  for(const change of [{run_id:id()},{arm_generation:'2'},{preparation_id:id()}])await assert.rejects(qualifyInitiator({...intent,...change}),{code:'run_endorsement_initiator_scope'});
  armOriginal={...issued,target_scope:{...scope,database_instance_id:id()}};
  await assert.rejects(qualifyInitiator(),{code:'run_endorsement_initiator_scope'});
  armOriginal={...issued,initiator:{...issued.initiator,principal_id:id()}};
  await assert.rejects(qualifyInitiator(),{code:'run_endorsement_policy_human'});
  armOriginal=issued;initiatorTokenCurrent=false;
  assert.throws(()=>db.transaction(qualifiedInitiator.assertCurrentInTransaction).immediate(),{code:'run_initiator_authorization'});
  initiatorTokenCurrent=true;
  assert.throws(()=>db.transaction(qualifiedInitiator.assertCurrentInTransaction).immediate(),{code:'run_endorsement_initiator_unavailable'});
  approvalTick+=2000000000n;
  assert.deepEqual(db.transaction(qualified.assertCurrentInTransaction).immediate(),qualified.eligibility);
  approvalTick+=3000000000n;
  assert.throws(()=>db.transaction(qualified.assertCurrentInTransaction).immediate(),{code:'run_endorsement_approval_expired'});
  approvalTick=6000000n;
  assert.throws(()=>db.transaction(qualified.assertCurrentInTransaction).immediate(),{code:'run_endorsement_approval_unavailable'});
  remoteApproval=reply({...approval,run_id:id()});
  await assert.rejects(qualify(),{code:'run_endorsement_approval_endorsement'});remoteApproval=reply(approval);
  remoteApproval={...remoteApproval,state:'revoking',local_eligibility:'blocked',eligible_before_ns:null};
  await assert.rejects(qualify(),{code:'run_endorsement_approval_ineligible'});remoteApproval=reply(approval);
  const peerQuery={endorsement_id:endorsementId,endorsement_digest:receipt.endorsement_ref.digest},readPeer=(query=peerQuery)=>endorsements.readForPeer(pair.binding_id,'tls',query);
  assert.deepEqual(readPeer(),{...stored,current_eligibility:'eligible',eligible_before_ns:String(end)});
  assert.throws(()=>readPeer({...peerQuery,endorsement_digest:digest('wrong')}),{code:'run_endorsement_missing'});
  originPeer={...seamer,database_instance_id:id()};
  assert.throws(()=>readPeer(),{code:'run_endorsement_missing'});originPeer=seamer;
  observed={...bundle,registration_ref:{...bundle.registration_ref,digest:digest('new registration')}};
  assert.equal(readPeer().current_eligibility,'blocked');observed=bundle;
  assert.deepEqual(await endorsements.endorse(token,submission),receipt);
  assert.equal(used(),1);
  writeAllowed=false;
  assert.deepEqual(await endorsements.endorse(token,submission),receipt);
  await assert.rejects(endorsements.endorse(token,{...submission,idempotency_key:id()}),{code:'request_context_closed'});
  writeAllowed=true;
  await assert.rejects(endorsements.endorse(token,{...submission,binding_id:id()}),{code:'run_endorsement_conflict'});
  await assert.rejects(endorsements.endorse(token,{...submission,idempotency_key:id()}),{code:'run_endorsement_proposal_already_endorsed'});
  reader={...human,principal_id:id()};
  assert.throws(()=>endorsements.get(token,endorsementId),{code:'run_endorsement_missing'});
  assert.throws(()=>endorsements.lookup(token,lookup),{code:'run_endorsement_context'});
  reader=human;
  const priorQualification=await qualify();
  const firstProposalId=proposalId;proposalId=id();
  const secondRequest=setTarget([clause(equals(12),'/value',deviceAction)]);
  const second=await endorsements.endorse(token,{...secondRequest,context_id:secondContext.context_id,idempotency_key:id()});
  const secondId=second.endorsement_ref.object_id;
  remoteApproval=reply({...approval,approval_id:id(),proposal_ref:secondRequest.proposal_ref,controller_endorsement_refs:[second.endorsement_ref]});
  const oldEligibility=await qualify();
  const revokeRequest={context_id:revokeContext.context_id,idempotency_key:id(),endorsement_ref:second.endorsement_ref,expected_status_revision:'1',reason:'撤回本机认可'};
  const revoke=()=>endorsements.revoke(revoker,secondId,revokeRequest);
  assert.throws(()=>endorsements.revoke(token,secondId,revokeRequest),{code:'run_endorsement_permission'});
  db.exec('CREATE TEMP TRIGGER fail_revocation_outbox BEFORE INSERT ON run_approval_endorsement_revocation_outbox BEGIN SELECT RAISE(IGNORE); END');
  assert.throws(revoke,{code:'run_endorsement_storage'});
  db.exec('DROP TRIGGER fail_revocation_outbox');
  assert.equal(endorsements.get(token,secondId).state,'active');
  const revokeLookup={context_id:revokeRequest.context_id,idempotency_key:revokeRequest.idempotency_key};
  assert.deepEqual(endorsements.lookupRevocation(revoker,revokeLookup),{request_digest:null,result:null});
  const reversal=revoke(),revoked=endorsements.readForPeer(pair.binding_id,'tls',{endorsement_id:secondId,endorsement_digest:second.endorsement_ref.digest});
  assert.deepEqual(revoke(),reversal);
  assert.deepEqual(endorsements.getRevocation(revoker,reversal.operation_id),reversal);
  assert.deepEqual(endorsements.lookupRevocation(revoker,revokeLookup).result,reversal);
  assert.equal(revoked.state,'revoking');assert.equal(revoked.status_revision,'2');assert.equal(revoked.current_eligibility,'blocked');
  assert.equal(revoked.revocation_operation_ref.digest,digest(reversal));
  const queued=endorsements.prepareRevocationDelivery(reversal.operation_id);
  assert.deepEqual(queued.revocation_operation_ref,revoked.revocation_operation_ref);
  assert.deepEqual(queued.endorsement_ref,second.endorsement_ref);
  assert.deepEqual(queued.target_scope,seamer);
  assert.deepEqual(reversal.targets,[{target_scope:seamer,purpose:'notify_seamer',state:'pending',receipt_ref:null}]);
  assert.throws(()=>db.transaction(oldEligibility.assertCurrentInTransaction).immediate(),{code:'run_endorsement_approval_endorsement'});
  remoteApproval=reply(approval);proposalId=firstProposalId;setTarget([clause(equals(12),'/value',deviceAction)]);
  const withdrawn=store.replace(null,{...request,request_id:id(),expected_policy_ref:ref(policy),device_actions:[],parameter_constraints:[]});
  assert.equal(withdrawn.revision,'2');await assert.rejects(store.check(null,peerRequest),{code:'run_endorsement_action_denied'});
  await assert.rejects(qualify(),{code:'run_endorsement_action_denied'});
  assert.deepEqual(readPeer(),{...stored,current_eligibility:'blocked',eligible_before_ns:null});
  const operationRef={kind:'run_approval_operation',scope:seamer,object_id:id(),revision:'1',digest:digest('revoke')};
  const notice={kind:'run_approval_revocation',origin_scope:seamer,target_scope:scope,revocation_operation_ref:operationRef,
   approval_ref:remoteApproval.object_ref,endorsement_ref:receipt.endorsement_ref,preparations:[],grants:[],arm_generations:[]};
  const receive=(input=notice)=>endorsements.receiveProtection(pair.binding_id,'tls',input);
  await assert.rejects(receive(),{code:'run_endorsement_protection_original'});
  remoteApproval={...remoteApproval,state:'revoking',local_eligibility:'blocked',eligible_before_ns:null,revocation_operation_ref:operationRef};
  db.exec('CREATE TEMP TRIGGER fail_protection BEFORE INSERT ON run_approval_rejection BEGIN SELECT RAISE(IGNORE); END');
  await assert.rejects(receive(),{code:'run_endorsement_storage'});
  db.exec('DROP TRIGGER fail_protection');
  assert.equal(db.prepare('SELECT count(*) FROM run_approval_rejection').pluck().get(),0);
  const rejection=await receive();assert.equal(rejection.request_digest,digest(notice));
  remoteApproval=reply(approval);
  assert.deepEqual(await receive(),rejection);
  await assert.rejects(receive({...notice,revocation_operation_ref:{...operationRef,digest:digest('conflict')}}),{code:'run_endorsement_protection_conflict'});
  assert.throws(()=>db.transaction(priorQualification.assertCurrentInTransaction).immediate(),{code:'run_endorsement_approval_rejected'});
  assert.deepEqual(store.replace(null,request),policy);
  const earlier=now.upper;now.upper=end;
  const expired=endorsements.get(token,endorsementId);
  assert.equal(expired.state,'expired');assert.equal(expired.status_revision,'2');
  assert.deepEqual(readPeer(),{...expired,eligible_before_ns:null});
  now.upper=earlier;
  assert.deepEqual(endorsements.get(token,endorsementId),expired);
  assert.deepEqual(endorsements.lookup(token,lookup).result,receipt);
  assert.equal(db.prepare('SELECT count(*) FROM run_approval_endorsement_notice').pluck().get(),4);
  assert.equal(db.prepare('SELECT count(*) FROM run_approval_endorsement_revocation_outbox').pluck().get(),1);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
  const persisted=()=>['run_approval_endorsement_revocation','run_approval_endorsement_revocation_outbox','run_approval_endorsement_state']
   .map(table=>db.prepare('SELECT * FROM '+table).raw().all());
  const beforeAdoption=persisted(),migrationHistory=db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all();
  db.exec('CREATE TABLE run_approval_endorsement_revocation_receipt(conflict TEXT)');db.close();
  await assert.rejects(migrateStorage(fixture.dir,76),{code:'migration_failed'});
  db=openFixture();assert.equal(db.pragma('user_version',{simple:true}),75);assert.deepEqual(persisted(),beforeAdoption);
  assert.deepEqual(db.prepare('SELECT * FROM schema_migration ORDER BY CAST(to_revision AS INTEGER)').raw().all(),migrationHistory);
  db.exec('DROP TABLE run_approval_endorsement_revocation_receipt');db.close();
  assert.equal((await migrateStorage(fixture.dir,76)).schema_revision,'76');
  db=openFixture();assert.deepEqual(persisted(),beforeAdoption);
  const remoteReceipt={format:'leafseamer.run-endorsement-rejection/1',receipt_id:id(),target_scope:seamer,
   endorsement_ref:queued.endorsement_ref,proposal_ref:queued.proposal_ref,revocation_operation_ref:queued.revocation_operation_ref,
   request_digest:digest(queued),identity_state:'denied',protection_operation_ref:null};
  let attempts=0;
  const send=(bindingId,notice)=>{assert.equal(db.inTransaction,false);assert.equal(bindingId,pair.binding_id);assert.deepEqual(notice,queued);attempts++;};
  const firstSender=openEndorsements('76');
  firstSender.bindRevocationTransport(async(...args)=>{send(...args);throw Error('test response lost');});
  const pending={items:[reversal.operation_id],next:null};
  await assert.rejects(firstSender.deliverPendingRevocation(reversal.operation_id),/test response lost/);
  assert.deepEqual(firstSender.scanRevocations({after:null,limit:16}),pending);
  db.close();db=openFixture();
  const resumed=openEndorsements('76');resumed.bindRevocationTransport(async(...args)=>{send(...args);return remoteReceipt;});
  db.exec('CREATE TEMP TRIGGER fail_endorsement_receipt BEFORE INSERT ON run_approval_endorsement_revocation_receipt BEGIN SELECT RAISE(IGNORE); END');
  await assert.rejects(resumed.deliverPendingRevocation(reversal.operation_id),{code:'run_endorsement_storage'});
  assert.deepEqual(resumed.scanRevocations({after:null,limit:16}),pending);
  db.exec('DROP TRIGGER fail_endorsement_receipt');
  const worker=startOutboxDelivery({scan:resumed.scanRevocations,intervalMs:10,async deliver(id){return (await resumed.deliverPendingRevocation(id)).state;}});
  let status;
  try{
   for(let i=0;i<75;i++){
    status=worker.status();if(status.delivered)break;
    await new Promise(resolve=>setTimeout(resolve,10));
   }
   assert.equal(status.delivered,1,JSON.stringify(status));
  }finally{await worker.close();}
  assert.deepEqual(resumed.scanRevocations({after:null,limit:16}),{items:[],next:null});
  assert.deepEqual(await resumed.deliverPendingRevocation(reversal.operation_id),{state:'acknowledged',receipt:remoteReceipt});
  assert.equal(attempts,3);
  assert.deepEqual(resumed.getRevocation(revoker,reversal.operation_id),{...reversal,state:'applying',targets:[{...reversal.targets[0],receipt_ref:{
   kind:'run_endorsement_rejection_receipt',scope:seamer,object_id:remoteReceipt.receipt_id,revision:'1',digest:digest(remoteReceipt)}}]});
  assert.deepEqual(resumed.lookupRevocation(revoker,revokeLookup).result,reversal);
  assert.deepEqual(resumed.revoke(revoker,secondId,revokeRequest),reversal);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 }finally{if(db.open)db.close();}
 const reopened=fixture.reopen();
 assert.equal(reopened.identity.schema_revision,'76');assert.equal(reopened.identity.service_id,service.service_id);assert.equal(reopened.identity.database_instance_id,service.database_instance_id);
 assert.equal(reopened.identity.control_epoch,service.control_epoch);assert.equal(reopened.identity.request_epoch,service.request_epoch);
});
