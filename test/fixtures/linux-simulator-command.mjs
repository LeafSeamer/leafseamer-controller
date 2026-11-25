import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {contractSelection} from '../../dist/sdk/index.mjs';

const id=()=>crypto.randomUUID();
const ref=value=>({id:value.id,revision:value.revision,digest:value.digest});
export const commandPermissions=['control.read','control.acquire','device.command','device.recover','command.read','request.create'];

async function changeControl(sessions,token,context,device,operation,reason){
  const control=sessions.getControl(token,device);
  const accepted=await sessions.changeControl(token,operation,{device_id:device},{context_id:context.context_id,idempotency_key:id(),
    expected_control:{epoch:control.control_epoch,version:control.effective_version},reason});
  const deadline=performance.now()+4000;
  for(;;){
    const current=sessions.getControlOperation(token,accepted.receipt.initial_result_ref.id);
    if(current.state==='effective')return sessions.getControl(token,device);
    assert.ok(current.state==='pending'&&performance.now()<deadline,JSON.stringify({state:current.state,reason:current.failure_code}));
    await delay(20);
  }
}

export async function prepareAutomaticSimulator({store,operator,device}){
  const {sessions,real}=operator,audience=store.identity.service_id;
  real.refresh();
  const token=operator.token(['control.read','control.acquire','control.release','request.create']);
  const context=sessions.createRequestContext(token,{audience,operations:['acquireControl','releaseControl'],selection:contractSelection,
    ttl_ms:30000,max_unique_requests:2});
  await changeControl(sessions,token,context,device,'acquireControl','登记模拟器动作目标的控制原件');
  const control=await changeControl(sessions,token,context,device,'releaseControl','切换模拟器动作目标到自动控制');
  assert.equal(control.mode,'automatic');
  assert.equal(control.gate_state,'protected');
}

export async function prepareManualSimulator({store,operator,device,device_ids=[device]}){
  const {sessions,auth,real}=operator,service=store.identity.service_id;
  real.refresh();
  const token=operator.token(commandPermissions);
  const context=sessions.createRequestContext(token,{audience:service,operations:['acquireControl','submitCommand'],
    selection:contractSelection,ttl_ms:60000,max_unique_requests:4});
  await changeControl(sessions,token,context,device,'acquireControl','模拟器人员控制');
  const now=real.current(),principal=sessions.createServicePrincipal(auth,{request_id:id(),display_name:'模拟器评估器',purpose:'controller_evaluator'});
  const approval=sessions.approveServicePrincipal(auth,{request_id:id(),principal_id:principal.id,expected_revision:principal.revision,
    audiences:[service],permissions:['identity.read'],device_ids,not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
  const staged=sessions.createServiceCredential(auth,{request_id:id(),principal_id:principal.id,expected_revision:approval.principal.revision,
    approval_ref:ref(approval.approval),expires_ns:String(BigInt(now.upper_ns)+1800000000000n)});
  const proof=sessions.proveServiceCredential({credential_id:staged.credential.id,secret:staged.secret,proof_request_id:id()});
  const proven=sessions.getServiceCredential(auth,staged.credential.id);
  const active=sessions.activateServiceCredential(auth,{request_id:id(),credential_id:proven.id,expected_revision:proven.revision,
    approval_ref:ref(approval.approval),proof_ref:ref(proof)});
  sessions.approveLocalServicePolicy(auth,{request_id:id(),principal_id:principal.id,subject_ref:ref(approval.principal),
    approval_ref:ref(approval.approval),audience:service,permissions:['identity.read'],device_ids,
    not_before_ns:now.lower_ns,expires_ns:approval.approval.expires_ns});
  const policy=sessions.approveDeviceEvaluatorPolicy(auth,{request_id:id(),principal_id:principal.id,subject_ref:ref(approval.principal),
    approval_ref:ref(approval.approval),device_ids,expires_ns:approval.approval.expires_ns});
  return {token,context,policy,credential_id:active.id,secret:staged.secret};
}

async function openSimulatorGate({store,operator,supervision,key,device,manual,successor=false,automatic=false,waitForClockRenewal}){
  const {sessions,real}=operator,{policy,credential_id,secret}=manual;
  const token=automatic?operator.token(['device.recover','device.command']):manual.token;
  const input=()=> {
    let manualSource=null;
    if(!automatic){
      const human=sessions.beginManualExecutionChallenge(token,device,id());
      manualSource=sessions.completeManualExecutionChallenge(token,{request_id:id(),challenge_ref:ref(human),nonce:human.nonce});
    }
    const evaluator=sessions.beginDeviceEvaluatorChallenge({request_id:id(),policy_ref:ref(policy),device_id:device});
    const evaluatorSource=sessions.completeDeviceEvaluatorChallenge({request_id:id(),challenge_ref:ref(evaluator),nonce:evaluator.nonce,credential_id,secret});
    return {device_id:device,manual_source_ref:manualSource?.ref??null,evaluator_source_ref:evaluatorSource.ref};
  };
  const refresh=async(renewClock=false)=>{
    await store.workerLaunches.runtime.refreshCurrent(key);
    if(renewClock)await waitForClockRenewal();
    await supervision.refreshCoreObservation();
    real.refresh();
  };
  await refresh();
  if(successor)await store.workerLaunches.captureDeviceBaseline(key,device);
  else await store.workerLaunches.initialDeviceFence(key,device);
  const original=input(),current=automatic?sessions.currentAutomaticAuthorizationContext(original):sessions.currentManualAuthorizationContext(original);
  const recovery=sessions.requestDeviceAuthorizationRecovery(token,{...original,request_id:id(),
    expected_state_ref:current.state_ref,expected_context_digest:current.context_digest});
  const state=sessions.consumeDeviceAuthorizationRecovery(token,recovery.receipt.id);
  const evidence=sessions.selectDeviceAuthorizationEvidence({...original,request_id:id(),expected_state_ref:state.ref,expected_evidence_ref:null});
  await refresh(automatic);
  const renewed=sessions.selectDeviceAuthorizationEvidence({...input(),request_id:id(),expected_state_ref:state.ref,expected_evidence_ref:evidence.ref});
  const resources=sessions.selectInitialDeviceResources({request_id:id(),device_id:device,expected_evidence_ref:renewed.ref});
  const opening=sessions.prepareInitialDeviceOpen({request_id:id(),device_id:device,expected_resource_ref:resources.ref});
  await store.workerLaunches.openInitialDevice(key,opening.ref);
}

export function openAutomaticSimulator(input){
  return openSimulatorGate({...input,automatic:true});
}

export async function writeManualSimulator({store,operator,supervision,key,device,manual,value,successor=false}){
  await openSimulatorGate({store,operator,supervision,key,device,manual,successor});
  const {sessions,real}=operator,{token,context}=manual;
  const control=sessions.getControl(token,device);
  const {adjudication}=await sessions.submitCommand(token,{device_id:device,action_id:'leafseamer.simulator.value.set',capability_version:'1.0.0',
    parameters:{value},context_id:context.context_id,idempotency_key:id(),expected_control:{epoch:control.control_epoch,version:control.effective_version},
    origin:'manual',automation_binding:null,required_completion:'sent',preconditions:[],dispatch:{mode:'immediate',max_queue_ms:3000},evidence_timeout_ms:1000},
  {withStatus:true});
  const commandId=adjudication.command_ref.object_id;
  await store.workerLaunches.whenCommandCleaned(commandId);
  real.refresh();
  const {record}=sessions.getCommand(token,commandId);
  assert.equal(record.state.outcome,'succeeded');
  return adjudication.command_ref;
}
