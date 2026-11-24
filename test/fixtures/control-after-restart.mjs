import fs from 'node:fs';
import crypto from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {openStorage} from '../../dist/storage.mjs';
import {createCoreBootstrapChannel,verifyCoreAdmission} from '../../dist/core-bootstrap.mjs';
import {connectCoreSupervisor} from '../../dist/supervisor-control.mjs';
import {openNativeClock} from '../../dist/native-clock.mjs';
import {contractSelection} from '../../dist/sdk/index.mjs';
import {authenticated} from './extension-auth.mjs';

const args=process.argv.slice(3),options=Object.fromEntries(Array.from({length:args.length/2},(_,i)=>[args[i*2],args[i*2+1]]));
const input=JSON.parse(fs.readFileSync(options['--fixture'],'utf8')),policy=JSON.parse(options['--bootstrap-policy']);
const boot=createCoreBootstrapChannel(process.stdin,process.stdout,{timeoutMs:10000});
const assignment=await boot.assignment(),receipt=await boot.proveAndReceive(assignment);boot.release();
const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],policy,
 binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
const store=openStorage(options['--data-dir']);
const report=entry=>process.stderr.write(JSON.stringify(entry)+'\n');
let manager;
try{
 store.bindCoreRuntime(await verifyCoreAdmission(assignment,receipt,policy),policy);
 store.workerLaunches.runtime.bindSource(source);
 store.workerLaunches.authorization.bindSource(source);
 manager=await authenticated({after(){}},{store},{native:{source:openNativeClock(),descriptor:assignment.clock_domain_descriptor},
  sampleWindowPolicy:'authentication-clock-sample/2'});
 const scopes=['control.read','control.release','control.acquire','command.read','request.create'],token=manager.token(scopes);
 const denied=async action=>{try{await action();return 'unexpected_success';}catch(error){return error.code;}};
 const oldLaunch=await denied(()=>store.workerLaunches.authorization.authorize(input.old_launch));
 const get=()=>manager.sessions.getControl(token,input.device_id);
 const previous=get(),oldContext=await denied(()=>manager.sessions.changeControl(token,'releaseControl',{device_id:input.device_id},{
  context_id:input.old_context,idempotency_key:crypto.randomUUID(),
  expected_control:{epoch:previous.control_epoch,version:previous.effective_version},reason:'校验旧请求上下文'}));
 const context=manager.sessions.createRequestContext(token,{audience:store.identity.service_id,operations:['releaseControl','acquireControl'],
  selection:contractSelection,ttl_ms:30000,max_unique_requests:2});
 async function change(method){
  const record=get(),response=await manager.sessions.changeControl(token,method,{device_id:input.device_id},{
   context_id:context.context_id,idempotency_key:crypto.randomUUID(),expected_control:{epoch:record.control_epoch,version:record.effective_version},
   reason:'重启后核验受监督设备退出'});
  const until=performance.now()+8000;
  for(;;){
   const operation=manager.sessions.getControlOperation(token,response.receipt.initial_result_ref.id);
   if(operation.state!=='pending')return operation;
   if(performance.now()>=until)throw new Error('restart_control_timeout');
   await delay(20);
  }
 }
 const released=await change('releaseControl');
 const acquired=released.state==='effective'?await change('acquireControl'):null;
 const historical=manager.sessions.getCommand(token,input.command_id).record;
 report({event:'obs-boot-control',boot:store.serviceBootId,domain:receipt.domain_ref,old_context:oldContext,old_launch:oldLaunch,
  released,acquired,control:get(),historical});
}catch(error){report({event:'obs-boot-control-failed',code:error.code??error.name,message:error.message});process.exitCode=1;}
await new Promise(resolve=>{
 process.stdin.setEncoding('utf8').on('data',chunk=>{if(chunk==='stop\n')resolve();});
 process.stdin.once('end',resolve);process.stdin.resume();
});
manager?.real.stop();store.close();source.close();process.stdin.destroy();
