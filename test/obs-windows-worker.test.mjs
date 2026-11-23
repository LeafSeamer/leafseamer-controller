import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import {once} from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {WebSocketServer} from 'ws';
import {digest} from '../dist/auth-clock-value.mjs';
import {connectDeviceModule} from '../dist/device-module-client.mjs';
import {executionSessionIdentity} from '../dist/device-execution-channel.mjs';
import {obsModuleDefinition} from '../dist/obs-module-profile.mjs';
import {initializeWindowsSecretStore, openWindowsSecretStore} from '../dist/secret-store.mjs';
import {windowsSecretDirectory} from '../dist/windows-secret-files.mjs';

const availableRequests = JSON.parse(fs.readFileSync(new URL('./fixtures/obs-cut-requests.json', import.meta.url)));
const program = 'ebc75716-e090-42b1-b9e5-ee8a1dd15879';
const alternate = 'c3a343d6-9f64-4862-a151-baf6201a5ae6';
const hash = value => createHash('sha256').update(value).digest('base64');
const close = server => new Promise(resolve => server.close(resolve));

test('Windows Worker 从 DPAPI 存储读取 OBS 密码，经两端命名管道完成只读采样并随 OBS 断线失效',
  {skip:process.platform!=='win32',timeout:30000},async t=>{
    const temp=path.resolve(os.tmpdir()),root=fs.mkdtempSync(path.join(temp,'leafseamer-obs-worker-'));
    assert.equal(path.dirname(path.resolve(root)),temp);
    t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
    const dataDir=path.join(root,'data'),obsSecretsDirectory=windowsSecretDirectory(dataDir);
    fs.mkdirSync(obsSecretsDirectory);
    const service='fixture-controller',database='fixture-database',memberBoot=randomBytes(16).toString('hex');
    const password=randomBytes(24).toString('base64url');
    const secret_ref={owner_service_id:service,secret_id:'resource',version:'1',purpose:'obs_websocket'};
    initializeWindowsSecretStore({owner:service,directory:obsSecretsDirectory});
    const writer=openWindowsSecretStore({owner:service,directory:obsSecretsDirectory});
    const passwordBytes=Buffer.from(password);
    try {writer.write(secret_ref,passwordBytes);writer.write(secret_ref,passwordBytes);}
    finally {passwordBytes.fill(0);writer.close();}
    assert.throws(()=>openWindowsSecretStore({owner:'other-service',directory:obsSecretsDirectory}),{code:'secret_store_dpapi'});

    const ws=new WebSocketServer({host:'127.0.0.1',port:0});
    await once(ws,'listening');
    const requests=[],scenes=[{sceneUuid:program,sceneName:'A'},{sceneUuid:alternate,sceneName:'B'}];
    const responses={
      GetVersion:{obsVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,availableRequests},
      GetSceneCollectionList:{currentSceneCollectionName:'Isolated',sceneCollections:['Isolated']},
      GetSceneList:{scenes,currentProgramSceneUuid:program,currentProgramSceneName:'A'},
      GetCurrentProgramScene:{sceneUuid:program,sceneName:'A'},
      GetStudioModeEnabled:{studioModeEnabled:false},
      GetCurrentSceneTransition:{transitionKind:'cut_transition',transitionUuid:program,transitionFixed:true,
        transitionConfigurable:false,transitionDuration:null,transitionSettings:null},
      GetStreamStatus:{outputActive:false,outputReconnecting:false},
      GetSceneSceneTransitionOverride:{transitionName:null,transitionDuration:null},
      GetSceneItemList:{sceneItems:[]}
    };
    let identified=false;
    ws.on('connection',socket=>{
      const salt=randomBytes(32).toString('base64'),challenge=randomBytes(32).toString('base64');
      const emit=(op,d)=>socket.send(JSON.stringify({op,d}));
      emit(0,{obsStudioVersion:'32.0.4',obsWebSocketVersion:'5.6.3',rpcVersion:1,authentication:{salt,challenge}});
      socket.on('message',bytes=>{
        const {op,d}=JSON.parse(bytes);
        if(op===1){
          assert.equal(d.authentication,hash(hash(password+salt)+challenge));
          identified=true;emit(2,{negotiatedRpcVersion:1});return;
        }
        assert.equal(op,6);assert.equal(identified,true);assert.ok(Object.hasOwn(responses,d.requestType),d.requestType);
        requests.push(d.requestType);
        emit(7,{requestType:d.requestType,requestId:d.requestId,requestStatus:{result:true,code:100},responseData:responses[d.requestType]});
      });
    });
    const pipes=[],connections=[];
    const ready=async side=>{
      const server=net.createServer(socket=>{
        connections.push(socket);
        if(connections.length===2){
          const [left,right]=connections;
          left.pipe(right);right.pipe(left);
          left.on('close',()=>right.destroy());right.on('close',()=>left.destroy());
        }
      });
      pipes.push(server);
      server.listen('\\\\.\\pipe\\LeafSeamer.Module.'+memberBoot+'.'+side);
      await once(server,'listening');
    };
    t.after(async()=>{for(const socket of ws.clients)socket.terminate();for(const socket of connections)socket.destroy();await Promise.all([close(ws),...pipes.map(close)]);});
    await Promise.all(['worker','core'].map(ready));

    const {module,policy}=obsModuleDefinition,scope={authority_service_id:service,database_instance_id:database};
    const entry={entry_id:'obs',kind:'worker',loader:'node_module',file_id:'module',io_policy_file_id:'policy'};
    const manifest={entrypoints:[entry],api_versions:['leafseamer-device-module/2'],ipc_versions:['device-module/3']};
    const inventory={files:[['module','module','obs-device-module.mjs',module],['policy','policy','obs-module-policy.json',policy]].map(([file_id,role,name,digest])=>{
      const bytes=fs.readFileSync(new URL('../dist/'+name,import.meta.url));
      fs.writeFileSync(path.join(root,name),bytes);
      return {file_id,role,path:name,size_bytes:String(bytes.length),digest};
    })};
    const ref=(kind,object_id,value)=>({kind,...scope,object_id,revision:'1',digest:digest(value)});
    const resource_record={format:'leafseamer-obs-local-resource/1',profile:'obs_isolated_empty_cut/1',resource_id:'resource',
      device_ref:ref('device','obs','descriptor'),endpoint:{address:'127.0.0.1',port:ws.address().port},
      obs_version:'32.0.4',websocket_version:'5.6.3',rpc_version:1,available_requests_digest:digest(availableRequests),
      collection_name:'Isolated',scene_uuids:[program,alternate].sort()};
    const value={resource_ref:ref('resource','resource',resource_record),resource_record,secret_ref};
    const configuration={reference:ref('configuration','config',{resource_ref:value.resource_ref,secret_ref}),value};
    const intent={object_scope:{kind:'devices',device_ids:['obs']},extension_binding:{entry_id:entry.entry_id,manifest_digest:digest(manifest),
      artifact_set_digest:digest(inventory),configuration_ref:configuration.reference}};
    const descriptor={clock_domain_id:'clock_'+'a'.repeat(64),descriptor_digest:digest('clock')},receipt={member_boot_id:memberBoot};
    const runtime={format:'leafseamer-worker-runtime-binding/1',runtime_binding_id:'runtime',service_id:service,database_instance_id:database,
      service_boot_id:'boot',launch_intent:intent,clock_domain_descriptor:descriptor,admission_receipt:receipt,gate_state:'closed'};
    const executionIdentity=executionSessionIdentity({...scope,controller_boot_id:'boot',worker_boot_id:memberBoot,...descriptor});
    const moduleUrl=new URL('../dist/device-module-host.mjs',import.meta.url).href;
    const child=spawn(process.execPath,['--disallow-code-generation-from-strings','--input-type=module','-e',
      `import {hostDeviceModule} from ${JSON.stringify(moduleUrl)};
        let input='';for await(const chunk of process.stdin)input+=chunk;
        hostDeviceModule({...JSON.parse(input),failed:()=>process.exit(1)});`],{stdio:['pipe','ignore','pipe'],windowsHide:true});
    const exit=once(child,'exit');
    let stderr='';child.stderr.setEncoding('utf8').on('data',chunk=>stderr+=chunk);
    t.after(()=>{if(child.exitCode===null)child.kill();});
    child.stdin.end(JSON.stringify({admitted:{intent,receipt,descriptor},materials:{root_path:root,manifest,inventory},executionIdentity,obsSecretsDirectory}));
    const record=[];
    let retired=false;
    const client=await connectDeviceModule({current:()=>({current_boot:!retired,ref:ref('runtime_binding','runtime',runtime),binding:runtime}),
      invalidate:()=>{retired=true;},configuration,journal:{open(){},record(direction,frame){record.push({direction,frame});}},catalog:null});
    t.after(()=>client.close());
    const connected=await client.connectReadOnly('obs');
    assert.deepEqual(connected.body.identity,obsModuleDefinition.identity);
    assert.deepEqual(connected.body.catalog.action_ids,[]);
    const sample=await client.captureBaseline('obs');
    assert.deepEqual(sample.body.value,{sample_sequence:'1',program_scene_uuid:program,
      scenes:[{obs_scene_uuid:alternate,display_name:'B'},{obs_scene_uuid:program,display_name:'A'}]});
    assert.ok(requests.includes('GetCurrentProgramScene'));
    assert.ok(!JSON.stringify(record).includes(password));
    for(const socket of ws.clients)socket.terminate();
    const [status] = await exit;
    assert.equal(status,1,stderr);
    await assert.rejects(client.captureBaseline('obs'),{code:'module_closed'});
    assert.equal(retired,true);
  });
