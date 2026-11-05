import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import canonicalize from '../dist/runtime/canonicalize.mjs';
import {initializeStorage} from '../dist/storage.mjs';
import {initializeProcessHost,installedCoreDigest} from '../dist/process-host.mjs';

test('固定运行包无外部npm依赖即可bootstrap，持续锁定Node和运行文件并拒绝环境预加载及库存漂移',
 {skip:process.platform!=='win32',timeout:30000},async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-runtime-')),bundle=path.join(root,'bundle'),data=path.join(root,'data');
  fs.mkdirSync(data);fs.cpSync(fileURLToPath(new URL('../dist/',import.meta.url)),bundle,{recursive:true});
  const identity=initializeStorage(data);await initializeProcessHost(data);
  let child,ended;
  t.after(async()=>{if(child&&child.exitCode===null&&child.signalCode===null)child.kill();await ended;
    assert.equal(path.dirname(path.resolve(root)),path.resolve(os.tmpdir()));fs.rmSync(root,{recursive:true,force:true});});
  const policy={format:'leafseamer-core-bootstrap-policy/1',service_id:identity.service_id,database_instance_id:identity.database_instance_id,
    artifact_manifest_ref:{manifest_id:'synthetic-runtime',revision:'1',digest:installedCoreDigest()},
    platform_profile_ref:{profile_id:'synthetic-profile',revision:'1'},policy_revision:'1',bootstrap_timeout_ms:10000,clock_backend_revision:'1'};
  const entry=path.join(root,'core.mjs'),marker=path.join(root,'preloaded'),preload=path.join(root,'preload.mjs');
  fs.writeFileSync(preload,`import fs from 'node:fs';fs.writeFileSync(${JSON.stringify(marker)},'preloaded');`);
  const url=name=>JSON.stringify(pathToFileURL(path.join(bundle,name)).href);
  fs.writeFileSync(entry,`import {createCoreBootstrapChannel} from ${url('core-bootstrap.mjs')};
import {connectCoreSupervisor} from ${url('supervisor-control.mjs')};
import {bootstrapDeviceWorker} from ${url('worker-bootstrap.mjs')};
const options=Object.fromEntries(Array.from({length:(process.argv.length-3)/2},(_,i)=>[process.argv[3+i*2],process.argv[4+i*2]]));
const channel=createCoreBootstrapChannel(process.stdin,process.stdout,{timeoutMs:10000});
const assignment=await channel.assignment(),receipt=await channel.proveAndReceive(assignment);channel.release();
const source=await connectCoreSupervisor({pipe:options['--supervisor-pipe'],channelId:options['--supervisor-channel'],
  policy:JSON.parse(options['--bootstrap-policy']),binding:{descriptor:assignment.clock_domain_descriptor,receipt}});
process.stderr.write(JSON.stringify({event:'ready',executable:process.execPath,node_options:process.env.NODE_OPTIONS??null,worker:typeof bootstrapDeviceWorker})+'\\n');
process.stdin.setEncoding('utf8').on('data',value=>{if(value==='stop\\n'){source.close();process.stdin.destroy();}});process.stdin.resume();
`);
  const launch=()=>{
    let output='',error='';
    child=spawn(path.join(bundle,'native/leafseamer_process_host.exe'),[data,path.join(root,'unselected.exe'),entry,'contained-core-auth','--bootstrap-policy',canonicalize(policy)],
      {stdio:['pipe','pipe','pipe'],windowsHide:true,env:{...process.env,NODE_OPTIONS:'--import='+pathToFileURL(preload).href,NODE_PATH:root}});
    ended=once(child,'close');child.stdin.on('error',()=>{});child.stdout.on('data',part=>{output+=part;});child.stderr.on('data',part=>{error+=part;});
    return {output:()=>output,error:()=>error};
  };
  let run=launch();const until=performance.now()+10000;
  while(!run.error().includes('"event":"ready"')){assert.equal(child.exitCode,null,run.output()+run.error());assert.ok(performance.now()<until,run.output()+run.error());await delay(20);}
  const ready=JSON.parse(run.error().trim());assert.equal(ready.worker,'function');assert.equal(ready.node_options,null);assert.equal(fs.existsSync(marker),false);
  assert.equal(fs.realpathSync(ready.executable),fs.realpathSync(path.join(bundle,'runtime/node.exe')));
  const protectedFiles=['build-manifest.json','runtime/node.exe','runtime/canonicalize.mjs','native/leafseamer_clock.node','worker-bootstrap.mjs'];
  for(const name of protectedFiles){const file=path.join(bundle,name);assert.throws(()=>{const fd=fs.openSync(file,'r+');fs.closeSync(fd);});assert.throws(()=>fs.renameSync(file,file+'.moved'));}
  child.stdin.end('stop\n');assert.equal((await ended)[0],0,run.output()+run.error());
  for(const name of protectedFiles){const fd=fs.openSync(path.join(bundle,name),'r+');fs.closeSync(fd);}
  const extra=path.join(bundle,'runtime/unlisted.mjs');fs.writeFileSync(extra,'export {};');
  run=launch();assert.notEqual((await ended)[0],0);assert.match(run.output(),/content_inventory_mismatch/);assert.doesNotMatch(run.error(),/"event":"ready"/);fs.unlinkSync(extra);
  const target=path.join(bundle,'runtime/canonicalize.mjs'),original=fs.readFileSync(target);fs.writeFileSync(target,Buffer.concat([original,Buffer.from('\n')]));
  run=launch();assert.notEqual((await ended)[0],0);assert.match(run.output(),/content_digest_mismatch/);assert.doesNotMatch(run.error(),/"event":"ready"/);
 });
