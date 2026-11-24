import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {Socket} from 'node:net';
import canonicalize from './runtime/canonicalize.mjs';
import {bootstrapDeviceWorker} from './worker-bootstrap.mjs';
import {hostDeviceModule} from './device-module-host.mjs';
import {executionSessionIdentity} from './device-execution-channel.mjs';
import {windowsSecretDirectory} from './windows-secret-files.mjs';

// 固定子进程入口；上下文只由原生父进程写入并持续保护，不接受模块路径或任意argv。
const linux = process.platform === 'linux';
const inherited = [];
try {
  const args=process.argv.slice(2);
  if(args.length!==4||args[0]!=='--context-file'||args[2]!=='--context-digest'||!path.isAbsolute(args[1])||
    !/^sha256:[0-9a-f]{64}(?![\s\S])/.test(args[3]))throw new Error('worker_context');
  const bytes=fs.readFileSync(args[1]);
  if(bytes.length>16777216||'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')!==args[3])throw new Error('worker_context');
  const value=JSON.parse(bytes.toString('utf8'));
  if(canonicalize(value)!==bytes.toString('utf8')||Object.keys(value).sort().join(',')!=='descriptor,execution,format,identity,intent,module,timeout_ms'||
    value.format!=='leafseamer-device-worker-start/3'||!value.execution||Object.keys(value.execution).join(',')!=='controller_boot_id'||
    !(linux?/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/:
      /^[0-9a-f]{32}$(?![\s\S])/).test(value.execution.controller_boot_id))throw new Error('worker_context');
  if(linux){
    const descriptors=[3,4,5],status=descriptors.map(fd=>fs.fstatSync(fd,{bigint:true}));
    if(!status.every(info=>info.isSocket())||new Set(status.map(info=>String(info.dev)+':'+info.ino)).size!==status.length)
      throw Object.assign(new Error('worker_channel'),{code:'worker_channel'});
    for(const fd of descriptors)inherited.push(new Socket({fd,readable:true,writable:true}));
  }
  const [bootstrap,moduleSocket,executionSocket]=inherited;
  // Linux模块与执行通道在bootstrap前已经定向交付。任何端点丢失都关闭整个worker。
  for(const socket of inherited)socket.once('error',()=>process.exit(1)).once('close',()=>process.exit(1));
  const input=bootstrap??process.stdin,output=bootstrap??process.stdout;
  const admitted=await bootstrapDeviceWorker({input,output,intentBytes:Buffer.from(canonicalize(value.intent)),
    identity:value.identity,descriptor:value.descriptor,timeoutMs:value.timeout_ms});
  // 准入后只建立定向通路；核心采用RuntimeBinding并显式LOAD之前不导入扩展。
  const executionIdentity=executionSessionIdentity({authority_service_id:value.identity.service_id,database_instance_id:value.identity.database_instance_id,
    controller_boot_id:value.execution.controller_boot_id,worker_boot_id:admitted.receipt.member_boot_id,
    clock_domain_id:admitted.descriptor.clock_domain_id,descriptor_digest:admitted.descriptor.descriptor_digest});
  const obsSecretsDirectory=process.platform==='win32'?windowsSecretDirectory(path.dirname(args[1])):undefined;
  const host=hostDeviceModule({admitted,materials:value.module,executionIdentity,obsSecretsDirectory,
    sockets:linux?{module:moduleSocket,execution:executionSocket}:undefined,failed:()=>process.exit(1)});
  let pending='';input.setEncoding('utf8');
  input.on('data',part=>{pending+=part;if(pending==='stop\n'){host.close();return;}
    if(pending.length>=5||!'stop\n'.startsWith(pending))host.close();});
  input.on('error',()=>host.close());input.on('end',()=>host.close());input.resume();
}catch(error){
  const code=typeof error.code==='string'&&/^[a-z_0-9]{1,96}$/.test(error.code)?error.code:'worker_start_failed';
  process.stderr.write(JSON.stringify({event:'worker_bootstrap_failure',code})+'\n');process.exitCode=1;
  for(const socket of inherited)socket.destroy();
  process.stdin.destroy();
}
