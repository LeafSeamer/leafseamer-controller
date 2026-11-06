import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {bootstrapDeviceWorker} from './worker-bootstrap.mjs';
import {hostDeviceModule} from './device-module-host.mjs';
import {executionSessionIdentity} from './device-execution-channel.mjs';

// 固定子进程入口；上下文只由原生父进程写入并持续保护，不接受模块路径或任意argv。
try {
  const args=process.argv.slice(2);
  if(args.length!==4||args[0]!=='--context-file'||args[2]!=='--context-digest'||!path.isAbsolute(args[1])||
    !/^sha256:[0-9a-f]{64}(?![\s\S])/.test(args[3]))throw new Error('worker_context');
  const bytes=fs.readFileSync(args[1]);
  if(bytes.length>16777216||'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')!==args[3])throw new Error('worker_context');
  const value=JSON.parse(bytes.toString('utf8'));
  if(canonicalize(value)!==bytes.toString('utf8')||Object.keys(value).sort().join(',')!=='descriptor,execution,format,identity,intent,module,timeout_ms'||
    value.format!=='leafseamer-device-worker-start/3'||!value.execution||Object.keys(value.execution).join(',')!=='controller_boot_id'||
    !/^[0-9a-f]{32}$(?![\s\S])/.test(value.execution.controller_boot_id))throw new Error('worker_context');
  const admitted=await bootstrapDeviceWorker({input:process.stdin,output:process.stdout,intentBytes:Buffer.from(canonicalize(value.intent)),
    identity:value.identity,descriptor:value.descriptor,timeoutMs:value.timeout_ms});
  // 准入后只建立定向通路；核心采用RuntimeBinding并显式LOAD之前不导入扩展。
  const executionIdentity=executionSessionIdentity({authority_service_id:value.identity.service_id,database_instance_id:value.identity.database_instance_id,
    controller_boot_id:value.execution.controller_boot_id,worker_boot_id:admitted.receipt.member_boot_id,
    clock_domain_id:admitted.descriptor.clock_domain_id,descriptor_digest:admitted.descriptor.descriptor_digest});
  const host=hostDeviceModule({admitted,materials:value.module,executionIdentity,failed:()=>process.exit(1)});
  let input='';process.stdin.setEncoding('utf8');
  process.stdin.on('data',part=>{input+=part;if(input==='stop\n'){host.close();return;}
    if(input.length>=5||!'stop\n'.startsWith(input))host.close();});
  process.stdin.on('error',()=>host.close());process.stdin.on('end',()=>host.close());process.stdin.resume();
}catch(error){
  const code=typeof error.code==='string'&&/^[a-z_0-9]{1,96}$/.test(error.code)?error.code:'worker_start_failed';
  process.stderr.write(JSON.stringify({event:'worker_bootstrap_failure',code})+'\n');process.exitCode=1;process.stdin.destroy();
}
