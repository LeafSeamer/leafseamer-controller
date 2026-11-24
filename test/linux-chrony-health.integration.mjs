import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import test from 'node:test';
import {observeLinuxChronyHealth} from '../dist/linux-chrony-health.mjs';
import {openNativeClock} from '../dist/native-clock.mjs';
import {canonical,digest,ref,seal} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const file=name=>fileURLToPath(new URL(name,import.meta.url));
const hash=filename=>'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');

test('独立 Chrony 实际追踪已批准源，-x、配置改变与源失联拒绝签发',{
  skip:process.platform!=='linux'||process.env.LEAFSEAMER_TEST_CHRONY_HOST!=='1',timeout:35000
},async t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'leafseamer-chrony-')),children=[];
  async function stop({child,exit}){
    if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');
    const timer=setTimeout(()=>child.kill('SIGKILL'),2000);
    try{return await exit;}finally{clearTimeout(timer);}
  }
  t.after(async()=>{
    await Promise.all(children.map(stop));
    assert.equal(path.dirname(root),os.tmpdir());fs.rmSync(root,{recursive:true,force:true});
  });
  const chronyc=fs.realpathSync('/usr/bin/chronyc'),chronyd=fs.realpathSync('/usr/sbin/chronyd');
  const reservation=dgram.createSocket('udp4');
  reservation.bind(0,'127.0.0.2');
  await once(reservation,'listening');
  const port=reservation.address().port;
  await new Promise(resolve=>reservation.close(resolve));
  function start(role,directives){
    const conf=path.join(root,role+'.conf'),pid=path.join(root,role+'.pid'),socket=path.join(root,role+'.sock');
    fs.writeFileSync(conf,["user root",'cmdport 0','pidfile '+pid,'bindcmdaddress '+socket,...directives].join('\n')+'\n',{mode:0o600});
    const child=spawn(chronyd,['-d','-x','-f',conf],{stdio:['ignore','ignore','pipe']});
    const exit=once(child,'close');
    let errors='';child.stderr.setEncoding('utf8').on('data',bytes=>{errors+=bytes;});
    const service={child,exit,conf,pid,socket,errors:()=>errors};children.push(service);return service;
  }
  const server=start('server',['bindaddress 127.0.0.2','port '+port,'allow 127.0.0.0/8','local stratum 8']);
  const client=start('client',['port 0','server 127.0.0.2 port '+port+' iburst minpoll 0 maxpoll 0']);
  const profile={format:'leafseamer.linux-chrony-health/1',chronyc_file:chronyc,chronyc_sha256:hash(chronyc),chronyd_sha256:hash(chronyd),
    configuration_file:client.conf,configuration_sha256:hash(client.conf),pid_file:client.pid,socket_file:client.socket,
    source_addresses:['127.0.0.2'],max_source_age_s:4};
  const deadline=performance.now()+17000;
  let report;
  for(;;){
    try{report=observeLinuxChronyHealth(profile);break;}
    catch(error){
      if(client.child.exitCode!==null||server.child.exitCode!==null||performance.now()>=deadline){
        throw new Error(client.errors()+server.errors(),{cause:error});
      }
      await delay(200);
    }
  }
  assert.equal(report.state,'tracking_only');assert.equal(report.source,'127.0.0.2');
  assert.equal(report.identity.pid,String(client.child.pid));
  assert.ok(report.reportedErrorNs>=0n);
  const pidMode=fs.statSync(client.pid).mode&0o777;
  fs.chmodSync(client.pid,0o666);
  assert.throws(()=>observeLinuxChronyHealth(profile),{code:'clock_evidence_chrony_file'});
  fs.chmodSync(client.pid,pidMode);

  const clock=openNativeClock(),scope={service_id:crypto.randomUUID(),service_boot_id:crypto.randomUUID()};
  const base=fixture(scope,{source:clock},{sampleWindowPolicy:'authentication-clock-sample/2'}).evidence;
  function reseal(value,overrides){const {digest:_original,...body}=value;return seal({...body,...overrides});}
  const policy=reseal(base.policy,{health_profile_ref:{...base.policy.health_profile_ref,digest:digest(profile)}});
  const runtime=reseal(base.runtime,{policy_ref:ref(policy)});
  const key=crypto.generateKeyPairSync('ed25519').privateKey.export({format:'pem',type:'pkcs8'});
  const keyFile=path.join(root,'test-key.pem'),evidenceFile=path.join(root,'evidence.json'),profileFile=path.join(root,'signer.json');
  const statementFile=path.join(root,'statement.json'),database_instance_id=crypto.randomUUID();
  fs.writeFileSync(keyFile,key,{mode:0o600});
  const signing={format:'leafseamer.authentication-clock-signing-profile/2',service_id:scope.service_id,database_instance_id,
    policy_digest:policy.digest,native_binary_digest:clock.artifactDigest,private_key_file:keyFile,evidence_file:evidenceFile,chrony:profile};
  function rejectSigner(codes,override={},lifetime=2000000000n){
    const health=reseal(base.health,{policy_ref:ref(policy),runtime_ref:ref(runtime),health_profile_ref:policy.health_profile_ref,
      valid_before_tick_ns:String(clock.tick()+lifetime)});
    const challenge={event:'authentication_clock_challenge',...scope,database_instance_id,native_binary_digest:clock.artifactDigest,
      continuity:runtime.continuity,tick_ns:String(clock.tick()),clock_domain_id:runtime.clock_domain_id,descriptor_digest:runtime.descriptor_digest};
    fs.writeFileSync(profileFile,canonical({...signing,...override}));
    fs.writeFileSync(statementFile,canonical({challenge,evidence:{policy,runtime,health}}));
    const result=spawnSync(process.execPath,['--disallow-code-generation-from-strings',file('../dist/clock-evidence.mjs'),
      '--profile',profileFile,'--statement',statementFile],{encoding:'utf8',timeout:4000});
    assert.equal(result.status,1,result.stderr);
    const message=JSON.parse(result.stderr);
    assert.deepEqual(Object.keys(message),['error']);
    assert.ok([codes].flat().includes(message.error),result.stderr);
    assert.equal(fs.existsSync(evidenceFile),false);
  }
  rejectSigner('clock_evidence_chrony_tracking_only');
  rejectSigner('clock_evidence_chrony_deadline',{},6000000000n);
  rejectSigner('clock_evidence_profile',{format:'leafseamer.authentication-clock-signing-profile/1'});
  rejectSigner('clock_evidence_chrony_binding',{chrony:{...profile,max_source_age_s:8}});
  fs.appendFileSync(client.conf,'# synthetic configuration change\n');
  rejectSigner('clock_evidence_chrony_configuration');
  fs.writeFileSync(client.conf,fs.readFileSync(client.conf,'utf8').replace('# synthetic configuration change\n',''));
  await stop(server);
  await delay(5100);
  rejectSigner([
    'clock_evidence_chrony_stale','clock_evidence_chrony_sources','clock_evidence_chrony_unsynchronized'
  ]);
  await stop(client);
  rejectSigner('clock_evidence_chrony_unavailable');
});
