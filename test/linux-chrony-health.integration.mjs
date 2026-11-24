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
import {canonical,context,digest,ref,seal} from '../dist/auth-clock-value.mjs';
import {fixture} from './auth-clock-fixture.mjs';

const file=name=>fileURLToPath(new URL(name,import.meta.url));
const hash=filename=>'sha256:'+crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
const guestDiscipline=process.env.LEAFSEAMER_TEST_CHRONY_GUEST==='1';
const envelopeFormat='leafseamer.authentication-clock-evidence/1';
const guestErrorLimit=100000000n;

test(guestDiscipline?'隔离客体实际校时后签发，失联后保留最后签发原件':'独立 Chrony 实际追踪已批准源，-x、配置改变与源失联拒绝签发',{
  skip:process.platform!=='linux'||!guestDiscipline&&process.env.LEAFSEAMER_TEST_CHRONY_HOST!=='1',
  timeout:guestDiscipline&&process.env.LEAFSEAMER_TEST_CHRONY_SUITE?215000:35000
},async t=>{
  function kernelClock(){
    const probe=spawnSync('/proof/read-kernel-clock',[],{encoding:'utf8',timeout:2000});
    assert.equal(probe.status,0,probe.stderr||probe.error?.message);
    return probe.stdout.trim();
  }
  if(guestDiscipline){
    // Only the dedicated diskless guest may start a clock-setting daemon.
    assert.equal(fs.readlinkSync('/proc/1/exe'),'/bin/busybox');
    assert.match(fs.readFileSync('/proc/cmdline','utf8'),/(?:^|\s)leafseamer.chrony_clock_guest=1(?:\s|$)/);
    assert.match(fs.readFileSync('/sys/class/dmi/id/product_name','utf8'),/^Standard PC \(Q35/);
    assert.deepEqual(fs.readdirSync('/sys/class/net'),['lo']);
    assert.equal(kernelClock(),'unsynchronized');
  }
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
  function start(role,directives,trackingOnly=true){
    const conf=path.join(root,role+'.conf'),pid=path.join(root,role+'.pid'),socket=path.join(root,role+'.sock');
    fs.writeFileSync(conf,["user root",'cmdport 0','pidfile '+pid,'bindcmdaddress '+socket,...directives].join('\n')+'\n',{mode:0o600});
    const child=spawn(chronyd,['-d',...(trackingOnly?['-x']:[]),'-f',conf],{stdio:['ignore','ignore','pipe']});
    const exit=once(child,'close');
    let errors='';child.stderr.setEncoding('utf8').on('data',bytes=>{errors+=bytes;});
    const service={child,exit,conf,pid,socket,errors:()=>errors};children.push(service);return service;
  }
  const server=start('server',['bindaddress 127.0.0.2','port '+port,'allow 127.0.0.0/8','local stratum 8']);
  const client=start('client',['port 0','server 127.0.0.2 port '+port+' iburst minpoll 0 maxpoll 0',
    ...(guestDiscipline?['rtcsync']:[])],!guestDiscipline);
  const profile={format:'leafseamer.linux-chrony-health/1',chronyc_file:chronyc,chronyc_sha256:hash(chronyc),chronyd_sha256:hash(chronyd),
    configuration_file:client.conf,configuration_sha256:hash(client.conf),pid_file:client.pid,socket_file:client.socket,
    source_addresses:['127.0.0.2'],max_source_age_s:4};
  const deadline=performance.now()+17000;
  let report;
  for(;;){
    try{
      report=observeLinuxChronyHealth(profile);
      if(guestDiscipline){
        assert.equal(kernelClock(),'synchronized');
        assert.ok(report.reportedErrorNs<=guestErrorLimit,'guest Chrony error estimate: '+report.reportedErrorNs+' ns');
      }
      break;
    }
    catch(error){
      if(client.child.exitCode!==null||server.child.exitCode!==null||performance.now()>=deadline){
        throw new Error(client.errors()+server.errors(),{cause:error});
      }
      await delay(200);
    }
  }
  assert.equal(report.state,guestDiscipline?'synchronized':'tracking_only');assert.equal(report.source,'127.0.0.2');
  assert.equal(report.identity.pid,String(client.child.pid));
  assert.ok(report.reportedErrorNs>=0n);
  const pidMode=fs.statSync(client.pid).mode&0o777;
  fs.chmodSync(client.pid,0o666);
  assert.throws(()=>observeLinuxChronyHealth(profile),{code:'clock_evidence_chrony_file'});
  fs.chmodSync(client.pid,pidMode);

  const clock=openNativeClock(),scope={service_id:crypto.randomUUID(),service_boot_id:crypto.randomUUID()};
  const base=fixture(scope,{source:clock},{sampleWindowPolicy:'authentication-clock-sample/2'}).evidence;
  function reseal(value,overrides){const {digest:_original,...body}=value;return seal({...body,...overrides});}
  const policy=reseal(base.policy,{health_profile_ref:{...base.policy.health_profile_ref,digest:digest(profile)},
    ...(guestDiscipline?{max_system_error_ns:String(guestErrorLimit)}:{})});
  const {privateKey,publicKey}=crypto.generateKeyPairSync('ed25519');
  const keyFile=path.join(root,'test-key.pem'),evidenceFile=path.join(root,'evidence.json'),profileFile=path.join(root,'signer.json');
  const statementFile=path.join(root,'statement.json'),database_instance_id=crypto.randomUUID();
  fs.writeFileSync(keyFile,privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});
  const signing={format:'leafseamer.authentication-clock-signing-profile/2',service_id:scope.service_id,database_instance_id,
    policy_digest:policy.digest,native_binary_digest:clock.artifactDigest,private_key_file:keyFile,evidence_file:evidenceFile,chrony:profile};
  function runSigner({override={},lifetime=2000000000n,approval=policy}={}){
    const runtime=reseal(base.runtime,{policy_ref:ref(approval)});
    const health=reseal(base.health,{policy_ref:ref(approval),runtime_ref:ref(runtime),health_profile_ref:approval.health_profile_ref,
      valid_before_tick_ns:String(clock.tick()+lifetime)});
    const challenge={event:'authentication_clock_challenge',...scope,database_instance_id,native_binary_digest:clock.artifactDigest,
      continuity:runtime.continuity,tick_ns:String(clock.tick()),clock_domain_id:runtime.clock_domain_id,descriptor_digest:runtime.descriptor_digest};
    const evidence={policy:approval,runtime,health};
    fs.writeFileSync(profileFile,canonical({...signing,policy_digest:approval.digest,...override}));
    fs.writeFileSync(statementFile,canonical({challenge,evidence}));
    const result=spawnSync(process.execPath,['--disallow-code-generation-from-strings',file('../dist/clock-evidence.mjs'),
      '--profile',profileFile,'--statement',statementFile],{encoding:'utf8',timeout:4000});
    return {result,evidence};
  }
  let published;
  let originalEvidence;
  function rejectSigner(codes,settings){
    const {result}=runSigner(settings);
    assert.equal(result.status,1,result.stderr);
    const message=JSON.parse(result.stderr);
    assert.deepEqual(Object.keys(message),['error']);
    assert.ok([codes].flat().includes(message.error),result.stderr);
    if(published)assert.deepEqual(fs.readFileSync(evidenceFile),published);
    else assert.equal(fs.existsSync(evidenceFile),false);
  }
  if(guestDiscipline){
    const {result,evidence}=runSigner();
    assert.equal(result.status,0,(result.stderr||result.error?.message||'')+
      '\ninitial estimate '+report.reportedErrorNs+' ns');
    assert.deepEqual(JSON.parse(result.stdout),{state:'published',...scope});
    published=fs.readFileSync(evidenceFile);
    const packet=JSON.parse(published.toString('utf8'));
    assert.equal(published.toString('utf8'),canonical(packet));
    assert.equal(packet.format,envelopeFormat);
    assert.deepEqual(packet.evidence,evidence);
    assert.ok(crypto.verify(null,Buffer.from(envelopeFormat+'\0'+canonical(evidence)),publicKey,Buffer.from(packet.signature,'base64url')));
    context(evidence,scope,clock.artifactDigest,clock.tick());
    originalEvidence=packet.evidence;
    rejectSigner('clock_evidence_chrony_error',{approval:reseal(policy,{max_system_error_ns:'1'})});
    const suite=process.env.LEAFSEAMER_TEST_CHRONY_SUITE;
    if(suite){
      const chronyProfile=path.join(root,'chrony-profile.json');
      fs.writeFileSync(chronyProfile,canonical(profile),{mode:0o600});
      const env={...process.env};
      delete env.NODE_TEST_CONTEXT;
      const integration=env.LEAFSEAMER_TEST_CHRONY_COMPOSE==='1'?'test/linux-compose.integration.mjs':'test/linux-core-bootstrap.integration.mjs';
      const child=spawn(process.execPath,['--disallow-code-generation-from-strings','--test',integration],{
        cwd:suite,env:{...env,LEAFSEAMER_TEST_NATIVE_CGROUP:'1',LEAFSEAMER_CONTROLLER_BOOTSTRAP_DIST:file('../dist'),
          LEAFSEAMER_TEST_CHRONY_PROFILE:chronyProfile},stdio:['ignore','inherit','inherit']});
      const service={child,exit:once(child,'close')};children.push(service);
      const [status]=await service.exit;
      assert.equal(status,0,'Product cores did not verify live Chrony signatures');
    }
  }else{
    rejectSigner('clock_evidence_chrony_tracking_only');
  }
  rejectSigner('clock_evidence_chrony_deadline',{lifetime:6000000000n});
  rejectSigner('clock_evidence_profile',{override:{format:'leafseamer.authentication-clock-signing-profile/1'}});
  rejectSigner('clock_evidence_chrony_binding',{override:{chrony:{...profile,max_source_age_s:8}}});
  fs.appendFileSync(client.conf,'# synthetic configuration change\n');
  rejectSigner('clock_evidence_chrony_configuration');
  fs.writeFileSync(client.conf,fs.readFileSync(client.conf,'utf8').replace('# synthetic configuration change\n',''));
  await stop(server);
  await delay(5100);
  if(originalEvidence)assert.throws(()=>context(originalEvidence,scope,clock.artifactDigest,clock.tick()),
    {code:'auth_clock_evidence_expired'});
  rejectSigner([
    'clock_evidence_chrony_stale','clock_evidence_chrony_sources','clock_evidence_chrony_unsynchronized'
  ]);
  await stop(client);
  rejectSigner('clock_evidence_chrony_unavailable');
});
