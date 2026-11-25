import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {once} from 'node:events';
import {createConnection,createServer} from 'node:net';
import {createInterface} from 'node:readline';
import test from 'node:test';
import canonicalize from '../dist/runtime/canonicalize.mjs';
import {openTimeProviderLink} from '../dist/time-provider-link.mjs';

test('Windows 授时链路继续使用原命名管道与原绑定，并在对端断开时失效',{
  skip:process.platform!=='win32',timeout:5000
},async t=>{
  const boot=randomBytes(16).toString('hex');
  const pipe='\\\\.\\pipe\\LeafSeamer.TimeCollector.'+boot+'.core';
  const server=createServer();
  t.after(()=>server.close());
  server.listen(pipe);await once(server,'listening');
  const text=canonicalize({format:'leafseamer-time-provider-runtime-binding/1'});
  const digest='sha256:'+createHash('sha256').update(text).digest('hex');
  const connected=once(server,'connection');
  const opening=openTimeProviderLink({text,digest,memberBoot:boot});
  opening.catch(()=>{});
  const [peer]=await connected;
  t.after(()=>peer.destroy());
  const frames=createInterface({input:peer})[Symbol.asyncIterator]();
  const request=JSON.parse((await frames.next()).value);
  assert.equal(request.type,'BIND');assert.equal(request.binding_digest,digest);
  assert.equal(request.binding.format,'leafseamer-time-provider-runtime-binding/1');
  const challenge=randomUUID(),write=value=>peer.write(canonicalize(value)+'\n');
  write({binding_digest:digest,request_id:challenge,tick_ns:'1',type:'AUTH_READ',version:'time-provider-auth/1'});
  assert.deepEqual(JSON.parse((await frames.next()).value),{binding_digest:digest,reply_to:challenge,sample:null,
    type:'AUTH_RESULT',version:'time-provider-auth/1'});
  write({binding_digest:digest,reply_to:request.request_id,type:'BOUND',version:'time-provider-link/1'});
  const link=await opening;
  link.assertCurrent();
  const lost=new Promise(resolve=>link.onLost(resolve));
  peer.destroy();
  await lost;
  assert.throws(()=>link.assertCurrent(),/time_provider_link_lost/);
});

test('NTS 证据仅接受同一尝试内核心实际签发的时钟读取及获准根', {timeout:7000},async t=>{
  const hash=value=>'sha256:'+createHash('sha256').update(value).digest('hex');
  for(const scenario of ['valid','foreign_read','reused_read','late_send','unapproved_root']){
    await t.test(scenario,async context=>{
      const server=createServer();
      server.listen(0,'127.0.0.1');
      await once(server,'listening');
      context.after(()=>server.close());
      const connected=once(server,'connection'),connection=createConnection(server.address().port,'127.0.0.1');
      const [peer]=await connected;
      context.after(()=>{peer.destroy();connection.destroy();});
      const frames=createInterface({input:peer})[Symbol.asyncIterator]();
      const next=async()=>JSON.parse((await frames.next()).value);
      const write=value=>peer.write(canonicalize(value)+'\n');
      const domain={clock_domain_id:'reference.fixture.domain',descriptor_digest:hash('clock')};
      const text=canonicalize({format:'leafseamer-time-provider-runtime-binding/2',clock_domain_descriptor:domain});
      const digest=hash(text);
      const opening=openTimeProviderLink({text,digest,memberBoot:randomBytes(16).toString('hex')},{connection});
      const bind=await next();
      const read=async tick=>{
        const read_id=randomUUID();
        write({binding_digest:digest,request_id:read_id,tick_ns:String(tick),type:'AUTH_READ',version:'time-provider-auth/1'});
        const reply=await next();
        assert.equal(reply.reply_to,read_id);
        return {read_id,tick_ns:String(tick+2)};
      };
      await read(1);
      write({binding_digest:digest,reply_to:bind.request_id,type:'BOUND',version:'time-provider-link/1'});
      const link=await opening;
      context.after(()=>link.close());
      const roots=Buffer.from('fixture root'),root=hash(roots),source={id:'reference.source',revision:'1',digest:hash('source')};
      const network={authentication:'nts',bootstrap_evidence:'nts-bootstrap/1',server_name:'reference.fixture.invalid',
        key_endpoint:'127.0.0.1:4460',root_der:[roots.toString('base64url')],targets:[{endpoint:'127.0.0.1:123'}]};
      const attempt={attempt_id:randomUUID(),attempted_tick_ns:'100',valid_before_tick_ns:'1000',poll_ref:{id:randomUUID(),digest:hash('poll')}};
      let authTick=110,saved=null;
      const completion=link.collect(()=>({network,attempt,reservation:{},
        authorize:()=>({tick_ns:String(authTick),valid_before_tick_ns:'1000',lower_ns:'2000',upper_ns:'2100',
          monotonic_quantization_ns:'1',drift_ppb:0,acquisition_ref:{id:randomUUID(),revision:'1',digest:hash('clock acquisition')},
          source_ref:source,policy_ref:source,runtime_ref:source,runtime_domain_ref:domain}),
        archive(candidate,proof){saved={candidate,proof};return {};},release(){}}));
      void completion.catch(()=>{});
      const poll=await next();
      const reads={};
      for(const [phase,at] of [['tls',110],['key_completion',120],['send',140],['receive',170]]){
        authTick=at;
        reads[phase]=await read(at-1);
      }
      const nts_bootstrap={format:'nts-bootstrap/1',aead_algorithm:15,alpn:'ntske/1',root_digests:[root],
        chain_digests:[hash('leaf'),root],key_endpoint:network.key_endpoint,server_name:network.server_name,tls_version:'1.3',...reads};
      if(scenario==='foreign_read')nts_bootstrap.receive={...reads.receive,read_id:randomUUID()};
      if(scenario==='reused_read')nts_bootstrap.key_completion=reads.tls;
      if(scenario==='late_send')nts_bootstrap.send={...reads.send,tick_ns:'151'};
      if(scenario==='unapproved_root')nts_bootstrap.chain_digests[1]=hash('other root');
      const datagram=Buffer.alloc(48).toString('base64url');
      write({type:'POLL_RESULT',version:'time-provider-link/1',binding_digest:digest,poll_sequence:poll.poll_sequence,
        attempt_id:attempt.attempt_id,poll_ref:attempt.poll_ref,status:'candidate',control:null,candidate:{endpoint:'127.0.0.1:123',
          key_reply:roots.toString('base64url'),key_reply_digest:root,m1_tick_ns:'150',m4_tick_ns:'160',
          nts_bootstrap,request:datagram,response:datagram}});
      if(scenario==='valid'){
        const stored=await next();
        assert.equal(stored.type,'POLL_STORED');
        write({...stored,type:'POLL_STORED_ACK'});
        assert.equal((await completion).status,'archived');
        assert.deepEqual(saved.proof.source_ref,source);
        assert.equal(saved.proof.reads.tls.lower_ns,'2000');
        assert.equal(saved.proof.reads.tls.upper_ns,'2103');
        assert.deepEqual(saved.proof.root_digests,[root]);
      }else{
        await assert.rejects(completion,/time_provider_link_response/);
        assert.equal(saved,null);
        assert.throws(()=>link.assertCurrent(),/time_provider_link_lost/);
      }
    });
  }
});
