import assert from 'node:assert/strict';
import {randomBytes,randomUUID,createHash} from 'node:crypto';
import {once} from 'node:events';
import {createServer} from 'node:net';
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
