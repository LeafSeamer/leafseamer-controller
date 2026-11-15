import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {peerCertificates} from './fixtures/peer-certificates.mjs';
import {fixture} from './auth-clock-fixture.mjs';
import {digest} from '../dist/auth-clock-value.mjs';
import {openStorage} from '../dist/storage.mjs';
import {startController} from '../dist/server.mjs';
const id=()=>crypto.randomUUID();
async function freePort(){const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;}
async function refused(port){await assert.rejects(new Promise((resolve,reject)=>{const socket=net.connect(port,'127.0.0.1');socket.once('connect',()=>{socket.destroy();resolve();});socket.once('error',reject);socket.setTimeout(2000,()=>socket.destroy(new Error('test_timeout')));}),{code:'ECONNREFUSED'});}
function provider({scope,source}){return fixture(scope,{source,descriptor:{clock_domain_id:id(),descriptor_digest:digest('synthetic-controller-lifecycle')}},{sampleWindowPolicy:'authentication-clock-sample/2'}).provider;}
test('显式要求配对而身份未初始化时拒绝启动，释放公共监听和文件库',async t=>{
 const f=await setup(t,62),port=await freePort(),certificates=peerCertificates();f.close();
 await assert.rejects(startController({dataDir:f.dir,port,authenticationProvider:provider,pairing:{...certificates.leaves[0],ca:certificates.ca,credential_id:id()}}),/pairing_runtime_unavailable/);
 await refused(port);const reopened=openStorage(f.dir);assert.equal(reopened.enrollment.summary().initialized,false);reopened.close();
 inspect(f.dir,db=>assert.equal(db.prepare("SELECT count(*) FROM service_boot WHERE state='started'").pluck().get(),0));
});
test('内部监听或绑定配置失败时关闭全部已开端口、采样器与库，不降级为部分服务',async t=>{
 const f=await setup(t,62),capability=f.store.enrollment.begin();await f.store.enrollment.complete({token_id:capability.token_id,secret:capability.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});f.close();
 const certificates=peerCertificates(),occupied=net.createServer();await new Promise(resolve=>occupied.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>occupied.close(resolve)));
 for(const invalidPeers of [false,true]){
  const port=await freePort(),peerPort=invalidPeers?await freePort():occupied.address().port;
  const pairing={...certificates.leaves[0],ca:certificates.ca,credential_id:id(),port:peerPort,...(invalidPeers?{peers:[{}]}:{})};
  await assert.rejects(startController({dataDir:f.dir,port,authenticationProvider:provider,pairing}),error=>error.code===(invalidPeers?'ERR_INVALID_ARG_TYPE':'EADDRINUSE'));await refused(port);if(invalidPeers)await refused(peerPort);
  const reopened=openStorage(f.dir);assert.equal(reopened.enrollment.summary().initialized,true);reopened.close();
  inspect(f.dir,db=>assert.equal(db.prepare("SELECT count(*) FROM service_boot WHERE state='started'").pluck().get(),0));
 }
});
