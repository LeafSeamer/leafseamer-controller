import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {narrowPermissions} from '../dist/extension-review-permissions.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {prepared} from './fixtures/extension-role.mjs';
import {inspect,hash} from './fixtures/extension-installation.mjs';
const ref=kind=>({kind,authority_service_id:'controller.test',database_instance_id:'database.test',object_id:kind,revision:'1',digest:hash(kind)});
function permissions(){const device=ref('device'),profile=ref('protocol_profile');return [
 {request_id:'data',kind:'data_scope',purpose:'数据',scope:{objects:[ref('data_object')],access:'read'}},
 {request_id:'device',kind:'device_scope',purpose:'设备',scope:{devices:[device],action_ids:['get','set'],trigger_ids:['changed']}},
 {request_id:'filesystem',kind:'filesystem_root_role',purpose:'缓存',scope:{role_ref:ref('filesystem_role'),access:'cache_write',quota_bytes:'1024'}},
 {request_id:'helper',kind:'helper_artifact',purpose:'帮助程序',scope:{artifact_ref:ref('helper_artifact'),launch_profile_ref:ref('validation_policy')}},
 {request_id:'network',kind:'network_endpoint',purpose:'网络',scope:{transport:'tcp',host:'192.0.2.10',port:5000,profile_ref:profile}},
 {request_id:'panel',kind:'panel_method',purpose:'面板',scope:{authority:'controller',method_ids:['getDevice','getState'],object_refs:[device]}},
 {request_id:'protocol',kind:'protocol_io',purpose:'协议',scope:{profile_ref:profile,endpoint_request_id:'network',frame_classes:['control','query']}},
 {request_id:'secret',kind:'secret_role',purpose:'凭据',scope:{role_ref:ref('secret_role'),devices:[device],sources:[ref('source')]}}
 ];}
test('审阅覆盖八种权限收窄，配额使用精确整数且不替换用途与固定引用',()=>{
 const original=permissions(),proposal=structuredClone(original);proposal[1].scope.action_ids=['get'];proposal[1].scope.trigger_ids=[];
 proposal[2].scope.quota_bytes='0';proposal[5].scope.method_ids=['getDevice'];proposal[6].scope.frame_classes=['query'];proposal[7].scope.sources=[];
 assert.deepEqual(narrowPermissions(original,proposal),proposal);assert.equal(original[1].scope.action_ids.length,2);
 assert.deepEqual(narrowPermissions(original,[]),[]);
 const large=structuredClone(original);large[2].scope.quota_bytes='18446744073709551615';const lowered=structuredClone(large);lowered[2].scope.quota_bytes='18446744073709551614';
 assert.deepEqual(narrowPermissions(large,lowered),lowered);
 for(const mutate of [
  x=>x[0].scope.access='propose',x=>x[1].purpose='替换用途',x=>x[1].scope.action_ids.push('unrequested'),
  x=>{x[1].scope.action_ids=[];x[1].scope.trigger_ids=[];},x=>x[2].scope.quota_bytes='1025',
  x=>x[3].scope.artifact_ref.digest=hash('wrong'),x=>x[4].scope.port=5001,x=>x[5].scope.authority='seamer',
  x=>x.splice(4,1),x=>x[6].scope.profile_ref=ref('other'),x=>{x[7].scope.devices=[];x[7].scope.sources=[];},
  x=>delete x[1].scope.trigger_ids,x=>x.push(x[0]),x=>x[1].scope.action_ids=['set','get']
 ]){const invalid=structuredClone(original);mutate(invalid);assert.throws(()=>narrowPermissions(original,invalid));}
});
async function reviewFixture(t,options={}){
 const f=await prepared(t,{revision:16,...options}),resolved=await f.api.roles.resolve(f.request),proposal=structuredClone(resolved.record.permissions);
 proposal[0].scope.action_ids=['get'];
 return {...f,resolved,reviewRequest:{request_id:'review',installation_ref:f.installed.installation_ref,configuration_ref:f.config.configuration_ref,
  role_resolution_ref:resolved.resolution_ref,expected_revision:'0',proposed_permissions:proposal}};
}
test('实际安装、配置及角色进入不可变审阅原件，收窄、策略、幂等、CAS和重启查原',{timeout:20000},async t=>{
 const {f,api,host,installed,reviewRequest}=await reviewFixture(t),first=await api.reviews.review(reviewRequest);
 assert.deepEqual(first.record.requested_permissions[0].scope.action_ids,['get','set']);assert.deepEqual(first.record.proposed_permissions[0].scope.action_ids,['get']);
 const {review_ref,content_digest,...body}=first.record;assert.equal(content_digest,hash(body));assert.equal(review_ref.digest,content_digest);
 assert.deepEqual(await api.reviews.review(reviewRequest),first);assert.deepEqual(api.reviews.current(installed.installation_ref),first);
 await assert.rejects(api.reviews.review({...reviewRequest,proposed_permissions:[]}),{code:'extension_review_conflict'});
 await assert.rejects(api.reviews.review({...reviewRequest,request_id:'stale'}),{code:'extension_review_stale'});
 const next=await api.reviews.review({...reviewRequest,request_id:'next',expected_revision:'1',proposed_permissions:[]});assert.equal(next.review_ref.revision,'2');assert.notEqual(next.review_ref.object_id,first.review_ref.object_id);
 assert.deepEqual(next.record.proposed_permissions,[]);f.close();const reopened=f.reopen().extensionInstallations;reopened.bindSource(host);
 assert.deepEqual(reopened.reviews.query('review'),first);assert.deepEqual(reopened.reviews.current(installed.installation_ref),next);
});
test('扩权、缺字段和客户端自报requested或policy均拒绝；解析推进使旧审阅失效',{timeout:20000},async t=>{
 const {api,installed,request,reviewRequest}=await reviewFixture(t),first=await api.reviews.review(reviewRequest);
 const expanded=structuredClone(reviewRequest);expanded.request_id='expanded';expanded.expected_revision='1';expanded.proposed_permissions[0].scope.action_ids=['unknown'];
 await assert.rejects(api.reviews.review(expanded),{code:'extension_review_expansion'});
 const malformed=structuredClone(expanded);delete malformed.proposed_permissions[0].scope.devices;await assert.rejects(api.reviews.review(malformed));
 for(const extra of [{requested_permissions:[]},{policy_ref:ref('validation_policy')}])await assert.rejects(api.reviews.review({...reviewRequest,request_id:'extra',...extra}),{code:'extension_review_input'});
 await api.roles.resolve({...request,request_id:'new-resolution',expected_revision:'1'});
 assert.deepEqual(api.reviews.query('review'),first);assert.throws(()=>api.reviews.current(installed.installation_ref),{code:'extension_review_resolution_stale'});
 await assert.rejects(api.reviews.review({...reviewRequest,request_id:'old-resolution',expected_revision:'1'}),{code:'extension_review_resolution_stale'});
});
test('策略、审阅、head及审计逐写失败全回滚；解析等待中变化不能提交',{timeout:20000},async t=>{
 for(const table of ['extension_review_policy','extension_permission_review','extension_review_head','extension_review_operation']){
  const {f,host,reviewRequest}=await reviewFixture(t);f.close();inspect(f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
  const api=f.reopen().extensionInstallations;api.bindSource(host);await assert.rejects(api.reviews.review(reviewRequest),/synthetic_failure/);f.close();
  inspect(f.dir,db=>{for(const name of ['extension_review_policy','extension_permission_review','extension_review_head','extension_review_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);});
 }
 let armed=false;
 const changed=await reviewFixture(t,{recheck:async(f,host)=>{if(!armed)return;armed=false;host.checkRoles=false;
  await f.store.extensionInstallations.roles.resolve({...changed.request,request_id:'raced-resolution',expected_revision:'1'});}});
 armed=true;await assert.rejects(changed.api.reviews.review(changed.reviewRequest),{code:'extension_review_resolution_stale'});assert.equal(changed.api.reviews.query('review'),null);
 let revoke=false;const revoked=await reviewFixture(t,{recheck:(_f,host)=>{if(revoke)host.revoked=true;}});revoke=true;
 await assert.rejects(revoked.api.reviews.review(revoked.reviewRequest),{code:'extension_review_source_unavailable'});
});
test('schema15显式迁移到16保留角色原件，旧版本不能发审阅',async t=>{
 const {f,api,resolved}=await reviewFixture(t,{revision:15});assert.equal(api.reviews,null);f.close();const migrated=await migrateStorage(f.dir,16);
 assert.equal(migrated.schema_revision,'16');assert.equal(migrated.steps.length,1);assert.deepEqual(f.reopen().extensionInstallations.roles.query('resolve'),resolved);
});
test('不同构建的独立进程保留审阅历史，但拒绝采用旧策略的current结果',{timeout:20000},async t=>{
 const {f,api,installed,reviewRequest}=await reviewFixture(t),review=await api.reviews.review(reviewRequest);f.close();
 const parent=fileURLToPath(new URL('.',import.meta.url)),root=fs.mkdtempSync(path.join(parent,'review-policy-'));
 try{
  fs.cpSync(fileURLToPath(new URL('../dist',import.meta.url)),path.join(root,'dist'),{recursive:true});
  const manifest=path.join(root,'dist/build-manifest.json'),value=JSON.parse(fs.readFileSync(manifest));value.test_build_revision='synthetic-next-build';fs.writeFileSync(manifest,JSON.stringify(value));
  fs.writeFileSync(path.join(root,'probe.mjs'),`import fs from 'node:fs';import {openStorage} from './dist/storage.mjs';
const input=JSON.parse(fs.readFileSync(0,'utf8')),store=openStorage(input.dir);try{
 const historical=store.extensionInstallations.reviews.query('review');let code=null;
 try{store.extensionInstallations.reviews.current(input.ref);}catch(error){code=error.code;}
 process.stdout.write(JSON.stringify({historical,code}));
}finally{store.close();}`);
  const child=spawnSync(process.execPath,['--disallow-code-generation-from-strings',path.join(root,'probe.mjs')],{
   input:JSON.stringify({dir:f.dir,ref:installed.installation_ref}),encoding:'utf8',timeout:10000,windowsHide:true});
  assert.equal(child.status,0,child.stderr);const output=JSON.parse(child.stdout);assert.equal(output.code,'extension_review_policy');assert.deepEqual(output.historical,review);
 }finally{assert.equal(path.dirname(path.resolve(root)),path.resolve(parent));fs.rmSync(root,{recursive:true,force:true});}
});
