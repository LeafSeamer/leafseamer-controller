import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {localIdentityPermissions} from '../dist/local-permission-store.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {prepared} from './fixtures/extension-role.mjs';
import {inspect,hash} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
const login={login:'role.test',password:'Synthetic-role-password-123'};
const sessionInput=value=>({credential_id:value.credential_id,secret:value.secret,csrf:value.csrf});
async function setup(t,options={}){
 const f=await prepared(t,{revision:17,...options}),resolved=await f.api.roles.resolve(f.request),reviewed=await f.api.reviews.review({request_id:'review',installation_ref:f.installed.installation_ref,
  configuration_ref:f.config.configuration_ref,role_resolution_ref:resolved.resolution_ref,expected_revision:'0',proposed_permissions:resolved.record.permissions});
 return {...f,resolved,reviewed,approvalRequest:{request_id:'approve',installation_ref:f.installed.installation_ref,permission_review_ref:reviewed.review_ref,
  configuration_ref:f.config.configuration_ref,approved_permission_ids:[]}};
}
test('真实人员会话须显式拥有管理权限；只批准提案权限，当前无能力证据的动作拒绝',{timeout:20000},async t=>{
 const x=await setup(t),a=await authenticated(t,x.f,{grant:false}),readOnly=a.token(['auth.read']);
 assert.throws(()=>a.token(),/local_authorization_denied/);
 await assert.rejects(a.sessions.approveExtension(readOnly,x.approvalRequest),/extension_management_denied/);
 const current=a.sessions.localPermissions(a.auth);a.sessions.replaceLocalPermissions(a.auth,{request_id:crypto.randomUUID(),principal_id:a.logged.session.principal_id,
  expected_revision:current.revision,permissions:[...localIdentityPermissions,'extension.manage','extension.read']});
 const token=a.token();await assert.rejects(a.sessions.approveExtension(token,{...x.approvalRequest,principal_id:a.logged.session.principal_id}),/extension_approval_input/);
 await assert.rejects(a.sessions.approveExtension(token,{...x.approvalRequest,approved_permission_ids:['device.request']}),/extension_approval_capability_unavailable/);
 await assert.rejects(a.sessions.approveExtension(token,{...x.approvalRequest,approved_permission_ids:['not.proposed']}),/extension_approval_permission_ids/);
 const approved=await a.sessions.approveExtension(token,x.approvalRequest);assert.deepEqual(approved.permissions,[]);assert.equal(approved.record.permissions_digest,hash([]));
 const {approval_ref,...body}=approved.record;assert.equal(approval_ref.digest,hash(body));assert.deepEqual(a.sessions.lookupExtensionApproval(token,'approve'),approved);
 assert.equal(a.sessions.getExtensionApproval(token,approval_ref).status,'approved');assert.deepEqual(await a.sessions.approveExtension(token,x.approvalRequest),approved);
 await assert.rejects(a.sessions.approveExtension(token,{...x.approvalRequest,approved_permission_ids:['device.request']}),/extension_approval_conflict/);
 const other=await a.sessions.login(login),otherIssued=a.sessions.issueToken(sessionInput(other),{request_id:crypto.randomUUID(),audience:x.f.store.identity.service_id,requested_scopes:['extension.manage','extension.read']});
 const otherToken={token_id:otherIssued.token.token_id,secret:otherIssued.secret};assert.equal(a.sessions.lookupExtensionApproval(otherToken,'approve'),null);
 await assert.rejects(a.sessions.approveExtension(otherToken,x.approvalRequest),/extension_approval_frozen/);
 a.state.offset=300000000000n;const later=a.token();
 await assert.rejects(a.sessions.approveExtension(later,x.approvalRequest),/extension_management_recent_required/);
 assert.deepEqual(a.sessions.lookupExtensionApproval(later,'approve'),approved);
});
test('批准冻结配置、角色和审阅；撤销是永久记录且原请求只返回历史',{timeout:20000},async t=>{
 const x=await setup(t),a=await authenticated(t,x.f),token=a.token(),approved=await a.sessions.approveExtension(token,x.approvalRequest);
 await assert.rejects(x.api.configurations.configure({request_id:'new-config',installation_ref:x.installed.installation_ref,expected_revision:'1',bytes:Buffer.from('{}')}),/extension_approved_frozen/);
 await assert.rejects(x.api.roles.resolve({...x.request,request_id:'new-role',expected_revision:'1'}),/extension_approved_frozen/);
 await assert.rejects(x.api.reviews.review({request_id:'new-review',installation_ref:x.installed.installation_ref,configuration_ref:x.config.configuration_ref,
  role_resolution_ref:x.resolved.resolution_ref,expected_revision:'1',proposed_permissions:[]}),/extension_approved_frozen/);
 const request={request_id:'revoke',approval_ref:approved.approval_ref,reason:'撤销测试'},denied=a.sessions.revokeExtensionApproval(token,request);
 assert.deepEqual(a.sessions.revokeExtensionApproval(token,request),denied);assert.deepEqual(a.sessions.revokeExtensionApproval(token,{...request,request_id:'again',reason:'再次确认'}),denied);
 assert.equal(a.sessions.getExtensionApproval(token,approved.approval_ref).status,'revoked');assert.deepEqual(await a.sessions.approveExtension(token,x.approvalRequest),approved);
 await assert.rejects(a.sessions.approveExtension(token,{...x.approvalRequest,request_id:'new-approval'}),/extension_approval_frozen/);
 a.real.stop();x.f.close();x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const b=await authenticated(t,x.f);
 assert.equal(b.sessions.getExtensionApproval(b.token(),approved.approval_ref).status,'revoked');
});
test('审批等待期间会话注销或权限撤销阻止提交；保护撤销不依赖安装来源可用',{timeout:20000},async t=>{
 let onCheck=()=>{};const x=await setup(t,{recheck:()=>onCheck()}),a=await authenticated(t,x.f),token=a.token();
 onCheck=()=>{onCheck=()=>{};a.sessions.logout(a.auth);};await assert.rejects(a.sessions.approveExtension(token,x.approvalRequest),/token_invalid/);
 const logged=await a.sessions.login(login),auth=sessionInput(logged),issued=a.sessions.issueToken(auth,{request_id:crypto.randomUUID(),audience:x.f.store.identity.service_id,requested_scopes:['extension.manage','extension.read']});
 const b={sessions:a.sessions},next={token_id:issued.token.token_id,secret:issued.secret};onCheck=()=>{onCheck=()=>{};const current=b.sessions.localPermissions(auth);
  b.sessions.replaceLocalPermissions(auth,{request_id:crypto.randomUUID(),principal_id:logged.session.principal_id,expected_revision:current.revision,permissions:[...localIdentityPermissions,'extension.read']});};
 await assert.rejects(b.sessions.approveExtension(next,{...x.approvalRequest,request_id:'revoked-permission'}),/token_invalid/);
 const y=await setup(t),c=await authenticated(t,y.f),credential=c.token(),approved=await c.sessions.approveExtension(credential,y.approvalRequest);y.host.revoked=true;
 const denied=c.sessions.revokeExtensionApproval(credential,{request_id:'revoke-source-gone',approval_ref:approved.approval_ref,reason:'来源已撤销'});assert.ok(denied.deny_ref);
});
test('批准与审计、拒绝与审计逐写失败均回滚，不留下冻结或永久拒绝的半写集',{timeout:20000},async t=>{
 for(const table of ['extension_approval','extension_approval_operation']){
  const x=await setup(t);x.f.close();inspect(x.f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
  x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const a=await authenticated(t,x.f);
  await assert.rejects(a.sessions.approveExtension(a.token(),x.approvalRequest),/synthetic_failure/);a.real.stop();x.f.close();
  inspect(x.f.dir,db=>assert.equal(db.prepare('SELECT count(*) FROM extension_approval').pluck().get(),0));
 }
 for(const table of ['extension_approval_deny','extension_approval_operation']){
  const x=await setup(t),a=await authenticated(t,x.f),approved=await a.sessions.approveExtension(a.token(),x.approvalRequest);a.real.stop();x.f.close();
  inspect(x.f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
  x.f.reopen();x.f.store.extensionInstallations.bindSource(x.host);const b=await authenticated(t,x.f);
  assert.throws(()=>b.sessions.revokeExtensionApproval(b.token(),{request_id:'revoke-failed',approval_ref:approved.approval_ref,reason:'测试'}),/synthetic_failure/);
  assert.equal(b.sessions.getExtensionApproval(b.token(),approved.approval_ref).status,'approved');
 }
});
test('schema16显式迁移到17保持审阅原件，未升级库不提供批准入口',async t=>{
 const x=await setup(t,{revision:16}),a=await authenticated(t,x.f);
 assert.throws(()=>a.sessions.approveExtension(a.token(),x.approvalRequest),/extension_management_unavailable/);a.real.stop();x.f.close();
 const migrated=await migrateStorage(x.f.dir,17);assert.equal(migrated.schema_revision,'17');assert.equal(migrated.steps.length,1);
 assert.deepEqual(x.f.reopen().extensionInstallations.reviews.query('review'),x.reviewed);
});
