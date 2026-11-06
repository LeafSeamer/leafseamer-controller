import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {authenticated} from './fixtures/extension-auth.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {ref,digest} from '../dist/auth-clock-value.mjs';
import {collectAuthorizationDependencies,currentAuthorizationDependencies} from '../dist/authorization-dependencies.mjs';
const request=()=>crypto.randomUUID();
async function fixture(t,{revision=36,inject=null}={}){
 const f=await setup(t,revision),e=f.store.enrollment.begin();
 await f.store.enrollment.complete({token_id:e.token_id,secret:e.secret,login:'role.test',password:'Synthetic-role-password-123',mode:'standalone'});
 if(inject){f.close();inspect(f.dir,db=>db.exec(inject));f.reopen();}
 const auth=await authenticated(t,f,{grant:false});return {...f,get store(){return f.store;},...auth};
}
function approved(f){
 const create={request_id:request(),display_name:'本机测试服务',purpose:'controller_evaluator'};
 const subject=f.sessions.createServicePrincipal(f.auth,create);assert.equal(subject.state,'disabled');assert.equal(subject.approval_ref,null);
 const now=f.real.current(),approve={request_id:request(),principal_id:subject.id,expected_revision:subject.revision,audiences:[f.store.identity.service_id],
  permissions:['identity.read'],device_ids:[],not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)};
 const accepted=f.sessions.approveServicePrincipal(f.auth,approve);
 return {create,subject,approve,...accepted};
}
function staged(f){const a=approved(f),stage={request_id:request(),principal_id:a.principal.id,expected_revision:a.principal.revision,
 approval_ref:ref(a.approval),expires_ns:String(BigInt(f.real.current().upper_ns)+1800000000000n)};
 return {...a,stage,...f.sessions.createServiceCredential(f.auth,stage)};
}
test('服务主体明确批准、一次秘密交付、持有证明与人员激活分开；重投不产生第二身份',async t=>{
 const f=await fixture(t),s=staged(f);assert.equal(s.credential.state,'staged');assert.equal(s.secret_delivery,'delivered');
 assert.deepEqual(f.sessions.createServicePrincipal(f.auth,s.create),s.subject);
 assert.throws(()=>f.sessions.createServicePrincipal(f.auth,{...s.create,display_name:'变更'}),e=>e.code==='service_identity_conflict');
 const retry=f.sessions.createServiceCredential(f.auth,s.stage);assert.equal(retry.credential.id,s.credential.id);assert.equal(retry.secret_delivery,'unavailable');assert.equal('secret'in retry,false);
 const proofInput={credential_id:s.credential.id,proof_request_id:request(),secret:s.secret};
 assert.throws(()=>f.sessions.proveServiceCredential({...proofInput,secret:'A'.repeat(43)}),e=>e.code==='service_identity_credential_invalid');
 const proof=f.sessions.proveServiceCredential(proofInput);
 assert.deepEqual(f.sessions.proveServiceCredential({...proofInput,proof_request_id:request()}),proof);
 const proven=f.sessions.getServiceCredential(f.auth,s.credential.id);assert.equal(proven.state,'proven');
 const activation={request_id:request(),credential_id:proven.id,expected_revision:proven.revision,approval_ref:proven.approval_ref,proof_ref:ref(proof)};
 assert.throws(()=>f.sessions.activateServiceCredential(f.auth,{...activation,proof_ref:{...ref(proof),id:request()}}),e=>e.code==='service_identity_proof_required');
 const active=f.sessions.activateServiceCredential(f.auth,activation);assert.equal(active.state,'active');
 assert.deepEqual(f.sessions.activateServiceCredential(f.auth,activation),active);
 assert.throws(()=>f.sessions.createServiceCredential(f.auth,{...s.stage,request_id:request()}),e=>e.code==='service_identity_rotation_unavailable');
 const revoked=f.sessions.revokeServiceCredential(f.auth,{request_id:request(),credential_id:active.id,expected_revision:active.revision});assert.equal(revoked.state,'revoked');
 assert.throws(()=>f.sessions.proveServiceCredential(proofInput),e=>e.code==='service_identity_credential_invalid');
 assert.throws(()=>f.sessions.verifyToken({token_id:s.credential.id,secret:s.secret},f.store.identity.service_id),e=>e.code==='token_invalid');
 f.real.stop();f.close();inspect(f.dir,db=>{
  assert.equal(db.prepare("SELECT count(*) FROM subject WHERE kind='service'").pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM local_principal').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM auth_session').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM service_credential').pluck().get(),1);
  assert.equal(db.prepare('SELECT count(*) FROM service_credential_proof').pluck().get(),1);
  const bodies=['service_identity_operation','service_principal_revision','service_approval','service_credential_revision','service_credential_proof']
   .flatMap(table=>db.prepare('SELECT body_jcs FROM '+table).pluck().all()).join('\n');
  assert.equal(bodies.includes(s.secret),false);assert.equal(bodies.includes('verifier'),false);assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('暂存凭据到期等号永久失效，早期认证区间不能复活；未批准主体不能建凭据',async t=>{
 const f=await fixture(t),s=staged(f);
 const proof=f.sessions.proveServiceCredential({credential_id:s.credential.id,proof_request_id:request(),secret:s.secret});
 f.state.offset=BigInt(s.credential.stage_deadline_ns)-BigInt(f.real.current().upper_ns);
 assert.throws(()=>f.sessions.proveServiceCredential({credential_id:s.credential.id,proof_request_id:request(),secret:s.secret}),e=>e.code==='service_identity_credential_expired');
 f.state.offset=0n;assert.equal(f.sessions.getServiceCredential(f.auth,s.credential.id).state,'expired');
 assert.throws(()=>f.sessions.activateServiceCredential(f.auth,{request_id:request(),credential_id:s.credential.id,expected_revision:'2',approval_ref:s.credential.approval_ref,proof_ref:ref(proof)}),e=>e.code==='service_identity_credential_expired');
 assert.throws(()=>f.sessions.proveServiceCredential({credential_id:s.credential.id,proof_request_id:request(),secret:s.secret}),e=>e.code==='service_identity_credential_expired');
 const disabled=f.sessions.createServicePrincipal(f.auth,{request_id:request(),display_name:'未批准',purpose:'integration'});
 assert.throws(()=>f.sessions.createServiceCredential(f.auth,{...s.stage,request_id:request(),principal_id:disabled.id,expected_revision:disabled.revision}),e=>e.code==='service_identity_approval_required');
});
test('人员管理权限与近期认证分别阻止服务主体变更，设备范围不能指向未登记设备',async t=>{
 const f=await fixture(t),a=approved(f),create={request_id:request(),display_name:'拒绝',purpose:'integration'};
 assert.throws(()=>f.sessions.approveServicePrincipal(f.auth,{...a.approve,request_id:request(),principal_id:f.sessions.createServicePrincipal(f.auth,create).id,
  device_ids:[request()]}),e=>e.code==='service_identity_scope');
 f.state.offset=300000000000n;assert.throws(()=>f.sessions.createServicePrincipal(f.auth,{...create,request_id:request()}),e=>e.code==='service_identity_management_denied');
 f.state.offset=0n;const p=f.sessions.localPermissions(f.auth);
 f.sessions.replaceLocalPermissions(f.auth,{request_id:request(),principal_id:p.principal_id,expected_revision:p.revision,permissions:p.permissions.filter(v=>v!=='auth.manage')});
 assert.throws(()=>f.sessions.createServicePrincipal(f.auth,{...create,request_id:request()}),e=>e.code==='service_identity_management_denied');
});
for(const table of ['service_principal_revision','service_principal_head','service_identity_operation'])test('服务主体创建缺写'+table+'整笔回滚',async t=>{
 const f=await fixture(t,{inject:`CREATE TRIGGER omit_service BEFORE INSERT ON ${table} BEGIN SELECT RAISE(IGNORE); END;`});
 assert.throws(()=>f.sessions.createServicePrincipal(f.auth,{request_id:request(),display_name:'回滚',purpose:'integration'}),e=>e.code==='service_identity_storage');
 f.real.stop();f.close();inspect(f.dir,db=>{
  assert.equal(db.prepare("SELECT count(*) FROM subject WHERE kind='service'").pluck().get(),0);
  for(const name of ['service_principal_revision','service_principal_head','service_identity_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});
test('暂存凭据提交缺写不留下验证值或可交付结果；修复后原请求可首次提交',async t=>{
 const f=await fixture(t),a=approved(f),stage={request_id:request(),principal_id:a.principal.id,expected_revision:a.principal.revision,
  approval_ref:ref(a.approval),expires_ns:String(BigInt(f.real.current().upper_ns)+1800000000000n)};
 f.real.stop();f.close();inspect(f.dir,db=>db.exec("CREATE TRIGGER omit_credential_commit BEFORE INSERT ON service_identity_operation WHEN NEW.kind='credential' BEGIN SELECT RAISE(IGNORE); END;"));
 f.reopen();const first=await authenticated(t,f,{grant:false});
 assert.throws(()=>first.sessions.createServiceCredential(first.auth,stage),e=>e.code==='service_identity_storage');first.real.stop();f.close();
 inspect(f.dir,db=>{for(const table of ['service_credential','service_credential_revision','service_credential_head'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  db.exec('DROP TRIGGER omit_credential_commit');assert.deepEqual(db.pragma('foreign_key_check'),[]);});
 f.reopen();const second=await authenticated(t,f,{grant:false}),created=second.sessions.createServiceCredential(second.auth,stage);
 assert.equal(created.secret_delivery,'delivered');assert.equal(created.credential.state,'staged');
 assert.equal(second.sessions.createServiceCredential(second.auth,stage).secret_delivery,'unavailable');
});

test('schema35到36保留原人员身份字节；证明缺写不能留下proven状态',async t=>{
 const f=await fixture(t,{revision:35});f.real.stop();f.close();let original;
 inspect(f.dir,db=>{original=db.prepare('SELECT * FROM subject').raw().all();});
 await migrateStorage(f.dir,36);inspect(f.dir,db=>assert.deepEqual(db.prepare('SELECT * FROM subject').raw().all(),original));
 f.reopen();const fresh=await authenticated(t,f,{grant:false}),current={...f,...fresh},s=staged(current);fresh.real.stop();f.close();
 inspect(f.dir,db=>db.exec('CREATE TRIGGER omit_proof BEFORE INSERT ON service_credential_proof BEGIN SELECT RAISE(IGNORE); END;'));
 f.reopen();const restarted=await authenticated(t,f,{grant:false});
 assert.throws(()=>restarted.sessions.proveServiceCredential({credential_id:s.credential.id,proof_request_id:request(),secret:s.secret}),e=>e.code==='service_identity_storage');
 assert.equal(restarted.sessions.getServiceCredential(restarted.auth,s.credential.id).state,'staged');restarted.real.stop();f.close();
 inspect(f.dir,db=>{assert.equal(db.prepare('SELECT count(*) FROM service_credential_proof').pluck().get(),0);
  assert.equal(db.prepare('SELECT count(*) FROM service_credential_revision').pluck().get(),1);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});

test('主体整体撤销关闭活动凭据和存量令牌，重投查原且不影响另一个服务主体',async t=>{
 const f=await fixture(t,{revision:39}),s=staged(f),other=staged(f),sessions=f.sessions;
 const proof=sessions.proveServiceCredential({credential_id:s.credential.id,secret:s.secret,proof_request_id:request()});
 const active=sessions.activateServiceCredential(f.auth,{request_id:request(),credential_id:s.credential.id,expected_revision:'2',approval_ref:s.credential.approval_ref,proof_ref:ref(proof)});
 sessions.approveLocalServicePolicy(f.auth,{request_id:request(),principal_id:s.principal.id,subject_ref:ref(s.principal),approval_ref:ref(s.approval),
  audience:f.store.identity.service_id,permissions:['identity.read'],device_ids:[],not_before_ns:s.approval.not_before_ns,expires_ns:s.approval.expires_ns});
 const tokenRequest={credential_id:active.id,secret:s.secret,request_id:request(),audience:f.store.identity.service_id,permissions:['identity.read'],device_ids:[]};
 const token=sessions.issueServiceToken(tokenRequest),revoke={request_id:request(),principal_id:s.principal.id,expected_revision:s.principal.revision};
 const result=sessions.revokeServicePrincipal(f.auth,revoke);assert.equal(result.principal.state,'revoked');assert.equal(result.revoked_credential_refs.length,1);
 assert.deepEqual(sessions.revokeServicePrincipal(f.auth,revoke),result);
 assert.throws(()=>sessions.revokeServicePrincipal(f.auth,{...revoke,expected_revision:'999'}),e=>e.code==='service_identity_conflict');
 assert.equal(sessions.getServiceCredential(f.auth,active.id).state,'revoked');
 assert.throws(()=>sessions.verifyServiceToken({token_id:token.binding.id,secret:token.secret}),e=>e.code==='service_token_invalid');
 assert.throws(()=>sessions.issueServiceToken({...tokenRequest,request_id:request()}),e=>e.code==='service_token_credential_invalid');
 assert.throws(()=>sessions.createServiceCredential(f.auth,{...s.stage,request_id:request(),expected_revision:result.principal.revision}),e=>e.code==='service_identity_approval_required');
 assert.equal(sessions.getServicePrincipal(f.auth,other.principal.id).state,'active');assert.equal(sessions.getServiceCredential(f.auth,other.credential.id).state,'staged');
 assert.equal(sessions.localPermissions(f.auth).state,'active');
});

test('主体整体撤销覆盖disabled及staged/proven凭据，终态不能重新批准',async t=>{
 const f=await fixture(t,{revision:39}),s=f.sessions,disabled=s.createServicePrincipal(f.auth,{request_id:request(),display_name:'禁用主体',purpose:'integration'});
 const closed=s.revokeServicePrincipal(f.auth,{request_id:request(),principal_id:disabled.id,expected_revision:disabled.revision});assert.equal(closed.principal.state,'revoked');assert.deepEqual(closed.revoked_credential_refs,[]);
 for(const proven of [false,true]){
  const value=staged(f);if(proven)s.proveServiceCredential({credential_id:value.credential.id,secret:value.secret,proof_request_id:request()});
  const result=s.revokeServicePrincipal(f.auth,{request_id:request(),principal_id:value.principal.id,expected_revision:value.principal.revision});
  assert.equal(result.revoked_credential_refs.length,1);assert.equal(s.getServiceCredential(f.auth,value.credential.id).state,'revoked');
  assert.throws(()=>s.proveServiceCredential({credential_id:value.credential.id,secret:value.secret,proof_request_id:request()}),e=>e.code==='service_identity_credential_invalid');
  assert.throws(()=>s.approveServicePrincipal(f.auth,{...value.approve,request_id:request(),expected_revision:result.principal.revision}),e=>e.code==='service_identity_approval_change_unavailable');
 }
});

for(const table of ['service_principal_revision','service_principal_head','service_credential_revision','service_credential_head','service_identity_operation'])test('主体整体撤销缺写'+table+'回滚主体与凭据全部修订',async t=>{
 const f=await fixture(t,{revision:39}),s=staged(f);f.real.stop();f.close();
 const names=['service_principal_revision','service_principal_head','service_credential_revision','service_credential_head','service_identity_operation'];let before;
 inspect(f.dir,db=>{before=names.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all());
  db.exec(`CREATE TRIGGER omit_principal_revoke BEFORE ${table.endsWith('_head')?'UPDATE':'INSERT'} ON ${table} ${table==='service_identity_operation'?"WHEN NEW.kind='revoke'":''} BEGIN SELECT RAISE(IGNORE); END;`);});
 f.reopen();const a=await authenticated(t,f,{grant:false});
 assert.throws(()=>a.sessions.revokeServicePrincipal(a.auth,{request_id:request(),principal_id:s.principal.id,expected_revision:s.principal.revision}),e=>e.code==='service_identity_storage');a.real.stop();f.close();
 inspect(f.dir,db=>{assert.deepEqual(names.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()),before);assert.deepEqual(db.pragma('foreign_key_check'),[]);});
});

test('schema38到39保留主体凭据原件，整体撤销要求显式升级',async t=>{
 const f=await fixture(t,{revision:38}),s=staged(f),r={request_id:request(),principal_id:s.principal.id,expected_revision:s.principal.revision};
 assert.throws(()=>f.sessions.revokeServicePrincipal(f.auth,r),e=>e.code==='service_identity_principal_revocation_migration');f.real.stop();f.close();let before;
 inspect(f.dir,db=>{before=db.prepare('SELECT * FROM service_principal_revision').raw().all();});await migrateStorage(f.dir,39);
 inspect(f.dir,db=>assert.deepEqual(db.prepare('SELECT * FROM service_principal_revision').raw().all(),before));
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.equal(a.sessions.revokeServicePrincipal(a.auth,r).principal.state,'revoked');assert.equal(a.sessions.getServiceCredential(a.auth,s.credential.id).state,'revoked');
});

test('schema39到40保留身份历史，不补造恢复请求或自动授予恢复权限',async t=>{
 const f=await fixture(t,{revision:39});staged(f);
 assert.throws(()=>f.sessions.requestDeviceAuthorizationRecovery({},{}),e=>e.code==='device_recovery_unavailable');
 assert.equal(f.sessions.localPermissions(f.auth).permissions.includes('device.recover'),false);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','local_permission_revision'],before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()));
 const upgraded=await migrateStorage(f.dir,40);assert.equal(upgraded.schema_revision,'40');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()),before);
  for(const table of ['device_recovery_request','device_recovery_authorization','device_recovery_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.equal(a.sessions.localPermissions(a.auth).permissions.includes('device.recover'),false);
});

test('schema40到41保留身份及恢复表，不补造消费或策略选择',async t=>{
 const f=await fixture(t,{revision:40});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','device_recovery_request','device_recovery_authorization','device_recovery_commit'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()));
 assert.equal((await migrateStorage(f.dir,41)).schema_revision,'41');
 inspect(f.dir,db=>{assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()),before);
  assert.equal(db.prepare('SELECT count(*) FROM device_recovery_consumption').pluck().get(),0);
  assert.equal(db.prepare("SELECT count(*) FROM device_authorization_state WHERE json_extract(body_jcs,'$.status')='policy_selected'").pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.equal(a.sessions.localPermissions(a.auth).permissions.includes('device.recover'),false);
});

test('schema41到42保留身份历史，不补造人员挑战及响应',async t=>{
 const f=await fixture(t,{revision:41});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','local_permission_revision','execution_manual_authority','execution_manual_authority_commit'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()));
 assert.equal((await migrateStorage(f.dir,42)).schema_revision,'42');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()),before);
  for(const table of ['manual_execution_challenge','manual_execution_challenge_commit','manual_execution_challenge_response'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
 f.reopen();const a=await authenticated(t,f,{grant:false});assert.equal(a.sessions.localPermissions(a.auth).permissions.includes('device.recover'),false);
});

test('schema42到43保留身份与挑战表，不补造设备授权Evidence',async t=>{
 const f=await fixture(t,{revision:42});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','manual_execution_challenge','manual_execution_challenge_commit','manual_execution_challenge_response'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()));
 assert.equal((await migrateStorage(f.dir,43)).schema_revision,'43');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1,2').raw().all()),before);
  for(const table of ['device_authorization_revocation_cut','device_authorization_evidence','device_authorization_evidence_commit','device_authorization_evidence_head'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema43到44保留身份与授权表，不补造初始资源证据',async t=>{
 const f=await fixture(t,{revision:43});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','device_authorization_evidence','device_authorization_evidence_head'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()));
 assert.equal((await migrateStorage(f.dir,44)).schema_revision,'44');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()),before);
  for(const table of ['device_initial_resource','device_initial_resource_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema47到48保留身份和控制原件，未确认OPEN不能补造Ready',async t=>{
 const f=await fixture(t,{revision:47});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','control_state_source','execution_initial_open_ack'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()));
 assert.equal((await migrateStorage(f.dir,48)).schema_revision,'48');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()),before);
  assert.equal(db.prepare('SELECT count(*) FROM device_initial_ready').pluck().get(),0);
  assert.throws(()=>db.prepare('INSERT INTO device_initial_ready VALUES(?,?,?,?,?,?,?)').run(request(),request(),request(),3,'{}','sha256:'+'0'.repeat(64),'{}'),/initial_ready_parent/);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema46到47保留身份及旧执行表，不补造OPEN原件',async t=>{
 const f=await fixture(t,{revision:46});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','execution_frame_record','execution_effect_commit','device_initial_open'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()));
 assert.equal((await migrateStorage(f.dir,47)).schema_revision,'47');
 inspect(f.dir,db=>{
  // 空旧执行表增加生成列；身份与已存计划正文保持不变。
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()),before);
  for(const name of ['execution_initial_open_dispatch','execution_initial_open_ack','execution_open_frame'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema45到46保留身份与开放计划表，模块帧迁移不补造装配确认',async t=>{
 const f=await fixture(t,{revision:45});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','device_module_frame','device_module_frame_commit','device_initial_open','device_initial_open_commit'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()));
 assert.equal((await migrateStorage(f.dir,46)).schema_revision,'46');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()),before);
  const definition=db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='device_module_frame'").pluck().get();
  assert.match(definition,/'BIND_EXECUTION','EXECUTION_BOUND'/);
  assert.equal(db.prepare("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND sql LIKE '%device_module_frame%'").pluck().get(),8);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('schema44到45保留身份和初始资源表，不补造开放计划',async t=>{
 const f=await fixture(t,{revision:44});staged(f);f.real.stop();f.close();
 const tables=['service_principal_revision','service_credential_revision','device_initial_resource','device_initial_resource_commit'];
 const before=inspect(f.dir,db=>tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()));
 assert.equal((await migrateStorage(f.dir,45)).schema_revision,'45');
 inspect(f.dir,db=>{
  assert.deepEqual(tables.map(n=>db.prepare('SELECT * FROM '+n+' ORDER BY 1').raw().all()),before);
  for(const table of ['device_initial_open','device_initial_open_commit'])assert.equal(db.prepare('SELECT count(*) FROM '+table).pluck().get(),0);
  assert.deepEqual(db.pragma('foreign_key_check'),[]);
 });
});

test('评估器依赖快照拒绝删项及相关撤销，无关主体不改变原快照',async t=>{
 const f=await fixture(t,{revision:39}),device=f.store.registerDevice({request_id:'dependency.device',device_kind:'simulator',display_name:'依赖范围'}).device_id;
 const p=f.sessions.createServicePrincipal(f.auth,{request_id:request(),display_name:'依赖服务',purpose:'integration'}),now=f.real.current();
 const approved=f.sessions.approveServicePrincipal(f.auth,{request_id:request(),principal_id:p.id,expected_revision:p.revision,audiences:[f.store.identity.service_id],
  permissions:['identity.read'],device_ids:[device],not_before_ns:now.lower_ns,expires_ns:String(BigInt(now.upper_ns)+3600000000000n)});
 const staged=f.sessions.createServiceCredential(f.auth,{request_id:request(),principal_id:p.id,expected_revision:approved.principal.revision,approval_ref:ref(approved.approval),expires_ns:approved.approval.expires_ns});
 const proof=f.sessions.proveServiceCredential({credential_id:staged.credential.id,secret:staged.secret,proof_request_id:request()});
 const active=f.sessions.activateServiceCredential(f.auth,{request_id:request(),credential_id:staged.credential.id,expected_revision:'2',approval_ref:ref(approved.approval),proof_ref:ref(proof)});
 const policy=f.sessions.approveDeviceEvaluatorPolicy(f.auth,{request_id:request(),principal_id:p.id,subject_ref:ref(approved.principal),approval_ref:ref(approved.approval),device_ids:[device],expires_ns:approved.approval.expires_ns});
 const service=f.store.identity,source={device_id:device,issuer_id:p.issuer_id,issuer_epoch:p.issuer_epoch,principal_id:p.id,subject_ref:ref(approved.principal),approval_ref:ref(approved.approval),credential_ref:ref(active),policy_ref:ref(policy)};
 const read=()=>inspect(f.dir,db=>db.transaction(()=>{
  const current=collectAuthorizationDependencies(db,service,'evaluator',source);if(source.authorization_dependencies)assert.deepEqual(currentAuthorizationDependencies(db,service,'evaluator',source),current);return current;
 }).immediate());
 f.real.stop();f.close();source.authorization_dependencies=read();assert.equal(source.authorization_dependencies.result,'no_matching_denial');
 assert.deepEqual(source.authorization_dependencies.records.map(r=>r.kind),['approval','credential','issuer','policy','principal','subject']);
 assert.equal(JSON.stringify(source.authorization_dependencies).includes(staged.secret),false);
 inspect(f.dir,db=>db.transaction(()=>{const {digest:_digest,...body}=source.authorization_dependencies,tampered={...body,records:body.records.filter(r=>r.kind!=='credential')};
  assert.throws(()=>currentAuthorizationDependencies(db,service,'evaluator',{...source,authorization_dependencies:{...tampered,digest:digest(tampered)}}),e=>e.code==='authorization_dependencies_changed');
 }).immediate());
 f.reopen();const a=await authenticated(t,f,{grant:false});a.sessions.createServicePrincipal(a.auth,{request_id:request(),display_name:'无关主体',purpose:'integration'});a.real.stop();f.close();read();
 f.reopen();const b=await authenticated(t,f,{grant:false});b.sessions.revokeServicePrincipal(b.auth,{request_id:request(),principal_id:p.id,expected_revision:approved.principal.revision});
 b.sessions.revokeDeviceEvaluatorPolicy(b.auth,{request_id:request(),policy_ref:ref(policy)});b.real.stop();f.close();
 inspect(f.dir,db=>db.transaction(()=>{const changed=collectAuthorizationDependencies(db,service,'evaluator',source);assert.equal(changed.result,'denied');
  assert.deepEqual(changed.denied,['credential','policy','principal']);assert.deepEqual(changed.events.map(v=>v.kind).sort(),['credential','policy','principal']);
  assert.throws(()=>currentAuthorizationDependencies(db,service,'evaluator',source),e=>e.code==='authorization_dependencies_changed');
 }).immediate());
});

test('人员依赖快照包括会话下界和减权记录，不能把旧令牌当作当前身份',async t=>{
 const f=await fixture(t,{revision:39}),p=f.sessions.localPermissions(f.auth);
 f.sessions.replaceLocalPermissions(f.auth,{request_id:request(),principal_id:p.principal_id,expected_revision:p.revision,permissions:[...p.permissions,'device.command']});
 const policy=f.sessions.localPermissions(f.auth),token=f.sessions.issueToken(f.auth,{request_id:request(),audience:f.store.identity.service_id,requested_scopes:['device.command']}),service=f.store.identity;
 f.real.stop();f.close();let source;
 inspect(f.dir,db=>db.transaction(()=>{const body=JSON.parse(db.prepare('SELECT authorization_body FROM access_token WHERE token_id=?').pluck().get(token.token.token_id).toString());
  source={binding:{device_id:request()},holder:{issuer_id:body.issuer_id,issuer_epoch:body.issuer_epoch,principal_id:body.principal_id},session_id:body.session_id,credential_id:body.credential_id,
   token_id:token.token.token_id,policy_ref:ref(policy),authorization:body};
  source.authorization_dependencies=collectAuthorizationDependencies(db,service,'manual',source);
  assert.deepEqual(source.authorization_dependencies.records.map(v=>v.kind),['access_token','credential','issuer','policy','principal','session','subject']);assert.equal(source.authorization_dependencies.result,'no_matching_denial');
 }).immediate());
 f.reopen();const a=await authenticated(t,f,{grant:false});a.sessions.logout(f.auth);const current=a.sessions.localPermissions(a.auth);
 a.sessions.replaceLocalPermissions(a.auth,{request_id:request(),principal_id:current.principal_id,expected_revision:current.revision,permissions:current.permissions.filter(v=>v!=='device.command')});a.real.stop();f.close();
 inspect(f.dir,db=>db.transaction(()=>{const changed=collectAuthorizationDependencies(db,service,'manual',source);assert.equal(changed.result,'denied');
  assert.deepEqual(changed.events.map(v=>v.kind).sort(),['policy','session']);assert.ok(changed.denied.includes('session_floor')&&changed.denied.includes('policy_floor'));
  assert.throws(()=>currentAuthorizationDependencies(db,service,'manual',source),e=>e.code==='authorization_dependencies_changed');
 }).immediate());
});
