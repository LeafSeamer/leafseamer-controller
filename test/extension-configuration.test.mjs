import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {validateConfiguration} from '../dist/configuration-validator.mjs';
import {migrateStorage} from '../dist/storage.mjs';
import {setup,fixture,inspect,hash} from './fixtures/extension-installation.mjs';
const bytes=value=>Buffer.from(JSON.stringify(value));
const schema={type:'object',properties:{count:{type:'integer',minimum:1,maximum:9},name:{type:'string',default:'unchanged'}},required:['count'],additionalProperties:false};
async function prepared(t,{afterSchema=()=>{}}={}){
  const f=await setup(t,14),host=fixture(f.store.identity),raw=bytes(schema),file=host.content.inventory.files.find(f=>f.file_id==='config');
  const describe=host.describeIntake;let schemaRead=false;host.describeIntake=async query=>schemaRead&&host.revoked?{status:'unavailable',content:null}:describe(query);
  Object.assign(file,{size_bytes:String(raw.length),digest:'sha256:'+crypto.createHash('sha256').update(raw).digest('hex')});
  host.content.manifest.inventory_digest=hash(host.content.inventory);host.content.receipt.artifact_set_digest=hash(host.content.inventory);
  host.content.receipt.manifest_digest=hash(host.content.manifest);host.content.receipt.file_inventory_digest=hash(host.content.inventory);host.content.intake_ref.digest=hash(host.content.receipt);
  host.describeConfigurationSchema=async()=>{schemaRead=true;afterSchema(host);return {status:'available',content:{format:'leafseamer-configuration-schema/1',intake_ref:host.content.intake_ref,
    manifest_digest:host.content.receipt.manifest_digest,artifact_set_digest:host.content.receipt.artifact_set_digest,file,bytes:raw}};};
  const api=f.store.extensionInstallations;api.bindSource(host);const slot=api.createSlot({request_id:'slot',extension_id:host.content.manifest.extension_id});
  const installed=await api.stage({request_id:'stage',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:host.content.intake_ref});
  return {f,host,api,installed,request:{request_id:'configuration',installation_ref:installed.installation_ref,expected_revision:'0',bytes:bytes({count:2})}};
}
test('固定子进程支持Schema约束和原始整数语义，不补默认值或读取外部引用',{timeout:20000},async()=>{
  assert.throws(()=>new Function('return 1'),EvalError);
  assert.deepEqual(await validateConfiguration(bytes(schema),bytes({count:2})),{count:2});
  for(const value of [{count:0},{count:2,extra:1},{count:'2'}])await assert.rejects(validateConfiguration(bytes(schema),bytes(value)),{code:'extension_configuration_schema_rejected'});
  await assert.rejects(validateConfiguration(bytes(schema),Buffer.from('{"count":2,"count":3}')));
  await assert.rejects(validateConfiguration(bytes({type:'integer'}),Buffer.from('9007199254740993')),{code:'extension_configuration_integer_range'});
  await assert.rejects(validateConfiguration(bytes({$ref:'https://schema.invalid/schema.json'}),bytes({})),{code:'extension_configuration_external_reference'});
  await assert.rejects(validateConfiguration(bytes({type:'object',unexpectedKeyword:true}),bytes({})),{code:'extension_configuration_schema_compile'});
  const unusual=Buffer.from('{"type":"object","properties":{"__proto__":{"type":"integer"}},"required":["__proto__"],"additionalProperties":false}');
  assert.equal((await validateConfiguration(unusual,Buffer.from('{"__proto__":4}'))).__proto__,4);
  await assert.rejects(validateConfiguration(unusual,Buffer.from('{"__proto__":"wrong"}')));
});
test('配置校验耗时预算可终止阻塞正则，核心事件循环继续运行',{timeout:10000},async()=>{
  let ticks=0;const timer=setInterval(()=>ticks++,20);
  try{await assert.rejects(validateConfiguration(bytes({type:'string',pattern:'^(a+)+$'}),bytes('a'.repeat(32000)+'!')),{code:'extension_configuration_timeout'});}
  finally{clearInterval(timer);}
  assert.ok(ticks>20);assert.deepEqual(await validateConfiguration(bytes({type:'object'}),bytes({})),{});
});
test('配置原件保持幂等和CAS，旧Ref保留历史且新修订绑定完整Schema',{timeout:20000},async t=>{
  const {f,host,api,installed,request}=await prepared(t),configs=api.configurations;
  const first=await configs.configure(request);assert.equal(first.configuration_ref.revision,'1');assert.deepEqual(first.record.configuration,{count:2});
  assert.deepEqual(await configs.configure(request),first);
  await assert.rejects(configs.configure({...request,bytes:bytes({count:3})}),{code:'extension_configuration_conflict'});
  await assert.rejects(configs.configure({...request,request_id:'stale'}),{code:'extension_configuration_stale'});
  const second=await configs.configure({...request,request_id:'new',expected_revision:'1',bytes:bytes({count:3})});
  assert.equal(second.configuration_ref.object_id,first.configuration_ref.object_id);assert.equal(second.configuration_ref.revision,'2');
  assert.deepEqual(configs.current(installed.installation_ref),second);f.close();
  const reopened=f.reopen().extensionInstallations;reopened.bindSource(host);assert.deepEqual(reopened.configurations.query(request.request_id),first);
  assert.deepEqual(reopened.configurations.current(installed.installation_ref),second);
});
test('配置写集逐写失败全部回滚，当前资格在编译后失效不能提交',{timeout:20000},async t=>{
  for(const table of ['extension_configuration','extension_configuration_head','extension_configuration_operation']){
    const {f,host,request}=await prepared(t);f.close();inspect(f.dir,db=>db.exec(`CREATE TRIGGER injected BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'synthetic_failure');END`));
    const api=f.reopen().extensionInstallations;api.bindSource(host);await assert.rejects(api.configurations.configure(request),/synthetic_failure/);f.close();
    inspect(f.dir,db=>{for(const name of ['extension_configuration','extension_configuration_head','extension_configuration_operation'])assert.equal(db.prepare('SELECT count(*) FROM '+name).pluck().get(),0);});
  }
  const {api,request}=await prepared(t,{afterSchema:host=>{host.revoked=true;}});
  await assert.rejects(api.configurations.configure(request),{code:'extension_configuration_source_unavailable'});assert.equal(api.configurations.query(request.request_id),null);
});
test('schema13明确迁移到14，已有候选原件不改写',async t=>{
  const f=await setup(t,13),host=fixture(f.store.identity),api=f.store.extensionInstallations;api.bindSource(host);assert.equal(api.configurations,null);
  const slot=api.createSlot({request_id:'slot',extension_id:host.content.manifest.extension_id});
  const installed=await api.stage({request_id:'stage',slot_id:slot.record.slot_id,expected_slot_revision:'1',intake_ref:host.content.intake_ref});f.close();
  const migrated=await migrateStorage(f.dir,14);assert.equal(migrated.schema_revision,'14');assert.equal(migrated.steps.length,1);
  const upgraded=f.reopen().extensionInstallations;assert.deepEqual(upgraded.query('stage'),installed);assert.equal(upgraded.configurations.current(installed.installation_ref),null);
});
