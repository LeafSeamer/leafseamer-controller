import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import canonicalize from 'canonicalize';
import {createDeviceModule,simulatorControlCatalog} from '../dist/simulator-control-module.mjs';
import {decodeCapabilityTemplate} from '../dist/sdk/capability-template.mjs';
const primitive_id='simulator_value_set',action_id='leafseamer.simulator.value.set';
async function setup(){
 const abort=new AbortController(),module=createDeviceModule({configuration:{},device_ids:['a','b'],signal:abort.signal}),input={device_id:'a',device_session_id:'a.1',signal:abort.signal};
 const identity=await module.connectReadOnly(input);return {abort,module,input,identity};
}

test('可安装能力声明与模块目录绑定同一动作及Schema，声明不等于运行批准',async()=>{
 const template=await decodeCapabilityTemplate(fs.readFileSync(new URL('../dist/simulator-control-capability.json',import.meta.url)));
 const catalog=simulatorControlCatalog();assert.deepEqual(template.state_schema,catalog.state_schema);
 assert.deepEqual(template.actions.map(v=>v.action_id),catalog.action_ids);
 const action=template.actions[0];assert.equal(action.retry.mode,'never');assert.equal(action.completion.default,'effect_verified');
 for(const schema of [template.state_schema,action.parameters_schema,action.result_schema,action.preconditions_schema])
  assert.equal(schema.digest,'sha256:'+crypto.createHash('sha256').update(canonicalize(schema.document)).digest('hex'));
 assert.deepEqual(action.platforms.map(v=>v.status),['untested','untested']);
 const policy=JSON.parse(fs.readFileSync(new URL('../dist/simulator-control-policy.json',import.meta.url)));
 assert.equal(policy.transport,'memory');assert.deepEqual(policy.external_resources,[]);assert.deepEqual(policy.writes,catalog.action_ids);
});

test('内存模拟器从纯编码到单次写入及新采样闭环，目录与真实状态Schema一致',async()=>{
 const {module,input,identity}=await setup(),catalog=await module.proposeCatalog({...input,identity});
 assert.deepEqual(catalog,simulatorControlCatalog());assert.deepEqual(catalog.action_ids,[action_id]);
 assert.equal(catalog.state_schema.digest,'sha256:'+crypto.createHash('sha256').update(canonicalize(catalog.state_schema.document)).digest('hex'));
 assert.deepEqual(await module.captureBaseline(input),{value:0,sample_sequence:'1',write_sequence:'0'});
 const bytes=await module.execution.encodePrimitive({...input,primitive_id,parameters:{value:-42}});
 assert.equal(Buffer.from(bytes).toString('hex'),'4c534d31ffffffd6');
 assert.deepEqual(await module.captureBaseline(input),{value:0,sample_sequence:'2',write_sequence:'0'});
 assert.deepEqual(await module.execution.writePrimitive({...input,bytes}),{bytes_written:8,response:{value:-42,write_sequence:'1'}});
 assert.deepEqual(await module.captureBaseline(input),{value:-42,sample_sequence:'3',write_sequence:'1'});
 // 单次传输观察没有命令完成或资源释放裁决。
 assert.deepEqual(Object.keys(await module.execution.writePrimitive({...input,bytes})).sort(),['bytes_written','response']);
 assert.deepEqual(await module.captureBaseline(input),{value:-42,sample_sequence:'4',write_sequence:'2'});
});

test('整数边界编码无损，错误参数及损坏包不产生副作用或隐式重试',async()=>{
 const {module,input}=await setup();
 for(const [value,hex] of [[-2147483648,'4c534d3180000000'],[2147483647,'4c534d317fffffff'],[0,'4c534d3100000000']]){
  const bytes=await module.execution.encodePrimitive({...input,primitive_id,parameters:{value}});assert.equal(Buffer.from(bytes).toString('hex'),hex);
  const result=await module.execution.writePrimitive({...input,bytes});assert.equal(result.response.value,value);
 }
 for(const parameters of [{},{value:1,extra:true},{value:-0},{value:0.5},{value:NaN},{value:Infinity},{value:2147483648},{value:-2147483649},{value:'1'}])
  await assert.rejects(module.execution.encodePrimitive({...input,primitive_id,parameters}),/simulator_parameters/);
 await assert.rejects(module.execution.encodePrimitive({...input,primitive_id:'other',parameters:{value:1}}),/simulator_primitive/);
 for(const bytes of [new Uint8Array(),new Uint8Array(9),new Uint8Array(8),[76,83,77,49,0,0,0,1]])
  await assert.rejects(module.execution.writePrimitive({...input,bytes}),/simulator_packet/);
 assert.deepEqual(await module.captureBaseline(input),{value:0,sample_sequence:'1',write_sequence:'3'});
});

test('状态隔离到设备；重连保持设备值但旧session、错身份及中止不能写入',async()=>{
 const {module,input,abort,identity}=await setup(),bytes=await module.execution.encodePrimitive({...input,primitive_id,parameters:{value:7}});
 await module.execution.writePrimitive({...input,bytes});
 const other={...input,device_id:'b',device_session_id:'b.1'};await module.connectReadOnly(other);
 assert.deepEqual(await module.captureBaseline(other),{value:0,sample_sequence:'1',write_sequence:'0'});
 await assert.rejects(module.proposeCatalog({...input,identity:{...identity,model:'physical.device'}}),/simulator_identity/);
 await module.stopReadOnly(input);
 await assert.rejects(module.execution.writePrimitive({...input,bytes}),/simulator_session/);
 await assert.rejects(module.connectReadOnly(input),/simulator_session/);
 const next={...input,device_session_id:'a.2'};await module.connectReadOnly(next);
 assert.deepEqual(await module.captureBaseline(next),{value:7,sample_sequence:'1',write_sequence:'1'});
 await assert.rejects(module.execution.writePrimitive({...input,bytes}),/simulator_session/);
 const operation=new AbortController();operation.abort();await assert.rejects(module.execution.writePrimitive({...next,signal:operation.signal,bytes}),/simulator_unavailable/);
 assert.equal((await module.captureBaseline(next)).write_sequence,'1');abort.abort();
 await assert.rejects(module.execution.writePrimitive({...next,bytes}),/simulator_unavailable/);
 await assert.rejects(module.captureBaseline(next),/simulator_unavailable/);
});

test('调用边界复制字节且样本/目录不暴露内部状态，实例重建不继承旧设备会话',async()=>{
 const {module,input,identity}=await setup(),bytes=await module.execution.encodePrimitive({...input,primitive_id,parameters:{value:3}});
 const result=module.execution.writePrimitive({...input,bytes});bytes.fill(0);assert.equal((await result).response.value,3);
 const sample=await module.captureBaseline(input);sample.value=100;
 const catalog=await module.proposeCatalog({...input,identity});catalog.action_ids.push('other');catalog.state_schema.document.properties.value.maximum=0;
 assert.equal((await module.captureBaseline(input)).value,3);assert.deepEqual((await module.proposeCatalog({...input,identity})).action_ids,[action_id]);
 const fresh=createDeviceModule({configuration:{},device_ids:['a'],signal:input.signal});
 await assert.rejects(fresh.execution.writePrimitive({...input,bytes:new Uint8Array([76,83,77,49,0,0,0,1])}),/simulator_session/);
 assert.throws(()=>createDeviceModule({configuration:{value:1},device_ids:['a'],signal:input.signal}),/simulator_configuration/);
 assert.throws(()=>createDeviceModule({configuration:{},device_ids:['a','a'],signal:input.signal}),/simulator_configuration/);
});
