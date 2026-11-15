import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=process.env.LEAFSEAMER_CONTROLLER_PACKAGE_UNDER_TEST??fileURLToPath(new URL('../',import.meta.url)),load=name=>import(pathToFileURL(path.join(root,'dist',name)));
const {createSubscriptionEndpoint}=await load('service-subscription-http.mjs'),{createHttpAdapter}=await load('sdk/http.mjs'),{contractSelection:selection}=await load('sdk/index.mjs');
const headers=[['x-leafseamer-contract',selection.contract_id],['x-leafseamer-contract-digest',selection.contract_digest]],route='/internal/subscriptions/subscription_1';
test('订阅错误状态与响应正文共同通过固定SDK，409使用conflict',async()=>{
 const adapter=createHttpAdapter(selection),request=adapter.prepareRequest('controller','GET',route,headers);
 for(const [reason,status,code]of [['subscription_slot_busy',409,'conflict'],['subscription_revision',409,'conflict'],['subscription_capacity',429,'capacity_exceeded'],['subscription_not_found',404,'not_found_or_invisible'],['service_token_policy_invalid',403,'forbidden'],['event_scope_inactive',503,'source_unavailable']]){
  const endpoint=createSubscriptionEndpoint({store:{access(){throw Object.assign(new Error(reason),{code:reason});}}});
  const reply=await endpoint.handle({bindingId:'binding',socket:null,method:'GET',path:route,headers,body:Buffer.alloc(0)});
  assert.equal(reply.status,status);const value=(await adapter.decodeResponse(reply.body,adapter.prepareResponse(request,String(status),reply.headers))).value;
  assert.equal(value.code,code);reply.beforeSend();
 }
});
test('不合模型的创建正文返回400且不进入持久层',async()=>{
 let calls=0;const endpoint=createSubscriptionEndpoint({store:{create(){calls++;}}}),body=Buffer.from('{"owner":"client"}'),pairs=[...headers,['content-type','application/json'],['content-length',String(body.length)]];
 const reply=await endpoint.handle({bindingId:'binding',socket:null,method:'POST',path:'/internal/subscriptions',headers:pairs,body});
 assert.equal(reply.status,400);assert.equal(JSON.parse(reply.body).code,'invalid_request');assert.equal(calls,0);
});
test('关闭使用固定SDK的查询参数且拒绝正文',async()=>{
 let calls=0;const endpoint=createSubscriptionEndpoint({store:{access(binding,socket,key,close){calls++;assert.equal(key,'subscription_1');assert.deepEqual(close,{expected_revision:'2'});throw Object.assign(new Error(),{code:'subscription_revision'});}}});
 const input={bindingId:'binding',socket:null,method:'DELETE',path:route+'?expected_revision=2',headers,body:Buffer.alloc(0)};
 assert.equal((await endpoint.handle(input)).status,409);assert.equal(calls,1);
 assert.equal((await endpoint.handle({...input,body:Buffer.from('{}')})).status,400);assert.equal(calls,1);
});
