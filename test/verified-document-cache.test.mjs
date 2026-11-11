import test from 'node:test';
import assert from 'node:assert/strict';
import {cacheVerifiedDocument} from '../dist/verified-document-cache.mjs';

test('原文及所有校验参数共同命中，返回值修改不能污染后续读取',()=>{
 let calls=0;
 const read=cacheVerifiedDocument((text,hash,field)=>{calls++;assert.equal(hash,'valid');return {...JSON.parse(text),field};});
 const first=read('{"nested":{"value":1}}','valid','digest');first.nested.value=9;
 assert.equal(read('{"nested":{"value":1}}','valid','digest').nested.value,1);assert.equal(calls,1);
 assert.throws(()=>read('{"nested":{"value":1}}','wrong','digest'));assert.equal(calls,2);
 assert.equal(read('{"nested":{"value":1}}','valid','other').field,'other');assert.equal(calls,3);
 assert.equal(read('{"nested":{"value":2}}','valid','digest').nested.value,2);assert.equal(calls,4);
});
test('失败和缺失不缓存，数量及字节上限驱逐旧原件',()=>{
 let calls=0;const read=cacheVerifiedDocument(text=>{calls++;return JSON.parse(text);},{maxEntries:2,maxBytes:256});
 for(let i=0;i<2;i++){assert.throws(()=>read('invalid'));assert.equal(read('null'),null);}assert.equal(calls,4);
 read('1');read('2');read('1');assert.equal(calls,6);read('3');read('2');assert.equal(calls,8);
 const large=JSON.stringify('x'.repeat(256));read(large);read(large);assert.equal(calls,10);
});

test('JSON键无法区分的参数不共享校验结果',()=>{
 let calls=0;const read=cacheVerifiedDocument((text,parameter='default')=>{calls++;return {text,parameter};});
 assert.equal(read('x',undefined).parameter,'default');assert.equal(read('x',null).parameter,null);
 assert.equal(read('x',undefined).parameter,'default');assert.equal(calls,3);
});
