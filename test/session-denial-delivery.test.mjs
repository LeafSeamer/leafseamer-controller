import test from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as wait} from 'node:timers/promises';
import {startSessionDenialDelivery} from '../dist/session-denial-delivery.mjs';
const transport={deliverSessionDenial(){}};
async function until(check){for(let i=0;i<200;i++){if(check())return;await wait(5);}assert.fail('delivery_wait_timeout');}
test('单并发分页继续处理失败目标，下一遍重试且回执状态不成为保护完成',async t=>{
 const visited=[],pages=[];let active=0,maximum=0;
 const store={scan({after,limit}){pages.push(after);assert.equal(limit,1);return after===null?{items:['offline'],next:['next']}:{items:['online'],next:null};},
  async deliverPending(item){active++;maximum=Math.max(maximum,active);visited.push(item);try{await wait(2);if(item==='offline')throw new Error('offline');return {state:'delivered'};}finally{active--;}}};
 const task=startSessionDenialDelivery({store,transport,intervalMs:10,pageSize:1});t.after(()=>task.close());
 await until(()=>task.status().delivered>=2);await task.close();assert.equal(maximum,1);assert.deepEqual(visited.slice(0,4),['offline','online','offline','online']);
 assert.ok(task.status().failed>=2);assert.equal(task.status().state,'stopped');assert.equal('protection_state' in task.status(),false);
});
test('停止等待当前发送终态，不开始后续任务；重复关闭无副作用',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});const sent=[];
 const task=startSessionDenialDelivery({store:{scan:()=>({items:[1,2],next:null}),async deliverPending(item){sent.push(item);await gate;return {state:'delivered'};}},transport,intervalMs:10});
 await until(()=>sent.length===1);let closed=false;const stopping=task.close().then(()=>{closed=true;});await wait(15);assert.equal(closed,false);
 release();await stopping;await task.close();await wait(15);assert.deepEqual(sent,[1]);assert.equal(task.status().active,false);
});
test('扫描故障不假报成功，恢复后重新从持久记录扫描',async t=>{
 let calls=0;const task=startSessionDenialDelivery({store:{scan(){if(++calls===1)throw new Error('database');return {items:[1],next:null};},async deliverPending(){return {state:'acknowledged'};}},transport,intervalMs:10});
 t.after(()=>task.close());await until(()=>task.status().acknowledged>0);await task.close();assert.equal(task.status().scan_failed,1);assert.equal(task.status().delivered,0);
});
