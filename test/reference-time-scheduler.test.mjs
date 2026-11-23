import test from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {referenceTimeScheduler} from '../dist/reference-time-scheduler.mjs';

test('自动采样的来源等待和别名拒绝不会阻塞其他来源', {timeout:5000}, async t=>{
 const emitted=[], retired=[];
 const task=referenceTimeScheduler({sourceSlots:['source.first','source.alias','source.recovered']},{
  plan(slot,expected){
   const authorization={source_digest:slot==='source.alias'?'source.first':slot};
   if(expected)assert.deepEqual(expected,authorization);
   if(slot==='source.recovered' && retired.length===0)return {state:'retirement_required',authorization};
   if(emitted.some(row=>row.slot===slot))return {state:'waiting',wait_ns:60000000000n,authorization};
   return {state:'ready',authorization};
  },
  async recover(slot){retired.push(slot);},
  async collect(slot,id,authorization){
   emitted.push({slot,id,authorization});
   return {status:'archived'};
  }
 });
 t.after(()=>task.close());
 task.start();
 const deadline=performance.now()+2500;
 while(!emitted.some(row=>row.slot==='source.recovered')){
  assert(performance.now()<deadline,'另一来源未完成自动采样');
  await delay(10);
 }
 await task.close();
 assert.deepEqual(emitted.map(row=>row.slot),['source.first','source.recovered']);
 assert.notEqual(emitted[0].id,emitted[1].id);
 assert.deepEqual(retired,['source.recovered']);
 assert.deepEqual(task.status()[1],{source_slot:'source.alias',state:'stopped',reason:'reference_time_schedule_source_alias'});
});
