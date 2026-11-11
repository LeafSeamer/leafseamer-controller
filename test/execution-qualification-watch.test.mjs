import test from 'node:test';
import assert from 'node:assert/strict';
import {executionQualificationWatch} from '../dist/execution-qualification-watch.mjs';
function fixture(inspect,failed){
 const jobs=new Map();let sequence=0;
 const watch=executionQualificationWatch({inspect,failed,schedule(fn,ms){assert.equal(ms,100);const id=++sequence;jobs.set(id,fn);return id;},cancel(id){jobs.delete(id);}});
 return {watch,jobs,fire(){const [id,fn]=jobs.entries().next().value;jobs.delete(id);fn();}};
}
test('成功业务复核合并已排队监视，空闲时仍持续检查',()=>{
 let checks=0;const f=fixture(()=>checks++,()=>assert.fail('unexpected failure'));
 assert.equal(f.jobs.size,1);const first=[...f.jobs.keys()][0];f.watch.refresh();
 assert.equal(f.jobs.size,1);assert.equal(f.jobs.has(first),false);assert.equal(checks,0);
 f.fire();assert.equal(checks,1);assert.equal(f.jobs.size,1);f.fire();assert.equal(checks,2);
 f.watch.stop();assert.equal(f.jobs.size,0);f.watch.refresh();assert.equal(f.jobs.size,0);
});
test('监视失败立即终止且不能被后来的刷新复活',()=>{
 const expected=new Error('expired');let failure;
 const f=fixture(()=>{throw expected;},e=>{failure=e;});f.fire();
 assert.equal(failure,expected);assert.equal(f.jobs.size,0);f.watch.refresh();assert.equal(f.jobs.size,0);
});
