import test from 'node:test';
import assert from 'node:assert/strict';
import {setup,inspect} from './fixtures/extension-installation.mjs';
import {fixture as clockFixture} from './auth-clock-fixture.mjs';
import {startAuthenticationClock} from '../dist/auth-clock.mjs';
import {selectAuthenticationWindow,currentAuthenticationWindow} from '../dist/authentication-window.mjs';
import {seal,extrapolate} from '../dist/auth-clock-value.mjs';
async function fixture(t,{fault=false,refresh=false}={}){
 const f=await setup(t,38),scope=f.store.authenticationClock.scope,base=clockFixture(scope),domain={clock_domain_id:'clock_'+'c'.repeat(64),descriptor_digest:'sha256:'+'c'.repeat(64)};
 const c=clockFixture(scope,{source:base.source,descriptor:domain}),clock=startAuthenticationClock(c.source,f.store.authenticationClock,c.provider,{schedule:false});
 const sampled=clock.current(),record=f.store.authenticationClock.current(domain.clock_domain_id),service=f.store.identity;
 if(refresh){c.source.advance(500000000n);clock.refresh();}
 if(fault)f.store.authenticationClock.fault(domain.clock_domain_id);clock.stop();f.close();
 return {...f,record,input:{service,coreRuntime:{value:{service_boot_id:scope.service_boot_id,domain_ref:domain}},acquisitionRef:sampled.acquisition_ref,
  domain,selectedTick:record.b,validFrom:record.effective_lower_ns,validBefore:String(BigInt(record.effective_upper_ns)+1000000000n),capTick:record.valid_before_tick_ns}};
}
function run(f,work){inspect(f.dir,db=>{db.pragma('foreign_keys=ON');db.pragma('trusted_schema=OFF');db.transaction(()=>work({...f.input,db})).immediate();});}
test('认证UTC上界精确换算半开单调截止：截止前满足，等号拒绝，晚读不延长',async t=>{
 const f=await fixture(t);run(f,input=>{
  for(const delta of [1n,2n,3n,999n,1000n,1001n,1000000000n]){
   const selected={...input,validBefore:String(BigInt(f.record.effective_upper_ns)+delta)},w=selectAuthenticationWindow(selected);
   const last=BigInt(w.before_tick_ns)-1n;assert.ok(BigInt(extrapolate(f.record,last).upper_ns)<BigInt(selected.validBefore));
   assert.ok(BigInt(extrapolate(f.record,BigInt(w.before_tick_ns)).upper_ns)>=BigInt(selected.validBefore));
   assert.deepEqual(currentAuthenticationWindow(selected,w,String(last)),w);
   assert.throws(()=>currentAuthenticationWindow(selected,w,w.before_tick_ns),e=>e.code==='authentication_window_expired');
  }
 });
});
test('认证样本、运行健康和外部挑战截止取交集，不把较晚采样当续期',async t=>{
 const f=await fixture(t);run(f,input=>{
  const bounded={...input,validBefore:String(BigInt(f.record.effective_upper_ns)+100000000000n),capTick:String(BigInt(input.selectedTick)+500n)},w=selectAuthenticationWindow(bounded);
  assert.equal(w.before_tick_ns,bounded.capTick);
  const sample=selectAuthenticationWindow({...bounded,capTick:String(BigInt(input.selectedTick)+10000000000n)});assert.equal(sample.before_tick_ns,f.record.valid_before_tick_ns);
  const {digest,...body}=w,extended=seal({...body,before_tick_ns:String(BigInt(w.before_tick_ns)+1n)});
  assert.throws(()=>currentAuthenticationWindow(bounded,extended,input.selectedTick),e=>e.code==='authentication_window_changed');
 });
});
test('跨域、错boot、尚未生效和已到期凭据范围不能生成窗口',async t=>{
 const f=await fixture(t);run(f,input=>{
  assert.throws(()=>selectAuthenticationWindow({...input,domain:{...input.domain,clock_domain_id:'clock_'+'d'.repeat(64)}}),e=>e.code==='authentication_window_domain');
  assert.throws(()=>selectAuthenticationWindow({...input,coreRuntime:{value:{...input.coreRuntime.value,service_boot_id:'different'}}}),e=>e.code==='authentication_window_domain');
  assert.throws(()=>selectAuthenticationWindow({...input,validFrom:String(BigInt(f.record.effective_lower_ns)+1n)}),e=>e.code==='authentication_window_validity');
  assert.throws(()=>selectAuthenticationWindow({...input,validBefore:f.record.effective_upper_ns}),e=>e.code==='authentication_window_validity');
 });
});
test('旧采样不能冒充当前选择；当前认证故障阻止所有来源窗口',async t=>{
 const old=await fixture(t,{refresh:true});run(old,input=>assert.throws(()=>selectAuthenticationWindow(input),e=>e.code==='authentication_window_changed'));
 const failed=await fixture(t,{fault:true});run(failed,input=>assert.throws(()=>selectAuthenticationWindow(input),e=>e.code==='authentication_window_fault'));
});
