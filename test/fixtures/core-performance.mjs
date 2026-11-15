import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Session} from 'node:inspector';
// 显式测试诊断；关闭时不启用采样，也不改变产品时限或业务行为。
export async function corePerformance(name){
 if(!name)return {record(){},async stop(){}};
 if(!/^[a-z0-9_-]{1,64}$/.test(name))throw Error('performance_name');
 const directory=fileURLToPath(new URL('../../logs/core-performance/',import.meta.url));fs.mkdirSync(directory,{recursive:true});
 const session=new Session();session.connect();const post=(method,params={})=>new Promise((resolve,reject)=>session.post(method,params,(error,result)=>error?reject(error):resolve(result)));
 await post('Profiler.enable');await post('Profiler.setSamplingInterval',{interval:1000});await post('Profiler.start');const events=[];let stopping;
 return {record(value){events.push({event:value.event,stage:value.stage,code:value.code,reported_ms:value.reported_ms,remaining_ms:value.remaining_ms});},stop(){return stopping??=(async()=>{try{const {profile}=await post('Profiler.stop');const base=path.join(directory,name+'-'+process.pid);fs.writeFileSync(base+'.cpuprofile',JSON.stringify(profile));fs.writeFileSync(base+'.json',JSON.stringify(events,null,2)+'\n');}finally{session.disconnect();}})();}};
}
