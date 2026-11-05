import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
export class ConfigurationValidationError extends Error {constructor(code){super(code);this.name='ConfigurationValidationError';this.code=code;}}
let active=0;
const fail=code=>new ConfigurationValidationError(code);
// 核心继续禁止动态代码生成；只有固定校验子进程编译已选Schema，结束后回收。
export const validateConfiguration=(schema,configuration)=>validate(schema,configuration,'configuration');
export const validateSchemaDocuments=schemas=>validate(schemas,Buffer.alloc(0),'schemas');
async function validate(schema,configuration,mode){
  if(!Buffer.isBuffer(schema)||!Buffer.isBuffer(configuration)||schema.length>1048576||configuration.length>1048576)throw fail('extension_configuration_capacity');
  if(active>=2)throw fail('extension_configuration_capacity');++active;
  const input=JSON.stringify({mode,schema:schema.toString('base64'),configuration:configuration.toString('base64')});
  const env=Object.fromEntries(['SystemRoot','WINDIR','TEMP','TMP'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
  try{return await new Promise((resolve,reject)=>{
    const child=spawn(process.execPath,['--max-old-space-size=64','--max-semi-space-size=4','--disable-proto=throw',fileURLToPath(new URL('./configuration-worker.mjs',import.meta.url))],
      {stdio:['pipe','pipe','pipe'],windowsHide:true,env});
    let output=Buffer.alloc(0),failure=null,errors=0;
    const stop=code=>{failure??=fail(code);child.kill();};
    const timer=setTimeout(()=>stop('extension_configuration_timeout'),3000);
    child.on('error',()=>{failure??=fail('extension_configuration_unavailable');});
    child.stdin.on('error',()=>stop('extension_configuration_unavailable'));
    child.stdout.on('data',chunk=>{if(output.length+chunk.length>1048704)stop('extension_configuration_capacity');else output=Buffer.concat([output,chunk]);});
    child.stderr.on('data',chunk=>{errors+=chunk.length;if(errors>65536)stop('extension_configuration_capacity');});
    child.on('close',code=>{
      clearTimeout(timer);if(failure){reject(failure);return;}if(code!==0){reject(fail('extension_configuration_unavailable'));return;}
      try{const result=JSON.parse(output.toString('utf8'));
        if(result?.ok===false&&typeof result.code==='string'){reject(fail('extension_configuration_'+result.code));return;}
        if(!result||result.ok!==true||Object.keys(result).sort().join(',')!=='ok,value')throw new Error();resolve(result.value);
      }catch{reject(fail('extension_configuration_protocol'));}
    });
    child.stdin.end(input);
  });}finally{--active;}
}
