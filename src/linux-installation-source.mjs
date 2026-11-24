import crypto from 'node:crypto';
import canonicalize from './runtime/canonicalize.mjs';
import {BootstrapError} from './core-bootstrap.mjs';

const version='leafseamer-linux-installation-read/1';
const maxResponse=9*1024*1024;
const id=value=>typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}(?![\s\S])/.test(value);
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===keys;
const need=(ok,code)=>{if(!ok)throw new BootstrapError('linux_installation_'+code);};

function decodedBytes(value){
  need(typeof value==='string'&&value.length<=1398104,'content');
  const bytes=Buffer.from(value,'base64');
  need(bytes.length<=1048576&&bytes.toString('base64')===value,'content');
  return bytes;
}

export async function connectLinuxInstallationSource({socket,receipt,serviceId,supervision}){
  let pending=null,chunks=[],size=0,closed=false,queued=0,tail=Promise.resolve();
  function close(){
    if(closed)return;
    closed=true;chunks=[];size=0;
    const call=pending;pending=null;
    if(call){clearTimeout(call.timer);call.reject(new BootstrapError('linux_installation_closed'));}
    socket.destroy();
  }
  socket.once('end',close).once('error',close).once('close',close);
  const unsubscribe=supervision.subscribeLost(close);
  socket.once('close',unsubscribe);
  socket.on('data',chunk=>{
    const end=chunk.indexOf(10);
    if(!pending||size+chunk.length>maxResponse||(end>=0&&end!==chunk.length-1)){close();return;}
    chunks.push(chunk);size+=chunk.length;
    if(end<0)return;
    const bytes=Buffer.concat(chunks,size),call=pending;
    pending=null;chunks=[];size=0;
    clearTimeout(call.timer);
    call.resolve(bytes.subarray(0,-1));
  });

  async function request(operation,intake_id){
    try{
      supervision.assertCurrent();
      need(!closed&&!pending,'closed');
      const request_id=crypto.randomBytes(16).toString('hex');
      const channel_binding_id=receipt.channel_binding_id;
      const bytes=await new Promise((resolve,reject)=>{
        pending={resolve,reject,timer:setTimeout(close,5000)};
        socket.write(canonicalize({version,channel_binding_id,operation,request_id,intake_id})+'\n',error=>{if(error)close();});
      });
      supervision.assertCurrent();
      const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes),reply=JSON.parse(text);
      need(exact(reply,'channel_binding_id,operation,request_id,result,version')&&canonicalize(reply)===text&&
        reply.version===version&&reply.channel_binding_id===channel_binding_id&&reply.operation===operation&&reply.request_id===request_id,'frame');
      return reply.result;
    }catch(error){close();throw error;}
  }
  try{
    const identity=await request('identity',null);
    need(exact(identity,'authority_service_id,database_instance_id,host_installation_id')&&Object.values(identity).every(id),'identity');
    function read(operation,input){
      need(exact(input,'intake_id,target_authority_service_id')&&id(input.intake_id)&&input.target_authority_service_id===serviceId,'query');
      need(queued<4,'capacity');
      const {intake_id}=input;
      queued++;
      const result=tail.then(async()=>{
        try{
          const value=await request(operation,intake_id);
          need(exact(value,'content,status'),'result');
          if(value.status==='unavailable'&&value.content===null)return value;
          const {content}=value;
          need(value.status==='available'&&content?.intake_ref?.object_id===intake_id&&
            content.intake_ref.authority_service_id===identity.authority_service_id&&
            content.intake_ref.database_instance_id===identity.database_instance_id,'result');
          if(operation==='configuration_schema')content.bytes=decodedBytes(content.bytes);
          if(operation==='capability_templates'){
            need(Array.isArray(content.files),'content');
            for(const file of content.files)file.bytes=decodedBytes(file.bytes);
          }
          return value;
        }catch(error){close();throw error;}
        finally{queued--;}
      });
      tail=result.catch(()=>{});
      return result;
    }
    return Object.freeze({identity:Object.freeze(identity),describeIntake:query=>read('intake',query),
      describeConfigurationSchema:query=>read('configuration_schema',query),
      describeCapabilityTemplates:query=>read('capability_templates',query)});
  }catch(error){close();throw error;}
}
