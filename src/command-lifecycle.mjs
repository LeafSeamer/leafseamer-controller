import {IdentityError} from './identity-crypto.mjs';
import {closeQueuedCommand} from './command-record-store.mjs';

// 独立于GET执行的有界队列维护。未知存储结果锁存失败，读取不能冒充当前投影。
export function commandLifecycle({db,service,bootId,writer,domain}){
 let timer=null,closed=false,failure=null,cursor='';
 const enabled=Number(service?.schema_revision)>=50;
 function currentDomain(){try{return domain();}catch(error){
  if(error instanceof IdentityError&&error.code==='control_source_unavailable')return null;throw error;
 }}
 function run(){
  if(closed||failure||!enabled)return;
  try{writer(()=>{
   const select=after=>db.prepare(`SELECT command_id FROM command_admission_source s WHERE command_id>?
    AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=s.command_id) ORDER BY command_id LIMIT 16`).pluck().all(after);
   let ids=select(cursor);if(!ids.length){cursor='';ids=select(cursor);}
   for(const id of ids){closeQueuedCommand(db,id,{bootId,domain:currentDomain});cursor=id;}
  });}catch(error){failure=error;}
  if(!closed&&!failure){timer=setTimeout(run,100);timer.unref();}
 }
 if(enabled){timer=setTimeout(run,100);timer.unref();}
 return Object.freeze({
  assertAvailable(){if(failure){const error=new IdentityError('command_lifecycle_unavailable');error.cause=failure;throw error;}},
  close(){closed=true;clearTimeout(timer);},
 });
}
