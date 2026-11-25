import Database from 'better-sqlite3';

export function scheduledReferenceWithdrawal({databasePath,tick,report}){
 let armed=false,withdrawn=false,reader=null,select=null;
 function close(){
  reader?.close();reader=null;select=null;
 }
 return Object.freeze({
  arm(){armed=true;},
  close,
  withdraw(){
   if(withdrawn)return true;
   if(!armed)return false;
   reader??=new Database(databasePath,{readonly:true,fileMustExist:true});
   select??=reader.prepare(`SELECT f.command_id,f.permit_id,g.guard_id,
    json_extract(f.body_jcs,'$.seal.send_window.before_tick_ns')
    FROM command_dispatch_request d JOIN command_final_admission f ON f.transaction_id=d.final_transaction_id
    JOIN command_guard_ack g ON g.guard_id=d.guard_id
    WHERE g.disposition='installed' AND json_extract(f.body_jcs,'$.guard.time_required')=1
    AND NOT EXISTS(SELECT 1 FROM command_dispatch_write w WHERE w.permit_id=d.permit_id)`).raw();
   const selected=select.get();
   if(!selected)return false;
   const [command_id,permit_id,guard_id,before_tick]=selected,at=tick();
   if(at>=BigInt(before_tick))return false;
   withdrawn=true;
   report({event:'scheduled-reference-withdrawn',command_id,permit_id,guard_id,tick_ns:String(at)});
   close();
   return true;
  }
 });
}
