import {canonical,digest} from './auth-clock-value.mjs';
import {readCommandRecord,readCommandResource,readCommandRevision} from './command-record-store.mjs';

function need(condition){
  if(!condition)throw new Error('backup_command_inventory');
}

function original(bytes){
  const value=JSON.parse(bytes.toString('utf8'));
  need(Buffer.from(canonical(value)).equals(bytes));
  return value;
}

export function verifyBackupCommands(db,scope){
  const revision=Number(scope.schema_revision);
  const inventory={requests:0,commands:0,pending:0,unresolved:0};
  if(revision<9)return inventory;
  const adjudications=db.prepare(`SELECT k.content_body,k.request_digest,k.operation_id,k.idempotency_key,k.device_id,
    a.adjudication_body,a.adjudication_digest,a.adjudication_id,a.decision,a.command_id,n.issuer_id,n.issuer_epoch,
    n.principal_id,n.request_epoch,s.authority_service_id,s.database_instance_id
    FROM ca_request_key k JOIN ca_adjudication a USING(key_id) JOIN ca_namespace n USING(namespace_id)
    JOIN ca_scope s ON s.singleton=n.scope_id`).raw();
  for(const [content,requestHash,operation,key,device,body,adjudicationHash,adjudicationId,decision,command,
    issuerId,issuerEpoch,principalId,requestEpoch,authorityId,databaseId] of adjudications.iterate()){
    const payload=original(content);
    need(digest(payload)===requestHash&&payload.device_id===device&&authorityId===scope.service_id&&databaseId===scope.database_instance_id);
    const {adjudication_digest,...originalBody}=original(body);
    const identity={request_digest:requestHash,key:{target_scope:{authority_service_id:authorityId,database_instance_id:databaseId},
      issuer_id:issuerId,issuer_epoch:issuerEpoch,principal_id:principalId,request_epoch:requestEpoch,operation_id:operation,idempotency_key:key}};
    need(adjudication_digest===adjudicationHash&&digest(originalBody)===adjudicationHash&&
      originalBody.adjudication_id===adjudicationId&&originalBody.decision===decision&&
      canonical(originalBody.identity)===canonical(identity)&&
      (decision==='accepted' ? command!==null : decision==='rejected'&&command===null&&originalBody.command_ref===null));
    inventory.requests++;
  }
  if(revision<49)return inventory;

  const entries=db.prepare(`SELECT command_id FROM command_admission_source
    WHERE command_id>? ORDER BY command_id LIMIT 64`).pluck();
  const history=revision>=50 ? db.prepare(`SELECT revision FROM command_lifecycle_revision
    WHERE command_id=? ORDER BY revision`).pluck() : null;
  let after='';
  for(;;){
    const batch=entries.all(after);
    if(batch.length===0)break;
    for(const id of batch){
      const command=readCommandRecord(db,id), state=command.record.state;
      if(history){
        const recorded=history.all(id);
        need(recorded.every((number,index)=>number===index+2)&&state.revision===String(recorded.length+1));
        for(const number of recorded){
          if(String(number)!==state.revision)readCommandRevision(db,id,String(number));
        }
      }
      inventory.commands++;
      if(state.phase!=='finished')inventory.pending++;
      if(state.resource_status==='unresolved')inventory.unresolved++;
      if(revision>=52)readCommandResource(db,command);
    }
    after=batch.at(-1);
  }
  return inventory;
}
