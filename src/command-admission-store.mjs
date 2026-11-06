import crypto from 'node:crypto';
import {IdentityError} from './identity-crypto.mjs';
import {canonical, digest} from './auth-clock-value.mjs';
import {contractSelection as selection} from './sdk/index.mjs';
import {createHttpAdapter} from './sdk/http.mjs';
import {commandPolicyInput,commandCapacity,prepareCommandRecord,storeCommandRecord,readCommandRecord,readCommandRevision} from './command-record-store.mjs';
import {withExecutionReadView} from './execution-read-view.mjs';

const fail = code => { throw new IdentityError(code); };
const executionFailure=error=>{if(error?.code?.startsWith('SQLITE_'))throw error;
  const failure=new IdentityError('command_execution_unavailable');failure.cause=error;throw failure;};
const bytes = value => Buffer.from(canonical(value));
const version = 'command-admission/0.1.0-draft.1';
// 只排除具名顶层运输字段，嵌套同名业务字段仍参与摘要。
export function commandContent({context_id, idempotency_key, correlation_id, ...content}) { return content; }

export function commandAdmissionStore({db, binding, writer, time, authorizeToken, rows,contextCurrent,devices,executionCurrent,domain,assertCurrentProjection=()=>{},queueCommand=null}) {
  const adapter = createHttpAdapter(selection), service = binding?.service;
  const scope = service && {authority_service_id: service.service_id, database_instance_id: service.database_instance_id};
  const available = () => { if (!service || Number(service.schema_revision) < 9) fail('command_admission_unavailable'); };
  const deliver = value => { if (value.denied) fail(value.denied); return value; };
  function evidenceRead(input,id,read){
    available();assertCurrentProjection();return deliver(writer(()=>{
      const proof=authenticate(input,'command.evidence.read');if(proof.denied)return proof;
      const row=rows(db,'SELECT c.command_id FROM ca_command_initial c JOIN ca_request_key k USING(key_id) JOIN ca_namespace n USING(namespace_id) WHERE c.command_id=? AND n.issuer_id=? AND n.issuer_epoch=? AND n.principal_id=?',
        id,proof.issuer_id,proof.issuer_epoch,proof.principal_id)[0];
      if(!row)fail('command_not_found');const saved=readCommandRecord(db,id),result=read(saved);
      const last=recheck(input,'command.evidence.read',saved.adjudication.identity);if(last.denied)return last;return result;
    }));
  }
  async function validate(operation, input) {
    available();
    try {
      const op = adapter.describe('controller', operation), body = Buffer.from(JSON.stringify(input));
      if (body.length > 16384) fail('command_request_invalid');
      const request = adapter.prepareRequest('controller', 'POST', op.path, [['Content-Type', 'application/json'],
        ['X-LeafSeamer-Contract', selection.contract_id], ['X-LeafSeamer-Contract-Digest', selection.contract_digest]]);
      return (await adapter.decodeRequest(body, request)).value;
    } catch { fail('command_request_invalid'); }
  }
  function authenticate(input, permission) {
    const proof = authorizeToken(input, service.service_id); if (proof.denied) return proof;
    if (proof.principal_kind !== 'human' || !proof.permissions.includes(permission)) fail('command_permission');
    return proof;
  }
  function ownership(proof, key) {
    if (canonical(key.target_scope) !== canonical(scope) || key.operation_id !== 'createCommand' ||
      key.issuer_id !== proof.issuer_id || key.issuer_epoch !== proof.issuer_epoch || key.principal_id !== proof.principal_id) fail('command_permission');
    const context = rows(db, `SELECT * FROM request_context WHERE service_id=? AND database_instance_id=? AND issuer_id=?
      AND issuer_epoch=? AND principal_id=? AND context_epoch=? ORDER BY context_id LIMIT 1`, service.service_id, service.database_instance_id,
      key.issuer_id, key.issuer_epoch, key.principal_id, key.request_epoch)[0];
    if (!context) fail('command_namespace');
    const original = JSON.parse(context.body.toString());
    if (digest(original) !== context.body_digest || canonical(original.context.selection) !== canonical(selection)) fail('command_binding');
    return context;
  }
  function find(identity) {
    const k = identity.key;
    const row = rows(db, `SELECT k.key_id,k.request_digest,a.adjudication_digest,a.adjudication_body FROM ca_namespace n
      JOIN ca_request_key k USING(namespace_id) JOIN ca_adjudication a USING(key_id)
      WHERE n.issuer_id=? AND n.issuer_epoch=? AND n.principal_id=? AND n.request_epoch=? AND k.operation_id=? AND k.idempotency_key=?`,
      k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch, k.operation_id, k.idempotency_key)[0];
    if (!row) return null;
    if (row.request_digest !== identity.request_digest) fail('command_conflict');
    const value = JSON.parse(row.adjudication_body.toString()), {adjudication_digest, ...body} = value;
    if (digest(body) !== adjudication_digest || adjudication_digest !== row.adjudication_digest || canonical(value.identity) !== canonical(identity)) fail('command_binding');
    return {keyId: row.key_id, value};
  }
  function recheck(input, permission, identity) {
    const proof = authenticate(input, permission); if (proof.denied) return proof;
    ownership(proof, identity.key); return proof;
  }
  function lookup(input, identity) {
    const proof = recheck(input, 'command.read', identity); if (proof.denied) return proof;
    const found = find(identity);
    const last = recheck(input, 'command.read', identity); if (last.denied) return last;
    return {state: found ? 'found' : 'not_found', adjudication: found?.value ?? null};
  }
  function freshSubmission(input,value) {
    const proof=authenticate(input,'device.command');if(proof.denied)return proof;
    if(value.origin!=='manual'||value.automation_binding!==null)fail('command_permission');
    if(!contextCurrent)fail('command_admission_unavailable');
    const context=contextCurrent(input,value.context_id,'submitCommand');if(context.denied)return context;
    const budget=rows(db,'SELECT used_count,max_unique_requests FROM request_context WHERE context_id=?',context.context_id)[0];
    if(!budget||budget.used_count>=budget.max_unique_requests)fail('command_capacity');
    if(Number(service.schema_revision)<26||!devices)fail('command_admission_unavailable');
    const control=devices.control(value.device_id);
    if(canonical(value.expected_control)!==canonical({epoch:control.control_epoch,version:control.effective_version}))fail('command_control_conflict');
    if(control.pending_change!==null)fail('command_control_pending');
    const actor={issuer_id:proof.issuer_id,issuer_epoch:proof.issuer_epoch,principal_id:proof.principal_id};
    if(control.mode!=='manual'||canonical(control.holder)!==canonical(actor))fail('command_control_owner');
    if(!executionCurrent)fail('command_execution_unavailable');
    let execution;
    try{execution=executionCurrent(value.device_id);}catch(error){executionFailure(error);}
    const action=execution.value.action;
    if(value.action_id!==action.action_id||value.capability_version!==action.capability_version)fail('command_capability');
    if(control.gate_state!=='ready')fail('command_gate_not_ready');
    // 身份取证允许读取未开放的执行绑定；新命令另须在同一writer内取得完整当前Ready。
    // 会话默认闸保持closed，不能用它替代设备级的已提交资格。
    try{execution=executionCurrent(value.device_id,{requireReady:true});}
    catch(error){executionFailure(error);}
    if(!execution.ready||execution.ready.value.gate_after.phase!=='ready')fail('command_gate_not_ready');
    const last=contextCurrent(input,value.context_id,'submitCommand');if(last.denied)return last;
    if(canonical(last)!==canonical(context))fail('command_binding');
    commandPolicyInput(value,execution);
    return {proof,context,control,execution,token_id:input.token_id};
  }
  return Object.freeze({
    async lookupCommandAdmission(input, request) {
      const identity = await validate('lookupCommandAdmission', request);
      return deliver(writer(() => lookup(input, identity)));
    },
    async rejectCommandAdmission(input, request) {
      const value = await validate('rejectCommandAdmission', request), {identity, content} = value;
      if (digest(content) !== identity.request_digest) fail('command_request_invalid');
      if (content.origin !== 'manual' || content.automation_binding !== null) fail('command_permission');
      return deliver(writer(() => {
        const proof = recheck(input, 'command.cancel', identity); if (proof.denied) return proof;
        const k = identity.key, operationDigest = digest(value), owner = ownership(proof, k);
        const prior = rows(db, `SELECT operation_digest,key_id FROM ca_rejection WHERE actor_issuer_id=? AND actor_issuer_epoch=?
          AND actor_principal_id=? AND rejection_operation_id=?`, proof.issuer_id, proof.issuer_epoch, proof.principal_id, value.rejection_operation_id)[0];
        if (prior) {
          if (prior.operation_digest !== operationDigest) fail('command_conflict');
          const found = find(identity); if (!found || found.keyId !== prior.key_id) fail('command_binding');
          return found.value;
        }
        const found = find(identity);
        if (db.prepare('SELECT count(*) FROM ca_rejection').pluck().get() >= 8192 ||
          !found && db.prepare('SELECT count(*) FROM ca_request_key').pluck().get() >= 4096) fail('command_capacity');
        let namespace = rows(db, 'SELECT namespace_id FROM ca_namespace WHERE issuer_id=? AND issuer_epoch=? AND principal_id=? AND request_epoch=?',
          k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch)[0];
        if (!namespace) {
          namespace = {namespace_id: crypto.randomUUID()};
          db.prepare('INSERT INTO ca_namespace VALUES (?,1,?,?,?,?,?,?)').run(namespace.namespace_id, k.issuer_id, k.issuer_epoch, k.principal_id, k.request_epoch, owner.context_id, owner.body);
        }
        const keyId = found?.keyId ?? crypto.randomUUID(), commitId = crypto.randomUUID(), rejectionId = crypto.randomUUID();
        const kind = found ? 'reject_existing' : 'reject_new';
        const commit = {kind: 'controller_commit', scope, object_id: commitId, revision: '1', operation: kind, identity,
          rejection_operation_id: value.rejection_operation_id, acquisition_ref: time().acquisition};
        const commitRef = {kind: commit.kind, scope, object_id: commitId, revision: '1', digest: digest(commit)};
        const body = {contract_version: version, adjudication_id: crypto.randomUUID(), revision: '1', identity, decision: 'rejected', command_ref: null, commit_ref: commitRef};
        const adjudication = found?.value ?? {...body, adjudication_digest: digest(body)};
        if (!found) {
          db.prepare('INSERT INTO ca_request_key VALUES (?,?,?,?,?,?,?)').run(keyId, namespace.namespace_id, 'createCommand', k.idempotency_key, identity.request_digest, content.device_id, bytes(content));
          db.prepare('INSERT INTO ca_adjudication VALUES (?,?,?, ?,NULL,?,?,?,?)').run(keyId, adjudication.adjudication_id, '1', 'rejected', commitId, kind, adjudication.adjudication_digest, bytes(adjudication));
        }
        db.prepare('INSERT INTO ca_commit VALUES (?,?,?,?,?,?)').run(commitId, keyId, kind, found ? null : keyId, rejectionId, bytes(commit));
        db.prepare('INSERT INTO ca_audit VALUES (?,?,?,?)').run(commitId, keyId, kind, bytes({identity, actor: {issuer_id: proof.issuer_id, issuer_epoch: proof.issuer_epoch, principal_id: proof.principal_id}, decision: adjudication.decision}));
        db.prepare('INSERT INTO ca_notification VALUES (?,?,?,?,?)').run(commitId, keyId, kind, crypto.randomUUID(), bytes({identity, adjudication}));
        db.prepare('INSERT INTO ca_rejection VALUES (?,?,?,?,?,?,?,?,?,?)').run(rejectionId, proof.issuer_id, proof.issuer_epoch, proof.principal_id,
          value.rejection_operation_id, operationDigest, keyId, commitId, bytes(value), bytes({authorization_digest: proof.authorization_digest, scope_digest: proof.scope_digest, token_id: input.token_id}));
        const last = recheck(input, 'command.cancel', identity); if (last.denied) fail(last.denied);
        return adjudication;
      }));
    },
    async submitCommand(input, request, {withStatus=false}={}) {
      const value = await validate('submitCommand', request);
      let created=false;const result=deliver(writer(() => {
        const proof = authenticate(input, 'command.read'); if (proof.denied) return proof;
        const context = rows(db, 'SELECT * FROM request_context WHERE context_id=?', value.context_id)[0];
        if (!context) fail('command_namespace');
        const identity = {key: {target_scope: scope, issuer_id: context.issuer_id, issuer_epoch: context.issuer_epoch, principal_id: context.principal_id,
          request_epoch: context.context_epoch, operation_id: 'createCommand', idempotency_key: value.idempotency_key}, request_digest: digest(commandContent(value))};
        const result = lookup(input, identity); if (result.denied) return result;
        if (result.state === 'found') return result.adjudication;
        assertCurrentProjection();
        // 原裁决只需当前查询权；新键必须使用当前凭据、上下文、控制权与执行来源。
        const current=withExecutionReadView(db,()=>freshSubmission(input,value));if(current.denied)return current;
        if(Number(service.schema_revision)<49||!domain)fail('command_admission_unavailable');
        commandCapacity(db,value.device_id);
        const k=identity.key,owner=ownership(current.proof,k),commitId=crypto.randomUUID(),keyId=crypto.randomUUID();
        const commit={kind:'controller_commit',scope,object_id:commitId,revision:'1',operation:'accept',identity,acquisition_ref:time().acquisition};
        const commitRef={kind:commit.kind,scope,object_id:commitId,revision:'1',digest:digest(commit)};
        const prepared=prepareCommandRecord({value,content:commandContent(value),identity,current,domain:domain(),commitRef});
        let namespace=rows(db,'SELECT namespace_id FROM ca_namespace WHERE issuer_id=? AND issuer_epoch=? AND principal_id=? AND request_epoch=?',
          k.issuer_id,k.issuer_epoch,k.principal_id,k.request_epoch)[0];
        const written=result=>{if(result.changes!==1)fail('command_storage');};
        if(!namespace){namespace={namespace_id:crypto.randomUUID()};written(db.prepare('INSERT INTO ca_namespace VALUES(?,1,?,?,?,?,?,?)')
          .run(namespace.namespace_id,k.issuer_id,k.issuer_epoch,k.principal_id,k.request_epoch,owner.context_id,owner.body));}
        written(db.prepare('INSERT INTO ca_request_key VALUES(?,?,?,?,?,?,?)').run(keyId,namespace.namespace_id,'createCommand',k.idempotency_key,identity.request_digest,value.device_id,bytes(commandContent(value))));
        const a=prepared.adjudication;
        written(db.prepare('INSERT INTO ca_adjudication VALUES(?,?,\'1\',\'accepted\',?,?,\'accept\',?,?)').run(keyId,a.adjudication_id,prepared.id,commitId,a.adjudication_digest,bytes(a)));
        const before=rows(db,'SELECT used_count FROM request_context WHERE context_id=?',value.context_id)[0].used_count;
        storeCommandRecord(db,prepared,keyId,commitId,before);
        written(db.prepare('INSERT INTO ca_commit VALUES(?,?,\'accept\',?,NULL,?)').run(commitId,keyId,keyId,bytes(commit)));
        written(db.prepare('INSERT INTO ca_audit VALUES(?,?,\'accept\',?)').run(commitId,keyId,bytes({identity,command_ref:a.command_ref,decision:'accepted'})));
        written(db.prepare('INSERT INTO ca_notification VALUES(?,?,\'accept\',?,?)').run(commitId,keyId,crypto.randomUUID(),bytes({identity,adjudication:a})));
        return withExecutionReadView(db,()=>{
        const saved=readCommandRecord(db,prepared.id);if(canonical(saved.adjudication)!==canonical(a))fail('command_binding');
        const last=contextCurrent(input,value.context_id,'submitCommand');if(last.denied)fail(last.denied);
        // T1只增加排队claim，不产生hold或出站帧；最终切点仍检查实际运行来源和原半开期限。
        const active=executionCurrent(value.device_id,{requireReady:true});if(canonical(active.ref)!==canonical(current.execution.ref)||canonical(active.ready.ref)!==canonical(current.execution.ready.ref))fail('command_execution_unavailable');
        const now=domain();if(canonical(now.ref)!==canonical(prepared.source.deadline.accepted.domain)||
          BigInt(now.tick)>=BigInt(current.execution.ready.value.expires_tick_ns)||BigInt(now.tick)>=BigInt(prepared.source.deadline.queue_deadline_tick_ns))fail('command_deadline');
        created=true;return a;
        });
      }));
      // 受理已经可靠提交才通知当前核心调度器；同键查原和进程重启不会补投。
      if(created&&Number(service.schema_revision)>=51)queueCommand?.(result.command_ref.object_id);
      return withStatus?{adjudication:result,replay:!created}:result;
    },
    getCommand(input,id){
      available();if(Number(service.schema_revision)<49)fail('command_admission_unavailable');
      assertCurrentProjection();
      return deliver(writer(()=>{
        const proof=authenticate(input,'command.read');if(proof.denied)return proof;
        const row=rows(db,'SELECT c.command_id FROM ca_command_initial c JOIN ca_request_key k USING(key_id) JOIN ca_namespace n USING(namespace_id) WHERE c.command_id=? AND n.issuer_id=? AND n.issuer_epoch=? AND n.principal_id=?',
          id,proof.issuer_id,proof.issuer_epoch,proof.principal_id)[0];
        if(!row)fail('command_not_found');const saved=readCommandRecord(db,id);
        const last=recheck(input,'command.read',saved.adjudication.identity);if(last.denied)return last;
        return {view:'current',record:saved.record};
      }));
    },
    getCommandEvidence(input,id,query){
      return evidenceRead(input,id,()=>{
        const revision=query.state_revision,limit=Number(query.limit);
        if(!/^[1-9][0-9]{0,19}$/.test(revision)||!Number.isSafeInteger(limit)||limit<1||limit>64)fail('command_request_invalid');
        const saved=readCommandRevision(db,id,revision),record=saved.record,index=record.evidence_index,
          evidence=saved.lifecycle?.settlement?.value.evidence??[];let offset=0;
        if(query.cursor!==undefined){try{
          if(typeof query.cursor!=='string'||query.cursor.length>1024||!/^[A-Za-z0-9_-]+$/.test(query.cursor))throw 0;
          const text=Buffer.from(query.cursor,'base64url').toString(),value=JSON.parse(text),{checksum,...body}=value;
          if(canonical(value)!==text||checksum!==digest(body)||body.command_id!==id||body.revision!==revision||body.snapshot_digest!==index.snapshot_ref.digest||
            !Number.isSafeInteger(body.offset)||body.offset<1||body.offset>=evidence.length||Object.keys(body).sort().join(',')!=='command_id,offset,revision,snapshot_digest')throw 0;
          offset=body.offset;
        }catch{fail('command_request_invalid');}}
        const items=evidence.slice(offset,offset+limit),next=offset+items.length,body={command_id:id,revision,snapshot_digest:index.snapshot_ref.digest,offset:next},
          next_cursor=next<evidence.length?Buffer.from(canonical({...body,checksum:digest(body)})).toString('base64url'):null,
          page={scope:record.scope,command_id:id,snapshot_ref:index.snapshot_ref,state_ref:record.state_ref,offset:String(offset),total:String(evidence.length),items,next_cursor};
        return {...page,page_digest:digest(page)};
      });
    },
    getCommandEvidenceRevision(input,id,evidenceId,revision){
      return evidenceRead(input,id,saved=>{
        if(revision!=='1')fail('command_not_found');const found=saved.lifecycle?.settlement?.value.evidence.find(v=>v.source_ref.id===evidenceId);
        if(!found)fail('command_not_found');return found;
      });
    },
    confirmCommandResult(input, identity, permission, expected) {
      available();
      return deliver(writer(() => {
        const proof = recheck(input, permission, identity); if (proof.denied) return proof;
        const found = find(identity), value = permission === 'command.read' && expected.state ? {state: found ? 'found' : 'not_found', adjudication: found?.value ?? null} : found?.value;
        if (canonical(value) !== canonical(expected)) fail('command_binding'); return value;
      }));
    },
  });
}
