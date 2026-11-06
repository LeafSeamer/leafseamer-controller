DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v47 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '47'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v47 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '47', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v47 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v47 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL)
    OR (from_revision = '3' AND to_revision = '4' AND backup_ref IS NOT NULL)
    OR (from_revision = '4' AND to_revision = '5' AND backup_ref IS NOT NULL)
    OR (from_revision = '5' AND to_revision = '6' AND backup_ref IS NOT NULL)
    OR (from_revision = '6' AND to_revision = '7' AND backup_ref IS NOT NULL)
    OR (from_revision = '7' AND to_revision = '8' AND backup_ref IS NOT NULL)
    OR (from_revision = '8' AND to_revision = '9' AND backup_ref IS NOT NULL)
    OR (from_revision = '9' AND to_revision = '10' AND backup_ref IS NOT NULL)
    OR (from_revision = '10' AND to_revision = '11' AND backup_ref IS NOT NULL)
    OR (from_revision = '11' AND to_revision = '12' AND backup_ref IS NOT NULL)
    OR (from_revision = '12' AND to_revision = '13' AND backup_ref IS NOT NULL)
    OR (from_revision = '13' AND to_revision = '14' AND backup_ref IS NOT NULL)
    OR (from_revision = '14' AND to_revision = '15' AND backup_ref IS NOT NULL)
    OR (from_revision = '15' AND to_revision = '16' AND backup_ref IS NOT NULL)
    OR (from_revision = '16' AND to_revision = '17' AND backup_ref IS NOT NULL)
    OR (from_revision = '17' AND to_revision = '18' AND backup_ref IS NOT NULL)
    OR (from_revision = '18' AND to_revision = '19' AND backup_ref IS NOT NULL)
    OR (from_revision = '19' AND to_revision = '20' AND backup_ref IS NOT NULL)
    OR (from_revision = '20' AND to_revision = '21' AND backup_ref IS NOT NULL)
    OR (from_revision = '21' AND to_revision = '22' AND backup_ref IS NOT NULL)
    OR (from_revision = '22' AND to_revision = '23' AND backup_ref IS NOT NULL)
    OR (from_revision = '23' AND to_revision = '24' AND backup_ref IS NOT NULL)
    OR (from_revision = '24' AND to_revision = '25' AND backup_ref IS NOT NULL)
    OR (from_revision = '25' AND to_revision = '26' AND backup_ref IS NOT NULL)
    OR (from_revision = '26' AND to_revision = '27' AND backup_ref IS NOT NULL)
    OR (from_revision = '27' AND to_revision = '28' AND backup_ref IS NOT NULL)
    OR (from_revision = '28' AND to_revision = '29' AND backup_ref IS NOT NULL)
    OR (from_revision = '29' AND to_revision = '30' AND backup_ref IS NOT NULL)
    OR (from_revision = '30' AND to_revision = '31' AND backup_ref IS NOT NULL)
    OR (from_revision = '31' AND to_revision = '32' AND backup_ref IS NOT NULL)
    OR (from_revision = '32' AND to_revision = '33' AND backup_ref IS NOT NULL)
    OR (from_revision = '33' AND to_revision = '34' AND backup_ref IS NOT NULL)
    OR (from_revision = '34' AND to_revision = '35' AND backup_ref IS NOT NULL)
    OR (from_revision = '35' AND to_revision = '36' AND backup_ref IS NOT NULL)
    OR (from_revision = '36' AND to_revision = '37' AND backup_ref IS NOT NULL)
    OR (from_revision = '37' AND to_revision = '38' AND backup_ref IS NOT NULL)
    OR (from_revision = '38' AND to_revision = '39' AND backup_ref IS NOT NULL)
    OR (from_revision = '39' AND to_revision = '40' AND backup_ref IS NOT NULL)
    OR (from_revision = '40' AND to_revision = '41' AND backup_ref IS NOT NULL)
    OR (from_revision = '41' AND to_revision = '42' AND backup_ref IS NOT NULL)
    OR (from_revision = '42' AND to_revision = '43' AND backup_ref IS NOT NULL)
    OR (from_revision = '43' AND to_revision = '44' AND backup_ref IS NOT NULL)
    OR (from_revision = '44' AND to_revision = '45' AND backup_ref IS NOT NULL)
    OR (from_revision = '45' AND to_revision = '46' AND backup_ref IS NOT NULL)
    OR (from_revision = '46' AND to_revision = '47' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v47 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v47 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TRIGGER request_context_parent BEFORE INSERT ON request_context
WHEN NOT EXISTS (
  SELECT 1 FROM service_state a JOIN service_boot b ON b.service_id = a.service_id
  JOIN auth_session s ON s.session_id = NEW.session_id
  JOIN session_refresh_credential c ON c.credential_id = NEW.credential_id AND c.session_id = s.session_id
  JOIN access_token t ON t.token_id = NEW.token_id AND t.session_id = s.session_id AND t.credential_id = c.credential_id
  WHERE a.service_id = NEW.service_id AND a.database_instance_id = NEW.database_instance_id
    AND a.request_epoch = NEW.context_epoch AND b.service_boot_id = NEW.service_boot_id AND b.state = 'started'
    AND s.issuer_id = NEW.issuer_id AND s.issuer_epoch = NEW.issuer_epoch AND s.principal_id = NEW.principal_id
    AND s.state = 'active' AND c.state != 'revoked' AND t.state = 'active' AND t.audience = NEW.service_id
    AND NEW.not_before_ns >= t.not_before_ns AND NEW.expires_ns <= t.expires_ns)
BEGIN SELECT RAISE(ABORT, 'request_context_parent'); END;

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;

CREATE TRIGGER device_authorization_state_parent BEFORE INSERT ON device_authorization_state
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_record_head h ON h.device_id=s.device_id AND h.revision=s.revision
 JOIN service_state v ON v.singleton=1 WHERE s.source_id=NEW.control_source_id AND s.device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format_version')='device-authorization-state/0.1.0-draft.1'
 AND json_extract(NEW.body_jcs,'$.state_id')=NEW.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.revision'),-20)=NEW.revision
 AND json_extract(NEW.body_jcs,'$.state_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.parent_ref.id') IS NEW.parent_id
 AND ((json_extract(NEW.body_jcs,'$.status')='protected' AND json_extract(NEW.body_jcs,'$.recovery_ref') IS NULL) OR
 (json_extract(NEW.body_jcs,'$.status')='policy_selected' AND EXISTS(SELECT 1 FROM device_recovery_consumption r
 JOIN device_recovery_authorization a USING(authorization_id) WHERE r.state_id=NEW.state_id AND r.commit_id=NEW.commit_id
 AND a.authorization_id=json_extract(NEW.body_jcs,'$.recovery_ref.id') AND a.protected_state_id=NEW.parent_id
 AND a.device_id=NEW.device_id)))
 AND json_extract(NEW.body_jcs,'$.context.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.context.scope.authority_service_id')=v.service_id
 AND json_extract(NEW.body_jcs,'$.context.scope.database_instance_id')=v.database_instance_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'device_authorization_state_parent'); END;

CREATE TABLE execution_initial_open_dispatch (
 opening_id TEXT PRIMARY KEY NOT NULL REFERENCES device_initial_open(opening_id),
 request_record_id TEXT NOT NULL UNIQUE,request_transaction_id TEXT NOT NULL UNIQUE,
 configuration_message_id TEXT NOT NULL REFERENCES device_module_frame(message_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 UNIQUE(opening_id,request_record_id,request_transaction_id),
 FOREIGN KEY(request_record_id,request_transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_initial_open_ack (
 opening_id TEXT PRIMARY KEY NOT NULL REFERENCES execution_initial_open_dispatch(opening_id),record_id TEXT NOT NULL UNIQUE,transaction_id TEXT NOT NULL UNIQUE,
 write_attempt_id TEXT NOT NULL REFERENCES execution_write_attempt(attempt_id),body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 UNIQUE(opening_id,record_id,transaction_id),FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_open_frame (
 record_id TEXT PRIMARY KEY NOT NULL,transaction_id TEXT NOT NULL UNIQUE,opening_id TEXT NOT NULL REFERENCES execution_initial_open_dispatch(opening_id) DEFERRABLE INITIALLY DEFERRED,
 phase TEXT NOT NULL CHECK(phase IN('request','ack')),domain_jcs TEXT NOT NULL CHECK(json_valid(domain_jcs)),domain_digest TEXT NOT NULL CHECK(length(domain_digest)=71),
 request_opening_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='request' THEN opening_id END) VIRTUAL,
 ack_opening_id TEXT GENERATED ALWAYS AS(CASE WHEN phase='ack' THEN opening_id END) VIRTUAL,
 UNIQUE(record_id,transaction_id),UNIQUE(opening_id,phase),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(request_opening_id,record_id,transaction_id) REFERENCES execution_initial_open_dispatch(opening_id,request_record_id,request_transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(ack_opening_id,record_id,transaction_id) REFERENCES execution_initial_open_ack(opening_id,record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
DROP TRIGGER execution_control_effect;
DROP TRIGGER execution_effect_domain;
DROP TRIGGER execution_frame_no_delete;
DROP TRIGGER execution_frame_no_update;
DROP TRIGGER execution_frame_parent;
DROP TRIGGER execution_handshake_effect;
DROP TRIGGER execution_handshake_parent;
DROP TRIGGER execution_initial_fence_ack_parent;
DROP TRIGGER execution_initial_fence_parent;
DROP TRIGGER execution_rejection_frame_required;
DROP TRIGGER execution_write_parent;
CREATE TABLE execution_frame_record_v47 (
 record_id TEXT PRIMARY KEY NOT NULL,
 ipc_session_id TEXT NOT NULL REFERENCES execution_session(ipc_session_id),
 direction TEXT NOT NULL CHECK(direction IN('c2w','w2c')),
 sequence TEXT NOT NULL CHECK(length(sequence)=20 AND sequence NOT GLOB '*[^0-9]*' AND sequence>'00000000000000000000'),
 message_id TEXT NOT NULL,
 message_type TEXT NOT NULL,
 device_id TEXT,
 reply_record_id TEXT REFERENCES execution_frame_record(record_id),
 wire BLOB NOT NULL CHECK(length(wire) BETWEEN 5 AND 262148),
 frame_jcs TEXT NOT NULL CHECK(json_valid(frame_jcs) AND length(CAST(frame_jcs AS BLOB))<=262144),
 wire_digest TEXT NOT NULL CHECK(length(wire_digest)=71),
 frame_digest TEXT NOT NULL CHECK(length(frame_digest)=71),
 record_jcs TEXT NOT NULL CHECK(json_valid(record_jcs) AND length(CAST(record_jcs AS BLOB))<=8192),
 record_digest TEXT NOT NULL CHECK(length(record_digest)=71),
 observed_tick TEXT NOT NULL CHECK(length(observed_tick)=20 AND observed_tick NOT GLOB '*[^0-9]*'),
 transaction_id TEXT NOT NULL UNIQUE,
 domain_kind TEXT NOT NULL CHECK(domain_kind IN('hello_rejection','hello_negotiation','initial_control','initial_open')),
 rejection_record_id TEXT GENERATED ALWAYS AS(CASE WHEN domain_kind='hello_rejection' THEN record_id END) VIRTUAL,
 handshake_record_id TEXT GENERATED ALWAYS AS(CASE WHEN domain_kind='hello_negotiation' THEN record_id END) VIRTUAL,
 control_record_id TEXT GENERATED ALWAYS AS(CASE WHEN domain_kind='initial_control' THEN record_id END) VIRTUAL,
 open_record_id TEXT GENERATED ALWAYS AS(CASE WHEN domain_kind='initial_open' THEN record_id END) VIRTUAL,
 UNIQUE(ipc_session_id,direction,sequence),UNIQUE(ipc_session_id,direction,message_id),
 UNIQUE(record_id,ipc_session_id,message_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_effect_commit(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(rejection_record_id,ipc_session_id,message_id,transaction_id) REFERENCES execution_rejection_frame(record_id,ipc_session_id,message_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(handshake_record_id,transaction_id) REFERENCES execution_handshake_frame(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(control_record_id,transaction_id) REFERENCES execution_control_frame(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(open_record_id,transaction_id) REFERENCES execution_open_frame(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO execution_frame_record_v47 (record_id,ipc_session_id,direction,sequence,message_id,message_type,device_id,reply_record_id,wire,frame_jcs,wire_digest,frame_digest,record_jcs,record_digest,observed_tick,transaction_id,domain_kind) SELECT record_id,ipc_session_id,direction,sequence,message_id,message_type,device_id,reply_record_id,wire,frame_jcs,wire_digest,frame_digest,record_jcs,record_digest,observed_tick,transaction_id,domain_kind FROM execution_frame_record;
DROP TABLE execution_frame_record;
ALTER TABLE execution_frame_record_v47 RENAME TO execution_frame_record;
CREATE UNIQUE INDEX execution_frame_transaction ON execution_frame_record(record_id,transaction_id);
CREATE TRIGGER execution_control_effect BEFORE INSERT ON execution_effect_commit
WHEN (SELECT domain_kind FROM execution_frame_record WHERE record_id=NEW.record_id)='initial_control' BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_control_frame x USING(record_id,transaction_id)
 JOIN execution_initial_fence p USING(fence_id) LEFT JOIN execution_initial_fence_ack a USING(fence_id)
 WHERE f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id AND f.observed_tick<=NEW.committed_tick AND NEW.disposition='applied'
 AND ((x.phase='request' AND f.record_id=p.request_record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=p.body_digest)
 OR (x.phase='ack' AND f.record_id=a.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=a.body_digest))
 AND json_extract(x.domain_jcs,'$.transaction_id')=f.transaction_id AND json_extract(x.domain_jcs,'$.source_ref.id')=p.fence_id||CASE WHEN x.phase='ack' THEN '.ack' ELSE '' END
 AND json_extract(NEW.effect_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.effect_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.effect_jcs,'$.disposition')='applied'
 AND json_array_length(NEW.effect_jcs,'$.domain_commit_refs')=1 AND json_array_length(NEW.effect_jcs,'$.reply_record_refs')=0
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')=f.transaction_id AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].digest')=x.domain_digest
 AND json_extract(NEW.effect_jcs,'$.audit_ref.id')=f.transaction_id||'.audit' AND json_extract(NEW.effect_jcs,'$.audit_ref.digest')=NEW.audit_digest
 AND json_extract(NEW.audit_jcs,'$.kind')='initial_control_'||x.phase AND json_extract(NEW.audit_jcs,'$.fence_id')=p.fence_id
 AND json_extract(NEW.audit_jcs,'$.source_digest')=json_extract(x.domain_jcs,'$.source_ref.digest')
 AND substr('00000000000000000000'||json_extract(NEW.effect_jcs,'$.committed_tick_ns'),-20)=NEW.committed_tick)
 THEN RAISE(ABORT,'execution_control_effect_binding') END;
END;
CREATE TRIGGER execution_effect_domain BEFORE INSERT ON execution_effect_commit
WHEN (SELECT domain_kind FROM execution_frame_record WHERE record_id=NEW.record_id)='hello_rejection' BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_rejection_frame x USING(record_id)
 JOIN execution_rejection r ON r.ipc_session_id=x.ipc_session_id AND r.message_id=x.message_id AND r.transaction_id=x.transaction_id
 JOIN execution_rejection_commit c ON c.transaction_id=r.transaction_id
 JOIN execution_session_end e ON e.ipc_session_id=r.ipc_session_id AND e.transaction_id=r.transaction_id AND e.reason=r.reason
 WHERE f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id AND NEW.disposition='rejected'
 AND f.observed_tick<=NEW.committed_tick AND f.wire=r.wire AND f.frame_jcs=r.frame_jcs AND f.frame_digest=r.frame_digest AND f.wire_digest=r.wire_digest
 AND json_extract(x.domain_jcs,'$.transaction_id')=r.transaction_id AND json_extract(x.domain_jcs,'$.ipc_session_id')=r.ipc_session_id
 AND json_extract(x.domain_jcs,'$.message_id')=r.message_id AND json_extract(x.domain_jcs,'$.frame_digest')=r.frame_digest
 AND json_extract(x.domain_jcs,'$.disposition')='rejected' AND json_extract(x.domain_jcs,'$.reason')=r.reason
 AND json_extract(NEW.effect_jcs,'$.record_ref.id')=f.record_id
 AND json_extract(NEW.effect_jcs,'$.record_ref.revision')='1'
 AND json_extract(NEW.effect_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.effect_jcs,'$.disposition')=NEW.disposition
 AND json_array_length(NEW.effect_jcs,'$.domain_commit_refs')=1
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')=r.transaction_id
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].revision')='1'
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].digest')=x.domain_digest
 AND json_type(NEW.effect_jcs,'$.reply_record_refs')='array'
 AND json_array_length(NEW.effect_jcs,'$.reply_record_refs')=0
 AND json_extract(NEW.effect_jcs,'$.audit_ref.id')=r.transaction_id||'.audit'
 AND json_extract(NEW.effect_jcs,'$.audit_ref.revision')='1'
 AND json_extract(NEW.effect_jcs,'$.audit_ref.digest')=NEW.audit_digest
 AND json_type(NEW.effect_jcs,'$.committed_tick_ns')='text'
 AND substr('00000000000000000000'||json_extract(NEW.effect_jcs,'$.committed_tick_ns'),-20)=NEW.committed_tick
 AND json_extract(NEW.audit_jcs,'$.kind')='execution_rejection'
 AND json_extract(NEW.audit_jcs,'$.ipc_session_id')=f.ipc_session_id
 AND json_extract(NEW.audit_jcs,'$.message_id')=f.message_id
 AND json_extract(NEW.audit_jcs,'$.frame_digest')=f.frame_digest
 AND json_extract(NEW.audit_jcs,'$.reason')=r.reason)
 THEN RAISE(ABORT,'execution_effect_domain') END;
END;
CREATE TRIGGER execution_frame_no_delete BEFORE DELETE ON execution_frame_record BEGIN SELECT RAISE(ABORT,'immutable_execution_frame'); END;
CREATE TRIGGER execution_frame_no_update BEFORE UPDATE ON execution_frame_record BEGIN SELECT RAISE(ABORT,'immutable_execution_frame'); END;
CREATE TRIGGER execution_frame_parent BEFORE INSERT ON execution_frame_record BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_session s JOIN service_boot b USING(service_boot_id)
 WHERE s.ipc_session_id=NEW.ipc_session_id AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id)
 AND json_extract(NEW.frame_jcs,'$.ipc_session_id')=s.ipc_session_id
 AND json_extract(NEW.frame_jcs,'$.ipc_version')=json_extract(s.binding_jcs,'$.ipc_version')
 AND json_extract(NEW.frame_jcs,'$.controller_boot_id')=s.controller_boot_id
 AND json_extract(NEW.frame_jcs,'$.worker_boot_id')=s.worker_boot_id
 AND json_extract(NEW.frame_jcs,'$.clock_domain_id')=s.clock_domain_id
 AND json_extract(NEW.frame_jcs,'$.descriptor_digest')=s.descriptor_digest
 AND json_extract(NEW.frame_jcs,'$.message_id')=NEW.message_id
 AND json_extract(NEW.frame_jcs,'$.type')=NEW.message_type
 AND json_extract(NEW.frame_jcs,'$.journal_mode')='durable'
 AND json_type(NEW.frame_jcs,'$.seq')='text'
 AND substr('00000000000000000000'||json_extract(NEW.frame_jcs,'$.seq'),-20)=NEW.sequence
 AND json_extract(NEW.frame_jcs,'$.device_id') IS NEW.device_id
 AND json_extract(NEW.record_jcs,'$.record_id')=NEW.record_id
 AND json_extract(NEW.record_jcs,'$.session_ref.id')=s.ipc_session_id
 AND json_extract(NEW.record_jcs,'$.session_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.session_ref.digest')=s.binding_digest
 AND json_extract(NEW.record_jcs,'$.direction')=NEW.direction
 AND json_extract(NEW.record_jcs,'$.sequence')=json_extract(NEW.frame_jcs,'$.seq')
 AND json_extract(NEW.record_jcs,'$.message_id')=NEW.message_id
 AND json_extract(NEW.record_jcs,'$.message_type')=NEW.message_type
 AND json_extract(NEW.record_jcs,'$.frame_digest')=NEW.frame_digest
 AND json_extract(NEW.record_jcs,'$.wire_digest')=NEW.wire_digest
 AND json_extract(NEW.record_jcs,'$.wire_length')=length(NEW.wire)
 AND json_extract(NEW.record_jcs,'$.record_digest')=NEW.record_digest
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.id')=NEW.record_id||'.frame'
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.frame_object_ref.digest')=NEW.frame_digest
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.id')=NEW.record_id||'.wire'
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.revision')='1'
 AND json_extract(NEW.record_jcs,'$.wire_object_ref.digest')=NEW.wire_digest)
 THEN RAISE(ABORT,'execution_frame_binding') END;
 SELECT CASE WHEN NEW.sequence!=coalesce((SELECT CASE WHEN substr(sequence,11,10)='9999999999'
 THEN printf('%010d',CAST(substr(sequence,1,10) AS INTEGER)+1)||'0000000000'
 ELSE substr(sequence,1,10)||printf('%010d',CAST(substr(sequence,11,10) AS INTEGER)+1) END
 FROM execution_frame_record WHERE ipc_session_id=NEW.ipc_session_id AND direction=NEW.direction ORDER BY sequence DESC LIMIT 1),'00000000000000000001')
 THEN RAISE(ABORT,'execution_frame_sequence') END;
 -- 每个已实现领域必须显式连接真实写集；尚未连接的类型不能以通用applied绕过。
 SELECT CASE WHEN NOT (NEW.sequence='00000000000000000001' AND NEW.device_id IS NULL AND (
 (NEW.direction='w2c' AND NEW.message_type='HELLO' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.domain_kind='hello_negotiation' AND NEW.direction='c2w' AND NEW.message_type='HELLO_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record h
 WHERE h.record_id=NEW.reply_record_id AND h.ipc_session_id=NEW.ipc_session_id AND h.direction='w2c' AND h.message_type='HELLO' AND h.domain_kind='hello_negotiation'
 AND h.message_id=json_extract(NEW.frame_jcs,'$.reply_to')))) OR
 (NEW.domain_kind='initial_control' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001' AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
 (NEW.direction='c2w' AND NEW.message_type='FENCE' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
 (NEW.direction='w2c' AND NEW.message_type='FENCE_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.direction='c2w' AND p.message_type='FENCE' AND p.domain_kind='initial_control' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))) OR (NEW.domain_kind='initial_open' AND NEW.device_id IS NOT NULL AND NEW.sequence>'00000000000000000001'
   AND EXISTS(SELECT 1 FROM execution_handshake n WHERE n.ipc_session_id=NEW.ipc_session_id) AND (
    (NEW.direction='c2w' AND NEW.message_type='OPEN_GATE' AND NEW.reply_record_id IS NULL AND json_type(NEW.frame_jcs,'$.reply_to')='null') OR
    (NEW.direction='w2c' AND NEW.message_type='OPEN_GATE_ACK' AND EXISTS(SELECT 1 FROM execution_frame_record p
     WHERE p.record_id=NEW.reply_record_id AND p.ipc_session_id=NEW.ipc_session_id AND p.direction='c2w' AND p.message_type='OPEN_GATE'
      AND p.domain_kind='initial_open' AND p.message_id=json_extract(NEW.frame_jcs,'$.reply_to'))))))
 THEN RAISE(ABORT,'execution_frame_domain') END;
 SELECT CASE WHEN (SELECT count(*) FROM execution_frame_record)>=65536 OR
 (SELECT coalesce(sum(length(wire)+length(CAST(frame_jcs AS BLOB))+length(CAST(record_jcs AS BLOB))+32768),0) FROM execution_frame_record)
 +length(NEW.wire)+length(CAST(NEW.frame_jcs AS BLOB))+length(CAST(NEW.record_jcs AS BLOB))+32768>67108864
 THEN RAISE(ABORT,'execution_frame_capacity') END;
END;
CREATE TRIGGER execution_handshake_effect BEFORE INSERT ON execution_effect_commit
WHEN (SELECT domain_kind FROM execution_frame_record WHERE record_id=NEW.record_id)='hello_negotiation' BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_handshake_frame x USING(record_id,transaction_id)
 JOIN execution_handshake n USING(negotiation_id)
 WHERE f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id AND f.observed_tick<=NEW.committed_tick
 AND ((f.direction='w2c' AND n.hello_record_id=f.record_id AND n.hello_transaction_id=f.transaction_id)
 OR (f.direction='c2w' AND n.ack_record_id=f.record_id AND n.ack_transaction_id=f.transaction_id))
 AND NEW.disposition='applied' AND NEW.audit_jcs=n.audit_jcs AND NEW.audit_digest=n.audit_digest
 AND json_extract(x.domain_jcs,'$.transaction_id')=NEW.transaction_id
 AND json_extract(x.domain_jcs,'$.negotiation_ref.id')=n.negotiation_id
 AND json_extract(x.domain_jcs,'$.negotiation_ref.digest')=n.body_digest
 AND json_extract(NEW.effect_jcs,'$.record_ref.id')=f.record_id
 AND json_extract(NEW.effect_jcs,'$.record_ref.revision')='1'
 AND json_extract(NEW.effect_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.effect_jcs,'$.disposition')='applied'
 AND json_array_length(NEW.effect_jcs,'$.domain_commit_refs')=1
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')=NEW.transaction_id
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].revision')='1'
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].digest')=x.domain_digest
 AND json_extract(NEW.effect_jcs,'$.audit_ref.id')=n.negotiation_id||'.audit'
 AND json_extract(NEW.effect_jcs,'$.audit_ref.revision')='1'
 AND json_extract(NEW.effect_jcs,'$.audit_ref.digest')=n.audit_digest
 AND json_type(NEW.effect_jcs,'$.committed_tick_ns')='text'
 AND substr('00000000000000000000'||json_extract(NEW.effect_jcs,'$.committed_tick_ns'),-20)=NEW.committed_tick
 AND ((f.direction='c2w' AND json_array_length(NEW.effect_jcs,'$.reply_record_refs')=0) OR
 (f.direction='w2c' AND json_array_length(NEW.effect_jcs,'$.reply_record_refs')=1
 AND json_extract(NEW.effect_jcs,'$.reply_record_refs[0]')=json_extract(n.body_jcs,'$.ack_record_ref'))))
 THEN RAISE(ABORT,'execution_handshake_effect') END;
END;
CREATE TRIGGER execution_handshake_parent BEFORE INSERT ON execution_handshake BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_session s
 JOIN execution_frame_record h ON h.record_id=NEW.hello_record_id AND h.transaction_id=NEW.hello_transaction_id
 JOIN execution_frame_record a ON a.record_id=NEW.ack_record_id AND a.transaction_id=NEW.ack_transaction_id
 WHERE s.ipc_session_id=NEW.ipc_session_id AND h.ipc_session_id=s.ipc_session_id AND a.ipc_session_id=s.ipc_session_id
 AND h.direction='w2c' AND h.message_type='HELLO' AND a.direction='c2w' AND a.message_type='HELLO_ACK'
 AND h.domain_kind='hello_negotiation' AND a.domain_kind='hello_negotiation' AND a.reply_record_id=h.record_id
 AND json_extract(NEW.body_jcs,'$.negotiation_id')=NEW.negotiation_id
 AND json_extract(NEW.body_jcs,'$.ipc_session_id')=s.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.gate_state')='closed'
 AND json_extract(NEW.body_jcs,'$.selected_ipc_version')=json_extract(s.binding_jcs,'$.ipc_version')
 AND json_extract(NEW.body_jcs,'$.selected_features')=json_extract(a.frame_jcs,'$.body.selected_features')
 AND json_extract(NEW.body_jcs,'$.module_id')=json_extract(h.frame_jcs,'$.body.module_id')
 AND json_extract(NEW.body_jcs,'$.module_digest')=json_extract(h.frame_jcs,'$.body.module_digest')
 AND json_extract(NEW.body_jcs,'$.hello_record_ref.id')=h.record_id
 AND json_extract(NEW.body_jcs,'$.hello_record_ref.digest')=h.record_digest
 AND json_extract(NEW.body_jcs,'$.ack_record_ref.id')=a.record_id
 AND json_extract(NEW.body_jcs,'$.ack_record_ref.digest')=a.record_digest
 AND json_extract(NEW.audit_jcs,'$.kind')='execution_handshake_closed'
 AND json_extract(NEW.audit_jcs,'$.negotiation_id')=NEW.negotiation_id
 AND json_extract(NEW.audit_jcs,'$.body_digest')=NEW.body_digest
 AND NOT EXISTS(SELECT 1 FROM json_each(a.frame_jcs,'$.body.selected_features') selected
 WHERE NOT EXISTS(SELECT 1 FROM json_each(h.frame_jcs,'$.body.supported_features') offered WHERE offered.value=selected.value)))
 THEN RAISE(ABORT,'execution_handshake_binding') END;
END;
CREATE TRIGGER execution_initial_fence_ack_parent BEFORE INSERT ON execution_initial_fence_ack BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_initial_fence p
 JOIN execution_frame_record request ON request.record_id=p.request_record_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN execution_write_attempt w ON w.record_id=request.record_id
 JOIN control_record_head h ON h.device_id=p.control_device_id AND h.revision=p.control_revision
 WHERE p.fence_id=NEW.fence_id AND f.reply_record_id=request.record_id AND f.ipc_session_id=request.ipc_session_id
 AND f.device_id=request.device_id AND f.direction='w2c' AND f.message_type='FENCE_ACK' AND f.domain_kind='initial_control'
 AND json_extract(NEW.body_jcs,'$.fence_ref.id')=p.fence_id AND json_extract(NEW.body_jcs,'$.fence_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.body_jcs,'$.gate_state')='closed'
 AND json_extract(f.frame_jcs,'$.body.ack.barrier_id')=p.fence_id
 AND json_extract(f.frame_jcs,'$.body.ack.control_epoch')=json_extract(request.frame_jcs,'$.body.control_epoch')
 AND json_extract(f.frame_jcs,'$.body.ack.installed_version')=json_extract(request.frame_jcs,'$.body.target_version')
 AND json_extract(f.frame_jcs,'$.body.ack.all_write_exits_fenced')=1
 AND json_extract(f.frame_jcs,'$.body.gate_revision')='1' AND json_extract(f.frame_jcs,'$.body.issued_cut_revision')='0'
 AND json_extract(f.frame_jcs,'$.body.attempt_binding')=json_extract(request.frame_jcs,'$.body.attempt_binding')
 AND json_array_length(f.frame_jcs,'$.body.coverage')=0 AND json_array_length(f.frame_jcs,'$.body.transmission_coverage')=0
 AND json_array_length(f.frame_jcs,'$.body.cancel_coverage')=0
 AND json_array_length(f.frame_jcs,'$.body.ack.discarded_permit_ids')=0 AND json_array_length(f.frame_jcs,'$.body.ack.in_flight_command_ids')=0
 AND json_array_length(f.frame_jcs,'$.body.ack.unresolved_command_ids')=0
 AND substr('00000000000000000000'||json_extract(f.frame_jcs,'$.body.effective_tick_ns'),-20) BETWEEN w.started_tick AND f.observed_tick)
 THEN RAISE(ABORT,'execution_initial_fence_ack_binding') END;
END;
CREATE TRIGGER execution_initial_fence_parent BEFORE INSERT ON execution_initial_fence BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM device_execution_binding b
 JOIN control_record_revision c ON c.device_id=NEW.control_device_id AND c.revision=NEW.control_revision
 JOIN control_record_head h ON h.device_id=c.device_id AND h.revision=c.revision
 JOIN execution_frame_record f ON f.record_id=NEW.request_record_id AND f.transaction_id=NEW.request_transaction_id
 JOIN execution_handshake n ON n.ipc_session_id=b.ipc_session_id
 WHERE b.binding_id=NEW.binding_id AND b.device_id=c.device_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id
 AND f.direction='c2w' AND f.message_type='FENCE' AND f.domain_kind='initial_control'
 AND json_extract(c.body_jcs,'$.mode')='manual' AND json_extract(c.body_jcs,'$.gate_state')='protected'
 AND json_type(c.body_jcs,'$.pending_change')='null'
 AND json_array_length(c.body_jcs,'$.in_flight_command_ids')=0 AND json_array_length(c.body_jcs,'$.unresolved_command_ids')=0
 AND json_extract(NEW.body_jcs,'$.fence_id')=NEW.fence_id
 AND json_extract(NEW.body_jcs,'$.gate_state')='closed'
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.control_record')=c.body_jcs
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(f.frame_jcs,'$.body.barrier_id')=NEW.fence_id
 AND json_extract(f.frame_jcs,'$.body.control_epoch')=json_extract(c.body_jcs,'$.control_epoch')
 AND json_extract(f.frame_jcs,'$.body.target_version')=json_extract(c.body_jcs,'$.effective_version')
 AND json_extract(f.frame_jcs,'$.body.target_gate_revision')='1' AND json_extract(f.frame_jcs,'$.body.issued_cut_revision')='0'
 AND json_array_length(f.frame_jcs,'$.body.open_intents')=0 AND json_array_length(f.frame_jcs,'$.body.open_transmission_intents')=0
 AND json_array_length(f.frame_jcs,'$.body.cancel_transmissions')=0
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.target_exit_id')=b.writer_exit_id
 AND json_extract(f.frame_jcs,'$.body.attempt_binding.attempt_ordinal')='1' AND json_type(f.frame_jcs,'$.body.attempt_binding.previous_barrier_id')='null'
 AND EXISTS(SELECT 1 FROM json_each(n.body_jcs,'$.selected_features') WHERE value='initial_control_fence')
 AND NOT EXISTS(SELECT 1 FROM ca_adjudication a JOIN ca_request_key k USING(key_id) WHERE k.device_id=b.device_id AND a.decision!='rejected'))
 THEN RAISE(ABORT,'execution_initial_fence_binding') END;
END;
CREATE TRIGGER execution_rejection_frame_required BEFORE INSERT ON execution_rejection_commit
WHEN NOT EXISTS(SELECT 1 FROM execution_rejection_frame x JOIN execution_frame_record f USING(record_id)
 WHERE x.ipc_session_id=NEW.ipc_session_id AND x.message_id=NEW.message_id AND x.transaction_id=NEW.transaction_id
 AND f.domain_kind='hello_rejection')
BEGIN SELECT RAISE(ABORT,'execution_rejection_frame_required'); END;
CREATE TRIGGER execution_write_parent BEFORE INSERT ON execution_write_attempt BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_effect_commit e USING(record_id,transaction_id)
 LEFT JOIN execution_handshake n ON n.ack_record_id=f.record_id LEFT JOIN execution_initial_fence c ON c.request_record_id=f.record_id LEFT JOIN execution_initial_open_dispatch o ON o.request_record_id=f.record_id JOIN execution_session s ON s.ipc_session_id=f.ipc_session_id
 JOIN service_boot b USING(service_boot_id)
 WHERE f.record_id=NEW.record_id AND f.direction='c2w' AND ((f.message_type='HELLO_ACK' AND n.ack_record_id=f.record_id) OR (f.message_type='FENCE' AND c.request_record_id=f.record_id) OR (f.message_type='OPEN_GATE' AND o.request_record_id=f.record_id)) AND e.disposition='applied'
 AND e.committed_tick<=NEW.started_tick AND b.state='started'
 AND NOT EXISTS(SELECT 1 FROM execution_session_end x WHERE x.ipc_session_id=s.ipc_session_id)
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=s.runtime_id))
 THEN RAISE(ABORT,'execution_write_binding') END;
END;
CREATE TRIGGER execution_initial_open_parent BEFORE INSERT ON execution_initial_open_dispatch WHEN NOT EXISTS (
 SELECT 1 FROM device_initial_open o JOIN device_initial_resource r ON r.source_id=o.resource_source_id
 JOIN device_execution_binding b ON b.binding_id=o.binding_id JOIN device_authorization_evidence_head h ON h.evidence_id=o.evidence_id
 JOIN device_module_frame a ON a.message_id=NEW.configuration_message_id JOIN device_module_frame q ON q.message_id=a.reply_to
 JOIN execution_frame_record f ON f.record_id=NEW.request_record_id AND f.transaction_id=NEW.request_transaction_id
 WHERE o.opening_id=NEW.opening_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id AND f.direction='c2w' AND f.message_type='OPEN_GATE' AND f.domain_kind='initial_open'
 AND a.message_type='EXECUTION_BOUND' AND a.direction='w2c' AND q.message_type='BIND_EXECUTION' AND q.direction='c2w' AND a.channel_id=q.channel_id
 AND json_extract(q.frame_jcs,'$.body.execution.value')=b.body_jcs AND json_extract(q.frame_jcs,'$.body.execution.ref.digest')=b.body_digest
 AND json_extract(a.frame_jcs,'$.body.execution_ref.id')=b.binding_id AND json_extract(a.frame_jcs,'$.body.execution_ref.digest')=b.body_digest
 AND json_extract(f.frame_jcs,'$.body')=json_extract(o.body_jcs,'$.plan.body')
 AND json_extract(NEW.body_jcs,'$.opening_ref.id')=o.opening_id AND json_extract(NEW.body_jcs,'$.opening_ref.digest')=o.body_digest
 AND json_extract(NEW.body_jcs,'$.worker_configuration_ref.id')=a.message_id AND json_extract(NEW.body_jcs,'$.worker_configuration_ref.digest')=a.frame_digest
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
) BEGIN SELECT RAISE(ABORT,'execution_initial_open_binding'); END;
CREATE TRIGGER execution_initial_open_ack_parent BEFORE INSERT ON execution_initial_open_ack WHEN NOT EXISTS (
 SELECT 1 FROM execution_initial_open_dispatch p JOIN execution_frame_record q ON q.record_id=p.request_record_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN execution_write_attempt w ON w.attempt_id=NEW.write_attempt_id AND w.record_id=q.record_id
 WHERE p.opening_id=NEW.opening_id AND f.direction='w2c' AND f.message_type='OPEN_GATE_ACK' AND f.domain_kind='initial_open'
 AND f.reply_record_id=q.record_id AND f.ipc_session_id=q.ipc_session_id AND f.device_id=q.device_id AND w.started_tick<=f.observed_tick
 AND NOT EXISTS(SELECT 1 FROM execution_write_result x WHERE x.attempt_id=w.attempt_id AND x.result='unknown')
 AND json_extract(NEW.body_jcs,'$.dispatch_ref.id')=p.opening_id||'.dispatch' AND json_extract(NEW.body_jcs,'$.dispatch_ref.digest')=p.body_digest
 AND json_extract(NEW.body_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.body_jcs,'$.write_attempt_id')=w.attempt_id AND json_extract(NEW.body_jcs,'$.gate_state')='open_observed'
 AND json_extract(f.frame_jcs,'$.body.state')='open' AND json_extract(f.frame_jcs,'$.body.gate_token')=json_extract(q.frame_jcs,'$.body.gate_token')
 AND json_extract(f.frame_jcs,'$.body.gate_revision')=json_extract(q.frame_jcs,'$.body.gate_revision')
 AND json_extract(f.frame_jcs,'$.body.gate_access_ref.id')=json_extract(q.frame_jcs,'$.body.gate_access.access_id')
 AND json_extract(f.frame_jcs,'$.body.gate_access_ref.digest')=json_extract(q.frame_jcs,'$.body.gate_access.access_digest')
) BEGIN SELECT RAISE(ABORT,'execution_initial_open_ack_binding'); END;
CREATE TRIGGER execution_open_effect BEFORE INSERT ON execution_effect_commit
WHEN (SELECT domain_kind FROM execution_frame_record WHERE record_id=NEW.record_id)='initial_open' BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM execution_frame_record f JOIN execution_open_frame x USING(record_id,transaction_id)
 JOIN execution_initial_open_dispatch p USING(opening_id) LEFT JOIN execution_initial_open_ack a USING(opening_id)
 WHERE f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id AND f.observed_tick<=NEW.committed_tick AND NEW.disposition='applied'
 AND ((x.phase='request' AND f.record_id=p.request_record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=p.body_digest)
 OR (x.phase='ack' AND f.record_id=a.record_id AND json_extract(x.domain_jcs,'$.source_ref.digest')=a.body_digest))
 AND json_extract(x.domain_jcs,'$.transaction_id')=f.transaction_id AND json_extract(x.domain_jcs,'$.source_ref.id')=p.opening_id||CASE WHEN x.phase='ack' THEN '.ack' ELSE '.dispatch' END
 AND json_extract(NEW.effect_jcs,'$.record_ref.id')=f.record_id AND json_extract(NEW.effect_jcs,'$.record_ref.digest')=f.record_digest
 AND json_extract(NEW.effect_jcs,'$.disposition')='applied'
 AND json_array_length(NEW.effect_jcs,'$.domain_commit_refs')=1 AND json_array_length(NEW.effect_jcs,'$.reply_record_refs')=0
 AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].id')=f.transaction_id AND json_extract(NEW.effect_jcs,'$.domain_commit_refs[0].digest')=x.domain_digest
 AND json_extract(NEW.effect_jcs,'$.audit_ref.id')=f.transaction_id||'.audit' AND json_extract(NEW.effect_jcs,'$.audit_ref.digest')=NEW.audit_digest
 AND json_extract(NEW.audit_jcs,'$.kind')='initial_open_'||x.phase AND json_extract(NEW.audit_jcs,'$.opening_id')=p.opening_id
 AND json_extract(NEW.audit_jcs,'$.source_digest')=json_extract(x.domain_jcs,'$.source_ref.digest')
 AND substr('00000000000000000000'||json_extract(NEW.effect_jcs,'$.committed_tick_ns'),-20)=NEW.committed_tick)
 THEN RAISE(ABORT,'execution_open_effect_binding') END;
END;
CREATE TRIGGER execution_initial_open_dispatch_no_update BEFORE UPDATE ON execution_initial_open_dispatch BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
CREATE TRIGGER execution_initial_open_dispatch_no_delete BEFORE DELETE ON execution_initial_open_dispatch BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
CREATE TRIGGER execution_initial_open_ack_no_update BEFORE UPDATE ON execution_initial_open_ack BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
CREATE TRIGGER execution_initial_open_ack_no_delete BEFORE DELETE ON execution_initial_open_ack BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
CREATE TRIGGER execution_open_frame_no_update BEFORE UPDATE ON execution_open_frame BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
CREATE TRIGGER execution_open_frame_no_delete BEFORE DELETE ON execution_open_frame BEGIN SELECT RAISE(ABORT,'immutable_execution_open'); END;
