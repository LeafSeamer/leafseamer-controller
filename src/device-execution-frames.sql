DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v28 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '28'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v28 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '28', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v28 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v28 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28')),
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
    OR (from_revision = '27' AND to_revision = '28' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v28 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v28 RENAME TO schema_migration;
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

-- 旧版本的拒收历史保留原样；不为过去的记录编造采样时刻或新的提交证明。
CREATE TABLE execution_frame_record (
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
 domain_kind TEXT NOT NULL CHECK(domain_kind='hello_rejection'),
 UNIQUE(ipc_session_id,direction,sequence),UNIQUE(ipc_session_id,direction,message_id),
 UNIQUE(record_id,ipc_session_id,message_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_effect_commit(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(record_id,ipc_session_id,message_id,transaction_id) REFERENCES execution_rejection_frame(record_id,ipc_session_id,message_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_effect_commit (
 record_id TEXT PRIMARY KEY NOT NULL REFERENCES execution_frame_record(record_id),
 transaction_id TEXT NOT NULL UNIQUE,
 disposition TEXT NOT NULL CHECK(disposition IN('applied','historical','rejected')),
 committed_tick TEXT NOT NULL CHECK(length(committed_tick)=20 AND committed_tick NOT GLOB '*[^0-9]*'),
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs) AND length(CAST(audit_jcs AS BLOB))<=8192),
 audit_digest TEXT NOT NULL CHECK(length(audit_digest)=71),
 effect_jcs TEXT NOT NULL CHECK(json_valid(effect_jcs) AND length(CAST(effect_jcs AS BLOB))<=16384),
 effect_digest TEXT NOT NULL CHECK(length(effect_digest)=71),
 UNIQUE(record_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES execution_frame_record(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE UNIQUE INDEX execution_frame_transaction ON execution_frame_record(record_id,transaction_id);
CREATE TABLE execution_rejection_frame (
 record_id TEXT PRIMARY KEY NOT NULL,
 ipc_session_id TEXT NOT NULL UNIQUE,
 message_id TEXT NOT NULL,
 transaction_id TEXT NOT NULL UNIQUE,
 domain_jcs TEXT NOT NULL CHECK(json_valid(domain_jcs) AND length(CAST(domain_jcs AS BLOB))<=8192),
 domain_digest TEXT NOT NULL CHECK(length(domain_digest)=71),
 UNIQUE(record_id,ipc_session_id,message_id,transaction_id),
 FOREIGN KEY(record_id,ipc_session_id,message_id,transaction_id) REFERENCES execution_frame_record(record_id,ipc_session_id,message_id,transaction_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(transaction_id,ipc_session_id,message_id) REFERENCES execution_rejection_commit(transaction_id,ipc_session_id,message_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
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
 SELECT CASE WHEN NEW.domain_kind!='hello_rejection' OR NEW.direction!='w2c' OR NEW.message_type!='HELLO'
 OR NEW.sequence!='00000000000000000001' OR NEW.device_id IS NOT NULL OR NEW.reply_record_id IS NOT NULL
 OR json_type(NEW.frame_jcs,'$.reply_to')!='null'
 THEN RAISE(ABORT,'execution_frame_domain') END;
 SELECT CASE WHEN (SELECT count(*) FROM execution_frame_record)>=65536 OR
 (SELECT coalesce(sum(length(wire)+length(CAST(frame_jcs AS BLOB))+length(CAST(record_jcs AS BLOB))+32768),0) FROM execution_frame_record)
 +length(NEW.wire)+length(CAST(NEW.frame_jcs AS BLOB))+length(CAST(NEW.record_jcs AS BLOB))+32768>67108864
 THEN RAISE(ABORT,'execution_frame_capacity') END;
END;
CREATE TRIGGER execution_rejection_frame_required BEFORE INSERT ON execution_rejection_commit
WHEN NOT EXISTS(SELECT 1 FROM execution_rejection_frame x JOIN execution_frame_record f USING(record_id)
 WHERE x.ipc_session_id=NEW.ipc_session_id AND x.message_id=NEW.message_id AND x.transaction_id=NEW.transaction_id
 AND f.domain_kind='hello_rejection')
BEGIN SELECT RAISE(ABORT,'execution_rejection_frame_required'); END;
CREATE TRIGGER execution_effect_domain BEFORE INSERT ON execution_effect_commit BEGIN
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
CREATE TRIGGER execution_frame_no_update BEFORE UPDATE ON execution_frame_record BEGIN SELECT RAISE(ABORT,'immutable_execution_frame'); END;
CREATE TRIGGER execution_frame_no_delete BEFORE DELETE ON execution_frame_record BEGIN SELECT RAISE(ABORT,'immutable_execution_frame'); END;
CREATE TRIGGER execution_effect_no_update BEFORE UPDATE ON execution_effect_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_effect'); END;
CREATE TRIGGER execution_effect_no_delete BEFORE DELETE ON execution_effect_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_effect'); END;
CREATE TRIGGER execution_rejection_frame_no_update BEFORE UPDATE ON execution_rejection_frame BEGIN SELECT RAISE(ABORT,'immutable_execution_domain'); END;
CREATE TRIGGER execution_rejection_frame_no_delete BEFORE DELETE ON execution_rejection_frame BEGIN SELECT RAISE(ABORT,'immutable_execution_domain'); END;

