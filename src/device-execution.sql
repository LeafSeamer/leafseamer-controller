DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v27 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '27'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v27 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '27', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v27 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v27 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27')),
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
    OR (from_revision = '26' AND to_revision = '27' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v27 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v27 RENAME TO schema_migration;
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

CREATE TABLE execution_session (
 ipc_session_id TEXT PRIMARY KEY NOT NULL,
 runtime_id TEXT NOT NULL UNIQUE REFERENCES worker_runtime_binding(runtime_id),
 service_boot_id TEXT NOT NULL REFERENCES service_boot(service_boot_id),
 controller_boot_id TEXT NOT NULL,
 worker_boot_id TEXT NOT NULL UNIQUE,
 clock_domain_id TEXT NOT NULL,
 descriptor_digest TEXT NOT NULL,
 binding_jcs TEXT NOT NULL CHECK(json_valid(binding_jcs) AND length(CAST(binding_jcs AS BLOB))<=32768),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=71),
 transaction_id TEXT NOT NULL UNIQUE,
 UNIQUE(transaction_id,ipc_session_id),
 FOREIGN KEY(transaction_id,ipc_session_id) REFERENCES execution_session_commit(transaction_id,ipc_session_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_session_commit (
 transaction_id TEXT PRIMARY KEY NOT NULL,
 ipc_session_id TEXT NOT NULL UNIQUE,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 UNIQUE(transaction_id,ipc_session_id),
 FOREIGN KEY(transaction_id,ipc_session_id) REFERENCES execution_session(transaction_id,ipc_session_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_session_end (
 ipc_session_id TEXT PRIMARY KEY NOT NULL REFERENCES execution_session(ipc_session_id),
 transaction_id TEXT NOT NULL UNIQUE,
 reason TEXT NOT NULL CHECK(reason IN('closed','restarted','runtime_lost','protocol_error','storage_failed','unsupported_message')),
 UNIQUE(ipc_session_id,transaction_id,reason)
) STRICT;
CREATE TABLE execution_rejection (
 ipc_session_id TEXT PRIMARY KEY NOT NULL REFERENCES execution_session(ipc_session_id),
 message_id TEXT NOT NULL,
 wire BLOB NOT NULL CHECK(length(wire) BETWEEN 5 AND 262148),
 frame_jcs TEXT NOT NULL CHECK(json_valid(frame_jcs) AND length(CAST(frame_jcs AS BLOB))<=262144),
 wire_digest TEXT NOT NULL CHECK(length(wire_digest)=71),
 frame_digest TEXT NOT NULL CHECK(length(frame_digest)=71),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 transaction_id TEXT NOT NULL UNIQUE,
 reason TEXT NOT NULL CHECK(reason='unsupported_message'),
 UNIQUE(transaction_id,ipc_session_id,message_id),
 FOREIGN KEY(transaction_id,ipc_session_id,message_id) REFERENCES execution_rejection_commit(transaction_id,ipc_session_id,message_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(ipc_session_id,transaction_id,reason) REFERENCES execution_session_end(ipc_session_id,transaction_id,reason) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE execution_rejection_commit (
 transaction_id TEXT PRIMARY KEY NOT NULL,
 ipc_session_id TEXT NOT NULL UNIQUE,
 message_id TEXT NOT NULL,
 UNIQUE(transaction_id,ipc_session_id,message_id),
 FOREIGN KEY(transaction_id,ipc_session_id,message_id) REFERENCES execution_rejection(transaction_id,ipc_session_id,message_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER execution_session_parent BEFORE INSERT ON execution_session WHEN NOT EXISTS(
 SELECT 1 FROM worker_runtime_binding r JOIN core_runtime_binding c USING(service_boot_id)
 JOIN service_boot b USING(service_boot_id)
 WHERE r.runtime_id=NEW.runtime_id AND r.service_boot_id=NEW.service_boot_id AND b.state='started'
 AND json_extract(NEW.binding_jcs,'$.authority')='controller'
 AND json_extract(NEW.binding_jcs,'$.service_id')=b.service_id
 AND json_extract(NEW.binding_jcs,'$.database_instance_id')=b.database_instance_id
 AND r.member_boot_id=NEW.worker_boot_id
 AND json_extract(c.receipt_jcs,'$.member_boot_id')=NEW.controller_boot_id
 AND json_extract(r.body_jcs,'$.clock_domain_descriptor.clock_domain_id')=NEW.clock_domain_id
 AND json_extract(r.body_jcs,'$.clock_domain_descriptor.descriptor_digest')=NEW.descriptor_digest
 AND json_extract(NEW.binding_jcs,'$.ipc_session_id')=NEW.ipc_session_id
 AND json_extract(NEW.binding_jcs,'$.runtime_binding_id')=NEW.runtime_id
 AND json_extract(NEW.binding_jcs,'$.service_boot_id')=NEW.service_boot_id
 AND json_extract(NEW.binding_jcs,'$.controller_boot_id')=NEW.controller_boot_id
 AND json_extract(NEW.binding_jcs,'$.worker_boot_id')=NEW.worker_boot_id
 AND json_extract(NEW.binding_jcs,'$.clock_domain_id')=NEW.clock_domain_id
 AND json_extract(NEW.binding_jcs,'$.descriptor_digest')=NEW.descriptor_digest
 AND json_extract(NEW.binding_jcs,'$.device_ids')=json_extract(r.body_jcs,'$.launch_intent.object_scope.device_ids')
 AND NOT EXISTS(SELECT 1 FROM worker_runtime_withdrawal w WHERE w.runtime_id=r.runtime_id)
) BEGIN SELECT RAISE(ABORT,'execution_runtime_binding'); END;
CREATE TRIGGER execution_session_capacity BEFORE INSERT ON execution_session
WHEN (SELECT count(*) FROM execution_session)>=4096
BEGIN SELECT RAISE(ABORT,'execution_session_capacity'); END;
CREATE TRIGGER execution_runtime_withdrawal AFTER INSERT ON worker_runtime_withdrawal
BEGIN
 INSERT INTO execution_session_end
 SELECT s.ipc_session_id,'runtime.'||NEW.transaction_id,'runtime_lost' FROM execution_session s
 WHERE s.runtime_id=NEW.runtime_id AND NOT EXISTS(SELECT 1 FROM execution_session_end e WHERE e.ipc_session_id=s.ipc_session_id);
END;
CREATE TRIGGER execution_rejection_parent BEFORE INSERT ON execution_rejection WHEN NOT EXISTS(
 SELECT 1 FROM execution_session s JOIN service_boot b USING(service_boot_id)
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
 AND json_extract(NEW.frame_jcs,'$.type')='HELLO'
 AND json_extract(NEW.frame_jcs,'$.seq')='1'
 AND json_type(NEW.frame_jcs,'$.seq')='text'
 AND json_type(NEW.frame_jcs,'$.device_id')='null'
 AND json_type(NEW.frame_jcs,'$.reply_to')='null'
 AND json_extract(NEW.frame_jcs,'$.journal_mode')='durable'
) BEGIN SELECT RAISE(ABORT,'execution_rejection_binding'); END;
CREATE TRIGGER execution_rejection_capacity BEFORE INSERT ON execution_rejection
WHEN (SELECT coalesce(sum(length(wire)+length(CAST(frame_jcs AS BLOB))),0) FROM execution_rejection)
 +length(NEW.wire)+length(CAST(NEW.frame_jcs AS BLOB))>67108864
BEGIN SELECT RAISE(ABORT,'execution_journal_capacity'); END;
CREATE TRIGGER execution_end_rejection AFTER INSERT ON execution_session_end WHEN NEW.reason='unsupported_message'
AND NOT EXISTS(SELECT 1 FROM execution_rejection WHERE ipc_session_id=NEW.ipc_session_id AND transaction_id=NEW.transaction_id)
BEGIN SELECT RAISE(ABORT,'execution_rejection_required'); END;
CREATE TRIGGER execution_session_no_update BEFORE UPDATE ON execution_session BEGIN SELECT RAISE(ABORT,'immutable_execution_session'); END;
CREATE TRIGGER execution_session_no_delete BEFORE DELETE ON execution_session BEGIN SELECT RAISE(ABORT,'immutable_execution_session'); END;
CREATE TRIGGER execution_session_commit_no_update BEFORE UPDATE ON execution_session_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_session'); END;
CREATE TRIGGER execution_session_commit_no_delete BEFORE DELETE ON execution_session_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_session'); END;
CREATE TRIGGER execution_session_end_no_update BEFORE UPDATE ON execution_session_end BEGIN SELECT RAISE(ABORT,'immutable_execution_end'); END;
CREATE TRIGGER execution_session_end_no_delete BEFORE DELETE ON execution_session_end BEGIN SELECT RAISE(ABORT,'immutable_execution_end'); END;
CREATE TRIGGER execution_rejection_no_update BEFORE UPDATE ON execution_rejection BEGIN SELECT RAISE(ABORT,'immutable_execution_rejection'); END;
CREATE TRIGGER execution_rejection_no_delete BEFORE DELETE ON execution_rejection BEGIN SELECT RAISE(ABORT,'immutable_execution_rejection'); END;
CREATE TRIGGER execution_rejection_commit_no_update BEFORE UPDATE ON execution_rejection_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_rejection'); END;
CREATE TRIGGER execution_rejection_commit_no_delete BEFORE DELETE ON execution_rejection_commit BEGIN SELECT RAISE(ABORT,'immutable_execution_rejection'); END;

