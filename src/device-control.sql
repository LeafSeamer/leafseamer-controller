DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v26 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '26'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v26 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '26', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v26 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v26 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26')),
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
    OR (from_revision = '25' AND to_revision = '26' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v26 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v26 RENAME TO schema_migration;
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

CREATE TABLE control_change_commit (
 commit_id TEXT PRIMARY KEY NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('acquire','release','transfer','offer','cancel_offer','expire_offer','effective','indeterminate','rejected')),
 members INTEGER NOT NULL CHECK(members BETWEEN 1 AND 4),
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 event_id TEXT NOT NULL UNIQUE,
 notification_jcs TEXT NOT NULL CHECK(json_valid(notification_jcs))
) STRICT;
CREATE TABLE control_record_revision (
 device_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 16384),
 target_device_id TEXT NOT NULL REFERENCES device_record(device_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=16384),
 body_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(device_id,revision)
) STRICT;
CREATE TABLE control_record_head (
 device_id TEXT PRIMARY KEY NOT NULL,
 revision INTEGER NOT NULL,
 FOREIGN KEY(device_id,revision) REFERENCES control_record_revision(device_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER control_record_revision_sequence BEFORE INSERT ON control_record_revision
WHEN NEW.revision!=coalesce((SELECT revision FROM control_record_head WHERE device_id=NEW.device_id),1)+1
BEGIN SELECT RAISE(ABORT,'control_revision_sequence'); END;
CREATE TRIGGER control_record_head_advance BEFORE UPDATE ON control_record_head
WHEN NEW.device_id!=OLD.device_id OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'control_head_sequence'); END;
CREATE TRIGGER control_record_head_no_delete BEFORE DELETE ON control_record_head BEGIN SELECT RAISE(ABORT,'control_head_required'); END;
CREATE TRIGGER control_record_revision_no_update BEFORE UPDATE ON control_record_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TRIGGER control_record_revision_no_delete BEFORE DELETE ON control_record_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TABLE control_operation_revision (
 operation_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 16384),
 target_device_id TEXT NOT NULL REFERENCES device_record(device_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=16384),
 body_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(operation_id,revision)
) STRICT;
CREATE TABLE control_operation_head (
 operation_id TEXT PRIMARY KEY NOT NULL,
 revision INTEGER NOT NULL,
 FOREIGN KEY(operation_id,revision) REFERENCES control_operation_revision(operation_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER control_operation_revision_sequence BEFORE INSERT ON control_operation_revision
WHEN NEW.revision!=coalesce((SELECT revision FROM control_operation_head WHERE operation_id=NEW.operation_id),0)+1
BEGIN SELECT RAISE(ABORT,'control_revision_sequence'); END;
CREATE TRIGGER control_operation_head_advance BEFORE UPDATE ON control_operation_head
WHEN NEW.operation_id!=OLD.operation_id OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'control_head_sequence'); END;
CREATE TRIGGER control_operation_head_no_delete BEFORE DELETE ON control_operation_head BEGIN SELECT RAISE(ABORT,'control_head_required'); END;
CREATE TRIGGER control_operation_revision_no_update BEFORE UPDATE ON control_operation_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TRIGGER control_operation_revision_no_delete BEFORE DELETE ON control_operation_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TABLE control_offer_revision (
 transfer_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 16384),
 target_device_id TEXT NOT NULL REFERENCES device_record(device_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=16384),
 body_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(transfer_id,revision)
) STRICT;
CREATE TABLE control_offer_head (
 transfer_id TEXT PRIMARY KEY NOT NULL,
 revision INTEGER NOT NULL,
 FOREIGN KEY(transfer_id,revision) REFERENCES control_offer_revision(transfer_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER control_offer_revision_sequence BEFORE INSERT ON control_offer_revision
WHEN NEW.revision!=coalesce((SELECT revision FROM control_offer_head WHERE transfer_id=NEW.transfer_id),0)+1
BEGIN SELECT RAISE(ABORT,'control_revision_sequence'); END;
CREATE TRIGGER control_offer_head_advance BEFORE UPDATE ON control_offer_head
WHEN NEW.transfer_id!=OLD.transfer_id OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'control_head_sequence'); END;
CREATE TRIGGER control_offer_head_no_delete BEFORE DELETE ON control_offer_head BEGIN SELECT RAISE(ABORT,'control_head_required'); END;
CREATE TRIGGER control_offer_revision_no_update BEFORE UPDATE ON control_offer_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TRIGGER control_offer_revision_no_delete BEFORE DELETE ON control_offer_revision BEGIN SELECT RAISE(ABORT,'immutable_control_revision'); END;
CREATE TABLE control_request (
 key_digest TEXT PRIMARY KEY NOT NULL,
 key_jcs TEXT NOT NULL UNIQUE CHECK(json_valid(key_jcs)),
 request_digest TEXT NOT NULL,
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 context_id TEXT NOT NULL REFERENCES request_context(context_id),
 receipt_jcs TEXT NOT NULL CHECK(json_valid(receipt_jcs)),
 receipt_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL UNIQUE REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE control_barrier_target (
 operation_id TEXT NOT NULL,
 launch_id TEXT NOT NULL REFERENCES worker_launch_preparation(launch_id),
 launch_intent_digest TEXT NOT NULL,
 service_boot_id TEXT NOT NULL,
 PRIMARY KEY(operation_id,launch_id),
 FOREIGN KEY(operation_id) REFERENCES control_operation_head(operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE control_barrier_evidence (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES control_operation_head(operation_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=4194304),
 body_digest TEXT NOT NULL,
 commit_id TEXT NOT NULL UNIQUE REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER control_commit_members BEFORE INSERT ON control_change_commit
WHEN NEW.members!=(SELECT count(*) FROM control_record_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_operation_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_offer_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_request WHERE commit_id=NEW.commit_id)
BEGIN SELECT RAISE(ABORT,'control_commit_members'); END;
CREATE TRIGGER control_prepare_block BEFORE INSERT ON worker_launch_device WHEN EXISTS(
 SELECT 1 FROM control_record_head h JOIN control_record_revision r USING(device_id,revision)
 WHERE h.device_id=NEW.device_id AND json_extract(r.body_jcs,'$.pending_change') IS NOT NULL)
BEGIN SELECT RAISE(ABORT,'control_pending'); END;
CREATE TRIGGER control_change_commit_no_update BEFORE UPDATE ON control_change_commit BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_change_commit_no_delete BEFORE DELETE ON control_change_commit BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_request_no_update BEFORE UPDATE ON control_request BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_request_no_delete BEFORE DELETE ON control_request BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_barrier_target_no_update BEFORE UPDATE ON control_barrier_target BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_barrier_target_no_delete BEFORE DELETE ON control_barrier_target BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_barrier_evidence_no_update BEFORE UPDATE ON control_barrier_evidence BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_barrier_evidence_no_delete BEFORE DELETE ON control_barrier_evidence BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
