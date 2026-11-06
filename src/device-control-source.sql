DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v32 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '32'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v32 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '32', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v32 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v32 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32')),
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
    OR (from_revision = '31' AND to_revision = '32' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v32 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v32 RENAME TO schema_migration;
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

-- 只为本版本之后的真实控制变更保存完整物理原件，不回填旧观察时刻。
CREATE TABLE control_state_source (
 source_id TEXT PRIMARY KEY NOT NULL,
 device_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>=2),
 change_kind TEXT NOT NULL,
 clock_domain_id TEXT NOT NULL,
 descriptor_digest TEXT NOT NULL,
 observed_tick TEXT NOT NULL CHECK(length(observed_tick)=20 AND observed_tick NOT GLOB '*[^0-9]*'),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=16384),
 body_digest TEXT NOT NULL,
 UNIQUE(device_id,revision),
 FOREIGN KEY(device_id,revision) REFERENCES control_record_revision(device_id,revision) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(source_id) REFERENCES control_change_commit(commit_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER control_source_parent BEFORE INSERT ON control_state_source
WHEN NOT EXISTS (SELECT 1 FROM control_record_revision r WHERE r.device_id=NEW.device_id AND r.revision=NEW.revision
 AND r.commit_id=NEW.source_id
 AND json_extract(NEW.body_jcs,'$.format_version')='control-storage-body/1'
 AND json_extract(NEW.body_jcs,'$.change_id')=NEW.source_id
 AND json_extract(NEW.body_jcs,'$.revision')=CAST(NEW.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.change_kind')=NEW.change_kind
 AND json_extract(NEW.body_jcs,'$.clock_domain_id')=NEW.clock_domain_id
 AND json_extract(NEW.body_jcs,'$.descriptor_digest')=NEW.descriptor_digest
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.observed_tick_ns'),-20)=NEW.observed_tick
 AND json_extract(NEW.body_jcs,'$.record_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.scope')=json_extract(r.body_jcs,'$.scope')
 AND json_extract(NEW.body_jcs,'$.control_epoch')=json_extract(r.body_jcs,'$.control_epoch')
 AND json_extract(NEW.body_jcs,'$.effective_version')=json_extract(r.body_jcs,'$.effective_version')
 AND json_extract(NEW.body_jcs,'$.reserved_version')=json_extract(r.body_jcs,'$.reserved_version')
 AND json_extract(NEW.body_jcs,'$.mode')=json_extract(r.body_jcs,'$.mode')
 AND json_extract(NEW.body_jcs,'$.gate_state')=json_extract(r.body_jcs,'$.gate_state')
 AND json_extract(NEW.body_jcs,'$.pending_operation_id') IS json_extract(r.body_jcs,'$.pending_change.operation_id')
 AND ((json_extract(r.body_jcs,'$.holder') IS NULL AND json_extract(NEW.body_jcs,'$.holder') IS NULL)
 OR (json_extract(NEW.body_jcs,'$.holder.kind')='human'
 AND json_extract(NEW.body_jcs,'$.holder.issuer_id')=json_extract(r.body_jcs,'$.holder.issuer_id')
 AND json_extract(NEW.body_jcs,'$.holder.issuer_epoch')=json_extract(r.body_jcs,'$.holder.issuer_epoch')
 AND json_extract(NEW.body_jcs,'$.holder.principal_id')=json_extract(r.body_jcs,'$.holder.principal_id'))))
BEGIN SELECT RAISE(ABORT,'control_source_parent'); END;
CREATE TRIGGER control_source_commit BEFORE INSERT ON control_change_commit
WHEN EXISTS (SELECT 1 FROM control_record_revision r WHERE r.commit_id=NEW.commit_id AND NOT EXISTS (
 SELECT 1 FROM control_state_source s WHERE s.source_id=NEW.commit_id AND s.device_id=r.device_id AND s.revision=r.revision AND s.change_kind=NEW.kind))
BEGIN SELECT RAISE(ABORT,'control_source_required'); END;
CREATE TRIGGER control_source_no_backfill BEFORE INSERT ON control_state_source
WHEN EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.source_id)
BEGIN SELECT RAISE(ABORT,'control_source_commit_closed'); END;
CREATE TRIGGER control_record_commit_closed BEFORE INSERT ON control_record_revision
WHEN EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.commit_id)
BEGIN SELECT RAISE(ABORT,'control_source_commit_closed'); END;
CREATE TRIGGER control_source_no_update BEFORE UPDATE ON control_state_source BEGIN SELECT RAISE(ABORT,'immutable_control_source'); END;
CREATE TRIGGER control_source_no_delete BEFORE DELETE ON control_state_source BEGIN SELECT RAISE(ABORT,'immutable_control_source'); END;
CREATE TRIGGER control_source_clock BEFORE INSERT ON control_state_source
WHEN EXISTS(SELECT 1 FROM control_state_source s WHERE s.device_id=NEW.device_id AND s.clock_domain_id=NEW.clock_domain_id
 AND (s.descriptor_digest!=NEW.descriptor_digest OR s.observed_tick>NEW.observed_tick))
BEGIN SELECT RAISE(ABORT,'control_source_clock'); END;

CREATE TRIGGER execution_fence_control_source BEFORE INSERT ON execution_initial_fence
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_change_commit c ON c.commit_id=s.source_id
 WHERE s.device_id=NEW.control_device_id AND s.revision=NEW.control_revision
 AND json_extract(NEW.body_jcs,'$.control_source_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.control_source_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.control_source_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'execution_control_source_required'); END;

