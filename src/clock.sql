DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v3 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '3'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v3 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '3', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v3 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v3 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v3 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v3 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

-- 每个服务boot只保存一份最新诊断和首故障，不冒充不可变的认证Acquisition。
CREATE TABLE authentication_clock_diagnostic (
  service_boot_id TEXT PRIMARY KEY NOT NULL REFERENCES service_boot(service_boot_id),
  state TEXT NOT NULL CHECK(state IN ('unqualified', 'faulted')),
  reason TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 0),
  last_capture BLOB CHECK(last_capture IS NULL OR length(last_capture) <= 8192),
  native_artifact_digest TEXT,
  CHECK((sequence = 0 AND last_capture IS NULL AND native_artifact_digest IS NULL)
    OR (sequence > 0 AND last_capture IS NOT NULL AND native_artifact_digest IS NOT NULL))
) STRICT;
CREATE TRIGGER authentication_clock_latch BEFORE UPDATE ON authentication_clock_diagnostic
WHEN NEW.service_boot_id != OLD.service_boot_id OR OLD.state = 'faulted' OR NEW.sequence < OLD.sequence
BEGIN SELECT RAISE(ABORT, 'clock_fault_latched'); END;
CREATE TRIGGER authentication_clock_no_delete BEFORE DELETE ON authentication_clock_diagnostic
BEGIN SELECT RAISE(ABORT, 'clock_history_required'); END;
