DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v4 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '4'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v4 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '4', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v4 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v4 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL)
    OR (from_revision = '2' AND to_revision = '3' AND backup_ref IS NOT NULL)
    OR (from_revision = '3' AND to_revision = '4' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v4 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v4 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE authentication_clock_evidence (
  id TEXT NOT NULL COLLATE BINARY,
  revision TEXT NOT NULL COLLATE BINARY,
  digest TEXT NOT NULL COLLATE BINARY,
  kind TEXT NOT NULL CHECK(kind IN ('policy', 'runtime', 'health')),
  body BLOB NOT NULL CHECK(length(body) <= 32768),
  PRIMARY KEY(id, revision),
  UNIQUE(id, revision, digest)
) STRICT;
CREATE TRIGGER auth_clock_evidence_no_update BEFORE UPDATE ON authentication_clock_evidence
BEGIN SELECT RAISE(ABORT, 'immutable_clock_evidence'); END;
CREATE TRIGGER auth_clock_evidence_no_delete BEFORE DELETE ON authentication_clock_evidence
BEGIN SELECT RAISE(ABORT, 'immutable_clock_evidence'); END;

CREATE TABLE authentication_clock_acquisition (
  id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  revision TEXT NOT NULL CHECK(revision = '1'),
  digest TEXT NOT NULL COLLATE BINARY,
  service_boot_id TEXT NOT NULL REFERENCES service_boot(service_boot_id),
  clock_domain_id TEXT NOT NULL COLLATE BINARY,
  sequence TEXT NOT NULL COLLATE BINARY CHECK(length(sequence) = 20),
  parent_id TEXT REFERENCES authentication_clock_acquisition(id),
  policy_id TEXT NOT NULL, policy_revision TEXT NOT NULL, policy_digest TEXT NOT NULL,
  runtime_id TEXT NOT NULL, runtime_revision TEXT NOT NULL, runtime_digest TEXT NOT NULL,
  health_id TEXT NOT NULL, health_revision TEXT NOT NULL, health_digest TEXT NOT NULL,
  body BLOB NOT NULL CHECK(length(body) <= 32768),
  UNIQUE(service_boot_id, clock_domain_id, sequence),
  UNIQUE(service_boot_id, clock_domain_id, id),
  FOREIGN KEY(policy_id, policy_revision, policy_digest) REFERENCES authentication_clock_evidence(id, revision, digest),
  FOREIGN KEY(runtime_id, runtime_revision, runtime_digest) REFERENCES authentication_clock_evidence(id, revision, digest),
  FOREIGN KEY(health_id, health_revision, health_digest) REFERENCES authentication_clock_evidence(id, revision, digest)
) STRICT;
CREATE TRIGGER auth_clock_acquisition_no_update BEFORE UPDATE ON authentication_clock_acquisition
BEGIN SELECT RAISE(ABORT, 'immutable_clock_acquisition'); END;
CREATE TRIGGER auth_clock_acquisition_no_delete BEFORE DELETE ON authentication_clock_acquisition
BEGIN SELECT RAISE(ABORT, 'immutable_clock_acquisition'); END;

CREATE TABLE authentication_clock_head (
  service_boot_id TEXT NOT NULL,
  clock_domain_id TEXT NOT NULL COLLATE BINARY,
  acquisition_id TEXT NOT NULL,
  PRIMARY KEY(service_boot_id, clock_domain_id),
  FOREIGN KEY(service_boot_id, clock_domain_id, acquisition_id)
    REFERENCES authentication_clock_acquisition(service_boot_id, clock_domain_id, id)
) STRICT;
CREATE TRIGGER auth_clock_head_scope BEFORE UPDATE ON authentication_clock_head
WHEN NEW.service_boot_id != OLD.service_boot_id OR NEW.clock_domain_id != OLD.clock_domain_id
BEGIN SELECT RAISE(ABORT, 'immutable_clock_domain'); END;
CREATE TRIGGER auth_clock_head_no_delete BEFORE DELETE ON authentication_clock_head
BEGIN SELECT RAISE(ABORT, 'clock_history_required'); END;

CREATE TABLE authentication_clock_fault (
  service_boot_id TEXT NOT NULL REFERENCES service_boot(service_boot_id),
  clock_domain_id TEXT NOT NULL COLLATE BINARY,
  id TEXT NOT NULL UNIQUE COLLATE BINARY,
  digest TEXT NOT NULL COLLATE BINARY,
  body BLOB NOT NULL CHECK(length(body) <= 32768),
  PRIMARY KEY(service_boot_id, clock_domain_id)
) STRICT;
CREATE TRIGGER auth_clock_fault_no_update BEFORE UPDATE ON authentication_clock_fault
BEGIN SELECT RAISE(ABORT, 'clock_fault_latched'); END;
CREATE TRIGGER auth_clock_fault_no_delete BEFORE DELETE ON authentication_clock_fault
BEGIN SELECT RAISE(ABORT, 'clock_fault_latched'); END;
