DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v7 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '7'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v7 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '7', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v7 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v7 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7')),
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
    OR (from_revision = '6' AND to_revision = '7' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v7 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v7 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE local_permission_revision (
  principal_id TEXT NOT NULL REFERENCES local_principal(principal_id),
  revision TEXT NOT NULL CHECK(length(revision) = 20 AND revision NOT GLOB '*[^0-9]*'
    AND revision > '00000000000000000000' AND revision <= '18446744073709551615'),
  id TEXT NOT NULL UNIQUE,
  state TEXT NOT NULL CHECK(state IN ('active', 'pending')),
  digest TEXT NOT NULL,
  body BLOB NOT NULL CHECK(length(body) <= 16384),
  PRIMARY KEY(principal_id, revision),
  UNIQUE(principal_id, revision, id)
) STRICT;
CREATE TABLE local_permission_head (
  principal_id TEXT PRIMARY KEY NOT NULL REFERENCES local_principal(principal_id),
  revision TEXT NOT NULL,
  id TEXT NOT NULL,
  FOREIGN KEY(principal_id, revision, id) REFERENCES local_permission_revision(principal_id, revision, id)
) STRICT;
CREATE TRIGGER local_permission_revision_immutable BEFORE UPDATE ON local_permission_revision
BEGIN SELECT RAISE(ABORT, 'immutable_permission_revision'); END;
CREATE TRIGGER local_permission_revision_no_delete BEFORE DELETE ON local_permission_revision
BEGIN SELECT RAISE(ABORT, 'immutable_permission_revision'); END;
CREATE TRIGGER local_permission_head_forward BEFORE UPDATE ON local_permission_head
WHEN NEW.principal_id != OLD.principal_id OR NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'permission_revision_order'); END;
CREATE TRIGGER local_permission_head_no_delete BEFORE DELETE ON local_permission_head
BEGIN SELECT RAISE(ABORT, 'immutable_permission_head'); END;
CREATE TABLE local_permission_operation (
  operation_id TEXT PRIMARY KEY NOT NULL,
  actor_credential_id TEXT NOT NULL REFERENCES session_refresh_credential(credential_id),
  request_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  acquisition_id TEXT NOT NULL REFERENCES authentication_clock_acquisition(id),
  body BLOB NOT NULL CHECK(length(body) <= 32768),
  UNIQUE(actor_credential_id, request_id),
  FOREIGN KEY(principal_id, revision, grant_id) REFERENCES local_permission_revision(principal_id, revision, id)
) STRICT;
CREATE TABLE local_permission_target (
  operation_id TEXT NOT NULL REFERENCES local_permission_operation(operation_id),
  target_service_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state = 'pending'),
  PRIMARY KEY(operation_id, target_service_id)
) STRICT;
CREATE TABLE local_permission_outbox (
  operation_id TEXT NOT NULL,
  target_service_id TEXT NOT NULL,
  PRIMARY KEY(operation_id, target_service_id),
  FOREIGN KEY(operation_id, target_service_id) REFERENCES local_permission_target(operation_id, target_service_id)
) STRICT;
CREATE TRIGGER local_permission_operation_immutable BEFORE UPDATE ON local_permission_operation
BEGIN SELECT RAISE(ABORT, 'immutable_permission_operation'); END;
CREATE TRIGGER local_permission_operation_no_delete BEFORE DELETE ON local_permission_operation
BEGIN SELECT RAISE(ABORT, 'immutable_permission_operation'); END;
CREATE TRIGGER local_permission_target_immutable BEFORE UPDATE ON local_permission_target
BEGIN SELECT RAISE(ABORT, 'immutable_permission_target'); END;
CREATE TRIGGER local_permission_target_no_delete BEFORE DELETE ON local_permission_target
BEGIN SELECT RAISE(ABORT, 'immutable_permission_target'); END;
