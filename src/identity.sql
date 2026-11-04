-- 显式从v1升级；调用方在事务外关闭FK，在提交前检查完整FK，再重新启用。
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v2 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '2'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v2 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '2', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v2 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v2 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2')),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK((from_revision = '0' AND to_revision = '1' AND backup_ref IS NULL)
    OR (from_revision = '1' AND to_revision = '2' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v2 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v2 RENAME TO schema_migration;
CREATE TRIGGER schema_migration_no_update BEFORE UPDATE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;
CREATE TRIGGER schema_migration_no_delete BEFORE DELETE ON schema_migration
BEGIN SELECT RAISE(ABORT, 'immutable_migration'); END;

CREATE TABLE identity_initialization (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  tx_id TEXT NOT NULL UNIQUE,
  challenge_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL UNIQUE,
  issuer_id TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL CHECK(mode IN ('standalone', 'suite_issuer')),
  FOREIGN KEY(challenge_id, tx_id) REFERENCES first_admin_challenge(token_id, consumed_tx_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(principal_id, tx_id) REFERENCES local_principal(principal_id, initialization_tx_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(principal_id, tx_id) REFERENCES local_authorization(principal_id, initialization_tx_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(issuer_id, tx_id) REFERENCES identity_issuer(issuer_id, initialization_tx_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(tx_id) REFERENCES identity_receipt(tx_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE identity_issuer (
  issuer_id TEXT PRIMARY KEY NOT NULL,
  issuer_epoch TEXT NOT NULL,
  initialization_tx_id TEXT NOT NULL UNIQUE REFERENCES identity_initialization(tx_id) DEFERRABLE INITIALLY DEFERRED,
  UNIQUE(issuer_id, issuer_epoch), UNIQUE(issuer_id, initialization_tx_id)
) STRICT;
CREATE TABLE subject (
  local_subject_id TEXT PRIMARY KEY NOT NULL,
  issuer_id TEXT NOT NULL,
  issuer_epoch TEXT NOT NULL,
  principal_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK(kind = 'human'),
  UNIQUE(issuer_id, issuer_epoch, principal_id),
  FOREIGN KEY(issuer_id, issuer_epoch) REFERENCES identity_issuer(issuer_id, issuer_epoch)
) STRICT;
CREATE TABLE local_principal (
  principal_id TEXT PRIMARY KEY NOT NULL REFERENCES subject(principal_id),
  login TEXT NOT NULL COLLATE BINARY UNIQUE,
  password_phc TEXT NOT NULL,
  password_profile TEXT NOT NULL CHECK(password_profile = 'identity-runtime/1'),
  state TEXT NOT NULL CHECK(state = 'active'),
  revision TEXT NOT NULL CHECK(revision = '1'),
  initialization_tx_id TEXT NOT NULL UNIQUE REFERENCES identity_initialization(tx_id) DEFERRABLE INITIALLY DEFERRED,
  UNIQUE(principal_id, initialization_tx_id)
) STRICT;
CREATE TABLE local_authorization (
  principal_id TEXT PRIMARY KEY NOT NULL REFERENCES subject(principal_id),
  role TEXT NOT NULL CHECK(role = 'administrator'),
  revision TEXT NOT NULL CHECK(revision = '1'),
  initialization_tx_id TEXT NOT NULL UNIQUE REFERENCES identity_initialization(tx_id) DEFERRABLE INITIALLY DEFERRED,
  UNIQUE(principal_id, initialization_tx_id)
) STRICT;
CREATE TABLE first_admin_challenge (
  token_id TEXT PRIMARY KEY NOT NULL,
  service_boot_id TEXT NOT NULL REFERENCES service_boot(service_boot_id),
  verifier BLOB NOT NULL CHECK(length(verifier) = 32),
  state TEXT NOT NULL CHECK(state IN ('pending', 'consumed', 'invalidated')),
  consumed_tx_id TEXT UNIQUE REFERENCES identity_initialization(tx_id) DEFERRABLE INITIALLY DEFERRED,
  CHECK((state = 'consumed' AND consumed_tx_id IS NOT NULL) OR (state != 'consumed' AND consumed_tx_id IS NULL)),
  UNIQUE(token_id, consumed_tx_id)
) STRICT;
CREATE UNIQUE INDEX first_admin_pending ON first_admin_challenge(state) WHERE state = 'pending';
CREATE TRIGGER first_admin_transition BEFORE UPDATE ON first_admin_challenge
WHEN NEW.token_id != OLD.token_id OR NEW.service_boot_id != OLD.service_boot_id OR NEW.verifier != OLD.verifier
  OR OLD.state != 'pending' OR NEW.state = 'pending'
BEGIN SELECT RAISE(ABORT, 'invalid_challenge_transition'); END;
CREATE TABLE identity_receipt (
  tx_id TEXT PRIMARY KEY NOT NULL REFERENCES identity_initialization(tx_id) DEFERRABLE INITIALLY DEFERRED,
  kind TEXT NOT NULL CHECK(kind = 'first_admin'),
  principal_id TEXT NOT NULL UNIQUE REFERENCES local_principal(principal_id),
  challenge_id TEXT NOT NULL UNIQUE REFERENCES first_admin_challenge(token_id)
) STRICT;
CREATE TRIGGER identity_initialization_no_update BEFORE UPDATE ON identity_initialization
BEGIN SELECT RAISE(ABORT, 'immutable_initialization'); END;
CREATE TRIGGER identity_initialization_no_delete BEFORE DELETE ON identity_initialization
BEGIN SELECT RAISE(ABORT, 'immutable_initialization'); END;
