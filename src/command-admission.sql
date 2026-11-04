DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v9 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '9'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v9 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '9', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v9 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v9 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9')),
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
    OR (from_revision = '8' AND to_revision = '9' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v9 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v9 RENAME TO schema_migration;
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

CREATE TABLE ca_scope (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  authority_service_id TEXT NOT NULL CHECK(length(authority_service_id)>0),
  database_instance_id TEXT NOT NULL CHECK(length(database_instance_id)>0),
  contract_version TEXT NOT NULL CHECK(contract_version='command-admission/0.1.0-draft.1')
) STRICT;

CREATE TABLE ca_namespace (
  namespace_id TEXT PRIMARY KEY NOT NULL,
  scope_id INTEGER NOT NULL CHECK(scope_id=1) REFERENCES ca_scope(singleton),
  issuer_id TEXT NOT NULL,
  issuer_epoch TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_epoch TEXT NOT NULL,
  owner_evidence_id TEXT NOT NULL REFERENCES request_context(context_id),
  owner_evidence_body BLOB NOT NULL CHECK(length(owner_evidence_body)>0),
  UNIQUE(issuer_id,issuer_epoch,principal_id,request_epoch),
  CHECK(length(namespace_id)>0 AND length(issuer_id)>0 AND length(issuer_epoch)>0
    AND length(principal_id)>0 AND length(request_epoch)>0 AND length(owner_evidence_id)>0)
) STRICT;

-- 只关闭新受理；仍保留查原和当前有权主体的永久拒收。
CREATE TABLE ca_namespace_closure (
  namespace_id TEXT PRIMARY KEY NOT NULL REFERENCES ca_namespace(namespace_id),
  protection_operation_id TEXT NOT NULL CHECK(length(protection_operation_id)>0),
  closure_body BLOB NOT NULL CHECK(length(closure_body)>0)
) STRICT;

CREATE TABLE ca_request_key (
  key_id TEXT PRIMARY KEY NOT NULL CHECK(length(key_id)>0),
  namespace_id TEXT NOT NULL REFERENCES ca_namespace(namespace_id),
  operation_id TEXT NOT NULL CHECK(operation_id='createCommand'),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key)>0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=71
    AND substr(request_digest,1,7)='sha256:'
    AND substr(request_digest,8) NOT GLOB '*[^0-9a-f]*'),
  device_id TEXT NOT NULL CHECK(length(device_id)>0),
  content_body BLOB NOT NULL CHECK(length(content_body) BETWEEN 1 AND 16384),
  UNIQUE(namespace_id,operation_id,idempotency_key),
  FOREIGN KEY(key_id) REFERENCES ca_adjudication(key_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_adjudication (
  key_id TEXT PRIMARY KEY NOT NULL REFERENCES ca_request_key(key_id),
  adjudication_id TEXT NOT NULL UNIQUE CHECK(length(adjudication_id)>0),
  revision TEXT NOT NULL CHECK(revision='1'),
  decision TEXT NOT NULL CHECK(decision IN ('accepted','rejected')),
  command_id TEXT,
  commit_id TEXT NOT NULL UNIQUE,
  commit_kind TEXT NOT NULL,
  adjudication_digest TEXT NOT NULL CHECK(length(adjudication_digest)=71
    AND substr(adjudication_digest,1,7)='sha256:'
    AND substr(adjudication_digest,8) NOT GLOB '*[^0-9a-f]*'),
  adjudication_body BLOB NOT NULL CHECK(length(adjudication_body)>0),
  CHECK((decision='accepted' AND command_id IS NOT NULL AND commit_kind='accept')
     OR (decision='rejected' AND command_id IS NULL AND commit_kind='reject_new')),
  UNIQUE(key_id,decision),
  UNIQUE(key_id,commit_id),
  FOREIGN KEY(key_id,command_id) REFERENCES ca_command_initial(key_id,command_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(commit_id,key_id,commit_kind) REFERENCES ca_commit(commit_id,key_id,kind)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_command_initial (
  command_id TEXT PRIMARY KEY NOT NULL CHECK(length(command_id)>0),
  key_id TEXT NOT NULL UNIQUE,
  decision TEXT NOT NULL CHECK(decision='accepted'),
  revision TEXT NOT NULL CHECK(revision='1'),
  command_digest TEXT NOT NULL CHECK(length(command_digest)=71
    AND substr(command_digest,1,7)='sha256:'
    AND substr(command_digest,8) NOT GLOB '*[^0-9a-f]*'),
  command_body BLOB NOT NULL CHECK(length(command_body)>0),
  admission_binding_body BLOB NOT NULL CHECK(length(admission_binding_body)>0),
  UNIQUE(key_id,command_id),
  FOREIGN KEY(key_id,decision) REFERENCES ca_adjudication(key_id,decision)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(key_id) REFERENCES ca_reservation(key_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;

-- 准入容量事实，不是设备活跃hold，也不充当可重传派发队列。
CREATE TABLE ca_reservation (
  key_id TEXT PRIMARY KEY NOT NULL,
  command_id TEXT NOT NULL UNIQUE,
  capacity_profile_ref_body BLOB NOT NULL CHECK(length(capacity_profile_ref_body)>0),
  dimensions_body BLOB NOT NULL CHECK(length(dimensions_body)>0),
  FOREIGN KEY(key_id,command_id) REFERENCES ca_command_initial(key_id,command_id)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_commit (
  commit_id TEXT PRIMARY KEY NOT NULL CHECK(length(commit_id)>0),
  key_id TEXT NOT NULL REFERENCES ca_request_key(key_id) DEFERRABLE INITIALLY DEFERRED,
  kind TEXT NOT NULL CHECK(kind IN ('accept','reject_new','reject_existing')),
  creation_key_id TEXT,
  rejection_id TEXT,
  commit_body BLOB NOT NULL CHECK(length(commit_body)>0),
  CHECK((kind='accept' AND creation_key_id IS NOT NULL AND creation_key_id=key_id AND rejection_id IS NULL)
     OR (kind='reject_new' AND creation_key_id IS NOT NULL AND creation_key_id=key_id AND rejection_id IS NOT NULL)
     OR (kind='reject_existing' AND creation_key_id IS NULL AND rejection_id IS NOT NULL)),
  UNIQUE(commit_id,key_id,kind),
  UNIQUE(commit_id,key_id,rejection_id),
  FOREIGN KEY(creation_key_id,commit_id) REFERENCES ca_adjudication(key_id,commit_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(rejection_id,commit_id,key_id) REFERENCES ca_rejection(rejection_id,commit_id,key_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(commit_id,key_id,kind) REFERENCES ca_audit(commit_id,key_id,kind)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(commit_id,key_id,kind) REFERENCES ca_notification(commit_id,key_id,kind)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_rejection (
  rejection_id TEXT PRIMARY KEY NOT NULL CHECK(length(rejection_id)>0),
  actor_issuer_id TEXT NOT NULL CHECK(length(actor_issuer_id)>0),
  actor_issuer_epoch TEXT NOT NULL CHECK(length(actor_issuer_epoch)>0),
  actor_principal_id TEXT NOT NULL CHECK(length(actor_principal_id)>0),
  rejection_operation_id TEXT NOT NULL CHECK(length(rejection_operation_id)>0),
  operation_digest TEXT NOT NULL CHECK(length(operation_digest)=71
    AND substr(operation_digest,1,7)='sha256:'
    AND substr(operation_digest,8) NOT GLOB '*[^0-9a-f]*'),
  key_id TEXT NOT NULL REFERENCES ca_adjudication(key_id) DEFERRABLE INITIALLY DEFERRED,
  commit_id TEXT NOT NULL UNIQUE,
  request_body BLOB NOT NULL CHECK(length(request_body) BETWEEN 1 AND 16384),
  authorization_evidence_body BLOB NOT NULL CHECK(length(authorization_evidence_body)>0),
  UNIQUE(actor_issuer_id,actor_issuer_epoch,actor_principal_id,rejection_operation_id),
  UNIQUE(rejection_id,commit_id,key_id),
  FOREIGN KEY(commit_id,key_id,rejection_id) REFERENCES ca_commit(commit_id,key_id,rejection_id)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_audit (
  commit_id TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  redacted_body BLOB NOT NULL CHECK(length(redacted_body)>0),
  UNIQUE(commit_id,key_id,kind),
  FOREIGN KEY(commit_id,key_id,kind) REFERENCES ca_commit(commit_id,key_id,kind)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE ca_notification (
  commit_id TEXT PRIMARY KEY NOT NULL,
  key_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  event_id TEXT NOT NULL UNIQUE CHECK(length(event_id)>0),
  payload_body BLOB NOT NULL CHECK(length(payload_body)>0),
  UNIQUE(commit_id,key_id,kind),
  FOREIGN KEY(commit_id,key_id,kind) REFERENCES ca_commit(commit_id,key_id,kind)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX ca_key_device ON ca_request_key(device_id,key_id);
CREATE INDEX ca_rejection_target ON ca_rejection(key_id,rejection_id);

CREATE TRIGGER ca_closed_namespace BEFORE INSERT ON ca_adjudication
WHEN NEW.decision='accepted' AND EXISTS(
  SELECT 1 FROM ca_request_key k JOIN ca_namespace_closure c USING(namespace_id)
  WHERE k.key_id=NEW.key_id)
BEGIN SELECT RAISE(ABORT,'namespace_closed'); END;

CREATE TRIGGER ca_scope_no_update BEFORE UPDATE ON ca_scope
BEGIN SELECT RAISE(ABORT,'immutable_scope'); END;
CREATE TRIGGER ca_scope_no_delete BEFORE DELETE ON ca_scope
BEGIN SELECT RAISE(ABORT,'immutable_scope'); END;
CREATE TRIGGER ca_namespace_no_update BEFORE UPDATE ON ca_namespace
BEGIN SELECT RAISE(ABORT,'immutable_namespace'); END;
CREATE TRIGGER ca_namespace_no_delete BEFORE DELETE ON ca_namespace
BEGIN SELECT RAISE(ABORT,'immutable_namespace'); END;
CREATE TRIGGER ca_closure_no_update BEFORE UPDATE ON ca_namespace_closure
BEGIN SELECT RAISE(ABORT,'permanent_closure'); END;
CREATE TRIGGER ca_closure_no_delete BEFORE DELETE ON ca_namespace_closure
BEGIN SELECT RAISE(ABORT,'permanent_closure'); END;
CREATE TRIGGER ca_key_no_update BEFORE UPDATE ON ca_request_key
BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER ca_key_no_delete BEFORE DELETE ON ca_request_key
BEGIN SELECT RAISE(ABORT,'immutable_request'); END;
CREATE TRIGGER ca_adjudication_no_update BEFORE UPDATE ON ca_adjudication
BEGIN SELECT RAISE(ABORT,'immutable_adjudication'); END;
CREATE TRIGGER ca_adjudication_no_delete BEFORE DELETE ON ca_adjudication
BEGIN SELECT RAISE(ABORT,'immutable_adjudication'); END;
CREATE TRIGGER ca_initial_no_update BEFORE UPDATE ON ca_command_initial
BEGIN SELECT RAISE(ABORT,'immutable_initial'); END;
CREATE TRIGGER ca_initial_no_delete BEFORE DELETE ON ca_command_initial
BEGIN SELECT RAISE(ABORT,'immutable_initial'); END;
CREATE TRIGGER ca_reservation_no_update BEFORE UPDATE ON ca_reservation
BEGIN SELECT RAISE(ABORT,'immutable_reservation'); END;
CREATE TRIGGER ca_reservation_no_delete BEFORE DELETE ON ca_reservation
BEGIN SELECT RAISE(ABORT,'immutable_reservation'); END;
CREATE TRIGGER ca_commit_no_update BEFORE UPDATE ON ca_commit
BEGIN SELECT RAISE(ABORT,'immutable_commit'); END;
CREATE TRIGGER ca_commit_no_delete BEFORE DELETE ON ca_commit
BEGIN SELECT RAISE(ABORT,'immutable_commit'); END;
CREATE TRIGGER ca_rejection_no_update BEFORE UPDATE ON ca_rejection
BEGIN SELECT RAISE(ABORT,'immutable_rejection'); END;
CREATE TRIGGER ca_rejection_no_delete BEFORE DELETE ON ca_rejection
BEGIN SELECT RAISE(ABORT,'immutable_rejection'); END;
CREATE TRIGGER ca_audit_no_update BEFORE UPDATE ON ca_audit
BEGIN SELECT RAISE(ABORT,'immutable_audit'); END;
CREATE TRIGGER ca_audit_no_delete BEFORE DELETE ON ca_audit
BEGIN SELECT RAISE(ABORT,'immutable_audit'); END;
CREATE TRIGGER ca_notification_no_update BEFORE UPDATE ON ca_notification
BEGIN SELECT RAISE(ABORT,'immutable_notification'); END;
CREATE TRIGGER ca_notification_no_delete BEFORE DELETE ON ca_notification
BEGIN SELECT RAISE(ABORT,'immutable_notification'); END;

INSERT INTO ca_scope SELECT 1, service_id, database_instance_id, 'command-admission/0.1.0-draft.1' FROM service_state;
CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;
-- 完整准入writer及控制/准备/资源来源接通前，任何入口均不能写accepted。
CREATE TRIGGER ca_accept_unavailable BEFORE INSERT ON ca_adjudication WHEN NEW.decision='accepted'
BEGIN SELECT RAISE(ABORT,'command_admission_unavailable'); END;
