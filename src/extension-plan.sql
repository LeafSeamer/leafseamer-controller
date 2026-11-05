DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v21 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '21'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v21 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '21', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v21 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v21 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21')),
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
    OR (from_revision = '20' AND to_revision = '21' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v21 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v21 RENAME TO schema_migration;
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

CREATE TABLE extension_dependency_generation (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991)
) STRICT;
INSERT INTO extension_dependency_generation VALUES(1,1);
CREATE TRIGGER extension_dependency_generation_update BEFORE UPDATE ON extension_dependency_generation
WHEN NEW.singleton!=OLD.singleton OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'dependency_revision'); END;
CREATE TRIGGER extension_dependency_generation_delete BEFORE DELETE ON extension_dependency_generation
BEGIN SELECT RAISE(ABORT,'dependency_revision'); END;

CREATE TABLE extension_dependency_plan (
 plan_id TEXT PRIMARY KEY NOT NULL,
 slot_id TEXT NOT NULL,
 slot_revision INTEGER NOT NULL,
 service_boot_id TEXT NOT NULL REFERENCES core_runtime_binding(service_boot_id),
 approval_id TEXT NOT NULL REFERENCES extension_approval(approval_id),
 dependency_revision INTEGER NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=4194304),
 body_digest TEXT NOT NULL,
 graph_jcs TEXT NOT NULL CHECK(json_valid(graph_jcs) AND length(CAST(graph_jcs AS BLOB))<=4194304),
 graph_digest TEXT NOT NULL,
 operation_id TEXT NOT NULL UNIQUE,
 UNIQUE(plan_id,operation_id),
 FOREIGN KEY(slot_id,slot_revision) REFERENCES extension_slot_revision(slot_id,revision),
 FOREIGN KEY(plan_id,operation_id) REFERENCES extension_plan_operation(plan_id,operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(body_jcs,'$.plan_ref.object_id') IS plan_id
  AND json_extract(body_jcs,'$.slot_ref.object_id') IS slot_id
  AND json_extract(body_jcs,'$.slot_ref.revision') IS CAST(slot_revision AS TEXT)
  AND json_extract(body_jcs,'$.dependency_revision') IS CAST(dependency_revision AS TEXT))
) STRICT;
CREATE TABLE extension_plan_operation (
 operation_id TEXT PRIMARY KEY NOT NULL,
 credential_id TEXT NOT NULL REFERENCES session_refresh_credential(credential_id),
 request_id TEXT NOT NULL,
 plan_id TEXT NOT NULL UNIQUE,
 input_jcs TEXT NOT NULL CHECK(json_valid(input_jcs)),
 input_digest TEXT NOT NULL,
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 UNIQUE(credential_id,request_id),
 UNIQUE(plan_id,operation_id),
 FOREIGN KEY(plan_id,operation_id) REFERENCES extension_dependency_plan(plan_id,operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(audit_jcs,'$.operation_id') IS operation_id AND json_extract(audit_jcs,'$.plan_id') IS plan_id)
) STRICT;
CREATE TRIGGER extension_dependency_plan_no_update BEFORE UPDATE ON extension_dependency_plan BEGIN SELECT RAISE(ABORT,'immutable_dependency_plan'); END;
CREATE TRIGGER extension_dependency_plan_no_delete BEFORE DELETE ON extension_dependency_plan BEGIN SELECT RAISE(ABORT,'immutable_dependency_plan'); END;
CREATE TRIGGER extension_plan_operation_no_update BEFORE UPDATE ON extension_plan_operation BEGIN SELECT RAISE(ABORT,'immutable_dependency_plan'); END;
CREATE TRIGGER extension_plan_operation_no_delete BEFORE DELETE ON extension_plan_operation BEGIN SELECT RAISE(ABORT,'immutable_dependency_plan'); END;


CREATE TRIGGER dependency_generation_extension_slot_head_insert AFTER INSERT ON extension_slot_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_slot_head_update AFTER UPDATE ON extension_slot_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_configuration_head_insert AFTER INSERT ON extension_configuration_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_configuration_head_update AFTER UPDATE ON extension_configuration_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_role_head_insert AFTER INSERT ON extension_role_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_role_head_update AFTER UPDATE ON extension_role_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_approval_insert AFTER INSERT ON extension_approval
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_extension_approval_deny_insert AFTER INSERT ON extension_approval_deny
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_virtual_device_resource_insert AFTER INSERT ON virtual_device_resource
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_worker_launch_preparation_insert AFTER INSERT ON worker_launch_preparation
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_worker_runtime_binding_insert AFTER INSERT ON worker_runtime_binding
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_worker_runtime_withdrawal_insert AFTER INSERT ON worker_runtime_withdrawal
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

CREATE TRIGGER dependency_generation_command AFTER INSERT ON ca_adjudication WHEN NEW.decision='accepted'
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;
