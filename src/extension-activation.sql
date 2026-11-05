DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v22 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '22'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v22 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '22', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v22 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v22 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22')),
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
    OR (from_revision = '21' AND to_revision = '22' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v22 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v22 RENAME TO schema_migration;
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

DROP TRIGGER extension_operation_complete;
DROP TRIGGER extension_operation_no_update;
DROP TRIGGER extension_operation_no_delete;
CREATE TABLE extension_operation_v22 (
  request_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  operation_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  kind TEXT NOT NULL CHECK(kind IN ('create_slot','stage','activate','enable')),
  slot_id TEXT NOT NULL COLLATE BINARY,
  revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 4096),
  installation_id TEXT COLLATE BINARY,
  input_jcs TEXT NOT NULL CHECK(json_valid(input_jcs)),
  input_digest TEXT NOT NULL COLLATE BINARY,
  result_jcs TEXT NOT NULL CHECK(json_valid(result_jcs)),
  result_digest TEXT NOT NULL COLLATE BINARY,
  audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
  candidate_operation_id TEXT,
  lifecycle_operation_id TEXT REFERENCES extension_activation(operation_id) DEFERRABLE INITIALLY DEFERRED,
  UNIQUE(operation_id,slot_id,revision),
  UNIQUE(operation_id,installation_id),
  CHECK((kind='create_slot' AND installation_id IS NULL AND revision=1 AND candidate_operation_id IS NULL AND lifecycle_operation_id IS NULL)
    OR (kind='stage' AND installation_id IS NOT NULL AND revision>1 AND candidate_operation_id IS operation_id AND lifecycle_operation_id IS NULL)
    OR (kind IN ('activate','enable') AND installation_id IS NOT NULL AND revision>1 AND candidate_operation_id IS NULL AND lifecycle_operation_id IS operation_id)),
  FOREIGN KEY(slot_id,revision,operation_id) REFERENCES extension_slot_revision(slot_id,revision,operation_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(installation_id,candidate_operation_id) REFERENCES extension_candidate(installation_id,operation_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO extension_operation_v22 SELECT *,CASE WHEN kind='stage' THEN operation_id ELSE NULL END,NULL FROM extension_operation;
DROP TABLE extension_operation;
ALTER TABLE extension_operation_v22 RENAME TO extension_operation;
CREATE TRIGGER extension_operation_complete BEFORE INSERT ON extension_operation
WHEN NOT EXISTS(SELECT 1 FROM extension_slot_head WHERE slot_id=NEW.slot_id AND revision=NEW.revision)
  OR json_extract(NEW.audit_jcs,'$.operation_id') IS NOT NEW.operation_id
  OR json_extract(NEW.audit_jcs,'$.request_id') IS NOT NEW.request_id
  OR json_extract(NEW.audit_jcs,'$.slot_id') IS NOT NEW.slot_id
  OR json_extract(NEW.audit_jcs,'$.installation_id') IS NOT NEW.installation_id
  OR json_extract(NEW.audit_jcs,'$.result_digest') IS NOT NEW.result_digest
BEGIN SELECT RAISE(ABORT,'extension_operation_incomplete'); END;
CREATE TRIGGER extension_operation_no_update BEFORE UPDATE ON extension_operation
BEGIN SELECT RAISE(ABORT,'immutable_extension_operation'); END;
CREATE TRIGGER extension_operation_no_delete BEFORE DELETE ON extension_operation
BEGIN SELECT RAISE(ABORT,'extension_history_required'); END;

CREATE TABLE extension_activation (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES extension_operation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 credential_id TEXT NOT NULL REFERENCES session_refresh_credential(credential_id),
 request_id TEXT NOT NULL,
 installation_id TEXT NOT NULL UNIQUE REFERENCES extension_candidate(installation_id),
 slot_id TEXT NOT NULL,
 slot_revision INTEGER NOT NULL,
 plan_id TEXT NOT NULL UNIQUE REFERENCES extension_dependency_plan(plan_id),
 approval_id TEXT NOT NULL REFERENCES extension_approval(approval_id),
 service_boot_id TEXT NOT NULL REFERENCES core_runtime_binding(service_boot_id),
 input_jcs TEXT NOT NULL CHECK(json_valid(input_jcs)),
 input_digest TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL,
 graph_jcs TEXT NOT NULL CHECK(json_valid(graph_jcs)),
 graph_digest TEXT NOT NULL,
 UNIQUE(credential_id,request_id),
 FOREIGN KEY(slot_id,slot_revision,operation_id) REFERENCES extension_slot_revision(slot_id,revision,operation_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(json_extract(body_jcs,'$.operation_ref.object_id') IS operation_id
  AND json_extract(body_jcs,'$.target_installation_ref.object_id') IS installation_id
  AND json_extract(body_jcs,'$.phase') IS 'accepted')
) STRICT;
CREATE TABLE extension_resource_owner (
 owner_id TEXT PRIMARY KEY NOT NULL,
 operation_id TEXT NOT NULL REFERENCES extension_activation(operation_id) DEFERRABLE INITIALLY DEFERRED,
 resource_id TEXT NOT NULL REFERENCES virtual_device_resource(resource_id),
 device_id TEXT NOT NULL REFERENCES device_record(device_id),
 resource_ref_jcs TEXT NOT NULL CHECK(json_valid(resource_ref_jcs)),
 UNIQUE(operation_id,resource_id),
 UNIQUE(owner_id,resource_id),
 CHECK(json_extract(resource_ref_jcs,'$.object_id') IS resource_id)
) STRICT;
CREATE TABLE extension_resource_owner_head (
 resource_id TEXT PRIMARY KEY NOT NULL,
 owner_id TEXT NOT NULL UNIQUE,
 FOREIGN KEY(owner_id,resource_id) REFERENCES extension_resource_owner(owner_id,resource_id)
) STRICT;
CREATE TRIGGER extension_owner_binding BEFORE INSERT ON extension_resource_owner
WHEN NOT EXISTS(SELECT 1 FROM virtual_device_resource r WHERE r.resource_id=NEW.resource_id AND r.device_id=NEW.device_id)
BEGIN SELECT RAISE(ABORT,'extension_owner_binding'); END;
CREATE TRIGGER extension_activation_complete BEFORE INSERT ON extension_operation
WHEN NEW.kind IN ('activate','enable') AND NOT EXISTS (
 SELECT 1 FROM extension_activation a JOIN extension_slot_revision s ON s.slot_id=a.slot_id AND s.revision=a.slot_revision
 WHERE a.operation_id=NEW.operation_id AND a.installation_id=NEW.installation_id AND a.slot_id=NEW.slot_id AND a.slot_revision=NEW.revision
 AND json_extract(s.body_jcs,'$.pending_operation_ref.object_id') IS a.operation_id
 AND json_extract(s.body_jcs,'$.desired_state') IS 'enabled'
 AND (SELECT count(*) FROM extension_resource_owner o WHERE o.operation_id=a.operation_id)=json_array_length(a.graph_jcs,'$.resources')
 AND NOT EXISTS(SELECT 1 FROM json_each(a.graph_jcs,'$.resources') r WHERE NOT EXISTS(
  SELECT 1 FROM extension_resource_owner o JOIN extension_resource_owner_head h USING(owner_id,resource_id)
  WHERE o.operation_id=a.operation_id AND o.resource_ref_jcs=r.value)))
BEGIN SELECT RAISE(ABORT,'extension_activation_incomplete'); END;
CREATE TRIGGER extension_owner_sealed BEFORE INSERT ON extension_resource_owner
WHEN EXISTS(SELECT 1 FROM extension_operation WHERE operation_id=NEW.operation_id)
BEGIN SELECT RAISE(ABORT,'extension_activation_sealed'); END;
CREATE TRIGGER extension_activation_no_update BEFORE UPDATE ON extension_activation BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
CREATE TRIGGER extension_activation_no_delete BEFORE DELETE ON extension_activation BEGIN SELECT RAISE(ABORT,'immutable_activation'); END;
CREATE TRIGGER extension_owner_no_update BEFORE UPDATE ON extension_resource_owner BEGIN SELECT RAISE(ABORT,'immutable_owner'); END;
CREATE TRIGGER extension_owner_no_delete BEFORE DELETE ON extension_resource_owner BEGIN SELECT RAISE(ABORT,'immutable_owner'); END;
CREATE TRIGGER extension_owner_head_no_update BEFORE UPDATE ON extension_resource_owner_head BEGIN SELECT RAISE(ABORT,'owner_release_required'); END;
CREATE TRIGGER extension_owner_head_no_delete BEFORE DELETE ON extension_resource_owner_head BEGIN SELECT RAISE(ABORT,'owner_release_required'); END;
CREATE TRIGGER dependency_generation_owner AFTER INSERT ON extension_resource_owner_head
BEGIN UPDATE extension_dependency_generation SET revision=revision+1 WHERE singleton=1; END;

ALTER TABLE worker_launch_preparation ADD COLUMN activation_operation_id TEXT REFERENCES extension_activation(operation_id);
CREATE UNIQUE INDEX worker_launch_activation_once ON worker_launch_preparation(activation_operation_id) WHERE activation_operation_id IS NOT NULL;
CREATE TRIGGER worker_launch_activation_required BEFORE INSERT ON worker_launch_preparation
WHEN NEW.activation_operation_id IS NULL OR NOT EXISTS(SELECT 1 FROM extension_activation a
 WHERE a.operation_id=NEW.activation_operation_id AND a.service_boot_id=NEW.service_boot_id
 AND a.installation_id IS json_extract(NEW.intent_jcs,'$.extension_binding.installation_ref.object_id')
 AND a.approval_id IS json_extract(NEW.intent_jcs,'$.extension_binding.approval_ref.object_id'))
BEGIN SELECT RAISE(ABORT,'worker_launch_activation_required'); END;
