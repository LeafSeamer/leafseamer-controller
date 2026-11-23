DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v99 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '99'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v99 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '99', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v99 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v99 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 99),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v99 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v99 RENAME TO schema_migration;
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

CREATE TRIGGER device_authorization_state_parent BEFORE INSERT ON device_authorization_state
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_record_head h ON h.device_id=s.device_id AND (h.revision=s.revision OR (
 s.revision=(SELECT max(a.revision) FROM control_state_source a WHERE a.device_id=s.device_id AND a.change_kind NOT IN('ready','gate_protect'))
 AND EXISTS(SELECT 1 FROM control_state_source g WHERE g.device_id=h.device_id AND g.revision=h.revision AND g.change_kind IN('ready','gate_protect'))))
 JOIN service_state v ON v.singleton=1 WHERE s.source_id=NEW.control_source_id AND s.device_id=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.format_version')='device-authorization-state/0.1.0-draft.1'
 AND json_extract(NEW.body_jcs,'$.state_id')=NEW.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.revision'),-20)=NEW.revision
 AND json_extract(NEW.body_jcs,'$.state_digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.parent_ref.id') IS NEW.parent_id
 AND ((json_extract(NEW.body_jcs,'$.status')='protected' AND json_extract(NEW.body_jcs,'$.recovery_ref') IS NULL) OR
 (json_extract(NEW.body_jcs,'$.status')='policy_selected' AND EXISTS(SELECT 1 FROM device_recovery_consumption r
 JOIN device_recovery_authorization a USING(authorization_id) WHERE r.state_id=NEW.state_id AND r.commit_id=NEW.commit_id
 AND a.authorization_id=json_extract(NEW.body_jcs,'$.recovery_ref.id') AND a.protected_state_id=NEW.parent_id
 AND a.device_id=NEW.device_id)))
 AND json_extract(NEW.body_jcs,'$.context.device_id')=NEW.device_id
 AND json_extract(NEW.body_jcs,'$.context.scope.authority_service_id')=v.service_id
 AND json_extract(NEW.body_jcs,'$.context.scope.database_instance_id')=v.database_instance_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.context.control_authority_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'device_authorization_state_parent'); END;

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NEW.owner_evidence_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;


CREATE TRIGGER obs_local_resource_parent BEFORE INSERT ON obs_local_resource
WHEN NOT EXISTS (
  SELECT 1 FROM device_record d JOIN service_state s ON s.singleton = 1
  WHERE d.device_id = NEW.device_id AND json_extract(CAST(d.descriptor_body AS TEXT), '$.device_kind') = 'obs'
    AND json_extract(NEW.body_jcs, '$.format') = 'leafseamer-obs-local-resource/1'
    AND json_extract(NEW.body_jcs, '$.resource_id') = NEW.resource_id
    AND json_extract(NEW.body_jcs, '$.device_ref.object_id') = NEW.device_id
    AND json_extract(NEW.body_jcs, '$.device_ref.digest') = d.descriptor_digest
    AND json_extract(NEW.body_jcs, '$.device_ref.authority_service_id') = s.service_id
    AND json_extract(NEW.body_jcs, '$.device_ref.database_instance_id') = s.database_instance_id
    AND json_extract(NEW.body_jcs, '$.endpoint.address') = '127.0.0.1'
    AND json_extract(NEW.body_jcs, '$.endpoint.port') = NEW.endpoint_port
    AND json_extract(NEW.body_jcs, '$.profile') = 'obs_isolated_empty_cut/1')
BEGIN SELECT RAISE(ABORT, 'obs_local_resource_parent'); END;

CREATE TABLE device_resource_identity (
  resource_id TEXT PRIMARY KEY NOT NULL,
  device_id TEXT NOT NULL REFERENCES device_record(device_id),
  body_digest TEXT NOT NULL,
  UNIQUE(resource_id, device_id),
  UNIQUE(device_id)
) STRICT;
CREATE TRIGGER device_resource_identity_parent BEFORE INSERT ON device_resource_identity
WHEN NOT EXISTS (
  SELECT 1 FROM virtual_device_resource r
  WHERE r.resource_id = NEW.resource_id AND r.device_id = NEW.device_id AND r.body_digest = NEW.body_digest
  UNION ALL
  SELECT 1 FROM obs_local_resource r
  WHERE r.resource_id = NEW.resource_id AND r.device_id = NEW.device_id AND r.body_digest = NEW.body_digest)
BEGIN SELECT RAISE(ABORT, 'device_resource_identity_parent'); END;
CREATE TRIGGER device_resource_identity_no_update BEFORE UPDATE ON device_resource_identity
BEGIN SELECT RAISE(ABORT, 'immutable_device_resource_identity'); END;
CREATE TRIGGER device_resource_identity_no_delete BEFORE DELETE ON device_resource_identity
BEGIN SELECT RAISE(ABORT, 'immutable_device_resource_identity'); END;

INSERT INTO device_resource_identity SELECT resource_id, device_id, body_digest FROM virtual_device_resource;
INSERT INTO device_resource_identity SELECT resource_id, device_id, body_digest FROM obs_local_resource;

CREATE TRIGGER virtual_device_resource_identity AFTER INSERT ON virtual_device_resource
BEGIN INSERT INTO device_resource_identity VALUES (NEW.resource_id, NEW.device_id, NEW.body_digest); END;
CREATE TRIGGER obs_local_resource_identity AFTER INSERT ON obs_local_resource
BEGIN INSERT INTO device_resource_identity VALUES (NEW.resource_id, NEW.device_id, NEW.body_digest); END;

DROP TRIGGER extension_activation_complete;
CREATE TABLE extension_resource_owner_v99 (
  owner_id TEXT PRIMARY KEY NOT NULL,
  operation_id TEXT NOT NULL REFERENCES extension_activation(operation_id) DEFERRABLE INITIALLY DEFERRED,
  resource_id TEXT NOT NULL,
  device_id TEXT NOT NULL REFERENCES device_record(device_id),
  resource_ref_jcs TEXT NOT NULL CHECK(json_valid(resource_ref_jcs)),
  UNIQUE(operation_id, resource_id),
  UNIQUE(owner_id, resource_id),
  FOREIGN KEY(resource_id, device_id) REFERENCES device_resource_identity(resource_id, device_id),
  CHECK(json_extract(resource_ref_jcs, '$.object_id') IS resource_id)
) STRICT;
INSERT INTO extension_resource_owner_v99 SELECT * FROM extension_resource_owner;
DROP TABLE extension_resource_owner;
ALTER TABLE extension_resource_owner_v99 RENAME TO extension_resource_owner;

CREATE TRIGGER extension_owner_binding BEFORE INSERT ON extension_resource_owner
WHEN NOT EXISTS (
  SELECT 1 FROM device_resource_identity r JOIN service_state s ON s.singleton = 1
  WHERE r.resource_id = NEW.resource_id AND r.device_id = NEW.device_id
    AND json_extract(NEW.resource_ref_jcs, '$.kind') = 'resource'
    AND json_extract(NEW.resource_ref_jcs, '$.revision') = '1'
    AND json_extract(NEW.resource_ref_jcs, '$.digest') = r.body_digest
    AND json_extract(NEW.resource_ref_jcs, '$.authority_service_id') = s.service_id
    AND json_extract(NEW.resource_ref_jcs, '$.database_instance_id') = s.database_instance_id)
BEGIN SELECT RAISE(ABORT, 'extension_owner_binding'); END;

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
CREATE TRIGGER extension_owner_no_update BEFORE UPDATE ON extension_resource_owner BEGIN SELECT RAISE(ABORT,'immutable_owner'); END;
CREATE TRIGGER extension_owner_no_delete BEFORE DELETE ON extension_resource_owner BEGIN SELECT RAISE(ABORT,'immutable_owner'); END;
