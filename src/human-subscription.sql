DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v114 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '114'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v114 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '114', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v114 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v114 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 114),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v114 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v114 RENAME TO schema_migration;
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

CREATE TABLE status_scope_reader (
 scope_id TEXT NOT NULL REFERENCES device_subscription_scope(scope_id),
 principal_id TEXT NOT NULL REFERENCES local_principal(principal_id),
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65536),
 request_id TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN('active','revoked')),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL,
 PRIMARY KEY(scope_id,principal_id,revision),
 CHECK(json_extract(body_jcs,'$.scope_ref.entity_id') IS scope_id
   AND json_extract(body_jcs,'$.principal_id') IS principal_id
   AND json_extract(body_jcs,'$.revision') IS CAST(revision AS TEXT)
   AND json_extract(body_jcs,'$.state') IS state)
) STRICT;

CREATE TRIGGER status_scope_reader_parent BEFORE INSERT ON status_scope_reader
WHEN NOT EXISTS(
 SELECT 1 FROM device_subscription_scope s JOIN subject p ON p.principal_id=NEW.principal_id
 WHERE s.scope_id=NEW.scope_id AND p.kind='human'
 AND json_extract(s.body_jcs,'$.purpose')='status_projection'
 AND json_extract(NEW.body_jcs,'$.scope_ref.content_digest')=substr(s.body_digest,8)
 AND NEW.revision=coalesce((SELECT max(revision)+1 FROM status_scope_reader WHERE scope_id=NEW.scope_id AND principal_id=NEW.principal_id),1)
)
BEGIN SELECT RAISE(ABORT,'status_scope_reader_parent'); END;
CREATE TRIGGER status_scope_reader_no_update BEFORE UPDATE ON status_scope_reader
BEGIN SELECT RAISE(ABORT,'immutable_status_scope_reader'); END;
CREATE TRIGGER status_scope_reader_no_delete BEFORE DELETE ON status_scope_reader
BEGIN SELECT RAISE(ABORT,'immutable_status_scope_reader'); END;

DROP TRIGGER service_event_subscription_outbox_complete;
DROP TRIGGER service_event_subscription_pin_parent;
CREATE TABLE service_event_subscription_v114 (
 subscription_id TEXT PRIMARY KEY NOT NULL,
 owner_key TEXT NOT NULL,
 slot_key TEXT NOT NULL,
 purpose TEXT NOT NULL CHECK(purpose IN('canonical_trigger','status_projection')),
 request_id TEXT NOT NULL,
 request_digest TEXT NOT NULL,
 creation_jcs TEXT NOT NULL CHECK(json_valid(creation_jcs)),
 creation_digest TEXT NOT NULL,
 expires_ns TEXT NOT NULL,
 initial_revision INTEGER NOT NULL CHECK(initial_revision=1),
 UNIQUE(owner_key,purpose,request_id),
 CHECK(json_extract(creation_jcs,'$.subscription_id')=subscription_id AND json_extract(creation_jcs,'$.expires_ns')=expires_ns),
 FOREIGN KEY(subscription_id,initial_revision) REFERENCES service_event_subscription_revision(subscription_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO service_event_subscription_v114 SELECT * FROM service_event_subscription;
DROP TABLE service_event_subscription;
ALTER TABLE service_event_subscription_v114 RENAME TO service_event_subscription;

CREATE TRIGGER human_event_subscription_parent BEFORE INSERT ON service_event_subscription
WHEN NEW.purpose='status_projection' AND NOT EXISTS(
 SELECT 1 FROM request_context c JOIN status_scope_reader p ON p.principal_id=c.principal_id
 WHERE c.context_id=json_extract(NEW.creation_jcs,'$.request.context_id')
 AND c.service_boot_id=json_extract(NEW.creation_jcs,'$.service_boot_id')
 AND c.state='active' AND c.used_count>0 AND p.state='active'
 AND c.issuer_id=json_extract(NEW.creation_jcs,'$.authorization.owner.issuer_id')
 AND c.issuer_epoch=json_extract(NEW.creation_jcs,'$.authorization.owner.issuer_epoch')
 AND c.session_id=json_extract(NEW.creation_jcs,'$.authorization.owner.session_id')
 AND c.principal_id=json_extract(NEW.creation_jcs,'$.authorization.owner.principal_id')
 AND json_extract(NEW.creation_jcs,'$.authorization.owner.kind')='human'
 AND json_extract(NEW.creation_jcs,'$.request.client_instance_id')=json_extract(NEW.creation_jcs,'$.authorization.owner.client_instance_id')
 AND p.scope_id=json_extract(NEW.creation_jcs,'$.authorization.scope_ref.entity_id')
 AND p.body_digest=json_extract(NEW.creation_jcs,'$.authorization.reader_digest')
 AND p.revision=(SELECT max(revision) FROM status_scope_reader WHERE scope_id=p.scope_id AND principal_id=p.principal_id)
)
BEGIN SELECT RAISE(ABORT,'human_event_subscription_parent'); END;

CREATE TRIGGER service_event_subscription_no_update BEFORE UPDATE ON service_event_subscription
BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_no_delete BEFORE DELETE ON service_event_subscription
BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_pin_parent BEFORE INSERT ON service_event_subscription_pin WHEN NOT EXISTS(
 SELECT 1 FROM service_event_subscription s,json_each(s.creation_jcs,'$.source_frontiers') f
 WHERE s.subscription_id=NEW.subscription_id AND json_extract(f.value,'$.source_key.registration_id')=NEW.registration_id
 AND json_extract(f.value,'$.registration_sequence')=NEW.after_sequence
) BEGIN SELECT RAISE(ABORT,'subscription_pin_parent'); END;
CREATE TRIGGER service_event_subscription_outbox_complete BEFORE INSERT ON service_event_subscription_outbox WHEN NOT EXISTS(
 SELECT 1 FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id)
 JOIN service_event_subscription_revision r USING(subscription_id,revision)
 JOIN service_event_subscription_audit a ON a.operation_id=NEW.operation_id
 WHERE s.subscription_id=NEW.subscription_id AND h.revision=NEW.revision AND r.operation_id=NEW.operation_id AND a.body_jcs=NEW.body_jcs
 AND json_array_length(s.creation_jcs,'$.source_frontiers') BETWEEN 1 AND 32
 AND json_array_length(s.creation_jcs,'$.source_frontiers')=(SELECT count(*) FROM service_event_subscription_pin p WHERE p.subscription_id=s.subscription_id)
 AND json_extract(NEW.body_jcs,'$.view_digest')=r.body_digest
) BEGIN SELECT RAISE(ABORT,'subscription_incomplete'); END;
