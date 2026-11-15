DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v70 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '70'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v70 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '70', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v70 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v70 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70')),
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
    OR (from_revision = '31' AND to_revision = '32' AND backup_ref IS NOT NULL)
    OR (from_revision = '32' AND to_revision = '33' AND backup_ref IS NOT NULL)
    OR (from_revision = '33' AND to_revision = '34' AND backup_ref IS NOT NULL)
    OR (from_revision = '34' AND to_revision = '35' AND backup_ref IS NOT NULL)
    OR (from_revision = '35' AND to_revision = '36' AND backup_ref IS NOT NULL)
    OR (from_revision = '36' AND to_revision = '37' AND backup_ref IS NOT NULL)
    OR (from_revision = '37' AND to_revision = '38' AND backup_ref IS NOT NULL)
    OR (from_revision = '38' AND to_revision = '39' AND backup_ref IS NOT NULL)
    OR (from_revision = '39' AND to_revision = '40' AND backup_ref IS NOT NULL)
    OR (from_revision = '40' AND to_revision = '41' AND backup_ref IS NOT NULL)
    OR (from_revision = '41' AND to_revision = '42' AND backup_ref IS NOT NULL)
    OR (from_revision = '42' AND to_revision = '43' AND backup_ref IS NOT NULL)
    OR (from_revision = '43' AND to_revision = '44' AND backup_ref IS NOT NULL)
    OR (from_revision = '44' AND to_revision = '45' AND backup_ref IS NOT NULL)
    OR (from_revision = '45' AND to_revision = '46' AND backup_ref IS NOT NULL)
    OR (from_revision = '46' AND to_revision = '47' AND backup_ref IS NOT NULL)
    OR (from_revision = '47' AND to_revision = '48' AND backup_ref IS NOT NULL)
    OR (from_revision = '48' AND to_revision = '49' AND backup_ref IS NOT NULL)
    OR (from_revision = '49' AND to_revision = '50' AND backup_ref IS NOT NULL)
    OR (from_revision = '50' AND to_revision = '51' AND backup_ref IS NOT NULL)
    OR (from_revision = '51' AND to_revision = '52' AND backup_ref IS NOT NULL)
    OR (from_revision = '52' AND to_revision = '53' AND backup_ref IS NOT NULL)
    OR (from_revision = '53' AND to_revision = '54' AND backup_ref IS NOT NULL)
    OR (from_revision = '54' AND to_revision = '55' AND backup_ref IS NOT NULL)
    OR (from_revision = '55' AND to_revision = '56' AND backup_ref IS NOT NULL)
    OR (from_revision = '56' AND to_revision = '57' AND backup_ref IS NOT NULL)
    OR (from_revision = '57' AND to_revision = '58' AND backup_ref IS NOT NULL)
    OR (from_revision = '58' AND to_revision = '59' AND backup_ref IS NOT NULL)
    OR (from_revision = '59' AND to_revision = '60' AND backup_ref IS NOT NULL)
    OR (from_revision = '60' AND to_revision = '61' AND backup_ref IS NOT NULL)
    OR (from_revision = '61' AND to_revision = '62' AND backup_ref IS NOT NULL)
    OR (from_revision = '62' AND to_revision = '63' AND backup_ref IS NOT NULL)
    OR (from_revision = '63' AND to_revision = '64' AND backup_ref IS NOT NULL)
    OR (from_revision = '64' AND to_revision = '65' AND backup_ref IS NOT NULL)
    OR (from_revision = '65' AND to_revision = '66' AND backup_ref IS NOT NULL)
    OR (from_revision = '66' AND to_revision = '67' AND backup_ref IS NOT NULL)
    OR (from_revision = '67' AND to_revision = '68' AND backup_ref IS NOT NULL)
    OR (from_revision = '68' AND to_revision = '69' AND backup_ref IS NOT NULL)
    OR (from_revision = '69' AND to_revision = '70' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v70 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v70 RENAME TO schema_migration;
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


DROP TRIGGER service_snapshot_publish_complete;
DROP TRIGGER service_subscription_connection_complete;
DROP TRIGGER service_snapshot_ready_parent;
DROP TRIGGER service_event_subscription_outbox_complete;
DROP TRIGGER service_event_subscription_head_cas;
CREATE TABLE service_event_subscription_revision_v70 (
 subscription_id TEXT NOT NULL REFERENCES service_event_subscription(subscription_id) DEFERRABLE INITIALLY DEFERRED,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65536),state TEXT NOT NULL CHECK(state IN('building','snapshot_ready','catching_up','closed','revoked','expired','resync_required')),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,
 PRIMARY KEY(subscription_id,revision),UNIQUE(subscription_id,revision,operation_id),
 CHECK((revision=1 AND state='building') OR revision>1),
 CHECK(json_extract(body_jcs,'$.binding.subscription_id')=subscription_id AND json_extract(body_jcs,'$.revision')=CAST(revision AS TEXT) AND json_extract(body_jcs,'$.state')=state),
 FOREIGN KEY(operation_id,subscription_id,revision) REFERENCES service_event_subscription_outbox(operation_id,subscription_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO service_event_subscription_revision_v70 SELECT * FROM service_event_subscription_revision;
DROP TABLE service_event_subscription_revision;
ALTER TABLE service_event_subscription_revision_v70 RENAME TO service_event_subscription_revision;
CREATE TRIGGER service_event_subscription_revision_no_update BEFORE UPDATE ON service_event_subscription_revision BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_revision_no_delete BEFORE DELETE ON service_event_subscription_revision BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_head_cas BEFORE UPDATE ON service_event_subscription_head WHEN NOT(
 OLD.subscription_id=NEW.subscription_id AND NEW.revision=OLD.revision+1 AND EXISTS(SELECT 1 FROM service_event_subscription_revision r WHERE r.subscription_id=OLD.subscription_id AND r.revision=OLD.revision AND r.state IN('building','snapshot_ready','catching_up')))
BEGIN SELECT RAISE(ABORT,'subscription_head_cas'); END;
CREATE TRIGGER service_event_subscription_outbox_complete BEFORE INSERT ON service_event_subscription_outbox WHEN NOT EXISTS(
 SELECT 1 FROM service_event_subscription s JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision)
 JOIN service_event_subscription_audit a ON a.operation_id=NEW.operation_id
 WHERE s.subscription_id=NEW.subscription_id AND h.revision=NEW.revision AND r.operation_id=NEW.operation_id AND a.body_jcs=NEW.body_jcs
 AND json_array_length(s.creation_jcs,'$.source_frontiers') BETWEEN 1 AND 32
 AND json_array_length(s.creation_jcs,'$.source_frontiers')=(SELECT count(*) FROM service_event_subscription_pin p WHERE p.subscription_id=s.subscription_id)
 AND json_extract(NEW.body_jcs,'$.view_digest')=r.body_digest
) BEGIN SELECT RAISE(ABORT,'subscription_incomplete'); END;

CREATE TRIGGER service_snapshot_ready_parent BEFORE INSERT ON service_event_subscription_revision WHEN NEW.state='snapshot_ready' AND NOT EXISTS(
 SELECT 1 FROM service_snapshot_manifest m WHERE m.subscription_id=NEW.subscription_id AND m.subscription_revision<=NEW.revision
 AND m.snapshot_id=json_extract(NEW.body_jcs,'$.snapshot_ref.snapshot_id') AND m.body_digest=json_extract(NEW.body_jcs,'$.snapshot_ref.manifest_digest'))
BEGIN SELECT RAISE(ABORT,'snapshot_missing'); END;
CREATE TABLE service_snapshot_baseline (
 subscription_id TEXT PRIMARY KEY NOT NULL, snapshot_id TEXT NOT NULL UNIQUE REFERENCES service_snapshot_manifest(snapshot_id),
 snapshot_cursor TEXT NOT NULL CHECK(snapshot_cursor='0'),manifest_digest TEXT NOT NULL,marker_digest TEXT NOT NULL,journal_sequence TEXT NOT NULL,
 connection_generation TEXT NOT NULL,subscription_revision INTEGER NOT NULL,
 FOREIGN KEY(subscription_id,subscription_revision) REFERENCES service_event_subscription_revision(subscription_id,revision) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(subscription_id,connection_generation) REFERENCES service_subscription_attempt(subscription_id,generation)
) STRICT;
CREATE TRIGGER service_snapshot_baseline_parent BEFORE INSERT ON service_snapshot_baseline WHEN NOT EXISTS(
 SELECT 1 FROM service_snapshot_manifest m JOIN service_event_subscription_head h ON h.subscription_id=m.subscription_id
 JOIN service_event_subscription_revision r ON r.subscription_id=h.subscription_id AND r.revision=h.revision
 JOIN service_subscription_connection c ON c.subscription_id=h.subscription_id JOIN service_subscription_attempt a ON a.subscription_id=c.subscription_id AND a.attempt_id=c.attempt_id
 WHERE m.snapshot_id=NEW.snapshot_id AND m.subscription_id=NEW.subscription_id AND m.body_digest=NEW.manifest_digest AND m.marker_digest=NEW.marker_digest AND m.journal_sequence=NEW.journal_sequence
 AND r.state='snapshot_ready' AND NEW.subscription_revision=h.revision+1 AND a.generation=NEW.connection_generation
 AND json_extract(r.body_jcs,'$.binding.connection_generation')=a.generation
 AND NOT EXISTS(SELECT 1 FROM service_subscription_disconnect d WHERE d.connection_id=a.connection_id)
) BEGIN SELECT RAISE(ABORT,'snapshot_baseline_parent'); END;
CREATE TRIGGER service_snapshot_catching_up_parent BEFORE INSERT ON service_event_subscription_revision WHEN NEW.state='catching_up' AND NOT EXISTS(
 SELECT 1 FROM service_snapshot_baseline b WHERE b.subscription_id=NEW.subscription_id AND b.subscription_revision<=NEW.revision
 AND b.snapshot_id=json_extract(NEW.body_jcs,'$.snapshot_ref.snapshot_id') AND b.manifest_digest=json_extract(NEW.body_jcs,'$.snapshot_ref.manifest_digest')
 AND b.snapshot_cursor=json_extract(NEW.body_jcs,'$.ack_cursor') AND b.marker_digest=json_extract(NEW.body_jcs,'$.ack_payload_digest')
) BEGIN SELECT RAISE(ABORT,'snapshot_baseline_missing'); END;
CREATE TRIGGER service_snapshot_baseline_no_update BEFORE UPDATE ON service_snapshot_baseline BEGIN SELECT RAISE(ABORT,'immutable_snapshot_baseline'); END;
CREATE TRIGGER service_snapshot_baseline_no_delete BEFORE DELETE ON service_snapshot_baseline BEGIN SELECT RAISE(ABORT,'immutable_snapshot_baseline'); END;

CREATE TRIGGER service_snapshot_publish_complete BEFORE INSERT ON service_snapshot_end WHEN NEW.state='published' AND NOT EXISTS(
 SELECT 1 FROM service_snapshot_manifest m JOIN service_snapshot_build b USING(snapshot_id)
 JOIN service_event_subscription_head h ON h.subscription_id=m.subscription_id AND h.revision=m.subscription_revision
 JOIN service_event_subscription_revision r ON r.subscription_id=h.subscription_id AND r.revision=h.revision
 WHERE m.snapshot_id=NEW.snapshot_id AND b.subscription_id=m.subscription_id AND r.state='snapshot_ready'
 AND json_extract(r.body_jcs,'$.snapshot_ref.snapshot_id')=m.snapshot_id AND json_extract(r.body_jcs,'$.snapshot_ref.manifest_digest')=m.body_digest
 AND m.page_count=(SELECT count(*) FROM service_snapshot_page p WHERE p.snapshot_id=m.snapshot_id)
 AND NOT EXISTS(SELECT 1 FROM service_snapshot_page p WHERE p.snapshot_id=m.snapshot_id AND (p.page_index>=m.page_count
 OR json_extract(m.body_jcs,'$.pages['||p.page_index||'].content_digest') IS NOT p.body_digest
 OR json_extract(m.body_jcs,'$.pages['||p.page_index||'].content_bytes') IS NOT p.content_bytes))
) BEGIN SELECT RAISE(ABORT,'snapshot_incomplete'); END;

CREATE TRIGGER service_subscription_connection_complete BEFORE INSERT ON service_subscription_connection WHEN NOT EXISTS(
 SELECT 1 FROM service_subscription_attempt a JOIN service_event_subscription_head h USING(subscription_id) JOIN service_event_subscription_revision r USING(subscription_id,revision)
 WHERE a.subscription_id=NEW.subscription_id AND a.attempt_id=NEW.attempt_id AND a.subscription_revision=h.revision AND json_extract(r.body_jcs,'$.binding.connection_generation')=a.generation)
BEGIN SELECT RAISE(ABORT,'subscription_connection_incomplete'); END;
