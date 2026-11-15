DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v64 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '64'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v64 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '64', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v64 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v64 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64')),
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
    OR (from_revision = '63' AND to_revision = '64' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v64 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v64 RENAME TO schema_migration;
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


CREATE TABLE device_event_source (
 registration_id TEXT PRIMARY KEY NOT NULL,
 channel_id TEXT NOT NULL REFERENCES device_module_channel(channel_id),
 capture_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 device_session_id TEXT NOT NULL,
 approval_id TEXT NOT NULL REFERENCES device_catalog_approval(approval_id),
 started_message_id TEXT NOT NULL UNIQUE REFERENCES device_module_frame(message_id),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL,
 UNIQUE(channel_id,capture_id)
) STRICT;
CREATE TABLE device_source_event (
 record_id TEXT PRIMARY KEY NOT NULL,
 registration_id TEXT NOT NULL REFERENCES device_event_source(registration_id),
 event_id TEXT NOT NULL,
 source_sequence TEXT NOT NULL CHECK(length(source_sequence) BETWEEN 1 AND 20 AND source_sequence NOT GLOB '*[^0-9]*' AND substr(source_sequence,1,1) BETWEEN '1' AND '9'),
 origin_jcs TEXT NOT NULL CHECK(json_valid(origin_jcs)),
 origin_digest TEXT NOT NULL,
 module_message_id TEXT NOT NULL REFERENCES device_module_frame(message_id),
 module_event_jcs TEXT NOT NULL CHECK(json_valid(module_event_jcs)),
 transaction_id TEXT NOT NULL,
 UNIQUE(registration_id,event_id),UNIQUE(registration_id,source_sequence),UNIQUE(record_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES device_source_event_outbox(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE INDEX device_source_event_order ON device_source_event(registration_id,length(source_sequence),source_sequence);
CREATE TABLE device_source_event_outbox (
 record_id TEXT PRIMARY KEY NOT NULL,
 transaction_id TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 UNIQUE(record_id,transaction_id),
 FOREIGN KEY(record_id,transaction_id) REFERENCES device_source_event(record_id,transaction_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE device_source_batch (
 message_id TEXT PRIMARY KEY NOT NULL REFERENCES device_module_frame(message_id),
 registration_id TEXT NOT NULL REFERENCES device_event_source(registration_id),
 batch_digest TEXT NOT NULL,
 through_sequence TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs))
) STRICT;
CREATE TABLE device_source_fault (
 registration_id TEXT PRIMARY KEY NOT NULL REFERENCES device_event_source(registration_id),
 reason TEXT NOT NULL CHECK(reason IN('capture_failed','capture_stopped','channel_closed')),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs))
) STRICT;
CREATE TRIGGER device_event_source_parent BEFORE INSERT ON device_event_source WHEN NOT EXISTS(
 SELECT 1 FROM device_module_frame f JOIN device_catalog_approval a ON a.approval_id=NEW.approval_id
 WHERE f.message_id=NEW.started_message_id AND f.message_type='EVENT_STARTED' AND f.direction='w2c'
 AND f.channel_id=NEW.channel_id AND a.channel_id=f.channel_id AND a.device_id=NEW.device_id AND a.device_session_id=NEW.device_session_id
 AND json_extract(f.frame_jcs,'$.body.capture_id')=NEW.capture_id
 AND json_extract(f.frame_jcs,'$.body.device_id')=NEW.device_id AND json_extract(f.frame_jcs,'$.body.device_session_id')=NEW.device_session_id
 AND json_extract(NEW.body_jcs,'$.registration_id')=NEW.registration_id
 AND json_extract(NEW.body_jcs,'$.qualification.capture_message_id')=NEW.started_message_id
 AND json_extract(NEW.body_jcs,'$.qualification.capture')=json_extract(f.frame_jcs,'$.body.capture')
) BEGIN SELECT RAISE(ABORT,'event_source_parent'); END;
CREATE TRIGGER device_source_event_parent BEFORE INSERT ON device_source_event WHEN NOT EXISTS(
 SELECT 1 FROM device_event_source s JOIN device_module_frame f ON f.message_id=NEW.module_message_id,
 json_each(f.frame_jcs,'$.body.result.batch.events') e
 WHERE s.registration_id=NEW.registration_id AND f.channel_id=s.channel_id AND f.direction='w2c' AND f.message_type='EVENT_BATCH'
 AND json_extract(f.frame_jcs,'$.body.capture_id')=s.capture_id AND e.value=NEW.module_event_jcs
 AND json_extract(e.value,'$.event_id')=NEW.event_id AND json_extract(e.value,'$.sequence')=NEW.source_sequence
 AND json_extract(NEW.origin_jcs,'$.event_id')=NEW.event_id AND json_extract(NEW.origin_jcs,'$.source_sequence')=NEW.source_sequence
 AND json_extract(NEW.origin_jcs,'$.source_key')=json_extract(s.body_jcs,'$.source_key')
 AND json_extract(NEW.origin_jcs,'$.binding_ref')=json_extract(s.body_jcs,'$.binding_ref')
 AND json_extract(NEW.origin_jcs,'$.payload.value')=json_extract(e.value,'$.payload')
 AND json_extract(NEW.origin_jcs,'$.payload.schema_ref')=json_extract(s.body_jcs,'$.payload_schema_ref')
 AND json_type(NEW.origin_jcs,'$.source_time_ref')='null'
) BEGIN SELECT RAISE(ABORT,'source_event_parent'); END;
CREATE TRIGGER device_source_outbox_parent BEFORE INSERT ON device_source_event_outbox WHEN NOT EXISTS(
 SELECT 1 FROM device_source_event e WHERE e.record_id=NEW.record_id AND e.transaction_id=NEW.transaction_id
 AND json_extract(NEW.body_jcs,'$.origin_digest')=e.origin_digest AND json_extract(NEW.body_jcs,'$.origin')=e.origin_jcs
 AND json_extract(NEW.body_jcs,'$.record_id')=e.record_id
) BEGIN SELECT RAISE(ABORT,'source_outbox_parent'); END;
CREATE TRIGGER device_source_batch_parent BEFORE INSERT ON device_source_batch WHEN NOT EXISTS(
 SELECT 1 FROM device_event_source s JOIN device_module_frame f ON f.message_id=NEW.message_id
 WHERE s.registration_id=NEW.registration_id AND f.message_type='EVENT_BATCH' AND f.direction='w2c' AND f.channel_id=s.channel_id
 AND json_extract(f.frame_jcs,'$.body.capture_id')=s.capture_id
 AND json_extract(f.frame_jcs,'$.body.result.batch_digest')=NEW.batch_digest
 AND json_extract(f.frame_jcs,'$.body.result.batch.through_sequence')=NEW.through_sequence
 AND NOT EXISTS(SELECT 1 FROM json_each(f.frame_jcs,'$.body.result.batch.events') m
  WHERE NOT EXISTS(SELECT 1 FROM device_source_event e WHERE e.registration_id=s.registration_id
   AND e.event_id=json_extract(m.value,'$.event_id') AND e.source_sequence=json_extract(m.value,'$.sequence') AND e.module_event_jcs=m.value))
) BEGIN SELECT RAISE(ABORT,'source_batch_parent'); END;
CREATE TRIGGER device_source_ack_committed BEFORE INSERT ON device_module_frame WHEN NEW.message_type='EVENT_ACK' AND NOT EXISTS(
 SELECT 1 FROM device_source_batch b JOIN device_event_source s USING(registration_id)
 WHERE s.channel_id=NEW.channel_id AND s.capture_id=json_extract(NEW.frame_jcs,'$.body.capture_id')
 AND b.batch_digest=json_extract(NEW.frame_jcs,'$.body.batch_digest') AND b.through_sequence=json_extract(NEW.frame_jcs,'$.body.through_sequence')
) BEGIN SELECT RAISE(ABORT,'source_ack_uncommitted'); END;

CREATE TRIGGER device_event_source_no_update BEFORE UPDATE ON device_event_source BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_event_source_no_delete BEFORE DELETE ON device_event_source BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_event_no_update BEFORE UPDATE ON device_source_event BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_event_no_delete BEFORE DELETE ON device_source_event BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_event_outbox_no_update BEFORE UPDATE ON device_source_event_outbox BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_event_outbox_no_delete BEFORE DELETE ON device_source_event_outbox BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_batch_no_update BEFORE UPDATE ON device_source_batch BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_batch_no_delete BEFORE DELETE ON device_source_batch BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_fault_no_update BEFORE UPDATE ON device_source_fault BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;

CREATE TRIGGER device_source_fault_no_delete BEFORE DELETE ON device_source_fault BEGIN SELECT RAISE(ABORT,'immutable_event_source'); END;
