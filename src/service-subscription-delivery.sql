DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v71 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '71'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v71 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '71', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v71 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v71 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71')),
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
    OR (from_revision = '69' AND to_revision = '70' AND backup_ref IS NOT NULL)
    OR (from_revision = '70' AND to_revision = '71' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v71 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v71 RENAME TO schema_migration;
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


CREATE TABLE service_subscription_reconcile (
  subscription_id TEXT PRIMARY KEY NOT NULL REFERENCES service_snapshot_baseline(subscription_id),
  start_sequence INTEGER NOT NULL CHECK(start_sequence BETWEEN 0 AND 9007199254740991),
  end_sequence INTEGER NOT NULL CHECK(end_sequence BETWEEN start_sequence AND 9007199254740991)
) STRICT;

DROP TRIGGER service_snapshot_baseline_parent;
DROP TRIGGER service_snapshot_catching_up_parent;
DROP TRIGGER service_snapshot_publish_complete;
DROP TRIGGER service_subscription_connection_complete;
DROP TRIGGER service_snapshot_ready_parent;
DROP TRIGGER service_event_subscription_outbox_complete;
DROP TRIGGER service_event_subscription_head_cas;
CREATE TABLE service_event_subscription_revision_v71 (
 subscription_id TEXT NOT NULL REFERENCES service_event_subscription(subscription_id) DEFERRABLE INITIALLY DEFERRED,
 revision INTEGER NOT NULL CHECK(revision BETWEEN 1 AND 65536),state TEXT NOT NULL CHECK(state IN('building','snapshot_ready','catching_up','live','closed','revoked','expired','resync_required')),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),body_digest TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,
 PRIMARY KEY(subscription_id,revision),UNIQUE(subscription_id,revision,operation_id),
 CHECK((revision=1 AND state='building') OR revision>1),
 CHECK(json_extract(body_jcs,'$.binding.subscription_id')=subscription_id AND json_extract(body_jcs,'$.revision')=CAST(revision AS TEXT) AND json_extract(body_jcs,'$.state')=state),
 FOREIGN KEY(operation_id,subscription_id,revision) REFERENCES service_event_subscription_outbox(operation_id,subscription_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO service_event_subscription_revision_v71 SELECT * FROM service_event_subscription_revision;
DROP TABLE service_event_subscription_revision;
ALTER TABLE service_event_subscription_revision_v71 RENAME TO service_event_subscription_revision;
CREATE TRIGGER service_event_subscription_revision_no_update BEFORE UPDATE ON service_event_subscription_revision BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_revision_no_delete BEFORE DELETE ON service_event_subscription_revision BEGIN SELECT RAISE(ABORT,'immutable_subscription'); END;
CREATE TRIGGER service_event_subscription_head_cas BEFORE UPDATE ON service_event_subscription_head WHEN NOT(
 OLD.subscription_id=NEW.subscription_id AND NEW.revision=OLD.revision+1 AND EXISTS(SELECT 1 FROM service_event_subscription_revision r WHERE r.subscription_id=OLD.subscription_id AND r.revision=OLD.revision AND r.state IN('building','snapshot_ready','catching_up','live')))
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
CREATE TRIGGER service_snapshot_baseline_parent BEFORE INSERT ON service_snapshot_baseline WHEN NOT EXISTS(
 SELECT 1 FROM service_snapshot_manifest m JOIN service_event_subscription_head h ON h.subscription_id=m.subscription_id
 JOIN service_event_subscription_revision r ON r.subscription_id=h.subscription_id AND r.revision=h.revision
 JOIN service_subscription_connection c ON c.subscription_id=h.subscription_id JOIN service_subscription_attempt a ON a.subscription_id=c.subscription_id AND a.attempt_id=c.attempt_id
 WHERE m.snapshot_id=NEW.snapshot_id AND m.subscription_id=NEW.subscription_id AND m.body_digest=NEW.manifest_digest AND m.marker_digest=NEW.marker_digest AND m.journal_sequence=NEW.journal_sequence
 AND r.state='snapshot_ready' AND NEW.subscription_revision=h.revision+1 AND a.generation=NEW.connection_generation
 AND json_extract(r.body_jcs,'$.binding.connection_generation')=a.generation
 AND NOT EXISTS(SELECT 1 FROM service_subscription_disconnect d WHERE d.connection_id=a.connection_id)
) BEGIN SELECT RAISE(ABORT,'snapshot_baseline_parent'); END;
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

CREATE TRIGGER service_subscription_reconcile_parent BEFORE INSERT ON service_subscription_reconcile
WHEN NOT EXISTS (
  SELECT 1 FROM service_snapshot_baseline b
  JOIN service_event_subscription_head h USING(subscription_id)
  JOIN service_event_subscription_revision r USING(subscription_id,revision)
  WHERE b.subscription_id=NEW.subscription_id AND b.journal_sequence=CAST(NEW.start_sequence AS TEXT)
    AND r.state='snapshot_ready' AND b.subscription_revision=h.revision+1
    AND NEW.end_sequence=(SELECT coalesce(max(sequence),0) FROM device_source_notification)
)
BEGIN SELECT RAISE(ABORT,'reconcile_window_parent'); END;

CREATE TRIGGER service_subscription_reconcile_required BEFORE INSERT ON service_event_subscription_revision
WHEN NEW.state IN('catching_up','live') AND NOT EXISTS (
  SELECT 1 FROM service_subscription_reconcile WHERE subscription_id=NEW.subscription_id
)
BEGIN SELECT RAISE(ABORT,'reconcile_window_missing'); END;

CREATE TABLE service_subscription_follow (
 subscription_id TEXT NOT NULL REFERENCES service_subscription_reconcile(subscription_id),
 connection_generation TEXT NOT NULL,
 end_sequence INTEGER NOT NULL CHECK(end_sequence BETWEEN 0 AND 9007199254740991),
 PRIMARY KEY(subscription_id,connection_generation),
 FOREIGN KEY(subscription_id,connection_generation) REFERENCES service_subscription_attempt(subscription_id,generation)
) STRICT;
CREATE TRIGGER service_subscription_follow_parent BEFORE INSERT ON service_subscription_follow
WHEN NOT EXISTS(
 SELECT 1 FROM service_subscription_connection c JOIN service_subscription_attempt a USING(subscription_id,attempt_id)
 JOIN service_subscription_reconcile w USING(subscription_id)
 WHERE c.subscription_id=NEW.subscription_id AND a.generation=NEW.connection_generation
 AND NEW.end_sequence>=w.end_sequence AND NEW.end_sequence=(SELECT coalesce(max(sequence),0) FROM device_source_notification)
) BEGIN SELECT RAISE(ABORT,'reconcile_follow_parent'); END;
CREATE TRIGGER service_subscription_follow_no_update BEFORE UPDATE ON service_subscription_follow
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_follow'); END;
CREATE TRIGGER service_subscription_follow_no_delete BEFORE DELETE ON service_subscription_follow
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_follow'); END;

CREATE TABLE service_subscription_delivery (
  subscription_id TEXT NOT NULL REFERENCES service_subscription_reconcile(subscription_id),
  cursor INTEGER NOT NULL CHECK(cursor BETWEEN 1 AND 65537),
  journal_sequence INTEGER REFERENCES device_source_notification(sequence),
  body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
  body_digest TEXT NOT NULL CHECK(length(body_digest)=71 AND substr(body_digest,1,7)='sha256:'
    AND substr(body_digest,8) NOT GLOB '*[^0-9a-f]*'),
  checkpoint_generation TEXT,
  PRIMARY KEY(subscription_id,cursor),
  UNIQUE(subscription_id,journal_sequence),
  UNIQUE(subscription_id,checkpoint_generation),
  FOREIGN KEY(subscription_id,checkpoint_generation) REFERENCES service_subscription_follow(subscription_id,connection_generation),
  CHECK(coalesce(json_extract(body_jcs,'$.entry_kind')='sync.ready',0)=(journal_sequence IS NULL)),
  CHECK((checkpoint_generation IS NOT NULL)=(journal_sequence IS NULL))
) STRICT;

CREATE TRIGGER service_subscription_delivery_parent BEFORE INSERT ON service_subscription_delivery
WHEN NEW.journal_sequence IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM service_subscription_reconcile w
  JOIN service_event_subscription_head h USING(subscription_id)
  JOIN service_event_subscription_revision r USING(subscription_id,revision)
  JOIN service_subscription_follow f ON f.subscription_id=w.subscription_id
   AND f.connection_generation=json_extract(r.body_jcs,'$.binding.connection_generation')
  JOIN device_source_notification n ON n.sequence=NEW.journal_sequence
  LEFT JOIN device_source_event e ON e.record_id=n.event_id AND e.registration_id=n.registration_id
  WHERE w.subscription_id=NEW.subscription_id AND r.state IN('catching_up','live')
    AND NEW.cursor=1+coalesce((SELECT max(d.cursor) FROM service_subscription_delivery d WHERE d.subscription_id=w.subscription_id),0)
    AND n.sequence=(
      SELECT min(candidate.sequence) FROM device_source_notification candidate
      JOIN service_event_subscription_pin p ON p.registration_id=candidate.registration_id AND p.subscription_id=w.subscription_id
      WHERE candidate.sequence BETWEEN coalesce(
        (SELECT max(d.journal_sequence) FROM service_subscription_delivery d WHERE d.subscription_id=w.subscription_id),w.start_sequence
      )+1 AND CASE WHEN r.state='live' THEN (SELECT max(sequence) FROM device_source_notification) ELSE f.end_sequence END
    )
    AND json_extract(NEW.body_jcs,'$.entry_kind')=n.entry_kind
    AND (
      (n.entry_kind='entity.upsert' AND json_extract(NEW.body_jcs,'$.payload')=n.body_jcs)
      OR (n.entry_kind='source.event' AND json_extract(NEW.body_jcs,'$.payload.origin')=e.origin_jcs
        AND json_extract(NEW.body_jcs,'$.payload.origin_digest')=e.origin_digest)
    )
)
BEGIN SELECT RAISE(ABORT,'reconcile_delivery_parent'); END;

CREATE TRIGGER service_subscription_ready_parent BEFORE INSERT ON service_subscription_delivery
WHEN NEW.journal_sequence IS NULL AND NOT EXISTS(
 SELECT 1 FROM service_subscription_reconcile w
 JOIN service_snapshot_baseline b USING(subscription_id)
 JOIN service_event_subscription_head h USING(subscription_id)
 JOIN service_event_subscription_revision r USING(subscription_id,revision)
 JOIN service_subscription_follow f ON f.subscription_id=w.subscription_id AND f.connection_generation=NEW.checkpoint_generation
 WHERE w.subscription_id=NEW.subscription_id AND r.state='catching_up'
   AND f.connection_generation=json_extract(r.body_jcs,'$.binding.connection_generation')
   AND NEW.cursor=1+coalesce((SELECT max(d.cursor) FROM service_subscription_delivery d WHERE d.subscription_id=w.subscription_id),0)
   AND NEW.cursor=1+CAST(json_extract(r.body_jcs,'$.ack_cursor') AS INTEGER)
   AND json_extract(NEW.body_jcs,'$.payload.baseline_snapshot_id')=b.snapshot_id
   AND NOT EXISTS(
    SELECT 1 FROM device_source_notification n
    JOIN service_event_subscription_pin p ON p.registration_id=n.registration_id AND p.subscription_id=w.subscription_id
    WHERE n.sequence BETWEEN coalesce(
     (SELECT max(d.journal_sequence) FROM service_subscription_delivery d WHERE d.subscription_id=w.subscription_id),w.start_sequence
    )+1 AND f.end_sequence
   )
) BEGIN SELECT RAISE(ABORT,'reconcile_ready_parent'); END;

CREATE TRIGGER service_subscription_reconcile_no_update BEFORE UPDATE ON service_subscription_reconcile
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_window'); END;
CREATE TRIGGER service_subscription_reconcile_no_delete BEFORE DELETE ON service_subscription_reconcile
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_window'); END;
CREATE TRIGGER service_subscription_delivery_no_update BEFORE UPDATE ON service_subscription_delivery
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_delivery'); END;
CREATE TRIGGER service_subscription_delivery_no_delete BEFORE DELETE ON service_subscription_delivery
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_delivery'); END;

CREATE TABLE service_subscription_transmitted (
  subscription_id TEXT NOT NULL, connection_generation TEXT NOT NULL, cursor INTEGER NOT NULL,
  PRIMARY KEY(subscription_id,connection_generation,cursor),
  FOREIGN KEY(subscription_id,connection_generation) REFERENCES service_subscription_attempt(subscription_id,generation),
  FOREIGN KEY(subscription_id,cursor) REFERENCES service_subscription_delivery(subscription_id,cursor)
) STRICT;
CREATE TRIGGER service_subscription_transmitted_parent BEFORE INSERT ON service_subscription_transmitted
WHEN NOT EXISTS(
  SELECT 1 FROM service_subscription_connection c JOIN service_subscription_attempt a USING(subscription_id,attempt_id)
  JOIN service_event_subscription_head h USING(subscription_id)
  JOIN service_event_subscription_revision r USING(subscription_id,revision)
  WHERE c.subscription_id=NEW.subscription_id AND a.generation=NEW.connection_generation
    AND r.state IN('catching_up','live') AND CAST(json_extract(r.body_jcs,'$.ack_cursor') AS INTEGER)+1=NEW.cursor
    AND NOT EXISTS(SELECT 1 FROM service_subscription_disconnect d WHERE d.connection_id=a.connection_id)
) BEGIN SELECT RAISE(ABORT,'reconcile_transmitted_parent'); END;

CREATE TABLE service_subscription_delivery_ack (
  subscription_id TEXT NOT NULL, cursor INTEGER NOT NULL, connection_generation TEXT NOT NULL,
  subscription_revision INTEGER NOT NULL,
  PRIMARY KEY(subscription_id,cursor),
  FOREIGN KEY(subscription_id,connection_generation,cursor) REFERENCES service_subscription_transmitted(subscription_id,connection_generation,cursor),
  FOREIGN KEY(subscription_id,subscription_revision) REFERENCES service_event_subscription_revision(subscription_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER service_subscription_delivery_ack_parent BEFORE INSERT ON service_subscription_delivery_ack
WHEN NOT EXISTS(
 SELECT 1 FROM service_event_subscription_head h JOIN service_event_subscription_revision r USING(subscription_id,revision)
 WHERE h.subscription_id=NEW.subscription_id AND r.state IN('catching_up','live')
   AND h.revision+1=NEW.subscription_revision
   AND json_extract(r.body_jcs,'$.binding.connection_generation')=NEW.connection_generation
   AND CAST(json_extract(r.body_jcs,'$.ack_cursor') AS INTEGER)+1=NEW.cursor
) BEGIN SELECT RAISE(ABORT,'reconcile_ack_parent'); END;

CREATE TRIGGER service_snapshot_catching_up_parent BEFORE INSERT ON service_event_subscription_revision
WHEN NEW.state IN('catching_up','live') AND NOT EXISTS(
 SELECT 1 FROM service_snapshot_baseline b WHERE b.subscription_id=NEW.subscription_id AND b.subscription_revision<=NEW.revision
 AND b.snapshot_id=json_extract(NEW.body_jcs,'$.snapshot_ref.snapshot_id')
 AND b.manifest_digest=json_extract(NEW.body_jcs,'$.snapshot_ref.manifest_digest')
 AND (
  (b.snapshot_cursor=json_extract(NEW.body_jcs,'$.ack_cursor') AND b.marker_digest=json_extract(NEW.body_jcs,'$.ack_payload_digest')
   AND NOT EXISTS(SELECT 1 FROM service_subscription_delivery_ack a WHERE a.subscription_id=b.subscription_id))
  OR EXISTS(
   SELECT 1 FROM service_subscription_delivery_ack a JOIN service_subscription_delivery d USING(subscription_id,cursor)
   WHERE a.subscription_id=b.subscription_id AND a.subscription_revision<=NEW.revision
    AND a.cursor=(SELECT max(cursor) FROM service_subscription_delivery_ack WHERE subscription_id=b.subscription_id)
    AND CAST(a.cursor AS TEXT)=json_extract(NEW.body_jcs,'$.ack_cursor')
    AND substr(d.body_digest,8)=json_extract(NEW.body_jcs,'$.ack_payload_digest')
   )
 )
) BEGIN SELECT RAISE(ABORT,'snapshot_baseline_missing'); END;

CREATE TRIGGER service_subscription_live_parent BEFORE INSERT ON service_event_subscription_revision
WHEN NEW.state='live' AND NOT EXISTS(
 SELECT 1 FROM service_subscription_delivery d JOIN service_subscription_delivery_ack a USING(subscription_id,cursor)
 WHERE d.subscription_id=NEW.subscription_id AND d.checkpoint_generation=json_extract(NEW.body_jcs,'$.binding.connection_generation')
   AND a.connection_generation=d.checkpoint_generation AND d.cursor<=CAST(json_extract(NEW.body_jcs,'$.ack_cursor') AS INTEGER)
) BEGIN SELECT RAISE(ABORT,'subscription_live_without_checkpoint'); END;

CREATE TRIGGER service_subscription_transmitted_no_update BEFORE UPDATE ON service_subscription_transmitted
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_transmitted'); END;
CREATE TRIGGER service_subscription_transmitted_no_delete BEFORE DELETE ON service_subscription_transmitted
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_transmitted'); END;
CREATE TRIGGER service_subscription_delivery_ack_no_update BEFORE UPDATE ON service_subscription_delivery_ack
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_ack'); END;
CREATE TRIGGER service_subscription_delivery_ack_no_delete BEFORE DELETE ON service_subscription_delivery_ack
BEGIN SELECT RAISE(ABORT,'immutable_reconcile_ack'); END;
