DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v86 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '86'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v86 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '86', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v86 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v86 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86')),
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
    OR (from_revision = '70' AND to_revision = '71' AND backup_ref IS NOT NULL)
    OR (from_revision = '71' AND to_revision = '72' AND backup_ref IS NOT NULL)
    OR (from_revision = '72' AND to_revision = '73' AND backup_ref IS NOT NULL)
    OR (from_revision = '73' AND to_revision = '74' AND backup_ref IS NOT NULL)
    OR (from_revision = '74' AND to_revision = '75' AND backup_ref IS NOT NULL)
    OR (from_revision = '75' AND to_revision = '76' AND backup_ref IS NOT NULL)
    OR (from_revision = '76' AND to_revision = '77' AND backup_ref IS NOT NULL)
    OR (from_revision = '77' AND to_revision = '78' AND backup_ref IS NOT NULL)
    OR (from_revision = '78' AND to_revision = '79' AND backup_ref IS NOT NULL)
    OR (from_revision = '79' AND to_revision = '80' AND backup_ref IS NOT NULL)
    OR (from_revision = '80' AND to_revision = '81' AND backup_ref IS NOT NULL)
    OR (from_revision = '81' AND to_revision = '82' AND backup_ref IS NOT NULL)
    OR (from_revision = '82' AND to_revision = '83' AND backup_ref IS NOT NULL)
    OR (from_revision = '83' AND to_revision = '84' AND backup_ref IS NOT NULL)
    OR (from_revision = '84' AND to_revision = '85' AND backup_ref IS NOT NULL)
    OR (from_revision = '85' AND to_revision = '86' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v86 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v86 RENAME TO schema_migration;
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

CREATE TABLE time_provider_poll_control (
  poll_id TEXT PRIMARY KEY NOT NULL REFERENCES time_provider_poll_attempt(poll_id),
  source_digest TEXT NOT NULL,
  attempt_id TEXT NOT NULL UNIQUE,
  received_tick TEXT NOT NULL CHECK(length(received_tick)=20 AND received_tick NOT GLOB '*[^0-9]*'),
  wait_ns TEXT NOT NULL CHECK(length(wait_ns)=20 AND wait_ns NOT GLOB '*[^0-9]*' AND wait_ns<='00000003600000000000'),
  next_allowed_tick TEXT CHECK(length(next_allowed_tick)=20 AND next_allowed_tick NOT GLOB '*[^0-9]*' AND next_allowed_tick>received_tick),
  body_jcs TEXT NOT NULL CHECK(length(body_jcs) BETWEEN 1 AND 8192),
  body_digest TEXT NOT NULL,
  UNIQUE(poll_id,body_digest),
  CHECK((wait_ns='00000000000000000000') IS (next_allowed_tick IS NULL)
    AND json_extract(body_jcs,'$.format') IS 'leafseamer-time-provider-poll-control/1'
    AND json_extract(body_jcs,'$.poll_ref.id') IS poll_id
    AND json_extract(body_jcs,'$.source_digest') IS source_digest
    AND json_extract(body_jcs,'$.attempt_id') IS attempt_id
    AND substr('00000000000000000000'||json_extract(body_jcs,'$.control.wait_ns'),-20) IS wait_ns
    AND (next_allowed_tick IS NULL OR json_extract(body_jcs,'$.control.code') IS 1380013125)
    AND substr('00000000000000000000'||json_extract(body_jcs,'$.received_tick_ns'),-20) IS received_tick
    AND substr('00000000000000000000'||json_extract(body_jcs,'$.next_allowed_tick_ns'),-20) IS next_allowed_tick)
) STRICT;
CREATE INDEX time_provider_poll_control_source ON time_provider_poll_control(source_digest);
CREATE TRIGGER time_provider_poll_control_parent BEFORE INSERT ON time_provider_poll_control
WHEN NOT EXISTS (SELECT 1 FROM time_provider_poll_reservation p JOIN time_provider_poll_attempt a USING(poll_id)
  JOIN service_boot b USING(service_boot_id)
  WHERE p.poll_id=NEW.poll_id AND p.source_digest=NEW.source_digest AND a.attempt_id=NEW.attempt_id
    AND b.state='started' AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND p.service_boot_id IS json_extract(NEW.body_jcs,'$.service_boot_id')
    AND p.body_digest IS json_extract(NEW.body_jcs,'$.poll_ref.digest')
    AND json_extract(p.body_jcs,'$.runtime_digest') IS json_extract(NEW.body_jcs,'$.runtime_digest')
    AND json_type(p.body_jcs,'$.effective_poll_interval_ns') IS 'text'
    AND a.attempted_tick<=substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.control.observed_tick_ns'),-20)
    AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.control.observed_tick_ns'),-20)<=NEW.received_tick
    AND NEW.received_tick<substr('00000000000000000000'||json_extract(a.body_jcs,'$.valid_before_tick_ns'),-20))
 OR EXISTS (SELECT 1 FROM time_provider_capture c WHERE c.poll_id=NEW.poll_id)
BEGIN SELECT RAISE(ABORT,'time_provider_poll_control_parent'); END;
CREATE TRIGGER time_provider_capture_control_exclusive BEFORE INSERT ON time_provider_capture
WHEN EXISTS (SELECT 1 FROM time_provider_poll_control c WHERE c.poll_id=NEW.poll_id)
BEGIN SELECT RAISE(ABORT,'time_provider_poll_control_already_stored'); END;
CREATE TRIGGER time_provider_poll_control_no_update BEFORE UPDATE ON time_provider_poll_control
BEGIN SELECT RAISE(ABORT,'immutable_time_provider_poll_control'); END;
CREATE TRIGGER time_provider_poll_control_no_delete BEFORE DELETE ON time_provider_poll_control
BEGIN SELECT RAISE(ABORT,'immutable_time_provider_poll_control'); END;

CREATE TABLE time_provider_control_release (
  poll_id TEXT PRIMARY KEY NOT NULL,
  control_digest TEXT NOT NULL,
  next_allowed_tick TEXT,
  confirmation_jcs TEXT NOT NULL CHECK(length(confirmation_jcs) BETWEEN 1 AND 2048),
  confirmation_digest TEXT NOT NULL,
  FOREIGN KEY(poll_id,control_digest) REFERENCES time_provider_poll_control(poll_id,body_digest),
  CHECK(json_extract(confirmation_jcs,'$.type') IS 'POLL_CONTROL_STORED_ACK'
    AND json_extract(confirmation_jcs,'$.receipt.poll_ref.id') IS poll_id
    AND json_extract(confirmation_jcs,'$.receipt.control_ref.id') IS poll_id
    AND json_extract(confirmation_jcs,'$.receipt.control_ref.digest') IS control_digest)
) STRICT;
CREATE TRIGGER time_provider_control_release_parent BEFORE INSERT ON time_provider_control_release
WHEN NOT EXISTS (SELECT 1 FROM time_provider_poll_control c JOIN time_provider_poll_reservation p USING(poll_id)
  JOIN service_boot b USING(service_boot_id)
  WHERE c.poll_id=NEW.poll_id AND c.body_digest=NEW.control_digest AND c.next_allowed_tick IS NEW.next_allowed_tick
    AND b.state='started' AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND c.attempt_id IS json_extract(NEW.confirmation_jcs,'$.receipt.attempt_id')
    AND p.body_digest IS json_extract(NEW.confirmation_jcs,'$.receipt.poll_ref.digest')
    AND json_extract(p.body_jcs,'$.runtime_digest') IS json_extract(NEW.confirmation_jcs,'$.binding_digest'))
BEGIN SELECT RAISE(ABORT,'time_provider_control_release_parent'); END;
CREATE TRIGGER time_provider_control_release_no_update BEFORE UPDATE ON time_provider_control_release
BEGIN SELECT RAISE(ABORT,'immutable_time_provider_control_release'); END;
CREATE TRIGGER time_provider_control_release_no_delete BEFORE DELETE ON time_provider_control_release
BEGIN SELECT RAISE(ABORT,'immutable_time_provider_control_release'); END;


DROP TRIGGER time_provider_source_recovery_parent;
CREATE TRIGGER time_provider_source_recovery_parent BEFORE INSERT ON time_provider_source_recovery
WHEN NOT EXISTS (
  SELECT 1 FROM time_provider_poll_reservation p JOIN time_provider_runtime_binding old USING(service_boot_id)
  JOIN time_provider_runtime_binding current ON current.service_boot_id=NEW.receiver_boot_id
  JOIN service_boot b ON b.service_boot_id=current.service_boot_id
  WHERE p.poll_id=NEW.predecessor_poll_id AND p.source_digest=NEW.source_digest
    AND p.rowid=(SELECT max(rowid) FROM time_provider_poll_reservation WHERE source_digest=NEW.source_digest)
    AND p.service_boot_id<>NEW.receiver_boot_id AND b.state='started' AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND json_extract(NEW.body_jcs,'$.predecessor_digest') IS p.body_digest
    AND json_extract(NEW.body_jcs,'$.old_runtime_digest') IS old.body_digest
    AND json_extract(NEW.body_jcs,'$.observation.record.launch_intent.launch_id') IS old.launch_id
    AND json_extract(NEW.body_jcs,'$.observation.record.admission_receipt.receipt_id') IS old.receipt_id
    AND json_extract(NEW.body_jcs,'$.observation.record.core_receipt_id') IS json_extract(old.body_jcs,'$.core_receipt_id')
    AND json_extract(NEW.body_jcs,'$.observation.receiving_domain_ref.clock_domain_id') IS json_extract(current.body_jcs,'$.clock_domain_descriptor.clock_domain_id')
    AND json_extract(NEW.body_jcs,'$.observation.receiving_domain_ref.descriptor_digest') IS json_extract(current.body_jcs,'$.clock_domain_descriptor.descriptor_digest')
    AND (NEW.wait_until_tick IS NULL OR (json_type(p.body_jcs,'$.authorization.minimum_poll_interval_ns') IS 'text'
      AND (NOT EXISTS (SELECT 1 FROM time_provider_poll_attempt a WHERE a.poll_id=p.poll_id)
        OR EXISTS (SELECT 1 FROM time_provider_capture c WHERE c.poll_id=p.poll_id)
        OR EXISTS (SELECT 1 FROM time_provider_poll_control z WHERE z.poll_id=p.poll_id AND z.next_allowed_tick IS NOT NULL)))))
BEGIN SELECT RAISE(ABORT,'time_provider_source_recovery_parent'); END;

DROP TRIGGER time_provider_poll_runtime;
CREATE TRIGGER time_provider_poll_runtime BEFORE INSERT ON time_provider_poll_reservation
WHEN NOT EXISTS (SELECT 1 FROM time_provider_runtime_binding r JOIN service_boot b USING(service_boot_id)
  JOIN authentication_clock_acquisition a ON a.id=NEW.acquisition_id AND a.service_boot_id=r.service_boot_id
  WHERE r.service_boot_id=NEW.service_boot_id AND b.state='started'
    AND b.rowid=(SELECT max(rowid) FROM service_boot)
    AND a.digest=json_extract(NEW.body_jcs,'$.acquisition_ref.digest')
    AND r.body_digest=json_extract(NEW.body_jcs,'$.runtime_digest'))
 OR json_type(NEW.body_jcs,'$.effective_poll_interval_ns') IS NOT 'text'
 OR substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.effective_poll_interval_ns'),-20)
    <substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.authorization.minimum_poll_interval_ns'),-20)
 OR EXISTS (SELECT 1 FROM time_provider_poll_control c WHERE c.source_digest=NEW.source_digest
    AND (c.next_allowed_tick IS NULL OR substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.effective_poll_interval_ns'),-20)<c.wait_ns))
 OR EXISTS (SELECT 1 FROM time_provider_poll_reservation p WHERE p.source_slot=NEW.source_slot AND p.source_digest<>NEW.source_digest)
 OR EXISTS (SELECT 1 FROM time_provider_poll_reservation p LEFT JOIN time_provider_poll_release x USING(poll_id)
   LEFT JOIN time_provider_control_release z USING(poll_id)
   LEFT JOIN time_provider_source_recovery q ON q.predecessor_poll_id=p.poll_id AND q.receiver_boot_id=NEW.service_boot_id
   WHERE p.rowid=(SELECT max(rowid) FROM time_provider_poll_reservation WHERE source_digest=NEW.source_digest)
     AND ((p.service_boot_id=NEW.service_boot_id AND (coalesce(x.next_allowed_tick,z.next_allowed_tick) IS NULL OR NEW.issued_tick<coalesce(x.next_allowed_tick,z.next_allowed_tick)))
       OR (p.service_boot_id<>NEW.service_boot_id AND (q.wait_until_tick IS NULL OR NEW.issued_tick<q.wait_until_tick))))
BEGIN SELECT RAISE(ABORT,'time_provider_poll_runtime_or_source'); END;
