DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v48 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '48'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v48 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '48', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v48 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v48 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48')),
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
    OR (from_revision = '47' AND to_revision = '48' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v48 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v48 RENAME TO schema_migration;
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

CREATE TABLE device_initial_ready (
 ready_id TEXT PRIMARY KEY NOT NULL,
 opening_id TEXT NOT NULL UNIQUE REFERENCES execution_initial_open_ack(opening_id),
 control_source_id TEXT NOT NULL UNIQUE REFERENCES control_state_source(source_id) DEFERRABLE INITIALLY DEFERRED,
 control_revision INTEGER NOT NULL CHECK(control_revision>2),
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=32768),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs))
) STRICT;
DROP TRIGGER control_change_commit_no_delete;
DROP TRIGGER control_change_commit_no_update;
DROP TRIGGER control_commit_members;
DROP TRIGGER control_record_commit_closed;
DROP TRIGGER control_source_commit;
DROP TRIGGER control_source_no_backfill;
DROP TRIGGER device_authorization_required;
DROP TRIGGER execution_fence_control_source;
CREATE TABLE control_change_commit_v48 (
 commit_id TEXT PRIMARY KEY NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('acquire','release','transfer','offer','cancel_offer','expire_offer','effective','indeterminate','rejected','ready','gate_protect')),
 members INTEGER NOT NULL CHECK(members BETWEEN 1 AND 4),
 audit_jcs TEXT NOT NULL CHECK(json_valid(audit_jcs)),
 event_id TEXT NOT NULL UNIQUE,
 notification_jcs TEXT NOT NULL CHECK(json_valid(notification_jcs)),
 ready_source_id TEXT GENERATED ALWAYS AS(CASE WHEN kind='ready' THEN commit_id END) VIRTUAL,
 FOREIGN KEY(ready_source_id) REFERENCES device_initial_ready(control_source_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO control_change_commit_v48(commit_id,kind,members,audit_jcs,event_id,notification_jcs) SELECT commit_id,kind,members,audit_jcs,event_id,notification_jcs FROM control_change_commit;
DROP TABLE control_change_commit;
ALTER TABLE control_change_commit_v48 RENAME TO control_change_commit;
CREATE TRIGGER control_change_commit_no_delete BEFORE DELETE ON control_change_commit BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_change_commit_no_update BEFORE UPDATE ON control_change_commit BEGIN SELECT RAISE(ABORT,'immutable_control_fact'); END;
CREATE TRIGGER control_commit_members BEFORE INSERT ON control_change_commit
WHEN NEW.members!=(SELECT count(*) FROM control_record_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_operation_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_offer_revision WHERE commit_id=NEW.commit_id)
 +(SELECT count(*) FROM control_request WHERE commit_id=NEW.commit_id)
BEGIN SELECT RAISE(ABORT,'control_commit_members'); END;
CREATE TRIGGER control_record_commit_closed BEFORE INSERT ON control_record_revision
WHEN EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.commit_id)
BEGIN SELECT RAISE(ABORT,'control_source_commit_closed'); END;
CREATE TRIGGER control_source_commit BEFORE INSERT ON control_change_commit
WHEN EXISTS (SELECT 1 FROM control_record_revision r WHERE r.commit_id=NEW.commit_id AND NOT EXISTS (
 SELECT 1 FROM control_state_source s WHERE s.source_id=NEW.commit_id AND s.device_id=r.device_id AND s.revision=r.revision AND s.change_kind=NEW.kind))
BEGIN SELECT RAISE(ABORT,'control_source_required'); END;
CREATE TRIGGER control_source_no_backfill BEFORE INSERT ON control_state_source
WHEN EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.source_id)
BEGIN SELECT RAISE(ABORT,'control_source_commit_closed'); END;
CREATE TRIGGER device_authorization_required BEFORE INSERT ON control_change_commit
WHEN EXISTS(SELECT 1 FROM control_state_source s WHERE s.source_id=NEW.commit_id AND NOT EXISTS(
 SELECT 1 FROM device_authorization_head h JOIN device_authorization_state a USING(state_id)
 JOIN device_authorization_commit c ON c.commit_id=h.commit_id AND c.state_id=a.state_id
 WHERE h.device_id=s.device_id AND (
 (NEW.kind NOT IN('ready','gate_protect') AND a.control_source_id=s.source_id) OR
 (NEW.kind='ready' AND json_extract(a.body_jcs,'$.status')='policy_selected' AND EXISTS(SELECT 1 FROM device_initial_ready r
 WHERE r.control_source_id=NEW.commit_id AND json_extract(r.body_jcs,'$.eligibility_refs.authorization.id')=a.state_id
 AND json_extract(r.body_jcs,'$.eligibility_refs.authorization.digest')=a.body_digest)) OR
 (NEW.kind='gate_protect' AND json_extract(a.body_jcs,'$.status')='protected'
 AND a.control_source_id=(SELECT authority.source_id FROM control_state_source authority WHERE authority.device_id=s.device_id
 AND authority.change_kind NOT IN('ready','gate_protect') ORDER BY authority.revision DESC LIMIT 1)
 AND json_extract(c.body_jcs,'$.sampled_tick_ns')=json_extract(s.body_jcs,'$.observed_tick_ns')))))
BEGIN SELECT RAISE(ABORT,'device_authorization_required'); END;
CREATE TRIGGER execution_fence_control_source BEFORE INSERT ON execution_initial_fence
WHEN NOT EXISTS (SELECT 1 FROM control_state_source s JOIN control_change_commit c ON c.commit_id=s.source_id
 WHERE s.device_id=NEW.control_device_id AND s.revision=NEW.control_revision
 AND json_extract(NEW.body_jcs,'$.control_source_ref.id')=s.source_id
 AND json_extract(NEW.body_jcs,'$.control_source_ref.revision')=CAST(s.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.control_source_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'execution_control_source_required'); END;
CREATE TRIGGER initial_ready_parent BEFORE INSERT ON device_initial_ready WHEN NOT EXISTS (
 SELECT 1 FROM execution_initial_open_ack a JOIN execution_initial_open_dispatch d USING(opening_id)
 JOIN device_initial_open o USING(opening_id) JOIN execution_write_result w ON w.attempt_id=a.write_attempt_id
 JOIN control_state_source b ON b.source_id=json_extract(NEW.body_jcs,'$.control_before_ref.id')
 JOIN control_record_revision r ON r.commit_id=NEW.control_source_id
 JOIN control_record_head h ON h.device_id=r.device_id AND h.revision=r.revision
 WHERE a.opening_id=NEW.opening_id AND w.result='complete' AND r.revision=NEW.control_revision AND b.device_id=r.device_id AND b.revision+1=r.revision
 AND b.body_digest=json_extract(NEW.body_jcs,'$.control_before_ref.digest')
 AND json_extract(o.body_jcs,'$.plan.state_refs.control')=json_extract(NEW.body_jcs,'$.control_before_ref')
 AND json_extract(o.body_jcs,'$.plan.binding')=json_extract(NEW.body_jcs,'$.binding')
 AND json_extract(NEW.body_jcs,'$.format')='initial-device-ready/1'
 AND json_extract(NEW.body_jcs,'$.id')=NEW.ready_id AND json_extract(NEW.body_jcs,'$.revision')='1'
 AND json_extract(NEW.body_jcs,'$.digest')=NEW.body_digest
 AND json_extract(NEW.body_jcs,'$.control_after_ref.id')=NEW.control_source_id
 AND json_extract(NEW.body_jcs,'$.control_after_ref.revision')=CAST(r.revision AS TEXT)
 AND json_extract(NEW.body_jcs,'$.dispatch_ref.digest')=d.body_digest
 AND json_extract(NEW.body_jcs,'$.confirmation_ref.digest')=a.body_digest
 AND json_extract(b.body_jcs,'$.gate_state')='protected' AND json_extract(r.body_jcs,'$.gate_state')='ready'
 AND json_extract(r.body_jcs,'$.pending_change') IS NULL AND json_extract(NEW.body_jcs,'$.gate_after.phase')='ready'
 AND json_extract(NEW.body_jcs,'$.expires_tick_ns')=json_extract(o.body_jcs,'$.plan.expires_tick_ns')
) BEGIN SELECT RAISE(ABORT,'initial_ready_parent'); END;
CREATE TRIGGER initial_ready_no_backfill BEFORE INSERT ON device_initial_ready
WHEN EXISTS(SELECT 1 FROM control_change_commit WHERE commit_id=NEW.control_source_id)
BEGIN SELECT RAISE(ABORT,'initial_ready_commit_closed'); END;
CREATE TRIGGER control_gate_successor BEFORE INSERT ON control_state_source
WHEN NEW.change_kind IN('ready','gate_protect') AND NOT EXISTS (
 SELECT 1 FROM control_state_source b WHERE b.device_id=NEW.device_id AND b.revision+1=NEW.revision
 AND json_extract(NEW.body_jcs,'$.scope')=json_extract(b.body_jcs,'$.scope')
 AND json_extract(NEW.body_jcs,'$.holder')=json_extract(b.body_jcs,'$.holder')
 AND json_extract(NEW.body_jcs,'$.mode')='manual'
 AND json_extract(NEW.body_jcs,'$.mode')=json_extract(b.body_jcs,'$.mode')
 AND json_extract(NEW.body_jcs,'$.control_epoch')=json_extract(b.body_jcs,'$.control_epoch')
 AND json_extract(NEW.body_jcs,'$.effective_version')=json_extract(b.body_jcs,'$.effective_version')
 AND json_extract(NEW.body_jcs,'$.reserved_version')=json_extract(b.body_jcs,'$.reserved_version')
 AND json_extract(NEW.body_jcs,'$.pending_operation_id') IS NULL
 AND b.clock_domain_id=NEW.clock_domain_id AND b.descriptor_digest=NEW.descriptor_digest
 AND ((NEW.change_kind='ready' AND json_extract(b.body_jcs,'$.gate_state')='protected'
 AND json_extract(NEW.body_jcs,'$.gate_state')='ready' AND EXISTS(SELECT 1 FROM device_initial_ready r WHERE r.control_source_id=NEW.source_id
 AND json_extract(r.body_jcs,'$.control_before_ref.id')=b.source_id AND json_extract(r.body_jcs,'$.control_after_ref.digest')=NEW.body_digest))
 OR (NEW.change_kind='gate_protect' AND b.change_kind='ready' AND json_extract(b.body_jcs,'$.gate_state')='ready'
 AND json_extract(NEW.body_jcs,'$.gate_state')='protected'))
) BEGIN SELECT RAISE(ABORT,'control_gate_successor'); END;
CREATE TRIGGER initial_ready_no_update BEFORE UPDATE ON device_initial_ready BEGIN SELECT RAISE(ABORT,'immutable_initial_ready'); END;
CREATE TRIGGER initial_ready_no_delete BEFORE DELETE ON device_initial_ready BEGIN SELECT RAISE(ABORT,'immutable_initial_ready'); END;

-- Ready只改变控制显示修订；新人员来源同时绑定实际控制头与稳定的控制权威。
DROP TRIGGER manual_authorization_state_parent;
CREATE TRIGGER manual_authorization_state_parent BEFORE INSERT ON execution_manual_authority
WHEN NOT EXISTS(SELECT 1 FROM device_authorization_head h JOIN device_authorization_state s USING(state_id)
 JOIN control_state_source c ON c.source_id=NEW.control_source_id
 JOIN control_record_head ch ON ch.device_id=c.device_id AND ch.revision=c.revision
 WHERE h.device_id=NEW.device_id AND c.device_id=NEW.device_id
 AND s.control_source_id=json_extract(NEW.body_jcs,'$.control_authority_ref.id')
 AND s.control_source_id=(SELECT a.source_id FROM control_state_source a WHERE a.device_id=NEW.device_id
 AND a.change_kind NOT IN('ready','gate_protect') ORDER BY a.revision DESC LIMIT 1)
 AND json_extract(NEW.body_jcs,'$.authorization_state_ref.id')=s.state_id
 AND substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.authorization_state_ref.revision'),-20)=s.revision
 AND json_extract(NEW.body_jcs,'$.authorization_state_ref.digest')=s.body_digest)
BEGIN SELECT RAISE(ABORT,'manual_authorization_state_parent'); END;
