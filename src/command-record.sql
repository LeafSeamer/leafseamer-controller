DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v49 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '49'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v49 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '49', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v49 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v49 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49')),
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
    OR (from_revision = '48' AND to_revision = '49' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v49 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v49 RENAME TO schema_migration;
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


CREATE TABLE command_admission_source (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES ca_command_initial(command_id) DEFERRABLE INITIALLY DEFERRED,
 key_id TEXT NOT NULL UNIQUE REFERENCES ca_request_key(key_id) DEFERRABLE INITIALLY DEFERRED,
 context_id TEXT NOT NULL REFERENCES request_context(context_id),
 token_id TEXT NOT NULL REFERENCES access_token(token_id),
 ready_id TEXT NOT NULL REFERENCES device_initial_ready(ready_id),
 binding_id TEXT NOT NULL REFERENCES device_execution_binding(binding_id),
 device_id TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 initial_revision INTEGER GENERATED ALWAYS AS (1) VIRTUAL,
 FOREIGN KEY(command_id) REFERENCES command_policy(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(command_id) REFERENCES command_resource_claim(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(command_id) REFERENCES command_context_charge(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(command_id,initial_revision) REFERENCES command_revision(command_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;
ALTER TABLE ca_command_initial ADD COLUMN source_id TEXT GENERATED ALWAYS AS (command_id) VIRTUAL
 REFERENCES command_admission_source(command_id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE command_policy (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES command_admission_source(command_id) DEFERRABLE INITIALLY DEFERRED,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)), body_digest TEXT NOT NULL CHECK(length(body_digest)=71)
) STRICT;
CREATE TABLE command_resource_claim (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES command_admission_source(command_id) DEFERRABLE INITIALLY DEFERRED,
 device_id TEXT NOT NULL, body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)), body_digest TEXT NOT NULL CHECK(length(body_digest)=71)
) STRICT;
CREATE TABLE command_context_charge (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES command_admission_source(command_id) DEFERRABLE INITIALLY DEFERRED,
 context_id TEXT NOT NULL REFERENCES request_context(context_id), before_count INTEGER NOT NULL CHECK(before_count>=0),
 after_count INTEGER NOT NULL CHECK(after_count=before_count+1), UNIQUE(context_id,after_count)
) STRICT;
-- 当前只允许无attempt的初始修订；后续执行修订须另有完整领域写集，不能直接覆盖此记录。
CREATE TABLE command_revision (
 command_id TEXT NOT NULL REFERENCES command_admission_source(command_id) DEFERRABLE INITIALLY DEFERRED,
 revision INTEGER NOT NULL CHECK(revision=1),
 record_jcs TEXT NOT NULL CHECK(json_valid(record_jcs)),record_digest TEXT NOT NULL CHECK(length(record_digest)=71),
 state_jcs TEXT NOT NULL CHECK(json_valid(state_jcs)),state_digest TEXT NOT NULL CHECK(length(state_digest)=71),
 manifest_jcs TEXT NOT NULL CHECK(json_valid(manifest_jcs)),manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=71),
 commit_id TEXT NOT NULL UNIQUE REFERENCES ca_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 PRIMARY KEY(command_id,revision)
) STRICT;
DROP TRIGGER ca_accept_unavailable;
CREATE TRIGGER command_source_parent BEFORE INSERT ON command_admission_source
WHEN NOT EXISTS(
 SELECT 1 FROM ca_command_initial c JOIN ca_adjudication a USING(command_id,key_id)
 JOIN ca_request_key k USING(key_id) JOIN ca_namespace n USING(namespace_id)
 JOIN device_initial_ready r ON r.ready_id=NEW.ready_id
 JOIN control_state_source t ON t.source_id=r.control_source_id
 JOIN control_record_head h ON h.device_id=t.device_id AND h.revision=t.revision
 JOIN device_execution_binding b ON b.binding_id=NEW.binding_id
 JOIN request_context x ON x.context_id=NEW.context_id JOIN access_token tok ON tok.token_id=NEW.token_id
 JOIN command_context_charge q ON q.command_id=c.command_id JOIN command_revision v ON v.command_id=c.command_id
 WHERE c.command_id=NEW.command_id AND c.key_id=NEW.key_id AND a.decision='accepted' AND a.commit_id=v.commit_id
 AND k.device_id=NEW.device_id AND t.device_id=NEW.device_id AND b.device_id=NEW.device_id
 AND x.token_id=NEW.token_id AND tok.state='active' AND x.state='active'
 AND n.issuer_id=x.issuer_id AND n.issuer_epoch=x.issuer_epoch AND n.principal_id=x.principal_id AND n.request_epoch=x.context_epoch
 AND q.context_id=x.context_id AND q.after_count=x.used_count
 AND json_extract(NEW.body_jcs,'$.format')='command-admission-source/1'
 AND json_extract(NEW.body_jcs,'$.command_id')=NEW.command_id
 AND json_extract(NEW.body_jcs,'$.context_id')=NEW.context_id AND json_extract(NEW.body_jcs,'$.token_id')=NEW.token_id
 AND json_extract(NEW.body_jcs,'$.initial_ref.digest')=c.command_digest
 AND json_extract(NEW.body_jcs,'$.ready_ref.id')=r.ready_id AND json_extract(NEW.body_jcs,'$.ready_ref.digest')=r.body_digest
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.binding')=json_extract(b.body_jcs,'$.binding')
 AND json_extract(NEW.body_jcs,'$.binding')=json_extract(r.body_jcs,'$.binding')
 AND json_extract(NEW.body_jcs,'$.metadata.actor.principal_id')=n.principal_id
 AND json_extract(NEW.body_jcs,'$.metadata.actor.issuer_id')=n.issuer_id
 AND json_extract(NEW.body_jcs,'$.metadata.actor.issuer_epoch')=n.issuer_epoch
 AND json_extract(NEW.body_jcs,'$.metadata.origin')='manual' AND json_type(NEW.body_jcs,'$.metadata.accepted_at')='null'
 AND json_extract(NEW.body_jcs,'$.metadata.dispatch.mode')='immediate'
 AND json_extract(v.record_jcs,'$.record_digest')=v.record_digest AND json_extract(v.record_jcs,'$.state')=json(v.state_jcs)
 AND json_extract(v.state_jcs,'$.phase')='queued' AND json_extract(v.state_jcs,'$.outcome')='pending'
 AND json_extract(v.state_jcs,'$.effect_status')='not_sent' AND json_extract(v.state_jcs,'$.resource_status')='clear'
 AND json_array_length(v.state_jcs,'$.attempt_ids')=0 AND json_array_length(v.manifest_jcs,'$.members')=0
) BEGIN SELECT RAISE(ABORT,'command_source_parent'); END;
CREATE TRIGGER command_source_no_backfill BEFORE INSERT ON command_admission_source
WHEN EXISTS(SELECT 1 FROM ca_commit c JOIN ca_command_initial i USING(key_id) WHERE i.command_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT,'command_commit_closed'); END;
CREATE TRIGGER command_accept_complete BEFORE INSERT ON ca_commit WHEN NEW.kind='accept' AND NOT EXISTS(
 SELECT 1 FROM command_admission_source s JOIN ca_command_initial i USING(command_id,key_id)
 JOIN command_revision r USING(command_id) JOIN command_context_charge q USING(command_id)
 JOIN request_context x ON x.context_id=s.context_id AND q.context_id=s.context_id WHERE s.key_id=NEW.key_id AND r.commit_id=NEW.commit_id
 AND q.after_count=x.used_count AND x.state='active'
) BEGIN SELECT RAISE(ABORT,'command_commit_incomplete'); END;
CREATE TRIGGER command_admission_source_no_update BEFORE UPDATE ON command_admission_source BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_admission_source_no_delete BEFORE DELETE ON command_admission_source BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_policy_no_update BEFORE UPDATE ON command_policy BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_policy_no_delete BEFORE DELETE ON command_policy BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_resource_claim_no_update BEFORE UPDATE ON command_resource_claim BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_resource_claim_no_delete BEFORE DELETE ON command_resource_claim BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_context_charge_no_update BEFORE UPDATE ON command_context_charge BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_context_charge_no_delete BEFORE DELETE ON command_context_charge BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_revision_no_update BEFORE UPDATE ON command_revision BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_revision_no_delete BEFORE DELETE ON command_revision BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
