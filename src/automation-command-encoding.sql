DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v97 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '97'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v97 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '97', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v97 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v97 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95', '96')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '90', '91', '92', '93', '94', '95', '96', '97')),
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
    OR (from_revision = '85' AND to_revision = '86' AND backup_ref IS NOT NULL)
    OR (from_revision = '86' AND to_revision = '87' AND backup_ref IS NOT NULL)
    OR (from_revision = '87' AND to_revision = '88' AND backup_ref IS NOT NULL)
    OR (from_revision = '88' AND to_revision = '89' AND backup_ref IS NOT NULL)
    OR (from_revision = '89' AND to_revision = '90' AND backup_ref IS NOT NULL)
    OR (from_revision = '90' AND to_revision = '91' AND backup_ref IS NOT NULL)
    OR (from_revision = '91' AND to_revision = '92' AND backup_ref IS NOT NULL)
    OR (from_revision = '92' AND to_revision = '93' AND backup_ref IS NOT NULL)
    OR (from_revision = '93' AND to_revision = '94' AND backup_ref IS NOT NULL)
    OR (from_revision = '94' AND to_revision = '95' AND backup_ref IS NOT NULL)
    OR (from_revision = '95' AND to_revision = '96' AND backup_ref IS NOT NULL)
    OR (from_revision = '96' AND to_revision = '97' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v97 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v97 RENAME TO schema_migration;
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



DROP TRIGGER command_encoding_request_parent;
DROP TRIGGER command_accept_complete;
PRAGMA legacy_alter_table=ON;

CREATE TABLE ca_namespace_v97 (
  namespace_id TEXT PRIMARY KEY NOT NULL,
  scope_id INTEGER NOT NULL CHECK(scope_id=1) REFERENCES ca_scope(singleton),
  issuer_id TEXT NOT NULL,
  issuer_epoch TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  request_epoch TEXT NOT NULL,
  owner_evidence_id TEXT REFERENCES request_context(context_id),
  owner_evidence_body BLOB NOT NULL CHECK(length(owner_evidence_body)>0),
  automation_preparation_id TEXT GENERATED ALWAYS AS (CASE WHEN owner_evidence_id IS NULL THEN request_epoch END) VIRTUAL REFERENCES run_preparation(preparation_id),
  UNIQUE(issuer_id,issuer_epoch,principal_id,request_epoch),
  CHECK(length(namespace_id)>0 AND length(issuer_id)>0 AND length(issuer_epoch)>0
    AND length(principal_id)>0 AND length(request_epoch)>0 AND (owner_evidence_id IS NULL OR length(owner_evidence_id)>0))
) STRICT;

INSERT INTO ca_namespace_v97 SELECT namespace_id,scope_id,issuer_id,issuer_epoch,principal_id,request_epoch,owner_evidence_id,owner_evidence_body FROM ca_namespace;
DROP TABLE ca_namespace;
ALTER TABLE ca_namespace_v97 RENAME TO ca_namespace;

CREATE TABLE command_admission_source_v97 (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES ca_command_initial(command_id) DEFERRABLE INITIALLY DEFERRED,
 key_id TEXT NOT NULL UNIQUE REFERENCES ca_request_key(key_id) DEFERRABLE INITIALLY DEFERRED,
 context_id TEXT REFERENCES request_context(context_id),
 token_id TEXT REFERENCES access_token(token_id),
 ready_id TEXT NOT NULL REFERENCES device_initial_ready(ready_id),
 binding_id TEXT NOT NULL REFERENCES device_execution_binding(binding_id),
 device_id TEXT NOT NULL,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs) AND length(CAST(body_jcs AS BLOB))<=65536),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 initial_revision INTEGER GENERATED ALWAYS AS (1) VIRTUAL,
 context_charge_id TEXT GENERATED ALWAYS AS (CASE WHEN context_id IS NOT NULL THEN command_id END) VIRTUAL,
 automation_command_id TEXT GENERATED ALWAYS AS (CASE WHEN context_id IS NULL THEN command_id END) VIRTUAL,
 CHECK((context_id IS NULL)=(token_id IS NULL)),
 FOREIGN KEY(command_id) REFERENCES command_policy(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(command_id) REFERENCES command_resource_claim(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(context_charge_id) REFERENCES command_context_charge(command_id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(automation_command_id) REFERENCES automation_command_adjudication(command_id),
 FOREIGN KEY(command_id,initial_revision) REFERENCES command_revision(command_id,revision) DEFERRABLE INITIALLY DEFERRED
) STRICT;

INSERT INTO command_admission_source_v97 SELECT command_id,key_id,context_id,token_id,ready_id,binding_id,device_id,body_jcs,body_digest FROM command_admission_source;
DROP TABLE command_admission_source;
ALTER TABLE command_admission_source_v97 RENAME TO command_admission_source;
PRAGMA legacy_alter_table=OFF;

CREATE TRIGGER ca_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NEW.owner_evidence_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM request_context c JOIN service_state s ON c.service_id=s.service_id
 WHERE c.context_id=NEW.owner_evidence_id AND c.database_instance_id=s.database_instance_id
 AND c.issuer_id=NEW.issuer_id AND c.issuer_epoch=NEW.issuer_epoch AND c.principal_id=NEW.principal_id
 AND c.context_epoch=NEW.request_epoch AND c.body=NEW.owner_evidence_body)
BEGIN SELECT RAISE(ABORT,'namespace_context_binding'); END;

CREATE TRIGGER command_source_parent BEFORE INSERT ON command_admission_source
WHEN NEW.context_id IS NOT NULL AND NOT EXISTS(
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
 AND json_extract(NEW.body_jcs,'$.metadata.origin')='manual'
 AND json_extract(NEW.body_jcs,'$.metadata.accepted_at') IS json_extract(CAST(c.command_body AS TEXT),'$.accepted_at')
 AND json_extract(NEW.body_jcs,'$.metadata.accepted_at') IS json_extract(v.record_jcs,'$.accepted_at')
 AND json_extract(NEW.body_jcs,'$.deadline.accepted') IS json_extract(CAST(c.command_body AS TEXT),'$.accepted_monotonic')
 AND (
  (json_type(NEW.body_jcs,'$.metadata.accepted_at') IS 'null'
    AND json_type(NEW.body_jcs,'$.accepted_reference') IS NULL
    AND json_type(CAST(c.command_body AS TEXT),'$.accepted_reference_ref') IS NULL)
  OR (json_type(NEW.body_jcs,'$.metadata.accepted_at') IS 'text'
    AND json_extract(NEW.body_jcs,'$.accepted_reference.format') IS 'leafseamer-command-reference-acceptance/1'
    AND json_extract(NEW.body_jcs,'$.accepted_reference.status') IS 'conditional'
    AND json_extract(NEW.body_jcs,'$.accepted_reference.accepted_at') IS json_extract(NEW.body_jcs,'$.metadata.accepted_at')
    AND json_extract(NEW.body_jcs,'$.accepted_reference.tick_ns') IS json_extract(NEW.body_jcs,'$.deadline.accepted.tick_ns')
    AND json_extract(NEW.body_jcs,'$.accepted_reference.domain_ref') IS json_extract(NEW.body_jcs,'$.deadline.accepted.domain')
    AND json_extract(CAST(c.command_body AS TEXT),'$.accepted_reference_ref.id') IS NEW.command_id||'_reference_acceptance'
    AND EXISTS (SELECT 1 FROM time_provider_reference_anchor anchor
      JOIN time_provider_runtime_binding rb USING(service_boot_id)
      JOIN execution_session execution USING(service_boot_id) JOIN service_boot live USING(service_boot_id)
      WHERE execution.ipc_session_id=b.ipc_session_id AND live.state='started' AND live.rowid=(SELECT max(rowid) FROM service_boot)
        AND anchor.anchor_id IS json_extract(NEW.body_jcs,'$.accepted_reference.anchor_ref.id')
        AND anchor.body_digest IS json_extract(NEW.body_jcs,'$.accepted_reference.anchor_ref.digest')
        AND anchor.rowid=(SELECT max(other.rowid) FROM time_provider_reference_anchor other WHERE other.service_boot_id=anchor.service_boot_id)
        AND json_extract(rb.body_jcs,'$.clock_domain_descriptor.clock_domain_id') IS json_extract(NEW.body_jcs,'$.deadline.accepted.domain.clock_domain_id')
        AND json_extract(rb.body_jcs,'$.clock_domain_descriptor.descriptor_digest') IS json_extract(NEW.body_jcs,'$.deadline.accepted.domain.descriptor_digest')
        AND substr('00000000000000000000'||json_extract(anchor.body_jcs,'$.published_tick_ns'),-20)
          <=substr('00000000000000000000'||json_extract(NEW.body_jcs,'$.deadline.accepted.tick_ns'),-20))))
 AND json_extract(NEW.body_jcs,'$.metadata.dispatch.mode')='immediate'
 AND json_extract(v.record_jcs,'$.record_digest')=v.record_digest AND json_extract(v.record_jcs,'$.state')=json(v.state_jcs)
 AND json_extract(v.state_jcs,'$.phase')='queued' AND json_extract(v.state_jcs,'$.outcome')='pending'
 AND json_extract(v.state_jcs,'$.effect_status')='not_sent' AND json_extract(v.state_jcs,'$.resource_status')='clear'
 AND json_array_length(v.state_jcs,'$.attempt_ids')=0 AND json_array_length(v.manifest_jcs,'$.members')=0) BEGIN SELECT RAISE(ABORT,'command_source_parent'); END;

CREATE TRIGGER command_encoding_request_parent BEFORE INSERT ON command_encoding_request WHEN EXISTS(SELECT 1 FROM command_admission_source WHERE command_id=NEW.command_id AND context_id IS NOT NULL) AND NOT EXISTS(
 SELECT 1 FROM command_admission_source s JOIN device_execution_binding b ON b.binding_id=s.binding_id
 JOIN command_encoding_reservation z ON z.prepare_id=NEW.prepare_id AND z.command_id=s.command_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN access_token t ON t.token_id=s.token_id JOIN ca_request_key k USING(key_id)
 WHERE s.command_id=NEW.command_id AND b.binding_id=NEW.binding_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id
 AND f.direction='c2w' AND f.message_type='ENCODE_PACKET' AND f.domain_kind='command_encoding'
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=s.command_id)
 AND t.state='active' AND json_extract(NEW.body_jcs,'$.prepare_id')=NEW.prepare_id
 AND json_extract(NEW.body_jcs,'$.command_id')=s.command_id
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(NEW.body_jcs,'$.binding_ref.id')=b.binding_id AND json_extract(NEW.body_jcs,'$.binding_ref.digest')=b.body_digest
 AND json_extract(NEW.body_jcs,'$.reservation_ref.digest')=z.body_digest
 AND json_extract(NEW.body_jcs,'$.authorization')=json_extract(f.frame_jcs,'$.body.encoding_authorization')
 AND json_extract(f.frame_jcs,'$.body.prepare_id')=NEW.prepare_id AND json_extract(f.frame_jcs,'$.body.command_id')=s.command_id
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.binding')=json_extract(b.body_jcs,'$.binding')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.admission_source_ref.digest')=s.body_digest
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.content_digest')=k.request_digest
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.principal_id')=json_extract(s.body_jcs,'$.metadata.actor.principal_id')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.issuer_id')=json_extract(s.body_jcs,'$.metadata.actor.issuer_id')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.issuer_epoch')=json_extract(s.body_jcs,'$.metadata.actor.issuer_epoch')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.max_bytes')=z.max_bytes
) BEGIN SELECT RAISE(ABORT,'command_encoding_request_binding'); END;

CREATE TRIGGER command_accept_complete BEFORE INSERT ON ca_commit WHEN NEW.kind='accept' AND NOT EXISTS(SELECT 1 FROM command_admission_source WHERE key_id=NEW.key_id AND context_id IS NULL) AND NOT EXISTS(
 SELECT 1 FROM command_admission_source s JOIN ca_command_initial i USING(command_id,key_id)
 JOIN command_revision r USING(command_id) JOIN command_context_charge q USING(command_id)
 JOIN request_context x ON x.context_id=s.context_id AND q.context_id=s.context_id WHERE s.key_id=NEW.key_id AND r.commit_id=NEW.commit_id
 AND q.after_count=x.used_count AND x.state='active'
) BEGIN SELECT RAISE(ABORT,'command_commit_incomplete'); END;

CREATE TRIGGER command_source_no_backfill BEFORE INSERT ON command_admission_source
WHEN EXISTS(SELECT 1 FROM ca_commit c JOIN ca_command_initial i USING(key_id) WHERE i.command_id=NEW.command_id)
BEGIN SELECT RAISE(ABORT,'command_commit_closed'); END;

CREATE TRIGGER ca_namespace_no_update BEFORE UPDATE ON ca_namespace
BEGIN SELECT RAISE(ABORT,'immutable_namespace'); END;
CREATE TRIGGER ca_namespace_no_delete BEFORE DELETE ON ca_namespace
BEGIN SELECT RAISE(ABORT,'immutable_namespace'); END;

CREATE TRIGGER command_admission_source_no_update BEFORE UPDATE ON command_admission_source BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;
CREATE TRIGGER command_admission_source_no_delete BEFORE DELETE ON command_admission_source BEGIN SELECT RAISE(ABORT,'immutable_command_fact'); END;

CREATE TRIGGER ca_automation_namespace_parent BEFORE INSERT ON ca_namespace
WHEN NEW.owner_evidence_id IS NULL AND NOT EXISTS(
 SELECT 1 FROM run_preparation p JOIN run_preparation_grant g USING(preparation_id)
 WHERE p.preparation_id=NEW.request_epoch AND p.request_jcs=CAST(NEW.owner_evidence_body AS TEXT)
 AND json_extract(g.body_jcs,'$.principal.principal_kind')='service' AND json_extract(g.body_jcs,'$.principal.principal_id')=NEW.principal_id
 AND json_extract(g.body_jcs,'$.principal.issuer_id')=NEW.issuer_id AND json_extract(g.body_jcs,'$.principal.issuer_epoch')=NEW.issuer_epoch
) BEGIN SELECT RAISE(ABORT,'namespace_automation_binding'); END;

CREATE TRIGGER command_automation_source_parent BEFORE INSERT ON command_admission_source
WHEN NEW.context_id IS NULL AND NOT EXISTS(
 SELECT 1 FROM automation_command_adjudication a JOIN ca_command_initial c USING(command_id)
 JOIN ca_adjudication decision ON decision.command_id=c.command_id AND decision.key_id=c.key_id
 JOIN ca_request_key k ON k.key_id=NEW.key_id JOIN ca_namespace n USING(namespace_id)
 JOIN device_initial_ready r ON r.ready_id=NEW.ready_id JOIN control_state_source t ON t.source_id=r.control_source_id
 JOIN control_record_head h ON h.device_id=t.device_id AND h.revision=t.revision
 JOIN device_execution_binding b ON b.binding_id=NEW.binding_id JOIN command_revision v ON v.command_id=c.command_id AND v.revision=1
 WHERE a.command_id=NEW.command_id AND a.device_id=NEW.device_id AND a.decision='accepted' AND n.owner_evidence_id IS NULL
 AND n.automation_preparation_id=a.preparation_id AND c.key_id=NEW.key_id AND k.device_id=a.device_id AND k.request_digest=a.request_digest
 AND n.issuer_id=json_extract(a.body_jcs,'$.adjudication.identity.key.issuer_id')
 AND n.issuer_epoch=json_extract(a.body_jcs,'$.adjudication.identity.key.issuer_epoch')
 AND n.principal_id=json_extract(a.body_jcs,'$.adjudication.identity.key.principal_id')
 AND k.idempotency_key=a.idempotency_key AND CAST(k.content_body AS TEXT)=json_extract(a.body_jcs,'$.request')
 AND CAST(c.command_body AS TEXT)=json_extract(a.body_jcs,'$.command')
 AND CAST(decision.adjudication_body AS TEXT)=json_extract(a.body_jcs,'$.adjudication') AND decision.commit_id=v.commit_id
 AND json_extract(a.body_jcs,'$.command.format')='leafseamer.automation-command/2'
 AND json_extract(a.body_jcs,'$.command.execution_basis.ready_ref.id')=r.ready_id
 AND json_extract(a.body_jcs,'$.command.execution_basis.ready_ref.digest')=r.body_digest
 AND json_extract(a.body_jcs,'$.command.execution_basis.binding_ref.id')=b.binding_id
 AND json_extract(a.body_jcs,'$.command.execution_basis.binding_ref.digest')=b.body_digest
 AND b.device_id=NEW.device_id AND t.device_id=NEW.device_id AND json_extract(t.body_jcs,'$.mode')='automatic'
 AND json_type(t.body_jcs,'$.holder')='null' AND json_extract(t.body_jcs,'$.gate_state')='ready'
 AND json_type(t.body_jcs,'$.pending_operation_id')='null'
 AND json_extract(NEW.body_jcs,'$.format')='command-admission-source/2'
 AND json_extract(NEW.body_jcs,'$.command_id')=a.command_id AND json_extract(NEW.body_jcs,'$.metadata.origin')='automation'
 AND json_extract(NEW.body_jcs,'$.initial_ref.digest')=c.command_digest
 AND json_extract(NEW.body_jcs,'$.ready_ref')=json_extract(a.body_jcs,'$.command.execution_basis.ready_ref')
 AND json_extract(NEW.body_jcs,'$.binding_ref')=json_extract(a.body_jcs,'$.command.execution_basis.binding_ref')
 AND json_extract(NEW.body_jcs,'$.binding')=json_extract(b.body_jcs,'$.binding')
 AND json_extract(v.state_jcs,'$.phase')='queued' AND json_extract(v.state_jcs,'$.outcome')='pending'
 AND json_extract(v.state_jcs,'$.effect_status')='not_sent' AND json_extract(v.state_jcs,'$.resource_status')='clear'
 AND json_array_length(v.state_jcs,'$.attempt_ids')=0 AND json_array_length(v.manifest_jcs,'$.members')=0
) BEGIN SELECT RAISE(ABORT,'command_automation_source_parent'); END;

CREATE TRIGGER command_automation_accept_complete BEFORE INSERT ON ca_commit
WHEN NEW.kind='accept' AND EXISTS(SELECT 1 FROM command_admission_source WHERE key_id=NEW.key_id AND context_id IS NULL)
 AND NOT EXISTS(SELECT 1 FROM command_admission_source s JOIN command_revision r USING(command_id)
 JOIN automation_command_adjudication a USING(command_id) WHERE s.key_id=NEW.key_id AND s.context_id IS NULL
 AND r.revision=1 AND r.commit_id=NEW.commit_id AND CAST(NEW.commit_body AS TEXT)=json_extract(a.body_jcs,'$.commit'))
BEGIN SELECT RAISE(ABORT,'command_automation_commit_incomplete'); END;

CREATE TRIGGER command_automation_encoding_parent BEFORE INSERT ON command_encoding_request
WHEN EXISTS(SELECT 1 FROM command_admission_source WHERE command_id=NEW.command_id AND context_id IS NULL) AND NOT EXISTS(
 SELECT 1 FROM command_admission_source s JOIN device_execution_binding b USING(binding_id)
 JOIN command_encoding_reservation z ON z.prepare_id=NEW.prepare_id AND z.command_id=s.command_id
 JOIN execution_frame_record f ON f.record_id=NEW.record_id AND f.transaction_id=NEW.transaction_id
 JOIN device_initial_ready r ON r.ready_id=s.ready_id JOIN control_state_source t ON t.source_id=r.control_source_id
 JOIN control_record_head h ON h.device_id=t.device_id AND h.revision=t.revision
 WHERE s.command_id=NEW.command_id AND b.binding_id=NEW.binding_id AND f.ipc_session_id=b.ipc_session_id AND f.device_id=b.device_id
 AND f.direction='c2w' AND f.message_type='ENCODE_PACKET' AND f.domain_kind='command_encoding'
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head head WHERE head.command_id=s.command_id)
 AND json_extract(NEW.body_jcs,'$.prepare_id')=NEW.prepare_id AND json_extract(NEW.body_jcs,'$.command_id')=s.command_id
 AND json_extract(NEW.body_jcs,'$.request_record_ref.id')=f.record_id AND json_extract(NEW.body_jcs,'$.request_record_ref.digest')=f.record_digest
 AND json_extract(NEW.body_jcs,'$.binding_ref')=json_extract(s.body_jcs,'$.binding_ref') AND json_extract(NEW.body_jcs,'$.reservation_ref.digest')=z.body_digest
 AND json_extract(NEW.body_jcs,'$.authorization')=json_extract(f.frame_jcs,'$.body.encoding_authorization')
 AND json_extract(f.frame_jcs,'$.body.prepare_id')=NEW.prepare_id AND json_extract(f.frame_jcs,'$.body.command_id')=s.command_id
 AND json_extract(f.frame_jcs,'$.body.request')=json_extract(s.body_jcs,'$.execution_request')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.binding')=json_extract(s.body_jcs,'$.binding')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.admission_source_ref.digest')=s.body_digest
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.content_digest')=json_extract(s.body_jcs,'$.execution_content_digest')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.kind')='service'
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.principal_id')=json_extract(s.body_jcs,'$.metadata.actor.principal_id')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.issuer_id')=json_extract(s.body_jcs,'$.metadata.actor.issuer_id')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.requester.issuer_epoch')=json_extract(s.body_jcs,'$.metadata.actor.issuer_epoch')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.expires_tick_ns')=json_extract(s.body_jcs,'$.deadline.queue_deadline_tick_ns')
 AND json_extract(f.frame_jcs,'$.body.encoding_authorization.max_bytes')=z.max_bytes
) BEGIN SELECT RAISE(ABORT,'command_automation_encoding_binding'); END;
