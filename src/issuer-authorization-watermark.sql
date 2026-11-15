DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;
CREATE TABLE service_state_v61 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '61'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v61 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '61', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v61 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v61 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision IN ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60')),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision IN ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61')),
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
    OR (from_revision = '60' AND to_revision = '61' AND backup_ref IS NOT NULL))
) STRICT;
INSERT INTO schema_migration_v61 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v61 RENAME TO schema_migration;
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

CREATE TABLE issuer_authorization_watermark (
 singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
 issuer_id TEXT NOT NULL, issuer_epoch TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0 AND revision<=9223372036854775807),
 FOREIGN KEY(issuer_id,issuer_epoch) REFERENCES identity_issuer(issuer_id,issuer_epoch)
) STRICT;
INSERT INTO issuer_authorization_watermark SELECT 1,issuer_id,issuer_epoch,1 FROM identity_issuer;
CREATE TRIGGER issuer_watermark_initialize AFTER INSERT ON identity_issuer
BEGIN INSERT INTO issuer_authorization_watermark VALUES(1,NEW.issuer_id,NEW.issuer_epoch,1); END;
CREATE TRIGGER issuer_watermark_forward BEFORE UPDATE ON issuer_authorization_watermark
WHEN NEW.singleton!=OLD.singleton OR NEW.issuer_id!=OLD.issuer_id OR NEW.issuer_epoch!=OLD.issuer_epoch OR NEW.revision!=OLD.revision+1
BEGIN SELECT RAISE(ABORT,'issuer_revision_order'); END;
CREATE TRIGGER issuer_watermark_no_delete BEFORE DELETE ON issuer_authorization_watermark
BEGIN SELECT RAISE(ABORT,'immutable_issuer_revision'); END;
CREATE TRIGGER issuer_watermark_subject_insert AFTER INSERT ON subject
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_subject_update AFTER UPDATE ON subject
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_subject_delete AFTER DELETE ON subject
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_principal_insert AFTER INSERT ON local_principal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_principal_update AFTER UPDATE ON local_principal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_principal_delete AFTER DELETE ON local_principal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_auth_session_insert AFTER INSERT ON auth_session
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_auth_session_update AFTER UPDATE ON auth_session
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_auth_session_delete AFTER DELETE ON auth_session
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_refresh_credential_insert AFTER INSERT ON session_refresh_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_refresh_credential_update AFTER UPDATE ON session_refresh_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_refresh_credential_delete AFTER DELETE ON session_refresh_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_access_token_insert AFTER INSERT ON access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_access_token_update AFTER UPDATE ON access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_access_token_delete AFTER DELETE ON access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_permission_revision_insert AFTER INSERT ON local_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_permission_revision_update AFTER UPDATE ON local_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_local_permission_revision_delete AFTER DELETE ON local_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_remote_permission_revision_insert AFTER INSERT ON remote_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_remote_permission_revision_update AFTER UPDATE ON remote_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_remote_permission_revision_delete AFTER DELETE ON remote_permission_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_peer_pairing_revision_insert AFTER INSERT ON peer_pairing_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_peer_pairing_revision_update AFTER UPDATE ON peer_pairing_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_peer_pairing_revision_delete AFTER DELETE ON peer_pairing_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_revocation_floor_insert AFTER INSERT ON session_revocation_floor
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_revocation_floor_update AFTER UPDATE ON session_revocation_floor
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_session_revocation_floor_delete AFTER DELETE ON session_revocation_floor
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_revision_insert AFTER INSERT ON service_principal_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_revision_update AFTER UPDATE ON service_principal_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_revision_delete AFTER DELETE ON service_principal_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_head_insert AFTER INSERT ON service_principal_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_head_update AFTER UPDATE ON service_principal_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_principal_head_delete AFTER DELETE ON service_principal_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_approval_insert AFTER INSERT ON service_approval
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_approval_update AFTER UPDATE ON service_approval
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_approval_delete AFTER DELETE ON service_approval
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_insert AFTER INSERT ON service_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_update AFTER UPDATE ON service_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_delete AFTER DELETE ON service_credential
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_revision_insert AFTER INSERT ON service_credential_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_revision_update AFTER UPDATE ON service_credential_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_revision_delete AFTER DELETE ON service_credential_revision
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_head_insert AFTER INSERT ON service_credential_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_head_update AFTER UPDATE ON service_credential_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_credential_head_delete AFTER DELETE ON service_credential_head
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_insert AFTER INSERT ON service_receiver_policy
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_update AFTER UPDATE ON service_receiver_policy
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_delete AFTER DELETE ON service_receiver_policy
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_revocation_insert AFTER INSERT ON service_receiver_policy_revocation
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_revocation_update AFTER UPDATE ON service_receiver_policy_revocation
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_receiver_policy_revocation_delete AFTER DELETE ON service_receiver_policy_revocation
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_insert AFTER INSERT ON service_access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_update AFTER UPDATE ON service_access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_delete AFTER DELETE ON service_access_token
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_terminal_insert AFTER INSERT ON service_access_token_terminal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_terminal_update AFTER UPDATE ON service_access_token_terminal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
CREATE TRIGGER issuer_watermark_service_access_token_terminal_delete AFTER DELETE ON service_access_token_terminal
BEGIN UPDATE issuer_authorization_watermark SET revision=revision+1 WHERE singleton=1; END;
