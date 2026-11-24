DROP TRIGGER obs_local_resource_parent;
DROP TRIGGER extension_owner_binding;
DROP TRIGGER device_authorization_state_parent;
DROP TRIGGER ca_namespace_parent;
DROP TRIGGER request_context_parent;
DROP TRIGGER service_state_no_update;
DROP TRIGGER service_state_no_delete;


CREATE TABLE service_state_v105 (
  singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
  authority TEXT NOT NULL CHECK(authority = 'controller'),
  service_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  database_instance_id TEXT NOT NULL COLLATE BINARY UNIQUE,
  control_epoch TEXT NOT NULL COLLATE BINARY,
  request_epoch TEXT NOT NULL COLLATE BINARY,
  schema_revision TEXT NOT NULL CHECK(schema_revision = '105'),
  maintenance_state TEXT NOT NULL CHECK(maintenance_state = 'protected'),
  state_revision TEXT NOT NULL CHECK(state_revision = '0'),
  UNIQUE(service_id, database_instance_id)
) STRICT;
INSERT INTO service_state_v105 SELECT singleton, authority, service_id, database_instance_id,
  control_epoch, request_epoch, '105', maintenance_state, state_revision FROM service_state;
DROP TABLE service_state;
ALTER TABLE service_state_v105 RENAME TO service_state;
CREATE TRIGGER service_state_no_update BEFORE UPDATE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;
CREATE TRIGGER service_state_no_delete BEFORE DELETE ON service_state
BEGIN SELECT RAISE(ABORT, 'immutable_service_identity'); END;

DROP TRIGGER schema_migration_no_update;
DROP TRIGGER schema_migration_no_delete;
CREATE TABLE schema_migration_v105 (
  migration_id TEXT PRIMARY KEY NOT NULL COLLATE BINARY,
  from_revision TEXT NOT NULL CHECK(from_revision = CAST(CAST(from_revision AS INTEGER) AS TEXT)),
  to_revision TEXT NOT NULL UNIQUE CHECK(to_revision = CAST(CAST(to_revision AS INTEGER) AS TEXT)),
  script_digest TEXT NOT NULL COLLATE BINARY,
  backup_ref TEXT,
  state TEXT NOT NULL CHECK(state = 'committed'),
  tx_id TEXT NOT NULL UNIQUE COLLATE BINARY,
  CHECK(CAST(to_revision AS INTEGER) BETWEEN 1 AND 105),
  CHECK(CAST(from_revision AS INTEGER) = CAST(to_revision AS INTEGER) - 1),
  CHECK((to_revision = '1') = (backup_ref IS NULL))
) STRICT;
INSERT INTO schema_migration_v105 SELECT * FROM schema_migration;
DROP TABLE schema_migration;
ALTER TABLE schema_migration_v105 RENAME TO schema_migration;
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

-- 已封存的发送许可只有在同会话持久终止且无实际出站预约时才能按未发送释放。
CREATE TABLE command_unsent_closure (
 command_id TEXT PRIMARY KEY NOT NULL REFERENCES command_admission_source(command_id),
 hold_id TEXT NOT NULL UNIQUE REFERENCES command_device_hold(hold_id),
 permit_id TEXT NOT NULL UNIQUE REFERENCES command_final_admission(permit_id),
 ipc_session_id TEXT NOT NULL,
 end_transaction_id TEXT NOT NULL,
 end_reason TEXT NOT NULL,
 commit_id TEXT NOT NULL UNIQUE REFERENCES command_lifecycle_commit(commit_id) DEFERRABLE INITIALLY DEFERRED,
 body_jcs TEXT NOT NULL CHECK(json_valid(body_jcs)),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=71),
 FOREIGN KEY(ipc_session_id,end_transaction_id,end_reason) REFERENCES execution_session_end(ipc_session_id,transaction_id,reason)
) STRICT;

CREATE TRIGGER command_unsent_closure_parent BEFORE INSERT ON command_unsent_closure WHEN NOT EXISTS(
 SELECT 1 FROM command_final_admission f JOIN device_execution_binding b USING(binding_id)
 JOIN execution_session_end e ON e.ipc_session_id=b.ipc_session_id
 JOIN command_device_hold t ON t.hold_id=f.hold_id AND t.command_id=f.command_id
 JOIN command_lifecycle_head h ON h.command_id=f.command_id AND h.revision=2 AND h.commit_id=f.commit_id
 JOIN command_lifecycle_revision p ON p.command_id=h.command_id AND p.revision=2 AND p.commit_id=h.commit_id
 JOIN command_lifecycle_revision n ON n.command_id=h.command_id AND n.revision=3 AND n.commit_id=NEW.commit_id
 LEFT JOIN command_dispatch_request d ON d.permit_id=f.permit_id
 WHERE f.command_id=NEW.command_id AND f.permit_id=NEW.permit_id AND t.hold_id=NEW.hold_id
 AND e.ipc_session_id=NEW.ipc_session_id AND e.transaction_id=NEW.end_transaction_id AND e.reason=NEW.end_reason
 AND NOT EXISTS(SELECT 1 FROM command_dispatch_write w WHERE w.permit_id=f.permit_id)
 AND NOT EXISTS(SELECT 1 FROM execution_write_attempt w JOIN execution_frame_record x USING(record_id)
  WHERE x.direction='c2w' AND x.message_type='DISPATCH' AND
  (json_extract(x.frame_jcs,'$.body.permit.command_id')=f.command_id OR json_extract(x.frame_jcs,'$.body.permit.permit_id')=f.permit_id))
 AND NOT EXISTS(SELECT 1 FROM command_hold_release r WHERE r.hold_id=t.hold_id)
 AND json_extract(p.state_jcs,'$.phase')='queued' AND json_extract(p.state_jcs,'$.outcome')='pending'
 AND json_extract(p.state_jcs,'$.resource_status')='held' AND json_extract(p.state_jcs,'$.effect_status')='not_sent'
 AND json_extract(NEW.body_jcs,'$.format')='command-unsent-closure/1'
 AND json_extract(NEW.body_jcs,'$.command_id')=f.command_id AND json_extract(NEW.body_jcs,'$.commit_id')=NEW.commit_id
 AND json_extract(NEW.body_jcs,'$.revision')='3'
 AND json_extract(NEW.body_jcs,'$.cut.permit_id')=f.permit_id AND json_extract(NEW.body_jcs,'$.cut.binding.ipc_session_id')=e.ipc_session_id
 AND json_extract(NEW.body_jcs,'$.cut.end.transaction_id')=e.transaction_id AND json_extract(NEW.body_jcs,'$.cut.end.reason')=e.reason
 AND json_extract(NEW.body_jcs,'$.cut.final_admission_ref.id')=f.transaction_id AND json_extract(NEW.body_jcs,'$.cut.final_admission_ref.digest')=f.body_digest
 AND json_extract(NEW.body_jcs,'$.cut.dispatch_ref.digest') IS d.body_digest
 AND json_extract(NEW.body_jcs,'$.previous_state_ref.digest')=p.state_digest
 AND json_extract(NEW.body_jcs,'$.record_digest')=n.record_digest AND json_extract(NEW.body_jcs,'$.state_digest')=n.state_digest
 AND json_extract(n.record_jcs,'$.state')=json(n.state_jcs)
 AND json_extract(n.state_jcs,'$.attempt_ids')=json_extract(p.state_jcs,'$.attempt_ids')
 AND json_extract(n.record_jcs,'$.attempts[0].attempt_id')=f.attempt_id
 AND json_extract(n.record_jcs,'$.attempts[0].outcome')='not_sent'
 AND json_extract(n.state_jcs,'$.phase')='finished' AND json_extract(n.state_jcs,'$.outcome')='blocked'
 AND json_extract(n.state_jcs,'$.revision')='3' AND json_extract(n.state_jcs,'$.terminal_revision')='3'
 AND json_extract(n.state_jcs,'$.effect_status')='not_sent' AND json_extract(n.state_jcs,'$.resource_status')='clear'
 AND json_extract(n.state_jcs,'$.automation_continuation')='paused_latched' AND json_extract(n.state_jcs,'$.reason_code')='execution_closed'
 AND json_array_length(NEW.body_jcs,'$.evidence')=1 AND json_array_length(n.manifest_jcs,'$.members')=1
 AND json_extract(NEW.body_jcs,'$.evidence[0].kind')='release' AND json_extract(NEW.body_jcs,'$.evidence[0].body.kind')='never_sent'
 AND json_extract(NEW.body_jcs,'$.evidence[0].body.hold_id')=t.hold_id
 AND json_extract(n.state_jcs,'$.resource_evidence_refs[0]')=json_extract(NEW.body_jcs,'$.evidence[0].source_ref')
 AND json_extract(n.manifest_jcs,'$.members[0].source_ref')=json_extract(NEW.body_jcs,'$.evidence[0].source_ref')
) BEGIN SELECT RAISE(ABORT,'command_unsent_closure_parent'); END;
CREATE TRIGGER command_unsent_closure_no_update BEFORE UPDATE ON command_unsent_closure
BEGIN SELECT RAISE(ABORT,'immutable_command_unsent_closure'); END;
CREATE TRIGGER command_unsent_closure_no_delete BEFORE DELETE ON command_unsent_closure
BEGIN SELECT RAISE(ABORT,'immutable_command_unsent_closure'); END;

CREATE VIEW command_hold_clearance AS
 SELECT hold_id,command_id,commit_id FROM command_hold_release
 UNION ALL
 SELECT hold_id,command_id,commit_id FROM command_unsent_closure;
DROP TRIGGER command_device_hold_exclusive;
CREATE TRIGGER command_device_hold_exclusive BEFORE INSERT ON command_device_hold WHEN EXISTS(
 SELECT 1 FROM command_device_hold h WHERE h.device_id=NEW.device_id
 AND NOT EXISTS(SELECT 1 FROM command_hold_clearance r WHERE r.hold_id=h.hold_id)
) BEGIN SELECT RAISE(ABORT,'command_resource_busy'); END;

DROP TRIGGER command_lifecycle_parent;
DROP TRIGGER command_settlement_commit;
CREATE TRIGGER command_lifecycle_parent BEFORE INSERT ON command_lifecycle_commit WHEN NEW.revision<>5 AND NOT EXISTS(
 SELECT 1 FROM command_unsent_closure u WHERE u.command_id=NEW.command_id AND u.commit_id=NEW.commit_id
 AND NEW.revision=3 AND NEW.body_jcs=u.body_jcs AND NEW.body_digest=u.body_digest
) AND NOT EXISTS(
 SELECT 1 FROM command_dispatch_interruption i WHERE i.commit_id=NEW.commit_id AND i.command_id=NEW.command_id
 AND NEW.revision=i.previous_revision+1 AND NEW.body_jcs=i.body_jcs AND NEW.body_digest=i.body_digest
) AND NOT (EXISTS(
 SELECT 1 FROM command_revision i JOIN command_lifecycle_revision r USING(command_id)
 JOIN command_admission_source s USING(command_id)
 WHERE r.commit_id=NEW.commit_id AND r.command_id=NEW.command_id AND r.revision=NEW.revision AND NEW.revision=2
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head h WHERE h.command_id=NEW.command_id)
 AND json_extract(i.state_jcs,'$.phase')='queued' AND json_array_length(i.state_jcs,'$.attempt_ids')=0
 AND json_extract(NEW.body_jcs,'$.format')='command-queued-closure/1'
 AND json_extract(NEW.body_jcs,'$.command_id')=NEW.command_id
 AND json_extract(NEW.body_jcs,'$.previous_state_ref.digest')=i.state_digest
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest
 AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs)
 AND json_extract(r.state_jcs,'$.revision')='2' AND json_extract(r.state_jcs,'$.terminal_revision')='2'
 AND json_extract(r.state_jcs,'$.phase')='finished' AND json_extract(r.state_jcs,'$.outcome') IN ('blocked','expired')
 AND json_extract(r.state_jcs,'$.effect_status')='not_sent' AND json_extract(r.state_jcs,'$.resource_status')='clear'
 AND json_extract(r.state_jcs,'$.automation_continuation')='paused_latched'
 AND json_array_length(r.state_jcs,'$.attempt_ids')=0 AND json_array_length(r.manifest_jcs,'$.members')=0
 AND NOT EXISTS(SELECT 1 FROM command_final_admission f WHERE f.command_id=NEW.command_id)
) OR EXISTS(SELECT 1 FROM command_final_admission f JOIN command_lifecycle_revision r ON r.command_id=f.command_id AND r.commit_id=f.commit_id
 JOIN command_attempt_inventory a ON a.transaction_id=f.transaction_id AND a.command_id=f.command_id
 JOIN command_device_hold h ON h.transaction_id=f.transaction_id AND h.hold_id=f.hold_id
 JOIN command_transmission_issue i ON i.transaction_id=f.transaction_id AND i.permit_id=f.permit_id
 WHERE f.commit_id=NEW.commit_id AND f.command_id=NEW.command_id AND r.revision=2 AND NEW.revision=2
 AND NOT EXISTS(SELECT 1 FROM command_lifecycle_head x WHERE x.command_id=NEW.command_id)
 AND json_extract(NEW.body_jcs,'$.format')='command-final-admission-commit/1'
 AND json_extract(NEW.body_jcs,'$.transaction_ref.digest')=f.body_digest
 AND json_extract(NEW.body_jcs,'$.transaction_ref.id')=f.transaction_id
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs)
 AND json_extract(r.state_jcs,'$.revision')='2' AND json_extract(r.state_jcs,'$.terminal_revision') IS NULL
 AND json_extract(r.state_jcs,'$.phase')='queued' AND json_extract(r.state_jcs,'$.outcome')='pending'
 AND json_extract(r.state_jcs,'$.resource_status')='held' AND json_extract(r.state_jcs,'$.effect_status')='not_sent'
 AND json_array_length(r.state_jcs,'$.attempt_ids')=1 AND json_extract(r.state_jcs,'$.attempt_ids[0]')=f.attempt_id
 AND json_array_length(r.record_jcs,'$.attempts')=1 AND json_extract(r.record_jcs,'$.attempts[0].attempt_id')=f.attempt_id
 AND json_array_length(r.manifest_jcs,'$.members')=0 AND (SELECT count(*) FROM json_each(f.body_jcs,'$.projections'))=18
) OR EXISTS(SELECT 1 FROM command_final_admission f JOIN command_dispatch_request d ON d.final_transaction_id=f.transaction_id
 JOIN command_dispatch_write w ON w.permit_id=d.permit_id LEFT JOIN command_dispatch_report t ON t.permit_id=d.permit_id
 JOIN command_lifecycle_head h ON h.command_id=f.command_id AND h.revision=NEW.revision AND h.commit_id=NEW.commit_id
 JOIN command_lifecycle_revision r ON r.command_id=h.command_id AND r.revision=h.revision AND r.commit_id=h.commit_id
 JOIN command_lifecycle_revision p ON p.command_id=h.command_id AND p.revision=h.revision-1
 WHERE f.command_id=NEW.command_id AND ((NEW.revision=3 AND w.commit_id=NEW.commit_id) OR (NEW.revision=4 AND t.commit_id=NEW.commit_id))
 AND json_extract(NEW.body_jcs,'$.format')='command-dispatch-state/1'
 AND json_extract(NEW.body_jcs,'$.dispatch_ref.id')=d.permit_id AND json_extract(NEW.body_jcs,'$.dispatch_ref.digest')=d.body_digest
 AND json_extract(NEW.body_jcs,'$.previous_state_ref.digest')=p.state_digest
 AND json_extract(NEW.body_jcs,'$.record_digest')=r.record_digest AND json_extract(NEW.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs) AND json_extract(r.state_jcs,'$.revision')=CAST(NEW.revision AS TEXT)
 AND json_extract(r.state_jcs,'$.phase')=CASE NEW.revision WHEN 3 THEN 'dispatching' ELSE 'awaiting_evidence' END
 AND json_extract(r.state_jcs,'$.outcome')='pending' AND json_extract(r.state_jcs,'$.effect_status')='possible'
 AND json_extract(r.state_jcs,'$.resource_status')='held' AND json_extract(r.state_jcs,'$.terminal_revision') IS NULL
 AND json_array_length(r.state_jcs,'$.attempt_ids')=1 AND json_extract(r.state_jcs,'$.attempt_ids[0]')=f.attempt_id
 AND json_array_length(r.record_jcs,'$.attempts')=1 AND json_extract(r.record_jcs,'$.attempts[0].attempt_id')=f.attempt_id
 AND json_array_length(r.manifest_jcs,'$.members')=0)
) BEGIN SELECT RAISE(ABORT,'command_lifecycle_parent'); END;


CREATE TRIGGER command_settlement_commit BEFORE INSERT ON command_lifecycle_commit WHEN NEW.revision=5 AND NOT EXISTS(
 SELECT 1 FROM command_dispatch_interruption i WHERE i.commit_id=NEW.commit_id AND i.command_id=NEW.command_id
 AND i.previous_revision=4 AND NEW.body_jcs=i.body_jcs AND NEW.body_digest=i.body_digest
) AND NOT EXISTS(
 SELECT 1 FROM command_settlement s JOIN command_lifecycle_revision r USING(command_id,commit_id)
 JOIN command_lifecycle_head h USING(command_id,revision,commit_id)
 WHERE s.command_id=NEW.command_id AND s.commit_id=NEW.commit_id AND r.revision=5
 AND NEW.body_jcs=s.body_jcs AND NEW.body_digest=s.body_digest
 AND json_extract(s.body_jcs,'$.record_digest')=r.record_digest AND json_extract(s.body_jcs,'$.state_digest')=r.state_digest
 AND json_extract(r.record_jcs,'$.state')=json(r.state_jcs) AND json_extract(r.state_jcs,'$.phase')='finished'
 AND json_extract(r.state_jcs,'$.terminal_revision')='5' AND json_extract(r.state_jcs,'$.revision')='5'
 AND ((json_extract(r.state_jcs,'$.outcome')='succeeded' AND json_extract(r.state_jcs,'$.resource_status')='clear'
       AND json_extract(r.state_jcs,'$.effect_status')='verified' AND EXISTS(SELECT 1 FROM command_hold_release x WHERE x.command_id=s.command_id AND x.commit_id=s.commit_id))
   OR (json_extract(r.state_jcs,'$.outcome')='unknown' AND json_extract(r.state_jcs,'$.resource_status')='unresolved'
       AND json_extract(r.state_jcs,'$.effect_status')='possible' AND json_extract(r.state_jcs,'$.automation_continuation')='paused_latched'
       AND NOT EXISTS(SELECT 1 FROM command_hold_release x WHERE x.command_id=s.command_id)))
 AND (SELECT count(*) FROM command_evidence_record e WHERE e.command_id=s.command_id AND e.commit_id=s.commit_id)=json_array_length(s.body_jcs,'$.evidence')
 AND json_array_length(r.manifest_jcs,'$.members')=json_array_length(s.body_jcs,'$.evidence')
) BEGIN SELECT RAISE(ABORT,'command_settlement_commit'); END;
DROP TRIGGER command_lifecycle_terminal;
CREATE TRIGGER command_lifecycle_terminal BEFORE UPDATE ON command_lifecycle_head WHEN NOT EXISTS(
 SELECT 1 FROM command_lifecycle_revision p JOIN command_lifecycle_commit c ON c.commit_id=p.commit_id
 JOIN command_lifecycle_revision n ON n.command_id=p.command_id AND n.revision=p.revision+1
 WHERE p.command_id=OLD.command_id AND p.revision=OLD.revision AND p.commit_id=OLD.commit_id
 AND NEW.command_id=OLD.command_id AND NEW.revision=n.revision AND NEW.commit_id=n.commit_id
 AND json_extract(p.state_jcs,'$.outcome')='pending'
 AND (((OLD.revision=2 AND json_extract(p.state_jcs,'$.phase')='queued' AND NEW.revision=3 AND json_extract(n.state_jcs,'$.phase')='dispatching')
 OR (OLD.revision=3 AND json_extract(p.state_jcs,'$.phase')='dispatching' AND NEW.revision=4 AND json_extract(n.state_jcs,'$.phase')='awaiting_evidence'))
 AND json_extract(n.state_jcs,'$.outcome')='pending'
 OR (OLD.revision=4 AND NEW.revision=5 AND json_extract(p.state_jcs,'$.phase')='awaiting_evidence' AND json_extract(n.state_jcs,'$.phase')='finished'
 AND EXISTS(SELECT 1 FROM command_settlement s WHERE s.command_id=n.command_id AND s.commit_id=n.commit_id))
 OR (NEW.revision IN(4,5) AND EXISTS(SELECT 1 FROM command_dispatch_interruption i
  WHERE i.command_id=n.command_id AND i.commit_id=n.commit_id AND i.previous_revision=OLD.revision))
 OR (OLD.revision=2 AND NEW.revision=3 AND EXISTS(SELECT 1 FROM command_unsent_closure u
  WHERE u.command_id=n.command_id AND u.commit_id=n.commit_id)))
) BEGIN SELECT RAISE(ABORT,'command_terminal'); END;
