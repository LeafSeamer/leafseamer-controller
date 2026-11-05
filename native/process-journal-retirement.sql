CREATE TABLE worker_group(
 attempt_id TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 object_name TEXT NOT NULL UNIQUE,
 reservation_jcs TEXT NOT NULL CHECK(length(reservation_jcs)<=8192),
 PRIMARY KEY(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_launch(attempt_id,launch_id)
) STRICT;
CREATE UNIQUE INDEX worker_state_retirement_key ON worker_state(attempt_id,launch_id,retirement_evidence);
CREATE TABLE worker_retirement(
 attempt_id TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 evidence_id TEXT NOT NULL UNIQUE,
 observation_id TEXT NOT NULL UNIQUE,
 request_jcs TEXT NOT NULL CHECK(length(request_jcs)<=8192),
 observation_jcs TEXT NOT NULL CHECK(length(observation_jcs)<=8192),
 evidence_jcs TEXT NOT NULL CHECK(length(evidence_jcs)<=8192),
 PRIMARY KEY(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_group(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id,evidence_jcs) REFERENCES worker_state(attempt_id,launch_id,retirement_evidence) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TRIGGER worker_group_initial BEFORE INSERT ON worker_group WHEN NOT EXISTS(
 SELECT 1 FROM worker_state WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND state='registered' AND creation_attempted=0
) BEGIN SELECT RAISE(ABORT,'worker_group_state'); END;
CREATE TRIGGER worker_group_no_update BEFORE UPDATE ON worker_group BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_group_no_delete BEFORE DELETE ON worker_group BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_retirement_initial BEFORE INSERT ON worker_retirement WHEN NOT EXISTS(
 SELECT 1 FROM worker_state WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND state='retiring'
) BEGIN SELECT RAISE(ABORT,'worker_retirement_state'); END;
CREATE TRIGGER worker_retirement_no_update BEFORE UPDATE ON worker_retirement BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_retirement_no_delete BEFORE DELETE ON worker_retirement BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_retired_evidence BEFORE UPDATE ON worker_state WHEN NEW.state='retired' AND NOT EXISTS(
 SELECT 1 FROM worker_retirement WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND evidence_jcs=NEW.retirement_evidence
) BEGIN SELECT RAISE(ABORT,'worker_retirement_evidence'); END;
PRAGMA user_version=4;
