CREATE TABLE worker_creation(
 attempt_id TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 creation_id TEXT NOT NULL UNIQUE,
 record_jcs TEXT NOT NULL CHECK(length(record_jcs)<=65536),
 PRIMARY KEY(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_launch(attempt_id,launch_id)
) STRICT;
CREATE TABLE worker_observation(
 attempt_id TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 observation_id TEXT NOT NULL UNIQUE,
 record_jcs TEXT NOT NULL CHECK(length(record_jcs)<=65536),
 PRIMARY KEY(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_creation(attempt_id,launch_id)
) STRICT;
CREATE TRIGGER worker_creation_initial BEFORE INSERT ON worker_creation WHEN NOT EXISTS(
 SELECT 1 FROM worker_state WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND state='registered' AND creation_attempted=0
) BEGIN SELECT RAISE(ABORT,'worker_creation_state'); END;
CREATE TRIGGER worker_creation_no_update BEFORE UPDATE ON worker_creation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_creation_no_delete BEFORE DELETE ON worker_creation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_observation_initial BEFORE INSERT ON worker_observation WHEN NOT EXISTS(
 SELECT 1 FROM worker_state WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND state='creating' AND creation_attempted=1
) BEGIN SELECT RAISE(ABORT,'worker_observation_state'); END;
CREATE TRIGGER worker_observation_no_update BEFORE UPDATE ON worker_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_observation_no_delete BEFORE DELETE ON worker_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_creating_evidence BEFORE UPDATE ON worker_state WHEN NEW.state='creating' AND NOT EXISTS(
 SELECT 1 FROM worker_creation WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id
) BEGIN SELECT RAISE(ABORT,'worker_creation_evidence'); END;
CREATE TRIGGER worker_observed_evidence BEFORE UPDATE ON worker_state WHEN NEW.state IN('awaiting_bootstrap','admitted_closed') AND NOT EXISTS(
 SELECT 1 FROM worker_observation WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id
) BEGIN SELECT RAISE(ABORT,'worker_observation_evidence'); END;
PRAGMA user_version=5;
