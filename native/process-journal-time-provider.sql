CREATE TABLE time_provider_attempt(
 launch_id TEXT PRIMARY KEY NOT NULL,
 core_attempt_id TEXT NOT NULL UNIQUE REFERENCES core_admission(attempt_id),
 job_name TEXT NOT NULL UNIQUE,
 policy_jcs TEXT NOT NULL CHECK(json_extract(policy_jcs,'$.format') IS 'leafseamer-time-provider-bootstrap-policy/1'),
 intent_jcs TEXT NOT NULL CHECK(json_extract(intent_jcs,'$.role') IS 'time_provider'
   AND json_extract(intent_jcs,'$.launch_id') IS launch_id AND json_type(intent_jcs,'$.device_ids') IS 'array'
   AND json_array_length(intent_jcs,'$.device_ids')=0)
) STRICT;
CREATE TABLE time_provider_observation(
 launch_id TEXT PRIMARY KEY NOT NULL REFERENCES time_provider_attempt(launch_id),
 provider_pid INTEGER NOT NULL CHECK(provider_pid>0),
 creation_time TEXT NOT NULL,
 image_id TEXT NOT NULL,
 observed_tick_ns TEXT NOT NULL
) STRICT;
CREATE TABLE time_provider_admission(
 launch_id TEXT PRIMARY KEY NOT NULL REFERENCES time_provider_observation(launch_id),
 receipt_id TEXT NOT NULL UNIQUE,
 receipt_jcs TEXT NOT NULL CHECK(json_extract(receipt_jcs,'$.role') IS 'time_provider'
   AND json_extract(receipt_jcs,'$.launch_id') IS launch_id AND json_extract(receipt_jcs,'$.receipt_id') IS receipt_id
   AND json_extract(receipt_jcs,'$.gate_state') IS 'closed')
) STRICT;
CREATE TABLE time_provider_exit(
 launch_id TEXT PRIMARY KEY NOT NULL REFERENCES time_provider_observation(launch_id),
 exit_code INTEGER NOT NULL CHECK(exit_code>=0),
 active_processes INTEGER NOT NULL CHECK(active_processes=0),
 forced INTEGER NOT NULL CHECK(forced IN(0,1))
) STRICT;
CREATE TRIGGER time_provider_attempt_no_update BEFORE UPDATE ON time_provider_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_attempt_no_delete BEFORE DELETE ON time_provider_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_observation_no_update BEFORE UPDATE ON time_provider_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_observation_no_delete BEFORE DELETE ON time_provider_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_admission_no_update BEFORE UPDATE ON time_provider_admission BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_admission_no_delete BEFORE DELETE ON time_provider_admission BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_exit_no_update BEFORE UPDATE ON time_provider_exit BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER time_provider_exit_no_delete BEFORE DELETE ON time_provider_exit BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER core_exit_time_provider_empty BEFORE INSERT ON core_exit WHEN EXISTS(
 SELECT 1 FROM time_provider_attempt a LEFT JOIN time_provider_exit e USING(launch_id)
 WHERE a.core_attempt_id=NEW.attempt_id AND e.launch_id IS NULL
) BEGIN SELECT RAISE(ABORT,'time_provider_exit_unproven'); END;
PRAGMA user_version=6;
