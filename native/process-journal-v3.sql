PRAGMA application_id=1280528456;
PRAGMA user_version=1;
CREATE TABLE host_meta(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 format TEXT NOT NULL CHECK(format='leafseamer-process-journal/1'),
 incarnation TEXT NOT NULL UNIQUE CHECK(length(incarnation)=32),
 directory_id TEXT NOT NULL,
 owner_sid TEXT NOT NULL
) STRICT;
CREATE TABLE core_attempt(
 attempt_id TEXT PRIMARY KEY NOT NULL CHECK(length(attempt_id)=32),
 job_name TEXT NOT NULL UNIQUE,
 supervisor_pid INTEGER NOT NULL CHECK(supervisor_pid>0)
) STRICT;
CREATE TABLE core_observation(
 attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES core_attempt(attempt_id),
 core_pid INTEGER NOT NULL CHECK(core_pid>0),
 creation_filetime TEXT NOT NULL,
 image_file_id TEXT NOT NULL
) STRICT;
CREATE TABLE core_exit(
 attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES core_observation(attempt_id),
 exit_code INTEGER NOT NULL CHECK(exit_code BETWEEN 0 AND 4294967295),
 active_processes INTEGER NOT NULL CHECK(active_processes=0),
 forced INTEGER NOT NULL CHECK(forced IN(0,1))
) STRICT;
CREATE TRIGGER attempt_pending BEFORE INSERT ON core_attempt WHEN EXISTS(
 SELECT 1 FROM core_attempt a LEFT JOIN core_exit e USING(attempt_id) WHERE e.attempt_id IS NULL
) BEGIN SELECT RAISE(ABORT,'previous_attempt_unresolved'); END;
CREATE TRIGGER attempt_capacity BEFORE INSERT ON core_attempt WHEN (SELECT count(*) FROM core_attempt)>=4096
BEGIN SELECT RAISE(ABORT,'process_journal_capacity'); END;
CREATE TRIGGER meta_no_insert BEFORE INSERT ON host_meta WHEN EXISTS(SELECT 1 FROM host_meta)
BEGIN SELECT RAISE(ABORT,'host_meta_exists'); END;
CREATE TRIGGER meta_no_update BEFORE UPDATE ON host_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER meta_no_delete BEFORE DELETE ON host_meta BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER attempt_no_update BEFORE UPDATE ON core_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER attempt_no_delete BEFORE DELETE ON core_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER observation_no_update BEFORE UPDATE ON core_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER observation_no_delete BEFORE DELETE ON core_observation BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER exit_no_update BEFORE UPDATE ON core_exit BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER exit_no_delete BEFORE DELETE ON core_exit BEGIN SELECT RAISE(ABORT,'immutable'); END;

CREATE TABLE core_bootstrap(
 attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES core_attempt(attempt_id),
 policy_jcs TEXT NOT NULL CHECK(length(policy_jcs)<=8192),
 descriptor_jcs TEXT NOT NULL CHECK(length(descriptor_jcs)<=8192),
 intent_jcs TEXT NOT NULL CHECK(length(intent_jcs)<=8192)
) STRICT;
CREATE TABLE core_admission(
 attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES core_bootstrap(attempt_id),
 receipt_id TEXT NOT NULL UNIQUE,
 receipt_jcs TEXT NOT NULL CHECK(length(receipt_jcs)<=8192),
 FOREIGN KEY(attempt_id) REFERENCES core_observation(attempt_id)
) STRICT;
CREATE TRIGGER bootstrap_no_update BEFORE UPDATE ON core_bootstrap BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER bootstrap_no_delete BEFORE DELETE ON core_bootstrap BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER admission_no_update BEFORE UPDATE ON core_admission BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER admission_no_delete BEFORE DELETE ON core_admission BEGIN SELECT RAISE(ABORT,'immutable'); END;
PRAGMA user_version=2;

CREATE TABLE launch_fence(
 attempt_id TEXT NOT NULL REFERENCES core_admission(attempt_id),
 revision TEXT NOT NULL CHECK(length(revision) BETWEEN 1 AND 20 AND revision NOT GLOB '*[^0-9]*' AND (revision='0' OR substr(revision,1,1)<>'0')),
 digest TEXT NOT NULL,
 snapshot_jcs TEXT NOT NULL CHECK(length(snapshot_jcs)<=262144),
 PRIMARY KEY(attempt_id,revision)
) STRICT;
CREATE TABLE launch_fence_item(
 attempt_id TEXT NOT NULL,
 revision TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 intent_digest TEXT NOT NULL,
 disposition TEXT NOT NULL CHECK(disposition IN('allow','deny')),
 PRIMARY KEY(attempt_id,revision,launch_id),
 FOREIGN KEY(attempt_id,revision) REFERENCES launch_fence(attempt_id,revision)
) STRICT;
CREATE TABLE launch_fence_current(
 attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES core_admission(attempt_id),
 revision TEXT NOT NULL,
 FOREIGN KEY(attempt_id,revision) REFERENCES launch_fence(attempt_id,revision)
) STRICT;
CREATE TRIGGER fence_no_update BEFORE UPDATE ON launch_fence BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER fence_no_delete BEFORE DELETE ON launch_fence BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER fence_item_no_update BEFORE UPDATE ON launch_fence_item BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER fence_item_no_delete BEFORE DELETE ON launch_fence_item BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER fence_current_no_delete BEFORE DELETE ON launch_fence_current BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER fence_item_sealed BEFORE INSERT ON launch_fence_item WHEN EXISTS(
 SELECT 1 FROM launch_fence_current WHERE attempt_id=NEW.attempt_id AND
 (length(revision)>length(NEW.revision) OR (length(revision)=length(NEW.revision) AND revision>=NEW.revision))
) BEGIN SELECT RAISE(ABORT,'fence_sealed'); END;
CREATE TRIGGER fence_item_identity BEFORE INSERT ON launch_fence_item WHEN EXISTS(
 SELECT 1 FROM launch_fence_item WHERE attempt_id=NEW.attempt_id AND launch_id=NEW.launch_id AND
 (intent_digest<>NEW.intent_digest OR (disposition='deny' AND NEW.disposition='allow'))
) BEGIN SELECT RAISE(ABORT,'fence_identity_or_denial'); END;
CREATE TRIGGER fence_current_forward BEFORE UPDATE ON launch_fence_current WHEN NEW.attempt_id<>OLD.attempt_id OR
 length(NEW.revision)<length(OLD.revision) OR (length(NEW.revision)=length(OLD.revision) AND NEW.revision<=OLD.revision)
BEGIN SELECT RAISE(ABORT,'fence_revision'); END;
CREATE TABLE worker_launch(
 attempt_id TEXT NOT NULL REFERENCES core_admission(attempt_id),
 launch_id TEXT NOT NULL,
 intent_digest TEXT NOT NULL,
 intent_jcs TEXT NOT NULL CHECK(length(intent_jcs)<=262144),
 member_id TEXT NOT NULL,
 group_id TEXT NOT NULL,
 group_generation TEXT NOT NULL,
 authorization_jcs TEXT NOT NULL CHECK(length(authorization_jcs)<=65536),
 PRIMARY KEY(attempt_id,launch_id),
 UNIQUE(attempt_id,member_id),
 UNIQUE(attempt_id,group_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_state(attempt_id,launch_id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
CREATE TABLE worker_state(
 attempt_id TEXT NOT NULL,
 launch_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('registered','creating','awaiting_bootstrap','admitted_closed','retiring','retired','rejected','indeterminate')),
 creation_attempted INTEGER NOT NULL CHECK(creation_attempted IN(0,1)),
 admission_receipt TEXT,
 retirement_evidence TEXT,
 PRIMARY KEY(attempt_id,launch_id),
 FOREIGN KEY(attempt_id,launch_id) REFERENCES worker_launch(attempt_id,launch_id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(state NOT IN('registered','rejected') OR creation_attempted=0),
 CHECK(state NOT IN('creating','awaiting_bootstrap','admitted_closed','indeterminate') OR creation_attempted=1),
 CHECK(state<>'admitted_closed' OR admission_receipt IS NOT NULL),
 CHECK(admission_receipt IS NULL OR state IN('admitted_closed','indeterminate','retiring','retired')),
 CHECK((state='retired')=(retirement_evidence IS NOT NULL))
) STRICT;
CREATE TRIGGER worker_launch_no_update BEFORE UPDATE ON worker_launch BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_launch_no_delete BEFORE DELETE ON worker_launch BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_state_no_delete BEFORE DELETE ON worker_state BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER worker_state_initial BEFORE INSERT ON worker_state WHEN NEW.state<>'registered' OR NEW.creation_attempted<>0
BEGIN SELECT RAISE(ABORT,'worker_initial_state'); END;
CREATE TRIGGER worker_state_transition BEFORE UPDATE ON worker_state WHEN NEW.attempt_id<>OLD.attempt_id OR NEW.launch_id<>OLD.launch_id OR
 NEW.creation_attempted<OLD.creation_attempted OR (OLD.admission_receipt IS NOT NULL AND NEW.admission_receipt IS NOT OLD.admission_receipt) OR NOT(
 (OLD.state='registered' AND NEW.state IN('creating','rejected','retiring')) OR
 (OLD.state='creating' AND NEW.state IN('awaiting_bootstrap','indeterminate','retiring')) OR
 (OLD.state='awaiting_bootstrap' AND NEW.state IN('admitted_closed','indeterminate','retiring')) OR
 (OLD.state='admitted_closed' AND NEW.state IN('indeterminate','retiring')) OR
 (OLD.state='indeterminate' AND NEW.state='retiring') OR (OLD.state='retiring' AND NEW.state='retired'))
BEGIN SELECT RAISE(ABORT,'worker_state_transition'); END;
PRAGMA user_version=3;
