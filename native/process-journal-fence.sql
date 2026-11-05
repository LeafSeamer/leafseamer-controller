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
