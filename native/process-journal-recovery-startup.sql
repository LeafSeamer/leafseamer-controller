CREATE TABLE recovery_startup_fence(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 attempt_id TEXT NOT NULL REFERENCES core_exit(attempt_id),
 plan_digest TEXT NOT NULL CHECK(length(plan_digest)=71 AND substr(plan_digest,1,7)='sha256:'
   AND substr(plan_digest,8) NOT GLOB '*[^0-9a-f]*'),
 retirement_id TEXT NOT NULL CHECK(length(retirement_id)=36 AND length(replace(retirement_id,'-',''))=32
   AND substr(retirement_id,9,1)='-' AND substr(retirement_id,14,2)='-4' AND substr(retirement_id,19,1)='-'
   AND substr(retirement_id,20,1) IN ('8','9','a','b') AND substr(retirement_id,24,1)='-'
   AND replace(retirement_id,'-','') NOT GLOB '*[^0-9a-f]*')
) STRICT;
CREATE TRIGGER recovery_startup_fence_latest BEFORE INSERT ON recovery_startup_fence
WHEN NOT EXISTS(SELECT 1 FROM core_attempt a JOIN core_admission c USING(attempt_id) JOIN core_exit e USING(attempt_id)
 WHERE a.attempt_id=NEW.attempt_id AND a.rowid=(SELECT max(rowid) FROM core_attempt) AND e.active_processes=0)
BEGIN SELECT RAISE(ABORT,'process_retirement_unproven'); END;
CREATE TRIGGER recovery_startup_fence_no_update BEFORE UPDATE ON recovery_startup_fence BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER recovery_startup_fence_no_delete BEFORE DELETE ON recovery_startup_fence BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER recovery_startup_fence_no_attempt BEFORE INSERT ON core_attempt BEGIN SELECT RAISE(ABORT,'process_recovery_startup_fenced'); END;
PRAGMA user_version=7;
