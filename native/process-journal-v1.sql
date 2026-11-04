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
