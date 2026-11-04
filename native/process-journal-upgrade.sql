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
