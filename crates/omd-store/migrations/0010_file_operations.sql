ALTER TABLE jobs ADD COLUMN history_removed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE artifacts ADD COLUMN checked_at TEXT;
CREATE TABLE file_operations (
 id TEXT PRIMARY KEY,
 job_id TEXT NOT NULL REFERENCES jobs(id),
 mode TEXT NOT NULL CHECK(mode IN ('reconcile','remove_files','forget_history','remove_files_and_history')),
 state TEXT NOT NULL CHECK(state IN ('ready','working','complete','canceled')),
 issue_json TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX one_active_file_operation ON file_operations(job_id) WHERE state IN ('ready','working');
CREATE TABLE file_operation_entries (
 operation_id TEXT NOT NULL REFERENCES file_operations(id),
 artifact_id TEXT NOT NULL REFERENCES artifacts(id),
 path TEXT NOT NULL,
 size INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 state TEXT NOT NULL,
 PRIMARY KEY(operation_id,artifact_id)
);
CREATE INDEX file_operation_queue ON file_operations(state,updated_at,id);
