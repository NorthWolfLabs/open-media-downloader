CREATE TABLE destination_checks (
 id TEXT PRIMARY KEY,
 destination_id TEXT NOT NULL REFERENCES destinations(id),
 state TEXT NOT NULL CHECK(state IN ('working','paused','complete','canceled')),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX one_active_destination_check ON destination_checks(destination_id) WHERE state IN ('working','paused');
ALTER TABLE file_operations ADD COLUMN destination_check TEXT REFERENCES destination_checks(id);
CREATE INDEX destination_check_children ON file_operations(destination_check,state);
