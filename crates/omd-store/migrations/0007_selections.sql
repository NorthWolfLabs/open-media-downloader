-- A scan commits each source page with its continuation. Ready snapshots never mutate.
CREATE TABLE selection_tasks (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('snapshot','batch')),
 state TEXT NOT NULL CHECK(state IN ('working','ready','failed','canceled','submitted')),
 request_json TEXT NOT NULL,
 source_digest TEXT NOT NULL,
 cursor TEXT,
 processed INTEGER NOT NULL DEFAULT 0,
 total INTEGER NOT NULL DEFAULT 0,
 issue_json TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at TEXT
);
CREATE INDEX selection_work ON selection_tasks(state,updated_at,id);
CREATE TABLE snapshot_releases (
 snapshot_id TEXT NOT NULL REFERENCES selection_tasks(id),
 ordinal INTEGER NOT NULL,
 release_key TEXT NOT NULL,
 data_json TEXT NOT NULL,
 PRIMARY KEY(snapshot_id,ordinal),
 UNIQUE(snapshot_id,release_key)
);
CREATE TABLE snapshot_cursors (
 snapshot_id TEXT NOT NULL REFERENCES selection_tasks(id),
 cursor TEXT NOT NULL,
 PRIMARY KEY(snapshot_id,cursor)
);
CREATE TABLE batch_items (
 batch_id TEXT NOT NULL REFERENCES selection_tasks(id),
 ordinal INTEGER NOT NULL,
 release_json TEXT NOT NULL,
 preview_json TEXT,
 PRIMARY KEY(batch_id,ordinal)
);
