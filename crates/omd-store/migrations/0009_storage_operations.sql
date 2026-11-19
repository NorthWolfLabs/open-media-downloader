ALTER TABLE destinations ADD COLUMN storage_operation TEXT;
CREATE TABLE storage_operations (
 id TEXT PRIMARY KEY,
 destination_id TEXT NOT NULL REFERENCES destinations(id),
 source_root TEXT NOT NULL,
 source_marker TEXT NOT NULL,
 target_root TEXT NOT NULL,
 target_marker TEXT NOT NULL,
 state TEXT NOT NULL,
 issue_json TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE storage_roots (
 operation_id TEXT NOT NULL REFERENCES storage_operations(id),
 path TEXT NOT NULL,
 private INTEGER NOT NULL,
 state TEXT NOT NULL,
 PRIMARY KEY(operation_id,path)
);
CREATE TABLE storage_entries (
 operation_id TEXT NOT NULL,
 root_path TEXT NOT NULL,
 path TEXT NOT NULL,
 kind TEXT NOT NULL,
 size INTEGER NOT NULL,
 sha256 TEXT NOT NULL,
 state TEXT NOT NULL,
 PRIMARY KEY(operation_id,root_path,path),
 FOREIGN KEY(operation_id,root_path) REFERENCES storage_roots(operation_id,path)
);
CREATE INDEX storage_queue ON storage_operations(state,updated_at,id);
