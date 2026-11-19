ALTER TABLE providers ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
CREATE TABLE source_removals (
 id TEXT PRIMARY KEY,
 provider TEXT NOT NULL,
 review_json TEXT NOT NULL,
 approval_digest TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('working','complete')),
 issue_json TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 UNIQUE(provider,approval_digest)
);
CREATE TABLE source_removal_entries (
 removal_id TEXT NOT NULL REFERENCES source_removals(id),
 kind TEXT NOT NULL CHECK(kind IN ('component','account')),
 item_key TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','removed','retained')),
 issue_json TEXT,
 PRIMARY KEY(removal_id,kind,item_key)
);
CREATE INDEX source_removal_queue ON source_removals(state,updated_at,id);
