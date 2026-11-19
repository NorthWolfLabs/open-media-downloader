CREATE TABLE metadata_overrides (
 kind TEXT NOT NULL CHECK(kind IN ('collection','release')),
 source_key TEXT NOT NULL,
 reference_json TEXT NOT NULL,
 data_json TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(kind,source_key)
);
