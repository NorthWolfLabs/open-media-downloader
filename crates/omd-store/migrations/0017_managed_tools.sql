CREATE TABLE managed_tool_sets (
    digest TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('installed','removing','removed','retained')),
    installed_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    issue_json TEXT,
    revision INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE managed_tool_active (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    digest TEXT REFERENCES managed_tool_sets(digest)
);
INSERT INTO managed_tool_active(singleton,digest) VALUES(1,NULL);
CREATE TABLE managed_tool_cleanup (
    digest TEXT NOT NULL REFERENCES managed_tool_sets(digest),
    name TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','removed','retained')),
    PRIMARY KEY(digest,name)
);
CREATE INDEX managed_tool_page ON managed_tool_sets(installed_at,digest);
