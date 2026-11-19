-- Page/cursor checkpoints reuse the bounded source-enumeration worker. A unique
-- link prevents overlapping observations of one subscription across clients.
CREATE TABLE subscription_scans (
 subscription_id TEXT PRIMARY KEY REFERENCES subscriptions(id),
 snapshot_id TEXT NOT NULL UNIQUE REFERENCES selection_tasks(id),
 request_json TEXT NOT NULL
);
