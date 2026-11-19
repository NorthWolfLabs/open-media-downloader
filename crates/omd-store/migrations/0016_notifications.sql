CREATE TABLE notification_batches (
    id TEXT PRIMARY KEY,
    count INTEGER NOT NULL CHECK(count > 0),
    state TEXT NOT NULL CHECK(state IN ('sending','delivered','failed','uncertain','dismissed')),
    issue_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE notification_outbox (
    action_id TEXT PRIMARY KEY REFERENCES actions(id),
    state TEXT NOT NULL CHECK(state IN ('pending','suppressed','batched')),
    batch_id TEXT REFERENCES notification_batches(id),
    created_at TEXT NOT NULL
);
CREATE INDEX notification_pending ON notification_outbox(state, created_at, action_id);
