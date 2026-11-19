-- Only public account labels and vault handles. Secret bytes never enter SQLite.
CREATE TABLE credential_profiles (
    provider TEXT NOT NULL,
    profile TEXT NOT NULL,
    label TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(provider, profile)
);
