ALTER TABLE jobs ADD COLUMN intent_key TEXT NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN generation INTEGER NOT NULL DEFAULT 0;
UPDATE jobs SET intent_key=acquisition_key;
CREATE UNIQUE INDEX job_intent_version ON jobs(intent_key,generation);
CREATE TABLE path_reservations (
    destination_id TEXT NOT NULL REFERENCES destinations(id),
    path_key TEXT NOT NULL,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
    PRIMARY KEY(destination_id,path_key)
);
