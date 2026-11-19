-- A satisfied intent may participate in multiple user operations without
-- duplicating the acquisition or losing either operation's membership.
CREATE TABLE job_groups(id TEXT PRIMARY KEY,created_at TEXT NOT NULL);
CREATE TABLE job_group_members(
 group_id TEXT NOT NULL REFERENCES job_groups(id),
 job_id TEXT NOT NULL REFERENCES jobs(id),
 PRIMARY KEY(group_id,job_id)
);
INSERT INTO job_groups SELECT group_id,MIN(created_at) FROM jobs WHERE group_id IS NOT NULL GROUP BY group_id;
INSERT INTO job_group_members SELECT group_id,id FROM jobs WHERE group_id IS NOT NULL;
CREATE INDEX memberships_by_job ON job_group_members(job_id,group_id);
