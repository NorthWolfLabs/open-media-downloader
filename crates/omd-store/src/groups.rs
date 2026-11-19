use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JobGroup {
    pub id: String,
    pub title: String,
    pub created_at: String,
    pub total: i64,
    pub completed: i64,
    pub active: i64,
    pub paused: i64,
    pub failed: i64,
    pub canceled: i64,
}
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GroupAction {
    pub changed: u64,
    pub unchanged: u64,
    pub publishing: u64,
    pub checkpointing: u64,
}
fn group(row: SqliteRow) -> JobGroup {
    JobGroup {
        id: row.get("id"),
        title: row.get("title"),
        created_at: row.get("created_at"),
        total: row.get("total"),
        completed: row.get("completed"),
        active: row.get("active"),
        paused: row.get("paused"),
        failed: row.get("failed"),
        canceled: row.get("canceled"),
    }
}
const COUNTS: &str = "SELECT g.id,g.created_at,MIN(json_extract(j.plan_json,'$.collection.title')) AS title,COUNT(*) AS total,SUM(j.state='completed') AS completed,SUM(j.state IN ('queued','resolving','transferring','verifying','publishing')) AS active,SUM(j.state='paused') AS paused,SUM(j.state='failed') AS failed,SUM(j.state='canceled') AS canceled FROM job_groups g JOIN job_group_members m ON m.group_id=g.id JOIN jobs j ON j.id=m.job_id";
impl Store {
    /// One command affects the entire current membership, independent of UI
    /// pagination. Publication cannot be interrupted by a user job command.
    pub async fn group_action(
        &self,
        id: &str,
        action: &str,
        running: &[String],
    ) -> Result<(GroupAction, Vec<String>)> {
        let (eligible, target, restarting) = match action {
            "pause" => (
                vec!["queued", "transferring", "verifying", "failed"],
                "paused",
                false,
            ),
            "cancel" => (
                vec!["queued", "transferring", "verifying", "failed", "paused"],
                "canceled",
                false,
            ),
            "resume" | "retry" => (vec!["paused", "failed", "canceled"], "queued", true),
            _ => return Err(StoreError::StateConflict),
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let running = serde_json::to_string(running)?;
        let eligible = serde_json::to_string(&eligible)?;
        let totals=sqlx::query("SELECT COUNT(*) AS total,COALESCE(SUM(j.state='publishing'),0) AS publishing,COALESCE(SUM(j.id IN (SELECT value FROM json_each(?)) AND j.state IN ('paused','failed','canceled')),0) AS checkpointing FROM job_group_members m JOIN jobs j ON j.id=m.job_id WHERE m.group_id=?")
            .bind(&running).bind(id).fetch_one(&mut *tx).await?;
        let total = totals.get::<i64, _>("total") as u64;
        if total == 0 {
            return Err(StoreError::NotFound);
        }
        let stop: Vec<String> = if restarting {
            vec![]
        } else {
            sqlx::query_scalar("SELECT j.id FROM job_group_members m JOIN jobs j ON j.id=m.job_id WHERE m.group_id=? AND j.state IN (SELECT value FROM json_each(?)) AND j.id IN (SELECT value FROM json_each(?))")
            .bind(id).bind(&eligible).bind(&running).fetch_all(&mut *tx).await?
        };
        let changed=sqlx::query("UPDATE jobs SET state=?,issue_json=NULL,updated_at=? WHERE id IN (SELECT job_id FROM job_group_members WHERE group_id=?) AND state IN (SELECT value FROM json_each(?)) AND (?=0 OR id NOT IN (SELECT value FROM json_each(?)))")
            .bind(target).bind(now()).bind(id).bind(eligible).bind(restarting).bind(running).execute(&mut *tx).await?.rows_affected();
        emit(&mut tx, "jobs.changed", id).await?;
        tx.commit().await?;
        Ok((
            GroupAction {
                changed,
                unchanged: total - changed,
                publishing: totals.get::<i64, _>("publishing") as u64,
                checkpointing: if restarting {
                    totals.get::<i64, _>("checkpointing") as u64
                } else {
                    0
                },
            },
            stop,
        ))
    }
    pub async fn job_groups(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<JobGroup>> {
        self.filtered_job_groups(query, cursor, limit, false).await
    }
    pub async fn filtered_job_groups(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
        active_only: bool,
    ) -> Result<Page<JobGroup>> {
        let limit = limit.clamp(1, 200) as usize;
        let sql = format!(
            "{COUNTS} WHERE (? IS NULL OR g.created_at || ':' || g.id < ?) AND EXISTS(SELECT 1 FROM job_group_members sm JOIN jobs sj ON sj.id=sm.job_id WHERE sm.group_id=g.id AND instr(lower(sj.title || ' ' || json_extract(sj.plan_json,'$.collection.title')),lower(?))>0) GROUP BY g.id HAVING (?=0 OR sum(CASE WHEN j.state NOT IN ('completed','canceled') THEN 1 ELSE 0 END)>0) ORDER BY g.created_at DESC,g.id DESC LIMIT ?"
        );
        let rows = sqlx::query(&sql)
            .bind(cursor)
            .bind(cursor)
            .bind(query)
            .bind(active_only)
            .bind((limit + 1) as i64)
            .fetch_all(&self.pool)
            .await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows.into_iter().take(limit).map(group).collect();
        let next_cursor = if more {
            items.last().map(|g| format!("{}:{}", g.created_at, g.id))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn job_group(&self, id: &str) -> Result<JobGroup> {
        let sql = format!("{COUNTS} WHERE g.id=? GROUP BY g.id");
        Ok(group(
            sqlx::query(&sql)
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StoreError::NotFound)?,
        ))
    }
    pub async fn group_jobs(
        &self,
        id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Job>> {
        self.job_group(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT j.* FROM job_group_members m JOIN jobs j ON j.id=m.job_id WHERE m.group_id=? AND instr(lower(j.title),lower(?))>0 AND (? IS NULL OR j.created_at || ':' || j.id < ?) ORDER BY j.created_at DESC,j.id DESC LIMIT ?")
            .bind(id).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(job_row)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if more {
            items.last().map(|j| format!("{}:{}", j.created_at, j.id))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn whole_group_actions_cover_all_pages_and_preserve_publication_and_checkpointing() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let destination = store.add_destination("Files", root.path()).await.unwrap();
        let mut ids = vec![];
        for n in 0..251 {
            let mut plan: Plan =
                serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
            plan.release.reference.id = format!("r-{n}");
            let (job, _) = store
                .enqueue(
                    &plan,
                    &destination.id,
                    &format!("r-{n}"),
                    &format!("r-{n}"),
                    Some("group"),
                )
                .await
                .unwrap();
            ids.push(job.id);
        }
        store
            .transition(&ids[0], &["queued"], "publishing", None)
            .await
            .unwrap();
        store
            .transition(&ids[1], &["queued"], "completed", None)
            .await
            .unwrap();
        let running = vec![ids[2].clone()];
        let (paused, stop) = store
            .group_action("group", "pause", &running)
            .await
            .unwrap();
        assert_eq!(paused.changed, 249);
        assert_eq!(paused.publishing, 1);
        assert_eq!(stop, running);
        let (resumed, _) = store
            .group_action("group", "resume", &running)
            .await
            .unwrap();
        assert_eq!(resumed.changed, 248);
        assert_eq!(resumed.checkpointing, 1);
        assert_eq!(
            store.job(&ids[2]).await.unwrap().state,
            omd_domain::JobState::Paused
        );
        let (resumed, _) = store.group_action("group", "resume", &[]).await.unwrap();
        assert_eq!(resumed.changed, 1);
        let (canceled, _) = store.group_action("group", "cancel", &[]).await.unwrap();
        assert_eq!(canceled.changed, 249);
        assert_eq!(canceled.unchanged, 2);
        assert_eq!(
            store.job(&ids[0]).await.unwrap().state,
            omd_domain::JobState::Publishing
        );
        assert_eq!(
            store.job(&ids[1]).await.unwrap().state,
            omd_domain::JobState::Completed
        );
        assert_eq!(
            store
                .group_action("group", "cancel", &[])
                .await
                .unwrap()
                .0
                .changed,
            0,
            "repeat commands are state-idempotent"
        );
    }
    #[tokio::test]
    async fn overlapping_groups_share_one_job_and_paginate_without_losing_membership() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let mut job_id = None;
        for n in 0..251 {
            let name = format!("group-{n:03}");
            let (job, created) = store
                .enqueue(&plan, &dest.id, &name, &name, Some(&name))
                .await
                .unwrap();
            assert_eq!(created, n == 0);
            if let Some(id) = &job_id {
                assert_eq!(id, &job.id);
            } else {
                job_id = Some(job.id);
            }
            assert_eq!(store.job_group(&name).await.unwrap().total, 1);
            assert_eq!(
                store
                    .group_jobs(&name, "", None, 100)
                    .await
                    .unwrap()
                    .items
                    .len(),
                1
            );
        }
        let mut cursor = None;
        let mut ids = std::collections::BTreeSet::new();
        loop {
            let page = store.job_groups("", cursor.as_deref(), 131).await.unwrap();
            for item in page.items {
                assert!(ids.insert(item.id));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(ids.len(), 251);
        assert_eq!(
            store.jobs("", None, None, 200).await.unwrap().items.len(),
            1
        );
        store
            .transition(job_id.as_ref().unwrap(), &["queued"], "paused", None)
            .await
            .unwrap();
        assert_eq!(store.job_group("group-250").await.unwrap().paused, 1);
        assert_eq!(store.job_group("group-000").await.unwrap().active, 0);
        // Filtering must happen before pagination: hundreds of completed groups
        // cannot conceal the first active download.
        store
            .transition(job_id.as_ref().unwrap(), &["paused"], "completed", None)
            .await
            .unwrap();
        let mut pending = plan.clone();
        pending.release.reference.id = "active-chapter".into();
        store
            .enqueue(&pending, &dest.id, "active", "active", Some("active-group"))
            .await
            .unwrap();
        let active = store.filtered_job_groups("", None, 1, true).await.unwrap();
        assert_eq!(active.items.len(), 1);
        assert_eq!(active.items[0].id, "active-group");
        assert!(active.next_cursor.is_none());
        let jobs = store.jobs("", Some("active"), None, 1).await.unwrap();
        assert_eq!(jobs.items.len(), 1);
        assert_eq!(jobs.items[0].plan.release.reference.id, "active-chapter");

        assert!(
            store
                .job_groups("does-not-exist", None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }
}
