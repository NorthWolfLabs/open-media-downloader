//! Frozen destination-wide reconciliation using the same durable per-file reader.
//! The membership and every child journal are committed together; no filesystem
//! mutation or source access is involved, and new acquisitions are not swept in.
use super::{Error, Result, Storage};
use omd_domain::{Page, Problem};
use omd_store::{id, now};
use serde::{Deserialize, Serialize};
use sqlx::Row;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DestinationCheck {
    pub id: String,
    pub destination_id: String,
    pub label: String,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    pub jobs: i64,
    pub completed_jobs: i64,
    pub files: i64,
    pub checked: i64,
    pub present: i64,
    pub modified: i64,
    pub missing: i64,
    pub detached: i64,
    pub blocked_jobs: i64,
    pub issue: Option<Problem>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DestinationCheckFile {
    pub job_id: String,
    pub artifact_id: String,
    pub path: String,
    pub state: String,
}
const SELECT:&str="SELECT c.*,d.label,
(SELECT COUNT(*) FROM file_operations o WHERE o.destination_check=c.id) AS jobs,
(SELECT COUNT(*) FROM file_operations o WHERE o.destination_check=c.id AND o.state='complete') AS completed_jobs,
(SELECT COUNT(*) FROM file_operations o WHERE o.destination_check=c.id AND o.issue_json IS NOT NULL) AS blocked_jobs,
(SELECT o.issue_json FROM file_operations o WHERE o.destination_check=c.id AND o.issue_json IS NOT NULL ORDER BY o.id LIMIT 1) AS issue_json,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id) AS files,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id AND e.state<>'pending') AS checked,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id AND e.state='present') AS present,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id AND e.state='modified') AS modified,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id AND e.state='missing') AS missing,
(SELECT COUNT(*) FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=c.id AND e.state='detached') AS detached
FROM destination_checks c JOIN destinations d ON d.id=c.destination_id";
fn decode(r: sqlx::sqlite::SqliteRow) -> Result<DestinationCheck> {
    Ok(DestinationCheck {
        id: r.get("id"),
        destination_id: r.get("destination_id"),
        label: r.get("label"),
        state: r.get("state"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        jobs: r.get("jobs"),
        completed_jobs: r.get("completed_jobs"),
        files: r.get("files"),
        checked: r.get("checked"),
        present: r.get("present"),
        modified: r.get("modified"),
        missing: r.get("missing"),
        detached: r.get("detached"),
        blocked_jobs: r.get("blocked_jobs"),
        issue: r
            .get::<Option<String>, _>("issue_json")
            .map(|s| serde_json::from_str(&s))
            .transpose()?,
    })
}
impl Storage {
    pub async fn destination_check(&self, id: &str) -> Result<DestinationCheck> {
        decode(
            sqlx::query(&format!("{SELECT} WHERE c.id=?"))
                .bind(id)
                .fetch_optional(&self.store.pool)
                .await?
                .ok_or(omd_store::StoreError::NotFound)?,
        )
    }
    pub async fn destination_checks(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<DestinationCheck>> {
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query(&format!("{SELECT} WHERE instr(lower(d.label),lower(?))>0 AND (? IS NULL OR c.created_at||':'||c.id<?) ORDER BY c.created_at DESC,c.id DESC LIMIT ?")).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.store.pool).await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(decode)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = more
            .then(|| items.last().map(|c| format!("{}:{}", c.created_at, c.id)))
            .flatten();
        Ok(Page { items, next_cursor })
    }
    pub async fn destination_check_files(
        &self,
        id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<DestinationCheckFile>> {
        self.destination_check(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT o.job_id,e.* FROM file_operation_entries e JOIN file_operations o ON o.id=e.operation_id WHERE o.destination_check=? AND instr(lower(e.path),lower(?))>0 AND (? IS NULL OR e.artifact_id>?) ORDER BY e.artifact_id LIMIT ?").bind(id).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.store.pool).await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(|r| DestinationCheckFile {
                job_id: r.get("job_id"),
                artifact_id: r.get("artifact_id"),
                path: r.get("path"),
                state: r.get("state"),
            })
            .collect();
        let next_cursor = more
            .then(|| items.last().map(|e| e.artifact_id.clone()))
            .flatten();
        Ok(Page { items, next_cursor })
    }
    pub async fn create_destination_check(&self, destination: &str) -> Result<DestinationCheck> {
        self.store.destination_root(destination).await?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let existing:Option<String>=sqlx::query_scalar("SELECT id FROM destination_checks WHERE destination_id=? AND state IN ('working','paused')").bind(destination).fetch_optional(&mut *tx).await?;
        if let Some(id) = existing {
            tx.commit().await?;
            return self.destination_check(&id).await;
        }
        let available:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM destinations d WHERE d.id=? AND d.storage_operation IS NULL AND NOT EXISTS(SELECT 1 FROM file_operations o JOIN jobs j ON j.id=o.job_id WHERE j.destination_id=d.id AND o.state IN ('ready','working')))").bind(destination).fetch_one(&mut *tx).await?;
        if !available {
            return Err(Error::CheckBusy);
        }
        let id = id("check");
        let time = now();
        sqlx::query("INSERT INTO destination_checks VALUES(?,?,'working',?,?)")
            .bind(&id)
            .bind(destination)
            .bind(&time)
            .bind(&time)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO file_operations(id,job_id,mode,state,created_at,updated_at,destination_check) SELECT ?||':'||j.id,j.id,'reconcile','working',?,?,? FROM jobs j WHERE j.destination_id=? AND j.state='completed' AND j.history_removed=0").bind(&id).bind(&time).bind(&time).bind(&id).bind(destination).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO file_operation_entries SELECT o.id,a.id,a.relative_path,a.size,a.sha256,'pending' FROM file_operations o JOIN artifacts a ON a.job_id=o.job_id WHERE o.destination_check=?").bind(&id).execute(&mut *tx).await?;
        sqlx::query("UPDATE destination_checks SET state='complete' WHERE id=? AND NOT EXISTS(SELECT 1 FROM file_operations WHERE destination_check=?)").bind(&id).bind(&id).execute(&mut *tx).await?;
        omd_store::emit(&mut tx, "storage.changed", &id).await?;
        tx.commit().await?;
        self.destination_check(&id).await
    }
    pub async fn destination_check_action(
        &self,
        id: &str,
        action: &str,
    ) -> Result<DestinationCheck> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let state: String = sqlx::query_scalar("SELECT state FROM destination_checks WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(omd_store::StoreError::NotFound)?;
        if !["working", "paused"].contains(&state.as_str()) {
            return Err(Error::CheckState);
        }
        let time = now();
        match action {
            "pause" => {
                let issue = serde_json::to_string(&Problem {
                    code: "destination_check_paused".into(),
                    message: "File checking is paused.".into(),
                    retryable: true,
                    actions: vec!["resume_destination_check".into()],
                })?;
                sqlx::query("UPDATE file_operations SET issue_json=?,updated_at=? WHERE destination_check=? AND state='working' AND issue_json IS NULL").bind(issue).bind(&time).bind(id).execute(&mut *tx).await?;
            }
            "resume" | "retry" => {
                sqlx::query("UPDATE file_operations SET issue_json=NULL,updated_at=? WHERE destination_check=? AND state='working' AND (?='retry' OR json_extract(issue_json,'$.code')='destination_check_paused')").bind(&time).bind(id).bind(action).execute(&mut *tx).await?;
            }
            "cancel" => {
                sqlx::query("UPDATE file_operations SET state='canceled',issue_json=NULL,updated_at=? WHERE destination_check=? AND state='working'").bind(&time).bind(id).execute(&mut *tx).await?;
            }
            _ => return Err(Error::CheckState),
        }
        sqlx::query("UPDATE destination_checks SET state=?,updated_at=? WHERE id=?")
            .bind(match action {
                "pause" => "paused",
                "cancel" => "canceled",
                _ => "working",
            })
            .bind(&time)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        omd_store::emit(&mut tx, "storage.changed", id).await?;
        tx.commit().await?;
        self.destination_check(id).await
    }
}
