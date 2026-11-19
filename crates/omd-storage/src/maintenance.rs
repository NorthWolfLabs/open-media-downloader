//! Durable inspection and deliberate removal of recorded acquisition files.
//! Changed files and user additions are never removed. History removal retains
//! an internal request tombstone so retries and version reservations remain safe.
use super::{Error, Result, Storage, hash_cancellable, owned_directory, stopped};
use omd_domain::{Page, Problem};
use omd_store::{id, now};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "FileOperationMode")]
pub enum Mode {
    Reconcile,
    RemoveFiles,
    ForgetHistory,
    RemoveFilesAndHistory,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Reconcile => "reconcile",
            Self::RemoveFiles => "remove_files",
            Self::ForgetHistory => "forget_history",
            Self::RemoveFilesAndHistory => "remove_files_and_history",
        }
    }
    fn forgets(self) -> bool {
        matches!(self, Self::ForgetHistory | Self::RemoveFilesAndHistory)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileOperation {
    pub destination_check: Option<String>,
    pub id: String,
    pub job_id: String,
    pub title: String,
    pub mode: Mode,
    pub state: String,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
    pub total: i64,
    pub processed: i64,
    pub retained: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "FileOperationEntry")]
pub struct FileEntry {
    pub artifact_id: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub state: String,
}
fn operation(r: sqlx::sqlite::SqliteRow) -> Result<FileOperation> {
    Ok(FileOperation {
        destination_check: r.get("destination_check"),
        id: r.get("id"),
        job_id: r.get("job_id"),
        title: r.get("title"),
        mode: serde_json::from_value(serde_json::Value::String(r.get("mode")))?,
        state: r.get("state"),
        issue: r
            .get::<Option<String>, _>("issue_json")
            .map(|v| serde_json::from_str(&v))
            .transpose()?,
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        total: r.get("total"),
        processed: r.get("processed"),
        retained: r.get("retained"),
    })
}
const SELECT: &str = "SELECT o.*,j.title,(SELECT COUNT(*) FROM file_operation_entries e WHERE e.operation_id=o.id) AS total,(SELECT COUNT(*) FROM file_operation_entries e WHERE e.operation_id=o.id AND e.state NOT IN ('pending','held')) AS processed,(SELECT COUNT(*) FROM file_operation_entries e WHERE e.operation_id=o.id AND e.state IN ('modified','detached','retained')) AS retained FROM file_operations o JOIN jobs j ON j.id=o.job_id";
impl Storage {
    pub async fn file_operation(&self, id: &str) -> Result<FileOperation> {
        operation(
            sqlx::query(&format!("{SELECT} WHERE o.id=?"))
                .bind(id)
                .fetch_optional(&self.store.pool)
                .await?
                .ok_or(omd_store::StoreError::NotFound)?,
        )
    }
    pub async fn file_operations(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<FileOperation>> {
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query(&format!("{SELECT} WHERE o.destination_check IS NULL AND instr(lower(j.title),lower(?))>0 AND (? IS NULL OR o.created_at || ':' || o.id < ?) ORDER BY o.created_at DESC,o.id DESC LIMIT ?")).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.store.pool).await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(operation)
            .collect::<Result<_>>()?;
        let next_cursor = if more {
            items.last().map(|v| format!("{}:{}", v.created_at, v.id))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn file_operation_entries(
        &self,
        id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<FileEntry>> {
        self.file_operation(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT * FROM file_operation_entries WHERE operation_id=? AND instr(lower(path),lower(?))>0 AND (? IS NULL OR path>?) ORDER BY path LIMIT ?").bind(id).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.store.pool).await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(|r| FileEntry {
                artifact_id: r.get("artifact_id"),
                path: r.get("path"),
                size: r.get::<i64, _>("size") as u64,
                sha256: r.get("sha256"),
                state: r.get("state"),
            })
            .collect();
        let next_cursor = if more {
            items.last().map(|v| v.path.clone())
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn create_file_operation(&self, job: &str, mode: Mode) -> Result<FileOperation> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let ready:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM jobs j JOIN destinations d ON d.id=j.destination_id WHERE j.id=? AND j.state='completed' AND j.history_removed=0 AND d.storage_operation IS NULL AND NOT EXISTS(SELECT 1 FROM file_operations o WHERE o.job_id=j.id AND o.state IN ('ready','working')))").bind(job).fetch_one(&mut *tx).await?;
        if !ready {
            return Err(Error::State);
        }
        let id = id("files");
        let time = now();
        sqlx::query("INSERT INTO file_operations(id,job_id,mode,state,issue_json,created_at,updated_at) VALUES(?,?,?,?,NULL,?,?)")
            .bind(&id)
            .bind(job)
            .bind(mode.name())
            .bind(if mode == Mode::Reconcile {
                "working"
            } else {
                "ready"
            })
            .bind(&time)
            .bind(&time)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO file_operation_entries SELECT ?,id,relative_path,size,sha256,'pending' FROM artifacts WHERE job_id=?").bind(&id).bind(job).execute(&mut *tx).await?;
        omd_store::emit(&mut tx, "files.changed", &id).await?;
        tx.commit().await?;
        self.file_operation(&id).await
    }
    pub async fn file_action(&self, id: &str, action: &str) -> Result<FileOperation> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM file_operations WHERE id=? AND destination_check IS NOT NULL)").bind(id).fetch_one(&mut *tx).await?;
        if owned {
            return Err(Error::CheckState);
        }
        let query = match action {
            "start" => {
                "UPDATE file_operations SET state='working',issue_json=NULL,updated_at=? WHERE id=? AND state='ready'"
            }
            "retry" => {
                "UPDATE file_operations SET issue_json=NULL,updated_at=? WHERE id=? AND state='working'"
            }
            // Cancel only before any file changes. Once started, the journal must
            // finish or retain its recoverable issue, including held files.
            "cancel" => {
                "UPDATE file_operations SET state='canceled',updated_at=? WHERE id=? AND state='ready'"
            }
            _ => return Err(Error::State),
        };
        if sqlx::query(query)
            .bind(now())
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            != 1
        {
            return Err(Error::State);
        }
        omd_store::emit(&mut tx, "files.changed", id).await?;
        omd_store::emit(&mut tx, "storage.changed", id).await?;
        tx.commit().await?;
        self.file_operation(id).await
    }
    pub async fn next_file_operation(&self) -> Result<Option<FileOperation>> {
        let id:Option<String>=sqlx::query_scalar("SELECT id FROM file_operations WHERE state='working' AND issue_json IS NULL ORDER BY updated_at,id LIMIT 1").fetch_optional(&self.store.pool).await?;
        match id {
            Some(id) => Ok(Some(self.file_operation(&id).await?)),
            None => Ok(None),
        }
    }
    pub async fn fail_file_operation(&self, id: &str, error: &Error) -> Result<()> {
        let mut issue = Problem::new(
            "file_operation_failed",
            "The file operation paused. Reconnect the destination or check its files, then retry.",
        );
        issue.retryable = true;
        issue.actions = vec![
            "reconnect_destination".into(),
            "retry_file_operation".into(),
        ];
        if matches!(error, Error::Collision) {
            issue.message="A recovery folder changed identity. Preserve its contents and restore the original recovery folder before retrying.".into();
        }
        let mut tx = self.store.pool.begin().await?;
        sqlx::query(
            "UPDATE file_operations SET issue_json=?,updated_at=? WHERE id=? AND state='working'",
        )
        .bind(serde_json::to_string(&issue)?)
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        omd_store::emit(&mut tx, "files.changed", id).await?;
        omd_store::emit(&mut tx, "storage.changed", id).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn checked_entry(
        &self,
        op: &FileOperation,
        entry: &FileEntry,
        state: &str,
    ) -> Result<()> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        if op.mode == Mode::Reconcile {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM file_operations WHERE id=? AND state='working' AND issue_json IS NULL)").bind(&op.id).fetch_one(&mut *tx).await?;
            if !active {
                return Ok(());
            }
        }
        sqlx::query(
            "UPDATE file_operation_entries SET state=? WHERE operation_id=? AND artifact_id=?",
        )
        .bind(state)
        .bind(&op.id)
        .bind(&entry.artifact_id)
        .execute(&mut *tx)
        .await?;
        if state != "held" {
            sqlx::query("UPDATE artifacts SET status=?,checked_at=? WHERE id=?")
                .bind(match state {
                    "removed" => "missing",
                    "retained" => "detached",
                    other => other,
                })
                .bind(now())
                .bind(&entry.artifact_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE file_operations SET updated_at=? WHERE id=?")
            .bind(now())
            .bind(&op.id)
            .execute(&mut *tx)
            .await?;
        omd_store::emit(&mut tx, "files.changed", &op.id).await?;
        omd_store::emit(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn step_file_operation(
        &self,
        op: &FileOperation,
        cancel: &CancellationToken,
    ) -> Result<()> {
        stopped(cancel)?;
        if op.mode == Mode::ForgetHistory {
            return self.finish_file_operation(op).await;
        }
        let job = self.store.job(&op.job_id).await?;
        // An unplugged destination is an unavailable operation, never evidence
        // that every artifact was removed.
        let root = self.store.destination_root(&job.destination_id).await?;
        let row=sqlx::query("SELECT * FROM file_operation_entries WHERE operation_id=? AND state IN ('pending','held') ORDER BY path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        let Some(r) = row else {
            return self.finish_file_operation(op).await;
        };
        let entry = FileEntry {
            artifact_id: r.get("artifact_id"),
            path: r.get("path"),
            size: r.get::<i64, _>("size") as u64,
            sha256: r.get("sha256"),
            state: r.get("state"),
        };
        let e = entry.clone();
        let stop = cancel.clone();
        let mode = op.mode;
        let operation_id = op.id.clone();
        let state = tokio::task::spawn_blocking(move || -> Result<&'static str> {
            stopped(&stop)?;
            let expected = (e.size, e.sha256.clone());
            if mode == Mode::Reconcile {
                return inspect(&root, &e.path, &expected, &stop);
            }
            let stage =
                owned_directory(&root, &format!(".omd-remove-{operation_id}"), &operation_id)?;
            let held = &e.artifact_id;
            if e.state == "pending" {
                match stage.read_file(held) {
                    Ok(_) => return Ok("held"),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                let current = inspect(&root, &e.path, &expected, &stop)?;
                if current != "present" {
                    return Ok(current);
                }
                root.publish(&e.path, &stage, held)?;
                // Persist held before deleting: a restart after deletion must
                // never pick up a new file at the original pathname.
                return Ok("held");
            }
            let status = inspect(&stage, held, &expected, &stop)?;
            if status == "missing" {
                return Ok("removed");
            }
            if status == "present" {
                stopped(&stop)?;
                stage.remove_file(held)?;
                return Ok("removed");
            }
            match stage.publish(held, &root, &e.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            Ok("retained")
        })
        .await
        .map_err(|_| Error::State)??;
        self.checked_entry(op, &entry, state).await
    }
    async fn finish_file_operation(&self, op: &FileOperation) -> Result<()> {
        if matches!(op.mode, Mode::RemoveFiles | Mode::RemoveFilesAndHistory) {
            let job = self.store.job(&op.job_id).await?;
            let root = self.store.destination_root(&job.destination_id).await?;
            super::cleanup_owner_directory(&root, &format!(".omd-remove-{}", op.id), &op.id)?;
        }
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        if op.mode == Mode::Reconcile {
            let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM file_operations WHERE id=? AND state='working' AND issue_json IS NULL)").bind(&op.id).fetch_one(&mut *tx).await?;
            if !active {
                return Ok(());
            }
        }
        // Only an explicit reviewed history request removes it from the ledger.
        if op.mode.forgets() {
            sqlx::query("UPDATE jobs SET history_removed=1 WHERE id=?")
                .bind(&op.job_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM job_group_members WHERE job_id=?")
                .bind(&op.job_id)
                .execute(&mut *tx)
                .await?;
            omd_store::emit(&mut tx, "groups.changed", &op.job_id).await?;
        }
        if op.mode == Mode::ForgetHistory {
            sqlx::query("UPDATE file_operation_entries SET state='retained' WHERE operation_id=?")
                .bind(&op.id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE file_operations SET state='complete',updated_at=? WHERE id=? AND state='working'").bind(now()).bind(&op.id).execute(&mut *tx).await?;
        sqlx::query("UPDATE destination_checks SET state='complete',updated_at=? WHERE id=? AND state IN ('working','paused') AND NOT EXISTS(SELECT 1 FROM file_operations WHERE destination_check=? AND state<>'complete')").bind(now()).bind(&op.destination_check).bind(&op.destination_check).execute(&mut *tx).await?;
        omd_store::emit(&mut tx, "storage.changed", &op.id).await?;
        omd_store::emit(&mut tx, "files.changed", &op.id).await?;
        omd_store::emit(&mut tx, "jobs.changed", &op.job_id).await?;
        tx.commit().await?;
        Ok(())
    }
}
fn inspect(
    root: &omd_files::Root,
    path: &str,
    expected: &(u64, String),
    cancel: &CancellationToken,
) -> Result<&'static str> {
    match root.read_file(path) {
        Ok(file) => Ok(if &hash_cancellable(file, cancel)? == expected {
            "present"
        } else {
            "modified"
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok("missing"),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData
            ) =>
        {
            Ok("detached")
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omd_domain::{Artifact, DuplicateBehavior, FileStatus, Plan};
    use omd_store::Store;
    use std::path::Path;
    async fn fixture(path: &Path) -> (Storage, String, String, Plan) {
        std::fs::create_dir_all(path.join("downloads")).unwrap();
        let store = Store::open(&path.join("db")).await.unwrap();
        let dest = store
            .add_destination("Files", &path.join("downloads"))
            .await
            .unwrap();
        let plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let (plan, _) = store
            .plan_intent(&plan, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        let (job, _) = store
            .enqueue(&plan, &dest.id, "initial", "initial", Some("group"))
            .await
            .unwrap();
        let root = store.destination_root(&dest.id).await.unwrap();
        let mut artifacts = vec![];
        for n in 0..3 {
            let path = format!("{}/file-{n}.txt", plan.final_relative_path);
            root.write_new(&path, format!("original-{n}").as_bytes())
                .unwrap();
            let (size, sha256) = root.hash(&path).unwrap();
            artifacts.push(Artifact {
                id: format!("artifact-{n}"),
                job_id: job.id.clone(),
                relative_path: path,
                size,
                sha256,
                media_type: "text/plain".into(),
                status: FileStatus::Present,
            });
        }
        root.write_new(
            &format!("{}/user-added.txt", plan.final_relative_path),
            b"user owned",
        )
        .unwrap();
        store.complete(&job.id, &artifacts).await.unwrap();
        (Storage { store }, job.id, dest.id, plan)
    }
    async fn finish(s: &Storage, id: &str) {
        for _ in 0..20 {
            let op = s.file_operation(id).await.unwrap();
            if op.state == "complete" {
                return;
            }
            s.step_file_operation(&op, &CancellationToken::new())
                .await
                .unwrap();
        }
        panic!("file operation did not finish")
    }
    #[tokio::test]
    async fn destination_check_freezes_more_than_200_acquisitions_and_recovers_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let (s, _, dest, plan) = fixture(temp.path()).await;
        let root = s.store.destination_root(&dest).await.unwrap();
        for n in 1..251 {
            let mut p = plan.clone();
            p.generation = 0;
            p.release.reference.id = format!("chapter-{n}");
            p.final_relative_path = format!("series/chapter-{n}");
            let (job, _) = s
                .store
                .enqueue(
                    &p,
                    &dest,
                    &format!("request-{n}"),
                    &format!("request-{n}"),
                    None,
                )
                .await
                .unwrap();
            let path = format!("{}/page.txt", job.plan.final_relative_path);
            root.write_new(&path, b"fixture").unwrap();
            let (size, sha256) = root.hash(&path).unwrap();
            s.store
                .complete(
                    &job.id,
                    &[Artifact {
                        id: format!("page-{n}"),
                        job_id: job.id.clone(),
                        relative_path: path,
                        size,
                        sha256,
                        media_type: "text/plain".into(),
                        status: FileStatus::Present,
                    }],
                )
                .await
                .unwrap();
        }
        sqlx::query("CREATE TRIGGER reject_check_entry BEFORE INSERT ON file_operation_entries BEGIN SELECT RAISE(ABORT,'fixture interruption'); END").execute(&s.store.pool).await.unwrap();
        assert!(s.create_destination_check(&dest).await.is_err());
        let partial:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM destination_checks)+(SELECT COUNT(*) FROM file_operations)+(SELECT COUNT(*) FROM file_operation_entries)").fetch_one(&s.store.pool).await.unwrap();
        assert_eq!(
            partial, 0,
            "A failed creation must leave no partial membership or journals"
        );
        sqlx::query("DROP TRIGGER reject_check_entry")
            .execute(&s.store.pool)
            .await
            .unwrap();
        let check = s.create_destination_check(&dest).await.unwrap();
        assert_eq!(check.jobs, 251);
        assert_eq!(check.files, 253);
        assert_eq!(
            s.create_destination_check(&dest).await.unwrap().id,
            check.id
        );
        assert!(
            s.file_operations("", None, 200)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        let mut cursor = None;
        let mut found = std::collections::HashSet::new();
        loop {
            let page = s
                .destination_check_files(&check.id, "", cursor.as_deref(), 100)
                .await
                .unwrap();
            for entry in page.items {
                assert!(found.insert(entry.artifact_id));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(found.len(), 253);
        for _ in 0..75 {
            let child = s.next_file_operation().await.unwrap().unwrap();
            s.step_file_operation(&child, &CancellationToken::new())
                .await
                .unwrap();
        }
        let saved = s.destination_check(&check.id).await.unwrap().checked;
        assert!(saved > 0);
        s.store.pool.close().await;
        drop(s);
        let s = Storage {
            store: Store::open(&temp.path().join("db")).await.unwrap(),
        };
        assert_eq!(s.destination_check(&check.id).await.unwrap().checked, saved);
        for _ in 0..600 {
            let Some(child) = s.next_file_operation().await.unwrap() else {
                break;
            };
            s.step_file_operation(&child, &CancellationToken::new())
                .await
                .unwrap();
        }
        let done = s.destination_check(&check.id).await.unwrap();
        assert_eq!(done.state, "complete");
        assert_eq!(done.present, 253);
        assert_eq!(done.completed_jobs, 251);
        assert_eq!(
            s.destination_check_files(&check.id, "file-1", None, 10)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        assert_ne!(
            s.create_destination_check(&dest).await.unwrap().id,
            check.id
        );
    }
    #[tokio::test]
    async fn destination_check_pause_cancel_and_offline_recovery_never_erase_file_state() {
        let temp = tempfile::tempdir().unwrap();
        let (s, job, dest, plan) = fixture(temp.path()).await;
        let check = s.create_destination_check(&dest).await.unwrap();
        let child = s.next_file_operation().await.unwrap().unwrap();
        s.destination_check_action(&check.id, "pause")
            .await
            .unwrap();
        assert!(s.next_file_operation().await.unwrap().is_none());
        assert!(matches!(
            s.file_action(&child.id, "retry").await,
            Err(Error::CheckState)
        ));
        s.step_file_operation(&child, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(s.destination_check(&check.id).await.unwrap().checked, 0);
        s.destination_check_action(&check.id, "resume")
            .await
            .unwrap();
        std::fs::rename(temp.path().join("downloads"), temp.path().join("offline")).unwrap();
        let error = s
            .step_file_operation(&child, &CancellationToken::new())
            .await
            .unwrap_err();
        s.fail_file_operation(&child.id, &error).await.unwrap();
        let blocked = s.destination_check(&check.id).await.unwrap();
        assert_eq!(blocked.checked, 0);
        assert_eq!(blocked.blocked_jobs, 1);
        assert!(
            s.store
                .artifacts(&job)
                .await
                .unwrap()
                .iter()
                .all(|a| matches!(a.status, FileStatus::Present))
        );
        std::fs::rename(temp.path().join("offline"), temp.path().join("downloads")).unwrap();
        s.destination_check_action(&check.id, "retry")
            .await
            .unwrap();
        std::fs::write(
            temp.path()
                .join("downloads")
                .join(&plan.final_relative_path)
                .join("file-1.txt"),
            b"user edit",
        )
        .unwrap();
        std::fs::remove_file(
            temp.path()
                .join("downloads")
                .join(&plan.final_relative_path)
                .join("file-2.txt"),
        )
        .unwrap();
        finish(&s, &child.id).await;
        let done = s.destination_check(&check.id).await.unwrap();
        assert_eq!((done.present, done.modified, done.missing), (1, 1, 1));
        assert_eq!(done.state, "complete");
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join("downloads")
                    .join(&plan.final_relative_path)
                    .join("user-added.txt")
            )
            .unwrap(),
            b"user owned"
        );
        let canceled = s.create_destination_check(&dest).await.unwrap();
        let stale = s.next_file_operation().await.unwrap().unwrap();
        s.destination_check_action(&canceled.id, "cancel")
            .await
            .unwrap();
        s.step_file_operation(&stale, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(
            s.destination_check(&canceled.id).await.unwrap().state,
            "canceled"
        );
        assert_eq!(s.destination_check(&canceled.id).await.unwrap().checked, 0);
    }
    #[tokio::test]
    async fn removal_recovers_each_checkpoint_preserves_edits_and_history() {
        for crash in 0..=7 {
            let temp = tempfile::tempdir().unwrap();
            let (s, job, dest, plan) = fixture(temp.path()).await;
            let root = s.store.destination_root(&dest).await.unwrap();
            std::fs::write(
                temp.path()
                    .join("downloads")
                    .join(&plan.final_relative_path)
                    .join("file-1.txt"),
                b"user edit",
            )
            .unwrap();
            let op = s
                .create_file_operation(&job, Mode::RemoveFiles)
                .await
                .unwrap();
            assert_eq!(op.state, "ready");
            assert!(
                root.read_file(&format!("{}/file-0.txt", plan.final_relative_path))
                    .is_ok()
            );
            assert!(
                s.create_file_operation(&job, Mode::Reconcile)
                    .await
                    .is_err()
            );
            assert!(
                s.store
                    .plan_intent(&plan, &dest, DuplicateBehavior::SkipSatisfied)
                    .await
                    .is_err()
            );
            s.file_action(&op.id, "start").await.unwrap();
            for _ in 0..crash {
                let state = s.file_operation(&op.id).await.unwrap();
                if state.state == "complete" {
                    break;
                }
                s.step_file_operation(&state, &CancellationToken::new())
                    .await
                    .unwrap();
            }
            s.store.pool.close().await;
            drop(s);
            let s = Storage {
                store: Store::open(&temp.path().join("db")).await.unwrap(),
            };
            finish(&s, &op.id).await;
            let op = s.file_operation(&op.id).await.unwrap();
            assert_eq!(op.retained, 1);
            assert_eq!(op.processed, 3);
            assert!(
                root.read_file(&format!("{}/file-0.txt", plan.final_relative_path))
                    .is_err()
            );
            assert_eq!(
                std::fs::read(
                    temp.path()
                        .join("downloads")
                        .join(&plan.final_relative_path)
                        .join("file-1.txt")
                )
                .unwrap(),
                b"user edit"
            );
            assert!(
                root.read_file(&format!("{}/user-added.txt", plan.final_relative_path))
                    .is_ok()
            );
            assert!(!s.store.history_removed(&job).await.unwrap());
            let (again, outcome) = s
                .store
                .plan_intent(&plan, &dest, DuplicateBehavior::SkipSatisfied)
                .await
                .unwrap();
            assert_eq!(outcome, "new_version");
            assert_eq!(again.generation, 2);
        }
    }
    #[tokio::test]
    async fn deletion_before_sql_never_picks_up_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let (s, job, dest, plan) = fixture(temp.path()).await;
        let op = s
            .create_file_operation(&job, Mode::RemoveFiles)
            .await
            .unwrap();
        s.file_action(&op.id, "start").await.unwrap();
        let op = s.file_operation(&op.id).await.unwrap();
        s.step_file_operation(&op, &CancellationToken::new())
            .await
            .unwrap();
        let root = s.store.destination_root(&dest).await.unwrap();
        let stage = owned_directory(&root, &format!(".omd-remove-{}", op.id), &op.id).unwrap();
        stage.remove_file("artifact-0").unwrap(); // deletion succeeded; its SQL checkpoint did not
        drop(stage);
        root.write_new(
            &format!("{}/file-0.txt", plan.final_relative_path),
            b"replacement",
        )
        .unwrap();
        finish(&s, &op.id).await;
        assert_eq!(
            std::fs::read(
                temp.path()
                    .join("downloads")
                    .join(plan.final_relative_path)
                    .join("file-0.txt")
            )
            .unwrap(),
            b"replacement"
        );
    }
    #[tokio::test]
    async fn rename_before_sql_and_edits_while_held_are_recovered() {
        let temp = tempfile::tempdir().unwrap();
        let (s, job, dest, plan) = fixture(temp.path()).await;
        let op = s
            .create_file_operation(&job, Mode::RemoveFiles)
            .await
            .unwrap();
        s.file_action(&op.id, "start").await.unwrap();
        let root = s.store.destination_root(&dest).await.unwrap();
        let stage = owned_directory(&root, &format!(".omd-remove-{}", op.id), &op.id).unwrap();
        let original = format!("{}/file-0.txt", plan.final_relative_path);
        root.publish(&original, &stage, "artifact-0").unwrap(); // rename succeeded; state is still pending
        std::fs::write(
            temp.path()
                .join("downloads")
                .join(format!(".omd-remove-{}", op.id))
                .join("artifact-0"),
            b"edited while held",
        )
        .unwrap();
        root.write_new(&original, b"new original").unwrap();
        drop(stage);
        finish(&s, &op.id).await;
        assert_eq!(s.file_operation(&op.id).await.unwrap().retained, 1);
        assert_eq!(
            root.hash(&original).unwrap().1,
            omd_domain::digest(b"new original")
        );
        assert_eq!(
            root.directory(&format!(".omd-remove-{}", op.id))
                .unwrap()
                .hash("artifact-0")
                .unwrap()
                .1,
            omd_domain::digest(b"edited while held")
        );
    }
    #[tokio::test]
    async fn reconciliation_and_forgetting_do_not_delete_files_or_reuse_versions() {
        let temp = tempfile::tempdir().unwrap();
        let (s, job, dest, plan) = fixture(temp.path()).await;
        let root = s.store.destination_root(&dest).await.unwrap();
        root.remove_file(&format!("{}/file-2.txt", plan.final_relative_path))
            .unwrap();
        let op = s
            .create_file_operation(&job, Mode::Reconcile)
            .await
            .unwrap();
        finish(&s, &op.id).await;
        let entries = s
            .file_operation_entries(&op.id, "file-", None, 2)
            .await
            .unwrap();
        assert!(entries.next_cursor.is_some());
        assert_eq!(
            s.file_operation_entries(&op.id, "file-", entries.next_cursor.as_deref(), 2)
                .await
                .unwrap()
                .items[0]
                .state,
            "missing"
        );
        let op = s
            .create_file_operation(&job, Mode::ForgetHistory)
            .await
            .unwrap();
        s.file_action(&op.id, "start").await.unwrap();
        finish(&s, &op.id).await;
        assert!(
            s.store
                .jobs("", None, None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        assert!(
            s.store
                .job_groups("", None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        assert!(
            root.read_file(&format!("{}/file-0.txt", plan.final_relative_path))
                .is_ok()
        );
        let (again, _) = s
            .store
            .plan_intent(&plan, &dest, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(again.generation, 2);
        // Historical idempotency still returns its original resource, and cannot enqueue again.
        let (replayed, created) = s
            .store
            .enqueue(&plan, &dest, "initial", "initial", None)
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(replayed.id, job);
    }
    #[tokio::test]
    async fn unavailable_destination_is_not_missing_and_review_can_be_canceled() {
        let temp = tempfile::tempdir().unwrap();
        let (s, job, _dest, plan) = fixture(temp.path()).await;
        let op = s
            .create_file_operation(&job, Mode::RemoveFilesAndHistory)
            .await
            .unwrap();
        s.file_action(&op.id, "cancel").await.unwrap();
        assert!(!s.store.history_removed(&job).await.unwrap());
        let op = s
            .create_file_operation(&job, Mode::Reconcile)
            .await
            .unwrap();
        std::fs::rename(
            temp.path().join("downloads"),
            temp.path().join("disconnected"),
        )
        .unwrap();
        assert!(
            s.step_file_operation(&op, &CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(s.file_operation(&op.id).await.unwrap().processed, 0);
        std::fs::rename(
            temp.path().join("disconnected"),
            temp.path().join("downloads"),
        )
        .unwrap();
        finish(&s, &op.id).await;
        let op = s
            .create_file_operation(&job, Mode::RemoveFilesAndHistory)
            .await
            .unwrap();
        s.file_action(&op.id, "start").await.unwrap();
        finish(&s, &op.id).await;
        assert!(s.store.history_removed(&job).await.unwrap());
        assert!(
            !temp
                .path()
                .join("downloads")
                .join(&plan.final_relative_path)
                .join("file-0.txt")
                .exists()
        );
        assert!(
            temp.path()
                .join("downloads")
                .join(plan.final_relative_path)
                .join("user-added.txt")
                .exists()
        );
    }
}
