//! Journaled destination relocation. Only inventoried owned trees are copied;
//! cleanup quarantines each original before checking its identity and deleting it.
pub mod checks;
pub mod maintenance;
use omd_domain::{Page, Problem, digest};
use omd_files::Root;
use omd_store::{Store, id, now};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    io::{Read, Seek, Write},
    path::Path,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Finish or cancel the existing file or relocation operation before checking this destination"
    )]
    CheckBusy,
    #[error("Use the destination check controls to manage this file check")]
    CheckState,
    #[error(transparent)]
    Store(#[from] omd_store::StoreError),
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("The filesystem is unavailable or changed during relocation")]
    Io(#[from] std::io::Error),
    #[error("The relocation state changed; refresh its progress")]
    State,
    #[error("A file changed after inventory; review the source files before retrying")]
    Changed,
    #[error("An unrelated path occupies the relocation destination")]
    Collision,
    #[error("Relocation paused at a safe checkpoint")]
    Canceled,
}
type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn problem(&self) -> Problem {
        let (code, action) = match self {
            Self::CheckBusy => ("destination_check_busy", "review_storage_operations"),
            Self::CheckState => ("destination_check_state", "refresh_destination_check"),
            Self::Changed => ("relocation_source_changed", "review_source_files"),
            Self::Collision => ("relocation_collision", "choose_destination"),
            Self::Canceled => ("relocation_paused", "retry_relocation"),
            Self::Io(_) => ("relocation_storage_unavailable", "reconnect_destination"),
            _ => ("relocation_state", "refresh_relocation"),
        };
        let mut issue = Problem::new(code, self.to_string());
        issue.actions = vec![action.into()];
        issue
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "Relocation")]
pub struct Operation {
    pub id: String,
    pub destination_id: String,
    pub source_root: String,
    pub source_marker: String,
    pub target_root: String,
    pub target_marker: String,
    pub state: String,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
    pub files: i64,
    pub bytes: i64,
    pub copied: i64,
    pub retained: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "RelocationFile")]
pub struct FileEntry {
    pub root_path: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub state: String,
}
fn operation(row: sqlx::sqlite::SqliteRow) -> Result<Operation> {
    Ok(Operation {
        id: row.get("id"),
        destination_id: row.get("destination_id"),
        source_root: row.get("source_root"),
        source_marker: row.get("source_marker"),
        target_root: row.get("target_root"),
        target_marker: row.get("target_marker"),
        state: row.get("state"),
        issue: row
            .get::<Option<String>, _>("issue_json")
            .map(|v| serde_json::from_str(&v))
            .transpose()?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        files: row.get("files"),
        bytes: row.get("bytes"),
        copied: row.get("copied"),
        retained: row.get("retained"),
    })
}
const OP_QUERY: &str = "SELECT o.*,(SELECT COUNT(*) FROM storage_entries e WHERE e.operation_id=o.id AND e.kind='file') AS files,(SELECT COALESCE(SUM(size),0) FROM storage_entries e WHERE e.operation_id=o.id AND e.kind='file') AS bytes,(SELECT COUNT(*) FROM storage_entries e WHERE e.operation_id=o.id AND e.kind='file' AND e.state<>'pending') AS copied,(SELECT COUNT(*) FROM storage_entries e WHERE e.operation_id=o.id AND e.state='retained')+(SELECT COUNT(*) FROM storage_roots r WHERE r.operation_id=o.id AND r.state='retained') AS retained FROM storage_operations o";
#[derive(Clone)]
pub struct Storage {
    pub store: Store,
}
async fn event(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, kind: &str, id: &str) -> Result<()> {
    omd_store::emit(tx, kind, id).await?;
    Ok(())
}
fn stopped(cancel: &CancellationToken) -> Result<()> {
    if cancel.is_cancelled() {
        Err(Error::Canceled)
    } else {
        Ok(())
    }
}
impl Storage {
    pub async fn operation(&self, id: &str) -> Result<Operation> {
        let sql = format!("{OP_QUERY} WHERE o.id=?");
        operation(
            sqlx::query(&sql)
                .bind(id)
                .fetch_optional(&self.store.pool)
                .await?
                .ok_or(omd_store::StoreError::NotFound)?,
        )
    }
    pub async fn operations(
        &self,
        cursor: Option<&str>,
        query: &str,
        limit: u32,
    ) -> Result<Page<Operation>> {
        let limit = limit.clamp(1, 200) as usize;
        let sql = format!(
            "{OP_QUERY} WHERE (? IS NULL OR o.created_at || ':' || o.id < ?) AND instr(lower(o.source_root || ' ' || o.target_root),lower(?))>0 ORDER BY o.created_at DESC,o.id DESC LIMIT ?"
        );
        let rows = sqlx::query(&sql)
            .bind(cursor)
            .bind(cursor)
            .bind(query)
            .bind((limit + 1) as i64)
            .fetch_all(&self.store.pool)
            .await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(operation)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if more {
            items.last().map(|o| format!("{}:{}", o.created_at, o.id))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn entries(
        &self,
        id: &str,
        cursor: Option<&str>,
        query: &str,
        limit: u32,
    ) -> Result<Page<FileEntry>> {
        self.operation(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT * FROM storage_entries WHERE operation_id=? AND (? IS NULL OR root_path || '/' || path > ?) AND instr(lower(root_path || '/' || path),lower(?))>0 ORDER BY root_path || '/' || path LIMIT ?")
            .bind(id).bind(cursor).bind(cursor).bind(query).bind((limit+1) as i64).fetch_all(&self.store.pool).await?;
        let more = rows.len() > limit;
        let items: Vec<_> = rows
            .into_iter()
            .take(limit)
            .map(|r| FileEntry {
                root_path: r.get("root_path"),
                path: r.get("path"),
                kind: r.get("kind"),
                size: r.get::<i64, _>("size") as u64,
                sha256: r.get("sha256"),
                state: r.get("state"),
            })
            .collect();
        let next_cursor = if more {
            items.last().map(|e| format!("{}/{}", e.root_path, e.path))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn create(&self, destination: &str, target: &Path) -> Result<Operation> {
        let target = std::fs::canonicalize(target)?;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query("SELECT * FROM destinations WHERE id=?")
            .bind(destination)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(omd_store::StoreError::NotFound)?;
        if row.get::<Option<String>, _>("storage_operation").is_some() {
            return Err(Error::State);
        }
        let unfinished:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM storage_operations WHERE destination_id=? AND state NOT IN ('complete','canceled'))").bind(destination).fetch_one(&mut *tx).await?;
        if unfinished {
            return Err(Error::State);
        }
        let source: String = row.get("root");
        let source_marker: String = row.get::<Option<String>, _>("marker").ok_or(Error::State)?;
        Root::identified(Path::new(&source), &source_marker)?;
        if target.starts_with(&source)
            || Path::new(&source).starts_with(&target)
            || target
                .ancestors()
                .any(|ancestor| Root::identified(ancestor, &source_marker).is_ok())
        {
            return Err(Error::Collision);
        }
        let registered: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM destinations WHERE root=?)")
                .bind(target.to_string_lossy().as_ref())
                .fetch_one(&mut *tx)
                .await?;
        if registered {
            return Err(Error::Collision);
        }
        let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM file_operations o JOIN jobs j ON j.id=o.job_id WHERE j.destination_id=? AND o.state IN ('ready','working'))").bind(destination).fetch_one(&mut *tx).await?;
        if busy {
            return Err(Error::State);
        }
        let operation_id = id("relocation");
        let marker = uuid::Uuid::new_v4().simple().to_string();
        sqlx::query("INSERT INTO storage_operations VALUES(?,?,?,?,?,?,'scanning',NULL,?,?)")
            .bind(&operation_id)
            .bind(destination)
            .bind(&source)
            .bind(&source_marker)
            .bind(target.to_string_lossy().as_ref())
            .bind(&marker)
            .bind(now())
            .bind(now())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO storage_roots SELECT ?,json_extract(plan_json,'$.final_relative_path'),0,'pending' FROM jobs WHERE destination_id=? AND history_removed=0").bind(&operation_id).bind(destination).execute(&mut *tx).await?;
        sqlx::query("INSERT OR IGNORE INTO storage_roots SELECT ?,'.omd-stage-v2-' || id,1,'pending' FROM jobs WHERE destination_id=? AND history_removed=0").bind(&operation_id).bind(destination).execute(&mut *tx).await?;
        sqlx::query("UPDATE destinations SET storage_operation=? WHERE id=?")
            .bind(&operation_id)
            .bind(destination)
            .execute(&mut *tx)
            .await?;
        // Establish filesystem identity before accepting a reviewable location.
        // A failed database commit can leave only this unique inert marker.
        let registered_target = Root::register(&target, &marker)?;
        // Marker ancestry detects aliases/case variants on Windows and macOS,
        // where lexical path comparisons alone do not establish containment.
        if Path::new(&source)
            .ancestors()
            .any(|ancestor| Root::identified(ancestor, &marker).is_ok())
        {
            registered_target.remove_file(&format!(".omd-destination-{marker}"))?;
            return Err(Error::Collision);
        }
        event(&mut tx, "storage.changed", &operation_id).await?;
        event(&mut tx, "destinations.changed", destination).await?;
        tx.commit().await?;
        self.operation(&operation_id).await
    }
    pub async fn action(&self, id: &str, action: &str) -> Result<Operation> {
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query("SELECT state,destination_id FROM storage_operations WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(omd_store::StoreError::NotFound)?;
        let state: String = row.get("state");
        let destination: String = row.get("destination_id");
        let next = match action {
            "start" if state == "ready" => "copying",
            "retry"
                if ["scanning", "copying", "publishing", "cleanup"].contains(&state.as_str()) =>
            {
                &state
            }
            "cancel"
                if ["scanning", "ready", "copying", "publishing"].contains(&state.as_str()) =>
            {
                "canceled"
            }
            _ => return Err(Error::State),
        };
        sqlx::query(
            "UPDATE storage_operations SET state=?,issue_json=NULL,updated_at=? WHERE id=?",
        )
        .bind(next)
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if next == "canceled" {
            sqlx::query(
                "UPDATE destinations SET storage_operation=NULL WHERE id=? AND storage_operation=?",
            )
            .bind(&destination)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            event(&mut tx, "destinations.changed", &destination).await?;
        }
        event(&mut tx, "storage.changed", id).await?;
        tx.commit().await?;
        self.operation(id).await
    }
    pub async fn next(&self) -> Result<Option<Operation>> {
        let sql = format!(
            "{OP_QUERY} WHERE o.state IN ('scanning','copying','publishing','cleanup') AND o.issue_json IS NULL ORDER BY o.updated_at,o.id LIMIT 1"
        );
        sqlx::query(&sql)
            .fetch_optional(&self.store.pool)
            .await?
            .map(operation)
            .transpose()
    }
    pub async fn fail(&self, op: &Operation, error: &Error) -> Result<()> {
        let mut tx = self.store.pool.begin().await?;
        sqlx::query(
            "UPDATE storage_operations SET issue_json=?,updated_at=? WHERE id=? AND state=?",
        )
        .bind(serde_json::to_string(&error.problem())?)
        .bind(now())
        .bind(&op.id)
        .bind(&op.state)
        .execute(&mut *tx)
        .await?;
        event(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn phase(&self, op: &Operation, next: &str) -> Result<()> {
        let mut tx = self.store.pool.begin().await?;
        let changed=sqlx::query("UPDATE storage_operations SET state=?,updated_at=? WHERE id=? AND state=? AND issue_json IS NULL").bind(next).bind(now()).bind(&op.id).bind(&op.state).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(Error::State);
        }
        event(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn step(&self, op: &Operation, cancel: &CancellationToken) -> Result<()> {
        stopped(cancel)?;
        match op.state.as_str() {
            "scanning" => self.scan(op, cancel).await,
            "copying" => self.copy(op, cancel).await,
            "publishing" => self.publish(op, cancel).await,
            "cleanup" => self.cleanup(op, cancel).await,
            _ => Err(Error::State),
        }
    }
    async fn scan(&self, op: &Operation, cancel: &CancellationToken) -> Result<()> {
        let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM jobs WHERE destination_id=? AND state IN ('transferring','verifying','publishing','resolving'))").bind(&op.destination_id).fetch_one(&self.store.pool).await?;
        if active {
            return Ok(());
        }
        let path:Option<String>=sqlx::query_scalar("SELECT path FROM storage_roots WHERE operation_id=? AND state='pending' ORDER BY path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        let Some(path) = path else {
            return self.phase(op, "ready").await;
        };
        let target = Root::identified(Path::new(&op.target_root), &op.target_marker)?;
        match target.directory(&path) {
            Ok(_) => return Err(Error::Collision),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let source = Root::identified(Path::new(&op.source_root), &op.source_marker)?;
        let tree = match source.directory(&path) {
            Ok(r) => Some(r),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let existed = tree.is_some();
        let stop = cancel.clone();
        let relative = path.clone();
        let entries = tokio::task::spawn_blocking(move || -> Result<Vec<FileEntry>> {
            let Some(root) = tree else {
                return Ok(vec![]);
            };
            let mut result = vec![];
            let mut folders = vec![String::new()];
            while let Some(folder) = folders.pop() {
                stopped(&stop)?;
                let dir = if folder.is_empty() {
                    root.try_clone()?
                } else {
                    root.directory(&folder)?
                };
                for entry in dir.entries()? {
                    stopped(&stop)?;
                    let entry = entry?;
                    let name = if folder.is_empty() {
                        entry.name
                    } else {
                        format!("{folder}/{}", entry.name)
                    };
                    let (kind, size, hash) = if entry.directory {
                        folders.push(name.clone());
                        ("directory", 0, String::new())
                    } else {
                        let (size, hash) = hash_cancellable(root.read_file(&name)?, &stop)?;
                        ("file", size, hash)
                    };
                    result.push(FileEntry {
                        root_path: relative.clone(),
                        path: name,
                        kind: kind.into(),
                        size,
                        sha256: hash,
                        state: "pending".into(),
                    });
                }
            }
            Ok(result)
        })
        .await
        .map_err(|_| Error::State)??;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let state: String = sqlx::query_scalar("SELECT state FROM storage_operations WHERE id=?")
            .bind(&op.id)
            .fetch_one(&mut *tx)
            .await?;
        if state != "scanning" {
            return Err(Error::State);
        }
        sqlx::query("DELETE FROM storage_entries WHERE operation_id=? AND root_path=?")
            .bind(&op.id)
            .bind(&path)
            .execute(&mut *tx)
            .await?;
        for entry in &entries {
            sqlx::query("INSERT INTO storage_entries VALUES(?,?,?,?,?,?,?)")
                .bind(&op.id)
                .bind(&path)
                .bind(&entry.path)
                .bind(&entry.kind)
                .bind(entry.size as i64)
                .bind(&entry.sha256)
                .bind("pending")
                .execute(&mut *tx)
                .await?;
        }
        // An empty but existing root is preserved; a missing one stays missing.
        if existed && source.directory(&path).is_err() {
            return Err(Error::Changed);
        }
        let exists = existed;
        sqlx::query("UPDATE storage_roots SET state=? WHERE operation_id=? AND path=?")
            .bind(if exists { "inventoried" } else { "missing" })
            .bind(&op.id)
            .bind(&path)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE storage_operations SET updated_at=? WHERE id=?")
            .bind(now())
            .bind(&op.id)
            .execute(&mut *tx)
            .await?;
        event(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn copy(&self, op: &Operation, cancel: &CancellationToken) -> Result<()> {
        let path:Option<String>=sqlx::query_scalar("SELECT path FROM storage_roots WHERE operation_id=? AND state='inventoried' ORDER BY path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        let Some(path) = path else {
            return self.phase(op, "publishing").await;
        };
        let target = Root::identified(Path::new(&op.target_root), &op.target_marker)?;
        let stage = owned_directory(&target, &stage_name(op), &op.id)?;
        let tree = owned_directory(&stage, &digest(path.as_bytes()), &op.id)?;
        let row=sqlx::query("SELECT * FROM storage_entries WHERE operation_id=? AND root_path=? AND state='pending' ORDER BY CASE kind WHEN 'directory' THEN 0 ELSE 1 END,length(path),path LIMIT 1").bind(&op.id).bind(&path).fetch_optional(&self.store.pool).await?;
        if let Some(row) = row {
            let relative: String = row.get("path");
            let kind: String = row.get("kind");
            let size = row.get::<i64, _>("size") as u64;
            let hash: String = row.get("sha256");
            if relative == OWNER {
                return Err(Error::Collision);
            }
            if kind == "directory" {
                match tree.create_directory(&relative, true) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        tree.directory(&relative)?;
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                let source = Root::identified(Path::new(&op.source_root), &op.source_marker)?
                    .directory(&path)?;
                let stop = cancel.clone();
                let name = relative.clone();
                tokio::task::spawn_blocking(move || {
                    copy_file(&source, &tree, &name, size, &hash, &stop)
                })
                .await
                .map_err(|_| Error::State)??;
            }
            self.entry_state(op, &path, &relative, "copied").await?;
        } else {
            let entries = self.root_entries(op, &path).await?;
            let stop = cancel.clone();
            tokio::task::spawn_blocking(move || verify_tree(&tree, &entries, &stop))
                .await
                .map_err(|_| Error::State)??;
            self.root_state(op, &path, "verified").await?;
        }
        Ok(())
    }
    async fn publish(&self, op: &Operation, cancel: &CancellationToken) -> Result<()> {
        let path:Option<String>=sqlx::query_scalar("SELECT path FROM storage_roots WHERE operation_id=? AND state='verified' ORDER BY path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        let target = Root::identified(Path::new(&op.target_root), &op.target_marker)?;
        if let Some(path) = path {
            let stage = owned_directory(&target, &stage_name(op), &op.id)?;
            let entries = self.root_entries(op, &path).await?;
            let stop = cancel.clone();
            let operation = op.id.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                // A journaled publish can have succeeded before its SQL update.
                match target.directory(&path) {
                    Ok(existing) => {
                        check_owner(&existing, &operation)?;
                        verify_tree(&existing, &entries, &stop)?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let tree = stage.directory(&digest(path.as_bytes()))?;
                        check_owner(&tree, &operation)?;
                        verify_tree(&tree, &entries, &stop)?;
                        stopped(&stop)?;
                        drop(tree);
                        stage
                            .publish(&digest(path.as_bytes()), &target, &path)
                            .map_err(|e| {
                                if e.kind() == std::io::ErrorKind::AlreadyExists {
                                    Error::Collision
                                } else {
                                    e.into()
                                }
                            })?;
                    }
                    Err(e) => return Err(e.into()),
                }
                Ok(())
            })
            .await
            .map_err(|_| Error::State)??;
            // Recover the path from the selected row, independently of the owned
            // closure's move, before updating its durable publication state.
            let path:String=sqlx::query_scalar("SELECT path FROM storage_roots WHERE operation_id=? AND state='verified' ORDER BY path LIMIT 1").bind(&op.id).fetch_one(&self.store.pool).await?;
            self.root_state(op, &path, "published").await?;
        } else {
            // Switching location and enabling dependent jobs is one transaction.
            let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
            let changed=sqlx::query("UPDATE destinations SET root=?,marker=?,storage_operation=NULL WHERE id=? AND root=? AND storage_operation=?")
                .bind(&op.target_root).bind(&op.target_marker).bind(&op.destination_id).bind(&op.source_root).bind(&op.id).execute(&mut *tx).await?.rows_affected();
            if changed != 1 {
                return Err(Error::State);
            }
            sqlx::query("UPDATE storage_operations SET state='cleanup',updated_at=? WHERE id=? AND state='publishing'").bind(now()).bind(&op.id).execute(&mut *tx).await?;
            event(&mut tx, "destinations.changed", &op.destination_id).await?;
            event(&mut tx, "storage.changed", &op.id).await?;
            tx.commit().await?;
        }
        Ok(())
    }
    async fn cleanup(&self, op: &Operation, cancel: &CancellationToken) -> Result<()> {
        let source = Root::identified(Path::new(&op.source_root), &op.source_marker)?;
        let quarantine = owned_directory(&source, &stage_name(op), &op.id)?;
        let row=sqlx::query("SELECT * FROM storage_entries WHERE operation_id=? AND kind='file' AND state='copied' ORDER BY root_path,path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        if let Some(row) = row {
            let root: String = row.get("root_path");
            let path: String = row.get("path");
            let expected = (
                row.get::<i64, _>("size") as u64,
                row.get::<String, _>("sha256"),
            );
            let full = format!("{root}/{path}");
            let held = digest(full.as_bytes());
            let stop = cancel.clone();
            let state = tokio::task::spawn_blocking(move || -> Result<&'static str> {
                stopped(&stop)?;
                // Move first, then verify in a private quarantine. A replacement
                // at the old pathname cannot be deleted by a stale hash check.
                match source.publish(&full, &quarantine, &held) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        if quarantine.read_file(&held).is_err() {
                            return Ok("cleaned");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
                let file = match quarantine.read_file(&held) {
                    Ok(file) => file,
                    Err(error) => {
                        // A replacement may be a symlink or special file. Restore
                        // it instead of treating it as an owned ordinary file.
                        match quarantine.publish(&held, &source, &full) {
                            Ok(()) => return Ok("retained"),
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                return Ok("retained");
                            }
                            Err(_) => return Err(error.into()),
                        }
                    }
                };
                let actual = hash_cancellable(file, &stop)?;
                if actual == expected {
                    quarantine.remove_file(&held)?;
                    Ok("cleaned")
                } else {
                    // If a new file occupies the original path, keep both. The
                    // retained counter exposes this private recovery location.
                    match quarantine.publish(&held, &source, &full) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                    }
                    Ok("retained")
                }
            })
            .await
            .map_err(|_| Error::State)??;
            self.entry_state(op, &root, &path, state).await?;
            return Ok(());
        }
        let path:Option<String>=sqlx::query_scalar("SELECT path FROM storage_roots WHERE operation_id=? AND state='published' ORDER BY path LIMIT 1").bind(&op.id).fetch_optional(&self.store.pool).await?;
        if let Some(path) = path {
            let dirs:Vec<String>=sqlx::query_scalar("SELECT path FROM storage_entries WHERE operation_id=? AND root_path=? AND kind='directory' ORDER BY length(path) DESC,path DESC").bind(&op.id).bind(&path).fetch_all(&self.store.pool).await?;
            let target = Root::identified(Path::new(&op.target_root), &op.target_marker)?;
            // Remove only our own marker from the published copy; new user files
            // and all original artifacts remain untouched at the active location.
            let tree = target.directory(&path)?;
            if check_owner(&tree, &op.id).is_ok() {
                tree.remove_file(OWNER)?;
            }
            let mut retained = false;
            for dir in dirs {
                match source.remove_empty_directory(&format!("{path}/{dir}")) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => retained = true,
                    Err(e) => return Err(e.into()),
                }
            }
            match source.remove_empty_directory(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => retained = true,
                Err(e) => return Err(e.into()),
            }
            self.root_state(op, &path, if retained { "retained" } else { "cleaned" })
                .await?;
        } else {
            // Quarantine may contain a user-modified file whose original pathname
            // was replaced. Keep that recovery directory when it is nonempty.
            drop(quarantine);
            if op.retained == 0 {
                cleanup_owner_directory(&source, &stage_name(op), &op.id)?;
            }
            let target = Root::identified(Path::new(&op.target_root), &op.target_marker)?;
            cleanup_owner_directory(&target, &stage_name(op), &op.id)?;
            self.phase(op, "complete").await?;
        }
        Ok(())
    }
    async fn root_entries(&self, op: &Operation, path: &str) -> Result<Vec<FileEntry>> {
        let rows = sqlx::query(
            "SELECT * FROM storage_entries WHERE operation_id=? AND root_path=? ORDER BY path",
        )
        .bind(&op.id)
        .bind(path)
        .fetch_all(&self.store.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| FileEntry {
                root_path: r.get("root_path"),
                path: r.get("path"),
                kind: r.get("kind"),
                size: r.get::<i64, _>("size") as u64,
                sha256: r.get("sha256"),
                state: r.get("state"),
            })
            .collect())
    }
    async fn root_state(&self, op: &Operation, path: &str, state: &str) -> Result<()> {
        let mut tx = self.store.pool.begin().await?;
        sqlx::query("UPDATE storage_roots SET state=? WHERE operation_id=? AND path=?")
            .bind(state)
            .bind(&op.id)
            .bind(path)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE storage_operations SET updated_at=? WHERE id=?")
            .bind(now())
            .bind(&op.id)
            .execute(&mut *tx)
            .await?;
        event(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn entry_state(&self, op: &Operation, root: &str, path: &str, state: &str) -> Result<()> {
        let mut tx = self.store.pool.begin().await?;
        sqlx::query(
            "UPDATE storage_entries SET state=? WHERE operation_id=? AND root_path=? AND path=?",
        )
        .bind(state)
        .bind(&op.id)
        .bind(root)
        .bind(path)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE storage_operations SET updated_at=? WHERE id=?")
            .bind(now())
            .bind(&op.id)
            .execute(&mut *tx)
            .await?;
        event(&mut tx, "storage.changed", &op.id).await?;
        tx.commit().await?;
        Ok(())
    }
}
const OWNER: &str = ".omd-relocation-owner";
fn stage_name(op: &Operation) -> String {
    format!(".omd-relocate-{}", op.id)
}
fn check_owner(root: &Root, owner: &str) -> Result<()> {
    let mut bytes = vec![];
    root.read_file(OWNER)?.take(256).read_to_end(&mut bytes)?;
    if bytes != owner.as_bytes() {
        return Err(Error::Collision);
    }
    Ok(())
}
fn owned_directory(root: &Root, path: &str, owner: &str) -> Result<Root> {
    let dir = match root.create_directory(path, true) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let dir = root.directory(path)?;
            // The unique, journaled directory may be empty after interruption between
            // mkdir and writing its marker. Never adopt a nonempty unmarked tree.
            if dir.entries()?.next().is_none() {
                dir.write_new(OWNER, owner.as_bytes())?;
            }
            check_owner(&dir, owner)?;
            return Ok(dir);
        }
        Err(e) => return Err(e.into()),
    };
    dir.write_new(OWNER, owner.as_bytes())?;
    Ok(dir)
}
fn cleanup_owner_directory(root: &Root, path: &str, owner: &str) -> Result<()> {
    let dir = match root.directory(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let entries = dir.entries()?.collect::<std::io::Result<Vec<_>>>()?;
    if entries.is_empty() {
        drop(dir);
        root.remove_empty_directory(path)?;
        return Ok(());
    }
    check_owner(&dir, owner)?;
    if entries.len() == 1 && entries[0].name == OWNER {
        dir.remove_file(OWNER)?;
        drop(dir);
        root.remove_empty_directory(path)?;
    }
    Ok(())
}
fn hash_cancellable(mut file: std::fs::File, cancel: &CancellationToken) -> Result<(u64, String)> {
    let mut hash = Sha256::new();
    let mut size = 0;
    let mut buffer = [0u8; 65536];
    loop {
        stopped(cancel)?;
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size += count as u64;
    }
    Ok((size, hex::encode(hash.finalize())))
}
fn copy_file(
    source: &Root,
    target: &Root,
    path: &str,
    size: u64,
    expected: &str,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut input = source.read_file(path)?;
    let mut output = match target.create_new(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => target.open_resume(path)?,
        Err(e) => return Err(e.into()),
    };
    let existing = output.metadata()?.len();
    // Compare saved partial bytes with the current source before reusing them.
    let mut prefix = target.read_file(path)?;
    let mut a = [0u8; 65536];
    let mut b = [0u8; 65536];
    let mut position = 0;
    while position < existing {
        stopped(cancel)?;
        let count = ((existing - position) as usize).min(a.len());
        if input.read_exact(&mut a[..count]).is_err()
            || prefix.read_exact(&mut b[..count]).is_err()
            || a[..count] != b[..count]
        {
            position = 0;
            break;
        }
        position += count as u64;
    }
    output.set_len(position)?;
    output.seek(std::io::SeekFrom::Start(position))?;
    input.seek(std::io::SeekFrom::Start(position))?;
    loop {
        stopped(cancel)?;
        let n = input.read(&mut a)?;
        if n == 0 {
            break;
        }
        output.write_all(&a[..n])?;
    }
    output.sync_all()?;
    target.sync()?;
    let actual = hash_cancellable(target.read_file(path)?, cancel)?;
    if actual != (size, expected.to_owned()) {
        return Err(Error::Changed);
    }
    Ok(())
}
fn verify_tree(root: &Root, entries: &[FileEntry], cancel: &CancellationToken) -> Result<()> {
    for entry in entries {
        stopped(cancel)?;
        if entry.kind == "directory" {
            root.directory(&entry.path)?;
        } else if hash_cancellable(root.read_file(&entry.path)?, cancel)?
            != (entry.size, entry.sha256.clone())
        {
            return Err(Error::Changed);
        }
    }
    root.sync()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omd_domain::{Artifact, FileStatus, Plan};
    async fn setup() -> (tempfile::TempDir, Storage, String, String, String) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("unrelated.txt"), b"keep target").unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Manga", &source).await.unwrap();
        let plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let (job, _) = store
            .enqueue(&plan, &dest.id, "original", "original", None)
            .await
            .unwrap();
        let root = store.destination_root(&dest.id).await.unwrap();
        let path = format!("{}/chapter.cbz", job.plan.final_relative_path);
        root.write_new(&path, b"saved chapter").unwrap();
        root.write_new(
            &format!("{}/notes/personal.txt", job.plan.final_relative_path),
            b"user addition",
        )
        .unwrap();
        store
            .complete(
                &job.id,
                &[Artifact {
                    id: "artifact".into(),
                    job_id: job.id.clone(),
                    relative_path: path.clone(),
                    size: 13,
                    sha256: digest(b"saved chapter"),
                    media_type: "application/zip".into(),
                    status: FileStatus::Present,
                }],
            )
            .await
            .unwrap();
        (temp, Storage { store }, dest.id, path, job.id)
    }
    async fn reach(storage: &Storage, id: &str, state: &str) {
        for _ in 0..100 {
            let op = storage.operation(id).await.unwrap();
            if op.state == state {
                return;
            }
            storage.step(&op, &CancellationToken::new()).await.unwrap();
        }
        panic!("Did not reach {state}");
    }
    #[tokio::test]
    async fn recovery_handles_rename_before_sql_and_quarantine_before_cleanup_record() {
        let (temp, mut storage, destination, path, _) = setup().await;
        let op = storage
            .create(&destination, &temp.path().join("target"))
            .await
            .unwrap();
        reach(&storage, &op.id, "ready").await;
        storage.action(&op.id, "start").await.unwrap();
        reach(&storage, &op.id, "publishing").await;
        let root_path: String = sqlx::query_scalar(
            "SELECT path FROM storage_roots WHERE operation_id=? AND state='verified' LIMIT 1",
        )
        .bind(&op.id)
        .fetch_one(&storage.store.pool)
        .await
        .unwrap();
        let target = Root::identified(Path::new(&op.target_root), &op.target_marker).unwrap();
        let stage = owned_directory(&target, &stage_name(&op), &op.id).unwrap();
        stage
            .publish(&digest(root_path.as_bytes()), &target, &root_path)
            .unwrap();
        drop(stage);
        // No publication-state update: the filesystem operation already happened.
        storage.store.pool.close().await;
        storage = Storage {
            store: Store::open(&temp.path().join("db")).await.unwrap(),
        };
        reach(&storage, &op.id, "cleanup").await;
        let source = Root::identified(Path::new(&op.source_root), &op.source_marker).unwrap();
        let held = owned_directory(&source, &stage_name(&op), &op.id).unwrap();
        source
            .publish(&path, &held, &digest(path.as_bytes()))
            .unwrap();
        source
            .write_new(&path, b"new unrelated replacement")
            .unwrap();
        drop(held);
        storage.store.pool.close().await;
        storage = Storage {
            store: Store::open(&temp.path().join("db")).await.unwrap(),
        };
        reach(&storage, &op.id, "complete").await;
        assert_eq!(
            std::fs::read(temp.path().join("source").join(&path)).unwrap(),
            b"new unrelated replacement"
        );
        assert_eq!(
            std::fs::read(temp.path().join("target").join(&path)).unwrap(),
            b"saved chapter"
        );
    }
    #[tokio::test]
    async fn relocation_restarts_at_every_persisted_phase_and_preserves_history_and_user_additions()
    {
        for stop in [
            "scanning",
            "ready",
            "copying",
            "publishing",
            "cleanup",
            "complete",
        ] {
            let (temp, mut storage, destination, path, job) = setup().await;
            let target = temp.path().join("target");
            let op = storage.create(&destination, &target).await.unwrap();
            assert!(
                !storage
                    .store
                    .destination(&destination)
                    .await
                    .unwrap()
                    .available
            );
            assert!(storage.store.destination_root(&destination).await.is_err());
            assert!(storage.store.claim().await.unwrap().is_none());
            if stop != "scanning" {
                reach(&storage, &op.id, "ready").await;
            }
            if !["scanning", "ready"].contains(&stop) {
                storage.action(&op.id, "start").await.unwrap();
                reach(&storage, &op.id, stop).await;
            }
            storage.store.pool.close().await;
            storage = Storage {
                store: Store::open(&temp.path().join("db")).await.unwrap(),
            };
            storage.store.recover().await.unwrap();
            if storage.operation(&op.id).await.unwrap().state == "scanning" {
                reach(&storage, &op.id, "ready").await;
            }
            if storage.operation(&op.id).await.unwrap().state == "ready" {
                storage.action(&op.id, "start").await.unwrap();
            }
            reach(&storage, &op.id, "complete").await;
            assert_eq!(std::fs::read(target.join(&path)).unwrap(), b"saved chapter");
            assert_eq!(
                std::fs::read(
                    target
                        .join(Path::new(&path).parent().unwrap())
                        .join("notes/personal.txt")
                )
                .unwrap(),
                b"user addition"
            );
            assert_eq!(
                std::fs::read(target.join("unrelated.txt")).unwrap(),
                b"keep target"
            );
            assert!(!temp.path().join("source").join(&path).exists());
            assert_eq!(
                storage.store.job(&job).await.unwrap().state,
                omd_domain::JobState::Completed
            );
            assert!(matches!(
                storage.store.artifact("artifact").await.unwrap().status,
                FileStatus::Present
            ));
            assert!(
                storage
                    .store
                    .destination(&destination)
                    .await
                    .unwrap()
                    .available
            );
            assert_eq!(storage.operation(&op.id).await.unwrap().retained, 0);
        }
    }
    #[tokio::test]
    async fn cleanup_preserves_modifications_and_files_added_after_inventory() {
        let (temp, storage, destination, path, _) = setup().await;
        let op = storage
            .create(&destination, &temp.path().join("target"))
            .await
            .unwrap();
        reach(&storage, &op.id, "ready").await;
        storage.action(&op.id, "start").await.unwrap();
        reach(&storage, &op.id, "cleanup").await;
        let source = temp.path().join("source").join(&path);
        std::fs::write(&source, b"edited during relocation").unwrap();
        std::fs::write(
            source.parent().unwrap().join("new-note.txt"),
            b"created after inventory",
        )
        .unwrap();
        reach(&storage, &op.id, "complete").await;
        assert_eq!(std::fs::read(&source).unwrap(), b"edited during relocation");
        assert_eq!(
            std::fs::read(source.parent().unwrap().join("new-note.txt")).unwrap(),
            b"created after inventory"
        );
        assert_eq!(
            std::fs::read(temp.path().join("target").join(&path)).unwrap(),
            b"saved chapter"
        );
        assert!(storage.operation(&op.id).await.unwrap().retained > 0);
    }
    #[tokio::test]
    async fn relocation_never_overwrites_target_collisions_and_cancel_unfreezes_source() {
        let (temp, storage, destination, path, _) = setup().await;
        let target = temp.path().join("target");
        let existing = target.join(Path::new(&path).parent().unwrap());
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("unrelated"), b"do not touch").unwrap();
        let op = storage.create(&destination, &target).await.unwrap();
        let mut collision = false;
        for _ in 0..10 {
            let task = storage.operation(&op.id).await.unwrap();
            if matches!(
                storage.step(&task, &CancellationToken::new()).await,
                Err(Error::Collision)
            ) {
                collision = true;
                break;
            }
        }
        assert!(collision);
        storage.action(&op.id, "cancel").await.unwrap();
        assert!(
            storage
                .store
                .destination(&destination)
                .await
                .unwrap()
                .available
        );
        assert_eq!(
            std::fs::read(existing.join("unrelated")).unwrap(),
            b"do not touch"
        );
        assert_eq!(
            std::fs::read(temp.path().join("source").join(path)).unwrap(),
            b"saved chapter"
        );
    }
    #[tokio::test]
    async fn partial_copy_is_reused_only_when_its_prefix_matches_and_source_changes_fail() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let source = Root::open(&a).unwrap();
        let target = Root::open(&b).unwrap();
        let bytes = vec![42u8; 200000];
        source.write_new("file", &bytes).unwrap();
        target.write_new("file", &bytes[..70000]).unwrap();
        copy_file(
            &source,
            &target,
            "file",
            bytes.len() as u64,
            &digest(&bytes),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(target.hash("file").unwrap(), source.hash("file").unwrap());
        std::fs::write(b.join("file"), b"wrong old partial").unwrap();
        copy_file(
            &source,
            &target,
            "file",
            bytes.len() as u64,
            &digest(&bytes),
            &CancellationToken::new(),
        )
        .unwrap();
        std::fs::write(a.join("file"), b"changed source").unwrap();
        assert!(matches!(
            copy_file(
                &source,
                &target,
                "file",
                bytes.len() as u64,
                &digest(&bytes),
                &CancellationToken::new()
            ),
            Err(Error::Changed)
        ));
    }
}
