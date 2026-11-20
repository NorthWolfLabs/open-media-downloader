//! SQLite owns durable transitions and their event/outbox records together.
pub mod groups;
pub mod history;
pub mod presentation;
pub mod selections;
pub mod source_removals;
mod upgrades;

use chrono::{SecondsFormat, Utc};
use omd_domain::*;
use serde_json::Value;
use sqlx::{
    Row, SqlitePool,
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
    },
};
use std::{path::Path, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("The selected destination is unavailable, changed identity, or cannot be written")]
    Destination,
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Migration(String),
    #[error("Resource not found")]
    NotFound,
    #[error("The idempotency key was already used for a different request")]
    IdempotencyConflict,
    #[error("The resource state does not permit this operation")]
    StateConflict,
    #[error("The event cursor has expired; take a new snapshot")]
    CursorExpired,
}
pub type Result<T> = std::result::Result<T, StoreError>;
pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
pub fn id(prefix: &str) -> String {
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}

/// A destination folder with its identity marker written but no database row
/// yet. See [`Store::prepare_destination`].
#[derive(Debug)]
pub struct PreparedDestination {
    root: std::path::PathBuf,
    marker: String,
    available: bool,
}
impl PreparedDestination {
    /// Remove the unused identity marker. A leftover marker names no database
    /// row and is harmless, so a failure here is ignored.
    pub async fn discard(self) {
        let _ = folder_io(move || {
            omd_files::Root::open(&self.root)?
                .remove_file(&format!(".omd-destination-{}", self.marker))
        })
        .await;
    }
}
/// Outcome of [`Store::record_first_destination`].
#[derive(Debug)]
pub enum Recorded {
    Added(Destination),
    /// Another destination already exists; this is its id.
    Existing(String),
}
fn register_marker(root: &Path, marker: &str) -> std::io::Result<()> {
    omd_files::Root::register(root, marker).map(drop)
}
async fn prepare_destination_with<F>(root: &Path, register: F) -> Result<PreparedDestination>
where
    F: FnOnce(&Path, &str) -> std::io::Result<()> + Send + 'static,
{
    let root = root.to_path_buf();
    folder_io(move || {
        let root = std::fs::canonicalize(root)?;
        let marker = uuid::Uuid::new_v4().simple().to_string();
        let available = root.is_dir();
        register(&root, &marker)?;
        Ok(PreparedDestination {
            root,
            marker,
            available,
        })
    })
    .await
}
/// Run destination folder I/O on a blocking thread, outside any transaction.
async fn folder_io<T: Send + 'static>(
    work: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| StoreError::StateConflict)?
        .map_err(|_| StoreError::Destination)
}

#[derive(Clone)]
pub struct Store {
    pub pool: SqlitePool,
}
impl Store {
    /// Replay, expiry validation, all group jobs, and the response commit together.
    pub async fn enqueue_prepared(
        &self,
        preparation: &str,
        key: &str,
        request_digest: &str,
    ) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(row) = sqlx::query("SELECT * FROM group_requests WHERE key=?")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
        {
            if row.get::<String, _>("request_digest") != request_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let result = serde_json::from_str(row.get("response_json"))?;
            tx.commit().await?;
            return Ok(result);
        }
        let row = sqlx::query("SELECT * FROM prepared WHERE id=?")
            .bind(preparation)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?;
        if row.get::<String, _>("expires_at") < now() {
            return Err(StoreError::StateConflict);
        }
        let data: Value = serde_json::from_str(row.get("data_json"))?;
        let plans: Vec<Plan> = serde_json::from_value(data["plans"].clone())?;
        let destination = data["destination_id"]
            .as_str()
            .ok_or(StoreError::StateConflict)?;
        let group = id("group");
        let time = now();
        let mut jobs = vec![];
        for plan in plans {
            let (job, created) =
                insert_job(&mut tx, &plan, destination, Some(&group), &time).await?;
            jobs.push(serde_json::json!({"job":job,"created":created}));
        }
        let response = serde_json::json!({"group_id":group,"items":jobs});
        sqlx::query("INSERT INTO group_requests VALUES(?,?,?,?)")
            .bind(key)
            .bind(request_digest)
            .bind(serde_json::to_string(&response)?)
            .bind(time)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(response)
    }
    pub async fn prepare(
        &self,
        request_digest: &str,
        plans: &Value,
        expires_at: &str,
    ) -> Result<String> {
        let id = id("prep");
        sqlx::query("INSERT INTO prepared VALUES(?,?,?,?)")
            .bind(&id)
            .bind(request_digest)
            .bind(serde_json::to_string(plans)?)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }
    pub async fn prepared(&self, id: &str) -> Result<Value> {
        let row = sqlx::query("SELECT * FROM prepared WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        let expires: String = row.get("expires_at");
        if expires < now() {
            return Err(StoreError::StateConflict);
        }
        Ok(serde_json::from_str(row.get("data_json"))?)
    }
    pub async fn providers(&self) -> Result<Vec<(ProviderManifest, String, String, bool)>> {
        let rows=sqlx::query("SELECT v.*,p.enabled FROM providers p JOIN provider_versions v ON v.provider_id=p.id AND v.digest=p.active_digest ORDER BY p.id").fetch_all(&self.pool).await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    serde_json::from_str(r.get("manifest_json"))?,
                    r.get("component_path"),
                    r.get("digest"),
                    r.get::<i64, _>("enabled") != 0,
                ))
            })
            .collect()
    }
    pub async fn install_provider(
        &self,
        manifest: &ProviderManifest,
        digest: &str,
        path: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO provider_versions VALUES(?,?,?,?,1,?) ON CONFLICT(provider_id,digest) DO UPDATE SET approved=1,component_path=excluded.component_path")
            .bind(&manifest.id)
            .bind(digest)
            .bind(serde_json::to_string(manifest)?)
            .bind(path)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO providers(id,active_digest,enabled,revision) VALUES(?,?,1,1) ON CONFLICT(id) DO UPDATE SET active_digest=excluded.active_digest,enabled=1,revision=providers.revision+1").bind(&manifest.id).bind(digest).execute(&mut *tx).await?;
        emit(&mut tx, "sources.changed", &manifest.id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn provider_version(
        &self,
        provider: &str,
        digest: &str,
    ) -> Result<(ProviderManifest, String)> {
        let row = sqlx::query("SELECT v.* FROM provider_versions v JOIN providers p ON p.id=v.provider_id WHERE v.provider_id=? AND v.digest=? AND v.approved=1 AND p.enabled=1")
            .bind(provider).bind(digest).fetch_optional(&self.pool).await?.ok_or(StoreError::NotFound)?;
        Ok((
            serde_json::from_str(row.get("manifest_json"))?,
            row.get("component_path"),
        ))
    }
    pub async fn provider_versions(
        &self,
        provider: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Value>> {
        self.search_provider_versions(provider, "", cursor, limit)
            .await
    }
    pub async fn search_provider_versions(
        &self,
        provider: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Value>> {
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT v.*,p.active_digest FROM provider_versions v JOIN providers p ON p.id=v.provider_id WHERE v.provider_id=? AND v.approved=1 AND instr(lower(v.digest || json_extract(v.manifest_json,'$.version')),lower(?))>0 AND v.digest>? ORDER BY v.digest LIMIT ?")
            .bind(provider).bind(query).bind(cursor.unwrap_or("")).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let items:Vec<Value>=rows.into_iter().take(limit).map(|r|Ok(serde_json::json!({"manifest":serde_json::from_str::<Value>(r.get("manifest_json"))?,"digest":r.get::<String,_>("digest"),"active":r.get::<String,_>("digest")==r.get::<String,_>("active_digest"),"installed_at":r.get::<String,_>("installed_at")}))).collect::<Result<_>>()?;
        let next_cursor = if more {
            items
                .last()
                .and_then(|v| v["digest"].as_str())
                .map(str::to_owned)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn activate_provider(&self, provider: &str, digest: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let changed=sqlx::query("UPDATE providers SET active_digest=?,revision=revision+1 WHERE id=? AND enabled=1 AND EXISTS(SELECT 1 FROM provider_versions WHERE provider_id=? AND digest=? AND approved=1)")
            .bind(digest).bind(provider).bind(provider).bind(digest).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        emit(&mut tx, "sources.changed", provider).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn artifacts(&self, job: &str) -> Result<Vec<Artifact>> {
        let rows = sqlx::query("SELECT * FROM artifacts WHERE job_id=? ORDER BY relative_path")
            .bind(job)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|r| {
                Ok(Artifact {
                    id: r.get("id"),
                    job_id: r.get("job_id"),
                    relative_path: r.get("relative_path"),
                    size: r.get::<i64, _>("size") as u64,
                    sha256: r.get("sha256"),
                    media_type: r.get("media_type"),
                    status: serde_json::from_value(Value::String(r.get("status")))?,
                })
            })
            .collect()
    }
    pub async fn artifact(&self, id: &str) -> Result<Artifact> {
        let r = sqlx::query("SELECT * FROM artifacts WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        Ok(Artifact {
            id: r.get("id"),
            job_id: r.get("job_id"),
            relative_path: r.get("relative_path"),
            size: r.get::<i64, _>("size") as u64,
            sha256: r.get("sha256"),
            media_type: r.get("media_type"),
            status: serde_json::from_value(Value::String(r.get("status")))?,
        })
    }
    pub async fn artifact_page(
        &self,
        job_id: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Artifact>> {
        self.search_artifacts(job_id, "", cursor, limit).await
    }
    pub async fn search_artifacts(
        &self,
        job_id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Artifact>> {
        let job = self.job(job_id).await?;
        let root = self.destination_root(&job.destination_id).await.ok();
        let limit = limit.clamp(1, 200);
        let rows=sqlx::query("SELECT * FROM artifacts WHERE job_id=? AND instr(lower(relative_path),lower(?))>0 AND (? IS NULL OR relative_path>?) ORDER BY relative_path LIMIT ?").bind(job_id).bind(query).bind(cursor).bind(cursor).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
        let mut items: Vec<Artifact> = rows
            .into_iter()
            .map(|r| Artifact {
                id: r.get("id"),
                job_id: r.get("job_id"),
                relative_path: r.get("relative_path"),
                size: r.get::<i64, _>("size") as u64,
                sha256: r.get("sha256"),
                media_type: r.get("media_type"),
                status: FileStatus::Present,
            })
            .collect();
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_cursor = if more {
            items.last().map(|a| a.relative_path.clone())
        } else {
            None
        };
        let items = tokio::task::spawn_blocking(move || {
            for artifact in &mut items {
                artifact.status = match &root {
                    None => FileStatus::DestinationUnavailable,
                    Some(root) => match root.hash(&artifact.relative_path) {
                        Ok((size, hash)) if size == artifact.size && hash == artifact.sha256 => {
                            FileStatus::Present
                        }
                        Ok(_) => FileStatus::Modified,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileStatus::Missing,
                        Err(_) => FileStatus::Detached,
                    },
                };
            }
            items
        })
        .await
        .map_err(|_| StoreError::StateConflict)?;
        Ok(Page { items, next_cursor })
    }
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        let migrator = sqlx::migrate!();
        if let Err(error) = upgrades::protect(&pool, path, &migrator).await {
            pool.close().await;
            return Err(error);
        }
        if let Err(error) = migrator.run(&pool).await {
            pool.close().await;
            return Err(StoreError::Migration(error.to_string()));
        }
        let store = Self { pool };
        if let Err(error) = store.normalize_reservations().await {
            store.pool.close().await;
            return Err(error);
        }
        Ok(store)
    }
    /// Rewrite reservation keys stored by earlier builds (plain lowercase, or
    /// an earlier non-fixpoint fold) to `reservation_key`, once per key
    /// version: one transaction, recorded in `settings` so later opens skip
    /// the scan. Idempotent. A row whose normalized key already exists keeps
    /// its old key: that name is reserved by the other row, and lookups also
    /// match the legacy lowercase spelling.
    async fn normalize_reservations(&self) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let done: Option<String> =
            sqlx::query_scalar("SELECT value_json FROM settings WHERE key='reservation_keys'")
                .fetch_optional(&mut *tx)
                .await?;
        if done.as_deref() == Some(RESERVATION_KEY_VERSION) {
            return Ok(());
        }
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT destination_id,path_key FROM path_reservations")
                .fetch_all(&mut *tx)
                .await?;
        for (destination, key) in rows {
            let normalized = reservation_key(&key);
            if normalized != key {
                sqlx::query(
                    "UPDATE OR IGNORE path_reservations SET path_key=? WHERE destination_id=? AND path_key=?",
                )
                .bind(normalized)
                .bind(destination)
                .bind(key)
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::query(
            "INSERT INTO settings VALUES('reservation_keys',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",
        )
        .bind(RESERVATION_KEY_VERSION)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn destination(&self, id: &str) -> Result<Destination> {
        let row = sqlx::query("SELECT * FROM destinations WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        let root: String = row.get("root");
        let marker: Option<String> = row.get("marker");
        let path = root.clone();
        let moving: Option<String> = row.get("storage_operation");
        let storage_operation = moving.clone();
        let available = tokio::task::spawn_blocking(move || {
            moving.is_none()
                && marker.is_some_and(|marker| {
                    omd_files::Root::identified(Path::new(&path), &marker).is_ok()
                })
        })
        .await
        .map_err(|_| StoreError::StateConflict)?;
        Ok(Destination {
            id: row.get("id"),
            label: row.get("label"),
            available,
            storage_operation,
            // The exact stored canonical root: internal consumers (staging and
            // helper work paths) use it. Service responses show its ordinary
            // spelling instead (`omd_files::display_path`).
            root,
        })
    }
    pub async fn destinations(&self) -> Result<Vec<Destination>> {
        let rows = sqlx::query("SELECT id FROM destinations ORDER BY label,id")
            .fetch_all(&self.pool)
            .await?;
        let mut result = vec![];
        for row in rows {
            result.push(self.destination(row.get("id")).await?);
        }
        Ok(result)
    }
    pub async fn destination_page(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Destination>> {
        let limit = limit.clamp(1, 200) as usize;
        let mut ids: Vec<String> = sqlx::query_scalar("SELECT id FROM destinations WHERE instr(lower(label),lower(?))>0 AND (? IS NULL OR id>?) ORDER BY id LIMIT ?")
            .bind(query).bind(cursor).bind(cursor).bind((limit + 1) as i64).fetch_all(&self.pool).await?;
        let more = ids.len() > limit;
        ids.truncate(limit);
        let next_cursor = if more { ids.last().cloned() } else { None };
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            items.push(self.destination(&id).await?);
        }
        Ok(Page { items, next_cursor })
    }
    pub async fn add_destination(&self, label: &str, root: &Path) -> Result<Destination> {
        self.add_destination_with(label, root, register_marker)
            .await
    }
    async fn add_destination_with<F>(
        &self,
        label: &str,
        root: &Path,
        register: F,
    ) -> Result<Destination>
    where
        F: FnOnce(&Path, &str) -> std::io::Result<()> + Send + 'static,
    {
        let prepared = prepare_destination_with(root, register).await?;
        match self.record_prepared(label, &prepared, false).await {
            Ok(Recorded::Added(destination)) => Ok(destination),
            Ok(Recorded::Existing(id)) => {
                prepared.discard().await;
                self.destination(&id).await
            }
            Err(error) => {
                prepared.discard().await;
                Err(error)
            }
        }
    }
    /// Write the identity marker of a new destination folder, without touching
    /// the database. The write can wait indefinitely: macOS suspends the first
    /// access to Downloads, Documents or a removable volume until the user
    /// answers its permission prompt. It therefore runs on a blocking thread,
    /// and callers must not hold a transaction or engine lock while awaiting it.
    pub async fn prepare_destination(root: &Path) -> Result<PreparedDestination> {
        prepare_destination_with(root, register_marker).await
    }
    /// The first destination's id, from the database only. Unlike
    /// [`Store::destination`], this never checks the folder on disk.
    pub async fn first_destination_id(&self) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT id FROM destinations ORDER BY id LIMIT 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }
    /// Record a prepared destination unless any destination exists, in one
    /// write transaction. It touches no files, so a caller may hold an engine
    /// lock around it. The caller still owns the prepared marker: discard it
    /// after an `Existing` result or an error, once that lock is released.
    pub async fn record_first_destination(
        &self,
        label: &str,
        prepared: &PreparedDestination,
    ) -> Result<Recorded> {
        self.record_prepared(label, prepared, true).await
    }
    async fn record_prepared(
        &self,
        label: &str,
        prepared: &PreparedDestination,
        first_only: bool,
    ) -> Result<Recorded> {
        let dest = Destination {
            id: id("dest"),
            label: label.into(),
            root: prepared.root.to_string_lossy().into(),
            available: prepared.available,
            storage_operation: None,
        };
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if first_only {
            let existing: Option<String> =
                sqlx::query_scalar("SELECT id FROM destinations ORDER BY id LIMIT 1")
                    .fetch_optional(&mut *tx)
                    .await?;
            if let Some(existing) = existing {
                return Ok(Recorded::Existing(existing));
            }
        }
        sqlx::query("INSERT INTO destinations(id,label,root,marker) VALUES(?,?,?,?)")
            .bind(&dest.id)
            .bind(&dest.label)
            .bind(&dest.root)
            .bind(&prepared.marker)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "destinations.changed", &dest.id).await?;
        tx.commit().await?;
        Ok(Recorded::Added(dest))
    }
    /// Open a handle to the registered filesystem, not merely its mount path.
    pub async fn destination_root(&self, id: &str) -> Result<omd_files::Root> {
        let row = sqlx::query("SELECT root,marker,storage_operation FROM destinations WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        if row.get::<Option<String>, _>("storage_operation").is_some() {
            return Err(StoreError::Destination);
        }
        let path: String = row.get("root");
        let marker: Option<String> = row.get("marker");
        let marker = marker.ok_or(StoreError::Destination)?;
        tokio::task::spawn_blocking(move || omd_files::Root::identified(Path::new(&path), &marker))
            .await
            .map_err(|_| StoreError::StateConflict)?
            .map_err(|_| StoreError::Destination)
    }
    /// Relink an existing destination by its identity marker. This never moves
    /// files or adopts a different mounted disk at the old path.
    pub async fn reconnect_destination(&self, id: &str, root: &Path) -> Result<Destination> {
        // Check the folder before the write transaction: like a new destination,
        // it can wait for a macOS permission prompt. The transaction then
        // confirms that the destination did not change in the meantime.
        let row = sqlx::query("SELECT marker,storage_operation FROM destinations WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        if row.get::<Option<String>, _>("storage_operation").is_some() {
            return Err(StoreError::StateConflict);
        }
        let expected: Option<String> = row.get("marker");
        let (root, marker, created) = {
            let root = root.to_path_buf();
            let expected = expected.clone();
            folder_io(move || {
                let root = std::fs::canonicalize(root)?;
                match expected {
                    Some(marker) => {
                        omd_files::Root::identified(&root, &marker)?;
                        Ok((root, marker, false))
                    }
                    None => {
                        // Explicit user reconnection is the only way to adopt an earlier
                        // v2 development root. Legacy v1 databases are never opened here.
                        let marker = uuid::Uuid::new_v4().simple().to_string();
                        register_marker(&root, &marker)?;
                        Ok((root, marker, true))
                    }
                }
            })
            .await?
        };
        let updated = async {
            let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
            let row = sqlx::query("SELECT marker,storage_operation FROM destinations WHERE id=?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
            if row.get::<Option<String>, _>("storage_operation").is_some()
                || row.get::<Option<String>, _>("marker") != expected
            {
                return Err(StoreError::StateConflict);
            }
            sqlx::query("UPDATE destinations SET root=?,marker=? WHERE id=?")
                .bind(root.to_string_lossy().as_ref())
                .bind(&marker)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            emit(&mut tx, "destinations.changed", id).await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        if let Err(error) = updated {
            if created {
                PreparedDestination {
                    root,
                    marker,
                    available: true,
                }
                .discard()
                .await;
            }
            return Err(error);
        }
        self.destination(id).await
    }
    /// Select a durable version before its complete output preview is shown.
    /// Modified files still satisfy prior acquisition: they are never replaced.
    /// Missing or detached files require a new, separate artifact set.
    pub async fn plan_intent(
        &self,
        plan: &Plan,
        destination: &str,
        behavior: DuplicateBehavior,
    ) -> Result<(Plan, &'static str)> {
        let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM file_operations o JOIN jobs j ON j.id=o.job_id WHERE j.intent_key=? AND o.state IN ('ready','working'))").bind(intent_key(plan,destination)?).fetch_one(&self.pool).await?;
        if busy {
            return Err(StoreError::StateConflict);
        }
        let intent = intent_key(plan, destination)?;
        let previous =
            sqlx::query("SELECT * FROM jobs WHERE intent_key=? ORDER BY generation DESC LIMIT 1")
                .bind(&intent)
                .fetch_optional(&self.pool)
                .await?
                .map(job_row)
                .transpose()?;
        if matches!(behavior, DuplicateBehavior::SkipSatisfied)
            && let Some(job) = &previous
            && !self.history_removed(&job.id).await?
        {
            match job.state {
                JobState::Completed => {
                    let mut cursor = None;
                    let mut count = 0;
                    let mut satisfied = true;
                    loop {
                        let page = self.artifact_page(&job.id, cursor.as_deref(), 200).await?;
                        count += page.items.len();
                        for artifact in page.items {
                            match artifact.status {
                                FileStatus::Present | FileStatus::Modified => {}
                                FileStatus::DestinationUnavailable => {
                                    return Err(StoreError::Destination);
                                }
                                _ => satisfied = false,
                            }
                        }
                        cursor = page.next_cursor;
                        if cursor.is_none() {
                            break;
                        }
                    }
                    if satisfied && count > 0 {
                        return Ok((job.plan.clone(), "already_acquired"));
                    }
                }
                JobState::Canceled => {}
                _ => return Ok((job.plan.clone(), "existing_job")),
            }
        }
        let root = self.destination_root(destination).await?;
        let mut selected = plan.clone();
        selected.generation = previous
            .as_ref()
            .map_or(Some(1), |job| job.plan.generation.checked_add(1))
            .ok_or(StoreError::StateConflict)?;
        // The first version of an intent uses the plain path. A distinct path is
        // needed only for a later version, whose files never replace earlier
        // ones, or when the plain path is already reserved by another intent
        // (another recipe or policy for the same release) or exists on disk.
        let taken = previous.is_some()
            || self
                .path_taken(destination, root, &plan.final_relative_path)
                .await?;
        if taken {
            selected.final_relative_path = format!(
                "{} [copy {}-{}]",
                plan.final_relative_path,
                &intent[..8],
                selected.generation
            );
        }
        Ok((
            selected,
            if previous.is_some() {
                "new_version"
            } else {
                "download"
            },
        ))
    }
    /// Whether a job of another intent reserved `path` (compared by
    /// `reservation_key`, as insertion does) or any entry already occupies it
    /// in the destination.
    async fn path_taken(
        &self,
        destination: &str,
        root: omd_files::Root,
        path: &str,
    ) -> Result<bool> {
        let reserved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM path_reservations WHERE destination_id=? AND path_key IN (?,?))",
        )
        .bind(destination)
        .bind(reservation_key(path))
        .bind(path.to_lowercase())
        .fetch_one(&self.pool)
        .await?;
        if reserved {
            return Ok(true);
        }
        let path = path.to_owned();
        // An unreadable parent counts as taken: publication there would fail.
        tokio::task::spawn_blocking(move || root.exists(&path).unwrap_or(true))
            .await
            .map_err(|_| StoreError::StateConflict)
    }
    pub async fn replay(&self, key: &str, request_digest: &str) -> Result<Option<Job>> {
        if let Some(row) = sqlx::query("SELECT * FROM idempotency WHERE key=?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
        {
            if row.get::<String, _>("request_digest") != request_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(Some(self.job(row.get("resource_id")).await?));
        }
        Ok(None)
    }
    pub async fn enqueue(
        &self,
        plan: &Plan,
        destination_id: &str,
        key: &str,
        request_digest: &str,
        group_id: Option<&str>,
    ) -> Result<(Job, bool)> {
        if let Some(job) = self.replay(key, request_digest).await? {
            return Ok((job, false));
        }
        let selected;
        let plan = if plan.generation == 0 {
            selected = self
                .plan_intent(plan, destination_id, DuplicateBehavior::SkipSatisfied)
                .await?
                .0;
            &selected
        } else {
            plan
        };
        let time = now();
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Repeat replay under the write lock: another client may have committed
        // while filesystem satisfaction was being checked.
        if let Some(row) = sqlx::query("SELECT * FROM idempotency WHERE key=?")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
        {
            if row.get::<String, _>("request_digest") != request_digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let job = job_row(
                sqlx::query("SELECT * FROM jobs WHERE id=?")
                    .bind(row.get::<String, _>("resource_id"))
                    .fetch_one(&mut *tx)
                    .await?,
            )?;
            tx.commit().await?;
            return Ok((job, false));
        }
        let (job, created) = insert_job(&mut tx, plan, destination_id, group_id, &time).await?;
        let actual = job.id.clone();
        sqlx::query(
            "INSERT OR IGNORE INTO idempotency(key,request_digest,resource_id) VALUES(?,?,?)",
        )
        .bind(key)
        .bind(request_digest)
        .bind(&actual)
        .execute(&mut *tx)
        .await?;
        let stored: String =
            sqlx::query_scalar("SELECT request_digest FROM idempotency WHERE key=?")
                .bind(key)
                .fetch_one(&mut *tx)
                .await?;
        if stored != request_digest {
            return Err(StoreError::IdempotencyConflict);
        }
        tx.commit().await?;
        Ok((self.job(&actual).await?, created))
    }
    pub async fn history_removed(&self, id: &str) -> Result<bool> {
        sqlx::query_scalar("SELECT history_removed FROM jobs WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)
    }
    pub async fn job(&self, id: &str) -> Result<Job> {
        let row = sqlx::query("SELECT * FROM jobs WHERE id=?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(StoreError::NotFound)?;
        job_row(row)
    }
    pub async fn jobs(
        &self,
        query: &str,
        state: Option<&str>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<Job>> {
        let limit = limit.clamp(1, 200);
        let rows=sqlx::query("SELECT * FROM jobs WHERE history_removed=0 AND instr(lower(title),lower(?))>0 AND (? IS NULL OR state=? OR (?='active' AND state NOT IN ('completed','canceled'))) AND (? IS NULL OR created_at || ':' || id < ?) ORDER BY created_at DESC,id DESC LIMIT ?")
            .bind(query).bind(state).bind(state).bind(state).bind(cursor).bind(cursor).bind(i64::from(limit)+1).fetch_all(&self.pool).await?;
        let mut items = rows.into_iter().map(job_row).collect::<Result<Vec<_>>>()?;
        let more = items.len() > limit as usize;
        items.truncate(limit as usize);
        let next_cursor = if more {
            items.last().map(|j| format!("{}:{}", j.created_at, j.id))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    pub async fn summary(&self) -> Result<Value> {
        let row=sqlx::query("SELECT (SELECT COUNT(*) FROM jobs WHERE state IN ('queued','resolving','transferring','verifying','publishing')) AS active_jobs,(SELECT COUNT(*) FROM jobs WHERE history_removed=0 AND state='completed') AS acquired,(SELECT COUNT(*) FROM subscriptions WHERE removed=0) AS following,(SELECT COUNT(*) FROM jobs WHERE history_removed=0 AND issue_json IS NOT NULL)+(SELECT COUNT(*) FROM subscriptions WHERE removed=0 AND issue_json IS NOT NULL)+(SELECT COUNT(*) FROM actions WHERE state='failed') AS attention").fetch_one(&self.pool).await?;
        Ok(
            serde_json::json!({"active_jobs":row.get::<i64,_>("active_jobs"),"acquired":row.get::<i64,_>("acquired"),"following":row.get::<i64,_>("following"),"attention":row.get::<i64,_>("attention")}),
        )
    }
    pub async fn claim(&self) -> Result<Option<Job>> {
        let time = now();
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query("UPDATE jobs SET state='transferring',attempt=attempt+1,issue_json=NULL,updated_at=? WHERE id=(SELECT j.id FROM jobs j JOIN destinations d ON d.id=j.destination_id WHERE j.state='queued' AND d.storage_operation IS NULL ORDER BY j.created_at,j.id LIMIT 1) RETURNING *").bind(time).fetch_optional(&mut *tx).await?;
        let result = row.map(job_row).transpose()?;
        if let Some(job) = &result {
            emit(&mut tx, "jobs.changed", &job.id).await?;
        }
        tx.commit().await?;
        Ok(result)
    }
    /// Refresh only transport locations while keeping the approved output identity.
    pub async fn refresh_job(&self, id: &str, replacement: &Plan) -> Result<Job> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query("SELECT * FROM jobs WHERE id=? AND state='transferring'")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::StateConflict)?;
        let mut job = job_row(row)?;
        job.plan = job
            .plan
            .refresh(replacement)
            .map_err(|_| StoreError::StateConflict)?;
        sqlx::query("UPDATE jobs SET plan_json=?,updated_at=? WHERE id=?")
            .bind(serde_json::to_string(&job.plan)?)
            .bind(now())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(job)
    }
    pub async fn transition(
        &self,
        job_id: &str,
        from: &[&str],
        state: &str,
        issue: Option<&Problem>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // The conditional update protects user pause/cancel from late worker results.
        let allowed = serde_json::to_string(from)?;
        let rows=sqlx::query("UPDATE jobs SET state=?,issue_json=?,updated_at=? WHERE id=? AND state IN (SELECT value FROM json_each(?))")
            .bind(state).bind(issue.map(serde_json::to_string).transpose()?).bind(now()).bind(job_id).bind(allowed).execute(&mut *tx).await?.rows_affected();
        if rows == 0 {
            return Err(StoreError::StateConflict);
        }
        emit(&mut tx, "jobs.changed", job_id).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Whether a download is running, or queued where the job runner can
    /// claim it. A job queued behind a destination's storage operation waits
    /// for that operation, which may itself wait for a person to start it.
    pub async fn has_unfinished_downloads(&self) -> Result<bool> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jobs j JOIN destinations d ON d.id=j.destination_id \
             WHERE j.state IN ('resolving','transferring','verifying','publishing') \
             OR (j.state='queued' AND d.storage_operation IS NULL))",
        )
        .fetch_one(&self.pool)
        .await?)
    }
    pub async fn recover(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE jobs SET state='queued',updated_at=? WHERE state IN ('resolving','transferring','verifying','publishing')").bind(now()).execute(&mut *tx).await?;
        sqlx::query("UPDATE actions SET state='pending' WHERE state='running'")
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "engine.recovered", "").await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn progress(&self, job_id: &str, done: u64, total: Option<u64>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE jobs SET bytes_done=?,bytes_total=?,updated_at=? WHERE id=? AND state='transferring'").bind(done.min(i64::MAX as u64) as i64).bind(total.map(|n|n.min(i64::MAX as u64) as i64)).bind(now()).bind(job_id).execute(&mut *tx).await?;
        emit(&mut tx, "jobs.progress", job_id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn checkpoint(
        &self,
        job_id: &str,
        output_id: &str,
        fingerprint: &str,
        data: &Value,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO checkpoints VALUES(?,?,?,?) ON CONFLICT(job_id,output_id) DO UPDATE SET fingerprint=excluded.fingerprint,data_json=excluded.data_json").bind(job_id).bind(output_id).bind(fingerprint).bind(serde_json::to_string(data)?).execute(&mut *tx).await?;
        // Checkpoints also hold verified manifests. Saving one must not reset
        // native transfer counters merely because its payload has no byte offset.
        if data.get("bytes").and_then(Value::as_u64).is_some() {
            sqlx::query("UPDATE jobs SET bytes_done=(SELECT COALESCE(SUM(COALESCE(json_extract(data_json,'$.bytes'),0)),0) FROM checkpoints WHERE job_id=?),updated_at=? WHERE id=? AND state='transferring'").bind(job_id).bind(now()).bind(job_id).execute(&mut *tx).await?;
        }
        emit(&mut tx, "jobs.progress", job_id).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Save per-stream recovery counters and their aggregate in one transaction.
    pub async fn checkpoint_progress(
        &self,
        job_id: &str,
        output_id: &str,
        fingerprint: &str,
        data: &Value,
        done: u64,
        total: Option<u64>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO checkpoints VALUES(?,?,?,?) ON CONFLICT(job_id,output_id) DO UPDATE SET fingerprint=excluded.fingerprint,data_json=excluded.data_json").bind(job_id).bind(output_id).bind(fingerprint).bind(serde_json::to_string(data)?).execute(&mut *tx).await?;
        sqlx::query("UPDATE jobs SET bytes_done=?,bytes_total=?,updated_at=? WHERE id=? AND state='transferring'").bind(done.min(i64::MAX as u64) as i64).bind(total.map(|n|n.min(i64::MAX as u64) as i64)).bind(now()).bind(job_id).execute(&mut *tx).await?;
        emit(&mut tx, "jobs.progress", job_id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn read_checkpoint(
        &self,
        job_id: &str,
        output_id: &str,
        fingerprint: &str,
    ) -> Result<Option<Value>> {
        let value: Option<String> = sqlx::query_scalar(
            "SELECT data_json FROM checkpoints WHERE job_id=? AND output_id=? AND fingerprint=?",
        )
        .bind(job_id)
        .bind(output_id)
        .bind(fingerprint)
        .fetch_optional(&self.pool)
        .await?;
        value
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    pub async fn journal_publication(&self, job_id: &str, manifest: &Value) -> Result<()> {
        sqlx::query("INSERT INTO publications VALUES(?,?,'prepared',?) ON CONFLICT(job_id) DO UPDATE SET manifest_json=excluded.manifest_json,updated_at=excluded.updated_at").bind(job_id).bind(serde_json::to_string(manifest)?).bind(now()).execute(&self.pool).await?;
        Ok(())
    }
    pub async fn publication(&self, job_id: &str) -> Result<Option<Value>> {
        let result: Option<String> =
            sqlx::query_scalar("SELECT manifest_json FROM publications WHERE job_id=?")
                .bind(job_id)
                .fetch_optional(&self.pool)
                .await?;
        result
            .map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    pub async fn publication_cleanup_batch(&self) -> Result<Vec<Job>> {
        let rows = sqlx::query("SELECT jobs.* FROM jobs JOIN publications ON jobs.id=publications.job_id WHERE jobs.state='completed' AND publications.state='completed' ORDER BY publications.updated_at,jobs.id LIMIT 100").fetch_all(&self.pool).await?;
        rows.into_iter().map(job_row).collect()
    }
    pub async fn publication_cleaned(&self, job: &str) -> Result<()> {
        sqlx::query("UPDATE publications SET state='cleaned' WHERE job_id=? AND state='completed'")
            .bind(job)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn defer_publication_cleanup(&self, job: &str) -> Result<()> {
        sqlx::query("UPDATE publications SET updated_at=? WHERE job_id=?")
            .bind(now())
            .bind(job)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn complete(&self, job_id: &str, artifacts: &[Artifact]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for a in artifacts {
            sqlx::query("INSERT INTO artifacts(id,job_id,relative_path,size,sha256,media_type,status) VALUES(?,?,?,?,?,?,?) ON CONFLICT(job_id,relative_path) DO UPDATE SET size=excluded.size,sha256=excluded.sha256,media_type=excluded.media_type,status=excluded.status")
                .bind(&a.id).bind(job_id).bind(&a.relative_path).bind(a.size as i64).bind(&a.sha256).bind(&a.media_type).bind("present").execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE publications SET state='completed',updated_at=? WHERE job_id=?")
            .bind(now())
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE jobs SET state='completed',issue_json=NULL,updated_at=? WHERE id=?")
            .bind(now())
            .bind(job_id)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "jobs.completed", job_id).await?;
        emit(&mut tx, "acquisitions.changed", job_id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn event_cursor(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(id) FROM events")
                .fetch_one(&self.pool)
                .await?
                .unwrap_or(0),
        )
    }
    pub async fn events(&self, after: i64, limit: u32) -> Result<Vec<Event>> {
        // Check retention and read the batch in the same SQLite snapshot.
        let mut tx = self.pool.begin().await?;
        let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(id) FROM events")
            .fetch_one(&mut *tx)
            .await?;
        if oldest.is_some_and(|first| after < first - 1) {
            return Err(StoreError::CursorExpired);
        }
        let items = sqlx::query("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?")
            .bind(after)
            .bind(i64::from(limit.clamp(1, 1000)))
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|r| Event {
                id: r.get("id"),
                kind: r.get("kind"),
                resource_id: r.get("resource_id"),
                created_at: r.get("created_at"),
            })
            .collect();
        tx.commit().await?;
        Ok(items)
    }
    pub async fn setting(&self, key: &str) -> Result<Option<Value>> {
        let s: Option<String> = sqlx::query_scalar("SELECT value_json FROM settings WHERE key=?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        s.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    pub async fn set_setting(&self, key: &str, value: &Value) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json").bind(key).bind(serde_json::to_string(value)?).execute(&mut *tx).await?;
        emit(&mut tx, "settings.changed", key).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn upsert_collection(&self, c: &Collection) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("INSERT INTO collections(key,provider_id,source_id,data_json) VALUES(?,?,?,?) ON CONFLICT(key) DO UPDATE SET data_json=excluded.data_json WHERE collections.data_json != excluded.data_json").bind(c.reference.key()).bind(&c.reference.provider).bind(&c.reference.id).bind(serde_json::to_string(c)?).execute(&mut *tx).await?.rows_affected();
        if changed != 0 {
            emit(&mut tx, "metadata.changed", &c.reference.key()).await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
pub async fn emit(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    kind: &str,
    resource_id: &str,
) -> Result<()> {
    let inserted = sqlx::query("INSERT INTO events(kind,resource_id,created_at) VALUES(?,?,?)")
        .bind(kind)
        .bind(resource_id)
        .bind(now())
        .execute(&mut **tx)
        .await?
        .last_insert_rowid();
    // Bound the journal without pruning every progress update. Clients older than
    // the retained window must resynchronize instead of silently losing changes.
    if inserted % 1000 == 0 {
        sqlx::query("DELETE FROM events WHERE id<=?")
            .bind(inserted - 100_000)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
/// The identity of a reserved destination path: Unicode NFC, then full case
/// folding (approximated as uppercase-then-lowercase, which applies the
/// special multi-character mappings such as "ß" -> "ss"), then NFC again,
/// repeated until it is a fixed point.
/// It is meant to be coarser than the supported filesystems' name identity
/// (APFS, NTFS, ext4 with or without casefolding): names it merges at worst
/// get a `[copy …]` suffix. Exclusive publication remains the final guard.
pub fn reservation_key(path: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let fold = |s: &str| -> String {
        let composed: String = s.nfc().collect();
        composed.to_uppercase().to_lowercase().nfc().collect()
    };
    // One pass is not always a fixed point ("ẞ" -> "ß" -> "ss"). Repeat until
    // stable; every scalar value converges within two passes.
    let mut key = fold(path);
    loop {
        let next = fold(&key);
        if next == key {
            return key;
        }
        key = next;
    }
}
/// Bump when `reservation_key` changes, so stored keys are converted again.
const RESERVATION_KEY_VERSION: &str = "\"fold-fixpoint-1\"";
fn intent_key(plan: &Plan, destination: &str) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(
        plan.acquisition_key(),
        destination,
    ))?))
}
async fn insert_job(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    plan: &Plan,
    destination: &str,
    group: Option<&str>,
    time: &str,
) -> Result<(Job, bool)> {
    let intent = intent_key(plan, destination)?;
    let key = if plan.generation == 0 {
        intent.clone()
    } else {
        digest(&serde_json::to_vec(&(&intent, plan.generation))?)
    };
    let created = sqlx::query("INSERT OR IGNORE INTO jobs(id,group_id,acquisition_key,intent_key,generation,title,destination_id,state,plan_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'queued',?,?,?)")
        .bind(id("job")).bind(group).bind(&key).bind(&intent).bind(plan.generation).bind(plan.release_title()).bind(destination).bind(serde_json::to_string(plan)?).bind(time).bind(time).execute(&mut **tx).await?.rows_affected() == 1;
    let job = job_row(
        sqlx::query("SELECT * FROM jobs WHERE acquisition_key=?")
            .bind(&key)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    let unavailable: bool = sqlx::query_scalar("SELECT history_removed=1 OR EXISTS(SELECT 1 FROM file_operations o WHERE o.job_id=jobs.id AND o.state IN ('ready','working')) FROM jobs WHERE id=?").bind(&job.id).fetch_one(&mut **tx).await?;
    if unavailable {
        return Err(StoreError::StateConflict);
    }
    if created {
        let path_key = reservation_key(&plan.final_relative_path);
        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM path_reservations WHERE destination_id=? AND path_key IN (?,?))",
        )
        .bind(destination)
        .bind(&path_key)
        .bind(plan.final_relative_path.to_lowercase())
        .fetch_one(&mut **tx)
        .await?;
        if occupied {
            return Err(StoreError::StateConflict);
        }
        sqlx::query("INSERT INTO path_reservations VALUES(?,?,?)")
            .bind(destination)
            .bind(path_key)
            .bind(&job.id)
            .execute(&mut **tx)
            .await?;
        emit(tx, "jobs.changed", &job.id).await?;
    } else if job.plan.final_relative_path != plan.final_relative_path {
        // A concurrently confirmed version had a different preview. Do not silently
        // acquire files at a path the caller never approved.
        return Err(StoreError::StateConflict);
    }
    if let Some(group) = group {
        sqlx::query("INSERT OR IGNORE INTO job_groups VALUES(?,?)")
            .bind(group)
            .bind(time)
            .execute(&mut **tx)
            .await?;
        let added = sqlx::query("INSERT OR IGNORE INTO job_group_members VALUES(?,?)")
            .bind(group)
            .bind(&job.id)
            .execute(&mut **tx)
            .await?
            .rows_affected();
        if added == 1 {
            emit(tx, "groups.changed", group).await?;
        }
    }
    Ok((job, created))
}
fn job_row(r: SqliteRow) -> Result<Job> {
    let state: String = r.get("state");
    let issue: Option<String> = r.get("issue_json");
    Ok(Job {
        id: r.get("id"),
        group_id: r.get("group_id"),
        acquisition_key: r.get("acquisition_key"),
        title: r.get("title"),
        destination_id: r.get("destination_id"),
        state: serde_json::from_value(Value::String(state))?,
        plan: serde_json::from_str(r.get("plan_json"))?,
        bytes_done: r.get::<i64, _>("bytes_done") as u64,
        bytes_total: r.get::<Option<i64>, _>("bytes_total").map(|n| n as u64),
        attempt: r.get::<i64, _>("attempt") as u32,
        issue: issue.map(|s| serde_json::from_str(&s)).transpose()?,
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn verification_checkpoints_do_not_erase_native_transfer_progress() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let (job, _) = store
            .enqueue(&plan(), &dest.id, "progress", "progress", None)
            .await
            .unwrap();
        store.claim().await.unwrap();
        store.progress(&job.id, 8192, Some(8192)).await.unwrap();
        store
            .checkpoint(
                &job.id,
                "__native_media",
                "verified",
                &serde_json::json!({"video":[4096,"sha"]}),
            )
            .await
            .unwrap();
        assert_eq!(store.job(&job.id).await.unwrap().bytes_done, 8192);
        store.pool.close().await;
        let reopened = Store::open(&root.path().join("db")).await.unwrap();
        assert_eq!(reopened.job(&job.id).await.unwrap().bytes_done, 8192);
    }
    #[tokio::test]
    async fn approved_versions_survive_updates_and_unknown_rollback_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let mut manifest: ProviderManifest =
            serde_json::from_str(include_str!("../../../tests/v2-provider/omd-plugin.json"))
                .unwrap();
        store
            .install_provider(&manifest, "first", "/first")
            .await
            .unwrap();
        manifest.version = "0.2.1".into();
        store
            .install_provider(&manifest, "second", "/second")
            .await
            .unwrap();
        assert_eq!(store.providers().await.unwrap()[0].2, "second");
        assert_eq!(
            store
                .provider_version(&manifest.id, "first")
                .await
                .unwrap()
                .1,
            "/first"
        );
        assert!(matches!(
            store.activate_provider(&manifest.id, "unapproved").await,
            Err(StoreError::NotFound)
        ));
        store
            .activate_provider(&manifest.id, "first")
            .await
            .unwrap();
        assert_eq!(store.providers().await.unwrap()[0].2, "first");
        assert_eq!(
            store
                .provider_versions(&manifest.id, None, 100)
                .await
                .unwrap()
                .items
                .len(),
            2
        );
    }
    #[tokio::test]
    async fn resumed_plan_preserves_checkpoint_identity_and_rejects_changed_outputs() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let original = plan();
        let (job, _) = store
            .enqueue(&original, &dest.id, "refresh", "refresh", None)
            .await
            .unwrap();
        store.claim().await.unwrap();
        let mut replacement = original.clone();
        replacement.outputs.reverse();
        for output in &mut replacement.outputs {
            if let Locator::Http { url, .. } = &mut output.locator {
                *url = format!("https://example.com/renewed/{}", output.id);
            }
        }
        let refreshed = store.refresh_job(&job.id, &replacement).await.unwrap();
        for (a, b) in original.outputs.iter().zip(&refreshed.plan.outputs) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.relative_path, b.relative_path);
        }
        replacement.outputs[0].expected_sha256 = Some("f".repeat(64));
        assert!(matches!(
            store.refresh_job(&job.id, &replacement).await,
            Err(StoreError::StateConflict)
        ));
        assert_eq!(
            serde_json::to_value(store.job(&job.id).await.unwrap().plan).unwrap(),
            serde_json::to_value(refreshed.plan).unwrap()
        );
    }
    #[tokio::test]
    async fn acquisition_history_survives_missing_modified_and_disconnected_files() {
        let root = tempfile::tempdir().unwrap();
        let folder = root.path().join("files");
        std::fs::create_dir(&folder).unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let destination = store.add_destination("Files", &folder).await.unwrap();
        let (job, _) = store
            .enqueue(&plan(), &destination.id, "files", "files", None)
            .await
            .unwrap();
        std::fs::write(folder.join("chapter.cbz"), b"x").unwrap();
        store
            .complete(
                &job.id,
                &[Artifact {
                    id: "artifact".into(),
                    job_id: job.id.clone(),
                    relative_path: "chapter.cbz".into(),
                    size: 1,
                    sha256: digest(b"x"),
                    media_type: "application/vnd.comicbook+zip".into(),
                    status: FileStatus::Present,
                }],
            )
            .await
            .unwrap();
        assert!(matches!(
            store.artifact_page(&job.id, None, 100).await.unwrap().items[0].status,
            FileStatus::Present
        ));
        std::fs::write(folder.join("chapter.cbz"), b"y").unwrap();
        assert!(matches!(
            store.artifact_page(&job.id, None, 100).await.unwrap().items[0].status,
            FileStatus::Modified
        ));
        std::fs::remove_file(folder.join("chapter.cbz")).unwrap();
        assert!(matches!(
            store.artifact_page(&job.id, None, 100).await.unwrap().items[0].status,
            FileStatus::Missing
        ));
        std::fs::rename(&folder, root.path().join("disconnected")).unwrap();
        assert!(matches!(
            store.artifact_page(&job.id, None, 100).await.unwrap().items[0].status,
            FileStatus::DestinationUnavailable
        ));
        assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Completed);
    }
    fn plan() -> Plan {
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap()
    }
    #[tokio::test]
    async fn missing_files_get_a_new_version_without_erasing_modified_files_or_history() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let (first, created) = store
            .enqueue(&plan(), &dest.id, "first", "first", None)
            .await
            .unwrap();
        assert!(created);
        let root = store.destination_root(&dest.id).await.unwrap();
        let path = format!("{}/chapter.cbz", first.plan.final_relative_path);
        root.write_new(&path, b"original").unwrap();
        store
            .complete(
                &first.id,
                &[Artifact {
                    id: id("artifact"),
                    job_id: first.id.clone(),
                    relative_path: path.clone(),
                    size: 8,
                    sha256: digest(b"original"),
                    media_type: "application/zip".into(),
                    status: FileStatus::Present,
                }],
            )
            .await
            .unwrap();
        let (satisfied, outcome) = store
            .plan_intent(&plan(), &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(outcome, "already_acquired");
        assert_eq!(satisfied.generation, 1);
        std::fs::write(temp.path().join(&path), b"user edited").unwrap();
        assert_eq!(
            store
                .plan_intent(&plan(), &dest.id, DuplicateBehavior::SkipSatisfied)
                .await
                .unwrap()
                .1,
            "already_acquired"
        );
        let (new, outcome) = store
            .plan_intent(&plan(), &dest.id, DuplicateBehavior::NewVersion)
            .await
            .unwrap();
        assert_eq!(outcome, "new_version");
        assert_eq!(new.generation, 2);
        assert_ne!(new.final_relative_path, first.plan.final_relative_path);
        std::fs::remove_file(temp.path().join(&path)).unwrap();
        let (missing, outcome) = store
            .plan_intent(&plan(), &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(outcome, "new_version");
        assert_eq!(missing.final_relative_path, new.final_relative_path);
        let (second, created) = store
            .enqueue(&missing, &dest.id, "second", "second", None)
            .await
            .unwrap();
        assert!(created);
        assert_ne!(first.id, second.id);
        assert_eq!(
            store.job(&first.id).await.unwrap().state,
            JobState::Completed
        );
        let (same, created) = store
            .enqueue(
                &missing,
                &dest.id,
                "overlapping-subscription",
                "third",
                None,
            )
            .await
            .unwrap();
        assert!(!created);
        assert_eq!(same.id, second.id);
        let (replay, _) = store
            .enqueue(&plan(), &dest.id, "first", "first", None)
            .await
            .unwrap();
        assert_eq!(replay.id, first.id);
    }
    #[tokio::test]
    async fn the_first_download_uses_the_plain_path_and_only_real_conflicts_get_a_copy_suffix() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        // Nothing exists yet: the preview and the job use the plain path.
        let (first, outcome) = store
            .plan_intent(&plan(), &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(outcome, "download");
        assert_eq!(first.generation, 1);
        assert_eq!(first.final_relative_path, plan().final_relative_path);
        let (job, created) = store
            .enqueue(&first, &dest.id, "first", "first", None)
            .await
            .unwrap();
        assert!(created);
        assert_eq!(job.plan.final_relative_path, plan().final_relative_path);
        // Another intent for the same release (a different policy) previews the
        // same plain path, which the first job has reserved.
        let mut other = plan();
        other.policy.languages = vec!["fr".into()];
        let (second, _) = store
            .plan_intent(&other, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(second.generation, 1);
        assert!(
            second
                .final_relative_path
                .starts_with(&format!("{} [copy ", plan().final_relative_path)),
            "{}",
            second.final_relative_path
        );
        assert!(
            store
                .enqueue(&second, &dest.id, "second", "second", None)
                .await
                .unwrap()
                .1
        );
        // A folder that already exists on disk is never adopted.
        let mut third = plan();
        third.release.reference.id = "chapter:111".into();
        third.final_relative_path = "Fixture/Chapter 111".into();
        std::fs::create_dir_all(temp.path().join("Fixture/Chapter 111")).unwrap();
        let (third, _) = store
            .plan_intent(&third, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert!(
            third
                .final_relative_path
                .starts_with("Fixture/Chapter 111 [copy "),
            "{}",
            third.final_relative_path
        );
        // A missing parent folder is not a conflict.
        let mut fourth = plan();
        fourth.release.reference.id = "chapter:112".into();
        fourth.final_relative_path = "Elsewhere/Chapter 112".into();
        let (fourth, _) = store
            .plan_intent(&fourth, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(fourth.final_relative_path, "Elsewhere/Chapter 112");
    }
    #[tokio::test]
    async fn internal_destination_roots_stay_the_exact_stored_canonical_path() {
        // Staging and helper work paths are built from `Destination::root`.
        // It must stay the canonical (on Windows verbatim `\\?\`) path, which
        // has no MAX_PATH limit for long staging descendants; only service
        // responses use the shortened display spelling.
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let canonical = std::fs::canonicalize(temp.path()).unwrap();
        let added = store.add_destination("Files", temp.path()).await.unwrap();
        let stored: String = sqlx::query_scalar("SELECT root FROM destinations WHERE id=?")
            .bind(&added.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, canonical.to_string_lossy());
        assert_eq!(added.root, stored);
        assert_eq!(store.destination(&added.id).await.unwrap().root, stored);
        #[cfg(windows)]
        assert!(stored.starts_with(r"\\?\"), "{stored}");
    }
    #[test]
    fn reservation_keys_merge_unicode_and_case_aliases() {
        let nfc = "Show/Caf\u{e9} [abcdef1234]";
        let nfd = "Show/Cafe\u{301} [abcdef1234]";
        assert_ne!(nfc.to_lowercase(), nfd.to_lowercase());
        for alias in [
            nfd,
            "SHOW/CAF\u{c9} [ABCDEF1234]",
            "show/CAFE\u{301} [abcdef1234]",
        ] {
            assert_eq!(reservation_key(alias), reservation_key(nfc), "{alias}");
        }
        for (a, b) in [
            ("Stra\u{df}e", "STRASSE"),
            ("\u{fb01}le", "FILE"),
            ("\u{212a}elvin", "kelvin"),
            ("\u{3c3}\u{3c2}", "\u{3a3}\u{3a3}"),
            ("\u{130}", "i\u{307}"),
        ] {
            assert_eq!(reservation_key(a), reservation_key(b), "{a} {b}");
        }
        assert_ne!(reservation_key("Cafe"), reservation_key(nfc));
        for key in [nfc, nfd, "Stra\u{df}e", "\u{130}"] {
            let once = reservation_key(key);
            assert_eq!(reservation_key(&once), once, "idempotent for {key}");
        }
    }
    #[test]
    fn the_reservation_key_is_a_fixed_point_for_every_scalar_value() {
        let mut checked = 0;
        for c in (0..=0x10ffffu32).filter_map(char::from_u32) {
            let text = format!("a{c}b");
            let key = reservation_key(&text);
            assert_eq!(reservation_key(&key), key, "U+{:04X}", c as u32);
            assert_eq!(
                reservation_key(&text.to_lowercase()),
                key,
                "U+{:04X} lower",
                c as u32
            );
            assert_eq!(
                reservation_key(&text.to_uppercase()),
                key,
                "U+{:04X} upper",
                c as u32
            );
            checked += 1;
        }
        assert!(checked > 1_100_000);
        assert_eq!(
            reservation_key("GRO\u{1e9e}E STRA\u{1e9e}E"),
            "grosse strasse"
        );
        assert_eq!(
            reservation_key("stra\u{df}e"),
            reservation_key("STRA\u{1e9e}E")
        );
    }
    #[tokio::test]
    async fn a_capital_sharp_s_reservation_survives_a_restart() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let mut first = plan();
        first.final_relative_path = "Fixture/GRO\u{1e9e}E STRA\u{1e9e}E [abcdef1234]".into();
        let (first, _) = store
            .plan_intent(&first, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        store
            .enqueue(&first, &dest.id, "first", "first", None)
            .await
            .unwrap();
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        for spelling in [
            "Fixture/GRO\u{1e9e}E STRA\u{1e9e}E [abcdef1234]",
            "Fixture/gro\u{df}e stra\u{df}e [abcdef1234]",
            "Fixture/GROSSE STRASSE [abcdef1234]",
        ] {
            let mut other = plan();
            other.final_relative_path = spelling.into();
            other.policy.languages = vec!["fr".into()];
            let (other, _) = store
                .plan_intent(&other, &dest.id, DuplicateBehavior::SkipSatisfied)
                .await
                .unwrap();
            assert!(
                other.final_relative_path.contains(" [copy "),
                "{spelling}: {}",
                other.final_relative_path
            );
        }
    }
    #[tokio::test]
    async fn reservation_keys_are_converted_once_per_key_version() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let mut nfd = plan();
        nfd.final_relative_path = "Fixture/Cafe\u{301} [abcdef1234]".into();
        let (job, _) = store
            .enqueue(&nfd, &dest.id, "legacy", "legacy", None)
            .await
            .unwrap();
        let legacy = job.plan.final_relative_path.to_lowercase();
        let set_legacy = |store: Store| {
            let legacy = legacy.clone();
            let id = job.id.clone();
            async move {
                sqlx::query("UPDATE path_reservations SET path_key=? WHERE job_id=?")
                    .bind(legacy)
                    .bind(id)
                    .execute(&store.pool)
                    .await
                    .unwrap();
                store.pool.close().await;
            }
        };
        let key = |store: &Store| {
            let id = job.id.clone();
            let pool = store.pool.clone();
            async move {
                sqlx::query_scalar::<_, String>(
                    "SELECT path_key FROM path_reservations WHERE job_id=?",
                )
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
            }
        };
        // The marker is already recorded by the first open: a later legacy
        // row is not rescanned on the next open.
        set_legacy(store).await;
        let store = Store::open(&db).await.unwrap();
        assert_eq!(key(&store).await, legacy);
        // An earlier key version (FIX-2 stores have no marker) converts once.
        sqlx::query("DELETE FROM settings WHERE key='reservation_keys'")
            .execute(&store.pool)
            .await
            .unwrap();
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        assert_eq!(
            key(&store).await,
            reservation_key(&job.plan.final_relative_path)
        );
        let marker: String =
            sqlx::query_scalar("SELECT value_json FROM settings WHERE key='reservation_keys'")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(marker, RESERVATION_KEY_VERSION);
        // Idempotent: another open changes nothing.
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        assert_eq!(
            key(&store).await,
            reservation_key(&job.plan.final_relative_path)
        );
    }
    #[tokio::test]
    async fn unicode_equivalent_names_never_share_a_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let mut nfc = plan();
        nfc.final_relative_path = "Fixture/Caf\u{e9} [abcdef1234]".into();
        let mut nfd = nfc.clone();
        nfd.final_relative_path = "Fixture/Cafe\u{301} [abcdef1234]".into();
        nfd.policy.languages = vec!["fr".into()];
        // Both previewed before either is queued: both see the plain name, and
        // the database refuses the second, which must prepare again.
        let (first, _) = store
            .plan_intent(&nfc, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        let (raced, _) = store
            .plan_intent(&nfd, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert_eq!(first.final_relative_path, nfc.final_relative_path);
        assert_eq!(raced.final_relative_path, nfd.final_relative_path);
        store
            .enqueue(&first, &dest.id, "nfc", "nfc", None)
            .await
            .unwrap();
        assert!(matches!(
            store
                .enqueue(&raced, &dest.id, "raced", "raced", None)
                .await,
            Err(StoreError::StateConflict)
        ));
        // Prepared again, the decomposed spelling gets a distinct copy path.
        let (second, _) = store
            .plan_intent(&nfd, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert!(
            second
                .final_relative_path
                .starts_with(&format!("{} [copy ", nfd.final_relative_path)),
            "{}",
            second.final_relative_path
        );
        assert!(
            store
                .enqueue(&second, &dest.id, "nfd", "nfd", None)
                .await
                .unwrap()
                .1
        );
        // Both publish: the folders never alias, even on APFS.
        let root = store.destination_root(&dest.id).await.unwrap();
        for (stage, path) in [
            ("stage-a", &first.final_relative_path),
            ("stage-b", &second.final_relative_path),
        ] {
            root.create_directory(stage, false).unwrap();
            root.publish(stage, &root, path).unwrap();
        }
    }
    #[tokio::test]
    async fn reservations_from_earlier_builds_are_normalized_on_open() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let mut nfd = plan();
        nfd.final_relative_path = "Fixture/Cafe\u{301} [abcdef1234]".into();
        let (job, _) = store
            .enqueue(&nfd, &dest.id, "legacy", "legacy", None)
            .await
            .unwrap();
        // An earlier build stored only the lowercase spelling, and recorded no
        // conversion marker.
        sqlx::query("UPDATE path_reservations SET path_key=? WHERE job_id=?")
            .bind(job.plan.final_relative_path.to_lowercase())
            .bind(&job.id)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM settings WHERE key='reservation_keys'")
            .execute(&store.pool)
            .await
            .unwrap();
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        let key: String =
            sqlx::query_scalar("SELECT path_key FROM path_reservations WHERE job_id=?")
                .bind(&job.id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(key, reservation_key(&job.plan.final_relative_path));
        let mut nfc = plan();
        nfc.final_relative_path = "Fixture/Caf\u{e9} [abcdef1234]".into();
        nfc.policy.languages = vec!["fr".into()];
        let (other, _) = store
            .plan_intent(&nfc, &dest.id, DuplicateBehavior::SkipSatisfied)
            .await
            .unwrap();
        assert!(
            other.final_relative_path.contains(" [copy "),
            "{}",
            other.final_relative_path
        );
    }
    #[tokio::test]
    async fn path_reservation_conflict_rolls_back_the_entire_group() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", temp.path()).await.unwrap();
        let mut other = plan();
        other.release.reference.id = "other".into();
        let prep = store
            .prepare(
                "collision",
                &serde_json::json!({"plans":[plan(),other],"destination_id":dest.id}),
                "9999",
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .enqueue_prepared(&prep, "collision", "collision")
                .await,
            Err(StoreError::StateConflict)
        ));
        assert!(
            store
                .jobs("", None, None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
        let reservations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM path_reservations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(reservations, 0);
    }
    #[tokio::test]
    async fn reconnect_requires_the_registered_folder_and_keeps_jobs() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("disk");
        std::fs::create_dir(&folder).unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let dest = store.add_destination("Disk", &folder).await.unwrap();
        let (job, _) = store
            .enqueue(&plan(), &dest.id, "job", "job", None)
            .await
            .unwrap();
        let moved = temp.path().join("remounted");
        std::fs::rename(&folder, &moved).unwrap();
        std::fs::create_dir(&folder).unwrap();
        assert!(!store.destination(&dest.id).await.unwrap().available);
        assert!(matches!(
            store.reconnect_destination(&dest.id, &folder).await,
            Err(StoreError::Destination)
        ));
        let connected = store.reconnect_destination(&dest.id, &moved).await.unwrap();
        assert!(connected.available);
        assert_eq!(connected.id, dest.id);
        assert_eq!(store.job(&job.id).await.unwrap().destination_id, dest.id);
    }
    /// macOS suspends the first write into Downloads until the user answers its
    /// permission prompt. On a first run the engine registers that folder, and
    /// while the prompt is open the rest of the engine must keep working.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_destination_awaiting_folder_permission_does_not_lock_the_database() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("Downloads");
        std::fs::create_dir(&folder).unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let (asked, prompt) = std::sync::mpsc::channel::<()>();
        let (answer, answered) = std::sync::mpsc::channel::<()>();
        let pending = tokio::spawn({
            let store = store.clone();
            let folder = folder.clone();
            async move {
                store
                    .add_destination_with("Downloads", &folder, move |root, marker| {
                        asked.send(()).unwrap();
                        // Dropping the sender also ends the wait, so a failing
                        // assertion below cannot leave this thread blocked.
                        let _ = answered.recv();
                        register_marker(root, marker)
                    })
                    .await
            }
        });
        tokio::task::spawn_blocking(move || prompt.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .expect("the marker write started");
        // Holding the write transaction here made every other writer wait for
        // SQLite's busy timeout and fail with "database is locked".
        let bounded = Duration::from_secs(2);
        let write = tokio::time::timeout(
            bounded,
            store.set_setting("preferences", &serde_json::json!({"background": false})),
        )
        .await;
        let read = tokio::time::timeout(bounded, store.event_cursor()).await;
        answer.send(()).unwrap();
        write
            .expect("a writer waited for the folder permission")
            .unwrap();
        read.expect("a reader waited for the folder permission")
            .unwrap();
        let destination = pending.await.unwrap().unwrap();
        assert!(store.destination(&destination.id).await.unwrap().available);
        assert_eq!(store.destinations().await.unwrap().len(), 1);
    }
    #[tokio::test]
    async fn an_unrecorded_destination_leaves_no_identity_marker() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("Downloads");
        std::fs::create_dir(&folder).unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let markers = || {
            std::fs::read_dir(&folder)
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".omd-destination-")
                })
                .count()
        };
        store.add_destination("Files", &folder).await.unwrap();
        // The folder is already registered, so the second row is refused after
        // its marker was written; that marker must not be left behind.
        assert!(store.add_destination("Again", &folder).await.is_err());
        let refused = Store::prepare_destination(&folder).await.unwrap();
        assert_eq!(markers(), 2);
        refused.discard().await;
        assert_eq!(markers(), 1);
        assert_eq!(store.destinations().await.unwrap().len(), 1);
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_first_destinations_record_once_without_reading_the_folder() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("Downloads");
        std::fs::create_dir(&folder).unwrap();
        let store = Store::open(&temp.path().join("db")).await.unwrap();
        let attempts: Vec<_> = (0..8)
            .map(|_| {
                let (store, folder) = (store.clone(), folder.clone());
                tokio::spawn(async move {
                    let prepared = Store::prepare_destination(&folder).await.unwrap();
                    let recorded = store
                        .record_first_destination("Downloads", &prepared)
                        .await
                        .unwrap();
                    if matches!(recorded, Recorded::Existing(_)) {
                        prepared.discard().await;
                    }
                    recorded
                })
            })
            .collect();
        let mut ids = Vec::new();
        let mut added = 0;
        for attempt in attempts {
            match attempt.await.unwrap() {
                Recorded::Added(destination) => {
                    added += 1;
                    ids.push(destination.id);
                }
                Recorded::Existing(id) => ids.push(id),
            }
        }
        assert_eq!(added, 1);
        assert!(ids.iter().all(|id| *id == ids[0]));
        let markers = std::fs::read_dir(&folder).unwrap().count();
        assert_eq!(markers, 1);
        assert!(store.destination(&ids[0]).await.unwrap().available);
        assert_eq!(
            store.first_destination_id().await.unwrap(),
            Some(ids[0].clone())
        );

        // Recording touches no files, so callers may hold an engine lock around
        // it: it still succeeds after the prepared folder has disappeared.
        let store = Store::open(&temp.path().join("other-db")).await.unwrap();
        let gone = temp.path().join("Removed");
        std::fs::create_dir(&gone).unwrap();
        let prepared = Store::prepare_destination(&gone).await.unwrap();
        std::fs::remove_dir_all(&gone).unwrap();
        let Recorded::Added(destination) = store
            .record_first_destination("Downloads", &prepared)
            .await
            .unwrap()
        else {
            panic!("the first destination was not recorded");
        };
        assert!(!store.destination(&destination.id).await.unwrap().available);
    }
    #[tokio::test]
    async fn replay_precedes_expiry_and_group_is_atomic() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let mut second = plan();
        second.release.reference.id = "second".into();
        second.final_relative_path = "second/chapter".into();
        let prep = store
            .prepare(
                "request",
                &serde_json::json!({"plans":[plan(),second],"destination_id":dest.id}),
                "9999-01-01",
            )
            .await
            .unwrap();
        let first = store
            .enqueue_prepared(&prep, "retry-key", "request")
            .await
            .unwrap();
        sqlx::query("UPDATE prepared SET expires_at='2000-01-01'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            first,
            store
                .enqueue_prepared(&prep, "retry-key", "request")
                .await
                .unwrap()
        );
        assert!(matches!(
            store.enqueue_prepared(&prep, "retry-key", "changed").await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert_eq!(
            store.jobs("", None, None, 100).await.unwrap().items.len(),
            2
        );
    }
    #[tokio::test]
    async fn unfinished_downloads_cover_claimable_and_running_jobs_only() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        assert!(!store.has_unfinished_downloads().await.unwrap());
        let (job, _) = store
            .enqueue(&plan(), &dest.id, "one", "one", None)
            .await
            .unwrap();
        assert!(store.has_unfinished_downloads().await.unwrap());
        // A storage operation holds the queued job back; it is not claimable.
        sqlx::query("UPDATE destinations SET storage_operation='op' WHERE id=?")
            .bind(&dest.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(!store.has_unfinished_downloads().await.unwrap());
        sqlx::query("UPDATE destinations SET storage_operation=NULL WHERE id=?")
            .bind(&dest.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(store.claim().await.unwrap().unwrap().id, job.id);
        assert!(store.has_unfinished_downloads().await.unwrap());
        for state in ["verifying", "publishing"] {
            store
                .transition(&job.id, &["transferring", "verifying"], state, None)
                .await
                .unwrap();
            assert!(store.has_unfinished_downloads().await.unwrap());
        }
        store
            .transition(&job.id, &["publishing"], "paused", None)
            .await
            .unwrap();
        assert!(!store.has_unfinished_downloads().await.unwrap());
        store
            .transition(&job.id, &["paused"], "failed", None)
            .await
            .unwrap();
        assert!(!store.has_unfinished_downloads().await.unwrap());
    }
    #[tokio::test]
    async fn history_pagination_does_not_truncate_at_one_hundred() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let dest = store.add_destination("Files", root.path()).await.unwrap();
        let plans: Vec<_> = (0..251)
            .map(|index| {
                let mut p = plan();
                p.release.reference.id = index.to_string();
                p.final_relative_path = format!("series/chapter-{index}");
                p
            })
            .collect();
        let prep = store
            .prepare(
                "many",
                &serde_json::json!({"plans":plans,"destination_id":dest.id}),
                "9999-01-01",
            )
            .await
            .unwrap();
        store.enqueue_prepared(&prep, "many", "many").await.unwrap();
        let mut cursor = None;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let page = store.jobs("", None, cursor.as_deref(), 100).await.unwrap();
            for job in page.items {
                assert!(seen.insert(job.id));
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(seen.len(), 251);
        assert_eq!(store.summary().await.unwrap()["active_jobs"], 251);
    }
    #[tokio::test]
    async fn database_is_durable_and_events_share_transactions() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("v2.sqlite3");
        let store = Store::open(&db).await.unwrap();
        let d = store.add_destination("Files", root.path()).await.unwrap();
        let cursor = store.event_cursor().await.unwrap();
        assert!(cursor > 0);
        store.pool.close().await;
        let reopened = Store::open(&db).await.unwrap();
        assert_eq!(reopened.destination(&d.id).await.unwrap().label, "Files");
        assert_eq!(reopened.events(0, 100).await.unwrap().len(), 1);
    }
}
