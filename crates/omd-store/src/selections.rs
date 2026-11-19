//! Persisted, bounded-page enumeration and preparation. No network work in transactions.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SelectionTask {
    pub id: String,
    pub kind: String,
    pub state: String,
    pub request: Value,
    pub source_digest: String,
    pub cursor: Option<String>,
    pub processed: i64,
    pub total: i64,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    /// Checked release outcomes, independent of preview pagination.
    #[serde(default)]
    pub outcomes: std::collections::BTreeMap<String, i64>,
}
fn task(row: SqliteRow) -> Result<SelectionTask> {
    Ok(SelectionTask {
        id: row.get("id"),
        kind: row.get("kind"),
        state: row.get("state"),
        request: serde_json::from_str(row.get("request_json"))?,
        source_digest: row.get("source_digest"),
        cursor: row.get("cursor"),
        processed: row.get("processed"),
        total: row.get("total"),
        issue: row
            .get::<Option<String>, _>("issue_json")
            .map(|v| serde_json::from_str(&v))
            .transpose()?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
        outcomes: Default::default(),
    })
}
impl Store {
    pub async fn create_snapshot(&self, request: &Value, digest: &str) -> Result<SelectionTask> {
        let id = id("snapshot");
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO selection_tasks(id,kind,state,request_json,source_digest,created_at,updated_at) VALUES(?,'snapshot','working',?,?,?,?)")
            .bind(&id).bind(serde_json::to_string(request)?).bind(digest).bind(now()).bind(now()).execute(&mut *tx).await?;
        emit(&mut tx, "selections.changed", &id).await?;
        tx.commit().await?;
        self.selection_task(&id).await
    }
    /// Reuse public interactive enumerations for fifteen minutes. Subscription
    /// scans deliberately use create_snapshot so each scheduled check is fresh.
    pub async fn cached_snapshot(&self, request: &Value, digest: &str) -> Result<SelectionTask> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let encoded = serde_json::to_string(request)?;
        let cutoff = (Utc::now() - chrono::Duration::minutes(15))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let existing: Option<String> = sqlx::query_scalar("SELECT id FROM selection_tasks WHERE kind='snapshot' AND state IN ('working','ready') AND request_json=? AND source_digest=? AND created_at>? AND (expires_at IS NULL OR expires_at>?) AND NOT EXISTS(SELECT 1 FROM subscription_scans WHERE snapshot_id=selection_tasks.id) ORDER BY created_at DESC LIMIT 1")
            .bind(&encoded).bind(digest).bind(cutoff).bind(now()).fetch_optional(&mut *tx).await?;
        if let Some(id) = existing {
            tx.commit().await?;
            return self.selection_task(&id).await;
        }
        let id = id("snapshot");
        sqlx::query("INSERT INTO selection_tasks(id,kind,state,request_json,source_digest,created_at,updated_at) VALUES(?,'snapshot','working',?,?,?,?)")
            .bind(&id).bind(encoded).bind(digest).bind(now()).bind(now()).execute(&mut *tx).await?;
        emit(&mut tx, "selections.changed", &id).await?;
        tx.commit().await?;
        self.selection_task(&id).await
    }
    pub async fn selection_task(&self, id: &str) -> Result<SelectionTask> {
        let mut selection = task(
            sqlx::query("SELECT * FROM selection_tasks WHERE id=?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StoreError::NotFound)?,
        )?;
        if selection.kind == "batch" && selection.state != "working" {
            let rows = sqlx::query("SELECT json_extract(preview_json,'$.outcome') AS outcome,count(*) AS count FROM batch_items WHERE batch_id=? AND preview_json IS NOT NULL GROUP BY outcome")
                .bind(id).fetch_all(&self.pool).await?;
            for row in rows {
                if let Some(outcome) = row.get::<Option<String>, _>("outcome") {
                    selection.outcomes.insert(outcome, row.get("count"));
                }
            }
        }
        Ok(selection)
    }
    pub async fn next_selection_task(&self) -> Result<Option<SelectionTask>> {
        sqlx::query(
            "SELECT * FROM selection_tasks WHERE state='working' ORDER BY updated_at,id LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .map(task)
        .transpose()
    }
    pub async fn selection_tasks(
        &self,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SelectionTask>> {
        self.search_selection_tasks("", cursor, limit).await
    }
    pub async fn search_selection_tasks(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SelectionTask>> {
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT * FROM selection_tasks WHERE instr(lower(id || ' ' || kind || ' ' || request_json),lower(?))>0 AND NOT EXISTS(SELECT 1 FROM subscription_scans WHERE snapshot_id=selection_tasks.id) AND (? IS NULL OR created_at || ':' || id < ?) ORDER BY created_at DESC,id DESC LIMIT ?")
            .bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(task)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = more
            .then(|| items.last().map(|t| format!("{}:{}", t.created_at, t.id)))
            .flatten();
        Ok(Page { items, next_cursor })
    }
    /// Compare the old cursor/progress under the write lock: late or repeated work
    /// cannot append a second copy, finish a canceled task, or mix source pages.
    pub async fn append_snapshot(
        &self,
        expected: &SelectionTask,
        page: &Page<Release>,
    ) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = task(
            sqlx::query("SELECT * FROM selection_tasks WHERE id=?")
                .bind(&expected.id)
                .fetch_one(&mut *tx)
                .await?,
        )?;
        if current.kind != "snapshot"
            || current.state != "working"
            || current.processed != expected.processed
            || current.cursor != expected.cursor
        {
            return Err(StoreError::StateConflict);
        }
        if page.items.len() > 200 {
            return Err(StoreError::StateConflict);
        }
        if let Some(cursor) = &page.next_cursor {
            if cursor.is_empty() || cursor.len() > 16384 || page.items.is_empty() {
                return Err(StoreError::StateConflict);
            }
            let inserted = sqlx::query("INSERT OR IGNORE INTO snapshot_cursors VALUES(?,?)")
                .bind(&expected.id)
                .bind(cursor)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if inserted != 1 {
                return Err(StoreError::StateConflict);
            }
        }
        for (i, release) in page.items.iter().enumerate() {
            let inserted = sqlx::query("INSERT OR IGNORE INTO snapshot_releases VALUES(?,?,?,?)")
                .bind(&expected.id)
                .bind(expected.processed + i as i64)
                .bind(release.reference.key())
                .bind(serde_json::to_string(release)?)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            // Duplicate identities across pages mean the source feed shifted. Do
            // not silently treat a potentially incomplete scan as a snapshot.
            if inserted != 1 && expected.request.get("search").is_none_or(|v| v.is_null()) {
                return Err(StoreError::StateConflict);
            }
        }
        let count = expected.processed + page.items.len() as i64;
        let expires = page.next_cursor.is_none().then(|| {
            (Utc::now() + chrono::Duration::hours(24)).to_rfc3339_opts(SecondsFormat::Millis, true)
        });
        sqlx::query("UPDATE selection_tasks SET state=?,cursor=?,processed=?,total=?,expires_at=?,updated_at=? WHERE id=?")
            .bind(if page.next_cursor.is_some(){"working"}else{"ready"}).bind(&page.next_cursor).bind(count).bind(count).bind(expires).bind(now()).bind(&expected.id).execute(&mut *tx).await?;
        if let Some(subscription) = sqlx::query_scalar::<_, String>(
            "SELECT subscription_id FROM subscription_scans WHERE snapshot_id=?",
        )
        .bind(&expected.id)
        .fetch_optional(&mut *tx)
        .await?
        {
            emit(&mut tx, "subscriptions.changed", &subscription).await?;
        } else {
            emit(&mut tx, "selections.changed", &expected.id).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn snapshot_page(
        &self,
        id: &str,
        query: &str,
        cursor: i64,
        limit: u32,
    ) -> Result<Page<Release>> {
        let snapshot = self.selection_task(id).await?;
        if snapshot.kind != "snapshot"
            || snapshot.state != "ready"
            || snapshot.expires_at.as_ref().is_some_and(|v| v < &now())
        {
            return Err(StoreError::StateConflict);
        }
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT ordinal,data_json FROM snapshot_releases WHERE snapshot_id=? AND ordinal>? AND instr(lower(json_extract(data_json,'$.title')),lower(?))>0 ORDER BY ordinal LIMIT ?")
            .bind(id).bind(cursor).bind(query).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let next_cursor = if more {
            Some(rows[limit - 1].get::<i64, _>("ordinal").to_string())
        } else {
            None
        };
        let items = rows
            .into_iter()
            .take(limit)
            .map(|r| Ok(serde_json::from_str(r.get("data_json"))?))
            .collect::<Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }
    /// Membership is copied in one transaction from the immutable snapshot. Later
    /// source changes or another client changing filters cannot alter the intent.
    pub async fn create_batch(
        &self,
        snapshot: &str,
        request: &Value,
        policy: &SelectionPolicy,
        selected: Option<&[String]>,
    ) -> Result<SelectionTask> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let source = task(
            sqlx::query("SELECT * FROM selection_tasks WHERE id=?")
                .bind(snapshot)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?,
        )?;
        if source.request.get("search").is_some_and(|v| !v.is_null())
            || source.kind != "snapshot"
            || source.state != "ready"
            || source.expires_at.as_ref().is_none_or(|v| v < &now())
        {
            return Err(StoreError::StateConflict);
        }
        // A repeated click or a second client gets the same live review. The
        // output preview keeps its original expiry and is revalidated at submit.
        let existing: Option<String> = sqlx::query_scalar("SELECT id FROM selection_tasks WHERE kind='batch' AND request_json=? AND source_digest=? AND (state='working' OR (state='ready' AND expires_at>?)) ORDER BY created_at DESC LIMIT 1")
            .bind(serde_json::to_string(request)?).bind(&source.source_digest).bind(now()).fetch_optional(&mut *tx).await?;
        if let Some(id) = existing {
            tx.commit().await?;
            return self.selection_task(&id).await;
        }
        let id = id("batch");
        sqlx::query("INSERT INTO selection_tasks(id,kind,state,request_json,source_digest,created_at,updated_at) VALUES(?,'batch','working',?,?,?,?)")
            .bind(&id).bind(serde_json::to_string(request)?).bind(&source.source_digest).bind(now()).bind(now()).execute(&mut *tx).await?;
        // SQL applies selection without materializing a long series in memory.
        let languages = serde_json::to_string(&policy.languages)?;
        let groups = serde_json::to_string(&policy.groups)?;
        let selected = selected.map(serde_json::to_string).transpose()?;
        let result=sqlx::query("INSERT INTO batch_items(batch_id,ordinal,release_json) SELECT ?,row_number() OVER(ORDER BY ordinal)-1,data_json FROM snapshot_releases WHERE snapshot_id=? AND json_extract(data_json,'$.availability')='available' AND (json_array_length(?)=0 OR json_extract(data_json,'$.language') IS NULL OR json_extract(data_json,'$.language') IN (SELECT value FROM json_each(?))) AND (json_array_length(?)=0 OR json_extract(data_json,'$.group') IN (SELECT value FROM json_each(?))) AND (? IS NULL OR release_key IN (SELECT value FROM json_each(?)))")
            .bind(&id).bind(snapshot).bind(&languages).bind(&languages).bind(&groups).bind(&groups).bind(&selected).bind(&selected).execute(&mut *tx).await?;
        let total = result.rows_affected() as i64;
        if let Some(selected) = &selected {
            let keys: std::collections::BTreeSet<String> = serde_json::from_str(selected)?;
            if total != keys.len() as i64 {
                return Err(StoreError::StateConflict);
            }
        }
        if total == 0 {
            return Err(StoreError::StateConflict);
        }
        sqlx::query("UPDATE selection_tasks SET total=? WHERE id=?")
            .bind(total)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "selections.changed", &id).await?;
        tx.commit().await?;
        self.selection_task(&id).await
    }
    pub async fn batch_release(&self, task: &SelectionTask) -> Result<Release> {
        let row =
            sqlx::query("SELECT release_json FROM batch_items WHERE batch_id=? AND ordinal=?")
                .bind(&task.id)
                .bind(task.processed)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StoreError::NotFound)?;
        Ok(serde_json::from_str(row.get("release_json"))?)
    }
    pub async fn append_batch(&self, expected: &SelectionTask, preview: &Value) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let done = expected.processed + 1;
        let expires = (done == expected.total).then(|| {
            (Utc::now() + chrono::Duration::minutes(30))
                .to_rfc3339_opts(SecondsFormat::Millis, true)
        });
        let changed=sqlx::query("UPDATE selection_tasks SET processed=?,state=?,expires_at=?,updated_at=? WHERE id=? AND kind='batch' AND state='working' AND processed=?")
            .bind(done).bind(if done==expected.total{"ready"}else{"working"}).bind(expires).bind(now()).bind(&expected.id).bind(expected.processed).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(StoreError::StateConflict);
        }
        sqlx::query("UPDATE batch_items SET preview_json=? WHERE batch_id=? AND ordinal=?")
            .bind(serde_json::to_string(preview)?)
            .bind(&expected.id)
            .bind(expected.processed)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "selections.changed", &expected.id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn batch_page(&self, id: &str, cursor: i64, limit: u32) -> Result<Page<Value>> {
        self.search_batch_page(id, "", cursor, limit).await
    }
    pub async fn search_batch_page(
        &self,
        id: &str,
        query: &str,
        cursor: i64,
        limit: u32,
    ) -> Result<Page<Value>> {
        let task = self.selection_task(id).await?;
        if task.kind != "batch" {
            return Err(StoreError::NotFound);
        }
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT ordinal,preview_json FROM batch_items WHERE batch_id=? AND instr(lower(json_extract(release_json,'$.title')),lower(?))>0 AND ordinal>? AND preview_json IS NOT NULL ORDER BY ordinal LIMIT ?")
            .bind(id).bind(query).bind(cursor).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let next_cursor = if more {
            Some(rows[limit - 1].get::<i64, _>("ordinal").to_string())
        } else {
            None
        };
        let items = rows
            .into_iter()
            .take(limit)
            .map(|r| Ok(serde_json::from_str(r.get("preview_json"))?))
            .collect::<Result<Vec<_>>>()?;
        Ok(Page { items, next_cursor })
    }
    pub async fn selection_state(
        &self,
        id: &str,
        state: &str,
        issue: Option<&Problem>,
    ) -> Result<()> {
        let from = match state {
            "failed" | "canceled" => "working",
            "working" => "failed,canceled",
            _ => return Err(StoreError::StateConflict),
        };
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query(
            "UPDATE selection_tasks SET state=?,issue_json=?,updated_at=? WHERE id=? AND instr(',' || ? || ',', ',' || state || ',')>0",
        )
        .bind(state)
        .bind(issue.map(serde_json::to_string).transpose()?)
        .bind(now())
        .bind(id)
        .bind(from)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::StateConflict);
        }
        emit(&mut tx, "selections.changed", id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn enqueue_batch(&self, id: &str, key: &str, fingerprint: &str) -> Result<Value> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(row) = sqlx::query("SELECT * FROM group_requests WHERE key=?")
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?
        {
            if row.get::<String, _>("request_digest") != fingerprint {
                return Err(StoreError::IdempotencyConflict);
            }
            return Ok(serde_json::from_str(row.get("response_json"))?);
        }
        let batch = task(
            sqlx::query("SELECT * FROM selection_tasks WHERE id=?")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?,
        )?;
        if batch.kind != "batch"
            || batch.state != "ready"
            || batch.expires_at.as_ref().is_none_or(|v| v < &now())
        {
            return Err(StoreError::StateConflict);
        }
        let destination = batch.request["destination_id"]
            .as_str()
            .ok_or(StoreError::StateConflict)?;
        let group = id.to_owned();
        let mut created = 0;
        // Bound memory even for tens of thousands of confirmed releases.
        for ordinal in 0..batch.total {
            let row =
                sqlx::query("SELECT preview_json FROM batch_items WHERE batch_id=? AND ordinal=?")
                    .bind(id)
                    .bind(ordinal)
                    .fetch_one(&mut *tx)
                    .await?;
            let preview: Value = serde_json::from_str(row.get("preview_json"))?;
            let plan: Plan = serde_json::from_value(preview["plan"].clone())?;
            created += i64::from(
                insert_job(&mut tx, &plan, destination, Some(&group), &now())
                    .await?
                    .1,
            );
        }
        let response = serde_json::json!({"group_id":group,"created":created,"existing":batch.total-created,"total":batch.total});
        sqlx::query("INSERT INTO group_requests VALUES(?,?,?,?)")
            .bind(key)
            .bind(fingerprint)
            .bind(serde_json::to_string(&response)?)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE selection_tasks SET state='submitted',updated_at=? WHERE id=?")
            .bind(now())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "selections.changed", id).await?;
        tx.commit().await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    async fn interactive_scans_coalesce_and_expire_without_reusing_canceled_or_other_accounts() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let request =
            json!({"reference":{"provider":"test","id":"series"},"credential_profile":null});
        let (a, b) = tokio::join!(
            store.cached_snapshot(&request, "v1"),
            store.cached_snapshot(&request, "v1")
        );
        let a = a.unwrap();
        assert_eq!(a.id, b.unwrap().id);
        assert_ne!(
            a.id,
            store.cached_snapshot(&request, "v2").await.unwrap().id
        );
        assert_ne!(a.id,store.cached_snapshot(&json!({"reference":{"provider":"test","id":"series"},"credential_profile":"other"}),"v1").await.unwrap().id);
        store
            .selection_state(&a.id, "canceled", None)
            .await
            .unwrap();
        let fresh = store.cached_snapshot(&request, "v1").await.unwrap();
        assert_ne!(a.id, fresh.id);
        sqlx::query("UPDATE selection_tasks SET created_at='2000-01-01' WHERE id=?")
            .bind(&fresh.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_ne!(
            fresh.id,
            store.cached_snapshot(&request, "v1").await.unwrap().id
        );
    }
    fn release(n: usize) -> Release {
        let mut plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        plan.release.reference.id = format!("release-{n}");
        plan.release.position = n as u64;
        plan.release.title = format!("Chapter {n}");
        plan.release
    }
    #[tokio::test]
    async fn snapshot_restart_pagination_and_atomic_continuations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let mut store = Store::open(&path).await.unwrap();
        let initial = store
            .create_snapshot(
                &json!({"reference":release(0).collection}),
                "approved-source",
            )
            .await
            .unwrap();
        for start in (0..2405).step_by(200) {
            let task = store.selection_task(&initial.id).await.unwrap();
            let end = (start + 200).min(2405);
            let page = Page {
                items: (start..end).map(release).collect(),
                next_cursor: (end < 2405).then(|| end.to_string()),
            };
            store.append_snapshot(&task, &page).await.unwrap();
            assert!(store.append_snapshot(&task, &page).await.is_err());
            if start == 400 {
                store.pool.close().await;
                store = Store::open(&path).await.unwrap();
                store.recover().await.unwrap();
            }
        }
        let ready = store.selection_task(&initial.id).await.unwrap();
        assert_eq!((ready.state.as_str(), ready.total), ("ready", 2405));
        let mut cursor = -1;
        let mut refs = std::collections::BTreeSet::new();
        loop {
            let page = store
                .snapshot_page(&ready.id, "", cursor, 137)
                .await
                .unwrap();
            for r in page.items {
                assert!(refs.insert(r.reference.key()));
            }
            match page.next_cursor {
                Some(c) => cursor = c.parse().unwrap(),
                None => break,
            }
        }
        assert_eq!(refs.len(), 2405);
        assert_eq!(
            store
                .snapshot_page(&ready.id, "Chapter 2404", -1, 200)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        assert!(
            store
                .append_snapshot(
                    &ready,
                    &Page {
                        items: vec![release(5000)],
                        next_cursor: None
                    }
                )
                .await
                .is_err()
        );
        let fresh = store.create_snapshot(&json!({}), "source").await.unwrap();
        store
            .append_snapshot(
                &fresh,
                &Page {
                    items: vec![release(0)],
                    next_cursor: Some("next".into()),
                },
            )
            .await
            .unwrap();
        let current = store.selection_task(&fresh.id).await.unwrap();
        assert!(
            store
                .append_snapshot(
                    &current,
                    &Page {
                        items: vec![release(1)],
                        next_cursor: Some("next".into())
                    }
                )
                .await
                .is_err()
        );
        assert!(
            store
                .append_snapshot(
                    &current,
                    &Page {
                        items: vec![release(0)],
                        next_cursor: None
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(store.selection_task(&fresh.id).await.unwrap().processed, 1);
        store
            .selection_state(&fresh.id, "canceled", None)
            .await
            .unwrap();
        assert!(
            store
                .append_snapshot(
                    &current,
                    &Page {
                        items: vec![release(1)],
                        next_cursor: None
                    }
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn bulk_over_2000_restart_preview_expiry_replay_and_no_partial_submission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db");
        let mut store = Store::open(&path).await.unwrap();
        let dest = store.add_destination("Files", dir.path()).await.unwrap();
        let snapshot = store.create_snapshot(&json!({}), "source").await.unwrap();
        for start in (0..2005).step_by(200) {
            let end = (start + 200).min(2005);
            let task = store.selection_task(&snapshot.id).await.unwrap();
            store
                .append_snapshot(
                    &task,
                    &Page {
                        items: (start..end).map(release).collect(),
                        next_cursor: (end < 2005).then(|| end.to_string()),
                    },
                )
                .await
                .unwrap();
        }
        let policy = SelectionPolicy {
            languages: vec![],
            ..Default::default()
        };
        let batch = store
            .create_batch(
                &snapshot.id,
                &json!({"destination_id":dest.id}),
                &policy,
                None,
            )
            .await
            .unwrap();
        assert_eq!(batch.total, 2005);
        assert!(
            store
                .enqueue_batch(&batch.id, "key", "fingerprint")
                .await
                .is_err()
        );
        for n in 0..2005 {
            let task = store.selection_task(&batch.id).await.unwrap();
            let r = store.batch_release(&task).await.unwrap();
            assert_eq!(r.reference, release(n).reference);
            let mut plan: Plan =
                serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
            plan.release = r;
            plan.final_relative_path = format!("chapter-{n}");
            store.append_batch(&task,&json!({"plan":plan,"files":[format!("chapter-{n}/chapter.cbz")],"outcome":"download"})).await.unwrap();
            if n == 999 {
                store
                    .selection_state(&batch.id, "canceled", None)
                    .await
                    .unwrap();
                let canceled = store.selection_task(&batch.id).await.unwrap();
                assert_eq!(canceled.outcomes.get("download"), Some(&1000));
                store
                    .selection_state(&batch.id, "working", None)
                    .await
                    .unwrap();
                assert_eq!(
                    store.selection_task(&batch.id).await.unwrap().processed,
                    1000
                );
                store.pool.close().await;
                store = Store::open(&path).await.unwrap();
                store.recover().await.unwrap();
            }
        }
        let mut count = 0;
        let mut cursor = -1;
        loop {
            let page = store.batch_page(&batch.id, cursor, 131).await.unwrap();
            count += page.items.len();
            match page.next_cursor {
                Some(c) => cursor = c.parse().unwrap(),
                None => break,
            }
        }
        assert_eq!(count, 2005);
        assert_eq!(
            store
                .selection_task(&batch.id)
                .await
                .unwrap()
                .outcomes
                .get("download"),
            Some(&2005)
        );
        let response = store
            .enqueue_batch(&batch.id, "key", "fingerprint")
            .await
            .unwrap();
        assert_eq!(response["created"], 2005);
        sqlx::query("UPDATE selection_tasks SET expires_at='2000-01-01' WHERE id=?")
            .bind(&batch.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store
                .enqueue_batch(&batch.id, "key", "fingerprint")
                .await
                .unwrap(),
            response
        );
        assert!(matches!(
            store.enqueue_batch(&batch.id, "key", "changed").await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(
            store
                .enqueue_batch(&batch.id, "new-key", "fingerprint")
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs")
                .fetch_one(&store.pool)
                .await
                .unwrap(),
            2005
        );
    }
}
