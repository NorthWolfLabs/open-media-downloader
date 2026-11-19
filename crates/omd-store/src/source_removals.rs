//! Revocation and cleanup intent commit before any package or vault mutation.
use super::*;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceRemovalReview {
    pub provider: String,
    pub name: String,
    pub approval_digest: String,
    pub enabled: bool,
    pub versions: i64,
    pub jobs: i64,
    pub subscriptions: i64,
    pub accounts: i64,
    pub previous_removal: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceRemoval {
    pub id: String,
    pub review: SourceRemovalReview,
    pub state: String,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
    pub total: i64,
    pub processed: i64,
    pub retained: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceRemovalEntry {
    pub kind: String,
    pub item_key: String,
    pub state: String,
    pub issue: Option<Problem>,
}
const SELECT: &str = "SELECT r.*,(SELECT COUNT(*) FROM source_removal_entries e WHERE e.removal_id=r.id) AS total,(SELECT COUNT(*) FROM source_removal_entries e WHERE e.removal_id=r.id AND e.state<>'pending') AS processed,(SELECT COUNT(*) FROM source_removal_entries e WHERE e.removal_id=r.id AND e.state='retained') AS retained FROM source_removals r";
fn decode(r: sqlx::sqlite::SqliteRow) -> Result<SourceRemoval> {
    Ok(SourceRemoval {
        id: r.get("id"),
        review: serde_json::from_str(r.get("review_json"))?,
        state: r.get("state"),
        issue: r
            .get::<Option<String>, _>("issue_json")
            .map(|s| serde_json::from_str(&s))
            .transpose()?,
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        total: r.get("total"),
        processed: r.get("processed"),
        retained: r.get("retained"),
    })
}
async fn review(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    provider: &str,
) -> Result<SourceRemovalReview> {
    let r=sqlx::query("SELECT p.*,json_extract(v.manifest_json,'$.name') AS name FROM providers p JOIN provider_versions v ON v.provider_id=p.id AND v.digest=p.active_digest WHERE p.id=?").bind(provider).fetch_optional(&mut **tx).await?.ok_or(StoreError::NotFound)?;
    let revision: i64 = r.get("revision");
    let active: String = r.get("active_digest");
    let approval_digest = digest(&serde_json::to_vec(&(provider, revision, active))?);
    let versions = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provider_versions WHERE provider_id=? AND approved=1",
    )
    .bind(provider)
    .fetch_one(&mut **tx)
    .await?;
    let jobs=sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE json_extract(plan_json,'$.release.reference.provider')=? AND state IN ('queued','transferring','verifying','paused','failed')").bind(provider).fetch_one(&mut **tx).await?;
    let subscriptions = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscriptions WHERE json_extract(data_json,'$.target.provider')=?",
    )
    .bind(provider)
    .fetch_one(&mut **tx)
    .await?;
    let accounts = sqlx::query_scalar("SELECT COUNT(*) FROM credential_profiles WHERE provider=?")
        .bind(provider)
        .fetch_one(&mut **tx)
        .await?;
    let previous_removal = sqlx::query_scalar(
        "SELECT id FROM source_removals WHERE provider=? ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(provider)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(SourceRemovalReview {
        provider: provider.into(),
        name: r.get("name"),
        approval_digest,
        enabled: r.get::<i64, _>("enabled") != 0,
        versions,
        jobs,
        subscriptions,
        accounts,
        previous_removal,
    })
}
impl Store {
    pub async fn review_source_removal(&self, provider: &str) -> Result<SourceRemovalReview> {
        let mut tx = self.pool.begin().await?;
        let value = review(&mut tx, provider).await?;
        tx.commit().await?;
        Ok(value)
    }
    pub async fn source_removal(&self, id: &str) -> Result<SourceRemoval> {
        decode(
            sqlx::query(&format!("{SELECT} WHERE r.id=?"))
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StoreError::NotFound)?,
        )
    }
    pub async fn source_removals(
        &self,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SourceRemoval>> {
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query(&format!("{SELECT} WHERE instr(lower(r.provider||json_extract(r.review_json,'$.name')),lower(?))>0 AND (? IS NULL OR r.created_at||':'||r.id<?) ORDER BY r.created_at DESC,r.id DESC LIMIT ?")).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(decode)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = more
            .then(|| items.last().map(|r| format!("{}:{}", r.created_at, r.id)))
            .flatten();
        Ok(Page { items, next_cursor })
    }
    pub async fn source_removal_entries(
        &self,
        id: &str,
        query: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SourceRemovalEntry>> {
        self.source_removal(id).await?;
        let limit = limit.clamp(1, 200) as usize;
        let rows=sqlx::query("SELECT * FROM source_removal_entries WHERE removal_id=? AND instr(lower(kind||item_key),lower(?))>0 AND (? IS NULL OR kind||':'||item_key>?) ORDER BY kind,item_key LIMIT ?").bind(id).bind(query).bind(cursor).bind(cursor).bind((limit+1) as i64).fetch_all(&self.pool).await?;
        let more = rows.len() > limit;
        let items = rows
            .into_iter()
            .take(limit)
            .map(|r| {
                Ok(SourceRemovalEntry {
                    kind: r.get("kind"),
                    item_key: r.get("item_key"),
                    state: r.get("state"),
                    issue: r
                        .get::<Option<String>, _>("issue_json")
                        .map(|s| serde_json::from_str(&s))
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = more
            .then(|| items.last().map(|e| format!("{}:{}", e.kind, e.item_key)))
            .flatten();
        Ok(Page { items, next_cursor })
    }
    pub async fn remove_source(&self, provider: &str, approval: &str) -> Result<SourceRemoval> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(id) = sqlx::query_scalar::<_, String>(
            "SELECT id FROM source_removals WHERE provider=? AND approval_digest=?",
        )
        .bind(provider)
        .bind(approval)
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.commit().await?;
            return self.source_removal(&id).await;
        }
        let reviewed = review(&mut tx, provider).await?;
        if !reviewed.enabled || reviewed.approval_digest != approval {
            return Err(StoreError::StateConflict);
        }
        let id = id("source_removal");
        let time = now();
        let issue=serde_json::to_string(&Problem{code:"source_removed".into(),message:"The source was removed. Reinstall and approve its package before resuming this work.".into(),retryable:false,actions:vec!["install_source".into()]})?;
        sqlx::query("INSERT INTO source_removals VALUES(?,?,?,?,'working',NULL,?,?)")
            .bind(&id)
            .bind(provider)
            .bind(serde_json::to_string(&reviewed)?)
            .bind(approval)
            .bind(&time)
            .bind(&time)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO source_removal_entries SELECT ?,'component',digest,'pending',NULL FROM provider_versions WHERE provider_id=? AND approved=1").bind(&id).bind(provider).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO source_removal_entries SELECT ?,'account',profile,'pending',NULL FROM credential_profiles WHERE provider=?").bind(&id).bind(provider).execute(&mut *tx).await?;
        sqlx::query("UPDATE source_removals SET state='complete' WHERE id=? AND NOT EXISTS(SELECT 1 FROM source_removal_entries WHERE removal_id=?)").bind(&id).bind(&id).execute(&mut *tx).await?;
        sqlx::query("UPDATE providers SET enabled=0,revision=revision+1 WHERE id=?")
            .bind(provider)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE provider_versions SET approved=0 WHERE provider_id=?")
            .bind(provider)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE jobs SET state='paused',issue_json=?,updated_at=? WHERE json_extract(plan_json,'$.release.reference.provider')=? AND state IN ('queued','transferring','verifying','paused','failed')").bind(&issue).bind(&time).bind(provider).execute(&mut *tx).await?;
        sqlx::query("UPDATE subscriptions SET enabled=0,issue_json=? WHERE json_extract(data_json,'$.target.provider')=?").bind(&issue).bind(provider).execute(&mut *tx).await?;
        // Delete private observation snapshots, retaining all committed observations.
        let snapshots:Vec<String>=sqlx::query_scalar("SELECT snapshot_id FROM subscription_scans sc JOIN subscriptions s ON s.id=sc.subscription_id WHERE json_extract(s.data_json,'$.target.provider')=?").bind(provider).fetch_all(&mut *tx).await?;
        sqlx::query("DELETE FROM subscription_scans WHERE subscription_id IN (SELECT id FROM subscriptions WHERE json_extract(data_json,'$.target.provider')=?)").bind(provider).execute(&mut *tx).await?;
        for snapshot in snapshots {
            for table in ["snapshot_releases", "snapshot_cursors"] {
                sqlx::query(&format!("DELETE FROM {table} WHERE snapshot_id=?"))
                    .bind(&snapshot)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("DELETE FROM selection_tasks WHERE id=?")
                .bind(snapshot)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("UPDATE selection_tasks SET state='canceled',issue_json=?,updated_at=? WHERE source_digest IN (SELECT digest FROM provider_versions WHERE provider_id=?) AND state IN ('working','ready','failed')").bind(&issue).bind(&time).bind(provider).execute(&mut *tx).await?;
        for event in [
            "sources.changed",
            "source-removals.changed",
            "jobs.changed",
            "groups.changed",
            "subscriptions.changed",
            "selections.changed",
        ] {
            emit(&mut tx, event, provider).await?;
        }
        tx.commit().await?;
        self.source_removal(&id).await
    }
    pub async fn next_source_removal(&self) -> Result<Option<SourceRemoval>> {
        let id:Option<String>=sqlx::query_scalar("SELECT id FROM source_removals WHERE state='working' AND issue_json IS NULL ORDER BY updated_at,id LIMIT 1").fetch_optional(&self.pool).await?;
        match id {
            Some(id) => Ok(Some(self.source_removal(&id).await?)),
            None => Ok(None),
        }
    }
    pub async fn update_source_removal_entry(
        &self,
        id: &str,
        entry: &SourceRemovalEntry,
        state: &str,
        issue: Option<&Problem>,
    ) -> Result<()> {
        if !["removed", "retained"].contains(&state) {
            return Err(StoreError::StateConflict);
        }
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query("UPDATE source_removal_entries SET state=?,issue_json=? WHERE removal_id=? AND kind=? AND item_key=? AND state='pending'").bind(state).bind(issue.map(serde_json::to_string).transpose()?).bind(id).bind(&entry.kind).bind(&entry.item_key).execute(&mut *tx).await?;
        sqlx::query("UPDATE source_removals SET updated_at=?,state=CASE WHEN EXISTS(SELECT 1 FROM source_removal_entries WHERE removal_id=? AND state='pending') THEN 'working' ELSE 'complete' END WHERE id=?").bind(now()).bind(id).bind(id).execute(&mut *tx).await?;
        emit(&mut tx, "source-removals.changed", id).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn source_removal_issue(&self, id: &str, issue: Option<&Problem>) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE source_removals SET issue_json=?,updated_at=? WHERE id=? AND state='working'",
        )
        .bind(issue.map(serde_json::to_string).transpose()?)
        .bind(now())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        emit(&mut tx, "source-removals.changed", id).await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn removal_revokes_approved_versions_atomically_and_preserves_acquisitions_and_observations()
     {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let downloads = root.path().join("downloads");
        std::fs::create_dir(&downloads).unwrap();
        let destination = store.add_destination("Files", &downloads).await.unwrap();
        let mut plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let provider = plan.release.reference.provider.clone();
        plan.provider_digest = "first".into();
        let mut manifest:ProviderManifest=serde_json::from_value(serde_json::json!({"api":"omd:provider@2","id":provider,"name":"Fixture source","version":"1","description":"fixture","source_hosts":["example.com"],"capabilities":["releases"],"grants":[]})).unwrap();
        store
            .install_provider(&manifest, "first", "unused")
            .await
            .unwrap();
        let (saved, _) = store
            .enqueue(&plan, &destination.id, "saved", "saved", None)
            .await
            .unwrap();
        std::fs::write(downloads.join("user-file.txt"), b"preserve this").unwrap();
        store
            .complete(
                &saved.id,
                &[Artifact {
                    id: "saved-file".into(),
                    job_id: saved.id.clone(),
                    relative_path: "user-file.txt".into(),
                    size: 13,
                    sha256: digest(b"preserve this"),
                    media_type: "text/plain".into(),
                    status: FileStatus::Present,
                }],
            )
            .await
            .unwrap();
        let mut pending = plan.clone();
        pending.release.reference.id = "pending".into();
        pending.final_relative_path = "pending/chapter".into();
        let (job, _) = store
            .enqueue(&pending, &destination.id, "pending", "pending", None)
            .await
            .unwrap();
        let request = SubscribeRequest {
            name: None,
            search: None,
            target: plan.collection.reference.clone(),
            policy: plan.policy.clone(),
            action: ActionPolicy::Notify,
            destination_id: destination.id,
            recipe: Recipe::Cbz,
            include_existing: false,
            interval_minutes: 15,
            credential_profile: None,
        };
        sqlx::query("INSERT INTO subscriptions(id,data_json,enabled,initialized,next_check) VALUES('sub',?,1,1,?)").bind(serde_json::to_string(&request).unwrap()).bind(now()).execute(&store.pool).await.unwrap();
        sqlx::query("INSERT INTO observations VALUES('sub','release','revision','{}')")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO credential_profiles VALUES(?,'personal','Personal',?)")
            .bind(&provider)
            .bind(now())
            .execute(&store.pool)
            .await
            .unwrap();
        let public = store
            .create_snapshot(
                &serde_json::json!({"reference":plan.collection.reference}),
                "first",
            )
            .await
            .unwrap();
        let private = store
            .create_snapshot(
                &serde_json::json!({"reference":plan.collection.reference}),
                "first",
            )
            .await
            .unwrap();
        sqlx::query("INSERT INTO subscription_scans VALUES('sub',?,'{}')")
            .bind(&private.id)
            .execute(&store.pool)
            .await
            .unwrap();
        let old = store.review_source_removal(&provider).await.unwrap();
        manifest.version = "2".into();
        store
            .install_provider(&manifest, "second", "unused-second")
            .await
            .unwrap();
        assert!(matches!(
            store.remove_source(&provider, &old.approval_digest).await,
            Err(StoreError::StateConflict)
        ));
        let review = store.review_source_removal(&provider).await.unwrap();
        assert_eq!(
            (
                review.versions,
                review.jobs,
                review.subscriptions,
                review.accounts
            ),
            (2, 1, 1, 1)
        );
        sqlx::query("CREATE TRIGGER reject_source_pause BEFORE UPDATE OF state ON jobs WHEN NEW.state='paused' BEGIN SELECT RAISE(ABORT,'fixture interruption'); END").execute(&store.pool).await.unwrap();
        assert!(
            store
                .remove_source(&provider, &review.approval_digest)
                .await
                .is_err()
        );
        assert!(store.provider_version(&provider, "first").await.is_ok());
        assert_eq!(
            store
                .source_removals("", None, 100)
                .await
                .unwrap()
                .items
                .len(),
            0
        );
        sqlx::query("DROP TRIGGER reject_source_pause")
            .execute(&store.pool)
            .await
            .unwrap();
        let removal = store
            .remove_source(&provider, &review.approval_digest)
            .await
            .unwrap();
        assert_eq!(removal.total, 3);
        assert!(store.provider_version(&provider, "first").await.is_err());
        assert!(store.provider_version(&provider, "second").await.is_err());
        assert!(!store.providers().await.unwrap()[0].3);
        assert_eq!(store.job(&job.id).await.unwrap().state, JobState::Paused);
        assert_eq!(
            store.job(&saved.id).await.unwrap().state,
            JobState::Completed
        );
        assert_eq!(
            std::fs::read(downloads.join("user-file.txt")).unwrap(),
            b"preserve this"
        );
        let observation_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(observation_count, 1);
        assert_eq!(
            store.selection_task(&public.id).await.unwrap().state,
            "canceled"
        );
        assert!(store.selection_task(&private.id).await.is_err());
        let enabled: i64 = sqlx::query_scalar("SELECT enabled FROM subscriptions WHERE id='sub'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(enabled, 0);
        let mut cursor = None;
        let mut count = 0;
        loop {
            let page = store
                .source_removal_entries(&removal.id, "", cursor.as_deref(), 1)
                .await
                .unwrap();
            count += page.items.len();
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(count, 3);
        store
            .install_provider(&manifest, "first", "restored")
            .await
            .unwrap();
        assert!(store.provider_version(&provider, "first").await.is_ok());
        assert!(store.provider_version(&provider, "second").await.is_err());
        assert_eq!(
            store
                .remove_source(&provider, &review.approval_digest)
                .await
                .unwrap()
                .id,
            removal.id
        );
        assert!(
            store.provider_version(&provider, "first").await.is_ok(),
            "Replaying an old removal never revokes newly reviewed installation"
        );
    }
}
