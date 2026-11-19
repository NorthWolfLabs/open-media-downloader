//! Complete source observations with durable, bounded pages. An interrupted scan
//! resumes the approved component and cursor; observations only advance at commit.
use super::*;

pub async fn begin(
    store: &Store,
    subscription: &Subscription,
    source_digest: &str,
) -> Result<String> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let current = observation_current(&mut tx, subscription).await?;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT snapshot_id FROM subscription_scans WHERE subscription_id=?")
            .bind(&current.id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(id) = existing {
        return Ok(id);
    }
    let snapshot = id("subscription_scan");
    let request = serde_json::json!({"reference":current.request.target,"credential_profile":current.request.credential_profile,"search":current.request.search,"policy":current.request.policy});
    sqlx::query("INSERT INTO selection_tasks(id,kind,state,request_json,source_digest,created_at,updated_at) VALUES(?,'snapshot','working',?,?,?,?)")
        .bind(&snapshot).bind(serde_json::to_string(&request)?).bind(source_digest).bind(now()).bind(now()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO subscription_scans VALUES(?,?,?)")
        .bind(&current.id)
        .bind(&snapshot)
        .bind(serde_json::to_string(&current.request)?)
        .execute(&mut *tx)
        .await?;
    emit(&mut tx, "subscriptions.changed", &current.id).await?;
    tx.commit().await?;
    Ok(snapshot)
}

/// Disposing a stale scan does not remove observations or pending effects.
/// The page worker compares progress under a write lock before every append.
pub(super) async fn discard(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    subscription: &str,
) -> Result<()> {
    let snapshot: Option<String> =
        sqlx::query_scalar("SELECT snapshot_id FROM subscription_scans WHERE subscription_id=?")
            .bind(subscription)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(snapshot) = snapshot {
        sqlx::query("DELETE FROM subscription_scans WHERE subscription_id=?")
            .bind(subscription)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM snapshot_releases WHERE snapshot_id=?")
            .bind(&snapshot)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM snapshot_cursors WHERE snapshot_id=?")
            .bind(&snapshot)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM selection_tasks WHERE id=?")
            .bind(&snapshot)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Commit one complete snapshot. No source call or entire-collection Vec occurs
/// inside this transaction. Crash before commit repeats the same deduplication keys.
pub async fn settle(store: &Store) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let row = sqlx::query("SELECT s.*,l.snapshot_id,l.request_json,t.state AS scan_state,t.issue_json AS scan_issue,t.expires_at FROM subscription_scans l JOIN subscriptions s ON s.id=l.subscription_id JOIN selection_tasks t ON t.id=l.snapshot_id WHERE t.state!='working' ORDER BY t.updated_at,t.id LIMIT 1")
        .fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Ok(false) };
    let snapshot: String = row.get("snapshot_id");
    let state: String = row.get("scan_state");
    let expected: SubscribeRequest = serde_json::from_str(row.get("request_json"))?;
    let issue: Option<String> = row.get("scan_issue");
    let expired = row
        .get::<Option<String>, _>("expires_at")
        .is_some_and(|v| v < now());
    let current = from_row(row)?;
    if !current.enabled
        || serde_json::to_value(&expected)? != serde_json::to_value(&current.request)?
    {
        discard(&mut tx, &current.id).await?;
    } else if state == "ready" && !expired {
        let mut cursor = -1_i64;
        let time = now();
        loop {
            let page = sqlx::query("SELECT ordinal,data_json FROM snapshot_releases WHERE snapshot_id=? AND ordinal>? ORDER BY ordinal LIMIT 200")
                .bind(&snapshot).bind(cursor).fetch_all(&mut *tx).await?;
            if page.is_empty() {
                break;
            }
            for row in page {
                let release: Release = serde_json::from_str(row.get("data_json"))?;
                observation_release(&mut tx, &current, &release, &time).await?;
                cursor = row.get("ordinal");
            }
        }
        observation_finish(&mut tx, &current, &time).await?;
        discard(&mut tx, &current.id).await?;
    } else {
        let mut problem = issue.map(|s|serde_json::from_str::<Problem>(&s)).transpose()?.unwrap_or_else(||Problem::new("subscription_reconciliation", "This collection scan must restart. Earlier observations and pending downloads are preserved."));
        // A cursor may cease to be usable even with unchanged package bytes.
        // The next scheduled attempt performs a full reconciliation, never a new baseline.
        problem.actions = vec!["check_subscription".into()];
        failure(&mut tx, &current, &problem).await?;
        discard(&mut tx, &current.id).await?;
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap()
    }
    async fn subscription(store: &Store, include_existing: bool) -> Subscription {
        let plan = plan();
        create(
            store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference,
                policy: plan.policy,
                action: ActionPolicy::Download,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing,
                interval_minutes: 15,
                credential_profile: None,
            },
        )
        .await
        .unwrap()
    }
    async fn page(store: &Store, snapshot: &str, start: usize, count: usize, more: bool) {
        let task = store.selection_task(snapshot).await.unwrap();
        let items = (start..start + count)
            .map(|i| {
                let mut release = plan().release;
                release.reference.id = format!("release-{i}");
                release.title = format!("Chapter {i}");
                release
            })
            .collect();
        store
            .append_snapshot(
                &task,
                &Page {
                    items,
                    next_cursor: more.then(|| (start + count).to_string()),
                },
            )
            .await
            .unwrap();
    }
    async fn count(store: &Store, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }
    #[tokio::test]
    async fn long_scan_resumes_pages_and_observation_commit_is_atomic() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let sub = subscription(&store, true).await;
        let snapshot = begin(&store, &sub, "original-component").await.unwrap();
        assert_eq!(
            begin(&store, &sub, "new-component").await.unwrap(),
            snapshot,
            "an active observation cannot mix component versions"
        );
        assert!(next_due(&store).await.unwrap().is_none());
        page(&store, &snapshot, 0, 200, true).await;
        let progress = get(&store, &sub.id).await.unwrap().current_check.unwrap();
        assert_eq!(progress.processed, 200);
        assert_eq!(progress.source_digest, "original-component");
        assert!(!settle(&store).await.unwrap());
        assert_eq!(count(&store, "observations").await, 0);
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        let recovered = store.selection_task(&snapshot).await.unwrap();
        assert_eq!(recovered.cursor.as_deref(), Some("200"));
        page(&store, &snapshot, 200, 200, true).await;
        page(&store, &snapshot, 400, 51, false).await;
        // Simulate failure after every observation/action was inserted but before
        // the final success marker. All effects must roll back together.
        sqlx::query("CREATE TRIGGER fail_observation BEFORE UPDATE OF initialized ON subscriptions BEGIN SELECT RAISE(ABORT,'fixture interruption'); END").execute(&store.pool).await.unwrap();
        assert!(settle(&store).await.is_err());
        assert_eq!(count(&store, "observations").await, 0);
        assert_eq!(count(&store, "actions").await, 0);
        sqlx::query("DROP TRIGGER fail_observation")
            .execute(&store.pool)
            .await
            .unwrap();
        store.pool.close().await;
        let store = Store::open(&db).await.unwrap();
        assert!(settle(&store).await.unwrap());
        assert_eq!(count(&store, "observations").await, 451);
        assert_eq!(count(&store, "actions").await, 451);
        assert_eq!(
            count(&store, "selection_tasks").await,
            0,
            "polling must not accumulate discarded full feeds"
        );
        assert!(!settle(&store).await.unwrap());
        let current = get(&store, &sub.id).await.unwrap();
        assert!(current.initialized);
        assert!(current.current_check.is_none());
        let snapshot = begin(&store, &current, "updated-component").await.unwrap();
        page(&store, &snapshot, 0, 200, true).await;
        page(&store, &snapshot, 200, 200, true).await;
        page(&store, &snapshot, 400, 52, false).await;
        settle(&store).await.unwrap();
        assert_eq!(
            count(&store, "actions").await,
            452,
            "an updated component reconciles with prior observations"
        );
    }
    #[tokio::test]
    async fn failed_cursor_does_not_reset_future_only_baseline_or_lose_actions() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let sub = subscription(&store, false).await;
        let snapshot = begin(&store, &sub, "a").await.unwrap();
        page(&store, &snapshot, 0, 2, false).await;
        settle(&store).await.unwrap();
        assert_eq!(count(&store, "actions").await, 0);
        let current = get(&store, &sub.id).await.unwrap();
        let snapshot = begin(&store, &current, "b").await.unwrap();
        page(&store, &snapshot, 0, 2, true).await;
        store
            .selection_state(
                &snapshot,
                "failed",
                Some(&Problem::new(
                    "cursor_expired",
                    "The source cursor expired.",
                )),
            )
            .await
            .unwrap();
        settle(&store).await.unwrap();
        let failed = get(&store, &sub.id).await.unwrap();
        assert!(failed.initialized);
        assert_eq!(failed.issue.as_ref().unwrap().code, "cursor_expired");
        let snapshot = begin(&store, &failed, "b").await.unwrap();
        page(&store, &snapshot, 0, 3, false).await;
        settle(&store).await.unwrap();
        assert_eq!(
            count(&store, "actions").await,
            1,
            "new releases after an incompatible cursor are not silently baselined away"
        );
    }
    #[tokio::test]
    async fn edits_pause_and_slow_scans_do_not_mix_policies_or_block_existing_actions() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let sub = subscription(&store, true).await;
        let snapshot = begin(&store, &sub, "a").await.unwrap();
        page(&store, &snapshot, 0, 1, false).await;
        settle(&store).await.unwrap();
        let snapshot = begin(&store, &get(&store, &sub.id).await.unwrap(), "a")
            .await
            .unwrap();
        page(&store, &snapshot, 0, 200, true).await;
        assert!(
            pending_action(&store).await.unwrap().is_some(),
            "queued effects run while another scan awaits more pages"
        );
        // The running action prevents policy edits until it has a durable result.
        let action: String = sqlx::query_scalar("SELECT id FROM actions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        finish_action(&store, &action, Some("job"), None)
            .await
            .unwrap();
        let stale = store.selection_task(&snapshot).await.unwrap();
        let mut request = sub.request.clone();
        request.policy.languages = vec!["ja".into()];
        update(&store, &sub.id, request).await.unwrap();
        assert!(store.selection_task(&snapshot).await.is_err());
        assert!(
            store
                .append_snapshot(
                    &stale,
                    &Page::<Release> {
                        items: vec![],
                        next_cursor: None
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(count(&store, "observations").await, 1);
        let snapshot = begin(&store, &get(&store, &sub.id).await.unwrap(), "a")
            .await
            .unwrap();
        action_pause(&store, &sub.id).await;
        assert!(store.selection_task(&snapshot).await.is_err());
        assert_eq!(count(&store, "actions").await, 1);
    }
    #[tokio::test]
    async fn overlapping_subscription_actions_recover_into_one_shared_job() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let destination = store.add_destination("Files", root.path()).await.unwrap();
        let mut original = plan();
        let mut a = subscription(&store, true).await;
        a.request.destination_id = destination.id.clone();
        a = update(&store, &a.id, a.request.clone()).await.unwrap();
        let mut request = a.request.clone();
        request.target.id = "overlapping-collection".into();
        let b = create(&store, request).await.unwrap();
        observe(&store, &a, &[original.release.clone()])
            .await
            .unwrap();
        let mut overlap = original.release.clone();
        overlap.collection = b.request.target.clone();
        observe(&store, &b, &[overlap]).await.unwrap();
        let (action_id, sub, release) = pending_action(&store).await.unwrap().unwrap();
        original.release = release;
        original.collection.reference = sub.request.target;
        let (first, created) = store
            .enqueue(
                &original,
                &destination.id,
                &format!("subscription:{action_id}"),
                &action_id,
                Some(&sub.id),
            )
            .await
            .unwrap();
        assert!(created);
        // Engine interruption after the job transaction but before action completion.
        store.recover().await.unwrap();
        let mut finished = 0;
        while let Some((id, sub, release)) = pending_action(&store).await.unwrap() {
            let mut resolved = plan();
            resolved.release = release;
            resolved.collection.reference = sub.request.target;
            let (job, created) = store
                .enqueue(
                    &resolved,
                    &destination.id,
                    &format!("subscription:{id}"),
                    &id,
                    Some(&sub.id),
                )
                .await
                .unwrap();
            assert!(!created);
            assert_eq!(job.id, first.id);
            finish_action(&store, &id, Some(&job.id), None)
                .await
                .unwrap();
            finished += 1;
        }
        assert_eq!(finished, 2);
        assert_eq!(count(&store, "jobs").await, 1);
        assert_eq!(count(&store, "job_group_members").await, 2);
    }
    #[tokio::test]
    async fn edited_language_can_include_previously_observed_missing_releases() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let sub = subscription(&store, false).await;
        let mut japanese = plan().release;
        japanese.language = Some("ja".into());
        observe(&store, &sub, &[japanese.clone()]).await.unwrap();
        assert_eq!(count(&store, "actions").await, 0);
        let mut request = sub.request.clone();
        request.policy.languages = vec!["ja".into()];
        request.include_existing = true;
        let edited = update(&store, &sub.id, request).await.unwrap();
        observe(&store, &edited, &[japanese]).await.unwrap();
        assert_eq!(count(&store, "actions").await, 1);
    }
    #[tokio::test]
    async fn saved_search_baseline_survives_restart_and_deduplicates_reordered_matches() {
        let root = tempfile::tempdir().unwrap();
        let db = root.path().join("db");
        let store = Store::open(&db).await.unwrap();
        let mut request = subscription(&store, false).await.request;
        request.search = Some(SubscriptionSearch {
            query: "  space  ".into(),
            discovery: Some(DiscoveryQuery::default()),
        });
        request.action = ActionPolicy::Notify;
        let sub = create(&store, request.clone()).await.unwrap();
        assert_eq!(sub.title.as_deref(), Some("space"));
        assert_eq!(
            search(&store, "space", None, 100)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        assert_eq!(create(&store, request.clone()).await.unwrap().id, sub.id);
        let mut filtered = request.clone();
        filtered
            .search
            .as_mut()
            .unwrap()
            .discovery
            .as_mut()
            .unwrap()
            .filters
            .insert("tags".into(), vec!["b".into(), "a".into()]);
        let another = create(&store, filtered.clone()).await.unwrap();
        assert_ne!(another.id, sub.id);
        filtered
            .search
            .as_mut()
            .unwrap()
            .discovery
            .as_mut()
            .unwrap()
            .filters
            .insert("tags".into(), vec!["a".into(), "b".into(), "a".into()]);
        assert_eq!(create(&store, filtered).await.unwrap().id, another.id);
        let mut invalid = request.clone();
        invalid.action = ActionPolicy::Download;
        assert!(create(&store, invalid).await.is_err());
        let make = |id: &str| {
            let mut r = plan().release;
            r.reference.id = id.into();
            r.collection = sub.request.target.clone();
            r.revision = None;
            r
        };
        let snap = begin(&store, &sub, "source-v1").await.unwrap();
        let task = store.selection_task(&snap).await.unwrap();
        store
            .append_snapshot(
                &task,
                &Page {
                    items: vec![make("a"), make("b")],
                    next_cursor: Some("next".into()),
                },
            )
            .await
            .unwrap();
        drop(store);
        let store = Store::open(&db).await.unwrap();
        let task = store.selection_task(&snap).await.unwrap();
        assert_eq!(task.cursor.as_deref(), Some("next"));
        // Rank shifts can repeat identities without creating duplicate notifications.
        store
            .append_snapshot(
                &task,
                &Page {
                    items: vec![make("b"), make("c")],
                    next_cursor: None,
                },
            )
            .await
            .unwrap();
        settle(&store).await.unwrap();
        assert_eq!(count(&store, "actions").await, 0);
        let current = get(&store, &sub.id).await.unwrap();
        assert!(current.initialized);
        let snap = begin(&store, &current, "source-v2").await.unwrap();
        let task = store.selection_task(&snap).await.unwrap();
        store
            .append_snapshot(
                &task,
                &Page {
                    items: vec![make("c"), make("new"), make("a")],
                    next_cursor: None,
                },
            )
            .await
            .unwrap();
        settle(&store).await.unwrap();
        assert_eq!(count(&store, "actions").await, 1);
        assert!(
            pending_action(&store).await.unwrap().is_none(),
            "Search notifications never resolve a collection as a release"
        );
        let current = get(&store, &sub.id).await.unwrap();
        observe(&store, &current, &[make("b"), make("new")])
            .await
            .unwrap();
        assert_eq!(
            count(&store, "actions").await,
            1,
            "Disappearing and returning matches remain seen"
        );
        let mut stripped = current.request.clone();
        stripped.search = None;
        assert!(update(&store, &sub.id, stripped).await.is_err());
        let mut changed = current.request.clone();
        changed.search.as_mut().unwrap().query = "different".into();
        assert!(update(&store, &sub.id, changed).await.is_err());
        let mut account = current.request.clone();
        account.credential_profile = Some("other-account".into());
        let updated = update(&store, &sub.id, account).await.unwrap();
        assert!(!updated.initialized);
        assert!(observe(&store, &current, &[]).await.is_err());
        observe(&store, &updated, &[make("account-existing")])
            .await
            .unwrap();
        assert_eq!(count(&store, "actions").await, 1);
    }

    async fn action_pause(store: &Store, id: &str) {
        super::super::action(store, id, "pause").await.unwrap();
    }
}
