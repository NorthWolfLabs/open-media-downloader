//! Subscription observations and their effects share one durable transaction.
use omd_domain::*;
use omd_store::{Result, Store, StoreError, emit, id, now};
use sqlx::Row;
pub mod scans;

pub async fn create(store: &Store, mut request: SubscribeRequest) -> Result<Subscription> {
    request
        .normalize_search()
        .map_err(|_| StoreError::StateConflict)?;
    if request.interval_minutes < 15 || request.interval_minutes > 7 * 24 * 60 {
        return Err(StoreError::StateConflict);
    }
    let existing: Option<String> = sqlx::query_scalar("SELECT id FROM subscriptions WHERE removed=0 AND json_extract(data_json,'$.target.provider')=? AND json_extract(data_json,'$.target.id')=? LIMIT 1").bind(&request.target.provider).bind(&request.target.id).fetch_optional(&store.pool).await?;
    if let Some(existing) = existing {
        return get(store, &existing).await;
    }
    let subscription = Subscription {
        id: id("sub"),
        title: None,
        request,
        enabled: true,
        initialized: false,
        current_check: None,
        last_success: None,
        next_check: now(),
        issue: None,
    };
    let mut tx = store.pool.begin().await?;
    sqlx::query(
        "INSERT INTO subscriptions(id,data_json,enabled,initialized,next_check) VALUES(?,?,1,0,?)",
    )
    .bind(&subscription.id)
    .bind(serde_json::to_string(&subscription.request)?)
    .bind(&subscription.next_check)
    .execute(&mut *tx)
    .await?;
    emit(&mut tx, "subscriptions.changed", &subscription.id).await?;
    tx.commit().await?;
    get(store, &subscription.id).await
}
pub async fn list(store: &Store, cursor: Option<&str>, limit: u32) -> Result<Page<Subscription>> {
    search(store, "", cursor, limit).await
}
pub async fn search(
    store: &Store,
    query: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<Subscription>> {
    let limit = limit.clamp(1, 200);
    let rows =
        sqlx::query("SELECT subscriptions.*,COALESCE(json_extract(subscriptions.data_json,'$.name'),json_extract(m.data_json,'$.title'),json_extract(c.data_json,'$.title')) AS title,(SELECT json_object('state',t.state,'processed',t.processed,'started_at',t.created_at,'source_digest',t.source_digest) FROM subscription_scans l JOIN selection_tasks t ON t.id=l.snapshot_id WHERE l.subscription_id=subscriptions.id) AS scan_json FROM subscriptions LEFT JOIN collections c ON c.provider_id=json_extract(subscriptions.data_json,'$.target.provider') AND c.source_id=json_extract(subscriptions.data_json,'$.target.id') LEFT JOIN metadata_overrides m ON m.kind='collection' AND m.source_key=c.key WHERE subscriptions.removed=0 AND instr(lower(json_extract(subscriptions.data_json,'$.target.provider') || ':' || json_extract(subscriptions.data_json,'$.target.id') || ' ' || COALESCE(json_extract(subscriptions.data_json,'$.name'),json_extract(m.data_json,'$.title'),json_extract(c.data_json,'$.title'),json_extract(subscriptions.data_json,'$.search.query'),'')),lower(?))>0 AND (? IS NULL OR subscriptions.id>?) ORDER BY subscriptions.id LIMIT ?")
            .bind(query)
            .bind(cursor)
            .bind(cursor)
            .bind(i64::from(limit) + 1)
            .fetch_all(&store.pool)
            .await?;
    let mut items = rows.into_iter().map(from_row).collect::<Result<Vec<_>>>()?;
    let more = items.len() > limit as usize;
    items.truncate(limit as usize);
    let next_cursor = if more {
        items.last().map(|s| s.id.clone())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}
pub async fn get(store: &Store, id: &str) -> Result<Subscription> {
    from_row(
        sqlx::query("SELECT subscriptions.*,COALESCE(json_extract(subscriptions.data_json,'$.name'),json_extract(m.data_json,'$.title'),json_extract(c.data_json,'$.title')) AS title,(SELECT json_object('state',t.state,'processed',t.processed,'started_at',t.created_at,'source_digest',t.source_digest) FROM subscription_scans l JOIN selection_tasks t ON t.id=l.snapshot_id WHERE l.subscription_id=subscriptions.id) AS scan_json FROM subscriptions LEFT JOIN collections c ON c.provider_id=json_extract(subscriptions.data_json,'$.target.provider') AND c.source_id=json_extract(subscriptions.data_json,'$.target.id') LEFT JOIN metadata_overrides m ON m.kind='collection' AND m.source_key=c.key WHERE subscriptions.id=?")
            .bind(id)
            .fetch_optional(&store.pool)
            .await?
            .ok_or(StoreError::NotFound)?,
    )
}
pub async fn update(
    store: &Store,
    id: &str,
    mut request: SubscribeRequest,
) -> Result<Subscription> {
    request
        .normalize_search()
        .map_err(|_| StoreError::StateConflict)?;
    if request.interval_minutes < 15 || request.interval_minutes > 10080 {
        return Err(StoreError::StateConflict);
    }
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let old = from_row(
        sqlx::query("SELECT * FROM subscriptions WHERE id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::NotFound)?,
    )?;
    if old.request.target != request.target
        || old.request.search.is_some() != request.search.is_some()
    {
        return Err(StoreError::StateConflict);
    }
    let mut previous = old.request.clone();
    previous.name = request.name.clone();
    if serde_json::to_value(previous)? == serde_json::to_value(&request)? {
        // Renaming must not interrupt a check, reset its baseline, or change its schedule.
        sqlx::query("UPDATE subscriptions SET data_json=? WHERE id=?")
            .bind(serde_json::to_string(&request)?)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        emit(&mut tx, "subscriptions.changed", id).await?;
        tx.commit().await?;
        return get(store, id).await;
    }
    let running: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM actions WHERE subscription_id=? AND state='running')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if running {
        return Err(StoreError::StateConflict);
    }
    let rebaseline = old.request.credential_profile != request.credential_profile
        || serde_json::to_value(&old.request.policy)? != serde_json::to_value(&request.policy)?;
    sqlx::query("UPDATE subscriptions SET data_json=?,initialized=CASE WHEN ? THEN 0 ELSE initialized END,next_check=?,issue_json=NULL,consecutive_failures=0 WHERE id=?")
        .bind(serde_json::to_string(&request)?).bind(rebaseline).bind(now()).bind(id).execute(&mut *tx).await?;
    let pending = sqlx::query("SELECT id,release_json FROM actions WHERE subscription_id=? AND state IN ('pending','failed')").bind(id).fetch_all(&mut *tx).await?;
    for action in pending {
        let release: Release = serde_json::from_str(action.get("release_json"))?;
        if matches!(request.action, ActionPolicy::Notify) || !request.policy.accepts(&release) {
            sqlx::query("UPDATE actions SET state='notified',issue_json=NULL WHERE id=?")
                .bind(action.get::<String, _>("id"))
                .execute(&mut *tx)
                .await?;
        }
    }
    scans::discard(&mut tx, id).await?;
    emit(&mut tx, "subscriptions.changed", id).await?;
    emit(&mut tx, "inbox.changed", id).await?;
    tx.commit().await?;
    get(store, id).await
}
pub async fn next_due(store: &Store) -> Result<Option<Subscription>> {
    sqlx::query("SELECT * FROM subscriptions WHERE enabled=1 AND next_check<=? AND NOT EXISTS(SELECT 1 FROM subscription_scans WHERE subscription_id=subscriptions.id) ORDER BY next_check,id LIMIT 1").bind(now()).fetch_optional(&store.pool).await?.map(from_row).transpose()
}
fn from_row(r: sqlx::sqlite::SqliteRow) -> Result<Subscription> {
    let issue: Option<String> = r.get("issue_json");
    Ok(Subscription {
        id: r.get("id"),
        title: serde_json::from_str::<SubscribeRequest>(r.get("data_json"))
            .ok()
            .and_then(|request| request.name)
            .or_else(|| r.try_get("title").ok().flatten())
            .or_else(|| {
                serde_json::from_str::<SubscribeRequest>(r.get("data_json"))
                    .ok()?
                    .search
                    .map(|s| s.query)
            }),
        request: serde_json::from_str(r.get("data_json"))?,
        enabled: r.get::<i64, _>("enabled") != 0,
        initialized: r.get::<i64, _>("initialized") != 0,
        current_check: r
            .try_get::<Option<String>, _>("scan_json")
            .ok()
            .flatten()
            .map(|s| serde_json::from_str(&s))
            .transpose()?,
        last_success: r.get("last_success"),
        next_check: r.get("next_check"),
        issue: issue.map(|s| serde_json::from_str(&s)).transpose()?,
    })
}
pub async fn action(store: &Store, id: &str, action: &str) -> Result<()> {
    let mut tx = store.pool.begin().await?;
    let query = match action {
        "pause" => "UPDATE subscriptions SET enabled=0 WHERE id=? AND removed=0",
        "unsubscribe" => "UPDATE subscriptions SET enabled=0,removed=1 WHERE id=? AND removed=0",
        "resume" => {
            "UPDATE subscriptions SET enabled=1,next_check='2000-01-01' WHERE id=? AND removed=0"
        }
        "check" => "UPDATE subscriptions SET next_check='2000-01-01' WHERE id=? AND removed=0",
        _ => return Err(StoreError::StateConflict),
    };
    if sqlx::query(query)
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        != 1
    {
        return Err(StoreError::NotFound);
    }
    if action == "pause" || action == "unsubscribe" {
        scans::discard(&mut tx, id).await?;
    }
    emit(&mut tx, "subscriptions.changed", id).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn observe(
    store: &Store,
    subscription: &Subscription,
    releases: &[Release],
) -> Result<usize> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let current = observation_current(&mut tx, subscription).await?;
    let time = now();
    let mut count = 0;
    for release in releases {
        count += observation_release(&mut tx, &current, release, &time).await?;
    }
    observation_finish(&mut tx, &current, &time).await?;
    tx.commit().await?;
    Ok(count)
}
async fn observation_current(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    subscription: &Subscription,
) -> Result<Subscription> {
    let current = from_row(
        sqlx::query("SELECT * FROM subscriptions WHERE id=?")
            .bind(&subscription.id)
            .fetch_one(&mut **tx)
            .await?,
    )?;
    if !current.enabled {
        return Err(StoreError::StateConflict);
    }
    if serde_json::to_value(&current.request)? != serde_json::to_value(&subscription.request)? {
        // A policy edit during enumeration must not turn a stale, filtered feed
        // into the new policy's initial baseline.
        return Err(StoreError::StateConflict);
    }
    Ok(current)
}
async fn observation_release(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    current: &Subscription,
    release: &Release,
    time: &str,
) -> Result<usize> {
    if release.reference.provider != current.request.target.provider
        || release.collection != current.request.target
    {
        return Err(StoreError::StateConflict);
    }
    // Availability changes are observable even if the source omits revisions.
    let revision = digest(&serde_json::to_vec(&(
        &release.revision,
        &release.availability,
    ))?);
    let inserted = sqlx::query("INSERT OR IGNORE INTO observations VALUES(?,?,?,?)")
        .bind(&current.id)
        .bind(release.reference.key())
        .bind(&revision)
        .bind(serde_json::to_string(release)?)
        .execute(&mut **tx)
        .await?
        .rows_affected()
        == 1;
    if ((inserted && current.initialized)
        || (!current.initialized && current.request.include_existing))
        && (current.request.search.is_some() || current.request.policy.accepts(release))
    {
        let action_id = digest(&serde_json::to_vec(&(
            &current.id,
            release.reference.key(),
            revision,
        ))?);
        let state = match current.request.action {
            ActionPolicy::Notify => "notified",
            ActionPolicy::Download => "pending",
        };
        let created = sqlx::query("INSERT OR IGNORE INTO actions(id,subscription_id,release_json,state,created_at) VALUES(?,?,?,?,?)").bind(&action_id).bind(&current.id).bind(serde_json::to_string(release)?).bind(state).bind(time).execute(&mut **tx).await?.rows_affected();
        if created == 1 {
            sqlx::query("INSERT INTO notification_outbox(action_id,state,created_at) VALUES(?,CASE WHEN COALESCE((SELECT json_extract(value_json,'$.enabled') FROM settings WHERE key='notifications'),0)=1 THEN 'pending' ELSE 'suppressed' END,?)").bind(&action_id).bind(time).execute(&mut **tx).await?;
            emit(tx, "notifications.changed", &action_id).await?;
            emit(tx, "inbox.changed", &action_id).await?;
        }
        return Ok(created as usize);
    }
    Ok(0)
}
async fn observation_finish(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    current: &Subscription,
    time: &str,
) -> Result<()> {
    // Deterministic per-subscription jitter spreads restarts without an ambient RNG.
    let jitter = u64::from_str_radix(&digest(current.id.as_bytes())[..4], 16).unwrap_or(0) % 61;
    let next = (chrono::Utc::now()
        + chrono::Duration::minutes(i64::from(current.request.interval_minutes))
        + chrono::Duration::seconds(jitter as i64))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    sqlx::query("UPDATE subscriptions SET initialized=1,last_success=?,next_check=?,issue_json=NULL,consecutive_failures=0 WHERE id=?").bind(time).bind(next).bind(&current.id).execute(&mut **tx).await?;
    emit(tx, "subscriptions.changed", &current.id).await?;
    Ok(())
}
pub async fn failed(store: &Store, subscription: &Subscription, issue: Problem) -> Result<()> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    failure(&mut tx, subscription, &issue).await?;
    tx.commit().await?;
    Ok(())
}
async fn failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    subscription: &Subscription,
    issue: &Problem,
) -> Result<()> {
    let id = &subscription.id;
    let current: String = sqlx::query_scalar("SELECT data_json FROM subscriptions WHERE id=?")
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
    if current != serde_json::to_string(&subscription.request)? {
        return Err(StoreError::StateConflict);
    }
    let failures: i64 =
        sqlx::query_scalar("SELECT consecutive_failures FROM subscriptions WHERE id=?")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
    let minutes = (15 * (1_i64 << failures.clamp(0, 5))).min(360);
    let jitter = u64::from_str_radix(&digest(id.as_bytes())[..4], 16).unwrap_or(0) % 61;
    let next = (chrono::Utc::now()
        + chrono::Duration::minutes(minutes)
        + chrono::Duration::seconds(jitter as i64))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    sqlx::query("UPDATE subscriptions SET issue_json=?,next_check=?,consecutive_failures=consecutive_failures+1 WHERE id=?")
        .bind(serde_json::to_string(&issue)?)
        .bind(next)
        .bind(id)
        .execute(&mut **tx)
        .await?;
    emit(tx, "subscriptions.changed", id).await?;
    Ok(())
}
pub async fn pending_action(store: &Store) -> Result<Option<(String, Subscription, Release)>> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let row=sqlx::query("UPDATE actions SET state='running',attempts=attempts+1 WHERE id=(SELECT a.id FROM actions a JOIN subscriptions s ON s.id=a.subscription_id WHERE a.state='pending' AND a.next_attempt<=? AND s.enabled=1 ORDER BY a.next_attempt,a.created_at,a.id LIMIT 1) RETURNING *").bind(now()).fetch_optional(&mut *tx).await?;
    let result = if let Some(row) = row {
        let sub = from_row(
            sqlx::query("SELECT * FROM subscriptions WHERE id=?")
                .bind(row.get::<String, _>("subscription_id"))
                .fetch_one(&mut *tx)
                .await?,
        )?;
        Some((
            row.get("id"),
            sub,
            serde_json::from_str(row.get("release_json"))?,
        ))
    } else {
        None
    };
    tx.commit().await?;
    Ok(result)
}
pub async fn finish_action(
    store: &Store,
    action: &str,
    job: Option<&str>,
    issue: Option<&Problem>,
) -> Result<()> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let attempts: i64 =
        sqlx::query_scalar("SELECT attempts FROM actions WHERE id=? AND state='running'")
            .bind(action)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(StoreError::StateConflict)?;
    let retry = issue.is_some_and(|p| p.retryable) && attempts < 5;
    let next = (chrono::Utc::now() + chrono::Duration::minutes(1_i64 << attempts.clamp(0, 5)))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    sqlx::query(
        "UPDATE actions SET state=?,resource_id=?,issue_json=?,next_attempt=? WHERE id=? AND state='running'",
    )
    .bind(if issue.is_some() {
        if retry {"pending"}else{"failed"}
    } else {
        "completed"
    })
    .bind(job)
    .bind(issue.map(serde_json::to_string).transpose()?)
    .bind(next)
    .bind(action)
    .execute(&mut *tx)
    .await?;
    emit(&mut tx, "inbox.changed", action).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn inbox_action(store: &Store, id: &str, action: &str) -> Result<()> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let changed=match action {
        "retry"=>sqlx::query("UPDATE actions SET state='pending',attempts=0,next_attempt='2000-01-01',issue_json=NULL WHERE id=? AND state='failed'").bind(id).execute(&mut *tx).await?.rows_affected(),
        "read"=>sqlx::query("UPDATE actions SET read_at=? WHERE id=?").bind(now()).bind(id).execute(&mut *tx).await?.rows_affected(),
        _=>return Err(StoreError::StateConflict),
    };
    if changed != 1 {
        return Err(StoreError::StateConflict);
    }
    emit(&mut tx, "inbox.changed", id).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn inbox(
    store: &Store,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<serde_json::Value>> {
    search_inbox(store, "", cursor, limit).await
}
pub async fn search_inbox(
    store: &Store,
    query: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<serde_json::Value>> {
    let limit = limit.clamp(1, 200);
    let rows=sqlx::query("SELECT * FROM actions WHERE instr(lower(json_extract(release_json,'$.title')),lower(?))>0 AND (? IS NULL OR created_at || ':' || id < ?) ORDER BY created_at DESC,id DESC LIMIT ?").bind(query).bind(cursor).bind(cursor).bind(i64::from(limit)+1).fetch_all(&store.pool).await?;
    let mut items=rows.into_iter().map(|r|->Result<_>{let issue:Option<String>=r.get("issue_json");Ok(serde_json::json!({"id":r.get::<String,_>("id"),"subscription_id":r.get::<String,_>("subscription_id"),"release":serde_json::from_str::<serde_json::Value>(r.get("release_json"))?,"state":r.get::<String,_>("state"),"job_id":r.get::<Option<String>,_>("resource_id"),"issue":issue.map(|s|serde_json::from_str::<serde_json::Value>(&s)).transpose()?,"created_at":r.get::<String,_>("created_at"),"read_at":r.get::<Option<String>,_>("read_at")}))}).collect::<Result<Vec<_>>>()?;
    let more = items.len() > limit as usize;
    items.truncate(limit as usize);
    let next_cursor = if more {
        items.last().map(|v| {
            format!(
                "{}:{}",
                v["created_at"].as_str().unwrap(),
                v["id"].as_str().unwrap()
            )
        })
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap()
    }
    #[tokio::test]
    async fn rename_survives_restart_without_rebaselining_or_renaming_source() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db");
        let store = Store::open(&path).await.unwrap();
        let plan = plan();
        store.upsert_collection(&plan.collection).await.unwrap();
        let sub = create(
            &store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference.clone(),
                policy: plan.policy,
                action: ActionPolicy::Notify,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing: false,
                interval_minutes: 60,
                credential_profile: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE subscriptions SET initialized=1,next_check='2030-01-01',last_success='2026-01-01' WHERE id=?").bind(&sub.id).execute(&store.pool).await.unwrap();
        let mut request = sub.request;
        request.name = Some("  My reading list  ".into());
        let renamed = update(&store, &sub.id, request).await.unwrap();
        assert_eq!(renamed.title.as_deref(), Some("My reading list"));
        assert!(renamed.initialized);
        assert_eq!(renamed.next_check, "2030-01-01");
        drop(store);
        let store = Store::open(&path).await.unwrap();
        let mut sub = get(&store, &renamed.id).await.unwrap();
        assert_eq!(sub.title.as_deref(), Some("My reading list"));
        assert_eq!(
            search(&store, "reading list", None, 20)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        sub.request.name = None;
        let reset = update(&store, &sub.id, sub.request).await.unwrap();
        assert_eq!(reset.title, Some(plan.collection.title));
        assert_eq!(reset.next_check, "2030-01-01");
    }

    #[tokio::test]
    async fn collection_titles_are_persistent_searchable_and_respect_user_overrides() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("db");
        let store = Store::open(&path).await.unwrap();
        let mut plan = plan();
        let subscription = create(
            &store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference.clone(),
                policy: plan.policy,
                action: ActionPolicy::Notify,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing: false,
                interval_minutes: 60,
                credential_profile: None,
            },
        )
        .await
        .unwrap();
        assert!(subscription.title.is_none());
        plan.collection.title = "Source collection title".into();
        store.upsert_collection(&plan.collection).await.unwrap();
        drop(store);
        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            get(&store, &subscription.id)
                .await
                .unwrap()
                .title
                .as_deref(),
            Some("Source collection title")
        );
        assert_eq!(
            search(&store, "collection title", None, 100)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        store
            .set_metadata_override(
                "collection",
                &plan.collection.reference,
                &MetadataOverride {
                    title: Some("My collection name".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        plan.collection.title = "Updated provider title".into();
        store.upsert_collection(&plan.collection).await.unwrap();
        assert_eq!(
            get(&store, &subscription.id)
                .await
                .unwrap()
                .title
                .as_deref(),
            Some("My collection name")
        );
        assert_eq!(
            search(&store, "my collection", None, 100)
                .await
                .unwrap()
                .items
                .len(),
            1
        );
        let source: String = sqlx::query_scalar("SELECT data_json FROM collections WHERE key=?")
            .bind(plan.collection.reference.key())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Collection>(&source).unwrap().title,
            "Updated provider title"
        );
        store
            .set_metadata_override(
                "collection",
                &plan.collection.reference,
                &MetadataOverride::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            get(&store, &subscription.id)
                .await
                .unwrap()
                .title
                .as_deref(),
            Some("Updated provider title")
        );
    }
    #[tokio::test]
    async fn unsubscribe_retains_history_but_removes_scheduling_and_list_entry() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let p = plan();
        let request = SubscribeRequest {
            name: None,
            search: None,
            target: p.collection.reference,
            policy: p.policy,
            action: ActionPolicy::Notify,
            destination_id: "offline".into(),
            recipe: Recipe::Cbz,
            include_existing: false,
            interval_minutes: 60,
            credential_profile: None,
        };
        let sub = create(&store, request.clone()).await.unwrap();
        assert_eq!(create(&store, request.clone()).await.unwrap().id, sub.id);
        action(&store, &sub.id, "unsubscribe").await.unwrap();
        assert_eq!(store.summary().await.unwrap()["following"], 0);
        assert!(list(&store, None, 100).await.unwrap().items.is_empty());
        assert!(!get(&store, &sub.id).await.unwrap().enabled);
        assert!(next_due(&store).await.unwrap().is_none());
        assert_ne!(create(&store, request).await.unwrap().id, sub.id);
    }
    #[tokio::test]
    async fn observations_and_actions_recover_without_duplicates() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let plan = plan();
        let subscription = create(
            &store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference.clone(),
                policy: plan.policy,
                action: ActionPolicy::Download,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing: true,
                interval_minutes: 15,
                credential_profile: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            observe(&store, &subscription, std::slice::from_ref(&plan.release))
                .await
                .unwrap(),
            1
        );
        let first = pending_action(&store).await.unwrap().unwrap();
        store.recover().await.unwrap();
        assert_eq!(
            observe(&store, &subscription, &[plan.release])
                .await
                .unwrap(),
            0
        );
        let recovered = pending_action(&store).await.unwrap().unwrap();
        assert_eq!(first.0, recovered.0);
        assert!(pending_action(&store).await.unwrap().is_none());
        let mut issue = Problem::new("temporary", "Temporary source failure");
        issue.retryable = true;
        finish_action(&store, &recovered.0, None, Some(&issue))
            .await
            .unwrap();
        assert!(
            pending_action(&store).await.unwrap().is_none(),
            "Backoff must prevent an immediate retry"
        );
        sqlx::query("UPDATE actions SET next_attempt='2000-01-01'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            pending_action(&store).await.unwrap().unwrap().0,
            recovered.0
        );
        issue.retryable = false;
        finish_action(&store, &recovered.0, None, Some(&issue))
            .await
            .unwrap();
        inbox_action(&store, &recovered.0, "retry").await.unwrap();
        assert_eq!(
            pending_action(&store).await.unwrap().unwrap().0,
            recovered.0
        );
        finish_action(&store, &recovered.0, Some("job"), None)
            .await
            .unwrap();
        assert!(
            inbox_action(&store, &recovered.0, "retry").await.is_err(),
            "Completed actions cannot run again"
        );
        inbox_action(&store, &recovered.0, "read").await.unwrap();
        assert!(!inbox(&store, None, 100).await.unwrap().items[0]["read_at"].is_null());
    }
    #[tokio::test]
    async fn observation_and_notification_outbox_commit_together_and_retries_do_not_duplicate_alerts()
     {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let plan: Plan =
            serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
        let request = SubscribeRequest {
            name: None,
            search: None,
            target: plan.collection.reference.clone(),
            policy: plan.policy,
            action: ActionPolicy::Notify,
            destination_id: "unused".into(),
            recipe: Recipe::Cbz,
            include_existing: true,
            interval_minutes: 15,
            credential_profile: None,
        };
        let sub = create(&store, request).await.unwrap();
        store
            .set_setting("notifications", &serde_json::json!({"enabled":true}))
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER stop_outbox BEFORE INSERT ON notification_outbox BEGIN SELECT RAISE(ABORT,'injected'); END").execute(&store.pool).await.unwrap();
        assert!(
            observe(&store, &sub, std::slice::from_ref(&plan.release))
                .await
                .is_err()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM actions")
                .fetch_one(&store.pool)
                .await
                .unwrap(),
            0
        );
        assert!(!get(&store, &sub.id).await.unwrap().initialized);
        sqlx::query("DROP TRIGGER stop_outbox")
            .execute(&store.pool)
            .await
            .unwrap();
        observe(&store, &sub, std::slice::from_ref(&plan.release))
            .await
            .unwrap();
        observe(&store, &sub, std::slice::from_ref(&plan.release))
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_outbox WHERE state='pending'"
            )
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            1
        );
        store
            .set_setting("notifications", &serde_json::json!({"enabled":false}))
            .await
            .unwrap();
        let mut another = plan.release;
        another.reference.id.push_str("-new");
        observe(&store, &sub, &[another]).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_outbox WHERE state='suppressed'"
            )
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            1
        );
    }
    #[tokio::test]
    async fn future_only_baseline_does_not_create_old_actions() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let plan = plan();
        let sub = create(
            &store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference.clone(),
                policy: plan.policy,
                action: ActionPolicy::Notify,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing: false,
                interval_minutes: 15,
                credential_profile: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            observe(&store, &sub, std::slice::from_ref(&plan.release))
                .await
                .unwrap(),
            0
        );
        let mut new = plan.release;
        new.reference.id = "new".into();
        assert_eq!(observe(&store, &sub, &[new]).await.unwrap(), 1);
    }
    #[tokio::test]
    async fn policy_edit_rejects_stale_enumeration_and_preserves_observations() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("db")).await.unwrap();
        let plan = plan();
        let sub = create(
            &store,
            SubscribeRequest {
                name: None,
                search: None,
                target: plan.collection.reference.clone(),
                policy: plan.policy,
                action: ActionPolicy::Download,
                destination_id: "offline".into(),
                recipe: Recipe::Cbz,
                include_existing: true,
                interval_minutes: 15,
                credential_profile: None,
            },
        )
        .await
        .unwrap();
        observe(&store, &sub, std::slice::from_ref(&plan.release))
            .await
            .unwrap();
        let mut request = sub.request.clone();
        request.action = ActionPolicy::Notify;
        request.policy.languages = vec!["ja".into()];
        request.include_existing = false;
        let edited = update(&store, &sub.id, request).await.unwrap();
        assert!(!edited.initialized);
        assert!(matches!(
            observe(&store, &sub, &[]).await,
            Err(StoreError::StateConflict)
        ));
        assert!(pending_action(&store).await.unwrap().is_none());
        let mut japanese = plan.release.clone();
        japanese.reference.id = "japanese".into();
        japanese.language = Some("ja".into());
        assert_eq!(
            observe(&store, &edited, &[japanese.clone()]).await.unwrap(),
            0
        );
        let observations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM observations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(observations, 2);
        japanese.reference.id = "future-japanese".into();
        assert_eq!(observe(&store, &edited, &[japanese]).await.unwrap(), 1);
        assert_eq!(inbox(&store, None, 100).await.unwrap().items.len(), 2);
    }
    #[tokio::test]
    async fn changing_accounts_respects_the_existing_release_choice() {
        for include_existing in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let store = Store::open(&root.path().join("db")).await.unwrap();
            let plan = plan();
            let sub = create(
                &store,
                SubscribeRequest {
                    name: None,
                    search: None,
                    target: plan.collection.reference.clone(),
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
            .unwrap();
            let mut restricted = plan.release.clone();
            restricted.availability = omd_domain::Availability::AuthenticationRequired;
            assert_eq!(observe(&store, &sub, &[restricted]).await.unwrap(), 0);
            let mut request = sub.request.clone();
            request.credential_profile = Some("signed-in".into());
            let edited = update(&store, &sub.id, request).await.unwrap();
            assert!(!edited.initialized);
            assert!(matches!(
                observe(&store, &sub, &[]).await,
                Err(StoreError::StateConflict)
            ));
            assert_eq!(
                observe(&store, &edited, std::slice::from_ref(&plan.release))
                    .await
                    .unwrap(),
                usize::from(include_existing)
            );
            let mut future = plan.release;
            future.reference.id = "future-release".into();
            assert_eq!(observe(&store, &edited, &[future]).await.unwrap(), 1);
        }
    }
}
