//! Durable native notifications are independent of acquisition actions and clients.
//! An interrupted OS handoff is reported as uncertain, never automatically replayed.
use omd_domain::{Page, Problem};
use omd_store::{Result, Store, StoreError, emit, now};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "NotificationBatch")]
pub struct Batch {
    pub id: String,
    pub count: i64,
    pub state: String,
    pub issue: Option<Problem>,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[schemars(rename = "NotificationStatus")]
pub struct Status {
    pub enabled: bool,
    pub pending: i64,
    pub failed: i64,
    pub uncertain: i64,
    pub last: Option<Batch>,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "NotificationSettings")]
pub struct Settings {
    pub enabled: bool,
}
/// The adapter's whole input: release counts only. Unknown fields are rejected, so
/// no client, request or engine value can name the application, a URL or a path.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub count: u32,
    pub test: bool,
}

/// Application identity under which `omd-notify` registers native alerts: the
/// macOS bundle identifier, the Windows AppUserModelID and the Linux desktop entry.
///
/// It is fixed when the adapter is compiled. Public builds use the stable reference
/// app identity; development packages enable the `development-identity` feature.
/// It is never read from the message, the environment, settings or a client.
pub mod identity {
    /// Bundle identifier of the public reference app (`tauri.public.conf.json`).
    pub const PUBLIC: &str = "labs.northwolf.omd";
    /// Bundle identifier of the development app configurations.
    pub const DEVELOPMENT: &str = "labs.northwolf.omd-v2-development";
    /// The identity compiled into this build.
    pub const APPLICATION: &str = if cfg!(feature = "development-identity") {
        DEVELOPMENT
    } else {
        PUBLIC
    };
}
fn decode(row: sqlx::sqlite::SqliteRow) -> Result<Batch> {
    Ok(Batch {
        id: row.get("id"),
        count: row.get("count"),
        state: row.get("state"),
        issue: row
            .get::<Option<String>, _>("issue_json")
            .map(|s| serde_json::from_str(&s))
            .transpose()?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}
pub async fn status(store: &Store) -> Result<Status> {
    Ok(Status {
        enabled: store
            .setting("notifications")
            .await?
            .is_some_and(|v| v["enabled"] == true),
        pending: sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_outbox WHERE state='pending'",
        )
        .fetch_one(&store.pool)
        .await?,
        failed: sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_batches WHERE state='failed'",
        )
        .fetch_one(&store.pool)
        .await?,
        uncertain: sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_batches WHERE state='uncertain'",
        )
        .fetch_one(&store.pool)
        .await?,
        last: sqlx::query(
            "SELECT * FROM notification_batches ORDER BY created_at DESC,id DESC LIMIT 1",
        )
        .fetch_optional(&store.pool)
        .await?
        .map(decode)
        .transpose()?,
    })
}
pub async fn configure(store: &Store, settings: &Settings) -> Result<Status> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("INSERT INTO settings(key,value_json) VALUES('notifications',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json").bind(serde_json::to_string(settings)?).execute(&mut *tx).await?;
    if !settings.enabled {
        sqlx::query("UPDATE notification_outbox SET state='suppressed' WHERE state='pending'")
            .execute(&mut *tx)
            .await?;
    }
    emit(&mut tx, "notifications.changed", "settings").await?;
    tx.commit().await?;
    status(store).await
}
pub async fn recover(store: &Store) -> Result<()> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let issue = Problem::new(
        "notification_delivery_uncertain",
        "OMD stopped during notification delivery. The notification may have appeared. Your in-app inbox is complete; retry only if you want another desktop alert.",
    );
    let changed=sqlx::query("UPDATE notification_batches SET state='uncertain',issue_json=?,updated_at=? WHERE state='sending'").bind(serde_json::to_string(&issue)?).bind(now()).execute(&mut *tx).await?.rows_affected();
    if changed > 0 {
        emit(&mut tx, "notifications.changed", "recovery").await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn claim(store: &Store) -> Result<Option<Batch>> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let enabled:bool=sqlx::query_scalar("SELECT COALESCE((SELECT json_extract(value_json,'$.enabled')=1 FROM settings WHERE key='notifications'),0)").fetch_one(&mut *tx).await?;
    if !enabled {
        tx.commit().await?;
        return Ok(None);
    }
    // Coalesce releases committed during an enumeration; bound native alerts to one
    // per minute even when many independent subscriptions finish together.
    let recent: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM notification_batches WHERE created_at>?")
            .bind(
                (chrono::Utc::now() - chrono::Duration::seconds(60))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .fetch_one(&mut *tx)
            .await?;
    if recent > 0 {
        tx.commit().await?;
        return Ok(None);
    }
    let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_outbox WHERE state='pending' AND created_at<=?",
    )
    .bind(&cutoff)
    .fetch_one(&mut *tx)
    .await?;
    if count == 0 {
        tx.commit().await?;
        return Ok(None);
    }
    let id = format!("notice_{}", uuid::Uuid::new_v4().simple());
    let time = now();
    sqlx::query("INSERT INTO notification_batches VALUES(?,?,'sending',NULL,?,?)")
        .bind(&id)
        .bind(count)
        .bind(&time)
        .bind(&time)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE notification_outbox SET state='batched',batch_id=? WHERE state='pending' AND created_at<=?").bind(&id).bind(&cutoff).execute(&mut *tx).await?;
    emit(&mut tx, "notifications.changed", &id).await?;
    tx.commit().await?;
    Ok(Some(Batch {
        id,
        count,
        state: "sending".into(),
        issue: None,
        created_at: time.clone(),
        updated_at: time,
    }))
}
pub async fn finish(
    store: &Store,
    id: &str,
    result: std::result::Result<(), Problem>,
) -> Result<()> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let issue = result.err();
    let changed=sqlx::query("UPDATE notification_batches SET state=?,issue_json=?,updated_at=? WHERE id=? AND state='sending'").bind(if issue.as_ref().is_some_and(|p|p.code=="notification_delivery_uncertain"){"uncertain"}else if issue.is_some(){"failed"}else{"delivered"}).bind(issue.map(|p|serde_json::to_string(&p)).transpose()?).bind(now()).bind(id).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(StoreError::StateConflict);
    }
    emit(&mut tx, "notifications.changed", id).await?;
    tx.commit().await?;
    Ok(())
}
pub async fn control(store: &Store, id: &str, action: &str) -> Result<Batch> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let state = match action {
        "retry" => "sending",
        "dismiss" => "dismissed",
        _ => return Err(StoreError::StateConflict),
    };
    let row=sqlx::query("UPDATE notification_batches SET state=?,issue_json=NULL,updated_at=? WHERE id=? AND state IN ('failed','uncertain') RETURNING *").bind(state).bind(now()).bind(id).fetch_optional(&mut *tx).await?.ok_or(StoreError::StateConflict)?;
    emit(&mut tx, "notifications.changed", id).await?;
    tx.commit().await?;
    decode(row)
}
pub async fn list(
    store: &Store,
    query: &str,
    cursor: Option<&str>,
    limit: u32,
) -> Result<Page<Batch>> {
    let cursor = cursor.unwrap_or("");
    let limit = limit.clamp(1, 200);
    let q = format!("%{}%", query.replace('%', "\\%").replace('_', "\\_"));
    let rows=sqlx::query("SELECT * FROM notification_batches WHERE id>? AND (state LIKE ? ESCAPE '\\' OR id LIKE ? ESCAPE '\\') ORDER BY id LIMIT ?").bind(cursor).bind(&q).bind(&q).bind(limit+1).fetch_all(&store.pool).await?;
    let mut items = rows.into_iter().map(decode).collect::<Result<Vec<_>>>()?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|b| b.id.clone())
    } else {
        None
    };
    Ok(Page { items, next_cursor })
}
fn unavailable(code: &str, message: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        retryable: true,
        actions: vec!["retry_notification".into(), "open_inbox".into()],
    }
}
/// The OS adapter runs in a bounded subprocess so an unavailable notification
/// daemon cannot block acquisition, shutdown, or retain a blocking worker thread.
pub async fn deliver(
    helper: &Path,
    message: &Message,
    cancel: &CancellationToken,
) -> std::result::Result<(), Problem> {
    let mut child = Command::new(helper)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            unavailable(
                "notification_adapter_unavailable",
                "The installed notification adapter is unavailable. Repair the OMD installation.",
            )
        })?;
    let work = async {
        let mut input = child.stdin.take().expect("piped");
        input
            .write_all(&serde_json::to_vec(message).expect("message JSON"))
            .await?;
        input.shutdown().await?;
        drop(input);
        let mut out = Vec::new();
        child
            .stdout
            .take()
            .expect("piped")
            .take(4097)
            .read_to_end(&mut out)
            .await?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status.success(), out))
    };
    tokio::select! {
     biased;
     _=cancel.cancelled()=>Err(unavailable("notification_delivery_uncertain","Notification delivery was interrupted. It may already have appeared. Check your inbox before retrying.")),
     value=tokio::time::timeout(Duration::from_secs(15),work)=>match value {
      Ok(Ok((true,bytes))) if bytes==b"{\"accepted\":true}\n"=>Ok(()),
      Ok(Ok((_,bytes)))=>Err(if bytes.len()<=4096{serde_json::from_slice::<Problem>(&bytes).unwrap_or_else(|_|unavailable("notification_unavailable","The operating system could not accept the notification. Check notification permissions and your desktop session."))}else{unavailable("notification_unavailable","The notification adapter returned an invalid response.")}),
      _=>Err(unavailable("notification_delivery_uncertain","The notification adapter did not finish. It may have delivered the alert; check your inbox before retrying."))
     }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn setup() -> (tempfile::TempDir, Store) {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(&root.path().join("v2.sqlite3")).await.unwrap();
        sqlx::query("INSERT INTO subscriptions(id,data_json,enabled,next_check) VALUES('s','{}',1,'2000-01-01')").execute(&store.pool).await.unwrap();
        (root, store)
    }
    async fn seed(store: &Store, count: u32) {
        let mut tx = store.pool.begin().await.unwrap();
        for index in 0..count {
            let id = format!("action-{index:04}");
            sqlx::query("INSERT INTO actions(id,subscription_id,release_json,state,created_at) VALUES(?,'s','{}','notified','2000-01-01')").bind(&id).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO notification_outbox(action_id,state,created_at) VALUES(?,'pending','2000-01-01')").bind(&id).execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
    }
    #[tokio::test]
    async fn complete_batches_are_durable_and_restart_never_replays_an_uncertain_os_handoff() {
        let (root, store) = setup().await;
        configure(&store, &Settings { enabled: true })
            .await
            .unwrap();
        seed(&store, 251).await;
        let batch = claim(&store).await.unwrap().unwrap();
        assert_eq!(batch.count, 251);
        assert_eq!(status(&store).await.unwrap().pending, 0);
        assert!(claim(&store).await.unwrap().is_none());
        store.pool.close().await;
        let store = Store::open(&root.path().join("v2.sqlite3")).await.unwrap();
        recover(&store).await.unwrap();
        assert_eq!(status(&store).await.unwrap().uncertain, 1);
        assert!(claim(&store).await.unwrap().is_none());
        let retry = control(&store, &batch.id, "retry").await.unwrap();
        assert_eq!(retry.count, 251);
        assert!(control(&store, &batch.id, "retry").await.is_err());
        finish(&store, &batch.id, Ok(())).await.unwrap();
        assert_eq!(
            status(&store).await.unwrap().last.unwrap().state,
            "delivered"
        );
        recover(&store).await.unwrap();
        assert_eq!(status(&store).await.unwrap().uncertain, 0);
    }
    #[tokio::test]
    async fn disabling_suppresses_backlog_and_failed_delivery_does_not_change_the_inbox() {
        let (_root, store) = setup().await;
        seed(&store, 2).await;
        assert!(claim(&store).await.unwrap().is_none());
        configure(&store, &Settings { enabled: false })
            .await
            .unwrap();
        configure(&store, &Settings { enabled: true })
            .await
            .unwrap();
        assert!(claim(&store).await.unwrap().is_none());
        sqlx::query("UPDATE notification_outbox SET state='pending'")
            .execute(&store.pool)
            .await
            .unwrap();
        let batch = claim(&store).await.unwrap().unwrap();
        finish(
            &store,
            &batch.id,
            Err(Problem::new("notification_unavailable", "Unavailable")),
        )
        .await
        .unwrap();
        assert_eq!(status(&store).await.unwrap().failed, 1);
        assert!(claim(&store).await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM actions WHERE state='notified' AND read_at IS NULL"
            )
            .fetch_one(&store.pool)
            .await
            .unwrap(),
            2
        );
        control(&store, &batch.id, "dismiss").await.unwrap();
        assert_eq!(status(&store).await.unwrap().failed, 0);
    }
    #[tokio::test]
    async fn notification_history_is_paginated_and_atomic_failure_cannot_lose_an_alert() {
        let (_root, store) = setup().await;
        configure(&store, &Settings { enabled: true })
            .await
            .unwrap();
        seed(&store, 1).await;
        sqlx::query("CREATE TRIGGER stop_notification BEFORE UPDATE ON notification_outbox BEGIN SELECT RAISE(ABORT,'injected'); END").execute(&store.pool).await.unwrap();
        assert!(claim(&store).await.is_err());
        assert_eq!(status(&store).await.unwrap().pending, 1);
        assert!(status(&store).await.unwrap().last.is_none());
        sqlx::query("DROP TRIGGER stop_notification")
            .execute(&store.pool)
            .await
            .unwrap();
        for i in 0..251 {
            sqlx::query("INSERT INTO notification_batches VALUES(?,1,'delivered',NULL,'2000-01-01','2000-01-01')").bind(format!("n-{i:03}")).execute(&store.pool).await.unwrap();
        }
        let mut cursor = None;
        let mut total = 0;
        loop {
            let page = list(&store, "delivered", cursor.as_deref(), 100)
                .await
                .unwrap();
            total += page.items.len();
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(total, 251);
    }
    #[test]
    fn alerts_are_registered_under_the_identity_selected_at_build_time() {
        #[cfg(not(feature = "development-identity"))]
        assert_eq!(identity::APPLICATION, "labs.northwolf.omd");
        #[cfg(feature = "development-identity")]
        assert_eq!(identity::APPLICATION, "labs.northwolf.omd-v2-development");
        assert_ne!(identity::PUBLIC, identity::DEVELOPMENT);
        // Usable unchanged as a bundle identifier, AppUserModelID and entry name.
        for id in [identity::PUBLIC, identity::DEVELOPMENT] {
            let labels: Vec<_> = id.split('.').collect();
            assert!(labels.len() >= 3, "{id}");
            assert!(
                labels.iter().all(|label| !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                "{id}"
            );
        }
    }
    #[test]
    fn adapter_input_is_counts_only_and_cannot_choose_an_identity() {
        let message: Message = serde_json::from_str(r#"{"count":2,"test":false}"#).unwrap();
        assert_eq!(
            serde_json::to_value(&message).unwrap(),
            serde_json::json!({"count": 2, "test": false})
        );
        for field in [
            "app_id",
            "application",
            "identifier",
            "bundle_id",
            "desktop_entry",
            "title",
            "url",
            "path",
        ] {
            let input = format!(
                r#"{{"count":1,"test":false,"{field}":"{}"}}"#,
                identity::DEVELOPMENT
            );
            assert!(serde_json::from_str::<Message>(&input).is_err(), "{field}");
        }
    }
    #[test]
    fn adapter_registers_every_platform_with_the_compiled_identity_only() {
        let adapter = include_str!("bin/omd-notify.rs");
        // macOS set_application, Windows app_id and the Linux desktop-entry hint.
        assert_eq!(
            adapter
                .matches("omd_notifications::identity::APPLICATION")
                .count(),
            3
        );
        for forbidden in ["\"labs.northwolf", "std::env", "env!(", "option_env!("] {
            assert!(!adapter.contains(forbidden), "{forbidden}");
        }
    }
    #[tokio::test]
    async fn unavailable_adapter_is_actionable_and_never_consumes_execution_capacity() {
        let root = tempfile::tempdir().unwrap();
        let issue = deliver(
            &root.path().join("missing"),
            &Message {
                count: 1,
                test: true,
            },
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(issue.code, "notification_adapter_unavailable");
        assert!(issue.actions.contains(&"open_inbox".to_owned()));
    }
}
