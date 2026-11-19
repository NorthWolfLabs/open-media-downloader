use super::*;
use omd_store::source_removals::{SourceRemoval, SourceRemovalEntry, SourceRemovalReview};
use sqlx::Row;
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveSource {
    pub approve_digest: Option<String>,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
pub(crate) struct SourceRemovalResponse {
    pub review_required: bool,
    pub review: Option<SourceRemovalReview>,
    pub operation: Option<SourceRemoval>,
}
pub(crate) async fn remove(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<RemoveSource>,
) -> ApiResult<SourceRemovalResponse> {
    let _changes = app.source_changes.lock().await;
    let review = app.store.review_source_removal(&id).await?;
    if !review.enabled {
        let operation = app
            .store
            .source_removal(
                review
                    .previous_removal
                    .as_deref()
                    .ok_or(omd_store::StoreError::NotFound)?,
            )
            .await?;
        return Ok(Json(SourceRemovalResponse {
            review_required: false,
            review: None,
            operation: Some(operation),
        }));
    }
    if input.approve_digest.as_deref() != Some(&review.approval_digest) {
        return Ok(Json(SourceRemovalResponse {
            review_required: true,
            review: Some(review),
            operation: None,
        }));
    }
    let operation = app
        .store
        .remove_source(&id, &review.approval_digest)
        .await?;
    app.providers.write().await.remove(&id);
    app.browser_sessions.revoke_source(&id).await;
    // Durable authority is already revoked. Cancel both worker calls and native
    // transfers; already-publishing verified files may finish their journal.
    {
        let running = app.running.lock().await;
        for (job, token) in running.iter() {
            if app.store.job(job).await.is_ok_and(|job| {
                job.plan.release.reference.provider == id && job.state != JobState::Publishing
            }) {
                token.cancel();
            }
        }
    }
    if app.runtime.revoke(&id).await.is_err() {
        app.store
            .source_removal_issue(
                &operation.id,
                Some(&Problem {
                    code: "source_stopping".into(),
                    message:
                        "The source is disabled. Retry cleanup after its execution has stopped."
                            .into(),
                    retryable: true,
                    actions: vec!["retry_source_removal".into()],
                }),
            )
            .await?;
    }
    Ok(Json(SourceRemovalResponse {
        review_required: false,
        review: None,
        operation: Some(app.store.source_removal(&operation.id).await?),
    }))
}
pub(crate) async fn list(
    State(app): State<App>,
    Query(q): Query<List>,
) -> ApiResult<Page<SourceRemoval>> {
    Ok(Json(
        app.store
            .source_removals(&q.q, q.cursor.as_deref(), q.limit.unwrap_or(100))
            .await?,
    ))
}
pub(crate) async fn get(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<SourceRemoval> {
    Ok(Json(app.store.source_removal(&id).await?))
}
pub(crate) async fn entries(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<List>,
) -> ApiResult<Page<SourceRemovalEntry>> {
    Ok(Json(
        app.store
            .source_removal_entries(&id, &q.q, q.cursor.as_deref(), q.limit.unwrap_or(100))
            .await?,
    ))
}
pub(crate) async fn retry(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<SourceRemoval> {
    app.store.source_removal(&id).await?;
    app.store.source_removal_issue(&id, None).await?;
    Ok(Json(app.store.source_removal(&id).await?))
}
fn cleanup_issue(code: &str, message: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        retryable: true,
        actions: vec!["retry_source_removal".into()],
    }
}
/// One bounded, restartable cleanup entry. The caller serializes this with source
/// installation and credential replacement; reapproved bytes are never deleted.
pub async fn step(app: &App, operation: &SourceRemoval) -> Result<(), Problem> {
    let row=sqlx::query("SELECT kind,item_key,state,issue_json FROM source_removal_entries WHERE removal_id=? AND state='pending' ORDER BY kind,item_key LIMIT 1").bind(&operation.id).fetch_optional(&app.store.pool).await.map_err(|_|cleanup_issue("storage_failed","The removal journal is unavailable."))?;
    let Some(row) = row else {
        return Ok(());
    };
    let entry = SourceRemovalEntry {
        kind: row.get("kind"),
        item_key: row.get("item_key"),
        state: row.get("state"),
        issue: None,
    };
    let provider = &operation.review.provider;
    let mut retained = None;
    if entry.kind == "account" {
        let enabled: bool = sqlx::query_scalar("SELECT enabled<>0 FROM providers WHERE id=?")
            .bind(provider)
            .fetch_one(&app.store.pool)
            .await
            .map_err(|_| cleanup_issue("storage_failed", "Source state could not be checked."))?;
        if enabled {
            retained = Some(Problem::new(
                "source_reinstalled",
                "The account was retained because the source was reinstalled.",
            ));
        } else {
            app.acquisition
                .network
                .vault
                .as_ref()
                .ok_or_else(|| omd_credentials::Error::Unavailable.problem())?
                .revoke(provider, &entry.item_key)
                .await
                .map_err(|e| e.problem())?;
        }
    } else {
        let version=sqlx::query("SELECT approved,manifest_json,component_path FROM provider_versions WHERE provider_id=? AND digest=?").bind(provider).bind(&entry.item_key).fetch_one(&app.store.pool).await.map_err(|_|cleanup_issue("storage_failed","Source package state could not be checked."))?;
        if version.get::<i64, _>("approved") != 0 {
            retained = Some(Problem::new(
                "package_reapproved",
                "These exact package bytes were retained because they were approved again.",
            ));
        } else {
            let digest = entry.item_key.clone();
            let profile = app.profile.clone();
            let path = version.get::<String, _>("component_path");
            let manifest = serde_json::from_str::<ProviderManifest>(version.get("manifest_json"))
                .map_err(|_| {
                cleanup_issue(
                    "package_metadata",
                    "Restore the source metadata before retrying removal.",
                )
            })?;
            let removed=tokio::task::spawn_blocking(move||->Result<bool,std::io::Error>{
                use std::io::Read;
                let expected=profile.join("providers").join(&digest).join("plugin.wasm");
                if digest.len()!=64||!digest.bytes().all(|b|b.is_ascii_hexdigit())||std::path::Path::new(&path)!=expected{return Ok(false);}
                let root=omd_files::Root::open(&profile)?;let relative=format!("providers/{digest}/plugin.wasm");
                let file=match root.read_file(&relative){Ok(file)=>file,Err(e)if e.kind()==std::io::ErrorKind::NotFound=>return Ok(true),Err(e)if matches!(e.kind(),std::io::ErrorKind::InvalidInput|std::io::ErrorKind::InvalidData)=>return Ok(false),Err(e)=>return Err(e)};
                let mut bytes=Vec::new();file.take(64*1024*1024+1).read_to_end(&mut bytes)?;
                if bytes.len()>64*1024*1024||omd_plugins::package_digest(&manifest,&bytes)!=digest{return Ok(false);}
                root.remove_file(&relative)?;Ok(true)
            }).await.map_err(|_|cleanup_issue("package_cleanup","Package cleanup was interrupted. Retry it."))?.map_err(|_|cleanup_issue("package_cleanup","The disabled package could not be removed. Check its file permissions and retry."))?;
            if !removed {
                retained = Some(Problem::new(
                    "modified_package_retained",
                    "A package file or location changed. Its execution permission is revoked, and the changed file was preserved.",
                ));
            }
        }
    }
    app.store
        .update_source_removal_entry(
            &operation.id,
            &entry,
            if retained.is_some() {
                "retained"
            } else {
                "removed"
            },
            retained.as_ref(),
        )
        .await
        .map_err(|_| {
            cleanup_issue(
                "storage_failed",
                "Cleanup succeeded but its journal needs recovery.",
            )
        })?;
    Ok(())
}
pub async fn run(app: App) {
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        let _changes = app.source_changes.lock().await;
        match app.store.next_source_removal().await {
            Ok(Some(operation)) => {
                if let Err(issue) = step(&app, &operation).await {
                    let _ = app
                        .store
                        .source_removal_issue(&operation.id, Some(&issue))
                        .await;
                }
                drop(_changes);
                tokio::task::yield_now().await;
            }
            _ => {
                drop(_changes);
                tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(500))=>{}}
            }
        }
    }
}
