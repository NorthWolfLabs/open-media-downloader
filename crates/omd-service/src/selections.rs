//! Asynchronous collection scans and acquisition preparation through public APIs.
use super::*;
use omd_store::selections::SelectionTask;

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotRequest {
    #[serde(default)]
    search: Option<SubscriptionSearch>,
    /// Explicit image posts selected in discovery, frozen one at a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release_refs: Option<Vec<SourceRef>>,
    #[serde(default)]
    policy: SelectionPolicy,
    reference: SourceRef,
    #[serde(default)]
    credential_profile: Option<String>,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchRequest {
    snapshot_id: String,
    /// Omit for all matching releases in the frozen snapshot.
    #[serde(default)]
    releases: Option<Vec<SourceRef>>,
    destination_id: String,
    recipe: Recipe,
    policy: SelectionPolicy,
    #[serde(default)]
    duplicate_behavior: DuplicateBehavior,
}
pub(crate) async fn create_snapshot(
    State(app): State<App>,
    Json(request): Json<SnapshotRequest>,
) -> ApiResult<SelectionTask> {
    if request.search.is_some() {
        return Err(omd_store::StoreError::StateConflict.into());
    }
    request.reference.validate().map_err(|_| {
        problem(
            StatusCode::BAD_REQUEST,
            "source_identity",
            "Choose a valid collection.",
        )
    })?;
    let source = provider(&app, &request.reference.provider).await?;
    if let Some(refs) = &request.release_refs {
        validate_image_selection(&request.reference, refs)?;
    }
    let capability = if request.release_refs.is_some() {
        "resolve"
    } else {
        "releases"
    };
    if !source.manifest.capabilities.iter().any(|v| v == capability) {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "unsupported_operation",
            "This source does not enumerate collections.",
        ));
    }
    Ok(Json(
        app.store
            .cached_snapshot(&serde_json::to_value(request).unwrap(), &source.digest)
            .await?,
    ))
}
fn validate_image_selection(reference: &SourceRef, refs: &[SourceRef]) -> Result<(), ApiError> {
    let unique: std::collections::HashSet<_> = refs.iter().map(SourceRef::key).collect();
    if refs.is_empty()
        || refs.len() > 2000
        || unique.len() != refs.len()
        || refs
            .iter()
            .any(|r| r.provider != reference.provider || r.validate().is_err())
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "selection_size",
            "Select 1–2000 distinct image posts from one source.",
        ));
    }
    Ok(())
}
pub(crate) async fn tasks(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<SelectionTask>> {
    Ok(Json(
        app.store
            .search_selection_tasks(
                &query.q,
                query.cursor.as_deref(),
                query.limit.unwrap_or(100),
            )
            .await?,
    ))
}
pub(crate) async fn task(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<SelectionTask> {
    Ok(Json(app.store.selection_task(&id).await?))
}
fn ordinal(query: &List) -> Result<i64, ApiError> {
    query
        .cursor
        .as_ref()
        .map(|s| {
            s.parse::<i64>().ok().filter(|n| *n >= 0).ok_or_else(|| {
                problem(
                    StatusCode::BAD_REQUEST,
                    "cursor_invalid",
                    "Use the next cursor returned by this snapshot.",
                )
            })
        })
        .transpose()
        .map(|v| v.unwrap_or(-1))
}
pub(crate) async fn releases(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<Release>> {
    Ok(Json(
        app.store
            .snapshot_page(&id, &query.q, ordinal(&query)?, query.limit.unwrap_or(100))
            .await?,
    ))
}
pub(crate) async fn create_batch(
    State(app): State<App>,
    Json(request): Json<BatchRequest>,
) -> ApiResult<SelectionTask> {
    let scan = app.store.selection_task(&request.snapshot_id).await?;
    if scan.request.get("search").is_some_and(|v| !v.is_null()) {
        return Err(omd_store::StoreError::StateConflict.into());
    }
    let dest = app.store.destination(&request.destination_id).await?;
    if !dest.available {
        return Err(omd_store::StoreError::Destination.into());
    }
    let selected = request
        .releases
        .as_ref()
        .map(|items| items.iter().map(SourceRef::key).collect::<Vec<_>>());
    if selected
        .as_ref()
        .is_some_and(|v| v.is_empty() || v.len() > 2000)
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "selection_size",
            "Select 1–2000 explicit releases, or omit releases to use all matching the snapshot.",
        ));
    }
    Ok(Json(
        app.store
            .create_batch(
                &request.snapshot_id,
                &serde_json::to_value(&request).unwrap(),
                &request.policy,
                selected.as_deref(),
            )
            .await?,
    ))
}
pub(crate) async fn preview(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<List>,
) -> ApiResult<Page<Value>> {
    Ok(Json(
        app.store
            .search_batch_page(&id, &query.q, ordinal(&query)?, query.limit.unwrap_or(100))
            .await?,
    ))
}
pub(crate) async fn action(
    State(app): State<App>,
    Path((id, action)): Path<(String, String)>,
) -> ApiResult<SelectionTask> {
    let state = match action.as_str() {
        "cancel" => "canceled",
        "retry" => "working",
        _ => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "action_invalid",
                "Use cancel or retry.",
            ));
        }
    };
    app.store.selection_state(&id, state, None).await?;
    Ok(Json(app.store.selection_task(&id).await?))
}
async fn pinned(app: &App, reference: &SourceRef, digest: &str) -> Result<Provider, ApiError> {
    let (manifest, path) = app
        .store
        .provider_version(&reference.provider, digest)
        .await?;
    Ok(Provider {
        manifest,
        component: path.into(),
        digest: digest.to_owned(),
    })
}
async fn step(app: &App, task: &SelectionTask, token: &CancellationToken) -> Result<(), ApiError> {
    if task.kind == "snapshot" {
        let request: SnapshotRequest = serde_json::from_value(task.request.clone())
            .map_err(|_| omd_store::StoreError::StateConflict)?;
        let source = pinned(app, &request.reference, &task.source_digest).await?;
        if let Some(refs) = &request.release_refs {
            validate_image_selection(&request.reference, refs)?;
            let reference = refs
                .get(task.processed as usize)
                .ok_or(omd_store::StoreError::StateConflict)?;
            let input = ProviderRequest {
                release_order: None,
                discovery: None,
                operation: "resolve".into(),
                reference: Some(reference.clone()),
                credential_profile: request.credential_profile,
                query: None,
                url: None,
                cursor: None,
                page_size: 1,
                policy: request.policy,
                now: omd_store::now(),
            };
            let resolved: ResolvedRelease = app.runtime.invoke(&source, &input, token).await?;
            if resolved.release.reference != *reference
                || resolved.release.collection != resolved.collection.reference
                || resolved.collection.kind != CollectionKind::Item
                || resolved
                    .collection
                    .summary
                    .as_ref()
                    .and_then(|s| s.image.as_ref())
                    .is_none_or(|i| i.release_id != reference.id)
            {
                return Err(problem(
                    StatusCode::CONFLICT,
                    "selection_changed",
                    "The source returned a different image post. Select the post again.",
                ));
            }
            let next = task.processed as usize + 1;
            app.store
                .append_snapshot(
                    task,
                    &Page {
                        items: vec![resolved.release],
                        next_cursor: (next < refs.len()).then(|| next.to_string()),
                    },
                )
                .await?;
            return Ok(());
        }
        if let Some(search) = &request.search {
            let input = ProviderRequest {
                release_order: None,
                discovery: search.discovery.clone(),
                operation: "search".into(),
                reference: None,
                credential_profile: request.credential_profile.clone(),
                query: Some(search.query.clone()),
                url: None,
                cursor: task.cursor.clone(),
                page_size: 200,
                policy: request.policy.clone(),
                now: omd_store::now(),
            };
            let page: Page<Collection> = app.runtime.invoke(&source, &input, token).await?;
            let mut entries = Vec::with_capacity(page.items.len());
            for (index, item) in page.items.into_iter().enumerate() {
                if item.reference.provider != request.reference.provider {
                    return Err(omd_plugins::PluginError::Invalid.into());
                }
                app.store.upsert_collection(&item).await?;
                // The durable observation/inbox envelope holds the actual matching item in preview.
                // It never goes through release resolution or automatic acquisition.
                entries.push(Release {
                    reference: item.reference.clone(),
                    collection: request.reference.clone(),
                    title: item.title.clone(),
                    canonical_url: item.canonical_url.clone(),
                    preview: Some(item),
                    chapter: None,
                    volume: None,
                    language: None,
                    group: None,
                    published_at: None,
                    revision: None,
                    availability: Availability::Available,
                    unavailable_reason: None,
                    position: index as u64,
                });
            }
            app.store
                .append_snapshot(
                    task,
                    &Page {
                        items: entries,
                        next_cursor: page.next_cursor,
                    },
                )
                .await?;
            return Ok(());
        }
        let input = ProviderRequest {
            release_order: None,
            discovery: None,
            operation: "releases".into(),
            reference: Some(request.reference.clone()),
            credential_profile: request.credential_profile,
            query: None,
            url: None,
            cursor: task.cursor.clone(),
            page_size: 200,
            policy: SelectionPolicy {
                languages: vec![],
                ..Default::default()
            },
            now: omd_store::now(),
        };
        let page: Page<Release> = app.runtime.invoke(&source, &input, token).await?;
        if page.items.iter().any(|r| r.collection != request.reference) {
            return Err(problem(
                StatusCode::CONFLICT,
                "source_changed",
                "The source returned a release from another collection. Create a new snapshot.",
            ));
        }
        app.store.append_snapshot(task, &page).await?;
    } else {
        let request: BatchRequest = serde_json::from_value(task.request.clone())
            .map_err(|_| omd_store::StoreError::StateConflict)?;
        let snapshot = app.store.selection_task(&request.snapshot_id).await?;
        let scan: SnapshotRequest = serde_json::from_value(snapshot.request)
            .map_err(|_| omd_store::StoreError::StateConflict)?;
        let release = app.store.batch_release(task).await?;
        let source = pinned(app, &release.reference, &task.source_digest).await?;
        let input = ProviderRequest {
            release_order: None,
            discovery: None,
            operation: "resolve".into(),
            reference: Some(release.reference.clone()),
            credential_profile: scan.credential_profile.clone(),
            query: None,
            url: None,
            cursor: None,
            page_size: 200,
            policy: request.policy.clone(),
            now: omd_store::now(),
        };
        let resolved: ResolvedRelease = app.runtime.invoke(&source, &input, token).await?;
        let actual = &resolved.release;
        if actual.reference != release.reference
            || actual.collection != release.collection
            || actual.revision != release.revision
            || actual.language != release.language
            || actual.group != release.group
            || actual.chapter != release.chapter
            || !request.policy.accepts(actual)
        {
            return Err(problem(
                StatusCode::CONFLICT,
                "selection_changed",
                "A selected release changed since enumeration. Create a new snapshot and review the new selection.",
            ));
        }
        let plan = build_plan(
            app,
            &source,
            omd_media::Preparation {
                resolved,
                recipe: request.recipe,
                policy: request.policy,
                provider_digest: source.digest.clone(),
                credential_profile: scan.credential_profile,
            },
            token,
        )
        .await?;
        let (plan, outcome) = app
            .store
            .plan_intent(&plan, &request.destination_id, request.duplicate_behavior)
            .await?;
        let bytes = plan.estimated_bytes();
        let preview = json!({"files":omd_acquisition::final_outputs(&plan),"estimated_bytes":bytes,"plan":plan,"outcome":outcome});
        app.store.append_batch(task, &preview).await?;
    }
    Ok(())
}
pub async fn run_selections(app: App) {
    loop {
        if app.shutdown.is_cancelled() {
            break;
        }
        match app.store.next_selection_task().await {
            Ok(Some(task)) => {
                let token = app.shutdown.child_token();
                let work = step(&app, &task, &token);
                tokio::pin!(work);
                let mut interval = tokio::time::interval(Duration::from_millis(250));
                let result = loop {
                    tokio::select! {
                        result = &mut work => break result,
                        _ = interval.tick() => {
                            if !app.store.selection_task(&task.id).await.is_ok_and(|current|current.state == "working") {
                                token.cancel();
                            }
                        }
                    }
                };
                if let Err(error) = result {
                    if app.shutdown.is_cancelled() {
                        break;
                    }
                    let _ = app
                        .store
                        .selection_state(&task.id, "failed", Some(&error.1))
                        .await;
                }
            }
            Ok(None) => {}
            Err(_) => tracing::warn!("Selection queue temporarily unavailable"),
        }
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(50))=>{}}
    }
}
