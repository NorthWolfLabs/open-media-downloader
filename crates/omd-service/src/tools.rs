use super::*;
use omd_tools::{Installed, Review};
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "InstallToolsRequest")]
pub(crate) struct Install {
    pub manifest_path: Option<PathBuf>,
    pub label: String,
    pub approve_digest: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[schemars(rename = "ToolInstallation")]
pub(crate) struct Installation {
    pub review_required: bool,
    pub review: Review,
    pub installed: Option<Installed>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "RemoveToolsRequest")]
pub(crate) struct Remove {
    pub approve_digest: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
#[schemars(rename = "ToolRemoval")]
pub(crate) struct Removal {
    pub review_required: bool,
    pub affected_jobs: i64,
    pub installed: Installed,
}
#[derive(Serialize, schemars::JsonSchema)]
#[schemars(rename = "ManagedToolStatus")]
pub(crate) struct Status {
    pub platform: String,
    pub bundled: Option<Review>,
    pub issue: Option<Problem>,
}
/// The digest the previous app run recorded for its included set.
pub(crate) async fn bundled_digest(store: &Store, setting: &str) -> Option<String> {
    store
        .setting(setting)
        .await
        .ok()
        .flatten()
        .and_then(|value| value.get("digest")?.as_str().map(str::to_owned))
}
/// Whether an upgraded app's included set replaces the active one.
pub(crate) fn adopts_bundled(previous: Option<&str>, active: Option<&str>, new: &str) -> bool {
    matches!((previous, active), (Some(previous), Some(active)) if previous == active && active != new)
}
fn error(problem: Problem) -> ApiError {
    ApiError(StatusCode::CONFLICT, problem)
}
pub async fn initialize(
    store: &Store,
    profile: &std::path::Path,
    network: &omd_network::Network,
    runtime: &Runtime,
    bundled: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(profile.join("helper-work"))?;
    let mut bootstrap_issue = None;
    if let Some(path) = bundled {
        store
            .set_setting("bundled_tools_path", &json!(path))
            .await?;
        let result = async {
            let tools = omd_tools::read_manifest(path).await?;
            let review = omd_tools::review(&tools).await?;
            let previous = bundled_digest(store, "bundled_tools_review").await;
            store
                .set_setting("bundled_tools_review", &json!(review))
                .await
                .map_err(|_| {
                    Problem::new("tool_storage", "Could not save the bundled tool review.")
                })?;
            let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM managed_tool_sets")
                .fetch_one(&store.pool)
                .await
                .map_err(|_| {
                    Problem::new("tool_storage", "Could not read managed tool history.")
                })?;
            let active: Option<String> =
                sqlx::query_scalar("SELECT digest FROM managed_tool_active WHERE singleton=1")
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|_| {
                        Problem::new("tool_storage", "Could not read the active tool set.")
                    })?;
            // First installation accepts the distribution's included tool set,
            // and an app upgrade replaces the set the previous app included
            // while that set is still the active one. A set the person chose
            // or removed is kept; the new included set is offered for review.
            if existing == 0
                || adopts_bundled(previous.as_deref(), active.as_deref(), &review.digest)
            {
                omd_tools::install(
                    store,
                    profile,
                    &tools,
                    &review.digest,
                    "Included media tools",
                )
                .await?;
                omd_tools::activate(store, profile, &review.digest).await?;
            }
            Ok::<_, Problem>(())
        }
        .await;
        if let Err(problem) = result {
            bootstrap_issue = Some(problem);
        }
    }
    store
        .set_setting("tools_bootstrap_issue", &json!(bootstrap_issue))
        .await?;
    let mut cursor = None;
    loop {
        let page = omd_tools::list(store, "", cursor.as_deref(), 200)
            .await
            .map_err(|p| anyhow::anyhow!(p.message))?;
        for installed in page.items {
            if installed.state != "installed" {
                continue;
            }
            let result = async {
                let tools = omd_tools::paths(profile, &installed.review)?;
                if omd_tools::review(&tools).await?.digest != installed.digest {
                    return Err(Problem::new(
                        "tool_integrity",
                        "The installed tool identity changed.",
                    ));
                }
                Ok::<_, Problem>(tools)
            }
            .await;
            match result {
                Ok(tools) => runtime.register_media(
                    &installed.digest,
                    omd_media::Media {
                        tools,
                        network: network.clone(),
                        work_root: profile.join("helper-work"),
                        revoked: CancellationToken::new(),
                    },
                    installed.active,
                ),
                Err(problem) => {
                    sqlx::query("UPDATE managed_tool_sets SET issue_json=? WHERE digest=?")
                        .bind(serde_json::to_string(&problem)?)
                        .bind(&installed.digest)
                        .execute(&store.pool)
                        .await?;
                }
            }
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(())
}
fn media(app: &App, installed: &Installed) -> Result<omd_media::Media, ApiError> {
    Ok(omd_media::Media {
        tools: omd_tools::paths(&app.profile, &installed.review).map_err(error)?,
        network: app.acquisition.network.clone(),
        work_root: app.profile.join("helper-work"),
        revoked: CancellationToken::new(),
    })
}
pub(crate) async fn status(State(app): State<App>) -> ApiResult<Status> {
    Ok(Json(Status {
        platform: omd_tools::platform(),
        bundled: app
            .store
            .setting("bundled_tools_review")
            .await?
            .filter(|v| !v.is_null())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "tool_metadata",
                    "The bundled tool review is invalid.",
                )
            })?,
        issue: app
            .store
            .setting("tools_bootstrap_issue")
            .await?
            .filter(|v| !v.is_null())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| {
                problem(
                    StatusCode::CONFLICT,
                    "tool_metadata",
                    "The bundled tool status is invalid.",
                )
            })?,
    }))
}
pub(crate) async fn list(
    State(app): State<App>,
    Query(q): Query<List>,
) -> ApiResult<Page<Installed>> {
    Ok(Json(
        omd_tools::list(
            &app.store,
            &q.q,
            q.cursor.as_deref(),
            q.limit.unwrap_or(100),
        )
        .await
        .map_err(error)?,
    ))
}
pub(crate) async fn get(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Installed> {
    Ok(Json(omd_tools::get(&app.store, &id).await.map_err(error)?))
}
pub(crate) async fn install(
    State(app): State<App>,
    Json(input): Json<Install>,
) -> ApiResult<Installation> {
    let _changes = app.source_changes.lock().await;
    let path = match input.manifest_path {
        Some(path) => path,
        None => app
            .store
            .setting("bundled_tools_path")
            .await?
            .and_then(|v| v.as_str().map(PathBuf::from))
            .ok_or_else(|| {
                problem(
                    StatusCode::CONFLICT,
                    "tool_package_missing",
                    "Choose a managed-tool manifest to review.",
                )
            })?,
    };
    let tools = omd_tools::read_manifest(&path).await.map_err(error)?;
    let review = omd_tools::review(&tools).await.map_err(error)?;
    if input.approve_digest.as_deref() != Some(&review.digest) {
        return Ok(Json(Installation {
            review_required: true,
            review,
            installed: None,
        }));
    }
    let installed = omd_tools::install(
        &app.store,
        &app.profile,
        &tools,
        &review.digest,
        &input.label,
    )
    .await
    .map_err(error)?;
    std::fs::create_dir_all(app.profile.join("helper-work")).map_err(|_| {
        problem(
            StatusCode::CONFLICT,
            "tool_storage",
            "The helper working directory is unavailable.",
        )
    })?;
    app.runtime.register_media(
        &installed.digest,
        media(&app, &installed)?,
        installed.active,
    );
    Ok(Json(Installation {
        review_required: false,
        review,
        installed: Some(installed),
    }))
}
pub(crate) async fn activate(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Installed> {
    let _changes = app.source_changes.lock().await;
    let installed = omd_tools::activate(&app.store, &app.profile, &id)
        .await
        .map_err(error)?;
    app.runtime
        .register_media(&installed.digest, media(&app, &installed)?, true);
    Ok(Json(installed))
}
fn selected(review: &Review) -> BTreeSet<String> {
    review.tools.iter().map(|t| t.sha256.clone()).collect()
}
fn uses(plan: &Plan, hashes: &BTreeSet<String>) -> bool {
    plan.media.as_ref().is_some_and(|m| {
        hashes.contains(&m.yt_dlp_digest)
            && hashes.contains(&m.ffmpeg_digest)
            && hashes.contains(&m.ffprobe_digest)
            && m.node_digest.as_ref().is_none_or(|s| hashes.contains(s))
    })
}
pub(crate) async fn remove(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Remove>,
) -> ApiResult<Removal> {
    let _changes = app.source_changes.lock().await;
    let installed = omd_tools::get(&app.store, &id).await.map_err(error)?;
    let hashes = selected(&installed.review);
    let affected_jobs = omd_tools::affected_jobs(&app.store, &installed.review)
        .await
        .map_err(error)?;
    if input.approve_digest.as_deref() != Some(&installed.approval_digest) {
        return Ok(Json(Removal {
            review_required: true,
            affected_jobs,
            installed,
        }));
    }
    let installed = omd_tools::begin_removal(&app.store, &id)
        .await
        .map_err(error)?;
    app.runtime.revoke_media(&id);
    let running = app.running.lock().await;
    for (id, token) in running.iter() {
        if app
            .store
            .job(id)
            .await
            .is_ok_and(|j| j.state != JobState::Publishing && uses(&j.plan, &hashes))
        {
            token.cancel();
        }
    }
    drop(running);
    Ok(Json(Removal {
        review_required: false,
        affected_jobs,
        installed,
    }))
}
pub(crate) async fn retry(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Installed> {
    let _changes = app.source_changes.lock().await;
    Ok(Json(
        omd_tools::cleanup(&app.store, &app.profile, &id)
            .await
            .map_err(error)?,
    ))
}
pub async fn run(app: App) {
    loop {
        tokio::select! {_=app.shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(2))=>{}}
        let _changes = app.source_changes.lock().await;
        let mut cursor = None;
        loop {
            let Ok(page) = omd_tools::list(&app.store, "", cursor.as_deref(), 200).await else {
                break;
            };
            for item in page.items {
                if item.state == "removing" {
                    let _ = omd_tools::cleanup(&app.store, &app.profile, &item.digest).await;
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
    }
}
