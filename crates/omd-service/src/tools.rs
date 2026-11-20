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
/// The `digest` a setting records: the included set the previous app run
/// recorded, or the set a person last activated themselves.
pub(crate) async fn bundled_digest(store: &Store, setting: &str) -> Option<String> {
    store
        .setting(setting)
        .await
        .ok()
        .flatten()
        .and_then(|value| value.get("digest")?.as_str().map(str::to_owned))
}
/// The label the engine gives the media tools a distribution includes.
pub(crate) const INCLUDED_TOOLS_LABEL: &str = "Included media tools";
/// The setting that records the media tool set a person last activated
/// themselves (`{"digest": ...}`), or null when they returned to the
/// included set.
pub(crate) const CHOSEN_TOOLS: &str = "chosen_tools";
/// Whether an upgraded app's included set replaces the active one.
///
/// `active` is the active set's digest and label, and `chosen` the set the
/// person last activated themselves. The engine adopts the new included set
/// when the active set is the one the previous app included, or when it still
/// carries the engine's own included label: an even older app installed it
/// automatically and the person never chose another. A set the person
/// activated themselves is kept even when it is an earlier included set (a
/// rollback), and so is a set installed under their own label, or having none
/// after a removal.
pub(crate) fn adopts_bundled(
    previous: Option<&str>,
    active: Option<(&str, &str)>,
    included_label: &str,
    new: &str,
    chosen: Option<&str>,
) -> bool {
    let Some((digest, label)) = active else {
        return false;
    };
    digest != new && chosen != Some(digest) && (previous == Some(digest) || label == included_label)
}
/// Records that the person activated `digest` themselves, so an app upgrade
/// keeps it. Activating the set this app includes clears the record instead:
/// the person returned to the included set, which later upgrades replace.
pub(crate) async fn record_choice(
    store: &Store,
    setting: &str,
    bundled_setting: &str,
    digest: &str,
) -> Result<(), omd_store::StoreError> {
    let included = bundled_digest(store, bundled_setting).await;
    let choice = if included.as_deref() == Some(digest) {
        Value::Null
    } else {
        json!({ "digest": digest })
    };
    store.set_setting(setting, &choice).await
}
/// The active entry's digest and label, read from a singleton active table.
pub(crate) async fn active_entry(
    store: &Store,
    query: &str,
) -> std::result::Result<Option<(String, String)>, sqlx::Error> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as(query).fetch_optional(&store.pool).await?;
    Ok(match row {
        Some((Some(digest), Some(label))) => Some((digest, label)),
        _ => None,
    })
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
            let chosen = bundled_digest(store, CHOSEN_TOOLS).await;
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
            let active = active_entry(
                store,
                "SELECT a.digest,t.label FROM managed_tool_active a \
                 LEFT JOIN managed_tool_sets t ON t.digest=a.digest WHERE a.singleton=1",
            )
            .await
            .map_err(|_| Problem::new("tool_storage", "Could not read the active tool set."))?;
            // First installation accepts the distribution's included tool set,
            // and an app upgrade replaces an included set that is still the
            // active one. A set the person chose or removed is kept; the new
            // included set is offered for review.
            if existing == 0
                || adopts_bundled(
                    previous.as_deref(),
                    active.as_ref().map(|(d, l)| (d.as_str(), l.as_str())),
                    INCLUDED_TOOLS_LABEL,
                    &review.digest,
                    chosen.as_deref(),
                )
            {
                omd_tools::install(store, profile, &tools, &review.digest, INCLUDED_TOOLS_LABEL)
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
    record_choice(
        &app.store,
        CHOSEN_TOOLS,
        "bundled_tools_review",
        &installed.digest,
    )
    .await?;
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
#[cfg(test)]
mod adoption_tests {
    use super::{INCLUDED_TOOLS_LABEL, adopts_bundled};
    use crate::browsers::INCLUDED_BROWSER_LABEL;

    #[test]
    fn upgrades_replace_only_sets_the_engine_installed_itself() {
        for label in [INCLUDED_TOOLS_LABEL, INCLUDED_BROWSER_LABEL] {
            let included = Some(("old", label));
            // The previous app's included set is still active.
            assert!(adopts_bundled(Some("old"), included, label, "new", None));
            // An even older app installed it: no matching record, or none.
            assert!(adopts_bundled(Some("other"), included, label, "new", None));
            assert!(adopts_bundled(None, included, label, "new", None));
            // A choice of some other set does not keep this one.
            assert!(adopts_bundled(None, included, label, "new", Some("x")));
            // Already the new set.
            assert!(!adopts_bundled(
                Some("old"),
                Some(("new", label)),
                label,
                "new",
                None
            ));
            // A set the person chose, or none after a removal, is kept.
            assert!(!adopts_bundled(
                Some("other"),
                Some(("old", "Mine")),
                label,
                "new",
                None
            ));
            assert!(!adopts_bundled(
                None,
                Some(("old", "Mine")),
                label,
                "new",
                None
            ));
            assert!(!adopts_bundled(Some("old"), None, label, "new", None));
            assert!(!adopts_bundled(None, None, label, "new", None));
            // An included set the person activated themselves (a rollback to
            // an earlier included set) is kept, with or without a record.
            for previous in [None, Some("old"), Some("other")] {
                assert!(!adopts_bundled(
                    previous,
                    included,
                    label,
                    "new",
                    Some("old")
                ));
            }
        }
        // The other kind's label is not this kind's included label.
        assert!(!adopts_bundled(
            None,
            Some(("old", INCLUDED_BROWSER_LABEL)),
            INCLUDED_TOOLS_LABEL,
            "new",
            None
        ));
    }
}
