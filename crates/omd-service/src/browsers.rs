use super::*;
use crate::native_sign_in;
use omd_browser::{Action, Browser, Mode, packages as packages_store};
use packages_store::{Installed, Review};

#[derive(Default, Clone)]
pub struct Sessions(Arc<Mutex<BTreeMap<String, Arc<Entry>>>>);
struct Entry {
    info: SignInSession,
    client: String,
    source_digest: String,
    session: Surface,
}
/// Where the person signs in: the engine's isolated browser (rendered for the
/// client as frames) or a native operating-system window owned by the engine.
enum Surface {
    Isolated(omd_browser::Session),
    Native(native_sign_in::Window),
}
impl Surface {
    fn cancel(&self) {
        match self {
            Self::Isolated(session) => session.cancel(),
            Self::Native(window) => window.cancel(),
        }
    }
    async fn closed(&self) {
        match self {
            Self::Isolated(session) => session.closed().await,
            Self::Native(window) => window.closed().await,
        }
    }
}
impl Sessions {
    async fn remove_matching(&self, predicate: impl Fn(&Entry) -> bool) {
        let removed = {
            let mut entries = self.0.lock().await;
            let ids: Vec<_> = entries
                .iter()
                .filter(|(_, entry)| predicate(entry))
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| entries.remove(&id))
                .collect::<Vec<_>>()
        };
        for entry in &removed {
            entry.session.cancel();
        }
        for entry in removed {
            entry.session.closed().await;
        }
    }
    pub async fn revoke_source(&self, source: &str) {
        self.remove_matching(|entry| entry.info.source_id == source)
            .await;
    }
    pub async fn detach(&self, client: &str) {
        self.remove_matching(|entry| entry.client == client).await;
    }
    pub async fn prune(&self, clients: &BTreeSet<String>) {
        self.remove_matching(|entry| {
            !clients.contains(&entry.client) || entry.info.expires_at <= chrono::Utc::now()
        })
        .await;
    }
    pub async fn close_all(&self) {
        self.remove_matching(|_| true).await;
    }
}
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct BrowserStatus {
    pub platform: String,
    pub bundled: Option<Review>,
    pub active: Option<Installed>,
    pub issue: Option<Problem>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallBrowser {
    manifest_path: Option<PathBuf>,
    label: String,
    approve_digest: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct BrowserInstallation {
    review_required: bool,
    review: Review,
    installed: Option<Installed>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveBrowser {
    approve_digest: Option<String>,
}
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct BrowserRemoval {
    review_required: bool,
    installed: Installed,
}
/// `isolated`: the engine's confined browser, shown to the client as frames.
/// `native`: a window using the operating system's web view, opened by the
/// engine on its desktop session. Native windows pass site checks that reject
/// automated browsers, but the page uses the ordinary network connection.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignInWindow {
    #[default]
    Isolated,
    Native,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartSignIn {
    client: String,
    profile: String,
    label: String,
    #[serde(default)]
    window: SignInWindow,
}
#[derive(Clone, Serialize, schemars::JsonSchema)]
pub(crate) struct SignInSession {
    pub id: String,
    pub source_id: String,
    pub profile: String,
    pub label: String,
    pub window: SignInWindow,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignInOwner {
    client: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignInAction {
    client: String,
    action: Action,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub(crate) struct SignInFrame {
    png: String,
    width: u32,
    height: u32,
    origin: String,
    controls: Vec<SignInControl>,
    controls_truncated: bool,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub(crate) struct SignInControl {
    id: String,
    kind: String,
    label: String,
    disabled: bool,
    value: String,
    entered: bool,
    checked: bool,
    options: Vec<SignInOption>,
}
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub(crate) struct SignInOption {
    value: String,
    label: String,
}
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct SignInReply {
    ready: bool,
    frame: Option<SignInFrame>,
}
#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct SignInClosed {
    closed: bool,
}
fn error(problem: Problem) -> ApiError {
    ApiError(StatusCode::CONFLICT, problem)
}
fn sign_in_url_denied() -> ApiError {
    problem(
        StatusCode::CONFLICT,
        "browser_url_denied",
        "This URL is outside the source's approved browser permissions.",
    )
}
fn native_only() -> ApiError {
    problem(
        StatusCode::CONFLICT,
        "browser_operation_denied",
        "This sign-in is in its own window. Finish signing in there.",
    )
}
fn missing() -> ApiError {
    problem(
        StatusCode::NOT_FOUND,
        "sign_in_expired",
        "This sign-in session is no longer available. Start sign-in again.",
    )
}
async fn validate_client(app: &App, id: &str) -> Result<(), ApiError> {
    if !app.clients.lock().await.is_live(id) {
        return Err(missing());
    }
    Ok(())
}
async fn entry(app: &App, id: &str, client: &str) -> Result<Arc<Entry>, ApiError> {
    validate_client(app, client).await?;
    let entry = app
        .browser_sessions
        .0
        .lock()
        .await
        .get(id)
        .cloned()
        .ok_or_else(missing)?;
    if entry.client != client || entry.info.expires_at <= chrono::Utc::now() {
        return Err(missing());
    }
    let source = provider(app, &entry.info.source_id).await?;
    if source.digest != entry.source_digest {
        entry.session.cancel();
        return Err(missing());
    }
    Ok(entry)
}
async fn register(app: &App, installed: &Installed) -> Result<(), ApiError> {
    let browser = Browser::new(
        packages_store::paths(&app.profile, &installed.review).map_err(error)?,
        app.acquisition.network.clone(),
        app.profile.join("helper-work"),
    );
    app.runtime
        .register_browser(&installed.digest, browser)
        .await;
    Ok(())
}
/// The label the engine gives the browser kit a distribution includes.
pub(crate) const INCLUDED_BROWSER_LABEL: &str = "Included browser";
/// The browser kit a person last activated themselves; see
/// [`tools::CHOSEN_TOOLS`].
pub(crate) const CHOSEN_BROWSER: &str = "chosen_browser";
pub async fn initialize(
    store: &Store,
    profile: &std::path::Path,
    network: &omd_network::Network,
    runtime: &Runtime,
    bundled: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(profile.join("helper-work"))?;
    let mut issue = None;
    if let Some(path) = bundled {
        store
            .set_setting("bundled_browser_path", &json!(path))
            .await?;
        let result = async {
            let kit = packages_store::read_manifest(path).await?;
            let review = packages_store::review(&kit).await?;
            let previous = tools::bundled_digest(store, "bundled_browser_review").await;
            let chosen = tools::bundled_digest(store, CHOSEN_BROWSER).await;
            store
                .set_setting("bundled_browser_review", &json!(review))
                .await
                .map_err(|_| {
                    Problem::new(
                        "browser_storage",
                        "Could not record the bundled browser review.",
                    )
                })?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM browser_packages")
                .fetch_one(&store.pool)
                .await
                .map_err(|_| {
                    Problem::new(
                        "browser_storage",
                        "Could not read browser installation history.",
                    )
                })?;
            let active = tools::active_entry(
                store,
                "SELECT a.digest,p.label FROM browser_package_active a \
                 LEFT JOIN browser_packages p ON p.digest=a.digest WHERE a.singleton=1",
            )
            .await
            .map_err(|_| Problem::new("browser_storage", "Could not read the active browser."))?;
            // Same policy as the media tools: an upgrade replaces an included
            // browser that is still active, unless the person activated it.
            if count == 0
                || tools::adopts_bundled(
                    previous.as_deref(),
                    active.as_ref().map(|(d, l)| (d.as_str(), l.as_str())),
                    INCLUDED_BROWSER_LABEL,
                    &review.digest,
                    chosen.as_deref(),
                )
            {
                packages_store::install(
                    store,
                    profile,
                    &kit,
                    &review.digest,
                    INCLUDED_BROWSER_LABEL,
                )
                .await?;
                packages_store::activate(store, profile, &review.digest).await?;
            }
            Ok::<_, Problem>(())
        }
        .await;
        if let Err(problem) = result {
            issue = Some(problem);
        }
    }
    let active: Option<String> =
        sqlx::query_scalar("SELECT digest FROM browser_package_active WHERE singleton=1")
            .fetch_one(&store.pool)
            .await?;
    if let Some(id) = active {
        let result = async {
            let installed = packages_store::get(store, &id).await?;
            let kit = packages_store::paths(profile, &installed.review)?;
            kit.verify().await?;
            runtime
                .register_browser(
                    &id,
                    Browser::new(kit, network.clone(), profile.join("helper-work")),
                )
                .await;
            Ok::<_, Problem>(())
        }
        .await;
        if let Err(problem) = result {
            issue = Some(problem);
        }
    }
    store
        .set_setting("browser_bootstrap_issue", &json!(issue))
        .await?;
    Ok(())
}
pub(crate) async fn status(State(app): State<App>) -> ApiResult<BrowserStatus> {
    let id: Option<String> =
        sqlx::query_scalar("SELECT digest FROM browser_package_active WHERE singleton=1")
            .fetch_one(&app.store.pool)
            .await
            .map_err(omd_store::StoreError::from)?;
    Ok(Json(BrowserStatus {
        platform: packages_store::platform(),
        bundled: app
            .store
            .setting("bundled_browser_review")
            .await?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| missing())?,
        active: match id {
            Some(id) => Some(packages_store::get(&app.store, &id).await.map_err(error)?),
            None => None,
        },
        issue: app
            .store
            .setting("browser_bootstrap_issue")
            .await?
            .filter(|v| !v.is_null())
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| missing())?,
    }))
}
pub(crate) async fn packages(
    State(app): State<App>,
    Query(query): Query<List>,
) -> ApiResult<Page<Installed>> {
    Ok(Json(
        packages_store::list(
            &app.store,
            &query.q,
            query.cursor.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await
        .map_err(error)?,
    ))
}
pub(crate) async fn package(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Installed> {
    Ok(Json(
        packages_store::get(&app.store, &id).await.map_err(error)?,
    ))
}
pub(crate) async fn install(
    State(app): State<App>,
    Json(input): Json<InstallBrowser>,
) -> ApiResult<BrowserInstallation> {
    let _changes = app.source_changes.lock().await;
    let path = match input.manifest_path {
        Some(path) => path,
        None => serde_json::from_value(
            app.store
                .setting("bundled_browser_path")
                .await?
                .ok_or_else(missing)?,
        )
        .map_err(|_| missing())?,
    };
    let kit = packages_store::read_manifest(&path).await.map_err(error)?;
    let review = packages_store::review(&kit).await.map_err(error)?;
    if input.approve_digest.as_deref() != Some(&review.digest) {
        return Ok(Json(BrowserInstallation {
            review_required: true,
            review,
            installed: None,
        }));
    }
    let installed =
        packages_store::install(&app.store, &app.profile, &kit, &review.digest, &input.label)
            .await
            .map_err(error)?;
    Ok(Json(BrowserInstallation {
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
    let installed = packages_store::activate(&app.store, &app.profile, &id)
        .await
        .map_err(error)?;
    app.browser_sessions.close_all().await;
    register(&app, &installed).await?;
    app.store
        .set_setting("browser_bootstrap_issue", &Value::Null)
        .await?;
    tools::record_choice(
        &app.store,
        CHOSEN_BROWSER,
        "bundled_browser_review",
        &installed.digest,
    )
    .await?;
    Ok(Json(installed))
}
pub(crate) async fn remove(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<RemoveBrowser>,
) -> ApiResult<BrowserRemoval> {
    let _changes = app.source_changes.lock().await;
    let installed = packages_store::get(&app.store, &id).await.map_err(error)?;
    if input.approve_digest.as_deref() != Some(&installed.approval_digest) {
        return Ok(Json(BrowserRemoval {
            review_required: true,
            installed,
        }));
    }
    let was_active = installed.active;
    let _installed = packages_store::begin_removal(&app.store, &id, &installed.approval_digest)
        .await
        .map_err(error)?;
    if was_active {
        app.browser_sessions.close_all().await;
    }
    app.runtime.revoke_browser(&id).await;
    Ok(Json(BrowserRemoval {
        review_required: false,
        installed: packages_store::cleanup(&app.store, &app.profile, &id)
            .await
            .map_err(error)?,
    }))
}
pub(crate) async fn cleanup(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Installed> {
    let _changes = app.source_changes.lock().await;
    if matches!(
        packages_store::get(&app.store, &id)
            .await
            .map_err(error)?
            .state
            .as_str(),
        "removing" | "retained"
    ) {
        app.runtime.revoke_browser(&id).await;
    }
    Ok(Json(
        packages_store::cleanup(&app.store, &app.profile, &id)
            .await
            .map_err(error)?,
    ))
}
pub(crate) async fn start(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<StartSignIn>,
) -> ApiResult<SignInSession> {
    let _changes = app.source_changes.lock().await;
    validate_client(&app, &input.client).await?;
    if input.profile.is_empty()
        || input.profile.len() > 128
        || !input
            .profile
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        || input.label.trim().is_empty()
        || input.label.len() > 200
    {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            "credential_profile_invalid",
            "Use a short account name and an alphanumeric profile identifier.",
        ));
    }
    if app.browser_sessions.0.lock().await.len() >= 4 {
        return Err(problem(
            StatusCode::CONFLICT,
            "browser_busy",
            "Close another sign-in session and retry.",
        ));
    }
    let source = provider(&app, &id).await?;
    let sign_in = source.manifest.sign_in.as_ref().ok_or_else(|| {
        problem(
            StatusCode::CONFLICT,
            "sign_in_unavailable",
            "This source does not declare an interactive sign-in flow.",
        )
    })?;
    let session = match input.window {
        SignInWindow::Isolated => {
            let browser = app.runtime.browser().ok_or_else(|| {
                problem(
                    StatusCode::CONFLICT,
                    "browser_unavailable",
                    "Install and activate the approved browser tools first.",
                )
            })?;
            let grants = source
                .manifest
                .grants
                .iter()
                .chain(sign_in.grants.iter())
                .cloned()
                .collect();
            Surface::Isolated(
                browser
                    .start(&sign_in.url, grants, None, Mode::SignIn, &app.shutdown)
                    .await
                    .map_err(error)?,
            )
        }
        SignInWindow::Native => {
            // The same start-page authority as the isolated browser.
            let url = url::Url::parse(&sign_in.url).map_err(|_| sign_in_url_denied())?;
            if !source
                .manifest
                .grants
                .iter()
                .chain(sign_in.grants.iter())
                .any(|g| g.credential && omd_network::validate_url(&url, g).is_ok())
            {
                return Err(sign_in_url_denied());
            }
            Surface::Native(
                native_sign_in::Window::launch(
                    &app.sign_in_helper,
                    &app.profile.join("helper-work"),
                    omd_credentials::native_sign_in::Request {
                        url: sign_in.url.clone(),
                        title: native_sign_in::title(&source.manifest.name),
                        completion_cookies: sign_in.completion_cookies.clone(),
                        // Only state for the source's own credential grants is kept.
                        grants: source.manifest.grants.clone(),
                        data_directory: PathBuf::new(),
                        timeout_seconds: 600,
                    },
                    &app.shutdown,
                )
                .await
                .map_err(error)?,
            )
        }
    };
    let info = SignInSession {
        id: omd_store::id("signin"),
        source_id: id,
        profile: input.profile,
        label: input.label.trim().into(),
        window: input.window,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    };
    app.browser_sessions.0.lock().await.insert(
        info.id.clone(),
        Arc::new(Entry {
            info: info.clone(),
            client: input.client,
            source_digest: source.digest,
            session,
        }),
    );
    Ok(Json(info))
}
pub(crate) async fn action(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<SignInAction>,
) -> ApiResult<SignInReply> {
    let entry = entry(&app, &id, &input.client).await?;
    let Surface::Isolated(session) = &entry.session else {
        return Err(native_only());
    };
    let frame = matches!(input.action, Action::Frame);
    let result = session
        .action(input.action, &app.shutdown)
        .await
        .map_err(error)?;
    Ok(Json(SignInReply {
        ready: true,
        frame: if frame {
            Some(serde_json::from_value(result).map_err(|_| missing())?)
        } else {
            None
        },
    }))
}
async fn connected(app: &App, entry: &Entry) -> Result<bool, ApiError> {
    let source = provider(app, &entry.info.source_id).await?;
    let session = match &entry.session {
        Surface::Isolated(session) => session,
        Surface::Native(window) => {
            if !window.ready().map_err(error)? {
                return Ok(false);
            }
            // Re-check the captured session with the engine's own rules.
            let session = window.session().ok_or_else(missing)?;
            return Ok(completion_met(&session, &source));
        }
    };
    let session = session.credentials(&app.shutdown).await.map_err(error)?;
    let names: Vec<&str> = session
        .cookies
        .iter()
        .filter(|cookie| {
            cookie
                .expires_at
                .is_none_or(|expiry| expiry > chrono::Utc::now().timestamp())
                && omd_credentials::cookie_authorized(cookie, &source.manifest.grants)
        })
        .map(|cookie| cookie.name.as_str())
        .collect();
    let required = &source
        .manifest
        .sign_in
        .as_ref()
        .ok_or_else(missing)?
        .completion_cookies;
    Ok(!names.is_empty() && required.iter().all(|name| names.contains(&name.as_str())))
}
fn completion_met(session: &omd_credentials::Session, source: &Provider) -> bool {
    let now = chrono::Utc::now().timestamp();
    let names: Vec<&str> = session
        .cookies
        .iter()
        .filter(|cookie| {
            cookie.expires_at.is_none_or(|expiry| expiry > now)
                && omd_credentials::cookie_authorized(cookie, &source.manifest.grants)
        })
        .map(|cookie| cookie.name.as_str())
        .collect();
    let required = source
        .manifest
        .sign_in
        .as_ref()
        .map(|s| s.completion_cookies.as_slice())
        .unwrap_or_default();
    !names.is_empty() && required.iter().all(|name| names.contains(&name.as_str()))
}
pub(crate) async fn sign_in_status(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<SignInOwner>,
) -> ApiResult<SignInReply> {
    let entry = entry(&app, &id, &input.client).await?;
    Ok(Json(SignInReply {
        ready: connected(&app, &entry).await?,
        frame: None,
    }))
}
pub(crate) async fn complete(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<SignInOwner>,
) -> ApiResult<Value> {
    // Source activation/removal must not race a completed browser export into
    // the vault after that source identity has been revoked.
    let _changes = app.source_changes.lock().await;
    let entry = entry(&app, &id, &input.client).await?;
    if !connected(&app, &entry).await? {
        return Err(problem(
            StatusCode::CONFLICT,
            "sign_in_pending",
            "Finish signing in in the browser window first.",
        ));
    }
    let source = provider(&app, &entry.info.source_id).await?;
    let mut session = match &entry.session {
        Surface::Isolated(session) => session.credentials(&app.shutdown).await.map_err(error)?,
        Surface::Native(window) => window.session().ok_or_else(missing)?,
    };
    // Identity-provider cookies stay in the temporary browser. Persist only
    // credentials authorized for acquisition requests to this source.
    session
        .cookies
        .retain(|cookie| omd_credentials::cookie_authorized(cookie, &source.manifest.grants));
    session.origins.retain(|storage| {
        omd_credentials::origin_authorized(&storage.origin, &source.manifest.grants)
    });
    session.validate(&source.manifest.grants)?;
    let result = save_credentials_locked(
        &app,
        entry.info.source_id.clone(),
        entry.info.profile.clone(),
        SaveCredentials {
            label: entry.info.label.clone(),
            session,
        },
    )
    .await?;
    app.browser_sessions.0.lock().await.remove(&id);
    entry.session.cancel();
    entry.session.closed().await;
    Ok(result)
}
pub(crate) async fn close(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<SignInOwner>,
) -> ApiResult<SignInClosed> {
    let entry = entry(&app, &id, &input.client).await?;
    app.browser_sessions.0.lock().await.remove(&id);
    entry.session.cancel();
    entry.session.closed().await;
    Ok(Json(SignInClosed { closed: true }))
}
pub async fn run(app: App) {
    loop {
        let mut cursor = None;
        loop {
            let page = match packages_store::list(&app.store, "", cursor.as_deref(), 200).await {
                Ok(page) => page,
                Err(_) => break,
            };
            for installed in page.items {
                if installed.state == "removing" {
                    let _changes = app.source_changes.lock().await;
                    app.runtime.revoke_browser(&installed.digest).await;
                    let _ =
                        packages_store::cleanup(&app.store, &app.profile, &installed.digest).await;
                }
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        tokio::select! {_=app.shutdown.cancelled()=>{app.browser_sessions.close_all().await;break;},_=tokio::time::sleep(Duration::from_secs(5))=>{}}
    }
}
