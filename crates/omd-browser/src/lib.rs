//! Engine-owned browser sessions. No provider receives launch configuration,
//! browser handles, cookie export, arbitrary evaluation, or local file access.
use omd_domain::{HostGrant, Problem};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Problem>;
pub mod packages;
const STORAGE_PROTOCOL_MARKER: &[u8] = b"omd-browser-protocol: 2";
fn update_required() -> Problem {
    issue(
        "browser_update_required",
        "This account needs the newer included browser tools. Install the included browser update, then retry.",
        "update_browser",
    )
}
fn same_site(value: Option<omd_credentials::SameSite>) -> &'static str {
    match value {
        Some(omd_credentials::SameSite::Strict) => "Strict",
        Some(omd_credentials::SameSite::None) => "None",
        Some(omd_credentials::SameSite::Lax) | None => "Lax",
    }
}
fn issue(code: &str, message: &str, action: &str) -> Problem {
    Problem {
        code: code.into(),
        message: message.into(),
        actions: vec![action.into()],
        retryable: action == "retry",
    }
}
fn failed() -> Problem {
    issue(
        "browser_failed",
        "The isolated browser could not complete this operation. Start the session again.",
        "restart_sign_in",
    )
}
fn integrity() -> Problem {
    issue(
        "browser_integrity",
        "The managed browser files failed verification. Restore the approved browser package.",
        "restore_tool",
    )
}

#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kit {
    pub root: PathBuf,
    pub version: String,
    pub node: omd_media::Tool,
    pub browser: String,
    pub adapter: String,
    pub files: BTreeMap<String, FileIdentity>,
}
impl Kit {
    pub fn executable(&self, name: &str) -> bool {
        name == self.browser
            || name.contains(".app/Contents/MacOS/")
            || name.ends_with("/chrome_crashpad_handler")
    }
    #[cfg(windows)]
    async fn stage(&self, work: &std::path::Path) -> Result<(Self, tempfile::TempDir)> {
        use std::io::Write;
        let runtime = tempfile::Builder::new()
            .prefix(".omd-runtime-")
            .tempdir_in(work)
            .map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
        let root = runtime.path().join("browser");
        omd_files::private_profile(&root).map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
        let source = omd_files::Root::open(&self.root).map_err(|_| integrity())?;
        for (name, identity) in &self.files {
            let mut input = source.read_file(name).map_err(|_| integrity())?;
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().ok_or_else(integrity)?).map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
            let mut output = omd_files::create_private_file(&path).map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
            std::io::copy(&mut input, &mut output)
                .and_then(|_| output.flush())
                .map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
            drop(output);
            let output = omd_files::Root::open(path.parent().ok_or_else(integrity)?)
                .map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?
                .read_file(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .ok_or_else(integrity)?,
                )
                .map_err(|_| issue("browser_runtime_storage", "The private browser runtime could not be created. Check available storage and retry.", "retry"))?;
            if omd_files::hash_file(output).map_err(|_| integrity())?
                != (identity.bytes, identity.sha256.clone())
            {
                return Err(integrity());
            }
        }
        let node = self.node.stage(runtime.path()).await?;
        Ok((
            Self {
                root,
                node,
                ..self.clone()
            },
            runtime,
        ))
    }
    /// Adapter protocol 2 restores and exports origin page storage. Older
    /// approved kits remain usable for cookie-only accounts.
    pub async fn storage_support(&self) -> bool {
        let kit = self.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let root = omd_files::Root::open(&kit.root).ok()?;
            let mut text = Vec::new();
            root.read_file(&kit.adapter)
                .ok()?
                .take(1024 * 1024)
                .read_to_end(&mut text)
                .ok()?;
            Some(
                text.windows(STORAGE_PROTOCOL_MARKER.len())
                    .any(|w| w == STORAGE_PROTOCOL_MARKER),
            )
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
    }
    pub async fn verify(&self) -> Result<()> {
        if self.files.is_empty()
            || self.files.len() > 8192
            || !self.files.contains_key(&self.browser)
            || !self.files.contains_key(&self.adapter)
        {
            return Err(integrity());
        }
        self.node.verify().await?;
        let kit = self.clone();
        tokio::task::spawn_blocking(move || {
            let root = omd_files::Root::open(&kit.root).map_err(|_| integrity())?;
            // Queue paths, not open directories: macOS GUI applications inherit
            // a 256-descriptor limit and Chromium has hundreds of locale folders.
            let mut pending = vec![String::new()];
            let mut count = 0;
            let mut total = 0u64;
            let mut directories = 0;
            while let Some(prefix) = pending.pop() {
                let directory = if prefix.is_empty() {
                    root.try_clone()
                } else {
                    root.directory(prefix.trim_end_matches('/'))
                }
                .map_err(|_| integrity())?;
                for entry in directory.entries().map_err(|_| integrity())? {
                    let entry = entry.map_err(|_| integrity())?;
                    let path = format!("{prefix}{}", entry.name);
                    if entry.directory {
                        directories += 1;
                        if directories > 2048 || path.len() > 1024 {
                            return Err(integrity());
                        }
                        pending.push(format!("{path}/"));
                    } else {
                        let identity = kit.files.get(&path).ok_or_else(integrity)?;
                        total = total.checked_add(identity.bytes).ok_or_else(integrity)?;
                        // A regular Chromium bundle includes the native sign-in UI and helpers.
                        if total > 2 * 1024 * 1024 * 1024 {
                            return Err(integrity());
                        }
                        let file = root.read_file(&path).map_err(|_| integrity())?;
                        if file.metadata().map_err(|_| integrity())?.len() != identity.bytes {
                            return Err(integrity());
                        }
                        let actual = omd_files::hash_file(file).map_err(|_| integrity())?;
                        if actual != (identity.bytes, identity.sha256.clone()) {
                            return Err(integrity());
                        }
                        count += 1;
                    }
                }
            }
            if count != kit.files.len() {
                return Err(integrity());
            }
            Ok(())
        })
        .await
        .map_err(|_| integrity())?
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Source,
    SignIn,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Control {
        control: String,
        action: ControlAction,
    },
    Navigate {
        url: String,
    },
    Wait {
        selector: String,
    },
    Click {
        selector: String,
    },
    Fill {
        selector: String,
        text: String,
    },
    Select {
        selector: String,
        value: String,
    },
    Press {
        key: String,
    },
    Pointer {
        x: u32,
        y: u32,
    },
    Type {
        text: String,
    },
    Scroll {
        delta: i32,
    },
    Snapshot,
    Frame,
}
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlAction {
    Click,
    Fill { text: String },
    Select { value: String },
}
#[derive(Clone)]
pub struct Browser {
    pub kit: Kit,
    pub network: omd_network::Network,
    pub work_root: PathBuf,
    permits: Arc<Semaphore>,
    pub revoked: CancellationToken,
}
struct Request {
    payload: Value,
    reply: oneshot::Sender<Result<Value>>,
    cancel: CancellationToken,
}
pub struct Session {
    commands: mpsc::Sender<Request>,
    grants: Vec<HostGrant>,
    mode: Mode,
    credentials: Option<omd_credentials::Session>,
    storage: bool,
    stop: CancellationToken,
    closed: CancellationToken,
}
struct Completion(CancellationToken);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Browser {
    pub async fn stop(&self) {
        self.revoked.cancel();
        // Each live or starting session owns one permit until process cleanup.
        let _quiescent = self.permits.acquire_many(4).await;
    }
    pub fn new(kit: Kit, network: omd_network::Network, work_root: PathBuf) -> Self {
        Self {
            kit,
            network,
            work_root,
            permits: Arc::new(Semaphore::new(4)),
            revoked: CancellationToken::new(),
        }
    }
    pub async fn start(
        &self,
        url: &str,
        grants: Vec<HostGrant>,
        credentials: Option<omd_credentials::Session>,
        mode: Mode,
        cancel: &CancellationToken,
    ) -> Result<Session> {
        validate_url(url, &grants, mode)?;
        if self.revoked.is_cancelled() {
            return Err(failed());
        }
        if let Some(session) = &credentials {
            session.validate(&grants).map_err(|e| e.problem())?;
            session
                .check_expiration(chrono::Utc::now().timestamp())
                .map_err(|e| e.problem())?;
        }
        let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
            issue(
                "browser_busy",
                "Close another browser session and retry.",
                "retry",
            )
        })?;
        self.kit.verify().await?;
        let storage = self.kit.storage_support().await;
        let origins = credentials
            .as_ref()
            .map(|s| s.origins.as_slice())
            .unwrap_or_default();
        if !origins.is_empty() && !storage {
            return Err(update_required());
        }
        if !origins.is_empty() && mode == Mode::SignIn {
            return Err(failed());
        }
        let work = tempfile::Builder::new()
            .prefix("browser-")
            .tempdir_in(&self.work_root)
            .map_err(|_| failed())?;
        #[cfg(windows)]
        let (kit, runtime) = self.kit.stage(work.path()).await?;
        #[cfg(not(windows))]
        let kit = &self.kit;
        // Browser owns its cookie jar. Passing an old session to the broker would
        // overwrite a replacement cookie after a successful reauthentication.
        let broker = omd_helper_broker::Broker::start(
            self.network.clone(),
            grants.clone(),
            credentials
                .as_ref()
                .filter(|s| !s.headers.is_empty())
                .map(|s| omd_credentials::Session {
                    expires_at: s.expires_at,
                    cookies: vec![],
                    headers: s.headers.clone(),
                    origins: vec![],
                }),
            true,
            16 * 1024 * 1024,
        )
        .await
        .and_then(|b| b.native())
        .map_err(|_| failed())?;
        let policy = omd_isolation::Policy {
            executable: kit.node.path.clone(),
            readable: vec![kit.root.clone()],
            executables: kit
                .files
                .keys()
                .filter(|name| kit.executable(name))
                .map(|name| kit.root.join(name))
                .collect(),
            work: work.path().into(),
            broker_port: Some(broker.port),
            broker_upstream_port: broker.isolation_upstream(),
            interactive: mode == Mode::SignIn,
        };
        let mut native = omd_isolation::Session::start(
            &policy,
            &[kit.root.join(&kit.adapter).to_string_lossy().into()],
            &BTreeMap::new(),
            true,
        )
        .map_err(native_error)?;
        let cookies: Vec<Value> = credentials.as_ref().map(|session| session.cookies.iter().filter(|c| c.expires_at.is_none_or(|expiry| expiry > chrono::Utc::now().timestamp())).map(|c| json!({
            "name": c.name, "value": c.value, "domain": if c.host_only { c.domain.clone() } else { format!(".{}", c.domain) }, "path": c.path,
            "expires": c.expires_at.unwrap_or(-1), "secure": c.secure, "httpOnly": c.http_only, "sameSite": same_site(c.same_site),
        })).collect()).unwrap_or_default();
        let mut payload = json!({"id":1,"op":"start","executable":kit.root.join(&kit.browser),"proxy":format!("http://127.0.0.1:{}",broker.port),"username":broker.username,"spki":broker.spki,"url":url,"cookies":cookies,"headed":mode == Mode::SignIn});
        // Older adapters reject unknown start fields, so send storage only when present.
        if !origins.is_empty() {
            payload["origins"] = Value::Array(origins.iter().map(|o| json!({
                "origin": o.origin,
                "localStorage": o.local_storage.iter().map(|i| json!({"name": i.name, "value": i.value})).collect::<Vec<_>>(),
            })).collect());
        }
        let started = tokio::select! { _ = self.revoked.cancelled() => Err(failed()), result = exchange(&mut native, payload, 1, cancel) => result };
        if let Err(error) = started {
            native.close().await;
            return Err(error);
        }
        let (commands, mut receiver) = mpsc::channel::<Request>(1);
        let stop = cancel.child_token();
        let task_stop = stop.clone();
        let revoked = self.revoked.clone();
        let closed = CancellationToken::new();
        let task_closed = closed.clone();
        tokio::spawn(async move {
            let _completed = Completion(task_closed);
            async move {
            let (_permit, _work, _broker) = (permit, work, broker);
            #[cfg(windows)]
            let _runtime = runtime;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
            let mut sequence = 1;
            loop {
                let request = tokio::select! {
                    _ = revoked.cancelled() => break,
                    _ = task_stop.cancelled() => break,
                    _ = tokio::time::sleep_until(deadline) => break,
                    request = receiver.recv() => match request { Some(r) => r, None => break },
                };
                sequence += 1;
                let mut payload = request.payload;
                payload["id"] = json!(sequence);
                let result = tokio::select! {
                    _ = revoked.cancelled() => Err(failed()),
                    _ = task_stop.cancelled() => Err(failed()),
                    _ = tokio::time::sleep_until(deadline) => Err(issue("browser_expired", "This browser session expired. Start sign-in again.", "restart_sign_in")),
                    result = exchange(&mut native, payload, sequence, &request.cancel) => result,
                };
                let failed = result
                    .as_ref()
                    .is_err_and(|error| error.code != "browser_operation_failed");
                let _ = request.reply.send(result);
                if failed {
                    break;
                }
            }
            native.close().await;
            drop(native);
            drop(_broker);
            drop(_work);
            drop(_permit);
            }.await;
        });
        Ok(Session {
            commands,
            grants,
            mode,
            credentials,
            storage,
            stop,
            closed,
        })
    }
}
fn native_error(error: omd_isolation::Error) -> Problem {
    if matches!(error, omd_isolation::Error::Elevated) {
        issue(
            "elevated_engine",
            "Close OMD and start it without Run as administrator.",
            "restart_engine",
        )
    } else if matches!(error, omd_isolation::Error::Unavailable) {
        issue(
            "browser_isolation_unavailable",
            "The operating system could not apply the required browser protection.",
            "restore_tool",
        )
    } else if matches!(error, omd_isolation::Error::Budget) {
        issue(
            "browser_budget",
            "The page exceeded the browser resource or response budget. Retry the operation or start a new sign-in session.",
            "retry",
        )
    } else {
        failed()
    }
}
async fn exchange(
    native: &mut omd_isolation::Session,
    payload: Value,
    id: u64,
    cancel: &CancellationToken,
) -> Result<Value> {
    let bytes = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| failed())?);
    let output = Zeroizing::new(
        native
            .exchange(&bytes, 4 * 1024 * 1024, Duration::from_secs(30), cancel)
            .await
            .map_err(native_error)?,
    );
    let mut response: Value = serde_json::from_slice(&output).map_err(|_| failed())?;
    #[cfg(feature = "fixture-tests")]
    if response.get("error").is_some() {
        eprintln!("Browser fixture failure: {response}");
    }
    if response["id"] == id && response["error"] == "browser_operation_failed" {
        return Err(issue(
            "browser_operation_failed",
            "The page did not complete this action. Refresh the sign-in view to check its state before retrying.",
            "refresh_sign_in",
        ));
    }
    if response["id"] != id || response.get("error").is_some() || response.get("result").is_none() {
        return Err(failed());
    }
    Ok(response["result"].take())
}
fn validate_url(text: &str, grants: &[HostGrant], mode: Mode) -> Result<()> {
    let url = url::Url::parse(text).map_err(|_| failed())?;
    if !grants.iter().any(|grant| {
        (mode != Mode::SignIn || grant.credential)
            && grant.methods.iter().any(|m| m == "GET")
            && omd_network::validate_url(&url, grant).is_ok()
    }) {
        return Err(issue(
            "browser_url_denied",
            "This URL is outside the source's approved browser permissions.",
            "review_permissions",
        ));
    }
    Ok(())
}
impl Session {
    pub fn cancel(&self) {
        self.stop.cancel();
    }
    pub async fn closed(&self) {
        self.closed.cancelled().await;
    }
    async fn request(&self, payload: Value, cancel: &CancellationToken) -> Result<Value> {
        if self.stop.is_cancelled() {
            return Err(failed());
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .try_send(Request {
                payload,
                reply,
                cancel: cancel.clone(),
            })
            .map_err(|_| failed())?;
        tokio::select! { _ = cancel.cancelled() => Err(failed()), result = response => result.map_err(|_| failed())? }
    }
    pub async fn action(&self, action: Action, cancel: &CancellationToken) -> Result<Value> {
        if let Action::Navigate { url } = &action {
            validate_url(url, &self.grants, self.mode)?;
        }
        // Image frames expose the rendered sign-in page only to its owner. They
        // are never a source-plugin result, and sign-in has no text export.
        if (self.mode == Mode::Source && matches!(action, Action::Frame | Action::Control { .. }))
            || (self.mode == Mode::SignIn && matches!(action, Action::Snapshot))
        {
            return Err(issue(
                "browser_operation_denied",
                "This operation is not available in this browser session.",
                "review_permissions",
            ));
        }
        let mut result = self
            .request(serde_json::to_value(action).map_err(|_| failed())?, cancel)
            .await?;
        if let Some(credentials) = &self.credentials {
            credentials.redact_value(&mut result);
        }
        if self.mode == Mode::Source {
            // A page may rotate its session cookie. Redact those new values too,
            // while keeping cookie export inaccessible to the provider.
            self.cookie_session(cancel).await?.redact_value(&mut result);
        }
        Ok(result)
    }
    /// Engine-only export, never included in a provider broker or frontend reply.
    pub async fn credentials(
        &self,
        cancel: &CancellationToken,
    ) -> Result<omd_credentials::Session> {
        if self.mode != Mode::SignIn {
            return Err(failed());
        }
        let mut session = self.cookie_session(cancel).await?;
        if self.storage {
            session.origins = self.storage_export(cancel).await?;
        }
        if !session.cookies.is_empty() || !session.origins.is_empty() {
            session.validate(&self.grants).map_err(|e| e.problem())?;
        }
        Ok(session)
    }
    /// Page storage of credential-authorized HTTPS origins the page visited.
    async fn storage_export(
        &self,
        cancel: &CancellationToken,
    ) -> Result<Vec<omd_credentials::OriginStorage>> {
        let response = self.request(json!({"op":"storage"}), cancel).await?;
        let origins = response["origins"]
            .as_array()
            .filter(|v| v.len() <= 64)
            .ok_or_else(failed)?;
        let mut kept = vec![];
        for origin in origins {
            let name = origin["origin"].as_str().ok_or_else(failed)?;
            // Identity-provider and unrelated origins stay in the temporary browser.
            if !omd_credentials::origin_authorized(name, &self.grants) {
                continue;
            }
            let items = origin["localStorage"]
                .as_array()
                .filter(|v| v.len() <= omd_credentials::MAX_STORAGE_ITEMS)
                .ok_or_else(failed)?;
            let mut local_storage = vec![];
            for item in items {
                local_storage.push(omd_credentials::StorageItem {
                    name: item["name"].as_str().ok_or_else(failed)?.to_owned(),
                    value: item["value"].as_str().ok_or_else(failed)?.to_owned(),
                });
            }
            if !local_storage.is_empty() {
                kept.push(omd_credentials::OriginStorage {
                    origin: name.to_owned(),
                    local_storage,
                });
            }
        }
        Ok(kept)
    }
    async fn cookie_session(&self, cancel: &CancellationToken) -> Result<omd_credentials::Session> {
        let response = self.request(json!({"op":"cookies"}), cancel).await?;
        let cookies = response["cookies"]
            .as_array()
            .filter(|v| v.len() <= 512)
            .ok_or_else(failed)?;
        let mut session = omd_credentials::Session {
            expires_at: None,
            cookies: vec![],
            headers: vec![],
            origins: vec![],
        };
        for cookie in cookies {
            let text = |key: &str| cookie[key].as_str().map(str::to_owned).ok_or_else(failed);
            let domain = text("domain")?;
            let expires = cookie["expires"]
                .as_f64()
                .filter(|n| n.is_finite())
                .ok_or_else(failed)?;
            let candidate = omd_credentials::Cookie {
                name: text("name")?,
                value: text("value")?,
                domain: domain.trim_start_matches('.').to_owned(),
                path: text("path")?,
                host_only: !domain.starts_with('.'),
                expires_at: if expires < 0.0 {
                    None
                } else {
                    Some(expires as i64)
                },
                secure: cookie["secure"].as_bool().unwrap_or(true),
                http_only: cookie["httpOnly"].as_bool().unwrap_or(true),
                same_site: match cookie["sameSite"].as_str() {
                    Some("Strict") => Some(omd_credentials::SameSite::Strict),
                    Some("None") => Some(omd_credentials::SameSite::None),
                    _ => Some(omd_credentials::SameSite::Lax),
                },
            };
            if candidate
                .expires_at
                .is_some_and(|expiry| expiry <= chrono::Utc::now().timestamp())
            {
                continue;
            }
            let individual = omd_credentials::Session {
                expires_at: None,
                cookies: vec![candidate],
                headers: vec![],
                origins: vec![],
            };
            // Ignore noncredential origins (e.g. public artwork). Their cookies
            // must never expand the authority granted to the saved account.
            if individual.validate(&self.grants).is_ok() {
                session.cookies.extend(individual.cookies.clone());
            }
        }
        if !session.cookies.is_empty() {
            session.validate(&self.grants).map_err(|e| e.problem())?;
        }
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn kit(root: &std::path::Path) -> Kit {
        Kit {
            root: root.into(),
            version: "fixture".into(),
            node: omd_media::Tool {
                path: root.join("node"),
                sha256: String::new(),
                version: "fixture".into(),
            },
            browser: "browser/chrome".into(),
            adapter: "adapter/adapter.mjs".into(),
            files: BTreeMap::new(),
        }
    }
    #[tokio::test]
    async fn only_protocol_two_adapters_receive_page_storage() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("adapter")).unwrap();
        let adapter = root.path().join("adapter/adapter.mjs");
        std::fs::write(&adapter, "import { frames } from './protocol.mjs';\n").unwrap();
        assert!(!kit(root.path()).storage_support().await);
        std::fs::write(
            &adapter,
            include_str!("../../../adapters/browser/adapter.mjs"),
        )
        .unwrap();
        assert!(kit(root.path()).storage_support().await);
        std::fs::remove_file(&adapter).unwrap();
        assert!(!kit(root.path()).storage_support().await);
        assert_eq!(update_required().code, "browser_update_required");
        assert_eq!(same_site(None), "Lax");
        assert_eq!(same_site(Some(omd_credentials::SameSite::None)), "None");
    }
}
