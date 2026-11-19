//! Cancellation owns the worker process and concurrency permit in one scope.
use omd_domain::*;
use omd_network::{Network, Request};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
};
use tokio_util::sync::CancellationToken;
mod authority;
mod http_cache;

const FRAME_LIMIT: usize = 16 * 1024 * 1024;
// Installation includes cold native compilation of the componentized JS runtime.
// This is separate from the ordinary 60-second operation allowance. The worker's
// fuel, guest-memory and 30-second execution-epoch limits still apply, including
// to initialization, and inspection never accepts a broker request.
const INSTALLATION_TIMEOUT: Duration = Duration::from_secs(300);
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error(transparent)]
    Credential(#[from] omd_credentials::Error),
    #[error("The source operation was canceled")]
    Canceled,
    #[error("The source exceeded its execution budget")]
    Budget,
    #[error(
        "The source installation exceeded its compilation allowance. Retry when the system has more available capacity."
    )]
    InstallationBudget,
    #[error("The source package failed integrity verification")]
    Integrity,
    #[error("The source returned an invalid response")]
    Invalid,
    #[error("The source does not support this operation")]
    Unsupported,
    #[error("The source worker is unavailable")]
    Worker,
    #[error("{}", .0.message)]
    Source(Problem),
}
pub type Result<T> = std::result::Result<T, PluginError>;

#[derive(Clone)]
pub struct Provider {
    pub manifest: ProviderManifest,
    pub component: PathBuf,
    pub digest: String,
}
impl Provider {
    pub async fn verify(&self) -> Result<()> {
        let meta = tokio::fs::metadata(&self.component)
            .await
            .map_err(|_| PluginError::Integrity)?;
        if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
            return Err(PluginError::Integrity);
        }
        let bytes = tokio::fs::read(&self.component)
            .await
            .map_err(|_| PluginError::Integrity)?;
        if package_digest(&self.manifest, &bytes) != self.digest {
            return Err(PluginError::Integrity);
        }
        Ok(())
    }
}
pub fn package_digest(manifest: &ProviderManifest, component: &[u8]) -> String {
    let mut bytes = serde_json::to_vec(manifest).expect("manifest serializes");
    bytes.extend_from_slice(component);
    digest(&bytes)
}

struct IdleWorker {
    provider: String,
    digest: String,
    used: std::time::Instant,
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::process::ChildStdout,
}
#[derive(Clone)]
pub struct Runtime {
    http_cache: http_cache::HttpCache,
    media_cache: http_cache::HttpCache,
    idle: Arc<tokio::sync::Mutex<Vec<IdleWorker>>>,
    authority: authority::Registry,
    worker: PathBuf,
    permits: Arc<Semaphore>,
    network: Network,
    cache_config: Option<PathBuf>,
    media: Arc<std::sync::RwLock<MediaVersions>>,
    browser: Arc<std::sync::RwLock<Option<(String, omd_browser::Browser)>>>,
}
#[derive(Default)]
struct MediaVersions {
    active: Option<String>,
    versions: std::collections::BTreeMap<String, omd_media::Media>,
}
impl Runtime {
    pub fn new(worker: PathBuf, network: Network, concurrency: usize) -> Self {
        Self {
            http_cache: http_cache::HttpCache::default(),
            media_cache: http_cache::HttpCache::default(),
            idle: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            authority: authority::Registry::default(),
            worker,
            network,
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            cache_config: None,
            media: Arc::new(std::sync::RwLock::new(MediaVersions::default())),
            browser: Arc::new(std::sync::RwLock::new(None)),
        }
    }
    pub fn media(&self) -> Option<omd_media::Media> {
        let versions = self.media.read().ok()?;
        versions.versions.get(versions.active.as_ref()?).cloned()
    }
    pub fn browser(&self) -> Option<omd_browser::Browser> {
        self.browser
            .read()
            .ok()?
            .as_ref()
            .map(|(_, browser)| browser.clone())
    }
    pub async fn register_browser(&self, id: &str, browser: omd_browser::Browser) {
        let previous = self.browser.write().expect("browser registry lock").take();
        if let Some((_, previous)) = previous {
            previous.stop().await;
        }
        *self.browser.write().expect("browser registry lock") = Some((id.into(), browser));
    }
    pub async fn revoke_browser(&self, id: &str) {
        let previous = {
            let mut active = self.browser.write().expect("browser registry lock");
            if active.as_ref().is_some_and(|(active, _)| active == id) {
                active.take()
            } else {
                None
            }
        };
        if let Some((_, browser)) = previous {
            browser.stop().await;
        }
    }
    pub fn with_media(self, media: omd_media::Media) -> Self {
        self.register_media("bundled", media, true);
        self
    }
    pub fn register_media(&self, id: &str, media: omd_media::Media, active: bool) {
        let mut versions = self.media.write().expect("media registry lock");
        versions.versions.entry(id.into()).or_insert(media);
        if active {
            versions.active = Some(id.into());
        }
    }
    pub fn revoke_media(&self, id: &str) {
        let mut versions = self.media.write().expect("media registry lock");
        if let Some(media) = versions.versions.remove(id) {
            media.revoked.cancel();
        }
        if versions.active.as_deref() == Some(id) {
            versions.active = None;
        }
    }
    pub fn activate_media(&self, id: &str) {
        let mut versions = self.media.write().expect("media registry lock");
        if versions.versions.contains_key(id) {
            versions.active = Some(id.into());
        }
    }
    pub fn media_for(&self, selection: &MediaSelection) -> Option<omd_media::Media> {
        self.media
            .read()
            .ok()?
            .versions
            .values()
            .find(|media| media.matches(selection))
            .cloned()
    }
    pub fn with_cache(mut self, path: PathBuf) -> Self {
        self.cache_config = Some(path);
        self
    }
    pub fn available_capacity(&self) -> usize {
        self.permits.available_permits()
    }
    /// Stop current/queued operations and deny future calls, including stale
    /// Provider clones. Installation must explicitly restore this authority.
    pub async fn revoke(&self, provider: &str) -> Result<()> {
        self.idle
            .lock()
            .await
            .retain(|worker| worker.provider != provider);
        self.authority.revoke(provider).await
    }
    pub fn restore(&self, provider: &str, digest: &str) {
        self.authority.restore(provider, digest);
    }
    /// Host adapters also carry the source's exact-byte authority and cancellation
    /// scope, so a media preparation cannot outlive removal of its source.
    pub async fn authorized<T>(
        &self,
        provider: &Provider,
        cancel: &CancellationToken,
        timeout: Duration,
        operation: impl std::future::Future<Output = T>,
    ) -> Result<T> {
        let timeout = self.network.bandwidth.operation_timeout(timeout).await;
        let guard = self
            .authority
            .enter(&provider.manifest.id, &provider.digest)?;
        tokio::select! {
            biased;
            _=guard.stop.cancelled()=>Err(authority::denied()),
            _=cancel.cancelled()=>Err(PluginError::Canceled),
            result=tokio::time::timeout(timeout,operation)=>result.map_err(|_|PluginError::Budget),
        }
    }
    /// Validate component imports and the typed execution interface before activation.
    /// Inspection runs in the same bounded worker, with no broker calls accepted.
    pub async fn inspect(&self, provider: &Provider, cancel: &CancellationToken) -> Result<()> {
        let _permit = tokio::select! {_ = cancel.cancelled()=>return Err(PluginError::Canceled), permit=self.permits.acquire()=>permit.map_err(|_|PluginError::Worker)?};
        provider.verify().await?;
        let mut child = Command::new(&self.worker)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| PluginError::Worker)?;
        let mut input = child.stdin.take().ok_or(PluginError::Worker)?;
        let mut output = child.stdout.take().ok_or(PluginError::Worker)?;
        let operation = async {
            write_frame(&mut input, &json!({"component":provider.component,"cache_config":self.cache_config,"payload":"{}","inspect":true})).await?;
            let result = read_frame(&mut output).await?;
            let imports = result
                .get("result")
                .and_then(|r| r.get("imports"))
                .and_then(Value::as_array)
                .ok_or(PluginError::Invalid)?;
            if imports
                .iter()
                .any(|i| i.as_str() != Some("omd:provider/broker@2.0.0"))
            {
                return Err(PluginError::Invalid);
            }
            Ok(())
        };
        let result = tokio::select! {_=cancel.cancelled()=>Err(PluginError::Canceled), result=tokio::time::timeout(INSTALLATION_TIMEOUT,operation)=>result.unwrap_or(Err(PluginError::InstallationBudget))};
        let _ = child.kill().await;
        let _ = child.wait().await;
        result
    }
    pub async fn invoke<T: serde::de::DeserializeOwned>(
        &self,
        provider: &Provider,
        request: &ProviderRequest,
        cancel: &CancellationToken,
    ) -> Result<T> {
        self.authorized(
            provider,
            cancel,
            Duration::from_secs(60),
            self.invoke_inner(provider, request, cancel),
        )
        .await?
    }
    async fn invoke_inner<T: serde::de::DeserializeOwned>(
        &self,
        provider: &Provider,
        request: &ProviderRequest,
        cancel: &CancellationToken,
    ) -> Result<T> {
        let started = std::time::Instant::now();
        if !provider.manifest.capabilities.contains(&request.operation) {
            return Err(PluginError::Unsupported);
        }
        if request
            .reference
            .as_ref()
            .is_some_and(|r| r.provider != provider.manifest.id)
            || request.page_size == 0
            || request.page_size > 200
        {
            return Err(PluginError::Invalid);
        }
        let session = self
            .network
            .session(
                &provider.manifest.id,
                request.credential_profile.as_deref(),
                &provider.manifest.grants,
            )
            .await
            .map_err(network_error)?;
        let queue_started = std::time::Instant::now();
        let _permit = tokio::select! {_ = cancel.cancelled()=>return Err(PluginError::Canceled), permit=self.permits.acquire()=>permit.map_err(|_|PluginError::Worker)?};
        let queue_ms = queue_started.elapsed().as_millis();
        let verification_started = std::time::Instant::now();
        provider.verify().await?;
        let verification_ms = verification_started.elapsed().as_millis();
        let worker = {
            let mut idle = self.idle.lock().await;
            idle.retain_mut(|w| {
                w.used.elapsed() < Duration::from_secs(60) && matches!(w.child.try_wait(), Ok(None))
            });
            idle.iter()
                .position(|w| w.provider == provider.manifest.id && w.digest == provider.digest)
                .map(|index| idle.swap_remove(index))
        };
        let (mut child, mut input, mut output) = if let Some(worker) = worker {
            (worker.child, worker.input, worker.output)
        } else {
            let mut child = Command::new(&self.worker)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| PluginError::Worker)?;
            let input = child.stdin.take().ok_or(PluginError::Worker)?;
            let output = child.stdout.take().ok_or(PluginError::Worker)?;
            (child, input, output)
        };
        let mut broker_ms = 0u128;
        let mut worker_timing = Value::Null;
        let operation = async {
            write_frame(&mut input,&json!({"component":provider.component,"cache_config":self.cache_config,"reuse":true,"payload":serde_json::to_string(request).map_err(|_|PluginError::Invalid)?})).await?;
            let mut calls = 0;
            let mut browser_session: Option<omd_browser::Session> = None;
            loop {
                let message = read_frame(&mut output).await?;
                if let Some(timing) = message.get("timing") {
                    worker_timing = timing.clone();
                }
                if let Some(broker) = message.get("broker") {
                    calls += 1;
                    if calls > 128 {
                        return Err(PluginError::Budget);
                    }
                    let operation = broker
                        .get("operation")
                        .and_then(Value::as_str)
                        .ok_or(PluginError::Invalid)?;
                    let payload = broker
                        .get("payload")
                        .and_then(Value::as_str)
                        .ok_or(PluginError::Invalid)?;
                    let broker_started = std::time::Instant::now();
                    let response = if operation.starts_with("browser.") {
                        if !provider.manifest.browser {
                            Err(PluginError::Unsupported)
                        } else {
                            match operation {
                                "browser.open" => {
                                    #[derive(serde::Deserialize)]
                                    #[serde(deny_unknown_fields)]
                                    struct Open {
                                        url: String,
                                    }
                                    let input: Open = serde_json::from_str(payload)
                                        .map_err(|_| PluginError::Invalid)?;
                                    if browser_session.is_some() {
                                        Err(PluginError::Invalid)
                                    } else {
                                        let browser=self.browser().ok_or_else(||PluginError::Source(Problem {code:"browser_unavailable".into(),message:"Install and activate the approved browser tools to use this source.".into(),retryable:false,actions:vec!["restore_tool".into()]}))?;
                                        match browser
                                            .start(
                                                &input.url,
                                                provider.manifest.grants.clone(),
                                                session.clone(),
                                                omd_browser::Mode::Source,
                                                cancel,
                                            )
                                            .await
                                        {
                                            Ok(value) => {
                                                browser_session = Some(value);
                                                Ok(json!({"ready":true}))
                                            }
                                            Err(error) => Err(PluginError::Source(error)),
                                        }
                                    }
                                }
                                "browser.action" => {
                                    let action: omd_browser::Action = serde_json::from_str(payload)
                                        .map_err(|_| PluginError::Invalid)?;
                                    match browser_session.as_ref() {
                                        Some(browser) => browser
                                            .action(action, cancel)
                                            .await
                                            .map_err(PluginError::Source),
                                        None => Err(PluginError::Invalid),
                                    }
                                }
                                "browser.close" => {
                                    if let Some(browser) = browser_session.take() {
                                        browser.cancel();
                                        browser.closed().await;
                                    }
                                    Ok(json!({"closed":true}))
                                }
                                _ => Err(PluginError::Unsupported),
                            }
                        }
                    } else {
                        self.broker(
                            provider,
                            operation,
                            payload,
                            session.as_ref(),
                            request,
                            cancel,
                        )
                        .await
                    };
                    broker_ms += broker_started.elapsed().as_millis();
                    if let Err(PluginError::Credential(error)) = response {
                        return Err(PluginError::Credential(error));
                    }
                    write_frame(
                        &mut input,
                        &match response {
                            Ok(value) => json!({"result":value.to_string()}),
                            Err(PluginError::Source(problem)) => json!({"error":serde_json::to_string(&problem).map_err(|_|PluginError::Invalid)?}),
                            Err(error) => json!({"error":error.to_string()}),
                        },
                    )
                    .await?;
                } else if let Some(result) = message.get("result") {
                    if result.get("ok") == Some(&Value::Bool(true)) {
                        let mut value =
                            result.get("result").cloned().ok_or(PluginError::Invalid)?;
                        bind_credentials(provider, request, &mut value)?;
                        validate_result(provider, request, &value)?;
                        return serde_json::from_value(value).map_err(|_| PluginError::Invalid);
                    }
                    let mut problem: Problem = serde_json::from_value(
                        result.get("error").cloned().ok_or(PluginError::Invalid)?,
                    )
                    .map_err(|_| PluginError::Invalid)?;
                    // Source-authored errors never contain host diagnostics or secrets.
                    problem.message = problem.message.chars().take(1000).collect();
                    problem.actions.retain(|a| {
                        [
                            "retry",
                            "reauthenticate",
                            "update_source",
                            "prepare_again",
                            "restore_tool",
                            "repair_confinement",
                            "update_tool",
                            "refresh",
                            "review_permissions",
                        ]
                        .contains(&a.as_str())
                    });
                    return Err(PluginError::Source(problem));
                } else if let Some(error) = message.get("error").and_then(Value::as_str) {
                    tracing::debug!(diagnostic=%error.chars().take(2000).collect::<String>(),"plugin worker failed");
                    return Err(
                        if error.contains("fuel")
                            || error.contains("interrupt")
                            || error.contains("limit")
                        {
                            PluginError::Budget
                        } else {
                            PluginError::Worker
                        },
                    );
                } else {
                    return Err(PluginError::Invalid);
                }
            }
        };
        let timeout = self
            .network
            .bandwidth
            .operation_timeout(Duration::from_secs(60))
            .await;
        let result = tokio::select! {_ = cancel.cancelled()=>Err(PluginError::Canceled),value=tokio::time::timeout(timeout,operation)=>value.unwrap_or(Err(PluginError::Budget))};
        let total_ms = started.elapsed().as_millis();
        tracing::debug!(source=%provider.manifest.id, operation=%request.operation, total_ms, queue_ms, verification_ms, broker_ms, worker=?worker_timing, success=result.is_ok(), "Source operation timing");
        if total_ms.saturating_sub(broker_ms) > 500 {
            tracing::warn!(source=%provider.manifest.id, operation=%request.operation, total_ms, queue_ms, verification_ms, broker_ms, worker=?worker_timing, "Slow source runtime overhead");
        }
        // Only a successfully validated invocation returns to the bounded pool.
        // The worker creates a new Store/instance for every invocation: no guest
        // globals, memories, fuel budget, or broker state cross the boundary.
        if result.is_ok() && !cancel.is_cancelled() && child.try_wait().ok().flatten().is_none() {
            let mut idle = self.idle.lock().await;
            if idle.len() >= 2 {
                let oldest = idle
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, worker)| worker.used)
                    .map(|(index, _)| index)
                    .unwrap();
                idle.swap_remove(oldest);
            }
            {
                idle.push(IdleWorker {
                    provider: provider.manifest.id.clone(),
                    digest: provider.digest.clone(),
                    used: std::time::Instant::now(),
                    child,
                    input,
                    output,
                });
                return result;
            }
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
        result
    }
    async fn broker(
        &self,
        provider: &Provider,
        operation: &str,
        payload: &str,
        session: Option<&omd_credentials::Session>,
        request: &ProviderRequest,
        cancel: &CancellationToken,
    ) -> Result<Value> {
        let credential_profile = request.credential_profile.as_deref();
        let metadata = request.operation != "resolve";
        match operation {
            "media.inspect" => {
                if !provider.manifest.media_tools {
                    return Err(PluginError::Unsupported);
                }
                let media = self.media().ok_or_else(|| {
                    PluginError::Source(Problem {
                        code: "media_tools_unavailable".into(),
                        message: "Install the approved managed media tools to use this source."
                            .into(),
                        retryable: false,
                        actions: vec!["restore_tool".into()],
                    })
                })?;
                let request = serde_json::from_str(payload).map_err(|_| PluginError::Invalid)?;
                let fetch = || async {
                    media
                        .inspect(
                            &request,
                            &provider.manifest.id,
                            &provider.manifest.grants,
                            credential_profile,
                            cancel,
                        )
                        .await
                        .map_err(PluginError::Source)
                };
                // Public projected metadata only. Acquisitions and signed-in reads
                // always revalidate access; a tool or provider update changes the key.
                if metadata && session.is_none() && credential_profile.is_none() {
                    let key = json!([provider.digest, media.tools, payload]).to_string();
                    tokio::select! { biased;
                        _ = media.revoked.cancelled() => Err(PluginError::Canceled),
                        result = self.media_cache.read_metadata(key, cancel, fetch) => result,
                    }
                } else {
                    fetch().await
                }
            }
            "http" => {
                let request: Request =
                    serde_json::from_str(payload).map_err(|_| PluginError::Invalid)?;
                let fetch = || async {
                    let response = self
                        .network
                        .text_authenticated(&request, &provider.manifest.grants, session, cancel)
                        .await
                        .map_err(network_error)?;
                    serde_json::to_value(response).map_err(|_| PluginError::Invalid)
                };
                if metadata
                    && session.is_none()
                    && credential_profile.is_none()
                    && request.method == "GET"
                    && request.body.is_empty()
                {
                    let key = json!([provider.digest, payload]).to_string();
                    self.http_cache.read(key, cancel, fetch).await
                } else {
                    fetch().await
                }
            }
            "log" => {
                // Arbitrary source fields can contain scraped personal data. Persist
                // only operation counts until the source explicitly supplies safe fields.
                tracing::debug!(provider=%provider.manifest.id,"source log event");
                Ok(Value::Null)
            }
            _ => Err(PluginError::Unsupported),
        }
    }
}
async fn write_frame(out: &mut (impl AsyncWrite + Unpin), value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| PluginError::Invalid)?;
    if bytes.len() > FRAME_LIMIT {
        return Err(PluginError::Budget);
    }
    out.write_u32_le(bytes.len() as u32)
        .await
        .map_err(|_| PluginError::Worker)?;
    out.write_all(&bytes)
        .await
        .map_err(|_| PluginError::Worker)?;
    out.flush().await.map_err(|_| PluginError::Worker)
}
async fn read_frame(input: &mut (impl AsyncRead + Unpin)) -> Result<Value> {
    let size = input.read_u32_le().await.map_err(|_| PluginError::Worker)? as usize;
    if size > FRAME_LIMIT {
        return Err(PluginError::Budget);
    }
    let mut bytes = vec![0; size];
    input
        .read_exact(&mut bytes)
        .await
        .map_err(|_| PluginError::Worker)?;
    serde_json::from_slice(&bytes).map_err(|_| PluginError::Invalid)
}

fn validate_result(provider: &Provider, request: &ProviderRequest, value: &Value) -> Result<()> {
    omd_domain::validate_provider_result(&provider.manifest, request, value)
        .map_err(|_| PluginError::Invalid)
}

fn network_error(error: omd_network::NetworkError) -> PluginError {
    match error {
        omd_network::NetworkError::Credential(error) => PluginError::Credential(error),
        other => PluginError::Source(Problem {
            code: "source_network".into(),
            message: other.to_string(),
            retryable: true,
            actions: vec!["retry".into()],
        }),
    }
}
/// Account selection belongs to the engine invocation, never to provider output.
fn bind_credentials(
    provider: &Provider,
    request: &ProviderRequest,
    value: &mut Value,
) -> Result<()> {
    if request.operation != "resolve" {
        return Ok(());
    }
    let mut resolved: ResolvedRelease =
        serde_json::from_value(value.clone()).map_err(|_| PluginError::Invalid)?;
    for resource in &mut resolved.resources {
        let (permission, profile) = match &mut resource.locator {
            Locator::Http {
                permission,
                credential_profile,
                ..
            }
            | Locator::Media {
                permission,
                credential_profile,
                ..
            } => (permission, credential_profile),
        };
        let grant = provider
            .manifest
            .grants
            .iter()
            .find(|g| g.id == *permission)
            .ok_or(PluginError::Invalid)?;
        if profile
            .as_ref()
            .is_some_and(|profile| Some(profile) != request.credential_profile.as_ref())
            || (profile.is_some() && !grant.credential)
        {
            return Err(PluginError::Credential(omd_credentials::Error::Denied));
        }
        *profile = if grant.credential {
            request.credential_profile.clone()
        } else {
            None
        };
    }
    *value = serde_json::to_value(resolved).map_err(|_| PluginError::Invalid)?;
    Ok(())
}
