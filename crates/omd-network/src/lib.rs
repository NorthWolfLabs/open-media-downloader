//! The only HTTP client available to providers. Resolve, validate, and pin every hop.
use omd_domain::HostGrant;
use reqwest::{
    Method, Response,
    header::{HeaderMap, HeaderName, HeaderValue, LOCATION},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Credential(#[from] omd_credentials::Error),
    #[error("The source requested a URL, method, address, or header outside its permission")]
    Denied,
    #[error("The source response exceeded its size limit")]
    ResponseLimit,
    #[error("The source returned too many redirects")]
    RedirectLimit,
    #[error("The source request was canceled")]
    Canceled,
    #[error("The source request timed out or could not connect")]
    Transport,
    #[error("The source returned invalid text")]
    InvalidText,
}
pub type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub url: String,
    pub permission: String,
    #[serde(default = "get")]
    pub method: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}
fn get() -> String {
    "GET".into()
}
#[derive(Serialize)]
pub struct TextResponse {
    pub status: u16,
    pub body: String,
}

/// One cancellation-safe token budget for direct transfers, artwork and native
/// adapter responses. Sleeping callers never reserve future bandwidth.
#[derive(Clone)]
pub struct Bandwidth {
    state: Arc<Mutex<BandwidthState>>,
}
struct BandwidthState {
    rate: u64,
    available: f64,
    updated: Instant,
}
impl Bandwidth {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(BandwidthState {
                rate: bytes_per_second,
                available: 0.0,
                updated: Instant::now(),
            })),
        }
    }
    pub async fn set_limit(&self, bytes_per_second: u64) {
        *self.state.lock().await = BandwidthState {
            rate: bytes_per_second,
            available: 0.0,
            updated: Instant::now(),
        };
    }
    /// Allow bounded control responses to finish under a user-selected bandwidth
    /// limit. Execution fuel/memory and network idle deadlines remain separate.
    pub async fn operation_timeout(&self, base: Duration) -> Duration {
        let rate = self.state.lock().await.rate;
        if rate == 0 {
            return base;
        }
        base.saturating_add(Duration::from_secs((32u64 * 1024 * 1024).div_ceil(rate)))
            .min(Duration::from_secs(15 * 60))
            .max(base)
    }
    pub async fn consume(&self, bytes: usize, cancel: &CancellationToken) -> Result<()> {
        let mut remaining = bytes;
        while remaining > 0 {
            let wait = {
                let mut state = tokio::select! {_=cancel.cancelled()=>return Err(NetworkError::Canceled),state=self.state.lock()=>state};
                if state.rate == 0 {
                    return Ok(());
                }
                let burst = state.rate.clamp(1, 16 * 1024) as f64;
                let now = Instant::now();
                state.available = (state.available
                    + now.duration_since(state.updated).as_secs_f64() * state.rate as f64)
                    .min(burst);
                state.updated = now;
                let needed = (remaining as f64).min(burst);
                if state.available >= needed {
                    state.available -= needed;
                    remaining -= needed as usize;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        (needed - state.available) / state.rate as f64,
                    ))
                }
            };
            if let Some(wait) = wait {
                tokio::select! {_=cancel.cancelled()=>return Err(NetworkError::Canceled),_=tokio::time::sleep(wait)=>{}}
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Network {
    clients: Arc<Mutex<BTreeMap<String, (Instant, reqwest::Client)>>>,
    pub bandwidth: Bandwidth,
    pacing: Arc<Mutex<BTreeMap<String, Instant>>>,
    pub artwork_slots: Arc<tokio::sync::Semaphore>,
    pub vault: Option<omd_credentials::Vault>,
    #[cfg(feature = "fixture-tests")]
    fixture: Option<Arc<NativeFixture>>,
    #[cfg(feature = "fixture-tests")]
    transfer_fixture: Option<Arc<TransferFixture>>,
}
/// A deterministic response transport for native-adapter acceptance tests.
/// This constructor and field do not exist in production builds.
#[cfg(feature = "fixture-tests")]
type NativeFixture =
    dyn Fn(&Url, &Method, &HeaderMap, &str) -> Result<http::Response<Vec<u8>>> + Send + Sync;
#[cfg(feature = "fixture-tests")]
type TransferFixture =
    dyn Fn(&Url, &Method, &HeaderMap) -> Result<http::Response<reqwest::Body>> + Send + Sync;
enum RequestMode {
    Source,
    Native { sign_in: bool },
    Artwork,
}

impl Network {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            clients: Arc::new(Mutex::new(BTreeMap::new())),
            bandwidth: Bandwidth::new(bytes_per_second),
            vault: None,
            #[cfg(feature = "fixture-tests")]
            fixture: None,
            #[cfg(feature = "fixture-tests")]
            transfer_fixture: None,
            pacing: Arc::new(Mutex::new(BTreeMap::new())),
            artwork_slots: Arc::new(tokio::sync::Semaphore::new(6)),
        }
    }
    #[cfg(feature = "fixture-tests")]
    pub fn with_native_fixture(
        mut self,
        fixture: impl Fn(&Url, &Method, &HeaderMap, &str) -> Result<http::Response<Vec<u8>>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.fixture = Some(Arc::new(fixture));
        self
    }
    #[cfg(feature = "fixture-tests")]
    pub fn with_transfer_fixture(
        mut self,
        fixture: impl Fn(&Url, &Method, &HeaderMap) -> Result<http::Response<reqwest::Body>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.transfer_fixture = Some(Arc::new(fixture));
        self
    }
    pub fn with_vault(mut self, vault: omd_credentials::Vault) -> Self {
        self.vault = Some(vault);
        self
    }
    pub async fn session(
        &self,
        provider: &str,
        profile: Option<&str>,
        grants: &[HostGrant],
    ) -> Result<Option<omd_credentials::Session>> {
        match profile {
            None => Ok(None),
            Some(profile) => {
                if profile.is_empty() || profile.len() > 128 {
                    return Err(omd_credentials::Error::Invalid.into());
                }
                let vault = self
                    .vault
                    .as_ref()
                    .ok_or(omd_credentials::Error::Unavailable)?;
                Ok(Some(vault.load(provider, profile, grants).await?))
            }
        }
    }
    pub async fn open(
        &self,
        request: &Request,
        grants: &[HostGrant],
        cancel: &CancellationToken,
    ) -> Result<Response> {
        self.open_authenticated(request, grants, None, cancel).await
    }
    pub async fn open_authenticated(
        &self,
        request: &Request,
        grants: &[HostGrant],
        session: Option<&omd_credentials::Session>,
        cancel: &CancellationToken,
    ) -> Result<Response> {
        self.open_mode(request, grants, session, cancel, RequestMode::Source)
            .await
    }
    /// Trusted native adapter requests still use the same URL, DNS, method and
    /// credential checks. Redirects are returned for the adapter to follow through
    /// this broker again; they never create an unvalidated connection.
    pub async fn open_native(
        &self,
        request: &Request,
        grants: &[HostGrant],
        session: Option<&omd_credentials::Session>,
        cancel: &CancellationToken,
        sign_in: bool,
    ) -> Result<Response> {
        self.open_mode(
            request,
            grants,
            session,
            cancel,
            RequestMode::Native { sign_in },
        )
        .await
    }
    /// Presentation-only lane. The service holds a bounded transfer permit and
    /// validates the response as an image. All URL/DNS/redirect checks still apply.
    pub async fn open_artwork(
        &self,
        request: &Request,
        grants: &[HostGrant],
        session: Option<&omd_credentials::Session>,
        cancel: &CancellationToken,
    ) -> Result<Response> {
        self.open_mode(request, grants, session, cancel, RequestMode::Artwork)
            .await
    }
    async fn pace(&self, host: &str, artwork: bool, cancel: &CancellationToken) -> Result<()> {
        let lane = format!("{}:{host}", if artwork { "artwork" } else { "source" });
        self.pace_interval(
            &lane,
            Duration::from_millis(if artwork { 0 } else { 250 }),
            cancel,
        )
        .await
    }
    async fn pace_interval(
        &self,
        lane: &str,
        interval: Duration,
        cancel: &CancellationToken,
    ) -> Result<()> {
        loop {
            if cancel.is_cancelled() {
                return Err(NetworkError::Canceled);
            }
            let wait = {
                let mut pacing = self.pacing.lock().await;
                let now = Instant::now();
                pacing.retain(|_, deadline| *deadline > now);
                if let Some(deadline) = pacing.get(lane) {
                    Some(*deadline)
                } else {
                    pacing.insert(lane.to_owned(), now + interval);
                    None
                }
            };
            let Some(deadline) = wait else {
                return Ok(());
            };
            tokio::select! {_=cancel.cancelled()=>return Err(NetworkError::Canceled),_=tokio::time::sleep_until(deadline)=>{}}
        }
    }
    async fn open_mode(
        &self,
        request: &Request,
        grants: &[HostGrant],
        session: Option<&omd_credentials::Session>,
        cancel: &CancellationToken,
        mode: RequestMode,
    ) -> Result<Response> {
        let (native, sign_in, artwork) = match mode {
            RequestMode::Source => (false, false, false),
            RequestMode::Native { sign_in } => (true, sign_in, false),
            RequestMode::Artwork => (false, false, true),
        };
        let grant = grants
            .iter()
            .find(|g| g.id == request.permission)
            .ok_or(NetworkError::Denied)?;
        let method =
            Method::from_bytes(request.method.as_bytes()).map_err(|_| NetworkError::Denied)?;
        if !grant.methods.iter().any(|m| m == method.as_str()) || request.body.len() > 1024 * 1024 {
            return Err(NetworkError::Denied);
        }
        let headers = if native {
            native_headers(&request.headers, sign_in && grant.credential)?
        } else {
            safe_headers(&request.headers)?
        };
        let mut url = Url::parse(&request.url).map_err(|_| NetworkError::Denied)?;
        for hop in 0..=5 {
            validate_url(&url, grant)?;
            let mut hop_headers = headers.clone();
            if grant.credential
                && let Some(session) = session
            {
                hop_headers.extend(session.headers_for(
                    &url,
                    grant,
                    chrono::Utc::now().timestamp(),
                )?);
            }
            #[cfg(feature = "fixture-tests")]
            if let Some(fixture) = &self.fixture {
                if !native {
                    return Err(NetworkError::Denied);
                }
                return Ok(reqwest::Response::from(fixture(
                    &url,
                    &method,
                    &hop_headers,
                    &request.body,
                )?));
            }
            #[cfg(feature = "fixture-tests")]
            if let Some(fixture) = &self.transfer_fixture {
                return Ok(reqwest::Response::from(fixture(
                    &url,
                    &method,
                    &hop_headers,
                )?));
            }
            let host = url.host_str().ok_or(NetworkError::Denied)?.to_owned();
            for (prefix, interval) in &grant.request_intervals {
                if url.path().starts_with(prefix) {
                    self.pace_interval(
                        &format!("endpoint:{host}:{prefix}"),
                        Duration::from_millis((*interval).clamp(250, 60_000)),
                        cancel,
                    )
                    .await?;
                }
            }
            self.pace(&host, artwork, cancel).await?;
            let addresses: Vec<SocketAddr> = tokio::select! {
                _ = cancel.cancelled() => return Err(NetworkError::Canceled),
                result = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((host.as_str(), 443))) => result.map_err(|_| NetworkError::Transport)?.map_err(|_| NetworkError::Transport)?.collect()
            };
            if addresses.is_empty() || addresses.iter().any(|a| !public_address(a.ip())) {
                return Err(NetworkError::Denied);
            }
            // Disable proxy environment variables and automatic redirects. The validated
            // DNS answer is the answer used to connect, including for HTTPS/SNI.
            // Re-resolve and validate on every hop. Pool only connections pinned to
            // this exact validated address set, never a hostname-only DNS cache.
            let mut pinned = addresses.clone();
            pinned.sort();
            pinned.dedup();
            let key = format!("{host}:{pinned:?}");
            let mut clients = self.clients.lock().await;
            clients.retain(|_, (used, _)| used.elapsed() < Duration::from_secs(90));
            let client = if let Some((used, client)) = clients.get_mut(&key) {
                *used = Instant::now();
                client.clone()
            } else {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .resolve_to_addrs(&host, &pinned)
                    .pool_idle_timeout(Duration::from_secs(60))
                    .pool_max_idle_per_host(6)
                    .connect_timeout(Duration::from_secs(15))
                    .read_timeout(Duration::from_secs(30))
                    .user_agent("OMD/0.2 (+source-acquisition)")
                    .build()
                    .map_err(|_| NetworkError::Transport)?;
                if clients.len() >= 64
                    && let Some(oldest) = clients
                        .iter()
                        .min_by_key(|(_, (used, _))| *used)
                        .map(|(key, _)| key.clone())
                {
                    clients.remove(&oldest);
                }
                clients.insert(key, (Instant::now(), client.clone()));
                client
            };
            drop(clients);
            let response = tokio::select! {
                _ = cancel.cancelled() => return Err(NetworkError::Canceled),
                response = client.request(method.clone(), url.clone()).headers(hop_headers).body(request.body.clone()).send() => response.map_err(|_| NetworkError::Transport)?
            };
            if native || !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if hop == 5 {
                return Err(NetworkError::RedirectLimit);
            }
            // Do not replay a non-idempotent request through a redirect.
            if method != Method::GET && method != Method::HEAD {
                return Err(NetworkError::Denied);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or(NetworkError::Denied)?;
            url = url.join(location).map_err(|_| NetworkError::Denied)?;
        }
        Err(NetworkError::RedirectLimit)
    }
    pub async fn text(
        &self,
        request: &Request,
        grants: &[HostGrant],
        cancel: &CancellationToken,
    ) -> Result<TextResponse> {
        self.text_authenticated(request, grants, None, cancel).await
    }
    pub async fn text_authenticated(
        &self,
        request: &Request,
        grants: &[HostGrant],
        session: Option<&omd_credentials::Session>,
        cancel: &CancellationToken,
    ) -> Result<TextResponse> {
        let mut response = self
            .open_authenticated(request, grants, session, cancel)
            .await?;
        let status = response.status().as_u16();
        if session.is_some() && matches!(status, 401 | 403) {
            return Err(omd_credentials::Error::Expired.into());
        }
        let limit = 8 * 1024 * 1024;
        if response.content_length().is_some_and(|n| n > limit as u64) {
            return Err(NetworkError::ResponseLimit);
        }
        let mut bytes = Vec::new();
        loop {
            let chunk = tokio::select! { _ = cancel.cancelled() => return Err(NetworkError::Canceled), result = response.chunk() => result.map_err(|_| NetworkError::Transport)? };
            let Some(chunk) = chunk else { break };
            if bytes.len() + chunk.len() > limit {
                return Err(NetworkError::ResponseLimit);
            }
            self.bandwidth.consume(chunk.len(), cancel).await?;
            bytes.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(bytes).map_err(|_| NetworkError::InvalidText)?;
        Ok(TextResponse {
            status,
            body: session.map_or_else(|| text.clone(), |s| s.redact(&text)),
        })
    }
}

pub fn validate_url(url: &Url, grant: &HostGrant) -> Result<()> {
    omd_domain::validate_broker_url(url, grant).map_err(|_| NetworkError::Denied)
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    omd_domain::host_matches(pattern, host)
}
fn safe_headers(values: &BTreeMap<String, String>) -> Result<HeaderMap> {
    if values.len() > 32 {
        return Err(NetworkError::Denied);
    }
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| NetworkError::Denied)?;
        // Credentials are engine-owned and injected separately. Never accept them
        // from a plugin or forward arbitrary authority/connection headers.
        if !matches!(
            name.as_str(),
            "accept"
                | "accept-language"
                | "content-type"
                | "range"
                | "if-range"
                | "if-none-match"
                | "if-modified-since"
                | "referer"
        ) || value.len() > 8192
        {
            return Err(NetworkError::Denied);
        }
        if name == "referer" {
            let url = Url::parse(value).map_err(|_| NetworkError::Denied)?;
            if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
                return Err(NetworkError::Denied);
            }
        }
        headers.insert(
            name,
            HeaderValue::from_str(value).map_err(|_| NetworkError::Denied)?,
        );
    }
    Ok(headers)
}

/// Whether a resolved address may be connected to. IPv4 follows the IANA IPv4
/// Special-Purpose Address Registry: every block it marks not globally
/// reachable is denied, plus multicast, reserved and limited broadcast.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                // Only 192.0.0.0/24 (IETF protocol assignments, denied whole,
                // including its anycast entries) and 192.0.2.0/24 (TEST-NET-1)
                // are reserved in 192.0.0.0/16. The rest is ordinary unicast.
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && (b == 168 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Only global unicast, excluding documentation, transition mechanisms,
            // and protocol assignments. IPv4-mapped/NAT64/6to4 never pass.
            s[0] & 0xe000 == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

fn native_headers(values: &BTreeMap<String, String>, sign_in: bool) -> Result<HeaderMap> {
    if values.len() > 128 {
        return Err(NetworkError::Denied);
    }
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| NetworkError::Denied)?;
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "proxy-authorization"
                | "proxy-connection"
                | "transfer-encoding"
                | "content-length"
                | "upgrade"
                | "te"
                | "trailer"
                | "keep-alive"
                | "accept-encoding"
        ) {
            continue;
        }
        if matches!(
            name.as_str(),
            "authorization" | "cookie" | "x-api-key" | "x-auth-token"
        ) && !sign_in
        {
            continue;
        }
        if value.len() > 16384 {
            return Err(NetworkError::Denied);
        }
        let mut value = HeaderValue::from_str(value).map_err(|_| NetworkError::Denied)?;
        if matches!(
            name.as_str(),
            "authorization" | "cookie" | "x-api-key" | "x-auth-token"
        ) {
            value.set_sensitive(true);
        }
        headers.insert(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    #[tokio::test(start_paused = true)]
    async fn artwork_pacing_does_not_queue_behind_metadata_and_cancellation_leaves_capacity() {
        use super::*;
        let network = Network::new(0);
        let cancel = CancellationToken::new();
        network.pace("example.com", false, &cancel).await.unwrap();
        let start = Instant::now();
        for _ in 0..6 {
            network.pace("example.com", true, &cancel).await.unwrap();
        }
        assert_eq!(start.elapsed(), Duration::from_millis(0));
        let aborted = CancellationToken::new();
        aborted.cancel();
        assert!(matches!(
            network.pace("example.com", true, &aborted).await,
            Err(NetworkError::Canceled)
        ));
        network.pace("example.com", true, &cancel).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(0));
        network.pace("example.com", false, &cancel).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(250));
        assert_eq!(network.artwork_slots.available_permits(), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn stricter_endpoint_limits_do_not_block_ordinary_browsing() {
        use super::*;
        let network = Network::new(0);
        let cancel = CancellationToken::new();
        network
            .pace_interval(
                "endpoint:example.org:/chapter-server/",
                Duration::from_millis(1600),
                &cancel,
            )
            .await
            .unwrap();
        network.pace("example.org", false, &cancel).await.unwrap();
        let start = Instant::now();
        network.pace("example.org", false, &cancel).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(250));
        network
            .pace_interval(
                "endpoint:example.org:/chapter-server/",
                Duration::from_millis(1600),
                &cancel,
            )
            .await
            .unwrap();
        assert_eq!(start.elapsed(), Duration::from_millis(1600));
    }

    #[tokio::test]
    async fn control_response_budgets_respect_throttling_and_stay_bounded() {
        let budget = super::Bandwidth::new(0);
        let base = std::time::Duration::from_secs(60);
        assert_eq!(budget.operation_timeout(base).await, base);
        budget.set_limit(1024 * 1024).await;
        assert_eq!(budget.operation_timeout(base).await.as_secs(), 92);
        budget.set_limit(1).await;
        assert_eq!(budget.operation_timeout(base).await.as_secs(), 900);
        budget.set_limit(u64::MAX).await;
        assert_eq!(budget.operation_timeout(base).await.as_secs(), 61);
    }
    #[tokio::test(start_paused = true)]
    async fn global_bandwidth_is_shared_and_canceled_waits_leave_no_future_debt() {
        let budget = super::Bandwidth::new(1024);
        let cancel = tokio_util::sync::CancellationToken::new();
        let started = tokio::time::Instant::now();
        let (a, b) = tokio::join!(budget.consume(4096, &cancel), budget.consume(4096, &cancel));
        a.unwrap();
        b.unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_secs(8));
        budget.set_limit(1).await;
        let interrupted = tokio_util::sync::CancellationToken::new();
        let task = {
            let budget = budget.clone();
            let token = interrupted.clone();
            tokio::spawn(async move { budget.consume(16384, &token).await })
        };
        tokio::task::yield_now().await;
        interrupted.cancel();
        assert!(task.await.unwrap().is_err());
        let started = tokio::time::Instant::now();
        budget.consume(1, &cancel).await.unwrap();
        assert!(started.elapsed() <= std::time::Duration::from_secs(1));
    }

    use super::*;
    #[test]
    fn private_and_transition_addresses_are_denied() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.1.1",
            "169.254.169.254",
            "192.168.1.1",
            "198.18.0.1",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
            "2001:db8::1",
            "fc00::1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn only_protocol_and_documentation_blocks_are_denied_in_192_0_0_0_16() {
        // Exhaustive: 192.0.0.0/24 and 192.0.2.0/24 are reserved; the other
        // 254 /24s are ordinary unicast that hosting providers use for
        // public websites.
        for c in 0..=255u8 {
            for d in 0..=255u8 {
                let ip = IpAddr::from([192, 0, c, d]);
                assert_eq!(public_address(ip), c != 0 && c != 2, "{ip}");
            }
        }
    }
    #[test]
    fn ipv4_special_purpose_registry_boundaries() {
        // First and last address of every IANA IPv4 special-purpose block that
        // is not globally reachable, plus multicast, reserved and broadcast.
        let denied = [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.0",
            "127.255.255.255",
            "169.254.0.0",
            "169.254.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.0",
            "192.0.0.7",
            "192.0.0.8",
            // PCP and TURN anycast are marked globally reachable, but they are
            // relay infrastructure, not sources; the protocol block stays closed.
            "192.0.0.9",
            "192.0.0.10",
            "192.0.0.170",
            "192.0.0.171",
            "192.0.0.255",
            "192.0.2.0",
            "192.0.2.255",
            "192.88.99.0",
            "192.88.99.2",
            "192.88.99.255",
            "192.168.0.0",
            "192.168.255.255",
            "198.18.0.0",
            "198.19.255.255",
            "198.51.100.0",
            "198.51.100.255",
            "203.0.113.0",
            "203.0.113.255",
            "224.0.0.0",
            "239.255.255.255",
            "240.0.0.0",
            "255.255.255.254",
            "255.255.255.255",
        ];
        for ip in denied {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        // The addresses just outside each block, and the blocks IANA marks
        // globally reachable (AS112-v4, AMT, AS112 direct delegation).
        let public = [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "191.255.255.255",
            "192.0.1.0",
            "192.0.1.255",
            "192.0.3.0",
            "192.0.64.0",
            "192.0.66.108",
            "192.0.255.255",
            "192.1.0.0",
            "192.31.196.1",
            "192.52.193.1",
            "192.88.98.255",
            "192.88.100.0",
            "192.167.255.255",
            "192.169.0.0",
            "192.175.48.1",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "223.255.255.255",
        ];
        for ip in public {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn public_ipv4_in_192_0_0_0_16_stays_denied_inside_ipv6_transition_forms() {
        // Allowing 192.0.66.108 must not open IPv6 wrappers around it.
        for ip in [
            "::ffff:192.0.66.108",
            "::192.0.66.108",
            "64:ff9b::192.0.66.108",
            "64:ff9b:1::c000:426c",
            "2002:c000:426c::1",
            "2001:0:4136:e378:8000:63bf:3fff:bd93",
            "::ffff:192.0.0.9",
            "::ffff:192.0.2.1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn grants_match_exact_https_authorities() {
        let grant = HostGrant {
            request_intervals: Default::default(),
            id: "read".into(),
            hosts: vec!["example.com".into()],
            methods: vec!["GET".into()],
            credential: false,
        };
        assert!(validate_url(&Url::parse("https://example.com/a").unwrap(), &grant).is_ok());
        for url in [
            "http://example.com/a",
            "https://example.com:444/a",
            "https://evil.example.com/a",
            "https://example.com.evil.test/a",
            "https://u:p@example.com/a",
            "https://127.0.0.1/a",
        ] {
            assert!(
                validate_url(&Url::parse(url).unwrap(), &grant).is_err(),
                "{url}"
            );
        }
    }
    #[tokio::test]
    async fn a_canceled_bandwidth_wait_releases_its_lock() {
        let budget = Bandwidth::new(1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(budget.consume(1024, &cancel).await.is_err());
        tokio::time::timeout(Duration::from_millis(100), budget.set_limit(0))
            .await
            .unwrap();
        budget
            .consume(1024, &CancellationToken::new())
            .await
            .unwrap();
    }
}
