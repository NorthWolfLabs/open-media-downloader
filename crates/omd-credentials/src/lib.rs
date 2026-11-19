//! Engine-owned credentials. Providers receive neither vault access nor secrets.
use omd_domain::{HostGrant, digest};
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Sign in to this source again")]
    Missing,
    #[error("The source session expired; sign in again")]
    Expired,
    #[error("Unlock the operating system credential store and retry")]
    Locked,
    #[error("The operating system credential store is unavailable")]
    Unavailable,
    #[error("The session data is invalid")]
    Invalid,
    #[error("The credential is not authorized for this destination")]
    Denied,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn problem(&self) -> omd_domain::Problem {
        let (code, action) = match self {
            Self::Missing | Self::Expired => ("authentication_required", "reauthenticate"),
            Self::Locked => ("credentials_locked", "unlock_credentials"),
            Self::Unavailable => ("credentials_unavailable", "retry"),
            Self::Invalid => ("credentials_invalid", "reauthenticate"),
            Self::Denied => ("credentials_denied", "review_permissions"),
        };
        omd_domain::Problem {
            code: code.into(),
            message: self.to_string(),
            retryable: matches!(self, Self::Locked | Self::Unavailable),
            actions: vec![action.into()],
        }
    }
}

/// Browser SameSite policy. An absent value keeps the earlier engine default (Lax).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    Strict,
    Lax,
    None,
}
fn enabled() -> bool {
    true
}
fn is_enabled(value: &bool) -> bool {
    *value
}
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub host_only: bool,
    pub expires_at: Option<i64>,
    /// Absent attributes keep the earlier engine defaults: Secure and HttpOnly.
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub secure: bool,
    #[serde(default = "enabled", skip_serializing_if = "is_enabled")]
    pub http_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub same_site: Option<SameSite>,
}
/// One local-storage entry restored only into its own HTTPS origin.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageItem {
    pub name: String,
    pub value: String,
}
/// Page storage for one credential-authorized HTTPS origin, such as a site's
/// signed-in session marker. Engine-owned like cookies; never sent to plugins.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginStorage {
    /// Serialized origin, for example `https://www.example.com`.
    pub origin: String,
    pub local_storage: Vec<StorageItem>,
}
/// Bounds that keep a saved account small enough for every OS credential store.
/// Shorter account values are treated as public markers, not secrets.
pub const MIN_REDACTED_SECRET: usize = 8;
pub const MAX_STORAGE_ORIGINS: usize = 16;
pub const MAX_STORAGE_ITEMS: usize = 256;
pub const MAX_ORIGIN_STORAGE_BYTES: usize = 128 * 1024;
pub const MAX_SESSION_STORAGE_BYTES: usize = 512 * 1024;
impl OriginStorage {
    fn bytes(&self) -> usize {
        self.local_storage
            .iter()
            .map(|item| item.name.len() + item.value.len())
            .sum()
    }
}
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub origin: String,
    pub name: String,
    pub value: String,
}
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub expires_at: Option<i64>,
    pub cookies: Vec<Cookie>,
    pub headers: Vec<Header>,
    /// Restored before page scripts run in engine-owned source browsers only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub origins: Vec<OriginStorage>,
}
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("cookies", &self.cookies.len())
            .field("headers", &self.headers.len())
            .field("origins", &self.origins.len())
            .field("secrets", &"[redacted]")
            .finish()
    }
}
/// Whether a cookie belongs to a host covered by one of the credential grants.
pub fn cookie_authorized(cookie: &Cookie, grants: &[HostGrant]) -> bool {
    grants.iter().any(|g| {
        g.credential
            && g.hosts.iter().any(|host| {
                let host = host.strip_prefix("*.").unwrap_or(host);
                host == cookie.domain
                    || (!cookie.host_only && host.ends_with(&format!(".{}", cookie.domain)))
            })
    })
}
/// Whether page storage for this serialized HTTPS origin may be kept.
pub fn origin_authorized(origin: &str, grants: &[HostGrant]) -> bool {
    // Same reach as broker requests: default HTTPS port and named hosts only.
    Url::parse(origin).is_ok_and(|url| {
        url.scheme() == "https"
            && url.port().is_none()
            && matches!(url.host(), Some(url::Host::Domain(_)))
            && url.origin().ascii_serialization() == origin
            && grants
                .iter()
                .any(|g| host_allowed(url.host_str().unwrap_or(""), g))
    })
}
fn host_allowed(host: &str, grant: &HostGrant) -> bool {
    grant.credential
        && grant.hosts.iter().any(|pattern| {
            pattern == host
                || pattern
                    .strip_prefix("*.")
                    .is_some_and(|suffix| host.ends_with(&format!(".{suffix}")))
        })
}
impl Session {
    pub fn check_expiration(&self, now: i64) -> Result<()> {
        if self.expires_at.is_some_and(|expiry| expiry <= now)
            || (self.headers.is_empty()
                && !self.cookies.is_empty()
                && self
                    .cookies
                    .iter()
                    .all(|cookie| cookie.expires_at.is_some_and(|expiry| expiry <= now)))
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub fn validate(&self, grants: &[HostGrant]) -> Result<()> {
        if self.cookies.len() > 512
            || self.headers.len() > 32
            || self.origins.len() > MAX_STORAGE_ORIGINS
            || (self.cookies.is_empty() && self.headers.is_empty() && self.origins.is_empty())
        {
            return Err(Error::Invalid);
        }
        for cookie in &self.cookies {
            if cookie.name.is_empty()
                || cookie.name.len() > 256
                || !cookie
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
                || cookie.value.len() > 16384
                || cookie
                    .value
                    .bytes()
                    .any(|c| c < 0x21 || c == b';' || c == b',' || c >= 0x7f)
                || !cookie.path.starts_with('/')
                || cookie.path.len() > 4096
                || cookie.domain.starts_with('.')
                || cookie.domain.to_lowercase() != cookie.domain
                // Browsers reject SameSite=None without Secure.
                || (cookie.same_site == Some(SameSite::None) && !cookie.secure)
            {
                return Err(Error::Invalid);
            }
            if !cookie_authorized(cookie, grants) {
                return Err(Error::Denied);
            }
        }
        let mut storage_bytes = 0usize;
        for (index, storage) in self.origins.iter().enumerate() {
            if self.origins[..index]
                .iter()
                .any(|other| other.origin == storage.origin)
                || storage.local_storage.len() > MAX_STORAGE_ITEMS
                || storage.bytes() > MAX_ORIGIN_STORAGE_BYTES
            {
                return Err(Error::Invalid);
            }
            for (position, item) in storage.local_storage.iter().enumerate() {
                if item.name.is_empty()
                    || item.name.len() > 1024
                    || storage.local_storage[..position]
                        .iter()
                        .any(|other| other.name == item.name)
                {
                    return Err(Error::Invalid);
                }
            }
            if !origin_authorized(&storage.origin, grants) {
                return Err(Error::Denied);
            }
            storage_bytes += storage.bytes();
        }
        if storage_bytes > MAX_SESSION_STORAGE_BYTES {
            return Err(Error::Invalid);
        }
        for header in &self.headers {
            let origin = Url::parse(&header.origin).map_err(|_| Error::Invalid)?;
            if origin.scheme() != "https"
                || origin.origin().ascii_serialization() != header.origin
                || !grants
                    .iter()
                    .any(|g| host_allowed(origin.host_str().unwrap_or(""), g))
            {
                return Err(Error::Denied);
            }
            if !matches!(
                header.name.to_ascii_lowercase().as_str(),
                "authorization" | "x-api-key" | "x-auth-token"
            ) || header.value.is_empty()
                || header.value.len() > 16384
                || HeaderValue::from_str(&header.value).is_err()
            {
                return Err(Error::Invalid);
            }
        }
        if Zeroizing::new(serde_json::to_vec(self).map_err(|_| Error::Invalid)?).len() > 1024 * 1024
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Remove known credential bytes if a remote endpoint reflects them in text.
    /// Withholds reflected account values (8 characters or longer) from text.
    pub fn redact(&self, text: &str) -> String {
        let mut value = text.to_owned();
        // Accounts commonly hold short public markers ("1", "true", "en") in
        // cookies and storage. Replacing those everywhere corrupts unrelated
        // JSON and page text without protecting a secret, so only values long
        // enough to be credentials are withheld.
        let mut secrets: Vec<&str> = self
            .cookies
            .iter()
            .map(|c| c.value.as_str())
            .chain(self.headers.iter().map(|h| h.value.as_str()))
            .chain(
                self.origins
                    .iter()
                    .flat_map(|o| o.local_storage.iter().map(|i| i.value.as_str())),
            )
            .filter(|s| s.len() >= MIN_REDACTED_SECRET)
            .collect();
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        for secret in secrets {
            value = value.replace(secret, "[redacted]");
        }
        value
    }
    pub fn redact_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(text) => *text = self.redact(text),
            serde_json::Value::Array(items) => {
                items.iter_mut().for_each(|value| self.redact_value(value))
            }
            serde_json::Value::Object(fields) => {
                let old = std::mem::take(fields);
                for (key, mut value) in old {
                    self.redact_value(&mut value);
                    fields.insert(self.redact(&key), value);
                }
            }
            _ => {}
        }
    }
    /// Called after network URL/address policy validation on every redirect hop.
    pub fn headers_for(&self, url: &Url, grant: &HostGrant, now: i64) -> Result<HeaderMap> {
        self.check_expiration(now)?;
        if url.scheme() != "https" || !host_allowed(url.host_str().unwrap_or(""), grant) {
            return Err(Error::Denied);
        }
        let mut headers = HeaderMap::new();
        let mut cookies: Vec<_> = self
            .cookies
            .iter()
            .filter(|cookie| {
                let host = url.host_str().unwrap_or("");
                (host == cookie.domain
                    || (!cookie.host_only && host.ends_with(&format!(".{}", cookie.domain))))
                    && (url.path() == cookie.path
                        || (url.path().starts_with(&cookie.path)
                            && (cookie.path.ends_with('/')
                                || url.path().as_bytes().get(cookie.path.len()) == Some(&b'/'))))
                    && cookie.expires_at.is_none_or(|expiry| expiry > now)
            })
            .collect();
        cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.path.len()));
        if !cookies.is_empty() {
            let mut text = Zeroizing::new(String::new());
            for cookie in cookies {
                if !text.is_empty() {
                    text.push_str("; ");
                }
                text.push_str(&cookie.name);
                text.push('=');
                text.push_str(&cookie.value);
            }
            let mut value = HeaderValue::from_str(&text).map_err(|_| Error::Invalid)?;
            value.set_sensitive(true);
            headers.insert(COOKIE, value);
        }
        for header in &self.headers {
            if url.origin().ascii_serialization() == header.origin {
                let mut value = HeaderValue::from_str(&header.value).map_err(|_| Error::Invalid)?;
                value.set_sensitive(true);
                headers.insert(
                    HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| Error::Invalid)?,
                    value,
                );
            }
        }
        Ok(headers)
    }
}

/// Protocol between the engine and its native sign-in window (`omd-signin`).
/// Kept here, free of GUI dependencies, so the engine never links a web view.
pub mod native_sign_in {
    use super::Session;
    use omd_domain::HostGrant;
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;

    /// Largest request accepted on stdin.
    pub const MAX_REQUEST: usize = 64 * 1024;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Request {
        /// The source's declared sign-in page.
        pub url: String,
        /// Window title shown to the person signing in.
        pub title: String,
        /// Cookie names whose presence marks a completed sign-in. When empty, the
        /// person finishes by closing the window after signing in.
        pub completion_cookies: Vec<String>,
        /// The source's acquisition grants. Only credential grants scope what is kept.
        pub grants: Vec<HostGrant>,
        /// Private engine-created directory for web-view runtime files (WebView2).
        pub data_directory: PathBuf,
        pub timeout_seconds: u64,
    }
    impl Request {
        pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
            if bytes.len() > MAX_REQUEST {
                return Err("invalid_request");
            }
            let request: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
            let url = url::Url::parse(&request.url).map_err(|_| "invalid_request")?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || request.title.trim().is_empty()
                || request.title.len() > 256
                || request.completion_cookies.len() > 16
                || request.grants.len() > 64
                || !request.data_directory.is_absolute()
                || !(30..=3600).contains(&request.timeout_seconds)
                || !request.grants.iter().any(|g| g.credential)
            {
                return Err("invalid_request");
            }
            Ok(request)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
    pub enum Outcome {
        /// Credential-scoped cookies and page storage captured after sign-in.
        Completed { session: Session },
        /// The person closed the window before signing in.
        Closed,
        /// The sign-in time limit passed.
        Expired,
        /// The window could not be shown (`display_unavailable`, `webview_unavailable`,
        /// `invalid_request`).
        Failed { code: String },
    }
}

pub trait Backend: Send + Sync {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()>;
    fn remove(&self, key: &str) -> Result<()>;
}
struct Native;
#[cfg(any(windows, test))]
mod chunked;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;
#[cfg(not(target_os = "linux"))]
fn native_error(error: keyring::Error) -> Error {
    match error {
        keyring::Error::NoEntry => Error::Missing,
        keyring::Error::NoStorageAccess(_) => Error::Locked,
        _ => Error::Unavailable,
    }
}
#[cfg(not(target_os = "linux"))]
impl Backend for NativeEntry {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        keyring::Entry::new("org.northwolf.omd.v2", key)
            .map_err(native_error)?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(native_error)
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        keyring::Entry::new("org.northwolf.omd.v2", key)
            .map_err(native_error)?
            .set_secret(bytes)
            .map_err(native_error)
    }
    fn remove(&self, key: &str) -> Result<()> {
        match keyring::Entry::new("org.northwolf.omd.v2", key)
            .map_err(native_error)?
            .delete_credential()
        {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(native_error(error)),
        }
    }
}
#[cfg(not(target_os = "linux"))]
struct NativeEntry;
#[cfg(target_os = "macos")]
impl Backend for Native {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        NativeEntry.read(key)
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
        NativeEntry.write(key, bytes)
    }
    fn remove(&self, key: &str) -> Result<()> {
        NativeEntry.remove(key)
    }
}
#[derive(Clone)]
pub struct Vault {
    namespace: String,
    backend: Arc<dyn Backend>,
}
impl Vault {
    pub fn native(profile_identity: &str) -> Self {
        Self::with_backend(profile_identity, Arc::new(Native))
    }
    pub fn with_backend(profile_identity: &str, backend: Arc<dyn Backend>) -> Self {
        Self {
            namespace: digest(profile_identity.as_bytes()),
            backend,
        }
    }
    fn key(&self, provider: &str, profile: &str) -> String {
        digest(
            &serde_json::to_vec(&(&self.namespace, provider, profile))
                .expect("identities serialize"),
        )
    }
    pub async fn save(
        &self,
        provider: &str,
        profile: &str,
        session: &Session,
        grants: &[HostGrant],
    ) -> Result<()> {
        session.validate(grants)?;
        let bytes = Zeroizing::new(serde_json::to_vec(session).map_err(|_| Error::Invalid)?);
        let backend = self.backend.clone();
        let key = self.key(provider, profile);
        tokio::task::spawn_blocking(move || backend.write(&key, &bytes))
            .await
            .map_err(|_| Error::Unavailable)?
    }
    pub async fn load(
        &self,
        provider: &str,
        profile: &str,
        grants: &[HostGrant],
    ) -> Result<Session> {
        let backend = self.backend.clone();
        let key = self.key(provider, profile);
        let bytes = tokio::task::spawn_blocking(move || backend.read(&key))
            .await
            .map_err(|_| Error::Unavailable)??;
        if bytes.len() > 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let session: Session = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        session.validate(grants)?;
        session.check_expiration(chrono::Utc::now().timestamp())?;
        Ok(session)
    }
    pub async fn revoke(&self, provider: &str, profile: &str) -> Result<()> {
        let backend = self.backend.clone();
        let key = self.key(provider, profile);
        tokio::task::spawn_blocking(move || backend.remove(&key))
            .await
            .map_err(|_| Error::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::Mutex};
    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
    impl Backend for Memory {
        fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
            self.0
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or(Error::Missing)
        }
        fn write(&self, key: &str, bytes: &[u8]) -> Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(key.into(), Zeroizing::new(bytes.to_vec()));
            Ok(())
        }
        fn remove(&self, key: &str) -> Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }
    fn grant() -> HostGrant {
        HostGrant {
            request_intervals: Default::default(),
            id: "account".into(),
            hosts: vec!["example.com".into(), "*.example.com".into()],
            methods: vec!["GET".into()],
            credential: true,
        }
    }
    fn session() -> Session {
        Session {
            expires_at: None,
            origins: vec![],
            cookies: vec![Cookie {
                name: "session".into(),
                value: "PRIVATE_COOKIE".into(),
                domain: "example.com".into(),
                path: "/account".into(),
                host_only: false,
                expires_at: Some(200),
                secure: true,
                http_only: true,
                same_site: None,
            }],
            headers: vec![Header {
                origin: "https://example.com".into(),
                name: "authorization".into(),
                value: "Bearer PRIVATE_TOKEN".into(),
            }],
        }
    }
    #[test]
    fn redirect_hops_recompute_origin_domain_path_and_expiry() {
        let session = session();
        session.validate(&[grant()]).unwrap();
        let headers = session
            .headers_for(
                &Url::parse("https://example.com/account/a").unwrap(),
                &grant(),
                100,
            )
            .unwrap();
        assert_eq!(headers[COOKIE], "session=PRIVATE_COOKIE");
        assert!(headers[COOKIE].is_sensitive());
        assert!(headers["authorization"].is_sensitive());
        let redirected = session
            .headers_for(
                &Url::parse("https://cdn.example.com/account/a").unwrap(),
                &grant(),
                100,
            )
            .unwrap();
        assert!(redirected.get("authorization").is_none());
        assert!(redirected.contains_key(COOKIE));
        for path in ["/", "/accounting"] {
            assert!(
                !session
                    .headers_for(
                        &Url::parse(&format!("https://example.com{path}")).unwrap(),
                        &grant(),
                        100
                    )
                    .unwrap()
                    .contains_key(COOKIE)
            );
        }
        assert!(
            !session
                .headers_for(
                    &Url::parse("https://example.com/account").unwrap(),
                    &grant(),
                    200
                )
                .unwrap()
                .contains_key(COOKIE)
        );
        let mut host_only = session.clone();
        host_only.cookies[0].host_only = true;
        assert!(
            !host_only
                .headers_for(
                    &Url::parse("https://cdn.example.com/account").unwrap(),
                    &grant(),
                    100
                )
                .unwrap()
                .contains_key(COOKIE)
        );
        let mut denied = grant();
        denied.credential = false;
        assert_eq!(
            session
                .headers_for(
                    &Url::parse("https://example.com/account").unwrap(),
                    &denied,
                    100
                )
                .unwrap_err(),
            Error::Denied
        );
        assert_eq!(
            session
                .headers_for(
                    &Url::parse("https://example.com.evil.test/account").unwrap(),
                    &grant(),
                    100
                )
                .unwrap_err(),
            Error::Denied
        );
        assert!(!format!("{session:?} {headers:?}").contains("PRIVATE"));
        assert_eq!(
            session.redact("PRIVATE_COOKIE / Bearer PRIVATE_TOKEN"),
            "[redacted] / [redacted]"
        );
    }
    #[test]
    fn short_public_markers_do_not_corrupt_responses() {
        let mut session = session();
        for (name, value) in [("signed_in", "true"), ("consent", "1")] {
            let mut marker = session.cookies[0].clone();
            marker.name = name.into();
            marker.value = value.into();
            session.cookies.push(marker);
        }
        let body = r#"{"permissions":{"read":true},"count":1,"size":10,"text":"step 1 true"}"#;
        assert_eq!(session.redact(body), body);
        let mut value: serde_json::Value = serde_json::from_str(body).unwrap();
        session.redact_value(&mut value);
        assert_eq!(
            value,
            serde_json::from_str::<serde_json::Value>(body).unwrap()
        );
        // Real credentials are still withheld next to the markers.
        assert_eq!(
            session.redact(r#"{"read":true,"token":"PRIVATE_COOKIE"}"#),
            r#"{"read":true,"token":"[redacted]"}"#
        );
    }
    #[test]
    fn expired_cookie_only_sessions_and_nested_reflections_are_handled() {
        let mut session = session();
        session.headers.clear();
        assert_eq!(session.check_expiration(200), Err(Error::Expired));
        assert_eq!(session.check_expiration(199), Ok(()));
        let mut value = serde_json::json!({"title":"PRIVATE_COOKIE","items":[{"PRIVATE_COOKIE":"reflected PRIVATE_COOKIE"}]});
        session.redact_value(&mut value);
        assert!(
            !serde_json::to_string(&value)
                .unwrap()
                .contains("PRIVATE_COOKIE")
        );
        assert_eq!(Error::Locked.problem().actions, vec!["unlock_credentials"]);
        assert_eq!(Error::Expired.problem().actions, vec!["reauthenticate"]);
    }
    #[tokio::test]
    async fn persistent_profile_provider_isolation_revocation_and_expiration() {
        let backend = Arc::new(Memory::default());
        let vault = Vault::with_backend("profile-a", backend.clone());
        vault
            .save("source-a", "personal", &session(), &[grant()])
            .await
            .unwrap();
        let restarted = Vault::with_backend("profile-a", backend.clone());
        assert_eq!(
            restarted
                .load("source-a", "personal", &[grant()])
                .await
                .unwrap()
                .cookies[0]
                .value,
            "PRIVATE_COOKIE"
        );
        for (namespace, provider, profile) in [
            ("profile-b", "source-a", "personal"),
            ("profile-a", "source-b", "personal"),
            ("profile-a", "source-a", "other"),
        ] {
            assert_eq!(
                Vault::with_backend(namespace, backend.clone())
                    .load(provider, profile, &[grant()])
                    .await
                    .unwrap_err(),
                Error::Missing
            );
        }
        let mut expired = session();
        expired.expires_at = Some(1);
        vault
            .save("source-a", "personal", &expired, &[grant()])
            .await
            .unwrap();
        assert_eq!(
            vault
                .load("source-a", "personal", &[grant()])
                .await
                .unwrap_err(),
            Error::Expired
        );
        vault.revoke("source-a", "personal").await.unwrap();
        vault.revoke("source-a", "personal").await.unwrap();
        assert_eq!(
            vault
                .load("source-a", "personal", &[grant()])
                .await
                .unwrap_err(),
            Error::Missing
        );
    }
    #[tokio::test]
    async fn locked_store_has_no_file_or_memory_fallback() {
        struct Locked;
        impl Backend for Locked {
            fn read(&self, _: &str) -> Result<Zeroizing<Vec<u8>>> {
                Err(Error::Locked)
            }
            fn write(&self, _: &str, _: &[u8]) -> Result<()> {
                Err(Error::Locked)
            }
            fn remove(&self, _: &str) -> Result<()> {
                Err(Error::Locked)
            }
        }
        let vault = Vault::with_backend("test", Arc::new(Locked));
        assert_eq!(
            vault
                .save("source", "profile", &session(), &[grant()])
                .await
                .unwrap_err(),
            Error::Locked
        );
        assert_eq!(
            vault
                .load("source", "profile", &[grant()])
                .await
                .unwrap_err(),
            Error::Locked
        );
        assert_eq!(
            vault.revoke("source", "profile").await.unwrap_err(),
            Error::Locked
        );
    }
    fn storage(origin: &str, name: &str, value: &str) -> OriginStorage {
        OriginStorage {
            origin: origin.into(),
            local_storage: vec![StorageItem {
                name: name.into(),
                value: value.into(),
            }],
        }
    }
    #[test]
    fn earlier_vault_records_keep_their_bytes_and_cookie_defaults() {
        let earlier = br#"{"expires_at":null,"cookies":[{"name":"session","value":"v","domain":"example.com","path":"/","host_only":true,"expires_at":null}],"headers":[]}"#;
        let session: Session = serde_json::from_slice(earlier).unwrap();
        let cookie = &session.cookies[0];
        assert!(cookie.secure && cookie.http_only && cookie.same_site.is_none());
        assert!(session.origins.is_empty());
        assert_eq!(serde_json::to_vec(&session).unwrap(), earlier);
        let mut readable = session.clone();
        readable.cookies[0].http_only = false;
        readable.cookies[0].same_site = Some(SameSite::Strict);
        let text = serde_json::to_string(&readable).unwrap();
        assert!(text.contains(r#""http_only":false"#) && text.contains(r#""same_site":"strict""#));
        let mut cross_site = session.clone();
        cross_site.cookies[0].same_site = Some(SameSite::None);
        cross_site.validate(&[grant()]).unwrap();
        cross_site.cookies[0].secure = false;
        assert_eq!(cross_site.validate(&[grant()]), Err(Error::Invalid));
    }
    #[test]
    fn origin_storage_is_scoped_bounded_and_redacted() {
        let mut session = session();
        session.origins = vec![storage(
            "https://www.example.com",
            "account",
            r#"{"user":"PRIVATE_STORAGE_TOKEN"}"#,
        )];
        session.validate(&[grant()]).unwrap();
        let mut storage_only = session.clone();
        storage_only.cookies.clear();
        storage_only.headers.clear();
        storage_only.validate(&[grant()]).unwrap();
        for (origin, expected) in [
            ("http://example.com", Error::Denied),
            ("https://example.com/path", Error::Denied),
            ("https://example.com:8443", Error::Denied),
            ("https://example.com.evil.test", Error::Denied),
            ("https://evil.test", Error::Denied),
        ] {
            let mut bad = session.clone();
            bad.origins[0].origin = origin.into();
            assert_eq!(bad.validate(&[grant()]), Err(expected), "{origin}");
        }
        let mut denied = grant();
        denied.credential = false;
        assert_eq!(session.validate(&[denied]), Err(Error::Denied));
        let mut duplicate = session.clone();
        duplicate.origins.push(duplicate.origins[0].clone());
        assert_eq!(duplicate.validate(&[grant()]), Err(Error::Invalid));
        let mut duplicate_key = session.clone();
        let item = duplicate_key.origins[0].local_storage[0].clone();
        duplicate_key.origins[0].local_storage.push(item);
        assert_eq!(duplicate_key.validate(&[grant()]), Err(Error::Invalid));
        let mut oversized = session.clone();
        oversized.origins[0].local_storage[0].value = "x".repeat(MAX_ORIGIN_STORAGE_BYTES);
        assert_eq!(oversized.validate(&[grant()]), Err(Error::Invalid));
        let mut total = session.clone();
        total.origins = (0..5)
            .map(|i| {
                storage(
                    &format!("https://h{i}.example.com"),
                    "k",
                    &"x".repeat(120 * 1024),
                )
            })
            .collect();
        assert_eq!(total.validate(&[grant()]), Err(Error::Invalid));
        let mut flags = session.clone();
        flags.origins[0].local_storage.push(StorageItem {
            name: "seen".into(),
            value: "1".into(),
        });
        assert_eq!(
            flags.redact(r#"{"user":"PRIVATE_STORAGE_TOKEN"} step 1"#),
            "[redacted] step 1"
        );
        assert!(!format!("{flags:?}").contains("PRIVATE"));
        assert!(
            !serde_json::to_string(&session)
                .unwrap()
                .contains("localStorage")
        );
    }
    #[test]
    fn injection_and_undeclared_credential_authority_are_rejected() {
        let mut bad = session();
        bad.cookies[0].value = "x\r\nAuthorization: injected".into();
        assert_eq!(bad.validate(&[grant()]), Err(Error::Invalid));
        let mut bad = session();
        bad.headers[0].origin = "https://evil.test".into();
        assert_eq!(bad.validate(&[grant()]), Err(Error::Denied));
        let mut bad = session();
        bad.headers[0].name = "host".into();
        assert_eq!(bad.validate(&[grant()]), Err(Error::Invalid));
        let mut bad = session();
        bad.cookies[0].domain = "evil.test".into();
        assert_eq!(bad.validate(&[grant()]), Err(Error::Denied));
    }
}

#[cfg(test)]
mod native_acceptance {
    use super::*;
    /// Creates and removes one uniquely named dummy entry; never reads existing entries.
    #[tokio::test]
    #[ignore = "requires an unlocked operating system credential store"]
    async fn native_vault_roundtrip_restart_and_revoke() {
        let identity = format!("acceptance-{}", uuid::Uuid::new_v4());
        let grant = HostGrant {
            request_intervals: Default::default(),
            id: "account".into(),
            hosts: vec!["example.com".into()],
            methods: vec!["GET".into()],
            credential: true,
        };
        let session = Session {
            expires_at: None,
            origins: vec![],
            cookies: vec![],
            headers: vec![Header {
                origin: "https://example.com".into(),
                name: "authorization".into(),
                value: "OMD-acceptance-dummy-value".into(),
            }],
        };
        let vault = Vault::native(&identity);
        vault
            .save("fixture", "account", &session, std::slice::from_ref(&grant))
            .await
            .unwrap();
        let loaded = Vault::native(&identity)
            .load("fixture", "account", std::slice::from_ref(&grant))
            .await;
        let removed = vault.revoke("fixture", "account").await;
        assert!(loaded.is_ok());
        assert!(removed.is_ok());
        assert_eq!(
            vault
                .load("fixture", "account", &[grant])
                .await
                .unwrap_err(),
            Error::Missing
        );
    }
}
