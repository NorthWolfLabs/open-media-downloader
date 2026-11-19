//! Protocol and capture rules for the engine-launched native sign-in window.
//!
//! The engine starts `omd-signin` with one JSON [`Request`] on stdin. The helper
//! shows the source's sign-in page in an ordinary operating-system web view
//! (WKWebView, WebView2 or WebKitGTK) with a private, temporary data store. It
//! writes exactly one JSON [`Outcome`] line to stdout and exits. Only the engine
//! reads that line; it re-validates the session against the source's credential
//! grants before saving it. Source plugins and clients never see these values.
pub use omd_credentials::native_sign_in::{MAX_REQUEST, Outcome, Request};
use omd_credentials::{Cookie, OriginStorage, SameSite, Session, StorageItem};
use omd_domain::HostGrant;

/// Largest page-storage export read from the web view.
pub const MAX_STORAGE_EXPORT: usize = 1024 * 1024;
/// Schemes a top-level page or frame may load. Everything else, including
/// plain HTTP, local files and application links, is blocked.
const ALLOWED_SCHEMES: &[&str] = &["https", "about", "data", "blob"];

pub fn navigation_allowed(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| ALLOWED_SCHEMES.contains(&u.scheme()))
}
/// Popups open in the same window, and only for HTTPS pages.
pub fn popup_target(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .filter(|u| u.scheme() == "https" && u.username().is_empty() && u.password().is_none())
        .map(|u| u.to_string())
}

/// Attributes read from the web view's cookie store.
pub struct NativeCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: Option<String>,
    pub expires_at: Option<i64>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<SameSite>,
}
/// Unexpired cookies for hosts covered by the source's credential grants.
pub fn credential_cookies(
    cookies: Vec<NativeCookie>,
    grants: &[HostGrant],
    now: i64,
) -> Vec<Cookie> {
    let mut kept: Vec<Cookie> = vec![];
    for native in cookies {
        let domain = native.domain.to_ascii_lowercase();
        let cookie = Cookie {
            name: native.name,
            value: native.value,
            host_only: !domain.starts_with('.'),
            domain: domain.trim_start_matches('.').to_owned(),
            path: native
                .path
                .filter(|p| p.starts_with('/'))
                .unwrap_or_else(|| "/".into()),
            expires_at: native.expires_at,
            secure: native.secure.unwrap_or(true),
            http_only: native.http_only.unwrap_or(false),
            same_site: native.same_site,
        };
        let single = Session {
            expires_at: None,
            cookies: vec![cookie],
            headers: vec![],
            origins: vec![],
        };
        if single.cookies[0].expires_at.is_some_and(|e| e <= now)
            || single.validate(grants).is_err()
        {
            continue;
        }
        let cookie = single.cookies[0].clone();
        // One value per name/domain/path, like a browser cookie jar.
        kept.retain(|c| {
            (&c.name, &c.domain, &c.path) != (&cookie.name, &cookie.domain, &cookie.path)
        });
        kept.push(cookie);
        if kept.len() >= 512 {
            break;
        }
    }
    kept
}
/// Declared completion cookies are present; with none declared, any
/// credential-scoped cookie counts once the person closes the window.
pub fn completed(cookies: &[Cookie], completion: &[String]) -> bool {
    !cookies.is_empty()
        && completion
            .iter()
            .all(|name| cookies.iter().any(|c| &c.name == name))
}

/// Script evaluated in the page once sign-in is complete. Its origin claim is
/// cross-checked against the web view's own URL before anything is kept.
pub const STORAGE_SCRIPT: &str = "JSON.stringify({origin: location.origin, items: Object.keys(localStorage).slice(0, 256).map(function (k) { return [k, localStorage.getItem(k)]; })})";

/// Page storage for the current top-level origin, kept only when that origin is
/// credential-authorized and matches the URL reported by the web view itself.
pub fn page_storage(
    result: &str,
    webview_url: &str,
    grants: &[HostGrant],
) -> Option<OriginStorage> {
    if result.len() > MAX_STORAGE_EXPORT {
        return None;
    }
    // Platforms return the script value JSON-encoded; a string result is
    // encoded once more.
    let mut value: serde_json::Value = serde_json::from_str(result).ok()?;
    if let serde_json::Value::String(inner) = &value {
        value = serde_json::from_str(inner).ok()?;
    }
    let actual = url::Url::parse(webview_url)
        .ok()?
        .origin()
        .ascii_serialization();
    let origin = value["origin"].as_str()?;
    if origin != actual || !omd_credentials::origin_authorized(origin, grants) {
        return None;
    }
    let mut local_storage = vec![];
    for pair in value["items"]
        .as_array()?
        .iter()
        .take(omd_credentials::MAX_STORAGE_ITEMS)
    {
        let (Some(name), Some(item)) = (pair[0].as_str(), pair[1].as_str()) else {
            continue;
        };
        if name.is_empty()
            || name.len() > 1024
            || local_storage.iter().any(|i: &StorageItem| i.name == name)
        {
            continue;
        }
        local_storage.push(StorageItem {
            name: name.into(),
            value: item.into(),
        });
    }
    let storage = OriginStorage {
        origin: origin.into(),
        local_storage,
    };
    let check = Session {
        expires_at: None,
        cookies: vec![],
        headers: vec![],
        origins: vec![storage],
    };
    (!check.origins[0].local_storage.is_empty() && check.validate(grants).is_ok())
        .then(|| check.origins[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn grants() -> Vec<HostGrant> {
        vec![
            HostGrant {
                request_intervals: Default::default(),
                id: "account".into(),
                hosts: vec!["fixture.example".into(), "*.fixture.example".into()],
                methods: vec!["GET".into()],
                credential: true,
            },
            HostGrant {
                request_intervals: Default::default(),
                id: "art".into(),
                hosts: vec!["art.example".into()],
                methods: vec!["GET".into()],
                credential: false,
            },
        ]
    }
    fn native(name: &str, domain: &str) -> NativeCookie {
        NativeCookie {
            name: name.into(),
            value: "PRIVATE_VALUE".into(),
            domain: domain.into(),
            path: Some("/".into()),
            expires_at: None,
            secure: Some(true),
            http_only: Some(true),
            same_site: Some(SameSite::Lax),
        }
    }
    fn request() -> serde_json::Value {
        serde_json::json!({"url":"https://fixture.example/login","title":"Sign in to Fixture","completion_cookies":["session"],"grants":grants(),"data_directory":if cfg!(windows){"C:\\work\\signin"}else{"/work/signin"},"timeout_seconds":600})
    }
    #[test]
    fn requests_are_bounded_https_and_credential_scoped() {
        Request::parse(request().to_string().as_bytes()).unwrap();
        for (key, value) in [
            ("url", serde_json::json!("http://fixture.example/login")),
            ("url", serde_json::json!("https://user:pw@fixture.example/")),
            ("title", serde_json::json!(" ")),
            ("data_directory", serde_json::json!("relative")),
            ("timeout_seconds", serde_json::json!(5)),
            ("grants", serde_json::json!([grants()[1]])),
        ] {
            let mut bad = request();
            bad[key] = value;
            assert!(Request::parse(bad.to_string().as_bytes()).is_err(), "{key}");
        }
        let mut extra = request();
        extra["script"] = serde_json::json!("x");
        assert!(Request::parse(extra.to_string().as_bytes()).is_err());
    }
    #[test]
    fn only_web_schemes_load_and_popups_stay_https() {
        for url in [
            "https://fixture.example/",
            "about:blank",
            "about:srcdoc",
            "data:text/html,x",
            "blob:https://fixture.example/1",
        ] {
            assert!(navigation_allowed(url), "{url}");
        }
        for url in [
            "http://fixture.example/",
            "file:///etc/passwd",
            "omd://x",
            "mailto:a@b",
            "not a url",
        ] {
            assert!(!navigation_allowed(url), "{url}");
        }
        assert_eq!(
            popup_target("https://login.example/x").as_deref(),
            Some("https://login.example/x")
        );
        assert!(popup_target("http://login.example/").is_none());
        assert!(popup_target("https://a:b@login.example/").is_none());
    }
    #[test]
    fn cookies_keep_attributes_and_only_credential_hosts() {
        let mut readable = native("marker", "fixture.example");
        readable.http_only = Some(false);
        readable.same_site = Some(SameSite::Strict);
        let mut expired = native("old", "fixture.example");
        expired.expires_at = Some(10);
        let mut replaced = native("session", ".fixture.example");
        replaced.value = "OLDER".into();
        let kept = credential_cookies(
            vec![
                replaced,
                native("session", ".fixture.example"),
                readable,
                expired,
                native("tracker", "art.example"),
                native("idp", "login.identity.example"),
            ],
            &grants(),
            100,
        );
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].value, "PRIVATE_VALUE");
        assert!(!kept[0].host_only && kept[0].domain == "fixture.example");
        assert!(kept[1].host_only && !kept[1].http_only);
        assert_eq!(kept[1].same_site, Some(SameSite::Strict));
        assert!(completed(&kept, &["session".into()]));
        assert!(!completed(&kept, &["session".into(), "absent".into()]));
        assert!(completed(&kept, &[]));
        assert!(!completed(&[], &[]));
    }
    #[test]
    fn storage_requires_matching_authorized_origin() {
        let script = |origin: &str| {
            serde_json::to_string(&serde_json::json!({"origin":origin,"items":[["account","{\"user\":7}"],["account","dup"],["", "x"],["n", 5]]}).to_string()).unwrap()
        };
        let storage = page_storage(
            &script("https://www.fixture.example"),
            "https://www.fixture.example/home?x=1",
            &grants(),
        )
        .unwrap();
        assert_eq!(storage.local_storage.len(), 1);
        assert_eq!(storage.local_storage[0].value, "{\"user\":7}");
        // A page cannot claim a different origin than the web view reports.
        assert!(
            page_storage(
                &script("https://fixture.example"),
                "https://evil.example/",
                &grants()
            )
            .is_none()
        );
        assert!(
            page_storage(
                &script("https://art.example"),
                "https://art.example/",
                &grants()
            )
            .is_none()
        );
        assert!(
            page_storage(
                &script("https://login.identity.example"),
                "https://login.identity.example/",
                &grants()
            )
            .is_none()
        );
        assert!(page_storage("not json", "https://fixture.example/", &grants()).is_none());
        assert!(
            page_storage(
                &"x".repeat(MAX_STORAGE_EXPORT + 1),
                "https://fixture.example/",
                &grants()
            )
            .is_none()
        );
        let empty = serde_json::json!({"origin":"https://fixture.example","items":[]}).to_string();
        assert!(page_storage(&empty, "https://fixture.example/", &grants()).is_none());
    }
    #[test]
    fn outcomes_are_tagged_and_redacted_in_debug() {
        let outcome = Outcome::Completed {
            session: Session {
                expires_at: None,
                cookies: credential_cookies(
                    vec![native("session", "fixture.example")],
                    &grants(),
                    0,
                ),
                headers: vec![],
                origins: vec![],
            },
        };
        let text = serde_json::to_string(&outcome).unwrap();
        assert!(text.starts_with(r#"{"status":"completed""#));
        assert!(!format!("{outcome:?}").contains("PRIVATE_VALUE"));
        assert_eq!(
            serde_json::to_string(&Outcome::Closed).unwrap(),
            r#"{"status":"closed"}"#
        );
        let failed: Outcome =
            serde_json::from_str(r#"{"status":"failed","code":"display_unavailable"}"#).unwrap();
        assert!(matches!(failed, Outcome::Failed { code } if code == "display_unavailable"));
    }
}
