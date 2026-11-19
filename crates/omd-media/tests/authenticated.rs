#![cfg(all(
    feature = "fixture-tests",
    any(target_os = "macos", target_os = "linux", windows)
))]
use omd_credentials::{Backend, Cookie, Error, Header, Session, Vault};
use omd_domain::HostGrant;
use omd_media::{Inspect, Media, Tool, Tools};
use omd_network::Network;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
#[derive(Default)]
struct Memory(Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
impl Backend for Memory {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or(Error::Missing)
    }
    fn write(&self, key: &str, bytes: &[u8]) -> Result<(), Error> {
        self.0
            .lock()
            .unwrap()
            .insert(key.into(), Zeroizing::new(bytes.to_vec()));
        Ok(())
    }
    fn remove(&self, key: &str) -> Result<(), Error> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}
#[tokio::test]
async fn native_media_uses_persisted_cookie_and_header_handles_without_reflecting_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let backend = Arc::new(Memory::default());
    let grants = vec![
        HostGrant {
            request_intervals: Default::default(),
            id: "account".into(),
            hosts: vec!["account.fixture.test".into()],
            methods: vec!["GET".into()],
            credential: true,
        },
        HostGrant {
            request_intervals: Default::default(),
            id: "public".into(),
            hosts: vec!["cdn.fixture.test".into()],
            methods: vec!["GET".into()],
            credential: false,
        },
    ];
    let session = Session {
        expires_at: None,
        origins: vec![],
        cookies: vec![Cookie {
            name: "login".into(),
            value: "FIXTURE_COOKIE_SECRET".into(),
            domain: "account.fixture.test".into(),
            path: "/".into(),
            host_only: true,
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            secure: true,
            http_only: true,
            same_site: None,
        }],
        headers: vec![Header {
            origin: "https://account.fixture.test".into(),
            name: "authorization".into(),
            value: "Bearer FIXTURE_HEADER_SECRET".into(),
        }],
    };
    Vault::with_backend("test-profile", backend.clone())
        .save("fixture-source", "personal", &session, &grants)
        .await
        .unwrap();
    let count = Arc::new(Mutex::new(0));
    let seen = count.clone();
    let network=Network::new(0).with_vault(Vault::with_backend("test-profile",backend.clone())).with_native_fixture(move |url,_,headers,_|{
        *seen.lock().unwrap()+=1;
        if url.host_str()==Some("account.fixture.test") {
            assert_eq!(headers["authorization"],"Bearer FIXTURE_HEADER_SECRET");
            assert_eq!(headers["cookie"],"login=FIXTURE_COOKIE_SECRET");
            Ok(http::Response::builder().status(302).header("Location","https://cdn.fixture.test/final").body(vec![]).unwrap())
        } else {
            assert_eq!(url.host_str(),Some("cdn.fixture.test"));
            assert!(!headers.contains_key("authorization"));assert!(!headers.contains_key("cookie"));
            Ok(http::Response::builder().header("Content-Type","application/json").body(serde_json::to_vec(&serde_json::json!({"id":"fixture-video","title":"reflected FIXTURE_COOKIE_SECRET and Bearer FIXTURE_HEADER_SECRET","duration":1,"http_headers":{"cookie":"FIXTURE_COOKIE_SECRET"}})).unwrap()).unwrap())
        }
    });
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_omd-media-probe"));
    let media = Media {
        revoked: tokio_util::sync::CancellationToken::new(),
        tools: Tools {
            yt_dlp: Tool {
                sha256: omd_domain::digest(&std::fs::read(&path).unwrap()),
                path,
                version: "test-only".into(),
            },
            node: None,
            ffmpeg: None,
            ffprobe: None,
        },
        network,
        work_root: temp.path().into(),
    };
    let input = Inspect {
        url: "https://account.fixture.test/start".into(),
        cursor: None,
        page_size: 1,
    };
    let output = media
        .inspect(
            &input,
            "fixture-source",
            &grants,
            Some("personal"),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(output["id"], "fixture-video");
    assert_eq!(*count.lock().unwrap(), 2);
    let serialized = serde_json::to_string(&output).unwrap();
    assert!(!serialized.contains("SECRET"));
    assert!(serialized.contains("[redacted]"));
    assert!(output.get("http_headers").is_none());
    let wrong = media
        .inspect(
            &input,
            "different-source",
            &grants,
            Some("personal"),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong.code, "authentication_required");
    let mut expired = session.clone();
    expired.expires_at = Some(1);
    Vault::with_backend("test-profile", backend.clone())
        .save("fixture-source", "personal", &expired, &grants)
        .await
        .unwrap();
    let issue = media
        .inspect(
            &input,
            "fixture-source",
            &grants,
            Some("personal"),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(issue.actions, vec!["reauthenticate"]);
    Vault::with_backend("test-profile", backend)
        .revoke("fixture-source", "personal")
        .await
        .unwrap();
    assert_eq!(
        *count.lock().unwrap(),
        2,
        "invalid credentials must fail before launching the native helper"
    );
}

/// An authenticated extractor receives the cookie jar only on stdin and
/// derives request authorization from it in memory. The broker accepts that
/// derived header at the initial credential-approved origin, attaches the
/// vault's cookies itself, and no jar or secret reaches files or the result.
#[tokio::test]
async fn extractor_receives_cookie_jar_and_derives_authorization_in_memory() {
    use serde_json::json;
    let work = tempfile::tempdir().unwrap();
    let grants = vec![HostGrant {
        request_intervals: Default::default(),
        id: "account".into(),
        hosts: vec!["account.fixture.test".into()],
        methods: vec!["GET".into()],
        credential: true,
    }];
    let vault = Vault::with_backend("fixture", Arc::new(Memory::default()));
    vault
        .save(
            "fixture-source",
            "personal",
            &Session {
                expires_at: None,
                origins: vec![],
                headers: vec![],
                cookies: vec![Cookie {
                    name: "session_id".into(),
                    value: "PRIVATE_FIXTURE_SID".into(),
                    domain: "account.fixture.test".into(),
                    path: "/".into(),
                    host_only: false,
                    expires_at: None,
                    secure: true,
                    http_only: true,
                    same_site: None,
                }],
            },
            &grants,
        )
        .await
        .unwrap();
    let expected = format!(
        "FixtureHash {}",
        omd_domain::digest(b"https://account.fixture.test session_id=PRIVATE_FIXTURE_SID")
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let observed = calls.clone();
    let network =
        Network::new(0)
            .with_vault(vault)
            .with_native_fixture(move |url, _, headers, _| {
                assert_eq!(url.host_str(), Some("account.fixture.test"));
                assert_eq!(headers["cookie"], "session_id=PRIVATE_FIXTURE_SID");
                let auth = headers
                    .get("authorization")
                    .expect("the extractor must derive authorization from the stdin cookie jar")
                    .to_str()
                    .unwrap()
                    .to_string();
                assert!(!auth.contains("PRIVATE_FIXTURE_SID"));
                observed.lock().unwrap().push(auth);
                Ok(http::Response::builder()
                .header("content-type", "application/json")
                .body(
                    serde_json::to_vec(
                        &json!({"id":"private-list","title":"Fixture private list","entries":[]}),
                    )
                    .unwrap(),
                )
                .unwrap())
            });
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_omd-media-probe"));
    let media = Media {
        revoked: CancellationToken::new(),
        tools: Tools {
            yt_dlp: Tool {
                sha256: omd_domain::digest(&std::fs::read(&path).unwrap()),
                path,
                version: "test-only".into(),
            },
            node: None,
            ffmpeg: None,
            ffprobe: None,
        },
        network,
        work_root: work.path().into(),
    };
    let result = media
        .inspect(
            &Inspect {
                url: "https://account.fixture.test/lists/private".into(),
                cursor: None,
                page_size: 10,
            },
            "fixture-source",
            &grants,
            Some("personal"),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(result["id"], "private-list");
    assert!(!result.to_string().contains("PRIVATE_FIXTURE_SID"));
    assert_eq!(*calls.lock().unwrap(), [expected]);
    assert_eq!(
        std::fs::read_dir(work.path()).unwrap().count(),
        0,
        "no cookie jar or raw info JSON may remain"
    );
}

fn probe_tools() -> Tools {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_omd-media-probe"));
    Tools {
        yt_dlp: Tool {
            sha256: omd_domain::digest(&std::fs::read(&path).unwrap()),
            path,
            version: "test-only".into(),
        },
        node: None,
        ffmpeg: None,
        ffprobe: None,
    }
}
fn grant(id: &str, host: &str, credential: bool) -> HostGrant {
    HostGrant {
        request_intervals: Default::default(),
        id: id.into(),
        hosts: vec![host.into()],
        methods: vec!["GET".into()],
        credential,
    }
}
fn ids(page: &serde_json::Value) -> Vec<serde_json::Value> {
    page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].clone())
        .collect()
}

/// Two fictional providers through the real confined helper, broker and vault.
/// Listings are generic flat windows; navigation stays plugin-owned; transport
/// URLs, credentials and helper paths never reach the projected result.
#[tokio::test]
async fn flat_listings_paginate_generically_and_leave_navigation_to_plugins() {
    use serde_json::json;
    let temp = tempfile::tempdir().unwrap();
    let backend = Arc::new(Memory::default());
    let lantern = vec![
        grant("pages", "lantern.fixture.test", true),
        grant("media", "cdn.lantern.fixture.test", false),
    ];
    let harbor = vec![grant("public", "harbor.fixture.test", false)];
    let session = Session {
        expires_at: None,
        origins: vec![],
        headers: vec![],
        cookies: vec![Cookie {
            name: "lantern_session".into(),
            value: "LANTERN_COOKIE_SECRET".into(),
            domain: "lantern.fixture.test".into(),
            path: "/".into(),
            host_only: true,
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            secure: true,
            http_only: true,
            same_site: None,
        }],
    };
    Vault::with_backend("test-profile", backend.clone())
        .save("fixture-lantern", "personal", &session, &lantern)
        .await
        .unwrap();
    let lantern_entries = json!([
        {"_type":"url","id":"lv-1","title":"Light 1","url":"https://lantern.fixture.test/watch/lv-1",
         "thumbnails":[{"url":"https://cdn.lantern.fixture.test/t/lv-1-small.jpg","width":120},
                       {"url":"https://cdn.lantern.fixture.test/t/lv-1.jpg","width":640}]},
        {"_type":"url","id":"lv-2","url":"https://cdn.lantern.fixture.test/v/lv-2/master.m3u8?token=LANTERN_SIGNED_SECRET",
         "http_headers":{"Cookie":"lantern_session=LANTERN_COOKIE_SECRET"}},
        {"_type":"url","id":"lv-3","url":"https://viewer:LANTERN_PASSWORD_SECRET@lantern.fixture.test/watch/lv-3"},
        {"_type":"url","id":"lv-4","title":"reflected LANTERN_COOKIE_SECRET","url":"https://lantern.fixture.test/watch/lv-4"},
        {"_type":"url","id":"lv-5","url":"https://lantern.fixture.test/watch/lv-5",
         "cookies":"lantern_session=LANTERN_COOKIE_SECRET",
         "manifest_url":"https://cdn.lantern.fixture.test/v/lv-5.mpd?sig=LANTERN_SIGNED_SECRET"}
    ]);
    let lantern_listing = json!({"_type":"playlist","id":"lights","title":"Lantern lights",
        "webpage_url":"https://lantern.fixture.test/channel/lights","playlist_count":5,"entries":lantern_entries});
    let lantern_video = json!({"id":"lv-1","title":"Light 1","webpage_url":"https://lantern.fixture.test/watch/lv-1",
        "timestamp":1_793_491_200,"upload_date":"20261101","duration":61,
        "thumbnail":"https://cdn.lantern.fixture.test/t/lv-1.jpg",
        "formats":[{"format_id":"hls-720","url":"https://cdn.lantern.fixture.test/v/lv-1/720.m3u8?token=LANTERN_SIGNED_SECRET",
            "http_headers":{"Cookie":"lantern_session=LANTERN_COOKIE_SECRET"},"cookies":"lantern_session=LANTERN_COOKIE_SECRET",
            "vcodec":"avc1","acodec":"mp4a"}],
        "requested_downloads":[{"filepath":"/private/LANTERN_PATH_SECRET/media.mp4"}],
        "http_headers":{"Cookie":"lantern_session=LANTERN_COOKIE_SECRET"}});
    let harbor_listing = json!({"id":"tide","title":"Tide clips","entries":[
        {"_type":"url","id":"hb-1","url":"https://harbor.fixture.test/clip/hb-1"},
        null,
        {"_type":"url","id":"hb-3","url":"https://harbor.fixture.test/clip/hb-3?session=HARBOR_SESSION_SECRET",
         "original_url":"https://harbor.fixture.test/clip/hb-3?session=HARBOR_SESSION_SECRET"}
    ]});
    let harbor_video = json!({"id":"hb-1","webpage_url":"https://harbor.fixture.test/clip/hb-1","upload_date":"20261030",
        "formats":[{"url":"https://harbor.fixture.test/media/hb-1.opus?signature=HARBOR_SIGNED_SECRET","acodec":"opus","vcodec":"none"}]});
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let network = Network::new(0)
        .with_vault(Vault::with_backend("test-profile", backend))
        .with_native_fixture(move |url, _, headers, _| {
            let host = url.host_str().unwrap_or_default().to_string();
            let cookie = headers
                .get("cookie")
                .map(|c| c.to_str().unwrap().to_string());
            // An authenticated extractor may derive authorization from its
            // cookie jar, accepted only at the credential origin; it never
            // carries the cookie itself.
            if let Some(auth) = headers.get("authorization") {
                assert_eq!(host, "lantern.fixture.test");
                assert!(!auth.to_str().unwrap().contains("SECRET"));
            }
            match host.as_str() {
                "lantern.fixture.test" => {
                    assert_eq!(
                        cookie.as_deref(),
                        Some("lantern_session=LANTERN_COOKIE_SECRET")
                    )
                }
                // Another provider never receives the first provider's session.
                _ => assert_eq!(cookie, None),
            }
            seen.lock().unwrap().push(format!("{host}{}", url.path()));
            let body = match (host.as_str(), url.path()) {
                ("lantern.fixture.test", "/channel/lights") => &lantern_listing,
                ("lantern.fixture.test", "/watch/lv-1") => &lantern_video,
                ("harbor.fixture.test", "/lists/tide") => &harbor_listing,
                ("harbor.fixture.test", "/clip/hb-1") => &harbor_video,
                _ => return Ok(http::Response::builder().status(404).body(vec![]).unwrap()),
            };
            Ok(http::Response::builder()
                .header("Content-Type", "application/json")
                .body(serde_json::to_vec(body).unwrap())
                .unwrap())
        });
    let media = Media {
        revoked: CancellationToken::new(),
        tools: probe_tools(),
        network,
        work_root: temp.path().into(),
    };
    let inspect = async |url: &str,
                         cursor: Option<&str>,
                         page_size: u32,
                         provider: &str,
                         grants: &[HostGrant],
                         profile: Option<&str>| {
        media
            .inspect(
                &Inspect {
                    url: url.into(),
                    cursor: cursor.map(Into::into),
                    page_size,
                },
                provider,
                grants,
                profile,
                &CancellationToken::new(),
            )
            .await
            .unwrap()
    };
    let listing = "https://lantern.fixture.test/channel/lights";
    let mut pages = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let page = inspect(
            listing,
            cursor.as_deref(),
            2,
            "fixture-lantern",
            &lantern,
            Some("personal"),
        )
        .await;
        assert_eq!(page["kind"], "collection");
        assert_eq!(page["id"], "lights");
        assert_eq!(
            page["webpage_url"], listing,
            "extractor-reported page is kept"
        );
        cursor = page["next_cursor"].as_str().map(Into::into);
        pages.push(page);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        pages.iter().map(ids).collect::<Vec<_>>(),
        [
            vec![json!("lv-1"), json!("lv-2")],
            vec![json!("lv-3"), json!("lv-4")],
            vec![json!("lv-5")]
        ]
    );
    assert_eq!(pages[0]["next_cursor"], "2");
    assert_eq!(pages[1]["next_cursor"], "4");
    assert_eq!(
        pages[0]["entries"][0]["thumbnail"],
        "https://cdn.lantern.fixture.test/t/lv-1.jpg"
    );
    assert!(
        pages[1]["entries"][1]["title"]
            .as_str()
            .unwrap()
            .contains("[redacted]")
    );
    for page in &pages {
        let text = page.to_string();
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!text.contains("cdn.lantern.fixture.test/v/"), "{text}");
        assert!(!text.contains("viewer"), "{text}");
        for entry in page["entries"].as_array().unwrap() {
            assert!(entry.get("webpage_url").is_none(), "core promoted {entry}");
            assert!(entry.get("url").is_none() && entry.get("accessible").is_none());
        }
    }

    // Plugin-owned navigation: the plugin rebuilds its page URL from the entry id
    // and the listing it inspected, then fully inspects that one item.
    let page_url = format!(
        "https://lantern.fixture.test/watch/{}",
        pages[0]["entries"][0]["id"].as_str().unwrap()
    );
    let full = inspect(
        &page_url,
        None,
        1,
        "fixture-lantern",
        &lantern,
        Some("personal"),
    )
    .await;
    assert_eq!(full["kind"], "video");
    assert_eq!(full["webpage_url"], page_url);
    assert_eq!(full["timestamp"], 1_793_491_200);
    assert_eq!(full["accessible"], true);
    for key in [
        "formats",
        "http_headers",
        "requested_downloads",
        "cookies",
        "url",
    ] {
        assert!(full.get(key).is_none(), "{key}");
    }
    assert!(!full.to_string().contains("SECRET"));

    let tide = inspect(
        "https://harbor.fixture.test/lists/tide",
        None,
        10,
        "fixture-harbor",
        &harbor,
        None,
    )
    .await;
    assert_eq!(
        ids(&tide),
        [json!("hb-1"), serde_json::Value::Null, json!("hb-3")]
    );
    assert_eq!(
        tide["entries"][1],
        json!({"availability":"unavailable","position":null})
    );
    assert!(tide["next_cursor"].is_null());
    assert!(
        tide.get("webpage_url").is_none(),
        "the extractor reported no page"
    );
    assert!(!tide.to_string().contains("SECRET"));
    assert!(
        tide["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e.get("webpage_url").is_none())
    );
    let clip = inspect(
        "https://harbor.fixture.test/clip/hb-1",
        None,
        1,
        "fixture-harbor",
        &harbor,
        None,
    )
    .await;
    assert_eq!(clip["webpage_url"], "https://harbor.fixture.test/clip/hb-1");
    assert_eq!(clip["accessible"], true);
    assert!(!clip.to_string().contains("SECRET"));

    // Flat listings never resolved entry transport URLs.
    assert_eq!(
        *requests.lock().unwrap(),
        [
            "lantern.fixture.test/channel/lights",
            "lantern.fixture.test/channel/lights",
            "lantern.fixture.test/channel/lights",
            "lantern.fixture.test/watch/lv-1",
            "harbor.fixture.test/lists/tide",
            "harbor.fixture.test/clip/hb-1",
        ]
    );
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}
