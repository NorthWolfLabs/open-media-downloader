#![cfg(all(
    any(target_os = "macos", target_os = "linux", windows),
    feature = "fixture-tests"
))]
use omd_browser::{Action, Browser, Kit, Mode};
use omd_domain::HostGrant;
use omd_network::Network;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires pinned browser fixture kit and real native helper confinement"]
async fn browser_sign_in_crosses_policy_broker_and_exports_only_approved_cookies() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kit: Kit = serde_json::from_slice(
        &std::fs::read(
            std::env::var_os("OMD_TEST_BROWSER_KIT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| root.join("artifacts/browser-fixture-kit.json")),
        )
        .unwrap(),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(vec![]));
    let observed = calls.clone();
    let network = Network::new(0).with_native_fixture(move |url, method, headers, body| {
        observed.lock().unwrap().push((url.host_str().unwrap().to_owned(), url.path().to_owned(), method.to_string(), headers.get("cookie").map(|h| h.to_str().unwrap().to_owned())));
        if url.path() == "/session" && method == "POST" {
            assert_eq!(body, "account=fixture-account&password=fixture-password");
            return Ok(http::Response::builder().status(200).header("content-type", "text/html").header("set-cookie", "session=PRIVATE_BROWSER_COOKIE; Secure; HttpOnly; Path=/; Max-Age=3600").body(b"<h1>Account connected</h1><script>localStorage.setItem('account','PRIVATE_STORAGE_VALUE')</script>".to_vec()).unwrap());
        }
        if url.path() == "/account" {
            assert_eq!(headers["cookie"], "session=PRIVATE_BROWSER_COOKIE");
            // Reads page storage while parsing, before any later script could restore it.
            return Ok(http::Response::builder().status(200).header("content-type", "text/html").body(b"<h1>PRIVATE_BROWSER_COOKIE</h1><p id='s'></p><script>document.getElementById('s').textContent='storage:'+(localStorage.getItem('account')?'restored ':'missing ')+localStorage.getItem('account')</script>".to_vec()).unwrap());
        }
        Ok(http::Response::builder().status(200).header("content-type", "text/html").body(br#"<main><h1>Connect account</h1><form action='/session' method='post'><label>Account<input name='account'></label><label>Password<input name='password' type='password'></label><button>Sign in</button></form><img src='https://undeclared.example/track'></main>"#.to_vec()).unwrap())
    });
    let work = tempfile::tempdir().unwrap();
    let browser = Browser::new(kit, network, work.path().into());
    let grants = vec![HostGrant {
        request_intervals: Default::default(),
        id: "account".into(),
        hosts: vec!["fixture.example".into()],
        methods: vec!["GET".into(), "POST".into()],
        credential: true,
    }];
    let cancel = CancellationToken::new();
    let session = browser
        .start(
            "https://fixture.example/",
            grants.clone(),
            None,
            Mode::SignIn,
            &cancel,
        )
        .await
        .unwrap();
    assert!(session.action(Action::Snapshot, &cancel).await.is_err());
    for (selector, text) in [
        ("input[name=account]", "fixture-account"),
        ("input[name=password]", "fixture-password"),
    ] {
        session
            .action(
                Action::Fill {
                    selector: selector.into(),
                    text: text.into(),
                },
                &cancel,
            )
            .await
            .unwrap();
    }
    session
        .action(
            Action::Click {
                selector: "button".into(),
            },
            &cancel,
        )
        .await
        .unwrap();
    session
        .action(
            Action::Wait {
                selector: "h1".into(),
            },
            &cancel,
        )
        .await
        .unwrap();
    let credentials = session.credentials(&cancel).await.unwrap();
    assert_eq!(credentials.cookies.len(), 1);
    assert_eq!(credentials.cookies[0].value, "PRIVATE_BROWSER_COOKIE");
    assert!(credentials.cookies[0].http_only && credentials.cookies[0].secure);
    assert_eq!(credentials.origins.len(), 1);
    assert_eq!(credentials.origins[0].origin, "https://fixture.example");
    assert_eq!(
        credentials.origins[0].local_storage[0].value,
        "PRIVATE_STORAGE_VALUE"
    );
    assert!(!format!("{credentials:?}").contains("PRIVATE_BROWSER_COOKIE"));
    let frame = session.action(Action::Frame, &cancel).await.unwrap();
    assert!(frame["png"].as_str().unwrap().len() > 1000);
    drop(session);
    let source = browser
        .start(
            "https://fixture.example/account",
            grants,
            Some(credentials),
            Mode::Source,
            &cancel,
        )
        .await
        .unwrap();
    assert!(source.credentials(&cancel).await.is_err());
    assert!(source.action(Action::Frame, &cancel).await.is_err());
    let snapshot = source.action(Action::Snapshot, &cancel).await.unwrap();
    assert!(snapshot["text"].as_str().unwrap().contains("[redacted]"));
    assert!(
        snapshot["text"]
            .as_str()
            .unwrap()
            .contains("storage:restored [redacted]")
    );
    assert!(!snapshot.to_string().contains("PRIVATE_BROWSER_COOKIE"));
    assert!(!snapshot.to_string().contains("PRIVATE_STORAGE_VALUE"));
    assert!(
        calls
            .lock()
            .unwrap()
            .iter()
            .all(|(host, _, _, _)| host == "fixture.example")
    );
}
