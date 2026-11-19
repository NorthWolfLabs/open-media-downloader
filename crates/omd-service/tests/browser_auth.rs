#![cfg(all(
    any(target_os = "macos", target_os = "linux", windows),
    feature = "fixture-tests"
))]
use axum::{body::Body, http::Request};
use omd_credentials::{Backend, Error, Vault};
use omd_service::{App, router};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use zeroize::Zeroizing;
#[derive(Default)]
struct Memory {
    locked: AtomicBool,
    values: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
}
impl Backend for Memory {
    fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        self.values
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or(Error::Missing)
    }
    fn write(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(Error::Locked);
        }
        self.values
            .lock()
            .unwrap()
            .insert(key.into(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    fn remove(&self, key: &str) -> Result<(), Error> {
        self.values.lock().unwrap().remove(key);
        Ok(())
    }
}
#[tokio::test]
#[ignore = "requires the pinned browser kit and real native confinement"]
async fn independent_client_sign_in_keeps_identity_provider_secrets_out_of_vault_and_survives_locked_store()
 {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("helper-work")).unwrap();
    let store = omd_store::Store::open(&root.path().join("db"))
        .await
        .unwrap();
    let backend = Arc::new(Memory::default());
    let network=omd_network::Network::new(0).with_vault(Vault::with_backend("signin-fixture",backend.clone())).with_native_fixture(|url,method,headers,body|{
        let response=if url.host_str()==Some("login.fixture.example") {
            if method=="POST" {assert_eq!(body,"account=fixture&password=dummy-password");assert_eq!(headers["cookie"],"idp=PRIVATE_IDENTITY_COOKIE");(303,Some("https://fixture.example/done"),None,"")}
            else{(200,None,Some("idp=PRIVATE_IDENTITY_COOKIE; Secure; HttpOnly; Path=/; Max-Age=3600"),"<h1>Fixture login</h1><form method='post'><label>Account<input name='account'></label><label>Password<input name='password' type='password'></label><button>Connect</button></form>")}
        }else{assert_eq!(url.host_str(),Some("fixture.example"));(200,None,Some("session=PRIVATE_SOURCE_COOKIE; Secure; HttpOnly; Path=/; Max-Age=3600"),"<h1>Connected</h1>")};
        let mut result=axum::http::Response::builder().status(response.0).header("content-type","text/html");if let Some(location)=response.1{result=result.header("location",location);}
        if let Some(cookie)=response.2{result=result.header("set-cookie",cookie);}Ok(result.body(response.3.as_bytes().to_vec()).unwrap())
    });
    let runtime = omd_plugins::Runtime::new("unused-worker".into(), network.clone(), 1);
    let kit = omd_browser::packages::read_manifest(
        &std::path::PathBuf::from(
            std::env::var_os("OMD_TEST_BROWSER_KIT")
                .expect("Set OMD_TEST_BROWSER_KIT to the verified native browser manifest"),
        )
        .canonicalize()
        .unwrap(),
    )
    .await
    .unwrap();
    let reviewed = omd_browser::packages::review(&kit).await.unwrap();
    omd_browser::packages::install(
        &store,
        root.path(),
        &kit,
        &reviewed.digest,
        "Fixture browser",
    )
    .await
    .unwrap();
    let kit = omd_browser::packages::paths(root.path(), &reviewed).unwrap();
    runtime
        .register_browser(
            "fixture",
            omd_browser::Browser::new(kit, network.clone(), root.path().join("helper-work")),
        )
        .await;
    let manifest:omd_domain::ProviderManifest=serde_json::from_value(json!({"api":"omd:provider@2.0.0","id":"fixture.source","name":"Fixture","version":"1","description":"fixture","source_hosts":["fixture.example"],"capabilities":[],"grants":[{"id":"source","hosts":["fixture.example"],"methods":["GET"],"credential":true}],"sign_in":{"completion_cookies":["session"],"url":"https://login.fixture.example/","grants":[{"id":"identity","hosts":["login.fixture.example"],"methods":["GET","POST"],"credential":true}]}})).unwrap();
    let grants = manifest.grants.clone();
    let app = App {
        browser_sessions: Default::default(),
        source_changes: Arc::new(AsyncMutex::new(())),
        notification_lock: Arc::new(AsyncMutex::new(())),
        notification_adapter: root.path().join("unused"),
        sign_in_helper: root.path().join("unused-sign-in"),
        store: store.clone(),
        runtime,
        acquisition: omd_acquisition::Acquisition { store, network },
        profile: root.path().into(),
        token: "normal".into(),
        admin_token: "admin".into(),
        shutdown: CancellationToken::new(),
        providers: Arc::new(RwLock::new(BTreeMap::from([(
            "fixture.source".into(),
            omd_plugins::Provider {
                manifest,
                component: "unused".into(),
                digest: "fixture".into(),
            },
        )]))),
        running: Arc::new(AsyncMutex::new(BTreeMap::new())),
        clients: Arc::new(AsyncMutex::new(BTreeMap::new())),
    };
    let api = router(app.clone(), vec![]);
    let call = async |method: &str, path: &str, body: Value| {
        let response = api
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", "Bearer normal")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        if path.contains("sign-ins") || path.contains("credentials") {
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_"));
        (status, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    let (_, owner) = call("POST", "/v2/clients", json!({})).await;
    let owner = owner["id"].as_str().unwrap();
    let (_, other) = call("POST", "/v2/clients", json!({})).await;
    let other = other["id"].as_str().unwrap();
    let (status, session) = call(
        "POST",
        "/v2/sources/fixture.source/sign-ins",
        json!({"client":owner,"profile":"personal","label":"Fixture account"}),
    )
    .await;
    assert_eq!(status, 200, "{session}");
    let id = session["id"].as_str().unwrap();
    let actions = format!("/v2/sign-ins/{id}/actions");
    let status_path = format!("/v2/sign-ins/{id}/status");
    assert_eq!(
        call("POST", &status_path, json!({"client":other})).await.0,
        404
    );
    assert_eq!(
        call("POST", &status_path, json!({"client":owner})).await.1["ready"],
        false
    );
    let pending = call(
        "POST",
        &format!("/v2/sign-ins/{id}/complete"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(pending.0, 409);
    assert_eq!(pending.1["code"], "sign_in_pending");

    assert_eq!(
        call(
            "POST",
            &actions,
            json!({"client":other,"action":{"op":"frame"}})
        )
        .await
        .0,
        404
    );
    let (status, frame) = call(
        "POST",
        &actions,
        json!({"client":owner,"action":{"op":"frame"}}),
    )
    .await;
    assert_eq!(status, 200);
    let controls = frame["frame"]["controls"].as_array().unwrap();
    for (label, kind, text) in [
        ("Account", "fill", Some("fixture")),
        ("Password", "fill", Some("dummy-password")),
        ("Connect", "click", None),
    ] {
        let id = controls.iter().find(|c| c["label"] == label).unwrap()["id"].clone();
        let action = if kind == "fill" {
            json!({"kind":kind,"text":text})
        } else {
            json!({"kind":kind})
        };
        let (status, response) = call(
            "POST",
            &actions,
            json!({"client":owner,"action":{"op":"control","control":id,"action":action}}),
        )
        .await;
        assert_eq!(status, 200, "{response}");
    }
    assert_eq!(
        call("POST", &status_path, json!({"client":owner})).await.1["ready"],
        true
    );
    backend.locked.store(true, Ordering::SeqCst);
    let (status, problem) = call(
        "POST",
        &format!("/v2/sign-ins/{id}/complete"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(problem["code"], "credentials_locked");
    assert_eq!(
        call(
            "POST",
            &actions,
            json!({"client":owner,"action":{"op":"frame"}})
        )
        .await
        .0,
        200
    );
    backend.locked.store(false, Ordering::SeqCst);
    assert_eq!(
        call(
            "POST",
            &format!("/v2/sign-ins/{id}/complete"),
            json!({"client":owner})
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(
            "POST",
            &actions,
            json!({"client":owner,"action":{"op":"frame"}})
        )
        .await
        .0,
        404
    );
    let restarted = Vault::with_backend("signin-fixture", backend.clone());
    let saved = restarted
        .load("fixture.source", "personal", &grants)
        .await
        .unwrap();
    assert_eq!(saved.cookies.len(), 1);
    assert_eq!(saved.cookies[0].value, "PRIVATE_SOURCE_COOKIE");
    assert!(
        backend
            .values
            .lock()
            .unwrap()
            .values()
            .all(|bytes| !String::from_utf8_lossy(bytes).contains("PRIVATE_IDENTITY_COOKIE"))
    );
    let (_, accounts) = call("GET", "/v2/sources/fixture.source/credentials", Value::Null).await;
    assert_eq!(accounts["items"][0]["status"], "ready");
    assert_eq!(
        call(
            "DELETE",
            "/v2/sources/fixture.source/credentials/personal",
            Value::Null
        )
        .await
        .0,
        200
    );
    assert!(matches!(
        restarted.load("fixture.source", "personal", &grants).await,
        Err(Error::Missing)
    ));
    // Client departure must quiesce the native session before acknowledging it.
    let (status, detached) = call(
        "POST",
        "/v2/sources/fixture.source/sign-ins",
        json!({"client":other,"profile":"another","label":"Another account"}),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        call("DELETE", &format!("/v2/clients/{other}"), Value::Null)
            .await
            .0,
        200
    );
    assert_eq!(
        call(
            "POST",
            &format!("/v2/sign-ins/{}/actions", detached["id"].as_str().unwrap()),
            json!({"client":other,"action":{"op":"frame"}})
        )
        .await
        .0,
        404
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("helper-work"))
            .unwrap()
            .count(),
        0
    );
    let (status, expired) = call(
        "POST",
        "/v2/sources/fixture.source/sign-ins",
        json!({"client":owner,"profile":"expired","label":"Expired client"}),
    )
    .await;
    assert_eq!(status, 200);
    app.clients.lock().await.insert(
        owner.into(),
        tokio::time::Instant::now() - std::time::Duration::from_secs(46),
    );
    assert_eq!(
        call(
            "POST",
            &format!("/v2/sign-ins/{}/complete", expired["id"].as_str().unwrap()),
            json!({"client":owner})
        )
        .await
        .0,
        404
    );
    app.browser_sessions.prune(&Default::default()).await;
    assert_eq!(
        std::fs::read_dir(root.path().join("helper-work"))
            .unwrap()
            .count(),
        0
    );
    app.runtime.revoke_browser("fixture").await;
    assert_eq!(
        std::fs::read_dir(root.path().join("helper-work"))
            .unwrap()
            .count(),
        0
    );
}
