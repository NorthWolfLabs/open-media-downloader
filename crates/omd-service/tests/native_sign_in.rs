//! Native sign-in windows through the public API, with a scripted stand-in for
//! the `omd-signin` helper. The real window is covered by the helper crate and
//! by separate native acceptance; this checks the engine's side of the protocol.
#![cfg(unix)]
use axum::{body::Body, http::Request};
use omd_credentials::{Backend, Error, Vault};
use omd_service::{App, router};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
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
    fn write(&self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.0
            .lock()
            .unwrap()
            .insert(key.into(), Zeroizing::new(value.to_vec()));
        Ok(())
    }
    fn remove(&self, key: &str) -> Result<(), Error> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

const COMPLETED: &str = r#"{"status":"completed","session":{"expires_at":null,"cookies":[{"name":"session","value":"PRIVATE_SESSION","domain":"fixture.example","path":"/","host_only":true,"expires_at":null,"http_only":false,"same_site":"strict"},{"name":"idp","value":"PRIVATE_IDP","domain":"login.fixture.example","path":"/","host_only":true,"expires_at":null}],"headers":[],"origins":[{"origin":"https://fixture.example","local_storage":[{"name":"account","value":"PRIVATE_STORAGE_VALUE"}]},{"origin":"https://login.fixture.example","local_storage":[{"name":"idp","value":"PRIVATE_IDP_STORAGE"}]}]}}"#;

#[tokio::test]
async fn native_window_saves_only_source_credentials_and_reports_each_ending() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("helper-work")).unwrap();
    let mode = root.path().join("mode");
    let captured = root.path().join("request.json");
    let helper = root.path().join("omd-signin");
    // Records its request, confirms the private work folder exists, then
    // answers according to the scenario written to `mode`.
    std::fs::write(
        &helper,
        format!(
            "#!/bin/sh\ncat > '{captured}'\ndir=$(sed -n 's/.*\"data_directory\":\"\\([^\"]*\\)\".*/\\1/p' '{captured}')\ntest -d \"$dir\" || exit 9\ncase \"$(cat '{mode}')\" in\n completed) printf '%s\\n' '{COMPLETED}' ;;\n closed) printf '{{\"status\":\"closed\"}}\\n' ;;\n display) printf '{{\"status\":\"failed\",\"code\":\"display_unavailable\"}}\\n' ;;\n crash) exit 127 ;;\n open) exec sleep 30 ;;\nesac\n",
            captured = captured.display(),
            mode = mode.display(),
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();

    let store = omd_store::Store::open(&root.path().join("db"))
        .await
        .unwrap();
    let backend = Arc::new(Memory::default());
    let network = omd_network::Network::new(0)
        .with_vault(Vault::with_backend("native-signin", backend.clone()));
    let runtime = omd_plugins::Runtime::new("unused-worker".into(), network.clone(), 1);
    let manifest: omd_domain::ProviderManifest = serde_json::from_value(json!({"api":"omd:provider@2.0.0","id":"fixture.source","name":"Fixture","version":"1","description":"fixture","source_hosts":["fixture.example"],"capabilities":[],"grants":[{"id":"source","hosts":["fixture.example"],"methods":["GET"],"credential":true}],"sign_in":{"completion_cookies":["session"],"url":"https://login.fixture.example/","grants":[{"id":"identity","hosts":["login.fixture.example"],"methods":["GET","POST"],"credential":true}]}})).unwrap();
    let grants = manifest.grants.clone();
    let mut app = App {
        browser_sessions: Default::default(),
        source_changes: Arc::new(AsyncMutex::new(())),
        notification_lock: Arc::new(AsyncMutex::new(())),
        notification_adapter: root.path().join("unused"),
        sign_in_helper: helper.clone(),
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
    let call = async |app: &App, method: &str, path: &str, body: Value| {
        let response = router(app.clone(), vec![])
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
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_"));
        (status, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    let owner = call(&app, "POST", "/v2/clients", json!({})).await.1["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let start = async |app: &App, scenario: &str, profile: &str| {
        std::fs::write(&mode, scenario).unwrap();
        call(
            app,
            "POST",
            "/v2/sources/fixture.source/sign-ins",
            json!({"client":owner,"profile":profile,"label":"Fixture account","window":"native"}),
        )
        .await
    };
    let wait_ready = async |app: &App, id: &str| {
        for _ in 0..200 {
            let reply = call(
                app,
                "POST",
                &format!("/v2/sign-ins/{id}/status"),
                json!({"client":owner}),
            )
            .await;
            if reply.0 != 200 || reply.1["ready"] == true {
                return reply;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("sign-in did not finish");
    };

    // Completed: only the source's own cookie and page storage are saved.
    let (status, session) = start(&app, "completed", "personal").await;
    assert_eq!(status, 200, "{session}");
    assert_eq!(session["window"], "native");
    let id = session["id"].as_str().unwrap().to_owned();
    assert_eq!(wait_ready(&app, &id).await.1["ready"], true);
    let request: Value = serde_json::from_slice(&std::fs::read(&captured).unwrap()).unwrap();
    assert_eq!(request["url"], "https://login.fixture.example/");
    assert_eq!(request["title"], "Sign in to Fixture");
    assert_eq!(request["completion_cookies"], json!(["session"]));
    assert_eq!(request["grants"], serde_json::to_value(&grants).unwrap());
    assert_eq!(request["timeout_seconds"], 600);
    let denied = call(
        &app,
        "POST",
        &format!("/v2/sign-ins/{id}/actions"),
        json!({"client":owner,"action":{"op":"frame"}}),
    )
    .await;
    assert_eq!(denied.1["code"], "browser_operation_denied");
    let saved = call(
        &app,
        "POST",
        &format!("/v2/sign-ins/{id}/complete"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(saved.1, json!({"profile":"personal","saved":true}));
    let stored = Vault::with_backend("native-signin", backend.clone())
        .load("fixture.source", "personal", &grants)
        .await
        .unwrap();
    assert_eq!(stored.cookies.len(), 1);
    assert_eq!(stored.cookies[0].value, "PRIVATE_SESSION");
    assert!(!stored.cookies[0].http_only);
    assert_eq!(
        stored.cookies[0].same_site,
        Some(omd_credentials::SameSite::Strict)
    );
    assert_eq!(stored.origins.len(), 1);
    assert_eq!(stored.origins[0].origin, "https://fixture.example");
    assert_eq!(
        stored.origins[0].local_storage[0].value,
        "PRIVATE_STORAGE_VALUE"
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v2/sign-ins/{id}/status"),
            json!({"client":owner})
        )
        .await
        .0,
        404
    );

    // Each other ending is reported as an actionable problem.
    for (scenario, code) in [
        ("closed", "sign_in_closed"),
        ("display", "native_sign_in_unavailable"),
        ("crash", "native_sign_in_unavailable"),
    ] {
        let (status, session) = start(&app, scenario, "other").await;
        assert_eq!(status, 200, "{session}");
        let reply = wait_ready(&app, session["id"].as_str().unwrap()).await;
        assert_eq!(reply.0, 409, "{scenario}");
        assert_eq!(reply.1["code"], code, "{scenario}");
        let id = session["id"].as_str().unwrap();
        call(
            &app,
            "POST",
            &format!("/v2/sign-ins/{id}/close"),
            json!({"client":owner}),
        )
        .await;
    }

    // An open window stays pending, and closing the session ends the helper
    // and removes its private work folder.
    let (_, session) = start(&app, "open", "other").await;
    let id = session["id"].as_str().unwrap().to_owned();
    let pending = call(
        &app,
        "POST",
        &format!("/v2/sign-ins/{id}/status"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(pending.1["ready"], false);
    let early = call(
        &app,
        "POST",
        &format!("/v2/sign-ins/{id}/complete"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(early.1["code"], "sign_in_pending");
    let closed = call(
        &app,
        "POST",
        &format!("/v2/sign-ins/{id}/close"),
        json!({"client":owner}),
    )
    .await;
    assert_eq!(closed.1, json!({"closed":true}));
    let leftovers = std::fs::read_dir(root.path().join("helper-work"))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("signin-"))
        .count();
    assert_eq!(leftovers, 0);

    // A missing helper is reported before any session is created.
    app.sign_in_helper = root.path().join("absent");
    let (status, problem) = start(&app, "completed", "other").await;
    assert_eq!(status, 409);
    assert_eq!(problem["code"], "native_sign_in_unavailable");
}
