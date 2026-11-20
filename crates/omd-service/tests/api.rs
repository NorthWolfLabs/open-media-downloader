#[path = "../../../tests/support/worker.rs"]
mod worker;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use omd_acquisition::Acquisition;
use omd_network::Network;
use omd_plugins::Runtime;
use omd_service::{App, router};
use omd_store::Store;
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

async fn setup() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(&root.path().join("test.sqlite3"))
        .await
        .unwrap();
    let network = Network::new(0);
    let app = App {
        browser_sessions: Default::default(),
        source_changes: Arc::new(Mutex::new(())),
        notification_lock: Arc::new(Mutex::new(())),
        notification_adapter: root.path().join("missing-notification-fixture"),
        sign_in_helper: root.path().join("missing-sign-in-fixture"),
        store: store.clone(),
        runtime: Runtime::new("unused-worker".into(), network.clone(), 1),
        acquisition: Acquisition { store, network },
        profile: root.path().into(),
        token: "normal".into(),
        admin_token: "admin".into(),
        shutdown: CancellationToken::new(),
        providers: Arc::new(RwLock::new(BTreeMap::new())),
        running: Arc::new(Mutex::new(BTreeMap::new())),
        clients: Default::default(),
    };
    (root, app)
}
#[tokio::test]
async fn app_upgrades_replace_the_included_tools_but_keep_a_chosen_set() {
    use omd_domain::digest;
    let (root, app) = setup().await;
    let toolkit = |version: &str| {
        let input = root.path().join(format!("kit-{version}"));
        std::fs::create_dir(&input).unwrap();
        let tool = |name: &str| {
            let bytes = format!("{name}-{version}");
            let path = input.join(name);
            std::fs::write(&path, &bytes).unwrap();
            omd_media::Tool {
                path,
                sha256: digest(bytes.as_bytes()),
                version: version.into(),
            }
        };
        let tools = omd_media::Tools {
            yt_dlp: tool("yt_dlp"),
            node: Some(tool("node")),
            ffmpeg: Some(tool("ffmpeg")),
            ffprobe: Some(tool("ffprobe")),
        };
        let path = input.join("tools.json");
        std::fs::write(&path, serde_json::to_vec(&tools).unwrap()).unwrap();
        (path, tools)
    };
    let start = async |manifest: &std::path::Path| {
        omd_service::tools::initialize(
            &app.store,
            &app.profile,
            &app.acquisition.network,
            &app.runtime,
            Some(manifest),
        )
        .await
        .unwrap();
        let active: Option<String> =
            sqlx::query_scalar("SELECT digest FROM managed_tool_active WHERE singleton=1")
                .fetch_one(&app.store.pool)
                .await
                .unwrap();
        active
    };
    let digest_of = async |tools: &omd_media::Tools| omd_tools::review(tools).await.unwrap().digest;
    let (one, one_tools) = toolkit("one");
    let (two, two_tools) = toolkit("two");
    let (_, chosen_tools) = toolkit("chosen");
    let (three, three_tools) = toolkit("three");
    let (four, four_tools) = toolkit("four");
    let (five, _) = toolkit("five");
    let (six, _) = toolkit("six");
    let forget_previous = async |recorded: serde_json::Value| {
        app.store
            .set_setting("bundled_tools_review", &recorded)
            .await
            .unwrap();
    };
    // First run and an upgrade that still uses the included set.
    assert_eq!(start(&one).await, Some(digest_of(&one_tools).await));
    assert_eq!(start(&one).await, Some(digest_of(&one_tools).await));
    assert_eq!(start(&two).await, Some(digest_of(&two_tools).await));
    // An even older app installed the active set automatically, so this
    // profile has no matching record of it: no record at all, or a record of
    // a different included set that was never adopted. The engine's own
    // included label still identifies it, and the upgrade replaces it.
    forget_previous(serde_json::Value::Null).await;
    assert_eq!(start(&three).await, Some(digest_of(&three_tools).await));
    forget_previous(serde_json::json!({"digest": "sha256:never-adopted"})).await;
    assert_eq!(start(&four).await, Some(digest_of(&four_tools).await));
    let included: String = sqlx::query_scalar(
        "SELECT t.label FROM managed_tool_sets t JOIN managed_tool_active a ON a.digest=t.digest",
    )
    .fetch_one(&app.store.pool)
    .await
    .unwrap();
    assert_eq!(included, "Included media tools");
    // A set the person chose survives the next upgrade.
    let chosen_digest = digest_of(&chosen_tools).await;
    omd_tools::install(
        &app.store,
        &app.profile,
        &chosen_tools,
        &chosen_digest,
        "Mine",
    )
    .await
    .unwrap();
    omd_tools::activate(&app.store, &app.profile, &chosen_digest)
        .await
        .unwrap();
    assert_eq!(start(&five).await, Some(chosen_digest.clone()));
    // Without a matching record the chosen label still keeps it.
    forget_previous(serde_json::json!({"digest": "sha256:never-adopted"})).await;
    assert_eq!(start(&six).await, Some(chosen_digest.clone()));
    // A removal is kept too: no set becomes active again by itself.
    omd_tools::begin_removal(&app.store, &chosen_digest)
        .await
        .unwrap();
    forget_previous(serde_json::Value::Null).await;
    assert_eq!(start(&one).await, None);
}
/// Activating an earlier included set is a choice: app restarts and upgrades
/// keep it, although it carries the included label. Activating the set the
/// app includes again hands upgrades back to the engine.
#[tokio::test]
async fn an_explicit_rollback_to_an_earlier_included_set_survives_upgrades() {
    use omd_domain::digest;
    let (root, app) = setup().await;
    let toolkit = |version: &str| {
        let input = root.path().join(format!("kit-{version}"));
        std::fs::create_dir(&input).unwrap();
        let tool = |name: &str| {
            let bytes = format!("{name}-{version}");
            let path = input.join(name);
            std::fs::write(&path, &bytes).unwrap();
            omd_media::Tool {
                path,
                sha256: digest(bytes.as_bytes()),
                version: version.into(),
            }
        };
        let tools = omd_media::Tools {
            yt_dlp: tool("yt_dlp"),
            node: Some(tool("node")),
            ffmpeg: Some(tool("ffmpeg")),
            ffprobe: Some(tool("ffprobe")),
        };
        let path = input.join("tools.json");
        std::fs::write(&path, serde_json::to_vec(&tools).unwrap()).unwrap();
        (path, tools)
    };
    let start = async |manifest: &std::path::Path| {
        omd_service::tools::initialize(
            &app.store,
            &app.profile,
            &app.acquisition.network,
            &app.runtime,
            Some(manifest),
        )
        .await
        .unwrap();
        let active: Option<String> =
            sqlx::query_scalar("SELECT digest FROM managed_tool_active WHERE singleton=1")
                .fetch_one(&app.store.pool)
                .await
                .unwrap();
        active
    };
    let api = router(app.clone(), vec![]);
    let admin = async |uri: String, body: serde_json::Value| {
        let response = api
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("Authorization", "Bearer admin")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    };
    let activate =
        async |id: &str| admin(format!("/v2/tools/{id}/activate"), serde_json::json!({})).await;
    let digest_of = async |tools: &omd_media::Tools| omd_tools::review(tools).await.unwrap().digest;
    let (one, one_tools) = toolkit("one");
    let (two, two_tools) = toolkit("two");
    let (three, three_tools) = toolkit("three");
    let (four, four_tools) = toolkit("four");
    let one_digest = digest_of(&one_tools).await;
    // A profile that never chose follows each included set.
    assert_eq!(start(&one).await, Some(one_digest.clone()));
    assert_eq!(start(&two).await, Some(digest_of(&two_tools).await));
    // The person rolls back to the earlier included set. The next start of
    // the same app, and an upgrade, keep it.
    activate(&one_digest).await;
    let label: String = sqlx::query_scalar(
        "SELECT t.label FROM managed_tool_sets t JOIN managed_tool_active a ON a.digest=t.digest",
    )
    .fetch_one(&app.store.pool)
    .await
    .unwrap();
    assert_eq!(label, "Included media tools");
    assert_eq!(start(&two).await, Some(one_digest.clone()));
    assert_eq!(start(&three).await, Some(one_digest.clone()));
    // The upgrade only offered its included set for review. Installing and
    // activating it returns the profile to the included sets.
    let three_digest = digest_of(&three_tools).await;
    admin(
        "/v2/tools/install".into(),
        serde_json::json!({"label": "Included media tools", "approve_digest": three_digest}),
    )
    .await;
    activate(&three_digest).await;
    assert_eq!(
        app.store.setting("chosen_tools").await.unwrap(),
        Some(serde_json::Value::Null)
    );
    assert_eq!(start(&four).await, Some(digest_of(&four_tools).await));
}
#[tokio::test]
async fn reviewed_tool_updates_revoke_stale_adapters_and_keep_pinned_versions() {
    use omd_domain::{MediaSelection, Plan, digest};
    let (root, app) = setup().await;
    let toolkit = |version: &str| {
        let input = root.path().join(version);
        std::fs::create_dir(&input).unwrap();
        let tool = |name: &str| {
            let bytes = format!("{name}-{version}");
            let path = input.join(name);
            std::fs::write(&path, &bytes).unwrap();
            omd_media::Tool {
                path,
                sha256: digest(bytes.as_bytes()),
                version: version.into(),
            }
        };
        let tools = omd_media::Tools {
            yt_dlp: tool("yt_dlp"),
            node: Some(tool("node")),
            ffmpeg: Some(tool("ffmpeg")),
            ffprobe: Some(tool("ffprobe")),
        };
        let path = input.join("tools.json");
        std::fs::write(&path, serde_json::to_vec(&tools).unwrap()).unwrap();
        (path, tools)
    };
    let (path, a) = toolkit("one");
    let (other_path, _) = toolkit("two");
    let api = router(app.clone(), vec![]);
    let call = async |method: &str, path: &str, body: serde_json::Value, admin: bool| {
        let response = api
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(
                        "Authorization",
                        if admin {
                            "Bearer admin"
                        } else {
                            "Bearer normal"
                        },
                    )
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        )
    };
    assert_eq!(
        call(
            "POST",
            "/v2/tools/install",
            serde_json::json!({"manifest_path":path,"label":"First"}),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, review) = call(
        "POST",
        "/v2/tools/install",
        serde_json::json!({"manifest_path":path,"label":"First"}),
        true,
    )
    .await;
    assert_eq!(review["review_required"], true);
    let id = review["review"]["digest"].as_str().unwrap().to_owned();
    let (_, installed) = call(
        "POST",
        "/v2/tools/install",
        serde_json::json!({"manifest_path":path,"label":"First","approve_digest":id}),
        true,
    )
    .await;
    assert_eq!(installed["review_required"], false);
    let removal_approval = installed["installed"]["approval_digest"].clone();
    assert_eq!(
        call(
            "POST",
            &format!("/v2/tools/{id}/activate"),
            serde_json::json!({}),
            true
        )
        .await
        .0,
        StatusCode::OK
    );
    let stale = app.runtime.media().unwrap();
    let selection = MediaSelection {
        source_signature: "signature".into(),
        selected_height: Some(240),
        duration_ms: Some(1000),
        format_ids: vec!["one".into()],
        subtitles: vec![],
        yt_dlp_digest: a.yt_dlp.sha256.clone(),
        ffmpeg_digest: a.ffmpeg.as_ref().unwrap().sha256.clone(),
        ffprobe_digest: a.ffprobe.as_ref().unwrap().sha256.clone(),
        node_digest: a.node.as_ref().map(|t| t.sha256.clone()),
    };
    let mut plan: Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    plan.media = Some(selection.clone());
    let dest = app
        .store
        .add_destination("Files", root.path())
        .await
        .unwrap();
    let (job, _) = app
        .store
        .enqueue(&plan, &dest.id, "tool-test", "tool-test", None)
        .await
        .unwrap();
    let (_, other) = call(
        "POST",
        "/v2/tools/install",
        serde_json::json!({"manifest_path":other_path,"label":"Second"}),
        true,
    )
    .await;
    let other_id = other["review"]["digest"].as_str().unwrap();
    call(
        "POST",
        "/v2/tools/install",
        serde_json::json!({"manifest_path":other_path,"label":"Second","approve_digest":other_id}),
        true,
    )
    .await;
    call(
        "POST",
        &format!("/v2/tools/{other_id}/activate"),
        serde_json::json!({}),
        true,
    )
    .await;
    assert!(app.runtime.media_for(&selection).is_some());
    assert_ne!(
        app.runtime.media().unwrap().tools.yt_dlp.sha256,
        selection.yt_dlp_digest
    );
    let (_, review) = call(
        "POST",
        &format!("/v2/tools/{id}/remove"),
        serde_json::json!({}),
        true,
    )
    .await;
    assert_eq!(review["affected_jobs"], 1);
    let (status, result) = call(
        "POST",
        &format!("/v2/tools/{id}/remove"),
        serde_json::json!({"approve_digest":removal_approval}),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["review_required"], false);
    assert!(stale.revoked.is_cancelled());
    assert!(app.runtime.media_for(&selection).is_none());
    assert!(app.runtime.media().is_some());
    assert_eq!(
        app.store.job(&job.id).await.unwrap().state,
        omd_domain::JobState::Paused
    );
    let denied = stale
        .inspect(
            &omd_media::Inspect {
                url: "https://example.com/".into(),
                cursor: None,
                page_size: 1,
            },
            "fixture",
            &[],
            None,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code, "tool_removed");
    assert_eq!(
        call(
            "POST",
            &format!("/v2/tools/{id}/retry-cleanup"),
            serde_json::json!({}),
            true
        )
        .await
        .1["state"],
        "removed"
    );
    call(
        "POST",
        "/v2/tools/install",
        serde_json::json!({"manifest_path":path,"label":"First","approve_digest":id}),
        true,
    )
    .await;
    assert_eq!(
        call(
            "POST",
            &format!("/v2/tools/{id}/remove"),
            serde_json::json!({"approve_digest":removal_approval}),
            true
        )
        .await
        .1["review_required"],
        true
    );
    assert_eq!(
        call("GET", "/v2/tools?q=First", serde_json::json!({}), false)
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn normal_clients_can_manage_resumable_destination_checks() {
    let (root, app) = setup().await;
    let directory = root.path().join("downloads");
    std::fs::create_dir(&directory).unwrap();
    let destination = app
        .store
        .add_destination("Saved manga", &directory)
        .await
        .unwrap();
    let plan: omd_domain::Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    let (job, _) = app
        .store
        .enqueue(&plan, &destination.id, "fixture", "fixture", None)
        .await
        .unwrap();
    app.store.complete(&job.id, &[]).await.unwrap();
    let router = router(app, vec![]);
    let call = async |method: &str, path: &str| {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    };
    let result = call(
        "POST",
        &format!("/v2/destinations/{}/check", destination.id),
    )
    .await;
    let id = result["id"].as_str().unwrap();
    assert_eq!(result["jobs"], 1);
    assert_eq!(
        call(
            "POST",
            &format!("/v2/destinations/{}/check", destination.id)
        )
        .await["id"],
        id
    );
    assert_eq!(
        call("GET", "/v2/destination-checks?q=Saved").await["items"][0]["id"],
        id
    );
    assert_eq!(
        call("GET", &format!("/v2/destination-checks/{id}/files")).await["items"],
        serde_json::json!([])
    );
    for (action, state) in [
        ("pause", "paused"),
        ("resume", "working"),
        ("retry", "working"),
        ("cancel", "canceled"),
    ] {
        assert_eq!(
            call("POST", &format!("/v2/destination-checks/{id}/{action}")).await["state"],
            state
        );
    }
    assert_eq!(
        call("GET", &format!("/v2/destination-checks/{id}")).await["state"],
        "canceled"
    );
}
#[tokio::test]
async fn reviewed_source_removal_recovers_cleanup_without_deleting_reapproved_or_changed_bytes() {
    use omd_credentials::{Backend, Error};
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;
    #[derive(Default)]
    struct Memory {
        data: std::sync::Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
        locked: AtomicBool,
    }
    impl Backend for Memory {
        fn read(&self, key: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
            self.data
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or(Error::Missing)
        }
        fn write(&self, key: &str, value: &[u8]) -> Result<(), Error> {
            self.data
                .lock()
                .unwrap()
                .insert(key.into(), Zeroizing::new(value.to_vec()));
            Ok(())
        }
        fn remove(&self, key: &str) -> Result<(), Error> {
            if self.locked.load(Ordering::SeqCst) {
                return Err(Error::Locked);
            }
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
    }
    for scenario in [
        "unlink-before-record",
        "modified",
        "reapproved",
        "outside-profile",
    ] {
        let (_root, mut app) = setup().await;
        let backend = Arc::new(Memory::default());
        let vault = omd_credentials::Vault::with_backend("fixture", backend.clone());
        app.acquisition.network = Network::new(0).with_vault(vault.clone());
        let manifest:omd_domain::ProviderManifest=serde_json::from_value(serde_json::json!({"api":"omd:provider@2","id":"source.removal","name":"Removal fixture","version":"1","description":"fixture","source_hosts":["example.com"],"capabilities":["search"],"grants":[{"id":"account","hosts":["example.com"],"methods":["GET"],"credential":true}]})).unwrap();
        let bytes = b"fixture component bytes; never executed";
        let digest = omd_plugins::package_digest(&manifest, bytes);
        let folder = app.profile.join("providers").join(&digest);
        std::fs::create_dir_all(&folder).unwrap();
        let path = folder.join("plugin.wasm");
        std::fs::write(&path, bytes).unwrap();
        std::fs::write(folder.join("user-note.txt"), b"preserve me").unwrap();
        app.store
            .install_provider(&manifest, &digest, path.to_str().unwrap())
            .await
            .unwrap();
        app.providers.write().await.insert(
            manifest.id.clone(),
            omd_plugins::Provider {
                manifest: manifest.clone(),
                component: path.clone(),
                digest: digest.clone(),
            },
        );
        let session = omd_credentials::Session {
            expires_at: None,
            origins: vec![],
            cookies: vec![],
            headers: vec![omd_credentials::Header {
                origin: "https://example.com".into(),
                name: "authorization".into(),
                value: "Bearer PRIVATE_FIXTURE".into(),
            }],
        };
        vault
            .save(&manifest.id, "personal", &session, &manifest.grants)
            .await
            .unwrap();
        sqlx::query("INSERT INTO credential_profiles VALUES(?,'personal','Personal',?)")
            .bind(&manifest.id)
            .bind(omd_store::now())
            .execute(&app.store.pool)
            .await
            .unwrap();
        let router = router(app.clone(), vec![]);
        let call = async |token: &str, body: serde_json::Value| {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v2/sources/source.removal/remove")
                        .header("Authorization", format!("Bearer {token}"))
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE_FIXTURE"));
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        };
        assert_eq!(
            call("normal", serde_json::json!({})).await.0,
            StatusCode::FORBIDDEN
        );
        let (status, review) = call("admin", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(review["review"]["accounts"], 1);
        let (status, result) = call(
            "admin",
            serde_json::json!({"approve_digest":review["review"]["approval_digest"]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let id = result["operation"]["id"].as_str().unwrap();
        assert!(app.providers.read().await.is_empty());
        backend.locked.store(true, Ordering::SeqCst);
        let operation = app.store.source_removal(id).await.unwrap();
        let issue = omd_service::source_removals::step(&app, &operation)
            .await
            .unwrap_err();
        assert_eq!(issue.code, "credentials_locked");
        app.store
            .source_removal_issue(id, Some(&issue))
            .await
            .unwrap();
        assert_eq!(app.store.source_removal(id).await.unwrap().processed, 0);
        backend.locked.store(false, Ordering::SeqCst);
        app.store.source_removal_issue(id, None).await.unwrap();
        match scenario {
            "unlink-before-record" => std::fs::remove_file(&path).unwrap(),
            "modified" => std::fs::write(&path, b"a user modification").unwrap(),
            "reapproved" => {
                app.store
                    .install_provider(&manifest, &digest, path.to_str().unwrap())
                    .await
                    .unwrap();
                app.runtime.restore(&manifest.id, &digest);
            }
            "outside-profile" => {
                sqlx::query("UPDATE provider_versions SET component_path=? WHERE provider_id=?")
                    .bind(folder.join("user-note.txt").to_str().unwrap())
                    .bind(&manifest.id)
                    .execute(&app.store.pool)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        for _ in 0..2 {
            let operation = app.store.source_removal(id).await.unwrap();
            omd_service::source_removals::step(&app, &operation)
                .await
                .unwrap();
        }
        let done = app.store.source_removal(id).await.unwrap();
        assert_eq!(done.state, "complete");
        assert_eq!(done.processed, 2);
        assert_eq!(
            std::fs::read(folder.join("user-note.txt")).unwrap(),
            b"preserve me"
        );
        assert_eq!(
            done.retained,
            match scenario {
                "unlink-before-record" => 0,
                "reapproved" => 2,
                _ => 1,
            }
        );
        if scenario == "reapproved" {
            assert!(
                vault
                    .load(&manifest.id, "personal", &manifest.grants)
                    .await
                    .is_ok()
            );
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        } else {
            assert!(matches!(
                vault.load(&manifest.id, "personal", &manifest.grants).await,
                Err(Error::Missing)
            ));
        }
    }
}
#[tokio::test]
async fn normal_shell_permissions_cover_queries_and_preferences_but_not_installation() {
    let (_root, app) = setup().await;
    let router = router(app, vec!["tauri://localhost".parse().unwrap()]);
    for (method, path, body, expected) in [
        ("GET", "/v2/sources", "", StatusCode::OK),
        ("GET", "/v2/jobs", "", StatusCode::OK),
        (
            "PATCH",
            "/v2/settings",
            r#"{"background":false,"languages":["en"]}"#,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v2/sources/install",
            r#"{"package_path":"x","approve_digest":null}"#,
            StatusCode::FORBIDDEN,
        ),
        ("POST", "/v2/service/shutdown", "", StatusCode::FORBIDDEN),
        (
            "POST",
            "/v2/sources/example/activate",
            r#"{"digest":"unknown"}"#,
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {path}");
    }
}
#[tokio::test]
async fn sse_reconnect_preflight_accepts_last_event_id() {
    let (_root, app) = setup().await;
    let router = router(app, vec!["tauri://localhost".parse().unwrap()]);
    let response = router
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v2/events")
                .header("Origin", "tauri://localhost")
                .header("Access-Control-Request-Method", "GET")
                .header(
                    "Access-Control-Request-Headers",
                    "authorization,last-event-id",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert!(
        response.headers()["access-control-allow-headers"]
            .to_str()
            .unwrap()
            .contains("last-event-id")
    );
}
#[tokio::test]
async fn each_declared_operation_enforces_its_exact_normal_client_scope() {
    for operation in omd_service::OPERATIONS {
        let (root, app) = setup().await;
        if operation.path == "/v2/destinations/default" {
            let destination = root.path().join("downloads");
            std::fs::create_dir(&destination).unwrap();
            app.store
                .add_destination("Fixture downloads", &destination)
                .await
                .unwrap();
        }
        let path = operation
            .path
            .replace("{id}", "absent")
            .replace("{artifact}", "absent")
            .replace("{action}", "retry");
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            router(app, vec![]).oneshot(
                Request::builder()
                    .method(operation.method)
                    .uri(&path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            ),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "operation timed out: {} {}",
                operation.method, operation.path
            )
        })
        .unwrap();
        assert_eq!(
            response.status() == StatusCode::FORBIDDEN,
            operation.scope == "admin",
            "{} {}",
            operation.method,
            operation.path
        );
    }
}
#[tokio::test]
async fn configuration_lists_enumerate_more_than_two_hundred_items_and_filter() {
    let (root, app) = setup().await;
    for index in 0..251 {
        let mut manifest: omd_domain::ProviderManifest =
            serde_json::from_str(include_str!("../../../tests/v2-provider/omd-plugin.json"))
                .unwrap();
        manifest.id = format!("org.example.provider{index:03}");
        manifest.name = format!("Provider {index:03}");
        app.providers.write().await.insert(
            manifest.id.clone(),
            omd_plugins::Provider {
                manifest,
                component: "unused".into(),
                digest: "fixture".into(),
            },
        );
        let folder = root.path().join(format!("folder-{index}"));
        std::fs::create_dir(&folder).unwrap();
        app.store
            .add_destination(&format!("Destination {index:03}"), &folder)
            .await
            .unwrap();
    }
    let router = router(app, vec![]);
    for resource in ["sources", "destinations"] {
        let mut cursor = None::<String>;
        let mut count = 0;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let uri = format!(
                "/v2/{resource}?limit=73&cursor={}",
                cursor.as_deref().unwrap_or("")
            );
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("Authorization", "Bearer normal")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            for item in page["items"].as_array().unwrap() {
                let id = item
                    .get("id")
                    .or_else(|| item["manifest"].get("id"))
                    .unwrap()
                    .as_str()
                    .unwrap();
                assert!(seen.insert(id.to_owned()));
                count += 1;
            }
            cursor = page["next_cursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(count, 251);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v2/{resource}?q=249"))
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap();
        let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(page["items"].as_array().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn malformed_requests_and_unknown_operations_return_redacted_structured_errors() {
    let (_root, app) = setup().await;
    let router = router(app, vec![]);
    for (method, path, content, body, expected) in [
        (
            "POST",
            "/v2/preparations",
            "application/json",
            "{secret",
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/v2/preparations",
            "application/json",
            "{\"releases\":\"secret\"}",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "GET",
            "/v2/jobs?limit=secret",
            "application/json",
            "",
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/v2/preparations",
            "text/plain",
            "secret",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "GET",
            "/v2/absent",
            "application/json",
            "",
            StatusCode::NOT_FOUND,
        ),
        (
            "PUT",
            "/v2/settings",
            "application/json",
            "{}",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer admin")
                    .header("Content-Type", content)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {path}");
        assert_eq!(response.headers()["content-type"], "application/json");
        let bytes = axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap();
        let issue: omd_domain::Problem = serde_json::from_slice(&bytes).unwrap();
        assert!(!issue.message.contains("secret"));
        assert!(!issue.code.is_empty());
    }
}
#[tokio::test]
async fn impossible_cursor_requires_resynchronization() {
    let (_root, app) = setup().await;
    let response = router(app, vec![])
        .oneshot(
            Request::builder()
                .uri("/v2/events?cursor=9999999")
                .header("Authorization", "Bearer normal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}
#[tokio::test]
async fn expired_event_cursor_requires_resynchronization() {
    let (_root, app) = setup().await;
    for n in 0..3 {
        app.store
            .set_setting("test", &serde_json::json!(n))
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM events WHERE id<3")
        .execute(&app.store.pool)
        .await
        .unwrap();
    let router = router(app, vec![]);
    for (cursor, expected) in [(0, StatusCode::CONFLICT), (2, StatusCode::OK)] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v2/events?cursor={cursor}"))
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}
#[tokio::test]
async fn published_acquisition_recovers_even_when_its_provider_is_missing() {
    let (root, app) = setup().await;
    let plan: omd_domain::Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    let dest = app
        .store
        .add_destination("Files", root.path())
        .await
        .unwrap();
    let (job, _) = app
        .store
        .enqueue(&plan, &dest.id, "recovery", "recovery", None)
        .await
        .unwrap();
    let plan = &job.plan;
    let final_dir = root.path().join(&plan.final_relative_path);
    std::fs::create_dir_all(&final_dir).unwrap();
    let mut artifacts = vec![];
    for name in omd_acquisition::final_outputs(plan) {
        std::fs::write(final_dir.join(&name), b"verified bytes").unwrap();
        artifacts.push(omd_domain::Artifact {
            id: omd_store::id("artifact"),
            job_id: job.id.clone(),
            relative_path: format!("{}/{name}", plan.final_relative_path),
            size: 14,
            sha256: omd_domain::digest(b"verified bytes"),
            media_type: "application/octet-stream".into(),
            status: omd_domain::FileStatus::Present,
        });
    }
    app.store
        .journal_publication(
            &job.id,
            &serde_json::json!({"final_path":plan.final_relative_path,"artifacts":artifacts}),
        )
        .await
        .unwrap();
    // This app has no installed source and an unusable worker executable.
    let runner = tokio::spawn(omd_service::run_jobs(app.clone()));
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let job = app.store.job(&job.id).await.unwrap();
            if job.state == omd_domain::JobState::Completed {
                break;
            }
            assert_ne!(job.state, omd_domain::JobState::Failed, "{:?}", job.issue);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    app.shutdown.cancel();
    runner.await.unwrap();
    assert_eq!(app.store.artifacts(&job.id).await.unwrap().len(), 3);
}
#[tokio::test]
async fn multiple_frontends_receive_independent_leases() {
    let (_root, app) = setup().await;
    let router = router(app.clone(), vec![]);
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/clients")
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert_eq!(app.clients.lock().await.len(), 2);
}

/// With background operation off, the last client to leave decides whether
/// the engine finishes its downloads first. The desktop attaches as before, so
/// quitting it still stops the engine with downloads queued; the CLI and MCP
/// attach with `finish_downloads`, so a download they submitted is not cut off
/// when they leave.
#[tokio::test]
async fn only_a_client_that_asks_keeps_the_engine_up_for_downloads_after_it_leaves() {
    let (root, app) = setup().await;
    let http = router(app.clone(), vec![]);
    let call = async |method: &str, uri: String| {
        let response = http
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
    };
    let attach = async |finish: Option<&str>| {
        let lease = call(
            "POST",
            match finish {
                Some(value) => format!("/v2/clients?finish_downloads={value}"),
                None => "/v2/clients".into(),
            },
        )
        .await;
        assert_eq!(lease["lease_seconds"], 45);
        (
            lease["id"].as_str().unwrap().to_owned(),
            lease["finish_downloads"].as_bool().unwrap(),
        )
    };
    let detach = async |id: &str| {
        call("DELETE", format!("/v2/clients/{id}")).await;
    };
    let expire = async |id: &str| {
        app.clients.lock().await.leases.get_mut(id).unwrap().seen =
            tokio::time::Instant::now() - std::time::Duration::from_secs(46);
    };
    let idle = std::time::Duration::from_secs(61);
    let due = async || omd_service::idle_exit_due(&app, idle).await;
    let plan: omd_domain::Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    let destination = app
        .store
        .add_destination("Files", root.path())
        .await
        .unwrap();
    let (job, _) = app
        .store
        .enqueue(&plan, &destination.id, "queued", "queued", None)
        .await
        .unwrap();
    assert!(app.store.has_unfinished_downloads().await.unwrap());
    // Nobody attached yet: after its first minute the engine stops as before.
    assert!(!omd_service::idle_exit_due(&app, std::time::Duration::from_secs(30)).await);
    assert!(due().await);
    // The desktop attaches without the option; quitting it stops the engine
    // although a download is queued, whether it detaches or its lease expires.
    let (desktop, finishing) = attach(None).await;
    assert!(!finishing);
    assert!(!due().await);
    detach(&desktop).await;
    assert!(due().await);
    let (desktop, finishing) = attach(Some("false")).await;
    assert!(!finishing);
    expire(&desktop).await;
    assert!(due().await);
    assert!(app.clients.lock().await.is_empty());
    // A CLI command attaches with it: after it leaves, the queued download
    // keeps the engine up, whether it detached or its lease expired.
    let (command, finishing) = attach(Some("true")).await;
    assert!(finishing);
    detach(&command).await;
    assert!(!due().await);
    let (command, _) = attach(Some("true")).await;
    expire(&command).await;
    assert!(!due().await);
    // With both attached, the one that leaves last decides.
    let (command, _) = attach(Some("true")).await;
    let (desktop, _) = attach(None).await;
    detach(&command).await;
    assert!(!due().await);
    detach(&desktop).await;
    assert!(due().await);
    let (desktop, _) = attach(None).await;
    let (command, _) = attach(Some("true")).await;
    detach(&desktop).await;
    detach(&command).await;
    assert!(!due().await);
    // Leases that expire together: the most recently seen client decides.
    let (desktop, _) = attach(None).await;
    let (command, _) = attach(Some("true")).await;
    expire(&command).await;
    expire(&desktop).await;
    app.clients
        .lock()
        .await
        .leases
        .get_mut(&desktop)
        .unwrap()
        .seen -= std::time::Duration::from_secs(1);
    assert!(!due().await);
    let (desktop, _) = attach(None).await;
    let (command, _) = attach(Some("true")).await;
    expire(&desktop).await;
    expire(&command).await;
    app.clients
        .lock()
        .await
        .leases
        .get_mut(&command)
        .unwrap()
        .seen -= std::time::Duration::from_secs(1);
    assert!(due().await);
    // Once the queue is empty, a CLI departure lets the engine stop too.
    let (command, _) = attach(Some("true")).await;
    call("POST", format!("/v2/jobs/{}/cancel", job.id)).await;
    detach(&command).await;
    assert!(!app.store.has_unfinished_downloads().await.unwrap());
    assert!(due().await);
    // Background operation keeps it up regardless.
    app.store
        .set_setting("preferences", &serde_json::json!({"background": true}))
        .await
        .unwrap();
    assert!(!due().await);
}

#[tokio::test]
async fn credential_api_persists_only_handles_and_never_returns_secrets() {
    use omd_credentials::{Backend, Error};
    use zeroize::Zeroizing;
    #[derive(Default)]
    struct Memory(std::sync::Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>);
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
    let (_root, mut app) = setup().await;
    app.acquisition.network = Network::new(0).with_vault(omd_credentials::Vault::with_backend(
        "fixture",
        Arc::new(Memory::default()),
    ));
    let manifest:omd_domain::ProviderManifest=serde_json::from_value(serde_json::json!({"api":"omd:provider@2","id":"source.fixture","name":"Fixture","version":"1","description":"fixture","source_hosts":["example.com"],"capabilities":["search"],"grants":[{"id":"account","hosts":["example.com"],"methods":["GET"],"credential":true}]})).unwrap();
    app.providers.write().await.insert(
        manifest.id.clone(),
        omd_plugins::Provider {
            manifest,
            component: "unused".into(),
            digest: "unused".into(),
        },
    );
    let router = router(app.clone(), vec![]);
    for (method, path, body, expected) in [
        (
            "PUT",
            "/v2/sources/source.fixture/credentials/personal",
            r#"{"label":"Personal account","session":{"expires_at":null,"cookies":[],"headers":[{"origin":"https://example.com","name":"authorization","value":"Bearer PRIVATE_TOKEN"}]}}"#,
            StatusCode::OK,
        ),
        (
            "GET",
            "/v2/sources/source.fixture/credentials",
            "",
            StatusCode::OK,
        ),
        (
            "DELETE",
            "/v2/sources/source.fixture/credentials/personal",
            "",
            StatusCode::OK,
        ),
        (
            "DELETE",
            "/v2/sources/source.fixture/credentials/personal",
            "",
            StatusCode::OK,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE"));
        if method == "GET" {
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["items"][0]["status"], "ready");
        }
        let metadata: Vec<(String, String, String, String)> =
            sqlx::query_as("SELECT * FROM credential_profiles")
                .fetch_all(&app.store.pool)
                .await
                .unwrap();
        assert!(!format!("{metadata:?}").contains("PRIVATE"));
    }
    assert!(matches!(
        app.acquisition
            .network
            .session(
                "source.fixture",
                Some("personal"),
                &app.providers.read().await["source.fixture"].manifest.grants
            )
            .await,
        Err(omd_network::NetworkError::Credential(Error::Missing))
    ));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/sources/source.fixture/credentials")
                .header("Authorization", "Bearer normal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(value["items"][0]["profile"], "personal");
    assert_eq!(value["items"][0]["status"], "attention");
    assert_eq!(
        value["items"][0]["issue"]["code"],
        "authentication_required"
    );
    // Reauthentication updates the exact handle retained by queued requests.
    let response=router.oneshot(Request::builder().method("PUT").uri("/v2/sources/source.fixture/credentials/personal").header("Authorization","Bearer normal").header("Content-Type","application/json").body(Body::from(r#"{"label":"Personal account","session":{"expires_at":null,"cookies":[],"headers":[{"origin":"https://example.com","name":"authorization","value":"Bearer REPLACEMENT_PRIVATE"}]}}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        app.acquisition
            .network
            .session(
                "source.fixture",
                Some("personal"),
                &app.providers.read().await["source.fixture"].manifest.grants
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn public_snapshot_batch_workflow_uses_real_component_and_resumes_saved_state() {
    use omd_domain::{Page, ProviderManifest, Release};
    use omd_plugins::Provider;
    use serde_json::{Value, json};
    let (root, mut app) = setup().await;
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = repository.join("tests/v2-acquisition-provider/.omd-build/plugin.wasm");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(repository.join("tests/v2-acquisition-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let digest = omd_plugins::package_digest(
        &manifest,
        &std::fs::read(&component)
            .expect("Build tests/v2-acquisition-provider through the TypeScript SDK"),
    );
    app.store
        .install_provider(&manifest, &digest, component.to_str().unwrap())
        .await
        .unwrap();
    app.providers.write().await.insert(
        manifest.id.clone(),
        Provider {
            manifest: manifest.clone(),
            component,
            digest,
        },
    );
    app.runtime = Runtime::new(worker::executable(), app.acquisition.network.clone(), 1)
        .with_cache(worker::cache_config(root.path()));
    app.runtime
        .inspect(
            &app.providers.read().await[&manifest.id],
            &CancellationToken::new(),
        )
        .await
        .unwrap();
    let dest = app
        .store
        .add_destination("Fixture", root.path())
        .await
        .unwrap();
    let http = router(app.clone(), vec![]);
    async fn request(router: &axum::Router, method: &str, path: &str, body: Value) -> Value {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .header(
                        "Idempotency-Key",
                        body.get("preparation_id")
                            .and_then(Value::as_str)
                            .unwrap_or("fixture-selection"),
                    )
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let value: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(status.is_success(), "{path}: {value}");
        value
    }
    async fn ready(app: &App, id: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                let task = app.store.selection_task(id).await.unwrap();
                assert_ne!(task.state, "failed", "{:?}", task.issue);
                if task.state == "ready" {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
    }
    let subscription = request(
        &http,
        "POST",
        "/v2/subscriptions",
        json!({
            "target":{"provider":manifest.id,"id":"fixture-series"},
            "policy":omd_domain::SelectionPolicy::default(), "action":"notify",
            "destination_id":dest.id, "recipe":"cbz", "include_existing":false,
            "interval_minutes":60, "credential_profile":null
        }),
    )
    .await;
    assert_eq!(subscription["title"], "Durable collection fixture");
    let source = app.providers.write().await.remove(&manifest.id).unwrap();
    let cached = request(&http, "GET", "/v2/subscriptions?q=durable", Value::Null).await;
    assert_eq!(cached["items"][0]["id"], subscription["id"]);
    assert_eq!(cached["items"][0]["title"], "Durable collection fixture");
    app.providers
        .write()
        .await
        .insert(manifest.id.clone(), source);
    let snapshot = request(
        &http,
        "POST",
        "/v2/snapshots",
        json!({"reference":{"provider":manifest.id,"id":"fixture-series"}}),
    )
    .await;
    let id = snapshot["id"].as_str().unwrap();
    // A queued HTTP request survives recovery before any worker has run.
    app.store.recover().await.unwrap();
    let worker = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    ready(&app, id).await;
    assert_eq!(app.store.selection_task(id).await.unwrap().total, 401);
    let page: Page<Release> = serde_json::from_value(
        request(
            &http,
            "GET",
            &format!("/v2/snapshots/{id}/releases?limit=200"),
            Value::Null,
        )
        .await,
    )
    .unwrap();
    assert_eq!(page.items.len(), 200);
    assert!(page.next_cursor.is_some());
    let batch=request(&http,"POST","/v2/batches",json!({"snapshot_id":id,"destination_id":dest.id,"recipe":"cbz","policy":{"languages":["en"]}})).await;
    let batch = batch["id"].as_str().unwrap();
    ready(&app, batch).await;
    let preview = request(
        &http,
        "GET",
        &format!("/v2/batches/{batch}/items"),
        Value::Null,
    )
    .await;
    assert_eq!(preview["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        preview["items"][0]["files"],
        json!(["chapter.cbz", "ComicInfo.xml", "provenance.json"])
    );
    let submitted = request(&http, "POST", "/v2/jobs", json!({"preparation_id":batch})).await;
    assert_eq!(submitted["created"], 2);
    assert_eq!(
        request(&http, "POST", "/v2/jobs", json!({"preparation_id":batch})).await,
        submitted
    );
    // Explicit selections span several image posts, never the whole search.
    let refs = json!([{"provider":manifest.id,"id":"image-one"},{"provider":manifest.id,"id":"image-two"}]);
    let images = request(
        &http,
        "POST",
        "/v2/snapshots",
        json!({"reference":{"provider":manifest.id,"id":"image-one"},"release_refs":refs}),
    )
    .await;
    let images = images["id"].as_str().unwrap();
    ready(&app, images).await;
    assert_eq!(app.store.selection_task(images).await.unwrap().total, 2);
    let batch = request(&http, "POST", "/v2/batches", json!({"snapshot_id":images,"destination_id":dest.id,"recipe":"original_images","policy":{"languages":[]}})).await;
    let batch = batch["id"].as_str().unwrap();
    ready(&app, batch).await;
    let preview = request(
        &http,
        "GET",
        &format!("/v2/batches/{batch}/items"),
        Value::Null,
    )
    .await;
    assert_eq!(preview["items"].as_array().unwrap().len(), 2);
    for item in preview["items"].as_array().unwrap() {
        assert_eq!(
            item["files"],
            json!(["00001.png", "metadata.json", "provenance.json"])
        );
        assert!(
            !item["plan"]["final_relative_path"]
                .as_str()
                .unwrap()
                .contains('/')
        );
    }
    let submitted = request(&http, "POST", "/v2/jobs", json!({"preparation_id":batch})).await;
    assert_eq!(submitted["created"], 2);
    // Profile subscriptions observe the artist feed, then resolve each post at its
    // own identity. All images must survive the automatic download path.
    let profile_request = json!({"target":{"provider":manifest.id,"id":"artist:fixture"},"policy":{"languages":[],"groups":[]},"action":"notify","destination_id":"","recipe":"original_images","include_existing":false,"interval_minutes":60});
    let profile_sub = request(&http, "POST", "/v2/subscriptions", profile_request.clone()).await;
    let sub_id = profile_sub["id"].as_str().unwrap();
    assert_eq!(profile_sub["title"], "Fixture artist");
    let mut renamed = profile_request.clone();
    renamed["name"] = json!("My artist");
    let edited = request(
        &http,
        "PATCH",
        &format!("/v2/subscriptions/{sub_id}"),
        renamed,
    )
    .await;
    assert_eq!(edited["title"], "My artist");
    let subscriptions = tokio::spawn(omd_service::run_subscriptions(app.clone()));
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if omd_subscriptions::get(&app.store, sub_id)
                .await
                .unwrap()
                .initialized
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE subscription_id=?")
        .bind(sub_id)
        .fetch_one(&app.store.pool)
        .await
        .unwrap();
    assert_eq!(actions, 0, "future-only follows establish a quiet baseline");
    // A second uploader/artist can include existing posts and download immediately.
    let mut download_request = profile_request;
    download_request["target"]["id"] = json!("artist:download");
    download_request["action"] = json!("download");
    download_request["destination_id"] = json!(dest.id);
    download_request["include_existing"] = json!(true);
    let downloading = request(&http, "POST", "/v2/subscriptions", download_request).await;
    let download_id = downloading["id"].as_str().unwrap();
    let job_id: String = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let job: Option<String> = sqlx::query_scalar("SELECT resource_id FROM actions WHERE subscription_id=? AND resource_id IS NOT NULL").bind(download_id).fetch_optional(&app.store.pool).await.unwrap();
            if let Some(job) = job { break job; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }).await.unwrap();
    let job = app.store.job(&job_id).await.unwrap();
    assert_eq!(job.plan.recipe, omd_domain::Recipe::OriginalImages);
    assert_eq!(job.plan.collection.reference.id, "image-multipage");
    assert_eq!(job.plan.outputs.len(), 2);
    assert_eq!(job.plan.release.collection, job.plan.collection.reference);
    assert!(job.plan.policy.languages.is_empty());
    // Re-checking the same feed must not queue another post.
    let previous = omd_subscriptions::get(&app.store, download_id)
        .await
        .unwrap()
        .last_success;
    request(
        &http,
        "POST",
        &format!("/v2/subscriptions/{download_id}/check"),
        Value::Null,
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if omd_subscriptions::get(&app.store, download_id)
                .await
                .unwrap()
                .last_success
                != previous
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE subscription_id=?")
        .bind(download_id)
        .fetch_one(&app.store.pool)
        .await
        .unwrap();
    assert_eq!(actions, 1);
    app.shutdown.cancel();
    subscriptions.await.unwrap();
    worker.await.unwrap();
}

#[tokio::test]
async fn public_file_removal_requires_review_preserves_history_and_returns_gone_after_forgetting() {
    use omd_domain::{Artifact, FileStatus, Plan};
    use serde_json::{Value, json};
    async fn call(app: &App, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = router(app.clone(), vec![])
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    let (root, app) = setup().await;
    let dest = app
        .store
        .add_destination("Fixture", root.path())
        .await
        .unwrap();
    let plan: Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    let (job, _) = app
        .store
        .enqueue(&plan, &dest.id, "fixture", "fixture", Some("group"))
        .await
        .unwrap();
    let file = app.store.destination_root(&dest.id).await.unwrap();
    file.write_new("chapter/page.jpg", b"fixture content")
        .unwrap();
    file.write_new("chapter/user.txt", b"unrelated").unwrap();
    let (size, sha256) = file.hash("chapter/page.jpg").unwrap();
    app.store
        .complete(
            &job.id,
            &[Artifact {
                id: "artifact".into(),
                job_id: job.id.clone(),
                relative_path: "chapter/page.jpg".into(),
                size,
                sha256,
                media_type: "image/jpeg".into(),
                status: FileStatus::Present,
            }],
        )
        .await
        .unwrap();
    let (status, op) = call(
        &app,
        "POST",
        &format!("/v2/jobs/{}/file-operations", job.id),
        json!({"mode":"remove_files"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(op["state"], "ready");
    assert!(file.read_file("chapter/page.jpg").is_ok());
    let id = op["id"].as_str().unwrap();
    let (status, preview) = call(
        &app,
        "GET",
        &format!("/v2/file-operations/{id}/files"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(preview["items"][0]["path"], "chapter/page.jpg");
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v2/file-operations/{id}/start"),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    let worker = tokio::spawn(omd_service::storage::run_storage(app.clone()));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (_, op) = call(
                &app,
                "GET",
                &format!("/v2/file-operations/{id}"),
                Value::Null,
            )
            .await;
            if op["state"] == "complete" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(file.read_file("chapter/page.jpg").is_err());
    assert!(file.read_file("chapter/user.txt").is_ok());
    let (status, files) = call(
        &app,
        "GET",
        &format!("/v2/jobs/{}/files", job.id),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(files["items"][0]["status"], "missing");
    let (_, op) = call(
        &app,
        "POST",
        &format!("/v2/jobs/{}/file-operations", job.id),
        json!({"mode":"forget_history"}),
    )
    .await;
    let id = op["id"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            &format!("/v2/file-operations/{id}/start"),
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if app.store.history_removed(&job.id).await.unwrap() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for path in [
        format!("/v2/jobs/{}", job.id),
        format!("/v2/jobs/{}/files", job.id),
        format!("/v2/jobs/{}/files/artifact", job.id),
    ] {
        assert_eq!(
            call(&app, "GET", &path, Value::Null).await.0,
            StatusCode::GONE
        );
    }
    assert_eq!(
        call(&app, "GET", "/v2/jobs", Value::Null).await.1["items"],
        json!([])
    );
    app.shutdown.cancel();
    worker.await.unwrap();
}

#[tokio::test]
async fn metadata_and_naming_api_validate_and_keep_source_identity_separate() {
    use serde_json::{Value, json};
    async fn call(app: &App, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
        let response = router(app.clone(), vec![])
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        (
            status,
            serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1_000_000)
                    .await
                    .unwrap(),
            )
            .unwrap(),
        )
    }
    let (_root, app) = setup().await;
    let reference = json!({"provider":"example","id":"chapter:12.5a"});
    let (status, value) = call(
        &app,
        "PUT",
        "/v2/metadata/release",
        json!({"reference":reference,"overrides":{"title":"Personal name","chapter":"12.5a"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["chapter"], "12.5a");
    assert_eq!(
        call(
            &app,
            "GET",
            "/v2/metadata/release/example?source_id=chapter%3A12.5a",
            Value::Null
        )
        .await
        .1,
        value
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            "/v2/metadata/collection",
            json!({"reference":reference,"overrides":{"chapter":"12"}})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            "/v2/naming",
            json!({"collection":"../{title}","release":"{title}"})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let good = json!({"collection":"{provider} - {title}","release":"{chapter} - {title}"});
    assert_eq!(
        call(&app, "PUT", "/v2/naming", good.clone()).await.0,
        StatusCode::OK
    );
    assert_eq!(call(&app, "GET", "/v2/naming", Value::Null).await.1, good);
}

#[tokio::test]
async fn normal_client_group_commands_cancel_live_tokens_and_wait_for_checkpointing() {
    let (root, app) = setup().await;
    let destination = app
        .store
        .add_destination("Files", root.path())
        .await
        .unwrap();
    let plan: omd_domain::Plan =
        serde_json::from_str(include_str!("../../../tests/fixtures/v2-plan.json")).unwrap();
    let (job, _) = app
        .store
        .enqueue(
            &plan,
            &destination.id,
            "group-command",
            "group-command",
            Some("operation"),
        )
        .await
        .unwrap();
    let token = CancellationToken::new();
    app.running
        .lock()
        .await
        .insert(job.id.clone(), token.clone());
    let service = router(app.clone(), vec![]);
    for (action, changed, checkpointing) in [("pause", 1, 0), ("resume", 0, 1)] {
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v2/groups/operation/{action}"))
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 16384)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["changed"], changed);
        assert_eq!(value["checkpointing"], checkpointing);
    }
    assert!(token.is_cancelled());
    app.running.lock().await.remove(&job.id);
    let response = service
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/groups/operation/resume")
                .header("Authorization", "Bearer normal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.store.job(&job.id).await.unwrap().state,
        omd_domain::JobState::Queued
    );
}

#[tokio::test]
async fn public_contract_and_typed_source_invocations_need_no_engine_internals() {
    let (_root, app) = setup().await;
    let service = router(app, vec![]);
    let response = service
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/openapi.json")
                .header("Authorization", "Bearer normal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let document: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(document["openapi"], "3.1.0");
    for (body, expected) in [
        (r#"{"operation":"search"}"#, StatusCode::NOT_FOUND),
        (r#"{"operation":"related"}"#, StatusCode::NOT_FOUND),
        (
            r#"{"operation":"releases","release_order":"desc"}"#,
            StatusCode::NOT_FOUND,
        ),
        (
            r#"{"operation":"releases","release_order":"sideways"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"operation":"search","now":"spoofed-clock"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"operation":"arbitrary-function"}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/sources/missing/invoke")
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    for path in ["/v2/service", "/v2/summary", "/v2/settings"] {
        let response = service
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        match path {
            "/v2/service" => {
                serde_json::from_slice::<omd_service::contract::models::Service>(&bytes).unwrap();
            }
            "/v2/summary" => {
                serde_json::from_slice::<omd_service::contract::models::Summary>(&bytes).unwrap();
            }
            _ => {
                serde_json::from_slice::<omd_service::contract::models::Settings>(&bytes).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn notification_preferences_and_recovery_are_public_and_adapter_failure_is_actionable() {
    let (_root, app) = setup().await;
    let api = router(app.clone(), vec![]);
    let request = |method: &str, path: &str, body: serde_json::Value| {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer normal")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = api
        .clone()
        .oneshot(request(
            "PUT",
            "/v2/notifications",
            serde_json::json!({"enabled":true}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(omd_notifications::status(&app.store).await.unwrap().enabled);
    let response = api
        .clone()
        .oneshot(request(
            "POST",
            "/v2/notifications/test",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["code"], "notification_adapter_unavailable");
    assert!(!body.to_string().contains("missing-notification-fixture"));
    sqlx::query(
        "INSERT INTO notification_batches VALUES('n',5,'sending',NULL,'2000-01-01','2000-01-01')",
    )
    .execute(&app.store.pool)
    .await
    .unwrap();
    omd_notifications::recover(&app.store).await.unwrap();
    let response = api
        .clone()
        .oneshot(request(
            "POST",
            "/v2/notifications/history/n/dismiss",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        omd_notifications::status(&app.store)
            .await
            .unwrap()
            .uncertain,
        0
    );
    let response = api
        .oneshot(request(
            "GET",
            "/v2/notifications/history",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn default_destination_preserves_existing_folder_and_requires_manage_permission() {
    let (root, app) = setup().await;
    let folder = root.path().join("existing");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("personal.txt"), b"untouched").unwrap();
    let existing = app
        .store
        .add_destination("Existing", &folder)
        .await
        .unwrap();
    let api = router(app, vec![]);
    let response = api
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/destinations/default")
                .header("Authorization", "Bearer normal")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let result: omd_domain::Destination = serde_json::from_slice(&body).unwrap();
    assert_eq!(result.id, existing.id);
    assert_eq!(
        std::fs::read(folder.join("personal.txt")).unwrap(),
        b"untouched"
    );
}
/// A selection that fails because the source changed a release ends reuse of
/// the cached enumeration: the client's refresh (an identical snapshot
/// request within the fifteen-minute reuse window) lists the source again
/// instead of getting the stale list back, and the stale list is not served.
#[tokio::test]
async fn a_changed_selection_makes_the_next_identical_snapshot_enumerate_again() {
    use omd_domain::ProviderManifest;
    use omd_plugins::Provider;
    use serde_json::{Value, json};
    let (root, mut app) = setup().await;
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let component = repository.join("tests/v2-acquisition-provider/.omd-build/plugin.wasm");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(repository.join("tests/v2-acquisition-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let digest = omd_plugins::package_digest(
        &manifest,
        &std::fs::read(&component)
            .expect("Build tests/v2-acquisition-provider through the TypeScript SDK"),
    );
    app.store
        .install_provider(&manifest, &digest, component.to_str().unwrap())
        .await
        .unwrap();
    let provider = Provider {
        manifest: manifest.clone(),
        component,
        digest,
    };
    app.providers
        .write()
        .await
        .insert(manifest.id.clone(), provider.clone());
    app.runtime = Runtime::new(worker::executable(), app.acquisition.network.clone(), 1)
        .with_cache(worker::cache_config(root.path()));
    app.runtime
        .inspect(&provider, &CancellationToken::new())
        .await
        .unwrap();
    let dest = app
        .store
        .add_destination("Fixture", root.path())
        .await
        .unwrap();
    let http = router(app.clone(), vec![]);
    let call = async |method: &str, path: &str, body: Value| {
        let response = http
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice::<Value>(&bytes).unwrap())
    };
    let settled = async |id: &str| {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                let task = app.store.selection_task(id).await.unwrap();
                if task.state != "working" {
                    return task;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
    };
    let worker = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let refresh = json!({"reference":{"provider":manifest.id,"id":"fixture-series"}});
    let (status, snapshot) = call("POST", "/v2/snapshots", refresh.clone()).await;
    assert_eq!(status, StatusCode::OK, "{snapshot}");
    let stale = snapshot["id"].as_str().unwrap().to_owned();
    assert_eq!(settled(&stale).await.state, "ready");
    // Within the reuse window an identical request gets the cached list.
    let (_, again) = call("POST", "/v2/snapshots", refresh.clone()).await;
    assert_eq!(again["id"], stale.as_str());
    // The source has since changed the selected releases: the listed
    // revision no longer matches what resolving them returns.
    sqlx::query(
        "UPDATE snapshot_releases SET data_json=json_set(data_json,'$.revision','superseded') \
         WHERE snapshot_id=?",
    )
    .bind(&stale)
    .execute(&app.store.pool)
    .await
    .unwrap();
    let (status, batch) = call(
        "POST",
        "/v2/batches",
        json!({"snapshot_id":stale,"destination_id":dest.id,"recipe":"cbz","policy":{"languages":["en"]}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{batch}");
    let failed = settled(batch["id"].as_str().unwrap()).await;
    assert_eq!(failed.state, "failed");
    assert_eq!(failed.issue.unwrap().code, "selection_changed");
    // Refresh enumerates again; the stale list is no longer served.
    let (status, fresh) = call("POST", "/v2/snapshots", refresh).await;
    assert_eq!(status, StatusCode::OK, "{fresh}");
    let fresh = fresh["id"].as_str().unwrap().to_owned();
    assert_ne!(fresh, stale);
    assert_eq!(settled(&fresh).await.state, "ready");
    let (status, listing) = call(
        "GET",
        &format!("/v2/snapshots/{stale}/releases"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{listing}");
    assert_eq!(listing["code"], "state_conflict");
    let (status, _) = call(
        "GET",
        &format!("/v2/snapshots/{fresh}/releases"),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    app.shutdown.cancel();
    worker.await.unwrap();
}

/// The synthetic acquisition source with a real worker. Its destination has its
/// own folder, so a test can disconnect it to stop downloads before any transfer.
struct ListedSource {
    root: tempfile::TempDir,
    app: App,
    http: axum::Router,
    source: String,
    destination: String,
}
impl ListedSource {
    /// Installs the fixture source; `declares_hint` keeps the
    /// `collection_hint` capability its manifest declares, or removes it.
    async fn install(declares_hint: bool) -> Self {
        use omd_domain::ProviderManifest;
        use omd_plugins::Provider;
        let (root, mut app) = setup().await;
        let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let component = repository.join("tests/v2-acquisition-provider/.omd-build/plugin.wasm");
        let mut manifest: ProviderManifest = serde_json::from_slice(
            &std::fs::read(repository.join("tests/v2-acquisition-provider/omd-plugin.json"))
                .unwrap(),
        )
        .unwrap();
        assert!(manifest.accepts_collection_hint());
        if !declares_hint {
            manifest
                .capabilities
                .remove(omd_domain::COLLECTION_HINT_CAPABILITY);
        }
        let digest = omd_plugins::package_digest(
            &manifest,
            &std::fs::read(&component)
                .expect("Build tests/v2-acquisition-provider through the TypeScript SDK"),
        );
        app.store
            .install_provider(&manifest, &digest, component.to_str().unwrap())
            .await
            .unwrap();
        let provider = Provider {
            manifest: manifest.clone(),
            component,
            digest,
        };
        app.providers
            .write()
            .await
            .insert(manifest.id.clone(), provider.clone());
        app.runtime = Runtime::new(worker::executable(), app.acquisition.network.clone(), 1)
            .with_cache(worker::cache_config(root.path()));
        app.runtime
            .inspect(&provider, &CancellationToken::new())
            .await
            .unwrap();
        let library = root.path().join("library");
        std::fs::create_dir(&library).unwrap();
        let destination = app
            .store
            .add_destination("Library", &library)
            .await
            .unwrap()
            .id;
        let http = router(app.clone(), vec![]);
        Self {
            root,
            app,
            http,
            source: manifest.id,
            destination,
        }
    }
    fn reference(&self, id: &str) -> serde_json::Value {
        serde_json::json!({"provider": self.source, "id": id})
    }
    async fn call(
        &self,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let key = body
            .get("preparation_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("listed-source")
            .to_owned();
        let response = self
            .http
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Authorization", "Bearer normal")
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", key)
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn settled(&self, id: &str) -> omd_store::selections::SelectionTask {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                let task = self.app.store.selection_task(id).await.unwrap();
                if task.state != "working" {
                    return task;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap()
    }
    /// Lists `collection` into a snapshot, then prepares every listed release
    /// matching `languages` as a batch. Returns the snapshot id and the settled batch.
    async fn prepare(
        &self,
        collection: &str,
        languages: &[&str],
    ) -> (String, omd_store::selections::SelectionTask) {
        let (status, snapshot) = self
            .call(
                "POST",
                "/v2/snapshots",
                serde_json::json!({"reference": self.reference(collection)}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{snapshot}");
        let snapshot = snapshot["id"].as_str().unwrap().to_owned();
        assert_eq!(self.settled(&snapshot).await.state, "ready");
        let (status, batch) = self
            .call(
                "POST",
                "/v2/batches",
                serde_json::json!({"snapshot_id": snapshot, "destination_id": self.destination,
                    "recipe": "cbz", "policy": {"languages": languages}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{batch}");
        let batch = self.settled(batch["id"].as_str().unwrap()).await;
        (snapshot, batch)
    }
    /// The prepared plans of a ready batch.
    async fn plans(&self, batch: &str) -> Vec<omd_domain::Plan> {
        let (status, page) = self
            .call(
                "GET",
                &format!("/v2/batches/{batch}/items"),
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| serde_json::from_value(item["plan"].clone()).unwrap())
            .collect()
    }
    async fn submit(&self, batch: &str) {
        let (status, submitted) = self
            .call(
                "POST",
                "/v2/jobs",
                serde_json::json!({"preparation_id": batch}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{submitted}");
        assert_eq!(submitted["created"], 2, "{submitted}");
    }
    /// Follows `collection` with automatic downloads of every listed release and
    /// returns the two jobs its actions queue. Needs `run_subscriptions` running.
    async fn follow(&self, collection: &str) -> Vec<omd_domain::Job> {
        let id = self.subscribe(collection).await;
        let jobs: Vec<String> = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                let issues: Vec<String> = sqlx::query_scalar(
                    "SELECT issue_json FROM actions WHERE subscription_id=? AND issue_json IS NOT NULL",
                )
                .bind(&id)
                .fetch_all(&self.app.store.pool)
                .await
                .unwrap();
                assert!(issues.is_empty(), "{issues:?}");
                let jobs: Vec<String> = sqlx::query_scalar(
                    "SELECT resource_id FROM actions WHERE subscription_id=? AND resource_id IS NOT NULL ORDER BY resource_id",
                )
                .bind(&id)
                .fetch_all(&self.app.store.pool)
                .await
                .unwrap();
                if jobs.len() == 2 {
                    break jobs;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let mut followed = vec![];
        for job in jobs {
            followed.push(self.app.store.job(&job).await.unwrap());
        }
        followed
    }
    /// Follows `collection` like `follow`, for a source that files its releases
    /// elsewhere: returns the problems of the two refused download actions,
    /// which queue nothing.
    async fn follow_refused(&self, collection: &str) -> Vec<omd_domain::Problem> {
        let id = self.subscribe(collection).await;
        let issues: Vec<String> = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                let issues: Vec<String> = sqlx::query_scalar(
                    "SELECT issue_json FROM actions WHERE subscription_id=? AND issue_json IS NOT NULL \
                     AND state='failed'",
                )
                .bind(&id)
                .fetch_all(&self.app.store.pool)
                .await
                .unwrap();
                if issues.len() == 2 {
                    break issues;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE subscription_id=? AND resource_id IS NOT NULL",
        )
        .bind(&id)
        .fetch_one(&self.app.store.pool)
        .await
        .unwrap();
        assert_eq!(queued, 0);
        issues
            .iter()
            .map(|issue| serde_json::from_str(issue).unwrap())
            .collect()
    }
    /// Creates a downloading subscription to `collection` and returns its id.
    async fn subscribe(&self, collection: &str) -> String {
        let (status, subscription) = self
            .call(
                "POST",
                "/v2/subscriptions",
                serde_json::json!({"target": self.reference(collection),
                    "policy": {"languages": [], "groups": []}, "action": "download",
                    "destination_id": self.destination, "recipe": "cbz",
                    "include_existing": true, "interval_minutes": 60}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{subscription}");
        subscription["id"].as_str().unwrap().to_owned()
    }
    /// Runs every queued job after its approved transport locations expired, so
    /// each one resolves its release again and refreshes its plan first. The
    /// destination is disconnected beforehand: a job whose refresh is accepted
    /// pauses there, before any transfer, and a refused refresh fails with
    /// `selection_changed`. Returns every job once none is left running.
    async fn download_expired(&self) -> Vec<omd_domain::Job> {
        let expired = sqlx::query(
            "UPDATE jobs SET plan_json=json_set(plan_json,'$.expires_at','2000-01-01T00:00:00Z') \
             WHERE state='queued'",
        )
        .execute(&self.app.store.pool)
        .await
        .unwrap();
        assert!(expired.rows_affected() > 0);
        std::fs::rename(
            self.root.path().join("library"),
            self.root.path().join("library-disconnected"),
        )
        .unwrap();
        assert!(
            !self
                .app
                .store
                .destination(&self.destination)
                .await
                .unwrap()
                .available
        );
        let runner = tokio::spawn(omd_service::run_jobs(self.app.clone()));
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                let running: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM jobs WHERE state IN \
                     ('queued','resolving','transferring','verifying','publishing')",
                )
                .fetch_one(&self.app.store.pool)
                .await
                .unwrap();
                if running == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        self.app.shutdown.cancel();
        runner.await.unwrap();
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM jobs ORDER BY id")
            .fetch_all(&self.app.store.pool)
            .await
            .unwrap();
        let mut jobs = vec![];
        for id in ids {
            jobs.push(self.app.store.job(&id).await.unwrap());
        }
        jobs
    }
}

/// The plan stopped only at the disconnected destination: its refresh at
/// download time was accepted and replaced the expired locations.
fn refreshed_before_transfer(job: &omd_domain::Job) {
    assert_eq!(job.state, omd_domain::JobState::Paused, "{:?}", job.issue);
    assert_eq!(
        job.issue.as_ref().map(|issue| issue.code.as_str()),
        Some("destination_unavailable")
    );
    assert_eq!(job.plan.expires_at, None);
}

/// A source can list one release in several collections (search results, a
/// playlist) while filing it under one canonical parent. The engine now tells
/// `resolve` which collection the release was listed under, so such a source
/// can keep it there: batches prepare, subscriptions follow, and expired plans
/// refresh at download time, while the engine still requires that collection.
#[tokio::test]
async fn a_source_keeps_a_listed_release_in_the_collection_it_was_listed_under() {
    let fixture = ListedSource::install(true).await;
    let app = &fixture.app;
    let selections = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let subscriptions = tokio::spawn(omd_service::run_subscriptions(app.clone()));
    // Search results list chapters 0 and 1. Without the hint the source would
    // file them under its canonical series and the batch would fail.
    let (_, batch) = fixture.prepare("results:0", &["en"]).await;
    assert_eq!(batch.state, "ready", "{:?}", batch.issue);
    let plans = fixture.plans(&batch.id).await;
    assert_eq!(plans.len(), 2);
    for plan in &plans {
        assert_eq!(plan.collection.reference.id, "results:0");
        assert_eq!(plan.release.collection, plan.collection.reference);
        assert_eq!(plan.collection.title, "Search results fixture");
    }
    fixture.submit(&batch.id).await;
    // Following other search results downloads chapters 2 and 3 under them.
    let followed = fixture.follow("results:2").await;
    assert_eq!(followed.len(), 2);
    for job in &followed {
        assert_eq!(job.plan.collection.reference.id, "results:2");
        assert_eq!(job.plan.release.collection, job.plan.collection.reference);
    }
    // Resolving again at download time keeps each approved collection.
    let jobs = fixture.download_expired().await;
    assert_eq!(jobs.len(), 4);
    let mut collections: Vec<_> = jobs
        .iter()
        .map(|job| {
            refreshed_before_transfer(job);
            (
                job.plan.release.reference.id.clone(),
                job.plan.collection.reference.id.clone(),
            )
        })
        .collect();
    collections.sort();
    assert_eq!(
        collections,
        [
            ("release-0".to_owned(), "results:0".to_owned()),
            ("release-1".to_owned(), "results:0".to_owned()),
            ("release-2".to_owned(), "results:2".to_owned()),
            ("release-3".to_owned(), "results:2".to_owned()),
        ]
    );
    selections.await.unwrap();
    subscriptions.await.unwrap();
}

/// A source that ignores the collection hint, as every source written before it
/// does (its manifest does not declare the capability), behaves exactly as
/// before: a release listed under another collection still fails its batch
/// with `selection_changed` (and ends reuse of that listing), while its
/// canonical collection, subscriptions and download-time refreshes work
/// unchanged.
#[tokio::test]
async fn a_source_that_ignores_the_collection_hint_behaves_as_before() {
    let fixture = ListedSource::install(false).await;
    let app = &fixture.app;
    let selections = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let subscriptions = tokio::spawn(omd_service::run_subscriptions(app.clone()));
    let (snapshot, batch) = fixture.prepare("playlist:4", &[]).await;
    assert_eq!(batch.state, "failed");
    let issue = batch.issue.unwrap();
    assert_eq!(issue.code, "selection_changed");
    assert_eq!(
        issue.message,
        "A selected release changed since enumeration. Create a new snapshot and review the new selection."
    );
    let (status, again) = fixture
        .call(
            "POST",
            "/v2/snapshots",
            serde_json::json!({"reference": fixture.reference("playlist:4")}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_ne!(again["id"], snapshot.as_str());
    // The canonical collection lists and prepares as it always did.
    let (_, batch) = fixture.prepare("fixture-series", &["en"]).await;
    assert_eq!(batch.state, "ready", "{:?}", batch.issue);
    let plans = fixture.plans(&batch.id).await;
    assert_eq!(plans.len(), 2);
    for plan in &plans {
        assert_eq!(plan.collection.reference.id, "fixture-series");
    }
    fixture.submit(&batch.id).await;
    // Subscriptions of such a source never required the listed collection; it
    // still files followed playlist chapters under its canonical series.
    let followed = fixture.follow("playlist:6").await;
    assert_eq!(followed.len(), 2);
    for job in &followed {
        assert_eq!(job.plan.collection.reference.id, "fixture-series");
    }
    let jobs = fixture.download_expired().await;
    assert_eq!(jobs.len(), 4);
    let mut collections: Vec<_> = jobs
        .iter()
        .map(|job| {
            refreshed_before_transfer(job);
            (
                job.plan.release.reference.id.clone(),
                job.plan.collection.reference.id.clone(),
            )
        })
        .collect();
    collections.sort();
    assert_eq!(
        collections,
        [
            ("release-0".to_owned(), "fixture-series".to_owned()),
            ("release-1".to_owned(), "fixture-series".to_owned()),
            ("release-6".to_owned(), "fixture-series".to_owned()),
            ("release-7".to_owned(), "fixture-series".to_owned()),
        ]
    );
    selections.await.unwrap();
    subscriptions.await.unwrap();
}

/// The engine sends the collection hint only to a source whose manifest
/// declares the `collection_hint` capability. The same component that keeps
/// `results:` releases where they were listed, installed without the
/// capability, never learns the listed collection: its batch fails with
/// `selection_changed`, and its subscription downloads are queued under its
/// canonical series, as before.
#[tokio::test]
async fn a_source_without_the_collection_hint_capability_never_receives_it() {
    let fixture = ListedSource::install(false).await;
    let app = &fixture.app;
    let selections = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let subscriptions = tokio::spawn(omd_service::run_subscriptions(app.clone()));
    let (_, batch) = fixture.prepare("results:0", &["en"]).await;
    assert_eq!(batch.state, "failed");
    assert_eq!(batch.issue.unwrap().code, "selection_changed");
    let followed = fixture.follow("results:2").await;
    assert_eq!(followed.len(), 2);
    for job in &followed {
        assert_eq!(job.plan.collection.reference.id, "fixture-series");
    }
    let jobs = fixture.download_expired().await;
    assert_eq!(jobs.len(), 2);
    for job in &jobs {
        refreshed_before_transfer(job);
        assert_eq!(job.plan.collection.reference.id, "fixture-series");
    }
    selections.await.unwrap();
    subscriptions.await.unwrap();
}

/// A source that declares the `collection_hint` capability must, as for a
/// batch, keep a followed release in the subscribed collection: when it files
/// the release elsewhere (this fixture ignores `playlist:` hints), each
/// download action is refused and nothing is queued.
#[tokio::test]
async fn a_source_that_reads_the_hint_must_keep_followed_releases_in_the_followed_collection() {
    let fixture = ListedSource::install(true).await;
    let app = &fixture.app;
    // Subscription scans run on the shared selection worker.
    let selections = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let subscriptions = tokio::spawn(omd_service::run_subscriptions(app.clone()));
    let issues = fixture.follow_refused("playlist:6").await;
    assert_eq!(issues.len(), 2);
    for issue in &issues {
        assert_eq!(issue.code, "subscription_selection_changed");
        assert_eq!(
            issue.message,
            "The new release no longer matches the subscription."
        );
        assert!(!issue.retryable);
    }
    app.shutdown.cancel();
    selections.await.unwrap();
    subscriptions.await.unwrap();
}
