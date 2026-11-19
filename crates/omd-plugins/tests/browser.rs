#[cfg(target_os = "macos")]
#[path = "../../../tests/support/worker.rs"]
mod worker;
#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires built TypeScript browser fixture, managed browser kit and macOS confinement"]
async fn pure_component_browser_uses_real_broker_and_releases_sessions_on_success_and_denial() {
    use omd_domain::{ProviderManifest, ProviderRequest, SelectionPolicy};
    use omd_plugins::{Provider, Runtime, package_digest};
    use serde_json::Value;
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(root.join("tests/v2-browser-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let component = root.join("tests/v2-browser-provider/.omd-build/plugin.wasm");
    let digest = package_digest(&manifest, &std::fs::read(&component).unwrap());
    let provider = Provider {
        manifest,
        component,
        digest,
    };
    let work = tempfile::tempdir().unwrap();
    let network=omd_network::Network::new(0).with_native_fixture(|url,_,_,_|{
        assert_eq!(url.host_str(),Some("fixture.example"));
        Ok(http::Response::builder().header("content-type","text/html").body(b"<h1>Fixture from a confined browser</h1><img src='https://advertising.example/track'>".to_vec()).unwrap())
    });
    let kit = omd_browser::packages::read_manifest(
        &root
            .join("artifacts/browser-fixture-kit.json")
            .canonicalize()
            .unwrap(),
    )
    .await
    .unwrap();
    let runtime = Runtime::new(worker::executable(), network.clone(), 1);
    runtime
        .register_browser(
            "fixture",
            omd_browser::Browser::new(kit, network, work.path().into()),
        )
        .await;
    let mut request = ProviderRequest {
        release_order: None,
        discovery: None,
        credential_profile: None,
        operation: "search".into(),
        reference: None,
        query: None,
        url: None,
        cursor: None,
        page_size: 10,
        policy: SelectionPolicy::default(),
        now: String::new(),
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    for _ in 0..5 {
        let result: Value = runtime.invoke(&provider, &request, &cancel).await.unwrap();
        assert_eq!(
            result["items"][0]["title"],
            "Fixture from a confined browser"
        );
        assert_eq!(runtime.available_capacity(), 1);
        assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
    }
    request.query = Some("identity".into());
    assert!(
        runtime
            .invoke::<Value>(&provider, &request, &cancel)
            .await
            .is_err()
    );
    assert_eq!(runtime.available_capacity(), 1);
    assert_eq!(std::fs::read_dir(work.path()).unwrap().count(), 0);
    runtime.revoke_browser("fixture").await;
    request.query = None;
    assert!(
        runtime
            .invoke::<Value>(&provider, &request, &cancel)
            .await
            .is_err()
    );
}
