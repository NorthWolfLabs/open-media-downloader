use omd_domain::{ProviderManifest, ProviderRequest, SelectionPolicy};
use omd_network::Network;
use omd_plugins::{PluginError, Provider, Runtime, package_digest};
use std::{path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
#[path = "../../../tests/support/worker.rs"]
mod worker;

#[tokio::test]
async fn cold_installation_is_cancellable_and_releases_its_worker_capacity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(root.join("tests/v2-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let component = root.join("tests/v2-provider/.omd-build/plugin.wasm");
    let digest = package_digest(&manifest, &std::fs::read(&component).unwrap());
    let provider = Provider {
        manifest,
        component,
        digest,
    };
    let runtime = Runtime::new(worker::executable(), Network::new(0), 1);
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let trigger = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        signal.cancel();
    });
    let result = tokio::time::timeout(Duration::from_secs(5), runtime.inspect(&provider, &cancel))
        .await
        .unwrap();
    assert!(matches!(result, Err(PluginError::Canceled)));
    trigger.await.unwrap();
    assert_eq!(runtime.available_capacity(), 1);
    // A disconnected caller also releases ownership while native compilation is
    // active; it cannot occupy the single installation slot for five minutes.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            runtime.inspect(&provider, &CancellationToken::new())
        )
        .await
        .is_err()
    );
    assert_eq!(runtime.available_capacity(), 1);
    runtime
        .inspect(&provider, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(runtime.available_capacity(), 1);
}

#[tokio::test]
async fn cancel_and_dropped_invocations_return_all_execution_capacity() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(root.join("tests/v2-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let component = root.join("tests/v2-provider/.omd-build/plugin.wasm");
    let digest = package_digest(
        &manifest,
        &std::fs::read(&component).expect("Build the TypeScript conformance component first"),
    );
    let provider = Provider {
        manifest,
        component,
        digest,
    };
    let cache = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(worker::executable(), Network::new(0), 1)
        .with_cache(worker::cache_config(cache.path()));
    runtime
        .inspect(&provider, &CancellationToken::new())
        .await
        .unwrap();
    let request = ProviderRequest {
        release_order: None,
        discovery: None,
        credential_profile: None,
        operation: "search".into(),
        reference: None,
        query: Some("loop".into()),
        url: None,
        cursor: None,
        page_size: 100,
        policy: SelectionPolicy::default(),
        now: String::new(),
        collection_hint: None,
    };
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let trigger = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    });
    assert!(matches!(
        runtime
            .invoke::<serde_json::Value>(&provider, &request, &stop)
            .await,
        Err(PluginError::Canceled)
    ));
    trigger.await.unwrap();
    assert_eq!(runtime.available_capacity(), 1);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            runtime.invoke::<serde_json::Value>(&provider, &request, &CancellationToken::new())
        )
        .await
        .is_err()
    );
    assert_eq!(runtime.available_capacity(), 1);
    // Removal also cancels an operation waiting for the same capacity slot.
    let first = runtime.clone();
    let p = provider.clone();
    let r = request.clone();
    let active = tokio::spawn(async move {
        first
            .invoke::<serde_json::Value>(&p, &r, &CancellationToken::new())
            .await
    });
    for _ in 0..100 {
        if runtime.available_capacity() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = runtime.clone();
    let p = provider.clone();
    let r = request.clone();
    let waiting = tokio::spawn(async move {
        second
            .invoke::<serde_json::Value>(&p, &r, &CancellationToken::new())
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;
    runtime.revoke(&provider.manifest.id).await.unwrap();
    for result in [active.await.unwrap(), waiting.await.unwrap()] {
        assert!(
            matches!(result,Err(PluginError::Source(problem)) if problem.code=="source_removed")
        );
    }
    assert_eq!(runtime.available_capacity(), 1);
    assert!(
        matches!(runtime.invoke::<serde_json::Value>(&provider,&request,&CancellationToken::new()).await,Err(PluginError::Source(problem)) if problem.code=="source_removed")
    );
    runtime.restore(&provider.manifest.id, "a-different-reviewed-digest");
    assert!(
        matches!(runtime.invoke::<serde_json::Value>(&provider,&request,&CancellationToken::new()).await,Err(PluginError::Source(problem)) if problem.code=="source_removed")
    );
    runtime.restore(&provider.manifest.id, &provider.digest);
    let mut identify = request.clone();
    identify.operation = "identify".into();
    identify.url = Some("https://example.com/item".into());
    identify.query = None;
    let result = runtime
        .invoke::<serde_json::Value>(&provider, &identify, &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result["kind"], "collection");
}

#[tokio::test]
async fn broker_wait_does_not_consume_plugin_execution_epochs_and_throttling_extends_io_budget() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: ProviderManifest = serde_json::from_slice(
        &std::fs::read(root.join("tests/v2-provider/omd-plugin.json")).unwrap(),
    )
    .unwrap();
    let component = root.join("tests/v2-provider/.omd-build/plugin.wasm");
    let digest = package_digest(&manifest, &std::fs::read(&component).unwrap());
    let provider = Provider {
        manifest,
        component,
        digest,
    };
    let network=Network::new(16*1024).with_transfer_fixture(|_,_,_|{
  let body=reqwest::Body::wrap_stream(futures_util::stream::once(async{
    tokio::time::sleep(Duration::from_secs(65)).await;
    Ok::<_,std::io::Error>(b"<article data-id='fixture'><h2>Fixture collection</h2><a href='/collection'>Open</a></article>".to_vec())
  }));Ok(http::Response::builder().header("content-type","text/html").body(body).unwrap())
 });
    let cache = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(worker::executable(), network, 1)
        .with_cache(worker::cache_config(cache.path()));
    runtime
        .inspect(&provider, &CancellationToken::new())
        .await
        .unwrap();
    let request = ProviderRequest {
        release_order: None,
        discovery: None,
        credential_profile: None,
        operation: "search".into(),
        reference: None,
        query: Some("fixture".into()),
        url: None,
        cursor: None,
        page_size: 100,
        policy: SelectionPolicy::default(),
        now: String::new(),
        collection_hint: None,
    };
    let value = tokio::time::timeout(
        Duration::from_secs(120),
        runtime.invoke::<serde_json::Value>(&provider, &request, &CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(value["items"][0]["title"], "Fixture collection");
    assert_eq!(runtime.available_capacity(), 1);
}
