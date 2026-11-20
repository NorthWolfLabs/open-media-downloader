//! The engine log names the limit that stopped a source invocation and where
//! the time went, without plugin data. The public error stays the same.
#[path = "../../../tests/support/worker.rs"]
mod worker;
use omd_domain::{ProviderManifest, ProviderRequest, SelectionPolicy};
use omd_network::Network;
use omd_plugins::{PluginError, Provider, Runtime, package_digest};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Log {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Log {
    /// Captures this thread's engine log at the level the engine records.
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let log = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(move || log.clone())
                .finish(),
        )
    }
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains("Source exceeded its execution budget"))
            .map(str::to_owned)
            .collect()
    }
}

fn provider() -> Provider {
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
    Provider {
        manifest,
        component,
        digest,
    }
}

/// The fixture spins forever on this query. The cursor stands in for request
/// data that must never reach the log.
fn spinning_request() -> ProviderRequest {
    ProviderRequest {
        release_order: None,
        discovery: None,
        credential_profile: None,
        operation: "search".into(),
        reference: None,
        query: Some("loop".into()),
        url: None,
        cursor: Some("private-cursor-https://fixture.example/?token=hidden".into()),
        page_size: 100,
        policy: SelectionPolicy::default(),
        now: String::new(),
        collection_hint: None,
    }
}

fn assert_private(line: &str) {
    for private in [
        "private-cursor",
        "fixture.example",
        "token",
        "hidden",
        "loop",
    ] {
        assert!(!line.contains(private), "{private} leaked into {line}");
    }
}

/// With the clock paused, time advances only while the engine waits on the
/// worker, so both 60-second deadlines fire at once without changing them.
/// The first invocation holds the only worker slot and meets the worker
/// deadline; the second is still queued when the invocation deadline fires.
#[tokio::test(start_paused = true)]
async fn deadlines_record_which_one_fired_and_where_time_went() {
    let log = Log::default();
    let _capture = log.capture();
    let cache = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(worker::executable(), Network::new(0), 1)
        .with_cache(worker::cache_config(cache.path()));
    let provider = provider();
    let request = spinning_request();
    let cancel = CancellationToken::new();
    let (first, second) = tokio::join!(
        runtime.invoke::<serde_json::Value>(&provider, &request, &cancel),
        runtime.invoke::<serde_json::Value>(&provider, &request, &cancel),
    );
    for result in [first, second] {
        let error = result.unwrap_err();
        assert!(matches!(error, PluginError::Budget), "{error:?}");
        assert_eq!(
            error.to_string(),
            "The source exceeded its execution budget"
        );
    }
    assert_eq!(runtime.available_capacity(), 1);
    let lines = log.lines();
    assert_eq!(lines.len(), 2, "{lines:#?}");
    let worker = lines
        .iter()
        .find(|line| line.contains("worker_deadline"))
        .expect("the running invocation records the worker deadline");
    let invocation = lines
        .iter()
        .find(|line| line.contains("invocation_deadline"))
        .expect("the queued invocation records the invocation deadline");
    for line in [worker, invocation] {
        assert_private(line);
        for field in [
            "source=",
            "operation=search",
            "phase=",
            "deadline_ms=60000",
            "elapsed_ms=",
            "queue_ms=",
            "verification_ms=",
            "broker_ms=",
            "inspection_ms=",
        ] {
            assert!(line.contains(field), "{field} missing from {line}");
        }
    }
    assert!(worker.contains("phase=\"worker\""), "{worker}");
    // Recorded only once a worker exchange began.
    assert!(worker.contains("worker_ms="), "{worker}");
    assert!(!invocation.contains("worker_ms="), "{invocation}");
    assert!(
        ["phase=\"queue\"", "phase=\"verification\""]
            .iter()
            .any(|phase| invocation.contains(phase)),
        "{invocation}"
    );
}

/// A real worker trap: the worker's execution-epoch or fuel limit stops the
/// spinning plugin well before the 60-second deadlines.
#[tokio::test]
async fn worker_traps_record_the_execution_limit() {
    let log = Log::default();
    let _capture = log.capture();
    let cache = tempfile::tempdir().unwrap();
    let runtime = Runtime::new(worker::executable(), Network::new(0), 1)
        .with_cache(worker::cache_config(cache.path()));
    let provider = provider();
    // Compile once first, as installation does, so the trap is not racing a
    // cold native compilation.
    runtime
        .inspect(&provider, &CancellationToken::new())
        .await
        .unwrap();
    let error = runtime
        .invoke::<serde_json::Value>(&provider, &spinning_request(), &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(matches!(error, PluginError::Budget), "{error:?}");
    let lines = log.lines();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let line = &lines[0];
    assert_private(line);
    assert!(
        ["limit=\"epoch\"", "limit=\"fuel\""]
            .iter()
            .any(|limit| line.contains(limit)),
        "{line}"
    );
    assert!(line.contains("phase=\"worker\""), "{line}");
    assert!(line.contains("execute_ms"), "{line}");
}
