#[cfg(target_os = "linux")]
#[tokio::test]
async fn browser_hardware_inventory_is_empty_readonly_and_namespace_private() {
    let mut before: Vec<_> = std::fs::read_dir("/sys/bus/pci/devices")
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    before.sort();
    let work = tempfile::tempdir().unwrap();
    let policy = omd_isolation::Policy {
        executable: std::env::var_os("OMD_TEST_ISOLATION_PROBE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_omd-isolation-probe").into()),
        readable: vec![],
        executables: vec![],
        work: work.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let output = omd_isolation::capture_progress(
        &policy,
        &[],
        omd_isolation::CaptureOptions {
            input: serde_json::to_vec(&serde_json::json!({"hardware_view": true})).unwrap(),
            environment: &std::collections::BTreeMap::new(),
            limit: 4096,
            timeout: std::time::Duration::from_secs(15),
            progress: None,
            browser: true,
        },
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        output.success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result,
        serde_json::json!({"devices": 0, "write_allowed": false, "host_devices_visible": false})
    );
    let mut after: Vec<_> = std::fs::read_dir("/sys/bus/pci/devices")
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    after.sort();
    assert_eq!(before, after, "The guardian changed the host hardware view");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[ignore = "requires the pinned managed Node and Playwright browser acceptance artifacts"]
async fn real_playwright_browser_starts_inside_native_policy() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let work = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "PRIVATE_BROWSER_FIXTURE").unwrap();
    let denied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    denied.set_nonblocking(true).unwrap();
    let browser=std::env::var_os("OMD_TEST_BROWSER").map(std::path::PathBuf::from).unwrap_or_else(|| root.join("artifacts/tools/browser/1.63.0/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64/chrome-headless-shell"));
    let node = std::env::var_os("OMD_TEST_MANAGED_NODE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            root.join("artifacts/tools/node/24.20.0/node-v24.20.0-darwin-arm64/bin/node")
        });
    assert!(browser.is_file());
    assert!(node.is_file());
    let adapter = std::env::var_os("OMD_TEST_BROWSER_ADAPTER")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("adapters/browser"));
    let policy = omd_isolation::Policy {
        executable: node,
        readable: vec![adapter.clone(), browser.parent().unwrap().into()],
        executables: vec![browser.clone()],
        work: work.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let output = omd_isolation::capture_progress(
        &policy,
        &[adapter.join("spike.mjs").to_string_lossy().into()],
        omd_isolation::CaptureOptions {
            input:serde_json::to_vec(&serde_json::json!({"executable":browser,"outside":outside.path(),"port":denied.local_addr().unwrap().port()})).unwrap(),
            environment:&std::collections::BTreeMap::new(),
            limit:65536,
            timeout:std::time::Duration::from_secs(30),
            progress:None,
            browser:true,
        },
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        output.success,
        "Browser confinement failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["heading"], "Isolated sign-in fixture");
    assert_eq!(result["value"], "fixture-account");
    for key in [
        "privateProc",
        "fileDenied",
        "executionDenied",
        "networkDenied",
        "browserFileDenied",
        "browserNetworkDenied",
    ] {
        assert_eq!(result[key], true, "{key}: {result}");
    }
    assert!(result["screenshotBytes"].as_u64().unwrap() > 1000);
    assert!(matches!(denied.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    assert_eq!(
        std::fs::read_to_string(outside.path()).unwrap(),
        "PRIVATE_BROWSER_FIXTURE"
    );
    std::fs::copy(
        work.path().join("signin-fixture.png"),
        std::env::var_os("OMD_TEST_BROWSER_EVIDENCE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| root.join("artifacts/browser-confinement-signin.png")),
    )
    .unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "native browser resource acceptance briefly reaches the 1 GiB group budget"]
async fn linux_browser_memory_and_process_budgets_terminate_the_namespace() {
    for budget in ["process", "memory"] {
        let work = tempfile::tempdir().unwrap();
        let policy = omd_isolation::Policy {
            executable: std::env::var_os("OMD_TEST_ISOLATION_PROBE")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| env!("CARGO_BIN_EXE_omd-isolation-probe").into()),
            readable: vec![],
            executables: vec![],
            work: work.path().into(),
            broker_port: None,
            broker_upstream_port: None,
            interactive: false,
        };
        let result = omd_isolation::capture_progress(
            &policy,
            &[],
            omd_isolation::CaptureOptions {
                input: serde_json::to_vec(&serde_json::json!({"native_budget":budget})).unwrap(),
                environment: &std::collections::BTreeMap::new(),
                limit: 8192,
                timeout: std::time::Duration::from_secs(15),
                progress: None,
                browser: true,
            },
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(result, Err(omd_isolation::Error::Budget)),
            "{budget}: expected group termination, budget did not terminate the namespace"
        );
        assert!(
            !std::fs::read_to_string(work.path().join("budget-pids"))
                .unwrap()
                .is_empty()
        );
        for _ in 0..40 {
            let live = std::fs::read_dir("/proc").unwrap().flatten().any(|p| {
                std::fs::read_link(p.path().join("cwd")).ok().as_deref() == Some(work.path())
            });
            if !live {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            !std::fs::read_dir("/proc")
                .unwrap()
                .flatten()
                .any(|p| std::fs::read_link(p.path().join("cwd")).ok().as_deref()
                    == Some(work.path())),
            "budget exceeded but namespace descendants remain"
        );
    }
}
