#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn real_helper_cannot_read_write_spawn_or_connect_outside_policy() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let outside = root.path().join("private.txt");
    std::fs::write(&outside, "fixture secret").unwrap();
    let broker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let policy = omd_isolation::Policy {
        executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
        readable: vec![],
        executables: vec![],
        work,
        broker_port: Some(broker.local_addr().unwrap().port()),
        broker_upstream_port: None,
        interactive: false,
    };
    let input=serde_json::to_vec(&serde_json::json!({"outside":outside,"outside_write":root.path().join("unrelated.txt"),"broker":broker.local_addr().unwrap().to_string(),"unbrokered":denied.local_addr().unwrap().to_string()})).unwrap();
    let output = omd_isolation::run(
        &policy,
        &[],
        input.clone(),
        8192,
        std::time::Duration::from_secs(10),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    let output = match output {
        Ok(value) => value,
        Err(error) => {
            use tokio::io::AsyncWriteExt;
            let mut child = policy.command(&[]).unwrap().spawn().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let _ = stdin.write_all(&input).await;
            drop(stdin);
            let diagnostic = child.wait_with_output().await.unwrap();
            panic!(
                "probe {error:?}: {:?} {}",
                diagnostic.status,
                String::from_utf8_lossy(&diagnostic.stderr)
            );
        }
    };
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        result,
        serde_json::json!({"outside_read":false,"outside_write":false,"work_write":true,"broker_connect":true,"unbrokered_connect":false,"ambient_env":false,"kill_guardian":false,"unapproved_process":false})
    );
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "fixture secret");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
#[cfg(target_os = "macos")]
#[ignore = "requires the verified managed yt-dlp artifact"]
async fn managed_ytdlp_runs_inside_the_same_confinement() {
    let work = tempfile::tempdir().unwrap();
    let executable = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/tools/yt-dlp/2026.10.26/yt-dlp_macos");
    let policy = omd_isolation::Policy {
        executable,
        readable: vec![],
        executables: vec![],
        work: work.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let args = vec![
        "--ignore-config".into(),
        "--no-plugin-dirs".into(),
        "--version".into(),
    ];
    let output = omd_isolation::run(
        &policy,
        &args,
        vec![],
        8192,
        std::time::Duration::from_secs(30),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    let output = match output {
        Ok(value) => value,
        Err(error) => {
            let diagnostic = policy.command(&args).unwrap().output().await.unwrap();
            panic!(
                "{error:?}: {:?} {}",
                diagnostic.status,
                String::from_utf8_lossy(&diagnostic.stderr)
            );
        }
    };
    assert_eq!(String::from_utf8(output).unwrap().trim(), "2026.10.26");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn completion_and_dropped_calls_reap_descendants() {
    for stall in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let policy = omd_isolation::Policy {
            executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
            readable: vec![],
            executables: vec![],
            work: root.path().into(),
            broker_port: None,
            broker_upstream_port: None,
            interactive: false,
        };
        let task = tokio::spawn(async move {
            omd_isolation::run(
                &policy,
                &[],
                serde_json::to_vec(&serde_json::json!({"spawn_child":true,"stall":stall})).unwrap(),
                8192,
                std::time::Duration::from_secs(10),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
        });
        let mut pid = None;
        for _ in 0..100 {
            if let Ok(value) = std::fs::read_to_string(root.path().join("child-pid")) {
                pid = Some(value.parse::<i32>().unwrap());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let Some(pid) = host_descendant(root.path(), pid.expect("confined child started")) else {
            assert!(!stall, "A stalled child must remain until cancellation");
            assert!(task.await.unwrap().is_ok());
            continue;
        };
        if stall {
            task.abort();
            let _ = task.await;
        } else {
            assert!(task.await.unwrap().is_ok());
        }
        let mut gone = false;
        for _ in 0..100 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(gone, "A helper descendant survived its owning operation");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn abrupt_engine_death_terminates_confined_helpers() {
    use tokio::io::AsyncWriteExt;
    let root = tempfile::tempdir().unwrap();
    let mut owner = tokio::process::Command::new(env!("CARGO_BIN_EXE_omd-isolation-probe"))
        .current_dir(root.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = owner.stdin.take().unwrap();
    input.write_all(b"{\"own_helper\":true}").await.unwrap();
    drop(input);
    let mut descendant = None;
    for _ in 0..200 {
        if let Ok(value) = std::fs::read_to_string(root.path().join("child-pid")) {
            descendant = Some(value.parse::<i32>().unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let descendant = host_descendant(
        root.path(),
        descendant.expect("supervised descendant started"),
    )
    .expect("live supervised descendant");
    owner.kill().await.unwrap();
    owner.wait().await.unwrap();
    for _ in 0..100 {
        if unsafe { libc::kill(descendant, 0) } != 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("A confined helper survived SIGKILL of the engine owner");
}

#[cfg(target_os = "macos")]
fn host_descendant(_: &std::path::Path, pid: i32) -> Option<i32> {
    Some(pid)
}
#[cfg(target_os = "linux")]
fn host_descendant(work: &std::path::Path, _namespace_pid: i32) -> Option<i32> {
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|v| v.parse::<i32>().ok())
        else {
            continue;
        };
        if std::fs::read_link(entry.path().join("cwd")).ok().as_deref() == Some(work)
            && std::fs::read(entry.path().join("cmdline"))
                .unwrap_or_default()
                .split(|c| *c == 0)
                .any(|v| v == b"--sleep")
        {
            return Some(pid);
        }
    }
    None
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_broker_roundtrip_and_alternate_escape_paths() {
    use std::io::{Read, Write};
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let outside = root.path().join("private");
    std::fs::write(&outside, "fixture").unwrap();
    let before = std::fs::metadata(&outside).unwrap();
    let socket = root.path().join("host.socket");
    let _unix = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let broker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = broker.local_addr().unwrap();
    broker.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < until {
            if let Ok((mut client, _)) = broker.accept() {
                client
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut request = [0u8; 7];
                client.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"request");
                client.write_all(b"approved").unwrap();
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("broker request never arrived");
    });
    let policy = omd_isolation::Policy {
        executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
        readable: vec![],
        executables: vec![],
        work,
        broker_port: Some(address.port()),
        broker_upstream_port: None,
        interactive: false,
    };
    let output = omd_isolation::run(&policy,&[],serde_json::to_vec(&serde_json::json!({"extended":true,"outside":outside,"unix":socket,"broker":address.to_string()})).unwrap(),8192,std::time::Duration::from_secs(10),&tokio_util::sync::CancellationToken::new()).await.unwrap();
    server.join().unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        result,
        serde_json::json!({"metadata_write":false,"timestamp_write":false,"symlink_escape":false,"unix_escape":false,"udp_socket":false,"namespace_escape":false,"io_uring_denied":true,"broker_roundtrip":true})
    );
    assert_eq!(
        std::fs::metadata(&outside).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "fixture");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_process_budget_is_enforced() {
    assert_ne!(
        unsafe { libc::getuid() },
        0,
        "Run release confinement acceptance as an ordinary user"
    );
    let root = tempfile::tempdir().unwrap();
    let policy = omd_isolation::Policy {
        executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
        readable: vec![],
        executables: vec![],
        work: root.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let output = omd_isolation::run(
        &policy,
        &[],
        b"{\"extended\":true,\"process_budget\":true}".to_vec(),
        8192,
        std::time::Duration::from_secs(10),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let children = result["children"].as_u64().unwrap();
    assert!(
        (1..64).contains(&children),
        "Native process count was not bounded: {children}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires the verified platform yt-dlp standalone artifact"]
async fn linux_managed_ytdlp_starts_inside_confinement() {
    let work = tempfile::tempdir().unwrap();
    let policy = omd_isolation::Policy {
        executable: std::env::var_os("OMD_TEST_MANAGED_YTDLP")
            .expect("verified test tool path")
            .into(),
        readable: vec![],
        executables: vec![],
        work: work.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let args = ["--ignore-config", "--no-plugin-dirs", "--version"].map(String::from);
    let output = omd_isolation::capture(
        &policy,
        &args,
        vec![],
        &std::collections::BTreeMap::new(),
        8192,
        std::time::Duration::from_secs(30),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        output.success,
        "Standalone tool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "2026.10.26"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires the verified platform Node artifact"]
async fn linux_managed_node_runs_javascript_inside_confinement() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let secret = root.path().join("private");
    std::fs::write(&secret, "fixture").unwrap();
    let code = r#"const fs=require('node:fs'); let denied=false;try{fs.readFileSync(process.argv[1])}catch(e){denied=e.code==='EACCES'}; fs.writeFileSync('result','approved');let executed=false;try{require('node:child_process').execFileSync('/usr/bin/true');executed=true}catch{};console.log(JSON.stringify({denied,executed,version:process.version}));"#;
    let policy = omd_isolation::Policy {
        executable: std::env::var_os("OMD_TEST_MANAGED_NODE")
            .expect("verified Node path")
            .into(),
        readable: vec![],
        executables: vec![],
        work: work.clone(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let output = omd_isolation::capture(
        &policy,
        &["-e".into(), code.into(), secret.to_string_lossy().into()],
        vec![],
        &std::collections::BTreeMap::new(),
        8192,
        std::time::Duration::from_secs(30),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        output.success,
        "Managed Node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value,
        serde_json::json!({"denied":true,"executed":false,"version":"v24.20.0"})
    );
    assert_eq!(
        std::fs::read_to_string(work.join("result")).unwrap(),
        "approved"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "must run with required namespace protection denied by the outer test container"]
async fn linux_missing_protection_never_executes_tool() {
    assert_eq!(
        std::env::var("OMD_EXPECT_CONFINEMENT_UNAVAILABLE").as_deref(),
        Ok("1")
    );
    let work = tempfile::tempdir().unwrap();
    let policy = omd_isolation::Policy {
        executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
        readable: vec![],
        executables: vec![],
        work: work.path().into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    };
    let result = omd_isolation::run(
        &policy,
        &[],
        b"{\"spawn_child\":true}".to_vec(),
        8192,
        std::time::Duration::from_secs(10),
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    assert!(
        matches!(result, Err(omd_isolation::Error::Unavailable)),
        "Unexpected confinement result: {result:?}"
    );
    assert!(!work.path().join("child-pid").exists());
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "native resource acceptance briefly allocates up to the 1 GiB group budget"]
async fn macos_group_process_and_aggregate_memory_budgets_terminate_all_descendants() {
    for budget in ["process", "memory"] {
        let work = tempfile::tempdir().unwrap();
        let policy = omd_isolation::Policy {
            executable: env!("CARGO_BIN_EXE_omd-isolation-probe").into(),
            readable: vec![],
            executables: vec![],
            work: work.path().into(),
            broker_port: None,
            broker_upstream_port: None,
            interactive: false,
        };
        let result = omd_isolation::capture(
            &policy,
            &[],
            serde_json::to_vec(&serde_json::json!({"macos_budget":budget})).unwrap(),
            &std::collections::BTreeMap::new(),
            8192,
            std::time::Duration::from_secs(15),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(result, Err(omd_isolation::Error::Budget)),
            "{budget}: expected native group budget termination"
        );
        let ids = std::fs::read_to_string(work.path().join("budget-pids")).unwrap();
        for pid in ids.lines().map(|pid| pid.parse::<i32>().unwrap()) {
            let mut alive = true;
            for _ in 0..40 {
                alive = unsafe { libc::kill(pid, 0) } == 0;
                if !alive {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            assert!(!alive, "budget termination left descendant {pid}");
        }
    }
}
