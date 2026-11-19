#![cfg(windows)]
use omd_isolation::Policy;
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn policy(work: &Path) -> Policy {
    let runtime = work.join(".omd-runtime-fixture");
    std::fs::create_dir(&runtime).unwrap();
    let executable = runtime.join("probe.exe");
    std::fs::copy(env!("CARGO_BIN_EXE_omd-isolation-probe"), &executable).unwrap();
    Policy {
        executable,
        readable: vec![],
        executables: vec![],
        work: work.into(),
        broker_port: None,
        broker_upstream_port: None,
        interactive: false,
    }
}

#[tokio::test]
async fn no_capability_container_uses_only_private_bridge_and_owned_files() {
    let parent = tempfile::tempdir().unwrap();
    let work = parent.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let outside = parent.path().join("secret.txt");
    std::fs::write(&outside, "private fixture").unwrap();
    let mut policy = policy(&work);
    let denied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    policy.broker_port = Some(reservation.local_addr().unwrap().port());
    drop(reservation);
    policy.broker_upstream_port = Some(broker.local_addr().unwrap().port());
    let reply = tokio::spawn(async move {
        let (mut stream, _) = broker.accept().await.unwrap();
        let mut request = [0; 7];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        stream.write_all(b"approved").await.unwrap();
    });
    let result = omd_isolation::capture(
        &policy,
        &[],
        serde_json::to_vec(&serde_json::json!({
            "windows_boundary": true, "outside": outside,
            "broker": format!("127.0.0.1:{}",policy.broker_port.unwrap()),
            "denied": denied.local_addr().unwrap().to_string(),
            "engine_pid":std::process::id(),
        }))
        .unwrap(),
        &BTreeMap::new(),
        8192,
        Duration::from_secs(40),
        &CancellationToken::new(),
    )
    .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let diagnostic = policy
                .command(&["--protocol".into()])
                .unwrap()
                .output()
                .await
                .unwrap();
            panic!("{error:?}: {}", String::from_utf8_lossy(&diagnostic.stderr));
        }
    };
    assert!(
        result.success,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let data: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        data,
        serde_json::json!({"appcontainer":true,"elevated":false,"broker":true,"host":false,"public":false,"outside":false,"work_write":true,"runtime_write":false,"terminate_engine":false,"private_temp":true,"ambient_env":false})
    );
    tokio::time::timeout(Duration::from_secs(2), reply)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read_to_string(outside).unwrap(), "private fixture");
}

#[tokio::test]
async fn session_exchanges_and_cancellation_use_the_same_windows_job() {
    let work = tempfile::tempdir().unwrap();
    let policy = policy(work.path());
    let mut session =
        omd_isolation::Session::start(&policy, &["--protocol".into()], &BTreeMap::new(), false)
            .unwrap();
    let cancel = CancellationToken::new();
    let ready = session
        .exchange(b"ready", 1024, Duration::from_secs(15), &cancel)
        .await;
    if let Err(error) = ready {
        let diagnostic = policy
            .command(&["--protocol".into()])
            .unwrap()
            .output()
            .await
            .unwrap();
        panic!("{error:?}: {}", String::from_utf8_lossy(&diagnostic.stderr));
    }
    assert_eq!(ready.unwrap(), b"ready");
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    assert!(matches!(
        session
            .exchange(b"stall", 1024, Duration::from_secs(10), &cancel)
            .await,
        Err(omd_isolation::Error::Canceled)
    ));
    session.close().await;
}

fn stopped(pid: u32) -> bool {
    use windows_sys::Win32::{Foundation::*, System::Threading::*};
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return std::io::Error::last_os_error().raw_os_error()
            == Some(ERROR_INVALID_PARAMETER as i32);
    }
    let stopped = unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0;
    unsafe {
        CloseHandle(handle);
    }
    stopped
}
async fn pid_file(work: &Path) -> u32 {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(value) = std::fs::read_to_string(work.join("child-pid"))
                && let Ok(pid) = value.parse()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Confined child did not start")
}
async fn assert_stopped(pid: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !stopped(pid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("A confined descendant survived its owner");
}
#[tokio::test]
async fn completion_and_cancellation_terminate_confined_descendants() {
    for stall in [false, true] {
        let work = tempfile::tempdir().unwrap();
        let policy = policy(work.path());
        let cancel = CancellationToken::new();
        let signal = cancel.clone();
        let operation = tokio::spawn(async move {
            omd_isolation::run(
                &policy,
                &[],
                serde_json::to_vec(&serde_json::json!({"spawn_child":true,"stall":stall})).unwrap(),
                8192,
                Duration::from_secs(40),
                &signal,
            )
            .await
        });
        let pid = pid_file(work.path()).await;
        if stall {
            cancel.cancel();
            assert!(matches!(
                operation.await.unwrap(),
                Err(omd_isolation::Error::Canceled)
            ));
        } else {
            operation.await.unwrap().unwrap();
        }
        // Returning cancellation must release executable/image handles before
        // the acquisition adapter removes its staged runtime, not a moment later.
        std::fs::remove_dir_all(work.path()).unwrap();
        assert_stopped(pid).await;
    }
}

#[tokio::test]
async fn deadline_waits_for_descendant_handles_before_returning_staging() {
    let work = tempfile::tempdir().unwrap();
    let policy = policy(work.path());
    let result = omd_isolation::run(
        &policy,
        &[],
        br#"{"spawn_child":true,"stall":true}"#.to_vec(),
        8192,
        Duration::from_secs(3),
        &CancellationToken::new(),
    )
    .await;
    assert!(matches!(result, Err(omd_isolation::Error::Budget)));
    let pid = std::fs::read_to_string(work.path().join("child-pid"))
        .unwrap()
        .parse()
        .unwrap();
    std::fs::remove_dir_all(work.path()).unwrap();
    assert_stopped(pid).await;
}
#[tokio::test]
async fn abrupt_engine_death_closes_the_job_and_its_descendants() {
    let work = tempfile::tempdir().unwrap();
    let mut owner = tokio::process::Command::new(env!("CARGO_BIN_EXE_omd-isolation-probe"))
        .current_dir(work.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = owner.stdin.take().unwrap();
    input.write_all(b"{\"own_helper\":true}").await.unwrap();
    drop(input);
    let pid = pid_file(work.path()).await;
    assert!(!stopped(pid));
    owner.kill().await.unwrap();
    owner.wait().await.unwrap();
    assert_stopped(pid).await;
    // A subsequent launch also performs abandoned-profile reconciliation.
    let next = tempfile::tempdir().unwrap();
    let policy = policy(next.path());
    let output = omd_isolation::run(
        &policy,
        &["--protocol".into()],
        b"recovered\n".to_vec(),
        8192,
        Duration::from_secs(20),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(output, b"recovered\n");
}

fn birth(process: std::os::windows::io::RawHandle) -> u64 {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    let mut create = FILETIME::default();
    let (mut exit, mut kernel, mut user) = (create, create, create);
    assert_ne!(
        unsafe { GetProcessTimes(process, &mut create, &mut exit, &mut kernel, &mut user) },
        0
    );
    (u64::from(create.dwHighDateTime) << 32) | u64::from(create.dwLowDateTime)
}
/// The guardian an engine started, held open so its identity stays reserved.
fn guardian_of(engine: u32) -> std::os::windows::io::OwnedHandle {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{Diagnostics::ToolHelp::*, Threading::*},
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert!(!snapshot.is_null() && snapshot as isize != -1);
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut found = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let length = entry.szExeFile.iter().position(|c| *c == 0).unwrap_or(0);
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ParentProcessID == engine
            && name.eq_ignore_ascii_case("omd-helper-guardian.exe")
        {
            found.push(entry.th32ProcessID);
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    assert_eq!(found.len(), 1, "expected exactly one guardian");
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            found[0],
        )
    };
    assert!(!process.is_null());
    unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(process) }
}
/// Read-only count of this user's registered OMD profiles whose moniker names
/// the given creator. Only that prefix is matched; nothing else is retained.
fn omd_profiles(pid: u32, born: u64) -> usize {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{Foundation::*, System::Registry::*};
    let prefix = format!("omd.helper.v2.p{pid}.t{born:016x}.");
    let wide = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<_>>();
    let scan = || {
        let mut mappings = null_mut();
        let path = wide(
            "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Mappings",
        );
        let status =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut mappings) };
        if status == ERROR_FILE_NOT_FOUND {
            return 0;
        }
        assert_eq!(status, 0);
        let value = wide("Moniker");
        let mut count = 0;
        for index in 0..16384 {
            let mut name = [0u16; 256];
            let mut size = name.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    mappings,
                    index,
                    name.as_mut_ptr(),
                    &mut size,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            assert_eq!(status, 0);
            let mut moniker = [0u16; 256];
            let mut bytes = (moniker.len() * 2) as u32;
            let status = unsafe {
                RegGetValueW(
                    mappings,
                    name.as_ptr(),
                    value.as_ptr(),
                    RRF_RT_REG_SZ,
                    null_mut(),
                    moniker.as_mut_ptr().cast(),
                    &mut bytes,
                )
            };
            // Mappings that other guardians delete during the scan are skipped.
            if status == 0
                && String::from_utf16_lossy(&moniker[..(bytes as usize / 2).saturating_sub(1)])
                    .to_ascii_lowercase()
                    .starts_with(&prefix)
            {
                count += 1;
            }
        }
        unsafe {
            RegCloseKey(mappings);
        }
        count
    };
    // Concurrent deletions shift enumeration indexes; repeat rather than miss one.
    (0..3).map(|_| scan()).max().unwrap()
}
/// Own the production mutex on this thread while preparing the recovery fixture.
/// The guardian already holds a handle, so the test opens rather than creates it.
struct ProfileFixtureHold(
    std::os::windows::io::OwnedHandle,
    std::marker::PhantomData<*const ()>,
);
impl ProfileFixtureHold {
    fn acquire() -> Self {
        use std::{
            os::windows::io::{AsRawHandle, FromRawHandle},
            ptr::null_mut,
        };
        use windows_sys::Win32::{
            Foundation::*,
            Security::{Authorization::ConvertSidToStringSidW, *},
            System::Threading::*,
        };
        let mut raw = null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
            0
        );
        let token = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
        }
        assert!(size > 0 && size <= 65536);
        let mut bytes = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    bytes.as_mut_ptr().cast(),
                    size,
                    &mut size,
                )
            },
            0
        );
        let mut sid = null_mut();
        assert_ne!(
            unsafe {
                ConvertSidToStringSidW((*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid, &mut sid)
            },
            0
        );
        let mut length = 0;
        while unsafe { *sid.add(length) } != 0 {
            length += 1;
        }
        let user = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, length) }).unwrap();
        unsafe {
            LocalFree(sid.cast());
        }
        let name = format!("Global\\OMD.V2.Helper.Profiles.{user}")
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        let raw = unsafe {
            OpenMutexW(
                SYNCHRONIZATION_SYNCHRONIZE | MUTEX_MODIFY_STATE,
                0,
                name.as_ptr(),
            )
        };
        assert!(
            !raw.is_null(),
            "The guardian did not open the global profile mutex: {}",
            std::io::Error::last_os_error()
        );
        let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        assert!(matches!(
            unsafe { WaitForSingleObject(handle.as_raw_handle(), 10000) },
            WAIT_OBJECT_0 | WAIT_ABANDONED
        ));
        Self(handle, std::marker::PhantomData)
    }
}
impl Drop for ProfileFixtureHold {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0.as_raw_handle());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn simultaneous_guardians_recover_one_abandoned_profile() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::WAIT_TIMEOUT, System::Threading::WaitForSingleObject};
    // Abandon a real, test-owned profile: kill an engine while its guardian runs.
    let work = tempfile::tempdir().unwrap();
    let mut owner = tokio::process::Command::new(env!("CARGO_BIN_EXE_omd-isolation-probe"))
        .current_dir(work.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = owner.stdin.take().unwrap();
    input.write_all(b"{\"own_helper\":true}").await.unwrap();
    drop(input);
    let descendant = pid_file(work.path()).await;
    let guardian = guardian_of(owner.id().unwrap());
    let identity = (
        unsafe { windows_sys::Win32::System::Threading::GetProcessId(guardian.as_raw_handle()) },
        birth(guardian.as_raw_handle()),
    );
    assert_eq!(omd_profiles(identity.0, identity.1), 1);
    // Acquire while the creator is alive. No other guardian can recover the
    // fixture between its creator's death and the contenders being launched.
    let fixture_hold = ProfileFixtureHold::acquire();
    owner.kill().await.unwrap();
    owner.wait().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while unsafe { WaitForSingleObject(guardian.as_raw_handle(), 0) } == WAIT_TIMEOUT {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("The guardian survived its engine");
    drop(guardian);
    assert_stopped(descendant).await;
    let abandoned = omd_profiles(identity.0, identity.1);
    assert_eq!(
        abandoned, 1,
        "The recovery fixture must contain an abandoned profile"
    );
    // Start the contenders behind the held mutex, then let them recover it.
    let works = (0..6)
        .map(|_| tempfile::tempdir().unwrap())
        .collect::<Vec<_>>();
    let commands = works
        .iter()
        .map(|work| policy(work.path()).command(&["--protocol".into()]).unwrap())
        .collect::<Vec<_>>();
    let mut contenders = Vec::new();
    for mut command in commands {
        contenders.push(command.spawn().unwrap());
    }
    drop(fixture_hold);
    let mut created = Vec::new();
    let mut outputs = Vec::new();
    for mut contender in contenders {
        let process = contender.raw_handle().unwrap();
        created.push((contender.id().unwrap(), birth(process)));
        outputs.push(tokio::spawn(async move {
            let mut input = contender.stdin.take().unwrap();
            input.write_all(b"recovered\n").await.unwrap();
            drop(input);
            tokio::time::timeout(Duration::from_secs(60), contender.wait_with_output()).await
        }));
    }
    let mut failures = Vec::new();
    for (index, output) in outputs.into_iter().enumerate() {
        let output = output
            .await
            .unwrap()
            .expect("A contending guardian did not finish")
            .unwrap();
        if !output.status.success() || output.stdout != b"recovered\n" {
            failures.push(format!(
                "guardian {index}: exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "abandoned profiles at start: {abandoned}; {failures:#?}"
    );
    assert_eq!(
        omd_profiles(identity.0, identity.1),
        0,
        "The abandoned profile was not recovered"
    );
    for (pid, born) in created {
        assert_eq!(
            omd_profiles(pid, born),
            0,
            "A guardian left its own profile"
        );
    }
    println!("abandoned profiles seen by simultaneous recovery: {abandoned}");
}

#[tokio::test]
async fn aggregate_job_limits_reject_memory_and_process_exhaustion_and_reap_children() {
    let work = tempfile::tempdir().unwrap();
    let policy = policy(work.path());
    let output = omd_isolation::run(
        &policy,
        &[],
        br#"{"windows_limits":true}"#.to_vec(),
        16384,
        Duration::from_secs(40),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["memory_denied"], true);
    assert_eq!(value["process_denied"], true);
    assert_eq!(value["memory_limit"], 2u64 * 1024 * 1024 * 1024);
    assert_eq!(value["process_limit"], 64);
    assert_eq!(value["cpu_flags"], 5); // ENABLE | HARD_CAP
    assert_eq!(value["cpu_rate"], 5000);
    let children = value["children"].as_array().unwrap();
    assert!(!children.is_empty() && children.len() < 64);
    for child in children {
        assert_stopped(child.as_u64().unwrap() as u32).await;
    }
}
