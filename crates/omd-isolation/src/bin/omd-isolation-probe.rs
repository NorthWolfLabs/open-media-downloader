//! Deterministic release acceptance helper. It receives no real user paths/data.
use std::{
    io::Read,
    net::{SocketAddr, TcpStream},
    time::Duration,
};
// This acceptance probe intentionally leaves a descendant for the supervisor
// to reap. Waiting here would defeat the process-tree cleanup regression test.
#[allow(clippy::zombie_processes)]
fn main() {
    if std::env::args().any(|arg| arg == "--hold-memory") {
        let mut bytes = vec![0u8; 192 * 1024 * 1024];
        for page in bytes.chunks_mut(4096) {
            page[0] = 1;
        }
        std::hint::black_box(&bytes);
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if std::env::args().any(|arg| arg == "--protocol") {
        use std::io::{BufRead, Write};
        for line in std::io::stdin().lock().lines() {
            let line = line.unwrap();
            match line.as_str() {
                "stall" => std::thread::sleep(Duration::from_secs(60)),
                "stdout-budget" => println!("{}", "x".repeat(65536)),
                "stderr-budget" => {
                    eprint!("{}", "x".repeat(131072));
                    std::thread::sleep(Duration::from_secs(60));
                }
                "unavailable" => {
                    eprintln!("OMD confinement unavailable");
                    return;
                }
                _ => println!("{line}"),
            }
            std::io::stdout().flush().unwrap();
        }
        return;
    }
    if std::env::args().any(|arg| arg == "--sleep") {
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let request: serde_json::Value = serde_json::from_str(&input).unwrap();
    #[cfg(windows)]
    if request["windows_limits"] == true {
        use windows_sys::Win32::System::{JobObjects::*, Memory::*};
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        unsafe {
            assert_ne!(
                QueryInformationJobObject(
                    std::ptr::null_mut(),
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_ne!(
                QueryInformationJobObject(
                    std::ptr::null_mut(),
                    JobObjectCpuRateControlInformation,
                    (&mut cpu as *mut JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                    std::mem::size_of_val(&cpu) as u32,
                    std::ptr::null_mut()
                ),
                0
            );
        }
        // Commit is rejected by the aggregate job limit; do not touch or retain
        // large allocations on the release machine even if this assertion fails.
        let allocation = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                2 * 1024 * 1024 * 1024 + 4096,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        };
        let memory_denied = allocation.is_null();
        if !memory_denied {
            unsafe {
                VirtualFree(allocation, 0, MEM_RELEASE);
            }
        }
        let mut children = Vec::new();
        let mut process_denied = false;
        for _ in 0..70 {
            match std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--sleep")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(child) => children.push(child),
                Err(_) => {
                    process_denied = true;
                    break;
                }
            }
        }
        println!(
            "{}",
            serde_json::json!({"memory_denied":memory_denied,"process_denied":process_denied,
            "memory_limit":limits.JobMemoryLimit,"process_limit":limits.BasicLimitInformation.ActiveProcessLimit,
            "cpu_flags":cpu.ControlFlags,"cpu_rate":unsafe {cpu.Anonymous.CpuRate},
            "children":children.iter().map(|child|child.id()).collect::<Vec<_>>()})
        );
        return;
    }
    #[cfg(windows)]
    if request["windows_boundary"] == true {
        use std::io::Write;
        use windows_sys::Win32::{Foundation::CloseHandle, Security::*, System::Threading::*};
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let (mut app, mut elevated, mut size) = (0u32, 0u32, 0u32);
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenIsAppContainer,
                    (&mut app as *mut u32).cast(),
                    4,
                    &mut size,
                )
            },
            0
        );
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenElevation,
                    (&mut elevated as *mut u32).cast(),
                    4,
                    &mut size,
                )
            },
            0
        );
        let mut info = vec![0usize; 128];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token,
                    TokenAppContainerSid,
                    info.as_mut_ptr().cast(),
                    (info.len() * std::mem::size_of::<usize>()) as u32,
                    &mut size,
                )
            },
            0
        );
        let sid = unsafe {
            (*(info.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>())).TokenAppContainer
        };
        let mut sid_text = std::ptr::null_mut();
        assert_ne!(
            unsafe { Authorization::ConvertSidToStringSidW(sid, &mut sid_text) },
            0
        );
        let mut folder = std::ptr::null_mut();
        assert_eq!(
            unsafe { Isolation::GetAppContainerFolderPath(sid_text, &mut folder) },
            0
        );
        let mut count = 0;
        while unsafe { *folder.add(count) } != 0 {
            count += 1;
            assert!(count < 32768);
        }
        let container_folder = std::path::PathBuf::from(
            String::from_utf16(unsafe { std::slice::from_raw_parts(folder, count) }).unwrap(),
        );
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(sid_text.cast());
            windows_sys::Win32::System::Com::CoTaskMemFree(folder.cast());
            CloseHandle(token);
        }
        let connect = |address: &str| {
            TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(1)).is_ok()
        };
        let mut broker = TcpStream::connect(request["broker"].as_str().unwrap()).unwrap();
        broker
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        broker.write_all(b"request").unwrap();
        let mut bytes = [0; 8];
        let roundtrip = broker.read_exact(&mut bytes).is_ok() && &bytes == b"approved";
        let engine = unsafe {
            OpenProcess(
                PROCESS_TERMINATE,
                0,
                request["engine_pid"].as_u64().unwrap() as u32,
            )
        };
        // Only test acquisition of the forbidden handle; never terminate the engine.
        let terminate = !engine.is_null();
        if terminate {
            unsafe {
                CloseHandle(engine);
            }
        }
        let own = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("forbidden.txt");
        let spelling = |path: std::path::PathBuf| {
            path.to_string_lossy()
                .strip_prefix(r"\\?\")
                .map(std::path::PathBuf::from)
                .unwrap_or(path)
        };
        let work = spelling(std::env::current_dir().unwrap());
        let temporary = std::env::temp_dir();
        let private_temp = spelling(temporary.clone()).starts_with(spelling(container_folder))
            && std::fs::write(temporary.join("temp-fixture.txt"), b"temporary fixture").is_ok();
        println!(
            "{}",
            serde_json::json!({"appcontainer":app==1,"elevated":elevated!=0,"broker":roundtrip,"host":connect(request["denied"].as_str().unwrap()),"public":connect("1.1.1.1:443"),"outside":std::fs::read(request["outside"].as_str().unwrap()).is_ok(),"work_write":std::fs::write("allowed.txt","fixture").is_ok(),"runtime_write":std::fs::write(own,"forbidden").is_ok(),"terminate_engine":terminate,"private_temp":private_temp,"ambient_env":std::env::var_os("USERPROFILE").map(std::path::PathBuf::from).map(spelling)!=Some(work)})
        );
        return;
    }
    if let Some(policy) = request.get("run_policy") {
        // Acceptance-only driver; this probe is never included in app packages.
        // Exercise the actual platform command builder instead of duplicating a
        // sandbox profile in the Python distribution verification harness.
        use std::io::Write;
        let policy: omd_isolation::Policy = serde_json::from_value(policy.clone()).unwrap();
        let args: Vec<String> = serde_json::from_value(request["args"].clone()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match runtime.block_on(omd_isolation::capture(
            &policy,
            &args,
            vec![],
            &std::collections::BTreeMap::new(),
            128 * 1024,
            Duration::from_secs(45),
            &tokio_util::sync::CancellationToken::new(),
        )) {
            Ok(output) if output.success => std::io::stdout().write_all(&output.stdout).unwrap(),
            Ok(output) => {
                std::io::stderr().write_all(&output.stderr).unwrap();
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(budget) = request["native_budget"]
        .as_str()
        .or_else(|| request["macos_budget"].as_str())
    {
        use std::io::Write;
        let mut ids = std::fs::File::create("budget-pids").unwrap();
        for _ in 0..if budget == "memory" { 7 } else { 35 } {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .arg(if budget == "memory" {
                    "--hold-memory"
                } else {
                    "--sleep"
                })
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            writeln!(&mut ids, "{}", child.id()).unwrap();
            ids.flush().unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    #[cfg(target_os = "linux")]
    if request["hardware_view"] == true {
        let devices = std::fs::read_dir("/sys/bus/pci/devices").unwrap();
        println!(
            "{}",
            serde_json::json!({
                "devices": devices.count(),
                "write_allowed": std::fs::write("/sys/bus/pci/devices/forbidden", "fixture").is_ok(),
                "host_devices_visible": std::fs::read_dir("/sys/devices").is_ok(),
            })
        );
        return;
    }
    #[cfg(target_os = "linux")]
    if request["extended"] == true {
        linux_extended(&request);
        return;
    }
    if request["own_helper"] == true {
        #[cfg(windows)]
        let executable = {
            let runtime = std::env::current_dir().unwrap().join(".omd-runtime-owner");
            std::fs::create_dir(&runtime).unwrap();
            let executable = runtime.join("probe.exe");
            std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
            executable
        };
        #[cfg(not(windows))]
        let executable = std::env::current_exe().unwrap();
        let policy = omd_isolation::Policy {
            executable,
            readable: vec![],
            executables: vec![],
            work: std::env::current_dir().unwrap(),
            broker_port: None,
            broker_upstream_port: None,
            interactive: false,
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime
            .block_on(omd_isolation::run(
                &policy,
                &[],
                serde_json::to_vec(&serde_json::json!({"spawn_child":true,"stall":true})).unwrap(),
                8192,
                Duration::from_secs(60),
                &tokio_util::sync::CancellationToken::new(),
            ))
            .unwrap();
        return;
    }
    if request["spawn_child"] == true {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--sleep")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Publish readiness only after the PID is complete. Readers can otherwise
        // observe the empty file between creation and the first write.
        std::fs::write("child-pid.tmp", child.id().to_string()).unwrap();
        std::fs::rename("child-pid.tmp", "child-pid").unwrap();
        if request["stall"] == true {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        println!("{{\"child\":{}}}", child.id());
        return;
    }
    let connect = |key: &str| {
        request[key].as_str().is_some_and(|value| {
            TcpStream::connect_timeout(
                &value.parse::<SocketAddr>().unwrap(),
                Duration::from_millis(500),
            )
            .is_ok()
        })
    };
    let result = serde_json::json!({
        "outside_read":std::fs::read(request["outside"].as_str().unwrap()).is_ok(),
        "outside_write":std::fs::write(request["outside_write"].as_str().unwrap(),"forbidden").is_ok(),
        "work_write":std::fs::write("allowed.txt","fixture").is_ok(),
        "broker_connect":connect("broker"),"unbrokered_connect":connect("unbrokered"),
        "ambient_env":std::env::var("OMD_AMBIENT_SECRET").is_ok(),
        "kill_guardian":kill_guardian(),
        "unapproved_process":std::process::Command::new(if cfg!(windows){"C:\\Windows\\System32\\cmd.exe"}else{"/usr/bin/true"}).status().is_ok_and(|s|s.success())
    });
    println!("{result}");
}

#[cfg(unix)]
fn kill_guardian() -> bool {
    unsafe { libc::kill(libc::getppid(), libc::SIGKILL) == 0 }
}
#[cfg(not(unix))]
fn kill_guardian() -> bool {
    false
}

#[cfg(target_os = "linux")]
fn linux_extended(request: &serde_json::Value) {
    use std::{
        io::Write,
        os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
            net::UnixStream,
        },
    };
    if request["process_budget"] == true {
        let mut children = vec![];
        for _ in 0..100 {
            match std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--sleep")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(child) => children.push(child),
                Err(_) => break,
            }
        }
        println!("{}", serde_json::json!({"children":children.len()}));
        return;
    }
    let outside = std::path::Path::new(request["outside"].as_str().unwrap());
    let path = std::ffi::CString::new(outside.as_os_str().as_bytes()).unwrap();
    let metadata_write =
        std::fs::set_permissions(outside, std::fs::Permissions::from_mode(0o600)).is_ok();
    let timestamp_write =
        unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), std::ptr::null(), 0) == 0 };
    let symlink_escape = symlink(outside, "escape").is_ok() && std::fs::read("escape").is_ok();
    let unix_escape = UnixStream::connect(request["unix"].as_str().unwrap()).is_ok();
    let udp = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if udp >= 0 {
        unsafe {
            libc::close(udp);
        }
    }
    let namespace_escape = unsafe { libc::unshare(libc::CLONE_NEWUSER) == 0 };
    let io_uring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 0, std::ptr::null::<u8>()) };
    let io_uring_denied =
        io_uring < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    let mut broker = TcpStream::connect(request["broker"].as_str().unwrap()).unwrap();
    broker
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    broker.write_all(b"request").unwrap();
    let mut response = [0u8; 8];
    let broker_roundtrip = broker.read_exact(&mut response).is_ok() && &response == b"approved";
    println!(
        "{}",
        serde_json::json!({"metadata_write":metadata_write,"timestamp_write":timestamp_write,
        "symlink_escape":symlink_escape,"unix_escape":unix_escape,"udp_socket":udp>=0,
        "namespace_escape":namespace_escape,"io_uring_denied":io_uring_denied,"broker_roundtrip":broker_roundtrip})
    );
}
