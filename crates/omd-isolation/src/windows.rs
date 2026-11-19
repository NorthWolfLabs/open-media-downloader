//! Per-invocation AppContainer with NO network capabilities or loopback exemption.
//! A second process in the same container bridges its internal TCP listener to a
//! private, SID-scoped named pipe. Only the guardian can reach the engine proxy.
//! No privileged service, machine firewall mutation, or unrestricted fallback.
use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{Console::*, Diagnostics::ToolHelp::*, JobObjects::*, Threading::*},
};

#[path = "windows_profiles.rs"]
mod profiles;
#[path = "windows_job.rs"]
mod windows_job;
use windows_job::Job;
type Result<T> = io::Result<T>;
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}
fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn at(phase: &str, error: io::Error) -> io::Error {
    io::Error::other(format!("{phase}: OS {:?}", error.raw_os_error()))
}
fn invalid() -> io::Error {
    io::Error::other("Invalid native confinement configuration")
}
fn owned(handle: HANDLE) -> Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid_text(sid: PSID) -> Result<String> {
    let mut value = null_mut();
    check(unsafe { ConvertSidToStringSidW(sid, &mut value) })?;
    let _memory = Local(value.cast());
    let mut n = 0;
    while unsafe { *value.add(n) } != 0 {
        n += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, n) }).map_err(|_| invalid())
}
fn owner() -> Result<String> {
    let mut raw = null_mut();
    check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
    let token = owned(raw)?;
    let (mut elevation, mut length) = (0u32, 0u32);
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut u32).cast(),
            4,
            &mut length,
        )
    })?;
    if elevation != 0 {
        return Err(io::Error::other(
            "OMD elevated engine: restart without administrator privileges",
        ));
    }
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err(invalid());
    }
    let mut bytes = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    check(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            bytes.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    })?;
    sid_text(unsafe { (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}
fn descriptor(sddl: &str) -> Result<Local> {
    let mut value = null_mut();
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut value,
            null_mut(),
        )
    })?;
    Ok(Local(value))
}
struct Container {
    name: String,
    sid: PSID,
    lock: profiles::ProfileLock,
}
impl Container {
    // Recovery and creation happen under one profile lock hold, which ends
    // before this returns. It is never held while a helper runs.
    fn new(user: &str) -> Result<Self> {
        let lock = profiles::ProfileLock::open(user)?;
        let held = lock.acquire()?;
        profiles::recover(&held)?;
        let born = profiles::birth(unsafe { GetCurrentProcess() })?;
        let name = format!(
            "OMD.Helper.V2.P{}.T{born:016x}.{}",
            std::process::id(),
            &uuid::Uuid::new_v4().simple().to_string()[..16]
        );
        let mut sid = null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                wide(&name).as_ptr(),
                wide("OMD private helper").as_ptr(),
                wide("Temporary acquisition helper").as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        drop(held);
        Ok(Self { name, sid, lock })
    }
}
impl Drop for Container {
    fn drop(&mut self) {
        // Delete only under the profile lock. If it cannot be acquired in time,
        // keep the profile: once this guardian exits it is abandoned, and the
        // next locked recovery pass can remove it if its mapping remains intact.
        if let Ok(_held) = self.lock.acquire() {
            unsafe {
                DeleteAppContainerProfile(wide(&self.name).as_ptr());
            }
        }
        unsafe {
            FreeSid(self.sid);
        }
    }
}

fn secure_tree(work: &Path, immutable: &[PathBuf], user: &str, sid: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    let mut pending = vec![work.to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        count += 1;
        if count > 16384 {
            return Err(invalid());
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid());
        }
        let read_only = immutable.iter().any(|root| path.starts_with(root));
        // No FILE_DELETE_CHILD on writable parents: otherwise a helper could
        // remove a read-only runtime directory through its parent permission.
        let mask = if read_only {
            "0x001200a9"
        } else {
            "0x001301bf"
        };
        let inheritance = if metadata.is_dir() { "OICI" } else { "" };
        let sd = descriptor(&format!(
            "D:P(A;{inheritance};FA;;;{user})(A;{inheritance};FA;;;SY)(A;{inheritance};{mask};;;{sid})S:(ML;;NW;;;LW)"
        ))?;
        let mut dacl = null_mut();
        let (mut present, mut defaulted) = (0, 0);
        check(unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) })?;
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide(&path).as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // Low-integrity helpers need a low label as well as the explicit DACL.
        check(unsafe { SetFileSecurityW(wide(&path).as_ptr(), LABEL_SECURITY_INFORMATION, sd.0) })?;
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}
fn parent_handle(expected: u32) -> Result<OwnedHandle> {
    let snapshot = owned(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    check(unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) })?;
    let actual = loop {
        if entry.th32ProcessID == std::process::id() {
            break entry.th32ParentProcessID;
        }
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            return Err(invalid());
        }
    };
    if actual != expected || expected <= 1 {
        return Err(invalid());
    }
    let parent = owned(unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            expected,
        )
    })?;
    // Toolhelp keeps numeric parent IDs after termination. Reject a new process
    // that reused that ID before this guardian could acquire its watch handle.
    if profiles::birth(parent.as_raw_handle())? > profiles::birth(unsafe { GetCurrentProcess() })?
        || unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } != WAIT_TIMEOUT
    {
        return Err(invalid());
    }
    Ok(parent)
}
// Windows command-line quoting, including trailing backslashes before a quote.
fn quote(value: &std::ffi::OsStr) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in value.to_string_lossy().chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        if c == '"' {
            result.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
        } else {
            result.extend(std::iter::repeat_n('\\', slashes));
        }
        slashes = 0;
        result.push(c);
    }
    result.extend(std::iter::repeat_n('\\', slashes * 2));
    result.push('"');
    result
}
struct Attributes {
    bytes: Vec<usize>,
}
impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size);
        }
        let mut value = Self {
            bytes: vec![0; size.div_ceil(size_of::<usize>())],
        };
        check(unsafe { InitializeProcThreadAttributeList(value.raw(), count, 0, &mut size) })?;
        Ok(value)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.bytes.as_mut_ptr().cast()
    }
    fn add<T>(&mut self, kind: u32, value: &T) -> Result<()> {
        check(unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                kind as usize,
                (value as *const T).cast(),
                size_of::<T>(),
                null_mut(),
                null(),
            )
        })
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.raw());
        }
    }
}
fn launch(
    exe: &Path,
    args: &[String],
    work: &Path,
    container: &Container,
    job: &Job,
    stdio: bool,
) -> Result<OwnedHandle> {
    let mut attrs = Attributes::new(if stdio { 3 } else { 2 })?;
    let caps = SECURITY_CAPABILITIES {
        AppContainerSid: container.sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    attrs.add(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps)?;
    let job_handle = job.as_raw_handle();
    attrs.add(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle)?;
    let mut handles = Vec::new();
    let mut list = [null_mut(); 3];
    if stdio {
        for (index, kind) in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
            .into_iter()
            .enumerate()
        {
            let original = unsafe { windows_sys::Win32::System::Console::GetStdHandle(kind) };
            let mut handle = null_mut();
            check(unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    original,
                    GetCurrentProcess(),
                    &mut handle,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            })?;
            handles.push(owned(handle)?);
            list[index] = handle;
        }
        attrs.add(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &list)?;
    }
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of_val(&startup) as u32;
    startup.lpAttributeList = attrs.raw();
    if stdio {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = list[0];
        startup.StartupInfo.hStdOutput = list[1];
        startup.StartupInfo.hStdError = list[2];
    }
    let text = std::iter::once(quote(exe.as_os_str()))
        .chain(args.iter().map(|s| quote(s.as_ref())))
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd = wide(text);
    if cmd.len() > 30000 {
        return Err(invalid());
    }
    // Keep LOCALAPPDATA for Windows to locate the newly registered container's
    // private scratch profile; this grants no access to other user data. Home
    // and configuration discovery still point at the acquisition workspace.
    // Sort case-insensitively as Win32 requires.
    let mut values = std::collections::BTreeMap::<String, (String, std::ffi::OsString)>::new();
    for name in [
        "CURL_CA_BUNDLE",
        "HOME",
        "LANG",
        "LOCALAPPDATA",
        "NODE_EXTRA_CA_CERTS",
        "PATH",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SystemRoot",
        "SystemDrive",
        "TEMP",
        "TMP",
        "TMPDIR",
        "windir",
    ] {
        if let Some(value) = std::env::var_os(name) {
            values.insert(name.to_ascii_uppercase(), (name.into(), value));
        }
    }
    // The MSVC CRT's temporary-directory check does not accept the verbatim
    // prefix returned by Rust canonicalize. Use the ordinary DOS spelling only
    // after proving it resolves back to the exact validated workspace.
    let conventional = work
        .to_string_lossy()
        .strip_prefix(r"\\?\")
        .map(PathBuf::from);
    let runtime_work = conventional
        .as_deref()
        .filter(|path| std::fs::canonicalize(path).is_ok_and(|canonical| canonical == work))
        .unwrap_or(work);
    for name in ["APPDATA", "USERPROFILE", "HOME", "TEMP", "TMP", "TMPDIR"] {
        values.insert(
            name.into(),
            (name.into(), runtime_work.as_os_str().to_owned()),
        );
    }
    // Verified runtime copies contain no symlinks. Node's default realpath walk
    // probes every ancestor (including C:\), which is intentionally outside
    // this container's authority. Preserve already-verified module paths.
    values.insert(
        "NODE_OPTIONS".into(),
        (
            "NODE_OPTIONS".into(),
            "--preserve-symlinks --preserve-symlinks-main".into(),
        ),
    );
    let mut environment = Vec::<u16>::new();
    for (_, (name, value)) in values {
        environment.extend(wide(format!("{name}={}", value.to_string_lossy())));
    }
    environment.push(0);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    check(unsafe {
        CreateProcessW(
            wide(exe).as_ptr(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            i32::from(stdio),
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            wide(work).as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    })?;
    let _thread = owned(process.hThread)?;
    owned(process.hProcess)
}
fn server(name: &str, first: bool, sd: &Local) -> Result<NamedPipeServer> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(32)
            .create_with_security_attributes_raw(
                name,
                (&attributes as *const SECURITY_ATTRIBUTES)
                    .cast_mut()
                    .cast(),
            )
    }
}
fn client(name: &str) -> Result<NamedPipeClient> {
    let handle = owned(unsafe {
        CreateFileW(
            wide(name).as_ptr(),
            0x0012019b,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    })?;
    use std::os::windows::io::IntoRawHandle;
    unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle()) }
}
async fn bridge(name: &str, port: u16) -> Result<()> {
    // The bridge itself has the exact same zero-capability AppContainer token.
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    let mut ready = client(name)?;
    ready.write_all(b"OMDREADY").await?;
    drop(ready);
    let capacity = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let permit = capacity
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| invalid())?;
        let (mut socket, _) = listener.accept().await?;
        let mut pipe = client(name)?;
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::io::copy_bidirectional(&mut socket, &mut pipe).await;
        });
    }
}
async fn supervise(parent: u32, policy: omd_isolation::Policy, args: Vec<String>) -> Result<i32> {
    let parent = parent_handle(parent).map_err(|e| at("parent", e))?;
    std::thread::spawn(move || unsafe {
        WaitForSingleObject(parent.as_raw_handle(), INFINITE);
        TerminateProcess(GetCurrentProcess(), 126);
    });
    let work = std::fs::canonicalize(&policy.work)?;
    let user = owner()?;
    let container = Container::new(&user).map_err(|e| at("profile", e))?;
    let sid = sid_text(container.sid)?;
    // Only per-session verified copies can receive access. Installed tools,
    // source packages, engine profile files and credential stores stay untouched.
    let mut immutable = Vec::new();
    for path in policy
        .readable
        .iter()
        .chain(policy.executables.iter())
        .chain([&policy.executable])
    {
        let path = std::fs::canonicalize(path)?;
        let relative = path.strip_prefix(&work).map_err(|_| invalid())?;
        let root = relative
            .components()
            .next()
            .ok_or_else(invalid)?
            .as_os_str();
        if !root.to_string_lossy().starts_with(".omd-runtime-") {
            return Err(invalid());
        }
        let root = work.join(root);
        if !immutable.contains(&root) {
            immutable.push(root);
        }
    }
    let runtime = work.join(format!(
        ".omd-runtime-bridge-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&runtime)?;
    struct Runtime(PathBuf);
    impl Drop for Runtime {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _runtime = Runtime(runtime.clone());
    // Windows redirects TEMP to the new AppContainer's own profile. Keep that
    // OS-owned scratch path independent of potentially long acquisition paths.
    // Its SID already grants exclusive package access; DeleteAppContainerProfile
    // handles normal cleanup and the recovery pass handles abandoned profiles.
    let executable = runtime.join("omd-helper-bridge.exe");
    std::fs::copy(std::env::current_exe()?, &executable)?;
    immutable.push(runtime);
    secure_tree(&work, &immutable, &user, &sid).map_err(|e| at("files", e))?;
    let job = Job::guardian().map_err(|e| at("job", e))?;
    let mut broker_task = None;
    let mut bridge_process = None;
    if let (Some(port), Some(upstream)) = (policy.broker_port, policy.broker_upstream_port) {
        if port == 0 || upstream == 0 || port == upstream {
            return Err(invalid());
        }
        let name = format!("\\\\.\\pipe\\{}", container.name);
        let sd = descriptor(&format!(
            "D:P(A;;GA;;;{user})(A;;0x0012019b;;;{sid})S:(ML;;NW;;;LW)"
        ))?;
        let mut ready = server(&name, true, &sd)?;
        bridge_process = Some(launch(
            &executable,
            &["--bridge".into(), name.clone(), port.to_string()],
            &work,
            &container,
            &job,
            false,
        )?);
        tokio::time::timeout(Duration::from_secs(15), ready.connect())
            .await
            .map_err(|_| invalid())??;
        // Hold the first instance while publishing the next to prevent name reuse.
        let mut next = server(&name, false, &sd)?;
        let mut marker = [0; 8];
        tokio::time::timeout(Duration::from_secs(5), ready.read_exact(&mut marker))
            .await
            .map_err(|_| invalid())??;
        if &marker != b"OMDREADY" {
            return Err(invalid());
        }
        drop(ready);
        // Build descriptors inside this task rather than sending raw pointers.
        let sddl = format!("D:P(A;;GA;;;{user})(A;;0x0012019b;;;{sid})S:(ML;;NW;;;LW)");
        broker_task = Some(tokio::spawn(async move {
            let capacity = std::sync::Arc::new(tokio::sync::Semaphore::new(16));
            loop {
                let permit = capacity
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| invalid())?;
                next.connect().await?;
                let following = {
                    let sd = descriptor(&sddl)?;
                    server(&name, false, &sd)?
                };
                let mut connected = std::mem::replace(&mut next, following);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Ok(mut upstream) =
                        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, upstream)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut connected, &mut upstream).await;
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), io::Error>(())
        }));
    } else if policy.broker_port.is_some() || policy.broker_upstream_port.is_some() {
        return Err(invalid());
    }
    let child = launch(&policy.executable, &args, &work, &container, &job, true)
        .map_err(|e| at("helper", e))?;
    let result = loop {
        if bridge_process
            .as_ref()
            .is_some_and(|p| unsafe { WaitForSingleObject(p.as_raw_handle(), 0) } != WAIT_TIMEOUT)
            || broker_task.as_ref().is_some_and(|t| t.is_finished())
        {
            break Err(invalid());
        }
        match unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 126;
                check(unsafe { GetExitCodeProcess(child.as_raw_handle(), &mut code) })?;
                break Ok(code as i32);
            }
            WAIT_TIMEOUT => {}
            _ => break Err(io::Error::last_os_error()),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Kill descendants and wait for kernel termination before deleting runtime
    // files or the AppContainer profile. Parent death also closes the job handle.
    unsafe {
        TerminateJobObject(job.as_raw_handle(), 126);
    }
    if let Some(task) = broker_task {
        task.abort();
    }
    unsafe {
        WaitForSingleObject(child.as_raw_handle(), 5000);
    }
    if let Some(process) = bridge_process {
        unsafe {
            WaitForSingleObject(process.as_raw_handle(), 5000);
        }
    }
    job.drain().await?;
    drop(child);
    drop(job);
    result
}
pub fn main() -> Result<i32> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or_else(invalid)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if first == "--bridge" {
        let name = args.next().ok_or_else(invalid)?;
        let port = args
            .next()
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        runtime.block_on(bridge(&name, port))?;
        Ok(0)
    } else {
        let parent = first.parse().map_err(|_| invalid())?;
        let policy =
            serde_json::from_str(&args.next().ok_or_else(invalid)?).map_err(|_| invalid())?;
        runtime.block_on(supervise(parent, policy, args.collect()))
    }
}
