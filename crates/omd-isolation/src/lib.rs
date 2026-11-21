//! Native adapter confinement. Every launch has an explicit read, write, execute,
//! and broker endpoint allowlist. Missing confinement never runs the raw command.
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
};
use tokio_util::sync::CancellationToken;
mod session;
#[cfg(windows)]
mod windows_job;
pub use session::Session;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Required native helper confinement is unavailable on this system")]
    Unavailable,
    #[error("Restart OMD without administrator privileges")]
    Elevated,
    #[error("The native helper configuration is invalid")]
    Invalid,
    #[error("The confined native helper could not start")]
    Start,
    #[error("The native helper exceeded its time or output budget")]
    Budget,
    #[error("The native helper was canceled")]
    Canceled,
    #[error("The confined native helper failed")]
    Failed,
}
pub type Result<T> = std::result::Result<T, Error>;
fn confinement_failure(stderr: &[u8]) -> Option<(&'static str, Option<i32>)> {
    // Diagnostics retain fixed phase names and numeric OS codes only. Never
    // forward a helper's arbitrary stderr, which can contain paths or secrets.
    let message = std::str::from_utf8(stderr)
        .ok()?
        .strip_prefix("OMD Windows confinement failed: ")?;
    let phase = ["parent", "profile", "files", "job", "helper"]
        .into_iter()
        .find(|phase| message.starts_with(&format!("{phase}: OS ")))
        .unwrap_or("setup");
    // Raw OS codes are signed: HRESULT failures such as E_ACCESSDENIED are negative.
    let code = message
        .split("OS Some(")
        .nth(1)
        .or_else(|| message.split("OS code Some(").nth(1))
        .and_then(|value| value.split(')').next())
        .filter(|value| {
            let digits = value.strip_prefix('-').unwrap_or(value);
            (1..=10).contains(&digits.len()) && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|value| value.parse::<i32>().ok());
    Some((phase, code))
}
fn log_confinement_failure(stderr: &[u8]) {
    let Some((phase, code)) = confinement_failure(stderr) else {
        return;
    };
    tracing::warn!(
        native_phase = phase,
        os_code = code,
        "Windows helper confinement could not start"
    );
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub executable: PathBuf,
    pub readable: Vec<PathBuf>,
    pub executables: Vec<PathBuf>,
    pub work: PathBuf,
    /// Only the engine-owned policy proxy can be contacted. No DNS or other egress.
    pub broker_port: Option<u16>,
    /// Windows private pipe bridge forwards only to this engine-owned endpoint.
    #[serde(default)]
    pub broker_upstream_port: Option<u16>,
    /// Engine-owned interactive sign-in window; never set by source plugins.
    #[serde(default)]
    pub interactive: bool,
}
impl Policy {
    fn canonical(&self) -> Result<Self> {
        let file = |p: &Path| std::fs::canonicalize(p).map_err(|_| Error::Invalid);
        let executable = file(&self.executable)?;
        let work = file(&self.work)?;
        if !executable.is_file() || !work.is_dir() || self.broker_port == Some(0) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            executable,
            work,
            readable: self
                .readable
                .iter()
                .map(|p| file(p))
                .collect::<Result<_>>()?,
            executables: self
                .executables
                .iter()
                .map(|p| file(p))
                .collect::<Result<_>>()?,
            broker_port: self.broker_port,
            broker_upstream_port: self.broker_upstream_port,
            interactive: self.interactive,
        })
    }
    pub fn command(&self, args: &[String]) -> Result<Command> {
        self.command_mode(args, false)
    }
    fn command_mode(&self, args: &[String], browser: bool) -> Result<Command> {
        if self.interactive && !browser {
            return Err(Error::Invalid);
        }
        let policy = self.canonical()?;
        let mut command = platform_command(&policy, args, browser)?;
        command
            .env_clear()
            .current_dir(&policy.work)
            .env("HOME", &policy.work)
            .env("TMPDIR", &policy.work)
            .env("TEMP", &policy.work)
            .env("TMP", &policy.work)
            .env("LANG", "en_US.UTF-8")
            .env("PATH", "")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        for name in [
            "SystemRoot",
            "windir",
            "SystemDrive",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(unix)]
        command.env("OPENSSL_CONF", "/dev/null");
        #[cfg(unix)]
        {
            command.process_group(0);
        }
        Ok(command)
    }
}
fn configured_command(
    policy: &Policy,
    args: &[String],
    environment: &std::collections::BTreeMap<String, String>,
    browser: bool,
) -> Result<Configured> {
    let mut command = policy.command_mode(args, browser)?;
    for (name, value) in environment {
        if !matches!(
            name.as_str(),
            "SSL_CERT_FILE" | "NODE_EXTRA_CA_CERTS" | "REQUESTS_CA_BUNDLE" | "CURL_CA_BUNDLE"
        ) {
            return Err(Error::Invalid);
        }
        let path = std::fs::canonicalize(value).map_err(|_| Error::Invalid)?;
        let work = std::fs::canonicalize(&policy.work).map_err(|_| Error::Invalid)?;
        if !path.starts_with(work) || !path.is_file() {
            return Err(Error::Invalid);
        }
        command.env(name, path);
    }
    #[cfg(windows)]
    let job = windows_job::Job::create().map_err(|_| Error::Unavailable)?;
    #[cfg(windows)]
    command.env("OMD_SUPERVISOR_JOB", &job.name);
    Ok(Configured {
        command,
        #[cfg(windows)]
        job,
    })
}
struct Configured {
    command: Command,
    #[cfg(windows)]
    job: windows_job::Job,
}
impl Configured {
    fn spawn(mut self) -> Result<Group> {
        let child = self.command.spawn().map_err(|_| Error::Start)?;
        let id = child.id();
        Ok(Group(
            child,
            id,
            #[cfg(windows)]
            self.job,
        ))
    }
}
#[cfg(target_os = "macos")]
fn platform_command(policy: &Policy, args: &[String], browser: bool) -> Result<Command> {
    if !Path::new("/usr/bin/sandbox-exec").is_file() {
        return Err(Error::Unavailable);
    }
    let executable = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let directory = executable.parent().ok_or(Error::Unavailable)?;
    // Cargo integration tests run from debug/deps; installed engines use a sibling.
    let directory = if directory.file_name().is_some_and(|n| n == "deps") {
        directory.parent().ok_or(Error::Unavailable)?
    } else {
        directory
    };
    let guardian = directory.join("omd-helper-guardian");
    if !guardian.is_file() {
        return Err(Error::Unavailable);
    }
    let mut command = Command::new(guardian);
    command.arg(std::process::id().to_string());
    if policy.interactive {
        command.arg("--interactive");
    }
    command
        .arg("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(macos_profile(policy, browser)?)
        .arg(&policy.executable)
        .args(args);
    Ok(command)
}
#[cfg(target_os = "linux")]
fn platform_command(policy: &Policy, args: &[String], browser: bool) -> Result<Command> {
    let executable = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let directory = executable.parent().ok_or(Error::Unavailable)?;
    let directory = if directory.file_name().is_some_and(|n| n == "deps") {
        directory.parent().ok_or(Error::Unavailable)?
    } else {
        directory
    };
    let guardian = directory.join("omd-helper-guardian");
    if !guardian.is_file() {
        return Err(Error::Unavailable);
    }
    let mut command = Command::new(guardian);
    command
        .arg(std::process::id().to_string())
        .arg(if browser { "browser" } else { "media" })
        .arg(serde_json::to_string(policy).map_err(|_| Error::Invalid)?)
        .args(args);
    Ok(command)
}
#[cfg(windows)]
fn platform_command(policy: &Policy, args: &[String], _browser: bool) -> Result<Command> {
    let executable = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    let directory = executable.parent().ok_or(Error::Unavailable)?;
    let directory = if directory.file_name().is_some_and(|n| n == "deps") {
        directory.parent().ok_or(Error::Unavailable)?
    } else {
        directory
    };
    let guardian = directory.join("omd-helper-guardian.exe");
    if !guardian.is_file() {
        return Err(Error::Unavailable);
    }
    let mut command = Command::new(guardian);
    command
        .arg(std::process::id().to_string())
        .arg(serde_json::to_string(policy).map_err(|_| Error::Invalid)?)
        .args(args);
    Ok(command)
}
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn platform_command(_policy: &Policy, _args: &[String], _browser: bool) -> Result<Command> {
    Err(Error::Unavailable)
}

#[cfg(target_os = "macos")]
fn macos_profile(policy: &Policy, browser: bool) -> Result<String> {
    fn quoted(path: &Path) -> Result<String> {
        serde_json::to_string(path.to_str().ok_or(Error::Invalid)?).map_err(|_| Error::Invalid)
    }
    fn rule(path: &Path) -> Result<String> {
        Ok(format!(
            "({} {})",
            if path.is_dir() { "subpath" } else { "literal" },
            quoted(path)?
        ))
    }
    let mut reads = vec![];
    for path in [
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/System/Cryptexes/OS",
        "/usr/lib",
        "/private/var/db/dyld",
        // The x86-64 system loader needs this exact Apple runtime on Rosetta.
        // No translation cache, helper executable or user directory is granted.
        "/Library/Apple/usr/libexec/oah/libRosettaRuntime",
        "/dev/null",
        "/dev/urandom",
        "/dev/random",
    ] {
        if Path::new(path).exists() {
            reads.push(rule(Path::new(path))?);
        }
    }
    if browser {
        for path in [
            "/usr/share/langid",
            "/usr/share/tokenizer",
            "/usr/share/icu",
        ] {
            if Path::new(path).exists() {
                reads.push(rule(Path::new(path))?);
            }
        }
    }
    for path in policy
        .readable
        .iter()
        .chain(std::iter::once(&policy.work))
        .chain(std::iter::once(&policy.executable))
        .chain(policy.executables.iter())
    {
        reads.push(rule(path)?);
    }
    let execs = std::iter::once(&policy.executable)
        .chain(policy.executables.iter())
        .map(|p| Ok(format!("(literal {})", quoted(p)?)))
        .collect::<Result<Vec<_>>>()?;
    let mut parents = std::collections::BTreeSet::new();
    for path in std::iter::once(&policy.executable)
        .chain(policy.readable.iter())
        .chain(std::iter::once(&policy.work))
        .chain(policy.executables.iter())
    {
        for parent in path.ancestors().skip(1) {
            parents.insert(format!("(literal {})", quoted(parent)?));
        }
    }
    let network = policy
        .broker_port
        .map(|port| format!("(allow network-outbound (remote tcp \"localhost:{port}\"))"))
        .unwrap_or_default();
    // Chromium’s macOS crash handler detaches itself; it retains this sandbox
    // and exits when its browser client closes. Other helpers cannot detach.
    let process_groups = if browser {
        "(deny syscall-unix (syscall-number SYS_setpgid))"
    } else {
        "(deny syscall-unix (syscall-number SYS_setsid SYS_setpgid))"
    };
    let browser_sockets = if browser {
        format!(
            "(allow network-bind network-outbound network-inbound (subpath {}))",
            quoted(&policy.work)?
        )
    } else {
        String::new()
    };
    let interactive_rules = if browser && policy.interactive {
        "(allow mach-lookup (global-name \"com.apple.pasteboard.1\") (global-name \"com.apple.windowmanager.server\")) (allow iokit-open (iokit-user-client-class \"IOSurfaceRootUserClient\"))"
    } else {
        ""
    };
    let browser_rules = if browser {
        "(allow mach-lookup (global-name \"com.apple.windowserver.active\") (global-name \"com.apple.FontObjectsServer\") (global-name \"com.apple.coreservices.launchservicesd\") (global-name \"com.apple.CoreServices.coreservicesd\") (global-name \"com.apple.CARenderServer\") (global-name \"com.apple.hiservices-xpcservice\")) (allow mach-register mach-lookup (global-name-prefix \"org.chromium.crashpad.child_port_handshake.\") (global-name-prefix \"com.google.chrome.for.testing.MachPortRendezvousServer.\")) (allow iokit-open (iokit-user-client-class \"RootDomainUserClient\")) (allow iokit-get-properties) (allow mach-register (global-name-prefix \"org.chromium.Chromium.MachPortRendezvousServer.\")) (allow mach-lookup (global-name-prefix \"org.chromium.Chromium.MachPortRendezvousServer.\"))"
    } else {
        ""
    };
    Ok(format!(
        "(version 1) (deny default) (import \"dyld-support.sb\") (allow sysctl-read) (allow ipc-sysv-sem) (allow signal (target self)) (allow process-fork) {process_groups} (allow process-exec {}) (allow file-read* {}) (allow file-read-metadata {}) (allow file-write* (subpath {}) (literal \"/dev/null\")) {network} {browser_rules} {browser_sockets} {interactive_rules}",
        execs.join(" "),
        reads.join(" "),
        parents.into_iter().collect::<Vec<_>>().join(" "),
        quoted(&policy.work)?
    ))
}

/// The group guard also kills descendants when the caller drops its future.
/// Native helpers never survive cancellation to keep writing staging files.
struct Group(
    Child,
    #[cfg_attr(windows, allow(dead_code))] Option<u32>,
    #[cfg(windows)] windows_job::Job,
);
impl Group {
    async fn close(&mut self) -> Result<()> {
        #[cfg(windows)]
        self.2.terminate();
        let _ = self.0.kill().await;
        let _ = self.0.wait().await;
        #[cfg(windows)]
        self.2.drain().await.map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        #[cfg(windows)]
        self.2.terminate();
        #[cfg(unix)]
        if let Some(id) = self.1
            && self.0.id() == Some(id)
        {
            unsafe {
                libc::kill(-(id as i32), libc::SIGKILL);
            }
        }
        let _ = self.0.start_kill();
    }
}
pub async fn run(
    policy: &Policy,
    args: &[String],
    input: Vec<u8>,
    limit: usize,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Vec<u8>> {
    let result = capture(
        policy,
        args,
        input,
        &std::collections::BTreeMap::new(),
        limit,
        timeout,
        cancel,
    )
    .await?;
    if !result.success {
        return Err(Error::Failed);
    }
    Ok(result.stdout)
}
/// Diagnostic bytes stay private to the engine adapter, which classifies and
/// redacts them before producing user-visible errors.
pub struct Capture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
    /// How the helper ended, so an adapter can tell the helper's own failure
    /// status from a crash or a kill.
    pub exit: Exit,
}
/// How a confined helper that ran to completion ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The helper exited with this status code; 0 is success. Under the Linux
    /// guardian a helper ended by a signal reports 128 plus the signal, and on
    /// Windows a crash reports its NTSTATUS code.
    Code(i32),
    /// A signal ended the helper (Unix), as a crash or a kill does.
    Signal(i32),
}
impl Exit {
    pub fn of(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Code(code);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Self::Signal(status.signal().unwrap_or(0))
        }
        #[cfg(not(unix))]
        Self::Signal(0)
    }
}
pub async fn capture(
    policy: &Policy,
    args: &[String],
    input: Vec<u8>,
    environment: &std::collections::BTreeMap<String, String>,
    limit: usize,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<Capture> {
    capture_progress(
        policy,
        args,
        CaptureOptions {
            input,
            environment,
            limit,
            timeout,
            progress: None,
            browser: false,
        },
        cancel,
    )
    .await
}
pub struct CaptureOptions<'a> {
    /// Reserved for the engine's browser adapter, never provider input.
    pub browser: bool,
    pub input: Vec<u8>,
    pub environment: &'a std::collections::BTreeMap<String, String>,
    pub limit: usize,
    pub timeout: Duration,
    pub progress: Option<tokio::sync::watch::Sender<serde_json::Value>>,
}
// A watch channel may coalesce several native output lines while SQLite is
// committing. Publish a bounded per-format snapshot so a completed stream is not
// lost when the next stream starts before the receiver gets scheduled.
fn publish_progress(
    sender: &tokio::sync::watch::Sender<serde_json::Value>,
    value: serde_json::Value,
) {
    let (Some(id), Some(done)) = (value["format"].as_str(), value["done"].as_u64()) else {
        return;
    };
    if id.is_empty() || id.len() > 128 || done > 1024_u64.pow(4) {
        return;
    }
    let total = value["total"]
        .as_u64()
        .filter(|n| *n >= done && *n <= 1024_u64.pow(4));
    sender.send_modify(|snapshot| {
        if !snapshot["streams"].is_object() {
            *snapshot = serde_json::json!({"streams":{}});
        }
        let streams = snapshot["streams"].as_object_mut().expect("object");
        if streams.len() < 16 || streams.contains_key(id) {
            streams.insert(
                id.into(),
                serde_json::json!({"format":id,"done":done,"total":total}),
            );
        }
    });
}
pub async fn capture_progress(
    policy: &Policy,
    args: &[String],
    options: CaptureOptions<'_>,
    cancel: &CancellationToken,
) -> Result<Capture> {
    let CaptureOptions {
        browser,
        input,
        environment,
        limit,
        timeout,
        progress,
    } = options;
    if limit == 0 || limit > 64 * 1024 * 1024 || input.len() > 16 * 1024 * 1024 {
        return Err(Error::Invalid);
    }
    let mut child = configured_command(policy, args, environment, browser)?.spawn()?;
    let mut stdin = child.0.stdin.take().ok_or(Error::Start)?;
    let stdout = child.0.stdout.take().ok_or(Error::Start)?;
    let stderr = child.0.stderr.take().ok_or(Error::Start)?;
    let operation = async {
        let send = async {
            stdin.write_all(&input).await.map_err(|_| Error::Failed)?;
            drop(stdin);
            Ok::<_, Error>(())
        };
        let read = async {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(stdout.take(limit as u64 + 1));
            let mut bytes = Vec::new();
            let mut total = 0;
            loop {
                let mut line = Vec::new();
                let size = reader
                    .read_until(b'\n', &mut line)
                    .await
                    .map_err(|_| Error::Failed)?;
                if size == 0 {
                    break;
                }
                total += size;
                if total > limit {
                    return Err(Error::Budget);
                }
                if let Some(progress) = &progress
                    && line.len() <= 4096
                    && let Some(payload) = line.strip_prefix(b"OMD_PROGRESS ")
                {
                    if let Ok(value) = serde_json::from_slice(payload) {
                        publish_progress(progress, value);
                    }
                } else {
                    bytes.extend_from_slice(&line);
                }
            }
            Ok(bytes)
        };
        // Drain only a bounded amount; diagnostics are classified by the adapter,
        // never automatically copied into logs or public errors.
        let diagnostic = async {
            let mut bytes = Vec::new();
            stderr
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| Error::Failed)?;
            if bytes.len() > 64 * 1024 {
                return Err(Error::Budget);
            }
            Ok(bytes)
        };
        let (_, bytes, stderr) = tokio::try_join!(send, read, diagnostic)?;
        let status = child.0.wait().await.map_err(|_| Error::Failed)?;
        if stderr
            .windows(b"OMD elevated engine".len())
            .any(|v| v == b"OMD elevated engine")
        {
            return Err(Error::Elevated);
        }
        if stderr
            .windows(b"OMD resource budget exceeded".len())
            .any(|v| v == b"OMD resource budget exceeded")
        {
            return Err(Error::Budget);
        }
        if stderr
            .windows(b"OMD resource accounting unavailable".len())
            .any(|v| v == b"OMD resource accounting unavailable")
            || (status.code() == Some(126) && stderr.starts_with(b"OMD "))
        {
            log_confinement_failure(&stderr);
            return Err(Error::Unavailable);
        }
        Ok(Capture {
            stdout: bytes,
            stderr,
            success: status.success(),
            exit: Exit::of(status),
        })
    };
    let result = tokio::select! {_=cancel.cancelled()=>Err(Error::Canceled),value=tokio::time::timeout(timeout,operation)=>value.unwrap_or(Err(Error::Budget))};
    #[cfg(unix)]
    if let Some(id) = child.1.take()
        && child.0.id() == Some(id)
    {
        unsafe {
            libc::kill(-(id as i32), libc::SIGKILL);
        }
    }
    child.close().await?;
    result
}

#[cfg(all(test, unix))]
mod exit_tests {
    use super::Exit;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    #[test]
    fn an_exit_status_is_told_from_a_signal() {
        assert_eq!(Exit::of(ExitStatus::from_raw(0)), Exit::Code(0));
        assert_eq!(Exit::of(ExitStatus::from_raw(1 << 8)), Exit::Code(1));
        assert_eq!(Exit::of(ExitStatus::from_raw(139 << 8)), Exit::Code(139));
        assert_eq!(
            Exit::of(ExitStatus::from_raw(libc::SIGSEGV)),
            Exit::Signal(libc::SIGSEGV)
        );
        assert_eq!(
            Exit::of(ExitStatus::from_raw(libc::SIGKILL)),
            Exit::Signal(libc::SIGKILL)
        );
    }
}
#[cfg(test)]
mod progress_snapshot_tests {
    use super::*;
    #[test]
    fn coalesced_updates_keep_completed_streams_and_strip_untrusted_fields() {
        let (tx, rx) = tokio::sync::watch::channel(serde_json::Value::Null);
        publish_progress(
            &tx,
            serde_json::json!({"format":"video","done":200,"total":200,"url":"PRIVATE_FIXTURE"}),
        );
        publish_progress(
            &tx,
            serde_json::json!({"format":"audio","done":40,"total":100}),
        );
        let value = rx.borrow().clone();
        assert_eq!(value["streams"]["video"]["done"], 200);
        assert_eq!(value["streams"]["audio"]["done"], 40);
        assert!(!value.to_string().contains("PRIVATE_FIXTURE"));
        for i in 0..50 {
            publish_progress(
                &tx,
                serde_json::json!({"format":format!("extra-{i}"),"done":1}),
            );
        }
        assert_eq!(rx.borrow()["streams"].as_object().unwrap().len(), 16);
    }
}

#[cfg(test)]
mod confinement_failure_tests {
    use super::confinement_failure;
    #[test]
    fn keeps_fixed_phases_and_signed_codes_but_no_free_text() {
        let failure = |text: &str| confinement_failure(text.as_bytes());
        assert_eq!(
            failure(
                "OMD Windows confinement failed: profile: OS Some(-2147024891) (OS code None)\n"
            ),
            Some(("profile", Some(-2147024891)))
        );
        assert_eq!(
            failure("OMD Windows confinement failed: profile: OS Some(258) (OS code None)"),
            Some(("profile", Some(258)))
        );
        assert_eq!(
            failure("OMD Windows confinement failed: C:\\private\\fixture (OS code Some(5))"),
            Some(("setup", Some(5)))
        );
        for code in ["--5", "-", "", "12345678901", "-2147483649", "5x"] {
            let text = format!("OMD Windows confinement failed: job: OS Some({code})");
            assert_eq!(failure(&text), Some(("job", None)), "{code}");
        }
        assert_eq!(failure("helper output: OS Some(5)"), None);
    }
}
