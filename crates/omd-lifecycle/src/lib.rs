//! Per-user startup registration. The same Rust engine owns both interactive and
//! background work. No shell commands, administrator service, or extra engine.
use omd_domain::digest;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub engine: PathBuf,
    pub profile: PathBuf,
    pub arguments: Vec<String>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "The operating system startup integration is unavailable. Check your user session and retry."
    )]
    Unavailable,
    #[error("The managed startup configuration is invalid. Repair the application installation.")]
    Invalid,
    #[error(
        "The startup configuration could not be saved. Check directory permissions and available space."
    )]
    Storage,
}
type Result<T> = std::result::Result<T, Error>;
/// The per-user startup job label of one profile.
pub fn label_for(profile: &Path) -> String {
    format!(
        "labs.northwolf.omd.v2.{}",
        &digest(profile.to_string_lossy().as_bytes())[..20]
    )
}
/// For an engine the OS started (`--service`) that exits with background
/// operation off: unregister its own startup job without waiting for itself.
/// It has no effect in any other process or on platforms that keep no
/// registration once the process has exited.
pub async fn retire_service(profile: &Path) -> Result<()> {
    platform_retire(profile).await
}
/// Suspend only this profile's startup registration without changing preferences
/// or requiring the old executable to remain on disk. Disable paths never use
/// the executable/arguments; the private profile's stable label owns the entry.
pub async fn suspend_registration(profile: &Path) -> Result<()> {
    if !profile.is_absolute() {
        return Err(Error::Invalid);
    }
    platform_set(
        &Launch {
            engine: PathBuf::new(),
            profile: profile.into(),
            arguments: vec![],
        },
        false,
    )
    .await
}
impl Launch {
    pub fn label(&self) -> String {
        label_for(&self.profile)
    }
    pub fn validate(&self) -> Result<()> {
        if !self.engine.is_absolute()
            || !self.engine.is_file()
            || !self.profile.is_absolute()
            || self.arguments.len() > 64
            || self
                .arguments
                .iter()
                .any(|s| s.len() > 16384 || s.chars().any(|c| c.is_control()))
            || [&self.engine, &self.profile]
                .iter()
                .any(|p| p.to_str().is_none_or(|s| s.chars().any(|c| c.is_control())))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn command(&self) -> Vec<String> {
        std::iter::once(self.engine.to_string_lossy().into_owned())
            .chain(self.arguments.clone())
            .chain(["--service".into()])
            .collect()
    }
    pub fn persist(&self) -> Result<()> {
        self.validate()?;
        write_private(
            &self.profile.join("service-launch.json"),
            &serde_json::to_vec(self).map_err(|_| Error::Invalid)?,
        )
    }
    pub fn load(profile: &Path) -> Result<Option<Self>> {
        let bytes = match std::fs::read(profile.join("service-launch.json")) {
            Ok(bytes) if bytes.len() <= 1024 * 1024 => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            _ => return Err(Error::Storage),
        };
        let launch: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        launch.validate()?;
        if launch.profile != profile {
            return Err(Error::Invalid);
        }
        Ok(Some(launch))
    }
    pub async fn set_enabled(&self, enabled: bool) -> Result<()> {
        self.validate()?;
        platform_set(self, enabled).await
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    std::fs::create_dir_all(parent).map_err(|_| Error::Storage)?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| Error::Storage)?;
    file.write_all(bytes).map_err(|_| Error::Storage)?;
    file.as_file().sync_all().map_err(|_| Error::Storage)?;
    file.persist(path).map_err(|_| Error::Storage)?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error::Storage)?;
    Ok(())
}
async fn command(program: &str, args: &[String]) -> Result<bool> {
    let mut process = tokio::process::Command::new(program);
    process
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = process.spawn().map_err(|_| Error::Unavailable)?;
    match tokio::time::timeout(Duration::from_secs(20), child.wait()).await {
        Ok(Ok(status)) => Ok(status.success()),
        _ => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(Error::Unavailable)
        }
    }
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub fn launch_agent(launch: &Launch) -> String {
    let args = launch
        .command()
        .iter()
        .map(|s| format!("<string>{}</string>", xml(s)))
        .collect::<String>();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array>{args}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>15</integer><key>ExitTimeOut</key><integer>90</integer><key>ProcessType</key><string>Background</string><key>Umask</key><integer>63</integer><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>{}</string></dict></plist>",
        launch.label(),
        xml(&launch.profile.join("service.log").to_string_lossy())
    )
}
fn unit_arg(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}
pub fn systemd_unit(launch: &Launch) -> String {
    format!(
        "[Unit]\nDescription=OMD acquisition manager\n\n[Service]\nType=simple\nExecStart={}\nRestart=on-failure\nRestartSec=15\nTimeoutStopSec=90\nKillMode=mixed\nUMask=0077\nStandardOutput=null\nStandardError=journal\n\n[Install]\nWantedBy=default.target\n",
        launch
            .command()
            .iter()
            .map(|s| unit_arg(s))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
/// CommandLineToArgvW quoting, passed directly to the Run registry value. This is
/// never interpreted by cmd.exe or PowerShell.
fn windows_arg(s: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in s.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            if c == '"' { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}
pub fn windows_command(launch: &Launch) -> String {
    launch
        .command()
        .iter()
        .map(|s| windows_arg(s))
        .collect::<Vec<_>>()
        .join(" ")
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(Error::Unavailable)
}
/// One `/bin/launchctl` call; `true` when it exits successfully.
#[cfg(any(target_os = "macos", test))]
trait Launchctl: Sync {
    fn run(&self, args: &[&str]) -> impl std::future::Future<Output = Result<bool>> + Send;
}
#[cfg(target_os = "macos")]
struct SystemLaunchctl;
#[cfg(target_os = "macos")]
impl Launchctl for SystemLaunchctl {
    async fn run(&self, args: &[&str]) -> Result<bool> {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        command("/bin/launchctl", &args).await
    }
}
/// The launchd job of one profile in the user's GUI domain.
#[cfg(any(target_os = "macos", test))]
struct Job {
    domain: String,
    target: String,
    label: String,
    file: PathBuf,
    /// This process is that job's own engine.
    instance: bool,
}
#[cfg(any(target_os = "macos", test))]
impl Job {
    fn new(profile: &Path, home: &Path, uid: u32, service_name: Option<&std::ffi::OsStr>) -> Self {
        let label = label_for(profile);
        let domain = format!("gui/{uid}");
        Self {
            target: format!("{domain}/{label}"),
            file: home
                .join("Library/LaunchAgents")
                .join(format!("{label}.plist")),
            // launchd names the job in XPC_SERVICE_NAME for each process it starts.
            instance: service_name.is_some_and(|name| name == label.as_str()),
            domain,
            label,
        }
    }
    async fn set(&self, ctl: &impl Launchctl, launch: &Launch, enabled: bool) -> Result<()> {
        let loaded = ctl.run(&["print", &self.target]).await?;
        if enabled {
            let plist = launch_agent(launch);
            let current = std::fs::read(&self.file).is_ok_and(|bytes| bytes == plist.as_bytes());
            require(ctl, &["enable", &self.target]).await?;
            // launchd keeps the definition a job was loaded with. Reload a job
            // left from an earlier registration or whose engine moved, unless
            // this engine is that job: its new definition applies at next login.
            let reload = loaded && !current && !self.instance;
            if reload {
                self.stop(ctl).await?;
            }
            // Preserve the old definition until enable and any required
            // unload succeed, so a retry cannot mistake pending bytes for
            // the definition launchd actually loaded.
            write_private(&self.file, plist.as_bytes())?;
            if !loaded || reload {
                let file = self.file.to_string_lossy();
                require(ctl, &["bootstrap", &self.domain, &file]).await?;
            }
        } else {
            if loaded || self.file.exists() {
                require(ctl, &["disable", &self.target]).await?;
                remove_agent(&self.file)?;
            }
            // `disable` alone leaves a loaded job registered until logout, and
            // its waiting service engine running. Stop it now, unless this
            // engine is that job: stopping it would end this request, so the
            // engine retires the job when it exits (see `retire_service`).
            if loaded && !self.instance {
                self.stop(ctl).await?;
            }
        }
        Ok(())
    }
    /// `bootout` stops the job's process, unregisters the job, then returns.
    async fn stop(&self, ctl: &impl Launchctl) -> Result<()> {
        if ctl.run(&["bootout", &self.target]).await? || !ctl.run(&["print", &self.target]).await? {
            Ok(())
        } else {
            Err(Error::Unavailable)
        }
    }
    async fn retire(&self, ctl: &impl Launchctl) -> Result<()> {
        if !self.instance {
            return Ok(());
        }
        remove_agent(&self.file)?;
        require(ctl, &["disable", &self.target]).await?;
        // Unlike `bootout`, `remove` does not wait for this process to exit;
        // launchd then stops it (it is already exiting) and unregisters the job.
        require(ctl, &["remove", &self.label]).await
    }
}
#[cfg(any(target_os = "macos", test))]
async fn require(ctl: &impl Launchctl, args: &[&str]) -> Result<()> {
    if ctl.run(args).await? {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}
#[cfg(any(target_os = "macos", test))]
fn remove_agent(file: &Path) -> Result<()> {
    match std::fs::remove_file(file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Storage),
    }
}
#[cfg(target_os = "macos")]
fn current_job(profile: &Path) -> Result<Job> {
    // SAFETY: getuid has no preconditions and reads the current process identity.
    let uid = unsafe { libc::getuid() };
    let service_name = std::env::var_os("XPC_SERVICE_NAME");
    Ok(Job::new(
        profile,
        &user_home()?,
        uid,
        service_name.as_deref(),
    ))
}
#[cfg(target_os = "macos")]
async fn platform_set(launch: &Launch, enabled: bool) -> Result<()> {
    current_job(&launch.profile)?
        .set(&SystemLaunchctl, launch, enabled)
        .await
}
#[cfg(target_os = "macos")]
async fn platform_retire(profile: &Path) -> Result<()> {
    current_job(profile)?.retire(&SystemLaunchctl).await
}
// systemd user units and Run keys keep no running registration once the
// service process has exited.
#[cfg(not(target_os = "macos"))]
async fn platform_retire(_: &Path) -> Result<()> {
    Ok(())
}
#[cfg(target_os = "linux")]
async fn platform_set(launch: &Launch, enabled: bool) -> Result<()> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or(user_home()?.join(".config"));
    let name = format!("{}.service", launch.label());
    let file = config.join("systemd/user").join(&name);
    if enabled {
        write_private(&file, systemd_unit(launch).as_bytes())?;
        if !command("systemctl", &["--user".into(), "daemon-reload".into()]).await?
            || !command(
                "systemctl",
                &["--user".into(), "enable".into(), "--now".into(), name],
            )
            .await?
        {
            return Err(Error::Unavailable);
        }
    } else if file.exists() {
        if !command("systemctl", &["--user".into(), "disable".into(), name]).await? {
            return Err(Error::Unavailable);
        }
        std::fs::remove_file(file).map_err(|_| Error::Storage)?;
        if !command("systemctl", &["--user".into(), "daemon-reload".into()]).await? {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
#[cfg(target_os = "windows")]
async fn platform_set(launch: &Launch, enabled: bool) -> Result<()> {
    let system = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(Error::Unavailable)?;
    let program = system
        .join("System32/reg.exe")
        .to_string_lossy()
        .into_owned();
    let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let label = launch.label();
    if enabled {
        if !command(
            &program,
            &[
                "ADD".into(),
                key.into(),
                "/v".into(),
                label,
                "/t".into(),
                "REG_SZ".into(),
                "/d".into(),
                windows_command(launch),
                "/f".into(),
            ],
        )
        .await?
        {
            return Err(Error::Unavailable);
        }
    } else if command(
        &program,
        &["QUERY".into(), key.into(), "/v".into(), label.clone()],
    )
    .await?
        && !command(
            &program,
            &["DELETE".into(), key.into(), "/v".into(), label, "/f".into()],
        )
        .await?
    {
        return Err(Error::Unavailable);
    }
    Ok(())
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn platform_set(_: &Launch, _: bool) -> Result<()> {
    Err(Error::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_formats_preserve_arguments_and_do_not_invoke_a_shell() {
        let launch = Launch {
            engine: PathBuf::from("/Apps/OMD & Test/engine"),
            profile: PathBuf::from("/Profiles/test"),
            arguments: vec![
                "--profile".into(),
                "/Profiles/100% $x `echo` \"quote\"".into(),
            ],
        };
        let plist = launch_agent(&launch);
        assert!(plist.contains("OMD &amp; Test"));
        assert!(plist.contains("&quot;quote&quot;"));
        let unit = systemd_unit(&launch);
        assert!(unit.contains("100%% $$x `echo` \\\"quote\\\""));
        assert!(unit.contains("--service"));
        assert_eq!(
            windows_arg("C:\\folder with spaces\\"),
            "\"C:\\folder with spaces\\\\\""
        );
        assert_eq!(windows_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_ne!(
            launch.label(),
            Launch {
                profile: PathBuf::from("/Profiles/other"),
                ..launch
            }
            .label()
        );
    }

    /// A modelled launchd domain holding at most this profile's job.
    #[derive(Default)]
    struct Launchd {
        loaded: std::sync::Mutex<bool>,
        calls: std::sync::Mutex<Vec<String>>,
    }
    impl Launchd {
        fn with_job() -> Self {
            Self {
                loaded: std::sync::Mutex::new(true),
                ..Default::default()
            }
        }
        fn loaded(&self) -> bool {
            *self.loaded.lock().unwrap()
        }
        fn calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
    }
    impl Launchctl for Launchd {
        async fn run(&self, args: &[&str]) -> Result<bool> {
            self.calls.lock().unwrap().push(args[0].to_owned());
            let mut loaded = self.loaded.lock().unwrap();
            Ok(match args[0] {
                "print" => *loaded,
                "bootstrap" => !std::mem::replace(&mut *loaded, true),
                "bootout" | "remove" => std::mem::replace(&mut *loaded, false),
                _ => true,
            })
        }
    }
    fn fixture() -> (tempfile::TempDir, Launch, Job, Job) {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("profile");
        let launch = Launch {
            engine: temp.path().join("engine"),
            profile: profile.clone(),
            arguments: vec![],
        };
        let other = Job::new(&profile, temp.path(), 501, None);
        let label = launch.label();
        let own = Job::new(
            &profile,
            temp.path(),
            501,
            Some(std::ffi::OsStr::new(&label)),
        );
        (temp, launch, other, own)
    }
    fn register(job: &Job, launch: &Launch) {
        write_private(&job.file, launch_agent(launch).as_bytes()).unwrap();
    }
    #[tokio::test]
    async fn disabling_unloads_the_job_unless_this_engine_is_it() {
        let (_temp, launch, other, own) = fixture();
        assert!(!other.instance && own.instance);
        // Another engine turned background off: the waiting service engine
        // stops and the job is unregistered now, not at logout.
        let launchd = Launchd::with_job();
        register(&other, &launch);
        other.set(&launchd, &launch, false).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "disable", "bootout"]);
        assert!(!launchd.loaded() && !other.file.exists());
        // The job's own engine keeps serving and retires the job when it exits.
        let launchd = Launchd::with_job();
        register(&own, &launch);
        own.set(&launchd, &launch, false).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "disable"]);
        assert!(launchd.loaded() && !own.file.exists());
        own.retire(&launchd).await.unwrap();
        assert_eq!(launchd.calls(), ["disable", "remove"]);
        assert!(!launchd.loaded());
        // No other process retires it.
        let launchd = Launchd::with_job();
        other.retire(&launchd).await.unwrap();
        assert!(launchd.calls().is_empty() && launchd.loaded());
    }
    #[tokio::test]
    async fn enabling_reloads_a_stale_job_but_keeps_a_current_one() {
        let (_temp, launch, other, own) = fixture();
        // Left loaded by an earlier disable: reload it with this definition.
        let launchd = Launchd::with_job();
        other.set(&launchd, &launch, true).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "enable", "bootout", "bootstrap"]);
        assert!(launchd.loaded());
        assert_eq!(
            std::fs::read(&other.file).unwrap(),
            launch_agent(&launch).as_bytes()
        );
        // Saving settings again leaves the running job alone.
        other.set(&launchd, &launch, true).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "enable"]);
        // First registration.
        let launchd = Launchd::default();
        std::fs::remove_file(&other.file).unwrap();
        other.set(&launchd, &launch, true).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "enable", "bootstrap"]);
        // The job's own engine never reloads, which would stop it.
        let launchd = Launchd::with_job();
        std::fs::remove_file(&own.file).unwrap();
        own.set(&launchd, &launch, true).await.unwrap();
        assert_eq!(launchd.calls(), ["print", "enable"]);
        assert!(launchd.loaded() && own.file.exists());
    }

    #[tokio::test]
    async fn failed_reload_preserves_the_old_definition_for_retry() {
        struct FailOnce {
            inner: Launchd,
            operation: &'static str,
            failed: std::sync::atomic::AtomicBool,
        }
        impl Launchctl for FailOnce {
            async fn run(&self, args: &[&str]) -> Result<bool> {
                if args[0] == self.operation
                    && !self.failed.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return Ok(false);
                }
                self.inner.run(args).await
            }
        }
        for operation in ["enable", "bootout", "bootstrap"] {
            let (_temp, launch, job, _) = fixture();
            let old = Launch {
                engine: launch.engine.with_file_name("old-engine"),
                ..launch.clone()
            };
            register(&job, &old);
            let ctl = FailOnce {
                inner: Launchd::with_job(),
                operation,
                failed: std::sync::atomic::AtomicBool::new(false),
            };
            assert!(job.set(&ctl, &launch, true).await.is_err());
            if ctl.inner.loaded() {
                assert_eq!(
                    std::fs::read(&job.file).unwrap(),
                    launch_agent(&old).as_bytes()
                );
            }
            ctl.inner.calls();
            job.set(&ctl, &launch, true).await.unwrap();
            assert!(
                ctl.inner.calls().contains(&"bootstrap".to_owned()),
                "{operation}"
            );
            assert!(ctl.inner.loaded());
            assert_eq!(
                std::fs::read(&job.file).unwrap(),
                launch_agent(&launch).as_bytes()
            );
        }
    }

    /// Opt-in native controls against the user's real launchd GUI domain.
    /// Each registers only a temporary job labelled from a profile under
    /// OMD_LIFECYCLE_NATIVE_DIR, and removes it again.
    #[cfg(target_os = "macos")]
    mod native {
        use super::*;
        use std::time::Instant;
        const CHILD: &str = "omd-lifecycle-native-child.json";

        fn root() -> PathBuf {
            let root = PathBuf::from(
                std::env::var_os("OMD_LIFECYCLE_NATIVE_DIR").expect("OMD_LIFECYCLE_NATIVE_DIR"),
            );
            assert!(root.is_absolute());
            // launchd does not load plists from external volumes, and an agent
            // reading one may stall on a consent prompt; use the startup disk.
            assert!(
                !root.starts_with("/Volumes"),
                "use a directory on the startup disk"
            );
            std::fs::create_dir_all(&root).unwrap();
            root
        }
        fn uid() -> u32 {
            // SAFETY: getuid has no preconditions and reads the current process identity.
            unsafe { libc::getuid() }
        }
        fn printed(job: &Job) -> Option<String> {
            let out = std::process::Command::new("/bin/launchctl")
                .args(["print", &job.target])
                .output()
                .unwrap();
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        }
        fn alive(pid: i32) -> bool {
            // SAFETY: signal 0 only checks that the process exists.
            unsafe { libc::kill(pid, 0) == 0 }
        }
        fn eventually(ready: impl FnMut() -> bool) -> bool {
            within(Duration::from_secs(20), ready)
        }
        fn within(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
            let start = Instant::now();
            while !ready() {
                if start.elapsed() > limit {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            true
        }
        fn wait(what: &str, ready: impl FnMut() -> bool) {
            assert!(eventually(ready), "timed out: {what}");
        }
        /// A stand-in engine: records its pid, then waits to be stopped.
        fn engine(root: &Path, name: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = root.join(name);
            std::fs::write(
                &path,
                "#!/bin/sh\necho $$ > \"$0.pid\"\nexec /bin/sleep 120\n",
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        }
        fn pid(engine: &Path) -> i32 {
            let file = engine.with_extension("pid");
            wait("service process start", || file.exists());
            std::fs::read_to_string(file)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }
        #[tokio::test]
        #[ignore = "registers a temporary launchd job; set OMD_LIFECYCLE_NATIVE_DIR"]
        async fn launchd_job_is_unloaded_on_disable_and_reloaded_when_stale() {
            let root = root().join("disable-and-reload");
            std::fs::create_dir(&root).unwrap();
            let profile = root.join("profile");
            let job = Job::new(&profile, &root.join("home"), uid(), None);
            assert!(printed(&job).is_none(), "label already registered");
            let first = Launch {
                engine: engine(&root, "first"),
                profile: profile.clone(),
                arguments: vec![],
            };
            job.set(&SystemLaunchctl, &first, true).await.unwrap();
            let running = pid(&first.engine);
            assert!(alive(running));
            // Disabling stops the waiting service process and unregisters the job.
            job.set(&SystemLaunchctl, &first, false).await.unwrap();
            let unloaded = printed(&job).is_none();
            let stopped = eventually(|| !alive(running));
            assert!(unloaded, "job still registered after disable");
            assert!(stopped, "service process still running after disable");
            assert!(!job.file.exists());
            // A job an earlier build left loaded after its disable is reloaded
            // with the current definition when background turns on again.
            std::fs::remove_file(first.engine.with_extension("pid")).unwrap();
            job.set(&SystemLaunchctl, &first, true).await.unwrap();
            let stale = pid(&first.engine);
            require(&SystemLaunchctl, &["disable", &job.target])
                .await
                .unwrap();
            remove_agent(&job.file).unwrap();
            let second = Launch {
                engine: engine(&root, "second"),
                ..first.clone()
            };
            job.set(&SystemLaunchctl, &second, true).await.unwrap();
            let current = pid(&second.engine);
            let definition = printed(&job).unwrap_or_default();
            wait("stale service process exit", || !alive(stale));
            assert!(
                definition.contains(&second.engine.to_string_lossy().into_owned()),
                "loaded job kept its stale definition"
            );
            job.set(&SystemLaunchctl, &second, false).await.unwrap();
            wait("service process exit", || !alive(current));
            assert!(printed(&job).is_none());
        }
        #[tokio::test]
        #[ignore = "registers a temporary launchd job; set OMD_LIFECYCLE_NATIVE_DIR"]
        async fn service_engine_retires_its_own_job_on_exit() {
            let root = root().join("self-retire");
            std::fs::create_dir(&root).unwrap();
            let profile = root.join("profile");
            let home = root.join("home");
            let result = root.join("child.json");
            let job = Job::new(&profile, &home, uid(), None);
            assert!(printed(&job).is_none(), "label already registered");
            // A copy on this volume: launchd agents may not read removable volumes
            // without a consent prompt, which would stall the child.
            let exe = root.join("engine");
            std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
            let config = exe.with_file_name(CHILD);
            std::fs::write(
                &config,
                serde_json::to_vec(
                    &serde_json::json!({"profile": profile, "home": home, "result": result}),
                )
                .unwrap(),
            )
            .unwrap();
            // launchd starts this test binary as the job's engine, running only
            // the child test below (`--service` follows `--` as an inert filter).
            let launch = Launch {
                engine: exe,
                profile,
                arguments: [
                    "--exact",
                    "tests::native::retiring_service_child",
                    "--include-ignored",
                    "--",
                ]
                .map(String::from)
                .to_vec(),
            };
            job.set(&SystemLaunchctl, &launch, true).await.unwrap();
            // The child reports once launchd has stopped it, or after 30 s without.
            assert!(
                within(Duration::from_secs(40), || result.exists()),
                "no child report"
            );
            let report: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&result).unwrap()).unwrap();
            let child = report["pid"].as_i64().unwrap() as i32;
            let unregistered = eventually(|| printed(&job).is_none());
            let exited = eventually(|| !alive(child));
            // Past launchd's 15-second throttle: the job was not started again.
            std::thread::sleep(Duration::from_secs(17));
            let restarted = unregistered && printed(&job).is_some();
            if printed(&job).is_some() {
                job.set(&SystemLaunchctl, &launch, false).await.unwrap();
            }
            std::fs::remove_file(&config).unwrap();
            assert_eq!(report["instance"], true);
            assert_eq!(report["retired"], true);
            assert_eq!(report["stopped_by_launchd"], true);
            assert!(
                unregistered,
                "job still registered after its engine retired it"
            );
            assert!(exited, "the retiring engine was not stopped");
            assert!(!restarted, "the retired job ran again");
            assert!(!job.file.exists());
        }
        /// Runs only when launchd starts it for the test above.
        #[tokio::test]
        #[ignore = "started by service_engine_retires_its_own_job_on_exit"]
        async fn retiring_service_child() {
            let Some(name) = std::env::var_os("XPC_SERVICE_NAME") else {
                return;
            };
            let config = std::env::current_exe().unwrap().with_file_name(CHILD);
            let Ok(config) = std::fs::read(config) else {
                return;
            };
            let config: serde_json::Value = serde_json::from_slice(&config).unwrap();
            let path = |key: &str| PathBuf::from(config[key].as_str().unwrap());
            let job = Job::new(&path("profile"), &path("home"), uid(), Some(&name));
            // Any other process, such as a test runner started from an app.
            if !job.instance {
                return;
            }
            // Like the engine, handle SIGTERM, so the stop launchd sends after
            // `remove` arrives while this process finishes on its own terms.
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            let retired = job.retire(&SystemLaunchctl).await.is_ok();
            let stopped = tokio::time::timeout(Duration::from_secs(30), terminate.recv())
                .await
                .is_ok();
            let report = serde_json::json!({"pid": std::process::id(), "instance": job.instance, "retired": retired, "stopped_by_launchd": stopped});
            let partial = path("result").with_extension("partial");
            std::fs::write(&partial, serde_json::to_vec(&report).unwrap()).unwrap();
            std::fs::rename(partial, path("result")).unwrap();
        }
    }
}
