//! The engine process ends after its own shutdown even while a blocking file
//! operation that nothing awaits any more stays stuck, as an `open()` does
//! while macOS holds it behind an unanswered folder permission dialog. A FIFO
//! stands in for that dialog: opening it for reading waits for a writer. The
//! catalog listing opens every `providers/*.omdp` next to the engine's `bin`.
#![cfg(unix)]
use std::{
    io::{Read, Write},
    net::TcpStream,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct Engine {
    child: Child,
    fifo: PathBuf,
    profile: PathBuf,
    _root: tempfile::TempDir,
}
impl Engine {
    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let engine = bin.join("omd-engine");
        let built = env!("CARGO_BIN_EXE_omd-engine");
        if std::fs::hard_link(built, &engine).is_err() {
            std::fs::copy(built, &engine).unwrap();
        }
        // Required to exist; never run because no source is installed.
        std::fs::write(bin.join("omd-plugin-worker-v2"), b"").unwrap();
        let providers = root.path().join("providers");
        std::fs::create_dir(&providers).unwrap();
        let fifo = providers.join("blocked.omdp");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let profile = root.path().join("profile");
        let child = Command::new(&engine)
            .arg("--profile")
            .arg(&profile)
            .env("HOME", root.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            fifo,
            profile,
            _root: root,
        }
    }
    fn instance(&self) -> serde_json::Value {
        let path = self.profile.join("instance.json");
        assert!(
            within(Duration::from_secs(60), || path.exists()),
            "engine did not start"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }
    /// Requests the catalog, which parks a blocking thread on the FIFO, and
    /// gives up after a second, as a client that quit would.
    fn abandon_catalog_request(&self) {
        let instance = self.instance();
        let address = instance["endpoint"]
            .as_str()
            .unwrap()
            .trim_start_matches("http://")
            .to_owned();
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        write!(stream, "GET /v2/source-catalog HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
               instance["token"].as_str().unwrap()).unwrap();
        let mut reply = [0; 64];
        assert!(
            stream.read(&mut reply).is_err(),
            "the catalog answered although its package blocks"
        );
    }
    fn terminate(&self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    /// The engine's own cleanup has run: discoverability removed, profile free.
    fn released(&self) -> bool {
        if self.profile.join("instance.json").exists() {
            return false;
        }
        let Ok(lock) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.profile.join("engine.lock"))
        else {
            return false;
        };
        fs2::FileExt::try_lock_exclusive(&lock).is_ok()
    }
    fn exited(&mut self, limit: Duration) -> Option<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if start.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    /// A writer ends the blocked open; non-blocking, so it fails if none waits.
    fn unblock(&self) -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc_nonblock())
            .open(&self.fifo)
            .map(drop)
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Never leave a test engine behind, whatever the assertions found.
        let _ = self.unblock();
        if self.exited(Duration::from_secs(5)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
fn libc_nonblock() -> i32 {
    // O_NONBLOCK on macOS and Linux.
    if cfg!(target_os = "macos") {
        0x0004
    } else {
        0o4000
    }
}
fn within(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while !ready() {
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}
fn stopped(engine: &Engine) -> Instant {
    assert!(
        within(Duration::from_secs(30), || engine.released()),
        "engine cleanup did not finish"
    );
    Instant::now()
}

#[test]
fn an_abandoned_blocking_open_cannot_keep_the_engine_process_alive() {
    let mut engine = Engine::start();
    engine.abandon_catalog_request();
    engine.terminate();
    let released = stopped(&engine);
    // The blocked open never returns by itself; the process must still end,
    // after its cleanup and within the bounded grace period.
    let status = engine.exited(Duration::from_secs(15));
    let elapsed = released.elapsed();
    let status = status
        .unwrap_or_else(|| panic!("engine still running {elapsed:?} after releasing its profile"));
    assert!(status.success(), "{status}");
}

#[test]
fn blocking_work_that_finishes_within_the_grace_still_completes() {
    let mut engine = Engine::start();
    engine.abandon_catalog_request();
    engine.terminate();
    let released = stopped(&engine);
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        engine.child.try_wait().unwrap().is_none(),
        "engine exited before its grace period"
    );
    let unblocked = Instant::now();
    engine
        .unblock()
        .expect("no blocked reader remained to unblock");
    // Not cut off at shutdown: the open completes and the process then ends
    // promptly, well before the grace period would have expired.
    let status = engine
        .exited(Duration::from_secs(3))
        .expect("engine did not end after its blocking work finished");
    assert!(status.success(), "{status}");
    assert!(
        unblocked.elapsed() < Duration::from_secs(3) && released.elapsed() < Duration::from_secs(5)
    );
}
