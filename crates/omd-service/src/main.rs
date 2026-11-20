#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
use clap::Parser;
use omd_acquisition::Acquisition;
use omd_network::Network;
use omd_plugins::{Provider, Runtime};
use omd_service::{App, router, run_jobs, run_subscriptions};
use omd_store::Store;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "OMD acquisition service")]
struct Args {
    /// A new v2 profile directory. Legacy databases are never opened.
    #[arg(long, required_unless_present = "identity")]
    profile: Option<PathBuf>,
    /// Print this executable's protocol, version and SHA-256 without opening a profile.
    #[arg(long, conflicts_with = "prepare_update")]
    identity: bool,
    /// Gracefully stop this profile's engine before replacing or uninstalling OMD.
    #[arg(long)]
    prepare_update: bool,
    #[arg(long, default_value = "0")]
    port: u16,
    #[arg(long)]
    worker: Option<PathBuf>,
    /// Verified, immutable managed-tool manifest supplied by the distribution.
    #[arg(long)]
    tools: Option<PathBuf>,
    /// Verified browser distribution manifest; included packages bootstrap once.
    #[arg(long)]
    browser_tools: Option<PathBuf>,
    #[arg(long)]
    allowed_origin: Vec<String>,
    /// Started by per-user OS startup integration; wait for the active owner.
    #[arg(long)]
    service: bool,
    /// Create or validate the private profile, then exit without starting a service.
    #[arg(long)]
    initialize_profile: bool,
}
/// How long blocking work may outlive normal graceful shutdown. Each awaited
/// engine task, including publishing, has finished on that path; what can
/// remain is file I/O nothing awaits any more, such as an `open()` that macOS
/// holds behind an unanswered folder permission dialog. `#[tokio::main]` would
/// wait for it forever, keeping a process that already released its profile.
const BLOCKING_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> anyhow::Result<()> {
    // The runtime `#[tokio::main]` builds, with a bounded wait at the end.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime");
    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(run())));
    // Tokio leaves blocking threads still running after the grace period to
    // end with the process.
    runtime.shutdown_timeout(BLOCKING_GRACE);
    match outcome {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The engine log without RUST_LOG: errors from every component, plus OMD's
/// own warnings, which carry only redacted diagnostics such as which
/// execution limit stopped a source and where its time went.
const DEFAULT_LOG: &str =
    "error,omd_engine=warn,omd_service=warn,omd_plugins=warn,omd_files=warn,omd_isolation=warn";

async fn run() -> anyhow::Result<()> {
    let filter = match std::env::var("RUST_LOG") {
        Ok(directives) if !directives.trim().is_empty() => {
            tracing_subscriber::EnvFilter::from_default_env()
        }
        _ => tracing_subscriber::EnvFilter::new(DEFAULT_LOG),
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    let mut args = Args::parse();
    if args.identity {
        println!(
            "{}",
            serde_json::to_string(omd_service::identity::current()?)?
        );
        return Ok(());
    }
    // Optional only for the profile-free identity command above. Clap rejects
    // every other invocation without --profile before any state is touched.
    let mut profile = args.profile.take().expect("Clap requires a profile");
    if args.prepare_update && !profile.exists() {
        return Ok(());
    }
    omd_files::private_profile(&profile)?;
    profile = std::fs::canonicalize(&profile)?;
    if args.initialize_profile {
        return Ok(());
    }
    if args.prepare_update {
        return omd_service::update::prepare(&profile).await;
    }
    // Capture before serving: an installer may later replace the file on disk.
    omd_service::identity::current()?;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=terminate.recv()=>{} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal.cancel();
    });
    // Instance ownership is acquired before opening SQLite or publishing tokens.
    let ownership = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(profile.join("engine.lock"))?;
    loop {
        if args.service && profile.join("update.pending").exists() {
            return Ok(());
        }
        match fs2::FileExt::try_lock_exclusive(&ownership) {
            Ok(()) => break,
            Err(error) if ownership_contended(&error) && args.service => {
                tokio::select! { _=shutdown.cancelled()=>return Ok(()), _=tokio::time::sleep(std::time::Duration::from_secs(1))=>{} }
            }
            Err(error) if ownership_contended(&error) => anyhow::bail!(
                "An engine already owns this profile. Attach using its instance.json file."
            ),
            Err(error) => return Err(error.into()),
        }
    }
    if !args.service && profile.join("update.pending").exists() {
        std::fs::remove_file(profile.join("update.pending"))?;
    }
    let store = Store::open(&profile.join("acquisitions-v2.sqlite3")).await?;
    if args.service
        && !store
            .setting("preferences")
            .await?
            .is_some_and(|v| v["background"] == true)
    {
        store.pool.close().await;
        // Started at login or by a registration that background was later
        // turned off for: unregister this job instead of starting again.
        release_after(ownership, async {
            let _ = omd_lifecycle::retire_service(&profile).await;
        })
        .await;
        return Ok(());
    }
    store.recover().await?;
    omd_notifications::recover(&store).await?;
    let worker = args
        .worker
        .unwrap_or(std::env::current_exe()?.with_file_name(if cfg!(windows) {
            "omd-plugin-worker-v2.exe"
        } else {
            "omd-plugin-worker-v2"
        }));
    anyhow::ensure!(
        worker.is_file(),
        "The packaged plugin worker is missing: {}",
        worker.display()
    );
    let cache = profile.join("wasmtime-cache.toml");
    std::fs::write(
        &cache,
        format!(
            "[cache]\ndirectory = {}\n",
            serde_json::to_string(&profile.join("compiled-components"))?
        ),
    )?;
    let identity_path = profile.join("profile-id");
    let identity = match std::fs::read_to_string(&identity_path) {
        Ok(identity) => {
            anyhow::ensure!(
                uuid::Uuid::parse_str(identity.trim()).is_ok(),
                "The profile identity is invalid; restore its profile-id file."
            );
            identity.trim().to_owned()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::io::Write;
            let identity = uuid::Uuid::new_v4().to_string();
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&identity_path)?;
            file.write_all(identity.as_bytes())?;
            file.sync_all()?;
            identity
        }
        Err(error) => return Err(error.into()),
    };
    let bandwidth = store
        .setting("preferences")
        .await?
        .and_then(|v| v["bandwidth_bytes_per_second"].as_u64())
        .unwrap_or(0);
    let network = Network::new(bandwidth).with_vault(omd_credentials::Vault::native(&identity));
    let worker = std::fs::canonicalize(worker)?;
    let mut launch_arguments = vec![
        "--profile".into(),
        profile.to_string_lossy().into_owned(),
        "--worker".into(),
        worker.to_string_lossy().into_owned(),
    ];
    if args.port != 0 {
        launch_arguments.extend(["--port".into(), args.port.to_string()]);
    }
    for origin in &args.allowed_origin {
        launch_arguments.extend(["--allowed-origin".into(), origin.clone()]);
    }
    let runtime = Runtime::new(worker, network.clone(), 4).with_cache(cache);
    if let Some(path) = &args.tools {
        launch_arguments.extend(["--tools".into(), path.to_string_lossy().into_owned()]);
    }
    omd_service::tools::initialize(&store, &profile, &network, &runtime, args.tools.as_deref())
        .await?;
    let mut providers = BTreeMap::new();
    if let Some(path) = &args.browser_tools {
        launch_arguments.extend([
            "--browser-tools".into(),
            path.to_string_lossy().into_owned(),
        ]);
    }
    omd_service::browsers::initialize(
        &store,
        &profile,
        &network,
        &runtime,
        args.browser_tools.as_deref(),
    )
    .await?;
    for (manifest, path, digest, enabled) in store.providers().await? {
        if enabled {
            let mut cursor = None;
            loop {
                let page = store
                    .provider_versions(&manifest.id, cursor.as_deref(), 200)
                    .await?;
                for version in page.items {
                    if let Some(digest) = version["digest"].as_str() {
                        runtime.restore(&manifest.id, digest);
                    }
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
            let provider = Provider {
                manifest,
                component: path.into(),
                digest,
            };
            // Prepare approved source code before announcing engine readiness.
            // Release workers retain a compiler-version cache across app updates;
            // the first interactive operation never pays compilation cost.
            let preparation = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                runtime.inspect(&provider, &tokio_util::sync::CancellationToken::new()),
            )
            .await;
            if !matches!(preparation, Ok(Ok(()))) {
                tracing::warn!(source=%provider.manifest.id, "Source preparation did not finish; source management remains available");
            }
            providers.insert(provider.manifest.id.clone(), provider);
        } else {
            runtime.revoke(&manifest.id).await?;
        }
    }
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let admin_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let launch = omd_lifecycle::Launch {
        engine: std::env::current_exe()?,
        profile: profile.clone(),
        arguments: launch_arguments,
    };
    launch.persist()?;
    if launch_background(&store).await {
        let issue = launch.set_enabled(true).await.err().map(|_| {
            omd_domain::Problem::new(
                "startup_unavailable",
                "Automatic startup could not be restored. Retry the background setting in OMD.",
            )
        });
        store
            .set_setting(
                "startup_status",
                &serde_json::json!({"enabled":issue.is_none(),"issue":issue}),
            )
            .await?;
    }
    let app = App {
        browser_sessions: Default::default(),
        source_changes: Arc::new(Mutex::new(())),
        notification_lock: Arc::new(Mutex::new(())),
        notification_adapter: std::env::current_exe()?.with_file_name(if cfg!(windows) {
            "omd-notify.exe"
        } else {
            "omd-notify"
        }),
        sign_in_helper: omd_service::sign_in_helper(&std::env::current_exe()?),
        store: store.clone(),
        runtime,
        acquisition: Acquisition { store, network },
        profile: profile.clone(),
        token: token.clone(),
        admin_token: admin_token.clone(),
        shutdown: shutdown.clone(),
        providers: Arc::new(RwLock::new(providers)),
        running: Arc::new(Mutex::new(BTreeMap::new())),
        clients: Default::default(),
    };
    let listener =
        tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, args.port)).await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let instance = profile.join("instance.json");
    let temporary = profile.join(format!("instance-{}.tmp", uuid::Uuid::new_v4().simple()));
    let contents = serde_json::to_vec_pretty(
        &serde_json::json!({"api":"v2","endpoint":endpoint,"token":token,"admin_token":admin_token,"pid":std::process::id()}),
    )?;
    use std::io::Write;
    let mut file = omd_files::create_private_file(&temporary)?;
    file.write_all(&contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, &instance)?;
    println!("OMD v2 listening at {endpoint}");
    let jobs = tokio::spawn(run_jobs(app.clone()));
    let subscriptions = tokio::spawn(run_subscriptions(app.clone()));
    let selections = tokio::spawn(omd_service::selections::run_selections(app.clone()));
    let storage = tokio::spawn(omd_service::storage::run_storage(app.clone()));
    let notifications = tokio::spawn(omd_service::notifications::run(app.clone()));
    let tools = tokio::spawn(omd_service::tools::run(app.clone()));
    let browsers = tokio::spawn(omd_service::browsers::run(app.clone()));
    let removals = tokio::spawn(omd_service::source_removals::run(app.clone()));

    let lifecycle = app.clone();
    let lifecycle_task = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        loop {
            tokio::select! {_=lifecycle.shutdown.cancelled()=>break,_=tokio::time::sleep(std::time::Duration::from_secs(5))=>{}}
            if omd_service::idle_exit_due(&lifecycle, started.elapsed()).await {
                lifecycle.shutdown.cancel();
                break;
            }
        }
    });
    let mut origins = vec![
        "tauri://localhost".parse()?,
        "http://tauri.localhost".parse()?,
        "https://tauri.localhost".parse()?,
    ];
    for origin in args.allowed_origin {
        origins.push(origin.parse()?);
    }
    let server = axum::serve(listener, router(app.clone(), origins))
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .await;
    shutdown.cancel();
    let _ = jobs.await;
    let _ = subscriptions.await;
    let _ = selections.await;
    let _ = storage.await;
    let _ = removals.await;
    let _ = notifications.await;
    let _ = tools.await;
    let _ = browsers.await;
    let _ = lifecycle_task.await;
    // A startup engine that served the switch to background off could not
    // unload its own job then; it does so once it has stopped serving.
    let retire = args.service
        && (profile.join("update.pending").exists()
            || matches!(
                app.store.setting("preferences").await,
                Ok(preferences) if !preferences.as_ref().is_some_and(|v| v["background"] == true)
            ));
    app.store.pool.close().await;
    // Lock still held while removing discoverability. A successor cannot race us.
    std::fs::remove_file(instance)?;
    release_after(ownership, async {
        if retire {
            let _ = omd_lifecycle::retire_service(&profile).await;
        }
    })
    .await;
    server?;
    Ok(())
}

async fn launch_background(store: &Store) -> bool {
    matches!(store.setting("preferences").await, Ok(Some(value)) if value["background"]==true)
}

/// Give up the profile only once `retire` has finished. A successor that owned
/// the profile earlier could register its own startup job under the same
/// label, which this engine's late retirement would then remove.
async fn release_after(ownership: std::fs::File, retire: impl std::future::Future<Output = ()>) {
    retire.await;
    drop(ownership);
}

fn ownership_contended(error: &std::io::Error) -> bool {
    // Windows reports ERROR_LOCK_VIOLATION, whose std::io::ErrorKind is not
    // WouldBlock. Compare fs2's actual platform error, without treating other
    // permission or storage failures as an existing owner.
    error.raw_os_error().is_some()
        && error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

#[cfg(test)]
mod ownership_tests {
    #[tokio::test]
    async fn a_successor_cannot_own_the_profile_until_retirement_finishes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("engine.lock");
        let owner = std::fs::File::create(&path).unwrap();
        fs2::FileExt::try_lock_exclusive(&owner).unwrap();
        let successor = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let (started, retiring) = tokio::sync::oneshot::channel::<()>();
        let release = tokio::spawn(super::release_after(owner, async move {
            started.send(()).unwrap();
            let _ = finished.await;
        }));
        retiring.await.unwrap();
        // While the predecessor still unregisters its startup job.
        let early = fs2::FileExt::try_lock_exclusive(&successor);
        finish.send(()).unwrap();
        release.await.unwrap();
        assert!(
            early.as_ref().is_err_and(super::ownership_contended),
            "a successor owned the profile during retirement"
        );
        fs2::FileExt::try_lock_exclusive(&successor).unwrap();
    }
    #[test]
    fn native_lock_contention_is_distinct_from_other_failures() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ownership.lock");
        let first = std::fs::File::create(&path).unwrap();
        let second = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&first).unwrap();
        let error = fs2::FileExt::try_lock_exclusive(&second).unwrap_err();
        assert!(super::ownership_contended(&error));
        assert!(!super::ownership_contended(&std::io::Error::other(
            "unrelated storage error"
        )));
        fs2::FileExt::unlock(&first).unwrap();
        fs2::FileExt::try_lock_exclusive(&second).unwrap();
    }
}
