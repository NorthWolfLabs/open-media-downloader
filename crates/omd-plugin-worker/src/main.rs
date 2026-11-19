#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]
//! Deliberately separate process: untrusted component memory cannot access engine memory.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

wasmtime::component::bindgen!({path:"../../sdk/provider/wit",world:"provider"});
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct Invocation {
    component: String,
    #[serde(default)]
    manifest: Option<omd_domain::ProviderManifest>,
    payload: String,
    #[serde(default)]
    inspect: bool,
    #[serde(default)]
    reuse: bool,
    #[serde(default)]
    cache_config: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct BrokerFrame {
    operation: String,
    payload: String,
}
#[derive(Serialize, Deserialize)]
struct BrokerReply {
    result: Option<String>,
    error: Option<String>,
}
struct State {
    limits: StoreLimits,
    calls: usize,
    executing: Arc<AtomicBool>,
}

/// Epochs measure time executing plugin code, not waiting for engine-owned I/O.
struct BrokerWait(Arc<AtomicBool>);
impl BrokerWait {
    fn enter(active: &Arc<AtomicBool>) -> Self {
        active.store(false, Ordering::SeqCst);
        Self(active.clone())
    }
}
impl Drop for BrokerWait {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl omd::provider::broker::Host for State {
    fn request(&mut self, operation: String, payload: String) -> Result<String, String> {
        self.calls += 1;
        if self.calls > 128 || payload.len() > 4 * 1024 * 1024 {
            return Err("Plugin broker budget exceeded".into());
        }
        let _waiting = BrokerWait::enter(&self.executing);
        write_frame(&serde_json::json!({"broker":BrokerFrame{operation,payload}}))
            .map_err(|_| "Broker transport failed".to_string())?;
        let reply: BrokerReply = read_frame().map_err(|_| "Broker transport failed".to_string())?;
        reply
            .result
            .ok_or_else(|| reply.error.unwrap_or_else(|| "Broker failed".into()))
    }
}
fn read_frame<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut size = [0; 4];
    std::io::stdin().read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    if size > FRAME_LIMIT {
        bail!("IPC frame exceeds limit");
    }
    let mut body = vec![0; size];
    std::io::stdin().read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}
fn write_frame(value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > FRAME_LIMIT {
        bail!("IPC result exceeds limit");
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&(bytes.len() as u32).to_le_bytes())?;
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}
struct Compiled {
    path: String,
    cache: Option<String>,
    engine: Engine,
    component: Component,
    executing: Arc<AtomicBool>,
}
#[derive(Default, Serialize)]
struct Timings {
    compile_ms: u128,
    instantiate_ms: u128,
    execute_ms: u128,
}
#[cfg(debug_assertions)]
const BUILD_PROFILE: &str = "OMD_WORKER_PROFILE=debug";
#[cfg(not(debug_assertions))]
const BUILD_PROFILE: &str = "OMD_WORKER_PROFILE=release";
fn run(
    input: Invocation,
    cached: &mut Option<Compiled>,
    timing: &mut Timings,
) -> Result<serde_json::Value> {
    if cached
        .as_ref()
        .is_some_and(|c| c.path != input.component || c.cache != input.cache_config)
    {
        bail!("A worker cannot switch source identity");
    }
    if cached.is_none() {
        let started = std::time::Instant::now();
        let mut config = Config::new();
        config
            .parallel_compilation(true)
            .wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .cranelift_opt_level(wasmtime::OptLevel::None);
        if let Some(path) = &input.cache_config {
            config.cache(Some(wasmtime::Cache::from_file(Some(
                std::path::Path::new(&path),
            ))?));
        }
        let engine = Engine::new(&config)?;
        let tick = engine.clone();
        let executing = Arc::new(AtomicBool::new(true));
        let active = executing.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if active.load(Ordering::SeqCst) {
                    tick.increment_epoch();
                }
            }
        });
        let component = Component::from_file(&engine, &input.component)
            .map_err(|e| anyhow::anyhow!("Compile provider: {e:#}"))?;
        timing.compile_ms = started.elapsed().as_millis();
        *cached = Some(Compiled {
            path: input.component.clone(),
            cache: input.cache_config.clone(),
            engine,
            component,
            executing,
        });
    }
    let compiled = cached.as_ref().unwrap();
    let engine = &compiled.engine;
    let component = &compiled.component;
    let executing = compiled.executing.clone();
    executing.store(true, Ordering::SeqCst);
    let imports: Vec<_> = component
        .component_type()
        .imports(engine)
        .map(|(name, _)| name.to_string())
        .collect();
    if imports
        .iter()
        .any(|name| name != "omd:provider/broker@2.0.0")
    {
        bail!("Component requests unapproved imports: {imports:?}");
    }
    let limits = StoreLimitsBuilder::new()
        .memory_size(256 * 1024 * 1024)
        .memories(4)
        .tables(16)
        .table_elements(100_000)
        .instances(64)
        .build();
    let mut store = Store::new(
        engine,
        State {
            limits,
            calls: 0,
            executing,
        },
    );
    store.limiter(|s| &mut s.limits);
    store.set_fuel(20_000_000_000)?;
    store.set_epoch_deadline(300);
    let mut linker = Linker::new(engine);
    Provider::add_to_linker::<_, wasmtime::component::HasSelf<_>>(&mut linker, |state| state)?;
    let started = std::time::Instant::now();
    let instance = Provider::instantiate(&mut store, component, &linker)?;
    timing.instantiate_ms = started.elapsed().as_millis();
    if input.inspect {
        return Ok(serde_json::json!({"imports":imports,"isolation":"wasm"}));
    }
    let started = std::time::Instant::now();
    let result = instance
        .call_invoke(&mut store, &input.payload)?
        .map_err(anyhow::Error::msg)?;
    timing.execute_ms = started.elapsed().as_millis();
    if result.len() > FRAME_LIMIT / 2 {
        bail!("Provider result exceeds limit");
    }
    let result: serde_json::Value = serde_json::from_str(&result)?;
    if let Some(manifest) = input.manifest
        && result["ok"] == true
    {
        let request: omd_domain::ProviderRequest = serde_json::from_str(&input.payload)?;
        omd_domain::validate_provider_result(&manifest, &request, &result["result"])?;
    }
    Ok(result)
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--build-info") {
        println!(
            "{}",
            serde_json::json!({"profile":BUILD_PROFILE,"wasmtime":"45.0.3"})
        );
        return;
    }
    if rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global()
        .is_err()
    {
        std::process::exit(1);
    }
    let mut cached = None;
    loop {
        let input: Invocation = match read_frame() {
            Ok(input) => input,
            Err(_) => return,
        };
        let reuse = input.reuse;
        let mut timing = Timings::default();
        let result = match run(input, &mut cached, &mut timing) {
            Ok(v) => serde_json::json!({"result":v,"timing":timing}),
            Err(e) => serde_json::json!({"error":format!("{e:#}"),"timing":timing}),
        };
        if let Some(compiled) = &cached {
            compiled.executing.store(false, Ordering::SeqCst);
        }
        if write_frame(&result).is_err() {
            std::process::exit(1);
        }
        if !reuse {
            return;
        }
    }
}
