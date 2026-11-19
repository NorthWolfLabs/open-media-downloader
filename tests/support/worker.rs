/// Keep fixture execution on the binaries built for this target and profile.
/// An explicit worker is useful when testing an independently packaged build.
pub fn executable() -> std::path::PathBuf {
    std::env::var_os("OMD_PLUGIN_WORKER")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let test = std::env::current_exe().expect("Locate the acceptance test executable");
            let directory = test.parent().expect("Test executable directory");
            let binaries = directory.parent().expect("Cargo target/profile directory");
            binaries.join(format!(
                "omd-plugin-worker-v2{}",
                std::env::consts::EXE_SUFFIX
            ))
        })
}

/// Match the installed engine's cache configuration. Tests timing plugin
/// execution inspect the component first, just as installation does, so their
/// deadline does not accidentally measure repeated cold native compilation.
#[allow(dead_code)]
pub fn cache_config(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("wasmtime-cache.toml");
    std::fs::write(
        &path,
        format!(
            "[cache]\ndirectory = {}\n",
            serde_json::to_string(&directory.join("compiled-components")).unwrap()
        ),
    )
    .unwrap();
    path
}
