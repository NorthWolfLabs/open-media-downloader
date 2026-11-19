# Deterministic ComponentizeJS initialization

This directory contains a WASI build tool, compiled from
`crates/omd-component-snapshot`. Plugin authors need Vite+ and the SDK; they do not
need Cargo or a separate installation of this tool.

ComponentizeJS 0.19.3 snapshots the initialized JavaScript runtime with Wizer.
OMD freezes the snapshot's WASI clock/random imports before initialization and
uses stable guest paths. Its isolated compiler process also fixes the splicer's
build-time clocks/randomness. These changes happen before compilation, not by
discarding different bytes or rewriting the final hash. The resulting component
still imports only the OMD broker and executes in the bounded Wasmtime worker.
This build tool never handles credentials or provides runtime cryptography.

`toolchain.json` pins the exact upstream compiler source and transformer WASM
hashes. Compiler source is adapted in memory; installed dependencies are never
modified. A changed compiler or unexpected initialization ABI fails the build.

Maintainers rebuild the artifact with Rust 1.93 and the wasm32-wasip1 target.
Use the [portable rebuild helper](../../../scripts/rebuild-snapshot-tool.py) from
the engine or SDK source-kit root. It remaps the project, Cargo, toolchain and
builder-home paths before compilation and rejects remaining host paths:

```sh
rustup target add wasm32-wasip1
uv run scripts/rebuild-snapshot-tool.py --target-dir /absolute/scratch/snapshot-target --output /absolute/scratch/omd-component-snapshot.wasm
```

Review and copy the candidate here and update its SHA-256 in `toolchain.json` and
the public source policies. A bare Cargo release build can still embed builder
paths in panic strings even with debug symbols stripped. Never sanitize those
strings by editing compiled bytes. Run SDK reproducibility tests and the actual Wasmtime
component conformance tests before publishing an SDK. The transformer uses
Walrus 0.26.5 (Apache-2.0/MIT); its full transitive build is pinned in Cargo.lock.
ComponentizeJS and Wizer retain their upstream licenses in the installed packages.

Host evidence does not establish cross-platform reproducibility. Run the same
SDK build fixtures on every supported authoring platform and compare hashes.
