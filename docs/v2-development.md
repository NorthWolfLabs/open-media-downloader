# Develop and test the engine

Use Rust 1.93.0, Node 24.20.0, Vite+ 0.2.8 and UV. The engine, SDKs and browser adapter
build from this project alone. No desktop or production source plugin is needed.
Preserve lockfiles, the provider snapshot WASM and approved vendor input identities.

## Setup and test order

Install each Node workspace independently; the root package does not install SDK
dependencies. Set CARGO_TARGET_DIR to an absolute scratch path if keeping the source
root free of build output. Keep test profiles and reports outside publication inputs.

```sh
(cd sdk/provider && vp install --frozen-lockfile)
(cd sdk/client && vp install --frozen-lockfile)
(cd sdk/provider && vp run check)
(cd sdk/client && vp run check)
(cd sdk/provider && vp exec node bin/omd-plugin.mjs build ../../tests/v2-provider)
(cd sdk/provider && vp exec node bin/omd-plugin.mjs build ../../tests/v2-browser-provider)
(cd sdk/provider && vp exec node bin/omd-plugin.mjs build ../../tests/v2-acquisition-provider)
cargo build --locked --workspace --bins
vp exec node scripts/check-v2-contracts.mjs
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
uv run scripts/test-mcp.py
uv run scripts/test-manual-updates.py
uv run scripts/test-package-runtime.py
uv run scripts/test-public-distribution.py
uv run scripts/test-build-public-engine.py
uv run scripts/test-verify-media-build.py
```

Set OMD_PLUGIN_WORKER to the absolute matching worker executable before SDK fixture
checks when it isn't discoverable from Cargo's target. Then run:

```sh
(cd sdk/provider && vp run test)
(cd sdk/client && vp exec node --test test/http.test.mjs)
vp exec node --test scripts/integration-config.test.mjs scripts/browser-source.test.mjs scripts/source-fingerprint.test.mjs scripts/cargo-paths.test.mjs
uv run tests/v2-openapi.py
```

Native confinement checks require their OS prerequisites. The CI workflow documents
the disposable Linux guardian policy. Ignored live/native tests require explicit
managed tool/browser inputs and separate acceptance; a skipped check is not a pass.
Synthetic providers are test fixtures and aren't distributed as production sources.

## Run a private development service

```sh
cargo run --locked --bin omd-engine -- --profile /absolute/private/dev-profile
```

The engine finds the worker next to its executable unless --worker supplies an
explicit matching binary. To test acquisition or browser sign-in, pass --tools and
--browser-tools with verified immutable distribution manifests. They are build/
distribution inputs, not files copied from a user's PATH or account profile.
Do not use a public user's profile for development or tests.

## Change a contract

Rust domain/service schemas own schemas/v2. Regenerate and compare the public
contract, provider types, client models/scopes and MCP catalog together. The
[provider](../sdk/provider/README.md) and [client](../sdk/client/README.md) SDKs
are generated in this order: build `omd-schema` and `omd-openapi` and write their
output to `schemas/v2/domain.json` and `schemas/v2/openapi.json`; run
`vp exec node bin/generate-contracts.mjs` in `sdk/provider`; run
`vp exec node bin/generate.mjs` in `sdk/client`. `scripts/check-v2-contracts.mjs`
compares the Rust output with the checked-in schemas, then reruns both SDK
generators and fails if any generated file changes, so a failed check may have
already rewritten files; review the result before keeping it.
After an HTTP contract change, run `uv run scripts/generate-mcp.py` and the MCP
process suite. Fixed-route tools must cover every public operation or account for
it explicitly as lifecycle/resource behavior.

New source-specific behavior belongs in a separate plugin project. The separate
NASA project demonstrates an independently packed provider; it isn't a build input
or test dependency for this engine.

## Release and maintenance tools

Public native builds use [path-remapping and source preparation](source-distribution.md),
not development binaries. Runtime/package tools accept explicit reviewed artifacts.
The [materials contract](materials-contract.md) and [macOS signing guide](macos-signing.md)
cover exact-byte binding and native acceptance. Keep their license/source inputs and
old immutable release evidence intact when cleaning caches. Agent reports belong
in .local/agent-reports/<task>/ or outside the project, not alongside source files.

Build caches can retain absolute build-script output locations. If a moved/copied
Tauri cache points to an old permissions/output directory, use a fresh target
rather than restoring an obsolete source-tree path just to satisfy that cache.

Environment-assignment examples use a POSIX shell. In PowerShell set
`$env:NAME = "value"` before the command; replace every example path with a real
absolute path for your platform.
