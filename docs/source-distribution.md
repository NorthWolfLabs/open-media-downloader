# Prepare a public source release

Each project owns a format-2 public source policy and exports **only its own root**.
The engine policy is distribution/public-source-inputs.json; the desktop and NASA
projects use packaging/public-source-inputs.json. There is no combined engine/UI/
plugin source archive and no source row can select another checkout.

Every row selects an explicit regular file and destination. Binary assets require
an approved SHA-256, including vendored SDK archives, icons and the provider snapshot
WASM. Adding a source file requires adding its policy row. Gitignore is helpful for
development; the explicit source policy is the publication boundary.

## Export and inspect

From the project being released:

```sh
uv run scripts/export-public-source.py prepare --project /absolute/project \
  --policy /absolute/project/distribution/public-source-inputs.json \
  --output /absolute/new-engine-source
# Inspect source/ and inventory.json before making an archive.
uv run scripts/export-public-source.py archive --output /absolute/new-engine-source
```

Use packaging/public-source-inputs.json for the UI or NASA source. Each output is
independent and starts empty. Reports and inventories stay beside source/; they are
not silently committed or published. Existing outputs are refused. Archives normalize
member order, modes, timestamps and gzip metadata, then reopen and hash-check every
member against the frozen inventory. Changed files or inventory abort acceptance.

The exporter rejects Git metadata, caches/build output, profiles/authorities, local
reports/evidence, plugin packages, special files and symlink ancestors. It checks
portable paths, case-folded collisions, binary approvals and size/count budgets.
A failed export/archive stays inspectable without a success report. The source
archive does not include another project's source to make a local build convenient.

## Verify independent projects

Follow [engine development](v2-development.md). In a separate UI export, frozen
install/check/test/build must resolve its own licensed client SDK archive. In a
separate NASA export, frozen install/check/test/build/pack must resolve its own
provider SDK archive. Supply a matching external worker for plugin conformance.
No private connector or sibling application source checkout is required.

The snapshot transformer is a required first-party build input. Its
[rebuild instructions](../sdk/provider/build-tool/README.md), pinned toolchain,
source and third-party notices stay with the engine/SDK source. Dependency and
managed-runtime terms are not replaced by this project's MIT license.

## Native releases

Development binaries can embed local builder paths. Use:

```sh
uv run scripts/build-public-engine.py --target aarch64-apple-darwin \
  --output /absolute/new-native-build --check
```

Remove --check to build the six locked release executables. The entry applies
--remap-path-prefix through CARGO_ENCODED_RUSTFLAGS to the project, target directory,
Cargo home, toolchain sysroot and installed rust-src. Canonical path aliases map to
the same logical prefixes. It refuses conflicting rustflags/wrappers and rejects
outputs still containing mapped roots or the builder's home. It also checks the
optimized worker marker. Development builds do not receive this public guarantee.
The UI's scripts/build-public.mjs applies the same rule to its own executable.

These checks don't rewrite literal strings or substitute for exact-byte materials,
license review, signing/notarization, old-OS support, other CPU/platform execution or
clean-account installation. Use the [materials contract](materials-contract.md),
[macOS payload gate](macos-payload-minimum.md) and [signing guide](macos-signing.md).
Source export and clean Git history do not by themselves accept a public release.

Windows MSVC public builds select the static C runtime for every engine binary.
Verify the final PE imports and execute on a clean Windows system; an ordinary
development machine may hide a missing Visual C++ runtime prerequisite. Keep
Microsoft's runtime terms and the exact SDK/compiler provenance as separate
materials. Rust/Cargo notices do not relicense Microsoft runtime code.
