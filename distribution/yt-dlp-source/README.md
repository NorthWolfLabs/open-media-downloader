# Controlled-source yt-dlp prototype (macOS arm64)

This profile builds yt-dlp 2026.10.26 as a PyInstaller onefile whose shipped Python
runtime, native libraries, Python packages and bootloader all come from pinned source
archives. Each input's version, hash, build flags and patch set is recorded, so the
build has its own provenance receipt. It replaces
nothing: the legacy recipe (`distribution/yt-dlp`, `scripts/build-ytdlp.py`), the
upstream `yt-dlp_macos` producer, its prepared copies and all existing evidence stay
unchanged and usable. The output is an **unaccepted, unpromotable prototype**. It is
ad-hoc signed only, and has no Developer ID signature or notarization.

**Not the public profile.** On 2026-11-02 the owner decided that the public extractor
must keep its current capabilities, including `curl_cffi` browser impersonation built from
pinned source with its native closure
(`artifacts/public-extractor-capability-decision-20261102.json`). This profile follows the
declared `[default]` extras without `curl_cffi`, so it stays an unpromotable prototype and is
never the public profile. `distribution/yt-dlp-source-curl` is the separate v2 profile that adds
source-built `curl_cffi` impersonation; its README describes the additions.

## Profile

`profile.json` (schema `omd-ytdlp-source-profile-v1`) pins every input by URL, size and
SHA-256, with its role:

- **shipped-source**: compiled or copied into the executable. CPython 3.13.14
  (python.org release-API SHA-256 and Sigstore identity `thomas@python.org`), OpenSSL
  3.5.7, XZ 5.2.3, SQLite 3.50.4, mpdecimal 4.0.1, the PyInstaller 6.22.0 sdist
  (bootloader and loader), and the sdists of yt-dlp and every `[default]` runtime
  dependency.
- **packaging-source**: built from sdist and used by PyInstaller at packaging time:
  altgraph, macholib, packaging, pyinstaller-hooks-contrib and setuptools. The legacy
  `--collect-all yt_dlp` flags also collect yt-dlp's own `__pyinstaller` hook package. That
  pulls some PyInstaller, setuptools, packaging, altgraph and macholib modules into the
  executable. The receipt's `origin_summary` counts them, and their sources and terms are in
  the kit.
- **build-tool**: build dependencies. Their templates can contribute generated
  shipped source, which is identified separately with generator, input and license
  hashes (including EJS's version module). These are 11 pure-Python build-backend wheels, the
  official Node 24.20.0 darwin-arm64 archive (the project's `.node-version`), and the
  189 npm tarballs that yt-dlp-ejs's own `package-lock.json` pins by sha512.

Runtime and packaging sdists must equal the legacy `distribution/yt-dlp/uv.lock`
entries exactly (`yt-dlp[default]==2026.10.26`, Python `==3.13.*`, `.python-version`
3.13.14). The only declared adjustment is PyInstaller 6.22.2 → 6.22.0, the version the
reviewed signing and extractor helpers pin. Its darwin dependency set is unchanged. The
optional `curl-cffi` extra is not part of `[default]`, so it is not built.

## Recipe

The native recipes follow CPython 3.13.14's `Mac/BuildScript/build-installer.py`.
Deviations are explicit in the profile:

- arm64 only, `MACOSX_DEPLOYMENT_TARGET=13.5`.
- All dependencies are built static (OpenSSL `no-shared`, `make build_sw`). They link into
  the extension modules instead of being shipped as separate dylibs.
- OpenSSL is 3.5.7 instead of the 3.13.14 recipe's 3.0.21. The 3.0 LTS series reached end of
  life in September 2026. 3.5.7 is the retained archive that CPython 3.14.6's recipe pins.
- CPython is a non-framework `--enable-shared` build with the recipe's `--with-mimalloc=no
  --with-system-libmpdec --with-computed-gotos --without-ensurepip --with-openssl`. It adds
  `--disable-test-modules --without-static-libpython --with-pkg-config=no` and
  `OPT='-O3 -Wall'`. Dropping the default `-g` keeps build-directory debug-map paths out of
  shipped Mach-O files. PGO/LTO and the framework/universal layout are not used.
- Installs go to a logical prefix (`/opt/omd-ytdlp-source/…`) through `DESTDIR`. One
  recorded post-link step points the staged `bin/python3.13` at
  `@executable_path/../lib/libpython3.13.dylib` and re-signs it ad hoc. libpython itself is
  unchanged.
- pip comes from the wheel bundled in the CPython source tarball and runs offline
  (`--no-index`). Every package is built with `pip wheel --no-binary :all:
  --no-build-isolation` from its extracted sdist, then installed by hash. Explicit switches:
  websockets `BUILD_EXTENSION=yes`, brotli `USE_SYSTEM_BROTLI=0`, charset-normalizer
  `CHARSET_NORMALIZER_USE_CYTHON=0` (the pure build).
- yt-dlp-ejs's hatch hook runs `npm ci` and `npm run bundle` (rollup) under the pinned Node.
  The npm cache contains only the integrity-checked tarballs, with `offline` and
  `ignore-scripts` set. Both bundles must equal the upstream wheel bytes.
- The PyInstaller sdist's prebuilt bootloaders are deleted. The stock (unmodified)
  bootloader source is compiled with `waf --no-universal2 configure all`, and the wheel
  must carry those compiled binaries.

The environment is reset to `/usr/bin:/bin:/usr/sbin:/sbin`, the Xcode SDK, `SOURCE_DATE_EPOCH`,
`ZERO_AR_DATE=1` and `PYTHONHASHSEED=0`, with no package-manager paths.

## Commands

From the engine root, with all caches and outputs on external storage:

```sh
uv run scripts/build-ytdlp-source.py fetch --output /new/sources --retained /retained/kit --report /new/fetch.json
uv run scripts/build-ytdlp-source.py plan --sources /new/sources --plan /new/plan.json
uv run scripts/build-ytdlp-source.py build --plan /new/plan.json --sources /new/sources --output /new/build
uv run scripts/build-ytdlp-source.py kit --plan /new/plan.json --sources /new/sources --build /new/build --output /new/kit.tar.gz
uv run scripts/build-ytdlp-source.py verify-kit --kit /new/kit.tar.gz --sha256 HEX
uv run scripts/test-build-ytdlp-source.py
```

These commands use this profile by default (`--profile distribution/yt-dlp-source/profile.json`).
A plan records the profile it was made for, and `build` and `kit` follow the plan.

`plan` refuses any input digest, size or npm integrity mismatch, and any extra or symlinked
file in the sources directory. It also refuses a lock or version difference, a prebuilt
platform wheel, a non-arm64 target or a minimum below 13.5. `build` re-derives the plan and
refuses a stale one before creating its new output directory. That directory must lie
outside the engine and the sources. A failure keeps all logs and writes a `failed` receipt;
only a fully verified build gets `bin/omd-yt-dlp` and status `built`. Receipts and plans
are portable, with no host paths.

## Verification performed by `build`

- Native libraries, the staged CPython and every wheel's Mach-O content must be thin arm64
  with a minimum no higher than 13.5. They may link only Apple OS libraries
  (`/usr/lib`, `/System/Library`) or bundle-relative paths.
- CPython must report exactly the expected disabled test modules and nothing missing or failed.
- The analysis environment must contain only the built wheels' files, plus pip's
  byte-compiled files and records.
- The onefile must be thin arm64 with an outer signature that passes
  `codesign --verify --strict`. Raw CArchive names and links are validated, and every packed
  Mach-O member must verify cryptographically. Both checks reuse the reviewed signing
  helpers unchanged.
- **Natives.** For each packed Mach-O, the build replays PyInstaller 6.22.0's own
  `process_collected_binary` on a private copy of its recorded build product. That is the
  install-name/rpath rewrite and the ad-hoc signature, run from the source-built runtime with
  the options PyInstaller recorded in `PKG-00.toc`. The result must equal the packed member
  byte for byte, which binds every load command, link-edit field, segment and data byte.
  An independent policy also requires every packed native and the executable to parse
  strictly, with known load commands only, clean strings and padding, and everything in
  bounds. The policy allows only these changes from the product: an `@rpath/<basename>`
  install name, non-system dependency paths rewritten to `@rpath/<basename>`, the
  replaced LC_RPATH set, and the signature with its `__LINKEDIT` sizes. Every other byte
  must be identical.
- **Executable.** The build replays the macOS steps of `EXE.assemble` with PyInstaller's
  own `osx` functions on the compiled bootloader (`run`, hash-bound, not the sdist's
  prebuilt or the vendored universal2 stock binary), the executable's own PKG and the built
  `libpython`. The result must equal the executable byte for byte. Independently, the
  reviewed extractor `bootloader_view` must match the bootloader exactly, except for the
  PKG-derived UUID, string-table size and signature fields, which are re-derived.
- **Python code.** Each PYZ module, packed script, bootstrap module and `base_library.zip`
  member is attributed by import-path resolution over the analysis roots: the launcher
  directory, the stdlib, `lib-dynload` and `site-packages`. Its expected source is
  compiled under the built CPython (bytecode magic, `PYTHONHASHSEED=0`, optimization 0)
  along PyInstaller's own compile path, then given PyInstaller's recursive `co_filename`
  replacement. The result must equal the unmarshalled packed code object as marshal
  version 2 data, so every code field and nested constant counts. Only marshal reference
  and interning flags, which depend on reference counts, are not compared. PYZ headers,
  TOCs, zlib streams and the base-library `.pyc` headers and zip writer are checked
  strictly and with size limits. Duplicate, unsorted, unattributable or missing modules
  fail, and the names and sources must also match PyInstaller's own `PYZ-00.toc` and
  `PKG-00.toc`. Packed code is only unmarshalled for comparison; it is never imported or
  executed.
- **Source provenance.** Archive-origin claims match immutable input archive bytes,
  including CPython `Lib/` and package sdists, rather than a post-build extraction tree.
  The launcher is bound separately. Generated `_sysconfigdata__darwin_darwin.py`
  matches the output captured after CPython's `make` and the build-root remapping below. EJS's generated `_version.py`
  records its pinned vcs-versioning template, inputs, output and retained license.
  Any other packed source that is neither an immutable sdist member nor that reviewed
  generated output fails the build. Data members match a built wheel file, a CPython file or
  pip's install records, and the file PyInstaller recorded.
- The CArchive layout (contiguous entries, pinned TOC serialization, cookie) is checked as
  the reviewed extractor checks it.
- No build, source, engine or home path may appear in packed bytes, and
  `expected.build_path_members` must be empty. CPython's `_sysconfigdata` records its
  configure arguments and build directories, so straight after `make` the build rewrites
  them to logical paths: the staged install tree becomes `logical_prefix`
  (`/opt/omd-ytdlp-source`) and the rest of the work directory (dependency prefix,
  extracted sources) becomes `<logical_prefix>/build`. The receipt records each
  replacement as `cpython_sysconfig`. The build fails if any host directory or host-path
  pattern remains in that module, and again if any packed member names the build root.
- A network-denied `sandbox-exec` smoke run with `--ignore-config --no-plugin-dirs` covers
  `--version`, `--list-extractors`, the `-v` header with no URL, and
  `--list-impersonate-targets`.
- PyInstaller packaging is repeated from the same environment and compared.

## Kit

`kit` writes a deterministic `.tar.gz` (sorted members, fixed mtime, no owners). It holds
every pinned input unchanged, the npm tarballs, this profile, the legacy lock files, the
MIT tooling, the plan, the portable receipt and `closure-fingerprints.json`. The tooling
includes the replay helper `ytdlp_source_replay.py` and the reviewed `macos_extractor.py`
it reuses. The fingerprints file lists, for every packed code object, its attributed
source (root, path, SHA-256, provenance), `co_filename`, compile path and canonical code
digest. `verify-kit` checks it against the receipt. The kit also carries byte-identical
top-level license files of each source archive under `terms/`, the license of each build tool
whose template generated shipped source (vcs-versioning for EJS's `_version.py`), and those
generated sources themselves under `generated/`, bound to their recorded digests. It mirrors the engine
layout, so the commands above work from it with `--sources sources`. Prerequisites are an
arm64 Mac with Xcode (the receipt records the SDK and clang versions), `uv`, `perl` and
`make` from the OS.

## Limits

Prototype only. Integration needs parent review. Under the owner's capability decision
above, a public profile must also build `curl_cffi` impersonation from pinned source. The
static closure proof replays PyInstaller with the host `install_name_tool` and `codesign`
(recorded toolchain), and is separate from the runtime smoke. Bit-identical reproduction
is not claimed: output bytes depend on the Xcode toolchain and on the absolute build
directory, which pip's entry-point shebangs record in installed `RECORD` hashes. The prototype makes no claim about
the upstream producer's undisclosed build inputs and claims no equivalence with that
producer. Developer ID signing would need a reviewed adapter, because the existing
extractor preparation pins the upstream universal2 bootloader digest.
