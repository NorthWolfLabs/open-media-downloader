# Controlled-source yt-dlp with curl_cffi impersonation (macOS arm64)

This profile extends the controlled-source prototype in `distribution/yt-dlp-source` with the
capability the owner decided to keep on 2026-11-02
(`artifacts/public-extractor-capability-decision-20261102.json`): `curl_cffi` browser
impersonation, built from pinned sources with its whole native closure. Like the lean
profile it is an **unaccepted, unpromotable prototype**, ad-hoc signed only. It replaces
nothing: the lean profile, the legacy recipe (`distribution/yt-dlp`), the upstream
`yt-dlp_macos` producer and all existing evidence stay unchanged.

Everything the lean README (`distribution/yt-dlp-source/README.md`) says about CPython,
OpenSSL, the PyInstaller bootloader, the EJS bundle, the closure proof and the kit also
holds here. This file describes the additions.

## Profile

`profile.json` uses schema `omd-ytdlp-source-profile-v2`. It keeps every v1 section and adds
an explicit lock, source-built tools and the curl-impersonate recipe.

- **Explicit lock.** `pyproject.toml` pins `yt-dlp[default,curl-cffi,pin-curl-cffi]==2026.8.19`
  and `pyinstaller==6.22.0` for Python `==3.13.*`. `curl-cffi` is yt-dlp's own extra name;
  `pin-curl-cffi` is yt-dlp's own pin set (certifi 2026.7.22, cffi 2.1.1, curl-cffi 0.16.0,
  pycparser 3.0), the curl closure the upstream producer bundles. `uv.lock` was produced by
  `uv lock` from a copy of the legacy `distribution/yt-dlp/uv.lock`. Against that lock it
  only adds curl-cffi 0.16.0 and pins PyInstaller at 6.22.0 directly, so this profile needs
  no lock adjustment. Every other package keeps its legacy version and sdist hash. The
  legacy lock itself is unchanged and still pins PyInstaller 6.22.2.
- **New shipped sources:** the pycparser 3.0, cffi 2.1.1 and curl_cffi 0.16.0 sdists; the
  curl-impersonate v2.0.0 recipe archive (commit `ec41b71`, the version curl_cffi 0.16.0's
  `scripts/build.py` names); and the eight dependency archives its `CMakeLists.txt` pins by
  URL and SHA-256: BoringSSL `156c7b75`, curl 8.21.0, nghttp2 1.63.0, ngtcp2 1.20.0,
  nghttp3 1.15.0, brotli 1.2.0, zlib 1.3.1 and zstd 1.5.7.
- **New build tools** (not shipped): CMake 4.4.3 and Ninja 1.13.2, both compiled here from
  their official source archives, and the pure `wheel` 0.48.0 wheel that curl_cffi's
  `setup.py` imports. CMake's digest is the one in its official SHA-256 list. Ninja's tag
  archive was checked by recomputing its git tree. Both are the newest stable releases
  before the profile's 2026-08-27 build-tool cutoff.
- **Patches.** The recipe applies five patches (BoringSSL, brotli, curl, nghttp3, ngtcp2).
  The profile pins each by SHA-256, plus the unused `OpenBSD.patch`. No other patch file may
  be present.

No prebuilt `libcurl-impersonate` archive and no platform wheel is an input. The vendor
release archive and official wheels in the retained materials were used only for read-only
comparison.

## Recipe

1. CMake is bootstrapped (`./bootstrap --parallel=4 -- -DCMAKE_USE_OPENSSL=OFF
   -DBUILD_TESTING=OFF`). Ninja is then built from its `CMakeLists.txt` with that CMake.
2. The curl-impersonate superbuild follows its `Makefile` targets and the macOS arm64 job in
   `.github/workflows/build.yml`: `cmake -G Ninja`, build, install. Each pinned dependency
   archive is first copied by digest to the path ExternalProject downloads to. ExternalProject
   then finds it, verifies its `URL_HASH` and applies the pinned patch. Deviations from the
   upstream route:
   - a 13.5 deployment target instead of the CI's 11.0;
   - `SUBJOBS=4` with one top-level job;
   - a plain install instead of `install-strip`, which strips nothing for this recipe's install
     rules;
   - `CFLAGS`/`CXXFLAGS` set to `-ffile-prefix-map=<superbuild>/deps/src/=` and nothing
     else. BoringSSL compiles its source file names into its error records (`__FILE__`); the
     map records them relative to the dependency sources, so no build path is shipped. The
     upstream wheel carries its CI runner's absolute paths there instead.
3. The CI step "Create tar release files" is replayed: `libtool -static` merges
   `libcurl-impersonate.a` with the eleven dependency archives. The headers are copied next to
   it, as in the release tarball.
4. pycparser, cffi and then curl_cffi are built with `pip wheel --no-binary :all:` like every
   other package. curl_cffi gets two environment variables:
   - `IMPERSONATE_BUILD_DIR`, which points its `scripts/build.py` at the merged archive;
   - `LDFLAGS`, which links CoreFoundation, Security, SystemConfiguration, libiconv and
     libicucore explicitly, and passes `-Wl,-S`.

   The official wheel leaves those OS symbols to flat dynamic lookup. BoringSSL compiles
   itself with debug information, so without `-Wl,-S` the linker would write a debug map into
   the extension: about 520 stab entries naming the build directory and archive members.
   The vendor wheel carries the same map with its CI runner's paths. `-Wl,-S` omits the map;
   code and data are unchanged.

The CMake/Ninja builds, the superbuild, the merge check and the three wheel builds run under
`sandbox-exec` with all networking denied. So does the compile/link replay, so no build script
can fetch anything.

## Verification performed by `build`

In addition to everything the lean profile verifies:

- **Plan.** The pins are read from the immutable recipe archive: every dependency URL and
  `URL_HASH` must equal a pinned input, and so must every recipe file and patch. A recipe
  that adds, drops or re-pins a dependency or patch is refused.
- **Superbuild.** Each generated ExternalProject download script must point at the staged
  archive and its hash. Each patch must apply exactly: one `patching file` line per file
  section of the patch, with no offset, fuzz or rejection. Staged archives must be unchanged
  afterwards. `curl-impersonate -V` must report exactly the pinned component versions and
  feature set (HTTP2, HTTP3, brotli, zstd, libz, ECH, AppleSecTrust and the rest).
- **Release archive.** Its members must be exactly the members of the twelve recorded static
  archives, byte for byte. Each member must be a thin arm64 macOS object with a minimum no
  higher than 13.5.
- **curl_cffi extension.**
  - Its build log must show `scripts/build.py` finding the source-built archive; any
    download attempt is refused.
  - The two logged compiles (the cffi-generated `_wrapper.c` and the sdist `ffi/shim.c`)
    are replayed and must reproduce their objects. The logged link, replayed on those
    objects, must reproduce the packaged `_wrapper.abi3.so` byte for byte. The link must
    force-load the merged archive.
  - The extension may link exactly the seven profile OS libraries. Only Python C-API
    symbols may stay as dynamic lookups.
  - The generated `_wrapper.c` is recorded with its generator: the source-built cffi wheel,
    its `recompiler.py` and its license. Its inputs, `ffi/cdef.c` and `scripts/build.py`,
    are recorded too.
- **Runtime environment.** `curl_cffi.__curl_version__` must equal the pinned libcurl
  string.
- **Closure proof.** This is unchanged. `_cffi_backend` and `_wrapper.abi3.so` are proven
  like every other packed native, and the curl_cffi, cffi and pycparser modules like every
  other packed module. A packed source that is neither an sdist member nor a reviewed
  generated output now fails the build.
- **Runtime smoke.**
  - `--list-impersonate-targets` must list exactly the profile's 37 targets, all available
    through curl_cffi.
  - `-v` must list the four request handlers (`urllib`, `requests`, `websockets`,
    `curl_cffi`) and the expected optional libraries.
- **Loopback fixture** (`scripts/ytdlp_source_fixture.py`). The executable is run with
  `--impersonate` against a local TLS server, under a sandbox that allows only the loopback
  interface and the local resolver.
  - The server uses a throwaway CA. The client trusts it only through `SSL_CERT_FILE`, which
    curl_cffi documents as its CA override. Validation stays on.
  - Chrome (zstd), Firefox (brotli), Safari (gzip), Edge (deflate) and Tor (identity) must
    each:
    - negotiate HTTP/2;
    - send their ClientHello with SNI `localhost`;
    - fetch and decode the page;
    - extract the linked video.
  - Without the CA, and with a certificate for another name, the request must fail with
    curl error 60.

## Commands

From the engine root, with all caches and outputs on external storage:

```sh
P=distribution/yt-dlp-source-curl/profile.json
uv run scripts/build-ytdlp-source.py fetch --profile $P --output /new/sources --retained /retained/kit --report /new/fetch.json
uv run scripts/build-ytdlp-source.py plan --profile $P --sources /new/sources --plan /new/plan.json
uv run scripts/build-ytdlp-source.py build --plan /new/plan.json --sources /new/sources --output /new/build
uv run scripts/build-ytdlp-source.py kit --plan /new/plan.json --sources /new/sources --build /new/build --output /new/kit.tar.gz
uv run scripts/build-ytdlp-source.py verify-kit --kit /new/kit.tar.gz --sha256 HEX
uv run scripts/build-ytdlp-source.py split-kit --kit /new/kit.tar.gz --output /new/kit-parts
uv run scripts/build-ytdlp-source.py join-kit --parts /new/kit-parts --output /new/joined.tar.gz
uv run scripts/test-build-ytdlp-source.py
```

`fetch` also matches retained files by size and digest, because retained materials may name
an archive differently. A plan names its profile; `build` and `kit` follow the plan.

A recipient rebuilds from the kit alone. Join the parts if it arrived split, verify it,
extract it into a new directory, then run the kit's own scripts on the kit's own sources
from `omd-ytdlp-source-kit-v1/engine`:

```sh
K=/new/extracted/omd-ytdlp-source-kit-v1
uv run scripts/build-ytdlp-source.py plan --profile distribution/yt-dlp-source-curl/profile.json --sources $K/sources --plan /new/plan.json
uv run scripts/build-ytdlp-source.py build --plan /new/plan.json --sources $K/sources --output /new/build
uv run scripts/test-build-ytdlp-source.py
```

The new plan must equal `receipt/plan.json` in the kit.

## Kit

The kit holds everything the lean kit holds for this profile, plus:

- the five recipe patches under `patches/curl-impersonate/`, byte-identical archive members;
- the generated sources compiled or packed into the executable under `generated/`: curl_cffi's
  `_wrapper.c` and EJS's `_version.py`;
- the license files of the curl dependency archives (including BoringSSL's zip) and of the
  build tool whose template generated shipped source (vcs-versioning).

`verify-kit` checks every member against the index. Each generated-source, patch and terms
row must also name a delivered member under its own prefix, once, with the recorded digest.
A kit whose inventory was edited to drop those files is refused.

With all native sources it is larger than 256 MiB. In-app budgets are not raised.
`split-kit` writes companion-delivery parts of at most 256 MiB (128 MiB by default) with a
`PARTS.json` manifest. `join-kit` checks every part and the whole digest before
reassembling.

## Limits

- Prototype only; parent and independent review come first. Source and terms review,
  Developer ID signing, notarization and release acceptance are separate gates.
- arm64 only. Intel and Windows builds are future gates, not claimed.
- HTTP/3 is compiled in (curl reports `HTTP3`, and ngtcp2/nghttp3 are linked) but is not
  exercised: the fixture has no QUIC server.
- ClientHello and HTTP/2 observations come from a loopback fixture. They show the
  impersonation settings the binary sends. They are not proof of equality with real
  browsers. Where they are compared with the upstream producer, the evidence states it.
- Output bytes depend on the toolchain and the absolute build directory. On one host, a
  rebuild from the extracted kit in another directory reproduced every packed native
  (including `_wrapper.abi3.so`), CPython native, wheel and bootloader byte for byte. The
  executable still differed:
  - `_sysconfigdata` records the build path;
  - pip's entry-point shebangs change three `RECORD` hashes;
  - the PKG-derived UUID and the signature follow from those changes.

  The intermediate BoringSSL archives also record the build directory in their debug
  information, which `-Wl,-S` keeps out of the extension. Bit-identical rebuilds elsewhere
  are not claimed.
- No equivalence with the upstream producer binary is claimed. The producer runs Python
  3.14.6 and links its vendor `libcurl-impersonate` archive; this prototype runs CPython
  3.13.14 and links the archive built here.
