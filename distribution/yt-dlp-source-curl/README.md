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

- **Explicit lock.** `pyproject.toml` pins `yt-dlp[default,curl-cffi,pin-curl-cffi]==2026.10.26`
  and `pyinstaller==6.22.0` for Python `==3.13.*`. `curl-cffi` is yt-dlp's own extra name;
  `pin-curl-cffi` is yt-dlp's own pin set (certifi 2026.10.23, cffi 2.1.1, curl-cffi 0.17.0,
  pycparser 3.11), the curl closure the upstream producer bundles. `uv.lock` was produced by
  `uv lock` (uv 0.13.5) from a copy of the legacy `distribution/yt-dlp/uv.lock`. Against that
  lock it only adds curl-cffi 0.17.0 and pins PyInstaller at 6.22.0 directly, so this profile
  needs no lock adjustment. Every other package keeps its legacy version and sdist hash. The
  legacy lock pins PyInstaller 6.22.2.
- **yt-dlp 2026.10.26** is a security release: brotli 1.2.1 and curl-cffi 0.17.0
  (GHSA-9v8h-qqgm-4m35; curl-cffi 0.17.0 also completes the certifi fix GHSA-6q48-6c7w-9gw2).
  The changed sdists are yt-dlp 2026.10.26, brotli 1.2.1, certifi 2026.10.23, pycparser 3.11
  and curl_cffi 0.17.0, each pinned by its PyPI SHA-256 and size, equal to the lock.
- **New shipped sources:** the pycparser 3.11, cffi 2.1.1 and curl_cffi 0.17.0 sdists; the
  curl-impersonate v2.3.1 recipe archive (commit `98de20e`, the version curl_cffi 0.17.0's
  `scripts/build.py` names; its git tree was recomputed from the archive); and the nine
  dependency archives its `CMakeLists.txt` pins by URL and SHA-256: BoringSSL `156c7b75`,
  curl 8.23.0, c-ares 1.34.9, nghttp2 1.63.0, ngtcp2 1.20.0, nghttp3 1.15.0, brotli 1.2.1,
  zlib 1.3.1 and zstd 1.5.7. c-ares is new in this recipe (curl's resolver); brotli 1.2.1
  is the recipe's security update.
- **New build tools** (not shipped): CMake 4.4.3, Ninja 1.13.2 and pkgconf 3.0.6, all
  compiled here from their official source archives, and the pure `wheel` 0.48.0 wheel that
  curl_cffi's `setup.py` imports. CMake's digest is the one in its official SHA-256 list.
  Ninja's tag archive was checked by recomputing its git tree. pkgconf's release tarball from
  its official distfiles has the same digest as its GitHub release asset. All three are the
  newest stable releases before the profile's 2026-08-27 build-tool cutoff. The new sdists
  declare the same build backends as before, so the build-tool wheel set and cutoff are
  unchanged.
- **Patches.** The recipe applies five patches (BoringSSL, brotli, curl, nghttp3, ngtcp2).
  The profile pins each by SHA-256. No other patch file may be present (v2.3.1 no longer
  ships the unused `OpenBSD.patch`).

No prebuilt `libcurl-impersonate` archive and no platform wheel is an input. The vendor
release archive and official wheels in the retained materials were used only for read-only
comparison.

## Recipe

1. CMake is bootstrapped (`./bootstrap --parallel=4 -- -DCMAKE_USE_OPENSSL=OFF
   -DBUILD_TESTING=OFF`). Ninja is then built from its `CMakeLists.txt` with that CMake.
   pkgconf is built with its shipped `configure` (`--prefix=<tools>/pkgconf --disable-shared
   --enable-static --with-system-libdir=/usr/lib --with-system-includedir=/usr/include`,
   `make`, `make install`). As its README leaves to the installer, a recorded step adds the
   `pkg-config` symlink to `pkgconf` in that private prefix.
2. The curl-impersonate superbuild follows its `Makefile` targets and the macOS arm64 job in
   `.github/workflows/build.yml`: `cmake -G Ninja`, build, install. Each pinned dependency
   archive is first copied by digest to the path ExternalProject downloads to. ExternalProject
   then finds it, verifies its `URL_HASH` and applies the pinned patch. Deviations from the
   upstream route:
   - a 13.5 deployment target instead of the CI's 11.0;
   - `SUBJOBS=4` with one top-level job;
   - `CURL_IMPERSONATE_VERSION=2.3.1` passed explicitly. The CI derives the same value with
     git from its v2.3.1 tag checkout; an archive build has no git metadata;
   - a plain install instead of `install-strip`. The release archive is merged from the build
     archives, as in the CI, so stripping the install would change nothing that ships;
   - `CFLAGS`/`CXXFLAGS` set to `-ffile-prefix-map=<superbuild>/deps/src/=` and nothing
     else. BoringSSL compiles its source file names into its error records (`__FILE__`); the
     map records them relative to the dependency sources, so no build path is shipped. The
     upstream wheel carries its CI runner's absolute paths there instead.

   pkg-config is not on the superbuild's `PATH`. The recipe's builds do not use it (curl is
   configured with `CURL_USE_PKGCONFIG=OFF`), so only CMake and Ninja are visible.
3. The macOS part of the CI step "Create tar release files" is replayed:
   - `cmake -P cmake/ReleasePkgConfig.cmake` resolves curl's generated `libcurl.pc` against
     the dependency `.pc` files with `pkg-config --static`. It drops the bundled archives
     and writes `libcurl-impersonate.pc` beside the release archive from the recipe's
     `cmake/libcurl-impersonate.pc.in`. The source-built pkg-config is passed as
     `PKG_CONFIG` and is the only one on `PATH`; the CI uses Homebrew's pkg-config, which is
     pkgconf.
   - `libtool -static` merges `libcurl-impersonate.a` with the twelve dependency archives
     (now including c-ares). The headers are copied next to it, as in the release tarball.
   - The license collection (`CollectLicenses.cmake`) is not run: the kit carries every
     archive and its license files.
4. pycparser, cffi and then curl_cffi are built with `pip wheel --no-binary :all:` like every
   other package. curl_cffi gets:
   - `IMPERSONATE_BUILD_DIR`, which points its `scripts/build.py` at the release directory;
   - the source-built pkg-config directory on `PATH`. Since 0.17.0, `scripts/build.py` runs
     `pkg-config --static --libs libcurl-impersonate` on the release `.pc` file and adds the
     resulting OS framework and library flags after `-Wl,-force_load,<archive>`;
   - `LDFLAGS=-Wl,-S` and nothing else. The OS frameworks and libraries (Security,
     CoreFoundation, CoreServices, libresolv, libc++, libicucore, libiconv) now come from the
     release `.pc` file, as in the upstream build. curl_cffi 0.16.0 left them to flat dynamic
     lookup, so the previous profile had to name them in `LDFLAGS`. With c-ares as curl's
     resolver the merged archive no longer references SystemConfiguration, which is no
     longer linked.

   BoringSSL compiles itself with debug information, so without `-Wl,-S` the linker would
   write a debug map into the extension: about 520 stab entries naming the build directory
   and archive members. The vendor wheel carries the same map with its CI runner's paths.
   `-Wl,-S` omits the map; code and data are unchanged.

The CMake/Ninja/pkgconf builds, the superbuild, the release pkg-config step, the merge check
and the three wheel builds run under `sandbox-exec` with all networking denied. So does the
compile/link replay, so no build script can fetch anything.

### Why a source-built pkgconf

curl_cffi 0.17.0 refuses to link the static archive without `libcurl-impersonate.pc` and a
`pkg-config` program ("Use the complete curl-impersonate 2.3.0 or newer release archive"),
and the v2.3.1 recipe writes that file with pkg-config. macOS has no pkg-config, and the
build resets `PATH`. A host or Homebrew pkg-config would be an unpinned prebuilt binary, and
a hand-written `.pc` file would replace the recipe's own release step. pkgconf is what the
upstream CI actually runs, it is small, and its official release tarball builds offline with
the host compiler. Like CMake and Ninja it is a recorded build tool and ships nothing. Its
output is checked twice: the `.pc` file must equal the pinned template with the expected
values, and the extension link must contain exactly the flags it resolves.

## Verification performed by `build`

In addition to everything the lean profile verifies:

- **Plan.** The pins are read from the immutable recipe archive: every dependency URL and
  `URL_HASH` must equal a pinned input, and so must every recipe file and patch. A recipe
  that adds, drops or re-pins a dependency or patch is refused. The profile may expose
  pkg-config only as a recorded symlink of a source-built tool, and the expected
  `Libs.private` may name only `-framework NAME` and `-lNAME` OS entries: no search path,
  file path or bundled archive.
- **Tools.** Each tool product must be a thin arm64 executable that links only OS libraries
  and reports its pinned version. The `pkg-config` link must be a symlink to exactly the
  verified `pkgconf` product and report the same version.
- **Superbuild.** Each generated ExternalProject download script must point at the staged
  archive and its hash. Each patch must apply exactly: one `patching file` line per file
  section of the patch, with no offset, fuzz or rejection. Staged archives must be unchanged
  afterwards. `curl-impersonate -V` must report exactly the pinned component versions and
  feature set (HTTP2, HTTP3, brotli, zstd, libz, ECH, AppleSecTrust and the rest).
- **Release archive.** Its members must be exactly the members of the thirteen recorded
  static archives, byte for byte. Each member must be a thin arm64 macOS object with a
  minimum no higher than 13.5.
- **Release pkg-config file.** `libcurl-impersonate.pc` must equal the pinned
  `cmake/libcurl-impersonate.pc.in` configured with the pinned curl version and the
  profile's expected `Libs.private`, byte for byte: a relocatable `${pcfiledir}` prefix,
  `-lcurl-impersonate`, no build path. The release directory may hold only the archive, this
  file and the headers. `pkg-config --static --libs libcurl-impersonate` is then run on it
  the way `scripts/build.py` runs it, and must resolve exactly the release directory, the
  archive name and those OS flags.
- **curl_cffi extension.**
  - Its build log must show `scripts/build.py` finding the source-built archive; any
    download attempt, a missing `.pc` file and a missing pkg-config are refused.
  - The two logged compiles (the cffi-generated `_wrapper.c` and the sdist `ffi/shim.c`)
    are replayed and must reproduce their objects. The logged link, replayed on those
    objects, must reproduce the packaged `_wrapper.abi3.so` byte for byte. The link must
    force-load the merged archive, directly followed by exactly the resolved pkg-config
    flags. The `.pc` file and archive must be unchanged at link time.
  - The extension may link exactly the eight profile OS libraries, the same set in the same
    order as the official 0.17.0 macOS arm64 wheel (compared read-only). CoreServices and
    libresolv come from the `.pc` file and have no bound symbols. Only Python C-API symbols
    may stay as dynamic lookups.
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
  - `--list-impersonate-targets` must list exactly the profile's 47
    targets, all available through curl_cffi.
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
