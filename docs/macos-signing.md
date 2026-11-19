# macOS signing preparation

`scripts/sign-macos.py` prepares a staged, plugin-free reference app for signing in
two explicit steps. `inspect` is read-only and writes a new plan. `execute` repeats
that inspection, refuses any difference from the reviewed plan and signs a new
independent copy. The input app, prior reviews and receipts are never modified.
Nothing here notarizes, reads credentials or accepts a release: every plan and
report records `release_accepted: false`.

## Commands

From the engine root (UV supplies the pinned PyInstaller 6.22.0 inspection reader):

```sh
uv run scripts/sign-macos.py inspect --app /abs/OMD.app --mode development-adhoc --identity - \
  [--purpose distribution-candidate] [--materials-binding single-phase|two-phase] \
  --plan /abs/new/plan.json [--expected-inventory /abs/app-inventory.json] \
  [--receipts /abs/receipts.json] [--prepared-extractor /abs/yt-dlp_macos \
   --prepared-extractor-sha256 HEX --prepared-extractor-version 2026.08.19 --prepared-extractor-arch arm64 \
   [--prepared-extractor-report /abs/work/extractor-report.json --prepared-extractor-report-sha256 HEX
    [--prepared-extractor-source-evidence /abs/source-evidence.json --prepared-extractor-source-evidence-sha256 HEX
     --prepared-extractor-source-kit /abs/source-kit.tar.gz --prepared-extractor-source-bootloader /abs/run]]]
uv run scripts/sign-macos.py execute --plan /abs/new/plan.json --output /abs/new/OMD.app --work /abs/new/work \
  [--purpose distribution-candidate|private-validation] [--materials-binding two-phase] [--allow-incomplete-development]
uv run scripts/test-sign-macos.py
```

Modes: `development-adhoc` takes identity `-` and no Team ID; it is a structural
rehearsal and never distributable. `developer-id` takes `Developer ID Application:
NAME (TEAMID)` or a SHA-1 certificate hash plus a matching `--team-id`; other
certificate kinds and ad-hoc identities are rejected. Only `developer-id` accepts
`--purpose private-validation` ([below](#private-validation-purpose)). Inspect exits 0 without
blockers, 2 with a plan containing blockers and 1 for invalid input (no plan).
Execute exits 0 only for a signed candidate, 2 for an incomplete development
rehearsal, an incomplete private validation or a two-phase output awaiting its final
materials binding, 3 for a complete private validation (never a candidate) and 1 when
refused, blocked or failed.

## Reviewed code roles

The fixed `distribution/macos-signing-policy.json` binds every Mach-O to an exact
logical path; basenames and producer signatures grant nothing. Unrecognized code
stops execution. Only two reviewed entitlement keys may ever be granted; library
validation, executable page protection, DYLD variables and get-task-allow are
forbidden. Libraries get no entitlements and no runtime flag.

| Role | Path under `resources/v2` | Entitlements | Basis |
| --- | --- | --- | --- |
| desktop shell | `Contents/MacOS/<executable>` (outer seal) | none | Tauri: hardened runtime, no entitlements; WebKit JIT is out of process |
| engine, CLI, guardian, notifier | `bin/…` | none | No JIT; guardian launches system `sandbox-exec` |
| plugin worker | `bin/omd-plugin-worker-v2` | allow-unsigned-executable-memory | Wasmtime 45.0.3 publishes code with `mprotect` without `MAP_JIT` |
| Node | `tools/node/node` | allow-jit | V8 `MAP_JIT` |
| ffmpeg, ffprobe | `tools/…` | none | No JIT |
| headless browser | `browser/content/browser/chrome-headless-shell` | allow-jit | Chromium 153 renderer/GPU helper entitlements |
| browser libraries | four exact `browser/content/browser/*.dylib` | none (library) | Loaded with `dlopen`; must share the host Team ID |
| yt-dlp | `tools/yt_dlp/yt-dlp_macos` | none | PyInstaller onefile; see below |

An ad-hoc hardened-runtime probe of the actual release worker and Node 24.20.0
confirmed this: the worker is killed when executing provider code with no
entitlement or with allow-jit only, and runs with allow-unsigned-executable-memory;
Node aborts without allow-jit and runs JS and WebAssembly with it. Compile-only
worker checks pass in every variant, so they cannot validate this policy.

## Inspection

Inspection rejects symlinks anywhere (including path ancestors), special files,
hard links, unsafe or case/normalization-colliding names, unexpected bundle
members, plugin packages (`OMDP2` framing or `providers/`), inventory or manifest
drift, misplaced managed tools, wrong Mach-O type, missing architecture slices
and missing release-worker markers. It reuses `check-macos-payload.py` for the
whole-payload macOS minimum, the shared path primitives and the native receipt
validator. `--expected-inventory` additionally requires exact whole-app identity.

The plan lists every code object with its role, order (libraries, executables,
then the outer bundle), identifier, entitlements, architectures, minimum, source
identity and producer signature. Producer signatures are retained provenance only:
for example Node's Developer ID signature carries get-task-allow and disabled
library validation, so it is replaced. Source identities stay bound by materials
and provenance; payload identities are what manifests, inventories and fresh
receipts bind after signing.

`signature_independent_sha256` (layout `omd-macho-signature-layout-v2`) covers every
byte except each slice's code signature, three signature-dependent fields and FAT
slice placement. It digests the FAT magic and each architecture's CPU type, subtype
and reserved field, and every slice byte before its signature, including
PyInstaller archives and padding inside `__LINKEDIT`. LC_CODE_SIGNATURE `datasize`
and `__LINKEDIT` `filesize` are excluded only after proving the signature ends its
slice and `__LINKEDIT` ends exactly at it. FAT offsets, sizes and alignments may
move (codesign relocates slices to 16K alignment), but every unassigned byte must be
zero; nonzero padding, bytes after the last slice or after a thin signature fail
closed. Execution claims `signature_only_change` only from a paired before/after
check: equal digests, every input slice already signed (adding a signature rewrites
load commands) and a `__LINKEDIT` `vmsize` that keeps its value or becomes the
page-rounded new file size. Code to be signed whose layout fails these rules gets
an `unsupported-code-layout` signing blocker.

## Packed extractor

The current yt-dlp has 103 packed native members, all ad-hoc without a Team ID.
Hardened-runtime library validation rejects them under a Developer ID outer
signature, and re-signing the bootloader cannot change them. Library validation
is never disabled and this signer never edits packed tools; the separate
[preparation step](#preparing-the-extractor) re-signs them. Without a prepared
extractor, Developer ID inspection blocks; development rehearsals retain the
producer bytes unchanged. A prepared extractor is accepted only for its exact
requested digest, the reviewed managed version, the requested architecture, a
readable CArchive, an acceptable macOS minimum and every native member passing
cryptographic verification. The producer's packed summary is parsed metadata only.

Inspection copies the digest-checked bytes into a private temporary directory
(under `TMPDIR`), reparses the raw CArchive table of contents and rejects duplicate
or case/normalization-colliding names, unsafe paths, unknown or dependency (`d`)
entries, members beneath another member or link, and links that escape, dangle or
cycle. Links are resolved lexically and never created. Each Mach-O member is then
written alone as a non-executable `0600` file, within a 1 GiB total budget, checked
with `codesign --verify --strict --all-architectures` and deleted. Developer ID mode
adds `--test-requirement` for a Developer ID Application leaf under Apple's
Developer ID CA with `subject.OU` equal to the Team ID. Parsed Team IDs or CMS
presence are never sufficient. Members are never executed; code inside other
containers or written at runtime is left to runtime library validation; trust is
evaluated locally at inspection time without revocation or notarization status.
The extractor is installed at the role path and signed; its own source and
materials review remains a separate gate. With `--prepared-extractor-report`, the
report must bind the app's exact producer, the prepared digest, version, mode and
Team ID, and inspection repeats the structural proof below from the app's own
producer bytes (the report only binds identities). Without it, behavior is unchanged.
The four `--prepared-extractor-source-*` options select the
[controlled-source route](#controlled-source-producer-route) for that proof.

## Preparing the extractor

`scripts/prepare-macos-extractor.py` makes such an extractor from the exact producer
by a signature-only transformation, not a rebuild. It supports only PyInstaller
6.22.0 macOS onefiles built on the stock universal2 `run` bootloader (pinned by
digest), as `universal2`, `arm64` or `x86_64` targets:

```sh
uv run scripts/prepare-macos-extractor.py inspect --producer /abs/yt-dlp_macos --producer-sha256 HEX \
  --version 2026.08.19 --target-arch universal2 --mode development-adhoc --identity - --plan /abs/new/plan.json
uv run scripts/prepare-macos-extractor.py execute --plan /abs/new/plan.json --output /abs/new/yt-dlp_macos --work /abs/new/work
uv run scripts/prepare-macos-extractor.py verify --producer … --producer-sha256 HEX --prepared … --prepared-sha256 HEX \
  --version 2026.08.19 --target-arch universal2 --mode development-adhoc --output /abs/new/verification.json
uv run scripts/test-prepare-macos-extractor.py
```

`inspect` (exit 0 ready, 2 blockers, 1 refused) checks the digest and reads the
version constants of the PYZ `yt_dlp.version` module statically. It requires
contiguous entries, a TOC equal to the pinned writer's serialization, a rebuilt
PKG byte-identical to the producer's, the cookie as the file's last archive magic
(the bootloader scans back to front), a string table ending at the PKG, zero
padding before the signature and per-slice UUIDs equal to PyInstaller's
`SHA-1(PKG + stock UUID)[:16]`. Raw TOC, name and link validation is reused from
the signer. Mach-O content must be exactly the `b` entries: signed dylibs or
bundles with one identifier, no entitlements and every target architecture. Every
producer member must pass `codesign --verify`, and level-9 streaming zlib must
reproduce each compressed native stream, or the plan has blockers.

`execute` re-derives the plan; the plan, output and work directory must be new and
outside the producer's directory. It first rebuilds the producer from the stock
bootloader and its own PKG with PyInstaller's macOS EXE steps (thin conversion,
signature removal, `update_exe_identifier`, append, `fix_exe_for_code_signing`,
SDK rule, sign), which must equal the producer outside its signature. Each native
member is then written alone as a private file and signed with its identifier,
no entitlements and no runtime flag (`--timestamp` for Developer ID), then verified
with the existing `verify_object` checks: strict verification, mode/Team, no
entitlements, the paired signature-only check and, for Developer ID, the Team
requirement and a secure timestamp. Other members keep their stored bytes. The
same steps assemble the candidate, which must pass a static proof against the
producer: bootloader bytes identical outside the PKG-derived fields, non-native
stored bytes identical, natives signature-only. Every member and the outer
executable must also verify cryptographically. Only then is a new `0755` output
written. Failures keep the work directory and a `failed` report. If failure occurs
after output creation, cleanup checks the path against a retained descriptor for
the created inode before removing it (`output_removed`). A replacement at that
path is retained. Cleanup errors are recorded as `cleanup_failure` without
suppressing the original failure report; an output retained after failure is not
an accepted candidate.
Members are never executed.

Ad-hoc candidates are structural and runtime evidence only, never Developer ID-ready.
For Developer ID, inspect and execute with `--mode developer-id` and the operator
identity and Team ID, then pass the output and report to `sign-macos.py inspect`.
Corresponding-source and materials review of the producer stay separate gates.

## Controlled-source producer route

The thin arm64 yt-dlp built by `scripts/build-ytdlp-source.py` from
`distribution/yt-dlp-source-curl/profile.json` runs on a `run` bootloader compiled from the
PyInstaller 6.22.0 sdist, so the stock route above refuses it. A separate route
(`scripts/macos_extractor_source.py`, method
`omd-pyinstaller-6.22.0-source-bootloader-onefile-signature-only-v1`) handles exactly that
producer. It is selected only when all four `--source-*` options are given. The two routes
never fall back to each other, and a plan or report cannot move between them.

```sh
src=(--source-evidence /abs/source-evidence.json --source-evidence-sha256 HEX \
     --source-kit /abs/source-kit.tar.gz --source-bootloader /abs/run)
uv run scripts/prepare-macos-extractor.py inspect --producer /abs/omd-yt-dlp --producer-sha256 HEX --version 2026.08.19 \
  --target-arch arm64 --mode development-adhoc --identity - --plan /abs/new/plan.json $src
uv run scripts/prepare-macos-extractor.py execute --plan /abs/new/plan.json --output /abs/new/omd-yt-dlp --work /abs/new/work
uv run scripts/prepare-macos-extractor.py verify --producer … --producer-sha256 HEX --prepared … --prepared-sha256 HEX \
  --version 2026.08.19 --target-arch arm64 --mode development-adhoc --output /abs/new/verification.json $src
uv run scripts/test-prepare-macos-extractor-source.py
```

The review root is an operator-reviewed evidence file, bound by its SHA-256 on the command
line. It holds digests only, no paths; unknown or missing fields are refused:

```json
{"schema": "omd-macos-extractor-source-evidence-v1", "route": "controlled-source",
 "profile": {"file": "distribution/yt-dlp-source-curl/profile.json", "id": "PROFILE-ID", "sha256": "HEX"},
 "kit": {"bytes": 0, "sha256": "HEX"}, "plan_sha256": "HEX", "receipt_sha256": "HEX",
 "producer": {"bytes": 0, "sha256": "HEX"}, "bootloader": {"bytes": 0, "sha256": "HEX"},
 "version": "2026.08.19", "target_arch": "arm64", "release_accepted": false}
```

Take the kit digest from the reviewed kit record and read the plan and receipt digests
from that kit's `KIT-INDEX.json`. Review the bootloader digest against the receipt. Only
`arm64` is supported, and the stock bootloader digest is refused. The plan, output and work
directory must lie outside the producer, evidence, kit and bootloader directories.

Every `inspect`, `execute` and `verify` re-derives the following from private copies of
the supplied bytes:

- The evidence, kit, producer and bootloader equal the reviewed digests. The kit passes the
  recipient verifier (`ytdlp_source.verify_kit`), and its profile equals the repository's
  pinned profile. Its plan and receipt are the ones named by the evidence; they bind each
  other, the profile and the arm64 13.5 target, and record this producer as the
  repeatable output.
- The receipt describes exactly these producer bytes: the CArchive layout, every member in
  order (type and expanded digest), every packed native (digest and signing identifier) and
  the outer onefile policy. That policy is recomputed with the builder's `onefile_policy`.
- The compiled bootloader equals the receipt's compiled `run` and the copy in the
  source-built PyInstaller wheel. It is a strict thin arm64 executable: only allowlisted
  load commands, a verifying ad-hoc linker signature, the recorded system libraries and the
  profile minimum.
- The running PyInstaller files whose functions are replayed (`archive/writers.py`,
  `building/api.py`, `utils/osx.py` and every other file the receipt pins) equal the
  digests the build recorded.
- The transformation is the stock route's, unchanged. The pinned steps replayed on the
  compiled bootloader and the producer PKG must reproduce the producer outside its
  signature. Each native is re-signed alone and proven signature-only, and every other
  member keeps its stored bytes. Both analyses must pass the full layout rules and the
  outer comparison, and every member and the outer file must pass `codesign`
  verification. The prepared outer file must still be the onefile assembly of the same
  bootloader, with unchanged architecture, minimum and SDK and no entitlements.

Some facts remain build and review evidence and are not re-derived here: compilation of
the bootloader, natives and code from the kit's sources (the receipt's closure proof and a
separate recipient rebuild), the sufficiency of sources and terms, and runtime capability.
Receipt statements such as `built` or `identical` are only checked for consistency with
these bytes; they never replace a byte check.

`sign-macos.py inspect` takes this route with `--prepared-extractor-report` plus
`--prepared-extractor-source-evidence`, `--prepared-extractor-source-evidence-sha256`,
`--prepared-extractor-source-kit` and `--prepared-extractor-source-bootloader`, all
together. The report must come from this route and name the same evidence. A stock report
is never relabelled, and a source report never passes without its evidence. The proof is
repeated from the app's own producer bytes. Developer ID inspection still requires every
packed native to satisfy the same-Team Developer ID requirement; roles, entitlements and
other checks are unchanged.

Limits: ad-hoc preparation of the reviewed source producer reproduces it byte for byte.
The build already ad-hoc signed every native and the outer file with codesign's default
16 KiB pages, and ad-hoc signing is deterministic; only a Developer ID run changes the
signatures. `bind-final-materials.py` still refuses this route under its default
`omd-final-materials-v1`, whose relation and desktop mirror pin the stock method.
`--contract omd-final-materials-v2` binds it
([materials contract](materials-contract.md#final-materials-v2-controlled-source-extractor-route-omd-final-materials-v2)).
That requires the preparation report and the same four source inputs, and the binder
repeats this proof from the input app's producer bytes with the Team requirement on every
packed member. The next steps, after review, are a Developer ID preparation (`--mode
developer-id` with the operator identity and Team) checked against the same-Team
requirement, then a two-phase signing of a release-staged app that installs it.

## Receipts

Signing changes executable bytes, so existing native receipts become stale. With
`--receipts`, inspection runs the existing generator on the input bytes and
compares each prior review scope, including the staged artifact identities; any
difference blocks carry-forward. Artifact-only rebinding is permitted only after
the signing transformation proves equivalence to that exact input. Execution:

1. signs nested code, then regenerates the engine receipt from signed bytes;
2. carries findings only through an explicit artifact-only rebinding record and a
   new copy of the prior review directory, then validates and installs it;
3. rewrites `tools-v2.json`, `browser-tools-v2.json` and `build-inventory.json`
   (with a `signing` record) to post-signature digests, then seals the bundle;
4. binds the sealed desktop executable in a detached receipt in the work
   directory, never inside the app, and checks its text spans are in the app.

```json
{"schema": "omd-macos-signing-receipts-v1", "target": "aarch64-apple-darwin", "version": "0.2.0",
 "engine": {"manifest": "/abs/engine/Cargo.toml", "roots": ["…"], "binaries": ["omd", "omd-engine", "omd-helper-guardian", "omd-notify", "omd-plugin-worker-v2", "omd-signin"],
            "features": "", "upstream_materials": "/abs/engine-upstream.json", "review": "/abs/review-base/engine-review.json"},
 "desktop": {"manifest": "/abs/desktop/src-tauri/Cargo.toml", "roots": ["open-media-downloader-desktop"], "binaries": ["open-media-downloader-desktop"],
             "features": "v2,tauri/custom-protocol", "upstream_materials": "/abs/desktop-upstream.json", "review": "/abs/review-base/desktop-review.json"}}
```

The engine receipt must select exactly the bundled engine binaries. The desktop
scope recursively includes legal texts staged under `src-tauri/resources/v2`, so
its manifest must be the exact build source (a byte-identical copy is fine), not
a checkout holding different staged resources. Without fresh reviewed receipts,
an opted-in development rehearsal removes the stale receipt from the output,
preserves it under `work/stale/` and reports `incomplete-development`; otherwise
a receipt failure during execution reports `blocked`. Engine receipt failures
occur before sealing; detached desktop receipt failures can occur after sealing.

Developer ID mode stops on any blocker. It also refuses development-staged
resources and release-staged materials whose manifest binds pre-signature payload
digests; this tool never rewrites reviewed materials.

## Two-phase materials binding

`--materials-binding two-phase` is an explicit opt-in that applies only to Developer ID
`distribution-candidate` signing (`single-phase` stays the default). It must be repeated
at execute. It downgrades exactly one blocker, `materials-bind-pre-signature`, to `release`
with a `final_binding` record. That requires release staging whose build inventory records
validated two-phase materials (deferring only `desktop-rust` and `frontend`). It also
requires an in-app complete `omd-materials-v1` manifest; otherwise the blocker keeps
`signing` severity and names the reason. No purpose exemption is involved: every other
blocker, every execution check and every receipt gap still stops or fails the run.

A successful run reports `signed-awaiting-final-materials` (exit 2) with
`distribution_candidate: false`. The sealed build inventory signing record carries
`materials_binding: two-phase`. The in-app manifest is left unchanged as the initial
review. The output becomes a coverage-validated distribution candidate only through
[`bind-final-materials.py`](materials-contract.md#final-materials-binding-two-phase-omd-final-materials-v1).
That binder independently re-derives every signing relation from bytes and refuses
private-validation output.

## Private validation purpose

Every plan records a `purpose`. The default, `distribution-candidate`, keeps all of
the behavior above and is the only purpose that can produce a candidate.
`--purpose private-validation` is an explicit opt-in for Developer ID mode only. It
signs a real same-Team hardened copy for local runtime checks while release
materials are not ready. Inspection downgrades only these release-material blockers
from `signing` to `release`, adding a `purpose_tolerance` record to each:
`development-staging`, `materials-bind-pre-signature`, `receipts-not-configured`,
`engine-receipt-missing`, `engine-receipt-binary-set`, `engine-receipt-selection`,
`desktop-receipt-selection`, `receipt-version`, `engine-review-scope` and
`desktop-review-scope`. Identity and Team checks, unrecognized code, roles and
entitlements, code layouts, the payload minimum and prepared-extractor problems
keep their `signing` severity. Unsafe paths and invalid input still refuse.

Execution requires the same `--purpose` again: a private plan never runs by
default, and a candidate plan cannot be re-labelled private (re-inspection must
reproduce it exactly). Every execution check is unchanged: strict verification,
Developer ID authority, Team, secure timestamp, entitlements, paired
signature-only changes, the prepared extractor and the embedded version check.
Any such failure reports `failed`, even after sealing. Receipt gaps are handled
like an incomplete rehearsal: a stale engine receipt is removed from the output
and preserved under `work/stale/`, and an ungenerated or blocked desktop receipt
is recorded.

The result is `private-validation-signed` (exit 3) when everything passed, or
`private-validation-incomplete` (exit 2) when a receipt gap remains. The report
records `purpose`, `distribution_candidate: false`, the tolerated gaps and
`suitable_for_public_distribution: false`; the build inventory signing record
also carries the purpose. Every record keeps `release_accepted: false`. Never
notarize, publish or give users such a copy. Use a distinct bundle identifier so
runtime checks cannot share an owner profile. Plans written before purposes
existed must be re-inspected.

## Outputs, notarization and limits

The work directory holds the executed plan copy, entitlements files, receipt
preparations, rebinding records and `signing-report.json` with every command,
exit status, output tail, per-object source and payload identities, and failures.
Failed runs retain their partial output and report `failed`. A failure in a
detached receipt or final verification can leave a sealed output; the presence of
a seal alone never establishes a successful run.

Notarization is a separate operator operation on a bound Developer ID candidate, for
example `xcrun notarytool submit --keychain-profile PROFILE` and `xcrun stapler staple` on a
copy, using an operator-managed keychain profile. This tool stores no credentials. Stapling
adds `Contents/CodeResources`, which the final materials binding correctly refuses. The
stapled app is bound by the detached
[notarized materials envelope](materials-contract.md#notarized-materials-envelope-omd-notarized-materials-v1).
It re-runs the unchanged binder on the pre-staple app, then verifies the stapled app with
actual codesign, `stapler validate` and Gatekeeper checks. It never signs, staples or submits.

Tests compile small fixtures and sign only temporary copies ad-hoc, exercising
the real generator and validators with synthetic Cargo metadata. Packed-member
tests cover corrupted ad-hoc code and corrupted code whose forged metadata claims a
Team ID and CMS blob; the Developer ID success path is canned there. Extractor
preparation tests assemble genuine PyInstaller 6.22.0 fixtures with its own writers
and macOS steps. Their Developer ID case records the requested commands, signs
ad-hoc instead and shows the genuine checks refusing the result. Controlled-source tests
do the same on a compiled thin bootloader fixture, with generated kits, receipts and
evidence that pass the real recipient verifier. Separate
evidence verified a private copy of the producer Node's genuine Developer ID
signature against its own Team requirement (and rejected another Team and a
corrupted copy). Purpose tests drive execution with a canned Developer ID runner
(ad-hoc substitutes) to show status, binding and failure handling; they are not
signature evidence. Real Developer ID signing with secure timestamps is recorded
separately for a private-validation copy; that maintainer evidence is not part of
the public source.
Notarization tests are separate (`test-notarized-materials.py`); quarantine and pristine-account installation are not exercised. Ad-hoc hardened processes cannot load ad-hoc libraries, so
development rehearsals do not represent browser or extractor runtime behavior.
Code inside `Contents/Resources` follows the current Tauri resource layout and is
sealed as resource data; notarization acceptance of that layout remains unverified.

Sources: Apple [hardened runtime](https://developer.apple.com/documentation/security/hardened-runtime),
[allow-jit](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit),
[allow-unsigned-executable-memory](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-unsigned-executable-memory),
[library validation](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.disable-library-validation),
[TN3127 code signing requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements),
[requirement language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html),
`codesign(1)` (`--test-requirement`, literal `=` requirements), the SDK `mach-o/loader.h` and `mach-o/fat.h` layouts,
[distribution signing](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac),
[notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues);
[PyInstaller code signing](https://pyinstaller.org/en/stable/feature-notes.html);
[Tauri macOS configuration](https://v2.tauri.app/reference/config/).
