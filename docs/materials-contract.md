# Release material preparation (v1)

This tooling prepares evidence. It does not determine legal compliance. First-party
source is MIT; retained third-party texts keep their original terms. Missing or
ambiguous materials are release failures, including when metadata has an SPDX ID.

## Native notices

Run `uv run scripts/generate-native-notices.py` with an absolute `--manifest`,
`--target` Rust triple, repeated `--root` Cargo package names, repeated `--binary`
names, optional `--features`, and a new external `--output`. Bind executables with
repeated `--artifact NAME=FILE`. Roots must own the selected binary targets.
For standalone select omd-cli, omd-service, omd-mcp, omd-plugin-worker-v2,
omd-isolation, omd-notifications and omd-signin; binaries are omd, omd-engine,
omd-mcp, omd-plugin-worker-v2, omd-helper-guardian, omd-notify and omd-signin.
Receipts name binaries; their installed paths are `bin/NAME` (`bin/NAME.exe` on
Windows), except that macOS installs the sign-in window as an app bundle. There its
artifact is the bundle executable `bin/OMD Sign-In.app/Contents/MacOS/omd-signin`.
For desktop select open-media-downloader-desktop with features v2 in its
independent native manifest.

The target-filtered locked Cargo metadata traversal retains full named license,
COPYING, copyright, NOTICE and AUTHORS files recursively, and SQLite amalgamations
with their embedded dedication. First-party packages inherit the root MIT text.
The graph includes build/dev edges and workspace-unified features: this is a
conservative overapproximation, not an exact minimal shipped graph. The receipt
records roots, binary ownership, target, features, lock digest and artifact hashes.
No host source paths are serialized. Full texts are never rewritten for sanitization.
`native-NOTICES.txt` concatenates the complete retained texts. Each receipt entry
records its byte offset, size and hash inside that asset. Duplicate executable
declarations/bindings are rejected; a partial binding remains explicitly pending.

Receipts use schema `omd-native-notices-v2`. Each output also has
`review-scope.json`: the exact scope a review must restate.

Exit 2 means a receipt was produced with explicit pending coverage; it is not
release-ready. Missing packaged texts and native/embedded applicability reviews
remain pending. Exact-version upstream additions use `--upstream-materials FILE`:
a JSON array of name, version, file (relative to that external JSON), sha256,
revision (40 hex), and immutable upstream URL. The preparer verifies supplied
bytes; reviewers must verify the revision against crate VCS/release provenance.
A supplied text still requires applicability review. It never clears review
merely by seeing a license string. Preserve source retrieval reports externally.

## Native review evidence (omd-native-review-v1)

`--review-evidence FILE` ingests factual findings for one exact preparation. All
paths in it are portable paths relative to that file's directory. Symlinks,
traversal, absolute or drive paths, duplicate JSON keys, unknown fields and
machine-local strings are rejected. Validation finishes before any output exists.

`scope` must equal that run's `review-scope.json`: target, full verbose rustc
output, Cargo.lock digest, requested/default features, roots, binaries and owners,
artifact names/sizes/hashes, and every package's name, version, source,
features and pre-review retained text descriptors (including upstream digest,
revision and URL). The scope is frozen before review materials are appended.
Engine and desktop scopes are separate; a superset or older scope is
stale. An empty desktop artifact list stays a missing binding and never matches
a run that later supplies an executable.

Each finding has a unique `id`, a `category`, an exact `subject`, nonempty `facts`
and `limits`, hash-bound `evidence`, and `materials`. It must match a pending
item of this run by category and identity, never by message text:

- `missing-packaged-texts`: needs at least one full `legal-text` material.
- `native-applicability` and `upstream-text-applicability`: facts about that
  package; materials are optional.
- `toolchain-runtime`: subject `{toolchain}`; needs attribution or legal text
  from official distribution archives: the compiler for its host and standard
  library for the requested target, both at the exact rustc release. URLs must
  name these exact components under https://static.rust-lang.org/dist/.
  This checks recorded provenance correspondence; it does not authenticate a
  downloaded upstream manifest or reconstruct historical link inputs.

Executable binding is not a review category. Unknown, duplicate or ambiguous
findings are rejected; packages without a finding keep their pending entries.

A registry package finding needs exactly one `crate-archive` evidence entry. Its
SHA-256 must equal the Cargo.lock checksum, and the local Cargo source must be
byte-identical to the archive (only Cargo's `.cargo-ok` marker may be extra).
Other evidence roles are `published-archive`, `distribution-archive`,
`upstream-document` (these need an https URL) and `inspection`. Evidence is only
hash-referenced; it is not copied into notices.

Each material has `path`, `sha256`, `bytes`, `kind` (`legal-text`,
`source-notice` or `attribution`), an explicit `reason`, and an `origin`:

- `archive-member`: bytes must equal that member of a hash-bound archive.
- `upstream-revision`: an https URL containing its 40-hex revision.
- `published-terms`: a steward's https publication; legal texts only.

Legal texts from an archive or revision must be license-named documents, so an
arbitrary source file cannot stand in for missing terms. Source notices come from
published source archives. `copied_sources` attaches copied code to the package
that contains it, not to an invented Cargo dependency. It names the original
crate, version, published archive and members. It needs the exact copied terms
and the adaptation notice from the package's own archive.

Materials are copied under `review/<finding>/` and bound into
`native-NOTICES.txt`. Package materials join that package's `texts`; runtime
materials go in top-level `runtime_materials`. Both carry `review_finding`,
`kind`, `reason` and `origin`. The receipt's `review` block records the input
digest and applied findings, and the input is kept as `review-input.json`.
Inspection files are not shipped unless one is explicitly selected as an
obligation-bearing notice. Documentation under separate terms, such as rmcp's
docs, must not be added as uniformly licensed code. A review never sets
`release_accepted`, interprets SPDX metadata or decides compliance.

## Frontend notices

The active Vite build includes `scripts/frontend-notices.mjs`. It uses production
chunk module inputs, installed package identities and complete recursively located
license/notice files. Virtual helpers identify the actual Vite/Vite+ CLI package
and compare its version (or bundled Vite version) to the running plugin context.
They retain that provider's complete license bundle, rather than attributing an
external managed builder to an unrelated project Vite package. The receipt records
provider metadata/entry hashes and whether it is covered by the project lock;
external managed-builder provenance is separate from that lock. Custom programmatic
builders must provide their actual package entry through `builderEntry`.
Unused dependencies do not enter coverage. Nonempty recognized license documents
are required; auxiliary copyright icon files cannot substitute for them. Missing
or blank license texts fail the build.
`third-party/NOTICES.txt` and `third-party/frontend-receipt.json` are emitted assets
installed with the frontend. No product UI copy is added. The final write hook
hashes actual output files (including HTML); receipt and notice bytes are excluded
from `emitted`, and notices are separately hashed. There is no hash of the receipt
inside itself. Build into a fresh external output directory to avoid stale files.

## Materials contract

Schema identifier `omd-materials-v1` is versioned. The manifest has `reviewed:true`,
`pending:[]`, exact `target` packaging identifier, release `version`, `locks`
(name-to-SHA256 map), and a nonempty `components` array. Every component has a
unique `id`, exact `version`, `status:"reviewed"`, `pending:[]`, `artifacts`
(installed portable relative path-to-SHA256 map), and `materials` with nonempty
maps for all four keys: `notices`, `source`, `instructions`, `provenance`.
A reviewed explanation of the chosen source route belongs in those materials;
unknown obligations cannot be filled with a generic label. Every selected file
must exist with matching bytes; every installed input must be covered. All
required component identities, versions and artifact prefixes must match the
packager's component inventory. Source/instructions/provenance are mandatory
coverage evidence; this schema does not interpret whether a license requires them.

Python and JavaScript independently implement this contract. Their versioned
fixture JSON files must be byte-identical; tests in each tree exercise the same
positive and negative cases. Desktop does not import or spawn sibling tooling.
Changes require synchronized fixture/schema review, not an implicit sibling link.

Both packagers default to development staging and mark it unaccepted. Use
`--staging-mode release --materials FILE --materials-locks DIR` (desktop also
requires `--version VERSION`) to request release preparation. The locks directory
must contain Cargo.lock and browser-package-lock.json; desktop additionally needs
desktop-Cargo.lock and desktop-package-lock.json. Engine Cargo.lock is checked
against the packager checkout, browser lock against installed adapter input, and
desktop locks against its checkout. The reviewed manifest binds these digests.
Install the native receipt via supplements as `native-receipt.json`; release mode
requires no pending coverage and matches target, Cargo lock and executable hashes.
Also install the generator's `native-NOTICES.txt` supplement under that exact
name. Both validators require complete roots/binaries/ownership/toolchain/package
metadata, matching root versions, and nonempty text inventories. They verify the
installed notice asset's hash and every referenced byte span, so a receipt without
the full retained texts cannot satisfy native coverage.
They accept only `omd-native-notices-v2` with `release_accepted:false` and a
`review` block. Each review span must be listed by exactly one finding for its
own package, or by the runtime finding. There must be exactly one runtime finding
with materials. A package with only review texts needs a full legal text, and
copied sources need both terms and a notice. A v1 receipt never had a review
path, so it can no longer satisfy release staging.
Use a receipt selecting the six engine binaries for desktop staging.
On macOS the required `omd-signin` component's artifact is the bundle executable
`bin/OMD Sign-In.app/Contents/MacOS/omd-signin`. Like every installed file, the bundle's
`Contents/Info.plist` and `Contents/Resources/AppIcon.icns` must be covered, normally by the
same component. Plugin
`publishable` describes only plugin selection. It never accepts materials or a
platform release. Successful coverage validation still has release_accepted:false.

Desktop release mode additionally requires desktop-rust and frontend components
with artifact prefixes native/ and frontend/. Current resource staging cannot bind
the final desktop executable: another packaging phase must supply and verify that
binding. Default (single-phase) release mode therefore still fails at that gate, rather
than treating native preparation as final executable evidence. The explicit two-phase
route below defers exactly those two components to the final binding of the signed
payload. No installer build is implied.

Remaining requirements include exact upstream yt-dlp_macos corresponding source
and provenance, sanitized media kit metadata, Chromium component source obligations,
native embedded-material review and platform acceptance. Preserve the existing
complete FFmpeg/Opus/LAME/zlib kit, script/build metadata/rebuild instructions. This
patch does not substitute build-ytdlp.py evidence for a different executable.
The controlled-source prototype in `distribution/yt-dlp-source` is also a different
executable. Its receipt covers only its own inputs and supplies no facts about the
upstream producer.

Primary interpretive references are [FFmpeg's own guidance](https://ffmpeg.org/legal.html),
[SQLite's dedication explanation](https://www.sqlite.org/copyright.html), and
[yt-dlp's combined executable licensing](https://github.com/yt-dlp/yt-dlp#licensing).
For rmcp 3.4.0, inspect the [exact commit license](https://github.com/modelcontextprotocol/rust-sdk/blob/fd7811fdaa9fefa1c8034534b4d7a31c97204f89/LICENSE).
Its transition text must not be replaced by current-main terms. These references
inform review; neither their presence nor this tool establishes compliance.

Installed frontend package versions must match their package-lock entries. Embedded
Tauri external helper modules retain their complete original source/header in the
notice asset. Native receipts also explicitly flag Rust standard-library/compiler
runtime materials outside Cargo's dependency graph; they are not silently covered
by the Cargo inventory. Only a `toolchain-runtime` finding with exact distribution
materials clears that flag. It shows distribution correspondence, not the link
inputs of an already built executable.

## Final materials binding (two-phase, omd-final-materials-v1)

Signing changes code bytes, so an `omd-materials-v1` manifest cannot describe a signed
payload. It stays the unchanged **initial review**: reviewed facts bound to original,
pre-signature artifact digests and validated at staging. A separate **final binding**
connects those facts to the signed bytes, outside the app (a document inside the app
would have to hash itself). Schema `omd-final-materials-v1` is versioned, and a v1
manifest checked against signed bytes still fails. Since 0.2.3 both final contracts also
accept the nested macOS sign-in bundle (below). Documents without a nested bundle validate
exactly as before, and the shared fixtures gained cases for it.

Flow: stage with `--staging-mode release --materials-binding two-phase` (desktop
`stage-v2.mjs`; it defers only `desktop-rust` and `frontend`, whose executable does not
exist yet), sign with `sign-macos.py … --purpose distribution-candidate --materials-binding
two-phase` (repeated at execute; status `signed-awaiting-final-materials`, exit 2, never
a candidate by itself), then:

```sh
uv run scripts/bind-final-materials.py prepare --input-app /abs/input.app --final-app /abs/signed.app \
  --plan /abs/plan.json --report /abs/work/signing-report.json --prepared-extractor /abs/yt-dlp_macos \
  --materials-locks /abs/locks --delivery-root NAME=/abs/dir … --desktop-receipt NAME/receipt.json \
  --desktop-notices NAME/native-NOTICES.txt --review /abs/final-review.json --output /abs/new-dir
uv run scripts/bind-final-materials.py verify … --final /abs/new-dir/final-materials-v1.json --output /abs/new.json
uv run scripts/test-final-materials.py
```

`prepare` writes `final-materials-v1.json` and `binding-report.json` into a new directory
outside both apps and every delivery root. Exit 0 means coverage validated (still
`release_accepted: false`); 2 means a binding with explicit pending gaps; 1 means refused,
with only a refusal report and never a binding. `verify` re-derives the binding from bytes
and requires exact agreement.

Every relation is recomputed from actual input and signed bytes; report claims such as
`signature_only_change` are never trusted. Each final payload file has exactly one relation:

- `signature-only`: reviewed code roles from the signing policy. The paired layout check
  (`omd-macho-signature-layout-v2`) plus the static role check: identifier, Team, mode,
  hardened runtime and exact entitlements.
- `prepared-extractor`: yt-dlp. The full pinned PyInstaller proof from the input producer
  to the plan's prepared file (every packed native signature-only and verified, every
  other member identical, bootloader identical outside PKG-derived fields), then a paired
  signature-only check to the signed file. This contract defines only the stock-bootloader
  method. A plan using the controlled-source extractor route
  ([macOS signing](macos-signing.md#controlled-source-producer-route)) is refused outright,
  with or without source inputs. Bind it with [`omd-final-materials-v2`](#final-materials-v2-controlled-source-extractor-route-omd-final-materials-v2).
- `managed-manifest`, `build-inventory`, `engine-receipt`: only digest fields change; the
  inventory gains a signer record whose purpose and binding must match the plan and report.
  The receipt keeps everything but its artifacts and rebound review digest, and its prior
  artifacts must bind the pre-signature binaries.
- `outer-seal`: `CodeResources` must hash exactly every other payload file, and every
  SHA-256 code directory of the outer executable must bind `Info.plist` and the seal.
- `nested-seal`: the one new file signing adds inside a nested app bundle under the
  resources (`bin/OMD Sign-In.app/Contents/_CodeSignature/CodeResources`). Its main
  executable is a `signature-only` code object, and its Info.plist and icon are `identical`.
  The seal must be new, must hash exactly the bundle's other resources (`sealed_files`),
  and every SHA-256 code directory of the bundle executable must bind the bundle's
  Info.plist and this seal. The build inventory relation expects the signer to append this
  seal after the staged rows. Like the outer seal it is a signing output, so a final-review
  component must cover it.
- `identical`: everything else, byte for byte.

Unexpected changes, additions or removals, unrecognized code and unsupported layouts are
refused. By default `codesign --verify` (Developer ID Team requirement) also runs on every
object and the bundle; it is verification only. The signing plan must have inspected this
exact input, and the report must name this plan and the signed code bytes. A report or
plan edited to another purpose, or a relabelled sealed inventory, is refused.

The engine receipt is validated against the final payload, and the detached desktop
receipt against the final executable. Both use the exact lock, target, version and binary
set, every legal text span, and spans present in the payload. Initial-review components
carry v1 facts only through these relations: original digests stay in `initial`, signed
digests in `final`. App-level components (`desktop-rust`, `frontend` and the bundle
metadata) come only from an explicit reviewed `omd-final-review-v1` input. Materials are
`payload:` or `delivery:` locators with digests. Delivery files are hashed in place under
`--delivery-root`; host paths are never serialized. A ~4 GB source archive can be bound by
digest without entering the app. A bound file is not evidence that its route is sufficient.

No status is inferred. Without a review, or for any component marked pending, left
ambiguous or missing a material kind, the binding stays pending. A private-validation
signing purpose, single-phase or development-staged input, missing locks or receipts,
and uncovered files are also explicit gaps. Only a complete reviewed input plus verified
relations yields `coverage_validated: true` and `distribution_candidate: true`.
`release_accepted` is always false.

`validate_final` (Python) and `validateFinal` (desktop `scripts/final-materials-contract.mjs`)
implement the same contract over the document and actual payload/delivery inventories.
They are tested with byte-identical `final-materials-fixtures-v1.json` and identical error
messages. Byte-level proofs live only in the engine binder. Limits: no legal or compliance
decision; static Developer ID checks do not re-establish secure timestamps, revocation or
notarization; frontend embedding is carried by the executable's signature-only relation,
not re-extracted.

## Final materials v2: controlled-source extractor route (omd-final-materials-v2)

`omd-final-materials-v2` is a separate, explicit contract version. It keeps every v1 rule
and adds one thing: the yt-dlp relation names its extractor route, and a typed `extractor`
section carries that route's proof identities. v1 is unchanged. Its fixtures are
byte-identical, it remains the default, it still pins the stock method and it still
refuses the controlled-source route. A v1 document is always held to v1 rules, and a
document with any other schema fails closed.

```sh
uv run scripts/bind-final-materials.py prepare --contract omd-final-materials-v2 … \
  --prepared-extractor /abs/omd-yt-dlp --prepared-extractor-report /abs/work/extractor-report.json \
  --prepared-extractor-source-evidence /abs/source-evidence.json --prepared-extractor-source-evidence-sha256 HEX \
  --prepared-extractor-source-kit kit/source-kit.tar.gz --delivery-root kit=/abs/kit-dir \
  --prepared-extractor-source-bootloader /abs/run --output /abs/new-dir   # writes final-materials-v2.json
uv run scripts/bind-final-materials.py verify --contract omd-final-materials-v2 … --final /abs/new-dir/final-materials-v2.json --output /abs/new.json
```

The route comes from what the signing plan inspected. A request with source evidence
means `controlled-source`; anything else means `upstream-stock`. The plan's
transformation method must agree, but neither label is trusted for the proof.

- `upstream-stock`: the v1 proof, unchanged. The section records `report: null` and
  `source: null`. Source inputs on a stock plan are refused; they cannot relabel it.
- `controlled-source`: needs `--prepared-extractor-report` and all four
  `--prepared-extractor-source-*` options together, and only with v2. The operator's
  evidence digest must equal the digest the signing plan inspected. The report digest
  comes from the plan. The binder then calls `macos_extractor.check_report` on the
  input app's own producer bytes and the plan's prepared file. That binds the report
  to those bytes, the mode and the Team ID. It then repeats the whole
  [source route](macos-signing.md#controlled-source-producer-route) from bytes: evidence,
  kit recipient verifier, pinned profile, kit plan and receipt, every recorded member and
  native, the outer onefile policy, the compiled bootloader structure, the replayed
  PyInstaller sources, and the signature-only transformation. Every packed member and
  the outer prepared file then pass `codesign --verify`. In Developer ID mode that
  includes the Developer ID Application requirement pinned to the signing Team. The
  usual paired signature-only relation and role check to the signed file follow.

Paths are private inputs and are never serialized. The section holds digests only:
evidence (`omd-macos-extractor-source-evidence-v1`), preparation report, compiled
bootloader (never the stock digest), pinned profile file, id and digest, the kit plan and
receipt, member and native counts, and the kit. The kit is the one material that is also
a file binding. It is given as a delivery path, hashed in place, added to the delivery
inventory, and recorded as a `delivery:` locator with its size and digest. Evidence for
another kit, profile, producer, target or Team fails the repeated proof.

The shared validators check that the section restates the relation it explains:

- path, method and route pairing;
- producer equal to the input bytes and the initial-review digest;
- prepared digest;
- `members_verified` equal to the natives;
- component and version from the required `yt_dlp` component;
- the architecture;
- for the source route, the evidence shape, a non-stock bootloader, the pinned profile
  file, `natives + non-natives = members`, arm64 on `darwin-arm64`, and a kit that is a
  bound delivery file of exactly that size and digest.

The extractor must be an artifact of its initial-review component. On the source route,
the kit must be that component's `source` material. Moving it to another component or
another kind is refused, and the binder keeps such a component pending with a stated
reason. A v2 binding cannot bootstrap a missing or stale initial review, and it cannot
promote a pending review. The source evidence is a digest root of trust, not a legal,
source or materials acceptance. Component statuses still come only from the reviewed
`omd-final-review-v1` input. Every other v1 rule is unchanged: before/after receipts,
manifests, inventory, seal and Info/CodeDirectory binding, private-validation refusal,
and `release_accepted: false`.

`final-materials-fixtures-v2.json` is byte-identical in both trees and pinned by digest in
both test suites. It has 107 cases: complete controlled-source and stock-route bindings, plus
negative cases for v1 relabelling, unknown versions and fields, route/method mismatch, a
missing or relabelled section, omitted source proof or report, a stock route carrying
evidence, the stock bootloader, stale kit digests, delivery tampering, a misplaced kit
material, pending components, private purpose and self-reference. Compilation from the kit
sources, source and terms sufficiency, and runtime capability remain build and review
evidence. A real same-Team Developer ID preparation and app are later evidence.

The v2 extractor's byte sizes and member counts use JSON safe-integer semantics:
integral numeric values are accepted through `9007199254740991`; booleans,
fractions and larger magnitudes are rejected. Thus `100` and `100.0` have the
same meaning in both validators. This does not change v1's validation rules.
The source-proof handoff receives the prepared digest already bound to the
signing plan, checks it before proof, and returns it for the caller's consistency
check. Replacing the prepared path cannot substitute a different proven digest.

## Notarized materials envelope (omd-notarized-materials-v1)

Stapling adds one file, `Contents/CodeResources` (the ticket), outside the code seal
(`Contents/_CodeSignature/CodeResources`). Final materials v1 and v2 bind the exact signed
payload, so they correctly refuse the stapled app ("Unexpected new payload files"). That
guard, both contracts and their fixtures are unchanged. A separate, detached envelope
composes the exact signed binding with one post-signing relation, method
`omd-apple-stapled-app-ticket-v1`: signed app to stapled app, plus the archive Apple accepted
and the distribution archive. It is not a v3 signing relation, and it never strips the ticket
or exempts `CodeResources` from either contract.

```sh
uv run scripts/bind-notarized-materials.py prepare --contract omd-notarized-materials-v1 \
  --signed-binding /abs/final-materials-v2.json --signed-binding-sha256 HEX \
  --signed-app /abs/signed/X.app --stapled-app /abs/stapled/X.app \
  --expected-team-id TEAM --expected-target darwin-arm64 --expected-version 0.2.0 \
  --expected-purpose distribution-candidate \
  --uploaded-archive /abs/upload.zip --uploaded-archive-sha256 HEX \
  --notary-log /abs/log.json --notary-log-sha256 HEX --submission-id UUID \
  --distribution-archive /abs/stapled.zip --distribution-archive-sha256 HEX \
  --evidence-root signed=/abs/signed --evidence-root notary=/abs/notary \
  --input-app … --plan … --report … [every other bind-final-materials.py input] --output /abs/new-dir
uv run scripts/bind-notarized-materials.py verify … --envelope /abs/new-dir/notarized-materials-v1.json \
  --envelope-sha256 HEX --output /abs/new.json
uv run scripts/test-notarized-materials.py
```

The original binder inputs are the same options as `bind-final-materials.py`, handled by its
own unchanged code. `--signed-app` takes the place of `--final-app`, and the original contract
comes from the pinned binding's schema. Expected Team, target, version and purpose come from
the caller, never from the envelope alone. Only `darwin-arm64` with one thin arm64 outer slice
and one SHA-256 CodeDirectory is supported. Other targets and architectures are refused until
they are proven.

`prepare` writes `notarized-materials-v1.json` and `verification-report.json` into a new
directory outside every app, evidence, delivery and source input directory, and only after
every check passes. Otherwise it writes only a refusal report. `verify` checks the pinned
envelope digest and strict shape first, then re-derives the whole envelope. It never replays a
report. Exit 0 means a fresh macOS verification passed; 1 means refused or a failed check; 2
means unverified (platform, missing tool, network, timeout, output overflow or a resource
bound). `release_accepted` is always false.

Every run re-derives from bytes, in this order:

1. The binding bytes must match the pinned digest. They are parsed strictly (duplicate keys
   refused), and only `omd-final-materials-v1` or `-v2` is accepted.
2. The retained log, both archives and the input, signed and stapled apps are read through
   no-follow descriptors into private snapshots. Later checks use only the snapshots, so a
   path swapped after hashing cannot be substituted.
3. Unchanged `final_materials.verify` runs on the signed snapshot, cryptographically, with every
   original input: plan, report, review, locks, prepared extractor and its source evidence,
   kit, bootloader, delivery roots and receipts. It must re-derive equal with no gaps. There is
   no option to skip this.
4. Exact closure: the stapled tree is the signed tree plus one regular, non-executable,
   non-code file at `Contents/CodeResources` (1 byte to 1 MiB). No removal, other addition,
   byte, permission or directory change is allowed, and no symlinks, hard links, special
   files, special permission bits or colliding names. Size, header and digest do not
   authenticate the ticket.
5. Actual Apple checks, with the tree hashed before and after:
   - `codesign --verify --deep --strict --all-architectures` with the Developer ID CA, leaf
     and Team requirement on both bundles, and on every explicit code object;
   - the static role check (identifier, Team, runtime, exact entitlements, current policy);
   - the outer CodeDirectory identity from `codesign -d` and from the verified bytes, which
     must agree and be unchanged by stapling;
   - `xcrun stapler validate` and `spctl --assess --type execute` on the stapled snapshot.
6. Strict archive reads. Every byte must be accounted for, with no comment, prepended data or
   zip64. Only regular files and directories are allowed, with no traversal, duplicates or
   collisions, exactly one app subtree and declared sizes enforced while streaming. The
   uploaded app must equal the signed tree and the distribution app the stapled tree (bytes,
   permissions and directories). Every `__MACOSX` member must be the AppleDouble of an entry
   of that app and is bound by digest in the envelope. It may carry only reviewed extended
   attributes (`com.apple.provenance`), no resource fork or Finder information. The
   distribution archive is then extracted privately with `ditto` and checked again with
   codesign, stapler and Gatekeeper.
7. The retained log must name the submission id, `Accepted` with status code 0, the uploaded
   archive digest and file name, and the outer arm64 CDHash. This is provenance consistency
   only. A ticket does not authenticate a local log's job id or chronology, and no history is
   fetched.
8. The apps, binding, log, archives, original inputs and every bound delivery file are
   rehashed after the run. The envelope must then pass the shared structural validator.

New wrapper tool invocations have fixed limits: codesign 45 s, stapler, spctl and ditto
60 s, and 1 MiB of combined output per command. These invocations run without a shell in
an owned process group, killed before reaping on timeout or overflow; nothing is retried.
The caller may lower the 600 s cooperative workflow deadline, but this is not a hard
wall-clock limit. The unchanged original verifier runs in process with its legacy
per-call timeouts, captured output without the new output cap, and legacy process
cleanup. Synchronous walking, hashing and ZIP parsing are not interrupted by the
deadline. Overruns are refused at subsequent deadline checks, including the final
check before success. The new runner's group cleanup does not cover escaped or
daemonized descendants. The
verifier never signs, staples, submits or reads credentials or profiles. Its tool policy
refuses such commands.

`validate_notarized` (Python) and `validateNotarized` (desktop
`scripts/notarized-materials-contract.mjs`) take the envelope, the raw binding and initial
review bytes, the actual signed and stapled inventories, the delivery inventory, archive
observations, evidence identities and caller expectations. They run the unchanged
`validate_final` on the signed payload and recompute every envelope equality. Success returns
only `structure_validated: true`, `macos_verification_required: true` and
`release_accepted: false`. It never emits a candidate, notarization or coverage promotion. A
serialized verification report is audit evidence, not a portable acceptance capability.
`load_strict` and `loadStrict` refuse duplicate keys, a BOM, invalid UTF-8, NaN or Infinity
literals and nesting deeper than 64. Envelope numbers use JSON safe-integer semantics, and the
inventory digest serializes integral sizes as integers.

`notarized-materials-fixtures-v1.json` is byte-identical in both trees and pinned by digest
in both suites. It has 105 contract cases and 28 raw loader cases, with identical messages in
both languages. The cases cover v1 stock and v2 controlled-source and stock-route
compositions, unknown fields and versions, duplicate keys, safe integers, paths,
self-reference, stale digests, private purpose, pending receipts and components, a missing or
misplaced kit, stock/source relabelling, ticket and payload changes, outer slices, and archive
and transport mismatches.

Limits: this is factual binding, not a legal, compliance or release decision. Gatekeeper and
stapler results are assessments on the current host. They do not establish other macOS
versions, Intel, revocation, quarantined pristine-account installation or GUI behavior.
Changing the ticket path, size bound, transport attributes, targets or archive layout needs
method review and a new version.

The opt-in real-data classes read a description JSON that is written next to the genuine
evidence, so a release round regenerates it without editing the suites:
OMD_FINAL_MATERIALS_GENUINE_PAIR (bind-final-materials.py prepare options of a signed pair and
the expected binding facts), OMD_FINAL_MATERIALS_SOURCE_PROOF (the controlled-source producer,
its ad-hoc control, evidence, kit, bootloader and expected proof facts) and
OMD_NOTARIZED_MATERIALS_CHAIN (bind-notarized-materials.py options and expected ticket, outer
code, binding digest and member counts). No developer-machine path is assumed.
