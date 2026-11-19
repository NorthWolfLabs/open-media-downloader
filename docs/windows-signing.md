# Windows signing

This guide signs OMD's Windows release artifacts with Authenticode through Azure Artifact Signing:

- the NSIS desktop installer;
- the standalone engine runtime archive.

It is the Windows counterpart of the [macOS signing guide](macos-signing.md) and uses the same principles:

- Sign only first-party code.
- Leave pinned third-party bytes untouched.
- Prove every signing change from bytes.
- Rebind receipts and materials to the signed bytes.

Every record keeps `release_accepted: false`. Signing is never release acceptance.

## What is signed

Signatures use a SHA-256 file digest and an RFC 3161 timestamp, and must pass `signtool verify /pa`.

| Object | Signed | When |
| --- | --- | --- |
| `omd-engine.exe`, `omd-plugin-worker-v2.exe`, `omd-helper-guardian.exe`, `omd-notify.exe`, `omd-signin.exe`, `omd.exe` | Yes | Before desktop staging or runtime packaging |
| `omd-mcp.exe` (standalone runtime only) | Yes | Before runtime packaging |
| Desktop executable | Yes | By Tauri during bundling, after it writes its bundle-type marker |
| NSIS uninstaller | Yes | By makensis `!uninstfinalize` during bundling |
| Setup executable | Yes | By Tauri after makensis |
| Managed extractor, `ffmpeg.exe`, `ffprobe.exe` | **No** | Their bytes are pinned by `tools-v2.json`, materials routes and source kits |
| `node.exe` | **No** | Keeps its publisher's signature; pinned by both tool manifests |
| Headless browser and its libraries | **No** | Pinned by `browser-tools-v2.json` |
| Tauri's NSIS plugins | **No** | Third-party; unpacked only while the installer runs |

None of the signed files needs a rebuild. The engine identifies itself by a runtime self-hash
(`omd-engine --identity`), and the desktop compares the running engine with the installed one at run time.
Tool manifests pin third-party tools only. Signing changes release documents, not code.

## Prerequisites

- **Signing account.** An Azure Artifact Signing account (`<ACCOUNT>`) in region endpoint `<ENDPOINT>`
  (for example `https://<region>.codesigning.azure.net`). The account needs completed identity validation and
  a public-trust certificate profile (`<PROFILE>`). The certificate subject is the validated organization.
  Record it; verification compares against it exactly.
- **Role.** The signing identity holds the **Artifact Signing Certificate Profile Signer** role, scoped to
  the certificate profile.
- **Build host.**
  - Windows x64 with the Windows SDK `signtool.exe` (10.0.26100 or later).
  - The Azure CLI, signed in interactively with `az login` as the signing identity.
  - No secret is stored on disk or passed on a command line. The client library authenticates through
    `DefaultAzureCredential`, which uses the Azure CLI session.
- **Client library.** Download the `Microsoft.ArtifactSigning.Client` NuGet package from nuget.org and pin
  its SHA-256. Before use:
  - extract it to a dedicated directory;
  - verify `bin\x64\Azure.CodeSigning.Dlib.dll` with `Get-AuthenticodeSignature`: status `Valid`, signer
    `CN=Microsoft Corporation, …`.
- **Metadata file.** Create `metadata.json` with exactly this shape:

  ```json
  {
    "Endpoint": "<ENDPOINT>",
    "CodeSigningAccountName": "<ACCOUNT>",
    "CertificateProfileName": "<PROFILE>"
  }
  ```

- **Tauri.** The pinned Tauri CLI (2.11.4). Set `TAURI_WINDOWS_SIGNTOOL_PATH` to the `signtool.exe` above.

The underlying command is:

```text
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib <DLIB> /dmdf <metadata.json> <FILE>
```

Never run it directly. Every signature goes through the signing gate below. Each signature is an
audit-logged event on the signing account, so sign each file once and never sign test files.

## Signing gate and policy

`scripts/windows-sign-gate.ps1 -Policy <policy.json> -Path <file>` is the only signing entry point. It is
used both for direct engine signing and as Tauri's `bundle.windows.signCommand`. A policy
(`omd-windows-signing-policy-v1`) contains:

```json
{
  "schema": "omd-windows-signing-policy-v1",
  "label": "<unique label>",
  "signtool": {"path": "<signtool.exe>", "sha256": "<hex>"},
  "dlib": {"path": "<Azure.CodeSigning.Dlib.dll>", "sha256": "<hex>"},
  "metadata": {"path": "<metadata.json>", "sha256": "<hex>"},
  "timestamp_url": "http://timestamp.acs.microsoft.com",
  "expected_subject": "<exact certificate subject>",
  "audit_log": "<audit.jsonl>", "output_logs": "<directory>",
  "max_signatures": 3, "dry_run": false,
  "explicit": [{"path": "<file>", "pre_sha256": "<hex>", "role": "<role>"}],
  "installer": {"path": "<target>\\x86_64-pc-windows-msvc\\release\\bundle\\nsis\\OMD_<version>_x64-setup.exe"},
  "uninstaller": {"max": 1},
  "skip": [
    {"root": "<desktop>\\src-tauri\\resources\\v2", "reason_id": "pinned-resource", "reason": "…",
     "inventory": "<…>\\build-inventory.json",
     "never_skip": ["bin/omd-engine.exe", "bin/omd-plugin-worker-v2.exe", "bin/omd-helper-guardian.exe", "bin/omd-notify.exe", "bin/omd-signin.exe", "bin/omd.exe"]},
    {"root": "<target>\\x86_64-pc-windows-msvc\\release\\nsis", "reason_id": "nsis-plugin", "reason": "…",
     "expected": [{"name": "System.dll", "sha256": "<Tauri NSIS cache digest>"}]}
  ]
}
```

The gate signs a file only when one of these rules matches:

- **`explicit`:** the exact path and the exact pre-signature digest.
- **`installer`:** the exact path, and the file is an NSIS image.
- **`uninstaller`:** an NSIS image at makensis's temporary path, at most one per policy.

Tauri also offers every unsigned resource `.exe`/`.dll` for signing. Under a `skip` root, the gate answers
success **without signing**, but only after proving the file still equals its inventory or cache digest.
A first-party binary reaching it unsigned is an error.

Anything else is refused. The gate also refuses any of the following:

- a file that already carries a signature;
- changed signing-tool digests;
- an exhausted signature budget.

After signing, it requires all of these:

- `Get-AuthenticodeSignature` reports `Valid`;
- the exact `expected_subject`;
- a Microsoft timestamp countersignature;
- `signtool verify /pa /tw` succeeds and reports a timestamp.

Every request appends one line to the JSONL audit log. Each line records the policy and its digest, the
rule, the action (`signed`, `skipped`, `refused`, `dry-run-not-signed`), the pre- and post-signing SHA-256,
signer facts and timestamp, and the signtool log names. The gate prints nothing on success and never
prints credentials.

`"dry_run": true` runs every check and records every request without signing. Use it to validate a new
configuration before the first real signature.

## Signature-only relation

`scripts/pe_authenticode.py` proves layout `omd-pe-authenticode-layout-v1`. Authenticode changes only:

- the optional-header `CheckSum`;
- the `IMAGE_DIRECTORY_ENTRY_SECURITY` entry;
- bytes appended at the end of the file.

A signed file S is signature-only-related to its unsigned input U when all of these hold:

- S starts with U, apart from those two fields;
- S then has 0–7 zero bytes;
- S then has an 8-byte-aligned table of `WIN_CERTIFICATE` entries (revision 0x0200,
  `WIN_CERT_TYPE_PKCS_SIGNED_DATA`) that ends the file.

A receipt may be rebound artifact-only only after this proof. For the desktop executable, U is the build
output with Tauri's `__TAURI_BUNDLE_TYPE_VAR_UNK` marker replaced by `__TAURI_BUNDLE_TYPE_VAR_NSS`. That is
the same bundled-copy identity `package-windows.ps1` records.

## Procedure

### 1. Sign the engine executables

Copy the executables bound by the reviewed native receipt. Check each copy against the receipt's artifact
digest. Sign each one with an `explicit` rule, then prove the signature-only relation. Executables shared
between the desktop and the standalone runtime are signed once and reused when their unsigned inputs are
byte-identical.

### 2. Rebind receipts and materials

1. Re-run `generate-native-notices.py` with `--artifact NAME=<signed file>`. Point `--manifest` at a
   clean source extraction, never at a checkout holding staged resources.
2. Check the new scope: it must equal the reviewed scope except `artifacts`, and the previous artifacts
   must be the proven unsigned digests.
3. Carry the findings unchanged, adding a limit that records the signature-only rebinding.
   `native-NOTICES.txt` must be byte-identical.
4. Rebind the reviewed `omd-materials-v1` manifest and its material routes. Only these may change:
   - `bin/*` digests;
   - the receipt digest;
   - for the standalone runtime, the `windows-crt` route's `bin/*` artifacts.

   Assert this change set.

### 3. Desktop installer

1. Stage the signed engine directory with desktop
   `stage-v2.mjs --staging-mode release --materials-binding two-phase`. Staging re-validates the receipt
   and materials against the signed bytes.
2. Build with `build-public.mjs --target x86_64-pc-windows-msvc`.
3. Package with `package-windows.ps1 … -SignGate <gate> -SignPolicy <policy>` (or set
   `OMD_WINDOWS_SIGN_GATE` and `OMD_WINDOWS_SIGN_POLICY`). Set `TAURI_WINDOWS_SIGNTOOL_PATH` too. With
   signing configured, Tauri signs, in order:
   - the marker-patched desktop executable (`explicit` rule with the patched digest);
   - the uninstaller;
   - the Setup.

   Budget: 3 signatures.

   Signing is off when neither parameter is given. Any gate refusal or signing failure aborts packaging
   before the output is written, and the build output is restored.

### 4. Standalone runtime

Run `package-runtime.py --staging-mode release` with the six signed executables and the rebound receipt and
materials.

### 5. Read back and verify

Run these on the downloaded artifacts:

```powershell
Get-AuthenticodeSignature OMD-<version>-windows-x64-setup.exe | Format-List Status,SignerCertificate,TimeStamperCertificate
signtool verify /pa /v /all OMD-<version>-windows-x64-setup.exe
```

Then check:

- **Installer:** extract it with 7-Zip.
  - Every resource equals the staged `build-inventory.json`.
  - The shipped desktop executable is signature-only-related to the marker-patched build output.
  - Every first-party PE verifies with the expected subject and a Microsoft timestamp.
  - No third-party PE carries the publisher's signature.

  Bind the detached desktop receipt and frontend binding to the signed shipped executable. The installed
  uninstaller is checked after installation.
- **Runtime archive:** every member equals `runtime-inventory.json`. Compared with the previous unsigned
  archive, only these may differ:
  - the six executables;
  - the native receipt;
  - the rebound routes;
  - `materials-v1.json`;
  - `runtime-inventory.json`.

  Every managed tool and browser file must equal its pinned digest.
- **Installation:** install as a fresh standard user and repeat the Authenticode checks on the installed
  files.

## Limits

- A valid signature does not establish SmartScreen application reputation. A new publisher or certificate
  can still show a warning on first downloads; that warning is expected and must not be suppressed or worked
  around. Check it interactively from a real download with Mark-of-the-Web.
- Verification is local at signing time. Revocation status and certificate expiry after the timestamp are
  not re-evaluated.
- Third-party files keep their own signatures or none; OMD's manifests integrity-pin them.
- Installer, platform and native GUI acceptance are separate gates.

Sources: Microsoft [Artifact Signing quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart),
[signing integrations](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations),
[role assignment](https://learn.microsoft.com/azure/artifact-signing/tutorial-assign-roles);
[Authenticode PE format](https://learn.microsoft.com/windows/win32/debug/pe-format#the-attribute-certificate-table-image-only);
[Tauri Windows signing](https://v2.tauri.app/distribute/sign/windows/); [NSIS `!uninstfinalize`](https://nsis.sourceforge.io/Docs/Chapter5.html).
