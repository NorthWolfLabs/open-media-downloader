# macOS payload minimum

The offered development application is macOS ARM64. Its whole-payload advertised
floor is 13.5. Engine binaries may retain lower deployment targets. Never patch
load commands or framework plists downward to make this gate pass.

After final bundling (including development overrides), run from the engine root:

```
UV_CACHE_DIR=/absolute/private/build-cache uv run scripts/check-macos-payload.py /path/to/OMD.app --arch arm64 --output /path/to/new-report.json
uv run scripts/test-macos-payload.py
```

A nonzero result rejects the candidate. The output must be new. This gate reads
all bundle files, thin/fat Mach-O slices and every member of the bundled yt-dlp
PyInstaller CArchive without executing them or writing extracted files. It pins
PyInstaller 6.22.0 as a build inspection dependency, never an end-user dependency.
Each packed member is capped at 256 MiB and total unpacked size at 1 GiB. Reports
retain all member hashes and all architecture metadata, but calculate the floor
only for the selected macOS CPU. ARM64 requires a general arm64 slice, not only
arm64e. Missing native architecture/platform/deployment metadata fails closed.
Per-architecture plist floors are currently rejected, requiring policy review.
Unknown future archive formats need an explicit inspector before acceptance.

Run the gate after bundling and before accepting/signing a release candidate;
Tauri overrides can supersede source configuration, so configuration inspection
alone is insufficient. Keep digest-bearing final native receipts detached from
the signed app. A metadata pass establishes a lower bound, not runtime support:
API availability, dylib resolution, CPU instructions, old-OS execution, Intel,
quarantine, pristine-account installation, signing and notarization remain gates.
No automatic release acceptance or runtime contracts are added by this tool.

Format sources: [Apple LSMinimumSystemVersion](https://developer.apple.com/documentation/bundleresources/information-property-list/lsminimumsystemversion),
[LLVM Mach-O definitions](https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/MachO.h),
[Tauri minimumSystemVersion](https://v2.tauri.app/reference/config/#minimumsystemversion),
[PyInstaller archive reader](https://github.com/pyinstaller/pyinstaller/blob/v6.22.0/PyInstaller/archive/readers.py).
