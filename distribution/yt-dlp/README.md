# Managed yt-dlp packaging

This is a build recipe for the upstream extractor executable. It contains no
engine orchestration or source-plugin runtime. Installed users need no Python.
The Rust engine still owns arguments, credentials, network policy, confinement,
verification, publication and acquisition state.

UV locks the upstream yt-dlp release, its dependencies, the embedded Python
version and PyInstaller. On macOS, supply the distribution's Developer ID:

```sh
uv run scripts/build-ytdlp.py --output /new/build-directory --identity 'Developer ID Application: Your Company (TEAM)'
```

PyInstaller signs embedded libraries with the same identity as its launcher.
Signing only the already-built upstream one-file executable does not do this:
the macOS hardened runtime rejects its differently signed embedded Python.
Library validation remains enabled. The build records dependency/source hashes
and rejects an existing output directory. Review the resulting executable's new
digest in the managed-tool manifest. Original installed tool bytes are retained.

`--identity` is macOS-only and required there. Other packaging hosts use their
native format and still require platform-specific signing and acceptance.

Windows packages target Windows 10 or newer. The recipe excludes build-host
API-set forwarders and ucrtbase.dll because those come from the supported OS.
It retains the Python/package extensions and VC runtime DLLs; keep their complete
terms and exact source/runtime provenance in the release materials. Check the
collected archive on Windows and execute it through OMD's ordinary-user
confinement before accepting it.
