"""Assemble a verified fixture kit from the pinned, already downloaded inputs."""
import hashlib
import json
from pathlib import Path
import shutil
import os
import platform
import subprocess
import argparse

root = Path(__file__).resolve().parents[1]
browser = root / "artifacts/tools/browser/1.63.0/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64"
adapter = root / "adapters/browser"
version = hashlib.sha256((adapter / "adapter.mjs").read_bytes() + (adapter / "protocol.mjs").read_bytes()).hexdigest()[:16]
output = root / "artifacts" / os.environ.get("OMD_BROWSER_FIXTURE_NAME", f"browser-fixture-kit-{version}")
node = root / "artifacts/tools/node/24.20.0/node-v24.20.0-darwin-arm64/bin/node"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--browser', type=Path, default=browser)
parser.add_argument('--node', type=Path, default=node)
parser.add_argument('--output', type=Path, default=output)
parser.add_argument('--manifest', type=Path, default=root / 'artifacts/browser-fixture-kit.json')
args = parser.parse_args()
browser, node, output = args.browser.resolve(), args.node.resolve(), args.output.resolve()
browser_executable='chrome-headless-shell.exe' if (browser/'chrome-headless-shell.exe').is_file() else 'chrome-headless-shell'
if not (browser / browser_executable).is_file() or not node.is_file():
    raise SystemExit('Provide the pinned extracted browser and Node executable.')
if args.manifest.exists() and args.manifest != parser.get_default('manifest'):
    raise SystemExit('The requested inventory already exists; retain its immutable identity.')
if output.exists():
    raise SystemExit("Fixture kit already exists; retain its immutable identity.")
output.mkdir()
def copy(source, destination):
    # APFS clones keep successive fixture inventories without multiplying the
    # pinned browser's physical storage. Later edits remain independent.
    if platform.system() == 'Darwin' and Path(source).stat().st_dev == Path(destination).parent.stat().st_dev:
        subprocess.run(["/bin/cp", "-c", str(source), str(destination)], check=True)
    else:
        shutil.copy2(source, destination)
    return str(destination)
shutil.copytree(browser, output / "browser", copy_function=copy)
(output / "adapter").mkdir()
for name in ["adapter.mjs", "protocol.mjs", "package.json", "package-lock.json"]:
    shutil.copy2(adapter / name, output / "adapter" / name)
shutil.copytree(adapter / "node_modules/playwright-core", output / "adapter/node_modules/playwright-core", copy_function=copy)
files = {}
for path in sorted(output.rglob("*")):
    if path.is_symlink():
        raise SystemExit("Unexpected symlink in managed browser input")
    if path.is_file():
        files[path.relative_to(output).as_posix()] = {"bytes": path.stat().st_size, "sha256": hashlib.file_digest(path.open("rb"), "sha256").hexdigest()}
manifest = {"root": str(output), "version": "playwright-1.63.0-chromium-1243", "browser": "browser/"+browser_executable, "adapter": "adapter/adapter.mjs", "node": {"path": str(node), "sha256": hashlib.file_digest(node.open("rb"), "sha256").hexdigest(), "version": "24.20.0"}, "files": files}
args.manifest.parent.mkdir(parents=True, exist_ok=True)
args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Verified inventory: {len(files)} files, {sum(x['bytes'] for x in files.values())} bytes")
