# /// script
# requires-python = ">=3.12"
# ///
"""Isolated local runtime smoke. Reports contain summaries, never instance credentials."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from mcp_stdio import smoke as mcp_smoke

spec = importlib.util.spec_from_file_location('package_runtime', Path(__file__).with_name('package-runtime.py'))
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


def extract(archive, root):
    seen = set()
    def write(name, stream, mode):
        rel = pkg.relative(name)
        pkg.require(str(rel).casefold() not in seen, 'Duplicate archive path')
        seen.add(str(rel).casefold())
        dest = root / str(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as out:
            shutil.copyfileobj(stream, out)
        dest.chmod(0o755 if mode & 0o111 else 0o644)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                pkg.require((item.external_attr >> 16) & 0o170000 in (0, 0o100000), 'Nonregular ZIP member')
                with z.open(item) as stream:
                    write(item.filename, stream, item.external_attr >> 16)
    else:
        with tarfile.open(archive, 'r:gz') as tar:
            for item in tar:
                pkg.require(item.isfile(), 'Nonregular tar member')
                with tar.extractfile(item) as stream:
                    write(item.name, stream, item.mode)
    inventory = pkg.load(root / 'runtime-inventory.json')
    files = inventory['files']
    expected = {x['path'] for x in files}
    pkg.require(len(expected) == len(files), 'Duplicate inventory entry')
    pkg.require(seen == {x.casefold() for x in expected | {'runtime-inventory.json'}}, 'Inventory membership mismatch')
    for item in files:
        actual = pkg.identity(pkg.regular(root / str(pkg.relative(item['path']))))
        pkg.require(actual == {k: item[k] for k in ('sha256', 'size')}, 'Inventory identity mismatch')
    return inventory



def expected_reviews(root, inventory):
    target = inventory['target']
    os_name, arch = target.split('-')
    runtime_platform = {'darwin': 'macos', 'win32': 'windows', 'linux': 'linux'}[os_name] + '-' + {'arm64': 'aarch64', 'x64': 'x86_64'}[arch]
    media = pkg.load(root / 'tools/tools-v2.json')
    tools = [{'name': name, 'version': media[name]['version'], 'sha256': media[name]['sha256'], 'bytes': (root / 'tools' / media[name]['path']).stat().st_size} for name in ('yt_dlp', 'node', 'ffmpeg', 'ffprobe')]
    def digest(value):
        return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    tool_review = {'platform': runtime_platform, 'tools': tools, 'digest': digest([runtime_platform, tools])}
    browser = pkg.load(root / 'browser/browser-tools-v2.json')
    node = {'bytes': tools[1]['bytes'], 'sha256': media['node']['sha256']}
    files = {name: {'bytes': browser['files'][name]['bytes'], 'sha256': browser['files'][name]['sha256']} for name in sorted(browser['files'])}
    browser_review = {'platform': runtime_platform, 'version': browser['version'], 'node_version': browser['node']['version'], 'node': node, 'browser': browser['browser'], 'adapter': browser['adapter'], 'files': files}
    browser_review['digest'] = digest([runtime_platform, browser['version'], browser['node']['version'], node, browser['browser'], browser['adapter'], files])
    return tool_review, browser_review


def verify_state(inventory, expected_media, expected_browser, service, sources, tools, media, browser):
    pkg.require(service.get('api') == 'v2' and service.get('version') == inventory['version'], 'Unexpected service API/version')
    pkg.require({'read', 'manage'}.issubset(service.get('scopes', [])), 'Service scopes unavailable')
    pkg.require({'media_acquisition', 'source_browser', 'isolated_sign_in'}.issubset(service.get('capabilities', [])), 'Service runtime capabilities unavailable')
    configured = service.get('media_tools') or {}
    pkg.require(configured.get('configured') is True and configured.get('complete') is True, 'Service media runtime incomplete')
    projection = [{k: item[k] for k in ('name', 'version', 'sha256')} for item in expected_media['tools']]
    pkg.require(configured.get('tools') == projection, 'Service media identities differ from archive')
    pkg.require(sources.get('items') == [] and sources.get('next_cursor') is None, 'Fresh source catalog is not empty')
    pkg.require(media.get('platform') == expected_media['platform'] and media.get('bundled') == expected_media and media.get('issue') is None, 'Bundled media identities differ from archive')
    active = [item for item in tools.get('items', []) if item.get('active') is True]
    pkg.require(len(active) == 1 and tools.get('next_cursor') is None, 'Expected one active media installation')
    pkg.require(active[0].get('state') == 'installed' and active[0].get('issue') is None and active[0].get('digest') == expected_media['digest'] and active[0].get('review') == expected_media, 'Active media identities differ from archive')
    pkg.require(browser.get('platform') == expected_browser['platform'] and browser.get('bundled') == expected_browser and browser.get('issue') is None, 'Bundled browser identities differ from archive')
    installed = browser.get('active') or {}
    pkg.require(installed.get('active') is True and installed.get('state') == 'installed' and installed.get('issue') is None and installed.get('digest') == expected_browser['digest'] and installed.get('review') == expected_browser, 'Active browser identities differ from archive')


def stop_engine(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        return process.wait(timeout=5)


def smoke(args):
    pkg.require(os.name == 'posix', 'Native smoke currently supports POSIX hosts only; Windows is fixture-tested')
    report_dir = Path(os.path.abspath(args.output))
    pkg.require(not os.path.lexists(report_dir), 'Refusing existing smoke evidence')
    report_dir.mkdir(parents=True)
    result = {'passed': False, 'archive_sha256': pkg.identity(args.archive)['sha256'], 'checks': []}
    process = None
    secrets = []
    temp_root = getattr(args, 'temp_root', Path('/tmp')).resolve()
    pkg.require(not temp_root.is_relative_to(Path(__file__).resolve().parents[2]), 'Smoke temporary storage must be outside project checkouts')
    with tempfile.TemporaryDirectory(prefix='omd-runtime-isolated-', dir=temp_root) as tmp:
        base = Path(tmp).resolve()
        root = base / 'extracted'
        root.mkdir()
        log = base / 'engine.log'
        try:
            inventory = extract(args.archive, root)
            target = ('darwin' if platform.system() == 'Darwin' else 'linux') + '-' + ('arm64' if platform.machine() in ('arm64', 'aarch64') else 'x64')
            pkg.require(inventory['target'] == target, 'Archive target differs from host')
            expected_media, expected_browser = expected_reviews(root, inventory)
            result.update(target=target, version=inventory['version'], extracted_outside_repositories=True)
            result['checks'].append('exact archive inventory')
            profile = base / 'fresh-profile'
            pkg.require(not profile.exists(), 'Smoke profile must start fresh')
            env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(base), 'TMPDIR': str(base), 'LANG': 'en_US.UTF-8'}
            previous_token = None
            profile_identity = None
            for phase in ('initial', 'restart'):
                with log.open('ab') as out:
                    process = subprocess.Popen([str(root / 'start-engine.sh'), '--profile', str(profile)], cwd=base, env=env, stdout=out, stderr=out, start_new_session=True)
                deadline = time.monotonic() + 60
                while True:
                    pkg.require(process.poll() is None, 'Engine exited before readiness')
                    pkg.require(time.monotonic() < deadline, 'Engine startup exceeded 60 seconds')
                    try:
                        instance = json.loads((profile / 'instance.json').read_text())
                        if instance['token'] != previous_token:
                            break
                    except (FileNotFoundError, json.JSONDecodeError, KeyError):
                        pass
                    time.sleep(.1)
                secrets.extend(instance.get(key, '') for key in ('token', 'admin_token'))
                previous_token = instance['token']
                def cli(command):
                    try:
                        completed = subprocess.run([str(root / 'bin/omd'), '--instance', str(profile / 'instance.json'), command], cwd=base, env=env, capture_output=True, timeout=10)
                        pkg.require(completed.returncode == 0, f'Bundled CLI {command} failed')
                        return json.loads(completed.stdout)
                    except subprocess.TimeoutExpired:
                        raise ValueError(f'Bundled CLI {command} exceeded 10 seconds') from None
                mcp_smoke(root / 'bin/omd-mcp', profile / 'instance.json', env)
                result['checks'].append('bundled MCP initialize/tools/list/status over stdio')
                service, sources, tools, media = [cli(command) for command in ('status', 'sources', 'tools', 'tool-status')]
                request = urllib.request.Request(instance['endpoint'] + '/v2/browser-tools/status', headers={'Authorization': 'Bearer ' + instance['token']})
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
                    browser = json.load(response)
                verify_state(inventory, expected_media, expected_browser, service, sources, tools, media, browser)
                identity = (profile / 'profile-id').read_bytes()
                if phase == 'initial':
                    profile_identity = identity
                    (profile / 'restart-sentinel').write_text('preserve')
                    code = stop_engine(process)
                    result['initial_engine_exit_code'] = code
                    pkg.require(code == 0, 'Initial engine did not exit cleanly')
                    process = None
                    result['checks'] += ['bundled CLI service API/version/capabilities', 'empty source catalog', 'exact bundled and active media identities', 'exact bundled and active browser identities']
                else:
                    pkg.require(identity == profile_identity and (profile / 'restart-sentinel').read_text() == 'preserve', 'Restart changed profile data')
                    result['checks'].append('launcher restart preserves profile and expected active installations')
                    result['restart_passed'] = True
            result['passed'] = True
        except Exception as error:
            result['failure_type'] = type(error).__name__
            if isinstance(error, ValueError):
                result['failure'] = str(error)
        finally:
            if process is not None:
                code = stop_engine(process)
                if code != 0:
                    result['passed'] = False
                    result['shutdown_failure'] = 'Engine did not exit cleanly'
                result['engine_exit_code'] = code
                result['process_reaped'] = True
            text = log.read_text(errors='replace') if log.exists() else ''
            for secret in secrets:
                if secret:
                    text = text.replace(secret, '[REDACTED]')
            text = re.sub(r'\b[a-fA-F0-9]{64}\b', '[REDACTED]', text)
            (report_dir / 'engine.log').write_text(text)
            pkg.dump(report_dir / 'smoke.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temp-root', type=Path, default=Path('/tmp'), help='Existing temporary storage outside project checkouts')
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = smoke(args)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
