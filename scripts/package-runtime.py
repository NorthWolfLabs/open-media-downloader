# /// script
# requires-python = ">=3.12"
# ///
"""Package explicit engine inputs; no desktop imports or developer runtime at use time."""
import argparse
from materials_contract import validate as validate_materials, sha as materials_sha, validate_native_receipt
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import zipfile

BINS = ('omd-engine', 'omd-plugin-worker-v2', 'omd-helper-guardian', 'omd-notify', 'omd-signin', 'omd', 'omd-mcp')
TARGETS = ('darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win32-x64', 'win32-arm64')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path, directory=False):
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        require(not part.is_symlink(), f'Symlink input: {part}')
    mode = path.stat().st_mode
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode), f'Invalid input type: {path}')
    return path


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and ':' not in value, 'Invalid relative path')
    p = PurePosixPath(value)
    require(not p.is_absolute() and all(x not in ('', '.', '..') for x in value.split('/')), 'Path escape')
    require(all(not x.endswith((' ', '.')) for x in p.parts), 'Nonportable path')
    return p


def source(parent, value):
    require(isinstance(value, str) and value, 'Missing source path')
    p = Path(value)
    require('..' not in p.parts, 'Source path escape')
    if not p.is_absolute():
        p = parent / relative(value)
    return regular(p)


def identity(path):
    with path.open('rb') as stream:
        require(stream.read(6) != b'OMDP2\0', f'Plugin package forbidden: {path.name}')
        stream.seek(0)
        return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'size': path.stat().st_size}


def digest(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value), 'Missing/invalid SHA-256')
    return value


def version(value):
    require(isinstance(value, str) and 0 < len(value) <= 100 and not any(ord(x) < 32 for x in value), 'Invalid version')
    return value


def load(path):
    return json.loads(regular(path).read_text())


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n')
    path.chmod(0o644)


SH = '''#!/bin/sh
set -eu
if [ "$#" -ne 2 ] || [ "$1" != --profile ]; then
  echo 'Usage: start-engine.sh --profile /absolute/profile' >&2; exit 2
fi
case "$2" in /*) ;; *) echo 'Profile must be absolute' >&2; exit 2;; esac
if [ -L "$2" ] || { [ -e "$2" ] && [ ! -d "$2" ]; }; then echo 'Profile must be a directory' >&2; exit 2; fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "$ROOT/bin/omd-engine" --profile "$2" --tools "$ROOT/tools/tools-v2.json" --browser-tools "$ROOT/browser/browser-tools-v2.json"
'''
CMD = '''@echo off\r
setlocal DisableDelayedExpansion\r
if not "%~1"=="--profile" exit /b 2\r
if "%~2"=="" exit /b 2\r
if not "%~3"=="" exit /b 2\r
if not "%~2"=="%~f2" exit /b 2\r
if exist "%~2" if not exist "%~2\\." exit /b 2\r
"%~dp0bin\\omd-engine.exe" --profile "%~2" --tools "%~dp0tools\\tools-v2.json" --browser-tools "%~dp0browser\\browser-tools-v2.json"\r
exit /b %errorlevel%\r
'''


def package(args):
    version(args.version)
    staging_mode = getattr(args, "staging_mode", "development")
    require(staging_mode in ("development", "release"), "Invalid staging mode")
    if staging_mode == "release":
        require(getattr(args, "materials", None) and getattr(args, "materials_locks", None), "Release staging requires materials and locks")
    require(args.target in TARGETS, 'Unsupported target')
    output = Path(os.path.abspath(args.output))
    output.parent.mkdir(parents=True, exist_ok=True)
    regular(output.parent, directory=True)
    require(not os.path.lexists(output), 'Refusing existing output')
    # The output is one exclusively-created container: runtime/, archive, report.
    output.mkdir()
    try:
        stage = output / 'runtime'
        stage.mkdir()
        entries = []
        provenance = []
        names = set()

        def copy(src, dest, expected=None, size=None, executable=False):
            src = regular(src)
            key = str(relative(dest)).casefold()
            require(key not in names, f'Duplicate output: {dest}')
            names.add(key)
            before = identity(src)
            if expected is not None:
                require(before['sha256'] == digest(expected), f'Integrity mismatch: {src}')
            if size is not None:
                require(type(size) is int and before['size'] == size, f'Size mismatch: {src}')
            dst = stage / dest
            dst.parent.mkdir(parents=True, exist_ok=True)
            with src.open('rb') as inp, dst.open('xb') as out:
                shutil.copyfileobj(inp, out)
            require(identity(dst) == before, f'Input changed during copy: {src}')
            mode = 0o755 if executable or src.stat().st_mode & 0o111 else 0o644
            dst.chmod(mode)
            entries.append({'path': dest, 'mode': mode, **before})
            provenance.append({'path': dest, 'source': str(src), **before})

        def generated(dest, value):
            dump(stage / dest, value)
            entries.append({'path': dest, 'mode': 0o644, **identity(stage / dest)})

        suffix = '.exe' if args.target.startswith('win32') else ''
        for name in BINS:
            src = regular(args.engine_bin / (name + suffix))
            if name == 'omd-plugin-worker-v2':
                require(b'OMD_WORKER_PROFILE=release' in src.read_bytes(), 'Optimized release worker required')
            copy(src, 'bin/' + name + suffix, executable=True)
        license_path = regular(args.license)
        require('MIT License' in license_path.read_text(), 'Project MIT license required')
        copy(license_path, 'LICENSE')
        tools = load(args.tools)
        bundled = {}
        for name in ('node', 'yt_dlp', 'ffmpeg', 'ffprobe'):
            tool = tools[name]
            version(tool['version'])
            src = source(args.tools.parent, tool['path'])
            dest = f'{name}/{src.name}'
            copy(src, 'tools/' + dest, digest(tool.get('sha256')), executable=True)
            bundled[name] = {'path': dest, 'version': tool['version'], 'sha256': tool['sha256']}
        generated('tools/tools-v2.json', bundled)
        browser = load(args.browser_tools)
        version(browser['version'])
        node = browser['node']
        require(node['sha256'] == tools['node']['sha256'] and node['version'] == tools['node']['version'], 'Browser/media Node mismatch')
        require(identity(source(args.browser_tools.parent, node['path']))['sha256'] == digest(node['sha256']), 'Browser Node hash mismatch')
        root = Path(browser['root'])
        if not root.is_absolute():
            root = args.browser_tools.parent / relative(browser['root'])
        root = regular(root, directory=True)
        files = browser['files']
        require(isinstance(files, dict) and 0 < len(files) <= 8192, 'Invalid browser inventory')
        for key in (browser['browser'], browser['adapter']):
            relative(key)
            require(key in files, 'Missing browser/adapter')
        actual = set()
        directories = 0
        total = 0
        for base, dirs, filenames in os.walk(root, followlinks=False):
            directories += len(dirs)
            require(directories <= 2048, 'Browser directory budget')
            for name in dirs:
                regular(Path(base) / name, directory=True)
            for name in filenames:
                src = Path(base) / name
                rel = src.relative_to(root).as_posix()
                relative(rel)
                require(rel in files, f'Unlisted browser file: {rel}')
                actual.add(rel)
                item = files[rel]
                require(type(item.get('bytes')) is int and item['bytes'] >= 0, 'Missing browser byte size')
                total += src.lstat().st_size
                require(total <= 2 * 1024**3, 'Browser byte budget')
                copy(src, 'browser/content/' + rel, digest(item.get('sha256')), item.get('bytes'))
        require(actual == set(files), 'Missing browser files')
        generated('browser/browser-tools-v2.json', {'root': 'content', 'version': browser['version'], 'browser': browser['browser'], 'adapter': browser['adapter'], 'files': files, 'node': {'version': node['version'], 'sha256': node['sha256'], 'path': '../tools/' + bundled['node']['path']}})
        supplements = load(args.supplements)
        require(isinstance(supplements, list) and 0 < len(supplements) <= 100, 'Explicit supplements required')
        for item in supplements:
            require(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', item['name']), 'Invalid supplement name')
            copy(source(args.supplements.parent, item['path']), 'third-party/' + item['name'], digest(item.get('sha256')))
        dump(output / 'build-inputs.json' , {'files': provenance, 'manifests': [{'source': str(regular(src)), **identity(src), 'contents': load(src)} for src in (args.tools, args.browser_tools, args.supplements)]})
        launcher = 'start-engine.cmd' if suffix else 'start-engine.sh'
        (stage / launcher).write_bytes((CMD if suffix else SH).encode())
        (stage / launcher).chmod(0o755)
        entries.append({'path': launcher, 'mode': 0o755, **identity(stage / launcher)})
        coverage = {'coverage_validated': False, 'release_accepted': False}
        if staging_mode == 'release':
            locks_root = regular(args.materials_locks, directory=True)
            locks = {name: identity(regular(locks_root / name))['sha256'] for name in ('Cargo.lock', 'browser-package-lock.json')}
            required = {name: {'version': args.version, 'prefix': 'bin/' + name + suffix} for name in BINS}
            required.update({name: {'version': tools[name]['version'], 'prefix': 'tools/' + name + '/'} for name in ('yt_dlp', 'ffmpeg', 'ffprobe', 'node')})
            required['browser'] = {'version': browser['version'], 'prefix': 'browser/content/'}
            require(locks['Cargo.lock'] == identity(Path(__file__).resolve().parent.parent / 'Cargo.lock')['sha256'], 'Stale engine Cargo lock')
            require(locks['browser-package-lock.json'] == identity(stage / 'browser/content/adapter/package-lock.json')['sha256'], 'Stale browser lock')
            triple = {'darwin-arm64': 'aarch64-apple-darwin', 'darwin-x64': 'x86_64-apple-darwin', 'linux-x64': 'x86_64-unknown-linux-gnu', 'linux-arm64': 'aarch64-unknown-linux-gnu', 'win32-x64': 'x86_64-pc-windows-msvc', 'win32-arm64': 'aarch64-pc-windows-msvc'}[args.target]
            validate_native_receipt(load(stage / 'third-party/native-receipt.json'), {x['path']: x['sha256'] for x in entries}, BINS, locks['Cargo.lock'], triple, regular(stage / 'third-party/native-NOTICES.txt').read_bytes(), args.version)
            coverage = validate_materials(load(args.materials), {x['path']: x['sha256'] for x in entries}, required, args.target, args.version, locks)
            copy(args.materials, 'third-party/materials-v1.json')
        inventory = {'format': 1, 'staging_mode': staging_mode, 'materials': coverage, 'target': args.target, 'version': args.version, 'worker_profile': 'release', 'plugins': [], 'assurance': 'Exact supplied hashes only; licensing and platform release acceptance remain separate.', 'files': sorted(entries, key=lambda x: x['path'])}
        dump(stage / 'runtime-inventory.json', inventory)
        modes = {item['path']: item['mode'] for item in entries}
        modes['runtime-inventory.json'] = 0o644
        (output / 'build-inputs.json').chmod(0o600)
        archive = output / ('omd-runtime.zip' if suffix else 'omd-runtime.tar.gz')
        if suffix:
            with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
                for p in sorted(stage.rglob('*')):
                    if p.is_file():
                        info = zipfile.ZipInfo(p.relative_to(stage).as_posix(), (1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | modes[p.relative_to(stage).as_posix()]) << 16
                        info.compress_type = zipfile.ZIP_DEFLATED
                        with p.open('rb') as inp, z.open(info, 'w') as out:
                            shutil.copyfileobj(inp, out)
        else:
            with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
                for p in sorted(stage.rglob('*')):
                    if p.is_file():
                        info = tar.gettarinfo(str(p), arcname=p.relative_to(stage).as_posix())
                        info.mode = modes[p.relative_to(stage).as_posix()]
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ''
                        with p.open('rb') as inp:
                            tar.addfile(info, inp)
        report = {'archive': archive.name, **identity(archive), 'inventory_sha256': identity(stage / 'runtime-inventory.json')['sha256'], 'target': args.target, 'version': args.version, 'release_accepted': False}
        dump(output / 'archive-report.json', report)
        return report
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('engine-bin', 'tools', 'browser-tools', 'license', 'supplements', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--target', choices=TARGETS, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--staging-mode', choices=('development', 'release'), default='development')
    p.add_argument('--materials', type=Path)
    p.add_argument('--materials-locks', type=Path)
    args = p.parse_args()
    print(json.dumps(package(args), indent=2))


if __name__ == '__main__':
    main()
