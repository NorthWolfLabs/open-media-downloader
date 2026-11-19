# /// script
# requires-python = ">=3.12"
# ///
"""Public engine build entry: the six optimized binaries with builder paths remapped.

rustc embeds source paths in panic locations, file!() and crate metadata. This entry
maps each builder root (engine checkout, Cargo target directory, CARGO_HOME, Rust
toolchain and its rust-src) to a stable logical prefix with --remap-path-prefix,
passed as CARGO_ENCODED_RUSTFLAGS so paths with spaces stay single arguments.
Windows MSVC builds also select the static C runtime to avoid a developer-only
VC runtime DLL prerequisite in the engine and private helper bridge. It
refuses ambient settings that would replace or bypass those flags, builds the locked
release binaries and refuses output that still contains a remapped root or the home
directory. Development builds use plain `cargo build` and are not remapped.
Signing, notarization and release acceptance remain separate steps.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ('omd-service', 'omd-plugin-worker-v2', 'omd-isolation', 'omd-notifications', 'omd-signin', 'omd-cli', 'omd-mcp')
BINS = ('omd-engine', 'omd-plugin-worker-v2', 'omd-helper-guardian', 'omd-notify', 'omd-signin', 'omd', 'omd-mcp')
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu',
           'x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')
LOGICAL = {'engine': '/omd/engine', 'target': '/omd/target', 'cargo-home': '/cargo', 'toolchain': '/rust/toolchain'}
WORKER_MARKER = b'OMD_WORKER_PROFILE=release'
# Ambient settings that would replace the remapping flags or the compiler that reads them.
OVERRIDES = re.compile(r'RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_RUSTFLAGS|CARGO_TARGET_\w+_RUSTFLAGS|CARGO_PROFILE_\w+_RUSTFLAGS'
                       r'|RUSTC|CARGO_BUILD_RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER')
CONFIG_KEYS = {'rustflags', 'rustc', 'rustc-wrapper', 'rustc-workspace-wrapper'}


def config_overrides(text):
    document = tomllib.loads(text)
    def walk(value):
        if isinstance(value, dict):
            return any(key in CONFIG_KEYS or walk(item) for key, item in value.items())
        return isinstance(value, list) and any(walk(item) for item in value)
    return walk(document)



def require(condition, message):
    if not condition:
        raise ValueError(message)


def overrides(env):
    return sorted(name for name in env if OVERRIDES.fullmatch(name))


def cargo_configs(start, cargo_home):
    """Cargo reads .cargo/config files in every ancestor of its working directory and in
    CARGO_HOME. Their rustflags would be silently ignored next to CARGO_ENCODED_RUSTFLAGS,
    and a compiler or wrapper setting would bypass the flags."""
    candidates = [d / '.cargo' / name for d in (Path(start), *Path(start).parents) for name in ('config', 'config.toml')]
    candidates += [Path(cargo_home) / name for name in ('config', 'config.toml')]
    found = []
    for file in candidates:
        try:
            text = file.read_text(encoding='utf-8')
        except (FileNotFoundError, NotADirectoryError):
            continue
        try:
            blocked = config_overrides(text)
        except tomllib.TOMLDecodeError:
            raise ValueError(f'Cannot parse Cargo configuration {file}; use valid TOML') from None
        found.append({'file': str(file), 'overrides': blocked})
    return found


def remap(roots, realpath=lambda p: os.path.realpath(p, strict=True)):
    """Ordered by host path length: rustc applies the last matching entry, so a nested
    root (such as the default target directory) overrides its parent. Canonical aliases
    of existing roots map to the same logical prefix."""
    by_host = {}
    for root in roots:
        role, host, logical = root['role'], root['host'], root['logical']
        require(isinstance(host, str) and os.path.isabs(host), f'The {role} path must be absolute')
        require(not re.search(r'[\x00-\x1f]', host), f'The {role} path contains a control character and cannot be passed to rustc')
        require(re.fullmatch(r'/[A-Za-z0-9._/-]+', logical) and '..' not in logical, f'Invalid logical prefix {logical}')
        hosts = [os.path.normpath(host)]
        try:
            canonical = realpath(hosts[0])
            if canonical != hosts[0]:
                hosts.append(canonical)
        except FileNotFoundError:
            pass
        for item in hosts:
            prior = by_host.get(item)
            require(not prior or prior['logical'] == logical, f'{item} cannot be both {prior and prior["role"]} and {role}')
            if not prior:
                by_host[item] = {'role': role, 'host': item, 'logical': logical, 'alias': item != hosts[0]}
    return sorted(by_host.values(), key=lambda entry: (len(entry['host']), entry['host']))


def encode(entries):
    # CARGO_ENCODED_RUSTFLAGS separates arguments with 0x1f; rustc splits FROM=TO at the last '='.
    return '\x1f'.join(f'--remap-path-prefix={entry["host"]}={entry["logical"]}' for entry in entries)


def toolchain(cwd, env):
    def rustc(*args):
        result = subprocess.run(['rustc', *args], cwd=cwd, env=env, capture_output=True, text=True)
        require(result.returncode == 0, f'rustc {" ".join(args)} failed: {result.stderr}')
        return result.stdout
    verbose, sysroot = rustc('-vV'), rustc('--print', 'sysroot').strip()
    commit = re.search(r'^commit-hash: ([0-9a-f]{40})$', verbose, re.M)
    require(commit and os.path.isabs(sysroot), 'rustc did not report its commit hash and sysroot')
    return {'verbose': verbose, 'sysroot': sysroot, 'commit': commit[1]}


def public_paths(engine, target_dir, cargo_home, tool, **options):
    return remap([
        {'role': 'engine', 'host': str(engine), 'logical': LOGICAL['engine']},
        {'role': 'target', 'host': str(target_dir), 'logical': LOGICAL['target']},
        {'role': 'cargo-home', 'host': str(cargo_home), 'logical': LOGICAL['cargo-home']},
        {'role': 'toolchain', 'host': tool['sysroot'], 'logical': LOGICAL['toolchain']},
        {'role': 'rust-src', 'host': os.path.join(tool['sysroot'], 'lib', 'rustlib', 'src', 'rust'), 'logical': f'/rustc/{tool["commit"]}'},
    ], **options)


def leaks(data, entries, home=str(Path.home())):
    """Exact host roots that must not remain in a public executable after remapping."""
    needles = list(dict.fromkeys([entry['host'] for entry in entries] + ([home] if home and len(home) > 1 else [])))
    return [{'host': needle, 'count': data.count(needle.encode())} for needle in needles if data.count(needle.encode())]


def digest(path):
    with open(path, 'rb') as f:
        return {'bytes': os.path.getsize(path), 'sha256': hashlib.file_digest(f, 'sha256').hexdigest()}


def plan(target, env, root=ROOT):
    require(target in TARGETS, f'Unsupported public engine target {target}; use one of {", ".join(TARGETS)}')
    names = overrides(env)
    require(not names, f'The public engine build sets its own Rust path remapping; unset {", ".join(names)}')
    # As given to Cargo (not canonicalized); remap() adds a canonical alias when it differs.
    cargo_home = Path(os.path.normpath(Path(root, env['CARGO_HOME']) if env.get('CARGO_HOME') else Path.home() / '.cargo'))
    configs = cargo_configs(root, cargo_home)
    blocked = [config['file'] for config in configs if config['overrides']]
    require(not blocked, f'Cargo configuration would replace or bypass the public path remapping; remove rustflags and rustc settings from {", ".join(blocked)}')
    # Cargo resolves CARGO_TARGET_DIR against its working directory, the engine root.
    target_dir = Path(root, env['CARGO_TARGET_DIR']) if env.get('CARGO_TARGET_DIR') else Path(root, 'target')
    tool = toolchain(root, {**env, 'CARGO_HOME': str(cargo_home), 'CARGO_TARGET_DIR': os.path.normpath(target_dir)})
    entries = public_paths(Path(root), Path(os.path.normpath(target_dir)), cargo_home, tool)
    command = ['cargo', 'build', '--locked', '--release', '--target', target, '--target-dir', os.path.normpath(target_dir)]
    for package in PACKAGES:
        command += ['-p', package]
    for binary in BINS:
        command += ['--bin', binary]
    return {'target': target, 'target_dir': os.path.normpath(target_dir), 'cargo_home': str(cargo_home), 'rustc': tool['verbose'], 'remap': entries,
            'cargo_config_files': [config['file'] for config in configs], 'command': command,
            'native_runtime': 'static-msvc-crt' if target.endswith('windows-msvc') else 'platform-default'}


def main(argv=None, env=None):
    env = dict(os.environ if env is None else env)
    parser = argparse.ArgumentParser(description='Build the six public engine binaries with builder paths remapped.')
    parser.add_argument('--target', required=True)
    parser.add_argument('--output', type=Path, help='new absolute directory for bin/ and build-report.json')
    parser.add_argument('--jobs', type=int, help='Cargo parallel jobs')
    parser.add_argument('--check', action='store_true', help='validate inputs and print the remapping plan without building')
    args = parser.parse_args(argv)
    require(args.check or (args.output and args.output.is_absolute() and not os.path.lexists(args.output)), 'Use --output with a new absolute directory, or --check')
    require(args.jobs is None or 1 <= args.jobs <= 64, '--jobs must be between 1 and 64')
    report = {'schema': 'omd-public-engine-build-v1', 'status': 'checked', 'release_accepted': False, **plan(args.target, env),
              'limits': 'Covers paths rustc derives from source locations under these roots; literal strings and linker inputs are checked after the build, not rewritten.'}
    if args.jobs:
        report['command'] += ['--jobs', str(args.jobs)]
    if not args.check:
        build = subprocess.run(report['command'], cwd=ROOT, env={**env, 'CARGO_HOME': report['cargo_home'], 'CARGO_TARGET_DIR': report['target_dir'], 'CARGO_ENCODED_RUSTFLAGS': encode(report['remap']) + ('\x1f-C\x1ftarget-feature=+crt-static' if args.target.endswith('windows-msvc') else '')})
        require(build.returncode == 0, f'cargo build failed ({build.returncode})')
        suffix = '.exe' if 'windows' in args.target else ''
        built = {name: Path(report['target_dir'], args.target, 'release', name + suffix) for name in BINS}
        found = {name: leaks(path.read_bytes(), report['remap']) for name, path in built.items()}
        found = {name: value for name, value in found.items() if value}
        require(not found, f'Built binaries still contain builder paths: {json.dumps(found)}')
        require(WORKER_MARKER in built['omd-plugin-worker-v2'].read_bytes(), 'The plugin worker is not an optimized release build')
        (args.output / 'bin').mkdir(parents=True)
        for name, path in built.items():
            shutil.copy2(path, args.output / 'bin' / path.name)
        report.update(status='built', worker_profile='release', builder_paths=0,
                      binaries={path.name: digest(args.output / 'bin' / path.name) for path in built.values()})
        with open(args.output / 'build-report.json', 'x') as f:
            f.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2, sort_keys=True))
    except ValueError as error:
        print(error, file=sys.stderr)
        sys.exit(2)
