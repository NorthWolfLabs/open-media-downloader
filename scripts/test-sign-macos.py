# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Signing workflow tests. Native cases compile tiny fixtures and sign only new
temporary copies ad-hoc. No identity, keychain, network, GUI or real app is used."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import platform
import plistlib
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import macos_signing as signing
from materials_contract import validate_native_receipt

NATIVE = platform.system() == 'Darwin' and shutil.which('xcrun') is not None and Path('/usr/bin/codesign').exists()
TOOLCHAIN = 'rustc 1.0.0 (synthetic)\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.0.0'
ENGINE = ['omd-engine', 'omd-plugin-worker-v2', 'omd-helper-guardian', 'omd-notify', 'omd-signin', 'omd']
EXE = 'open-media-downloader-desktop'
RES = 'Contents/Resources/resources/v2'
DIST = ['rust-std-1.0.0-aarch64-apple-darwin', 'rustc-1.0.0-aarch64-apple-darwin']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*argv):
    subprocess.run([str(x) for x in argv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def js(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def scratch(test):
    folder = Path(tempfile.mkdtemp(prefix='omd-sign-test-')).resolve()
    test.addCleanup(shutil.rmtree, folder, True)
    return folder


class Native:
    """Compiled once: plain executable, release-marked worker, dylib, unsigned bootloader."""
    root = None

    @classmethod
    def get(cls):
        if cls.root is None:
            root = Path(tempfile.mkdtemp(prefix='omd-sign-native-')).resolve()
            (root / 'main.c').write_text('int main(void) { return 0; }\n')
            (root / 'worker.c').write_text('#include <stdio.h>\nconst char *marker = "OMD_WORKER_PROFILE=release";\nint main(void) { return puts(marker) < 0; }\n')
            (root / 'lib.c').write_text('int fixture_value(void) { return 7; }\n')
            cc = ['xcrun', 'clang', '-O0', '-mmacosx-version-min=13.0']
            run(*cc, '-arch', 'arm64', '-o', root / 'exe', root / 'main.c')
            run(*cc, '-arch', 'arm64', '-o', root / 'worker', root / 'worker.c')
            run(*cc, '-arch', 'arm64', '-dynamiclib', '-o', root / 'lib.dylib', root / 'lib.c')
            run(*cc, '-arch', 'x86_64', '-o', root / 'exe-x86_64', root / 'main.c')
            run('/usr/bin/codesign', '--force', '--sign', '-', root / 'exe-x86_64')
            run(*cc, '-arch', 'arm64', '-Wl,-no_adhoc_codesign', '-o', root / 'boot', root / 'main.c')
            cls.root = root
        return cls.root

    @classmethod
    def extractor(cls, out, data=b'fixture data', library=None, extra=()):
        """A real PyInstaller-layout onefile: bootloader plus CArchive inside __LINKEDIT.
        `extra` entries are (name, source path or link target, compress, typecode)."""
        from PyInstaller.archive.writers import CArchiveWriter
        from PyInstaller.utils.osx import fix_exe_for_code_signing
        root = cls.get()
        work = Path(tempfile.mkdtemp(prefix='omd-extractor-', dir=out.parent))
        (work / 'data.txt').write_bytes(data)
        CArchiveWriter(str(work / 'pkg'), [('libfixture.dylib', str(library or root / 'lib.dylib'), True, 'b'), ('fixture.txt', str(work / 'data.txt'), True, 'x'),
                                           *[(n, str(work / 'data.txt') if s is None else str(s), c, t) for n, s, c, t in extra]], 'Python')
        out.write_bytes((root / 'boot').read_bytes() + (work / 'pkg').read_bytes())
        shutil.rmtree(work)
        fix_exe_for_code_signing(str(out))
        run('/usr/bin/codesign', '--force', '--sign', '-', out)
        out.chmod(0o755)
        return out


def segment(data, name):
    endian, _, _, _, commands = signing.load_commands(data)
    return endian, next(off for cmd, off, _ in commands if cmd == 0x19 and data[off + 8:off + 24].rstrip(b'\0') == name)


def flip_code(data):
    """Corrupt one instruction byte in __TEXT,__text; signature metadata is untouched."""
    endian, seg = segment(data, b'__TEXT')
    for i in range(struct.unpack_from(endian + 'I', data, seg + 64)[0]):
        section = seg + 72 + 80 * i
        if data[section:section + 16].rstrip(b'\0') == b'__text':
            out = bytearray(data)
            out[struct.unpack_from(endian + 'I', data, section + 48)[0]] ^= 0xff
            return bytes(out)
    raise AssertionError('no __text section')


def forge_team_signature(data, team):
    """Rewrite a thin ad-hoc signature so parsed metadata claims `team`, no ad-hoc
    flag and a CMS blob. No certificate exists: only metadata parsing is fooled."""
    endian, _, _, _, commands = signing.load_commands(data)
    at = next(off for cmd, off, _ in commands if cmd == 0x1d)
    dataoff, _ = struct.unpack_from(endian + 'II', data, at + 8)
    blob = data[dataoff:]
    _, _, count = struct.unpack_from('>III', blob, 0)
    slots = []
    for i in range(count):
        kind, offset = struct.unpack_from('>II', blob, 12 + 8 * i)
        slots.append((kind, blob[offset:offset + struct.unpack_from('>I', blob, offset + 4)[0]]))
    directory = bytearray(dict(slots)[0])
    assert struct.unpack_from('>I', directory, 8)[0] >= 0x20200
    struct.pack_into('>I', directory, 12, struct.unpack_from('>I', directory, 12)[0] & ~0x20002)
    struct.pack_into('>I', directory, 48, len(directory))
    directory += team.encode() + b'\0'
    struct.pack_into('>I', directory, 4, len(directory))
    slots = [(k, bytes(directory) if k == 0 else b) for k, b in slots] + [(0x10000, struct.pack('>II', 0xfade0b01, 72) + b'\x5a' * 64)]
    index, body, offset = b'', b'', 12 + 8 * len(slots)
    for kind, b in slots:
        index, body, offset = index + struct.pack('>II', kind, offset), body + b, offset + len(b)
    superblob = struct.pack('>III', 0xfade0cc0, offset, len(slots)) + index + body
    size = -(-len(superblob) // 16) * 16
    out = bytearray(data[:dataoff] + superblob + b'\0' * (size - len(superblob)))
    struct.pack_into(endian + 'I', out, at + 12, size)
    _, seg = segment(data, b'__LINKEDIT')
    _, vmsize, fileoff, _ = struct.unpack_from(endian + 'QQQQ', out, seg + 24)
    struct.pack_into(endian + 'Q', out, seg + 48, dataoff + size - fileoff)
    struct.pack_into(endian + 'Q', out, seg + 32, max(vmsize, -(-(dataoff + size - fileoff) // 0x4000) * 0x4000))
    return bytes(out)


class Receipts:
    """Exact synthetic native scopes driven through the real generator."""

    def __init__(self, root, version='1.0.0'):
        self.root, self.metadata, self.base = root, {}, {}
        for kind, name, bins in (('engine', 'omd-fixture-engine', ENGINE), ('desktop', EXE, [EXE])):
            project = root / kind / 'project'
            project.mkdir(parents=True)
            (project / 'Cargo.toml').write_text('fixture')
            (project / 'Cargo.lock').write_text(f'# {kind} fixture lock\n')
            (project / 'LICENSE').write_bytes(f'{kind} first-party MIT fixture terms'.encode())
            self.metadata[str(project / 'Cargo.toml')] = {
                'packages': [{'id': 'root', 'name': name, 'version': version, 'manifest_path': str(project / 'Cargo.toml'), 'source': None,
                              'license': 'MIT', 'targets': [{'name': b, 'kind': ['bin']} for b in bins]}],
                'resolve': {'nodes': [{'id': 'root', 'dependencies': [], 'features': []}]}}
            base = root / kind / 'review-base'
            for prefix in DIST:
                path = base / 'dist' / (prefix + '.tar.gz')
                path.parent.mkdir(parents=True, exist_ok=True)
                with tarfile.open(path, 'w:gz') as tar:
                    for member, data in {'COPYRIGHT': f'{kind} synthetic runtime copyright'.encode()}.items():
                        info = tarfile.TarInfo(prefix + '/' + member)
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
            (base / 'notices').mkdir()
            (base / 'notices/COPYRIGHT').write_bytes(f'{kind} synthetic runtime copyright'.encode())
            self.base[kind] = base
        self.features = {'engine': '', 'desktop': 'v2'}

    def manifest(self, kind):
        return self.root / kind / 'project/Cargo.toml'

    def section(self, kind, review=None, binaries=None):
        return {'manifest': str(self.manifest(kind)), 'roots': ['omd-fixture-engine' if kind == 'engine' else EXE],
                'binaries': binaries or (list(ENGINE) if kind == 'engine' else [EXE]), 'features': self.features[kind],
                'upstream_materials': None, 'review': str(review or self.base[kind] / 'review.json')}

    def fake(self, cmd, **_):
        if cmd[0] == 'rustc':
            return TOOLCHAIN
        return json.dumps(self.metadata[cmd[cmd.index('--manifest-path') + 1]]).encode()

    def patched(self):
        return mock.patch.object(signing.generator().subprocess, 'check_output', side_effect=self.fake)

    def entry(self, which, rel, **extra):
        data = (self.base[which] / rel).read_bytes()
        return {'path': rel, 'sha256': digest(data), 'bytes': len(data), **extra}

    def review(self, kind, artifacts):
        """Prior review bound to the given (pre-signature) artifacts."""
        with self.patched():
            out = Path(tempfile.mkdtemp(dir=self.root)) / 'scope'
            signing.run_generator(kind, self.section(kind), 'aarch64-apple-darwin', artifacts, out)
        scope = json.loads((out / 'review-scope.json').read_text())
        url = 'https://static.rust-lang.org/dist/{}.tar.gz'
        review = {'schema': 'omd-native-review-v1', 'scope': scope, 'findings': [{
            'id': 'rust-runtime', 'category': 'toolchain-runtime', 'subject': {'toolchain': TOOLCHAIN},
            'facts': ['Attribution matches the exact official distribution'], 'limits': ['Historical link inputs are not reconstructed'],
            'evidence': [self.entry(kind, f'dist/{p}.tar.gz', role='distribution-archive', url=url.format(p)) for p in DIST],
            'materials': [self.entry(kind, 'notices/COPYRIGHT', kind='attribution', reason='Runtime attribution',
                                     origin={'type': 'archive-member', 'archive': f'dist/{DIST[0]}.tar.gz', 'member': f'{DIST[0]}/COPYRIGHT'})]}]}
        (self.base[kind] / 'review.json').write_bytes(js(review))
        return self.base[kind] / 'review.json'

    def reviewed(self, kind, artifacts):
        with self.patched():
            out = Path(tempfile.mkdtemp(dir=self.root)) / 'reviewed'
            self_code = signing.run_generator(kind, self.section(kind), 'aarch64-apple-darwin', artifacts, out, self.base[kind] / 'review.json')
        assert self_code == 0
        return (out / 'receipt.json').read_bytes(), (out / 'native-NOTICES.txt').read_bytes()

    def config(self, path, engine_binaries=None):
        path.write_bytes(js({'schema': signing.RECEIPTS_SCHEMA, 'target': 'aarch64-apple-darwin', 'version': '1.0.0',
                             'engine': self.section('engine', binaries=engine_binaries), 'desktop': self.section('desktop')}))
        return path


def build_app(root, *, receipts=None, mutate=None, minimum='13.5', staging='development', extractor=None):
    """A synthetic app with the current public plugin-free Tauri resource layout."""
    native = Native.get()
    app = root / 'Fixture.app'
    resources = {}

    def put(rel, data, executable=False):
        path = app / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if executable else 0o644)

    def res(rel, data, executable=False):
        put(RES + '/' + rel, data, executable)
        resources[rel] = data

    exe, worker, lib = (native / 'exe').read_bytes(), (native / 'worker').read_bytes(), (native / 'lib.dylib').read_bytes()
    put('Contents/MacOS/' + EXE, exe, True)
    put('Contents/Info.plist', plistlib.dumps({'CFBundleExecutable': EXE, 'CFBundleIdentifier': 'labs.northwolf.omd-fixture', 'CFBundleIconFile': 'icon.icns',
                                               'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '1.0.0', 'LSMinimumSystemVersion': minimum}))
    put('Contents/Resources/icon.icns', b'icns fixture')
    res('LICENSE', b'MIT fixture terms\n')
    for name in ENGINE:
        res('bin/' + name, worker if name == 'omd-plugin-worker-v2' else exe, True)
    for name in ('node', 'ffmpeg', 'ffprobe'):
        res(f'tools/{name}/{name}', exe, True)
    extractor_bytes = (extractor or Native.extractor(root / 'producer-yt-dlp')).read_bytes()
    res('tools/yt_dlp/yt-dlp_macos', extractor_bytes, True)
    tools = {'yt_dlp': {'path': 'yt_dlp/yt-dlp_macos', 'sha256': digest(extractor_bytes), 'version': '2026.08.19'},
             'ffmpeg': {'path': 'ffmpeg/ffmpeg', 'version': '9.0.1', 'sha256': digest(exe)},
             'ffprobe': {'path': 'ffprobe/ffprobe', 'version': '9.0.1', 'sha256': digest(exe)},
             'node': {'path': 'node/node', 'sha256': digest(exe), 'version': '24.20.0'}}
    res('tools/tools-v2.json', js(tools))
    browser = {'adapter/adapter.mjs': b'export {}\n', 'adapter/package.json': b'{"name":"fixture-adapter"}\n', 'browser/chrome-headless-shell': exe,
               'browser/ABOUT': b'fixture browser\n', **{f'browser/{n}.dylib': lib for n in ('libEGL', 'libGLESv2', 'libvk_swiftshader', 'libvulkan')}}
    for rel, data in browser.items():
        res('browser/content/' + rel, data, rel.endswith('shell'))
    res('browser/browser-tools-v2.json', js({'adapter': 'adapter/adapter.mjs', 'browser': 'browser/chrome-headless-shell',
                                             'files': {rel: {'bytes': len(d), 'sha256': digest(d)} for rel, d in browser.items()},
                                             'node': {'path': '../tools/node/node', 'sha256': digest(exe), 'version': '24.20.0'},
                                             'root': 'content', 'version': 'fixture-browser'}))
    if receipts:
        res('third-party/native-receipt.json', receipts['engine'][0])
        res('third-party/native-NOTICES.txt', receipts['engine'][1])
        res('third-party/desktop-native-NOTICES.txt', receipts['desktop_notices'])
    else:
        res('third-party/native-NOTICES.txt', b'stub notices\n')
        res('third-party/native-receipt.json', js({'schema': 'omd-native-notices-v2', 'binaries': ENGINE, 'artifacts': []}))
    inventory = {'platform': 'darwin', 'arch': 'arm64', 'build_host': {'platform': 'darwin', 'arch': 'arm64'},
                 'files': [{'path': rel, 'sha256': digest(d), 'size': len(d)} for rel, d in resources.items()],
                 'worker_profile': 'release', 'plugins': {'mode': 'public', 'publishable': True, 'packages': []},
                 'staging_mode': staging, 'release_accepted': False, 'materials': {'coverage_validated': False}}
    put(RES + '/build-inventory.json', js(inventory))
    if mutate:
        mutate(app)
    run('/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime', app)
    return app


def reinventory(app, change=None):
    """Re-record the build inventory after a deliberate fixture mutation."""
    path = app / RES / 'build-inventory.json'
    inventory = json.loads(path.read_text())
    files = {p.relative_to(app / RES).as_posix(): p.read_bytes() for p in sorted((app / RES).rglob('*')) if p.is_file() and not p.is_symlink() and p.name != 'build-inventory.json'}
    inventory['files'] = [{'path': rel, 'sha256': digest(d), 'size': len(d)} for rel, d in files.items()]
    if change:
        change(inventory)
    path.write_bytes(js(inventory))


def add_browser_file(app, rel, data, executable=False):
    path = app / RES / 'browser/content' / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755 if executable else 0o644)
    manifest_path = app / RES / 'browser/browser-tools-v2.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['files'][rel] = {'bytes': len(data), 'sha256': digest(data)}
    manifest_path.write_bytes(js(manifest))
    reinventory(app)


def request(app, mode='development-adhoc', identity='-', team=None, **extra):
    return {'app': str(app), 'mode': mode, 'identity': identity, 'team_id': team, 'arch': 'arm64', 'prepared_extractor': None,
            'receipts': None, 'expected_inventory': None, **extra}


def write_plan(folder, plan, name='plan.json'):
    path = folder / name
    signing.write_new(path, signing.json_bytes(plan))
    return path


class PolicyAndIdentity(unittest.TestCase):
    def test_identity_mode_combinations(self):
        signing.check_identity('development-adhoc', '-', None)
        signing.check_identity('developer-id', 'Developer ID Application: Example Labs (ABCDE12345)', 'ABCDE12345')
        signing.check_identity('developer-id', 'A' * 40, 'ABCDE12345')
        for mode, identity, team in [('development-adhoc', 'Developer ID Application: Example Labs (ABCDE12345)', None),
                                     ('development-adhoc', '-', 'ABCDE12345'), ('developer-id', '-', 'ABCDE12345'),
                                     ('developer-id', 'Apple Development: someone (ABCDE12345)', 'ABCDE12345'),
                                     ('developer-id', 'Developer ID Installer: Example Labs (ABCDE12345)', 'ABCDE12345'),
                                     ('developer-id', 'Developer ID Application: Example Labs (ABCDE12345)', 'ZZZZZ99999'),
                                     ('developer-id', 'Developer ID Application: Example Labs (ABCDE12345)', None),
                                     ('developer-id', 'Example Labs', 'ABCDE12345'), ('release', '-', None)]:
            with self.subTest(mode=mode, identity=identity, team=team), self.assertRaises(ValueError):
                signing.check_identity(mode, identity, team)

    def test_policy_is_role_specific_and_closed(self):
        policy, identity = signing.load_policy()
        grants = {r['path']: r['entitlements'] for r in policy['roles'] if r['entitlements']}
        self.assertEqual(grants, {'{resources}/bin/omd-plugin-worker-v2': {'com.apple.security.cs.allow-unsigned-executable-memory': True},
                                  '{resources}/tools/node/node': {'com.apple.security.cs.allow-jit': True},
                                  '{resources}/browser/content/browser/chrome-headless-shell': {'com.apple.security.cs.allow-jit': True}})
        self.assertEqual(identity['path'], 'distribution/macos-signing-policy.json')
        original = json.loads(signing.POLICY_PATH.read_text())
        folder = scratch(self)

        def broken(change, why):
            data = copy.deepcopy(original)
            change(data)
            path = folder / f'policy-{why[:12].replace(" ", "-")}.json'
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, why):
                signing.load_policy(path)
        broken(lambda p: p['roles'][1]['entitlements'].update({'com.apple.security.cs.disable-library-validation': True}), 'Unreviewed entitlement')
        broken(lambda p: p['roles'][1]['entitlements'].update({'com.apple.security.get-task-allow': True}), 'Unreviewed entitlement')
        broken(lambda p: p['roles'][1]['entitlements'].update({'com.apple.security.cs.allow-jit': False}), 'explicit true')
        broken(lambda p: p['roles'][-1]['entitlements'].update({'com.apple.security.cs.allow-jit': True}), 'Libraries cannot')
        broken(lambda p: p['roles'].append(dict(p['roles'][2])), 'Duplicate signing role path')
        broken(lambda p: p['reviewed_entitlements'].append('com.apple.security.get-task-allow'), 'overlap')
        broken(lambda p: p['roles'][2].update(basis=' '), 'reviewed basis')
        broken(lambda p: p.update(extra=True), 'Invalid signing policy fields')

    def test_path_folding_and_inventory_collisions(self):
        self.assertTrue(signing.within('/X/Out.app/Contents', '/x/out.app'))
        self.assertTrue(signing.within('/x/café.app', '/x/café.app'))
        self.assertFalse(signing.within('/x/out.application', '/x/out.app'))
        actual = {'LICENSE': {'bytes': 1, 'sha256': '0' * 64}}
        base = {'platform': 'darwin', 'arch': 'arm64', 'worker_profile': 'release', 'release_accepted': False, 'staging_mode': 'development',
                'plugins': {'mode': 'public', 'publishable': True, 'packages': []}, 'files': [{'path': 'LICENSE', 'sha256': '0' * 64, 'size': 1}]}
        signing.check_build_inventory(json.dumps(base), actual, 'arm64')
        for change, why in [(lambda i: i['files'].append({'path': 'license', 'sha256': '0' * 64, 'size': 1}), 'Duplicate'),
                            (lambda i: i['files'].append({'path': '../escape', 'sha256': '0' * 64, 'size': 1}), 'unsafe relative'),
                            (lambda i: i['files'].append({'path': '/abs', 'sha256': '0' * 64, 'size': 1}), 'unsafe relative'),
                            (lambda i: i['files'].append({'path': 'a\\b', 'sha256': '0' * 64, 'size': 1}), 'unsafe relative'),
                            (lambda i: i['files'].append({'path': 'providers/x.omdp', 'sha256': '0' * 64, 'size': 1}), 'Unexpected build inventory member'),
                            (lambda i: i['plugins']['packages'].append({'name': 'starter'}), 'plugin-free'),
                            (lambda i: i.update(signing={}), 'already processed'),
                            (lambda i: i.update(arch='x86_64'), 'architecture'),
                            (lambda i: i.update(worker_profile='debug'), 'release worker'),
                            (lambda i: i.update(release_accepted=True), 'release_accepted')]:
            data = copy.deepcopy(base)
            change(data)
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.check_build_inventory(json.dumps(data), actual, 'arm64')
        with self.assertRaisesRegex(ValueError, 'Duplicate key'):
            signing.check_build_inventory(json.dumps(base).replace('"arch": "arm64"', '"arch": "arm64", "arch": "arm64"'), actual, 'arm64')

    def test_runner_refuses_credential_and_notary_tools(self):
        runner = signing.Runner(Path(tempfile.gettempdir()))
        for tool in ('/usr/bin/security', '/usr/bin/xcrun', 'notarytool'):
            with self.subTest(tool), self.assertRaisesRegex(ValueError, 'outside this workflow'):
                runner([tool, 'find-identity'], label='forbidden')
        self.assertEqual(runner.records, [])

    def test_developer_id_command_shape(self):
        obj = {'hardened_runtime': True, 'action': 'sign', 'identifier': 'labs.example.app.node', 'entitlements': {'com.apple.security.cs.allow-jit': True}}
        argv = signing.sign_argv('Developer ID Application: Example Labs (ABCDE12345)', 'developer-id', obj, Path('/w/e.plist'), Path('/o/node'))
        self.assertEqual(argv, ['/usr/bin/codesign', '--force', '--sign', 'Developer ID Application: Example Labs (ABCDE12345)', '--options', 'runtime',
                                '--timestamp', '--identifier', 'labs.example.app.node', '--entitlements', '/w/e.plist', '/o/node'])
        library = signing.sign_argv('-', 'development-adhoc', {**obj, 'hardened_runtime': False, 'entitlements': {}}, None, Path('/o/lib.dylib'))
        self.assertEqual(library, ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'labs.example.app.node', '/o/lib.dylib'])
        outer = signing.sign_argv('-', 'development-adhoc', {**obj, 'action': 'outer-bundle', 'entitlements': {}}, None, Path('/o/A.app'))
        self.assertNotIn('--identifier', outer)
        self.assertNotIn('--deep', outer + argv + library)


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class Inspection(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)

    def test_nonexecutable_code_role_rejected_without_byte_changes(self):
        app = build_app(self.root)
        node = app / RES / 'tools/node/node'
        before = signing.inventory_of(app)
        node.chmod(0o644)
        self.assertEqual(signing.inventory_of(app), before)
        with self.assertRaisesRegex(ValueError, 'lacks owner execute permission'):
            signing.inspect(request(app))

    def test_current_layout_classification_and_blockers(self):
        app = build_app(self.root)
        plan = signing.inspect(request(app))
        roles = {o['path'].removeprefix(RES + '/'): (o['role'], o['action'], o['entitlements']) for o in plan['code_objects']}
        self.assertEqual(len(roles), 16)
        self.assertEqual(roles['bin/omd-plugin-worker-v2'], ('plugin-worker', 'sign', {'com.apple.security.cs.allow-unsigned-executable-memory': True}))
        self.assertEqual(roles['tools/node/node'][2], {'com.apple.security.cs.allow-jit': True})
        self.assertEqual(roles['browser/content/browser/chrome-headless-shell'][2], {'com.apple.security.cs.allow-jit': True})
        self.assertEqual(roles['tools/yt_dlp/yt-dlp_macos'][:2], ('yt-dlp', 'retain'))
        self.assertEqual(roles['Contents/MacOS/' + EXE], ('desktop-shell', 'outer-bundle', {}))
        for rel in ('bin/omd', 'bin/omd-engine', 'bin/omd-helper-guardian', 'bin/omd-notify', 'bin/omd-signin', 'tools/ffmpeg/ffmpeg', 'tools/ffprobe/ffprobe'):
            self.assertEqual(roles[rel][2], {}, rel)
        order = [o['path'] for o in plan['code_objects']]
        dylibs = [i for i, p in enumerate(order) if p.endswith('.dylib')]
        self.assertLess(max(dylibs), order.index(RES + '/browser/content/browser/chrome-headless-shell'))
        self.assertEqual(order[-1], 'Contents/MacOS/' + EXE)
        self.assertTrue(all(not o['hardened_runtime'] for o in plan['code_objects'] if o['path'].endswith('.dylib')))
        ids = {b['id']: b['severity'] for b in plan['blockers']}
        self.assertEqual(ids, {'prepared-extractor-missing': 'release', 'receipts-not-configured': 'release'})
        self.assertTrue(plan['ready_for_execution'])
        self.assertFalse(plan['release_accepted'] or plan['notarized'] or plan['developer_id_signed'])
        self.assertIn('not representative', ' '.join(plan['mode_limits']))
        self.assertEqual(plan['checks']['payload_minimum']['packed_components'], 1)
        expected = self.root / 'expected.json'
        expected.write_bytes(js(signing.inventory_of(app)))
        signing.inspect(request(app, expected_inventory={'path': str(expected), 'sha256': digest(expected.read_bytes())}))
        changed = signing.inventory_of(app)
        changed['Contents/Info.plist']['sha256'] = '0' * 64
        expected.write_bytes(js(changed))
        with self.assertRaisesRegex(ValueError, 'expected exact inventory'):
            signing.inspect(request(app, expected_inventory={'path': str(expected), 'sha256': digest(expected.read_bytes())}))

    def test_developer_id_mode_blocks_development_staging_and_unprepared_extractor(self):
        app = build_app(self.root)
        plan = signing.inspect(request(app, 'developer-id', 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345'))
        ids = {b['id']: b['severity'] for b in plan['blockers']}
        self.assertEqual(ids, {'development-staging': 'signing', 'prepared-extractor-missing': 'signing', 'receipts-not-configured': 'signing'})
        self.assertFalse(plan['ready_for_execution'])
        extractor = next(o for o in plan['code_objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(extractor['action'], 'stop')
        self.assertEqual(extractor['packed']['images_by_team'], {'none': 1})

    def test_links_special_files_and_hard_links_reject(self):
        def link_file(app):
            (app / RES / 'third-party/linked.txt').symlink_to(app / RES / 'LICENSE')
        def link_dir(app):
            (app / 'Contents/Frameworks').symlink_to(self.root)
        def fifo(app):
            os.mkfifo(app / RES / 'third-party/pipe')
        def hard(app):
            os.link(app / RES / 'LICENSE', app / RES / 'third-party/LICENSE-copy')
        for index, (mutate, why) in enumerate([(link_file, 'Symlink in bundle'), (link_dir, 'Symlink in bundle'), (fifo, 'Special file'), (hard, 'Hard-linked')]):
            with self.subTest(why):
                folder = self.root / f'link-{index}'
                folder.mkdir()
                app = build_app(folder)
                mutate(app)
                with self.assertRaisesRegex(ValueError, why):
                    signing.inspect(request(app))
        linked = self.root / 'linked-parent'
        linked.symlink_to(self.root / 'link-0')
        with self.assertRaisesRegex(ValueError, 'Symlink path component'):
            signing.inspect(request(linked / 'Fixture.app'))

    def test_inventory_and_public_package_escapes_reject(self):
        cases = [
            (lambda app: (app / RES / 'third-party/extra.txt').write_text('uninventoried'), 'differ from the build inventory'),
            (lambda app: (app / RES / 'LICENSE').write_text('changed after staging'), 'changed after staging'),
            (lambda app: (app / 'Contents/Resources/extra.txt').write_text('outside resources'), 'Unexpected bundle members'),
            (lambda app: ((app / RES / 'third-party/LICENSE-plugin.txt').write_bytes(b'OMDP2\0' + b'\x00' * 8), reinventory(app)), 'Plugin package'),
            (lambda app: ((app / RES / 'providers').mkdir(), (app / RES / 'providers/p.txt').write_text('x'), reinventory(app)), 'Unexpected build inventory member'),
            (lambda app: reinventory(app, lambda i: i['plugins']['packages'].append({'name': 'starter'})), 'plugin-free'),
            (lambda app: reinventory(app, lambda i: i['files'].append({'path': '../escape.txt', 'sha256': '0' * 64, 'size': 0})), 'unsafe relative'),
            (lambda app: (app / RES / 'tools/tools-v2.json').write_text(json.dumps({'node': {}})), 'changed after staging'),
        ]
        for index, (mutate, why) in enumerate(cases):
            with self.subTest(why):
                folder = self.root / f'case-{index}'
                folder.mkdir()
                app = build_app(folder, mutate=mutate)
                with self.assertRaisesRegex(ValueError, why):
                    signing.inspect(request(app))

    def test_unexpected_and_misclassified_code(self):
        native = Native.get()
        exe = (native / 'exe').read_bytes()
        (self.root / 'stray').mkdir()
        app = build_app(self.root / 'stray', mutate=lambda app: add_browser_file(app, 'adapter/node_modules/.bin/node', exe, True))
        plan = signing.inspect(request(app))
        stray = next(o for o in plan['code_objects'] if o['path'].endswith('node_modules/.bin/node'))
        self.assertEqual((stray['role'], stray['action']), ('unrecognized', 'stop'))
        self.assertNotIn('entitlements', stray)
        self.assertFalse(plan['ready_for_execution'])
        self.assertIn('unrecognized-code', [b['id'] for b in plan['blockers']])

        def node_points_at_ffmpeg(app):
            path = app / RES / 'tools/tools-v2.json'
            tools = json.loads(path.read_text())
            tools['node']['path'] = 'ffmpeg/ffmpeg'
            path.write_bytes(js(tools))
            reinventory(app)

        def dylib_as_engine(app):
            shutil.copyfile(native / 'lib.dylib', app / RES / 'bin/omd-notify')
            reinventory(app)

        def debug_worker(app):
            shutil.copyfile(native / 'exe', app / RES / 'bin/omd-plugin-worker-v2')
            reinventory(app)

        def intel_shell(app):
            shutil.copyfile(native / 'exe-x86_64', app / 'Contents/MacOS' / EXE)

        def missing_role(app):
            (app / RES / 'browser/content/browser/libvulkan.dylib').write_bytes(b'not code')
            add_browser_file(app, 'browser/libvulkan.dylib', b'not code')

        for index, (mutate, why) in enumerate([(node_points_at_ffmpeg, 'not at its reviewed role path'), (dylib_as_engine, 'type differs'),
                                               (debug_worker, 'marker'), (intel_shell, 'missing compatible arm64'), (missing_role, 'Missing reviewed code objects')]):
            with self.subTest(why):
                folder = self.root / f'mis-{index}'
                folder.mkdir()
                with self.assertRaisesRegex(ValueError, why):
                    signing.inspect(request(build_app(folder, mutate=mutate)))

    def test_declared_minimum_below_payload_blocks(self):
        plan = signing.inspect(request(build_app(self.root, minimum='12.0')))
        self.assertIn(('payload-minimum', 'signing'), [(b['id'], b['severity']) for b in plan['blockers']])
        self.assertFalse(plan['ready_for_execution'])

    def test_prepared_extractor_binding(self):
        app = build_app(self.root)
        prepared = Native.extractor(self.root / 'prepared-yt-dlp', b'prepared build')
        good = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}
        plan = signing.inspect(request(app, prepared_extractor=good))
        extractor = next(o for o in plan['code_objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(extractor['action'], 'replace-and-sign')
        self.assertEqual(extractor['replacement']['sha256'], good['sha256'])
        self.assertIn('separate gate', extractor['replacement']['provenance'])
        self.assertNotIn('prepared-extractor-missing', [b['id'] for b in plan['blockers']])
        plain = self.root / 'plain-macho'
        shutil.copyfile(Native.get() / 'exe', plain)
        producer = app / RES / 'tools/yt_dlp/yt-dlp_macos'
        for change, why in [({'sha256': '0' * 64}, 'differs from the requested digest'), ({'sha256': 'ABC'}, '64 lowercase'),
                            ({'version': '2026.09.01'}, 'differs from the reviewed managed version'), ({'arch': 'x86_64'}, 'architecture differs'),
                            ({'path': str(plain), 'sha256': digest(plain.read_bytes())}, 'packed|PyInstaller|cookie|MEI|archive'),
                            ({'path': str(producer), 'sha256': digest(producer.read_bytes())}, 'unprepared producer'),
                            ({'path': 'relative/yt-dlp'}, 'absolute path')]:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(request(app, prepared_extractor={**good, **change}))
        # Developer ID requires every packed member to carry the signing team.
        devid = request(app, 'developer-id', 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345', prepared_extractor=good)
        plan = signing.inspect(devid)
        problems = [b['message'] for b in plan['blockers'] if b['id'] == 'prepared-extractor']
        self.assertTrue(problems and 'Team ID none, not ABCDE12345' in problems[0])
        real = signing.packed_native_members

        def team_members(path, arch):
            inventory, members = real(path, arch)
            for member in members:
                for image in member['signature']:
                    image.update(team='ABCDE12345', certificates=True, adhoc=False)
            return inventory, members
        # Spoofed parsed metadata (the pre-fix prerequisite) no longer suffices:
        # the actual ad-hoc members fail the cryptographic Team requirement.
        with mock.patch.object(signing, 'packed_native_members', side_effect=team_members):
            plan = signing.inspect(devid)
        problems = [b['message'] for b in plan['blockers'] if b['id'] == 'prepared-extractor']
        self.assertEqual(len(problems), 1, problems)
        self.assertIn('libfixture.dylib failed cryptographic signature verification against the Developer ID Team requirement', problems[0])

    def prepared(self, name, **options):
        path = Native.extractor(self.root / name, b'prepared build', **options)
        return {'path': str(path), 'sha256': digest(path.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}

    def test_packed_members_are_cryptographically_verified(self):
        app = build_app(self.root)
        native = Native.get()
        valid = signing.inspect(request(app, prepared_extractor=self.prepared('valid-yt-dlp')))
        verification = next(o for o in valid['code_objects'] if o['role'] == 'yt-dlp')['replacement']['packed']['signature_verification']
        self.assertEqual((verification['native_members'], verification['verified'], verification['failed'], verification['requirement']), (1, 1, 0, None))
        self.assertNotIn('prepared-extractor', [b['id'] for b in valid['blockers']])
        # Ad-hoc member with one corrupted instruction: parsed metadata is unchanged.
        corrupted = self.root / 'corrupted.dylib'
        corrupted.write_bytes(flip_code((native / 'lib.dylib').read_bytes()))
        self.assertEqual(signing.producer_summary(signing.signature(corrupted.read_bytes())), signing.producer_summary(signing.signature((native / 'lib.dylib').read_bytes())))
        plan = signing.inspect(request(app, prepared_extractor=self.prepared('corrupted-yt-dlp', library=corrupted)))
        problems = [b for b in plan['blockers'] if b['id'] == 'prepared-extractor']
        self.assertEqual([(b['severity'], 'libfixture.dylib failed cryptographic signature verification:' in b['message']) for b in problems], [('signing', True)], problems)
        self.assertFalse(plan['ready_for_execution'])
        # Corrupted code whose parsed metadata claims the signing Team and a CMS blob.
        forged = self.root / 'forged.dylib'
        forged.write_bytes(forge_team_signature(flip_code((native / 'lib.dylib').read_bytes()), 'ABCDE12345'))
        claims = signing.signature(forged.read_bytes())[0]
        self.assertEqual((claims['team'], claims['certificates'], claims['adhoc'], claims['linker_signed']), ('ABCDE12345', True, False, False))
        spec = self.prepared('forged-yt-dlp', library=forged)
        devid = signing.inspect(request(app, 'developer-id', 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345', prepared_extractor=spec))
        replacement = next(o for o in devid['code_objects'] if o['role'] == 'yt-dlp')['replacement']
        self.assertEqual(replacement['packed']['images_by_team'], {'ABCDE12345': 1})  # metadata alone would pass
        problems = [b['message'] for b in devid['blockers'] if b['id'] == 'prepared-extractor']
        self.assertEqual(len(problems), 1, problems)
        self.assertIn('failed cryptographic signature verification against the Developer ID Team requirement', problems[0])
        self.assertEqual(replacement['packed']['signature_verification']['requirement'], signing.developer_id_requirement('ABCDE12345'))
        adhoc = signing.inspect(request(app, prepared_extractor=spec))
        self.assertIn('prepared-extractor', [b['id'] for b in adhoc['blockers']])

    def test_developer_id_member_requirement_is_exact_canned(self):
        """Canned codesign success only: shows the requirement and private materialization, not a real Developer ID signature."""
        app = build_app(self.root)
        spec = self.prepared('canned-yt-dlp')
        temp = self.root / 'verify-temp'
        temp.mkdir()
        seen = []

        def canned(argv, env, timeout=signing.VERIFY_TIMEOUT):
            info = os.lstat(argv[-1])
            seen.append((argv, stat.S_ISREG(info.st_mode), info.st_mode & 0o777, signing.within(argv[-1], temp), env['TMPDIR']))
            return 0, ''
        real = signing.packed_native_members

        def team_members(path, arch):
            inventory, members = real(path, arch)
            for member in members:
                for image in member['signature']:
                    image.update(team='ABCDE12345', certificates=True, adhoc=False)
            return inventory, members
        devid = request(app, 'developer-id', 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345', prepared_extractor=spec)
        with mock.patch.object(signing, 'codesign_check', side_effect=canned), mock.patch.object(signing, 'packed_native_members', side_effect=team_members):
            plan = signing.inspect(devid, temp_root=temp)
        self.assertNotIn('prepared-extractor', [b['id'] for b in plan['blockers']])
        requirement = ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
                       'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "ABCDE12345"')
        self.assertEqual(len(seen), 1)
        argv, regular, mode, inside, tmpdir = seen[0]
        self.assertEqual(argv[:-1], ['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', '--test-requirement==' + requirement])
        self.assertEqual((regular, mode, inside), (True, 0o600, True))
        self.assertTrue(signing.within(tmpdir, temp))
        self.assertEqual(list(temp.iterdir()), [])
        with self.assertRaisesRegex(ValueError, 'Invalid Team ID'):
            signing.developer_id_requirement('abc" or true')
        with self.assertRaisesRegex(ValueError, 'Only codesign verification'):
            signing.codesign_check(['/bin/sh', '-c', 'true'], {})

    def test_packed_archive_names_links_and_budget(self):
        app = build_app(self.root)
        lib = Native.get() / 'lib.dylib'
        accepted = signing.inspect(request(app, prepared_extractor=self.prepared('links-yt-dlp', extra=[
            ('Current', 'libfixture.dylib', False, 'n'), ('sub/data.txt', None, True, 'x'), ('Data', 'sub', False, 'n'), ('Deep', 'Data/data.txt', False, 'n')])))
        self.assertEqual(next(o for o in accepted['code_objects'] if o['role'] == 'yt-dlp')['replacement']['packed']['signature_verification']['links_validated'], 3)
        cases = [
            ([('libfixture.dylib', None, True, 'x')], 'Duplicate CArchive member names'),
            ([('LIBFIXTURE.dylib', None, True, 'x')], 'case/normalization-colliding'),
            ([('escape', '../outside.dylib', False, 'n')], 'unsafe relative path'),
            ([('absolute', '/usr/lib/libz.dylib', False, 'n')], 'unsafe relative path'),
            ([('dangling', 'missing.dylib', False, 'n')], 'does not resolve'),
            ([('a', 'b', False, 'n'), ('b', 'a', False, 'n')], 'cyclic'),
            ([('alias', 'sub', False, 'n'), ('sub/x.txt', None, True, 'x'), ('alias/y.txt', None, True, 'x')], 'passes through'),
            ([('dep.dylib', 'other', False, 'd')], "Unsupported CArchive entry type 'd'"),
            ([('../escape.dylib', lib, True, 'b')], 'unsafe'),
        ]
        for index, (extra, why) in enumerate(cases):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(request(app, prepared_extractor=self.prepared(f'bad-{index}', extra=extra)))
        with mock.patch.object(signing, 'MAX_MATERIALIZED_BYTES', 1024), self.assertRaisesRegex(ValueError, 'materialization budget'):
            signing.inspect(request(app, prepared_extractor=self.prepared('budget-yt-dlp')))


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class Execution(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)

    def receipts_app(self, mutate_metadata=None):
        native = Native.get()
        fixture = Receipts(self.root / 'receipts')
        raw = [(n, native / ('worker' if n == 'omd-plugin-worker-v2' else 'exe')) for n in ENGINE]
        fixture.review('engine', raw)
        engine = fixture.reviewed('engine', raw)
        # Staging installs reviewed desktop texts before bundling; the final
        # review is then bound to the sealed input executable, as in production.
        fixture.review('desktop', [(EXE, native / 'exe')])
        _, desktop_notices = fixture.reviewed('desktop', [(EXE, native / 'exe')])
        app = build_app(self.root, receipts={'engine': engine, 'desktop_notices': desktop_notices})
        fixture.review('desktop', [(EXE, app / 'Contents/MacOS' / EXE)])
        if mutate_metadata:
            mutate_metadata(fixture)
        return fixture, app, fixture.config(self.root / 'receipts.json')

    def signed_entitlements(self, path):
        shown = subprocess.run(['/usr/bin/codesign', '--display', '--entitlements', '-', '--xml', path], capture_output=True, check=True).stdout
        return plistlib.loads(shown) if shown.strip() else {}

    def test_prior_review_must_bind_exact_input_artifacts(self):
        fixture, app, config = self.receipts_app()
        review_path = Path(fixture.section('engine')['review'])
        review = json.loads(review_path.read_text())
        review['scope']['artifacts'][0]['sha256'] = 'f' * 64
        review_path.write_text(json.dumps(review))
        with fixture.patched():
            plan = signing.inspect(request(app, receipts=str(config)))
        check = plan['receipts']['engine']
        self.assertEqual(check['differences_before_signing'], ['artifacts'])
        self.assertFalse(check['prior_review_binds_input_artifacts'])
        self.assertFalse(check['carry_after_signing'])
        self.assertIn('engine-review-scope', [b['id'] for b in plan['blockers']])

    def test_complete_adhoc_rehearsal_with_receipts_and_prepared_extractor(self):
        fixture, app, config = self.receipts_app()
        prepared = Native.extractor(self.root / 'prepared-yt-dlp', b'prepared build')
        spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}
        before = signing.inventory_of(app)
        prior = {k: digest(Path(fixture.section(k)['review']).read_bytes()) for k in ('engine', 'desktop')}
        with fixture.patched():
            plan = signing.inspect(request(app, prepared_extractor=spec, receipts=str(config)))
            self.assertEqual(plan['blockers'], [])
            self.assertTrue(plan['receipts']['engine']['carry_after_signing'] and plan['receipts']['desktop']['carry_after_signing'])
            plan_path = write_plan(self.root, plan)
            status, report_path = signing.execute(plan_path, self.root / 'Signed.app', self.root / 'work')
        report = json.loads(report_path.read_text())
        self.assertEqual((status, report['status']), ('signed-development-candidate', 'signed-development-candidate'), report.get('failure'))
        self.assertFalse(report['release_accepted'] or report['developer_id_signed'] or report['notarized'])
        out = self.root / 'Signed.app'
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', out], check=True, capture_output=True)
        self.assertEqual(signing.inventory_of(app), before)
        self.assertEqual({k: digest(Path(fixture.section(k)['review']).read_bytes()) for k in prior}, prior)
        policy = {o['path']: o['entitlements'] for o in plan['code_objects'] if o['action'] != 'outer-bundle'}
        for rel, wanted in policy.items():
            self.assertEqual(self.signed_entitlements(out / rel), wanted, rel)
            image = signing.signature((out / rel).read_bytes())[0]
            self.assertTrue(image['adhoc'] and not image['linker_signed'] and image['identifier'].startswith('labs.northwolf.omd-fixture.'), rel)
            self.assertEqual(image['runtime'], not rel.endswith('.dylib'), rel)
        for row in report['objects']:
            if row['action'] in ('sign', 'replace-and-sign', 'outer-bundle'):
                self.assertTrue(row['payload']['signature_only_change'], row['path'])
                self.assertNotEqual(row['payload']['sha256'], (row.get('replacement') or row['source'])['sha256'], row['path'])
        resources = out / RES
        tools = json.loads((resources / 'tools/tools-v2.json').read_text())
        for name, row in tools.items():
            self.assertEqual(row['sha256'], digest((resources / 'tools' / row['path']).read_bytes()), name)
        self.assertEqual(tools['yt_dlp']['version'], '2026.08.19')
        browser = json.loads((resources / 'browser/browser-tools-v2.json').read_text())
        self.assertEqual(browser['node']['sha256'], tools['node']['sha256'])
        for rel, row in browser['files'].items():
            self.assertEqual(row, signing.file_identity(resources / 'browser/content' / rel), rel)
        inventory = json.loads((resources / 'build-inventory.json').read_text())
        self.assertEqual(inventory['signing']['engine_receipt'], 'fresh-post-signature')
        self.assertEqual(inventory['signing']['payload_digests'], 'post-signature')
        self.assertIs(inventory['release_accepted'], False)
        self.assertEqual(signing.verify_public_resources(resources), len(inventory['files']))
        receipt = json.loads((resources / 'third-party/native-receipt.json').read_text())
        notices = (resources / 'third-party/native-NOTICES.txt').read_bytes()
        files = {rel: v['sha256'] for rel, v in signing.resource_identities(resources).items()}
        validate_native_receipt(receipt, files, ENGINE, digest(fixture.manifest('engine').with_name('Cargo.lock').read_bytes()), 'aarch64-apple-darwin', notices, '1.0.0')
        self.assertEqual(report['engine_receipt']['rebinding']['differences'], ['artifacts'])
        self.assertTrue(report['engine_receipt']['rebinding']['artifact_only'])
        desktop = report['desktop_receipt']
        self.assertEqual(desktop['status'], 'fresh-detached')
        self.assertFalse(signing.within(desktop['path'], out))
        self.assertEqual(desktop['binds']['bin/' + EXE], digest((out / 'Contents/MacOS' / EXE).read_bytes()))
        self.assertFalse(any(p.name == 'receipt.json' for p in out.rglob('*')))
        steps = [s['step'] for s in report['steps']]
        self.assertLess(steps.index('managed-manifests'), steps.index('seal'))
        labels = [c['label'] for c in report['commands']]
        self.assertEqual(labels[-1].split(':')[0], 'entitlements')
        self.assertLess(max(i for i, l in enumerate(labels) if l.startswith('sign:')), labels.index('seal:bundle'))

    def test_execution_time_receipt_failure_stops_without_opt_in(self):
        fixture, app, config = self.receipts_app()
        prepared = Native.extractor(self.root / 'prepared-yt-dlp', b'prepared build')
        spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}
        with fixture.patched():
            plan_path = write_plan(self.root, signing.inspect(request(app, prepared_extractor=spec, receipts=str(config))))
            with mock.patch.object(signing, 'fresh_receipt', side_effect=StopIteration()):
                status, report_path = signing.execute(plan_path, self.root / 'Stopped.app', self.root / 'work')
        report = json.loads(report_path.read_text())
        self.assertEqual((status, report['status']), ('blocked', 'blocked'))
        self.assertIn('native receipt preparation rejected: StopIteration', report['failure'])
        self.assertFalse((self.root / 'Stopped.app/Contents/_CodeSignature').exists())
        self.assertNotIn('seal:bundle', [c['label'] for c in report['commands']])
        self.assertEqual(json.loads((self.root / 'Stopped.app' / RES / 'third-party/native-receipt.json').read_bytes()), json.loads((app / RES / 'third-party/native-receipt.json').read_bytes()))

    def test_incomplete_rehearsal_removes_stale_receipt_and_claims_no_success(self):
        app = build_app(self.root)
        plan_path = write_plan(self.root, signing.inspect(request(app)))
        with self.assertRaisesRegex(ValueError, 'allow-incomplete-development'):
            signing.execute(plan_path, self.root / 'Refused.app', self.root / 'refused-work')
        self.assertFalse((self.root / 'Refused.app').exists() or (self.root / 'refused-work').exists())
        stale = (app / RES / 'third-party/native-receipt.json').read_bytes()
        status, report_path = signing.execute(plan_path, self.root / 'Rehearsal.app', self.root / 'work', allow_incomplete=True)
        report = json.loads(report_path.read_text())
        self.assertEqual(status, 'incomplete-development')
        self.assertNotIn('signed', report['status'])
        out = self.root / 'Rehearsal.app'
        self.assertFalse((out / RES / 'third-party/native-receipt.json').exists())
        self.assertEqual((self.root / 'work/stale/native-receipt.pre-signature.json').read_bytes(), stale)
        self.assertEqual((app / RES / 'third-party/native-receipt.json').read_bytes(), stale)
        self.assertEqual(report['desktop_receipt']['status'], 'not-generated')
        self.assertEqual(json.loads((out / RES / 'build-inventory.json').read_text())['signing']['engine_receipt'], 'removed-stale-pre-signature')
        retained = next(o for o in report['objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(retained['payload']['sha256'], retained['source']['sha256'])
        ids = {b['id'] for b in report['blockers']}
        self.assertTrue({'prepared-extractor-missing', 'receipts-not-configured', 'engine-receipt-stale', 'desktop-receipt-missing'} <= ids)
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', out], check=True, capture_output=True)

    def test_scope_mismatch_is_not_carried(self):
        def change_features(fixture):
            fixture.metadata[str(fixture.manifest('engine'))]['resolve']['nodes'][0]['features'] = ['extra']
        fixture, app, config = self.receipts_app(change_features)
        review = Path(fixture.section('engine')['review'])
        before = digest(review.read_bytes())
        with fixture.patched():
            plan = signing.inspect(request(app, receipts=str(config)))
            blocker = next(b for b in plan['blockers'] if b['id'] == 'engine-review-scope')
            self.assertIn('packages', blocker['message'])
            status, report_path = signing.execute(write_plan(self.root, plan), self.root / 'Scope.app', self.root / 'work', allow_incomplete=True)
        report = json.loads(report_path.read_text())
        self.assertEqual(status, 'incomplete-development')
        self.assertEqual(report['engine_receipt']['status'], 'removed-stale')
        self.assertFalse((self.root / 'work/receipts/engine-review-base').exists())
        self.assertEqual(digest(review.read_bytes()), before)
        self.assertEqual(report['desktop_receipt']['status'], 'fresh-detached', report['desktop_receipt'])
        engine_selection = fixture.config(self.root / 'six.json', ENGINE + ['omd-mcp'])
        with fixture.patched():
            plan = signing.inspect(request(app, receipts=str(engine_selection)))
        self.assertIn('engine-receipt-selection', [b['id'] for b in plan['blockers']])

    def test_execution_refuses_unsafe_paths_drift_and_release_modes(self):
        app = build_app(self.root)
        plan = signing.inspect(request(app))
        plan_path = write_plan(self.root, plan)
        (self.root / 'Exists.app').mkdir()
        (self.root / 'linked').symlink_to(self.root)
        cases = [(self.root / 'Exists.app', self.root / 'w1', 'new .app'), (app / 'Contents/Nested.app', self.root / 'w2', 'overlap'),
                 (self.root / 'FIXTURE.APP', self.root / 'w3', 'new .app|overlap'), (self.root / 'Out.app', app / 'work', 'inside the input'),
                 (self.root / 'Out.app', self.root / 'Out.app/work', 'inside the output'), (self.root / 'linked/Out.app', self.root / 'w4', 'Symlink path component'),
                 (self.root / 'Out.app', plan_path, 'Work directory must be new')]
        for output, work, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.execute(plan_path, output, work, allow_incomplete=True)
            self.assertFalse((self.root / 'Out.app').exists())
        with self.assertRaisesRegex(ValueError, 'only permitted for development-adhoc'):
            devid = signing.inspect(request(app, 'developer-id', 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345'))
            signing.execute(write_plan(self.root, devid, 'devid.json'), self.root / 'D.app', self.root / 'dw', allow_incomplete=True)
        with self.assertRaisesRegex(ValueError, 'Signing blockers'):
            signing.execute(self.root / 'devid.json', self.root / 'D.app', self.root / 'dw')
        tampered = json.loads(plan_path.read_text())
        next(o for o in tampered['code_objects'] if o['role'] == 'node')['entitlements'] = {}
        with self.assertRaisesRegex(ValueError, 'changed since the reviewed plan'):
            signing.execute(write_plan(self.root, tampered, 'tampered.json'), self.root / 'T.app', self.root / 'tw', allow_incomplete=True)
        (app / RES / 'LICENSE').write_text('drift')
        with self.assertRaisesRegex(ValueError, 'changed after staging'):
            signing.execute(plan_path, self.root / 'Drift.app', self.root / 'dw2', allow_incomplete=True)
        self.assertFalse(any((self.root / n).exists() for n in ('D.app', 'dw', 'T.app', 'tw', 'Drift.app', 'dw2', 'Out.app')))

    def test_copy_must_equal_reviewed_input(self):
        app = build_app(self.root)
        plan_path = write_plan(self.root, signing.inspect(request(app)))
        real = signing.copy_app

        def drifting(source, output):
            copied = real(source, output)
            (output / RES / 'LICENSE').write_text('changed between inspection and copy')
            copied[RES + '/LICENSE'] = signing.file_identity(output / RES / 'LICENSE')
            return copied
        with mock.patch.object(signing, 'copy_app', side_effect=drifting):
            status, report_path = signing.execute(plan_path, self.root / 'Drift.app', self.root / 'work', allow_incomplete=True)
        report = json.loads(report_path.read_text())
        self.assertEqual(status, 'failed')
        self.assertIn('reviewed input inventory', report['failure'])
        self.assertEqual(report['commands'], [])

    def test_partial_failure_is_recorded_without_success(self):
        app = build_app(self.root)
        plan_path = write_plan(self.root, signing.inspect(request(app)))

        class Failing(signing.Runner):
            signs = 0

            def __call__(self, argv, label, timeout=600, check=True):
                if label.startswith('sign:'):
                    Failing.signs += 1
                    if Failing.signs == 3:
                        record = {'label': label, 'argv': [str(x) for x in argv], 'exit': 1, 'seconds': 0, 'stdout': '', 'stderr': 'injected failure'}
                        self.records.append(record)
                        raise signing.CommandFailed(record)
                return super().__call__(argv, label, timeout, check)
        status, report_path = signing.execute(plan_path, self.root / 'Partial.app', self.root / 'work', allow_incomplete=True, runner_factory=Failing)
        report = json.loads(report_path.read_text())
        self.assertEqual((status, report['status']), ('failed', 'failed'))
        self.assertIn('injected failure', report['failure'])
        self.assertEqual(sum(c['label'].startswith('sign:') for c in report['commands']), 3)
        self.assertEqual(report['commands'][-1]['exit'], 1)
        self.assertEqual(len([o for o in report['objects'] if o['action'] == 'sign']), 2)
        self.assertFalse((self.root / 'Partial.app/Contents/_CodeSignature').exists())
        self.assertNotEqual(subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', self.root / 'Partial.app'], capture_output=True).returncode, 0)
        self.assertFalse(report['release_accepted'])


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class DeveloperIdVerification(unittest.TestCase):
    """Canned codesign output only: proves the checks, not a real Developer ID signature."""

    def test_requires_team_authority_and_secure_timestamp(self):
        root = scratch(self)
        path = root / 'node'
        shutil.copyfile(Native.get() / 'exe', path)
        path.chmod(0o755)
        layout, independent = signing.macho_layout(path.read_bytes())
        obj = {'path': 'tools/node/node', 'filetype': 'execute', 'identifier': 'labs.example.node', 'entitlements': {'com.apple.security.cs.allow-jit': True},
               'hardened_runtime': True, 'action': 'sign', 'source': {'signature_independent_sha256': independent, 'signature_layout': layout}}
        plan = {'mode': 'developer-id', 'team_id': 'ABCDE12345'}
        image = {'signed': True, 'identifier': 'labs.example.node', 'adhoc': False, 'certificates': True, 'team': 'ABCDE12345',
                 'runtime': True, 'linker_signed': False, 'entitlements': obj['entitlements'], 'cpu': 0x100000c, 'filetype': 'execute'}
        good = 'Authority=Developer ID Application: Example Labs (ABCDE12345)\nTimestamp=Nov 2, 2026\nTeamIdentifier=ABCDE12345\n'

        class Canned:
            def __init__(self, details):
                self.records, self.details = [], details

            def __call__(self, argv, label, timeout=600, check=True):
                out = plistlib.dumps(obj['entitlements']) if '--entitlements' in argv else b''
                self.records.append({'label': label, 'stderr': self.details if label.startswith('details:') else ''})
                return out
        with mock.patch.object(signing, 'signature', return_value=[image]):
            self.assertTrue(signing.verify_object(Canned(good), plan, obj, path)['signature_only_change'])
            for details, why in [(good.replace('Timestamp=Nov 2, 2026', 'Signed Time=Nov 2, 2026'), 'secure timestamp'),
                                 (good.replace('Developer ID Application', 'Apple Development'), 'Developer ID team'),
                                 (good.replace('TeamIdentifier=ABCDE12345', 'TeamIdentifier=ZZZZZ99999'), 'Developer ID team')]:
                with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                    signing.verify_object(Canned(details), plan, obj, path)
        with mock.patch.object(signing, 'signature', return_value=[{**image, 'team': 'ZZZZZ99999'}]), self.assertRaisesRegex(ValueError, 'mode/team'):
            signing.verify_object(Canned(good), plan, obj, path)
        with mock.patch.object(signing, 'signature', return_value=[{**image, 'adhoc': True, 'certificates': False}]), self.assertRaisesRegex(ValueError, 'mode/team'):
            signing.verify_object(Canned(good), plan, obj, path)


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SignatureIdentity(unittest.TestCase):
    def test_signature_independent_digest(self):
        root = scratch(self)
        native = Native.get()
        subprocess.run(['xcrun', 'lipo', '-create', native / 'exe', native / 'exe-x86_64', '-output', root / 'fat'], check=True)
        for name in ('exe', 'fat'):
            source = root / name if name == 'fat' else native / name
            original = signing.signature_independent_sha256(source.read_bytes())
            copy_path = root / f'{name}-signed'
            shutil.copyfile(source, copy_path)
            run('/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime', '--identifier', 'labs.example.x', copy_path)
            signed = copy_path.read_bytes()
            self.assertNotEqual(digest(signed), digest(source.read_bytes()))
            self.assertEqual(signing.signature_independent_sha256(signed), original, name)
            self.assertTrue(all(i['identifier'] == 'labs.example.x' and i['runtime'] for i in signing.signature(signed)))
        data = bytearray((native / 'exe').read_bytes())
        offset = data.find(b'__TEXT') + 64
        data[offset] ^= 1
        self.assertNotEqual(signing.signature_independent_sha256(bytes(data)), signing.signature_independent_sha256((native / 'exe').read_bytes()))

    def resign(self, source, target, identifier='labs.example.x', options=('--options', 'runtime')):
        shutil.copyfile(source, target)
        run('/usr/bin/codesign', '--force', '--sign', '-', *options, '--timestamp=none', '--identifier', identifier, target)
        return target.read_bytes()

    def test_legitimate_thin_fat_and_pyinstaller_resigning_is_proven(self):
        root = scratch(self)
        native = Native.get()
        run('xcrun', 'lipo', '-create', native / 'exe', native / 'exe-x86_64', '-output', root / 'fat')
        sources = {'thin-arm64': native / 'exe', 'thin-x86_64': native / 'exe-x86_64', 'fat': root / 'fat', 'pyinstaller': Native.extractor(root / 'yt-dlp')}
        grown = 'labs.example.' + 'y' * 30000  # forces signature growth past the __LINKEDIT vmsize
        for name, source in sources.items():
            layout, independent = signing.macho_layout(source.read_bytes())
            for label, identifier in (('plain', 'labs.example.x'), ('grown', grown)):
                with self.subTest(name=name, case=label):
                    after = self.resign(source, root / f'{name}-{label}', identifier)
                    comparison = signing.signature_change(independent, layout, after)
                    self.assertEqual((comparison['method'], comparison['slices']), ('paired-structure', len(layout['slices'])))
                    run('/usr/bin/codesign', '--verify', '--strict', '--all-architectures', root / f'{name}-{label}')
                    if name == 'fat':
                        # lipo places x86_64 at 4K alignment; codesign relocates it to 16K.
                        self.assertTrue(comparison['fat_slices_relocated'])
                        self.assertNotEqual(signing.macho_layout(after)[0]['container'], layout['container'])
                    if label == 'grown':
                        self.assertTrue(all(new > old for old, new in comparison['linkedit_vmsize']), comparison)
            # Re-signing a grown signature smaller shrinks vmsize to the page-rounded size.
            grown_layout, grown_digest = signing.macho_layout((root / f'{name}-grown').read_bytes())
            signing.signature_change(grown_digest, grown_layout, self.resign(root / f'{name}-grown', root / f'{name}-shrunk', 'a.b', ()))

    def test_unassigned_trailing_and_dependent_bytes_fail_closed(self):
        root = scratch(self)
        native = Native.get()
        run('xcrun', 'lipo', '-create', native / 'exe', native / 'exe-x86_64', '-output', root / 'fat')
        fat = self.resign(root / 'fat', root / 'fat-signed')
        layout, independent = signing.macho_layout(fat)
        # Astra's repro: different appended data used to hash equal; now any trailer fails closed.
        for tail in (b'original-data', b'changed--data', b'\0' * 16):
            with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, 'after the last FAT slice'):
                signing.signature_independent_sha256(fat + tail)
        header_end = 8 + 2 * 20
        first = min(a['offset'] for a in layout['container']['arches'])
        for at in (header_end, first - 4):
            padded = bytearray(fat)
            padded[at:at + 4] = b'\x01\x02\x03\x04'
            with self.subTest(gap=at), self.assertRaisesRegex(ValueError, 'Nonzero unassigned bytes'):
                signing.signature_independent_sha256(bytes(padded))
        misaligned = bytearray(fat)
        struct.pack_into('>I', misaligned, 8 + 16, 15)  # first arch align 2^15; offset 16384 is not aligned
        with self.assertRaisesRegex(ValueError, 'not aligned'):
            signing.signature_independent_sha256(bytes(misaligned))
        thin = (native / 'exe').read_bytes()
        with self.assertRaisesRegex(ValueError, 'must end its image'):
            signing.signature_independent_sha256(thin + b'\0' * 16)
        thin_layout, thin_digest = signing.macho_layout(thin)
        endian, seg = segment(thin, b'__LINKEDIT')
        _, vmsize, _, filesize = struct.unpack_from(endian + 'QQQQ', thin, seg + 24)
        shrunk = bytearray(thin)
        struct.pack_into(endian + 'Q', shrunk, seg + 48, filesize - 16)
        with self.assertRaisesRegex(ValueError, 'end exactly at the code signature'):
            signing.signature_independent_sha256(bytes(shrunk))
        # vmsize is outside the digest, so the paired check must constrain it.
        signed = bytearray(self.resign(native / 'exe', root / 'exe-signed'))
        struct.pack_into(endian + 'Q', signed, seg + 32, vmsize + 0x40000)
        self.assertEqual(signing.signature_independent_sha256(bytes(signed)), thin_digest)
        with self.assertRaisesRegex(ValueError, 'vmsize changed beyond'):
            signing.signature_change(thin_digest, thin_layout, bytes(signed))
        # PyInstaller archive bytes and the padding before the signature are covered.
        extractor = Native.extractor(root / 'yt-dlp').read_bytes()
        x_layout, x_digest = signing.macho_layout(extractor)
        dataoff = x_layout['slices'][0]['signature_offset']
        for at in (extractor.index(b'MEI\014\013\012\013\016') + 9, dataoff - 1):
            changed = bytearray(extractor)
            changed[at] ^= 0xff
            with self.subTest(archive_byte=at), self.assertRaisesRegex(ValueError, 'bytes other than the signature changed'):
                signing.signature_change(x_digest, x_layout, bytes(changed))
        # An unsigned input would gain a load command: never claimed signature-only.
        boot_layout, boot_digest = signing.macho_layout((native / 'boot').read_bytes())
        self.assertEqual([s['signed'] for s in boot_layout['slices']], [False])
        with self.assertRaisesRegex(ValueError, 'Unsigned input slices'):
            signing.signature_change(boot_digest, boot_layout, self.resign(native / 'boot', root / 'boot-signed'))


DEVID, TEAM = 'Developer ID Application: Fixture Labs (ABCDE12345)', 'ABCDE12345'
_cli = importlib.util.spec_from_file_location('omd_sign_macos_cli', Path(__file__).with_name('sign-macos.py'))
SIGN_CLI = importlib.util.module_from_spec(_cli)
_cli.loader.exec_module(SIGN_CLI)


@contextlib.contextmanager
def canned_team_members():
    """Canned: packed members claim the Team and codesign accepts them. The genuine
    refusal of such members is covered by the packed-member tests above."""
    real = signing.packed_native_members

    def team_members(path, arch):
        inventory, members = real(path, arch)
        for member in members:
            for image in member['signature']:
                image.update(team=TEAM, certificates=True, adhoc=False)
        return inventory, members
    with mock.patch.object(signing, 'codesign_check', return_value=(0, '')), mock.patch.object(signing, 'packed_native_members', side_effect=team_members):
        yield


class CannedDeveloperId(signing.Runner):
    """Records each requested Developer ID command, then signs ad-hoc instead. It
    drives execution only; it is never evidence of a real Developer ID signature."""
    version = b'2026.08.19\n'

    def __call__(self, argv, label, timeout=600, check=True):
        argv = [str(x) for x in argv]
        if label == 'extractor-version':
            self.records.append({'label': label, 'argv': argv, 'exit': 0, 'seconds': 0, 'stdout': self.version.decode(), 'stderr': '', 'canned': True})
            return self.version
        if not label.startswith(('sign:', 'seal:')):
            return super().__call__(argv, label, timeout, check)
        substituted = ['-' if a == DEVID else '--timestamp=none' if a == '--timestamp' else a for a in argv]
        try:
            return super().__call__(substituted, label, timeout, check)
        finally:
            self.records[-1]['requested_argv'] = argv


REAL_VERIFY = signing.verify_object


def adhoc_verify(runner, plan, obj, path):
    """The real structural verification of the ad-hoc substitute (Developer ID checks are unit-tested above)."""
    return REAL_VERIFY(runner, {**plan, 'mode': 'development-adhoc', 'team_id': None}, obj, path)


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class PrivateValidationPurpose(unittest.TestCase):
    """Explicit private validation: real Developer ID mode for a never-distributable copy."""
    receipts_app = Execution.receipts_app

    def setUp(self):
        self.root = scratch(self)

    def devid(self, app, purpose=None, **extra):
        return request(app, 'developer-id', DEVID, TEAM, **({'purpose': purpose} if purpose else {}), **extra)

    def prepared(self):
        path = Native.extractor(self.root / 'prepared-yt-dlp', b'prepared build')
        return {'path': str(path), 'sha256': digest(path.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}

    def test_purpose_tolerates_only_release_material_gaps(self):
        app = build_app(self.root)
        self.assertEqual(SIGN_CLI.parser().parse_args(['inspect', '--app', str(app), '--mode', 'developer-id', '--identity', DEVID, '--plan', 'p']).purpose, 'distribution-candidate')
        default = signing.inspect(self.devid(app))
        self.assertEqual((default['purpose'], default['request']['purpose']), ('distribution-candidate', 'distribution-candidate'))
        self.assertEqual({b['id']: b['severity'] for b in default['blockers']}, {'development-staging': 'signing', 'prepared-extractor-missing': 'signing', 'receipts-not-configured': 'signing'})
        self.assertFalse(any('purpose_tolerance' in b for b in default['blockers']))
        private = signing.inspect(self.devid(app, 'private-validation'))
        self.assertEqual((private['purpose'], private['request']['purpose']), ('private-validation', 'private-validation'))
        self.assertEqual({b['id']: (b['severity'], b.get('purpose_tolerance', {}).get('original_severity')) for b in private['blockers']},
                         {'development-staging': ('release', 'signing'), 'receipts-not-configured': ('release', 'signing'), 'prepared-extractor-missing': ('signing', None)})
        self.assertFalse(private['ready_for_execution'] or private['release_accepted'] or private['developer_id_signed'])
        self.assertIn('never a distribution candidate', ' '.join(private['purpose_limits']))
        with canned_team_members():
            spec = self.prepared()
            ready = signing.inspect(self.devid(app, 'private-validation', prepared_extractor=spec))
            self.assertEqual({b['id'] for b in ready['blockers']}, {'development-staging', 'receipts-not-configured'})
            self.assertTrue(ready['ready_for_execution'])
            self.assertFalse(ready['complete_without_blockers'])
            self.assertFalse(signing.inspect(self.devid(app, prepared_extractor=spec))['ready_for_execution'])
        # Ad-hoc packed members fail the genuine Team requirement in either purpose.
        adhoc = signing.inspect(self.devid(app, 'private-validation', prepared_extractor=spec))
        self.assertIn(('prepared-extractor', 'signing'), [(b['id'], b['severity']) for b in adhoc['blockers']])
        self.assertFalse(adhoc['ready_for_execution'])
        # Release staging with pre-signature materials: tolerated only for private validation.
        (self.root / 'release').mkdir()
        staged = build_app(self.root / 'release', staging='release')
        self.assertIn(('materials-bind-pre-signature', 'signing'), [(b['id'], b['severity']) for b in signing.inspect(self.devid(staged))['blockers']])
        self.assertIn(('materials-bind-pre-signature', 'release'), [(b['id'], b['severity']) for b in signing.inspect(self.devid(staged, 'private-validation'))['blockers']])
        # Substantive blockers keep their signing severity.
        self.assertFalse({'payload-minimum', 'unrecognized-code', 'unsupported-code-layout', 'prepared-extractor', 'prepared-extractor-missing'} & signing.PRIVATE_VALIDATION_TOLERATED)
        for name, options in (('minimum', {'minimum': '12.0'}),
                              ('stray', {'mutate': lambda a: add_browser_file(a, 'adapter/node_modules/.bin/node', (Native.get() / 'exe').read_bytes(), True)})):
            (self.root / name).mkdir()
            plan = signing.inspect(self.devid(build_app(self.root / name, **options), 'private-validation'))
            substantive = [b['id'] for b in plan['blockers'] if b['severity'] == 'signing']
            self.assertIn({'minimum': 'payload-minimum', 'stray': 'unrecognized-code'}[name], substantive)
            self.assertFalse(plan['ready_for_execution'])
            self.assertTrue(all(('purpose_tolerance' in b) == (b['id'] in signing.PRIVATE_VALIDATION_TOLERATED) for b in plan['blockers']))
        for req, why in ((request(app, purpose='private-validation'), 'only to developer-id'), (self.devid(app, 'release'), 'Unknown signing purpose'),
                         (request(app, 'developer-id', 'Apple Development: someone (ABCDE12345)', TEAM, purpose='private-validation'), 'Developer ID Application'),
                         (request(app, 'developer-id', DEVID, 'ZZZZZ99999', purpose='private-validation'), 'differs from --team-id')):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(req)

    def test_purpose_is_bound_again_at_execution(self):
        app = build_app(self.root)
        adhoc = write_plan(self.root, signing.inspect(request(app)), 'adhoc.json')
        private = write_plan(self.root, signing.inspect(self.devid(app, 'private-validation')), 'private.json')
        default = signing.inspect(self.devid(app))
        relabelled = copy.deepcopy(default)
        relabelled['purpose'] = 'private-validation'
        for blocker in relabelled['blockers']:
            blocker['severity'] = 'release'
        both = copy.deepcopy(relabelled)
        both['request']['purpose'] = 'private-validation'
        cases = [(adhoc, {'purpose': 'private-validation'}, 'differs from the requested execution purpose'),
                 (private, {}, 'Plan purpose private-validation differs'),
                 (private, {'purpose': 'release'}, 'Unknown signing purpose'),
                 (private, {'purpose': 'private-validation', 'allow_incomplete': True}, 'only permitted for development-adhoc'),
                 (private, {'purpose': 'private-validation'}, 'Signing blockers: prepared-extractor-missing'),
                 (write_plan(self.root, relabelled, 'relabelled.json'), {'purpose': 'private-validation'}, 'changed since the reviewed plan'),
                 (write_plan(self.root, both, 'both.json'), {'purpose': 'private-validation'}, 'changed since the reviewed plan')]
        for index, (plan_path, options, why) in enumerate(cases):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.execute(plan_path, self.root / f'Out{index}.app', self.root / f'work{index}', **options)
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = SIGN_CLI.main(['execute', '--plan', str(private), '--output', str(self.root / 'Cli.app'), '--work', str(self.root / 'cli-work')])
        self.assertEqual(code, 1)
        self.assertIn('differs from the requested execution purpose', stderr.getvalue())
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.suffix == '.app' or p.name.startswith(('work', 'cli'))), ['Fixture.app'])

    def test_private_validation_signed_copy_is_never_a_candidate(self):
        fixture, app, config = self.receipts_app()
        before = signing.inventory_of(app)
        with fixture.patched(), canned_team_members():
            spec = self.prepared()
            default = signing.inspect(self.devid(app, prepared_extractor=spec, receipts=str(config)))
            self.assertEqual([(b['id'], b['severity']) for b in default['blockers']], [('development-staging', 'signing')])
            with self.assertRaisesRegex(ValueError, 'Signing blockers: development-staging'):
                signing.execute(write_plan(self.root, default, 'default.json'), self.root / 'Default.app', self.root / 'default-work')
            plan = signing.inspect(self.devid(app, 'private-validation', prepared_extractor=spec, receipts=str(config)))
            self.assertEqual([(b['id'], b['severity'], b['purpose_tolerance']['original_severity']) for b in plan['blockers']], [('development-staging', 'release', 'signing')])
            self.assertTrue(plan['ready_for_execution'] and plan['receipts']['engine']['carry_after_signing'] and plan['receipts']['desktop']['carry_after_signing'])
            with mock.patch.object(signing, 'verify_object', side_effect=adhoc_verify):
                status, report_path = signing.execute(write_plan(self.root, plan), self.root / 'Private.app', self.root / 'work',
                                                      runner_factory=CannedDeveloperId, purpose='private-validation')
        report = json.loads(report_path.read_text())
        self.assertEqual((status, report['status']), ('private-validation-signed', 'private-validation-signed'), report.get('failure'))
        self.assertEqual(SIGN_CLI.EXIT[status], 3)
        self.assertNotIn('candidate', status)
        self.assertEqual((report['purpose'], report['distribution_candidate'], report['release_accepted'], report['notarized']), ('private-validation', False, False, False))
        self.assertEqual(report['private_validation']['tolerated_release_gaps'], ['development-staging'])
        self.assertFalse(report['private_validation']['suitable_for_public_distribution'])
        self.assertEqual([b['id'] for b in report['blockers']], ['development-staging'])
        self.assertEqual((report['engine_receipt']['status'], report['desktop_receipt']['status']), ('fresh', 'fresh-detached'))
        out = self.root / 'Private.app'
        inventory = json.loads((out / RES / 'build-inventory.json').read_text())
        self.assertEqual((inventory['signing']['purpose'], inventory['staging_mode'], inventory['release_accepted'], inventory['signing']['release_accepted']),
                         ('private-validation', 'development', False, False))
        requested = [c['requested_argv'] for c in report['commands'] if c['label'].startswith(('sign:', 'seal:'))]
        self.assertEqual(len(requested), 16)
        self.assertTrue(all(argv[3] == DEVID and '--timestamp' in argv and '--timestamp=none' not in argv for argv in requested))
        self.assertIn('extractor-version', [c['label'] for c in report['commands']])
        subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', out], check=True, capture_output=True)
        self.assertEqual(signing.inventory_of(app), before)

    def test_private_validation_cannot_waive_substantive_failures(self):
        fixture, app, config = self.receipts_app()
        with fixture.patched(), canned_team_members():
            plan_path = write_plan(self.root, signing.inspect(self.devid(app, 'private-validation', prepared_extractor=self.prepared(), receipts=str(config))))

            class WrongVersion(CannedDeveloperId):
                version = b'2026.01.01\n'
            real_fresh = signing.fresh_receipt

            def desktop_fails(kind, *args):
                if kind == 'desktop':
                    raise signing.Blocked('desktop review evidence unavailable')
                return real_fresh(kind, *args)
            runs = {}
            # Genuine Developer ID verification of the ad-hoc substitute: Team/mode mismatch.
            runs['team'] = signing.execute(plan_path, self.root / 'Team.app', self.root / 'team-work', runner_factory=CannedDeveloperId, purpose='private-validation')
            with mock.patch.object(signing, 'verify_object', side_effect=adhoc_verify):
                runs['version'] = signing.execute(plan_path, self.root / 'Version.app', self.root / 'version-work', runner_factory=WrongVersion, purpose='private-validation')
                with mock.patch.object(signing, 'fresh_receipt', side_effect=desktop_fails):
                    runs['receipt'] = signing.execute(plan_path, self.root / 'Receipt.app', self.root / 'receipt-work', runner_factory=CannedDeveloperId, purpose='private-validation')
        reports = {k: json.loads(path.read_text()) for k, (_, path) in runs.items()}
        self.assertEqual({k: status for k, (status, _) in runs.items()}, {'team': 'failed', 'version': 'failed', 'receipt': 'private-validation-incomplete'})
        self.assertIn('signature mode/team mismatch', reports['team']['failure'])
        self.assertFalse((self.root / 'Team.app/Contents/_CodeSignature').exists())
        self.assertIn('embedded-runtime version check', reports['version']['failure'])
        # A seal alone never establishes success.
        self.assertTrue((self.root / 'Version.app/Contents/_CodeSignature/CodeResources').exists())
        self.assertTrue((self.root / 'Receipt.app/Contents/_CodeSignature/CodeResources').exists())
        self.assertEqual(SIGN_CLI.EXIT['private-validation-incomplete'], 2)
        self.assertEqual(reports['receipt']['desktop_receipt']['status'], 'blocked')
        self.assertEqual([b['id'] for b in reports['receipt']['blockers']], ['development-staging', 'desktop-receipt-blocked'])
        for report in reports.values():
            self.assertFalse(report['developer_id_signed'] or report['distribution_candidate'] or report['release_accepted'])
            self.assertEqual(report['purpose'], 'private-validation')


def tearDownModule():
    if Native.root is not None:
        shutil.rmtree(Native.root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
