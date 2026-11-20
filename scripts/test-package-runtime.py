# /// script
# requires-python = ">=3.12"
# ///
import argparse
import copy
import hashlib
import os
import plistlib
import struct
import shutil
import stat
import subprocess
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


p = module('package-runtime')
s = module('smoke-runtime')
BUNDLE = 'bin/OMD Sign-In.app/'


def macho(cpu=0x100000c, minimum=(11, 0), filetype=2):
    """A minimal thin 64-bit Mach-O with one LC_BUILD_VERSION (macOS) load command."""
    version = minimum[0] << 16 | minimum[1] << 8
    return struct.pack('<8I', 0xfeedfacf, cpu, 0, filetype, 1, 24, 0, 0) + struct.pack('<6I', 0x32, 24, 1, version, version, 0) + b'omd-signin fixture'


def icns(payload=b'fixture artwork'):
    entry = b'ic07' + struct.pack('>I', 8 + len(payload)) + payload
    return b'icns' + struct.pack('>I', 8 + len(entry)) + entry


class Packaging(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        def put(name, data):
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
            return file
        self.put = put
        for name in p.BINS:
            put('bin/' + name, b'OMD_WORKER_PROFILE=release' if 'worker' in name else macho() if name == 'omd-signin' else name.encode())
        icon = put('icon/AppIcon.icns', icns())
        tools = {}
        for name in ('node', 'yt_dlp', 'ffmpeg', 'ffprobe'):
            file = put('tools/' + name, name.encode())
            tools[name] = {'path': name, 'version': '1', 'sha256': p.identity(file)['sha256']}
        p.dump(self.root / 'tools/manifest.json', tools)
        files = {}
        for name in ('browser', 'adapter'):
            file = put('content/' + name, name.encode())
            files[name] = {'sha256': p.identity(file)['sha256'], 'bytes': file.stat().st_size}
        p.dump(self.root / 'browser.json', {'root': 'content', 'version': '1', 'browser': 'browser', 'adapter': 'adapter', 'node': {**tools['node'], 'path': 'tools/node'}, 'files': files})
        put('LICENSE', b'MIT License\nfixture')
        file = put('notice', b'explicit fixture notice')
        p.dump(self.root / 'supplements.json', [{'name': 'notice', 'path': 'notice', 'sha256': p.identity(file)['sha256']}])
        self.args = argparse.Namespace(engine_bin=self.root / 'bin', tools=self.root / 'tools/manifest.json', browser_tools=self.root / 'browser.json', license=self.root / 'LICENSE', supplements=self.root / 'supplements.json', output=self.root / 'output', target='darwin-arm64', version='1',
                                       signin_icon=icon, signin_icon_sha256=p.identity(icon)['sha256'])
        self.original = {x: x.read_bytes() for x in self.root.rglob('*') if x.is_file()}

    def mutate(self, file, change):
        path = self.root / file
        data = p.load(path)
        change(data)
        path.write_text(json.dumps(data))

    def rejected(self):
        with self.assertRaises((ValueError, KeyError, OSError)):
            p.package(self.args)
        self.assertFalse(self.args.output.exists())

    def test_exact_archive_and_preserved_inputs(self):
        result = p.package(self.args)
        extracted = self.root / 'extracted'
        extracted.mkdir()
        inventory = s.extract(self.args.output / result['archive'], extracted)
        self.assertEqual(inventory['plugins'], [])
        for file, data in self.original.items():
            self.assertEqual(file.read_bytes(), data)
        for file in (self.args.output / 'runtime').rglob('*'):
            if file.is_file():
                self.assertEqual(file.read_bytes(), (extracted / file.relative_to(self.args.output / 'runtime')).read_bytes())
        self.args.output = self.root / 'second'
        again = p.package(self.args)
        self.assertEqual(result['sha256'], again['sha256'])

    def test_release_requires_materials_before_creating_output(self):
        self.args.staging_mode = 'release'
        self.rejected()

    def test_reviewed_synthetic_release_coverage_and_stale_material(self):
        self.check_release_target('darwin-arm64', 'aarch64-apple-darwin')

    def test_arm_release_targets(self):
        for target, triple in [('linux-arm64', 'aarch64-unknown-linux-gnu'), ('win32-arm64', 'aarch64-pc-windows-msvc')]:
            with self.subTest(target=target):
                self.setUp()
                self.check_release_target(target, triple)

    def other_platform(self, target):
        self.args.target, self.args.signin_icon, self.args.signin_icon_sha256 = target, None, None

    def check_release_target(self, target, triple):
        if target.startswith('darwin'):
            self.args.target = target
        else:
            self.other_platform(target)
        suffix = '.exe' if target.startswith('win32') else ''
        if suffix:
            for name in p.BINS:
                self.put('bin/' + name + suffix, (self.root / 'bin' / name).read_bytes())
        lock = Path(__file__).resolve().parent.parent / 'Cargo.lock'
        self.put('locks/Cargo.lock', lock.read_bytes())
        (self.root / 'content/adapter').rename(self.root / 'content/adapter-entry')
        browser_lock = self.put('content/adapter/package-lock.json', b'{}')
        self.put('locks/browser-package-lock.json', b'{}')
        browser = p.load(self.args.browser_tools)
        browser['files']['adapter-entry'] = browser['files'].pop('adapter')
        browser['adapter'] = 'adapter-entry'
        browser['files']['adapter/package-lock.json'] = {'bytes': 2, 'sha256': p.identity(browser_lock)['sha256']}
        self.args.browser_tools.write_text(json.dumps(browser))
        fixture = p.load(Path(__file__).resolve().parent.parent / 'distribution/materials-contract-fixtures-v1.json')['native']
        native = copy.deepcopy(fixture['receipt'])
        native.update(lock_sha256=p.identity(lock)['sha256'], target=triple, binaries=list(p.BINS), binary_roots={name: 'org-example-root' for name in p.BINS}, artifacts=[{'name': name, 'sha256': p.identity(self.root / 'bin' / (name + suffix))['sha256'], 'bytes': (self.root / 'bin' / (name + suffix)).stat().st_size} for name in p.BINS])
        # A cross-target fixture needs that target's standard-library evidence;
        # compiler attribution still belongs to the build host.
        runtime_finding = next(f for f in native['review']['findings'] if f['category'] == 'toolchain-runtime')
        for evidence in runtime_finding['evidence']:
            if 'rust-std-' in evidence.get('url', ''):
                evidence['url'] = evidence['url'].replace(fixture['target'], triple)
        p.dump(self.root / 'native-receipt.json', native)
        self.put('native-NOTICES.txt', fixture['notice_text'].encode())
        supplements = p.load(self.args.supplements)
        supplements.append({'name': 'native-receipt.json', 'path': 'native-receipt.json', 'sha256': p.identity(self.root / 'native-receipt.json')['sha256']})
        supplements.append({'name': 'native-NOTICES.txt', 'path': 'native-NOTICES.txt', 'sha256': p.identity(self.root / 'native-NOTICES.txt')['sha256']})
        self.args.supplements.write_text(json.dumps(supplements))
        p.package(self.args)
        files = {x['path']: x['sha256'] for x in p.load(self.args.output / 'runtime/runtime-inventory.json')['files']}
        # The receipt binds the macOS sign-in helper at its bundle executable path.
        self.assertEqual(BUNDLE + 'Contents/MacOS/omd-signin' in files, target.startswith('darwin'))
        self.assertEqual('bin/omd-signin' + suffix in files, not target.startswith('darwin'))
        material = {'third-party/notice': files['third-party/notice']}
        manifest = {'schema': 'omd-materials-v1', 'reviewed': True, 'pending': [], 'target': target, 'version': '1', 'locks': {name: p.identity(self.root / 'locks' / name)['sha256'] for name in ('Cargo.lock', 'browser-package-lock.json')}, 'components': [{'id': name, 'version': '1', 'status': 'reviewed', 'pending': [], 'artifacts': files, 'materials': {kind: material for kind in ('notices', 'source', 'instructions', 'provenance')}} for name in (*p.BINS, 'node', 'yt_dlp', 'ffmpeg', 'ffprobe', 'browser')]}
        p.dump(self.root / 'materials.json', manifest)
        self.args.staging_mode = 'release'; self.args.materials = self.root / 'materials.json'; self.args.materials_locks = self.root / 'locks'; self.args.output = self.root / 'release'
        result = p.package(self.args)
        self.assertFalse(result['release_accepted'])
        self.assertTrue(p.load(self.args.output / 'runtime/runtime-inventory.json')['materials']['coverage_validated'])
        self.args.output = self.root / 'stale'
        manifest['components'][0]['materials']['source'] = {'third-party/notice': '0' * 64}
        self.args.materials.write_text(json.dumps(manifest))
        self.rejected()

    def test_mcp_is_required_in_standalone(self):
        self.assertEqual(p.BINS, ('omd-engine', 'omd-plugin-worker-v2', 'omd-helper-guardian', 'omd-notify', 'omd-signin', 'omd', 'omd-mcp'))
        (self.root / 'bin/omd-mcp').unlink()
        self.rejected()

    def test_sign_in_window_is_required(self):
        (self.root / 'bin/omd-signin').unlink()
        self.rejected()

    def test_macos_sign_in_window_is_a_deterministic_app_bundle(self):
        result = p.package(self.args)
        runtime = self.args.output / 'runtime'
        rows = {x['path']: x for x in p.load(runtime / 'runtime-inventory.json')['files']}
        bundle = {path[len(BUNDLE):]: row for path, row in rows.items() if path.startswith(BUNDLE)}
        self.assertEqual({rel: row['mode'] for rel, row in bundle.items()},
                         {'Contents/Info.plist': 0o644, 'Contents/MacOS/omd-signin': 0o755, 'Contents/Resources/AppIcon.icns': 0o644})
        self.assertNotIn('bin/omd-signin', rows)
        self.assertFalse((runtime / 'bin/omd-signin').exists())
        self.assertEqual((runtime / BUNDLE / 'Contents/MacOS/omd-signin').read_bytes(), macho())
        self.assertEqual((runtime / BUNDLE / 'Contents/Resources/AppIcon.icns').read_bytes(), icns())
        if os.name == 'posix':
            for rel, row in bundle.items():
                self.assertEqual(stat.S_IMODE((runtime / BUNDLE / rel).stat().st_mode), row['mode'], rel)
        info = (runtime / BUNDLE / 'Contents/Info.plist').read_bytes()
        self.assertEqual(plistlib.loads(info), {
            'CFBundleDisplayName': 'OMD Sign-In', 'CFBundleExecutable': 'omd-signin', 'CFBundleIconFile': 'AppIcon',
            'CFBundleIdentifier': 'labs.northwolf.omd.signin', 'CFBundleInfoDictionaryVersion': '6.0', 'CFBundleName': 'OMD Sign-In',
            'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': '1', 'CFBundleVersion': '1',
            'LSMinimumSystemVersion': '11.0.0', 'NSHighResolutionCapable': True})
        # Sorted-key XML: the same bytes for the same version and executable minimum.
        self.assertEqual(info, plistlib.dumps(plistlib.loads(info), fmt=plistlib.FMT_XML, sort_keys=True))
        self.assertEqual(hashlib.sha256(info).hexdigest(), 'c7767d5617695b94f6f479e7bfc10afd93a0eacf6701a2e38a700d4ab12fe762')
        import tarfile
        with tarfile.open(self.args.output / result['archive']) as archive:
            members = {m.name: m for m in archive}
        self.assertEqual({m[len(BUNDLE):]: members[m].mode for m in members if m.startswith(BUNDLE)},
                         {rel: row['mode'] for rel, row in bundle.items()})
        self.assertNotIn('bin/omd-signin', members)
        extracted = self.root / 'extracted-bundle'
        extracted.mkdir()
        s.extract(self.args.output / result['archive'], extracted)
        self.assertTrue(os.access(extracted / BUNDLE / 'Contents/MacOS/omd-signin', os.X_OK))
        self.args.output = self.root / 'again'
        self.assertEqual(p.package(self.args)['sha256'], result['sha256'])

    def test_macos_bundle_inputs_are_explicit_and_checked(self):
        cases = [
            ('missing icon', lambda: setattr(self.args, 'signin_icon', None)),
            ('missing icon digest', lambda: setattr(self.args, 'signin_icon_sha256', None)),
            ('wrong icon digest', lambda: setattr(self.args, 'signin_icon_sha256', '0' * 64)),
            ('icon is not ICNS', lambda: (self.put('icon/AppIcon.icns', b'\x89PNG fixture artwork'), setattr(self.args, 'signin_icon_sha256', hashlib.sha256(b'\x89PNG fixture artwork').hexdigest()))),
            ('truncated ICNS', lambda: (self.put('icon/AppIcon.icns', icns()[:-1]), setattr(self.args, 'signin_icon_sha256', hashlib.sha256(icns()[:-1]).hexdigest()))),
            ('helper is not Mach-O', lambda: self.put('bin/omd-signin', b'omd-signin')),
            ('helper is a library', lambda: self.put('bin/omd-signin', macho(filetype=6))),
            ('helper lacks the target slice', lambda: setattr(self.args, 'target', 'darwin-x64')),
            ('version is not numeric', lambda: setattr(self.args, 'version', '1.0-beta')),
        ]
        for name, change in cases:
            with self.subTest(name):
                self.setUp()
                change()
                self.rejected()

    def test_linux_and_windows_keep_the_bare_sign_in_helper(self):
        for target, suffix in (('linux-x64', ''), ('win32-x64', '.exe')):
            with self.subTest(target):
                self.setUp()
                for name in p.BINS:
                    self.put('bin/' + name + suffix, (self.root / 'bin' / name).read_bytes())
                self.args.target = target
                self.rejected()
                self.other_platform(target)
                p.package(self.args)
                paths = {x['path'] for x in p.load(self.args.output / 'runtime/runtime-inventory.json')['files']}
                self.assertIn('bin/omd-signin' + suffix, paths)
                self.assertFalse(any(path.startswith(BUNDLE) for path in paths))

    def test_missing_digest(self):
        self.mutate('tools/manifest.json', lambda x: x['node'].pop('sha256'))
        self.rejected()

    def test_invalid_digest(self):
        self.mutate('tools/manifest.json', lambda x: x['ffmpeg'].update(sha256='bad'))
        self.rejected()

    def test_wrong_digest(self):
        self.put('tools/ffprobe', b'changed')
        self.rejected()

    def test_browser_digest(self):
        self.put('content/browser', b'changed')
        self.rejected()

    def test_debug_worker(self):
        self.put('bin/omd-plugin-worker-v2', b'debug')
        self.rejected()

    def test_escape(self):
        self.mutate('tools/manifest.json', lambda x: x['node'].update(path='../notice'))
        self.rejected()

    def test_symlink(self):
        file = self.root / 'content/browser'
        file.unlink()
        file.symlink_to(self.root / 'notice')
        self.rejected()

    def test_hidden_plugin(self):
        self.put('notice', b'OMDP2\0disguised')
        self.rejected()

    def test_unlisted_browser(self):
        self.put('content/extra', b'extra')
        self.rejected()

    def test_node_mismatch(self):
        self.mutate('browser.json', lambda x: x['node'].update(version='2'))
        self.rejected()

    def test_existing_output(self):
        p.package(self.args)
        report = (self.args.output / 'archive-report.json').read_bytes()
        with self.assertRaises(ValueError):
            p.package(self.args)
        self.assertEqual(report, (self.args.output / 'archive-report.json').read_bytes())

    def test_missing_browser_size(self):
        self.mutate('browser.json', lambda x: x['files']['browser'].pop('bytes'))
        self.rejected()

    def test_missing_version(self):
        self.mutate('tools/manifest.json', lambda x: x['node'].update(version=''))
        self.rejected()

    def test_symlink_ancestor(self):
        (self.root / 'alias').symlink_to(self.root / 'tools', target_is_directory=True)
        self.mutate('tools/manifest.json', lambda x: x['node'].update(path=str(self.root / 'alias/node')))
        self.rejected()

    def test_special_file(self):
        import os
        if not hasattr(os, 'mkfifo'):
            self.skipTest('POSIX FIFO fixture')
        (self.root / 'notice').unlink()
        os.mkfifo(self.root / 'notice')
        self.rejected()

    def test_matching_hidden_browser_plugin(self):
        self.put('content/adapter', b'OMDP2\0hidden')
        import hashlib
        self.mutate('browser.json', lambda x: x['files']['adapter'].update(sha256=hashlib.sha256(b'OMDP2\0hidden').hexdigest(), bytes=12))
        self.rejected()

    def test_arbitrary_existing_output(self):
        self.args.output.mkdir()
        marker = self.args.output / 'preserve'
        marker.write_bytes(b'original')
        with self.assertRaises(ValueError):
            p.package(self.args)
        self.assertEqual(marker.read_bytes(), b'original')

    def test_windows_zip(self):
        for name in p.BINS:
            self.put('bin/' + name + '.exe', (self.root / 'bin' / name).read_bytes())
        self.other_platform('win32-x64')
        result = p.package(self.args)
        extracted = self.root / 'zip'
        extracted.mkdir()
        s.extract(self.args.output / result['archive'], extracted)
        launcher = (extracted / 'start-engine.cmd').read_text()
        self.assertIn('DisableDelayedExpansion', launcher)
        self.assertIn('%~dp0bin\\omd-engine.exe', launcher)
        self.assertTrue((extracted / 'bin/omd.exe').is_file())
        import zipfile
        with zipfile.ZipFile(self.args.output / result['archive']) as archive:
            self.assertEqual((archive.getinfo('runtime-inventory.json').external_attr >> 16) & 0o777, 0o644)

    def test_reproducible_after_input_relocation(self):
        for file in ('tools/manifest.json', 'browser.json', 'supplements.json'):
            path = self.root / file
            data = p.load(path)
            if file.startswith('tools'):
                for tool in data.values():
                    tool['path'] = str(self.root / 'tools' / tool['path'])
            elif file == 'browser.json':
                data['root'] = str(self.root / data['root'])
                data['node']['path'] = str(self.root / data['node']['path'])
            else:
                data[0]['path'] = str(self.root / data[0]['path'])
            path.write_text(json.dumps(data))
        first = p.package(self.args)
        with tempfile.TemporaryDirectory() as temp:
            moved = Path(temp).resolve() / 'different-checkout'
            shutil.copytree(self.root, moved, ignore=shutil.ignore_patterns('output'))
            for file in ('tools/manifest.json', 'browser.json', 'supplements.json'):
                path = moved / file
                data = p.load(path)
                def relocate(value):
                    return str(moved / Path(value).relative_to(self.root))
                if file.startswith('tools'):
                    for tool in data.values():
                        tool['path'] = relocate(tool['path'])
                elif file == 'browser.json':
                    data['root'] = relocate(data['root'])
                    data['node']['path'] = relocate(data['node']['path'])
                else:
                    data[0]['path'] = relocate(data[0]['path'])
                path.write_text(json.dumps(data))
            args = copy.copy(self.args)
            for name in ('engine_bin', 'tools', 'browser_tools', 'license', 'supplements', 'output', 'signin_icon'):
                setattr(args, name, moved / getattr(self.args, name).relative_to(self.root))
            second = p.package(args)
            self.assertEqual(first['sha256'], second['sha256'])
            self.assertTrue(all(Path(item['source']).is_relative_to(moved)
                                for item in p.load(args.output / 'build-inputs.json')['files']))
        for path in (self.args.output / 'runtime').rglob('*'):
            if path.is_file():
                for spelling in (str(self.root), self.root.as_posix(), json.dumps(str(self.root))[1:-1]):
                    self.assertNotIn(spelling.encode(), path.read_bytes())
        self.assertEqual([item['source'] for item in p.load(self.args.output / 'build-inputs.json')['manifests']],
                         [str(file) for file in (self.args.tools, self.args.browser_tools, self.args.supplements)])

    def test_reproducible_across_umasks(self):
        previous = os.umask(0o022)
        try:
            first = p.package(self.args)
            self.args.output = self.root / 'private-umask'
            os.umask(0o077)
            second = p.package(self.args)
        finally:
            os.umask(previous)
        self.assertEqual(first['sha256'], second['sha256'])
        if os.name == 'posix':
            for path in (self.args.output / 'runtime').rglob('*.json'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        import tarfile
        with tarfile.open(self.args.output / second['archive']) as archive:
            for member in archive:
                if member.name.endswith('.json'):
                    self.assertEqual(member.mode, 0o644)

    @unittest.skipUnless(os.name == 'posix', 'POSIX launcher execution')
    def test_launcher_reuses_directory_and_preserves_existing_data(self):
        p.package(self.args)
        runtime = self.args.output / 'runtime'
        binary = runtime / 'bin/omd-engine'
        binary.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
        binary.chmod(0o755)
        profile = self.root / 'existing profile'
        profile.mkdir()
        marker = profile / 'preserve'
        marker.write_text('original')
        result = subprocess.run([str(runtime / 'start-engine.sh'), '--profile', str(profile)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(profile).encode(), result.stdout)
        self.assertEqual(marker.read_text(), 'original')
        marker_result = subprocess.run([str(runtime / 'start-engine.sh'), '--profile', str(marker)], capture_output=True, timeout=10)
        self.assertEqual(marker_result.returncode, 2)

    def smoke_responses(self):
        p.package(self.args)
        runtime = self.args.output / 'runtime'
        inventory = p.load(runtime / 'runtime-inventory.json')
        media, browser = s.expected_reviews(runtime, inventory)
        installed = lambda review: {'active': True, 'state': 'installed', 'issue': None, 'digest': review['digest'], 'review': review}
        service = {'api': 'v2', 'version': '1', 'scopes': ['read', 'manage'], 'capabilities': ['media_acquisition', 'source_browser', 'isolated_sign_in'], 'media_tools': {'configured': True, 'complete': True, 'tools': [{k: tool[k] for k in ('name', 'version', 'sha256')} for tool in media['tools']]}}
        responses = [service, {'items': [], 'next_cursor': None}, {'items': [installed(media)], 'next_cursor': None}, {'bundled': media, 'issue': None, 'platform': media['platform']}, {'bundled': browser, 'active': installed(browser), 'issue': None, 'platform': browser['platform']}]
        return inventory, media, browser, responses

    def test_smoke_requires_exact_expected_installations(self):
        inventory, media, browser, responses = self.smoke_responses()
        s.verify_state(inventory, media, browser, *responses)
        mutations = [
            lambda r: r[0].update(api='v1'),
            lambda r: r[0].update(version='different'),
            lambda r: r[0].update(capabilities=[]),
            lambda r: r[0]['media_tools'].update(complete=False),
            lambda r: r[0]['media_tools']['tools'][0].update(sha256='0' * 64),
            lambda r: r[2]['items'][0].update(digest='0' * 64),
            lambda r: r[2]['items'][0]['review']['tools'][0].update(version='different'),
            lambda r: r[4]['active'].update(digest='0' * 64),
            lambda r: r[4]['active']['review'].update(version='different'),
            lambda r: r[4]['active'].update(active=False),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                changed = copy.deepcopy(responses)
                mutate(changed)
                with self.assertRaises(ValueError):
                    s.verify_state(inventory, media, browser, *changed)


class SignInBundleEntry(unittest.TestCase):
    """The assembly entry used by development integration: the packager's exact members."""

    def test_assembles_the_same_bundle_and_refuses_unsafe_requests(self):
        bundle = module('signin_bundle')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            (root / 'omd-signin').write_bytes(macho())
            (root / 'AppIcon.icns').write_bytes(icns())
            sha = hashlib.sha256(icns()).hexdigest()
            args = ['--binary', str(root / 'omd-signin'), '--icon', str(root / 'AppIcon.icns'), '--icon-sha256', sha, '--target', 'darwin-arm64', '--version', '1']
            report = bundle.main([*args, '--output', str(root / 'OMD Sign-In.app')])
            self.assertEqual(report['identifier'], 'labs.northwolf.omd.signin')
            for rel, (data, mode) in bundle.members(macho(), icns(), '1', 'darwin-arm64').items():
                self.assertEqual((root / 'OMD Sign-In.app' / rel).read_bytes(), data, rel)
                if os.name == 'posix':
                    self.assertEqual(stat.S_IMODE((root / 'OMD Sign-In.app' / rel).stat().st_mode), mode, rel)
            self.assertEqual(hashlib.sha256((root / 'OMD Sign-In.app/Contents/Info.plist').read_bytes()).hexdigest(), 'c7767d5617695b94f6f479e7bfc10afd93a0eacf6701a2e38a700d4ab12fe762')
            self.assertEqual(plistlib.loads((root / 'OMD Sign-In.app/Contents/Info.plist').read_bytes())['CFBundleShortVersionString'], '1')
            for output, change, why in ((root / 'OMD Sign-In.app', {}, 'new --output'), (root / 'Other.app', {}, 'new --output'),
                                        (root / 'x' / 'OMD Sign-In.app', {}, 'new --output'), (root / 'fresh' / 'OMD Sign-In.app', {'--icon-sha256': '0' * 64}, 'pinned digest')):
                output.parent.mkdir(exist_ok=True) if output.parent.name == 'fresh' else None
                request = [*args, '--output', str(output)]
                for key, value in change.items():
                    request[request.index(key) + 1] = value
                with self.subTest(str(output)), self.assertRaisesRegex(ValueError, why):
                    bundle.main(request)
            self.assertFalse((root / 'fresh' / 'OMD Sign-In.app').exists())



NATIVE = os.uname().sysname == 'Darwin' if hasattr(os, 'uname') else False
NATIVE = NATIVE and shutil.which('xcrun') is not None and Path('/usr/bin/codesign').exists()


@unittest.skipUnless(NATIVE, 'needs macOS clang and codesign')
class SignedSignInBundle(unittest.TestCase):
    """A helper signed as the nested bundle (here ad-hoc, as a stand-in for Developer ID)
    is packaged with exactly its bundle seal, which its code directory binds."""

    def setUp(self):
        self.case = Packaging(methodName='test_exact_archive_and_preserved_inputs')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root, self.args = self.case.root, self.case.args
        work = self.root / 'signed'
        work.mkdir()
        (work / 'main.c').write_text('int main(void) { return 0; }\n')
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-mmacosx-version-min=13.0', '-O0', '-o', work / 'omd-signin', work / 'main.c'], check=True, capture_output=True)
        bundle_module = module('signin_bundle')
        self.icon = icns()
        self.bundle = work / 'OMD Sign-In.app'
        for rel, (data, mode) in bundle_module.members((work / 'omd-signin').read_bytes(), self.icon, '1', 'darwin-arm64').items():
            (self.bundle / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.bundle / rel).write_bytes(data)
            (self.bundle / rel).chmod(mode)
        self.sign()
        self.case.put('bin/omd-signin', (self.bundle / 'Contents/MacOS/omd-signin').read_bytes())
        self.seal = self.bundle / 'Contents/_CodeSignature/CodeResources'
        self.args.signin_seal, self.args.signin_seal_sha256 = self.seal, p.identity(self.seal)['sha256']

    def sign(self):
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime', '--timestamp=none',
                        '--identifier', 'labs.northwolf.omd.signin', self.bundle], check=True, capture_output=True)

    def test_signed_helper_ships_with_its_exact_seal(self):
        result = p.package(self.args)
        runtime = self.args.output / 'runtime'
        rows = {x['path']: x for x in p.load(runtime / 'runtime-inventory.json')['files']}
        bundle = {path[len(BUNDLE):]: row for path, row in rows.items() if path.startswith(BUNDLE)}
        self.assertEqual({rel: row['mode'] for rel, row in bundle.items()},
                         {'Contents/Info.plist': 0o644, 'Contents/MacOS/omd-signin': 0o755, 'Contents/Resources/AppIcon.icns': 0o644,
                          'Contents/_CodeSignature/CodeResources': 0o644})
        for rel in bundle:
            self.assertEqual((runtime / BUNDLE / rel).read_bytes(), (self.bundle / rel).read_bytes(), rel)
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', runtime / BUNDLE], check=True, capture_output=True)
        self.args.output = self.root / 'again'
        self.assertEqual(p.package(self.args)['sha256'], result['sha256'])

    def test_seal_inputs_are_explicit_and_bound(self):
        other = self.root / 'other-seal'
        cases = [
            ('seal without digest', lambda: setattr(self.args, 'signin_seal_sha256', None)),
            ('digest without seal', lambda: setattr(self.args, 'signin_seal', None)),
            ('wrong seal digest', lambda: setattr(self.args, 'signin_seal_sha256', '0' * 64)),
            ('seal of another signature', lambda: (other.write_bytes(self.seal.read_bytes() + b'\n'),
                                                   setattr(self.args, 'signin_seal', other), setattr(self.args, 'signin_seal_sha256', p.identity(other)['sha256']))),
            ('unsigned helper with a seal', lambda: self.case.put('bin/omd-signin', macho())),
            ('seal for another target', lambda: (self.case.other_platform('linux-x64'), setattr(self.args, 'signin_seal', self.seal),
                                                 setattr(self.args, 'signin_seal_sha256', p.identity(self.seal)['sha256']))),
        ]
        for name, change in cases:
            with self.subTest(name):
                self.setUp()
                change()
                self.case.rejected()


if __name__ == '__main__':
    unittest.main()
