# /// script
# requires-python = ">=3.12"
# ///
import argparse
import copy
import os
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
            put('bin/' + name, b'OMD_WORKER_PROFILE=release' if 'worker' in name else name.encode())
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
        self.args = argparse.Namespace(engine_bin=self.root / 'bin', tools=self.root / 'tools/manifest.json', browser_tools=self.root / 'browser.json', license=self.root / 'LICENSE', supplements=self.root / 'supplements.json', output=self.root / 'output', target='darwin-arm64', version='1')
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

    def check_release_target(self, target, triple):
        self.args.target = target
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
        self.args.target = 'win32-x64'
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
            for name in ('engine_bin', 'tools', 'browser_tools', 'license', 'supplements', 'output'):
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


if __name__ == '__main__':
    unittest.main()
