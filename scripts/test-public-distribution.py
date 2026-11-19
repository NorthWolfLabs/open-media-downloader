# /// script
# requires-python = ">=3.12"
# ///
"""Synthetic rejection and byte reproducibility tests; no live providers/runtimes."""
import importlib.util
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from public_inputs import identity, inventory, write_json


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

source = load('export-public-source')
browser = load('package-browser')


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.engine = self.root / 'engine'
        self.engine.mkdir()
        (self.engine / 'a.txt').write_text('public source\n')
        (self.engine / 'private.txt').write_text('must not ship')
        self.policy = self.root / 'policy.json'
        self.rows = [{'source': 'a.txt', 'destination': 'a.txt'}]

    def prepare(self, name='output'):
        self.policy.write_text(json.dumps({'format': 2, 'files': self.rows}))
        out = self.root / name
        source.prepare(self.engine, self.policy, out)
        return out

    def test_reproducibility_inventory_and_preservation(self):
        first = self.prepare('one')
        before = os.umask(0o077)
        try:
            relocated = self.root / 'relocated'
            shutil.copytree(self.engine, relocated)
            self.engine = relocated
            second = self.prepare('two')
        finally:
            os.umask(before)
        source.archive(first)
        source.archive(second)
        self.assertEqual(identity(first / 'public-source.tar.gz'), identity(second / 'public-source.tar.gz'))
        with tarfile.open(first / 'public-source.tar.gz') as tar:
            self.assertEqual(tar.getnames(), ['a.txt'])
        with self.assertRaises(FileExistsError):
            source.archive(first)
        with self.assertRaises(FileExistsError):
            self.prepare('one')
        self.assertEqual((self.engine / 'private.txt').read_text(), 'must not ship')

    def test_escape_and_absolute_paths(self):
        for value in ['../a', '/a', 'a/../a', 'a\\b', './a', 'a//b', 'C:/outside', 'C:outside', 'a:b', 'a.']:
            with self.subTest(value=value):
                self.rows[0]['source'] = value
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_output_symlink_ancestor(self):
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink output'):
            self.prepare('alias/output')

    def test_excluded_inputs(self):
        self.rows[0]['source'] = 'artifacts/leak.txt'
        with self.assertRaisesRegex(ValueError, 'excluded'):
            self.prepare()

    def test_policy_cannot_select_a_sibling_project(self):
        self.rows[0]['root'] = 'desktop'
        with self.assertRaisesRegex(ValueError, 'another project'):
            self.prepare()

    def test_local_reports_and_authority_inputs_are_excluded(self):
        for name in ['REPORT.md', 'report.md', '.env', 'instance.json', 'profiles/private.json', 'review-2026-09-05/notes.md']:
            with self.subTest(name=name):
                self.rows[0] = {'source': name, 'destination': 'a.txt'}
                with self.assertRaisesRegex(ValueError, 'excluded'):
                    self.prepare()

    def test_collision(self):
        self.rows.append({**self.rows[0], 'destination': 'A.TXT'})
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.prepare()

    def test_missing_required(self):
        self.rows[0]['source'] = 'absent'
        with self.assertRaises(FileNotFoundError):
            self.prepare()

    def test_symlink_ancestor(self):
        (self.engine / 'link').symlink_to(self.engine, target_is_directory=True)
        self.rows[0]['source'] = 'link/a.txt'
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.prepare()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO fixture')
    def test_special_file(self):
        os.mkfifo(self.engine / 'fifo')
        self.rows[0]['source'] = 'fifo'
        with self.assertRaisesRegex(ValueError, 'regular'):
            self.prepare()

    def test_binary_requires_matching_approval(self):
        (self.engine / 'asset.wasm').write_bytes(b'\0asm')
        self.rows[0]['source'] = 'asset.wasm'
        with self.assertRaisesRegex(ValueError, 'unreviewed binary'):
            self.prepare()
        self.rows[0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            self.prepare()
        self.rows[0]['sha256'] = identity(self.engine / 'asset.wasm')['sha256']
        self.prepare()

    def test_archive_exact_inventory(self):
        for action in ['add', 'change', 'remove']:
            out = self.prepare(action)
            target = out / 'source/a.txt'
            if action == 'add':
                (out / 'source/extra').write_text('unexpected')
            elif action == 'change':
                target.write_text('changed')
            else:
                target.unlink()
            with self.assertRaisesRegex(ValueError, 'inventory'):
                source.archive(out)

    def test_mutation_during_archive_cannot_produce_success_report(self):
        original_add = tarfile.TarFile.addfile
        for mutation in ['member', 'inventory']:
            with self.subTest(mutation=mutation):
                out = self.prepare(mutation)
                def mutate(tar, member, stream=None):
                    if mutation == 'member':
                        target = out / 'source/a.txt'
                        target.write_bytes(b'!' * target.stat().st_size)
                    else:
                        target = out / 'inventory.json'
                        target.write_bytes(target.read_bytes() + b'\n')
                    return original_add(tar, member, stream)
                with patch.object(tarfile.TarFile, 'addfile', mutate):
                    with self.assertRaisesRegex(ValueError, 'inventory'):
                        source.archive(out)
                self.assertTrue((out / 'public-source.tar.gz').is_file())
                self.assertFalse((out / 'archive-report.json').exists())


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.adapter = self.root / 'adapter'
        self.dependency = self.adapter / 'node_modules/playwright-core'
        self.dependency.mkdir(parents=True)
        for name in browser.PRODUCTION:
            (self.adapter / name).write_text('production')
        (self.adapter / 'package.json').write_text(json.dumps({'dependencies': {'playwright-core': '1.63.0'}}))
        (self.adapter / 'package-lock.json').write_text(json.dumps({'packages': {'': {}, 'node_modules/playwright-core': {'version': '1.63.0'}}}))
        for name in ['LICENSE', 'NOTICE', 'ThirdPartyNotices.txt', 'lib.js']:
            (self.dependency / name).write_text('required material')
        (self.dependency / 'package.json').write_text(json.dumps({'name': 'playwright-core', 'version': '1.63.0'}))
        (self.dependency / 'browsers.json').write_text(json.dumps({'browsers': [{'name': 'chromium-headless-shell', 'revision': '1243'}]}))
        self.policy = self.root / 'policy.json'
        write_json(self.policy, {'version': '1.63.0', 'lock_sha256': identity(self.adapter / 'package-lock.json')['sha256'], 'files': inventory(self.dependency)})

    def runtime_fixture(self):
        runtime = self.root / 'runtime'
        runtime.mkdir()
        (runtime / 'chrome').write_text('verified executable')
        node = self.root / 'node'
        node.write_text('verified node')
        verified = self.root / 'verified.json'
        write_json(verified, {'version': 'playwright-1.63.0-chromium-1243-fixture', 'browser': 'browser/chrome', 'node': {'sha256': identity(node)['sha256'], 'version': '24.20.0'}, 'files': {'browser/chrome': identity(runtime / 'chrome')}})
        return runtime, node, verified

    def test_excludes_caches_probes_unrelated_packages_preserves_materials(self):
        for name in ['spike.mjs', 'test/probe.mjs', 'node_modules/.vite/task-cache/cache.db', 'node_modules/unrelated/code.js']:
            file = self.adapter / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('excluded')
        runtime, node, verified = self.runtime_fixture()
        out = self.root / 'out'
        browser.package(runtime, 'chrome', node, '24.20.0', 'playwright-1.63.0-chromium-1243-new', out, self.adapter, self.policy, verified)
        actual = inventory(out / 'content')
        self.assertEqual(set(actual), {'browser/chrome'} | {'adapter/' + n for n in browser.PRODUCTION} | {'adapter/node_modules/playwright-core/' + n for n in inventory(self.dependency)})
        (runtime / 'chrome').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'runtime differs'):
            browser.package(runtime, 'chrome', node, '24.20.0', 'playwright-1.63.0-chromium-1243-new', self.root / 'other', self.adapter, self.policy, verified)

    def test_checked_in_policy_pins_the_checked_in_adapter_lock(self):
        # A version bump rewrites the adapter lock; the policy must follow it.
        root = Path(__file__).resolve().parents[1]
        policy = json.loads((root / 'distribution/browser-runtime-inputs.json').read_text())
        lock = identity(root / 'adapters/browser/package-lock.json')
        self.assertEqual(policy['lock_sha256'], lock['sha256'])

    def test_changed_lock_identity_and_dependency_files_reject(self):
        for mutation in ['extra', 'link', 'version', 'lock']:
            with self.subTest(mutation=mutation):
                if mutation == 'extra':
                    file = self.dependency / 'cache.db'
                    file.write_text('unreviewed')
                elif mutation == 'link':
                    file = self.dependency / 'link'
                    file.symlink_to(self.dependency / 'LICENSE')
                else:
                    file = self.dependency / 'package.json' if mutation == 'version' else self.adapter / 'package-lock.json'
                    original = file.read_text()
                    file.write_text(original.replace('1.63.0', '1.64.0'))
                with self.assertRaises(ValueError):
                    browser.adapter_inputs(self.adapter, self.policy)
                if mutation in ('extra', 'link'):
                    file.unlink()
                else:
                    file.write_text(original)

    def test_mutation_after_validation_rejects_unapproved_copies_and_node(self):
        runtime, node, verified = self.runtime_fixture()
        original_copy = shutil.copyfile
        for kind, changed in [('runtime', runtime / 'chrome'), ('dependency', self.dependency / 'lib.js'), ('production', self.adapter / 'adapter.mjs'), ('node', node)]:
            with self.subTest(kind=kind):
                original = changed.read_bytes()
                def mutate(src, dest):
                    if Path(src) == (runtime / 'chrome' if kind == 'node' else changed):
                        changed.write_bytes(b'!' * len(original))
                    return original_copy(src, dest)
                out = self.root / ('output-' + kind)
                try:
                    with patch.object(shutil, 'copyfile', mutate):
                        with self.assertRaisesRegex(ValueError, 'approved|changed'):
                            browser.package(runtime, 'chrome', node, '24.20.0', 'playwright-1.63.0-chromium-1243-new', out, self.adapter, self.policy, verified)
                    self.assertFalse((out / 'browser-tools-v2.json').exists())
                finally:
                    changed.write_bytes(original)

if __name__ == '__main__':
    unittest.main()
