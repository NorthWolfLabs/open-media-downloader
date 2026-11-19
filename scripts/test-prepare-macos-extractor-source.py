# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Controlled-source route tests for extractor preparation (macos_extractor_source.py).

Fixtures: a thin arm64 executable compiled here stands in for the source-built `run`
bootloader; producers are genuine PyInstaller 6.22.0 onefile assemblies of it (the stock
tests' writers and macOS steps); small source kits, receipts, plans and evidence are
generated from the fixture bytes and pass the real recipient verifier. Only new temporary
copies are signed, ad-hoc. Developer ID cases are canned controls: the requested commands
are recorded and performed ad-hoc, and the genuine Team checks refuse the result. No
identity, keychain, network, GUI or real producer is used, and no fixture is executed."""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import final_materials as fm
import macos_extractor as ex
import macos_extractor_source as source_route
import macos_signing as signing
import ytdlp_source

SCRIPTS = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load('omd_extractor_tests_for_source', 'test-prepare-macos-extractor.py')
NATIVE, VERSION, DEVID, TEAM = base.NATIVE, base.VERSION, base.DEVID, base.TEAM
PROFILE_ID = 'fixture-controlled-source-profile'
TARGET = {'arch': 'arm64', 'macos_minimum': '13.5', 'os': 'macos'}
digest = base.digest
run = base.run


def js(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class Boot:
    """Compiled once: fixture bootloaders and a fixture profile with one pinned input."""
    root = None

    @classmethod
    def get(cls):
        if cls.root is None:
            root = Path(tempfile.mkdtemp(prefix='omd-source-boot-')).resolve()
            cc = ['xcrun', 'clang', '-O0']
            for name, body, flags in (('run', 'int value = 42; int main(void){return value - 42;}', ['-arch', 'arm64', '-mmacosx-version-min=13.5']),
                                      ('other-run', 'int value = 43; int main(void){return value - 43;}', ['-arch', 'arm64', '-mmacosx-version-min=13.5']),
                                      ('fat-run', 'int main(void){return 0;}', ['-arch', 'arm64', '-arch', 'x86_64', '-mmacosx-version-min=13.5']),
                                      ('old-run', 'int main(void){return 0;}', ['-arch', 'arm64', '-mmacosx-version-min=13.0']),
                                      ('z-run', '#include <zlib.h>\nint main(void){return zlibVersion()[0] == 0;}', ['-arch', 'arm64', '-mmacosx-version-min=13.5', '-lz'])):
                (root / f'{name}.c').write_text(body + '\n')
                run(*cc, *flags, '-o', root / name, root / f'{name}.c')
            shutil.copyfile(root / 'run', root / 'resigned-run')
            run('/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', root / 'resigned-run')
            (root / 'corrupt-run').write_bytes(base.flip_code((root / 'run').read_bytes()))
            (root / 'fixture-source.tar.gz').write_bytes(b'fixture pinned source input\n')
            profile = {'schema': 'omd-ytdlp-source-profile-v1', 'id': PROFILE_ID, 'release_accepted': False,
                       'inputs': [{'id': 'fixture', 'file': 'fixture-source.tar.gz', 'sha256': digest(b'fixture pinned source input\n')}]}
            (root / 'profile.json').write_bytes(js(profile))
            cls.root = root
        return cls.root


def slices_of(boot):
    return [{'arch': 'arm64', 'cpu': 0x100000c, 'subtype': 0, 'uuid': ex.uuid_of(boot).hex(), 'sdk': ex.sdk_of(boot)}]


def source_producer(folder, boot_name='run', **options):
    folder.mkdir(parents=True)
    return base.producer(folder / 'yt-dlp_macos', 'arm64', bootloader=Boot.get() / boot_name, **options)


def pyinstaller_sources():
    import PyInstaller
    root = Path(PyInstaller.__file__).resolve().parent
    return {rel: digest((root / rel).read_bytes()) for rel in source_route.REPLAYED}


def receipt_for(producer, boot, plan_sha256, fingerprints_sha256):
    """A built receipt describing exactly these fixture bytes, as the builder records them."""
    data = producer.read_bytes()
    with tempfile.TemporaryDirectory(prefix='omd-source-receipt-') as folder:
        private, analysis = ex.private_analysis(data, 'arm64', slices_of(boot), folder, 'producer')
        policy = ytdlp_source.onefile_policy(data, boot, analysis['archive']['start'], analysis['archive']['end'], source_route.python_library(analysis, private))
    members = [{'name': m['name'], 'type': 'o', 'origin': 'fixture'} if m['type'] == 'o' else
               {'name': m['name'], 'type': m['type'], 'origin': 'fixture', 'bytes': m['expanded']['bytes'], 'sha256': m['expanded']['sha256']} for m in analysis['members']]
    natives = [{'name': m['name'], 'bytes': m['expanded']['bytes'], 'sha256': m['expanded']['sha256'], 'replay': 'identical',
                'signature': {'identifier': m['native']['identifier']}} for m in analysis['members'] if 'native' in m]
    linked = [r['path'] for r in ytdlp_source.macho_structure(boot, 'run')['commands'] if r['cmd'] in ytdlp_source.DYLIB_COMMANDS]
    identity = {'bytes': len(data), 'sha256': digest(data)}
    return {'schema': ytdlp_source.RECEIPT_SCHEMA, 'status': 'built', 'release_accepted': False, 'promotable': False, 'prototype': True,
            'plan_sha256': plan_sha256, 'profile': PROFILE_ID, 'profile_file': source_route.PROFILE_FILE, 'target': TARGET,
            'output': {'path': 'bin/omd-yt-dlp', **identity}, 'packaging_repeat': {'identical': True, 'sha256': identity['sha256']},
            'bootloader': {'compiled': {'run': digest(boot)}, 'removed_prebuilt': {'run': ex.STOCK_BOOTLOADER['sha256']}},
            'wheels': {'pyinstaller': {'natives': [{'path': source_route.WHEEL_BOOTLOADER, 'bytes': len(boot), 'sha256': digest(boot), 'minimum': '13.5.0'}]}},
            'closure': {'schema': ytdlp_source.PROOF_SCHEMA, 'problems': [], 'archive': {k: analysis['archive'][k] for k in ('start', 'end', 'entries', 'pkg_sha256', 'toc_sha256', 'cookie')},
                        'executable': {**identity, 'linked': linked}, 'members': members, 'natives': natives,
                        'outer': {'bootloader': {'bytes': len(boot), 'sha256': digest(boot), 'origin': 'fixture'}, 'policy': policy, 'replay': 'identical'},
                        'packed_verification': {'failed': 0, 'verified': len(natives), 'native_members': len(natives)},
                        'python': {'items': 3, 'matched': 3, 'fingerprints': {'sha256': fingerprints_sha256},
                                   'pyinstaller': {'version': ex.PYINSTALLER_VERSION, 'sources': pyinstaller_sources()}}}}


def write_kit(path, members, raw=()):
    """A recipient kit: gzip PAX tar under the kit prefix; `raw` adds (TarInfo, data) as is."""
    with open(path, 'xb') as out, gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(f'{ytdlp_source.KIT_PREFIX}/{name}')
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
        for info, data in raw:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return path


class Case:
    """One evidence-bound source fixture: producer, bootloader, kit and evidence files."""

    def __init__(self, root, name, producer, boot_name='run', receipt=None, plan=None, index=None, profile=None, raw=(), skip_index=()):
        # The receipt always describes the producer's own bootloader (`run`); a variant
        # bootloader is named only through the digests a `receipt` change records for it.
        f = Boot.get()
        self.root, self.producer = root / name, producer
        self.root.mkdir()
        self.boot_path = self.root / 'boot' / 'run'
        self.boot_path.parent.mkdir()
        shutil.copyfile(f / boot_name, self.boot_path)
        boot = self.boot_path.read_bytes()
        profile_raw = profile if profile is not None else (f / 'profile.json').read_bytes()
        plan_doc = {'schema': ytdlp_source.PLAN_SCHEMA, 'status': 'ready', 'profile': PROFILE_ID, 'profile_file': source_route.PROFILE_FILE,
                    'profile_sha256': digest((f / 'profile.json').read_bytes()), 'files': {source_route.KIT_PROFILE: digest(profile_raw)},
                    'inputs': [], 'npm': [], 'target': dict(TARGET), 'release_accepted': False, 'promotable': False}
        if plan:
            plan(plan_doc)
        plan_raw = js(plan_doc)
        fingerprints = js({'schema': 'omd-ytdlp-source-fingerprints-v1', 'rows': []})
        receipt_doc = receipt_for(producer, (f / 'run').read_bytes(), digest(plan_raw), digest(fingerprints))
        if receipt:
            receipt(receipt_doc)
        receipt_raw = js(receipt_doc)
        members = {source_route.KIT_PROFILE: profile_raw, source_route.KIT_PLAN: plan_raw, source_route.KIT_RECEIPT: receipt_raw,
                   f'receipt/{ytdlp_source.FINGERPRINTS}': fingerprints, 'sources/fixture-source.tar.gz': (f / 'fixture-source.tar.gz').read_bytes()}
        index_doc = {'schema': ytdlp_source.KIT_SCHEMA, 'profile': PROFILE_ID, 'profile_file': source_route.PROFILE_FILE, 'release_accepted': False,
                     'promotable': False, 'plan_sha256': digest(plan_raw), 'executable_sha256': digest(producer.read_bytes()),
                     'fingerprints_sha256': digest(fingerprints), 'terms': [], 'generated_sources': [], 'patches': [], 'limits': [],
                     'files': [{'path': n, 'role': 'fixture', 'bytes': len(d), 'sha256': digest(d)} for n, d in sorted(members.items()) if n not in skip_index]}
        if index:
            index(index_doc)
        members[source_route.KIT_INDEX] = js(index_doc)
        (self.root / 'kit').mkdir()
        self.kit = write_kit(self.root / 'kit' / 'source-kit.tar.gz', members, raw)
        data = producer.read_bytes()
        self.doc = {'schema': source_route.EVIDENCE_SCHEMA, 'route': source_route.ROUTE,
                    'profile': {'file': source_route.PROFILE_FILE, 'id': PROFILE_ID, 'sha256': digest((f / 'profile.json').read_bytes())},
                    'kit': signing.file_identity(self.kit), 'plan_sha256': digest(plan_raw), 'receipt_sha256': digest(receipt_raw),
                    'producer': {'bytes': len(data), 'sha256': digest(data)}, 'bootloader': {'bytes': len(boot), 'sha256': digest(boot)},
                    'version': VERSION, 'target_arch': 'arm64', 'release_accepted': False}
        (self.root / 'evidence').mkdir()
        self.count = 0

    def spec(self, change=None, raw=None, **paths):
        """Source spec for a (possibly changed) evidence document written to a new file."""
        doc = json.loads(json.dumps(self.doc))
        if change:
            change(doc)
        self.count += 1
        path = self.root / 'evidence' / f'evidence-{self.count}.json'
        path.write_bytes(raw if raw is not None else js(doc))
        result = {'evidence': {'path': str(path), 'sha256': digest(path.read_bytes())}, 'kit': str(self.kit), 'bootloader': str(self.boot_path)}
        result.update(paths)
        return result

    def request(self, source=None, **change):
        data = self.producer.read_bytes()
        return {'producer': str(self.producer), 'producer_sha256': digest(data), 'version': VERSION, 'target_arch': 'arm64',
                'mode': 'development-adhoc', 'identity': '-', 'team_id': None, 'source': source or self.spec(), **change}


def records_boot(name):
    """Receipt change: the build recorded bootloader `name` as compiled, in the wheel and in the outer replay."""
    data = (Boot.get() / name).read_bytes()

    def change(doc):
        doc['bootloader']['compiled']['run'] = digest(data)
        for row in (doc['wheels']['pyinstaller']['natives'][0], doc['closure']['outer']['bootloader']):
            row.update(bytes=len(data), sha256=digest(data))
    return change


def pinned_fixture_profile(test):
    patcher = mock.patch.object(source_route, 'PROFILE_PATH', Boot.get() / 'profile.json')
    patcher.start()
    test.addCleanup(patcher.stop)


def prepare(root, case, name='prepared', runner_factory=signing.Runner, **change):
    plan = ex.inspect(case.request(**change), temp_root=root)
    plan_path = base.write_plan(root, plan, f'{name}-plan.json')
    out = root / f'{name}-out'
    out.mkdir()
    status, report_path = ex.execute(plan_path, out / 'yt-dlp_macos', root / f'{name}-work', runner_factory=runner_factory)
    return plan, status, json.loads(report_path.read_text()), out / 'yt-dlp_macos', report_path


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SourceRoute(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='omd-source-route-')).resolve()
        cls.patcher = mock.patch.object(source_route, 'PROFILE_PATH', Boot.get() / 'profile.json')
        cls.patcher.start()
        cls.source = source_producer(cls.root / 'producer')
        cls.case = Case(cls.root, 'case', cls.source)
        cls.plan, cls.status, cls.report, cls.prepared, cls.report_path = prepare(cls.root, cls.case)
        assert cls.status == 'prepared-development-candidate', cls.report['failure']

    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        shutil.rmtree(cls.root, ignore_errors=True)

    def scratch(self):
        folder = Path(tempfile.mkdtemp(prefix='t-', dir=self.root))
        return folder

    def ident(self, path):
        return {'path': str(path), 'sha256': digest(Path(path).read_bytes())}

    def test_signature_only_transformation_on_the_compiled_bootloader(self):
        plan, report, out, source = self.plan, self.report, self.prepared, self.source
        self.assertEqual((plan['method'], report['method']), (ex.SOURCE_METHOD, ex.SOURCE_METHOD))
        self.assertNotIn('stock_slices', plan)
        self.assertEqual(plan['bootloader_slices'], slices_of(self.case.boot_path.read_bytes()))
        self.assertEqual(sorted(plan['tool']), ['check-macos-payload.py', 'macos_extractor.py', 'macos_extractor_source.py', 'macos_signing.py', 'ytdlp_source.py'])
        evidence = plan['source']
        self.assertEqual((evidence['route'], evidence['kit']['sha256'], evidence['bootloader']['sha256']),
                         (source_route.ROUTE, self.case.doc['kit']['sha256'], self.case.doc['bootloader']['sha256']))
        self.assertTrue(evidence['kit']['recipient_verifier']['verified'])
        self.assertEqual((evidence['producer_binding']['natives'], evidence['producer_binding']['members']), (2, len(plan['members'])))
        self.assertEqual(evidence['bootloader']['load_commands'][-1], 'LC_CODE_SIGNATURE')
        self.assertIn('linker_signed', json.dumps(evidence['bootloader']['signature']))
        self.assertEqual(report['steps'], ['plan-rederived', 'producer-reproduced', 'members-signed', 'outer-assembled', 'candidate-verified'])
        self.assertIn('compiled bootloader', report['reproduction']['note'])
        self.assertEqual(report['pinned']['replayed_sources'], pyinstaller_sources())
        proof = report['verification']['structural_equivalence']
        self.assertEqual((proof['signature_only_natives'], proof['identical_non_natives']), (2, 7))
        crypto = report['verification']['cryptographic']
        self.assertEqual((crypto['members']['verified'], crypto['members']['failed'], crypto['outer']['exit']), (2, 0, 0))
        candidate = out.read_bytes()
        self.assertEqual(report['output']['sha256'], digest(candidate))
        self.assertFalse(report['output']['identical_to_producer'])
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o755)
        # Independent of the module: non-native stored bytes identical, natives signature-only.
        old, _ = base.stored_entries(source)
        new, new_pkg = base.stored_entries(out)
        self.assertEqual([(n, c, f) for n, c, f, _ in old], [(n, c, f) for n, c, f, _ in new])
        for (name, code, flag, a), (_, _, _, b) in zip(old, new):
            if code == 'b':
                self.assertNotEqual(a, b, name)
                pa, pb = (zlib.decompress(x) if flag else x for x in (a, b))
                self.assertEqual(signing.signature_independent_sha256(pa), signing.signature_independent_sha256(pb), name)
            else:
                self.assertEqual(a, b, name)
        boot = self.case.boot_path.read_bytes()
        self.assertEqual(ex.uuid_of(candidate), hashlib.sha1(new_pkg + ex.uuid_of(boot)).digest()[:16])
        self.assertEqual((ex.sdk_of(candidate), signing.macho_layout(candidate)[0]['container']['format']), (ex.sdk_of(source.read_bytes()), 'thin'))
        outer = report['source']['candidate_outer']
        self.assertEqual((outer['arch'], outer['bootloader_uuid'], outer['view_sha256']),
                         ('arm64', ex.uuid_of(boot).hex(), evidence['producer_binding']['outer_policy']['view_sha256']))
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', out], check=True, capture_output=True)
        for image in signing.signature(candidate):
            self.assertEqual((image['adhoc'], image['team'], image['runtime'], image['entitlements']), (True, None, False, None))
        result = ex.verify_pair(self.ident(source), self.ident(out), VERSION, 'arm64', 'development-adhoc', None, self.root, source=self.case.spec())
        self.assertTrue(result['pass'])
        self.assertEqual((result['method'], result['source']['prepared_outer']['uuid']), (ex.SOURCE_METHOD, ex.uuid_of(candidate).hex()))

    def test_no_fallback_between_routes(self):
        # The stock route refuses the source producer; it is never relabelled.
        stock = {k: v for k, v in self.case.request().items() if k != 'source'}
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID for the pinned bootloader"):
            ex.inspect(stock, temp_root=self.root)
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID"):
            ex.verify_pair(self.ident(self.source), self.ident(self.prepared), VERSION, 'arm64', 'development-adhoc', None, self.root)
        # Source evidence never turns a stock producer into a controlled-source one.
        folder = self.scratch() / 'stock'
        folder.mkdir()
        stock_producer = base.producer(folder / 'yt-dlp_macos', 'arm64')
        with self.assertRaisesRegex(ValueError, 'not the evidence-bound controlled-source producer'):
            ex.inspect({**stock, 'producer': str(stock_producer), 'producer_sha256': digest(stock_producer.read_bytes()), 'source': self.case.spec()}, temp_root=self.root)
        with self.assertRaisesRegex(ValueError, 'Source evidence needs'):
            ex.inspect({**stock, 'source': None}, temp_root=self.root)
        with self.assertRaisesRegex(ValueError, 'Request needs'):
            ex.inspect({**stock, 'source': self.case.spec(), 'extra': 1}, temp_root=self.root)
        # A stock plan keeps its exact default shape.
        plan = ex.inspect({**stock, 'producer': str(stock_producer), 'producer_sha256': digest(stock_producer.read_bytes())}, temp_root=self.root)
        self.assertEqual((plan['method'], 'source' in plan, 'bootloader_slices' in plan, sorted(plan['tool'])),
                         (ex.METHOD, False, False, ['check-macos-payload.py', 'macos_extractor.py', 'macos_signing.py']))
        self.assertEqual(plan['allowed_differences'], ex.ALLOWED_DIFFERENCES)

    def test_evidence_and_input_binding_refusals(self):
        case, spec = self.case, self.case.spec
        link = case.root / 'linked-evidence.json'
        link.symlink_to(spec()['evidence']['path'])
        kit_link = case.root / 'linked-kit.tar.gz'
        kit_link.symlink_to(case.kit)
        boot_link = case.root / 'linked-run'
        boot_link.symlink_to(case.boot_path)
        good = spec()
        bad_digest = {**good, 'evidence': {**good['evidence'], 'sha256': '0' * 64}}
        stock_boot = {'bytes': ex.STOCK_BOOTLOADER['bytes'], 'sha256': ex.STOCK_BOOTLOADER['sha256']}
        cases = [
            (bad_digest, {}, 'Source evidence digest differs'),
            ({**good, 'evidence': {'path': 'relative.json', 'sha256': good['evidence']['sha256']}}, {}, 'absolute path'),
            ({**good, 'evidence': {'path': str(link), 'sha256': good['evidence']['sha256']}}, {}, '(?i)symlink'),
            ({**good, 'kit': str(kit_link)}, {}, '(?i)symlink'),
            ({**good, 'bootloader': str(boot_link)}, {}, '(?i)symlink'),
            ({**good, 'kit': 'kit.tar.gz'}, {}, 'Source kit must be an absolute path'),
            ({'evidence': good['evidence'], 'kit': good['kit']}, {}, 'Source evidence needs'),
            (spec(lambda d: d.update(extra=True)), {}, 'fields differ'),
            (spec(lambda d: d.pop('receipt_sha256')), {}, 'fields differ'),
            (spec(lambda d: d.update(schema='omd-macos-extractor-source-evidence-v2')), {}, 'Unsupported source evidence schema'),
            (spec(lambda d: d.update(route='upstream-stock')), {}, 'Unsupported source evidence schema or route'),
            (spec(lambda d: d.update(release_accepted=True)), {}, 'release_accepted false'),
            (spec(lambda d: d.update(target_arch='universal2')), {}, 'Unsupported controlled-source target'),
            (spec(lambda d: d.update(target_arch='x86_64')), {}, 'Unsupported controlled-source target'),
            (spec(lambda d: d['profile'].update(file='distribution/yt-dlp-source/profile.json')), {}, 'must name the pinned profile'),
            (spec(lambda d: d['profile'].update(sha256='0' * 64)), {}, 'differs from the pinned repository profile'),
            (spec(lambda d: d['profile'].update(id='other')), {}, 'profile id differs'),
            (spec(lambda d: d.update(bootloader=stock_boot)), {}, 'stock bootloader is not controlled-source evidence'),
            (spec(lambda d: d['producer'].update(sha256='1' * 64)), {}, 'not the evidence-bound controlled-source producer'),
            (spec(lambda d: d.update(version='2026.09.01')), {}, 'requested version differs'),
            (spec(lambda d: d['kit'].update(sha256='2' * 64)), {}, 'source kit differs from the evidence-bound reviewed kit'),
            (spec(lambda d: d['kit'].update(bytes=d['kit']['bytes'] + 1)), {}, 'source kit differs'),
            (spec(lambda d: d.update(plan_sha256='3' * 64)), {}, 'kit index does not bind'),
            (spec(lambda d: d.update(receipt_sha256='4' * 64)), {}, 'kit receipt differs from the evidence receipt digest'),
            (spec(lambda d: d['bootloader'].update(sha256='5' * 64)), {}, 'kit receipt compiled a different bootloader'),
            (good, {'target_arch': 'universal2'}, 'differs from the evidence target'),
            (good, {'version': '2026.09.01'}, r"differ from the requested 2026.09.01|requested version differs"),
        ]
        for source, change, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.inspect(case.request(source, **change), temp_root=self.root)
        # The real anchor is the repository profile: a kit profile that differs is refused.
        with mock.patch.object(source_route, 'PROFILE_PATH', ytdlp_source.REPO / source_route.PROFILE_FILE), \
                self.assertRaisesRegex(ValueError, 'differs from the pinned repository profile'):
            ex.inspect(case.request(), temp_root=self.root)

    def test_kit_and_receipt_refusals(self):
        root = self.scratch()
        src = self.source
        f = Boot.get()

        def build(name, **options):
            return Case(root, name, src, **options)

        def member(name, change):
            def edit(doc):
                change(next(m for m in doc['closure']['members'] if m['name'] == name))
            return edit
        symlink = tarfile.TarInfo(f'{ytdlp_source.KIT_PREFIX}/receipt/link')
        symlink.type, symlink.linkname = tarfile.SYMTYPE, 'plan.json'
        escape = tarfile.TarInfo(f'{ytdlp_source.KIT_PREFIX}/../escape')
        escape.size = 1
        duplicate = tarfile.TarInfo(f'{ytdlp_source.KIT_PREFIX}/{source_route.KIT_PLAN.upper()}')
        duplicate.size = 2
        cases = [
            (build('profile', profile=b'{"id": "fixture-controlled-source-profile", "inputs": [], "schema": "omd-ytdlp-source-profile-v1"}\n'),
             'kit profile differs from the pinned repository profile'),
            (build('malformed-profile', profile=b'{"id": "fixture-controlled-source-profile", "inputs": []}\n'), 'fails the recipient verifier: KeyError'),
            (build('status', receipt=lambda d: d.update(status='failed')), 'Kit receipt does not bind its plan|not a built, unaccepted'),
            (build('accepted', receipt=lambda d: d.update(release_accepted=True)), 'not a built, unaccepted'),
            (build('problems', receipt=lambda d: d['closure'].update(problems=['x'])), 'closure proof is not clean'),
            (build('replay', receipt=lambda d: d['closure']['natives'][0].update(replay='differs')), 'does not replay every packed native'),
            (build('outer-replay', receipt=lambda d: d['closure']['outer'].update(replay='differs')), 'does not replay the executable'),
            (build('unmatched', receipt=lambda d: d['closure']['python'].update(matched=2)), 'unmatched code objects'),
            (build('unverified', receipt=lambda d: d['closure']['packed_verification'].update(failed=1)), 'unverified packed natives'),
            (build('compiled', receipt=lambda d: d['bootloader']['compiled'].update(run='6' * 64)), 'compiled a different bootloader'),
            (build('prebuilt', receipt=lambda d: d['bootloader']['removed_prebuilt'].update(run='6' * 64)), 'removal of the stock prebuilt bootloader'),
            (build('wheel', receipt=lambda d: d['wheels']['pyinstaller'].update(natives=[])), 'wheel does not carry'),
            (build('output', receipt=lambda d: d['output'].update(sha256='7' * 64)), 'does not record the evidence producer'),
            (build('repeat', receipt=lambda d: d['packaging_repeat'].update(identical=False)), 'does not record the evidence producer'),
            (build('missing', receipt=lambda d: d['closure'].pop('outer')), 'lacks closure.outer'),
            (build('malformed-wheel', receipt=lambda d: d['wheels']['pyinstaller'].update(natives=7)), 'Malformed controlled-source kit records or bootloader: TypeError'),
            (build('malformed-natives', receipt=lambda d: d['closure'].update(natives={'name': 'x'})), 'does not replay every packed native'),
            (build('malformed-native-name', receipt=lambda d: d['closure']['natives'][0].update(name=[])), 'Malformed packed native'),
            (build('malformed-native-signature', receipt=lambda d: d['closure']['natives'][0].update(signature=1)), 'Malformed packed native'),
            (build('plan-of-receipt', receipt=lambda d: d.update(plan_sha256='8' * 64)), 'Kit receipt does not bind its plan|does not bind the evidence plan'),
            (build('target', receipt=lambda d: d.update(target={**TARGET, 'macos_minimum': '14.0'})), 'does not bind the evidence plan, profile and target'),
            (build('member', receipt=member('fixture/data.txt', lambda m: m.update(sha256='9' * 64))), r'members differ from the evidence receipt \(entry \d+\)'),
            (build('order', receipt=lambda d: d['closure']['members'].reverse()), r'members differ from the evidence receipt \(entry 0\)'),
            (build('identifier', receipt=lambda d: d['closure']['natives'][0]['signature'].update(identifier='other')), 'packed natives differ'),
            (build('archive', receipt=lambda d: d['closure']['archive'].update(toc_sha256='a' * 64)), 'CArchive layout differs'),
            (build('policy', receipt=lambda d: d['closure']['outer']['policy'].update(uuid='0' * 32)), 'onefile policy'),
            (build('pins', receipt=lambda d: d['closure']['python']['pyinstaller']['sources'].update({'utils/osx.py': 'b' * 64})), 'running PyInstaller differs'),
            (build('pins-missing', receipt=lambda d: d['closure']['python']['pyinstaller']['sources'].pop('archive/writers.py')), 'does not pin the replayed'),
            (build('pyinstaller', receipt=lambda d: d['closure']['python']['pyinstaller'].update(version='6.22.2')), 'another PyInstaller version'),
            (build('plan-profile', plan=lambda d: d.update(profile_sha256='c' * 64)), 'kit plan does not bind the pinned profile'),
            (build('plan-target', plan=lambda d: d.update(target={**TARGET, 'arch': 'x86_64'})), 'kit plan target differs'),
            (build('index', index=lambda d: d.update(executable_sha256='d' * 64)), 'kit index does not bind'),
            (build('unindexed', skip_index=(source_route.KIT_RECEIPT,)), 'Kit index and members differ'),
            (build('symlink', raw=[(symlink, None)]), 'Kit members must be regular files'),
            (build('escape', raw=[(escape, b'x')]), 'unsafe|outside|Unsafe'),
            (build('duplicate', raw=[(duplicate, b'{}')]), 'Duplicate or colliding kit member'),
        ]
        for case, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.inspect(case.request(), temp_root=root)
        # The kit bytes themselves: one changed byte breaks the evidence-bound digest.
        tampered = build('tampered')
        data = bytearray(tampered.kit.read_bytes())
        data[-40] ^= 1
        tampered.kit.chmod(0o644)
        tampered.kit.write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, 'source kit differs from the evidence-bound reviewed kit'):
            ex.inspect(tampered.request(), temp_root=root)
        self.assertTrue((f / 'run').exists())

    def test_compiled_bootloader_refusals(self):
        root = self.scratch()
        cases = [('fat-run', 'not a thin 64-bit Mach-O image'), ('resigned-run', 'only its ad-hoc linker signature'),
                 ('corrupt-run', 'linker signature does not verify'), ('old-run', 'minimum 13.0.0 differs from the profile target'),
                 ('z-run', 'links libraries other than the recorded system libraries')]
        for name, why in cases:
            # The receipt records the standard bootloader's libraries and the producer is unchanged:
            # each variant fails its own structural check before the producer is examined.
            case = Case(root, name, self.source, boot_name=name, receipt=records_boot(name))
            with self.subTest(name), self.assertRaisesRegex(ValueError, why):
                ex.inspect(case.request(), temp_root=root)
        # A genuine compiled bootloader that did not build this producer: the UUID rule fails.
        other = Case(root, 'other', self.source, boot_name='other-run', receipt=records_boot('other-run'))
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID"):
            ex.inspect(other.request(), temp_root=root)

    def rebuild(self, root, name, replacements, boot=None):
        folder = root / name
        folder.mkdir()
        data = self.source.read_bytes()
        boot = boot or self.case.boot_path.read_bytes()
        analysis = ex.analyse(self.source, data, 'arm64', slices_of(self.case.boot_path.read_bytes()))
        (folder / 'pkg').write_bytes(ex.build_pkg(data, analysis, self.source, replacements))
        return ex.assemble(signing.Runner(folder), boot, folder / 'pkg', 'arm64', folder / 'out', 'yt-dlp_macos', 'development-adhoc', '-', analysis['sdk'])

    def verify(self, candidate, mode='development-adhoc', team=None):
        return ex.verify_pair(self.ident(self.source), self.ident(candidate), VERSION, 'arm64', mode, team, self.root, source=self.case.spec())

    def test_prepared_tampering_is_detected(self):
        root = self.scratch()
        members = {m['name']: m['index'] for m in self.plan['members']}
        signed = {row['index']: (self.root / 'prepared-work/members' / f"{row['index']:05d}").read_bytes() for row in self.report['members']}
        python = members['Python.framework/Versions/3.14/Python']
        renamed = root / 'renamed.dylib'
        renamed.write_bytes(signed[python])
        run('/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'other.identifier', renamed)
        cases = [('data', {**signed, members['fixture/data.txt']: b'other fixture data\n'}, 'fixture/data.txt: non-native member bytes differ'),
                 ('script', {**signed, members['yt_dlp_ejs/yt/solver/core.min.js']: b'export const solver = 2;\n'}, 'non-native member bytes differ'),
                 ('native-code', {**signed, python: base.flip_code(signed[python])}, 'bytes other than the signature changed'),
                 ('identifier', {**signed, python: renamed.read_bytes()}, 'signing identifier changed')]
        for name, replacements, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                self.verify(self.rebuild(root, name, replacements))
        # Another genuine compiled bootloader assembles a structurally valid onefile, but it is
        # not the evidence-bound bootloader assembly.
        other = self.rebuild(root, 'other-boot', signed, (Boot.get() / 'other-run').read_bytes())
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID"):
            self.verify(other)
        data = self.prepared.read_bytes()
        code = bytearray(base.flip_code(data))
        (root / 'outer-code').mkdir()
        (root / 'outer-code/yt-dlp_macos').write_bytes(bytes(code))
        run('/usr/bin/codesign', '-s', '-', '--force', '--timestamp=none', root / 'outer-code/yt-dlp_macos')
        with self.assertRaisesRegex(ValueError, 'arm64 bootloader bytes differ'):
            self.verify(root / 'outer-code/yt-dlp_macos')
        _, _, _, _, commands = signing.load_commands(data)
        at = next(a for c, a, _ in commands if c == ex.LC_UUID)
        uuid = bytearray(data)
        uuid[at + 8] ^= 1
        (root / 'uuid').mkdir()
        (root / 'uuid/yt-dlp_macos').write_bytes(bytes(uuid))
        run('/usr/bin/codesign', '-s', '-', '--force', '--timestamp=none', root / 'uuid/yt-dlp_macos')
        with self.assertRaisesRegex(ValueError, "arm64 LC_UUID is not PyInstaller's"):
            self.verify(root / 'uuid/yt-dlp_macos')
        (root / 'trailing').mkdir()
        (root / 'trailing/yt-dlp_macos').write_bytes(data + b'\0')
        with self.assertRaisesRegex(ValueError, 'must end its image|Bytes after'):
            self.verify(root / 'trailing/yt-dlp_macos')
        with self.assertRaisesRegex(ValueError, 'producer itself'):
            self.verify(self.source)
        corrupted = self.rebuild(root, 'crypto', {**signed, python: base.flip_code(signed[python])})
        with mock.patch.object(ex, 'compare', return_value={}):
            result = self.verify(corrupted)
        self.assertFalse(result['pass'])
        self.assertEqual(result['cryptographic']['members']['failed'], 1)
        # Genuine Developer ID requirement: an ad-hoc candidate is never Team-ready.
        devid = self.verify(self.prepared, 'developer-id', TEAM)
        self.assertFalse(devid['pass'])
        self.assertEqual((devid['cryptographic']['members']['failed'], devid['cryptographic']['members']['verified']), (2, 0))
        self.assertNotEqual(devid['cryptographic']['outer']['exit'], 0)

    def test_execute_stale_plan_relabel_and_paths(self):
        root = self.scratch()
        folder = root / 'producer'
        folder.mkdir()
        producer = folder / 'yt-dlp_macos'
        shutil.copyfile(self.source, producer)
        case = Case(root, 'case', producer)
        plan = ex.inspect(case.request(), temp_root=root)
        plan_path = base.write_plan(root, plan)
        edited = json.loads(plan_path.read_text())
        edited['source']['bootloader']['uuid'] = '0' * 32
        status, report = ex.execute(base.write_plan(root, edited, 'edited.json'), root / 'edited-out', root / 'edited-work')
        self.assertEqual(status, 'failed')
        self.assertIn('source evidence or analysis changed since the plan', json.loads(report.read_text())['failure'])
        self.assertFalse((root / 'edited-out').exists())
        for name, value in (('stock-method.json', {**plan, 'method': ex.METHOD}),
                            ('stock-relabel.json', {**plan, 'request': {k: v for k, v in plan['request'].items() if k != 'source'}})):
            with self.subTest(name), self.assertRaisesRegex(ValueError, 'plan method differs from its producer route'):
                ex.execute(base.write_plan(root, value, name), root / 'relabel-out', root / 'relabel-work')
        refusals = [(case.kit.parent / 'out', root / 'w1', 'independent of the source evidence, kit and bootloader directories'),
                    (root / 'o2', case.boot_path.parent / 'work', 'independent of the source evidence, kit and bootloader directories'),
                    (root / 'o3', Path(plan['request']['source']['evidence']['path']).parent / 'work', 'independent of the source evidence'),
                    (folder / 'out', root / 'w4', 'independent of the producer directory'), (plan_path, root / 'w5', 'already exists')]
        for output, work, why in refusals:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.execute(plan_path, output, work)
        # Inputs replaced after inspection: re-derivation refuses before anything is written.
        original = case.boot_path.read_bytes()
        case.boot_path.write_bytes((Boot.get() / 'other-run').read_bytes())
        status, report = ex.execute(plan_path, root / 'o6', root / 'w6')
        self.assertEqual(status, 'failed')
        self.assertIn('compiled bootloader differs from the evidence-bound bootloader', json.loads(report.read_text())['failure'])
        self.assertFalse((root / 'o6').exists())
        case.boot_path.write_bytes(original)
        evidence = Path(plan['request']['source']['evidence']['path'])
        evidence.write_bytes(evidence.read_bytes() + b'\n')
        status, report = ex.execute(plan_path, root / 'o7', root / 'w7')
        self.assertIn('Source evidence digest differs', json.loads(report.read_text())['failure'])
        self.assertFalse((root / 'o7').exists())

    def test_failure_after_writing_removes_only_the_owned_output(self):
        root = self.scratch()
        real = signing.file_identity
        for route, make, scenario in (
                (route, make, scenario)
                for route, make in (('source', lambda: self.case.request()), ('stock', None))
                for scenario in ('owned', 'replacement', 'unlink-error')):
            name = f'{route}-{scenario}'
            with self.subTest(route=route, scenario=scenario):
                if make is None:
                    folder = root / f'{name}-src'
                    folder.mkdir()
                    producer = base.producer(folder / 'yt-dlp_macos', 'arm64')
                    request = base.request(producer, target_arch='arm64')
                else:
                    request = make()
                plan_path = base.write_plan(root, ex.inspect(request, temp_root=root), f'{name}-plan.json')
                out = root / f'{name}-out'
                out.mkdir()
                target = out / 'yt-dlp_macos'
                def fake(path):
                    if Path(path) != target:
                        return real(path)
                    if scenario == 'replacement':
                        target.rename(out / 'owned-original')
                        target.write_bytes(b'keep replacement')
                    return {'bytes': 0, 'sha256': '0' * 64}
                real_unlink = Path.unlink
                def unlink(path, *args, **kwargs):
                    if Path(path) == target and scenario == 'unlink-error':
                        raise PermissionError('injected cleanup refusal')
                    return real_unlink(path, *args, **kwargs)
                with mock.patch.object(signing, 'file_identity', side_effect=fake), mock.patch.object(Path, 'unlink', new=unlink):
                    status, report = ex.execute(plan_path, target, root / f'{name}-work')
                report = json.loads(report.read_text())
                self.assertEqual(status, 'failed')
                self.assertIn('Written output differs from the verified candidate', report['failure'])
                if scenario == 'owned':
                    self.assertTrue(report['output_removed'])
                    self.assertFalse(target.exists())
                else:
                    self.assertFalse(report['output_removed'])
                    self.assertTrue(target.exists())
                    if scenario == 'replacement':
                        self.assertEqual(target.read_bytes(), b'keep replacement')
                    else:
                        self.assertIn('injected cleanup refusal', report['cleanup_failure'])
        # An output path that already exists is never overwritten or removed.
        existing = root / 'existing'
        existing.write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            ex.execute(root / 'source-owned-plan.json', existing, root / 'existing-work')
        self.assertEqual(existing.read_bytes(), b'keep')

    def test_report_route_binding(self):
        root = self.scratch()
        spec = {'path': str(self.prepared), 'sha256': digest(self.prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64'}
        report = {'path': str(self.report_path), 'sha256': digest(self.report_path.read_bytes())}
        producer_sha = digest(self.source.read_bytes())
        proof = ex.check_report(report, spec, self.source, producer_sha, 'development-adhoc', None, root, source=self.case.spec())
        self.assertEqual((proof['method'], proof['signature_only_natives'], proof['source']['kit_sha256']), (ex.SOURCE_METHOD, 2, self.case.doc['kit']['sha256']))
        with self.assertRaisesRegex(ValueError, 'comes from the controlled-source route'):
            ex.check_report(report, spec, self.source, producer_sha, 'development-adhoc', None, root)
        # A stock-route report cannot be presented as a controlled-source report, edited or not.
        folder = root / 'stock-src'
        folder.mkdir()
        stock = base.producer(folder / 'yt-dlp_macos', 'arm64')
        _, status, stock_report, stock_prepared = base.prepare(self, root, stock, 'arm64', name='stock')
        self.assertEqual(status, 'prepared-development-candidate')
        stock_path = root / 'stock-work/extractor-report.json'
        stock_spec = {'path': str(stock_prepared), 'sha256': digest(stock_prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64'}
        relabelled = json.loads(stock_path.read_text())
        relabelled['method'] = ex.SOURCE_METHOD
        relabelled_path = root / 'relabelled.json'
        relabelled_path.write_bytes(signing.json_bytes(relabelled))
        forged = json.loads(stock_path.read_text())
        forged['method'], forged['request']['source'] = ex.SOURCE_METHOD, self.case.spec()
        forged_path = root / 'forged.json'
        forged_path.write_bytes(signing.json_bytes(forged))
        # The forged report names this exact evidence; the proof is still re-derived and the
        # stock producer is not the evidence producer.
        cases = [(stock_path, 'a stock-route report cannot be relabelled'), (relabelled_path, 'different source evidence'),
                 (forged_path, 'not the evidence-bound controlled-source producer')]
        for path, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.check_report({'path': str(path), 'sha256': digest(path.read_bytes())}, stock_spec, stock, digest(stock.read_bytes()), 'development-adhoc', None, root,
                                source=self.case.spec())
        with self.assertRaisesRegex(ValueError, 'A stock-route report cannot carry source evidence'):
            ex.check_report(self.relabel_stock(root, stock_path), stock_spec, stock, digest(stock.read_bytes()), 'development-adhoc', None, root)
        other = self.case.spec(raw=js(self.case.doc) + b' ')
        with self.assertRaisesRegex(ValueError, 'different source evidence'):
            ex.check_report(report, spec, self.source, producer_sha, 'development-adhoc', None, root, source=other)
        with self.assertRaisesRegex(ValueError, 'different signing mode or Team ID'):
            ex.check_report(report, spec, self.source, producer_sha, 'developer-id', TEAM, root, source=self.case.spec())
        with self.assertRaisesRegex(ValueError, 'Report version or architecture differs'):
            ex.check_report(report, {**spec, 'arch': 'x86_64'}, self.source, producer_sha, 'development-adhoc', None, root, source=self.case.spec())

    def relabel_stock(self, root, stock_path):
        """A stock report whose request was edited to carry source evidence (method unchanged)."""
        doc = json.loads(stock_path.read_text())
        doc['request']['source'] = self.case.spec()
        path = root / 'stock-with-source.json'
        path.write_bytes(signing.json_bytes(doc))
        return {'path': str(path), 'sha256': digest(path.read_bytes())}

    def test_developer_id_commands_and_genuine_refusal_canned(self):
        """Canned control: the identity is never used. Sign commands are recorded, then
        performed ad-hoc, and the genuine Developer ID checks refuse the result."""
        root = self.scratch()
        requested = []

        class Substitute(signing.Runner):
            def __call__(self, argv, label, timeout=600, check=True):
                argv = [str(x) for x in argv]
                flag = next((x for x in ('--sign', '-s') if x in argv), None)
                if argv[0] == signing.CODESIGN and flag and argv[argv.index(flag) + 1] != '-':
                    requested.append(list(argv))
                    options = [x for x in argv[1:-1] if x not in ('--timestamp', '--options=runtime')]
                    options[options.index(flag) + 1] = '-'
                    argv = [argv[0], *options, '--timestamp=none', argv[-1]]
                return super().__call__(argv, label, timeout, check)
        plan, status, report, out, _ = prepare(root, self.case, runner_factory=Substitute, mode='developer-id', identity=DEVID, team_id=TEAM)
        self.assertEqual(plan['signing']['outer_argv'], ['/usr/bin/codesign', '-s', DEVID, '--force', '--all-architectures', '--timestamp', '--options=runtime', '<extractor>'])
        self.assertEqual(status, 'failed')
        self.assertIn('signature mode/team mismatch', report['failure'])
        self.assertFalse(out.exists())
        self.assertTrue(report['reproduction']['equal_to_producer'])
        first = next(m for m in plan['members'] if 'native' in m)
        self.assertEqual(requested, [['/usr/bin/codesign', '--force', '--sign', DEVID, '--timestamp', '--identifier', first['native']['identifier'],
                                      str(root / 'prepared-work/members' / f"{first['index']:05d}")]])

    def test_preparer_cli_requires_all_source_options(self):
        cli = load('omd_prepare_cli', 'prepare-macos-extractor.py')
        root = self.scratch()
        spec = self.case.spec()
        common = ['inspect', '--producer', str(self.source), '--producer-sha256', digest(self.source.read_bytes()), '--version', VERSION,
                  '--target-arch', 'arm64', '--mode', 'development-adhoc', '--identity', '-']
        options = ['--source-evidence', spec['evidence']['path'], '--source-evidence-sha256', spec['evidence']['sha256'],
                   '--source-kit', spec['kit'], '--source-bootloader', spec['bootloader']]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main([*common, '--plan', str(root / 'partial.json'), *options[:6]]), 1)
        self.assertIn('together', err.getvalue())
        self.assertFalse((root / 'partial.json').exists())
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main([*common, '--plan', str(root / 'plan.json'), *options]), 0)
        self.assertEqual(json.loads(out.getvalue())['method'], ex.SOURCE_METHOD)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main([*common, '--plan', str(self.case.kit.parent / 'plan.json'), *options]), 1)
        self.assertIn('independent of the source evidence', err.getvalue())


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SigningIntegration(unittest.TestCase):
    def setUp(self):
        self.sign = load('omd_test_sign_macos_for_source', 'test-sign-macos.py')
        self.addCleanup(lambda: self.sign.Native.root and shutil.rmtree(self.sign.Native.root, ignore_errors=True))
        self.root = Path(tempfile.mkdtemp(prefix='omd-source-signing-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        pinned_fixture_profile(self)

    def test_signing_inspection_repeats_the_source_route_proof(self):
        source = source_producer(self.root / 'src')
        case = Case(self.root, 'case', source)
        app = self.sign.build_app(self.root, extractor=source)
        _, status, report, prepared, report_path = prepare(self.root, case)
        self.assertEqual(status, 'prepared-development-candidate', report['failure'])
        spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64',
                'report': {'path': str(report_path), 'sha256': digest(report_path.read_bytes())}}
        plan = signing.inspect(self.sign.request(app, prepared_extractor={**spec, 'source': case.spec()}))
        extractor = next(o for o in plan['code_objects'] if o['role'] == 'yt-dlp')
        proof = extractor['replacement']['transformation']
        self.assertEqual((extractor['action'], proof['method'], proof['signature_only_natives'], proof['identical_non_natives']),
                         ('replace-and-sign', ex.SOURCE_METHOD, 2, 7))
        self.assertEqual(proof['source']['bootloader_sha256'], case.doc['bootloader']['sha256'])
        self.assertIn('controlled-source producer', extractor['replacement']['provenance'])
        self.assertFalse({'prepared-extractor', 'prepared-extractor-missing'} & {b['id'] for b in plan['blockers']})
        self.assertEqual(set(plan['request']['prepared_extractor']), {'path', 'sha256', 'version', 'arch', 'report', 'source'})
        # The reviewed plan executes as an ad-hoc rehearsal: re-inspection repeats the proof.
        plan_path = self.sign.write_plan(self.root, plan)
        status, signing_report = signing.execute(plan_path, self.root / 'Rehearsal.app', self.root / 'signing-work', allow_incomplete=True)
        signed = next(o for o in json.loads(signing_report.read_text())['objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(status, 'incomplete-development')
        self.assertTrue(signed['payload']['signature_only_change'])
        # Route binding at the signer: evidence needs the report, reports never change route.
        cases = [({k: v for k, v in spec.items() if k != 'report'} | {'source': case.spec()}, 'requires the preparation report'),
                 (spec, 'comes from the controlled-source route'),
                 ({**spec, 'source': case.spec(lambda d: d['bootloader'].update(sha256='e' * 64))}, 'different source evidence|compiled bootloader differs')]
        for change, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(self.sign.request(app, prepared_extractor=change))
        with self.assertRaisesRegex(ValueError, 'different signing mode'):
            signing.inspect(self.sign.request(app, 'developer-id', DEVID, TEAM, prepared_extractor={**spec, 'source': case.spec()}))
        # The same evidence and report against an app holding a stock producer.
        (self.root / 'stock').mkdir()
        stock = base.producer(self.root / 'stock/yt-dlp_macos', 'arm64')
        (self.root / 'stock-app').mkdir()
        stock_app = self.sign.build_app(self.root / 'stock-app', extractor=stock)
        with self.assertRaisesRegex(ValueError, 'does not bind this producer'):
            signing.inspect(self.sign.request(stock_app, prepared_extractor={**spec, 'source': case.spec()}))
        # Final materials. omd-final-materials-v1 (the default) still refuses the route precisely,
        # with or without source inputs: nothing is bound by the stock proof (fail-closed control).
        # omd-final-materials-v2 needs the route's own inputs and the evidence the plan inspected.
        path = extractor['path']
        role = {'id': 'yt-dlp', 'sign': 'prepared-extractor', 'filetype': 'execute', 'entitlements': {}}
        evidence = case.spec()['evidence']
        inputs = {'report': report_path, 'evidence': Path(evidence['path']), 'evidence_sha256': evidence['sha256'],
                  'kit': 'kits/source-kit.tar.gz', 'bootloader': case.boot_path}

        def derive(**spec):
            derivation = fm.Derivation({'prepared_extractor': prepared, 'temp_root': self.root, 'delivery_roots': {'kits': case.kit.parent}, **spec})
            derivation.plan = plan
            return derivation, lambda: derivation.extractor(path, app / path, source.read_bytes(), prepared.read_bytes(), 'development-adhoc', None,
                                                            'labs.northwolf.omd-fixture.yt-dlp', role)
        other = case.spec(raw=js(case.doc) + b' ')
        for spec, why in (({}, 'controlled-source extractor route is not supported by omd-final-materials-v1'),
                          ({'contract': fm.FINAL_SCHEMA, 'extractor_source': inputs}, 'controlled-source extractor route is not supported by omd-final-materials-v1'),
                          ({'contract': fm.FINAL_SCHEMA_V2}, 'uses the controlled-source extractor route; supply its preparation report'),
                          ({'contract': fm.FINAL_SCHEMA_V2, 'extractor_source': {**inputs, 'evidence': Path(other['evidence']['path']), 'evidence_sha256': other['evidence']['sha256']}},
                           'differs from the evidence the signing plan inspected'),
                          ({'contract': fm.FINAL_SCHEMA_V2, 'extractor_source': {**inputs, 'kit': 'elsewhere/source-kit.tar.gz'}}, 'outside every declared delivery root')):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                derive(**spec)[1]()
        # With its inputs, v2 repeats the whole source proof and binds the kit as a delivery file;
        # the next relation (prepared -> final signature) then applies to this ad-hoc stand-in.
        derivation, run_extractor = derive(contract=fm.FINAL_SCHEMA_V2, extractor_source=inputs)
        with self.assertRaisesRegex(ValueError, 'unexpected signing identifier'):
            run_extractor()
        self.assertEqual(derivation.bound_delivery, {'kits/source-kit.tar.gz': signing.file_identity(case.kit)})

    def test_signer_cli_requires_the_complete_source_option_set(self):
        cli = load('omd_sign_cli', 'sign-macos.py')
        app = self.sign.build_app(self.root)
        base_args = ['inspect', '--app', str(app), '--mode', 'development-adhoc', '--identity', '-', '--plan', str(self.root / 'plan.json'),
                     '--prepared-extractor', str(app / self.sign.RES / 'tools/yt_dlp/yt-dlp_macos'), '--prepared-extractor-sha256', '0' * 64,
                     '--prepared-extractor-version', VERSION, '--prepared-extractor-arch', 'arm64']
        source = ['--prepared-extractor-source-evidence', str(self.root / 'e.json'), '--prepared-extractor-source-evidence-sha256', '0' * 64,
                  '--prepared-extractor-source-kit', str(self.root / 'k.tar.gz'), '--prepared-extractor-source-bootloader', str(self.root / 'run')]
        for argv in ([*base_args, *source], [*base_args, *source[:4], '--prepared-extractor-report', str(self.root / 'r.json'), '--prepared-extractor-report-sha256', '0' * 64]):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(cli.main(argv), 1)
            self.assertIn('all four --prepared-extractor-source-* options and a prepared extractor report', err.getvalue())
        self.assertFalse((self.root / 'plan.json').exists())


def tearDownModule():
    for owner in (Boot, base.Fixture):
        if owner.root is not None:
            shutil.rmtree(owner.root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
