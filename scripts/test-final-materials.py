# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Final materials binding tests (omd-final-materials-v1 and -v2).

Shared contract fixtures (one file per contract version) are byte-identical to the
desktop copies and pinned by digest in both trees. Native cases build tiny
release-staged fixture apps, prepare a genuine PyInstaller 6.22.0 fixture extractor
(stock bootloader, or the controlled-source route on a compiled thin bootloader with a
generated kit, receipt and evidence that pass the real recipient verifier) and sign
only new temporary copies with the canned Developer ID runners of the signing and
preparation tests (ad-hoc substitutes, canned Team checks): they exercise binding
mechanics, never signature evidence. Uncanned controls show genuine codesign refusing
the ad-hoc substitutes. Opt-in, read-only real data:
OMD_FINAL_MATERIALS_REHEARSAL (+ OMD_FINAL_MATERIALS_LOCKS) reads the genuine Developer
ID private-validation pair; OMD_FINAL_MATERIALS_SOURCE_ADAPTER and
OMD_FINAL_MATERIALS_SOURCE_KIT run the v2 controlled-source proof on the real producer,
its labelled ad-hoc changed-signature control and the reviewed evidence, kit and
bootloader. Nothing is modified and no identity is used.
"""
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
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import final_materials as fm
import macos_extractor as ex
import macos_signing as signing

SCRIPTS = Path(__file__).resolve().parent
NATIVE = platform.system() == 'Darwin' and shutil.which('xcrun') is not None and Path('/usr/bin/codesign').exists()
REHEARSAL = os.environ.get('OMD_FINAL_MATERIALS_REHEARSAL')
SOURCE_ADAPTER = os.environ.get('OMD_FINAL_MATERIALS_SOURCE_ADAPTER')
SOURCE_KIT = os.environ.get('OMD_FINAL_MATERIALS_SOURCE_KIT')


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sign_tests = load('omd_sign_tests', 'test-sign-macos.py')
extractor_tests = load('omd_extractor_tests', 'test-prepare-macos-extractor.py')
source_tests = load('omd_source_extractor_tests', 'test-prepare-macos-extractor-source.py')
BIND_CLI = load('omd_bind_cli', 'bind-final-materials.py')
RES, EXE, ENGINE = sign_tests.RES, sign_tests.EXE, sign_tests.ENGINE
DEVID, TEAM = sign_tests.DEVID, sign_tests.TEAM
SHELL = 'Contents/MacOS/' + EXE
EXTRACTOR = RES + '/tools/yt_dlp/yt-dlp_macos'
KIT = 'kits/source-kit.tar.gz'
V1, V2 = fm.FINAL_SCHEMA, fm.FINAL_SCHEMA_V2
FIXTURE_DIGESTS = {V1: '6c07008986773c2583d6ee2466db2acc86cd07953b9fbf249d517669f2f516ca', V2: 'fa191ccd7529e2b4386c5433611ff2c3959776335ffafbb1de81c0206c6ed08e'}
digest = sign_tests.digest
REAL_CHECK = fm.check_signature
REAL_OUTER = ex.verify_outer


def adhoc_check(path, role, data, mode, team, identifier):
    """The real static check of the ad-hoc substitute; Developer ID attributes are tested separately."""
    return REAL_CHECK(path, role, data, 'development-adhoc', None, identifier)


@contextlib.contextmanager
def canned_binder():
    with mock.patch.object(fm, 'check_signature', side_effect=adhoc_check), mock.patch.object(signing, 'codesign_check', return_value=(0, '')):
        yield


def scratch(test):
    folder = Path(tempfile.mkdtemp(prefix='omd-final-test-')).resolve()
    test.addCleanup(shutil.rmtree, folder, True)
    return folder


class CannedPreparation(signing.Runner):
    """Drives a Developer ID extractor preparation for binding mechanics only. Each requested
    Developer ID signing command is recorded and performed ad-hoc (identity '-', no timestamp,
    no runtime flag) and Team requirement checks are recorded as canned. It never touches an
    identity or keychain and is never evidence of a Developer ID signature."""

    def __call__(self, argv, label, timeout=600, check=True):
        argv = [str(x) for x in argv]
        if label.startswith('requirement:'):
            self.records.append({'label': label, 'argv': argv, 'exit': 0, 'seconds': 0, 'stdout': '', 'stderr': '', 'canned': True})
            return b''
        if label.startswith('sign:') or label == 'sign-outer':
            substituted = ['-' if a == DEVID else '--timestamp=none' if a == '--timestamp' else a for a in argv if a != '--options=runtime']
            try:
                return super().__call__(substituted, label, timeout, check)
            finally:
                self.records[-1].update(requested_argv=argv, canned=True)
        return super().__call__(argv, label, timeout, check)


@contextlib.contextmanager
def canned_preparation():
    """Canned Team checks for the preparation: the real ad-hoc structural verification of the
    substitutes, and codesign requirement checks reported as passing."""
    with mock.patch.object(signing, 'verify_object', side_effect=sign_tests.adhoc_verify), \
            mock.patch.object(ex, 'verify_outer', side_effect=lambda runner, path, mode, team: REAL_OUTER(runner, path, 'development-adhoc', None)), \
            mock.patch.object(signing, 'codesign_check', return_value=(0, '')):
        yield


def canned_source_preparation(root, case, evidence):
    """A controlled-source preparation report in Developer ID mode for the fixture Team (canned)."""
    plan = ex.inspect(case.request(evidence, mode='developer-id', identity=DEVID, team_id=TEAM), temp_root=root)
    plan_path = sign_tests.write_plan(root, plan, 'extractor-plan.json')
    out = root / 'extractor-out'
    out.mkdir()
    with canned_preparation():
        status, report_path = ex.execute(plan_path, out / 'yt-dlp_macos', root / 'extractor-work', runner_factory=CannedPreparation)
    report = json.loads(report_path.read_text())
    assert status == 'prepared-developer-id-candidate' and report['method'] == ex.SOURCE_METHOD, report['failure']
    return out / 'yt-dlp_macos', report_path


def apply_edits(fixtures, edits):
    s = copy.deepcopy(fixtures['base'])
    for edit in edits:
        if edit['target'] == 'initial':
            s['initial'] = edit['value']
            continue
        current = s[edit['target']]
        for part in edit['path'][:-1]:
            current = current[part]
        if edit.get('delete'):
            del current[edit['path'][-1]]
        else:
            current[edit['path'][-1]] = copy.deepcopy(edit['value'])
    return s


class SharedContract(unittest.TestCase):
    """The same fixture cases and messages as desktop scripts/final-materials-contract.test.mjs."""

    def test_verify_rejects_unknown_or_missing_top_level_fields(self):
        fixtures = json.loads((SCRIPTS.parent / 'distribution/final-materials-fixtures-v1.json').read_text())
        doc = fixtures['base']['doc']
        for changed in ({**doc, 'unrecognized_field': True}, {k: v for k, v in doc.items() if k != 'initial_review'}):
            with self.subTest(keys=list(changed)), mock.patch.object(fm, 'prepare', return_value=(0, doc, {'distribution_validation': {'pass': True}, 'gaps': []})):
                with self.assertRaisesRegex(ValueError, 'Unknown/missing final materials fields'):
                    fm.verify({}, json.dumps(changed).encode())

    def test_shared_fixtures(self):
        fixtures = json.loads((SCRIPTS.parent / 'distribution/final-materials-fixtures-v1.json').read_text())
        self.assertEqual(fixtures['schema'], 'omd-final-materials-contract-fixtures-v1')
        self.assertGreaterEqual(len(fixtures['cases']), 70)
        for case in fixtures['cases']:
            with self.subTest(case['name']):
                s = copy.deepcopy(fixtures['base'])
                for edit in case['edits']:
                    if edit['target'] == 'initial':
                        s['initial'] = edit['value']
                        continue
                    current = s[edit['target']]
                    for part in edit['path'][:-1]:
                        current = current[part]
                    if edit.get('delete'):
                        del current[edit['path'][-1]]
                    else:
                        current[edit['path'][-1]] = copy.deepcopy(edit['value'])
                run = lambda: fm.validate_final(s['doc'], s['initial'].encode(), s['payload'], s['delivery'], s['expect'])
                if case['valid']:
                    self.assertEqual(run(), {'schema': fm.FINAL_SCHEMA, 'coverage_validated': True, 'distribution_candidate': True, 'release_accepted': False})
                else:
                    with self.assertRaises(ValueError) as caught:
                        run()
                    self.assertIn(case['error'], str(caught.exception))

    def test_v1_contract_and_fixtures_are_unchanged(self):
        fixtures = (SCRIPTS.parent / 'distribution/materials-contract-fixtures-v1.json').read_bytes()
        # omd-materials-v1 stays the unchanged initial-review contract (its fixtures are byte-identical).
        self.assertEqual(digest(fixtures), '8e26ca2efc0167354670c4d581417070f643460e28d66c8039354e6abb18f077')
        self.assertEqual(json.loads(fixtures)['schema'], 'omd-materials-contract-fixtures-v1')

    def test_final_fixture_copies_are_pinned(self):
        # v1 final fixtures are unchanged; v2 is a separate file. The desktop test pins the same digests.
        for schema, name in ((V1, 'final-materials-fixtures-v1.json'), (V2, 'final-materials-fixtures-v2.json')):
            with self.subTest(name):
                self.assertEqual(digest((SCRIPTS.parent / 'distribution' / name).read_bytes()), FIXTURE_DIGESTS[schema])

    def test_shared_fixtures_v2(self):
        fixtures = json.loads((SCRIPTS.parent / 'distribution/final-materials-fixtures-v2.json').read_text())
        self.assertEqual(fixtures['schema'], 'omd-final-materials-contract-fixtures-v2')
        self.assertGreaterEqual(len(fixtures['cases']), 80)
        names = {c['name'] for c in fixtures['cases'] if c['valid']}
        self.assertTrue({'complete-controlled-source-binding', 'complete-stock-route-binding', 'stock-route-thin-target'} <= names)
        for case in fixtures['cases']:
            with self.subTest(case['name']):
                s = apply_edits(fixtures, case['edits'])
                run = lambda: fm.validate_final(s['doc'], s['initial'].encode(), s['payload'], s['delivery'], s['expect'])
                if case['valid']:
                    self.assertEqual(run(), {'schema': V2, 'coverage_validated': True, 'distribution_candidate': True, 'release_accepted': False})
                else:
                    with self.assertRaises(ValueError) as caught:
                        run()
                    self.assertIn(case['error'], str(caught.exception))

    def test_verify_requires_the_requested_contract(self):
        v1 = json.loads((SCRIPTS.parent / 'distribution/final-materials-fixtures-v1.json').read_text())['base']['doc']
        v2 = json.loads((SCRIPTS.parent / 'distribution/final-materials-fixtures-v2.json').read_text())['base']['doc']
        cases = [({}, v2, 'not an omd-final-materials-v1 document'), ({'contract': V2}, v1, 'not an omd-final-materials-v2 document'),
                 ({'contract': V2}, {**v2, 'unrecognized_field': True}, 'Unknown/missing final materials fields'),
                 ({'contract': V2}, {k: v for k, v in v2.items() if k != 'extractor'}, 'Unknown/missing final materials fields'),
                 ({'contract': 'omd-final-materials-v3'}, v2, 'Unknown final materials contract')]
        for spec, doc, why in cases:
            with self.subTest(why), mock.patch.object(fm, 'prepare', return_value=(0, v2, {'distribution_validation': {'pass': True}, 'gaps': []})):
                with self.assertRaisesRegex(ValueError, why):
                    fm.verify(spec, json.dumps(doc).encode())


def v1_manifest(app, locks, version='1.0.0'):
    """A complete omd-materials-v1 initial review of the staged resources (pre-signature)."""
    root = app / RES
    files = {p.relative_to(root).as_posix(): digest(p.read_bytes()) for p in sorted(root.rglob('*')) if p.is_file()}
    files.pop('build-inventory.json', None)
    pick = lambda *paths: {p: files[p] for p in paths}
    engine = {'notices': pick('third-party/native-NOTICES.txt'), 'source': pick('LICENSE'), 'instructions': pick('LICENSE'), 'provenance': pick('third-party/native-receipt.json')}
    tool = {'notices': pick('LICENSE'), 'source': pick('LICENSE'), 'instructions': pick('LICENSE'), 'provenance': pick('tools/tools-v2.json')}
    browser = {p: h for p, h in files.items() if p.startswith('browser/content/')}
    component = lambda cid, ver, artifacts, materials: {'id': cid, 'version': ver, 'status': 'reviewed', 'pending': [], 'artifacts': artifacts, 'materials': copy.deepcopy(materials)}
    components = [component(n, version, pick('bin/' + n), engine) for n in ENGINE]
    tools = json.loads((root / 'tools/tools-v2.json').read_text())
    components += [component(n, tools[n]['version'], {p: h for p, h in files.items() if p.startswith(f'tools/{n}/')}, tool) for n in ('yt_dlp', 'ffmpeg', 'ffprobe', 'node')]
    components.append(component('browser', 'fixture-browser', browser, {'notices': pick('browser/content/browser/ABOUT'), 'source': pick('browser/content/adapter/adapter.mjs'),
                                                                        'instructions': pick('browser/content/browser/ABOUT'), 'provenance': pick('browser/browser-tools-v2.json')}))
    components.append(component('staged-notices', version, pick('third-party/desktop-native-NOTICES.txt'), {k: pick('LICENSE') for k in fm.KINDS}))
    return {'schema': 'omd-materials-v1', 'reviewed': True, 'pending': [], 'target': 'darwin-arm64', 'version': version, 'locks': locks, 'components': components}


class BindingFixtures:
    """Stage (two-phase release) -> sign (two-phase, canned Developer ID) -> bind helpers."""

    def setUp(self):
        self.root = scratch(self)

    def build(self, root, *, staging='two-phase', producer_data=None, prepared_data=None, source_route=False):
        """(app, plan, report, prepared, locks, delivery) for a complete two-phase run under `root`.
        `source_route` uses a controlled-source producer, a canned Developer ID source preparation
        and its report, evidence, kit (copied to a delivery root) and compiled bootloader."""
        native = sign_tests.Native.get()
        fixture = sign_tests.Receipts(root / 'receipts')
        raw = [(n, native / ('worker' if n == 'omd-plugin-worker-v2' else 'exe')) for n in ENGINE]
        fixture.review('engine', raw)
        engine = fixture.reviewed('engine', raw)
        fixture.review('desktop', [(EXE, native / 'exe')])
        _, desktop_notices = fixture.reviewed('desktop', [(EXE, native / 'exe')])
        locks = root / 'locks'
        locks.mkdir()
        lock_bytes = b'{"name":"fixture-adapter","lockfileVersion":3}\n'
        for name, data in (('Cargo.lock', fixture.manifest('engine').with_name('Cargo.lock').read_bytes()), ('browser-package-lock.json', lock_bytes),
                           ('desktop-Cargo.lock', fixture.manifest('desktop').with_name('Cargo.lock').read_bytes()), ('desktop-package-lock.json', b'{"lockfileVersion":3}\n')):
            (locks / name).write_bytes(data)
        lock_map = {p.name: digest(p.read_bytes()) for p in locks.iterdir()}

        def stage(app):
            sign_tests.add_browser_file(app, 'adapter/package-lock.json', lock_bytes)
            if staging == 'development':
                return
            manifest = v1_manifest(app, lock_map)
            (app / RES / 'third-party/materials-v1.json').write_bytes(sign_tests.js(manifest))
            sign_tests.reinventory(app, lambda inv: inv.update(staging_mode='release', materials={
                'schema': 'omd-materials-v1', 'coverage_validated': True, 'release_accepted': False, 'binding': 'two-phase', 'deferred': ['desktop-rust', 'frontend']}))
        if source_route:
            producer = source_tests.source_producer(root / 'source-producer')
            case = source_tests.Case(root, 'source-case', producer)
        else:
            producer = extractor_tests.producer(extractor_tests.src(root), 'arm64', **({'data': producer_data} if producer_data else {}))
        app = sign_tests.build_app(root, receipts={'engine': engine, 'desktop_notices': desktop_notices}, staging='development' if staging == 'development' else 'release',
                                   extractor=producer, mutate=stage)
        fixture.review('desktop', [(EXE, app / 'Contents/MacOS' / EXE)])
        config = fixture.config(root / 'receipts.json')
        source = None
        if source_route:
            evidence = case.spec()
            prepared, report_path = canned_source_preparation(root, case, evidence)
            spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64',
                    'report': {'path': str(report_path), 'sha256': digest(report_path.read_bytes())}, 'source': evidence}
            kits = root / 'kits'
            kits.mkdir()
            shutil.copyfile(case.kit, kits / 'source-kit.tar.gz')
            source = {'report': report_path, 'evidence': Path(evidence['evidence']['path']), 'evidence_sha256': evidence['evidence']['sha256'], 'kit': KIT,
                      'bootloader': case.boot_path, 'kits': kits, 'case': case}
        else:
            origin = producer
            if prepared_data:
                origin = extractor_tests.producer(extractor_tests.src(root, 'other-src'), 'arm64', data=prepared_data)
            _, status, _, prepared = extractor_tests.prepare(self, root, origin, 'arm64')
            self.assertEqual(status, 'prepared-development-candidate')
            spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': '2026.08.19', 'arch': 'arm64'}
        two_phase = staging == 'two-phase'
        purpose = 'distribution-candidate' if two_phase else 'private-validation'
        binding = 'two-phase' if two_phase else 'single-phase'
        with fixture.patched(), sign_tests.canned_team_members():
            plan = signing.inspect(sign_tests.request(app, 'developer-id', DEVID, TEAM, purpose=purpose, materials_binding=binding, prepared_extractor=spec, receipts=str(config)))
            plan_path = sign_tests.write_plan(root, plan)
            with mock.patch.object(signing, 'verify_object', side_effect=sign_tests.adhoc_verify):
                status, report_path = signing.execute(plan_path, root / 'Signed.app', root / 'work', runner_factory=sign_tests.CannedDeveloperId,
                                                      purpose=purpose, materials_binding=binding)
        report = json.loads(report_path.read_text())
        self.assertEqual(status, signing.TWO_PHASE_STATUS if two_phase else 'private-validation-signed', report.get('failure'))
        delivery = root / 'delivery'
        for rel, data in (('sources/first-party.tar.gz', b'first-party source archive'), ('notes/route.md', b'Source and notice routes\n'),
                          ('notes/frontend-NOTICES.txt', b'frontend notices\n'), ('notes/frontend-receipt.json', b'{}\n')):
            (delivery / rel).parent.mkdir(parents=True, exist_ok=True)
            (delivery / rel).write_bytes(data)
        return {'app': app, 'final': root / 'Signed.app', 'plan': plan_path, 'report': report_path, 'prepared': prepared, 'locks': locks,
                'delivery': delivery, 'work': root / 'work', 'fixture': fixture, 'config': config, 'plan_body': plan, 'source': source}

    def review(self, run, root, change=None):
        delivery = run['delivery']
        entry = lambda rel: {'path': rel, **signing.file_identity(delivery / rel)}
        input_inventory = fm.canonical_inventory(signing.inventory_of(run['app']))
        v1 = run['app'] / RES / 'third-party/materials-v1.json'
        facts, limits = ['Fixture fact bound by digest'], ['Synthetic fixture; no legal determination']
        initial = json.loads(v1.read_text())['components'] if v1.exists() else []
        components = [{'id': c['id'], 'version': c['version'], 'basis': 'initial-review', 'status': 'reviewed', 'pending': [], 'artifacts': [], 'materials': {},
                       'facts': facts, 'limits': limits} for c in initial]
        if run.get('source'):
            # The kit is the extractor component's typed source material (a delivery file).
            next(c for c in components if c['id'] == 'yt_dlp')['materials'] = {'source': ['delivery:' + KIT]}
        final = lambda cid, artifacts, materials: {'id': cid, 'version': '1.0.0', 'basis': 'final-review', 'status': 'reviewed', 'pending': [], 'artifacts': artifacts,
                                                   'materials': materials, 'facts': facts, 'limits': limits}
        components += [
            final('desktop-rust', [SHELL], {'notices': ['delivery:receipts/native-NOTICES.txt'], 'source': ['delivery:sources/first-party.tar.gz'],
                                            'instructions': ['delivery:notes/route.md'], 'provenance': ['delivery:receipts/receipt.json']}),
            final('frontend', [SHELL], {'notices': ['delivery:notes/frontend-NOTICES.txt'], 'source': ['delivery:sources/first-party.tar.gz'],
                                        'instructions': ['delivery:notes/route.md'], 'provenance': ['delivery:notes/frontend-receipt.json']}),
            final('desktop-bundle', ['Contents/Info.plist', 'Contents/Resources/icon.icns', 'Contents/_CodeSignature/CodeResources', RES + '/build-inventory.json',
                                     *([RES + '/third-party/materials-v1.json'] if v1.exists() else [])],
                  {'notices': ['payload:' + RES + '/LICENSE'], 'source': ['delivery:sources/first-party.tar.gz'], 'instructions': ['delivery:notes/route.md'],
                   'provenance': ['payload:' + RES + '/build-inventory.json']})]
        review = {'schema': fm.REVIEW_SCHEMA, 'target': 'darwin-arm64', 'version': '1.0.0', 'input_inventory_sha256': input_inventory,
                  'initial_review_sha256': digest(v1.read_bytes()) if v1.exists() else None, 'components': components,
                  'delivery': [entry(r) for r in ('sources/first-party.tar.gz', 'notes/route.md', 'notes/frontend-NOTICES.txt', 'notes/frontend-receipt.json')]}
        if change:
            change(review)
        path = root / f'review-{len(list(root.glob("review-*.json")))}.json'
        path.write_bytes(sign_tests.js(review))
        return path

    def spec(self, run, review=None, **change):
        roots = {'receipts': run['work'] / 'receipts/desktop-reviewed', 'sources': run['delivery'] / 'sources', 'notes': run['delivery'] / 'notes'}
        extra = {}
        if run.get('source'):
            roots['kits'] = run['source']['kits']
            extra = {'contract': V2, 'extractor_source': {k: run['source'][k] for k in ('report', 'evidence', 'evidence_sha256', 'kit', 'bootloader')}}
        return {'input_app': run['app'], 'final_app': run['final'], 'plan': run['plan'], 'report': run['report'], 'prepared_extractor': run['prepared'],
                'locks': run['locks'], 'delivery_roots': roots, 'desktop_receipt': {'receipt': 'receipts/receipt.json', 'notices': 'receipts/native-NOTICES.txt'},
                'review': review, 'cryptographic': True, 'temp_root': self.root, **extra, **change}

    def prepare(self, spec):
        with canned_binder():
            return fm.prepare(spec)

    def refused(self, spec, why):
        with self.assertRaisesRegex(ValueError, why):
            self.prepare(spec)

    def copy_final(self, run, name):
        out = self.root / name / 'Signed.app'
        out.parent.mkdir()
        shutil.copytree(run['final'], out)
        return out


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class TwoPhaseBinding(BindingFixtures, unittest.TestCase):
    """Stage (two-phase release) -> sign (two-phase, canned Developer ID) -> bind."""

    def test_two_phase_stage_sign_and_bind(self):
        run = self.build(self.root)
        report = json.loads(run['report'].read_text())
        self.assertEqual((report['status'], report['distribution_candidate'], report['developer_id_signed'], report['release_accepted']),
                         (signing.TWO_PHASE_STATUS, False, True, False))
        self.assertEqual(report['final_materials']['bound'], False)
        self.assertEqual([(b['id'], b['severity']) for b in run['plan_body']['blockers']], [('materials-bind-pre-signature', 'release')])
        self.assertEqual(BIND_CLI.EXIT['final-materials-validated'], 0)
        inventory = json.loads((run['final'] / RES / 'build-inventory.json').read_text())
        self.assertEqual((inventory['signing']['materials_binding'], inventory['signing']['purpose']), ('two-phase', 'distribution-candidate'))
        # The in-app initial review is never rewritten by signing, and it stays stale for
        # post-signature bytes: v1 validation of the signed resources still fails.
        v1 = (run['final'] / RES / 'third-party/materials-v1.json').read_bytes()
        self.assertEqual(v1, (run['app'] / RES / 'third-party/materials-v1.json').read_bytes())
        signed = {rel: row['sha256'] for rel, row in signing.resource_identities(run['final'] / RES).items() if rel not in ('build-inventory.json', 'third-party/materials-v1.json')}
        with self.assertRaisesRegex(ValueError, 'Missing/changed material or artifact'):
            fm.materials_contract.validate(json.loads(v1), signed, result_expect(run, {'version': '1.0.0', 'target': 'darwin-arm64', 'locks': {}})['required'],
                                           'darwin-arm64', '1.0.0', json.loads(v1)['locks'])
        review = self.review(run, self.root)
        status, doc, result = self.prepare(self.spec(run, review))
        self.assertEqual(status, 'final-materials-validated', result['gaps'])
        self.assertEqual((doc['coverage_validated'], doc['distribution_candidate'], doc['reviewed'], doc['release_accepted']), (True, True, True, False))
        self.assertEqual(result['distribution_validation'], {'pass': True})
        counts = result['relations']
        self.assertEqual((counts['signature-only'], counts['prepared-extractor'], counts['managed-manifest'], counts['build-inventory'], counts['engine-receipt'], counts['outer-seal']),
                         (14, 1, 2, 1, 1, 1))
        self.assertEqual(doc['payload']['inventory_sha256'], fm.canonical_inventory(signing.inventory_of(run['final'])))
        self.assertEqual(result['extractor']['signature_only_natives'], 2)
        self.assertNotIn(str(self.root), json.dumps(doc))
        # Original digests stay bound for initial-review components; final digests are separate.
        yt = next(c for c in doc['components'] if c['id'] == 'yt_dlp')
        path = RES + '/tools/yt_dlp/yt-dlp_macos'
        self.assertEqual(yt['artifacts'][path]['initial'], digest((run['app'] / path).read_bytes()))
        self.assertEqual(yt['artifacts'][path]['final'], digest((run['final'] / path).read_bytes()))
        self.assertEqual(doc['relations'][path]['prepared'], digest(run['prepared'].read_bytes()))
        # The shared contract accepts exactly this binding, against actual inventories.
        initial = (run['app'] / RES / 'third-party/materials-v1.json').read_bytes()
        delivery = doc['delivery']['files']
        self.assertEqual(fm.validate_final(doc, initial, signing.inventory_of(run['final']), delivery, {**result_expect(run, doc)})['coverage_validated'], True)
        # verify re-derives and requires exact agreement; any edit to the document is refused.
        with canned_binder():
            verified = fm.verify(self.spec(run, review), signing.json_bytes(doc))
            self.assertTrue(verified['rederived_equal'] and verified['distribution_validation']['pass'])
            forged = copy.deepcopy(doc)
            forged['relations'][RES + '/LICENSE']['after'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'differs from the binding re-derived'):
                fm.verify(self.spec(run, review), signing.json_bytes(forged))
        # The second phase never rewrote the signed output, the input or the plan/report.
        self.assertEqual(json.loads(run['report'].read_text())['status'], signing.TWO_PHASE_STATUS)

    def test_byte_level_relation_failures(self):
        run = self.build(self.root)
        review = self.review(run, self.root)
        base = self.spec(run, review)
        cases = []

        def changed_native(app):
            path = app / RES / 'bin/omd'
            data = bytearray(path.read_bytes())
            data[len(data) // 3] ^= 0xff
            path.write_bytes(bytes(data))
        cases.append(('native', changed_native, 'bin/omd: not a signature-only change'))

        def manifest(app):
            path = app / RES / 'tools/tools-v2.json'
            value = json.loads(path.read_text())
            value['yt_dlp']['version'] = '2026.09.01'
            path.write_bytes(fm.serialize(value))
            # A consistent forgery also re-inventories it; the manifest relation still refuses.
            inventory_path = app / RES / 'build-inventory.json'
            inventory = json.loads(inventory_path.read_text())
            row = next(r for r in inventory['files'] if r['path'] == 'tools/tools-v2.json')
            row.update(sha256=digest(path.read_bytes()), size=len(path.read_bytes()))
            inventory_path.write_bytes(fm.serialize(inventory))
        cases.append(('manifest', manifest, 'tools-v2.json: changed beyond its digest fields'))
        cases.append(('unlisted', lambda app: (app / RES / 'third-party/unlisted.txt').write_bytes(b'x'), 'Unexpected new payload files'))
        cases.append(('removed', lambda app: (app / RES / 'third-party/desktop-native-NOTICES.txt').unlink(), 'Unexpected removal of input files'))
        cases.append(('data', lambda app: (app / RES / 'LICENSE').write_bytes(b'edited\n'), 'Unexpected payload change: ' + RES + '/LICENSE'))

        def entitlement(app):
            path = app / RES / 'bin/omd-plugin-worker-v2'
            plist = self.root / 'jit.plist'
            plist.write_bytes(plistlib.dumps({'com.apple.security.cs.allow-jit': True}))
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime', '--timestamp=none', '--identifier',
                            'labs.northwolf.omd-fixture.plugin-worker', '--entitlements', str(plist), str(path)], check=True, capture_output=True)
        cases.append(('entitlement', entitlement, 'omd-plugin-worker-v2: entitlements differ from the reviewed role'))

        def identifier(app):
            path = app / RES / 'bin/omd'
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime', '--timestamp=none', '--identifier',
                            'labs.northwolf.omd-fixture.engine', str(path)], check=True, capture_output=True)
        cases.append(('role', identifier, 'bin/omd: unexpected signing identifier'))

        def seal(app):
            path = app / 'Contents/_CodeSignature/CodeResources'
            value = plistlib.loads(path.read_bytes())
            value['files2']['Resources/icon.icns'] = {'hash2': b'\0' * 32}
            path.write_bytes(plistlib.dumps(value))
        cases.append(('seal', seal, 'CodeResources seal entry differs'))
        for name, mutate, why in cases:
            with self.subTest(name):
                out = self.copy_final(run, name)
                mutate(out)
                # The signing report binds signed bytes, so first it refuses tampered code; a
                # forged report that "binds" the tampered bytes reaches the relation itself.
                report = json.loads(run['report'].read_text())
                for row in report['objects']:
                    if row.get('payload') and (out / row['path']).exists():
                        row['payload']['sha256'] = digest((out / row['path']).read_bytes())
                forged = self.root / name / 'forged-report.json'
                forged.write_bytes(signing.json_bytes(report))
                self.refused({**base, 'final_app': out, 'report': forged}, why)
                if name in ('native', 'entitlement', 'role'):
                    self.refused({**base, 'final_app': out}, 'The signing report does not bind this final payload')
        # Wrong Team: the genuine static check of the ad-hoc output against the plan's Team.
        with mock.patch.object(signing, 'codesign_check', return_value=(0, '')):
            with self.assertRaisesRegex(ValueError, 'signature mode/team mismatch'):
                fm.prepare(base)
        # Cryptographic verification is real unless canned: the ad-hoc output fails the Team requirement.
        with mock.patch.object(fm, 'check_signature', side_effect=adhoc_check):
            with self.assertRaisesRegex(ValueError, 'failed cryptographic verification|Cryptographic signature verification failed'):
                fm.prepare(base)
        # A prepared extractor other than the one bound by the plan is refused.
        self.refused({**base, 'prepared_extractor': run['app'] / RES / 'tools/yt_dlp/yt-dlp_macos'}, 'differs from the one bound by the signing plan')

    def test_non_native_extractor_change_is_refused(self):
        # The signer accepts any cryptographically valid prepared extractor without a
        # preparation report; only the final binding proves its relation to the producer.
        run = self.build(self.root, prepared_data=b'different bundled data\n')
        self.refused(self.spec(run, self.review(run, self.root)), 'non-native member bytes differ')

    def test_receipts_locks_and_materials(self):
        run = self.build(self.root)
        review = self.review(run, self.root)
        base = self.spec(run, review)
        with run['fixture'].patched():
            stale_receipt, stale_notices = run['fixture'].reviewed('desktop', [(EXE, run['app'] / 'Contents/MacOS' / EXE)])
        stale = self.root / 'stale-receipt'
        stale.mkdir()
        (stale / 'receipt.json').write_bytes(stale_receipt)
        (stale / 'native-NOTICES.txt').write_bytes(stale_notices)
        self.refused({**base, 'delivery_roots': {**base['delivery_roots'], 'receipts': stale}}, 'Native receipt artifact mismatch')
        locks = self.root / 'stale-locks'
        shutil.copytree(run['locks'], locks)
        (locks / 'Cargo.lock').write_bytes(b'# changed lock\n')
        self.refused({**base, 'locks': locks}, 'Stale/unresolved native receipt')
        (locks / 'Cargo.lock').write_bytes((run['locks'] / 'Cargo.lock').read_bytes())
        (locks / 'browser-package-lock.json').write_bytes(b'{}\n')
        self.refused({**base, 'locks': locks}, 'Stale browser lock')
        (run['delivery'] / 'notes/route.md').write_bytes(b'edited after review\n')
        self.refused(base, 'Stale/changed delivery material: notes/route.md')

    def test_reviews_stay_pending_unless_explicitly_reviewed(self):
        run = self.build(self.root)
        status, doc, report = self.prepare(self.spec(run, None))
        self.assertEqual(status, 'final-materials-incomplete')
        self.assertFalse(doc['coverage_validated'] or doc['reviewed'] or doc['distribution_candidate'])
        self.assertEqual([c['id'] for c in doc['components']], [])
        self.assertIn('review-input', report['gaps'])
        self.assertIn('Pending final materials coverage', report['distribution_validation']['error'])

        def pending_source(r):
            c = next(c for c in r['components'] if c['id'] == 'yt_dlp')
            c.update(status='pending', pending=['upstream corresponding-source delivery route not reviewed'])
        _, doc, report = self.prepare(self.spec(run, self.review(run, self.root, pending_source)))
        self.assertFalse(doc['coverage_validated'])
        self.assertEqual(next(c for c in doc['components'] if c['id'] == 'yt_dlp')['status'], 'pending')
        self.assertIn('yt_dlp: upstream corresponding-source delivery route not reviewed', report['gaps']['component-materials'])

        def ambiguous(r):
            next(c for c in r['components'] if c['id'] == 'frontend')['pending'] = ['applicability unclear']
        _, doc, _ = self.prepare(self.spec(run, self.review(run, self.root, ambiguous)))
        frontend = next(c for c in doc['components'] if c['id'] == 'frontend')
        self.assertEqual((frontend['status'], frontend['pending'][0]), ('pending', 'ambiguous review: marked reviewed with unresolved statements; kept pending'))

        def no_source(r):
            next(c for c in r['components'] if c['id'] == 'desktop-rust')['materials'].pop('source')
        _, doc, _ = self.prepare(self.spec(run, self.review(run, self.root, no_source)))
        self.assertEqual(next(c for c in doc['components'] if c['id'] == 'desktop-rust')['pending'],
                         ['ambiguous review: marked reviewed with unresolved statements; kept pending', 'no source material bound'])

        def missing_bundle(r):
            r['components'] = [c for c in r['components'] if c['id'] != 'desktop-bundle']
        _, doc, report = self.prepare(self.spec(run, self.review(run, self.root, missing_bundle)))
        self.assertTrue(any('not covered by any component' in g for g in report['gaps']['coverage']))
        (run['delivery'] / 'sources/unused.tar.gz').write_bytes(b'unused archive')
        refusals = [
            (lambda r: r.update(input_inventory_sha256='0' * 64), 'reviewed a different pre-signature input'),
            (lambda r: r.update(initial_review_sha256='0' * 64), 'reviewed a different initial review'),
            (lambda r: r['delivery'].append(dict(r['delivery'][0])), 'Duplicate or colliding delivery path'),
            (lambda r: r['delivery'][0].update(path='../escape.tar.gz'), 'Invalid portable path'),
            (lambda r: r['delivery'][0].update(path='sources/final-materials-v1.json'), 'outside the signed payload and delivery set'),
            (lambda r: r['components'].append(copy.deepcopy(r['components'][0])), 'Duplicate/invalid final review component'),
            (lambda r: r['components'][-1]['materials']['source'].append('delivery:/Volumes/private-volume/source.tar.gz'), 'Machine-local'),
            (lambda r: r['components'][-1]['materials']['source'].append('url:https://example.org/src.tar.gz'), 'unknown material route'),
            (lambda r: r['components'][-1]['materials']['source'].append('delivery:sources/not-delivered.tar.gz'), 'not in the bound delivery inventory'),
            (lambda r: r['components'][-1]['artifacts'].append('Contents/Missing'), 'not in the final payload'),
            (lambda r: r['components'][0].update(basis='final-review', artifacts=[SHELL]), 'cannot replace initial review facts'),
            (lambda r: r['components'][0].update(version='9.9.9'), 'not a component of the initial review'),
            (lambda r: r['components'][0].update(status='accepted'), 'Invalid final review component'),
            (lambda r: r['components'][0].update(release_accepted=True), 'Unknown/missing final review component fields'),
            (lambda r: r['delivery'].append({'path': 'sources/unused.tar.gz', **signing.file_identity(run['delivery'] / 'sources/unused.tar.gz')}), 'not referenced by any component'),
        ]
        for change, why in refusals:
            with self.subTest(why):
                self.refused(self.spec(run, self.review(run, self.root, change)), why)

    def test_private_validation_is_never_promoted(self):
        run = self.build(self.root, staging='development')
        status, doc, report = self.prepare(self.spec(run, self.review(run, self.root)))
        self.assertEqual((status, doc['purpose'], doc['distribution_candidate']), ('final-materials-incomplete', 'private-validation', False))
        self.assertEqual(report['distribution_validation']['error'], 'Private-validation output is never a distribution candidate')
        self.assertTrue(any('never a distribution candidate' in g for g in report['gaps']['signing-run']))
        self.assertTrue(any('no in-app omd-materials-v1' in g for g in report['gaps']['initial-review']))
        base = self.spec(run, None)
        # Edited purpose in the report only, then in both plan and report.
        edited = self.root / 'edited'
        edited.mkdir()
        rep = json.loads(run['report'].read_text())
        rep['purpose'] = 'distribution-candidate'
        (edited / 'report.json').write_bytes(signing.json_bytes(rep))
        self.refused({**base, 'report': edited / 'report.json'}, 'Signing report and plan disagree')
        plan = json.loads(run['plan'].read_text())
        plan['purpose'] = 'distribution-candidate'
        (edited / 'plan.json').write_bytes(signing.json_bytes(plan))
        rep['plan']['sha256'] = digest((edited / 'plan.json').read_bytes())
        (edited / 'report2.json').write_bytes(signing.json_bytes(rep))
        self.refused({**base, 'plan': edited / 'plan.json', 'report': edited / 'report2.json'}, 'sealed signing record disagrees with the signing plan')
        # Rehash: relabel the sealed inventory, then also the seal; signatures still bind the originals.
        out = self.copy_final(run, 'rehash')
        path = out / RES / 'build-inventory.json'
        inventory = json.loads(path.read_text())
        inventory['signing']['purpose'] = 'distribution-candidate'
        path.write_bytes(fm.serialize(inventory))
        rehash = {**base, 'final_app': out, 'plan': edited / 'plan.json', 'report': edited / 'report2.json'}
        self.refused(rehash, 'The signing report does not bind this final payload|CodeResources seal entry differs')
        seal = out / 'Contents/_CodeSignature/CodeResources'
        value = plistlib.loads(seal.read_bytes())
        value['files2']['Resources/resources/v2/build-inventory.json'] = {'hash2': hashlib.sha256(path.read_bytes()).digest()}
        seal.write_bytes(plistlib.dumps(value))
        self.refused({**base, 'final_app': out}, 'does not bind Info.plist and the seal')
        # Report reuse: another run's distribution-candidate plan and report cannot bind this app.
        other_root = self.root / 'other'
        other_root.mkdir()
        other = self.build(other_root)
        self.refused({**base, 'plan': other['plan'], 'report': other['report']}, 'did not inspect this input app|does not bind this final payload')
        self.refused({**self.spec(other, None), 'final_app': run['final']}, 'does not bind this final payload|Unexpected')

    def test_cli_refusal_writes_no_binding_and_never_self_references(self):
        run = self.build(self.root)
        review = self.review(run, self.root)
        args = ['prepare', '--input-app', str(run['app']), '--final-app', str(run['final']), '--plan', str(run['plan']), '--report', str(run['report']),
                '--prepared-extractor', str(run['prepared']), '--materials-locks', str(run['locks']),
                '--delivery-root', f"receipts={run['work'] / 'receipts/desktop-reviewed'}", '--delivery-root', f"sources={run['delivery'] / 'sources'}",
                '--delivery-root', f"notes={run['delivery'] / 'notes'}", '--desktop-receipt', 'receipts/receipt.json', '--desktop-notices', 'receipts/native-NOTICES.txt',
                '--review', str(review)]
        with canned_binder(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BIND_CLI.main([*args, '--output', str(self.root / 'bound')]), 0)
        self.assertEqual(sorted(p.name for p in (self.root / 'bound').iterdir()), ['binding-report.json', fm.FINAL_NAME])
        with canned_binder(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BIND_CLI.main(['verify', *args[1:], '--final', str(self.root / 'bound' / fm.FINAL_NAME), '--output', str(self.root / 'verified.json')]), 0)
        # Partial failure late in derivation: only a refusal report, never a binding.
        (run['locks'] / 'desktop-Cargo.lock').write_bytes(b'# stale\n')
        with canned_binder(), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(BIND_CLI.main([*args, '--output', str(self.root / 'refused')]), 1)
        self.assertEqual([p.name for p in (self.root / 'refused').iterdir()], ['binding-report.json'])
        refusal = json.loads((self.root / 'refused/binding-report.json').read_text())
        self.assertEqual((refusal['status'], refusal['coverage_validated'], refusal['release_accepted']), ('refused', False, False))
        for output in (run['delivery'] / 'notes' / 'bound', run['final'] / 'Contents' / 'bound'):
            with self.subTest(str(output)), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(BIND_CLI.main([*args, '--output', str(output)]), 1)
                self.assertFalse(output.exists())


    def test_v2_binds_the_stock_route_with_v1_relations(self):
        run = self.build(self.root)
        review = self.review(run, self.root)
        status, doc, report = self.prepare(self.spec(run, review, contract=V2))
        self.assertEqual(status, 'final-materials-validated', report['gaps'])
        self.assertEqual((doc['schema'], report['schema'], report['distribution_validation']), (V2, fm.REPORT_SCHEMA_V2, {'pass': True}))
        x = doc['extractor']
        self.assertEqual((x['route'], x['method'], x['report'], x['source'], x['target_arch'], x['members_verified']),
                         ('upstream-stock', fm.EXTRACTOR_METHOD, None, None, 'arm64', 2))
        self.assertEqual((x['producer']['sha256'], x['prepared']['sha256']), (digest((run['app'] / EXTRACTOR).read_bytes()), digest(run['prepared'].read_bytes())))
        # Everything but the schema, the route label and the limits equals the v1 binding of the same run.
        _, v1doc, _ = self.prepare(self.spec(run, review))
        self.assertEqual(v1doc['schema'], V1)
        self.assertEqual(doc['relations'][EXTRACTOR].pop('route'), 'upstream-stock')
        for key in fm.TOP:
            if key not in ('schema', 'limits'):
                self.assertEqual(doc[key], v1doc[key], key)
        doc['relations'][EXTRACTOR]['route'] = 'upstream-stock'
        with canned_binder():
            self.assertTrue(fm.verify(self.spec(run, review, contract=V2), signing.json_bytes(doc))['rederived_equal'])
            with self.assertRaisesRegex(ValueError, 'not an omd-final-materials-v1 document'):
                fm.verify(self.spec(run, review), signing.json_bytes(doc))
            with self.assertRaisesRegex(ValueError, 'not an omd-final-materials-v2 document'):
                fm.verify(self.spec(run, review, contract=V2), signing.json_bytes(v1doc))
        # Source inputs can never relabel a stock plan, and v1 has no source route at all.
        decoy = {'report': run['report'], 'evidence': run['plan'], 'evidence_sha256': '0' * 64, 'kit': 'notes/route.md', 'bootloader': run['plan']}
        self.refused(self.spec(run, review, contract=V2, extractor_source=decoy), 'stock extractor route; controlled-source inputs cannot relabel it')
        self.refused(self.spec(run, review, extractor_source=decoy), 'has no controlled-source extractor route')
        self.refused(self.spec(run, review, contract='omd-final-materials-v3'), 'Unknown final materials contract')


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SourceRouteBinding(BindingFixtures, unittest.TestCase):
    """omd-final-materials-v2 on the controlled-source route: synthetic stage -> canned Developer
    ID source preparation and two-phase signing -> bind. Canned mechanics, not signature evidence."""

    def setUp(self):
        super().setUp()
        source_tests.pinned_fixture_profile(self)

    def test_source_proof_refuses_replaced_prepared_bytes(self):
        run = self.build(self.root, source_route=True)
        expected = digest(run['prepared'].read_bytes())
        real = fm.resolve_delivery
        def replace(path, roots):
            if path == run['source']['kit']:
                run['prepared'].write_bytes(b'replacement prepared bytes')
            return real(path, roots)
        with mock.patch.object(fm, 'resolve_delivery', side_effect=replace):
            self.refused(self.spec(run), 'Prepared extractor changed before the source proof')
        self.assertNotEqual(digest(run['prepared'].read_bytes()), expected)

    def test_controlled_source_stage_sign_and_bind(self):
        run = self.build(self.root, source_route=True)
        case, given = run['source']['case'], run['source']
        planned = next(o for o in run['plan_body']['code_objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(planned['replacement']['transformation']['method'], fm.SOURCE_EXTRACTOR_METHOD)
        review = self.review(run, self.root)
        status, doc, report = self.prepare(self.spec(run, review))
        self.assertEqual(status, 'final-materials-validated', report['gaps'])
        self.assertEqual((doc['schema'], doc['coverage_validated'], doc['distribution_candidate'], doc['reviewed'], doc['release_accepted']), (V2, True, True, True, False))
        x = doc['extractor']
        self.assertEqual((x['path'], x['component'], x['route'], x['method'], x['version'], x['target_arch'], x['members_verified']),
                         (EXTRACTOR, 'yt_dlp', 'controlled-source', fm.SOURCE_EXTRACTOR_METHOD, '2026.08.19', 'arm64', 2))
        producer, prepared = (run['app'] / EXTRACTOR).read_bytes(), run['prepared'].read_bytes()
        self.assertEqual(x['producer'], {'bytes': len(producer), 'sha256': digest(producer)})
        self.assertEqual(x['producer']['sha256'], case.doc['producer']['sha256'])
        self.assertEqual(x['prepared'], {'bytes': len(prepared), 'sha256': digest(prepared)})
        self.assertEqual(x['report'], signing.file_identity(given['report']))
        source = x['source']
        self.assertEqual(source['evidence'], {'schema': fm.SOURCE_EVIDENCE_SCHEMA, **signing.file_identity(given['evidence'])})
        self.assertEqual(source['evidence']['sha256'], given['evidence_sha256'])
        self.assertEqual(source['kit'], {'locator': 'delivery:' + KIT, **case.doc['kit']})
        self.assertEqual((source['bootloader'], source['profile'], source['plan_sha256'], source['receipt_sha256']),
                         (case.doc['bootloader'], case.doc['profile'], case.doc['plan_sha256'], case.doc['receipt_sha256']))
        self.assertEqual((source['natives'], source['members']), (2, 9))
        relation = doc['relations'][EXTRACTOR]
        self.assertEqual((relation['route'], relation['method'], relation['before'], relation['prepared'], relation['signature_only_natives'], relation['identical_non_natives']),
                         ('controlled-source', fm.SOURCE_EXTRACTOR_METHOD, digest(producer), digest(prepared), 2, 7))
        self.assertEqual(report['relations'], {'build-inventory': 1, 'engine-receipt': 1, 'identical': report['relations']['identical'], 'managed-manifest': 2,
                                               'outer-seal': 1, 'prepared-extractor': 1, 'signature-only': 14})
        # The kit is a bound delivery file and the extractor component's typed source material;
        # the initial review keeps the producer digest and the final digest is separate.
        self.assertEqual(doc['delivery']['files'][KIT], case.doc['kit'])
        yt = next(c for c in doc['components'] if c['id'] == 'yt_dlp')
        self.assertEqual((yt['basis'], yt['status'], yt['materials']['source']['delivery:' + KIT]), ('initial-review', 'reviewed', case.doc['kit']['sha256']))
        self.assertEqual(yt['artifacts'][EXTRACTOR], {'initial': digest(producer), 'final': digest((run['final'] / EXTRACTOR).read_bytes())})
        dumped = json.dumps(doc)
        for local in (str(self.root), str(given['kits']), str(case.root)):
            self.assertNotIn(local, dumped)
        initial = (run['app'] / RES / 'third-party/materials-v1.json').read_bytes()
        self.assertEqual(fm.validate_final(doc, initial, signing.inventory_of(run['final']), doc['delivery']['files'], result_expect(run, doc))['schema'], V2)
        # verify re-derives every byte relation and route proof; any edit to the document is refused.
        with canned_binder():
            verified = fm.verify(self.spec(run, review), signing.json_bytes(doc))
            self.assertEqual((verified['schema'], verified['rederived_equal'], verified['distribution_validation']), (fm.VERIFICATION_SCHEMA_V2, True, {'pass': True}))

            def relabel_stock(d):
                d['relations'][EXTRACTOR].update(method=fm.EXTRACTOR_METHOD, route='upstream-stock')
                d['extractor'].update(method=fm.EXTRACTOR_METHOD, route='upstream-stock', report=None, source=None)

            def other_bootloader(d):
                d['extractor']['source']['bootloader']['sha256'] = '1' * 64
            for change in (relabel_stock, other_bootloader):
                forged = copy.deepcopy(doc)
                change(forged)
                with self.subTest(change.__name__), self.assertRaisesRegex(ValueError, 'differs from the binding re-derived from actual bytes: extractor'):
                    fm.verify(self.spec(run, review), signing.json_bytes(forged))
        # The v1 contract still refuses this run outright (fail-closed control); nothing is bound.
        self.refused(self.spec(run, review, contract=V1, extractor_source=None), 'controlled-source extractor route is not supported by omd-final-materials-v1')
        # Delivery tampering after binding: the kit is re-derived at verify and refused.
        with (given['kits'] / 'source-kit.tar.gz').open('ab') as stream:
            stream.write(b'\0')
        with canned_binder(), self.assertRaisesRegex(ValueError, 'The source kit differs from the evidence-bound reviewed kit'):
            fm.verify(self.spec(run, review), signing.json_bytes(doc))

    def test_controlled_source_refusals(self):
        run = self.build(self.root, source_route=True)
        review = self.review(run, self.root)
        base = self.spec(run, review)
        given, case = base['extractor_source'], run['source']['case']
        other = self.root / 'other-inputs'
        other.mkdir()
        # Another kit: same producer, different kit bytes (its own evidence would differ too).
        other_case = source_tests.Case(other, 'other-kit', case.producer, index=lambda d: d['limits'].append('another kit'))
        (other / 'kits').mkdir()
        shutil.copyfile(other_case.kit, other / 'kits/source-kit.tar.gz')
        shutil.copyfile(source_tests.Boot.get() / 'other-run', other / 'other-run')
        edited_report = other / 'extractor-report.json'
        edited_report.write_bytes(given['report'].read_bytes() + b' ')
        other_evidence = case.spec(raw=source_tests.js(case.doc) + b' ')['evidence']
        refusals = [
            ({'extractor_source': None}, 'uses the controlled-source extractor route; supply its preparation report'),
            ({'extractor_source': {**given, 'evidence': Path(other_evidence['path']), 'evidence_sha256': other_evidence['sha256']}},
             'differs from the evidence the signing plan inspected'),
            ({'extractor_source': {**given, 'evidence': Path(other_evidence['path'])}}, 'Source evidence digest differs from the requested digest'),
            ({'extractor_source': {**given, 'report': edited_report}}, 'Prepared extractor report digest differs from the requested digest'),
            ({'extractor_source': {**given, 'bootloader': other / 'other-run'}}, 'The compiled bootloader differs from the evidence-bound bootloader'),
            ({'delivery_roots': {**base['delivery_roots'], 'kits': other / 'kits'}}, 'The source kit differs from the evidence-bound reviewed kit'),
            ({'extractor_source': {**given, 'kit': 'missing/source-kit.tar.gz'}}, 'outside every declared delivery root'),
            ({'extractor_source': {**given, 'kit': 'kits/absent.tar.gz'}}, 'not a regular file|No such file'),
        ]
        for change, why in refusals:
            with self.subTest(why):
                self.refused({**base, **change}, why)
        # A stale review delivery row for the kit is refused (bytes are hashed in place).
        stale = self.review(run, self.root, lambda r: r['delivery'].append({'path': KIT, 'bytes': 1, 'sha256': '0' * 64}))
        self.refused(self.spec(run, stale), 'Stale/changed delivery material: ' + KIT)
        # Genuine codesign (uncanned): the ad-hoc substitutes fail the Developer ID Team requirement.
        with mock.patch.object(fm, 'check_signature', side_effect=adhoc_check):
            with self.assertRaisesRegex(ValueError, 'failed cryptographic verification|Cryptographic signature verification failed'):
                fm.prepare(base)
        # Edited signing plans: a source plan relabelled stock is refused before any proof, and a
        # consistent stock relabel falls to the stock proof, which refuses the source producer.
        plan = json.loads(run['plan'].read_text())
        report = json.loads(run['report'].read_text())

        def forged(name, change):
            body = copy.deepcopy(plan)
            change(body)
            path = other / f'{name}-plan.json'
            path.write_bytes(signing.json_bytes(body))
            edited = copy.deepcopy(report)
            edited['plan']['sha256'] = digest(path.read_bytes())
            report_path = other / f'{name}-report.json'
            report_path.write_bytes(signing.json_bytes(edited))
            return {'plan': path, 'report': report_path}

        def drop_source(body):
            del body['request']['prepared_extractor']['source']

        def stock_relabel(body):
            drop_source(body)
            yt = next(o for o in body['code_objects'] if o['role'] == 'yt-dlp')
            yt['replacement']['transformation']['method'] = fm.EXTRACTOR_METHOD
        self.refused({**base, **forged('drop-source', drop_source)}, r"route \(upstream-stock\) and its transformation method .* disagree")
        self.refused({**base, **forged('stock-relabel', stock_relabel)}, 'controlled-source inputs cannot relabel it')
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID for the pinned bootloader"):
            self.prepare({**base, **forged('stock-relabel-2', stock_relabel), 'extractor_source': None})

    def test_controlled_source_stays_pending_without_reviewed_kit_material(self):
        run = self.build(self.root, source_route=True)

        def unbound_kit(r):
            next(c for c in r['components'] if c['id'] == 'yt_dlp')['materials'] = {}
        status, doc, report = self.prepare(self.spec(run, self.review(run, self.root, unbound_kit)))
        self.assertEqual((status, doc['coverage_validated'], doc['distribution_candidate']), ('final-materials-incomplete', False, False))
        yt = next(c for c in doc['components'] if c['id'] == 'yt_dlp')
        self.assertEqual((yt['status'], yt['pending']), ('pending', ['ambiguous review: marked reviewed with unresolved statements; kept pending',
                                                                    f'the controlled-source kit delivery:{KIT} is not bound as a source material']))
        self.assertIn(f'yt_dlp: the controlled-source kit delivery:{KIT} is not bound as a source material', report['gaps']['component-materials'])
        self.assertEqual(doc['extractor']['source']['kit']['locator'], 'delivery:' + KIT)

        def pending(r):
            next(c for c in r['components'] if c['id'] == 'yt_dlp').update(status='pending', pending=['controlled-source kit terms review pending'])
        status, doc, report = self.prepare(self.spec(run, self.review(run, self.root, pending)))
        self.assertEqual((status, next(c for c in doc['components'] if c['id'] == 'yt_dlp')['status']), ('final-materials-incomplete', 'pending'))
        self.assertIn('Pending final materials coverage', report['distribution_validation']['error'])
        # Without a review the route proof still runs; nothing is reviewed or promoted.
        status, doc, report = self.prepare(self.spec(run, None))
        self.assertEqual((status, doc['components'], doc['extractor']['route']), ('final-materials-incomplete', [], 'controlled-source'))
        self.assertIn('review-input', report['gaps'])

    def test_cli_controlled_source_route(self):
        run = self.build(self.root, source_route=True)
        review = self.review(run, self.root)
        given = run['source']
        args = ['prepare', '--input-app', str(run['app']), '--final-app', str(run['final']), '--plan', str(run['plan']), '--report', str(run['report']),
                '--prepared-extractor', str(run['prepared']), '--materials-locks', str(run['locks']),
                '--delivery-root', f"receipts={run['work'] / 'receipts/desktop-reviewed'}", '--delivery-root', f"sources={run['delivery'] / 'sources'}",
                '--delivery-root', f"notes={run['delivery'] / 'notes'}", '--delivery-root', f"kits={given['kits']}",
                '--desktop-receipt', 'receipts/receipt.json', '--desktop-notices', 'receipts/native-NOTICES.txt', '--review', str(review)]
        source = ['--prepared-extractor-report', str(given['report']), '--prepared-extractor-source-evidence', str(given['evidence']),
                  '--prepared-extractor-source-evidence-sha256', given['evidence_sha256'], '--prepared-extractor-source-kit', KIT,
                  '--prepared-extractor-source-bootloader', str(given['bootloader'])]
        with canned_binder(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BIND_CLI.main([*args, '--contract', V2, *source, '--output', str(self.root / 'bound')]), 0)
        self.assertEqual(sorted(p.name for p in (self.root / 'bound').iterdir()), ['binding-report.json', fm.FINAL_NAME_V2])
        bound = json.loads((self.root / 'bound' / fm.FINAL_NAME_V2).read_text())
        self.assertEqual((bound['schema'], bound['extractor']['route'], bound['coverage_validated']), (V2, 'controlled-source', True))
        with canned_binder(), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(BIND_CLI.main(['verify', *args[1:], '--contract', V2, *source, '--final', str(self.root / 'bound' / fm.FINAL_NAME_V2),
                                            '--output', str(self.root / 'verified.json')]), 0)
        self.assertEqual(json.loads((self.root / 'verified.json').read_text())['schema'], fm.VERIFICATION_SCHEMA_V2)
        # Refusals: v1 refuses the route (refusal report only); source options need v2, all together.
        with canned_binder(), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(BIND_CLI.main([*args, '--output', str(self.root / 'v1')]), 1)
        self.assertEqual([p.name for p in (self.root / 'v1').iterdir()], ['binding-report.json'])
        self.assertIn('not supported by omd-final-materials-v1', json.loads((self.root / 'v1/binding-report.json').read_text())['refused'])
        for argv, why in (([*args, *source], 'need --contract omd-final-materials-v2'), ([*args, '--contract', V2, *source[:8]], 'all four --prepared-extractor-source-* options together'),
                          ([*args, '--contract', V2, *source[:5], 'ABC', *source[6:]], '64 lowercase hex')):
            with self.subTest(why), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(BIND_CLI.main([*argv, '--output', str(self.root / 'never')]), 1)
                self.assertIn(why, err.getvalue())
                self.assertFalse((self.root / 'never').exists())
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(BIND_CLI.main([*args, '--contract', V2, *source, '--output', str(given['evidence'].parent / 'bound')]), 1)
        self.assertIn('outside the controlled-source input directories', err.getvalue())


def result_expect(run, doc):
    """Expectations as the binder derives them from the pre-signature input."""
    tools = json.loads((run['app'] / RES / 'tools/tools-v2.json').read_text())
    browser = json.loads((run['app'] / RES / 'browser/browser-tools-v2.json').read_text())
    required = {n: {'version': doc['version'], 'prefix': 'bin/' + n} for n in ENGINE}
    required.update({n: {'version': tools[n]['version'], 'prefix': f'tools/{n}/'} for n in ('yt_dlp', 'ffmpeg', 'ffprobe', 'node')})
    required['browser'] = {'version': browser['version'], 'prefix': 'browser/content/'}
    return {'target': doc['target'], 'version': doc['version'], 'locks': doc['locks'], 'required': required,
            'final_components': {n: {'version': doc['version'], 'artifact': SHELL} for n in ('desktop-rust', 'frontend')}}


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SignerTwoPhaseOption(unittest.TestCase):
    """The narrow signer integration: explicit, Developer ID distribution-candidate only."""

    def test_two_phase_is_explicit_and_narrow(self):
        root = scratch(self)
        app = sign_tests.build_app(root, staging='release')
        devid = lambda **extra: sign_tests.request(app, 'developer-id', DEVID, TEAM, **extra)
        for request, why in ((sign_tests.request(app, materials_binding='two-phase'), 'only to developer-id distribution-candidate'),
                             (devid(purpose='private-validation', materials_binding='two-phase'), 'only to developer-id distribution-candidate'),
                             (devid(materials_binding='three-phase'), 'Unknown materials binding')):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(request)
        # Release staging without a validated two-phase record keeps the signing blocker.
        plan = signing.inspect(devid(materials_binding='two-phase'))
        blocker = next(b for b in plan['blockers'] if b['id'] == 'materials-bind-pre-signature')
        self.assertEqual(blocker['severity'], 'signing')
        self.assertIn('two-phase binding unavailable: the build inventory does not record validated two-phase release staging', blocker['message'])
        self.assertNotIn('final_binding', blocker)
        default = signing.inspect(devid())
        self.assertEqual(default['materials_binding'], 'single-phase')
        self.assertEqual(next(b for b in default['blockers'] if b['id'] == 'materials-bind-pre-signature')['severity'], 'signing')
        plan_path = sign_tests.write_plan(root, plan)
        with self.assertRaisesRegex(ValueError, 'differs from the requested execution binding'):
            signing.execute(plan_path, root / 'Out.app', root / 'work')
        with self.assertRaisesRegex(ValueError, 'Signing blockers'):
            signing.execute(plan_path, root / 'Out.app', root / 'work', materials_binding='two-phase')
        self.assertEqual(sign_tests.SIGN_CLI.EXIT[signing.TWO_PHASE_STATUS], 2)


@unittest.skipUnless(NATIVE and REHEARSAL and os.environ.get('OMD_FINAL_MATERIALS_EXTRACTOR'), 'set OMD_FINAL_MATERIALS_REHEARSAL and OMD_FINAL_MATERIALS_EXTRACTOR to explicit private validation inputs')
class GenuinePrivatePair(unittest.TestCase):
    """Read-only: the genuine Developer ID private-validation pair binds mechanically but
    stays a private, pending binding; genuine signed bytes reject tampering and wrong roles."""

    @classmethod
    def setUpClass(cls):
        root = Path(REHEARSAL)
        cls.input = root / 'input/OMD Private Validation.app'
        cls.final = root / 'signing/signed/OMD Private Validation.app'
        cls.spec = {'input_app': cls.input, 'final_app': cls.final, 'plan': root / 'signing/plan-private-validation.json', 'report': root / 'signing/work/signing-report.json',
                    'prepared_extractor': Path(os.environ['OMD_FINAL_MATERIALS_EXTRACTOR']),
                    'locks': Path(os.environ['OMD_FINAL_MATERIALS_LOCKS']) if os.environ.get('OMD_FINAL_MATERIALS_LOCKS') else None,
                    'delivery_roots': {'desktop-receipt': root / 'signing/work/receipts/desktop-reviewed'},
                    'desktop_receipt': {'receipt': 'desktop-receipt/receipt.json', 'notices': 'desktop-receipt/native-NOTICES.txt'},
                    'review': None, 'cryptographic': True, 'temp_root': None}

    def test_genuine_pair_binds_privately(self):
        before = fm.canonical_inventory(signing.inventory_of(self.final))
        status, doc, report = fm.prepare(self.spec)
        self.assertEqual(before, 'e25c44881efc487cd3a798ee5198d7b678f71bfba705a29588d6cc32bdf2dbc7')
        self.assertEqual(doc['payload']['inventory_sha256'], before)
        self.assertEqual((status, doc['purpose'], doc['coverage_validated'], doc['distribution_candidate'], doc['release_accepted']),
                         ('final-materials-incomplete', 'private-validation', False, False, False))
        self.assertEqual(report['relations'], {'build-inventory': 1, 'engine-receipt': 1, 'identical': 147, 'managed-manifest': 2, 'outer-seal': 1,
                                               'prepared-extractor': 1, 'signature-only': 14})
        self.assertEqual((report['extractor']['signature_only_natives'], report['extractor']['identical_non_natives'], report['extractor']['members_verified']), (103, 40, 103))
        self.assertEqual((report['receipts']['engine']['findings'], report['receipts']['engine']['spans'], report['receipts']['desktop']['spans_in_payload']), (74, 1011, 553))
        self.assertEqual(report['distribution_validation']['error'], 'Private-validation output is never a distribution candidate')
        self.assertEqual(fm.canonical_inventory(signing.inventory_of(self.final)), before)

    def test_genuine_signed_bytes_reject_tampering_and_wrong_roles(self):
        policy, _ = signing.load_policy()
        roles = {signing.expand(r['path'], policy['resources'], EXE): r for r in policy['roles']}
        bundle = 'labs.northwolf.omd-private-validation-20261102'
        before = (self.input / RES / 'bin/omd').read_bytes()
        after = (self.final / RES / 'bin/omd').read_bytes()
        layout, independent = signing.macho_layout(before)
        signing.signature_change(independent, layout, after)
        fm.check_signature('bin/omd', roles[RES + '/bin/omd'], after, 'developer-id', 'ALPX923Y54', bundle + '.cli')
        tampered = bytearray(after)
        tampered[len(tampered) // 3] ^= 0xff
        with self.assertRaisesRegex(ValueError, 'other than the signature changed'):
            signing.signature_change(independent, layout, bytes(tampered))
        for team, role, identifier, why in (('ZZZZZ99999', RES + '/bin/omd', bundle + '.cli', 'mode/team mismatch'),
                                            ('ALPX923Y54', RES + '/tools/node/node', bundle + '.cli', 'entitlements differ'),
                                            ('ALPX923Y54', RES + '/bin/omd', bundle + '.engine', 'unexpected signing identifier')):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                fm.check_signature('bin/omd', roles[role], after, 'developer-id', team, identifier)
        worker = (self.final / RES / 'bin/omd-plugin-worker-v2').read_bytes()
        with self.assertRaisesRegex(ValueError, 'entitlements differ'):
            fm.check_signature('worker', roles[RES + '/bin/omd'], worker, 'developer-id', 'ALPX923Y54', bundle + '.plugin-worker')
        slots = fm.code_directories((self.final / SHELL).read_bytes())
        self.assertTrue(slots and all(s[1] == digest((self.final / 'Contents/Info.plist').read_bytes()) and s[3] == digest((self.final / fm.SEAL).read_bytes()) for s in slots))


@unittest.skipUnless(NATIVE and SOURCE_ADAPTER and SOURCE_KIT,
                     'set OMD_FINAL_MATERIALS_SOURCE_ADAPTER (signing adapter evidence directory) and OMD_FINAL_MATERIALS_SOURCE_KIT (reviewed kit)')
class GenuineSourceExtractor(unittest.TestCase):
    """Read-only: the v2 controlled-source proof of the binder on the real reviewed producer and
    its labelled ad-hoc changed-signature control (4 KiB pages), with the reviewed evidence, kit and
    compiled bootloader. Development mode only: this is not a same-Team or Developer ID result."""
    EVIDENCE = '51b8e3642c496883994d354e65340fd10110114e7711a55dc72e5024e0460822'
    REPORT = '83b2f2b0686db0022af5eb52855431b41f1dfff32850de44d7fca0ead4b182b4'

    @classmethod
    def setUpClass(cls):
        root = Path(SOURCE_ADAPTER)
        cls.producer = root / 'inputs/producer/omd-yt-dlp'
        cls.prepared = root / 'real/control-4k/out/omd-yt-dlp'
        cls.inputs = {'report': root / 'real/control-4k/work/extractor-report.json', 'evidence': root / 'evidence/source-evidence.json', 'evidence_sha256': cls.EVIDENCE,
                      'kit': Path(SOURCE_KIT), 'kit_locator': 'delivery:ytdlp-source-kit/source-kit.tar.gz', 'bootloader': root / 'inputs/bootloader/run'}

    def prove(self, **change):
        args = {'producer_path': self.producer, 'prepared_path': self.prepared, 'version': '2026.08.19', 'target': 'arm64', 'mode': 'development-adhoc', 'team': None,
                'inputs': self.inputs, 'report_sha256': self.REPORT, 'evidence_sha256': self.EVIDENCE,
                'prepared_sha256': '75ce2c163e41e0d2b159a862477a5cc43aa81afa8413b4a2db28805bb2f45865', 'temp_root': None, **change}
        return fm.prove_source_extractor(**args)

    def test_real_controlled_source_proof(self):
        before = {k: signing.file_identity(v) for k, v in (('producer', self.producer), ('prepared', self.prepared), *((k, self.inputs[k]) for k in ('report', 'evidence', 'kit', 'bootloader')))}
        result = self.prove()
        proof, members, source = result['proof'], result['cryptographic']['members'], result['source']
        self.assertEqual((proof['method'], proof['signature_only_natives'], proof['identical_non_natives']), (fm.SOURCE_EXTRACTOR_METHOD, 99, 1107))
        self.assertEqual((members['native_members'], members['verified'], members['failed'], result['cryptographic']['outer']['exit']), (99, 99, 0, 0))
        self.assertEqual((source['members'], source['natives']), (1206, 99))
        self.assertEqual((before['producer']['sha256'], before['prepared']['sha256']),
                         ('82f044442f05edc077a4a3b70238186cdab99870407aa6ffb3366466867b9783', '75ce2c163e41e0d2b159a862477a5cc43aa81afa8413b4a2db28805bb2f45865'))
        self.assertEqual((source['evidence']['sha256'], source['kit']['sha256'], source['bootloader']['sha256'], source['plan_sha256'], source['receipt_sha256'],
                          source['profile']['sha256']),
                         (self.EVIDENCE, '10748f83c08e083ff3d49e4e48dde1fac946a40a7e45c46b6be0091d3b59bdab',
                          '6164c9082504a628c58e3d3a7268cfd70cea3a0b70e41712cd4325e41d304ec8', 'bc6bc7e488b40fdab642b2c013303b29bb201732d873dc29814a610becf65a0b',
                          '57b952254b8fb2a504d3937e57dc99d3f8d7625eae70508000bd12f862e2a5e1', '3822cd3dba4751ee41251203def6f20e3ebfa6eafada3fb20c5f24d3b6aa2c52'))
        self.assertEqual((source['kit']['bytes'], source['bootloader']['bytes'], result['report']['sha256']), (278327344, 71952, self.REPORT))
        self.assertNotIn('/Volumes/', json.dumps({'report': result['report'], 'source': source}))
        self.assertEqual({k: signing.file_identity(v) for k, v in (('producer', self.producer), ('prepared', self.prepared),
                                                                   *((k, self.inputs[k]) for k in ('report', 'evidence', 'kit', 'bootloader')))}, before)

    def test_real_route_refusals(self):
        cases = [({'prepared_path': self.producer}, 'The prepared extractor is the producer itself'),
                 ({'prepared_sha256': '0' * 64}, 'Prepared extractor changed before the source proof'),
                 ({'mode': 'developer-id', 'team': 'ZZZZZ99999'}, 'different signing mode or Team ID'),
                 ({'evidence_sha256': '0' * 64}, 'differs from the evidence the signing plan inspected'),
                 ({'report_sha256': '0' * 64}, 'Prepared extractor report digest differs'),
                 ({'version': '2026.09.01'}, 'Report version or architecture differs')]
        for change, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                self.prove(**change)
        # The stock route never proves the controlled-source pair.
        with self.assertRaisesRegex(ValueError, "LC_UUID is not PyInstaller's PKG-derived UUID for the pinned bootloader"):
            ex.verify_pair({'path': str(self.producer), 'sha256': digest(self.producer.read_bytes())}, {'path': str(self.prepared), 'sha256': digest(self.prepared.read_bytes())},
                           '2026.08.19', 'arm64', 'development-adhoc', None, crypto=False)


def tearDownModule():
    for owner in (sign_tests.Native, extractor_tests.Fixture, source_tests.Boot, source_tests.base.Fixture):
        if owner.root is not None:
            shutil.rmtree(owner.root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
