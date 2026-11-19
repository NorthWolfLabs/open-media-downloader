# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Notarized materials envelope tests (omd-notarized-materials-v1).

Shared contract cases and raw strict-loader cases are byte-identical to the desktop copy and
pinned by digest in both trees; messages must be identical. The final-materials v1/v2 fixtures
the envelope composes stay pinned and unchanged. Native cases use small synthetic trees and
archives, real ditto and real codesign on a linker-signed fixture executable. Canned tool runs
(marked as such) exercise orchestration and race detection only, never Apple acceptance;
uncanned codesign and stapler refuse those fixtures.

Opt-in, read-only real data: OMD_NOTARIZED_MATERIALS_CHAIN names a JSON file with the
bind-notarized-materials.py options of the genuine signed/stapled chain. It runs the full
prepare/verify with uncanned Apple tools and negative controls on owned private copies
(ticket corruption, magic-only, truncated and zero-length tickets, code corruption, an extra
file, a seal change, a wrong Team, timeouts, missing tools, output overflow and replacement
of a verified input during the Apple checks). Nothing is signed, stapled or submitted.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import final_materials as fm
import macos_signing as signing
import notarized_materials as nm

SCRIPTS = Path(__file__).resolve().parent
NATIVE = platform.system() == 'Darwin' and Path(nm.CODESIGN).exists() and Path(nm.DITTO).exists()
COMPILER = shutil.which('clang')
CHAIN = os.environ.get('OMD_NOTARIZED_MATERIALS_CHAIN')
FIXTURE_DIGEST = 'f1adf252720868eb5542ecf9f1763be1df2230a48ec2227cfe8add9a500f554a'
FINAL_DIGESTS = {1: '6c07008986773c2583d6ee2466db2acc86cd07953b9fbf249d517669f2f516ca', 2: 'fa191ccd7529e2b4386c5433611ff2c3959776335ffafbb1de81c0206c6ed08e'}
PROVENANCE = (('com.apple.provenance', bytes.fromhex('010200a390490c9b0c10d0')),)
STRUCTURE = {'schema': nm.SCHEMA, 'structure_validated': True, 'macos_verification_required': True, 'release_accepted': False}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLI = load('omd_bind_notarized_cli', 'bind-notarized-materials.py')
sha = lambda data: hashlib.sha256(data).hexdigest()


def scratch(test):
    folder = Path(tempfile.mkdtemp(prefix='omd-notarized-test-')).resolve()
    test.addCleanup(shutil.rmtree, folder, True)
    return folder


def apply(base, edits):
    s = copy.deepcopy(base)
    for e in edits:
        if e['target'] in ('binding', 'initial'):
            s[e['target']] = e['value']
            continue
        current = s[e['target']]
        for part in e['path'][:-1]:
            current = current[part]
        if e.get('delete'):
            del current[e['path'][-1]]
        else:
            current[e['path'][-1]] = copy.deepcopy(e['value'])
    return s


class SharedContract(unittest.TestCase):
    """The same cases and exact messages as desktop scripts/notarized-materials-contract.test.mjs."""

    @classmethod
    def setUpClass(cls):
        cls.raw = (SCRIPTS.parent / 'distribution/notarized-materials-fixtures-v1.json').read_bytes()
        cls.fixtures = json.loads(cls.raw)

    def test_fixture_copy_is_pinned_and_final_fixtures_are_unchanged(self):
        self.assertEqual(sha(self.raw), FIXTURE_DIGEST)
        self.assertEqual(self.fixtures['schema'], 'omd-notarized-materials-contract-fixtures-v1')
        for version, digest in FINAL_DIGESTS.items():
            self.assertEqual(sha((SCRIPTS.parent / f'distribution/final-materials-fixtures-v{version}.json').read_bytes()), digest)

    def test_shared_cases(self):
        cases = self.fixtures['cases']
        self.assertGreaterEqual(len(cases), 100)
        self.assertTrue({'complete-v2-controlled-source-envelope', 'complete-v1-stock-envelope', 'complete-v2-stock-route-envelope'}
                        <= {c['name'] for c in cases if c['valid']})
        for case in cases:
            with self.subTest(case['name']):
                s = apply(self.fixtures['bases'][case['base']], case['edits'])
                run = lambda: nm.validate_notarized(s['doc'], s['binding'].encode(), s['initial'].encode(), s['signed_payload'], s['stapled_payload'],
                                                    s['delivery'], s['archives'], s['evidence'], s['expect'])
                if case['valid']:
                    self.assertEqual(run(), STRUCTURE)
                else:
                    with self.assertRaises(ValueError) as caught:
                        run()
                    self.assertEqual(str(caught.exception), case['error'])

    def test_strict_loader_cases(self):
        self.assertGreaterEqual(len(self.fixtures['loader']), 25)
        for case in self.fixtures['loader']:
            with self.subTest(case['name']):
                run = lambda: nm.load_strict(bytes.fromhex(case['raw_hex']))
                if case['valid']:
                    run()
                else:
                    with self.assertRaises(ValueError) as caught:
                        run()
                    self.assertEqual(str(caught.exception), case['error'])

    def test_structure_never_promotes(self):
        base = self.fixtures['bases']['v2']
        result = nm.validate_notarized(base['doc'], base['binding'].encode(), base['initial'].encode(), base['signed_payload'], base['stapled_payload'],
                                       base['delivery'], base['archives'], base['evidence'], base['expect'])
        self.assertEqual(set(result), {'schema', 'structure_validated', 'macos_verification_required', 'release_accepted'})
        self.assertNotIn('distribution_candidate', result)
        # The unchanged v2 contract still refuses the stapled payload as a final payload.
        final = json.loads(base['binding'])
        with self.assertRaisesRegex(ValueError, 'Final payload differs from the bound payload inventory'):
            fm.validate_final(final, base['initial'].encode(), base['stapled_payload'], base['delivery'], {k: base['expect'][k] for k in ('target', 'version', 'locks', 'required', 'final_components')})

    def test_python_json_alone_keeps_the_last_duplicate(self):
        text = b'{"release_accepted":false,"release_accepted":true}'
        self.assertIs(json.loads(text)['release_accepted'], True)
        with self.assertRaisesRegex(ValueError, 'Duplicate JSON key'):
            nm.load_strict(text)


@unittest.skipUnless(platform.system() == 'Darwin', 'macOS process-group behavior')
class BoundedProcess(unittest.TestCase):
    env = {'PATH': '/usr/bin:/bin'}

    def test_exit_output_and_missing_tools(self):
        self.assertEqual({k: v for k, v in nm.run_bounded(['/bin/echo', 'hi'], 5, self.env, 1024).items() if k in ('exit', 'stdout')}, {'exit': 0, 'stdout': 'hi\n'})
        self.assertEqual(nm.run_bounded(['/usr/bin/false'], 5, self.env, 1024)['exit'], 1)
        for argv in (['/nonexistent/tool'], ['echo', 'relative']):
            self.assertEqual(nm.run_bounded(argv, 5, self.env, 1024)['exit'], 'missing')

    def test_timeout_and_overflow_kill_only_the_owned_group(self):
        started = time.monotonic()
        record = nm.run_bounded(['/bin/sh', '-c', 'sleep 30 & echo $!; sleep 30'], 0.5, self.env, 1024)
        self.assertEqual(record['exit'], 'timeout')
        self.assertLess(time.monotonic() - started, 5)
        child = int(record['stdout'].split()[0])
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)
        record = nm.run_bounded(['/usr/bin/yes'], 10, self.env, 4096)
        self.assertEqual((record['exit'], record['output_bytes'] > 4096, len(record['stdout']) <= 4096), ('overflow', True, True))

    def test_lingering_descendant_is_reaped_with_the_group(self):
        record = nm.run_bounded(['/bin/sh', '-c', 'sleep 30 >/dev/null 2>&1 & echo $!'], 5, self.env, 1024)
        self.assertEqual(record['exit'], 0)
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(record['stdout'].split()[0]), 0)

    def test_run_classifies_unverified_and_refuses_mutating_commands(self):
        run = nm.Run(seconds=30, timeouts={'codesign': 0.001})
        self.addCleanup(run.cleanup)
        with mock.patch.object(nm, 'run_bounded', return_value={'exit': 'timeout', 'stdout': '', 'stderr': ''}), self.assertRaises(nm.Unverified):
            run.tool('codesign', [nm.CODESIGN, '--verify', '/x.app'], 'probe')
        self.assertEqual(run.timeouts['codesign'], 0.001)
        for argv in ([nm.CODESIGN, '--sign', '-', '/x.app'], [nm.CODESIGN, '--verify', '-d', '/x.app'], [nm.XCRUN, 'stapler', 'staple', '/x.app'],
                     [nm.XCRUN, 'notarytool', 'history'], ['/usr/bin/security', 'find-generic-password'], [nm.SPCTL, '--add', '/x.app']):
            with self.subTest(argv), self.assertRaisesRegex(ValueError, 'outside the read-only verification command policy'):
                run.tool('codesign', argv, 'probe')
        with self.assertRaisesRegex(ValueError, 'workflow bound'):
            nm.Run(seconds=nm.WORKFLOW_SECONDS + 1)
        expired = nm.Run(seconds=0.001)
        self.addCleanup(expired.cleanup)
        time.sleep(0.01)
        with self.assertRaisesRegex(nm.Unverified, 'workflow bound expired'):
            expired.tool('info', [nm.SW_VERS], 'probe')


def tiny_tree(root, ticket=None, executable=b'\xcf\xfa\xed\xfe' + bytes(60)):
    """A small app-shaped tree: Info.plist, an executable, a seal and optionally a ticket."""
    app = root / 'X.app'
    for rel, data, mode in (('Contents/Info.plist', b'<plist/>', 0o644), ('Contents/MacOS/x', executable, 0o755),
                            ('Contents/_CodeSignature/CodeResources', b'seal', 0o644), ('Contents/Resources/data.txt', b'data', 0o644)):
        path = app / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    if ticket is not None:
        (app / nm.TICKET).write_bytes(ticket)
        (app / nm.TICKET).chmod(0o644)
    return app


class TreeAndClosure(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)

    def test_snapshot_copies_bytes_and_permissions(self):
        app = tiny_tree(self.root / 'a', ticket=b's8ch' + bytes(100))
        tree = nm.walk_tree(app, copy_to=self.root / 'copy.app')
        self.assertEqual(nm.walk_tree(self.root / 'copy.app'), tree)
        self.assertEqual(tree['modes']['Contents/MacOS/x'], 0o755)
        self.assertEqual(set(tree['dirs']), {'', 'Contents', 'Contents/MacOS', 'Contents/_CodeSignature', 'Contents/Resources'})

    def test_walk_refusals(self):
        cases = [('symlink', lambda app: (app / 'Contents/link').symlink_to('Info.plist'), 'Symlink in the app tree'),
                 ('hardlink', lambda app: os.link(app / 'Contents/Info.plist', app / 'Contents/hard'), 'Hard-linked file'),
                 ('fifo', lambda app: os.mkfifo(app / 'Contents/fifo'), 'Special file in the app tree'),
                 ('setuid', lambda app: (app / 'Contents/MacOS/x').chmod(0o4755), 'Special permission bits'),
                 ('unportable-name', lambda app: (app / 'Contents/a:b').write_bytes(b''), 'Invalid portable path'),
                 ('trailing-space', lambda app: (app / 'Contents/a ').write_bytes(b''), 'Invalid portable path')]
        for name, change, why in cases:
            with self.subTest(name):
                app = tiny_tree(self.root / name)
                change(app)
                with self.assertRaisesRegex(ValueError, why):
                    nm.walk_tree(app)
        with mock.patch.object(nm, 'MAX_TREE_FILES', 2), self.assertRaises(nm.Unverified):
            nm.walk_tree(tiny_tree(self.root / 'budget'))
        link = self.root / 'linked.app'
        link.symlink_to(tiny_tree(self.root / 'target'))
        with self.assertRaisesRegex(ValueError, 'Symlink'):
            nm.walk_tree(link)

    def test_ticket_only_closure(self):
        signed = nm.walk_tree(tiny_tree(self.root / 's'))
        stapled_app = tiny_tree(self.root / 't', ticket=b's8ch' + bytes(1943))
        self.assertEqual(nm.closure(signed, nm.walk_tree(stapled_app)), {'bytes': 1947, 'sha256': sha(b's8ch' + bytes(1943))})
        cases = [('extra-file', lambda app: (app / 'Contents/Resources/extra.txt').write_bytes(b'x'), 'Stapling must add exactly Contents/CodeResources'),
                 ('removal', lambda app: (app / 'Contents/Resources/data.txt').unlink(), 'Stapling removed signed payload files'),
                 ('changed-bytes', lambda app: (app / 'Contents/_CodeSignature/CodeResources').write_bytes(b'Seal'), 'Stapling changed signed payload files'),
                 ('changed-mode', lambda app: (app / 'Contents/Resources/data.txt').chmod(0o755), 'Stapling changed file permissions'),
                 ('new-directory', lambda app: (app / 'Contents/Library').mkdir(), 'directory closure'),
                 ('directory-mode', lambda app: (app / 'Contents/Resources').chmod(0o700), 'directory closure'),
                 ('no-ticket', lambda app: (app / nm.TICKET).unlink(), 'Stapling must add exactly Contents/CodeResources'),
                 ('zero-length-ticket', lambda app: (app / nm.TICKET).write_bytes(b''), 'outside the method bound'),
                 ('oversized-ticket', lambda app: (app / nm.TICKET).write_bytes(bytes(nm.TICKET_MAX + 1)), 'outside the method bound'),
                 ('executable-ticket', lambda app: (app / nm.TICKET).chmod(0o755), 'must not be executable')]
        for name, change, why in cases:
            with self.subTest(name):
                app = tiny_tree(self.root / ('c-' + name), ticket=b's8ch' + bytes(1943))
                change(app)
                with self.assertRaisesRegex(ValueError, why):
                    nm.closure(signed, nm.walk_tree(app))
        lower = copy.deepcopy(signed)
        lower['files']['Contents/coderesources'] = {'bytes': 1, 'sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'already contains a file at the ticket path'):
            nm.closure(lower, nm.walk_tree(stapled_app))


def appledouble(attrs=PROVENANCE, finder=bytes(32), rsrc=b''):
    """A sequestered AppleDouble member in ditto's layout."""
    table, values, offsets = b'', b'', []
    sizes = [(11 + len(name) + 1 + 3) & ~3 for name, _ in attrs]
    start = 120 + sum(sizes)
    for name, value in attrs:
        offsets.append(start + len(values))
        values += value
    for (name, value), offset in zip(attrs, offsets):
        entry = struct.pack('>IIHB', offset, len(value), 0, len(name) + 1) + name.encode() + b'\0'
        table += entry + bytes((-len(entry)) % 4)
    if attrs:
        total = start + len(values)
        block = finder + b'\0\0' + b'ATTR' + struct.pack('>IIII', 0, total, start, len(values)) + bytes(12) + struct.pack('>HH', 0, len(attrs)) + table + values
    else:
        block = finder
    header = struct.pack('>II', 0x00051607, 0x00020000) + b'Mac OS X        ' + struct.pack('>H', 2)
    header += struct.pack('>III', 9, 50, len(block)) + struct.pack('>III', 2, 50 + len(block), len(rsrc))
    return header + block + rsrc


def make_zip(path, app, tree, name='X.app', transport=True, skip=(), extra=(), modes=None, comment=b'', directories=True):
    """A ditto-shaped archive of `app` (directories, files with their modes, AppleDouble members)."""
    def info(member, mode):
        zi = zipfile.ZipInfo(member)
        zi.create_system = 3
        zi.external_attr = mode << 16
        zi.compress_type = zipfile.ZIP_STORED if member.endswith('/') else zipfile.ZIP_DEFLATED
        return zi
    with zipfile.ZipFile(path, 'w') as z:
        if directories:
            for rel, mode in tree['dirs'].items():
                z.writestr(info(name + '/' + (rel + '/' if rel else ''), stat.S_IFDIR | mode), b'')
        for rel in tree['files']:
            if rel not in skip:
                z.writestr(info(name + '/' + rel, stat.S_IFREG | (modes or {}).get(rel, tree['modes'][rel])), (app / rel).read_bytes())
        if transport:
            z.writestr(info('__MACOSX/', stat.S_IFDIR | 0o775), b'')
            for rel in tree['dirs']:
                z.writestr(info('__MACOSX/' + name + '/' + (rel + '/' if rel else ''), stat.S_IFDIR | 0o775), b'')
            for rel in ('Contents', 'Contents/Info.plist', *([nm.TICKET] if nm.TICKET in tree['files'] else [])):
                z.writestr(info(nm.appledouble(name + '/' + rel), stat.S_IFREG | 0o644), appledouble())
        for member, data, mode in extra:
            z.writestr(info(member, mode), data)
        z.comment = comment
    return path


class Archives(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)
        self.app = tiny_tree(self.root / 'src', ticket=b's8ch' + bytes(60))
        self.tree = nm.walk_tree(self.app)

    def read(self, path):
        return nm.read_archive(path, self.tree, 'X.app')

    def test_ditto_shaped_archive(self):
        seen = self.read(make_zip(self.root / 'ok.zip', self.app, self.tree))
        self.assertEqual(seen['payload'], self.tree['files'])
        self.assertEqual(set(seen['transport']), {'__MACOSX/X.app/._Contents', '__MACOSX/X.app/Contents/._Info.plist', '__MACOSX/X.app/Contents/._CodeResources'})
        self.assertEqual(seen['attributes'], ['com.apple.provenance'])
        bare = self.read(make_zip(self.root / 'bare.zip', self.app, self.tree, transport=False))
        self.assertEqual(bare['transport'], {})

    @unittest.skipUnless(NATIVE, 'needs ditto')
    def test_real_ditto_archive_round_trip(self):
        archive = self.root / 'ditto.zip'
        subprocess.run([nm.DITTO, '-c', '-k', '--sequesterRsrc', '--keepParent', self.app, archive], check=True)
        seen = self.read(archive)
        self.assertEqual(seen['payload'], self.tree['files'])
        self.assertTrue(set(seen['attributes']) <= set(nm.TRANSPORT_ATTRIBUTES))

    def test_archive_refusals(self):
        reg, dirmode = stat.S_IFREG | 0o644, stat.S_IFDIR | 0o755
        cases = [
            ('traversal', {'extra': [('X.app/../evil', b'x', reg)]}, 'Invalid portable path'),
            ('absolute', {'extra': [('/evil', b'x', reg)]}, 'Invalid portable path'),
            ('case-collision', {'extra': [('X.app/Contents/info.plist', b'x', reg)]}, 'Colliding ZIP member names'),
            ('symlink-member', {'extra': [('X.app/Contents/link', b'Info.plist', stat.S_IFLNK | 0o777)]}, 'regular files or directories'),
            ('second-app', {'extra': [('Y.app/Contents/Info.plist', b'x', reg)]}, 'exactly the expected app'),
            ('unknown-top-level', {'extra': [('README', b'x', reg)]}, 'exactly the expected app'),
            ('orphan-appledouble', {'extra': [('__MACOSX/X.app/Contents/._missing', appledouble(), reg)]}, 'Unbound transport member'),
            ('arbitrary-macosx', {'extra': [('__MACOSX/payload.bin', b'x', reg)]}, 'Unbound transport member'),
            ('resource-fork', {'extra': [('__MACOSX/X.app/Contents/Resources/._data.txt', appledouble(rsrc=b'code'), reg)]}, 'only extended attributes'),
            ('quarantine', {'extra': [('__MACOSX/X.app/Contents/Resources/._data.txt', appledouble(attrs=(('com.apple.quarantine', b'0081;'),)), reg)]},
             'Unreviewed AppleDouble transport attributes: com.apple.quarantine'),
            ('finder-info', {'extra': [('__MACOSX/X.app/Contents/Resources/._data.txt', appledouble(finder=b'\x01' + bytes(31)), reg)]}, 'Finder information must be empty'),
            ('orphan-transport-directory', {'extra': [('__MACOSX/X.app/Other/', b'', stat.S_IFDIR | 0o775)]}, 'Unexpected transport directory'),
            ('missing-file', {'skip': ('Contents/Resources/data.txt',)}, 'differs from the expected payload'),
            ('extra-file', {'extra': [('X.app/Contents/Resources/extra.txt', b'x', reg)]}, 'Unexpected archive member'),
            ('extra-directory', {'extra': [('X.app/Contents/Library/', b'', dirmode)]}, 'Unexpected archive directory'),
            ('missing-directories', {'directories': False}, 'directory closure differs'),
            ('permissions', {'modes': {'Contents/Info.plist': 0o755}}, 'Archive permissions differ'),
            ('comment', {'comment': b'hidden'}, 'archive comment'),
        ]
        for name, options, why in cases:
            with self.subTest(name), self.assertRaisesRegex(ValueError, why):
                self.read(make_zip(self.root / (name + '.zip'), self.app, self.tree, **options))
        with self.subTest('duplicate'), self.assertRaisesRegex(ValueError, 'Duplicate'):
            with contextlib.redirect_stderr(io.StringIO()), mock.patch('warnings.warn'):
                self.read(make_zip(self.root / 'dup.zip', self.app, self.tree, extra=[('X.app/Contents/Info.plist', b'other', reg)]))

    def test_byte_accounting_and_bombs(self):
        good = make_zip(self.root / 'good.zip', self.app, self.tree).read_bytes()
        for name, data, why in (('prepended', b'junk' + good, 'end record|central directory|Unaccounted'), ('appended', good + b'junk', 'end record|ZIP')):
            with self.subTest(name), self.assertRaisesRegex(ValueError, why):
                (self.root / (name + '.zip')).write_bytes(data)
                self.read(self.root / (name + '.zip'))
        # A member whose declared size understates its data (a decompression bomb shape).
        archive = zipfile.ZipFile(io.BytesIO(good))
        target = next(i for i in archive.infolist() if i.filename == 'X.app/Contents/Resources/data.txt')
        bomb = bytearray(good)
        struct.pack_into('<I', bomb, target.header_offset + 22, target.file_size - 1)
        offset = good.index(b'PK\x01\x02')
        while True:
            name_length = struct.unpack_from('<H', good, offset + 28)[0]
            if good[offset + 46:offset + 46 + name_length] == target.filename.encode():
                break
            offset = good.index(b'PK\x01\x02', offset + 4)
        struct.pack_into('<I', bomb, offset + 24, target.file_size - 1)
        (self.root / 'bomb.zip').write_bytes(bomb)
        with self.assertRaisesRegex(ValueError, 'Invalid ZIP archive|declared size|shorter'):
            self.read(self.root / 'bomb.zip')
        with mock.patch.object(nm, 'MAX_ARCHIVE_MEMBERS', 3), self.assertRaises(nm.Unverified):
            self.read(self.root / 'good.zip')
        with mock.patch.object(nm, 'MAX_UNCOMPRESSED', 10), self.assertRaises(nm.Unverified):
            self.read(self.root / 'good.zip')

    def test_local_header_semantics(self):
        good = make_zip(self.root / 'headers.zip', self.app, self.tree).read_bytes()
        with zipfile.ZipFile(io.BytesIO(good)) as z:
            target = next(i for i in z.infolist() if i.filename.endswith('Info.plist'))
        for label, offset, fmt, value in [('method', 8, '<H', 0), ('flags', 6, '<H', 1),
                                          ('crc', 14, '<I', 0), ('size', 22, '<I', 999),
                                          ('version', 4, '<H', 45)]:
            with self.subTest(label), self.assertRaisesRegex(ValueError, 'Local ZIP header'):
                data = bytearray(good)
                struct.pack_into(fmt, data, target.header_offset + offset, value)
                path = self.root / (label + '.zip'); path.write_bytes(data); self.read(path)
        for local, data in [(True, b'\x01\x00\x00\x00'), (False, b'\x55\x58\xff\x00')]:
            with self.assertRaisesRegex(ValueError, 'extra fields'):
                nm._zip_extra(data, local)

    def test_exact_deflate_regions(self):
        good = make_zip(self.root / 'streams.zip', self.app, self.tree).read_bytes()
        # Append ignored data to a payload stream and a transport stream, adjusting
        # all affected ZIP lengths/offsets so only exact decompressor consumption fails.
        with zipfile.ZipFile(io.BytesIO(good)) as z:
            infos = z.infolist()
        for target in [next(i for i in infos if i.filename.endswith('Info.plist') and not i.filename.startswith('__MACOSX')),
                       next(i for i in infos if i.filename.endswith('._Info.plist'))]:
            data = bytearray(good); junk = b'UNACCOUNTED-BYTES'
            extra = struct.unpack_from('<H', good, target.header_offset + 28)[0]
            end = target.header_offset + 30 + len(target.filename) + extra + target.compress_size
            data[end:end] = junk
            struct.pack_into('<I', data, target.header_offset + 18, target.compress_size + len(junk))
            cd = struct.unpack_from('<I', good, len(good) - 6)[0]; at = cd + len(junk)
            for entry in infos:
                nl, el, cl = struct.unpack_from('<HHH', data, at + 28)
                if entry.header_offset > target.header_offset:
                    struct.pack_into('<I', data, at + 42, entry.header_offset + len(junk))
                if entry.filename == target.filename:
                    struct.pack_into('<I', data, at + 20, entry.compress_size + len(junk))
                at += 46 + nl + el + cl
            struct.pack_into('<I', data, len(data) - 6, cd + len(junk))
            path = self.root / 'trailing.zip'; path.write_bytes(data)
            with self.subTest(target.filename), self.assertRaisesRegex(ValueError, 'Trailing ZIP compressed bytes'):
                self.read(path)

    def test_appledouble_byte_closure(self):
        data = appledouble()
        variants = [appledouble(attrs=()) + b'UNACCOUNTED-BYTES', data + b'UNACCOUNTED-BYTES']
        # Misplaced entry, nonzero table padding, duplicate name, aliased values,
        # and unclaimed value bytes are invalid even if the outer ZIP binds them.
        moved = bytearray(data); struct.pack_into('>I', moved, 30, 49); variants.append(bytes(moved))
        padded = bytearray(data); padded[151] = 1; variants.append(bytes(padded))
        duplicate = appledouble(attrs=PROVENANCE + PROVENANCE); variants.append(duplicate)
        overlap = bytearray(appledouble(attrs=PROVENANCE + (('other', b'x'),)))
        struct.pack_into('>I', overlap, 152, struct.unpack_from('>I', overlap, 120)[0]); variants.append(bytes(overlap))
        gap = bytearray(data); struct.pack_into('>I', gap, 124, 10); variants.append(bytes(gap))
        for value in variants:
            with self.subTest(value=value.hex()), self.assertRaises(ValueError):
                nm.appledouble_attributes(value)
        path = make_zip(self.root / 'transport-tail.zip', self.app, self.tree, transport=False,
                        extra=[(nm.appledouble('X.app/Contents/Info.plist'), variants[0], stat.S_IFREG | 0o644)])
        with self.assertRaisesRegex(ValueError, 'Unaccounted AppleDouble'):
            self.read(path)

    def test_appledouble_parser(self):
        # One genuine 163-byte member (Contents/._CodeResources) of the real ditto archive.
        real = bytes.fromhex('00051607000200004d6163204f5320582020202020202020000200000009000000320000007100000002000000a3000000000000000000000000000000000000'
                             '00000000000000000000000000000000000000004154545200000000000000a3000000980000000b00000000000000000000000000000001000000980000000b'
                             '000015636f6d2e6170706c652e70726f76656e616e636500010200a390490c9b0c10d0')
        self.assertEqual(nm.appledouble_attributes(real), ['com.apple.provenance'])
        self.assertEqual(appledouble(), real)
        self.assertEqual(nm.appledouble_attributes(appledouble(attrs=())), [])
        for name, data, why in (('short', real[:40], 'Invalid AppleDouble'), ('magic', real[:1] + bytes([real[1] ^ 0xff]) + real[2:], 'Invalid AppleDouble'),
                                ('truncated-attribute', real[:-3], 'Invalid AppleDouble'), ('one-entry', real[:25] + b'\x01' + real[26:], 'Unexpected AppleDouble entries')):
            with self.subTest(name), self.assertRaisesRegex(ValueError, why):
                nm.appledouble_attributes(data)


@unittest.skipUnless(NATIVE and COMPILER, 'needs macOS codesign and clang')
class OuterIdentity(unittest.TestCase):
    """CodeDirectory identities parsed from bytes agree with uncanned codesign."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='omd-notarized-macho-')).resolve()
        source = cls.root / 'main.c'
        source.write_text('int main(void){return 0;}\n')
        cls.binaries = {}
        for arch in ('arm64', 'x86_64'):
            out = cls.root / arch
            subprocess.run([COMPILER, '-arch', arch, '-mmacosx-version-min=13.5', source, '-o', out], check=True, capture_output=True)
            cls.binaries[arch] = out
        cls.binaries['universal'] = cls.root / 'universal'
        subprocess.run(['/usr/bin/lipo', '-create', cls.binaries['arm64'], cls.binaries['x86_64'], '-output', cls.binaries['universal']], check=True)
        # x86_64 output is not linker-signed; sign only this temporary fixture ad-hoc.
        subprocess.run([nm.CODESIGN, '-s', '-', '-f', cls.binaries['x86_64']], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_thin_arm64_identity_matches_codesign(self):
        identity = nm.outer_identity(self.binaries['arm64'].read_bytes())
        shown = subprocess.run([nm.CODESIGN, '-d', '-vvvv', '--arch', 'arm64', self.binaries['arm64']], capture_output=True, text=True)
        record = {'stdout': shown.stdout, 'stderr': shown.stderr}
        display = nm.display_identity(record)
        self.assertEqual((display['code_directory_hash'], display['cdhash']), (identity['code_directory_hash'], identity['cdhash']))

    def test_other_layouts_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'only the arm64 outer architecture'):
            nm.outer_identity(self.binaries['x86_64'].read_bytes())
        with self.assertRaisesRegex(ValueError, 'only a thin 64-bit outer executable'):
            nm.outer_identity(self.binaries['universal'].read_bytes())
        with self.assertRaisesRegex(ValueError, 'exactly one SHA-256 outer CodeDirectory'):
            nm.display_identity({'stdout': '', 'stderr': 'Hash choices=sha1,sha256\nCandidateCDHashFull sha256=' + '0' * 64 + '\nCDHash=' + '0' * 40})


@unittest.skipUnless(NATIVE and COMPILER, 'needs macOS codesign, stapler and clang')
class AppleCheckMechanics(unittest.TestCase):
    """Canned tool results drive apple_checks on a tiny app to show orchestration and race
    detection (never Apple acceptance); uncanned tools then refuse the same fixture."""

    def setUp(self):
        self.root = scratch(self)
        source = self.root / 'main.c'
        source.write_text('int main(void){return 0;}\n')
        exe = self.root / 'exe'
        subprocess.run([COMPILER, '-arch', 'arm64', '-mmacosx-version-min=13.5', source, '-o', exe], check=True, capture_output=True)
        self.app = tiny_tree(self.root / 'src', ticket=b's8ch' + bytes(60), executable=exe.read_bytes())
        import plistlib
        (self.app / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundlePackageType': 'APPL', 'CFBundleExecutable': 'x', 'CFBundleIdentifier': 'labs.example.x',
                                                                     'LSMinimumSystemVersion': '13.5'}))
        self.identity = nm.outer_identity(exe.read_bytes())

    def canned(self, overrides=None, hook=None):
        def fake(argv, timeout, env, limit):
            label = ' '.join(argv[1:3])
            if hook:
                hook(argv)
            result = (overrides or {}).get(Path(argv[0]).name)
            if result is not None:
                return {'argv': argv, 'exit': result, 'stdout': '', 'stderr': 'canned failure', 'seconds': 0}
            stderr = ''
            if argv[0] == nm.CODESIGN and '-d' in argv:
                stderr = (f"Hash choices=sha256\nCandidateCDHash sha256={self.identity['cdhash']}\nCandidateCDHashFull sha256={self.identity['code_directory_hash']}\n"
                          f"CDHash={self.identity['cdhash']}\nTeamIdentifier=ABCDE12345\n")
            return {'argv': argv, 'exit': 0, 'stdout': '', 'stderr': stderr, 'seconds': 0, 'canned': label}
        return mock.patch.object(nm, 'run_bounded', side_effect=fake)

    def checks(self, team='ABCDE12345'):
        run = nm.Run(seconds=60)
        self.addCleanup(run.cleanup)
        return run, (lambda: nm.apple_checks(run, self.app, team, 'fixture', stapled=True))

    def test_canned_orchestration_records_every_command(self):
        run, check = self.checks()
        with self.canned():
            result = check()
        self.assertEqual(result['outer'], self.identity)
        self.assertEqual([Path(r['argv'][0]).name for r in run.records], ['codesign', 'codesign', 'xcrun', 'spctl'])

    def test_canned_failures_timeouts_and_input_replacement(self):
        for tool, value, error in (('xcrun', 65, ValueError), ('spctl', 3, ValueError), ('codesign', 'timeout', nm.Unverified), ('xcrun', 'overflow', nm.Unverified),
                                   ('spctl', 'missing', nm.Unverified)):
            with self.subTest(tool=tool, value=value):
                _, check = self.checks()
                with self.canned({tool: value}), self.assertRaises(error):
                    check()
        replaced = lambda argv: (self.app / 'Contents/Resources/data.txt').write_bytes(b'replaced') if Path(argv[0]).name == 'spctl' else None
        _, check = self.checks()
        with self.canned(hook=replaced), self.assertRaisesRegex(ValueError, 'changed during the Apple checks'):
            check()
        _, check = self.checks(team='ZZZZZ99999')
        with self.canned(), self.assertRaisesRegex(ValueError, 'disagree on the outer CodeDirectory identity'):
            check()

    def test_uncanned_tools_refuse_the_fixture(self):
        _, check = self.checks()
        with self.assertRaisesRegex(ValueError, 'codesign bundle failed'):
            check()
        run = nm.Run(seconds=60)
        self.addCleanup(run.cleanup)
        record = run.tool('stapler', [nm.XCRUN, 'stapler', 'validate', self.app], 'uncanned stapler')
        self.assertNotEqual(record['exit'], 0)


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.root = scratch(self)
        (self.root / 'evidence').mkdir()
        for name in ('binding.json', 'log.json', 'up.zip', 'dist.zip'):
            (self.root / 'evidence' / name).write_bytes(b'{}')

    def argv(self, command, output, *extra):
        e = self.root / 'evidence'
        return [command, '--contract', nm.SCHEMA, '--signed-binding', e / 'binding.json', '--signed-binding-sha256', sha(b'{}'), '--signed-app', self.root / 'S.app',
                '--stapled-app', self.root / 'N.app', '--expected-team-id', 'ABCDE12345', '--expected-target', 'darwin-arm64', '--expected-version', '0.2.0',
                '--expected-purpose', 'distribution-candidate', '--uploaded-archive', e / 'up.zip', '--uploaded-archive-sha256', sha(b'{}'),
                '--notary-log', e / 'log.json', '--notary-log-sha256', sha(b'{}'), '--submission-id', 'fd49acc0-0000-4000-8000-0123456789ab',
                '--distribution-archive', e / 'dist.zip', '--distribution-archive-sha256', sha(b'{}'), '--evidence-root', f'ev={e}',
                '--input-app', self.root / 'I.app', '--plan', self.root / 'plan.json', '--report', self.root / 'report.json', '--output', output, *extra]

    def main(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return CLI.main([str(a) for a in argv])

    @unittest.skipUnless(platform.system() == 'Darwin', 'macOS verifier')
    def test_refused_prepare_writes_only_a_refusal_report(self):
        out = self.root / 'out'
        self.assertEqual(self.main(self.argv('prepare', out)), 1)
        self.assertEqual(sorted(os.listdir(out)), [nm.REPORT_NAME])
        report = json.loads((out / nm.REPORT_NAME).read_text())
        self.assertEqual((report['status'], report['release_accepted']), ('refused', False))
        self.assertIn('signed binding must be omd-final-materials-v1', report['reason'])
        with mock.patch.object(nm, 'derive', side_effect=nm.Unverified('tool missing')):
            self.assertEqual(self.main(self.argv('prepare', self.root / 'out2')), 2)
        self.assertEqual(json.loads((self.root / 'out2' / nm.REPORT_NAME).read_text())['status'], 'unverified')
        self.assertEqual(self.main(self.argv('prepare', self.root / 'evidence/out')), 1)
        self.assertFalse((self.root / 'evidence/out').exists())

    @unittest.skipUnless(platform.system() == 'Darwin', 'macOS verifier')
    def test_verify_checks_the_pinned_envelope_before_any_derivation(self):
        envelope = self.root / 'envelope.json'
        envelope.write_bytes(b'{"schema":"omd-notarized-materials-v1","schema":"x"}')
        with mock.patch.object(nm, 'derive', side_effect=AssertionError('derive must not run')):
            for digest, why in (('0' * 64, 'caller-pinned digest'), (sha(envelope.read_bytes()), 'Duplicate JSON key')):
                out = self.root / f'verify-{why[:3]}.json'
                self.assertEqual(self.main(self.argv('verify', out, '--envelope', envelope, '--envelope-sha256', digest)), 1)
                self.assertIn(why, json.loads(out.read_text())['reason'])

    def test_non_macos_is_unverified(self):
        with mock.patch.object(platform, 'system', return_value='Linux'):
            self.assertEqual(self.main(self.argv('prepare', self.root / 'out')), 2)
            with self.assertRaises(nm.Unverified):
                nm.derive({'contract': nm.SCHEMA})
        self.assertFalse((self.root / 'out').exists())

    def test_contract_is_explicit(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            CLI.parser().parse_args([str(a) for a in self.argv('prepare', self.root / 'o')][:1] + ['--contract', 'omd-notarized-materials-v2'])


def chain():
    return json.loads(Path(CHAIN).read_text())


def chain_argv(command, output, overrides=None, extra=()):
    options = {**chain()['options'], **(overrides or {})}
    argv = [command]
    for flag, value in options.items():
        for item in (value if isinstance(value, list) else [value]):
            argv += [flag, str(item)]
    return argv + ['--output', str(output), *map(str, extra)]


@unittest.skipUnless(NATIVE and CHAIN, 'set OMD_NOTARIZED_MATERIALS_CHAIN to the genuine chain options JSON')
class GenuineChain(unittest.TestCase):
    """Read-only on the genuine chain: full prepare/verify with uncanned Apple tools and refusals.
    Mutations happen only in owned private copies."""

    @classmethod
    def setUpClass(cls):
        cls.chain = chain()
        cls.root = Path(tempfile.mkdtemp(prefix='omd-notarized-genuine-')).resolve()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = CLI.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_genuine_prepare_and_verify(self):
        out = self.root / 'prepared'
        code, text = self.main(chain_argv('prepare', out))
        self.assertEqual(code, 0, text)
        envelope = json.loads((out / nm.NAME).read_text())
        report = json.loads((out / nm.REPORT_NAME).read_text())
        want = self.chain['expect']
        self.assertEqual((len(envelope['signed_payload']['files']), len(envelope['stapled_payload']['files'])), (180, 181))
        self.assertEqual(envelope['ticket'], want['ticket'])
        self.assertEqual(envelope['outer_code']['slices'], [want['outer']])
        self.assertEqual((envelope['signed_binding']['sha256'], envelope['release_accepted'], report['release_accepted']), (want['binding_sha256'], False, False))
        self.assertEqual(report['structure'], STRUCTURE)
        self.assertEqual(report['original_binding_verification']['status'], 'final-materials-validated')
        self.assertNotIn('/Volumes/', (out / nm.NAME).read_text())
        digest = sha((out / nm.NAME).read_bytes())
        code, text = self.main(chain_argv('verify', self.root / 'verified.json', extra=('--envelope', out / nm.NAME, '--envelope-sha256', digest)))
        self.assertEqual(code, 0, text)
        self.assertTrue(json.loads((self.root / 'verified.json').read_text())['rederived_equal'])

    def test_genuine_cheap_refusals(self):
        cases = [({'--expected-team-id': 'ZZZZZ99999'}, 1, 'Team differs'), ({'--expected-purpose': 'private-validation'}, 1, 'never a distribution candidate'),
                 ({'--expected-target': 'darwin-x64'}, 1, 'supports only the darwin-arm64 target'), ({'--signed-binding-sha256': '0' * 64}, 1, 'caller-pinned digest'),
                 ({'--submission-id': '00000000-0000-4000-8000-000000000000'}, 1, 'different submission id'),
                 ({'--uploaded-archive-sha256': '0' * 64}, 1, 'different uploaded archive digest'),
                 ({'--distribution-archive-sha256': '0' * 64}, 1, 'distribution archive differs from the caller-pinned digest'),
                 ({'--max-seconds': '1'}, 2, 'workflow bound expired')]
        for overrides, want, why in cases:
            with self.subTest(why):
                out = self.root / ('refused-' + sha(json.dumps(overrides).encode())[:8])
                code, text = self.main(chain_argv('prepare', out, overrides))
                self.assertEqual(code, want, text)
                self.assertEqual(os.listdir(out), [nm.REPORT_NAME])
                self.assertIn(why, json.loads((out / nm.REPORT_NAME).read_text())['reason'])

    def test_genuine_stale_extractor_handoff_is_refused(self):
        out = self.root / 'stale-handoff'
        code, text = self.main(chain_argv('prepare', out, {'--prepared-extractor': self.chain['stale_prepared_extractor']}))
        self.assertEqual(code, 1, text)
        self.assertIn('differs from the one bound by the signing plan', json.loads((out / nm.REPORT_NAME).read_text())['reason'])

    def test_genuine_archives_bind_exact_trees(self):
        options = self.chain['options']
        signed, stapled = nm.walk_tree(Path(options['--signed-app'])), nm.walk_tree(Path(options['--stapled-app']))
        app = Path(options['--stapled-app']).name
        uploaded = nm.read_archive(Path(options['--uploaded-archive']), signed, app)
        distribution = nm.read_archive(Path(options['--distribution-archive']), stapled, app)
        self.assertEqual((len(uploaded['payload']), len(distribution['payload']), len(uploaded['transport']), len(distribution['transport'])), (180, 181, 228, 229))
        self.assertEqual(distribution['attributes'], ['com.apple.provenance'])
        with self.assertRaisesRegex(ValueError, 'differs from the expected payload'):
            nm.read_archive(Path(options['--uploaded-archive']), stapled, app)
        with self.assertRaisesRegex(ValueError, 'Unexpected archive member|Unbound transport member'):
            nm.read_archive(Path(options['--distribution-archive']), signed, app)

    def test_genuine_apple_controls_on_owned_copies(self):
        options, want = self.chain['options'], self.chain['expect']
        team = options['--expected-team-id']
        run = nm.Run(seconds=nm.WORKFLOW_SECONDS, temp_root=self.root)
        self.addCleanup(run.cleanup)
        signed = nm.walk_tree(Path(options['--signed-app']))
        copy_app = run.temp / 'owned' / Path(options['--stapled-app']).name
        copy_app.parent.mkdir()
        baseline = nm.walk_tree(Path(options['--stapled-app']), copy_to=copy_app)
        result = nm.apple_checks(run, copy_app, team, 'owned stapled copy', stapled=True)
        self.assertEqual(result['outer'], want['outer'])
        ticket = copy_app / nm.TICKET
        original = ticket.read_bytes()
        executable = copy_app / 'Contents/MacOS' / signing.strict_plist(copy_app / 'Contents/Info.plist')['CFBundleExecutable']
        code = executable.read_bytes()
        seal = copy_app / fm.SEAL
        seal_bytes = seal.read_bytes()

        def restore():
            ticket.write_bytes(original)
            executable.write_bytes(code)
            seal.write_bytes(seal_bytes)
            (copy_app / 'Contents/Resources/extra.txt').unlink(missing_ok=True)
            self.assertEqual(nm.walk_tree(copy_app), baseline)
        flipped = bytearray(original)
        flipped[len(flipped) // 2] ^= 0xff
        corrupted = bytearray(code)
        corrupted[0x4000 + 100] ^= 0xff
        changed_seal = bytearray(seal_bytes)
        changed_seal[len(changed_seal) // 2] ^= 0x01
        mutations = [('ticket-byte', lambda: ticket.write_bytes(bytes(flipped)), 'stapler validate failed', None),
                     ('magic-only-ticket', lambda: ticket.write_bytes(original[:4]), 'stapler validate failed', None),
                     ('truncated-ticket', lambda: ticket.write_bytes(original[:len(original) // 2]), 'stapler validate failed', None),
                     ('zero-length-ticket', lambda: ticket.write_bytes(b''), None, 'outside the method bound'),
                     ('code-byte', lambda: executable.write_bytes(bytes(corrupted)), 'codesign bundle failed', 'Stapling changed signed payload files'),
                     ('extra-file', lambda: (copy_app / 'Contents/Resources/extra.txt').write_bytes(b'x'), 'codesign bundle failed', 'Stapling must add exactly'),
                     ('seal-change', lambda: seal.write_bytes(bytes(changed_seal)), 'codesign bundle failed', 'Stapling changed signed payload files')]
        for name, mutate, apple_error, closure_error in mutations:
            with self.subTest(name):
                mutate()
                try:
                    if apple_error:
                        with self.assertRaisesRegex(ValueError, apple_error):
                            nm.apple_checks(run, copy_app, team, name, stapled=True)
                    if closure_error:
                        with self.assertRaisesRegex(ValueError, closure_error):
                            nm.closure(signed, nm.walk_tree(copy_app))
                finally:
                    restore()
        with self.subTest('wrong-team'), self.assertRaisesRegex(ValueError, 'codesign bundle failed'):
            nm.apple_checks(run, copy_app, 'ZZZZZ99999', 'wrong team', stapled=True)
        with self.subTest('replaced-during-check'):
            real = nm.run_bounded

            def replace(argv, timeout, env, limit):
                record = real(argv, timeout, env, limit)
                if Path(argv[0]).name == 'spctl':
                    (copy_app / 'Contents/Resources/extra.txt').write_bytes(b'x')
                return record
            try:
                with mock.patch.object(nm, 'run_bounded', side_effect=replace), self.assertRaisesRegex(ValueError, 'changed during the Apple checks'):
                    nm.apple_checks(run, copy_app, team, 'replacement', stapled=True)
            finally:
                restore()
        for name, patches, why in (('timeout', {'timeouts': {'codesign': 0.001}}, 'timeout'), ('missing-tool', {'CODESIGN': '/nonexistent/codesign'}, 'missing'),
                                   ('output-overflow', {'OUTPUT_LIMIT': 16}, 'overflow')):
            with self.subTest(name):
                bounded = nm.Run(seconds=60, temp_root=self.root, **({'timeouts': patches['timeouts']} if 'timeouts' in patches else {}))
                self.addCleanup(bounded.cleanup)
                module = {k: v for k, v in patches.items() if k != 'timeouts'}
                with mock.patch.multiple(nm, **module) if module else contextlib.nullcontext(), self.assertRaisesRegex(nm.Unverified, why):
                    nm.apple_checks(bounded, copy_app, team, name, stapled=True)
        self.assertEqual(nm.walk_tree(Path(options['--stapled-app'])), baseline)

    def test_genuine_log_is_consistency_only(self):
        options, want = self.chain['options'], self.chain['expect']
        log = nm.load_strict(Path(options['--notary-log']).read_bytes())
        app = Path(options['--stapled-app']).name
        archive = Path(options['--uploaded-archive']).name
        outer_path = 'Contents/MacOS/' + want['executable']
        record = nm.log_consistency(log, options['--submission-id'], options['--uploaded-archive-sha256'], archive, app, outer_path, want['outer'])
        self.assertIn('not cryptographically authenticated', record['scope'])
        fake = {**want['outer'], 'cdhash': '0' * 40}
        with self.assertRaisesRegex(ValueError, 'does not name the verified outer arm64 CDHash'):
            nm.log_consistency(log, options['--submission-id'], options['--uploaded-archive-sha256'], archive, app, outer_path, fake)
        for change, why in (({'status': 'Invalid'}, 'accepted submission'), ({'statusCode': True}, 'accepted submission'), ({'jobId': '0' * 8}, 'different submission id'),
                            ({'sha256': '0' * 64}, 'different uploaded archive digest')):
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                nm.log_consistency({**log, **change}, options['--submission-id'], options['--uploaded-archive-sha256'], archive, app, outer_path, want['outer'])


if __name__ == '__main__':
    unittest.main()
