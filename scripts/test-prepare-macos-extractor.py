# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Extractor preparation tests. Fixture producers are genuine PyInstaller 6.22.0 onefile
assemblies (stock run bootloader, pinned CArchive/PYZ writers and macOS EXE steps) of
tiny compiled libraries. Only new temporary copies are signed, ad-hoc. No identity,
keychain, network, GUI or real producer is used, and no fixture is executed."""
import hashlib
import importlib.util
import json
import platform
import py_compile
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import macos_extractor as ex
import macos_signing as signing

NATIVE = platform.system() == 'Darwin' and shutil.which('xcrun') is not None and Path('/usr/bin/codesign').exists()
VERSION = '2026.08.19'
DEVID = 'Developer ID Application: Fixture Labs (ABCDE12345)'
TEAM = 'ABCDE12345'
SCRIPTS = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(*argv):
    subprocess.run([str(x) for x in argv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scratch(test):
    folder = Path(tempfile.mkdtemp(prefix='omd-extractor-test-')).resolve()
    test.addCleanup(shutil.rmtree, folder, True)
    return folder


def flip_code(data):
    """Corrupt one __TEXT,__text byte in every slice; signature metadata is untouched."""
    out = bytearray(data)
    for off, length in signing.slice_regions(data):
        image = data[off:off + length]
        endian, _, _, _, commands = signing.load_commands(image)
        seg = next(at for cmd, at, _ in commands if cmd == 0x19 and image[at + 8:at + 24].rstrip(b'\0') == b'__TEXT')
        for i in range(struct.unpack_from(endian + 'I', image, seg + 64)[0]):
            section = seg + 72 + 80 * i
            if image[section:section + 16].rstrip(b'\0') == b'__text':
                out[off + struct.unpack_from(endian + 'I', image, section + 48)[0]] ^= 0xff
    assert bytes(out) != data
    return bytes(out)


class Fixture:
    """Compiled once: FAT and thin libraries/bundles, an executable, an unsigned dylib."""
    root = None

    @classmethod
    def get(cls):
        if cls.root is None:
            root = Path(tempfile.mkdtemp(prefix='omd-extractor-native-')).resolve()
            (root / 'lib.c').write_text('int fixture_value(void) { return 7; }\n')
            (root / 'ext.c').write_text('int fixture_ext(void) { return 3; }\n')
            (root / 'main.c').write_text('int main(void) { return 0; }\n')
            cc = ['xcrun', 'clang', '-O0', '-mmacosx-version-min=13.0']
            fat = ['-arch', 'x86_64', '-arch', 'arm64']
            for suffix, arches in (('', fat), ('-thin', ['-arch', 'arm64'])):
                run(*cc, *arches, '-dynamiclib', '-install_name', '@rpath/Python', '-o', root / f'Python{suffix}', root / 'lib.c')
                run(*cc, *arches, '-bundle', '-o', root / f'ext{suffix}.so', root / 'ext.c')
                for name in (f'Python{suffix}', f'ext{suffix}.so'):
                    # 4 KiB code pages, like the real producer: an ad-hoc re-sign here
                    # (16 KiB pages) then really changes the signature bytes.
                    run('/usr/bin/codesign', '--force', '--sign', '-', '--pagesize', '4096', '--timestamp=none', root / name)
            run(*cc, *fat, '-o', root / 'exe', root / 'main.c')
            run('/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', root / 'exe')
            run(*cc, '-arch', 'arm64', '-dynamiclib', '-Wl,-no_adhoc_codesign', '-o', root / 'unsigned.dylib', root / 'lib.c')
            run(*cc, *fat, '-o', root / 'custom-boot', root / 'main.c')
            (root / 'boot.py').write_text('import sys\n')
            (root / 'struct.py').write_text('from _struct import *\n')
            py_compile.compile(str(root / 'struct.py'), cfile=str(root / 'struct.pyc'))
            (root / 'data.txt').write_bytes(b'fixture data\n')
            (root / 'core.min.js').write_bytes(b'export const solver = 1;\n')
            cls.root = root
        return cls.root


def src(root, name='src'):
    """A producer in its own directory: outputs may never be written beside a producer."""
    folder = root / name
    folder.mkdir()
    return folder / 'yt-dlp_macos'


def stock_path():
    import PyInstaller
    return Path(PyInstaller.__file__).resolve().parent / ex.STOCK_BOOTLOADER['path']


def producer(out, target='universal2', *, python=None, extension=None, extra=(), version=VERSION, modules=None, level=9,
             bootloader=None, trailer=b'', pkg=None, data=None):
    """PyInstaller 6.22.0 EXE.assemble for a onefile, built with PyInstaller's own functions."""
    from PyInstaller.archive.writers import CArchiveWriter, ZlibArchiveWriter
    from PyInstaller.utils import osx as osxutils
    f = Fixture.get()
    thin = target != 'universal2'
    work = Path(tempfile.mkdtemp(prefix='fixture-', dir=out.parent))
    mods = modules if modules is not None else {'yt_dlp.version': f"__version__ = '{version}'\nRELEASE_GIT_HEAD = 'fixture'\n_pkg_version = '{version}'\n"}
    ZlibArchiveWriter(str(work / 'PYZ.pyz'), [(n, str(work / (n + '.py')), 'PYMODULE') for n in mods],
                      code_dict={n: compile(s, n + '.py', 'exec') for n, s in mods.items()})
    data_file = f / 'data.txt'
    if data is not None:
        data_file = work / 'data.txt'
        data_file.write_bytes(data)
    entries = [('struct', str(f / 'struct.pyc'), True, 'm'), ('pyiboot01_bootstrap', str(f / 'boot.py'), True, 's'),
               ('Python.framework/Versions/3.14/Python', str(python or f / ('Python-thin' if thin else 'Python')), True, 'b'),
               ('_fixture.cpython-314-darwin.so', str(extension or f / ('ext-thin.so' if thin else 'ext.so')), True, 'b'),
               ('Python', 'Python.framework/Versions/3.14/Python', False, 'n'),
               ('fixture/data.txt', str(data_file), True, 'x'), ('yt_dlp_ejs/yt/solver/core.min.js', str(f / 'core.min.js'), True, 'x'),
               ('pyi-contents-directory _internal', '', False, 'o'), *extra]
    if modules != {}:
        entries.append(('PYZ.pyz', str(work / 'PYZ.pyz'), False, 'z'))
    with mock.patch.object(CArchiveWriter, '_COMPRESSION_LEVEL', level):
        CArchiveWriter(str(work / 'pkg'), entries, 'Python')
    if pkg is not None:
        (work / 'pkg').write_bytes(pkg((work / 'pkg').read_bytes()))
    shutil.copyfile(bootloader or stock_path(), out)
    out.chmod(0o755)
    osxutils.binary_to_target_arch(str(out), target)
    osxutils.remove_signature_from_binary(str(out))
    osxutils.update_exe_identifier(str(out), str(work / 'pkg'))
    with open(out, 'ab') as stream:
        stream.write((work / 'pkg').read_bytes() + trailer)
    osxutils.fix_exe_for_code_signing(str(out))
    pylib = osxutils.get_macos_sdk_version(str(python or f / ('Python-thin' if thin else 'Python')))
    if pylib < osxutils.get_macos_sdk_version(str(out)):
        osxutils.set_macos_sdk_version(str(out), *pylib)
    run('/usr/bin/codesign', '-s', '-', '--force', '--all-architectures', '--timestamp=none', out)
    shutil.rmtree(work)
    return out


def toc_rows(pkg):
    _, _, toc_offset, toc_length, pyvers, pylib = struct.unpack(ex.COOKIE, pkg[-ex.COOKIE_BYTES:])
    toc, rows, pos = pkg[toc_offset:toc_offset + toc_length], [], 0
    while pos < len(toc):
        size, offset, stored, expanded, flag, code = struct.unpack_from('!IIIIBc', toc, pos)
        rows.append((offset, stored, expanded, flag, code.decode(), toc[pos + 18:pos + size].rstrip(b'\0').decode()))
        pos += size
    return rows, toc_offset, pyvers, pylib


def with_gap(pkg):
    """One zero byte between the first two entries, all later offsets shifted: a valid
    reader layout that the pinned writer never produces."""
    rows, toc_offset, pyvers, pylib = toc_rows(pkg)
    end = rows[0][0] + rows[0][1]
    shifted = [(o + (i > 0), s, e, f, c, n) for i, (o, s, e, f, c, n) in enumerate(rows)]
    body = pkg[:end] + b'\0' + pkg[end:toc_offset]
    toc = ex.serialize_toc(shifted)
    return body + toc + struct.pack(ex.COOKIE, ex.MAGIC, len(body) + len(toc) + ex.COOKIE_BYTES, len(body), len(toc), pyvers, pylib)


def with_toc_overrun(pkg):
    _, length, toc_offset, toc_length, pyvers, pylib = struct.unpack(ex.COOKIE, pkg[-ex.COOKIE_BYTES:])
    return pkg[:-ex.COOKIE_BYTES] + struct.pack(ex.COOKIE, ex.MAGIC, length, toc_offset, toc_length + 4096, pyvers, pylib)


def request(path, **change):
    data = Path(path).read_bytes()
    return {'producer': str(path), 'producer_sha256': digest(data), 'version': VERSION, 'target_arch': 'universal2',
            'mode': 'development-adhoc', 'identity': '-', 'team_id': None, **change}


def write_plan(folder, plan, name='plan.json'):
    path = folder / name
    signing.write_new(path, signing.json_bytes(plan))
    return path


def prepare(test, root, source, target='universal2', name='prepared', runner_factory=signing.Runner, **change):
    plan = ex.inspect(request(source, target_arch=target, **change), temp_root=root)
    plan_path = write_plan(root, plan, f'{name}-plan.json')
    out = root / f'{name}-out'
    out.mkdir()
    status, report_path = ex.execute(plan_path, out / 'yt-dlp_macos', root / f'{name}-work', runner_factory=runner_factory)
    return plan, status, json.loads(report_path.read_text()), out / 'yt-dlp_macos'


def stored_entries(path):
    archive, entries = signing.archive_entries(Path(path))
    data = Path(path).read_bytes()
    return [(n, e[4], e[3], data[archive._start_offset + e[0]:archive._start_offset + e[0] + e[1]]) for n, e in entries], data[archive._start_offset:archive._end_offset]


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class Transformation(unittest.TestCase):
    def test_universal2_signature_only_transformation(self):
        root = scratch(self)
        source = producer(src(root))
        before = source.read_bytes()
        plan, status, report, out = prepare(self, root, source)
        self.assertTrue(plan['ready_for_execution'], plan['blockers'])
        self.assertEqual((plan['producer']['archive']['native_members'], plan['producer']['archive']['links_validated'], plan['producer']['embedded_versions']), (2, 1, [VERSION]))
        self.assertEqual(status, 'prepared-development-candidate', report['failure'])
        self.assertEqual(report['steps'], ['plan-rederived', 'producer-reproduced', 'members-signed', 'outer-assembled', 'candidate-verified'])
        self.assertTrue(report['reproduction']['equal_to_producer'])
        self.assertEqual((report['signature_kind'], report['developer_id_ready'], report['release_accepted']), ('ad-hoc', False, False))
        self.assertEqual(source.read_bytes(), before)
        candidate = out.read_bytes()
        self.assertEqual(report['output'], {'path': str(out), 'bytes': len(candidate), 'sha256': digest(candidate), 'mode': '0755', 'identical_to_producer': False})
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o755)
        proof = report['verification']['structural_equivalence']
        self.assertEqual((proof['signature_only_natives'], proof['identical_non_natives']), (2, 7))
        crypto = report['verification']['cryptographic']
        self.assertEqual((crypto['members']['native_members'], crypto['members']['verified'], crypto['members']['failed'], crypto['outer']['exit']), (2, 2, 0, 0))
        # Independent of the module: every non-native stored stream is byte-identical,
        # natives differ but have equal signature-independent digests, order is kept.
        old, _ = stored_entries(source)
        new, new_pkg = stored_entries(out)
        self.assertEqual([(n, c, f) for n, c, f, _ in old], [(n, c, f) for n, c, f, _ in new])
        for (name, code, flag, a), (_, _, _, b) in zip(old, new):
            if code == 'b':
                self.assertNotEqual(a, b, name)
                pa, pb = (zlib.decompress(x) if flag else x for x in (a, b))
                self.assertEqual(signing.signature_independent_sha256(pa), signing.signature_independent_sha256(pb), name)
            else:
                self.assertEqual(a, b, name)
        for row in report['members']:
            self.assertTrue(row['signature_only_change'])
            self.assertNotEqual(row['before']['sha256'], row['after']['sha256'])
            signed = (root / 'prepared-work/members' / f"{row['index']:05d}").read_bytes()
            self.assertEqual(digest(signed), row['after']['sha256'])
            self.assertEqual(signing.signature_independent_sha256(signed), row['signature_independent_sha256'])
            self.assertEqual({s['identifier'] for s in signing.signature(signed)}, {row['identifier']})
        # PyInstaller's UUID rule, recomputed here from the stock bootloader.
        stock = stock_path().read_bytes()
        for (so, sn), (co, cn) in zip(signing.slice_regions(stock), signing.slice_regions(candidate)):
            self.assertEqual(ex.uuid_of(candidate[co:co + cn]), hashlib.sha1(new_pkg + ex.uuid_of(stock[so:so + sn])).digest()[:16])
        self.assertNotEqual(report['outer']['before']['uuids'], report['outer']['after']['uuids'])
        subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', out], check=True, capture_output=True)
        for image in signing.signature(candidate):
            self.assertEqual((image['adhoc'], image['team'], image['runtime'], image['entitlements']), (True, None, False, None))
        result = ex.verify_pair({'path': str(source), 'sha256': digest(before)}, {'path': str(out), 'sha256': digest(candidate)}, VERSION, 'universal2', 'development-adhoc', None, root)
        self.assertTrue(result['pass'])
        self.assertEqual(result['structural_equivalence']['slices'][0]['compared_bytes'] > 0, True)

    def test_thin_arm64_and_sdk_rewrite(self):
        root = scratch(self)
        source = producer(src(root), 'arm64')
        plan, status, report, out = prepare(self, root, source, 'arm64')
        self.assertEqual(status, 'prepared-development-candidate', report['failure'])
        self.assertEqual(report['outer']['after']['signature_layout']['container']['format'], 'thin')
        self.assertFalse(plan['producer']['sdk']['rewrite'])
        # A Python library built against an older SDK makes PyInstaller rewrite the bootloader SDK.
        from PyInstaller.utils import osx as osxutils
        old = root / 'Python-old-sdk'
        shutil.copyfile(Fixture.get() / 'Python', old)
        osxutils.set_macos_sdk_version(str(old), 13, 1, 0)
        run('/usr/bin/codesign', '--force', '--sign', '-', '--pagesize', '4096', '--timestamp=none', old)
        (root / 'sdk').mkdir()
        source = producer(root / 'sdk/yt-dlp_macos', python=old)
        plan, status, report, out = prepare(self, root, source, name='sdk')
        self.assertEqual(plan['producer']['sdk']['python_library'], [13, 1, 0])
        self.assertTrue(plan['producer']['sdk']['rewrite'])
        self.assertEqual(status, 'prepared-development-candidate', report['failure'])
        self.assertEqual(osxutils.get_macos_sdk_version(str(out)), (13, 1, 0))


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class Contract(unittest.TestCase):
    def test_request_identity_version_and_architecture_contract(self):
        root = scratch(self)
        source = producer(src(root))
        thin = producer(root / 'yt-dlp_thin', 'arm64')
        link = root / 'linked'
        link.symlink_to(source)
        cases = [({'producer_sha256': '0' * 64}, 'differs from the requested digest'), ({'producer_sha256': 'ABC'}, '64 lowercase'),
                 ({'version': '2026.09.01'}, r"Embedded yt-dlp version constants \['2026.08.19'\] differ"), ({'version': 'latest'}, 'Invalid yt-dlp version'),
                 ({'target_arch': 'arm64'}, 'differ from target arm64'), ({'target_arch': 'x86_64'}, 'differ from target x86_64'), ({'target_arch': 'arm64e'}, 'target_arch must'),
                 ({'mode': 'developer-id'}, 'ad-hoc identity'), ({'team_id': TEAM}, 'no Team ID'),
                 ({'mode': 'developer-id', 'identity': f'Apple Development: Fixture ({TEAM})', 'team_id': TEAM}, 'Only a Developer ID Application'),
                 ({'mode': 'developer-id', 'identity': DEVID, 'team_id': 'ZZZZZ99999'}, 'differs from --team-id'),
                 ({'producer': 'relative/yt-dlp_macos'}, 'absolute path'), ({'producer': str(link)}, '(?i)symlink')]
        for change, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.inspect({**request(source), **change}, temp_root=root)
        with self.assertRaisesRegex(ValueError, 'differ from target universal2'):
            ex.inspect(request(thin), temp_root=root)
        with self.assertRaisesRegex(ValueError, 'Request needs'):
            ex.inspect({k: v for k, v in request(source).items() if k != 'team_id'}, temp_root=root)
        plan = ex.inspect(request(source, mode='developer-id', identity=DEVID, team_id=TEAM), temp_root=root)
        self.assertEqual(plan['signing']['member_argv'][:6], ['/usr/bin/codesign', '--force', '--sign', DEVID, '--timestamp', '--identifier'])
        self.assertEqual(plan['signing']['outer_argv'], ['/usr/bin/codesign', '-s', DEVID, '--force', '--all-architectures', '--timestamp', '--options=runtime', '<extractor>'])
        self.assertEqual((plan['signature_kind'], plan['developer_id_ready'], plan['release_accepted']), ('developer-id', False, False))

    def test_layout_archive_and_member_rejections(self):
        root = scratch(self)
        f = Fixture.get()
        good = producer(src(root))
        data = good.read_bytes()
        cases = []

        def variant(name, why, **options):
            folder = root / name
            folder.mkdir()
            cases.append((producer(folder / 'yt-dlp_macos', **options), why))

        def raw(name, content, why):
            folder = root / name
            folder.mkdir()
            (folder / 'yt-dlp_macos').write_bytes(content)
            cases.append((folder / 'yt-dlp_macos', why))
        raw('trailing', data + b'\0', 'Bytes after the last FAT slice')
        overlap = bytearray(data)
        struct.pack_into('>I', overlap, 8 + 20 + 8, struct.unpack_from('>I', data, 8 + 8)[0])
        raw('overlap', bytes(overlap), 'overlapping fat slice')
        variant('gap', 'not contiguous', pkg=with_gap)
        variant('toc-overrun', 'TOC exceeds its archive', pkg=with_toc_overrun)
        variant('after-cookie', 'string table must end exactly at the PKG', trailer=b'\0' * 32)
        variant('custom-bootloader', "LC_UUID is not PyInstaller's PKG-derived UUID", bootloader=f / 'custom-boot')
        variant('duplicate', 'Duplicate CArchive member names', extra=[('fixture/data.txt', str(f / 'data.txt'), True, 'x')])
        variant('colliding', 'case/normalization-colliding', extra=[('FIXTURE/DATA.txt', str(f / 'data.txt'), True, 'x')])
        variant('escape', 'unsafe relative path', extra=[('escape', '../outside.dylib', False, 'n')])
        variant('dangling', 'does not resolve', extra=[('dangling', 'missing.dylib', False, 'n')])
        variant('dependency', "Unsupported CArchive entry type 'd'", extra=[('dep.dylib', 'other', False, 'd')])
        variant('macho-data', 'Mach-O content must be exactly the binary', extra=[('lib/extra.dylib', str(f / 'Python'), True, 'x')])
        variant('data-binary', 'unrecognized packed binary|Mach-O content must be exactly', extra=[('lib/notcode.so', str(f / 'data.txt'), True, 'b')])
        variant('executable-member', 'must be a dylib or bundle', extra=[('helper', str(f / 'exe'), True, 'b')])
        variant('missing-arch', r"architectures \['arm64'\] do not cover target universal2", extension=f / 'ext-thin.so')
        variant('no-pyz', 'exactly one PYZ', modules={})
        variant('no-version', 'exactly one yt_dlp.version', modules={'yt_dlp.other': 'x = 1\n'})
        for path, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.inspect(request(path), temp_root=root)
        (root / 'unsigned').mkdir()
        unsigned = producer(root / 'unsigned/yt-dlp_macos', 'arm64', python=f / 'unsigned.dylib')
        with self.assertRaisesRegex(ValueError, 'unsigned packed slice'):
            ex.inspect(request(unsigned, target_arch='arm64'), temp_root=root)
        with mock.patch.object(signing, 'MAX_MATERIALIZED_BYTES', 1024), self.assertRaisesRegex(ValueError, 'materialization budget'):
            ex.inspect(request(good), temp_root=root)
        from PyInstaller.archive.writers import CArchiveWriter
        with mock.patch.object(CArchiveWriter, '_COMPRESSION_LEVEL', 6), self.assertRaisesRegex(ValueError, 'overrides the pinned CArchive compression level'):
            ex.inspect(request(good), temp_root=root)
        with mock.patch.dict(ex.STOCK_BOOTLOADER, sha256='0' * 64), self.assertRaisesRegex(ValueError, 'differs from the pinned 6.22.0'):
            ex.inspect(request(good), temp_root=root)
        # A producer whose streams the pinned writer would not produce gets a blocker.
        (root / 'level6').mkdir()
        level6 = producer(root / 'level6/yt-dlp_macos', level=6)
        plan, status, report, out = prepare(self, root, level6, name='level6')
        self.assertEqual({b['id'] for b in plan['blockers']}, {'compression-rule'})
        self.assertFalse(plan['ready_for_execution'])
        self.assertEqual(status, 'failed')
        self.assertIn('The plan has blockers', report['failure'])
        self.assertFalse(out.exists())

    def test_corrupted_producer_member_blocks(self):
        root = scratch(self)
        bad = root / 'Python-corrupt'
        bad.write_bytes(flip_code((Fixture.get() / 'Python').read_bytes()))
        self.assertEqual(signing.producer_summary(signing.signature(bad.read_bytes())), signing.producer_summary(signing.signature((Fixture.get() / 'Python').read_bytes())))
        source = producer(src(root), python=bad)
        plan, status, report, out = prepare(self, root, source)
        self.assertEqual([(b['id'], b['member']) for b in plan['blockers']], [('producer-member-signature', 'Python.framework/Versions/3.14/Python')])
        self.assertEqual(status, 'failed')
        self.assertFalse(out.exists())
        self.assertEqual(report['members'], [])


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class Tampering(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix='omd-extractor-tamper-')).resolve()
        cls.source = producer(src(cls.root))
        _, status, cls.report, cls.prepared = prepare(None, cls.root, cls.source)
        assert status == 'prepared-development-candidate', cls.report['failure']

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def spec(self, path):
        return {'path': str(path), 'sha256': digest(Path(path).read_bytes())}

    def verify(self, candidate, mode='development-adhoc', team=None):
        return ex.verify_pair(self.spec(self.source), self.spec(candidate), VERSION, 'universal2', mode, team, self.root)

    def rebuild(self, name, replacements):
        """A candidate assembled by the module's pinned steps from the producer PKG with replacements."""
        folder = self.root / name
        folder.mkdir()
        data = self.source.read_bytes()
        _, stock_bytes = ex.pinned()
        analysis = ex.analyse(self.source, data, 'universal2', ex.stock_slices(stock_bytes, 'universal2'))
        (folder / 'pkg').write_bytes(ex.build_pkg(data, analysis, self.source, replacements))
        return ex.assemble(signing.Runner(folder), stock_bytes, folder / 'pkg', 'universal2', folder / 'out', 'yt-dlp_macos', 'development-adhoc', '-', analysis['sdk'])

    def signed(self):
        return {row['index']: (self.root / 'prepared-work/members' / f"{row['index']:05d}").read_bytes() for row in self.report['members']}

    def resign(self, path):
        run('/usr/bin/codesign', '-s', '-', '--force', '--all-architectures', '--timestamp=none', path)
        return path

    def test_candidate_tampering_is_detected(self):
        self.assertTrue(self.verify(self.prepared)['pass'])
        members = {m['name']: m['index'] for m in ex.inspect(request(self.source), temp_root=self.root)['members']}
        signed = self.signed()
        python = members['Python.framework/Versions/3.14/Python']
        cases = [('altered-data', {**signed, members['fixture/data.txt']: b'other fixture data\n'}, 'fixture/data.txt: non-native member bytes differ'),
                 ('altered-script-entry', {**signed, members['yt_dlp_ejs/yt/solver/core.min.js']: b'export const solver = 2;\n'}, 'non-native member bytes differ'),
                 ('corrupted-native', {**signed, python: flip_code(signed[python])}, 'bytes other than the signature changed')]
        renamed = self.root / 'renamed.dylib'
        renamed.write_bytes(signed[python])
        run('/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier', 'other.identifier', renamed)
        cases.append(('identifier', {**signed, python: renamed.read_bytes()}, 'signing identifier changed'))
        for name, replacements, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                self.verify(self.rebuild(name, replacements))
        corrupted = self.rebuild('corrupted-crypto', {**signed, python: flip_code(signed[python])})
        with mock.patch.object(ex, 'compare', return_value={}):
            result = self.verify(corrupted)
        self.assertFalse(result['pass'])
        self.assertEqual(result['cryptographic']['members']['failed'], 1)
        # Outer bootloader code and UUIDs.
        data = self.prepared.read_bytes()
        # A different FAT container is not a permitted archive/signature field,
        # even when all slice bytes and offsets remain unchanged.
        layout = signing.macho_layout(data)[0]
        arches = layout['container']['arches']
        fat64 = bytearray(data)
        struct.pack_into('>II', fat64, 0, 0xcafebabf, len(arches))
        for i, arch in enumerate(arches):
            struct.pack_into('>IIQQII', fat64, 8 + i * 32, arch['cpu'], arch['subtype'],
                             arch['offset'], arch['bytes'], arch['align'], 0x12345678)
        changed_container = self.root / 'changed-container'
        changed_container.write_bytes(fat64)
        with self.assertRaisesRegex(ValueError, 'container format differs'):
            self.verify(changed_container)
        (off, length) = signing.slice_regions(data)[0]
        code = bytearray(data)
        code[off:off + length] = flip_code(data[off:off + length])
        (self.root / 'bootloader').mkdir()
        tampered = self.root / 'bootloader/yt-dlp_macos'
        tampered.write_bytes(bytes(code))
        with self.assertRaisesRegex(ValueError, 'x86_64 bootloader bytes differ'):
            self.verify(self.resign(tampered))
        off, length = signing.slice_regions(data)[1]
        _, _, _, _, commands = signing.load_commands(data[off:off + length])
        at = off + next(a for c, a, _ in commands if c == ex.LC_UUID)
        uuid = bytearray(data)
        uuid[at + 8] ^= 0x01
        (self.root / 'uuid').mkdir()
        (self.root / 'uuid/yt-dlp_macos').write_bytes(bytes(uuid))
        with self.assertRaisesRegex(ValueError, "arm64 LC_UUID is not PyInstaller's"):
            self.verify(self.resign(self.root / 'uuid/yt-dlp_macos'))
        (self.root / 'other').mkdir()
        other = producer(self.root / 'other/yt-dlp_macos', extra=[('extra.txt', str(Fixture.get() / 'data.txt'), True, 'x')])
        with self.assertRaisesRegex(ValueError, 'Entry count differs'):
            self.verify(other)
        with self.assertRaisesRegex(ValueError, 'producer itself'):
            self.verify(self.source)
        with self.assertRaisesRegex(ValueError, 'prepared digest differs'):
            ex.verify_pair(self.spec(self.source), {**self.spec(self.prepared), 'sha256': '0' * 64}, VERSION, 'universal2', 'development-adhoc', None, self.root)
        # Genuine Developer ID requirement: an ad-hoc candidate is never Team-ready.
        devid = self.verify(self.prepared, 'developer-id', TEAM)
        self.assertFalse(devid['pass'])
        self.assertEqual((devid['cryptographic']['members']['failed'], devid['cryptographic']['members']['verified']), (2, 0))
        self.assertNotEqual(devid['cryptographic']['outer']['exit'], 0)

    def test_stale_plan_producer_and_output_rules(self):
        root = self.root / 'stale'
        root.mkdir()
        source = root / 'producer/yt-dlp_macos'
        source.parent.mkdir()
        shutil.copyfile(self.source, source)
        plan = ex.inspect(request(source), temp_root=root)
        plan_path = write_plan(root, plan)
        edited = json.loads(plan_path.read_text())
        edited['members'][0]['stored']['sha256'] = '0' * 64
        status, report_path = ex.execute(write_plan(root, edited, 'edited.json'), root / 'edited-out', root / 'edited-work')
        self.assertEqual(status, 'failed')
        self.assertIn('changed since the plan', json.loads(report_path.read_text())['failure'])
        self.assertFalse((root / 'edited-out').exists())
        with mock.patch.object(ex, 'tool_identity', return_value={'macos_extractor.py': {'bytes': 0, 'sha256': '0' * 64}}):
            status, report_path = ex.execute(plan_path, root / 'tool-out', root / 'tool-work')
        self.assertEqual(status, 'failed')
        self.assertIn('tool', json.loads(report_path.read_text())['failure'])
        self.assertEqual(sorted(plan['tool']), ['check-macos-payload.py', 'macos_extractor.py', 'macos_signing.py'])
        refusals = [(root / 'producer/out', root / 'w1', 'independent of the producer directory'),
                    (root / 'o2', root / 'producer/work', 'independent of the producer directory'),
                    (plan_path, root / 'w3', 'already exists'), (root / 'w4/out', root / 'w4', 'directory does not exist'),
                    (root / 'o5', root, 'Work directory must be new')]
        for output, work, why in refusals:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                ex.execute(plan_path, output, work)
        (root / 'w6').mkdir()
        with self.assertRaisesRegex(ValueError, 'Work directory must be new'):
            ex.execute(plan_path, root / 'w6/out', root / 'w6')
        with self.assertRaisesRegex(ValueError, 'Not an extractor preparation plan'):
            ex.execute(write_plan(root, {**plan, 'schema': 'other'}, 'schema.json'), root / 'o7', root / 'w7')
        shutil.copyfile(self.prepared, source)  # producer replaced after inspection
        status, report_path = ex.execute(plan_path, root / 'o8', root / 'w8')
        self.assertEqual(status, 'failed')
        self.assertIn('Producer digest differs', json.loads(report_path.read_text())['failure'])
        self.assertFalse((root / 'o8').exists())

    def test_partial_failure_is_preserved_without_output(self):
        root = self.root / 'partial'
        root.mkdir()

        class FailSecondMember(signing.Runner):
            def __call__(self, argv, label, timeout=600, check=True):
                if label.startswith('sign:member:') and sum(r['label'].startswith('sign:member:') for r in self.records) == 1:
                    argv = ['/usr/bin/false']
                return super().__call__(argv, label, timeout, check)
        _, status, report, out = prepare(self, root, self.source, runner_factory=FailSecondMember)
        self.assertEqual(status, 'failed')
        self.assertIn('exited 1', report['failure'])
        self.assertFalse(out.exists())
        self.assertEqual(len(report['members']), 1)
        self.assertEqual(report['steps'], ['plan-rederived', 'producer-reproduced'])
        self.assertTrue(any(r['label'].startswith('sign:member:') and r['exit'] == 1 for r in report['commands']))
        self.assertEqual(sorted(p.name for p in (root / 'prepared-work/members').iterdir()), ['00002', '00003'])

    def test_developer_id_commands_and_genuine_refusal_canned(self):
        """The identity is never used: sign commands are recorded, then performed ad-hoc,
        and the genuine Developer ID checks refuse the result."""
        root = self.root / 'devid'
        root.mkdir()
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
        plan, status, report, out = prepare(self, root, self.source, runner_factory=Substitute, mode='developer-id', identity=DEVID, team_id=TEAM)
        self.assertEqual(status, 'failed')
        self.assertIn('signature mode/team mismatch', report['failure'])
        self.assertFalse(out.exists())
        self.assertEqual(report['members'], [])
        self.assertTrue(report['reproduction']['equal_to_producer'])
        first = next(m for m in plan['members'] if 'native' in m)
        self.assertEqual(requested, [['/usr/bin/codesign', '--force', '--sign', DEVID, '--timestamp', '--identifier', first['native']['identifier'],
                                      str(root / 'prepared-work/members' / f"{first['index']:05d}")]])


@unittest.skipUnless(NATIVE, 'requires macOS with Xcode command line tools')
class SigningAdapter(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('omd_test_sign_macos', SCRIPTS / 'test-sign-macos.py')
        self.sign = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sign)
        self.addCleanup(lambda: self.sign.Native.root and shutil.rmtree(self.sign.Native.root, ignore_errors=True))
        self.root = scratch(self)

    def test_signing_inspection_repeats_the_transformation_proof(self):
        source = producer(src(self.root))
        app = self.sign.build_app(self.root, extractor=source)
        _, status, report, prepared = prepare(self, self.root, source)
        self.assertEqual(status, 'prepared-development-candidate', report['failure'])
        report_path = self.root / 'prepared-work/extractor-report.json'
        spec = {'path': str(prepared), 'sha256': digest(prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64'}
        bound = {**spec, 'report': {'path': str(report_path), 'sha256': digest(report_path.read_bytes())}}
        plain = signing.inspect(self.sign.request(app, prepared_extractor=spec))
        self.assertNotIn('transformation', next(o for o in plain['code_objects'] if o['role'] == 'yt-dlp')['replacement'])
        plan = signing.inspect(self.sign.request(app, prepared_extractor=bound))
        extractor = next(o for o in plan['code_objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(extractor['action'], 'replace-and-sign')
        proof = extractor['replacement']['transformation']
        self.assertEqual((proof['verified_independently'], proof['signature_only_natives'], proof['identical_non_natives']), (True, 2, 7))
        self.assertIn('Signature-only transformation of the producer', extractor['replacement']['provenance'])
        self.assertNotIn('prepared-extractor', [b['id'] for b in plan['blockers']])
        self.assertNotIn('prepared-extractor-missing', [b['id'] for b in plan['blockers']])
        # The reviewed plan executes: the prepared bytes are installed and re-signed
        # with only a signature change (development rehearsal without receipts).
        plan_path = self.sign.write_plan(self.root, plan)
        status, signing_report = signing.execute(plan_path, self.root / 'Rehearsal.app', self.root / 'signing-work', allow_incomplete=True)
        signed = next(o for o in json.loads(signing_report.read_text())['objects'] if o['role'] == 'yt-dlp')
        self.assertEqual(status, 'incomplete-development')
        self.assertTrue(signed['payload']['signature_only_change'])
        self.assertEqual(signed['payload']['signature_independent_sha256'], signing.signature_independent_sha256(prepared.read_bytes()))
        # Wrong digests, another producer, a forged report and another mode are refused.
        (self.root / 'other').mkdir()
        other = producer(self.root / 'other/yt-dlp_macos', data=b'other producer\n')
        _, status, _, other_prepared = prepare(self, self.root, other, name='other-prepared')
        self.assertEqual(status, 'prepared-development-candidate')
        other_path = self.root / 'other-prepared-work/extractor-report.json'
        forged = json.loads(other_path.read_text())
        forged['producer'] = report['producer']
        forged_path = self.root / 'forged.json'
        forged_path.write_bytes(signing.json_bytes(forged))
        cases = [({**bound, 'report': {**bound['report'], 'sha256': '0' * 64}}, 'report digest differs'),
                 ({'path': str(other_prepared), 'sha256': digest(other_prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64',
                   'report': {'path': str(other_path), 'sha256': digest(other_path.read_bytes())}}, 'does not bind'),
                 ({'path': str(other_prepared), 'sha256': digest(other_prepared.read_bytes()), 'version': VERSION, 'arch': 'arm64',
                   'report': {'path': str(forged_path), 'sha256': digest(forged_path.read_bytes())}}, 'non-native member bytes differ'),
                 ({**bound, 'report': {'path': 'relative.json', 'sha256': '0' * 64}}, 'absolute path')]
        for change, why in cases:
            with self.subTest(why), self.assertRaisesRegex(ValueError, why):
                signing.inspect(self.sign.request(app, prepared_extractor=change))
        with self.assertRaisesRegex(ValueError, 'different signing mode'):
            signing.inspect(self.sign.request(app, 'developer-id', DEVID, TEAM, prepared_extractor=bound))


def tearDownModule():
    if Fixture.root is not None:
        shutil.rmtree(Fixture.root, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
