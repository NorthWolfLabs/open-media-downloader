# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Controlled-source builder guard tests. Inputs are tiny synthetic archives with a
matching synthetic legacy lock; Mach-O fixtures are compiled with the local SDK and only
ad-hoc signed temporary copies. Closure-proof tests run the replay helper the way the build
does, with this interpreter and its PyInstaller 6.22.0 standing in for the build runtime.
No network, identity, real producer or full build is used."""
import base64
import gzip
import hashlib
import io
import json
import marshal
import os
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

import ytdlp_source as source

NATIVE = platform.system() == 'Darwin' and platform.machine() == 'arm64' and Path('/usr/bin/xcrun').exists()
REAL_PROFILE = json.loads((source.REPO / source.PROFILE_REL).read_text())
REAL_CURL_PROFILE = json.loads((source.REPO / source.CURL_PROFILE_REL).read_text())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def targz(top, files):
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f'{top}/{name}')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def tarxz(top, files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:xz') as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f'{top}/{name}')
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def wheel(files):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return raw.getvalue()


def compile_dylib(folder, name, code='int f(void){return 1;}', arch='arm64', minimum='13.5', install_name=None, extra=(), executable=False):
    src = Path(folder) / f'{name}.c'
    src.write_text(code)
    out = Path(folder) / (name if executable else f'{name}.dylib')
    kind = [] if executable else ['-dynamiclib', *(['-install_name', install_name] if install_name else [])]
    subprocess.run(['/usr/bin/xcrun', 'clang', '-arch', arch, f'-mmacosx-version-min={minimum}', *kind, '-o', out, src, *extra], check=True, capture_output=True)
    return out


# ---------------------------------------------------------------- closure-proof helpers

def interpreter():
    """This test interpreter stands in for the built CPython (it is CPython 3.13.14 with
    PyInstaller 6.22.0, the versions the replay pins)."""
    import importlib.machinery
    import importlib.util
    return {'version': sys.version.split()[0], 'magic': importlib.util.MAGIC_NUMBER.hex(), 'cache_tag': sys.implementation.cache_tag,
            'extension_suffixes': importlib.machinery.EXTENSION_SUFFIXES}


def replay_pins():
    import PyInstaller
    return {'version': PyInstaller.__version__, 'site_packages': str(Path(PyInstaller.__file__).resolve().parent.parent), 'sources': source.PYINSTALLER_REPLAYED}


class Replayer:
    """Runs scripts/ytdlp_source_replay.py the way the build does (-s -P -B,
    PYTHONHASHSEED=0, a clean environment), with this interpreter as the runtime."""

    def __init__(self, folder):
        self.folder, self.count = Path(folder), 0

    def __call__(self, command, job):
        self.count += 1
        work = self.folder / f'replay-{command}-{self.count}'
        work.mkdir()
        job_path, result = work / 'job.json', work / 'result.json'
        job_path.write_text(json.dumps(job))
        env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(work), 'TMPDIR': str(work), 'LANG': 'C', 'LC_ALL': 'C', 'PYTHONHASHSEED': '0',
               'PYINSTALLER_CONFIG_DIR': str(work / 'config')}
        done = subprocess.run([sys.executable, '-s', '-P', '-B', str(source.REPLAY), command, str(job_path), str(result)], env=env,
                              capture_output=True, text=True, timeout=600)
        if done.returncode:
            raise ValueError(f'replay {command} refused: {done.stderr.strip().splitlines()[-1] if done.stderr.strip() else done.returncode}')
        return json.loads(result.read_text())


def native_job(folder, product, dest, strict=False):
    cache = Path(folder) / f'cache-{digest(dest.encode())[:8]}-{len(list(Path(folder).glob("cache-*")))}'
    cache.mkdir()
    return {'schema': source.REPLAY_SCHEMA, 'pyinstaller': replay_pins(), 'cachedir': str(cache), 'target_arch': 'arm64', 'options': source.REPLAY_OPTIONS,
            'items': [{'id': dest, 'source': str(product), 'source_sha256': digest(Path(product).read_bytes()), 'dest': dest, 'strict': strict}]}


def resign(data, folder, name='signed'):
    path = Path(folder) / f'{name}-{digest(data)[:12]}'
    path.write_bytes(data)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', path], check=True, capture_output=True)
    return path.read_bytes()


def load_commands(data):
    ncmds, = struct.unpack_from('<I', data, 16)
    rows, at = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, at)
        rows.append((cmd, at, size))
        at += size
    return rows


def segment(data, name):
    return next(at for cmd, at, _ in load_commands(data) if cmd == 0x19 and data[at + 8:at + 24].rstrip(b'\0') == name)


def section_offset(data, segname, sectname):
    at = segment(data, segname)
    nsects, = struct.unpack_from('<I', data, at + 64)
    for i in range(nsects):
        s = at + 72 + 80 * i
        if data[s:s + 16].rstrip(b'\0') == sectname:
            return struct.unpack_from('<I', data, s + 48)[0]
    raise AssertionError(f'{segname},{sectname} not found')


def mutate(data, kind):
    """Mutations a signature alone would not catch; each is re-signed by the caller."""
    data = bytearray(data)
    if kind == 'system-dependency':
        at = data.index(b'/usr/lib/libSystem.B.dylib')
        data[at:at + 26] = b'/usr/lib/libOtherX.B.dylib'
    elif kind == 'segment-protection':
        struct.pack_into('<i', data, segment(data, b'__DATA') + 60, 7)
    elif kind == 'symtab':
        at = next(at for cmd, at, _ in load_commands(data) if cmd == 0x2)
        struct.pack_into('<I', data, at + 12, struct.unpack_from('<I', data, at + 12)[0] - 1)
    elif kind == 'linkedit-vmaddr':
        at = segment(data, b'__LINKEDIT')
        struct.pack_into('<Q', data, at + 24, struct.unpack_from('<Q', data, at + 24)[0] + 0x4000)
    elif kind == 'data':
        data[section_offset(data, b'__DATA', b'__data')] ^= 0xff
    elif kind == 'unknown-command':
        at = next(at for cmd, at, _ in load_commands(data) if cmd == 0x2a)
        struct.pack_into('<I', data, at, 0x7f)
    elif kind == 'uuid':
        at = next(at for cmd, at, _ in load_commands(data) if cmd == 0x1b)
        data[at + 8] ^= 0xff
    else:
        raise AssertionError(kind)
    return bytes(data)


def section_digests(data):
    """The old section-only provenance view: sha256 of each file-backed section."""
    rows = {}
    for cmd, at, _ in load_commands(data):
        if cmd != 0x19:
            continue
        for i in range(struct.unpack_from('<I', data, at + 64)[0]):
            s = at + 72 + 80 * i
            _, size, offset = struct.unpack_from('<QQI', data, s + 32)
            if size and (struct.unpack_from('<I', data, s + 64)[0] & 0xff) not in (1, 0xc, 0x12):
                rows[data[s + 16:s + 32].rstrip(b'\0') + b',' + data[s:s + 16].rstrip(b'\0')] = digest(data[offset:offset + size])
    return rows


PYINSTALLER_CODE = r'''
import ast, importlib.util, json, marshal, sys
from PyInstaller.building.utils import create_base_library_zip, replace_filename_in_code_object
from PyInstaller.archive.writers import ZlibArchiveWriter
job = json.loads(sys.argv[1])
def compiled(path):
    data = open(path, 'rb').read()
    return compile(compile(importlib.util.decode_source(data), path, 'exec', ast.PyCF_ONLY_AST, True), path, 'exec', 0, True)
if job['kind'] == 'code':
    open(job['out'], 'wb').write(marshal.dumps(replace_filename_in_code_object(compiled(job['source']), job['filename'])))
elif job['kind'] == 'base':
    create_base_library_zip(job['out'], [tuple(r) for r in job['toc']], {n: compiled(s) for n, s, _ in job['toc']})
else:
    ZlibArchiveWriter(job['out'], [tuple(r) for r in job['toc']], {n: compiled(s) for n, s, _ in job['toc'] if s != '-'})
'''


def pyinstaller_output(job):
    """Run PyInstaller 6.22.0's own code writers under PYTHONHASHSEED=0, as in the build."""
    env = {'PATH': '/usr/bin:/bin', 'PYTHONHASHSEED': '0', 'HOME': str(Path(job['out']).parent), 'LANG': 'C', 'LC_ALL': 'C'}
    subprocess.run([sys.executable, '-s', '-P', '-B', '-c', PYINSTALLER_CODE, json.dumps(job)], env=env, check=True, capture_output=True)
    return Path(job['out']).read_bytes()


class Fixture:
    """A synthetic engine root, sources directory and matching legacy lock."""

    def __init__(self, tmp):
        self.tmp = Path(tmp).resolve()
        self.repo, self.sources = self.tmp / 'engine', self.tmp / 'sources'
        (self.repo / 'distribution/yt-dlp-source').mkdir(parents=True)
        (self.repo / 'distribution/yt-dlp').mkdir(parents=True)
        (self.sources / 'npm').mkdir(parents=True)
        tiny = targz('package', {'package.json': b'{"name":"tiny","version":"1.0.0"}'})
        self.write_source('npm/tiny-1.0.0.tgz', tiny)
        integrity = 'sha512-' + base64.b64encode(hashlib.sha512(tiny).digest()).decode()
        lock = {'lockfileVersion': 3, 'packages': {'': {'name': 'ejs'},
                'node_modules/tiny': {'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/tiny/-/tiny-1.0.0.tgz', 'integrity': integrity},
                'node_modules/@rollup/rollup-linux-x64-gnu': {'version': '1.0.0', 'os': ['linux'], 'cpu': ['x64'], 'optional': True,
                                                             'resolved': 'https://registry.npmjs.org/x.tgz', 'integrity': 'sha512-AA=='}}}
        archives = {
            'cpython': ('Python-3.13.14.tar.xz', tarxz('Python-3.13.14', {'README.rst': b'cpython'})),
            'xz': ('xz-5.2.3.tar.gz', targz('xz-5.2.3', {'configure': b'#!/bin/sh\n'})),
            'sdist:yt-dlp': ('yt_dlp-2026.8.19.tar.gz', targz('yt_dlp-2026.8.19', {'PKG-INFO': b'yt-dlp'})),
            'sdist:mutagen': ('mutagen-1.48.1.tar.gz', targz('mutagen-1.48.1', {'PKG-INFO': b'mutagen'})),
            'sdist:yt-dlp-ejs': ('yt_dlp_ejs-0.8.0.tar.gz', targz('yt_dlp_ejs-0.8.0', {'package-lock.json': json.dumps(lock).encode(), 'LICENSE': b'Unlicense'})),
            'sdist:pyinstaller': ('pyinstaller-6.22.0.tar.gz', targz('pyinstaller-6.22.0', {'COPYING.txt': b'GPL with exception'})),
            'sdist:altgraph': ('altgraph-0.17.5.tar.gz', targz('altgraph-0.17.5', {'PKG-INFO': b'altgraph'})),
            'tool:node': ('node-v24.20.0-darwin-arm64.tar.gz', targz('node-v24.20.0-darwin-arm64', {'bin/node': b'#!/bin/sh\n'})),
            'tool:flit-core': ('flit_core-4.0.2-py3-none-any.whl', wheel({'flit_core/__init__.py': b''})),
        }
        meta = {'cpython': ('cpython', 'cpython', 'shipped-source', '3.13.14'), 'xz': ('native', 'xz', 'shipped-source', '5.2.3'),
                'sdist:yt-dlp': ('sdist', 'yt-dlp', 'shipped-source', '2026.8.19'), 'sdist:mutagen': ('sdist', 'mutagen', 'shipped-source', '1.48.1'),
                'sdist:yt-dlp-ejs': ('sdist', 'yt-dlp-ejs', 'shipped-source', '0.8.0'), 'sdist:pyinstaller': ('sdist', 'pyinstaller', 'shipped-source', '6.22.0'),
                'sdist:altgraph': ('sdist', 'altgraph', 'packaging-source', '0.17.5'), 'tool:node': ('node', 'node', 'build-tool', '24.20.0'),
                'tool:flit-core': ('wheel', 'flit-core', 'build-tool', '4.0.2')}
        inputs = []
        for ident, (file, data) in archives.items():
            kind, package, role, version = meta[ident]
            self.write_source(file, data)
            inputs.append({'id': ident, 'kind': kind, 'role': role, 'package': package, 'version': version, 'file': file,
                           'url': f'https://example.invalid/{file}', 'sha256': digest(data), 'bytes': len(data)})
        profile = json.loads(json.dumps(REAL_PROFILE))
        profile.update(inputs=inputs, native=[{'id': 'xz', 'input': 'xz', 'official_recipe': 'fixture', 'steps': [['/usr/bin/true']], 'products': ['lib/liblzma.a']}])
        profile['packages'] = {'build_order': ['altgraph', 'pyinstaller', 'mutagen', 'yt-dlp-ejs', 'yt-dlp'], 'environment': {}, 'native': ['pyinstaller']}
        self.profile = profile
        self.write_profile()
        (self.repo / 'distribution/yt-dlp-source/launcher.py').write_text('from yt_dlp import main\n')
        (self.repo / source.README_REL).write_text('# fixture\n')
        (self.repo / 'LICENSE').write_text('MIT\n')
        (self.repo / 'distribution/yt-dlp/.python-version').write_text('3.13.14\n')
        (self.repo / 'distribution/yt-dlp/pyproject.toml').write_text(
            '[project]\nname = "x"\nversion = "0"\nrequires-python = "==3.13.*"\ndependencies = ["yt-dlp[default]==2026.8.19", "pyinstaller==6.22.2"]\n')
        self.write_lock()

    def write_source(self, name, data):
        path = self.sources / name
        path.write_bytes(data)
        return path

    def row(self, ident):
        return next(r for r in self.profile['inputs'] if r['id'] == ident)

    def write_profile(self):
        (self.repo / source.PROFILE_REL).write_text(json.dumps(self.profile, indent=1))

    def write_lock(self, overrides=None):
        def sdist(ident):
            row = self.row(ident)
            return f'sdist = {{ url = "https://files.example/{row["file"]}", hash = "sha256:{row["sha256"]}", size = {row["bytes"]} }}'
        versions = {'yt-dlp': '2026.8.19', 'mutagen': '1.48.1', 'yt-dlp-ejs': '0.8.0', 'pyinstaller': '6.22.2', 'altgraph': '0.17.5', **(overrides or {})}
        text = f'''version = 1
[[package]]
name = "yt-dlp"
version = "{versions['yt-dlp']}"
{sdist('sdist:yt-dlp')}
[package.optional-dependencies]
default = [{{ name = "mutagen" }}, {{ name = "yt-dlp-ejs" }}, {{ name = "brotlicffi", marker = "implementation_name != 'cpython'" }}]
[[package]]
name = "mutagen"
version = "{versions['mutagen']}"
{sdist('sdist:mutagen')}
[[package]]
name = "yt-dlp-ejs"
version = "{versions['yt-dlp-ejs']}"
{sdist('sdist:yt-dlp-ejs')}
[[package]]
name = "brotlicffi"
version = "1.0"
[[package]]
name = "pyinstaller"
version = "{versions['pyinstaller']}"
dependencies = [{{ name = "altgraph" }}, {{ name = "pefile", marker = "sys_platform == 'win32'" }}]
[[package]]
name = "altgraph"
version = "{versions['altgraph']}"
{sdist('sdist:altgraph')}
[[package]]
name = "pefile"
version = "1"
'''
        (self.repo / 'distribution/yt-dlp/uv.lock').write_text(text)

    def plan(self, name='plan.json'):
        path = self.tmp / name
        path.write_bytes(source.json_bytes(source.make_plan(self.repo, self.sources)))
        return path


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class PlanGuards(unittest.TestCase):
    def test_archive_provenance_ignores_rewritten_extraction_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            archive = root / 'package.tar.gz'
            archive.write_bytes(targz('package-1', {'package/module.py': b'VALUE = 1\n'}))
            expected = digest(archive.read_bytes())
            extracted = root / 'extracted/package/module.py'
            extracted.parent.mkdir(parents=True)
            extracted.write_bytes(b'VALUE = 2\n')
            rows = source.sdist_index(archive, expected)['package/module.py']
            self.assertEqual(rows, [{'member': 'package-1/package/module.py', 'sha256': digest(b'VALUE = 1\n')}])
            self.assertNotIn(digest(extracted.read_bytes()), [row['sha256'] for row in rows])
            archive.write_bytes(targz('package-1', {'package/module.py': b'VALUE = 2\n'}))
            with self.assertRaisesRegex(ValueError, 'Source archive changed'):
                source.sdist_index(archive, expected)

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.dir.name).resolve())

    def tearDown(self):
        self.dir.cleanup()

    def refused(self, pattern, function, *args):
        with self.assertRaisesRegex(ValueError, pattern):
            function(*args)

    def test_fixture_plan_is_portable(self):
        plan = source.make_plan(self.fx.repo, self.fx.sources)
        self.assertEqual(plan['status'], 'ready')
        self.assertEqual([r['file'] for r in plan['npm']], ['npm/tiny-1.0.0.tgz'])  # linux-only optional entry skipped
        self.assertTrue(plan['lock']['packages'][-1]['adjusted'] or any(r['adjusted'] for r in plan['lock']['packages']))
        self.assertIsNone(source.HOST_PATH.search(source.canonical(plan)))

    def test_input_digest_and_extra_files(self):
        self.fx.write_source('mutagen-1.48.1.tar.gz', b'tampered')
        self.refused('digest or size mismatch', source.make_plan, self.fx.repo, self.fx.sources)
        fx = Fixture(Path(self.dir.name) / 'second')
        fx.write_source('extra.whl', b'prebuilt')
        self.refused('Sources differ from the pinned inputs', source.make_plan, fx.repo, fx.sources)
        (fx.sources / 'extra.whl').unlink()
        (fx.sources / 'link.tar.gz').symlink_to(fx.sources / 'xz-5.2.3.tar.gz')
        self.refused('regular files|Sources differ', source.make_plan, fx.repo, fx.sources)

    def test_npm_integrity(self):
        self.fx.write_source('npm/tiny-1.0.0.tgz', b'not the pinned tarball')
        self.refused('npm integrity mismatch', source.make_plan, self.fx.repo, self.fx.sources)

    def test_version_and_lock_mismatches(self):
        self.fx.write_lock({'mutagen': '1.48.0'})
        self.refused('differs from the legacy lock', source.make_plan, self.fx.repo, self.fx.sources)
        self.fx.write_lock({'pyinstaller': '6.22.1'})
        self.refused('Lock adjustment for pyinstaller does not match', source.make_plan, self.fx.repo, self.fx.sources)
        self.fx.write_lock()
        (self.fx.repo / 'distribution/yt-dlp/.python-version').write_text('3.13.15\n')
        self.refused('differs from the legacy profile', source.make_plan, self.fx.repo, self.fx.sources)

    def test_profile_refuses_prebuilt_wheels_and_other_targets(self):
        cases = [
            (lambda p: p['inputs'].append({**p['inputs'][-1], 'id': 'tool:cffi', 'package': 'cffi', 'file': 'cffi-2.1.1-cp313-cp313-macosx_11_0_arm64.whl',
                                            'url': 'https://example.invalid/cffi-2.1.1-cp313-cp313-macosx_11_0_arm64.whl'}), 'Prebuilt platform wheel refused'),
            (lambda p: p['inputs'][-1].update(role='shipped-source'), 'Wheels may only be build tools'),
            (lambda p: p['target'].update(arch='x86_64'), 'Only the explicit macOS arm64 target'),
            (lambda p: p['target'].update(macos_minimum='11.0'), 'may not be below 13.5'),
            (lambda p: p.update(release_accepted=True), 'unaccepted prototype'),
            (lambda p: p.update(jobs=16), 'between 1 and 4'),
            (lambda p: p['inputs'][0].update(url='http://example.invalid/Python-3.13.14.tar.xz'), 'https'),
        ]
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                profile = json.loads(json.dumps(self.fx.profile))
                mutate(profile)
                path = Path(self.dir.name) / 'profile.json'
                path.write_text(json.dumps(profile))
                self.refused(pattern, source.load_profile, path)

    def test_stale_plan_and_unsafe_outputs(self):
        plan = self.fx.plan()
        output = Path(self.dir.name).resolve() / 'out'
        self.fx.profile['jobs'] = 3
        self.fx.write_profile()
        with self.assertRaisesRegex(source.Stale, 'Stale plan'):
            source.build(self.fx.repo, plan, self.fx.sources, output)
        self.assertFalse(output.exists())
        self.fx.profile['jobs'] = 4
        self.fx.write_profile()
        for bad in (self.fx.sources / 'out', self.fx.repo / 'out', self.fx.sources):
            with self.subTest(output=bad.name):
                self.refused('Output must be outside|already exists', source.build, self.fx.repo, plan, self.fx.sources, bad)
        self.refused('absolute', source.new_output_directory, 'relative/out', [])

    def test_failed_build_writes_no_ready_receipt(self):
        self.fx.profile['native'][0]['steps'] = [['/usr/bin/false']]
        self.fx.write_profile()
        plan = self.fx.plan()
        output = Path(self.dir.name).resolve() / 'out'
        with self.assertRaises(source.BuildFailed):
            source.build(self.fx.repo, plan, self.fx.sources, output)
        receipt = json.loads((output / 'receipt.json').read_text())
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['failure']['step'], 'native-xz-0')
        self.assertFalse((output / 'bin').exists())
        self.assertNotIn('output', receipt)
        self.assertIsNone(source.HOST_PATH.search(source.canonical(receipt)))
        self.refused('built receipt', source.make_kit, self.fx.repo, plan, self.fx.sources, output, Path(self.dir.name).resolve() / 'kit.tar.gz')

    def test_cpython_module_report(self):
        summary = 'Checked 112 modules (33 built-in, 61 shared, 2 n/a on macosx-13.5-arm64, 2 disabled, 1 missing, 0 failed on import)\n'
        disabled = 'The following modules are *disabled* in configure script:\n_testcapi          xxsubtype\n\n'
        missing = 'The necessary bits to build these optional modules were not found:\n_curses\nTo find the necessary bits, look in configure.ac and config.log.\n\n'
        report = source.check_missing_modules(disabled + missing + summary, ['_curses'], ['_testcapi', 'xxsubtype'])
        self.assertEqual((report['missing_or_failed'], report['disabled']), (['_curses'], ['_testcapi', 'xxsubtype']))
        self.refused(r"missing or failed: \['_curses'\]", source.check_missing_modules, disabled + missing + summary, [], ['_testcapi', 'xxsubtype'])
        self.refused('disabled modules differ', source.check_missing_modules, disabled + summary, [], ['_testcapi'])
        self.refused('summary not found', source.check_missing_modules, disabled, [], ['_testcapi', 'xxsubtype'])
        self.refused('ssl module', source.check_missing_modules, summary + 'Could not build the ssl module!\n', [], [])


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class NativeGuards(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()

    def tearDown(self):
        self.dir.cleanup()

    def test_architecture_and_minimum(self):
        good = compile_dylib(self.tmp, 'good').read_bytes()
        self.assertEqual(source.check_target_macho(good, 'good', '13.5'), '13.5.0')
        for name, kwargs, pattern in [('intel', {'arch': 'x86_64'}, 'thin arm64'), ('newer', {'minimum': '14.0'}, 'above the profile minimum')]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, pattern):
                source.check_target_macho(compile_dylib(self.tmp, name, **kwargs).read_bytes(), name, '13.5')
        fat = self.tmp / 'fat.dylib'
        subprocess.run(['/usr/bin/lipo', '-create', self.tmp / 'good.dylib', self.tmp / 'intel.dylib', '-output', fat], check=True)
        with self.assertRaisesRegex(ValueError, 'thin arm64'):
            source.check_target_macho(fat.read_bytes(), 'fat', '13.5')

    def test_linkage_policy(self):
        facts = [{'dylibs': ['/usr/lib/libSystem.B.dylib', '@rpath/libpython3.13.dylib'], 'rpaths': ['@loader_path/..']}]
        source.check_linkage(facts, 'ok', ('@rpath/',))
        for dylib in ('/opt/homebrew/opt/openssl/lib/libssl.3.dylib', '/usr/local/lib/libz.dylib', '/Users/x/lib.dylib'):
            with self.subTest(dylib=dylib), self.assertRaisesRegex(ValueError, 'links'):
                source.check_linkage([{'dylibs': [dylib], 'rpaths': []}], 'bad', ('@rpath/',))
        with self.assertRaisesRegex(ValueError, 'LC_RPATH'):
            source.check_linkage([{'dylibs': [], 'rpaths': ['/tmp/lib']}], 'bad', ())

    def test_packed_native_maps_only_to_recorded_products(self):
        """A packed native must be PyInstaller's processing of its own build product:
        the replay reproduces it byte for byte and the relocation policy explains it.
        A different product with otherwise valid code is refused."""
        product = compile_dylib(self.tmp, 'product', install_name='/opt/fixture/lib/libproduct.dylib')
        packed = Path(Replayer(self.tmp)('natives', native_job(self.tmp, product, 'libproduct.dylib'))['rows'][0]['output']).read_bytes()
        self.assertNotEqual(digest(packed), digest(product.read_bytes()))
        report = source.relocation_policy(product.read_bytes(), packed, 'libproduct.dylib')
        self.assertEqual(report['changes'], [{'command': 'LC_ID_DYLIB', 'from': '/opt/fixture/lib/libproduct.dylib', 'to': '@rpath/libproduct.dylib'}])
        foreign = compile_dylib(self.tmp, 'foreign', 'int f(void){return 2;}', install_name='/opt/fixture/lib/libproduct.dylib').read_bytes()
        with self.assertRaisesRegex(ValueError, 'differ from the build product'):
            source.relocation_policy(foreign, packed, 'libproduct.dylib')

    def test_wheels_refuse_foreign_natives_and_tags(self):
        native = compile_dylib(self.tmp, 'mod').read_bytes()
        intel = compile_dylib(self.tmp, 'intel', arch='x86_64').read_bytes()
        cases = [
            ('pkg-1.0-py3-none-any.whl', {'pkg/_x.so': native}, False, 'must be pure Python'),
            ('pkg-1.0-cp313-cp313-macosx_10_9_universal2.whl', {'pkg/_x.so': native}, True, 'not this build target'),
            ('pkg-1.0-cp313-cp313-macosx_13_0_arm64.whl', {'pkg/_x.so': intel}, True, 'thin arm64'),
            ('pkg-1.0-cp313-cp313-macosx_13_0_arm64.whl', {'pkg/x.py': b''}, True, 'expected to contain native'),
            ('pkg-1.0-cp313-cp313-macosx_11_0_arm64.whl', {'pkg/_x.so': native}, True, 'not this build target'),
            ('other-1.0-py3-none-any.whl', {'other/x.py': b''}, False, 'name or version'),
        ]
        for file, files, native_expected, pattern in cases:
            with self.subTest(file=file, pattern=pattern):
                path = self.tmp / file
                path.write_bytes(wheel(files))
                with self.assertRaisesRegex(ValueError, pattern):
                    source.wheel_facts(path, 'pkg', '1.0', native_expected, '13.5')
                path.unlink()
        good = self.tmp / 'pkg-1.0-cp37-abi3-macosx_13_0_arm64.whl'
        good.write_bytes(wheel({'pkg/_x.so': native, 'pkg-1.0.dist-info/RECORD': b''}))
        facts, _ = source.wheel_facts(good, 'pkg', '1.0', True, '13.5')
        self.assertEqual(len(facts['natives']), 1)

    def test_installed_environment_must_equal_built_wheels(self):
        native = compile_dylib(self.tmp, 'mod').read_bytes()
        site = self.tmp / 'site-packages'
        files = {'pkg/__init__.py': b'', 'pkg/_x.so': native, 'pkg-1.0.dist-info/METADATA': b'Name: pkg'}

        def install(extra=None, changed=None):
            shutil.rmtree(site, ignore_errors=True)
            for rel, data in {**files, **(changed or {})}.items():
                (site / rel).parent.mkdir(parents=True, exist_ok=True)
                (site / rel).write_bytes(data)
            records = [*files, 'pkg-1.0.dist-info/RECORD', 'pkg-1.0.dist-info/INSTALLER', *(extra or {})]
            (site / 'pkg-1.0.dist-info/INSTALLER').write_text('pip\n')
            (site / 'pkg-1.0.dist-info/RECORD').write_text(''.join(f'{r},,\n' for r in records))
            for rel, data in (extra or {}).items():
                (site / rel).parent.mkdir(parents=True, exist_ok=True)
                (site / rel).write_bytes(data)
        built = {'pkg': {rel: digest(data) for rel, data in files.items()}}
        install()
        self.assertEqual(source.check_installed(site, built)['distributions'], ['pkg-1.0.dist-info'])
        install(changed={'pkg/_x.so': compile_dylib(self.tmp, 'other', 'int g(void){return 3;}').read_bytes()})
        with self.assertRaisesRegex(ValueError, 'differs from its built wheel'):
            source.check_installed(site, built)
        install(extra={'pkg/_prebuilt.so': native})
        with self.assertRaisesRegex(ValueError, 'not part of any built wheel'):
            source.check_installed(site, built)
        install()
        (site / 'stray.so').write_bytes(native)
        with self.assertRaisesRegex(ValueError, 'not recorded'):
            source.check_installed(site, built)
        install()
        (site / 'extra-2.0.dist-info').mkdir()
        with self.assertRaisesRegex(ValueError, 'Installed distributions differ'):
            source.check_installed(site, built)


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class NativeClosureProof(unittest.TestCase):
    """Packed natives and the onefile executable against their recorded products, with
    PyInstaller's own processing replayed. Each mutation below keeps every file-backed
    section of the native (or __TEXT,__text of the executable) unchanged unless noted,
    so the earlier section-only proof accepted it."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()
        self.replay = Replayer(self.tmp)
        dep = compile_dylib(self.tmp, 'libdep', 'int g(void){return 2;}', install_name='/opt/fixture/lib/libdep.dylib')
        self.product = compile_dylib(self.tmp, 'libprod', 'int value = 42; int g(void); int f(void){return g() + value;}',
                                     install_name='/opt/fixture/lib/libprod.dylib', extra=[f'-L{self.tmp}', '-ldep', '-Wl,-rpath,/opt/fixture/lib'])
        self.assertTrue(dep.is_file())
        self.dest = 'lib/libprod.dylib'
        self.packed = Path(self.replay('natives', native_job(self.tmp, self.product, self.dest))['rows'][0]['output']).read_bytes()

    def tearDown(self):
        self.dir.cleanup()

    def test_actual_pyinstaller_relocation_passes(self):
        report = source.relocation_policy(self.product.read_bytes(), self.packed, self.dest)
        self.assertEqual(report['changes'], [
            {'command': 'LC_ID_DYLIB', 'from': '/opt/fixture/lib/libprod.dylib', 'to': '@rpath/libprod.dylib'},
            {'command': 'LC_LOAD_DYLIB', 'from': '/opt/fixture/lib/libdep.dylib', 'to': '@rpath/libdep.dylib'},
            {'command': 'LC_RPATH', 'from': '/opt/fixture/lib', 'to': None},
            {'command': 'LC_RPATH', 'from': None, 'to': '@loader_path/..'}])
        again = Path(self.replay('natives', native_job(self.tmp, self.product, self.dest))['rows'][0]['output']).read_bytes()
        self.assertEqual(again, self.packed)  # the replay is deterministic
        source.check_linkage(source.macho_facts(self.packed), self.dest, ('@rpath/', '@loader_path/', '@executable_path/'))

    def test_mutated_natives_are_refused(self):
        product = self.product.read_bytes()
        cases = {'system-dependency': 'load commands differ', 'segment-protection': 'load commands differ', 'symtab': 'load commands differ',
                 'linkedit-vmaddr': 'load commands differ', 'uuid': 'load commands differ', 'data': 'section, data or link-edit bytes differ',
                 'unknown-command': 'unknown or unsupported load command'}
        for kind, pattern in cases.items():
            with self.subTest(mutation=kind):
                bad = mutate(self.packed, kind)
                if kind != 'unknown-command':
                    bad = resign(bad, self.tmp, kind)
                    if kind != 'data':
                        self.assertEqual(section_digests(bad), section_digests(self.packed))  # the section-only proof accepted this
                self.assertNotEqual(bad, self.packed)  # and the byte-identical replay refuses it
                with self.assertRaisesRegex(ValueError, pattern):
                    source.relocation_policy(product, bad, self.dest)

    def test_unaccounted_rewrites_are_refused(self):
        product = self.product.read_bytes()
        absolute = resign(self.packed.replace(b'@loader_path/..', b'/tmp/xxxxxxxxxx'), self.tmp, 'rpath')
        with self.assertRaisesRegex(ValueError, 'load commands differ'):
            source.relocation_policy(product, absolute, self.dest)
        # The same bytes are not a valid result for another destination (another target rpath).
        with self.assertRaisesRegex(ValueError, 'load commands differ'):
            source.relocation_policy(product, self.packed, 'libprod.dylib')
        # An install name that was not normalized is not PyInstaller's output.
        with self.assertRaisesRegex(ValueError, 'load commands differ'):
            source.relocation_policy(product, resign(product, self.tmp, 'unprocessed'), self.dest)

    def onefile(self):
        boot = compile_dylib(self.tmp, 'run', 'int value = 42; int main(void){return value - 42;}', executable=True)
        pylib = compile_dylib(self.tmp, 'libpython3.13')
        pkg = self.tmp / 'pkg'
        pkg.write_bytes(b'MEI-FIXTURE-PKG' * 997)
        out = self.tmp / 'out'
        out.mkdir()
        job = {'schema': source.REPLAY_SCHEMA, 'pyinstaller': replay_pins(), 'target_arch': 'arm64', 'bootloader': str(boot),
               'bootloader_sha256': digest(boot.read_bytes()), 'pkg': str(pkg), 'pkg_sha256': digest(pkg.read_bytes()), 'python_library': str(pylib),
               'python_library_sha256': digest(pylib.read_bytes()), 'output': str(out / 'omd-yt-dlp')}
        exe = Path(self.replay('onefile', job)['output']).read_bytes()
        start = source.macho_structure(boot.read_bytes(), 'run')['linkedit_data_end']
        return exe, boot.read_bytes(), pylib.read_bytes(), start, start + pkg.stat().st_size

    def test_onefile_assembly_of_the_compiled_bootloader(self):
        exe, boot, pylib, start, end = self.onefile()
        report = source.onefile_policy(exe, boot, start, end, pylib)
        self.assertFalse(report['sdk']['rewritten'])
        self.assertNotEqual(report['uuid'], report['bootloader_uuid'])
        cases = {'data': 'differ from the compiled bootloader', 'system-dependency': 'differ from the compiled bootloader',
                 'segment-protection': 'differ from the compiled bootloader', 'linkedit-vmaddr': 'differ from the compiled bootloader',
                 'uuid': 'PKG-derived UUID', 'unknown-command': 'unknown or unsupported load command'}
        text = lambda data: section_digests(data)[b'__TEXT,__text']
        for kind, pattern in cases.items():
            with self.subTest(mutation=kind):
                bad = mutate(exe, kind)
                if kind != 'unknown-command':
                    bad = resign(bad, self.tmp, f'exe-{kind}')
                    self.assertEqual(text(bad), text(exe))  # the earlier __TEXT,__text-only check accepted this
                with self.assertRaisesRegex(ValueError, pattern):
                    source.onefile_policy(bad, boot, start, end, pylib)
        with self.assertRaisesRegex(ValueError, 'PKG must start'):
            source.onefile_policy(exe, boot, start + 16, end, pylib)
        other = compile_dylib(self.tmp, 'other-run', 'int value = 43; int main(void){return value - 43;}', executable=True).read_bytes()
        with self.assertRaisesRegex(ValueError, 'differ from the compiled bootloader|PKG must start'):
            source.onefile_policy(exe, other, start, end, pylib)


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class PythonClosureProof(unittest.TestCase):
    """Packed code must equal its attributed source compiled by the same CPython with
    PyInstaller's documented co_filename replacement; names alone prove nothing."""

    SOURCE = ("'''fixture'''\nimport os\nFLAGS = frozenset({'alpha', 'beta', 'gamma'})\nNEG = -0.0\n"
              "def check(word):\n    return word in {'alpha', 'beta', 'gamma'} and (lambda: NEG)()\n"
              "class Thing:\n    def method(self, *a, **k):\n        return [x for x in a if x]\n")

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()
        self.replay = Replayer(self.tmp)
        self.stdlib, self.site = self.tmp / 'stdlib', self.tmp / 'site-packages'
        for rel, text in {'stdlib/os.py': 'SEP = "/"\n', 'stdlib/pkg/__init__.py': self.SOURCE, 'stdlib/pkg/mod.py': self.SOURCE + 'X = 1\n',
                          'stdlib/nsp/a.py': 'A = 1\n', 'site-packages/os.py': 'SEP = "shadowed"\n', 'site-packages/nsp/b.py': 'B = 2\n',
                          'site-packages/third.py': 'T = 3\n', 'site-packages/ext.py': 'E = 4\n', 'site-packages/ext.cpython-313-darwin.so': ''}.items():
            (self.tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.tmp / rel).write_text(text)
        self.roots = [('stdlib', self.stdlib), ('lib-dynload', self.stdlib / 'lib-dynload'), ('site-packages', self.site)]

    def tearDown(self):
        self.dir.cleanup()

    def packed(self, path, filename, name='packed'):
        return pyinstaller_output({'kind': 'code', 'source': str(path), 'filename': filename, 'out': str(self.tmp / f'{name}.code')})

    def job(self, items, base=None):
        job = {'schema': source.REPLAY_SCHEMA, 'interpreter': {k: interpreter()[k] for k in ('version', 'magic', 'cache_tag')},
               'pyinstaller': replay_pins(), 'items': items}
        if base:
            job['base_library'] = base
        return job

    def item(self, ident, path, filename, packed, modes=('modulegraph', 'compile-bytes')):
        target = self.tmp / f'{ident.replace(":", "-")}.packed'
        target.write_bytes(packed)
        return {'id': ident, 'source': str(path), 'source_sha256': digest(Path(path).read_bytes()), 'filename': filename, 'modes': list(modes),
                'packed': str(target), 'packed_sha256': digest(packed)}

    def test_import_path_attribution(self):
        suffixes = interpreter()['extension_suffixes']
        resolve = lambda name: source.resolve_module(name, self.roots, suffixes)
        self.assertEqual(resolve('os')[:3], ('module', 'stdlib', self.stdlib / 'os.py'))  # first root wins over site-packages
        self.assertEqual(resolve('pkg')[:3], ('package', 'stdlib', self.stdlib / 'pkg' / '__init__.py'))
        self.assertEqual(resolve('pkg.mod')[:3], ('module', 'stdlib', self.stdlib / 'pkg' / 'mod.py'))
        self.assertEqual(resolve('nsp')[0], 'namespace')
        self.assertEqual(resolve('nsp.b')[:3], ('module', 'site-packages', self.site / 'nsp' / 'b.py'))
        self.assertEqual(resolve('ext')[0], 'unsupported')  # an extension module shadows ext.py
        self.assertIsNone(resolve('missing'))
        context = {'roots': self.roots, 'interpreter': interpreter()}
        for name, kind, pattern in [('ext', 'module', 'unsupported'), ('os', 'package', 'resolve'), ('missing', 'module', 'nothing'), ('pkg.mod', 'namespace', 'resolve')]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'Unattributable'):
                source.attribute_module(name, kind, context)

    def test_code_must_equal_its_source(self):
        mod = self.stdlib / 'pkg' / 'mod.py'
        good = self.item('pyz:pkg.mod', mod, 'pkg/mod.py', self.packed(mod, 'pkg/mod.py'))
        altered_source = self.tmp / 'altered.py'
        altered_source.write_text(self.SOURCE.replace("'gamma'", "'delta'") + 'X = 1\n')
        altered = self.item('pyz:altered', mod, 'pkg/mod.py', self.packed(altered_source, 'pkg/mod.py', 'altered'))
        path_left = self.item('pyz:path', mod, 'pkg/mod.py', self.packed(mod, str(mod), 'path'))
        rows = {r['id']: r for r in self.replay('code', self.job([good, altered, path_left]))['rows']}
        self.assertTrue(rows['pyz:pkg.mod']['equal'])
        self.assertEqual(rows['pyz:pkg.mod']['mode'], 'modulegraph')
        self.assertFalse(rows['pyz:altered']['equal'])
        self.assertIn('co_consts', rows['pyz:altered']['difference'])
        self.assertFalse(rows['pyz:path']['equal'])
        self.assertIn('co_filename', rows['pyz:path']['difference'])

    def test_malformed_code_is_refused(self):
        mod = self.stdlib / 'pkg' / 'mod.py'
        valid = self.packed(mod, 'pkg/mod.py')
        for name, data, pattern in [('garbage', b'\x00arbitrary non-bytecode bytes', 'not a marshalled code object'),
                                    ('tuple', marshal.dumps(('not', 'code')), 'not a code object'), ('trailing', valid + b'JUNK', 'trailing bytes'),
                                    ('empty', b'', 'not a marshalled code object')]:
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, pattern):
                self.replay('code', self.job([self.item(f'pyz:{name}', mod, 'pkg/mod.py', data)]))
        changed = self.item('pyz:pkg.mod', mod, 'pkg/mod.py', valid)
        changed['source_sha256'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'recorded digest'):
            self.replay('code', self.job([changed]))

    def base_library(self, blob, toc):
        target = self.tmp / f'base-{digest(blob)[:12]}.zip'
        target.write_bytes(blob)
        members = [n.replace('.', '/') + ('/__init__' if s.endswith('__init__.py') else '') + '.pyc' for n, s, _ in toc]
        sources = {m: {'id': f'base:{m}', 'source': s, 'source_sha256': digest(Path(s).read_bytes()), 'filename': m[:-1], 'modes': ['modulegraph', 'compile-bytes']}
                   for m, (_, s, _) in zip(members, toc)}
        return {'path': str(target), 'sha256': digest(blob), 'members': members, 'sources': sources}

    def rezip(self, members, compress=zipfile.ZIP_STORED):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            for name, data in members:
                info = zipfile.ZipInfo(name)
                info.compress_type = compress
                archive.writestr(info, data)
        return raw.getvalue()

    def test_base_library_code_and_headers(self):
        toc = [['os', str(self.stdlib / 'os.py'), 'PYMODULE'], ['pkg', str(self.stdlib / 'pkg' / '__init__.py'), 'PYMODULE']]
        blob = pyinstaller_output({'kind': 'base', 'toc': toc, 'out': str(self.tmp / 'base_library.zip')})
        result = self.replay('code', self.job([], self.base_library(blob, toc)))['base_library']
        self.assertTrue(result['writer_replayed'] and all(r['equal'] for r in result['rows']))
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            members = [(i.filename, archive.read(i)) for i in archive.infolist()]
        header, os_code = members[0][1][:16], members[0][1][16:]
        cases = {
            # Astra's repro: same name, arbitrary non-bytecode payload. Name-only checks accepted it.
            'arbitrary-os-pyc': (self.rezip([('os.pyc', header + b'arbitrary non-bytecode bytes'), members[1]]), 'not a marshalled code object'),
            'other-module-code': (self.rezip([('os.pyc', members[1][1]), members[1]]), None),
            'bad-magic': (self.rezip([('os.pyc', b'\x00\x00\r\n' + header[4:] + os_code), members[1]]), 'bytecode magic'),
            'checked-hash-flag': (self.rezip([('os.pyc', header[:4] + b'\x03\x00\x00\x00' + header[8:] + os_code), members[1]]), 'unchecked-hash header'),
            'nonzero-hash': (self.rezip([('os.pyc', header[:8] + b'\x01' * 8 + os_code), members[1]]), 'unchecked-hash header'),
            'deflated': (self.rezip(members, zipfile.ZIP_DEFLATED), 'Unexpected base_library.zip member'),
            'trailing': (blob + b'JUNK', 'differs from PyInstaller writer output'),
        }
        for name, (bad, pattern) in cases.items():
            with self.subTest(case=name):
                spec = self.base_library(bad, toc)
                if pattern is None:
                    rows = {r['id']: r for r in self.replay('code', self.job([], spec))['base_library']['rows']}
                    self.assertFalse(rows['base:os.pyc']['equal'])
                else:
                    with self.assertRaisesRegex(ValueError, pattern):
                        self.replay('code', self.job([], spec))

    def test_pyz_structure(self):
        toc = [['nsp', '-', 'PYMODULE'], ['os', str(self.stdlib / 'os.py'), 'PYMODULE'], ['pkg', str(self.stdlib / 'pkg' / '__init__.py'), 'PYMODULE'],
               ['pkg.mod', str(self.stdlib / 'pkg' / 'mod.py'), 'PYMODULE']]
        blob = pyinstaller_output({'kind': 'pyz', 'toc': toc, 'out': str(self.tmp / 'PYZ.pyz')})
        magic = interpreter()['magic']
        rows = source.pyz_entries(blob, magic)
        self.assertEqual([(n, k) for n, k, _ in rows], [('nsp', 'namespace'), ('os', 'module'), ('pkg', 'package'), ('pkg.mod', 'module')])
        offset, = struct.unpack_from('!i', blob, 8)
        entries = marshal.loads(blob[offset:])

        def with_toc(value):
            return blob[:offset] + marshal.dumps(value)
        cases = {'bad-magic': (blob[:4] + b'\x00\x00\r\n' + blob[8:], 'bytecode magic'),
                 'padding': (blob[:12] + b'\x01' + blob[13:], 'padding'),
                 'trailing': (blob + b'JUNK', 'Trailing bytes'),
                 'duplicate': (with_toc(entries[:2] + [entries[1]] + entries[2:]), 'Duplicate or unsorted'),
                 'unsorted': (with_toc([entries[0], entries[2], entries[1], entries[3]]), 'Duplicate or unsorted|not contiguous'),
                 'gap': (with_toc([entries[0], (entries[1][0], (entries[1][1][0], entries[1][1][1] + 1, entries[1][1][2] - 1))] + entries[2:]), 'not contiguous'),
                 'namespace-data': (with_toc([(entries[0][0], (3, entries[0][1][1], 1))] + entries[1:]), 'not contiguous|carries data'),
                 'data-entry': (with_toc([entries[0], (entries[1][0], (2,) + entries[1][1][1:])] + entries[2:]), 'Unsupported PYZ entry type'),
                 'not-a-list': (with_toc(tuple(entries)), 'Invalid PYZ TOC'),
                 'corrupt-stream': (blob[:entries[1][1][1]] + b'\x00' * entries[1][1][2] + blob[entries[1][1][1] + entries[1][1][2]:], 'Invalid compressed|Truncated')}
        for name, (bad, pattern) in cases.items():
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, pattern):
                source.pyz_entries(bad, magic)


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class KitGuards(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()
        self.fx = Fixture(self.tmp)
        self.plan = self.fx.plan()
        self.build = self.tmp / 'build'
        self.build.mkdir()
        fingerprints = source.json_bytes({'schema': source.FINGERPRINTS_SCHEMA, 'rows': [{'kind': 'pyz', 'name': 'x', 'code_sha256': 'cd' * 32}]})
        (self.build / source.FINGERPRINTS).write_bytes(fingerprints)
        self.closure = {'python': {'fingerprints': {'file': source.FINGERPRINTS, 'sha256': digest(fingerprints)}}}
        self.receipt({'schema': source.RECEIPT_SCHEMA, 'status': 'built', 'plan_sha256': source.file_sha(self.plan), 'output': {'sha256': 'ab' * 32},
                      'closure': self.closure})

    def tearDown(self):
        self.dir.cleanup()

    def receipt(self, value):
        (self.build / 'receipt.json').write_bytes(source.json_bytes(value))

    def test_kit_binds_closure_fingerprints(self):
        kit = self.tmp / 'kit.tar.gz'
        source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, kit)
        with tarfile.open(kit) as tar:
            self.assertIn(f'{source.KIT_PREFIX}/receipt/{source.FINGERPRINTS}', tar.getnames())
            self.assertIn(f'{source.KIT_PREFIX}/engine/scripts/ytdlp_source_replay.py', tar.getnames())
        bad = self.tmp / 'bad.tar.gz'
        with tarfile.open(kit) as src, tarfile.open(bad, 'w:gz') as out:
            index = None
            for info in src:
                data = src.extractfile(info).read()
                if info.name.endswith(f'receipt/{source.FINGERPRINTS}'):
                    data = data.replace(b'cdcd', b'efef', 1)
                    info.size = len(data)
                    changed = data
                if info.name.endswith('KIT-INDEX.json'):
                    index = (info, data)
                    continue
                out.addfile(info, io.BytesIO(data))
            # Even with a consistent index entry, the fingerprints must match the receipt.
            value = json.loads(index[1])
            for row in value['files']:
                if row['path'] == f'receipt/{source.FINGERPRINTS}':
                    row.update(sha256=digest(changed), bytes=len(changed))
            data = source.json_bytes(value)
            index[0].size = len(data)
            out.addfile(index[0], io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, 'fingerprints do not match'):
            source.verify_kit(bad)
        (self.build / source.FINGERPRINTS).write_bytes(b'{"rows": []}\n')
        with self.assertRaisesRegex(ValueError, 'fingerprints differ from the receipt'):
            source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.tmp / 'kit-2.tar.gz')

    def test_kit_contents_determinism_and_tampering(self):
        first, second = self.tmp / 'kit-1.tar.gz', self.tmp / 'kit-2.tar.gz'
        made = source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, first)
        source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        report = source.verify_kit(first, made['sha256'])
        self.assertTrue(report['verified'])
        with tarfile.open(first) as tar:
            names = {n.split('/', 1)[1] for n in tar.getnames()}
        for row in self.fx.profile['inputs']:
            self.assertIn(f'sources/{row["file"]}', names)
        self.assertIn('sources/npm/tiny-1.0.0.tgz', names)
        self.assertIn('engine/scripts/ytdlp_source.py', names)
        self.assertIn('terms/sdist-yt-dlp-ejs/yt_dlp_ejs-0.8.0/LICENSE', names)
        self.assertIn('terms/sdist-pyinstaller/pyinstaller-6.22.0/COPYING.txt', names)
        with self.assertRaisesRegex(ValueError, 'expected value'):
            source.verify_kit(first, '00' * 32)
        for mode in ('extra', 'changed', 'traversal'):
            with self.subTest(mode=mode):
                bad = self.tmp / f'bad-{mode}.tar.gz'
                with tarfile.open(first) as src, tarfile.open(bad, 'w:gz') as out:
                    for info in src:
                        data = src.extractfile(info).read()
                        if mode == 'changed' and info.name.endswith('sources/mutagen-1.48.1.tar.gz'):
                            data = b'changed'
                            info.size = len(data)
                        out.addfile(info, io.BytesIO(data))
                    if mode in ('extra', 'traversal'):
                        info = tarfile.TarInfo(f'{source.KIT_PREFIX}/sources/prebuilt.whl' if mode == 'extra' else f'{source.KIT_PREFIX}/../escape')
                        info.size = 1
                        out.addfile(info, io.BytesIO(b'x'))
                with self.assertRaises(ValueError):
                    source.verify_kit(bad)

    def test_kit_refuses_host_paths_and_unbuilt_receipts(self):
        self.receipt({'status': 'built', 'plan_sha256': source.file_sha(self.plan), 'output': {'sha256': 'ab' * 32}, 'log': '/Users/someone/build.log'})
        with self.assertRaisesRegex(ValueError, 'host path'):
            source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.tmp / 'kit.tar.gz')
        self.receipt({'status': 'failed', 'plan_sha256': source.file_sha(self.plan)})
        with self.assertRaisesRegex(ValueError, 'built receipt'):
            source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.tmp / 'kit.tar.gz')
        self.receipt({'status': 'built', 'plan_sha256': '00' * 32, 'output': {'sha256': 'ab' * 32}})
        with self.assertRaisesRegex(ValueError, 'built receipt'):
            source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.tmp / 'kit.tar.gz')
        self.receipt({'status': 'built', 'plan_sha256': source.file_sha(self.plan), 'output': {'sha256': 'ab' * 32}})
        with self.assertRaisesRegex(ValueError, 'outside'):
            source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.fx.sources / 'kit.tar.gz')


# ---------------------------------------------------------------- curl_cffi profile (v2)

def recipe_archive(deps, patches, extra_vars='', top='curl-impersonate-0000000000000000000000000000000000000000'):
    """A tiny curl-impersonate-shaped recipe: CMakeLists pins, ExternalProjects and patches."""
    lines = ['cmake_minimum_required(VERSION 3.20)']
    for name, (version, url_template, digest) in deps.items():
        upper = name.upper()
        lines += [f'set({upper}_VERSION "{version}")', f'set({upper}_URL_HASH "SHA256={digest}")', f'set({upper}_URL "{url_template}")']
    lines.append(extra_vars)
    for name in deps:
        if f'patches/{name}.patch' in patches:
            lines.append(f'_track_external_project_patch({name} _p _c)')
        lines += [f'ExternalProject_Add({name}', f'  URL "${{{name.upper()}_URL}}"', ')']
    files = {'CMakeLists.txt': ('\n'.join(lines) + '\n').encode(), **patches}
    return targz(top, files)


CURL_PATCH = b'diff --git a/lib/a.c b/lib/a.c\n--- a/lib/a.c\n+++ b/lib/a.c\n@@ -1 +1 @@\n-a\n+b\ndiff --git a/lib/b.c b/lib/b.c\n--- a/lib/b.c\n+++ b/lib/b.c\n@@ -1 +1 @@\n-c\n+d\n'


class CurlFixture(Fixture):
    """The synthetic engine extended with a v2 profile, its explicit lock and a tiny recipe."""

    def __init__(self, tmp):
        super().__init__(tmp)
        (self.repo / 'distribution/yt-dlp-source-curl').mkdir(parents=True)
        self.deps = {'zlib': ('1.3.1', 'zlib-1.3.1.tar.gz', 'https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz'),
                     'curl': ('curl-8_21_0', 'curl-8_21_0.tar.gz', 'https://github.com/curl/curl/archive/${CURL_VERSION}.tar.gz')}
        inputs = [r for r in self.profile['inputs']]
        extra = {
            'sdist:pycparser': ('sdist', 'pycparser', 'shipped-source', '3.0', 'pycparser-3.0.tar.gz', targz('pycparser-3.0', {'LICENSE': b'BSD'})),
            'sdist:cffi': ('sdist', 'cffi', 'shipped-source', '2.1.1', 'cffi-2.1.1.tar.gz', targz('cffi-2.1.1', {'LICENSE': b'MIT'})),
            'sdist:curl-cffi': ('sdist', 'curl-cffi', 'shipped-source', '0.16.0', 'curl_cffi-0.16.0.tar.gz', targz('curl_cffi-0.16.0', {'LICENSE': b'MIT'})),
            'tool:cmake': ('tool-source', 'cmake', 'build-tool', '4.4.3', 'cmake-4.4.3.tar.gz', targz('cmake-4.4.3', {'bootstrap': b'#!/bin/sh\n'})),
            'tool:ninja': ('tool-source', 'ninja', 'build-tool', '1.13.2', 'v1.13.2.tar.gz', targz('ninja-1.13.2', {'CMakeLists.txt': b''})),
            'curl:zlib': ('curl-dep', 'zlib', 'shipped-source', '1.3.1', 'zlib-1.3.1.tar.gz', targz('zlib-1.3.1', {'LICENSE': b'zlib'})),
            'curl:curl': ('curl-dep', 'curl', 'shipped-source', '8.21.0', 'curl-8_21_0.tar.gz', targz('curl-curl-8_21_0', {'COPYING': b'curl'})),
        }
        for ident, (kind, package, role, version, file, data) in extra.items():
            self.write_source(file, data)
            url = f'https://example.invalid/{file}'
            if ident.startswith('curl:'):
                name = ident.split(':')[1]
                url = self.deps[name][2].replace('${ZLIB_VERSION}', '1.3.1').replace('${CURL_VERSION}', 'curl-8_21_0')
            inputs.append({'id': ident, 'kind': kind, 'role': role, 'package': package, 'version': version, 'file': file, 'url': url,
                           'sha256': digest(data), 'bytes': len(data)})
        self.inputs = inputs
        self.patches = {'patches/curl.patch': CURL_PATCH, 'patches/OpenBSD.patch': b'unused\n'}
        self.write_recipe()
        self.write_curl_profile()
        (self.repo / 'distribution/yt-dlp-source-curl/.python-version').write_text('3.13.14\n')
        (self.repo / 'distribution/yt-dlp-source-curl/pyproject.toml').write_text(
            '[project]\nname = "x"\nversion = "0"\nrequires-python = "==3.13.*"\n'
            'dependencies = ["yt-dlp[default,curl-cffi,pin-curl-cffi]==2026.8.19", "pyinstaller==6.22.0"]\n')
        (self.repo / 'distribution/yt-dlp-source-curl/README.md').write_text('# curl fixture\n')
        self.write_curl_lock()

    def write_recipe(self, extra_vars='', patches=None, hashes=None):
        data = recipe_archive({n: (v[0], v[2], (hashes or {}).get(n, self.row_of(self.inputs, f'curl:{n}')['sha256'])) for n, v in self.deps.items()},
                              patches if patches is not None else self.patches, extra_vars)
        self.write_source('ec41b71ce888806bfec56ada7a7258d333eb3d19.tar.gz', data)
        rows = [r for r in self.inputs if r['id'] != 'curl-impersonate']
        rows.append({'id': 'curl-impersonate', 'kind': 'curl-recipe', 'role': 'shipped-source', 'package': 'curl-impersonate', 'version': '2.0.0',
                     'file': 'ec41b71ce888806bfec56ada7a7258d333eb3d19.tar.gz',
                     'url': 'https://github.com/lexiforest/curl-impersonate/archive/ec41b71ce888806bfec56ada7a7258d333eb3d19.tar.gz',
                     'sha256': digest(data), 'bytes': len(data)})
        self.inputs = rows
        self.recipe = data

    @staticmethod
    def row_of(rows, ident):
        return next(r for r in rows if r['id'] == ident)

    def write_curl_profile(self, mutate=None):
        profile = json.loads(json.dumps(REAL_CURL_PROFILE))
        profile['inputs'] = self.inputs
        profile['native'] = self.profile['native']
        profile['packages'] = {'build_order': ['altgraph', 'pyinstaller', 'mutagen', 'pycparser', 'cffi', 'curl-cffi', 'yt-dlp-ejs', 'yt-dlp'],
                               'environment': {}, 'native': ['pyinstaller', 'cffi', 'curl-cffi']}
        profile['tools'] = [{**t, 'steps': [['/usr/bin/true']]} for t in profile['tools']]
        cur = profile['impersonate']
        cur['dependencies'] = [{'input': f'curl:{n}', 'project': n, 'url_variable': f'{n.upper()}_URL', 'hash_variable': f'{n.upper()}_URL_HASH'} for n in self.deps]
        cur['recipe_files'] = {'CMakeLists.txt': digest(archive_member(self.recipe, 'CMakeLists.txt'))}
        cur['patches'] = {'patches/curl.patch': digest(CURL_PATCH)}
        cur['unused_patches'] = {'patches/OpenBSD.patch': digest(b'unused\n')}
        cur['steps'] = [['/usr/bin/true']]
        if mutate:
            mutate(profile)
        self.curl_profile = profile
        (self.repo / source.CURL_PROFILE_REL).write_text(json.dumps(profile, indent=1))

    def write_curl_lock(self):
        def sdist(ident):
            row = self.row_of(self.inputs, ident)
            return f'sdist = {{ url = "https://files.example/{row["file"]}", hash = "sha256:{row["sha256"]}", size = {row["bytes"]} }}'
        packages = [('yt-dlp', '2026.8.19', 'sdist:yt-dlp', None), ('mutagen', '1.48.1', 'sdist:mutagen', None), ('yt-dlp-ejs', '0.8.0', 'sdist:yt-dlp-ejs', None),
                    ('curl-cffi', '0.16.0', 'sdist:curl-cffi', '[{ name = "cffi" }]'), ('cffi', '2.1.1', 'sdist:cffi', '[{ name = "pycparser", marker = "implementation_name != \'PyPy\'" }]'),
                    ('pycparser', '3.0', 'sdist:pycparser', None), ('pyinstaller', '6.22.0', 'sdist:pyinstaller', '[{ name = "altgraph" }]'),
                    ('altgraph', '0.17.5', 'sdist:altgraph', None)]
        text = 'version = 1\n'
        for name, version, ident, deps in packages:
            text += f'[[package]]\nname = "{name}"\nversion = "{version}"\n{sdist(ident)}\n'
            if deps:
                text += f'dependencies = {deps}\n'
            if name == 'yt-dlp':
                text += ('[package.optional-dependencies]\ndefault = [{ name = "mutagen" }, { name = "yt-dlp-ejs" }]\n'
                         'curl-cffi = [{ name = "curl-cffi", marker = "implementation_name == \'cpython\'" }]\n'
                         'pin-curl-cffi = [{ name = "cffi", marker = "implementation_name == \'cpython\'" }, { name = "curl-cffi", marker = "implementation_name == \'cpython\'" }, '
                         '{ name = "pycparser", marker = "implementation_name == \'cpython\'" }]\n')
        (self.repo / 'distribution/yt-dlp-source-curl/uv.lock').write_text(text)

    def curl_plan(self, name='curl-plan.json'):
        path = self.tmp / name
        path.write_bytes(source.json_bytes(source.make_plan(self.repo, self.sources, source.CURL_PROFILE_REL)))
        return path


def archive_member(data, rel):
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = next(m for m in tar.getmembers() if m.name.split('/', 1)[1:] == [rel])
        return tar.extractfile(member).read()


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class CurlPlanGuards(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.fx = CurlFixture(Path(self.dir.name).resolve())

    def tearDown(self):
        self.dir.cleanup()

    def refused(self, pattern, function, *args):
        with self.assertRaisesRegex(ValueError, pattern):
            function(*args)

    def plan_refused(self, pattern):
        self.refused(pattern, source.make_plan, self.fx.repo, self.fx.sources, source.CURL_PROFILE_REL)

    def test_curl_plan_binds_profile_recipe_and_explicit_lock(self):
        plan = source.make_plan(self.fx.repo, self.fx.sources, source.CURL_PROFILE_REL)
        self.assertEqual(plan['profile_file'], source.CURL_PROFILE_REL)
        self.assertEqual(plan['impersonate']['patches'], {'patches/curl.patch': {'sha256': digest(CURL_PATCH), 'files': 2}})
        self.assertEqual([d['project'] for d in plan['impersonate']['dependencies']], ['curl', 'zlib'])
        self.assertIn('engine/distribution/yt-dlp-source-curl/uv.lock', plan['files'])
        self.assertNotIn('engine/distribution/yt-dlp/uv.lock', plan['files'])
        self.assertFalse(any(r['adjusted'] for r in plan['lock']['packages']))
        self.assertIn('curl-cffi', [r['package'] for r in plan['lock']['packages']])
        self.assertIn('libtool', plan['toolchain'])
        self.assertIsNone(source.HOST_PATH.search(source.canonical(plan)))
        # Plans without a profile name predate v2 and mean the lean profile; nothing else is accepted.
        self.assertEqual(source.plan_profile({}), source.PROFILE_REL)
        self.refused('unknown profile', source.plan_profile, {'profile_file': 'distribution/other/profile.json'})
        self.refused('Unknown profile', source.make_plan, self.fx.repo, self.fx.sources, 'distribution/other/profile.json')

    def test_recipe_pins_patches_and_dependencies_are_enforced(self):
        with self.subTest('patch pin'):
            self.fx.write_curl_profile(lambda p: p['impersonate']['patches'].update({'patches/curl.patch': '00' * 32}))
            self.plan_refused('recipe file differs from its pin')
        with self.subTest('unpinned patch file'):
            self.fx.write_recipe(patches={**self.fx.patches, 'patches/extra.patch': CURL_PATCH})
            self.fx.write_curl_profile()
            self.plan_refused('Unpinned curl-impersonate patch files')
        with self.subTest('recipe URL_HASH'):
            self.fx.write_recipe(hashes={'zlib': '11' * 32})
            self.fx.write_curl_profile()
            self.plan_refused('zlib: the recipe URL_HASH differs from the pinned input')
        with self.subTest('extra recipe dependency'):
            self.fx.write_recipe(extra_vars='set(LIBIDN2_URL_HASH "SHA256=' + '22' * 32 + '")')
            self.fx.write_curl_profile()
            self.plan_refused('Superbuild dependencies differ from the profile')
        with self.subTest('dependency bytes'):
            self.fx.write_recipe()
            self.fx.write_curl_profile()
            source.make_plan(self.fx.repo, self.fx.sources, source.CURL_PROFILE_REL)
            self.fx.write_source('zlib-1.3.1.tar.gz', b'prebuilt or tampered')
            self.plan_refused('Input digest or size mismatch')

    def test_profile_refuses_prebuilt_and_unsafe_curl_inputs(self):
        vendor = {'id': 'curl:vendor', 'kind': 'curl-dep', 'role': 'shipped-source', 'package': 'libcurl-impersonate', 'version': '2.0.0',
                  'file': 'libcurl-impersonate-v2.0.0.arm64-macos.tar.gz', 'url': 'https://example.invalid/libcurl-impersonate-v2.0.0.arm64-macos.tar.gz',
                  'sha256': 'ab' * 32, 'bytes': 13466475}
        wheel_row = {'id': 'tool:curl-cffi-wheel', 'kind': 'wheel', 'role': 'build-tool', 'package': 'curl-cffi', 'version': '0.16.0',
                     'file': 'curl_cffi-0.16.0-cp310-abi3-macosx_11_0_arm64.whl', 'url': 'https://example.invalid/curl_cffi-0.16.0-cp310-abi3-macosx_11_0_arm64.whl',
                     'sha256': 'cd' * 32, 'bytes': 2780341}
        cases = [
            (lambda p: p['inputs'].append(vendor), 'Every curl dependency input needs exactly one recipe entry'),
            (lambda p: p['inputs'].append(wheel_row), 'Prebuilt platform wheel refused'),
            (lambda p: p['impersonate']['binding']['lookup_prefixes'].append('_CF'), 'only be allowed for the Python C API'),
            (lambda p: p['impersonate']['binding']['linked'].append('/opt/homebrew/lib/libcurl-impersonate.dylib'), 'may link only OS libraries'),
            (lambda p: p['impersonate']['binding'].update(build_requires=['yt-dlp']), 'build requirements must be built first'),
            (lambda p: p['impersonate']['binding']['environment'].pop('IMPERSONATE_BUILD_DIR'), 'Invalid curl binding environment'),
            (lambda p: p['impersonate']['patches'].update({'../curl.patch': '00' * 32}), 'relative|Patches must be pinned'),
            (lambda p: p['expected']['impersonate_targets'].append(p['expected']['impersonate_targets'][0]), 'Invalid expected impersonate targets'),
            (lambda p: p['expected']['fixture'].append({'target': 'chrome', 'encoding': 'compress'}), 'Invalid fixture cases'),
            (lambda p: self.fx.row_of(p['inputs'], 'tool:cmake').update(role='shipped-source'), 'Invalid build-tool source|must be source archives'),
            (lambda p: p['tools'].pop(), 'Every tool source needs exactly one recipe'),
            (lambda p: p['impersonate']['release'].update(tool='/opt/homebrew/bin/libtool'), 'Invalid release section'),
            (lambda p: p['impersonate']['environment'].update(CFLAGS='-O0 -DCURL_DISABLE_VERIFY'), 'may only remap source paths'),
            (lambda p: p['impersonate']['environment'].update(LDFLAGS='-L/opt/homebrew/lib'), 'may only remap source paths'),
        ]
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                profile = json.loads(json.dumps(self.fx.curl_profile))
                mutate(profile)
                path = self.fx.tmp / 'profile.json'
                path.write_text(json.dumps(profile))
                self.refused(pattern, source.load_profile, path)
        lean = json.loads(json.dumps(self.fx.profile))
        lean['inputs'].append(self.fx.row_of(self.fx.inputs, 'curl:zlib'))
        path = self.fx.tmp / 'lean.json'
        path.write_text(json.dumps(lean))
        self.refused('needs the v2 profile schema', source.load_profile, path)

    def test_explicit_lock_mismatches(self):
        lock = self.fx.repo / 'distribution/yt-dlp-source-curl/uv.lock'
        good = lock.read_text()
        lock.write_text(good.replace('version = "0.16.0"', 'version = "0.16.1"'))
        self.plan_refused('curl-cffi 0.16.0 differs from the explicit profile lock 0.16.1')
        lock.write_text(good)
        pyproject = self.fx.repo / 'distribution/yt-dlp-source-curl/pyproject.toml'
        pyproject.write_text(pyproject.read_text().replace('default,curl-cffi,pin-curl-cffi', 'default'))
        self.plan_refused('extras differ from the explicit profile')

    def test_stale_curl_plan_and_failed_build(self):
        plan = self.fx.curl_plan()
        output = self.fx.tmp / 'out'
        self.fx.write_curl_profile(lambda p: p['impersonate']['binding']['environment'].update(LDFLAGS='-framework Security'))
        with self.assertRaisesRegex(source.Stale, 'Stale plan'):
            source.build(self.fx.repo, plan, self.fx.sources, output)
        self.assertFalse(output.exists())
        self.fx.write_curl_profile(lambda p: p['tools'][0].update(steps=[['/usr/bin/false']]))
        plan = self.fx.curl_plan('curl-plan-2.json')
        with self.assertRaises(source.BuildFailed):
            source.build(self.fx.repo, plan, self.fx.sources, output)
        receipt = json.loads((output / 'receipt.json').read_text())
        self.assertEqual((receipt['status'], receipt['failure']['step'], receipt['profile_file']), ('failed', 'tool-cmake-0', source.CURL_PROFILE_REL))
        self.assertIn('/usr/bin/sandbox-exec', receipt['steps'][0]['argv'])
        self.assertFalse((output / 'bin').exists())
        self.assertNotIn('output', receipt)
        self.assertIsNone(source.HOST_PATH.search(source.canonical(receipt)))
        self.refused('built receipt', source.make_kit, self.fx.repo, plan, self.fx.sources, output, self.fx.tmp / 'kit.tar.gz')


GOOD_PATCH_LOG = """[3/9] Performing download step (verify and extract) for 'zlib'
[4/9] Performing patch step for 'curl'
patching file lib/a.c
patching file lib/b.c
[5/9] Performing configure step for 'curl'
-- Performing Test HAVE_FILE_OFFSET_BITS - Success
"""


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class CurlEvidenceGuards(unittest.TestCase):
    PATCHES = {'patches/curl.patch': {'sha256': 'ab' * 32, 'files': 2}}

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()

    def tearDown(self):
        self.dir.cleanup()

    def test_patches_must_apply_exactly(self):
        self.assertEqual(source.check_patch_log(GOOD_PATCH_LOG, self.PATCHES), {'curl': {'files': 2, 'sha256': 'ab' * 32}})
        bad = {
            'fuzz': GOOD_PATCH_LOG.replace('patching file lib/b.c', 'patching file lib/b.c\nHunk #1 succeeded at 7 with fuzz 2.'),
            'offset': GOOD_PATCH_LOG.replace('patching file lib/b.c', 'patching file lib/b.c\nHunk #1 succeeded at 9 (offset 2 lines).'),
            'failed': GOOD_PATCH_LOG.replace('patching file lib/b.c', 'patching file lib/b.c\nHunk #1 FAILED at 1.\n1 out of 1 hunk FAILED -- saving rejects to file lib/b.c.rej'),
            'missing file': GOOD_PATCH_LOG.replace('patching file lib/b.c\n', ''),
            'unpinned project': GOOD_PATCH_LOG + "[6/9] Performing patch step for 'zlib'\npatching file zlib.h\n",
            'not run': GOOD_PATCH_LOG.replace("Performing patch step for 'curl'", "No patch step for 'curl'"),
        }
        for label, text in bad.items():
            with self.subTest(label):
                with self.assertRaises(ValueError):
                    source.check_patch_log(text, self.PATCHES)

    def objects(self, *specs):
        rows = []
        for name, arch, minimum in specs:
            src = self.tmp / f'{name}.c'
            src.write_text(f'int {name}(void) {{ return 1; }}\n')
            out = self.tmp / f'{name}-{arch}-{minimum}.o'
            subprocess.run(['/usr/bin/xcrun', 'clang', '-arch', arch, f'-mmacosx-version-min={minimum}', '-c', src, '-o', out], check=True, capture_output=True)
            rows.append(out)
        return rows

    def archive(self, name, members, tool='libtool'):
        out = self.tmp / name
        argv = ['/usr/bin/libtool', '-static', '-o', out, *members] if tool == 'libtool' else ['/usr/bin/ar', '-rcs', out, *members]
        subprocess.run(argv, check=True, capture_output=True, env={**os.environ, 'ZERO_AR_DATE': '1'})
        return out

    def test_release_archive_holds_exactly_the_recorded_members(self):
        a, b, c = self.objects(('alpha', 'arm64', '13.5'), ('beta', 'arm64', '13.5'), ('gamma', 'arm64', '13.5'))
        first, second = self.archive('libfirst.a', [a, b]), self.archive('libsecond.a', [c])
        merged = self.archive('libmerged.a', [first, second])
        report = source.check_release_archive(merged, [first, second], '13.5')
        self.assertEqual((report['members'], sorted(report['inputs'])), (3, ['libfirst.a', 'libsecond.a']))
        foreign, = self.objects(('foreign', 'arm64', '13.5'))
        intel, = self.objects(('intel', 'x86_64', '13.5'))
        newer, = self.objects(('newer', 'arm64', '15.0'))
        cases = {'extra prebuilt object': (self.archive('extra.a', [first, second, foreign]), [first, second], 'differ from its recorded inputs'),
                 'missing member': (self.archive('short.a', [first]), [first, second], 'differ from its recorded inputs'),
                 'foreign architecture': (self.archive('intel.a', [intel], 'ar'), [self.archive('in-intel.a', [intel], 'ar')], 'not an arm64 object'),
                 'universal archive': (self.archive('fat.a', [first, intel]), [first], 'not an ar archive'),
                 'newer minimum': (self.archive('newer.a', [first, newer]), [first, self.archive('in-newer.a', [newer])], 'another macOS minimum')}
        for label, (archive, inputs, pattern) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, pattern):
                    source.check_release_archive(archive, inputs, '13.5')
        (self.tmp / 'not-ar.a').write_bytes(b'prebuilt')
        with self.assertRaisesRegex(ValueError, 'not an ar archive'):
            source.check_release_archive(self.tmp / 'not-ar.a', [first], '13.5')

    def test_curl_features_and_impersonation_capabilities(self):
        check = REAL_CURL_PROFILE['impersonate']['check']
        line = 'curl 8.21.0-IMPERSONATE (Darwin) ' + ' '.join(check['version_components'])
        good = f'{line}\nRelease-Date: [unreleased]\nProtocols: http https\nFeatures: ' + ' '.join(check['features']) + '\n'
        self.assertEqual(source.check_curl_version(good, check)['components'], check['version_components'])
        with self.assertRaisesRegex(ValueError, 'features differ'):
            source.check_curl_version(good.replace(' HTTP3', ''), check)
        with self.assertRaisesRegex(ValueError, 'components differ'):
            source.check_curl_version(good.replace('nghttp2/1.63.0', 'nghttp2/1.65.0'), check)
        expected = REAL_CURL_PROFILE['expected']
        table = ['[info] Available impersonate targets', 'Client          OS           Source', '-' * 38]
        table += [f'{client:<16}{system:<13}curl_cffi' for client, system in expected['impersonate_targets']]
        verbose = {'Request Handlers': expected['request_handlers'], 'Optional libraries': expected['optional_libraries']}
        report = source.check_capabilities(expected, table, verbose)
        self.assertEqual((report['targets'], report['families']), (37, ['Chrome', 'Edge', 'Firefox', 'Safari', 'Tor']))
        cases = {'missing target': (table[:-1], verbose, 'Missing impersonate targets'),
                 'unavailable target': (table[:-1] + [table[-1].replace('curl_cffi', 'curl_cffi (unavailable)')], verbose, 'Unavailable impersonate targets'),
                 'lean default build': (table[:3] + ['Chrome    -    curl_cffi (unavailable)'], verbose, 'Unavailable impersonate targets'),
                 'reordered': (table[:3] + table[4:] + table[3:4], verbose, 'differ from the expected list'),
                 'no curl handler': (table, {**verbose, 'Request Handlers': ['urllib', 'requests', 'websockets']}, 'Request handlers differ'),
                 'no curl library': (table, {**verbose, 'Optional libraries': [x for x in expected['optional_libraries'] if 'curl' not in x]}, 'Optional libraries differ')}
        for label, (lines, header, pattern) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, pattern):
                    source.check_capabilities(expected, lines, header)

    def binding_log(self, archive, generated='build/temp.macosx-13.5-arm64-cpython-313/curl_cffi._wrapper.c', extra=''):
        obj = 'build/temp.macosx-13.5-arm64-cpython-313'
        return (f'  Using {archive.parent} to store libcurl-impersonate\n  libcurl-impersonate: {archive} already downloaded.\n'
                f"  generating cffi module '{generated}'\n"
                f'  /usr/bin/clang -O3 -Iinclude -c {generated} -o {obj}/{obj}/curl_cffi._wrapper.o\n'
                f'  /usr/bin/clang -O3 -Iinclude -c ffi/shim.c -o {obj}/ffi/shim.o\n'
                f'  /usr/bin/clang -bundle -undefined dynamic_lookup {obj}/{obj}/curl_cffi._wrapper.o {obj}/ffi/shim.o -o build/lib.macosx-13.5-arm64-cpython-313/curl_cffi/_wrapper.abi3.so '
                f'-Wl,-force_load,{archive} -lc++\n{extra}')

    def test_binding_log_refuses_the_prebuilt_fallback(self):
        archive = self.tmp / 'release' / 'libcurl-impersonate.a'
        compiles, link, generated, product = source.binding_log_facts(self.binding_log(archive), archive, 'curl_cffi/_wrapper.abi3.so')
        self.assertEqual((len(compiles), generated, product.split('/')[-1]), (2, 'build/temp.macosx-13.5-arm64-cpython-313/curl_cffi._wrapper.c', '_wrapper.abi3.so'))
        vendor = self.tmp / 'tmplibdir' / 'libcurl-impersonate.a'
        cases = {
            'download fallback': (self.binding_log(archive).replace(f'libcurl-impersonate: {archive} already downloaded.',
                                  'Downloading libcurl-impersonate from https://github.com/lexiforest/curl-impersonate/releases/download/v2.0.0/x.tar.gz...'), 'did not find'),
            'download after find': (self.binding_log(archive, extra='Downloading libcurl-impersonate from https://example.invalid\n'), 'download fallback'),
            'another archive': (self.binding_log(vendor), 'did not find'),
            'no force_load': (self.binding_log(archive).replace(f'-Wl,-force_load,{archive}', '-lcurl-impersonate'), 'does not force-load'),
            'extra source': (self.binding_log(archive, extra='  /usr/bin/clang -c ffi/extra.c -o build/extra.o\n'), 'Expected two compiles'),
            'generated twice': (self.binding_log(archive).replace("generating cffi module", "generated elsewhere"), 'wrapper source was not found once'),
        }
        for label, (text, pattern) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(ValueError, pattern):
                    source.binding_log_facts(text, archive, 'curl_cffi/_wrapper.abi3.so')

    def test_fixture_refusals_must_be_certificate_errors(self):
        long = ("ERROR: [generic] watch: Unable to download webpage: Failed to perform, curl: (60) SSL certificate OpenSSL verify result: unable to get "
                "local issuer certificate (20). See https://curl.se/libcurl/c/libcurl-errors.html first for more details. (caused by CertificateVerifyError("
                "'Failed to perform, curl: (60) ...')); please report this issue on  https://github.com/yt-dlp/yt-dlp/issues?q= , filling out the "
                "appropriate issue template. Confirm you are on the latest version using  yt-dlp -U")
        tail = ['[generic] Extracting URL: https://localhost:1/watch', '[generic] watch: Downloading webpage', long]
        row = {'exit': 1, 'found_video': False, 'error': source.error_line(tail)}
        source.check_refusal(row, 'An untrusted certificate')
        with self.assertRaisesRegex(ValueError, 'was accepted'):
            source.check_refusal({**row, 'exit': 0, 'found_video': True}, 'An untrusted certificate')
        with self.assertRaisesRegex(ValueError, 'failed for another reason'):
            source.check_refusal({**row, 'error': source.error_line(['ERROR: [generic] watch: Unable to download webpage: curl: (7) Failed to connect'])},
                                 'An untrusted certificate')

    def test_dynamic_lookup_inventory(self):
        text = ('                 (undefined) external _CFRelease (from CoreFoundation)\n'
                '                 (undefined) external _PyLong_FromLong (dynamically looked up)\n'
                '                 (undefined) weak external __Py_NoneStruct (dynamically looked up)\n')
        self.assertEqual(source.dynamic_lookups(text), ({'CoreFoundation': 1}, ['_PyLong_FromLong', '__Py_NoneStruct']))
        flat = source.dynamic_lookups(text + '                 (undefined) external _SecTrustCreateWithCertificates (dynamically looked up)\n')[1]
        self.assertFalse(all(s.startswith(tuple(REAL_CURL_PROFILE['impersonate']['binding']['lookup_prefixes'])) for s in flat))
        with self.assertRaisesRegex(ValueError, 'Unparsed'):
            source.dynamic_lookups(text + 'garbage line\n')

    def test_unreviewed_generated_sources_fail_closed(self):
        sources = self.tmp / 'sources'
        sources.mkdir()
        tool = wheel({'vcs_versioning/_dump_version.py': b'TEMPLATE', 'vcs_versioning-2.3.1.dist-info/licenses/LICENSE.txt': b'MIT'})
        (sources / 'vcs_versioning-2.3.1-py3-none-any.whl').write_bytes(tool)
        profile = {'inputs': [{'id': 'tool:vcs-versioning', 'kind': 'wheel', 'package': 'vcs-versioning', 'version': '2.3.1',
                               'file': 'vcs_versioning-2.3.1-py3-none-any.whl', 'sha256': digest(tool)}]}
        owner = {'version': '0.8.0', 'sha256': 'ef' * 32}
        row = source.generated_provenance(profile, sources, 'yt-dlp-ejs', 'yt_dlp_ejs/_version.py', 'aa' * 32, [], owner)
        self.assertEqual((row['kind'], row['generator']['package'], row['output_sha256']), ('wheel-build-generated', 'vcs-versioning', 'aa' * 32))
        for package, rel in (('curl-cffi', 'curl_cffi/_version.py'), ('yt-dlp-ejs', 'yt_dlp_ejs/other.py'), ('cffi', 'cffi/_generated.py')):
            with self.subTest(rel):
                with self.assertRaisesRegex(source.Refused, 'neither an sdist member nor a reviewed generated output'):
                    source.generated_provenance(profile, sources, package, rel, 'bb' * 32, [], owner)


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class LoopbackFixture(unittest.TestCase):
    """The fixture used by the curl build's runtime smoke: normal validation against a
    throwaway CA, ClientHello capture and content encodings, on the loopback interface."""

    def test_validation_capture_and_encodings(self):
        import socket
        import ssl
        import ytdlp_source_fixture as fixture
        with tempfile.TemporaryDirectory() as folder:
            pki = fixture.pki(Path(folder).resolve() / 'pki')

            def fetch(server, cafile=None, host='localhost'):
                context = ssl.create_default_context(cafile=str(cafile)) if cafile else ssl.create_default_context()
                context.set_alpn_protocols(['http/1.1'])
                with socket.create_connection(('127.0.0.1', server.port), timeout=10) as raw, context.wrap_socket(raw, server_hostname=host) as conn:
                    conn.sendall(b'GET /watch HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n')
                    data = b''
                    while chunk := conn.recv(65536):
                        data += chunk
                return data

            with fixture.Server(*pki['leaf'], encoding='gzip') as server:
                head, body = fetch(server, pki['ca']).split(b'\r\n\r\n', 1)
                self.assertIn(b'Content-Encoding: gzip', head)
                self.assertEqual(zlib.decompress(body, 31), fixture.PAGE)
                hello = server.connections[0]['client_hello']
                self.assertEqual((hello['sni'], hello['alpn'], server.connections[0]['alpn']), ('localhost', ['http/1.1'], 'http/1.1'))
                self.assertRegex(hello['fingerprint_sha256'], '^[0-9a-f]{64}$')
                with self.assertRaises(ssl.SSLCertVerificationError):
                    fetch(server)
            with fixture.Server(*pki['wrong']) as server:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    fetch(server, pki['ca'])
        self.assertEqual(zlib.decompress(fixture.encode(fixture.PAGE, 'deflate')), fixture.PAGE)
        frame = fixture.encode(fixture.PAGE, 'zstd')
        self.assertEqual((frame[:4], frame[4], frame[-len(fixture.PAGE):]), (b'\x28\xb5\x2f\xfd', 0x60, fixture.PAGE))
        self.assertEqual(struct.unpack('<H', frame[5:7])[0] + 256, len(fixture.PAGE))
        with self.assertRaises(ValueError):
            fixture.encode(fixture.PAGE, 'compress')
        self.assertEqual(fixture.label(0x3a3a), 'GREASE')
        self.assertEqual(fixture.label(0x1301), 0x1301)


@unittest.skipUnless(NATIVE, 'requires an arm64 macOS host with Xcode')
class CurlKitGuards(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.dir.name).resolve()
        self.fx = CurlFixture(self.tmp)
        self.plan = self.fx.curl_plan()
        self.build = self.tmp / 'build'
        generated = self.build / 'work/src/sdist-curl-cffi/curl_cffi-0.16.0/build/temp.macosx-13.5-arm64-cpython-313/curl_cffi._wrapper.c'
        generated.parent.mkdir(parents=True)
        generated.write_bytes(b'/* generated by cffi */\n')
        fingerprints = source.json_bytes({'schema': source.FINGERPRINTS_SCHEMA, 'rows': [{'kind': 'pyz', 'name': 'x', 'code_sha256': 'cd' * 32}]})
        (self.build / source.FINGERPRINTS).write_bytes(fingerprints)
        self.base = {'schema': source.RECEIPT_SCHEMA, 'status': 'built', 'plan_sha256': source.file_sha(self.plan), 'output': {'sha256': 'ab' * 32},
                     'closure': {'python': {'fingerprints': {'file': source.FINGERPRINTS, 'sha256': digest(fingerprints)}}},
                     'impersonate': {'release': {'sha256': 'ef' * 32}},
                     'curl_binding': {'replay': 'identical', 'generated_source': {'path': 'build/temp.macosx-13.5-arm64-cpython-313/curl_cffi._wrapper.c',
                                                                                 'sha256': digest(b'/* generated by cffi */\n')}}}

    def tearDown(self):
        self.dir.cleanup()

    def receipt(self, value):
        (self.build / 'receipt.json').write_bytes(source.json_bytes(value))

    def test_curl_kit_carries_patches_generated_source_and_proofs(self):
        self.receipt(self.base)
        kit = self.tmp / 'kit.tar.gz'
        made = source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, kit)
        report = source.verify_kit(kit, made['sha256'])
        self.assertTrue(report['verified'])
        with tarfile.open(kit) as tar:
            names = {n.split('/', 1)[1] for n in tar.getnames()}
            index = json.loads(tar.extractfile(f'{source.KIT_PREFIX}/KIT-INDEX.json').read())
        for name in ('patches/curl-impersonate/curl.patch', 'generated/curl_cffi/curl_cffi._wrapper.c', 'engine/distribution/yt-dlp-source-curl/uv.lock',
                     'engine/distribution/yt-dlp-source-curl/profile.json', 'engine/scripts/ytdlp_source_fixture.py', 'sources/zlib-1.3.1.tar.gz',
                     'sources/cmake-4.4.3.tar.gz', 'terms/curl-zlib/zlib-1.3.1/LICENSE', 'terms/curl-curl/curl-curl-8_21_0/COPYING'):
            self.assertIn(name, names)
        self.assertIn('engine/distribution/yt-dlp-source/profile.json', names)  # the bundled tests load both profiles
        self.assertEqual(index['profile_file'], source.CURL_PROFILE_REL)
        for label, receipt in (('no binding proof', {k: v for k, v in self.base.items() if k != 'curl_binding'}),
                               ('changed generated source', {**self.base, 'curl_binding': {**self.base['curl_binding'],
                                                             'generated_source': {**self.base['curl_binding']['generated_source'], 'sha256': '00' * 32}}})):
            with self.subTest(label):
                self.receipt(receipt)
                with self.assertRaises(ValueError):
                    source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, self.tmp / f'kit-{label}.tar.gz')
                    source.verify_kit(self.tmp / f'kit-{label}.tar.gz')

    def test_delivery_rows_bind_actual_archive_bytes(self):
        self.receipt(self.base)
        kit = self.tmp / 'delivery.tar.gz'
        source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, kit)
        with tarfile.open(kit) as tar:
            members = {m.name.split('/', 1)[1]: tar.extractfile(m).read() for m in tar}
        original = json.loads(members['KIT-INDEX.json'])
        for category in ('generated_sources', 'patches', 'terms'):
            target = original[category][0]['path']
            for mode in ('removed', 'substituted'):
                with self.subTest(category=category, mode=mode):
                    changed = dict(members)
                    index = json.loads(members['KIT-INDEX.json'])
                    if mode == 'removed':
                        del changed[target]
                        index['files'] = [r for r in index['files'] if r['path'] != target]
                    else:
                        changed[target] = b'substituted delivery bytes'
                        for row in index['files']:
                            if row['path'] == target:
                                row.update(sha256=digest(changed[target]), bytes=len(changed[target]))
                    changed['KIT-INDEX.json'] = source.json_bytes(index)
                    bad = self.tmp / f'{category}-{mode}.tar.gz'
                    with tarfile.open(bad, 'w:gz') as tar:
                        for name, data in sorted(changed.items()):
                            info = tarfile.TarInfo(f'{source.KIT_PREFIX}/{name}')
                            info.size = len(data)
                            tar.addfile(info, io.BytesIO(data))
                    # Both the file inventory and caller's archive digest are consistent;
                    # the independent delivery row must still bind the delivered bytes.
                    with self.assertRaisesRegex(ValueError, 'delivery member'):
                        source.verify_kit(bad, source.file_sha(bad))

    def test_split_parts_rejoin_and_refuse_tampering(self):
        self.receipt(self.base)
        kit = self.tmp / 'kit.tar.gz'
        made = source.make_kit(self.fx.repo, self.plan, self.fx.sources, self.build, kit)
        with self.assertRaisesRegex(ValueError, 'between 1 MiB and 256 MiB'):
            source.split_kit(kit, self.tmp / 'too-big', 512 * 1024**2)
        split = source.split_kit(kit, self.tmp / 'parts', 1024**2)
        self.assertEqual(split['kit_sha256'], made['sha256'])
        joined = source.join_kit(self.tmp / 'parts', self.tmp / 'joined.tar.gz')
        self.assertEqual((joined['sha256'], (self.tmp / 'joined.tar.gz').read_bytes()), (made['sha256'], kit.read_bytes()))
        part = sorted((self.tmp / 'parts').glob('*.part*'))[0]
        data = bytearray(part.read_bytes())
        data[len(data) // 2] ^= 0xff
        part.write_bytes(bytes(data))
        with self.assertRaisesRegex(ValueError, 'differs from its manifest'):
            source.join_kit(self.tmp / 'parts', self.tmp / 'joined-2.tar.gz')
        (self.tmp / 'parts' / 'extra.bin').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'Unexpected files'):
            source.join_kit(self.tmp / 'parts', self.tmp / 'joined-3.tar.gz')


if __name__ == '__main__':
    unittest.main(verbosity=2)
