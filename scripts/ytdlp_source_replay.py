"""Replay helper for the controlled-source closure proof (omd-ytdlp-source-replay-v1).

`scripts/ytdlp_source.py` runs this file as a separate process under the build's runtime
environment, which is the built CPython with only the wheels built from pinned sdists.
Each command reads a JSON job and writes a new JSON result:

code     Compile every expected source as PyInstaller 6.22.0 does and apply its
         co_filename replacement. Compare the result with the packed code object as
         marshal version 2 data, which has no reference or interning flags. Also
         re-serialize base_library.zip with PyInstaller's writer steps.
natives  Run PyInstaller's own process_collected_binary on private copies of recorded
         build products.
onefile  Run the macOS steps of PyInstaller's EXE.assemble on a private copy of the
         compiled bootloader and the executable's own PKG bytes.

Packed code objects are only unmarshalled and compared. Nothing taken from the
executable is imported, executed or loaded. The PyInstaller files whose logic is
replayed or transcribed here must match the digests pinned in the job. Only the
Python standard library is imported at module level.
"""
import ast
import hashlib
import importlib.util
import io
import json
import marshal
import os
import re
import shutil
import sys
import types
import zipfile
from pathlib import Path

SCHEMA = 'omd-ytdlp-source-replay-v1'
MAX_SOURCE = 16 * 1024**2
MAX_CODE = 32 * 1024**2
MAX_ITEMS = 65536
MAX_BASE_LIBRARY = 256 * 1024**2
MODES = ('modulegraph', 'compile-bytes')
MEMBER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*\.pyc')
CODE_FIELDS = ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize', 'co_flags', 'co_code', 'co_consts',
               'co_names', 'co_varnames', 'co_freevars', 'co_cellvars', 'co_filename', 'co_name', 'co_qualname', 'co_firstlineno',
               'co_linetable', 'co_exceptiontable')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit, digest=None):
    with open(path, 'rb') as stream:
        data = stream.read(limit + 1)
    need(len(data) <= limit, f'Input exceeds its size limit: {Path(path).name}')
    if digest is not None:
        need(sha(data) == digest, f'Input changed or differs from its recorded digest: {Path(path).name}')
    return data


def load_code(data, what):
    """Unmarshal one code object that must consume every byte (no trailing data)."""
    stream = io.BytesIO(data)
    try:
        value = marshal.load(stream)
    except (EOFError, ValueError, TypeError) as error:
        raise ValueError(f'{what}: not a marshalled code object ({error})') from error
    need(type(value) is types.CodeType, f'{what}: marshalled value is not a code object')
    need(stream.tell() == len(data), f'{what}: trailing bytes after the code object')
    return value


def pinned_pyinstaller(job):
    """The running PyInstaller must be the build's own install, with the pinned sources."""
    import PyInstaller
    root = Path(PyInstaller.__file__).resolve().parent
    need(PyInstaller.__version__ == job['pyinstaller']['version'], f'PyInstaller {PyInstaller.__version__} differs from the pinned version')
    need(root.parent == Path(job['pyinstaller']['site_packages']).resolve(), 'PyInstaller was not imported from the build runtime environment')
    found = {rel: sha((root / rel).read_bytes()) for rel in job['pyinstaller']['sources']}
    need(found == job['pyinstaller']['sources'], f'Replayed PyInstaller sources differ from the pins: {sorted(k for k in found if found[k] != job["pyinstaller"]["sources"][k])}')
    return {'version': PyInstaller.__version__, 'sources': found}


def interpreter(job):
    from PyInstaller.compat import BYTECODE_MAGIC
    want = job['interpreter']
    found = {'version': sys.version.split()[0], 'magic': importlib.util.MAGIC_NUMBER.hex(), 'cache_tag': sys.implementation.cache_tag}
    need(found == want, f'Replay interpreter {found} differs from the built CPython {want}')
    need(BYTECODE_MAGIC == importlib.util.MAGIC_NUMBER, 'PyInstaller bytecode magic differs from the interpreter')
    need(sys.flags.optimize == 0 and sys.flags.hash_randomization == 0 and sys.flags.no_user_site and sys.flags.safe_path and sys.flags.dont_write_bytecode,
         'The replay interpreter must run with -s -P -B, optimization 0 and PYTHONHASHSEED=0')
    return found


# ---------------------------------------------------------------- code


def canonical(code):
    """Marshal version 2 of the whole code object graph: every code constructor field,
    including the localsplus kinds, nested code and exact constant types and float bits,
    but no reference or interning flags, which depend on reference counts at dump time.
    Both sides are objects loaded from version 4 marshal data written under
    PYTHONHASHSEED=0, so their frozenset constants are rebuilt in the same order."""
    return marshal.dumps(code, 2)


def first_difference(a, b, path='code'):
    """Diagnostic only: the first differing field, for the refusal message."""
    if type(a) is not type(b):
        return f'{path}: type {type(a).__name__} != {type(b).__name__}'
    if type(a) is types.CodeType:
        for field in CODE_FIELDS:
            found = first_difference(getattr(a, field), getattr(b, field), f'{path}.{field}')
            if found:
                return found
        return None
    if type(a) is tuple:
        if len(a) != len(b):
            return f'{path}: length {len(a)} != {len(b)}'
        for i, (x, y) in enumerate(zip(a, b)):
            found = first_difference(x, y, f'{path}[{i}]')
            if found:
                return found
        return None
    if type(a) is frozenset:
        return None if a == b else f'{path}: frozenset members'
    if type(a) is float:
        return None if a.hex() == b.hex() and str(a) == str(b) else f'{path}: float'
    return None if marshal.dumps(a, 2) == marshal.dumps(b, 2) else f'{path}: value'


def expected_code(source, path, filename, mode):
    """PyInstaller 6.22.0's compile path, then its recursive co_filename replacement."""
    from PyInstaller.building.utils import get_code_object, replace_filename_in_code_object
    if mode == 'modulegraph':
        # lib/modulegraph/modulegraph.py ModuleGraph._load_module / _safe_import_module:
        # source from the loader (decode_source), compiled to an AST, then to code.
        tree = compile(importlib.util.decode_source(source), path, 'exec', ast.PyCF_ONLY_AST, True)
        code = compile(tree, path, 'exec', 0, True)
    else:
        # building/utils.py: compile(source bytes, path, 'exec', optimize=0), the call in
        # get_code_object (scripts, uncached modules) and compile_pymodule (bootstrap modules).
        code = get_code_object(Path(path).stem, path, optimize=0)
    return replace_filename_in_code_object(code, filename)


def compare(item, packed_bytes):
    source = read(item['source'], MAX_SOURCE, item['source_sha256'])
    packed = load_code(packed_bytes, item['id'])
    packed_canonical = canonical(packed)
    tried = []
    for mode in item['modes']:
        need(mode in MODES, f'Unknown compile mode: {mode}')
        expected = expected_code(source, item['source'], item['filename'], mode)
        # Round-trip through marshal like the packed object, then compare canonically.
        expected = marshal.loads(marshal.dumps(expected))
        expected_canonical = canonical(expected)
        tried.append(mode)
        if expected_canonical == packed_canonical:
            return {'id': item['id'], 'equal': True, 'mode': mode, 'code_sha256': sha(packed_canonical), 'co_filename': packed.co_filename}
        difference = first_difference(expected, packed)
    read(item['source'], MAX_SOURCE, item['source_sha256'])
    return {'id': item['id'], 'equal': False, 'tried': tried, 'expected_sha256': sha(expected_canonical), 'packed_sha256': sha(packed_canonical),
            'difference': difference or 'canonical encoding'}


def base_library(job):
    """Strict base_library.zip members, PyInstaller's zip writer replayed, and every
    .pyc header (bytecode magic, PEP 552 unchecked-hash flag, zero hash) checked."""
    spec = job['base_library']
    blob = read(spec['path'], MAX_BASE_LIBRARY, spec['sha256'])
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        need(archive.comment == b'', 'base_library.zip has a comment')
        infos = archive.infolist()
        need(0 < len(infos) <= MAX_ITEMS, 'base_library.zip member count out of range')
        names = [i.filename for i in infos]
        need(len(set(names)) == len(names), 'Duplicate base_library.zip member')
        members = []
        for info in infos:
            need(MEMBER.fullmatch(info.filename) and info.compress_type == zipfile.ZIP_STORED and 16 < info.file_size <= MAX_CODE,
                 f'Unexpected base_library.zip member: {info.filename}')
            members.append((info.filename, archive.read(info)))
    replay = io.BytesIO()
    with zipfile.ZipFile(replay, 'w') as archive:  # building/utils.py create_base_library_zip
        for name, data in members:
            archive.writestr(zipfile.ZipInfo(name), data)
    need(replay.getvalue() == blob, 'base_library.zip differs from PyInstaller writer output for its own members')
    need(names == spec['members'], 'base_library.zip members differ from the attributed list')
    magic = importlib.util.MAGIC_NUMBER
    rows = []
    for name, data in members:
        need(data[:4] == magic, f'{name}: bytecode magic differs from the built CPython')
        need(int.from_bytes(data[4:8], 'little') == 1 and data[8:16] == bytes(8), f'{name}: header is not the unchecked-hash header PyInstaller writes')
        rows.append(compare(spec['sources'][name], data[16:]))
    return {'members': len(members), 'sha256': spec['sha256'], 'writer_replayed': True, 'rows': rows}


def code(job):
    found = interpreter(job)
    pins = pinned_pyinstaller(job)
    need(len(job['items']) <= MAX_ITEMS, 'Too many code items')
    rows = [compare(item, read(item['packed'], MAX_CODE, item['packed_sha256'])) for item in job['items']]
    result = {'interpreter': found, 'pyinstaller': pins, 'rows': rows}
    if job.get('base_library'):
        result['base_library'] = base_library(job)
    return result


# ---------------------------------------------------------------- natives


def natives(job):
    """building/utils.py process_collected_binary with the onefile PKG arguments."""
    pins = pinned_pyinstaller(job)
    from PyInstaller.building.utils import process_collected_binary
    from PyInstaller.config import CONF
    cache = Path(job['cachedir'])
    need(cache.is_dir() and not any(cache.iterdir()), 'The replay cache must be a new empty directory')
    CONF['cachedir'] = str(cache)
    options = job['options']
    need(options == {'use_strip': False, 'use_upx': False, 'upx_exclude': [], 'codesign_identity': None, 'entitlements_file': None},
         'Only the unstripped, non-UPX, ad-hoc profile options are replayed')
    rows = []
    for item in job['items']:
        read(item['source'], 1024**3, item['source_sha256'])
        out = process_collected_binary(item['source'], item['dest'], target_arch=job['target_arch'], strict_arch_validation=item['strict'], **options)
        need(Path(out).resolve().is_relative_to(cache.resolve()), 'Processed binary outside the replay cache')
        data = Path(out).read_bytes()
        rows.append({'id': item['id'], 'output': str(out), 'sha256': sha(data), 'bytes': len(data)})
    return {'pyinstaller': pins, 'rows': rows}


# ---------------------------------------------------------------- onefile


def onefile(job):
    """building/api.py EXE.assemble, macOS onefile path, with append_pkg=True:
    copy, binary_to_target_arch, remove_signature_from_binary, update_exe_identifier,
    append the PKG, fix_exe_for_code_signing, the SDK rule against the Python library,
    then sign_binary (ad hoc)."""
    pins = pinned_pyinstaller(job)
    from PyInstaller.utils import osx as osxutils
    out = Path(job['output'])
    need(not os.path.lexists(out) and out.parent.is_dir(), 'Replay output must be a new file')
    read(job['bootloader'], 64 * 1024**2, job['bootloader_sha256'])
    read(job['pkg'], 2 * 1024**3, job['pkg_sha256'])
    read(job['python_library'], 1024**3, job['python_library_sha256'])
    shutil.copyfile(job['bootloader'], out)
    os.chmod(out, 0o755)
    osxutils.binary_to_target_arch(str(out), job['target_arch'], display_name='Bootloader EXE')
    osxutils.remove_signature_from_binary(str(out))
    osxutils.update_exe_identifier(str(out), job['pkg'])
    with open(out, 'ab') as target, open(job['pkg'], 'rb') as pkg:
        shutil.copyfileobj(pkg, target, length=64 * 1024)
    osxutils.fix_exe_for_code_signing(str(out))
    pylib_version = osxutils.get_macos_sdk_version(job['python_library'])
    exe_version = osxutils.get_macos_sdk_version(str(out))
    rewritten = pylib_version < exe_version
    if rewritten:
        osxutils.set_macos_sdk_version(str(out), *pylib_version)
    osxutils.sign_binary(str(out), None, None)
    os.chmod(out, 0o755)
    data = out.read_bytes()
    return {'pyinstaller': pins, 'output': str(out), 'sha256': sha(data), 'bytes': len(data),
            'sdk': {'python_library': list(pylib_version), 'bootloader': list(exe_version), 'rewritten': rewritten}}


COMMANDS = {'code': code, 'natives': natives, 'onefile': onefile}


def main(argv):
    need(len(argv) == 3 and argv[0] in COMMANDS, 'usage: ytdlp_source_replay.py code|natives|onefile JOB RESULT')
    job = json.loads(Path(argv[1]).read_text())
    need(job.get('schema') == SCHEMA, 'Unsupported replay job')
    result = {'schema': SCHEMA, 'command': argv[0], **COMMANDS[argv[0]](job)}
    fd = os.open(argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, sort_keys=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
