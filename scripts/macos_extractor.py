"""Signature-only preparation of a PyInstaller 6.22.0 macOS onefile extractor
(omd-macos-extractor-plan-v1).

`inspect` is read-only: it validates an exact producer executable against the pinned
PyInstaller 6.22.0 onefile rules and writes a reviewable plan. `execute` re-derives
that plan, re-signs every packed native member so that only its code signature
changes, rebuilds the CArchive and outer executable by the same pinned rules, proves
the candidate equivalent to the producer and only then writes a new file. `verify`
repeats the equivalence proof for an existing pair. Nothing here executes archive
members, notarizes, reads credentials, rewrites reviewed materials or accepts a
release.

Producer routes: by default only the stock universal2 `run` bootloader of PyInstaller
6.22.0 (pinned digest) is accepted. A request that carries `source` evidence selects the
separate controlled-source route of macos_extractor_source.py (the thin arm64 bootloader
compiled by scripts/build-ytdlp-source.py, bound by digest-checked evidence). The routes
never fall back to each other and have distinct methods.
"""
import hashlib
import marshal
import os
import plistlib
import re
import shutil
import struct
import tempfile
import zlib
from pathlib import Path

import macos_signing as signing
from macos_signing import need, sha

payload = signing.payload

PLAN_SCHEMA = 'omd-macos-extractor-plan-v1'
REPORT_SCHEMA = 'omd-macos-extractor-report-v1'
VERIFICATION_SCHEMA = 'omd-macos-extractor-verification-v1'
METHOD = 'omd-pyinstaller-6.22.0-onefile-signature-only-v1'
# The explicit controlled-source route (macos_extractor_source.py): same pinned steps on an
# evidence-bound compiled bootloader instead of the stock one.
SOURCE_METHOD = 'omd-pyinstaller-6.22.0-source-bootloader-onefile-signature-only-v1'
METHODS = (METHOD, SOURCE_METHOD)
PYINSTALLER_VERSION = '6.22.0'
# The universal2 console bootloader of pyinstaller-6.22.0-py3-none-macosx_10_13_universal2.whl
# (RECORD sha256=yjzGVM69t6AFhypP9PrRC_40km9vZCWUaw3GKFKJqHk).
STOCK_BOOTLOADER = {'path': 'bootloader/Darwin-64bit/run', 'bytes': 154192,
                    'sha256': 'ca3cc654cebdb7a005872a4ff4fad10bfe34926f6f6425946b0dc6285289a879'}
TARGETS = {'universal2': ('x86_64', 'arm64'), 'arm64': ('arm64',), 'x86_64': ('x86_64',)}
REQUEST_FIELDS = {'producer', 'producer_sha256', 'version', 'target_arch', 'mode', 'identity', 'team_id'}
COMPRESSION_LEVEL = 9          # CArchiveWriter._COMPRESSION_LEVEL default
STREAM_CHUNK = 16 * 1024       # CArchiveWriter._write_file read buffer
MAGIC = b'MEI\014\013\012\013\016'
COOKIE = '!8sIIII64s'
COOKIE_BYTES = struct.calcsize(COOKIE)
MAX_ENTRIES = 65536
MAX_PYZ_TOC = 64 * 1024**2
MAX_VERSION_MODULE = 4 * 1024**2
SIGNATURE_ALIGN = 16
LC_SYMTAB, LC_UUID, LC_CODE_SIGNATURE, LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION = 0x2, 0x1b, 0x1d, 0x24, 0x32
BASENAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}')
IDENTIFIER = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}')
VERSION = re.compile(r'\d{4}\.\d{2}\.\d{2}(?:\.\d{1,6})?')
# Marshalled short ASCII string constants (TYPE_SHORT_ASCII[_INTERNED], optionally FLAG_REF).
MARSHALLED_VERSION = re.compile(rb'[\x5a\x7a\xda\xfa]([\x0a-\x11])(\d{4}\.\d{2}\.\d{2}(?:\.\d{1,6})?)')

ALLOWED_DIFFERENCES = [
    'Packed native members: only each slice code signature, LC_CODE_SIGNATURE datasize, __LINKEDIT filesize/vmsize (page-rounded) and FAT slice placement (paired signature-only check). The signing identifier is preserved.',
    'Compressed native members are re-encoded with the pinned CArchiveWriter rule (zlib level 9, 16 KiB stream chunks), which must reproduce every producer native stream byte for byte.',
    'Every other member: stored and expanded bytes identical; only its TOC offset moves.',
    'CArchive: TOC offset and length fields of each entry and the cookie archive length and TOC offset; names, order, types, compression flags, Python version and library name are identical.',
    'Outer executable: per-slice LC_UUID (PyInstaller update_exe_identifier: SHA-1 of the PKG and the stock bootloader UUID), LC_SYMTAB strsize (fix_exe_for_code_signing: ends at the PKG), the PKG slice LC_CODE_SIGNATURE dataoff, up to 15 zero bytes before that 16-byte-aligned signature, signature-dependent fields and FAT placement.',
    'Outer codesign identifier: chosen by codesign from the file name and UUID, as in the PyInstaller build; the app signing workflow later assigns its reviewed identifier.',
]
LIMITS = [
    'Static proof: no archive member is executed or loaded during verification; runtime smoke checks are separate evidence.',
    'Only the pinned PyInstaller 6.22.0 macOS onefile layout with the stock universal2 run bootloader is supported; anything else fails closed.',
    'Ad-hoc candidates carry no Team ID: they are structural and runtime evidence only, never Developer ID-ready or distributable.',
    'Developer ID mode needs the operator keychain identity; this tool never stores, reads or requests credentials, notarizes or uploads.',
    'Corresponding-source, materials and license review of the producer remain separate gates; this tool rewrites no reviewed materials.',
]


# ---------------------------------------------------------------- pinned PyInstaller

def pinned_runtime():
    """The exact PyInstaller implementation reused here (version, compression level, cookie)."""
    import PyInstaller
    from PyInstaller.archive.readers import CArchiveReader
    from PyInstaller.archive.writers import CArchiveWriter
    need(PyInstaller.__version__ == PYINSTALLER_VERSION, f'PyInstaller {PYINSTALLER_VERSION} is required, found {PyInstaller.__version__}')
    need(CArchiveWriter._COMPRESSION_LEVEL == COMPRESSION_LEVEL, 'PYINSTALLER_ZLIB_COMPRESSION_LEVEL overrides the pinned CArchive compression level')
    need(CArchiveWriter._COOKIE_FORMAT == CArchiveReader._COOKIE_FORMAT == COOKIE and CArchiveWriter._COOKIE_MAGIC_PATTERN == MAGIC,
         'Unexpected pinned CArchive cookie format')
    return PyInstaller


def pinned():
    """The exact PyInstaller implementation reused here, plus the stock bootloader bytes."""
    PyInstaller = pinned_runtime()
    path = Path(PyInstaller.__file__).resolve().parent / STOCK_BOOTLOADER['path']
    data = signing.public_inputs.regular(path).read_bytes()
    need(len(data) == STOCK_BOOTLOADER['bytes'] and sha(data) == STOCK_BOOTLOADER['sha256'],
         'The installed PyInstaller bootloader differs from the pinned 6.22.0 universal2 run bootloader')
    return {'pyinstaller': PYINSTALLER_VERSION, 'bootloader': {'path': str(path), **{k: STOCK_BOOTLOADER[k] for k in ('bytes', 'sha256')}},
            'compression_level': COMPRESSION_LEVEL, 'cookie_format': COOKIE,
            'rules': ['PyInstaller/building/api.py EXE.assemble (macOS onefile)', 'PyInstaller/utils/osx.py update_exe_identifier, fix_exe_for_code_signing, sign_binary',
                      'PyInstaller/archive/writers.py CArchiveWriter._write_file and _serialize_toc']}, data


def tool_identity(route=None):
    """Sources of this transformation; bound by the plan, so execute refuses a changed tool.
    The controlled-source route adds its own module and the reused builder checks."""
    files = [('macos_extractor.py', __file__), ('macos_signing.py', signing.__file__), ('check-macos-payload.py', payload.__file__)]
    if route is not None and route['source'] is not None:
        files += route['tool_files']
    return {name: signing.file_identity(Path(path)) for name, path in files}


def producer_route(request, temp_root=None):
    """The producer route of a request: the stock universal2 bootloader (default), or the
    explicit controlled-source route when the request carries `source` evidence. There is
    no fallback between them."""
    if 'source' not in request:
        pin, stock_bytes = pinned()
        return {'name': 'upstream-stock', 'method': METHOD, 'pin': pin, 'bootloader': stock_bytes,
                'slices': stock_slices(stock_bytes, request['target_arch']), 'source': None, 'allowed_differences': ALLOWED_DIFFERENCES,
                'limits': LIMITS, 'reproduction_note': 'Stock bootloader plus the producer PKG through the same pinned steps; only signature bytes differ.'}
    import macos_extractor_source
    return macos_extractor_source.route(request, temp_root)


def source_input_dirs(request):
    """Directories of the controlled-source inputs (none for the stock route); outputs never go there."""
    source = request.get('source')
    if source is None:
        return []
    return [signing.absolute(p).parent for p in (source['evidence']['path'], source['kit'], source['bootloader'])]


def route_texts(source_route):
    """(allowed differences, limits) of a route, without loading its inputs."""
    if not source_route:
        return ALLOWED_DIFFERENCES, LIMITS
    import macos_extractor_source
    return macos_extractor_source.ALLOWED_DIFFERENCES, macos_extractor_source.LIMITS


def serialize_toc(rows):
    """Pinned CArchiveWriter TOC serialization of (offset, stored, expanded, flag, code, name)."""
    from PyInstaller.archive.writers import CArchiveWriter
    return CArchiveWriter._serialize_toc(rows)


def pinned_compress(data):
    """CArchiveWriter._write_file: streaming zlib at the pinned level in 16 KiB reads."""
    compressor = zlib.compressobj(COMPRESSION_LEVEL)
    out = [compressor.compress(data[i:i + STREAM_CHUNK]) for i in range(0, len(data), STREAM_CHUNK)]
    return b''.join(out) + compressor.flush()


def pkg_uuid(pkg, original):
    """PyInstaller update_exe_identifier: SHA-1 of the PKG, then the original UUID, truncated to 16 bytes."""
    digest = hashlib.sha1(pkg)
    digest.update(original)
    return digest.digest()[:16]


# ---------------------------------------------------------------- Mach-O fields

def only(commands, kind, what):
    found = [at for cmd, at, _ in commands if cmd == kind]
    need(len(found) == 1, f'Expected exactly one {what} load command')
    return found[0]


def uuid_of(image):
    _, _, _, _, commands = signing.load_commands(image)
    at = only(commands, LC_UUID, 'LC_UUID')
    return image[at + 8:at + 24]


def sdk_of(image):
    """SDK version as PyInstaller get_macos_sdk_version reads it (first version command)."""
    endian, _, _, _, commands = signing.load_commands(image)
    for cmd, at, _ in commands:
        if cmd in (LC_BUILD_VERSION, LC_VERSION_MIN_MACOSX):
            value, = struct.unpack_from(endian + 'I', image, at + (16 if cmd == LC_BUILD_VERSION else 12))
            return [value >> 16 & 0xff, value >> 8 & 0xff, value & 0xff]
    raise ValueError('Missing macOS SDK version command')


def stock_slices(stock, target):
    """Slices binary_to_target_arch keeps from the stock bootloader, in order."""
    regions = signing.slice_regions(stock)
    need(len(regions) == 2, 'The pinned bootloader must be universal2')
    rows = []
    for off, length in regions:
        image = stock[off:off + length]
        _, cpu, subtype, _, _ = signing.load_commands(image)
        rows.append({'arch': signing.payload_arch(cpu), 'cpu': cpu, 'subtype': subtype, 'uuid': uuid_of(image).hex(), 'sdk': sdk_of(image)})
    kept = [r for r in rows if r['arch'] in TARGETS[target]]
    need(tuple(r['arch'] for r in kept) == TARGETS[target], f'The pinned bootloader cannot produce target {target}')
    return kept


def linkedit_pages_ok(record):
    filesize, vmsize = record['linkedit']['filesize'], record['linkedit']['vmsize']
    return vmsize in {-(-filesize // page) * page for page in signing.LINKEDIT_PAGES.get(record['cpu'], (0x1000, 0x4000))}


def bootloader_view(image, pkg_range=None):
    """Non-signature bytes of one slice with the PKG-derived fields masked: LC_UUID and,
    in the slice holding the PKG, LC_SYMTAB strsize and LC_CODE_SIGNATURE dataoff; the
    PKG and the padding after it are cut. Everything else must be byte-identical."""
    _, canonical = signing.thin_layout(image)
    endian, _, _, _, commands = signing.load_commands(image)
    view = bytearray(canonical)
    at = only(commands, LC_UUID, 'LC_UUID')
    view[at + 8:at + 24] = bytes(16)
    if pkg_range:
        struct.pack_into(endian + 'I', view, only(commands, LC_SYMTAB, 'LC_SYMTAB') + 20, 0)
        struct.pack_into(endian + 'I', view, only(commands, LC_CODE_SIGNATURE, 'LC_CODE_SIGNATURE') + 8, 0)
        view = view[:pkg_range[0]]
    return bytes(view)


# ---------------------------------------------------------------- archive analysis

def resolve(name, links, depth=0):
    """Lexical link resolution relative to each link's directory (links already validated)."""
    need(depth < 32, 'CArchive link chain is cyclic or too deep')
    out = []
    for part in name.split('/'):
        here = '/'.join(out + [part])
        out = resolve('/'.join(out + [links[here]]), links, depth + 1).split('/') if here in links else out + [part]
    return '/'.join(out)


def embedded_versions(path, start, entries):
    """Version constants of the PYZ yt_dlp.version module, read statically: the PYZ TOC
    (plain containers) is unmarshalled, module code is never unmarshalled or run."""
    pyz = [entry for _, entry in entries if entry[4] == 'z']
    need(len(pyz) == 1, 'Expected exactly one PYZ archive entry')
    blob = payload.extract_member(path, start, pyz[0])
    need(len(blob) >= 17 and blob[:4] == b'PYZ\0', 'Invalid PYZ header')
    toc_offset, = struct.unpack_from('!i', blob, 8)
    need(17 <= toc_offset < len(blob) and len(blob) - toc_offset <= MAX_PYZ_TOC, 'Invalid PYZ TOC offset')
    try:
        toc = marshal.loads(blob[toc_offset:])
    except (EOFError, ValueError, TypeError) as error:
        raise ValueError(f'Unreadable PYZ TOC: {error}') from error
    need(isinstance(toc, list) and len(toc) <= 4 * MAX_ENTRIES, 'Invalid PYZ TOC')
    found = []
    for item in toc:
        need(isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], tuple) and len(item[1]) == 3
             and all(type(v) is int for v in item[1]), 'Malformed PYZ TOC entry')
        if item[0] == 'yt_dlp.version':
            found.append(item[1])
    need(len(found) == 1, 'The PYZ must hold exactly one yt_dlp.version module')
    _, offset, length = found[0]
    need(17 <= offset and 0 < length and offset + length <= toc_offset, 'yt_dlp.version lies outside the PYZ data')
    decoder = zlib.decompressobj()
    try:
        module = decoder.decompress(blob[offset:offset + length], MAX_VERSION_MODULE)
    except zlib.error as error:
        raise ValueError('Invalid compressed yt_dlp.version module') from error
    need(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data, 'Truncated or oversized yt_dlp.version module')
    need(b'__version__' in module, 'yt_dlp.version defines no __version__')
    return sorted({m[2].decode() for m in MARSHALLED_VERSION.finditer(module) if ord(m[1]) == len(m[2])})


def native_record(name, data, target):
    layout, independent = signing.macho_layout(data)
    images = signing.signature(data)
    need(all(i['signed'] for i in images), f'{name}: unsigned packed slice; adding a signature would rewrite load commands')
    need(all(i['filetype'] in ('dylib', 'bundle') for i in images), f'{name}: packed code must be a dylib or bundle')
    identifiers = {i['identifier'] for i in images}
    need(len(identifiers) == 1, f'{name}: slices carry different signing identifiers')
    identifier = identifiers.pop()
    need(IDENTIFIER.fullmatch(identifier or ''), f'{name}: unsupported signing identifier {identifier!r}')
    need(not any(i['entitlements'] for i in images), f'{name}: packed libraries cannot carry entitlements')
    arches = [signing.payload_arch(s['cpu']) for s in layout['slices']]
    need(set(TARGETS[target]) <= set(arches), f'{name}: architectures {arches} do not cover target {target}')
    return {'identifier': identifier, 'filetypes': sorted({i['filetype'] for i in images}), 'architectures': arches,
            'minimum': {a: payload.component(data, name, a)['minimum'] for a in TARGETS[target]},
            'signature_independent_sha256': independent, 'signature_layout': layout, 'producer_signature': signing.producer_summary(images)}


def analyse(path, data, target, stock):
    """Strict structure of a pinned PyInstaller 6.22.0 macOS onefile at `path` (bytes `data`)."""
    need(signing.is_macho(data), 'Not a Mach-O executable')
    need(all(image['filetype'] == 2 for image in payload.slices(data)), 'Every slice must be an executable')
    layout, independent = signing.macho_layout(data)
    need(all(s['signed'] for s in layout['slices']), 'Unsigned slices are unsupported')
    arches = tuple(signing.payload_arch(s['cpu']) for s in layout['slices'])
    need(arches == TARGETS[target] and (layout['container']['format'] != 'thin') == (target == 'universal2'),
         f'Slices {list(arches)} ({layout["container"]["format"]}) differ from target {target}')
    need([(s['cpu'], s['subtype']) for s in layout['slices']] == [(s['cpu'], s['subtype']) for s in stock], 'Slice architectures differ from the pinned bootloader')
    for arch in arches:
        payload.component(data, 'extractor', arch)
    at = data.rfind(MAGIC)  # the bootloader's back-to-front cookie scan
    need(at >= 0 and at + COOKIE_BYTES <= len(data), 'Missing CArchive cookie')
    _, length, toc_offset, toc_length, _, _ = struct.unpack(COOKIE, data[at:at + COOKIE_BYTES])
    need(length <= at + COOKIE_BYTES and toc_length <= signing.MAX_TOC_BYTES and toc_offset + toc_length + COOKIE_BYTES == length,
         'CArchive TOC exceeds its archive or does not end at the cookie')
    archive, entries = signing.archive_entries(path)
    links_validated = signing.check_archive_names(path, archive, entries)
    need(len(entries) <= MAX_ENTRIES, 'Too many CArchive entries')
    start, end = archive._start_offset, archive._end_offset
    regions = signing.slice_regions(data)
    last_off, last_len = regions[-1]
    need(last_off + last_len == len(data) and last_off <= start < end <= last_off + last_len, 'The PKG must lie inside the last slice, which ends the file')
    _, length, toc_offset, toc_length, pyvers, pylib = struct.unpack(COOKIE, data[end - COOKIE_BYTES:end])
    need(data.rfind(MAGIC) == end - COOKIE_BYTES, 'The cookie is not the last archive magic; the bootloader would read another archive')
    need(length == end - start, 'Cookie archive length differs from its placement')
    name, _, tail = pylib.partition(b'\0')
    need(name and tail.count(0) == len(tail), 'Invalid Python library name in the cookie')
    cursor = 0
    for member, (offset, stored, expanded, flag, code) in entries:
        need(offset == cursor, f'CArchive entry {member!r} is not contiguous with the previous entry')
        need(flag in (0, 1) and (flag or stored == expanded), f'Invalid compression metadata for {member!r}')
        need(code != 'o' or stored == expanded == flag == 0, f'Option entry {member!r} carries data')
        cursor += stored
    need(toc_offset == cursor and toc_offset + toc_length + COOKIE_BYTES == length, 'The TOC and cookie must immediately follow the entry data')
    toc = data[start + toc_offset:start + toc_offset + toc_length]
    need(serialize_toc([(o, s, e, f, c, n) for n, (o, s, e, f, c) in entries]) == toc, 'The TOC differs from the pinned PyInstaller serialization')
    image = data[last_off:last_off + last_len]
    endian, _, _, _, commands = signing.load_commands(image)
    stroff, strsize = struct.unpack_from(endian + 'II', image, only(commands, LC_SYMTAB, 'LC_SYMTAB') + 16)
    pkg_range = (start - last_off, end - last_off)
    need(stroff <= pkg_range[0] and stroff + strsize == pkg_range[1], 'The LC_SYMTAB string table must end exactly at the PKG (fix_exe_for_code_signing)')
    signature_offset = layout['slices'][-1]['signature_offset']
    pad = image[pkg_range[1]:signature_offset]
    need(signature_offset % SIGNATURE_ALIGN == 0 and len(pad) < SIGNATURE_ALIGN and pad.count(0) == len(pad), 'Unexpected bytes between the PKG and the code signature')
    need(all(linkedit_pages_ok(s) for s in layout['slices']), '__LINKEDIT vmsize is not its page-rounded file size')
    pkg = data[start:end]
    uuids = [uuid_of(data[o:o + n]) for o, n in regions]
    for uuid, base in zip(uuids, stock):
        need(uuid == pkg_uuid(pkg, bytes.fromhex(base['uuid'])), f"{base['arch']} LC_UUID is not PyInstaller's PKG-derived UUID for the pinned bootloader")
    links, members, total = {}, [], 0
    for index, (member, entry) in enumerate(entries):
        offset, stored, expanded, flag, code = entry
        raw = data[start + offset:start + offset + stored]
        plain = payload.extract_member(path, start, entry) if code != 'o' else b''
        row = {'index': index, 'name': member, 'type': code, 'compressed': bool(flag), 'offset': offset,
               'stored': {'bytes': stored, 'sha256': sha(raw)}, 'expanded': {'bytes': expanded, 'sha256': sha(plain)}}
        native = signing.is_macho(plain)
        need(native == (code == 'b'), f'{member}: Mach-O content must be exactly the binary (b) entries')
        if code == 'n':
            links[member] = plain[:-1].decode('utf-8')
        if native:
            total += len(plain)
            need(total <= signing.MAX_MATERIALIZED_BYTES, 'Packed native members exceed the materialization budget')
            row['native'] = native_record(member, plain, target)
            row['native']['compression_rule'] = (pinned_compress(plain) == raw) if flag else 'stored'
        row['action'] = 'sign-signature-only' if native else 'copy-stored-bytes'
        members.append(row)
    python = resolve(name.decode('ascii'), links)
    library = [m for m in members if m['name'] == python]
    need(len(library) == 1 and library[0]['type'] == 'b', 'The cookie Python library does not resolve to a packed native member')
    library_bytes = payload.extract_member(path, start, entries[library[0]['index']][1])
    first = signing.slice_regions(library_bytes)[0]
    sdk = {'python_library': sdk_of(library_bytes[first[0]:first[0] + first[1]]), 'bootloader': stock[0]['sdk']}
    sdk['rewrite'] = sdk['python_library'] < sdk['bootloader']
    counts = {}
    for row in members:
        counts[row['type']] = counts.get(row['type'], 0) + 1
    natives = [m for m in members if 'native' in m]
    return {'bytes': len(data), 'sha256': sha(data), 'signature_independent_sha256': independent, 'signature_layout': layout,
            'producer_signature': signing.producer_summary(signing.signature(data)), 'uuids': [u.hex() for u in uuids],
            'archive': {'start': start, 'end': end, 'length': length, 'toc_offset': toc_offset, 'toc_length': toc_length, 'toc_sha256': sha(toc),
                        'pkg_sha256': sha(pkg), 'cookie': {'python_version': pyvers, 'python_library': name.decode('ascii')}, 'python_library_member': python,
                        'string_table': {'stroff': stroff, 'strsize': strsize}, 'signature_padding': len(pad), 'entries': len(entries), 'by_type': dict(sorted(counts.items())),
                        'links_validated': links_validated, 'native_members': len(natives), 'native_bytes': total},
            'sdk': sdk, 'embedded_versions': embedded_versions(path, start, entries), 'members': members}


def private_analysis(data, target, stock, folder, name):
    """Analyse a private 0600 copy of digest-checked bytes, so parsing sees exactly them."""
    private = Path(folder) / name
    signing.write_private(private, data)
    return private, analyse(private, data, target, stock)


# ---------------------------------------------------------------- equivalence

def compare(producer, candidate, ppath, cpath, pdata, cdata):
    """Producer-to-candidate proof; both analyses already passed the pinned layout rules."""
    pl, cl = producer['signature_layout'], candidate['signature_layout']
    need(pdata[:4] == cdata[:4] and pl['container']['format'] == cl['container']['format'], 'Outer Mach-O/FAT container format differs')
    if pl['container']['format'] != 'thin':
        need([(a['cpu'], a['subtype'], a['reserved']) for a in pl['container']['arches']] ==
             [(a['cpu'], a['subtype'], a['reserved']) for a in cl['container']['arches']], 'Outer FAT architecture identity or reserved metadata differs')
    need([(s['cpu'], s['subtype']) for s in pl['slices']] == [(s['cpu'], s['subtype']) for s in cl['slices']], 'Slice architectures differ')
    pregions, cregions = signing.slice_regions(pdata), signing.slice_regions(cdata)
    slices = []
    for i, ((po, pn), (co, cn)) in enumerate(zip(pregions, cregions)):
        last = i == len(pregions) - 1
        pr = (producer['archive']['start'] - po, producer['archive']['end'] - po) if last else None
        cr = (candidate['archive']['start'] - co, candidate['archive']['end'] - co) if last else None
        pv, cv = bootloader_view(pdata[po:po + pn], pr), bootloader_view(cdata[co:co + cn], cr)
        arch = signing.payload_arch(pl['slices'][i]['cpu'])
        need(pv == cv, f'{arch} bootloader bytes differ beyond the PyInstaller PKG-derived fields')
        slices.append({'arch': arch, 'compared_bytes': len(pv), 'sha256': sha(pv), 'holds_pkg': last})
    need(producer['archive']['cookie'] == candidate['archive']['cookie'], 'Cookie Python version or library differs')
    need(producer['sdk'] == candidate['sdk'] and producer['embedded_versions'] == candidate['embedded_versions'], 'SDK rule or embedded version differs')
    pm, cm = producer['members'], candidate['members']
    need(len(pm) == len(cm), 'Entry count differs')
    _, centries = signing.archive_entries(cpath)
    rows, signature_only, copied = [], 0, 0
    for before, after in zip(pm, cm):
        need((before['name'], before['type'], before['compressed']) == (after['name'], after['type'], after['compressed']),
             f"Entry {before['index']} name, type or compression differs")
        row = {'index': before['index'], 'name': before['name'], 'type': before['type'], 'offset': [before['offset'], after['offset']],
               'stored': [before['stored'], after['stored']], 'expanded': [before['expanded'], after['expanded']]}
        if 'native' not in before:
            need(before['stored'] == after['stored'] and before['expanded'] == after['expanded'], f"{before['name']}: non-native member bytes differ")
            row['relation'] = 'identical-stored-bytes'
            copied += 1
        else:
            plain = payload.extract_member(cpath, candidate['archive']['start'], centries[after['index']][1])
            try:
                comparison = signing.signature_change(before['native']['signature_independent_sha256'], before['native']['signature_layout'], plain)
            except ValueError as error:
                raise ValueError(f"{before['name']}: {error}") from error
            need(after['native']['identifier'] == before['native']['identifier'], f"{before['name']}: signing identifier changed")
            need(after['native']['compression_rule'] in (True, 'stored'), f"{before['name']}: stream not encoded by the pinned compression rule")
            row.update(relation='signature-only', identifier=before['native']['identifier'], signature_independent_sha256=before['native']['signature_independent_sha256'],
                       comparison=comparison, signature=[before['native']['producer_signature'], after['native']['producer_signature']])
            signature_only += 1
        rows.append(row)
    need(producer['archive']['toc_length'] == candidate['archive']['toc_length'], 'TOC length differs although names are identical')
    return {'slices': slices, 'members': rows, 'signature_only_natives': signature_only, 'identical_non_natives': copied,
            'producer_uuids': producer['uuids'], 'candidate_uuids': candidate['uuids']}


def cryptographic(path, mode, team, folder):
    """codesign verification of every packed member and of the outer executable."""
    members = signing.verify_packed_natives(path, mode, team, folder)
    requirement = signing.developer_id_requirement(team) if mode == 'developer-id' else None
    env = {k: v for k, v in os.environ.items() if not k.startswith(('APPLE_', 'NOTARY', 'CODESIGN_'))}
    env['TMPDIR'] = str(folder)
    code, err = signing.codesign_check([signing.CODESIGN, '--verify', '--strict', '--all-architectures',
                                        *([f'--test-requirement=={requirement}'] if requirement else []), str(path)], env)
    return {'members': members, 'outer': {'exit': code, 'reason': ' '.join(err.split())[-300:], 'requirement': requirement}}


def verify_pair(producer, prepared, version, target, mode, team, temp_root=None, crypto=True, source=None):
    """Re-derive the full equivalence proof for digest-bound producer and prepared files.
    `source` (controlled-source evidence) selects that route explicitly; it is never inferred."""
    if source is None:
        route = producer_route({'target_arch': target}, temp_root)
    else:
        need(isinstance(producer, dict), 'producer needs path and sha256')
        route = producer_route({'target_arch': target, 'producer_sha256': producer.get('sha256'), 'version': version, 'source': source}, temp_root)
    pin, stock = route['pin'], route['slices']
    loaded = {}
    for key, spec in (('producer', producer), ('prepared', prepared)):
        need(isinstance(spec, dict) and set(spec) == {'path', 'sha256'} and signing.HEX64.fullmatch(spec['sha256'] or ''), f'{key} needs path and sha256')
        path = signing.regular_input(spec['path'], key)
        need(path.stat().st_size <= signing.MAX_EXTRACTOR_BYTES, f'{key} exceeds the size budget')
        data = path.read_bytes()
        need(sha(data) == spec['sha256'], f'{key} digest differs from the requested digest')
        loaded[key] = data
    need(producer['sha256'] != prepared['sha256'], 'The prepared extractor is the producer itself')
    with tempfile.TemporaryDirectory(prefix='omd-extractor-verify-', dir=temp_root) as folder:
        ppath, before = private_analysis(loaded['producer'], target, stock, folder, 'producer')
        cpath, after = private_analysis(loaded['prepared'], target, stock, folder, 'prepared')
        need(before['embedded_versions'] == [version] == after['embedded_versions'], f"Embedded versions {before['embedded_versions']}/{after['embedded_versions']} differ from {version}")
        if route['source'] is not None:
            binding = route['module'].producer_binding(route, before, loaded['producer'], ppath)
        proof = compare(before, after, ppath, cpath, loaded['producer'], loaded['prepared'])
        if route['source'] is not None:
            outer = route['module'].candidate_outer(route, after, loaded['prepared'], cpath, binding)
        checks = cryptographic(cpath, mode, team, folder) if crypto else None
    ok = checks is None or (checks['members']['failed'] == 0 and checks['members']['native_members'] == after['archive']['native_members'] and checks['outer']['exit'] == 0)
    result = {'schema': VERIFICATION_SCHEMA, 'method': route['method'], 'pinned': pin, 'version': version, 'target_arch': target, 'mode': mode, 'team_id': team,
              'producer': {k: before[k] for k in ('bytes', 'sha256', 'signature_independent_sha256', 'uuids', 'archive')},
              'prepared': {k: after[k] for k in ('bytes', 'sha256', 'signature_independent_sha256', 'uuids', 'archive', 'producer_signature')},
              'structural_equivalence': proof, 'cryptographic': checks, 'pass': ok,
              'allowed_differences': route['allowed_differences'], 'limits': route['limits'], 'release_accepted': False, 'notarized': False}
    if route['source'] is not None:
        result['source'] = {**route['source'], 'producer_binding': binding, 'prepared_outer': outer}
    return result


def check_report(report_spec, prepared_spec, producer_path, producer_sha256, mode, team, temp_root=None, source=None):
    """Signing-workflow adapter: bind a preparation report to the exact producer and
    prepared bytes, then repeat the structural proof independently of the report.
    `source` opts into the controlled-source route; its evidence is re-verified here and the
    report must name the same evidence. Reports never move between routes."""
    need(isinstance(report_spec, dict) and set(report_spec) == {'path', 'sha256'} and signing.HEX64.fullmatch(report_spec['sha256'] or ''),
         'Prepared extractor report needs path and a 64-hex sha256')
    raw = signing.regular_input(report_spec['path'], 'Prepared extractor report').read_bytes()
    need(sha(raw) == report_spec['sha256'], 'Prepared extractor report digest differs from the requested digest')
    report = signing.strict_json(raw)
    if source is None:
        need(report.get('method') != SOURCE_METHOD, 'The report comes from the controlled-source route; supply its source evidence')
        need(report.get('schema') == REPORT_SCHEMA and report.get('method') == METHOD and report.get('status') in DONE, 'Not a completed extractor preparation report')
        need('source' not in report['request'], 'A stock-route report cannot carry source evidence')
    else:
        need(report.get('schema') == REPORT_SCHEMA and report.get('method') == SOURCE_METHOD and report.get('status') in DONE,
             'Not a completed controlled-source extractor preparation report; a stock-route report cannot be relabelled')
        reported = report['request'].get('source')
        need(isinstance(reported, dict) and isinstance(reported.get('evidence'), dict) and isinstance(source, dict) and isinstance(source.get('evidence'), dict)
             and reported['evidence'].get('sha256') == source['evidence'].get('sha256'), 'The report was prepared with different source evidence')
    request = report['request']
    need(report['output']['sha256'] == prepared_spec['sha256'] and report['producer']['sha256'] == producer_sha256,
         'The report does not bind this producer and prepared extractor')
    need(request['version'] == prepared_spec['version'] and prepared_spec['arch'] in TARGETS[request['target_arch']], 'Report version or architecture differs')
    need(request['mode'] == mode and request['team_id'] == team, 'The report was prepared for a different signing mode or Team ID')
    proof = verify_pair({'path': str(producer_path), 'sha256': producer_sha256}, {'path': prepared_spec['path'], 'sha256': prepared_spec['sha256']},
                        request['version'], request['target_arch'], mode, team, temp_root, crypto=False, source=source)
    rows = proof['structural_equivalence']
    result = {'report': {**report_spec, 'bytes': len(raw)}, 'method': proof['method'], 'target_arch': request['target_arch'], 'verified_independently': True,
              'producer_sha256': producer_sha256, 'signature_only_natives': rows['signature_only_natives'], 'identical_non_natives': rows['identical_non_natives'],
              'bootloader_slices': rows['slices'],
              'evidence': 'Structural proof repeated from the app producer bytes; packed members are verified cryptographically by the signing inspection itself.'}
    if source is not None:
        found = proof['source']
        result['source'] = {'route': found['route'], 'evidence_sha256': found['evidence']['sha256'], 'kit_sha256': found['kit']['sha256'],
                            'plan_sha256': found['plan']['sha256'], 'receipt_sha256': found['receipt']['sha256'], 'bootloader_sha256': found['bootloader']['sha256'],
                            'profile': found['profile'], 'producer_binding': found['producer_binding'], 'prepared_outer': found['prepared_outer']}
    return result


# ---------------------------------------------------------------- inspection

def request_check(request):
    need(isinstance(request, dict) and set(request) in (REQUEST_FIELDS, REQUEST_FIELDS | {'source'}),
         'Request needs producer, producer_sha256, version, target_arch, mode, identity and team_id (and only optional source evidence)')
    need(request['target_arch'] in TARGETS, 'target_arch must be universal2, arm64 or x86_64')
    need(isinstance(request['version'], str) and VERSION.fullmatch(request['version']), 'Invalid yt-dlp version')
    need(isinstance(request['producer_sha256'], str) and signing.HEX64.fullmatch(request['producer_sha256']), 'Producer digest must be 64 lowercase hex characters')
    signing.check_identity(request['mode'], request['identity'], request['team_id'])
    if 'source' in request:
        import macos_extractor_source
        macos_extractor_source.request_check(request['source'])


def inspect(request, temp_root=None):
    """Read-only: validate the producer and return a plan (without created_at)."""
    return inspect_route(request, temp_root)[0]


def inspect_route(request, temp_root=None):
    """inspect, plus the re-derived producer route that execute uses (never the plan's copy)."""
    request_check(request)
    target, mode = request['target_arch'], request['mode']
    path = signing.regular_input(request['producer'], 'Producer extractor')
    need(BASENAME.fullmatch(path.name), 'Unsupported producer file name')
    need(path.stat().st_size <= signing.MAX_EXTRACTOR_BYTES, 'Producer exceeds the size budget')
    data = path.read_bytes()
    need(sha(data) == request['producer_sha256'], 'Producer digest differs from the requested digest')
    route = producer_route(request, temp_root)
    pin, stock = route['pin'], route['slices']
    with tempfile.TemporaryDirectory(prefix='omd-extractor-inspect-', dir=temp_root) as folder:
        private, analysis = private_analysis(data, target, stock, folder, 'producer')
        need(build_pkg(data, analysis, private, {}) == data[analysis['archive']['start']:analysis['archive']['end']],
             'The pinned CArchive writer layout does not reproduce the producer PKG')
        if route['source'] is not None:
            binding = route['module'].producer_binding(route, analysis, data, private)
        current = signing.verify_packed_natives(private, 'development-adhoc', None, folder)
    need(analysis['embedded_versions'] == [request['version']], f"Embedded yt-dlp version constants {analysis['embedded_versions']} differ from the requested {request['version']}")
    natives = [m for m in analysis['members'] if 'native' in m]
    need(natives and current['native_members'] == len(natives), 'Native member set differs between parsing and verification')
    blockers = [{'id': 'producer-member-signature', 'member': f['member'],
                 'message': f"Producer member {f['member']} fails codesign verification; re-signing would hide a modified page: {f['reason']}"} for f in current['failures']]
    if current['failed'] > len(current['failures']):
        blockers.append({'id': 'producer-member-signature', 'member': None, 'message': f"{current['failed']} producer members fail verification in total"})
    blockers += [{'id': 'compression-rule', 'member': m['name'], 'message': f"The pinned zlib rule does not reproduce the producer stream of {m['name']}"}
                 for m in natives if m['native']['compression_rule'] is False]
    developer = mode == 'developer-id'
    sample = {'hardened_runtime': False, 'action': 'sign', 'identifier': '<member identifier>', 'entitlements': {}}
    plan = {
        'schema': PLAN_SCHEMA, 'method': route['method'], 'request': request, 'pinned': pin, 'tool': tool_identity(route),
        'producer': {'path': str(path), 'name': path.name, **{k: v for k, v in analysis.items() if k != 'members'}, 'current_member_verification': current},
        'members': analysis['members'],
        'signing': {'member_argv': signing.sign_argv(request['identity'], mode, sample, None, '<member>'),
                    'outer_argv': outer_sign_argv(request['identity'], mode, '<extractor>'),
                    'member_checks': ['codesign --verify --strict --all-architectures' + (' plus the Developer ID Application Team requirement' if developer else ''),
                                      'identifier preserved; no entitlements; no hardened-runtime flag (libraries); not linker-signed',
                                      'paired signature-only check against the producer member']},
        'allowed_differences': route['allowed_differences'], 'blockers': blockers, 'ready_for_execution': not blockers,
        'signature_kind': 'developer-id' if developer else 'ad-hoc', 'developer_id_ready': False, 'notarized': False, 'release_accepted': False,
        'limits': route['limits'],
    }
    if route['source'] is None:
        plan['stock_slices'] = stock
    else:
        plan['bootloader_slices'] = stock
        plan['source'] = {**route['source'], 'producer_binding': binding}
    return plan, route


# ---------------------------------------------------------------- transformation

def build_pkg(data, analysis, path, replacements):
    """CArchive bytes in the pinned writer layout: entries in producer order, contiguous,
    then the pinned TOC and cookie. Entries without a replacement keep their stored bytes
    verbatim; replacements are encoded as CArchiveWriter._write_file encodes files."""
    archive = analysis['archive']
    _, entries = signing.archive_entries(path)
    out, rows = bytearray(), []
    for index, (name, (offset, stored, expanded, flag, code)) in enumerate(entries):
        if index in replacements:
            plain = replacements[index]
            blob, expanded = (pinned_compress(plain) if flag else plain), len(plain)
        else:
            blob = data[archive['start'] + offset:archive['start'] + offset + stored]
        rows.append((len(out), len(blob), expanded, flag, code, name))
        out += blob
    toc = serialize_toc(rows)
    toc_offset = len(out)
    length = toc_offset + len(toc) + COOKIE_BYTES
    need(length < 2**32, 'Rebuilt CArchive exceeds the 32-bit cookie fields')
    cookie = archive['cookie']
    out += toc + struct.pack(COOKIE, MAGIC, length, toc_offset, len(toc), cookie['python_version'], cookie['python_library'].encode('ascii'))
    return bytes(out)


def outer_sign_argv(identity, mode, path):
    """PyInstaller 6.22.0 sign_binary, with an explicit no-timestamp for ad-hoc signatures."""
    developer = mode == 'developer-id'
    return [signing.CODESIGN, '-s', identity, '--force', '--all-architectures', '--timestamp' if developer else '--timestamp=none',
            *(['--options=runtime'] if developer else []), str(path)]


def assemble(runner, stock_bytes, pkg_path, target, folder, name, mode, identity, sdk):
    """PyInstaller 6.22.0 EXE.assemble for a macOS onefile, step for step, on private files.
    External commands go through the recording runner with PyInstaller's own arguments."""
    from PyInstaller.utils import osx as osxutils
    folder.mkdir()
    exe = folder / name
    signing.write_new(exe, stock_bytes)
    exe.chmod(0o755)
    fat, arches = osxutils.get_binary_architectures(str(exe))
    if target == 'universal2':  # binary_to_target_arch: a fat bootloader is kept as is
        need(fat, 'The pinned bootloader is not fat')
    elif fat:
        runner(['/usr/bin/lipo', '-thin', target, str(exe), '-output', str(exe)], label='bootloader-target-arch')
    else:  # binary_to_target_arch: a thin bootloader of the target architecture is kept as is
        need(list(arches) == [target], f'The thin bootloader is not a {target} executable')
    runner([signing.CODESIGN, '--remove', '--all-architectures', str(exe)], label='bootloader-remove-signature')
    osxutils.update_exe_identifier(str(exe), str(pkg_path))
    with open(exe, 'ab') as stream, open(pkg_path, 'rb') as source:
        shutil.copyfileobj(source, stream, length=64 * 1024)
    osxutils.fix_exe_for_code_signing(str(exe))
    exe_sdk = list(osxutils.get_macos_sdk_version(str(exe)))
    need(exe_sdk == sdk['bootloader'], 'Bootloader SDK differs from the plan')
    if sdk['python_library'] < exe_sdk:
        osxutils.set_macos_sdk_version(str(exe), *sdk['python_library'])
    runner(outer_sign_argv(identity, mode, exe), label='sign-outer')
    return exe


def verify_outer(runner, path, mode, team):
    developer = mode == 'developer-id'
    requirement = [f'--test-requirement=={signing.developer_id_requirement(team)}'] if developer else []
    runner([signing.CODESIGN, '--verify', '--strict', '--all-architectures', *requirement, str(path)], label='verify-outer')
    shown = runner([signing.CODESIGN, '--display', '--entitlements', '-', '--xml', str(path)], label='entitlements-outer')
    need(not shown.strip() or plistlib.loads(shown) == {}, 'The prepared extractor carries entitlements')
    for image in signing.signature(Path(path).read_bytes()):
        need(image['signed'] and image['adhoc'] is not developer and image['certificates'] is developer and image['team'] == team, 'Outer signature mode/team mismatch')
        need(image['runtime'] is developer and not image['linker_signed'] and not image['entitlements'], 'Outer hardened-runtime or entitlement mismatch')
    if developer:
        runner([signing.CODESIGN, '--display', '--verbose=2', str(path)], label='details-outer')
        details = runner.records[-1]['stderr']
        need('Authority=Developer ID Application:' in details and f'TeamIdentifier={team}' in details, 'Outer is not signed by the Developer ID team')
        need(re.search(r'^Timestamp=', details, re.MULTILINE) and 'Signed Time=' not in details, 'Outer lacks a secure timestamp')


DONE = ('prepared-development-candidate', 'prepared-developer-id-candidate')


def plan_body(plan):
    return {k: v for k, v in plan.items() if k != 'created_at'}


def execute(plan_path, output, work, runner_factory=signing.Runner, temp_root=None):
    """Prepare a new extractor exactly as a reviewed plan describes. Returns (status, report path)."""
    plan_path = signing.absolute(plan_path)
    plan_raw = signing.regular_input(str(plan_path), 'Plan').read_bytes()
    plan = signing.strict_json(plan_raw)
    need(plan.get('schema') == PLAN_SCHEMA and plan.get('method') in METHODS, 'Not an extractor preparation plan')
    request_check(plan['request'])
    source_route = 'source' in plan['request']
    need(plan['method'] == (SOURCE_METHOD if source_route else METHOD), 'The plan method differs from its producer route')
    allowed, limits = route_texts(source_route)
    producer_dir = signing.absolute(plan['request']['producer']).parent
    output = signing.new_file(output, 'Output extractor')
    work = signing.no_link_ancestors(work)
    need(not os.path.lexists(work) and work.parent.is_dir(), f'Work directory must be new in an existing directory: {work}')
    for what, path in (('Output', output), ('Work directory', work), ('Plan', plan_path)):
        need(not signing.within(path, producer_dir), f'{what} must be independent of the producer directory')
        for folder in source_input_dirs(plan['request']):
            need(not signing.within(path, folder), f'{what} must be independent of the source evidence, kit and bootloader directories')
    need(not signing.within(output, work), 'The output must not be inside the work directory')
    work.mkdir()
    temp = work / 'tmp'
    temp.mkdir()
    runner = runner_factory(temp)
    mode, team, target = plan['request']['mode'], plan['request']['team_id'], plan['request']['target_arch']
    report = {'schema': REPORT_SCHEMA, 'method': plan['method'], 'status': 'started', 'started_at': signing.now(), 'request': plan['request'],
              'plan': {'path': str(plan_path), 'bytes': len(plan_raw), 'sha256': sha(plan_raw)}, 'pinned': plan['pinned'], 'tool': plan.get('tool'),
              'producer': None, 'reproduction': None, 'members': [], 'archive': None, 'outer': None, 'verification': None, 'output': None,
              'allowed_differences': allowed, 'commands': runner.records, 'steps': [], 'failure': None,
              'signature_kind': plan['signature_kind'], 'developer_id_ready': False, 'notarized': False, 'release_accepted': False, 'limits': limits}
    if source_route:
        report['source'] = None
    status = 'failed'
    created = False
    created_fd = None
    try:
        fresh, route = inspect_route(plan['request'], temp_root=temp)
        need(plan_body(fresh) == plan_body(plan), 'Producer, tool, pinned PyInstaller, source evidence or analysis changed since the plan')
        need(plan['ready_for_execution'], 'The plan has blockers')
        if source_route:
            report['source'] = fresh['source']
        report['steps'].append('plan-rederived')
        data = signing.regular_input(plan['request']['producer'], 'Producer extractor').read_bytes()
        need(sha(data) == plan['request']['producer_sha256'], 'Producer changed after inspection')
        producer = work / 'producer'
        signing.write_private(producer, data)
        report['producer'] = {k: plan['producer'][k] for k in ('path', 'bytes', 'sha256', 'signature_independent_sha256', 'uuids', 'archive', 'sdk')}
        # The re-derived route, never the plan's copy: the stock bootloader, or the
        # evidence-bound compiled bootloader of the controlled-source route.
        stock_bytes, stock = route['bootloader'], route['slices']
        name = plan['producer']['name']
        sdk = plan['producer']['sdk']
        # Precondition: the same pinned steps rebuild the producer from its own PKG.
        analysis = {'archive': plan['producer']['archive']}
        source_pkg = work / 'producer.pkg'
        signing.write_private(source_pkg, build_pkg(data, analysis, producer, {}))
        need(signing.file_identity(source_pkg)['sha256'] == plan['producer']['archive']['pkg_sha256'], 'Producer PKG rebuild differs')
        rebuilt = assemble(runner, stock_bytes, source_pkg, target, work / 'reproduction', name, 'development-adhoc', '-', sdk)
        reproduced = signing.signature_independent_sha256(rebuilt.read_bytes())
        need(reproduced == plan['producer']['signature_independent_sha256'], 'The pinned PyInstaller steps do not reproduce the producer outside its signature')
        report['reproduction'] = {'signature_independent_sha256': reproduced, 'equal_to_producer': True, 'mode': 'development-adhoc',
                                  'note': route['reproduction_note']}
        report['steps'].append('producer-reproduced')
        # Re-sign each native member; only its signature may change.
        _, entries = signing.archive_entries(producer)
        start = plan['producer']['archive']['start']
        members_dir = work / 'members'
        members_dir.mkdir()
        replacements = {}
        for member in plan['members']:
            if 'native' not in member:
                continue
            plain = payload.extract_member(producer, start, entries[member['index']][1])
            need(sha(plain) == member['expanded']['sha256'], f"{member['name']}: producer member changed")
            path = members_dir / f"{member['index']:05d}"
            signing.write_private(path, plain)
            obj = {'path': 'member:' + member['name'], 'filetype': 'dylib', 'hardened_runtime': False, 'action': 'sign', 'entitlements': {},
                   'identifier': member['native']['identifier'],
                   'source': {k: member['native'][k] for k in ('signature_independent_sha256', 'signature_layout')}}
            runner(signing.sign_argv(plan['request']['identity'], mode, obj, None, path), label='sign:' + obj['path'])
            result = signing.verify_object(runner, {'mode': mode, 'team_id': team}, obj, path)
            if mode == 'developer-id':
                runner([signing.CODESIGN, '--verify', '--strict', '--all-architectures', f'--test-requirement=={signing.developer_id_requirement(team)}', str(path)],
                       label='requirement:' + obj['path'])
            replacements[member['index']] = path.read_bytes()
            need(sha(replacements[member['index']]) == result['sha256'], f"{member['name']}: signed member changed during verification")
            report['members'].append({'index': member['index'], 'name': member['name'], 'identifier': obj['identifier'],
                                      'before': member['expanded'], 'after': {'bytes': result['bytes'], 'sha256': result['sha256']},
                                      'signature_independent_sha256': result['signature_independent_sha256'], 'signature_only_change': True,
                                      'comparison': result['signature_comparison'], 'signature': result['signature']})
        report['steps'].append('members-signed')
        candidate_pkg = work / 'candidate.pkg'
        signing.write_private(candidate_pkg, build_pkg(data, analysis, producer, replacements))
        report['archive'] = {'before': plan['producer']['archive'], 'after': signing.file_identity(candidate_pkg)}
        exe = assemble(runner, stock_bytes, candidate_pkg, target, work / 'assembly', name, mode, plan['request']['identity'], sdk)
        verify_outer(runner, exe, mode, team)
        report['steps'].append('outer-assembled')
        candidate = exe.read_bytes()
        with tempfile.TemporaryDirectory(prefix='omd-extractor-proof-', dir=temp) as folder:
            ppath, before = private_analysis(data, target, stock, folder, 'producer')
            cpath, after = private_analysis(candidate, target, stock, folder, 'candidate')
            need(after['embedded_versions'] == [plan['request']['version']], 'Candidate embedded version differs')
            proof = compare(before, after, ppath, cpath, data, candidate)
            if source_route:
                binding = route['module'].producer_binding(route, before, data, ppath)
                need(binding == fresh['source']['producer_binding'], 'The producer binding changed during execution')
                report['source'] = {**fresh['source'], 'candidate_outer': route['module'].candidate_outer(route, after, candidate, cpath, binding)}
            checks = cryptographic(cpath, mode, team, folder)
        need(checks['members']['failed'] == 0 and checks['members']['native_members'] == len(replacements) and checks['outer']['exit'] == 0,
             'Candidate cryptographic verification failed')
        report['archive']['after'] = after['archive']
        report['outer'] = {'before': {k: before[k] for k in ('bytes', 'sha256', 'signature_independent_sha256', 'uuids', 'producer_signature')},
                           'after': {k: after[k] for k in ('bytes', 'sha256', 'signature_independent_sha256', 'uuids', 'producer_signature', 'signature_layout')}}
        report['verification'] = {'structural_equivalence': proof, 'cryptographic': checks}
        report['steps'].append('candidate-verified')
        with open(output, 'xb') as stream:  # new file only; from here on this run owns it
            created = True
            # Keep the created inode alive through verification and failure cleanup.
            # The path can be replaced; a pathname alone does not establish ownership.
            created_fd = os.dup(stream.fileno())
            stream.write(candidate)
        output.chmod(0o755)
        identity = signing.file_identity(output)
        need(identity == {'bytes': len(candidate), 'sha256': sha(candidate)}, 'Written output differs from the verified candidate')
        need(signing.file_identity(signing.regular_input(plan['request']['producer'], 'Producer'))['sha256'] == plan['request']['producer_sha256'], 'Producer changed during execution')
        # Ad-hoc signatures are deterministic: a producer already signed exactly so is reproduced
        # unchanged, and the signing workflow refuses such a file as unprepared.
        report['output'] = {'path': str(output), **identity, 'mode': '0755', 'identical_to_producer': candidate == data}
        status = DONE[mode == 'developer-id']
    except (ValueError, OSError, KeyError, struct.error, AssertionError, RuntimeError, signing.CommandFailed, zlib.error) as error:
        report['failure'] = f'{type(error).__name__}: {error}'
        if created:
            report['output_removed'] = False
            try:
                need(created_fd is not None, 'Output ownership descriptor is unavailable')
                owned = os.fstat(created_fd)
                current = output.lstat()
                if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
                    output.unlink()
                    report['output_removed'] = True
                else:
                    report['cleanup_skipped'] = 'Output path no longer names the file created by this run'
            except FileNotFoundError:
                report['output_removed'] = True
            except (OSError, ValueError) as cleanup_error:
                report['cleanup_failure'] = f'{type(cleanup_error).__name__}: {cleanup_error}'
    finally:
        if created_fd is not None:
            try:
                os.close(created_fd)
            except OSError as cleanup_error:
                report['cleanup_failure'] = f'{type(cleanup_error).__name__}: {cleanup_error}'
    report['status'] = status
    report['finished_at'] = signing.now()
    path = work / 'extractor-report.json'
    signing.write_new(path, signing.json_bytes(report))
    return status, path
