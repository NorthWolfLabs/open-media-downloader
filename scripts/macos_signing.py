"""macOS application signing preparation (omd-macos-signing-plan-v1).

Inspection is read-only: it validates a staged plugin-free reference app and
writes a reviewable plan. Execution is a separate explicit step that re-derives
the same plan, signs a new independent copy and records every command and
verification. Neither step notarizes, accepts a release or touches credentials.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import materials_contract
import native_review
import public_inputs

PLAN_SCHEMA = 'omd-macos-signing-plan-v1'
REPORT_SCHEMA = 'omd-macos-signing-report-v1'
RECEIPTS_SCHEMA = 'omd-macos-signing-receipts-v1'
POLICY_SCHEMA = 'omd-macos-signing-policy-v1'
INVENTORY_SIGNING_SCHEMA = 'omd-macos-signing-inventory-v1'
MODES = ('development-adhoc', 'developer-id')
TRIPLES = {'arm64': 'aarch64-apple-darwin', 'x86_64': 'x86_64-apple-darwin'}
CODESIGN = '/usr/bin/codesign'
SCRIPTS = Path(__file__).resolve().parent
POLICY_PATH = SCRIPTS.parent / 'distribution' / 'macos-signing-policy.json'
MAX_EXTRACTOR_BYTES = 1024**3
OUTPUT_LIMIT = 4096
HEX64 = re.compile(r'[a-f0-9]{64}')
TEAM = re.compile(r'[A-Z0-9]{10}')
BUNDLE_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+')
DEVELOPER_ID = re.compile(r'Developer ID Application: (.+) \(([A-Z0-9]{10})\)')
WRONG_IDENTITIES = ('Apple Development', 'Apple Distribution', 'Mac Developer', '3rd Party Mac Developer', 'Developer ID Installer', 'Mac App Distribution', 'Mac Installer Distribution')
FILETYPES = {2: 'execute', 6: 'dylib', 8: 'bundle'}
OPEN_GATES = [
    'Notarization and stapling (future: xcrun notarytool submit --keychain-profile PROFILE --wait, then stapler); no credentials are stored or read by this tool.',
    'Quarantined, pristine-account and offered-platform installation journeys against the final artifact hash.',
    'Third-party materials, source-route and managed-tool provenance review for the signed payload.',
    'Release-candidate and full-distribution acceptance; this tool always records release_accepted false.',
]

MODE_LIMITS = {
    'development-adhoc': ['Ad-hoc signatures have no Team ID and are never distributable.',
                          'Library validation rejects ad-hoc libraries in hardened processes, so browser and extractor runtime behavior of this rehearsal is not representative.'],
    'developer-id': ['Execution needs the operator keychain identity; this tool never stores, reads or requests credentials.',
                     'A successful run is a signed candidate only: notarization, stapling and acceptance remain separate.'],
}

# Why the copy is signed. `distribution-candidate` (the default) is the only purpose
# that can produce a candidate. `private-validation` is an explicit Developer ID-only
# opt-in for local same-Team runtime checks of an input whose release materials are
# not ready yet; it is bound into the plan and must be requested again at execution.
PURPOSES = ('distribution-candidate', 'private-validation')
# The only blockers private validation may carry: release-material readiness gaps.
# Identity, Team, roles, entitlements, code layouts, the payload minimum and
# prepared-extractor problems are never tolerated, and execution-time verification
# failures always fail the run.
PRIVATE_VALIDATION_TOLERATED = frozenset({
    'development-staging', 'materials-bind-pre-signature', 'receipts-not-configured', 'engine-receipt-missing',
    'engine-receipt-binary-set', 'engine-receipt-selection', 'desktop-receipt-selection', 'receipt-version',
    'engine-review-scope', 'desktop-review-scope'})
# How release materials reach the final payload. `single-phase` (the default) keeps the
# pre-signature materials blocker. `two-phase` is an explicit Developer ID
# distribution-candidate opt-in for two-phase release staging: the in-app
# omd-materials-v1 manifest stays the unchanged initial review, and the signed output
# awaits a separate final binding (scripts/bind-final-materials.py) outside the app.
BINDINGS = ('single-phase', 'two-phase')
TWO_PHASE_STATUS = 'signed-awaiting-final-materials'
TWO_PHASE_DEFERRED = ['desktop-rust', 'frontend']
PURPOSE_LIMITS = {
    'distribution-candidate': ['Every blocker stops Developer ID execution; a successful run is a distribution candidate only.'],
    'private-validation': ['Private validation only: the copy is Developer ID signed for local same-Team checks and is never a distribution candidate.',
                           'Tolerated release-material gaps remain listed as release blockers; nothing here clears, approves or rewrites reviewed materials.',
                           'Do not notarize, staple, publish or give this copy to users; sign a release-staged input as a distribution candidate instead.'],
}


class Blocked(Exception):
    """A required prerequisite is unavailable; the step must not claim success."""


class CommandFailed(Exception):
    def __init__(self, record):
        super().__init__(f"{record['label']} exited {record['exit']}: {record['stderr'][-400:]}")
        self.record = record


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def strict_json(data):
    return native_review.strict_json(data.decode('utf-8') if isinstance(data, bytes) else data)


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


payload = load_script('omd_check_macos_payload', 'check-macos-payload.py')
_generator = None


def generator():
    global _generator
    if _generator is None:
        _generator = load_script('omd_generate_native_notices', 'generate-native-notices.py')
    return _generator


# ---------------------------------------------------------------- paths

def absolute(path):
    return Path(os.path.abspath(path))


def no_link_ancestors(path):
    """Reject any existing symlink component; later components may be absent."""
    path = absolute(path)
    for part in [*reversed(path.parents), path]:
        try:
            mode = part.lstat().st_mode
        except FileNotFoundError:
            break
        need(not stat.S_ISLNK(mode), f'Symlink path component: {part}')
    return path


def fold(path):
    return unicodedata.normalize('NFD', str(path)).casefold()


def within(child, parent):
    child, parent = fold(child), fold(parent).rstrip('/')
    return child == parent or child.startswith(parent + '/')


def regular_input(path, what):
    need(isinstance(path, str) and os.path.isabs(path), f'{what} must be an absolute path')
    no_link_ancestors(path)
    return public_inputs.regular(path)


def new_file(path, what):
    """A new output file in an existing, link-free directory."""
    path = no_link_ancestors(path)
    need(not os.path.lexists(path), f'{what} already exists: {path}')
    need(path.parent.is_dir(), f'{what} directory does not exist: {path.parent}')
    return path


def write_new(path, data):
    with open(path, 'xb') as stream:
        stream.write(data)


def json_bytes(value, sort=True):
    return (json.dumps(value, indent=2, sort_keys=sort, ensure_ascii=False) + '\n').encode()


def file_identity(path):
    with open(path, 'rb') as stream:
        return {'bytes': os.fstat(stream.fileno()).st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


# ---------------------------------------------------------------- Mach-O

THIN = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xcf': ('>', 32), b'\xce\xfa\xed\xfe': ('<', 28), b'\xfe\xed\xfa\xce': ('>', 28)}


def is_macho(head):
    return head[:4] in THIN or head[:4] in payload.FAT


def slice_regions(data):
    """(offset, length) for each thin image; structure is validated by the payload gate."""
    payload.slices(data)
    magic = data[:4]
    if magic not in payload.FAT:
        return [(0, len(data))]
    endian, wide = payload.FAT[magic]
    count, = struct.unpack_from(endian + 'I', data, 4)
    size = 32 if wide else 20
    regions = []
    for i in range(count):
        _, _, off, length = struct.unpack_from(endian + ('IIQQ' if wide else 'IIII'), data, 8 + i * size)
        regions.append((off, length))
    return regions


def load_commands(image):
    endian, header = THIN[image[:4]]
    cpu, subtype, filetype, count, _ = struct.unpack_from(endian + 'IIIII', image, 4)
    commands, off = [], header
    for _ in range(count):
        cmd, size = struct.unpack_from(endian + 'II', image, off)
        commands.append((cmd, off, size))
        off += size
    return endian, cpu, subtype, filetype, commands


def cstring(blob, offset):
    need(0 < offset < len(blob), 'Invalid code directory string')
    end = blob.find(b'\0', offset)
    need(end >= 0, 'Unterminated code directory string')
    return blob[offset:end].decode('utf-8', 'strict')


def image_signature(image):
    """Parse the embedded code signature of one thin image without executing it."""
    endian, cpu, subtype, filetype, commands = load_commands(image)
    found = [(off, size) for cmd, off, size in commands if cmd == 0x1d]
    base = {'cpu': cpu, 'subtype': subtype, 'filetype': FILETYPES.get(filetype, filetype)}
    if not found:
        return {**base, 'signed': False}
    need(len(found) == 1, 'Multiple code signature commands')
    dataoff, datasize = struct.unpack_from(endian + 'II', image, found[0][0] + 8)
    need(dataoff + datasize <= len(image) and datasize >= 12, 'Truncated code signature')
    blob = image[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from('>III', blob, 0)
    need(magic == 0xfade0cc0 and 12 + 8 * count <= length <= len(blob) and count <= 64, 'Invalid code signature superblob')
    slots = {}
    for i in range(count):
        kind, offset = struct.unpack_from('>II', blob, 12 + 8 * i)
        need(offset + 8 <= length, 'Invalid code signature slot')
        _, size = struct.unpack_from('>II', blob, offset)
        need(8 <= size and offset + size <= length and kind not in slots, 'Invalid code signature blob')
        slots[kind] = blob[offset:offset + size]
    directory = slots.get(0)
    need(directory is not None and len(directory) >= 44, 'Missing code directory')
    cd_magic, _, version, flags, _, ident_offset = struct.unpack_from('>IIIIII', directory, 0)
    need(cd_magic == 0xfade0c02, 'Invalid code directory')
    team = None
    if version >= 0x20200 and len(directory) >= 52:
        team_offset, = struct.unpack_from('>I', directory, 48)
        team = cstring(directory, team_offset) if team_offset else None
    entitlements = None
    if 5 in slots:
        need(slots[5][:4] == b'\xfa\xde\x71\x71', 'Invalid entitlements blob')
        entitlements = plistlib.loads(slots[5][8:])
    cms = slots.get(0x10000, b'')
    return {**base, 'signed': True, 'identifier': cstring(directory, ident_offset), 'team': team,
            'flags': flags, 'adhoc': bool(flags & 0x2), 'runtime': bool(flags & 0x10000),
            'linker_signed': bool(flags & 0x20000), 'certificates': len(cms) > 8,
            'entitlements': entitlements, 'code_directory_version': hex(version)}


def signature(data):
    return [image_signature(data[off:off + length]) for off, length in slice_regions(data)]


LAYOUT_VERSION = 'omd-macho-signature-layout-v2'
# codesign_allocate rounds a grown __LINKEDIT vmsize to these page sizes (observed:
# 16K for arm64 and x86_64 on macOS 27; 4K kept for older x86_64 producers).
LINKEDIT_PAGES = {0x100000c: (0x4000,), 0x1000007: (0x1000, 0x4000)}


def thin_layout(image):
    """(record, canonical bytes) for one thin image.

    Only three values may depend on the signature: LC_CODE_SIGNATURE datasize and
    __LINKEDIT filesize/vmsize. filesize is excluded only after proving __LINKEDIT
    ends exactly at the signature, which must end the image; vmsize is excluded
    from the digest and constrained by the paired check in signature_change.
    """
    endian, cpu, subtype, _, commands = load_commands(image)
    signatures = [at for cmd, at, _ in commands if cmd == 0x1d]
    linkedits = [(cmd, at) for cmd, at, _ in commands if cmd in (0x1, 0x19) and image[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT']
    need(len(signatures) <= 1 and len(linkedits) <= 1, 'Ambiguous code signature or __LINKEDIT load commands')
    record = {'cpu': cpu, 'subtype': subtype, 'signed': bool(signatures)}
    if not signatures:
        return {**record, 'bytes': len(image)}, image
    need(linkedits, 'Signed image has no __LINKEDIT segment')
    at = signatures[0]
    dataoff, datasize = struct.unpack_from(endian + 'II', image, at + 8)
    need(datasize > 0 and dataoff + datasize == len(image), 'The code signature must end its image; trailing or overlapping bytes are unsupported')
    cmd, seg = linkedits[0]
    wide = cmd == 0x19
    fields = endian + ('QQQQ' if wide else 'IIII')
    _, vmsize, fileoff, filesize = struct.unpack_from(fields, image, seg + 24)
    vm_at, file_at, width = (seg + 32, seg + 48, 'Q') if wide else (seg + 28, seg + 36, 'I')
    need(fileoff <= dataoff and fileoff + filesize == dataoff + datasize, '__LINKEDIT must end exactly at the code signature')
    need(vmsize >= filesize, '__LINKEDIT vmsize is smaller than its file size')
    canonical = bytearray(image[:dataoff])
    struct.pack_into(endian + 'I', canonical, at + 12, 0)
    struct.pack_into(endian + width, canonical, vm_at, 0)
    struct.pack_into(endian + width, canonical, file_at, 0)
    return {**record, 'signature_offset': dataoff, 'signature_bytes': datasize,
            'linkedit': {'fileoff': fileoff, 'filesize': filesize, 'vmsize': vmsize}}, bytes(canonical)


def macho_layout(data):
    """Validated signature-independent structure and digest of a thin or FAT file.

    Every byte is either digested, part of a slice's code signature, one of the
    validated signature-dependent fields above, or FAT placement (slice offset,
    size, alignment and zero padding). Nonzero unassigned bytes and any data after
    the last slice fail closed.
    """
    payload.slices(data)
    digest = hashlib.sha256(LAYOUT_VERSION.encode() + b'\0')
    magic = data[:4]
    if magic in payload.FAT:
        endian, wide = payload.FAT[magic]
        count, = struct.unpack_from(endian + 'I', data, 4)
        size = 32 if wide else 20
        arches = []
        for i in range(count):
            if wide:
                cpu, subtype, off, length, align, reserved = struct.unpack_from(endian + 'IIQQII', data, 8 + i * size)
            else:
                (cpu, subtype, off, length, align), reserved = struct.unpack_from(endian + 'IIIII', data, 8 + i * size), 0
            need(align <= 16 and off % (1 << align) == 0, 'FAT slice offset is not aligned as declared')
            arches.append({'cpu': cpu, 'subtype': subtype, 'offset': off, 'bytes': length, 'align': align, 'reserved': reserved})
        cursor = 8 + count * size
        for arch in sorted(arches, key=lambda a: a['offset']):
            gap = data[cursor:arch['offset']]
            need(gap.count(0) == len(gap), 'Nonzero unassigned bytes in the FAT container are unsupported')
            cursor = arch['offset'] + arch['bytes']
        need(cursor == len(data), 'Bytes after the last FAT slice are unsupported')
        container = {'format': 'fat64' if wide else 'fat', 'arches': arches}
        digest.update(b'fat' + magic + struct.pack('>I', count))
        for arch in arches:
            digest.update(struct.pack('>IIQ', arch['cpu'], arch['subtype'], arch['reserved']))
        regions = [(a['offset'], a['bytes']) for a in arches]
    else:
        container = {'format': 'thin'}
        digest.update(b'thin')
        regions = [(0, len(data))]
    slices = []
    for off, length in regions:
        record, canonical = thin_layout(data[off:off + length])
        digest.update(struct.pack('>IIQ', record['cpu'], record['subtype'], len(canonical)))
        digest.update(hashlib.sha256(canonical).digest())
        slices.append(record)
    return {'version': LAYOUT_VERSION, 'container': container, 'slices': slices}, digest.hexdigest()


def signature_independent_sha256(data):
    """Digest of all non-signature content; see macho_layout for what is excluded."""
    return macho_layout(data)[1]


def signature_change(before_sha256, before, data):
    """Paired proof that re-signing changed only signature data and permitted fields.

    Digest equality covers every other byte. Each slice must already carry a
    signature (adding one rewrites load commands), and the signed __LINKEDIT vmsize
    may only keep its value or become the page-rounded new file size.
    """
    after, after_sha256 = macho_layout(data)
    need(before['version'] == after['version'] == LAYOUT_VERSION and len(before['slices']) == len(after['slices']), 'Signature layout version or slice count changed')
    for old, new in zip(before['slices'], after['slices']):
        need(old['signed'] and new['signed'], 'Unsigned input slices are unsupported: adding a signature rewrites load commands')
    need(after_sha256 == before_sha256, 'bytes other than the signature changed')
    for old, new in zip(before['slices'], after['slices']):
        filesize = new['linkedit']['filesize']
        allowed = {old['linkedit']['vmsize']} | {-(-filesize // page) * page for page in LINKEDIT_PAGES.get(new['cpu'], (0x1000, 0x4000))}
        need(new['linkedit']['vmsize'] in allowed, '__LINKEDIT vmsize changed beyond page-rounded signature growth')
    relocated = before['container'] != after['container']
    return {'method': 'paired-structure', 'version': LAYOUT_VERSION, 'container': after['container']['format'], 'slices': len(after['slices']),
            'fat_slices_relocated': relocated, 'signature_bytes': [s['signature_bytes'] for s in after['slices']],
            'linkedit_vmsize': [[o['linkedit']['vmsize'], n['linkedit']['vmsize']] for o, n in zip(before['slices'], after['slices'])]}


def producer_summary(signatures):
    """Retained provenance only; never used to grant policy."""
    return [{k: s.get(k) for k in ('cpu', 'filetype', 'signed', 'identifier', 'team', 'adhoc', 'runtime', 'linker_signed', 'certificates', 'entitlements')} for s in signatures]


def packed_native_members(path, arch):
    """Bounded CArchive member signatures for a PyInstaller payload (no extraction to disk)."""
    from PyInstaller.archive.readers import CArchiveReader
    try:
        _, inventory = payload.packed_members(path, path.name, arch)
        archive = CArchiveReader(str(path))
    except RuntimeError as error:
        raise ValueError(f'Not a readable PyInstaller CArchive payload: {error}') from error
    members = []
    for name, entry in archive.toc.items():
        data = payload.extract_member(path, archive._start_offset, entry)
        if is_macho(data):
            members.append({'name': name, 'sha256': sha(data), 'bytes': len(data), 'signature': producer_summary(signature(data)),
                            'minimum': payload.component(data, name, arch)['minimum']})
    need(len(members) == sum(1 for row in inventory if row['macho']), 'Packed member inventory changed during inspection')
    return inventory, members


def member_summary(members):
    teams, kinds = {}, {'unsigned': 0, 'adhoc': 0, 'linker-signed': 0, 'certificate': 0}
    for member in members:
        for image in member['signature']:
            teams[image.get('team') or 'none'] = teams.get(image.get('team') or 'none', 0) + 1
            if not image['signed']:
                kinds['unsigned'] += 1
            else:
                kinds['linker-signed' if image['linker_signed'] else 'adhoc' if image['adhoc'] else 'certificate'] += 1
    return {'native_members': len(members), 'images_by_team': dict(sorted(teams.items())), 'images_by_signature': kinds}


# Pinned PyInstaller 6.22 CArchive entry types. 'd' (load from a sibling
# executable) is rejected: it would load code outside the verified archive.
CARCHIVE_TYPES = {'b', 'x', 'z', 'Z', 'm', 'M', 's', 'o', 'l', 'n'}
CARCHIVE_EXTRACTED = {'b', 'x', 'Z', 'n'}
MAX_TOC_BYTES = 64 * 1024**2
MAX_LINK_BYTES = 4096
MAX_MATERIALIZED_BYTES = 1024**3
VERIFY_TIMEOUT = 300
PACKED_VERIFICATION_LIMITS = [
    'Static verification only: no packed member is executed or loaded.',
    'Only members that begin with a Mach-O magic are verified; code inside other containers or written at runtime relies on runtime library validation.',
    'Certificate trust is evaluated by the local Security framework at inspection time; revocation and notarization status are not established.',
]


def developer_id_requirement(team):
    """Developer ID Application leaf under Apple's Developer ID CA, pinned to the Team ID."""
    need(TEAM.fullmatch(team or ''), 'Invalid Team ID for the Developer ID requirement')
    return ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            f'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "{team}"')


def archive_entries(path):
    """Every raw CArchive TOC entry, in order. The pinned reader's dict collapses
    duplicate names, so the TOC is reparsed and must match it exactly."""
    from PyInstaller.archive.readers import CArchiveReader
    try:
        archive = CArchiveReader(str(path))
    except RuntimeError as error:  # includes the reader's ArchiveReadError
        raise ValueError(f'Not a readable PyInstaller CArchive payload: {error}') from error
    size = CArchiveReader._COOKIE_LENGTH
    with open(path, 'rb') as stream:
        stream.seek(archive._end_offset - size)
        magic, length, toc_offset, toc_length, _, _ = struct.unpack(CArchiveReader._COOKIE_FORMAT, stream.read(size))
        need(magic == CArchiveReader._COOKIE_MAGIC_PATTERN and archive._start_offset >= 0, 'Invalid CArchive cookie')
        need(toc_length <= MAX_TOC_BYTES and toc_offset + toc_length <= length, 'CArchive TOC exceeds its archive')
        stream.seek(archive._start_offset + toc_offset)
        toc = stream.read(toc_length)
    need(len(toc) == toc_length, 'Truncated CArchive TOC')
    entries, pos = [], 0
    while pos < len(toc):
        need(pos + 18 <= len(toc), 'Truncated CArchive TOC entry')
        entry_length, offset, stored, expanded, flag, code = struct.unpack_from('!IIIIBc', toc, pos)
        need(entry_length > 18 and pos + entry_length <= len(toc), 'Invalid CArchive TOC entry length')
        name = toc[pos + 18:pos + entry_length].rstrip(b'\0').decode('utf-8')
        entries.append((name, (offset, stored, expanded, flag, code.decode('ascii'))))
        pos += entry_length
    members = [(name, entry) for name, entry in entries if entry[4] != 'o']
    need(len(members) == len(archive.toc) and dict(members) == archive.toc, 'Duplicate CArchive member names')
    return archive, entries


def check_archive_names(path, archive, entries):
    """Reject unknown or dependency entries, unsafe or colliding names, and links
    that escape, dangle or cycle. Links are validated, never materialized."""
    folded, extracted, links = set(), {}, {}
    for name, entry in entries:
        code = entry[4]
        need(code in CARCHIVE_TYPES, f'Unsupported CArchive entry type {code!r}: {name!r}')
        if code == 'o':
            continue
        public_inputs.relative(name)
        need(fold(name) not in folded, f'Duplicate or case/normalization-colliding CArchive member: {name}')
        folded.add(fold(name))
        if code == 'n':
            raw = payload.extract_member(path, archive._start_offset, entry, MAX_LINK_BYTES)
            need(raw.endswith(b'\0') and raw.count(b'\0') == 1, f'Invalid CArchive link target: {name}')
            target = raw[:-1].decode('utf-8')
            public_inputs.relative(target)
            links[fold(name)] = fold(target)
        elif code in CARCHIVE_EXTRACTED:
            extracted[fold(name)] = name
    names = set(extracted) | set(links)
    directories = {'/'.join(n.split('/')[:i]) for n in extracted for i in range(1, n.count('/') + 1)}
    for name in names:
        parts = name.split('/')
        for i in range(1, len(parts)):
            need('/'.join(parts[:i]) not in names, f'CArchive member path passes through another member or link: {name}')

    def resolve(path, depth):
        need(depth < 32, 'CArchive link chain is cyclic or too deep')
        out = []
        for part in path.split('/'):
            here = '/'.join(out + [part])
            out = resolve('/'.join(out + [links[here]]), depth + 1).split('/') if here in links else out + [part]
        return '/'.join(out)
    for name in links:
        final = resolve(name, 0)
        need((final in extracted or final in directories) and final not in links, f'CArchive link does not resolve to an archive member: {name}')
    return len(links)


def codesign_check(argv, env, timeout=VERIFY_TIMEOUT):
    """One bounded static codesign verification: (exit status, stderr tail)."""
    need(Path(argv[0]) == Path(CODESIGN) and '--verify' in argv, 'Only codesign verification is permitted here')
    try:
        process = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout)
        return process.returncode, process.stderr.decode(errors='replace')[-OUTPUT_LIMIT:]
    except subprocess.TimeoutExpired:
        return 'timeout', ''


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def verify_packed_natives(path, mode, team, folder):
    """Materialize every packed Mach-O member one at a time as a private,
    non-executable file under `folder` and verify it cryptographically: every
    architecture's code pages against its code directory and, for Developer ID,
    the Developer ID Application requirement pinned to the signing Team ID."""
    requirement = developer_id_requirement(team) if mode == 'developer-id' else None
    archive, entries = archive_entries(path)
    links = check_archive_names(path, archive, entries)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('APPLE_', 'NOTARY', 'CODESIGN_'))}
    env['TMPDIR'] = str(folder)
    total, verified, failures, members = 0, 0, [], 0
    for index, (name, entry) in enumerate(entries):
        if entry[4] in ('o', 'n'):
            continue
        data = payload.extract_member(path, archive._start_offset, entry)
        if not is_macho(data):
            continue
        members += 1
        total += len(data)
        need(total <= MAX_MATERIALIZED_BYTES, 'Packed native members exceed the materialization budget')
        target = Path(folder) / f'member-{index:05d}'
        write_private(target, data)
        argv = [CODESIGN, '--verify', '--strict', '--all-architectures', *([f'--test-requirement=={requirement}'] if requirement else []), str(target)]
        code, err = codesign_check(argv, env)
        target.unlink()
        if code == 0:
            verified += 1
        else:
            failures.append({'member': name, 'exit': code, 'reason': ' '.join(err.replace(str(target), name).split())[-300:]})
    return {'method': 'codesign --verify --strict --all-architectures' + (' --test-requirement (Developer ID Application, Team ID)' if requirement else ''),
            'requirement': requirement, 'native_members': members, 'verified': verified, 'materialized_bytes': total,
            'links_validated': links, 'failures': failures[:20], 'failed': len(failures), 'limits': PACKED_VERIFICATION_LIMITS}


# ---------------------------------------------------------------- policy

def load_policy(path=POLICY_PATH):
    data = public_inputs.regular(path).read_bytes()
    policy = strict_json(data)
    need(set(policy) == {'schema', 'layout', 'resources', 'app_files', 'reviewed_entitlements', 'forbidden_entitlements', 'roles', 'sources'}, 'Invalid signing policy fields')
    need(policy['schema'] == POLICY_SCHEMA, 'Wrong signing policy schema')
    reviewed, forbidden = set(policy['reviewed_entitlements']), set(policy['forbidden_entitlements'])
    need(not reviewed & forbidden, 'Policy entitlement lists overlap')
    paths = set()
    for role in policy['roles']:
        need({'id', 'path', 'filetype', 'sign', 'entitlements', 'binding', 'basis'} <= set(role) <= {'id', 'path', 'filetype', 'sign', 'entitlements', 'binding', 'basis', 'receipt', 'marker', 'packed'}, 'Invalid signing role fields')
        need(role['path'] not in paths, 'Duplicate signing role path')
        paths.add(role['path'])
        need(role['filetype'] in ('execute', 'dylib') and role['sign'] in ('nested', 'outer-bundle', 'prepared-extractor'), 'Invalid signing role kind')
        need(isinstance(role['entitlements'], dict) and all(v is True for v in role['entitlements'].values()), 'Entitlements must be explicit true values')
        need(set(role['entitlements']) <= reviewed, f"Unreviewed entitlement for {role['id']}")
        need(role['filetype'] == 'execute' or not role['entitlements'], 'Libraries cannot carry entitlements')
        need(isinstance(role['basis'], str) and role['basis'].strip(), 'Each role needs a reviewed basis')
    need(sum(r['sign'] == 'outer-bundle' for r in policy['roles']) == 1, 'Exactly one outer bundle role')
    return policy, {'path': 'distribution/macos-signing-policy.json', 'bytes': len(data), 'sha256': sha(data)}


def expand(template, resources, executable):
    return template.replace('{resources}', resources).replace('{executable}', executable)


# ---------------------------------------------------------------- inspection

def check_identity(mode, identity, team):
    need(mode in MODES, 'Unknown signing mode')
    need(isinstance(identity, str) and identity, 'Missing signing identity')
    if mode == 'development-adhoc':
        need(identity == '-', 'development-adhoc mode signs only with the ad-hoc identity "-"')
        need(team is None, 'development-adhoc mode has no Team ID')
        return
    need(identity != '-', 'developer-id mode cannot use an ad-hoc identity')
    need(not identity.startswith(WRONG_IDENTITIES), 'Only a Developer ID Application identity can sign for direct distribution')
    need(isinstance(team, str) and TEAM.fullmatch(team), 'developer-id mode requires an explicit 10-character Team ID')
    named = DEVELOPER_ID.fullmatch(identity)
    need(named or re.fullmatch(r'[A-F0-9]{40}', identity), 'Identity must be "Developer ID Application: NAME (TEAMID)" or a SHA-1 certificate hash')
    need(not named or named[2] == team, 'Identity Team ID differs from --team-id')


def walk_bundle(app):
    """Regular files and directories only; safe, collision-free relative names."""
    files, names, seen = {}, [], {}
    total = 0
    for parent, dirnames, filenames in os.walk(app, followlinks=False):
        for name in sorted(dirnames) + sorted(filenames):
            path = Path(parent) / name
            rel = path.relative_to(app).as_posix()
            public_inputs.relative(rel)
            info = path.lstat()
            need(not stat.S_ISLNK(info.st_mode), f'Symlink in bundle: {rel}')
            key = fold(rel)
            need(seen.setdefault(key, rel) == rel, f'Case/normalization collision in bundle: {rel}')
            if stat.S_ISDIR(info.st_mode):
                names.append(rel)
                continue
            need(stat.S_ISREG(info.st_mode), f'Special file in bundle: {rel}')
            need(info.st_nlink == 1, f'Hard-linked bundle file: {rel}')
            total += info.st_size
            need(len(files) < public_inputs.MAX_FILES and total <= public_inputs.MAX_BYTES, 'Bundle exceeds the inspection budget')
            files[rel] = path
    return dict(sorted(files.items())), names


def read_identities(files):
    result, heads = {}, {}
    for rel, path in files.items():
        with open(path, 'rb') as stream:
            heads[rel] = stream.read(8)
            stream.seek(0)
            result[rel] = {'bytes': os.fstat(stream.fileno()).st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}
    return result, heads


def check_build_inventory(data, actual, arch):
    inventory = strict_json(data)
    need(isinstance(inventory, dict) and 'signing' not in inventory, 'Input resources were already processed by the signer; sign the staged build')
    need(inventory.get('platform') == 'darwin' and inventory.get('arch') == arch, 'Build inventory platform/architecture differs from the requested signing target')
    need(inventory.get('worker_profile') == 'release', 'Build inventory does not record a release worker')
    need(inventory.get('release_accepted') is False, 'Build inventory must record release_accepted false')
    need(inventory.get('staging_mode') in ('development', 'release'), 'Unknown staging mode')
    need(inventory.get('plugins') == {'mode': 'public', 'publishable': True, 'packages': []},
         'Only the public plugin-free layout is reviewed for signing; plugin packages need a new signing role review')
    rows = inventory.get('files')
    need(isinstance(rows, list) and rows, 'Invalid build inventory files')
    recorded, folded = {}, set()
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'sha256', 'size'}, 'Invalid build inventory entry')
        public_inputs.relative(row['path'])
        need(isinstance(row['sha256'], str) and HEX64.fullmatch(row['sha256']) and type(row['size']) is int and row['size'] >= 0, 'Invalid build inventory identity')
        need(row['path'] not in recorded and fold(row['path']) not in folded, f"Duplicate build inventory entry: {row['path']}")
        need(not row['path'].startswith('providers/') and row['path'] != 'build-inventory.json', 'Unexpected build inventory member')
        recorded[row['path']] = {'bytes': row['size'], 'sha256': row['sha256']}
        folded.add(fold(row['path']))
    need(set(recorded) == set(actual), 'Resource files differ from the build inventory: ' + ', '.join(sorted(set(recorded) ^ set(actual))[:8]))
    for rel, identity in recorded.items():
        need(actual[rel] == identity, f'Resource changed after staging: {rel}')
    return inventory


def check_tools_manifest(data, roles, actual):
    manifest = strict_json(data)
    need(isinstance(manifest, dict) and set(manifest) == {'yt_dlp', 'ffmpeg', 'ffprobe', 'node'}, 'Unexpected managed media tool set')
    for name, row in manifest.items():
        need(isinstance(row, dict) and set(row) == {'path', 'version', 'sha256'}, f'Invalid managed tool entry: {name}')
        need(isinstance(row['version'], str) and row['version'] and HEX64.fullmatch(row['sha256']), f'Invalid managed tool identity: {name}')
        rel = 'tools/' + public_inputs.relative(row['path'])
        role = roles.get('tool:' + name)
        need(role is not None and role == rel, f'Managed tool {name} is not at its reviewed role path')
        need(actual.get(rel, {}).get('sha256') == row['sha256'], f'Managed tool digest differs from its bytes: {name}')
    return manifest


def check_browser_manifest(data, tools, actual):
    manifest = strict_json(data)
    need(isinstance(manifest, dict) and set(manifest) == {'root', 'version', 'browser', 'adapter', 'node', 'files'}, 'Unexpected browser manifest fields')
    need(manifest['root'] == 'content' and manifest['browser'] == 'browser/chrome-headless-shell' and manifest['adapter'] == 'adapter/adapter.mjs', 'Unexpected browser layout')
    need(manifest['node'] == {'path': '../tools/' + tools['node']['path'], 'sha256': tools['node']['sha256'], 'version': tools['node']['version']}, 'Browser Node identity differs from the managed Node tool')
    files = manifest['files']
    present = {rel[len('browser/content/'):]: v for rel, v in actual.items() if rel.startswith('browser/content/')}
    need(isinstance(files, dict) and set(files) == set(present), 'Browser files differ from the browser manifest')
    for rel, row in files.items():
        public_inputs.relative(rel)
        need(row == present[rel], f'Browser file changed: {rel}')
    return manifest


def load_receipts_config(path, arch):
    data = regular_input(path, 'Receipt inputs').read_bytes()
    config = strict_json(data)
    need(set(config) == {'schema', 'target', 'version', 'engine', 'desktop'} and config['schema'] == RECEIPTS_SCHEMA, 'Invalid receipt inputs')
    need(config['target'] == TRIPLES[arch] and isinstance(config['version'], str) and config['version'], 'Receipt target/version mismatch')
    for kind in ('engine', 'desktop'):
        section = config[kind]
        need(isinstance(section, dict) and set(section) == {'manifest', 'roots', 'binaries', 'features', 'upstream_materials', 'review'}, f'Invalid {kind} receipt inputs')
        manifest = regular_input(section['manifest'], f'{kind} Cargo manifest')
        need(manifest.name == 'Cargo.toml', f'{kind} manifest must be Cargo.toml')
        public_inputs.regular(manifest.with_name('Cargo.lock'))
        regular_input(section['review'], f'{kind} prior review')
        if section['upstream_materials'] is not None:
            regular_input(section['upstream_materials'], f'{kind} upstream materials')
        for key in ('roots', 'binaries'):
            need(isinstance(section[key], list) and section[key] and all(isinstance(x, str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', x) for x in section[key]) and len(set(section[key])) == len(section[key]), f'Invalid {kind} {key}')
        need(isinstance(section['features'], str), f'Invalid {kind} features')
    return config, {'path': str(absolute(path)), 'bytes': len(data), 'sha256': sha(data)}


def input_identities(config):
    """Every external receipt input bound by hash."""
    result = {}
    for kind in ('engine', 'desktop'):
        section = config[kind]
        manifest = Path(section['manifest'])
        for label, file in [('manifest', manifest), ('lock', manifest.with_name('Cargo.lock')), ('review', Path(section['review']))] + ([('upstream', Path(section['upstream_materials']))] if section['upstream_materials'] else []):
            result[f'{kind}:{label}'] = {'path': str(file), **file_identity(file)}
    return result


def run_generator(kind, section, target, artifacts, output, review=None):
    """Invoke the existing native notice generator in-process from its checkout."""
    namespace = argparse.Namespace(
        manifest=Path(section['manifest']), output=output, root=list(section['roots']), binary=list(section['binaries']),
        artifact=[f'{name}={file}' for name, file in artifacts], features=section['features'], target=target,
        upstream_materials=Path(section['upstream_materials']) if section['upstream_materials'] else None, review_evidence=review)
    with contextlib.chdir(Path(section['manifest']).parent):
        return generator().generate(namespace)


def scope_differences(prior, fresh):
    return [k for k in native_review.SCOPE_KEYS if canonical(prior.get(k)) != canonical(fresh.get(k))]


def prior_review(section):
    data = Path(section['review']).read_bytes()
    review = strict_json(data)
    need(isinstance(review, dict) and isinstance(review.get('scope'), dict), f"Prior review lacks a scope: {section['review']}")
    return review


def receipt_scope_check(kind, section, target, artifacts, temp_root):
    """The prior review must bind the exact staged input before signing.

    Artifact-only rebinding is permitted later, after the signing transform has
    proven equivalence to this input; it cannot authorize unrelated input bytes.
    """
    with tempfile.TemporaryDirectory(prefix=f'omd-{kind}-scope-', dir=temp_root) as folder:
        output = Path(folder) / 'prepared'
        code = run_generator(kind, section, target, artifacts, output)
        fresh = json.loads((output / 'review-scope.json').read_text())
    review = prior_review(section)
    differences = scope_differences(review['scope'], fresh)
    return {'generator_exit': code, 'differences_before_signing': differences,
            'prior_review_binds_input_artifacts': 'artifacts' not in differences,
            'carry_after_signing': not differences}


def inspect(request, temp_root=None):
    """Read-only validation and plan construction; raises ValueError for invalid input."""
    mode, identity, team, arch = request['mode'], request['identity'], request.get('team_id'), request['arch']
    purpose = request.get('purpose', 'distribution-candidate')
    binding = request.get('materials_binding', 'single-phase')
    need(arch in TRIPLES, 'Unsupported architecture')
    need(purpose in PURPOSES, 'Unknown signing purpose')
    need(purpose == 'distribution-candidate' or mode == 'developer-id', 'The private-validation purpose applies only to developer-id signing')
    need(binding in BINDINGS, 'Unknown materials binding')
    need(binding == 'single-phase' or (mode == 'developer-id' and purpose == 'distribution-candidate'),
         'Two-phase materials binding applies only to developer-id distribution-candidate signing')
    check_identity(mode, identity, team)
    policy, policy_identity = load_policy()
    app = no_link_ancestors(request['app'])
    need(app.suffix == '.app' and app.is_dir() and not app.is_symlink(), 'Input must be an existing .app directory')
    files, _ = walk_bundle(app)
    identities, heads = read_identities(files)
    for rel, head in heads.items():
        need(not head.startswith(b'OMDP2\0'), f'Plugin package in public application: {rel}')
    info = strict_plist(files.get('Contents/Info.plist'))
    executable, bundle_id = info['CFBundleExecutable'], info['CFBundleIdentifier']
    icon = info.get('CFBundleIconFile', '')
    icon = icon if not icon or icon.endswith('.icns') else icon + '.icns'
    resources = policy['resources']
    allowed = {expand(x, resources, executable).replace('{icon}', icon) for x in policy['app_files']['required']}
    if not icon:
        allowed.discard('Contents/Resources/')
    optional = set(policy['app_files']['optional']) | {policy['app_files']['input_seal']}
    prefix = resources + '/'
    resource_files = {rel[len(prefix):]: v for rel, v in identities.items() if rel.startswith(prefix)}
    outside = set(identities) - {prefix + rel for rel in resource_files}
    need(allowed <= outside, 'Missing required bundle files: ' + ', '.join(sorted(allowed - outside)))
    need(outside <= allowed | optional, 'Unexpected bundle members: ' + ', '.join(sorted(outside - allowed - optional)[:8]))
    need('build-inventory.json' in resource_files, 'Missing build inventory')
    inventory_bytes = files[prefix + 'build-inventory.json'].read_bytes()
    staged = {k: v for k, v in resource_files.items() if k != 'build-inventory.json'}
    inventory = check_build_inventory(inventory_bytes, staged, arch)
    roles, bindings = {}, {}
    for role in policy['roles']:
        path = expand(role['path'], resources, executable)
        roles[path] = role
        rel = path[len(prefix):] if path.startswith(prefix) else None
        if role['binding'].startswith('tool:'):
            bindings[role['binding']] = rel
    tools = check_tools_manifest(files[prefix + 'tools/tools-v2.json'].read_bytes(), bindings, staged)
    browser = check_browser_manifest(files[prefix + 'browser/browser-tools-v2.json'].read_bytes(), tools, staged)
    declared = info['LSMinimumSystemVersion']
    try:
        gate = payload.check(app, arch)
    except RuntimeError as error:
        raise ValueError(f'Payload gate could not read a packed archive: {error}') from error
    blockers = []

    def block(ident, severity, subject, message, action):
        blockers.append({'id': ident, 'severity': severity, 'subject': subject, 'message': message, 'action': action})

    if not gate['pass']:
        block('payload-minimum', 'signing', 'Contents/Info.plist', f"Declared macOS {declared} is below the payload floor {gate['required']}", 'Correct the bundle minimum or dependencies; never lower binary metadata')
    floors = {c['path']: c['minimum'] for c in gate['components']}
    objects = []
    seen_roles = set()
    for rel, head in heads.items():
        if not is_macho(head):
            continue
        data = files[rel].read_bytes()
        images = signature(data)
        role = roles.get(rel)
        try:
            layout, independent = macho_layout(data)
        except ValueError as error:  # Fail closed: such an object can never be proven signature-only.
            layout, independent = {'unsupported': str(error)}, None
        source = {**identities[rel], 'signature_independent_sha256': independent, 'signature_layout': layout, 'producer_signature': producer_summary(images)}
        entry = {'path': rel, 'source': source, 'architectures': sorted({payload_arch(s['cpu']) for s in images}), 'minimum': floors.get(rel)}
        if role is None:
            entry.update(role='unrecognized', action='stop')
            block('unrecognized-code', 'signing', rel, 'Mach-O code without a reviewed signing role', 'Review a logical role and entitlements in distribution/macos-signing-policy.json before signing')
            objects.append(entry)
            continue
        seen_roles.add(rel)
        if role['filetype'] == 'execute':
            need(files[rel].stat().st_mode & 0o100, f'{rel}: reviewed executable lacks owner execute permission')
        need(all(s['filetype'] == role['filetype'] for s in images), f"{rel}: Mach-O type differs from its reviewed role ({role['filetype']})")
        need(arch in entry['architectures'], f'{rel}: missing {arch} slice')
        if 'marker' in role:
            need(role['marker'].encode() in data, f"{rel}: required marker {role['marker']} is absent")
        name = 'bin/' + rel.rsplit('/', 1)[-1] if role['binding'] == 'engine-bin' else None
        identifier = bundle_id if role['sign'] == 'outer-bundle' else f"{bundle_id}.{role['id']}" + ('.' + rel.rsplit('/', 1)[-1].removesuffix('.dylib') if role['id'] == 'browser-library' else '')
        entry.update(role=role['id'], filetype=role['filetype'], entitlements=role['entitlements'], identifier=identifier,
                     hardened_runtime=role['filetype'] == 'execute', receipt=role.get('receipt'), basis=role['basis'],
                     action={'nested': 'sign', 'outer-bundle': 'outer-bundle', 'prepared-extractor': 'prepared-extractor'}[role['sign']],
                     rank={'dylib': 1, 'execute': 2}[role['filetype']] if role['sign'] != 'outer-bundle' else 3)
        if name:
            entry['receipt_binary'] = name[4:]
        if role.get('packed'):
            inventory_rows, members = packed_native_members(files[rel], arch)
            entry['packed'] = {'format': role['packed'], 'members': len(inventory_rows), **member_summary(members),
                               'evidence': 'parsed signature metadata only; prepared extractors are verified cryptographically'}
        objects.append(entry)
    missing = set(roles) - seen_roles
    need(not missing, 'Missing reviewed code objects: ' + ', '.join(sorted(missing)))
    objects.sort(key=lambda o: (o.get('rank', 0), o['path']))
    for index, entry in enumerate(objects):
        entry['order'] = index + 1
    # Prepared extractor contract, or an explicit blocker.
    extractor = next(o for o in objects if o.get('action') == 'prepared-extractor')
    prepared = None
    if request.get('prepared_extractor'):
        prepared = check_prepared_extractor(request['prepared_extractor'], tools['yt_dlp'], arch, mode, team, declared, extractor, temp_root, files[extractor['path']])
        extractor['action'] = 'replace-and-sign'
        extractor['replacement'] = prepared
        for problem in prepared.pop('problems'):
            block('prepared-extractor', 'signing', extractor['path'], problem, 'Supply an extractor whose packed native members all pass cryptographic verification (Developer ID: signed by the signing team)')
    else:
        extractor['action'] = 'retain' if mode == 'development-adhoc' else 'stop'
        teams = extractor['packed']['images_by_team']
        block('prepared-extractor-missing', 'release' if mode == 'development-adhoc' else 'signing', extractor['path'],
              f"Packed yt-dlp has {extractor['packed']['native_members']} native members (images by team: {teams}); re-signing the outer bootloader does not make them pass hardened-runtime library validation",
              'Supply --prepared-extractor with an exact digest/version/architecture whose members carry the signing Team ID; development mode retains the producer bytes unchanged')
    for entry in objects:
        layout = entry['source']['signature_layout']
        if entry.get('action') in ('sign', 'outer-bundle') and ('unsupported' in layout or not all(s['signed'] for s in layout['slices'])):
            block('unsupported-code-layout', 'signing', entry['path'], 'Signature-only change cannot be proven: ' + layout.get('unsupported', 'an unsigned slice would gain new load commands'),
                  'Rebuild or repackage the object so every byte belongs to a slice or its existing code signature')
    if mode == 'developer-id' and inventory['staging_mode'] != 'release':
        block('development-staging', 'signing', prefix + 'build-inventory.json', 'Developer ID signing of development-staged resources would bypass release material guards', 'Stage with --staging-mode release, or rehearse with development-adhoc')
    if inventory['staging_mode'] == 'release' or 'third-party/materials-v1.json' in staged:
        final_binding, unavailable = two_phase_initial(inventory, staged, files, prefix) if binding == 'two-phase' else (None, None)
        block('materials-bind-pre-signature', 'release' if final_binding or mode != 'developer-id' else 'signing', 'third-party/materials-v1.json',
              'The reviewed materials manifest binds pre-signature payload digests; this tool never rewrites reviewed materials'
              + (f'; two-phase binding unavailable: {unavailable}' if unavailable else ''),
              'Sign with --materials-binding two-phase and bind the signed payload with bind-final-materials.py' if binding == 'single-phase' or unavailable
              else 'After signing, bind the signed payload to this initial review with bind-final-materials.py; the output is not a candidate until then')
        if final_binding:
            blockers[-1]['final_binding'] = final_binding
    version = info.get('CFBundleShortVersionString')
    receipts = inspect_receipts(request, staged, files, prefix, objects, arch, executable, version, temp_root, block, mode)
    if purpose == 'private-validation':
        for blocker in blockers:
            if blocker['id'] in PRIVATE_VALIDATION_TOLERATED and blocker['severity'] == 'signing':
                blocker.update(severity='release', purpose_tolerance={
                    'purpose': purpose, 'original_severity': 'signing',
                    'effect': 'Signing continues for private validation only; this release gap stays open and the output is never a distribution candidate.'})
    plan = {
        'schema': PLAN_SCHEMA, 'request': request_record(request, receipts.pop('config_identity', None)),
        'purpose': purpose, 'purpose_limits': PURPOSE_LIMITS[purpose], 'materials_binding': binding,
        'mode': mode, 'identity': identity, 'team_id': team, 'architecture': arch,
        'policy': policy_identity,
        'input': {'app': str(app), 'resources': resources, 'bundle_id': bundle_id, 'executable': executable, 'version': version, 'declared_minimum': declared,
                  'files': len(identities), 'bytes': sum(v['bytes'] for v in identities.values()),
                  'inventory_sha256': sha(canonical(identities).encode()), 'build_inventory': {'bytes': len(inventory_bytes), 'sha256': sha(inventory_bytes)},
                  'staging_mode': inventory['staging_mode'], 'input_seal': identities.get(policy['app_files']['input_seal'])},
        'checks': {'payload_minimum': {'pass': gate['pass'], 'required': gate['required'], 'declared': declared,
                                       'components': len(gate['components']), 'packed_components': sum('!/' in c['path'] for c in gate['components'])},
                   'public_resources': {'files': len(staged), 'plugins': 0, 'plugin_framed_files': 0, 'symlinks': 0},
                   'managed_manifests': {'tools': sorted(tools), 'browser_files': len(browser['files'])}},
        'code_objects': objects,
        'transformations': transformations(objects, prefix, receipts, mode, purpose),
        'receipts': receipts,
        'blockers': blockers,
        'ready_for_execution': not any(b['severity'] == 'signing' for b in blockers),
        'complete_without_blockers': not blockers,
        'distinctions': {
            'source': 'Input bytes: the identities bound by materials, provenance and native receipts before signing.',
            'payload': 'Post-signature bytes: what manifests, inventories and fresh receipts must bind after execution.',
            'signature_independent_sha256': 'Digest of every byte except each slice code signature, its dependent size fields and FAT slice placement; unassigned or trailing bytes fail closed.',
            'signature_only_change': 'Equal digests plus a paired before/after layout check: existing signatures only, __LINKEDIT ends at the signature, vmsize kept or page-rounded.'},
        'mode_limits': MODE_LIMITS[mode],
        'open_gates': OPEN_GATES, 'developer_id_signed': False, 'notarized': False, 'release_accepted': False,
    }
    if expected := request.get('expected_inventory'):
        check_expected_inventory(expected, identities)
    return plan


def two_phase_initial(inventory, staged, files, prefix):
    """(record, None) when the input is two-phase release staging with an in-app,
    complete omd-materials-v1 initial review; otherwise (None, reason). The manifest
    is only identified here; bind-final-materials.py validates it against the input."""
    materials = inventory.get('materials')
    if inventory['staging_mode'] != 'release':
        return None, 'the input is not release-staged'
    if not (isinstance(materials, dict) and materials.get('coverage_validated') is True and materials.get('release_accepted') is False
            and materials.get('binding') == 'two-phase' and materials.get('deferred') == TWO_PHASE_DEFERRED):
        return None, 'the build inventory does not record validated two-phase release staging'
    row = staged.get('third-party/materials-v1.json')
    if row is None:
        return None, 'third-party/materials-v1.json is not installed'
    try:
        manifest = strict_json(files[prefix + 'third-party/materials-v1.json'].read_bytes())
    except ValueError as error:
        return None, f'the in-app manifest is not strict JSON: {error}'
    if not (isinstance(manifest, dict) and manifest.get('schema') == 'omd-materials-v1' and manifest.get('reviewed') is True and manifest.get('pending') == []):
        return None, 'the in-app manifest is not a complete omd-materials-v1 review'
    return {'binding': 'two-phase', 'initial_review': {'path': prefix + 'third-party/materials-v1.json', **row}, 'deferred': list(TWO_PHASE_DEFERRED),
            'effect': 'The signed output awaits final materials binding outside the app; it is not a distribution candidate until bound.'}, None


def payload_arch(cpu):
    return {0x100000c: 'arm64', 0x1000007: 'x86_64'}.get(cpu, hex(cpu))


def strict_plist(path):
    need(path is not None, 'Missing Info.plist')
    info = plistlib.loads(path.read_bytes())
    need(isinstance(info, dict) and info.get('CFBundlePackageType') == 'APPL', 'Info.plist is not an application bundle')
    need(isinstance(info.get('CFBundleExecutable'), str) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}', info['CFBundleExecutable']), 'Invalid CFBundleExecutable')
    need(isinstance(info.get('CFBundleIdentifier'), str) and BUNDLE_ID.fullmatch(info['CFBundleIdentifier']), 'Invalid CFBundleIdentifier')
    payload.version(info.get('LSMinimumSystemVersion'))
    icon = info.get('CFBundleIconFile', '')
    need(isinstance(icon, str) and (not icon or re.fullmatch(r'[A-Za-z0-9._-]{1,128}', icon)), 'Invalid CFBundleIconFile')
    return info


def check_expected_inventory(expected, identities):
    data = regular_input(expected['path'], 'Expected inventory').read_bytes()
    need(sha(data) == expected['sha256'], 'Expected inventory changed since the plan')
    rows = strict_json(data)
    need(rows == identities, 'Application differs from the expected exact inventory')


def check_prepared_extractor(spec, managed, arch, mode, team, declared, current, temp_root=None, producer=None):
    need(set(spec) - {'report', 'source'} == {'path', 'sha256', 'version', 'arch'}, 'Prepared extractor needs path, sha256, version and arch')
    # Controlled-source evidence is an explicit route for the transformation proof, so it
    # only exists together with the preparation report whose proof is repeated.
    need('source' not in spec or 'report' in spec, 'Controlled-source evidence requires the preparation report; the transformation proof is repeated from it')
    need(HEX64.fullmatch(spec['sha256'] or ''), 'Prepared extractor digest must be 64 lowercase hex characters')
    path = regular_input(spec['path'], 'Prepared extractor')
    need(path.stat().st_size <= MAX_EXTRACTOR_BYTES, 'Prepared extractor exceeds the size budget')
    data = path.read_bytes()
    need(sha(data) == spec['sha256'], 'Prepared extractor digest differs from the requested digest')
    need(spec['sha256'] != current['source']['sha256'], 'Prepared extractor is the unprepared producer executable')
    need(spec['version'] == managed['version'], f"Prepared extractor version {spec['version']} differs from the reviewed managed version {managed['version']}")
    need(spec['arch'] == arch, 'Prepared extractor architecture differs from the signing target')
    need(is_macho(data), 'Prepared extractor is not Mach-O')
    outer = payload.component(data, 'prepared-extractor', arch)
    need(all(image['filetype'] == 2 for image in payload.slices(data)), 'Prepared extractor is not an executable')
    layout, independent = macho_layout(data)
    # Every later read uses a private copy of the digest-checked bytes, so the
    # members parsed and verified are exactly the bytes that will be installed.
    with tempfile.TemporaryDirectory(prefix='omd-prepared-extractor-', dir=temp_root) as folder:
        private = Path(folder) / 'prepared-extractor'
        write_private(private, data)
        verification = verify_packed_natives(private, mode, team, folder)  # raw TOC checks first
        inventory, members = packed_native_members(private, arch)
    need(verification['native_members'] == len(members), 'Packed native member set differs between parsing and verification')
    floor = max([outer['minimum'], *(m['minimum'] for m in members)], key=payload.version)
    need(payload.version(floor) <= payload.version(declared), f'Prepared extractor requires macOS {floor}, above the declared {declared}')
    problems = [] if all(s['signed'] for s in layout['slices']) else ['Prepared extractor has an unsigned slice; signature-only change cannot be proven']
    for member in members:
        for image in member['signature']:
            if not image['signed']:
                problems.append(f"Packed member {member['name']} is unsigned")
            elif mode == 'developer-id' and (image['team'] != team or not image['certificates']):
                problems.append(f"Packed member {member['name']} has Team ID {image['team'] or 'none'}, not {team}")
    for failure in verification['failures']:
        problems.append(f"Packed member {failure['member']} failed cryptographic signature verification"
                        + (' against the Developer ID Team requirement' if verification['requirement'] else '') + f": {failure['reason']}")
    result = {'sha256': spec['sha256'], 'bytes': len(data), 'version': spec['version'], 'arch': arch, 'path': str(path),
              'signature_independent_sha256': independent, 'signature_layout': layout, 'producer_signature': producer_summary(signature(data)),
              'packed': {'members': len(inventory), **member_summary(members), 'signature_verification': verification}, 'minimum': floor, 'problems': problems[:20],
              'provenance': 'Replacement bytes differ from the reviewed upstream executable; its corresponding-source and materials review is a separate gate.'}
    if 'report' in spec:
        # Optional preparation report: the structural signature-only proof is repeated from
        # the app's own producer bytes; the report itself only binds identities.
        import macos_extractor
        need(producer is not None, 'A preparation report needs the producer extractor')
        result['transformation'] = proof = macos_extractor.check_report(spec['report'], spec, producer, current['source']['sha256'], mode, team, temp_root,
                                                                        source=spec.get('source'))
        if spec.get('source') is None:
            result['provenance'] = (f"Signature-only transformation of the producer {proof['producer_sha256']}, re-proven at inspection: {proof['signature_only_natives']} native members "
                                    f"changed only in their code signatures, {proof['identical_non_natives']} other members are byte-identical and the bootloader is identical "
                                    'outside PyInstaller PKG-derived fields. The producer corresponding-source and materials review remains a separate gate.')
        else:
            found = proof['source']
            result['provenance'] = (f"Signature-only transformation of the controlled-source producer {proof['producer_sha256']}, re-proven at inspection from the app's "
                                    f"producer bytes and the digest-bound source evidence {found['evidence_sha256']} (kit {found['kit_sha256']}, compiled bootloader "
                                    f"{found['bootloader_sha256']}): {proof['signature_only_natives']} native members changed only in their code signatures, "
                                    f"{proof['identical_non_natives']} other members are byte-identical and the outer executable is the compiled bootloader outside "
                                    'PyInstaller PKG-derived fields. Compilation from the kit sources and the kit source/terms review are build and review evidence.')
    return result


def inspect_receipts(request, staged, files, prefix, objects, arch, executable, version, temp_root, block, mode):
    severity = 'signing' if mode == 'developer-id' else 'release'
    engine_names = sorted(o['receipt_binary'] for o in objects if o.get('receipt') == 'engine')
    result = {'engine_binaries': engine_names, 'desktop_binary': executable,
              'sequence': ['sign nested code objects in plan order',
                           'regenerate the engine receipt from signed engine bytes; carry review findings only by explicit artifact-only rebinding',
                           'install the fresh engine receipt, then rewrite managed manifests and build inventory to post-signature digests',
                           'seal the outer bundle and verify every nested signature',
                           'bind the sealed desktop executable in a detached external receipt; never inside the app']}
    installed = staged.get('third-party/native-receipt.json')
    if installed is None:
        result['installed_engine_receipt'] = None
        block('engine-receipt-missing', severity, prefix + 'third-party/native-receipt.json', 'No installed engine receipt', 'Stage the reviewed engine receipt and native-NOTICES.txt')
    else:
        receipt = strict_json(files[prefix + 'third-party/native-receipt.json'].read_bytes())
        need(isinstance(receipt, dict), 'Installed native receipt is not a JSON object')
        notices = files.get(prefix + 'third-party/native-NOTICES.txt')
        artifacts = receipt.get('artifacts') if isinstance(receipt.get('artifacts'), list) else []
        bound = {a.get('name'): a.get('sha256') for a in artifacts if isinstance(a, dict)}
        current = {n: staged.get('bin/' + n, {}).get('sha256') for n in engine_names}
        status = {'identity': installed, 'binaries': receipt.get('binaries'), 'binds_input_bytes': all(bound.get(n) == current[n] for n in engine_names),
                  'after_signing': 'stale: binds pre-signature engine bytes'}
        try:
            need(notices is not None, 'Missing installed native-NOTICES.txt')
            materials_contract.validate_native_receipt(receipt, {k: v['sha256'] for k, v in staged.items()}, engine_names, receipt.get('lock_sha256'), TRIPLES[arch], notices.read_bytes(), version)
            status['structural_validation_against_bundle'] = 'pass (lock taken from the receipt itself)'
        except ValueError as error:
            status['structural_validation_against_bundle'] = f'fail: {error}'
        binaries = receipt.get('binaries')
        status['selects_bundled_binaries'] = isinstance(binaries, list) and all(isinstance(x, str) for x in binaries) and sorted(binaries) == engine_names
        result['installed_engine_receipt'] = status
    config = request.get('receipts')
    if not config:
        result['config'] = None
        if installed is not None and not result['installed_engine_receipt']['selects_bundled_binaries']:
            block('engine-receipt-binary-set', severity, prefix + 'third-party/native-receipt.json',
                  f"Installed receipt selects {result['installed_engine_receipt']['binaries']}; this app bundles {engine_names}",
                  'Prepare and review a receipt scope that selects exactly the bundled engine binaries')
        block('receipts-not-configured', severity, 'receipts', 'Fresh signed-engine and detached desktop receipts cannot be generated without receipt inputs',
              'Supply --receipts with exact checkouts, prior reviews and upstream materials')
        return result
    cfg, identity = load_receipts_config(config, arch)
    result['config_identity'] = identity
    result['config'] = {'target': cfg['target'], 'version': cfg['version'], 'inputs': input_identities(cfg)}
    if cfg['version'] != version:
        block('receipt-version', severity, 'receipts', f"Receipt version {cfg['version']} differs from bundle version {version}", 'Use the bundle version')
    if sorted(cfg['engine']['binaries']) != engine_names:
        block('engine-receipt-selection', severity, 'receipts', f"Engine receipt selects {cfg['engine']['binaries']}; bundled engine binaries are {engine_names}", 'Select exactly the bundled engine binaries')
    if cfg['desktop']['binaries'] != [executable]:
        block('desktop-receipt-selection', severity, 'receipts', f"Desktop receipt selects {cfg['desktop']['binaries']}, not {executable}", 'Select the bundle executable')
    for kind, artifacts in (('engine', [(n, files[prefix + 'bin/' + n]) for n in cfg['engine']['binaries'] if prefix + 'bin/' + n in files]),
                            ('desktop', [(executable, files['Contents/MacOS/' + executable])])):
        try:
            check = receipt_scope_check(kind, cfg[kind], cfg['target'], artifacts, temp_root)
        except Exception as error:  # Any generator rejection means findings cannot be carried.
            check = {'error': f'generator rejected this scope: {type(error).__name__}: {error}', 'carry_after_signing': False}
        result[kind] = check
        if not check['carry_after_signing']:
            block(f'{kind}-review-scope', severity, 'receipts', f"{kind} prior review does not bind the staged input scope: {check.get('differences_before_signing', check.get('error'))}",
                  'Factual findings are not carried; prepare a new review for the exact scope')
    return result


def request_record(request, receipts_identity):
    record = {k: request.get(k) for k in ('app', 'mode', 'identity', 'team_id', 'arch')}
    record['purpose'] = request.get('purpose', 'distribution-candidate')
    record['materials_binding'] = request.get('materials_binding', 'single-phase')
    record['prepared_extractor'] = request.get('prepared_extractor')
    record['receipts'] = receipts_identity
    record['expected_inventory'] = request.get('expected_inventory')
    return record


def transformations(objects, prefix, receipts, mode, purpose='distribution-candidate'):
    incomplete = mode == 'development-adhoc' or purpose == 'private-validation'
    rows = []
    for o in objects:
        if o.get('action') in ('sign', 'replace-and-sign'):
            rows.append({'path': o['path'], 'kind': 'nested-signature' if o['action'] == 'sign' else 'prepared-replacement-signature',
                         'note': 'Only the code signature, its dependent size fields and FAT slice placement may change' if o['action'] == 'sign' else 'Bytes replaced by the bound prepared extractor, then signed'})
    rows += [
        {'path': prefix + 'tools/tools-v2.json', 'kind': 'managed-manifest', 'note': 'sha256 values become post-signature payload digests; paths and versions unchanged'},
        {'path': prefix + 'browser/browser-tools-v2.json', 'kind': 'managed-manifest', 'note': 'node and signed browser file digests become post-signature; other files unchanged'},
        {'path': prefix + 'third-party/native-receipt.json', 'kind': 'engine-receipt',
         'note': 'Replaced by a fresh receipt bound to signed engine bytes before sealing' + ('; in incomplete development or private-validation output the stale receipt is removed and preserved externally' if incomplete else '')},
        {'path': prefix + 'build-inventory.json', 'kind': 'build-inventory', 'note': 'Post-signature payload digests plus a signing record; staging/material fields unchanged'},
        {'path': 'Contents/_CodeSignature/CodeResources', 'kind': 'outer-seal', 'note': 'Input seal discarded; regenerated by the final outer signature'},
        {'path': 'external: desktop-receipt/', 'kind': 'detached-desktop-receipt', 'note': 'Generated after sealing from the sealed executable; never placed inside the app'},
    ]
    return rows


# ---------------------------------------------------------------- execution

class Runner:
    """Records every command; never invokes keychain or notarization tools."""

    def __init__(self, temp):
        self.records = []
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('APPLE_', 'NOTARY', 'CODESIGN_'))}
        self.env['TMPDIR'] = str(temp)

    def __call__(self, argv, label, timeout=600, check=True):
        need(Path(argv[0]).name not in ('security', 'notarytool', 'altool', 'xcrun'), 'Credential/notarization tools are outside this workflow')
        started = time.monotonic()
        try:
            process = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, timeout=timeout)
            code, out, err = process.returncode, process.stdout, process.stderr
        except subprocess.TimeoutExpired as error:
            code, out, err = 'timeout', error.stdout or b'', error.stderr or b''
        record = {'label': label, 'argv': [str(x) for x in argv], 'exit': code, 'seconds': round(time.monotonic() - started, 3),
                  'stdout': out.decode(errors='replace')[-OUTPUT_LIMIT:], 'stderr': err.decode(errors='replace')[-OUTPUT_LIMIT:]}
        self.records.append(record)
        if check and code != 0:
            raise CommandFailed(record)
        return out


def plan_body(plan):
    return {k: v for k, v in plan.items() if k != 'created_at'}


def copy_app(source, output):
    """Independent copy: data and normalized modes only, no xattrs, links or seal."""
    files, dirs = walk_bundle(source)
    output.mkdir()
    for rel in dirs:
        if rel != 'Contents/_CodeSignature':
            (output / rel).mkdir()
    copied = {}
    for rel, path in files.items():
        if rel.startswith('Contents/_CodeSignature/'):
            continue
        target = output / rel
        shutil.copyfile(path, target)
        target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        copied[rel] = file_identity(target)
    return copied


def entitlements_plist(values):
    return plistlib.dumps(values, fmt=plistlib.FMT_XML)


def sign_argv(identity, mode, obj, entitlements_file, path):
    argv = [CODESIGN, '--force', '--sign', identity]
    if obj['hardened_runtime']:
        argv += ['--options', 'runtime']
    argv.append('--timestamp' if mode == 'developer-id' else '--timestamp=none')
    if obj['action'] != 'outer-bundle':
        argv += ['--identifier', obj['identifier']]
    if obj['entitlements']:
        argv += ['--entitlements', str(entitlements_file)]
    return argv + [str(path)]


def verify_object(runner, plan, obj, path):
    """Verify actual signature, flags, identifier, team and entitlements."""
    if obj['filetype'] == 'execute':
        need(Path(path).stat().st_mode & 0o100, f"{obj['path']}: signed executable lacks owner execute permission")
    runner([CODESIGN, '--verify', '--strict', '--all-architectures', path], label='verify:' + obj['path'])
    shown = runner([CODESIGN, '--display', '--entitlements', '-', '--xml', path], label='entitlements:' + obj['path'])
    actual = plistlib.loads(shown) if shown.strip() else {}
    need(actual == obj['entitlements'], f"{obj['path']}: signed entitlements {actual} differ from policy {obj['entitlements']}")
    data = Path(path).read_bytes()
    developer = plan['mode'] == 'developer-id'
    for image in signature(data):
        need(image['signed'] and image['identifier'] == obj['identifier'], f"{obj['path']}: unexpected signing identifier")
        need(image['adhoc'] is not developer and image['certificates'] is developer and image['team'] == plan['team_id'], f"{obj['path']}: signature mode/team mismatch")
        need(image['runtime'] is obj['hardened_runtime'] and not image['linker_signed'], f"{obj['path']}: hardened runtime flag mismatch")
        need((image['entitlements'] or {}) == obj['entitlements'], f"{obj['path']}: embedded entitlements mismatch")
    if developer:
        # Notarization needs a Developer ID chain and a secure timestamp, not a local signing time.
        runner([CODESIGN, '--display', '--verbose=2', path], label='details:' + obj['path'])
        details = runner.records[-1]['stderr']
        need("Authority=Developer ID Application:" in details and f"TeamIdentifier={plan['team_id']}" in details, f"{obj['path']}: not signed by the Developer ID team")
        need(re.search(r'^Timestamp=', details, re.M) and 'Signed Time=' not in details, f"{obj['path']}: missing secure timestamp")
    before = obj['replacement'] if obj['action'] == 'replace-and-sign' else obj['source']
    need(before['signature_independent_sha256'] is not None, f"{obj['path']}: unsupported layout; signature-only change cannot be proven")
    try:
        comparison = signature_change(before['signature_independent_sha256'], before['signature_layout'], data)
    except ValueError as error:
        raise ValueError(f"{obj['path']}: {error}") from error
    return {**file_identity(path), 'signature_independent_sha256': before['signature_independent_sha256'], 'signature_only_change': True,
            'signature_comparison': comparison, 'signature': producer_summary(signature(data))}


def resource_identities(resources):
    files, _ = walk_bundle(resources)
    return {rel: file_identity(path) for rel, path in files.items()}


def rewrite_manifests(resources, signed):
    """Update digests only; field order and other values are preserved."""
    tools_path, browser_path = resources / 'tools/tools-v2.json', resources / 'browser/browser-tools-v2.json'
    tools, browser = json.loads(tools_path.read_text()), json.loads(browser_path.read_text())
    for row in tools.values():
        row['sha256'] = file_identity(resources / 'tools' / row['path'])['sha256']
    browser['node']['sha256'] = tools['node']['sha256']
    for rel in browser['files']:
        if 'browser/content/' + rel in signed:
            browser['files'][rel] = file_identity(resources / 'browser/content' / rel)
    for path, value in ((tools_path, tools), (browser_path, browser)):
        path.write_bytes((json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode())
    return {'tools': {k: v['sha256'] for k, v in tools.items()}, 'browser_signed_files': sorted(r for r in browser['files'] if 'browser/content/' + r in signed)}


def rewrite_inventory(resources, signing):
    path = resources / 'build-inventory.json'
    inventory = json.loads(path.read_text())
    actual = {k: v for k, v in resource_identities(resources).items() if k != 'build-inventory.json'}
    inventory['files'] = [{'path': row['path'], 'sha256': actual[row['path']]['sha256'], 'size': actual[row['path']]['bytes']} for row in inventory['files'] if row['path'] in actual]
    need({row['path'] for row in inventory['files']} == set(actual), 'Signing introduced an unexpected resource')
    inventory['signing'] = signing
    path.write_bytes((json.dumps(inventory, indent=2, ensure_ascii=False) + '\n').encode())


def verify_public_resources(resources):
    """The plugin-free public layout survives signing exactly as inventoried."""
    inventory = json.loads((resources / 'build-inventory.json').read_text())
    actual = {k: v for k, v in resource_identities(resources).items() if k != 'build-inventory.json'}
    recorded = {row['path']: {'bytes': row['size'], 'sha256': row['sha256']} for row in inventory['files']}
    need(recorded == actual, 'Signed resources differ from the rewritten build inventory')
    need(inventory['plugins'] == {'mode': 'public', 'publishable': True, 'packages': []} and inventory['worker_profile'] == 'release', 'Signed resources are not the public plugin-free layout')
    for rel in actual:
        with open(resources / rel, 'rb') as stream:
            need(stream.read(6) != b'OMDP2\0', f'Plugin package in signed resources: {rel}')
    need(b'OMD_WORKER_PROFILE=release' in (resources / 'bin/omd-plugin-worker-v2').read_bytes(), 'Signed worker lost its release marker')
    return len(actual)


def copy_tree(source, destination):
    """Identity-verified copy of a review evidence directory (no links)."""
    expected = public_inputs.inventory(source)
    for rel in expected:
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / rel, target)
    need(public_inputs.inventory(destination) == expected, 'Review evidence changed while copying')
    return {'files': len(expected), 'bytes': sum(v['bytes'] for v in expected.values()), 'inventory_sha256': sha(canonical(expected).encode())}


def fresh_receipt(kind, section, target, artifacts, work):
    """Unreviewed preparation, explicit artifact-only rebinding, reviewed preparation."""
    folder = work / 'receipts'
    folder.mkdir(exist_ok=True)
    unreviewed = folder / f'{kind}-unreviewed'
    run_generator(kind, section, target, artifacts, unreviewed)
    fresh_scope = json.loads((unreviewed / 'review-scope.json').read_text())
    review_path = Path(section['review'])
    review = prior_review(section)
    differences = scope_differences(review['scope'], fresh_scope)
    record = {'kind': kind, 'differences': differences, 'prior_review': {'path': str(review_path), **file_identity(review_path)},
              'fresh_scope': file_identity(unreviewed / 'review-scope.json'), 'release_accepted': False}
    if not set(differences) <= {'artifacts'}:
        record['carried'] = False
        write_new(folder / f'{kind}-scope-mismatch.json', json_bytes(record))
        raise Blocked(f'{kind} review scope differs beyond artifacts: {differences}; findings not carried')
    evidence = review_path
    if differences:
        base = folder / f'{kind}-review-base'
        record['copied_review_base'] = copy_tree(review_path.parent, base)
        evidence = base / f'{kind}-rebound-review.json'
        need(not evidence.exists(), 'Rebound review name collides with prior evidence')
        write_new(evidence, json_bytes({**review, 'scope': fresh_scope}))
        record.update(artifact_only=True, facts_carried_unchanged=True, rebound_review=file_identity(evidence),
                      artifacts={'old': review['scope']['artifacts'], 'new': fresh_scope['artifacts']},
                      limits='Factual material coverage rebinding only; executable bytes changed by signing. No legal or release acceptance.')
    write_new(folder / f'{kind}-scope-rebinding.json', json_bytes(record))
    reviewed = folder / f'{kind}-reviewed'
    code = run_generator(kind, section, target, artifacts, reviewed, evidence)
    receipt = json.loads((reviewed / 'receipt.json').read_text())
    if code != 0 or receipt['pending']:
        raise Blocked(f"{kind} reviewed receipt still has pending items: {receipt['pending'][:3]}")
    return reviewed, receipt, (reviewed / 'native-NOTICES.txt').read_bytes(), record


def guarded(function, *args):
    """Generator rejections (including bare StopIteration) become explicit blockers."""
    try:
        return function(*args)
    except Blocked:
        raise
    except Exception as error:
        raise Blocked(f'native receipt preparation rejected: {type(error).__name__}: {error}') from error


def text_span_coverage(receipt, notices, resources):
    texts = []
    for path in sorted(resources.rglob('*')):
        if path.is_file() and (path.suffix == '.txt' or re.search(r'licen[cs]e|copying|copyright|notice|authors', path.name, re.I)):
            texts.append(path.read_bytes())
    spans = [t for p in receipt['packages'] for t in p['texts']] + receipt['runtime_materials']
    missing = [t['path'] for t in spans if not any(notices[t['offset']:t['offset'] + t['bytes']] in body for body in texts)]
    return len(spans), missing


def execute(plan_path, output, work, allow_incomplete=False, runner_factory=Runner, temp_root=None, purpose='distribution-candidate',
            materials_binding='single-phase'):
    """Explicit signing of a new independent copy. Returns (status, report path)."""
    plan_bytes = regular_input(str(absolute(plan_path)), 'Plan').read_bytes()
    plan = strict_json(plan_bytes)
    need(plan.get('schema') == PLAN_SCHEMA, 'Not a signing plan')
    mode = plan['mode']
    need(purpose in PURPOSES, 'Unknown signing purpose')
    need(materials_binding in BINDINGS, 'Unknown materials binding')
    # The purpose is chosen at inspection and must be requested again here, so a
    # private-validation plan never runs by default and a candidate plan is never
    # re-labelled private to carry its blockers.
    need(plan.get('purpose') == purpose, f"Plan purpose {plan.get('purpose')} differs from the requested execution purpose {purpose}")
    # Likewise the materials binding: a two-phase plan never runs by default.
    need(plan.get('materials_binding', 'single-phase') == materials_binding,
         f"Plan materials binding {plan.get('materials_binding', 'single-phase')} differs from the requested execution binding {materials_binding}")
    private = purpose == 'private-validation'
    two_phase = materials_binding == 'two-phase'
    need(not allow_incomplete or mode == 'development-adhoc', 'Incomplete output is only permitted for development-adhoc rehearsals')
    app = no_link_ancestors(plan['input']['app'])
    output, work = no_link_ancestors(output), no_link_ancestors(work)
    for a, b, why in ((output, app, 'Output and input overlap'), (app, output, 'Input lies inside the output'), (work, app, 'Work directory inside the input'),
                      (app, work, 'Input inside the work directory'), (work, output, 'Work directory inside the output'), (absolute(plan_path), output, 'Plan inside the output')):
        need(not within(a, b), why)
    need(output.suffix == '.app' and not os.path.lexists(output) and output.parent.is_dir(), 'Output must be a new .app path in an existing directory')
    need(not os.path.lexists(work) and work.parent.is_dir(), 'Work directory must be new')
    request = dict(plan['request'])
    if request.get('receipts'):
        need(file_identity(request['receipts']['path'])['sha256'] == request['receipts']['sha256'], 'Receipt inputs changed since the plan')
        request['receipts'] = request['receipts']['path']
    fresh = inspect(request, temp_root)
    need(canonical(plan_body(fresh)) == canonical(plan_body(plan)), 'Input, policy or prerequisites changed since the reviewed plan')
    blockers = plan['blockers']
    need(not any(b['severity'] == 'signing' for b in blockers), 'Signing blockers: ' + ', '.join(b['id'] for b in blockers if b['severity'] == 'signing'))
    if private:
        need(all(b['id'] in PRIVATE_VALIDATION_TOLERATED and b.get('purpose_tolerance') for b in blockers), 'Private validation carries only tolerated release-material gaps')
    if two_phase:
        need(mode == 'developer-id' and purpose == 'distribution-candidate' and len(blockers) == 1 and blockers[0]['id'] == 'materials-bind-pre-signature'
             and blockers[0].get('final_binding'), 'Two-phase signing carries only the pre-signature materials gap of two-phase release staging')
    need(not blockers or allow_incomplete or private or two_phase, 'Plan has blockers; development rehearsal requires --allow-incomplete-development, release modes stop')
    work.mkdir()
    (work / 'tmp').mkdir()
    (work / 'entitlements').mkdir()
    write_new(work / 'plan.json', plan_bytes)
    runner = runner_factory(work / 'tmp')
    report = {'schema': REPORT_SCHEMA, 'status': 'running', 'mode': mode, 'purpose': purpose, 'plan': {'path': str(absolute(plan_path)), 'bytes': len(plan_bytes), 'sha256': sha(plan_bytes)},
              'input_app': str(app), 'output_app': str(output), 'started_at': now(), 'steps': [], 'objects': [], 'blockers': list(blockers),
              'allow_incomplete_development': allow_incomplete, 'distribution_candidate': False,
              'developer_id_signed': False, 'notarized': False, 'notarization': 'not submitted', 'release_accepted': False}
    if private:
        report['private_validation'] = {'suitable_for_public_distribution': False, 'tolerated_release_gaps': [b['id'] for b in blockers], 'limits': PURPOSE_LIMITS[purpose]}
    if two_phase:
        report['materials_binding'] = materials_binding
        report['final_materials'] = {**blockers[0]['final_binding'], 'required': True, 'bound': False,
                                     'next': 'bind-final-materials.py prepare against this input, output, plan and report'}
    tolerate = allow_incomplete or private
    input_before = plan['input']['inventory_sha256']
    resources = output / plan['input']['resources']
    prefix = plan['input']['resources'] + '/'
    incomplete = []

    def step(name, **detail):
        report['steps'].append({'step': name, 'at': now(), **detail})

    try:
        copied = copy_app(app, output)
        reviewed = dict(copied)
        if plan['input']['input_seal'] is not None:
            reviewed['Contents/_CodeSignature/CodeResources'] = plan['input']['input_seal']
        need(sha(canonical(dict(sorted(reviewed.items()))).encode()) == input_before, 'Copied bytes differ from the reviewed input inventory')
        step('copy', files=len(copied), bound_to_reviewed_inventory=True)
        objects = plan['code_objects']
        for obj in objects:
            if obj.get('filetype') == 'execute':
                need((output / obj['path']).stat().st_mode & 0o100, f"{obj['path']}: copied executable lacks owner execute permission")
        extractor = next(o for o in objects if o.get('role') == 'yt-dlp')
        if extractor['action'] == 'replace-and-sign':
            target = output / extractor['path']
            source = Path(extractor['replacement']['path'])
            need(file_identity(source)['sha256'] == extractor['replacement']['sha256'], 'Prepared extractor changed since the plan')
            shutil.copyfile(source, target)
            target.chmod(0o755)
            need(file_identity(target)['sha256'] == extractor['replacement']['sha256'], 'Prepared extractor copy differs')
            step('install-prepared-extractor', sha256=extractor['replacement']['sha256'])
        signed = set()
        for obj in objects:
            if obj['action'] == 'outer-bundle':
                continue
            if obj['action'] not in ('sign', 'replace-and-sign'):
                report['objects'].append({'path': obj['path'], 'role': obj['role'], 'action': obj['action'], 'source': obj['source'],
                                          'payload': copied[obj['path']], 'note': 'Producer bytes retained unchanged'})
                continue
            path = output / obj['path']
            entitlements = work / 'entitlements' / f"{obj['order']:02d}-{obj['role']}.plist"
            if obj['entitlements']:
                write_new(entitlements, entitlements_plist(obj['entitlements']))
            runner(sign_argv(plan['identity'], mode, obj, entitlements, path), label='sign:' + obj['path'])
            result = verify_object(runner, plan, obj, path)
            report['objects'].append({'path': obj['path'], 'role': obj['role'], 'action': obj['action'], 'entitlements': obj['entitlements'],
                                      'source': obj['source'], 'replacement': obj.get('replacement'), 'payload': result})
            signed.add(obj['path'][len(prefix):])
        step('nested-signatures', signed=len(signed))
        step('managed-manifests', **rewrite_manifests(resources, signed))
        receipt_state = install_engine_receipt(plan, request, resources, work, report, incomplete, tolerate)
        rewrite_inventory(resources, {'schema': INVENTORY_SIGNING_SCHEMA, 'mode': mode, 'purpose': purpose, 'payload_digests': 'post-signature',
                                      'source_build_inventory_sha256': plan['input']['build_inventory']['sha256'],
                                      'engine_receipt': receipt_state, **({'materials_binding': materials_binding} if two_phase else {}),
                                      'release_accepted': False})
        step('public-resources', files=verify_public_resources(resources))
        before_seal = {rel: v for rel, v in resource_identities(output).items() if rel != 'Contents/MacOS/' + plan['input']['executable']}
        shell = next(o for o in objects if o['action'] == 'outer-bundle')
        runner(sign_argv(plan['identity'], mode, shell, None, output), label='seal:bundle')
        runner([CODESIGN, '--verify', '--deep', '--strict', '--verbose=2', output], label='verify:bundle')
        shell_result = verify_object(runner, plan, shell, output / shell['path'])
        report['objects'].append({'path': shell['path'], 'role': shell['role'], 'action': 'outer-bundle', 'source': shell['source'], 'payload': shell_result})
        after = {rel: v for rel, v in resource_identities(output).items() if rel not in ('Contents/MacOS/' + plan['input']['executable'], 'Contents/_CodeSignature/CodeResources')}
        need(after == before_seal, 'Outer sealing changed nested files')
        for obj in objects:
            if obj['action'] in ('sign', 'replace-and-sign'):
                verify_object(runner, plan, obj, output / obj['path'])
        gate = payload.check(output, plan['architecture'])
        need(gate['pass'], 'Signed payload fails the macOS minimum gate')
        step('seal', sealed_files=len(after) + 2, payload_minimum=gate['required'])
        if mode == 'developer-id' and extractor['action'] == 'replace-and-sign':
            shown = runner([output / extractor['path'], '--ignore-config', '--no-plugin-dirs', '--version'], label='extractor-version', timeout=60)
            need(shown.decode().strip() == extractor['replacement']['version'], 'Signed extractor failed its embedded-runtime version check')
        detached_desktop_receipt(plan, request, output, resources, work, report, incomplete, tolerate)
        need(file_identity(output / shell['path']) == shell_result_identity(shell_result), 'Sealed executable changed after receipt binding')
        need(sha(canonical(inventory_of(app)).encode()) == input_before, 'Input application changed during execution')
        step('input-unchanged')
        report['blockers'] += [{'id': x[0], 'severity': 'release', 'message': x[1]} for x in incomplete]
        if private:
            # Never a candidate, even when every signature and receipt passed.
            report['status'] = 'private-validation-incomplete' if incomplete else 'private-validation-signed'
            report['developer_id_signed'] = not incomplete
        elif two_phase:
            # Receipt gaps are never tolerated here (they raise above). Signed, but not a
            # candidate until bind-final-materials.py validates the final payload binding.
            need(not incomplete, 'Two-phase signing cannot carry receipt gaps')
            report['status'] = TWO_PHASE_STATUS
            report['developer_id_signed'] = True
        elif report['blockers']:
            report['status'] = 'incomplete-development'
        else:
            report['status'] = 'signed-developer-id-candidate' if mode == 'developer-id' else 'signed-development-candidate'
            report['developer_id_signed'] = report['distribution_candidate'] = mode == 'developer-id'
    except Blocked as error:
        report.update(status='blocked', failure=str(error))
    except Exception as error:  # Every failure is reported; nothing claims success.
        report.update(status='failed', failure=f'{type(error).__name__}: {error}')
    report['commands'] = runner.records
    report['finished_at'] = now()
    report['limits'] = ['Structural signing evidence only.', *(PURPOSE_LIMITS[purpose] if private else []), *OPEN_GATES]
    write_new(work / 'signing-report.json', json_bytes(report))
    return report['status'], work / 'signing-report.json'


def shell_result_identity(result):
    return {'bytes': result['bytes'], 'sha256': result['sha256']}


def inventory_of(app):
    files, _ = walk_bundle(app)
    return read_identities(files)[0]


def now():
    return datetime.now(timezone.utc).isoformat()


def install_engine_receipt(plan, request, resources, work, report, incomplete, allow):
    installed = resources / 'third-party/native-receipt.json'
    names = plan['receipts']['engine_binaries']
    if not request.get('receipts') or any(b['id'] in ('engine-review-scope', 'engine-receipt-selection', 'receipt-version', 'engine-receipt-missing') for b in plan['blockers']):
        if installed.exists():
            stale = work / 'stale'
            stale.mkdir()
            shutil.copyfile(installed, stale / 'native-receipt.pre-signature.json')
            installed.unlink()
            report['engine_receipt'] = {'status': 'removed-stale', 'preserved': str(stale / 'native-receipt.pre-signature.json'),
                                        'reason': 'Pre-signature receipt cannot bind signed engine bytes; no fresh reviewed receipt was available'}
            incomplete.append(('engine-receipt-stale', 'Stale pre-signature engine receipt removed from the output; no fresh reviewed receipt installed'))
            return 'removed-stale-pre-signature'
        incomplete.append(('engine-receipt-missing', 'No engine receipt installed'))
        return 'absent'
    cfg, _ = load_receipts_config(request['receipts'], plan['architecture'])
    artifacts = [(n, resources / 'bin' / n) for n in names]
    try:
        folder, receipt, notices, record = guarded(fresh_receipt, 'engine', cfg['engine'], cfg['target'], artifacts, work)
        need(notices == (resources / 'third-party/native-NOTICES.txt').read_bytes(), 'Fresh engine notice asset differs from the installed native-NOTICES.txt')
        files = {rel: v['sha256'] for rel, v in resource_identities(resources).items()}
        lock = sha(Path(cfg['engine']['manifest']).with_name('Cargo.lock').read_bytes())
        materials_contract.validate_native_receipt(receipt, files, names, lock, cfg['target'], notices, cfg['version'])
    except Blocked as error:
        if not allow:
            raise
        incomplete.append(('engine-receipt-blocked', str(error)))
        return install_engine_receipt(plan, {**request, 'receipts': None}, resources, work, report, incomplete, allow)
    old = file_identity(installed)
    installed.write_bytes((folder / 'receipt.json').read_bytes())
    report['engine_receipt'] = {'status': 'fresh', 'previous': old, 'installed': file_identity(installed), 'rebinding': record, 'validator': 'pass', 'spans': sum(len(p['texts']) for p in receipt['packages']) + len(receipt['runtime_materials'])}
    return 'fresh-post-signature'


def detached_desktop_receipt(plan, request, output, resources, work, report, incomplete, allow):
    if not request.get('receipts') or any(b['id'] in ('desktop-review-scope', 'desktop-receipt-selection', 'receipt-version') for b in plan['blockers']):
        report['desktop_receipt'] = {'status': 'not-generated'}
        incomplete.append(('desktop-receipt-missing', 'No detached receipt binds the sealed desktop executable'))
        return
    cfg, _ = load_receipts_config(request['receipts'], plan['architecture'])
    executable = output / 'Contents/MacOS' / plan['input']['executable']
    try:
        folder, receipt, notices, record = guarded(fresh_receipt, 'desktop', cfg['desktop'], cfg['target'], [(plan['input']['executable'], executable)], work)
        files = {'bin/' + plan['input']['executable']: file_identity(executable)['sha256'], 'third-party/native-NOTICES.txt': sha(notices)}
        lock = sha(Path(cfg['desktop']['manifest']).with_name('Cargo.lock').read_bytes())
        materials_contract.validate_native_receipt(receipt, files, cfg['desktop']['binaries'], lock, cfg['target'], notices, cfg['version'])
        spans, missing = text_span_coverage(receipt, notices, resources)
        if missing:
            raise Blocked(f'{len(missing)} desktop receipt text spans are absent from signed app resources')
    except Blocked as error:
        if not allow:
            raise
        report['desktop_receipt'] = {'status': 'blocked', 'reason': str(error)}
        incomplete.append(('desktop-receipt-blocked', str(error)))
        return
    report['desktop_receipt'] = {'status': 'fresh-detached', 'path': str(folder / 'receipt.json'), 'identity': file_identity(folder / 'receipt.json'),
                                 'binds': files, 'rebinding': record, 'validator': 'pass', 'spans_present_in_app': spans, 'inside_app': False}
