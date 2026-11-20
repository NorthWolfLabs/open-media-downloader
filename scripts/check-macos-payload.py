#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Read-only macOS payload metadata gate. No payload is executed or extracted to disk."""
import argparse
import hashlib
import json
import plistlib
import re
import struct
import zlib
from pathlib import Path, PurePosixPath

THIN = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xfe\xed\xfa\xcf': ('>', 32),
        b'\xce\xfa\xed\xfe': ('<', 28), b'\xfe\xed\xfa\xce': ('>', 28)}
FAT = {b'\xca\xfe\xba\xbe': ('>', False), b'\xbe\xba\xfe\xca': ('<', False),
       b'\xca\xfe\xba\xbf': ('>', True), b'\xbf\xba\xfe\xca': ('<', True)}
CPUS = {'arm64': 0x100000c, 'x86_64': 0x1000007}
MAX_MEMBER_BYTES = 256*1024*1024
MAX_ARCHIVE_BYTES = 1024*1024*1024

def version(s):
    if not isinstance(s, str) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', s):
        raise ValueError('missing/malformed macOS version')
    return tuple((list(map(int, s.split('.'))) + [0])[:3])

def unpack(fmt, data, offset=0):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise ValueError('truncated Mach-O')
    return struct.unpack_from(fmt, data, offset)

def slices(data):
    """All slice metadata; malformed non-target slices also fail closed."""
    magic = data[:4]
    if magic in FAT:
        endian, wide = FAT[magic]
        count, = unpack(endian+'I', data, 4)
        if not 1 <= count <= 32:
            raise ValueError('invalid fat slice count')
        size = 32 if wide else 20
        regions = []; result = []
        for i in range(count):
            cpu, subtype, off, length = unpack(endian+('IIQQ' if wide else 'IIII'), data, 8+i*size)
            if off < 8+count*size or not length or off+length > len(data) or any(off < b and a < off+length for a,b in regions):
                raise ValueError('invalid/overlapping fat slice')
            regions.append((off, off+length))
            inner = slices(data[off:off+length])
            if len(inner) != 1 or inner[0]['cpu'] != cpu or inner[0]['subtype'] != subtype:
                raise ValueError('fat architecture mismatch')
            result += inner
        if len({(r['cpu'],r['subtype']) for r in result}) != count:
            raise ValueError('duplicate fat architecture')
        return result
    if magic not in THIN:
        raise ValueError('not Mach-O')
    endian, header = THIN[magic]
    cpu, subtype, kind, count, size = unpack(endian+'IIIII', data, 4)
    if header+size > len(data) or count > size//8:
        raise ValueError('invalid load command region')
    off = header; floors = []
    for _ in range(count):
        cmd, length = unpack(endian+'II', data, off)
        if length < 8 or length % 4 or off+length > header+size:
            raise ValueError('invalid load command')
        if cmd == 0x32:
            if length < 24: raise ValueError('short LC_BUILD_VERSION')
            platform, minimum, sdk, tools = unpack(endian+'IIII', data, off+8)
            if 24+tools*8 != length: raise ValueError('invalid build tools')
            floors.append((platform, minimum))
        elif cmd in (0x24, 0x25, 0x2f, 0x30):
            if length != 16: raise ValueError('invalid legacy version command')
            minimum, = unpack(endian+'I', data, off+8)
            floors.append((1 if cmd == 0x24 else -1, minimum))
        off += length
    if off != header+size or len(floors) != 1 or floors[0][1] == 0:
        raise ValueError('missing/ambiguous deployment metadata')
    platform, v = floors[0]
    return [{'cpu':cpu, 'subtype':subtype, 'filetype':kind, 'platform':platform,
             'minimum':f'{v >> 16}.{(v >> 8)&255}.{v&255}'}]

def component(data, name, arch):
    rows = slices(data)
    selected = [r for r in rows if r['cpu'] == CPUS[arch]]
    # arm64e alone is not a general arm64 application payload.
    if arch == 'arm64': selected = [r for r in selected if r['subtype'] & 0xffffff == 0]
    if not selected or any(r['platform'] != 1 for r in selected):
        raise ValueError(f'{name}: missing compatible {arch} macOS slice')
    return {'path':name, 'sha256':hashlib.sha256(data).hexdigest(), 'bytes':len(data),
            'slices':rows, 'minimum':max((r['minimum'] for r in selected), key=version)}

def extract_member(path, start, entry, limit=MAX_MEMBER_BYTES):
    """Bound both stored input and actual output; never trust a TOC size alone."""
    offset, stored, expected, compressed, _ = entry
    if any(type(n) is not int or n < 0 for n in (start, offset, stored, expected)) or compressed not in (0, 1):
        raise ValueError('invalid archive member metadata')
    if max(stored, expected) > limit or start+offset+stored > path.stat().st_size:
        raise ValueError('archive member bounds exceeded')
    with path.open('rb') as stream:
        stream.seek(start+offset); data = stream.read(stored)
    if len(data) != stored:
        raise ValueError('truncated archive member')
    if compressed:
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(data, expected+1)
        except zlib.error as error:
            raise ValueError('invalid compressed archive member') from error
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('truncated, trailing or oversized archive expansion')
    if len(data) != expected:
        raise ValueError('archive expansion differs from declared size')
    return data

def packed_members(path, logical, arch):
    from PyInstaller.archive.readers import CArchiveReader
    archive = CArchiveReader(str(path)); rows = []; inventory = []; total = 0
    for name, entry in archive.toc.items():
        if PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts or '\\' in name:
            raise ValueError('unsafe archive member')
        # CArchive TOC: offset, compressed length, uncompressed length, flag, type.
        if entry[2] > MAX_MEMBER_BYTES: raise ValueError('oversize archive member')
        total += entry[2]
        if total > MAX_ARCHIVE_BYTES: raise ValueError('archive expansion limit')
        # The pinned 6.22 reader identifies the cookie/TOC and archive origin.
        # Its public extract() has unbounded zlib output, so read bounded bytes.
        data = extract_member(path, archive._start_offset, entry)
        native = data[:4] in THIN or data[:4] in FAT
        if entry[4] == 'b' and not native:
            raise ValueError(f'unrecognized packed binary {name}')
        inventory.append({'name':name,'type':entry[4],'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'macho':native})
        if native: rows.append(component(data, logical+'!/'+name, arch))
    if not rows: raise ValueError('no packed native components')
    return rows, inventory

def nested_bundles(app, rows, outer):
    """Each nested application bundle (such as the sign-in window under the resources)
    declares its own floor: it must cover the code inside it and must not exceed the
    whole app's declared floor, so the helper launches wherever the app is offered."""
    result = []
    for info in sorted(app.rglob('*.app/Contents/Info.plist')):
        root = info.parent.parent
        if root == app or info.is_symlink() or not info.is_file(): continue
        name = str(root.relative_to(app))
        plist = plistlib.loads(info.read_bytes())
        if not isinstance(plist, dict): raise ValueError(f'{name}: invalid nested Info.plist')
        declared = plist.get('LSMinimumSystemVersion'); version(declared)
        if 'LSMinimumSystemVersionByArchitecture' in plist:
            raise ValueError(f'{name}: per-architecture plist override unsupported; require explicit policy')
        executable = plist.get('CFBundleExecutable')
        inside = [r for r in rows if r['path'].startswith(name + '/')]
        if not isinstance(executable, str) or name + '/Contents/MacOS/' + executable not in [r['path'] for r in inside]:
            raise ValueError(f'{name}: missing nested main executable')
        floor = max((r['minimum'] for r in inside), key=version)
        result.append({'path':name,'declared':declared,'required':floor,'pass':version(floor)<=version(declared)<=version(outer)})
    return result

def check(app, arch):
    plist = plistlib.loads((app/'Contents/Info.plist').read_bytes())
    declared = plist.get('LSMinimumSystemVersion'); version(declared)
    if 'LSMinimumSystemVersionByArchitecture' in plist:
        raise ValueError('per-architecture plist override unsupported; require explicit policy')
    rows = []; packed = {}; files = {}
    for path in sorted(app.rglob('*')):
        if path.is_symlink():
            if not path.resolve().is_relative_to(app.resolve()): raise ValueError('external bundle symlink')
            continue
        if not path.is_file(): continue
        name = str(path.relative_to(app)); data = path.read_bytes()
        files[name] = {'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
        native = data[:4] in THIN or data[:4] in FAT
        if native: rows.append(component(data, name, arch))
        if path.name in ('yt-dlp', 'yt-dlp_macos'):
            if not native: raise ValueError('yt-dlp must be a native PyInstaller payload')
            members, inventory = packed_members(path, name, arch)
            rows += members; packed[name] = inventory
    main = 'Contents/MacOS/'+plist['CFBundleExecutable']
    if main not in [r['path'] for r in rows] or not packed: raise ValueError('missing main executable or packed yt-dlp')
    floor = max((r['minimum'] for r in rows), key=version)
    bundles = nested_bundles(app, rows, declared)
    return {'schema':'omd-macos-payload-v1','app':str(app),'architecture':arch,'platform':'macOS',
            'declared':declared,'required':floor,'pass':version(declared)>=version(floor) and all(b['pass'] for b in bundles),
            'components':rows,'nested_bundles':bundles,'packed_inventory':packed,'files':files,
            'limit':'Metadata lower bound only; no runtime, Intel-app, signing or release acceptance.'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('app', type=Path); p.add_argument('--arch', required=True, choices=CPUS)
    p.add_argument('--output', required=True, type=Path); a = p.parse_args()
    try: report = check(a.app, a.arch)
    except (ValueError, OSError, KeyError, struct.error) as error:
        report = {'pass':False,'error':str(error)}
    with a.output.open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print(json.dumps({k:v for k,v in report.items() if k in ('pass','error','required','declared')}))
    return 0 if report['pass'] else 2

if __name__ == '__main__': raise SystemExit(main())
