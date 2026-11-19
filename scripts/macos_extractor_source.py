"""Controlled-source producer route for extractor preparation (omd-macos-extractor-source-evidence-v1).

The default route of macos_extractor.py accepts only producers built on PyInstaller
6.22.0's stock universal2 `run` bootloader (pinned digest). A producer built by
scripts/build-ytdlp-source.py instead carries a thin arm64 `run` bootloader compiled from
the PyInstaller 6.22.0 sdist. This module is the explicit, separate opt-in for exactly
that producer. It never relaxes the stock route and the two never fall back to each other.

Root of trust: an operator-reviewed evidence file, bound by its SHA-256 on the command
line, names the exact digests of the reviewed source kit, the kit's build plan and
receipt, the pinned profile, the producer and the compiled bootloader. Paths are passed
separately. Every inspect, execute and verify re-derives the following from bytes:

* the kit equals its reviewed digest and passes the recipient verifier
  (ytdlp_source.verify_kit); the kit's profile equals the repository's pinned profile;
  its plan and receipt are the evidence's and bind each other, the profile and the target;
* the receipt binds this exact producer: CArchive layout, every member in order (type and
  expanded digest), every packed native (digest and signing identifier) and the outer
  onefile policy, which is recomputed here (ytdlp_source.onefile_policy);
* the compiled bootloader equals the receipt's compiled `run` (also the source-built
  PyInstaller wheel's) and passes a strict structure check: thin arm64 executable,
  allowlisted load commands, a verifying ad-hoc linker signature, the recorded system
  libraries and the profile's minimum;
* the running PyInstaller files whose functions are replayed equal the build's pinned digests.

The transformation itself is macos_extractor's: pinned steps, every native re-signed with
only its signature changed, every other member byte-identical. That the bootloader, natives
and code were compiled from the kit's sources, and the sufficiency of sources and terms,
remain build and review evidence; they are not re-derived here.
"""
import gzip
import hashlib
import os
import struct
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

import macos_extractor as ex
import macos_signing as signing
import public_inputs
import ytdlp_source
from macos_signing import need, sha

payload = signing.payload

EVIDENCE_SCHEMA = 'omd-macos-extractor-source-evidence-v1'
ROUTE = 'controlled-source'
PROFILE_FILE = ytdlp_source.CURL_PROFILE_REL
PROFILE_PATH = ytdlp_source.REPO / PROFILE_FILE
TARGETS = ('arm64',)
SOURCE_FIELDS = {'evidence', 'kit', 'bootloader'}
EVIDENCE_FIELDS = {'schema', 'route', 'profile', 'kit', 'plan_sha256', 'receipt_sha256', 'producer', 'bootloader', 'version', 'target_arch', 'release_accepted'}
MAX_EVIDENCE_BYTES = 1024**2
MAX_BOOTLOADER_BYTES = 16 * 1024**2
KIT_INDEX, KIT_PLAN, KIT_RECEIPT, KIT_PROFILE = 'KIT-INDEX.json', 'receipt/plan.json', 'receipt/build-receipt.json', 'engine/' + PROFILE_FILE
WHEEL_BOOTLOADER = 'PyInstaller/bootloader/Darwin-64bit/run'
# PyInstaller files whose functions macos_extractor replays (writer, onefile steps, EXE.assemble).
REPLAYED = ('archive/writers.py', 'building/api.py', 'utils/osx.py')

ALLOWED_DIFFERENCES = [
    'Packed native members: only each slice code signature, LC_CODE_SIGNATURE datasize, __LINKEDIT filesize/vmsize (page-rounded) and FAT slice placement (paired signature-only check). The signing identifier is preserved.',
    'Compressed native members are re-encoded with the pinned CArchiveWriter rule (zlib level 9, 16 KiB stream chunks), which must reproduce every producer native stream byte for byte.',
    'Every other member: stored and expanded bytes identical; only its TOC offset moves.',
    'CArchive: TOC offset and length fields of each entry and the cookie archive length and TOC offset; names, order, types, compression flags, Python version and library name are identical.',
    'Outer executable (thin arm64): LC_UUID (PyInstaller update_exe_identifier: SHA-1 of the PKG and the evidence-bound compiled bootloader UUID), LC_SYMTAB strsize (fix_exe_for_code_signing: ends at the PKG), LC_CODE_SIGNATURE dataoff, up to 15 zero bytes before that 16-byte-aligned signature and the signature-dependent fields. Architecture, minimum, SDK and every other bootloader byte are unchanged.',
    'Outer codesign identifier: chosen by codesign from the file name and UUID, as in the PyInstaller build; the app signing workflow later assigns its reviewed identifier.',
]
LIMITS = [
    'Static proof: no archive member is executed or loaded during verification; runtime smoke checks are separate evidence.',
    'Only the controlled-source route named by digest-checked evidence is supported: a PyInstaller 6.22.0 macOS onefile for thin arm64 on the evidence-bound compiled bootloader. Anything else fails closed; the stock route is never a fallback.',
    'The reviewed kit and evidence digests are the root of trust for the compiled bootloader identity. That the bootloader, natives and code were compiled from the kit sources, and source/terms sufficiency, are build and review evidence that is not re-derived here.',
    'Ad-hoc candidates carry no Team ID: they are structural and runtime evidence only, never Developer ID-ready or distributable.',
    'Developer ID mode needs the operator keychain identity; this tool never stores, reads or requests credentials, notarizes or uploads.',
    'omd-final-materials-v1 does not support this route. Explicit omd-final-materials-v2 binding requires the source evidence and preparation report, '
    'repeated byte and signature proofs, and independently reviewed materials; preparation alone never accepts final coverage.',
]
STRUCTURALLY_VERIFIED = [
    'Evidence, kit, producer and compiled bootloader bytes equal the operator-reviewed digests; the kit passes the recipient verifier and its profile equals the repository pinned profile.',
    'The kit plan and receipt are the evidence ones and bind each other, the profile, the arm64 13.5 target and this producer as the repeatable output.',
    'The receipt describes exactly these producer bytes: CArchive layout, every member in order (type and expanded digest), every packed native (digest and signing identifier) and the outer onefile policy, recomputed here.',
    'The compiled bootloader is a strict thin arm64 executable (allowlisted load commands, verifying ad-hoc linker signature, recorded system libraries, profile minimum) and equals the receipt and wheel records.',
    'The producer is the PyInstaller 6.22.0 onefile assembly of that bootloader and its own PKG; execute replays the pinned steps and reproduces it outside its signature.',
    'The running PyInstaller writer, osx and api sources equal the digests the build recorded.',
]
BUILD_AND_REVIEW_EVIDENCE = [
    'Compilation of the bootloader, natives and code from the kit sources (the receipt closure proof and the separate recipient rebuild).',
    'Source, terms and materials sufficiency of the kit (separate recipient review).',
    'Runtime capability (targets, request handlers) and absence of HTTP/3 wire or browser-equivalence claims (separate smoke evidence).',
]


# ---------------------------------------------------------------- inputs

def request_check(source):
    need(isinstance(source, dict) and set(source) == SOURCE_FIELDS, 'Source evidence needs evidence {path, sha256}, kit and bootloader')
    evidence = source['evidence']
    need(isinstance(evidence, dict) and set(evidence) == {'path', 'sha256'} and isinstance(evidence['sha256'], str) and signing.HEX64.fullmatch(evidence['sha256']),
         'Source evidence needs path and a 64-hex sha256')
    for what, value in (('evidence', evidence['path']), ('kit', source['kit']), ('bootloader', source['bootloader'])):
        need(isinstance(value, str) and os.path.isabs(value), f'Source {what} must be an absolute path')


def identity_field(value, what):
    need(isinstance(value, dict) and set(value) == {'bytes', 'sha256'} and type(value['bytes']) is int and value['bytes'] > 0
         and isinstance(value['sha256'], str) and signing.HEX64.fullmatch(value['sha256']), f'Source evidence {what} needs bytes and a 64-hex sha256')


def dig(value, *keys):
    for key in keys:
        need(isinstance(value, dict) and key in value, f"The build receipt lacks {'.'.join(keys)}")
        value = value[key]
    return value


def private_copy(path, folder, name, limit):
    """A private 0600 copy and its identity, so later reads see exactly the hashed bytes."""
    target = Path(folder) / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest, total = hashlib.sha256(), 0
    with open(path, 'rb') as stream, os.fdopen(fd, 'wb') as out:
        while chunk := stream.read(1 << 20):
            total += len(chunk)
            need(total <= limit, f'{name} exceeds its size budget')
            digest.update(chunk)
            out.write(chunk)
    return target, {'bytes': total, 'sha256': digest.hexdigest()}


def load_evidence(spec):
    path = signing.regular_input(spec['path'], 'Source evidence')
    need(path.stat().st_size <= MAX_EVIDENCE_BYTES, 'Source evidence exceeds its size budget')
    raw = path.read_bytes()
    need(sha(raw) == spec['sha256'], 'Source evidence digest differs from the requested digest')
    doc = signing.strict_json(raw)
    need(isinstance(doc, dict) and set(doc) == EVIDENCE_FIELDS, f'Source evidence fields differ from {EVIDENCE_SCHEMA}')
    need(doc['schema'] == EVIDENCE_SCHEMA and doc['route'] == ROUTE, 'Unsupported source evidence schema or route')
    need(doc['release_accepted'] is False, 'Source evidence must record release_accepted false')
    profile = doc['profile']
    need(isinstance(profile, dict) and set(profile) == {'file', 'id', 'sha256'} and profile['file'] == PROFILE_FILE and isinstance(profile['id'], str)
         and profile['id'] and isinstance(profile['sha256'], str) and signing.HEX64.fullmatch(profile['sha256']),
         f'Source evidence must name the pinned profile {PROFILE_FILE}, its id and digest')
    for key in ('kit', 'producer', 'bootloader'):
        identity_field(doc[key], key)
    for key in ('plan_sha256', 'receipt_sha256'):
        need(isinstance(doc[key], str) and signing.HEX64.fullmatch(doc[key]), f'Source evidence {key} must be 64 lowercase hex characters')
    need(doc['target_arch'] in TARGETS, f"Unsupported controlled-source target {doc['target_arch']!r}; only thin arm64 is reviewed")
    need(isinstance(doc['version'], str) and ex.VERSION.fullmatch(doc['version']), 'Invalid source evidence version')
    need(doc['bootloader']['sha256'] != ex.STOCK_BOOTLOADER['sha256'], 'The stock bootloader is not controlled-source evidence; the default route covers it')
    return doc, {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def pinned_profile(doc):
    """The repository's pinned controlled-source profile must be the evidence profile."""
    raw = public_inputs.regular(PROFILE_PATH).read_bytes()
    need(sha(raw) == doc['profile']['sha256'], f'The evidence profile differs from the pinned repository profile {PROFILE_FILE}')
    need(signing.strict_json(raw).get('id') == doc['profile']['id'], 'The evidence profile id differs from the pinned profile')
    return raw


def kit_members(path):
    """The four kit documents used here (the recipient verifier has already checked the kit)."""
    wanted, found = {KIT_INDEX, KIT_PLAN, KIT_RECEIPT, KIT_PROFILE}, {}
    with tarfile.open(path, 'r:gz') as tar:
        for info in tar:
            name = info.name[len(ytdlp_source.KIT_PREFIX) + 1:]
            if name in wanted:
                need(info.isfile() and name not in found and info.size <= 64 * 1024**2, f'Invalid kit document {name}')
                found[name] = tar.extractfile(info).read()
    need(set(found) == wanted, 'The kit lacks ' + ', '.join(sorted(wanted - set(found))))
    return found


def check_documents(members, doc, profile_raw):
    """The kit index, plan and receipt bind the evidence; returns (plan, receipt)."""
    profile = doc['profile']
    index = signing.strict_json(members[KIT_INDEX])
    need(isinstance(index, dict) and index.get('schema') == ytdlp_source.KIT_SCHEMA and index.get('profile') == profile['id'] and index.get('profile_file') == PROFILE_FILE
         and index.get('plan_sha256') == doc['plan_sha256'] and index.get('executable_sha256') == doc['producer']['sha256']
         and index.get('release_accepted') is False and index.get('promotable') is False, 'The kit index does not bind the evidence profile, plan and producer')
    need(members[KIT_PROFILE] == profile_raw, 'The kit profile differs from the pinned repository profile')
    need(sha(members[KIT_PLAN]) == doc['plan_sha256'], 'The kit plan differs from the evidence plan digest')
    plan = signing.strict_json(members[KIT_PLAN])
    need(isinstance(plan, dict) and plan.get('schema') == ytdlp_source.PLAN_SCHEMA and plan.get('profile') == profile['id'] and plan.get('profile_file') == PROFILE_FILE
         and plan.get('profile_sha256') == profile['sha256'] and isinstance(plan.get('files'), dict) and plan['files'].get(KIT_PROFILE) == profile['sha256']
         and plan.get('release_accepted') is False and plan.get('promotable') is False, 'The kit plan does not bind the pinned profile')
    target = plan.get('target')
    need(isinstance(target, dict) and set(target) == {'arch', 'macos_minimum', 'os'} and target['arch'] == doc['target_arch'] and target['os'] == 'macos',
         'The kit plan target differs from the evidence target')
    payload.version(target['macos_minimum'])
    need(sha(members[KIT_RECEIPT]) == doc['receipt_sha256'], 'The kit receipt differs from the evidence receipt digest')
    receipt = signing.strict_json(members[KIT_RECEIPT])
    need(isinstance(receipt, dict) and receipt.get('schema') == ytdlp_source.RECEIPT_SCHEMA and receipt.get('status') == 'built'
         and receipt.get('release_accepted') is False and receipt.get('promotable') is False, 'The kit receipt is not a built, unaccepted controlled-source receipt')
    need(receipt.get('plan_sha256') == doc['plan_sha256'] and receipt.get('profile') == profile['id'] and receipt.get('profile_file') == PROFILE_FILE
         and receipt.get('target') == target, 'The kit receipt does not bind the evidence plan, profile and target')
    producer, boot = doc['producer'], doc['bootloader']
    need({k: dig(receipt, 'output', k) for k in ('bytes', 'sha256')} == producer and receipt.get('packaging_repeat') == {'identical': True, 'sha256': producer['sha256']},
         'The kit receipt does not record the evidence producer as its repeatable output')
    need(dig(receipt, 'bootloader', 'compiled', 'run') == boot['sha256'], 'The kit receipt compiled a different bootloader')
    need(dig(receipt, 'bootloader', 'removed_prebuilt', 'run') == ex.STOCK_BOOTLOADER['sha256'], 'The kit receipt does not record removal of the stock prebuilt bootloader')
    wheel = [r for r in dig(receipt, 'wheels', 'pyinstaller', 'natives') if isinstance(r, dict) and r.get('path') == WHEEL_BOOTLOADER]
    need(len(wheel) == 1 and {k: wheel[0].get(k) for k in ('bytes', 'sha256')} == boot, 'The source-built PyInstaller wheel does not carry the evidence bootloader')
    closure = dig(receipt, 'closure')
    need(closure.get('schema') == ytdlp_source.PROOF_SCHEMA and closure.get('problems') == [], 'The kit receipt closure proof is not clean')
    need({k: dig(receipt, 'closure', 'executable', k) for k in ('bytes', 'sha256')} == producer, 'The closure proof covers a different executable')
    outer = dig(receipt, 'closure', 'outer')
    need({k: dig(receipt, 'closure', 'outer', 'bootloader', k) for k in ('bytes', 'sha256')} == boot and outer.get('replay') == 'identical'
         and isinstance(dig(receipt, 'closure', 'outer', 'policy'), dict), 'The closure proof does not replay the executable from the evidence bootloader')
    natives = dig(receipt, 'closure', 'natives')
    need(isinstance(natives, list) and natives and all(isinstance(r, dict) and r.get('replay') == 'identical' for r in natives),
         'The closure proof does not replay every packed native identically')
    packed = dig(receipt, 'closure', 'packed_verification')
    need(packed.get('failed') == 0 and packed.get('verified') == packed.get('native_members') == len(natives), 'The closure proof has unverified packed natives')
    python = dig(receipt, 'closure', 'python')
    need(type(python.get('items')) is int and python['items'] > 0 and python.get('matched') == python['items'], 'The closure proof has unmatched code objects')
    need(isinstance(dig(receipt, 'closure', 'members'), list) and isinstance(dig(receipt, 'closure', 'archive'), dict), 'The closure proof lacks its archive records')
    linked = dig(receipt, 'closure', 'executable', 'linked')
    need(isinstance(linked, list) and linked and all(isinstance(p, str) for p in linked), 'The closure proof lacks the executable libraries')
    return plan, receipt


def check_pyinstaller(receipt):
    """The running PyInstaller is the pinned version and its replayed sources are the build's."""
    PyInstaller = ex.pinned_runtime()
    pins = dig(receipt, 'closure', 'python', 'pyinstaller')
    need(pins.get('version') == ex.PYINSTALLER_VERSION, 'The producer was built with another PyInstaller version')
    sources = pins.get('sources')
    need(isinstance(sources, dict) and set(REPLAYED) <= set(sources) and all(isinstance(v, str) and signing.HEX64.fullmatch(v) for v in sources.values()),
         'The receipt does not pin the replayed PyInstaller sources')
    root = Path(PyInstaller.__file__).resolve().parent
    found = {rel: sha(public_inputs.regular(root / public_inputs.relative(rel)).read_bytes()) for rel in sorted(sources)}
    differ = sorted(rel for rel in sources if found[rel] != sources[rel])
    need(not differ, f'The running PyInstaller differs from the sources that built the producer: {differ}')
    return found


def bootloader_check(boot, private, folder, receipt, plan, target):
    """Strict structure of the compiled bootloader; returns (slices, record)."""
    structure = ytdlp_source.macho_structure(boot, 'compiled bootloader')
    images = signing.signature(boot)
    need(len(images) == 1 and images[0]['filetype'] == 'execute' and signing.payload_arch(images[0]['cpu']) == target,
         f'The compiled bootloader must be a thin {target} executable')
    image = images[0]
    need(image['signed'] and image['adhoc'] and image['linker_signed'] and not image['certificates'] and image['team'] is None
         and not image['entitlements'] and not image['runtime'], 'The compiled bootloader must carry only its ad-hoc linker signature')
    minimum = payload.component(boot, 'compiled bootloader', target)['minimum']
    need(payload.version(minimum) == payload.version(plan['target']['macos_minimum']), f'The compiled bootloader minimum {minimum} differs from the profile target')
    linked = [row['path'] for row in structure['commands'] if row['cmd'] in ytdlp_source.DYLIB_COMMANDS]
    need(linked and all(ytdlp_source.system_library(p) for p in linked) and sorted(linked) == sorted(dig(receipt, 'closure', 'executable', 'linked')),
         'The compiled bootloader links libraries other than the recorded system libraries')
    env = {k: v for k, v in os.environ.items() if not k.startswith(('APPLE_', 'NOTARY', 'CODESIGN_'))}
    env['TMPDIR'] = str(folder)
    code, err = signing.codesign_check([signing.CODESIGN, '--verify', '--strict', '--all-architectures', str(private)], env)
    need(code == 0, f"The compiled bootloader linker signature does not verify: {' '.join(err.split())[-300:]}")
    slices = [{'arch': target, 'cpu': image['cpu'], 'subtype': image['subtype'], 'uuid': ex.uuid_of(boot).hex(), 'sdk': ex.sdk_of(boot)}]
    return slices, {'uuid': slices[0]['uuid'], 'sdk': slices[0]['sdk'], 'minimum': minimum, 'linked': linked,
                    'load_commands': [row['name'] for row in structure['commands']], 'signature': signing.producer_summary(images),
                    'codesign_verify': 'pass (codesign --verify --strict --all-architectures)'}


# ---------------------------------------------------------------- route

def route(request, temp_root=None):
    """The controlled-source route of macos_extractor.producer_route, re-derived from bytes."""
    source = request['source']
    request_check(source)
    target = request['target_arch']
    doc, evidence = load_evidence(source['evidence'])
    need(target == doc['target_arch'], f"Target {target} differs from the evidence target {doc['target_arch']}")
    need(request.get('producer_sha256') == doc['producer']['sha256'], 'The producer is not the evidence-bound controlled-source producer')
    need(request.get('version') == doc['version'], 'The requested version differs from the evidence version')
    profile_raw = pinned_profile(doc)
    kit_path = signing.regular_input(source['kit'], 'Source kit')
    boot_path = signing.regular_input(source['bootloader'], 'Compiled bootloader')
    with tempfile.TemporaryDirectory(prefix='omd-extractor-source-', dir=temp_root) as folder:
        # macOS may spell its default temp root through /var -> /private/var.
        # Canonicalize only this newly created private workspace; caller-supplied
        # source paths still pass the strict input/symlink checks above.
        folder = Path(folder).resolve(strict=True)
        private_kit, kit_identity = private_copy(kit_path, folder, 'source-kit.tar.gz', ytdlp_source.MAX_KIT_BYTES)
        need(kit_identity == doc['kit'], 'The source kit differs from the evidence-bound reviewed kit')
        try:
            verified = ytdlp_source.verify_kit(private_kit, doc['kit']['sha256'])
            members = kit_members(private_kit)
        except (KeyError, TypeError, AttributeError, IndexError, UnicodeDecodeError, EOFError, gzip.BadGzipFile, tarfile.TarError, zlib.error) as error:
            raise ValueError(f'The source kit fails the recipient verifier: {type(error).__name__}: {error}') from error
        try:
            plan, receipt = check_documents(members, doc, profile_raw)
            private_boot, boot_identity = private_copy(boot_path, folder, 'run', MAX_BOOTLOADER_BYTES)
            need(boot_identity == doc['bootloader'], 'The compiled bootloader differs from the evidence-bound bootloader')
            boot = private_boot.read_bytes()
            need(sha(boot) == doc['bootloader']['sha256'], 'The compiled bootloader changed while it was read')
            slices, boot_record = bootloader_check(boot, private_boot, folder, receipt, plan, target)
            replayed = check_pyinstaller(receipt)
        except (KeyError, TypeError, AttributeError, IndexError, struct.error) as error:
            # Digest-bound but malformed records are refused, never half-trusted.
            raise ValueError(f'Malformed controlled-source kit records or bootloader: {type(error).__name__}: {error}') from error
    closure = receipt['closure']
    pin = {'pyinstaller': ex.PYINSTALLER_VERSION, 'compression_level': ex.COMPRESSION_LEVEL, 'cookie_format': ex.COOKIE,
           'bootloader': {'path': str(boot_path), **doc['bootloader'], 'origin': 'controlled-source: compiled from the PyInstaller 6.22.0 sdist in the evidence-bound kit receipt'},
           'replayed_sources': replayed,
           'rules': ['PyInstaller/building/api.py EXE.assemble (macOS onefile, thin bootloader kept as is)',
                     'PyInstaller/utils/osx.py update_exe_identifier, fix_exe_for_code_signing, sign_binary',
                     'PyInstaller/archive/writers.py CArchiveWriter._write_file and _serialize_toc']}
    record = {
        'route': ROUTE,
        'evidence': {**evidence, 'document': doc},
        'kit': {'path': str(kit_path), **kit_identity, 'recipient_verifier': {k: verified[k] for k in ('files', 'payload_bytes', 'executable_sha256', 'verified')}},
        'profile': {**doc['profile'], 'equals_repository_profile': True},
        'plan': {'sha256': doc['plan_sha256'], 'bytes': len(members[KIT_PLAN]), 'target': plan['target']},
        'receipt': {'sha256': doc['receipt_sha256'], 'bytes': len(members[KIT_RECEIPT]), 'status': receipt['status'], 'closure_schema': closure['schema'],
                    'members': len(closure['members']), 'natives': len(closure['natives']), 'python_code_objects': closure['python']['items'],
                    'packaging_repeat_identical': True},
        'bootloader': {'path': str(boot_path), **doc['bootloader'], **boot_record},
        'pyinstaller_sources': replayed,
        'structurally_verified': STRUCTURALLY_VERIFIED,
        'build_and_review_evidence': BUILD_AND_REVIEW_EVIDENCE,
    }
    return {'name': ROUTE, 'method': ex.SOURCE_METHOD, 'pin': pin, 'bootloader': boot, 'slices': slices, 'source': record, 'receipt': receipt,
            'module': sys.modules[__name__], 'allowed_differences': ALLOWED_DIFFERENCES, 'limits': LIMITS,
            'tool_files': [('macos_extractor_source.py', __file__), ('ytdlp_source.py', ytdlp_source.__file__)],
            'reproduction_note': 'Evidence-bound compiled bootloader plus the producer PKG through the same pinned steps; only signature bytes differ.'}


# ---------------------------------------------------------------- byte bindings

def python_library(analysis, private):
    archive = analysis['archive']
    library = next(m for m in analysis['members'] if m['name'] == archive['python_library_member'])
    _, entries = signing.archive_entries(private)
    return payload.extract_member(Path(private), archive['start'], entries[library['index']][1])


def member_row(member):
    if member['type'] == 'o':
        return (member['name'], 'o', None, None)
    return (member['name'], member['type'], member['expanded']['bytes'], member['expanded']['sha256'])


def producer_binding(route_, analysis, data, private):
    """The evidence receipt describes exactly these producer bytes (re-derived, never trusted)."""
    closure = route_['receipt']['closure']
    need({'bytes': len(data), 'sha256': sha(data)} == route_['source']['evidence']['document']['producer'], 'The producer differs from the evidence producer')
    archive = analysis['archive']
    found = {k: archive[k] for k in ('start', 'end', 'entries', 'pkg_sha256', 'toc_sha256', 'cookie')}
    need(found == closure['archive'], 'The producer CArchive layout differs from the evidence receipt')
    actual = [member_row(m) for m in analysis['members']]
    expected = [(r.get('name'), r.get('type'), r.get('bytes'), r.get('sha256')) if isinstance(r, dict) else None for r in closure['members']]
    if actual != expected:
        index = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), min(len(actual), len(expected)))
        raise ValueError(f'The producer CArchive members differ from the evidence receipt (entry {index})')
    natives = {m['name']: (m['expanded']['bytes'], m['expanded']['sha256'], m['native']['identifier']) for m in analysis['members'] if 'native' in m}
    recorded = {}
    for row in closure['natives']:
        need(isinstance(row, dict) and isinstance(row.get('name'), str) and bool(row['name'])
             and isinstance(row.get('signature'), dict) and isinstance(row['signature'].get('identifier'), str)
             and bool(row['signature']['identifier']), 'Malformed packed native in the evidence receipt')
        need(row['name'] not in recorded, 'Duplicate packed native in the evidence receipt')
        recorded[row['name']] = (row.get('bytes'), row.get('sha256'), row['signature']['identifier'])
    need(natives == recorded, 'The producer packed natives differ from the evidence receipt (digest or signing identifier)')
    policy = ytdlp_source.onefile_policy(data, route_['bootloader'], archive['start'], archive['end'], python_library(analysis, private))
    need(policy == closure['outer']['policy'], 'The producer outer executable differs from the evidence receipt onefile policy')
    return {'archive': found, 'members': len(actual), 'natives': len(natives), 'outer_policy': policy,
            'relation': 'The evidence receipt describes exactly these producer bytes; the outer executable is the compiled bootloader outside PyInstaller PKG-derived fields.'}


def candidate_outer(route_, analysis, data, private, binding):
    """The prepared outer executable is the same onefile assembly of the compiled bootloader:
    strict structure, re-derived UUID, unchanged view, SDK, minimum and architecture."""
    archive = analysis['archive']
    policy = ytdlp_source.onefile_policy(data, route_['bootloader'], archive['start'], archive['end'], python_library(analysis, private))
    before = binding['outer_policy']
    need({k: policy[k] for k in ('bootloader_uuid', 'sdk', 'compared_bytes', 'view_sha256')} == {k: before[k] for k in ('bootloader_uuid', 'sdk', 'compared_bytes', 'view_sha256')},
         'The prepared outer executable is not the evidence-bound bootloader assembly')
    target = route_['slices'][0]['arch']
    return {**policy, 'arch': target, 'minimum': payload.component(data, 'prepared extractor', target)['minimum'], 'sdk_version': ex.sdk_of(data)}
