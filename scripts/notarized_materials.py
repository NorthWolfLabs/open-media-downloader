"""Notarized materials envelope (omd-notarized-materials-v1).

A detached, explicitly versioned envelope that composes one UNCHANGED exact
omd-final-materials-v1 or -v2 signed binding with exactly one post-signing operation:
Apple's stapled app ticket (method omd-apple-stapled-app-ticket-v1). The signed binding,
its exact file closure and its fixtures are untouched. The envelope adds only the
relation signed app -> stapled app (the signed payload plus exactly one ticket file at
Contents/CodeResources, outside the code seal), the archive Apple accepted and the
distribution archive.

* `validate_notarized` is the shared structural contract, implemented identically by
  the desktop's scripts/notarized-materials-contract.mjs and exercised by byte-identical
  fixtures (notarized-materials-fixtures-v1.json). It dispatches the unchanged
  `final_materials.validate_final` on the signed payload, then recomputes every envelope
  equality. Success means structural consistency only: it always reports
  macos_verification_required true and never emits a candidate, notarization or coverage
  promotion. `load_strict` is the shared raw loader (duplicate keys refused).
* `derive` (macOS only, used by bind-notarized-materials.py prepare/verify) re-derives
  everything from bytes: it calls the unchanged `final_materials.verify` with
  cryptographic verification and every original input on a private snapshot of the true
  pre-staple signed app, proves the exact ticket-only closure against a private snapshot
  of the stapled app, runs actual codesign, `xcrun stapler validate` and `spctl` on those
  snapshots and on a private readback of the distribution archive, strictly reads both
  archives and checks the retained notary log for consistency. Bytes are rehashed around
  the Apple checks and after the run. Missing tools, timeouts, output overflow and
  resource bounds are unverified, never a pass.

Nothing here signs, staples, submits, reads credentials or profiles, or accepts a
release. The retained notary log is provenance consistency only: a stapled ticket does
not authenticate a local log's submission id or chronology.
"""
import hashlib
import json
import os
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import time
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

import final_materials as final

SCHEMA = 'omd-notarized-materials-v1'
METHOD = 'omd-apple-stapled-app-ticket-v1'
NAME = 'notarized-materials-v1.json'
REPORT_NAME = 'verification-report.json'
REPORT_SCHEMA = 'omd-notarized-materials-report-v1'
VERIFICATION_SCHEMA = 'omd-notarized-materials-verification-v1'
TICKET = 'Contents/CodeResources'
TICKET_MAX = 1048576
# Method v1 is proven only for a thin arm64 outer executable with one SHA-256 CodeDirectory.
TARGETS = {'darwin-arm64': 'arm64'}
PURPOSE = 'distribution-candidate'
ACCEPTED = 'Accepted'
BINDING_SCHEMAS = (final.FINAL_SCHEMA, final.FINAL_SCHEMA_V2)
TRANSPORT_ROOT = '__MACOSX'
MAX_SAFE = 9007199254740991
MAX_JSON_BYTES = 16 * 1024**2
MAX_JSON_DEPTH = 64
HEX = final.HEX
TEAM = final.TEAM
LOCAL = final.LOCAL
CDHASH = re.compile(r'[a-f0-9]{40}')
UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
TOP = ('schema', 'method', 'target', 'version', 'purpose', 'signing', 'signed_binding', 'signed_payload', 'stapled_payload', 'ticket',
       'outer_code', 'submission', 'distribution_archive', 'release_accepted')
SIGNING = ('mode', 'team_id', 'bundle_id')
BINDING_REF = ('schema', 'locator', 'bytes', 'sha256')
REF = ('locator', 'bytes', 'sha256')
INVENTORY = ('inventory_sha256', 'files')
TICKET_FIELDS = ('path', 'bytes', 'sha256')
SLICE = ('arch', 'algorithm', 'cdhash', 'code_directory_hash')
SUBMISSION = ('id', 'status', 'status_code', 'app_member', 'log', 'uploaded_archive', 'transport')
DISTRIBUTION = ('app_member', 'artifact', 'payload_inventory_sha256', 'transport')
EXPECT = ('binding_sha256', 'team_id', 'target', 'version', 'purpose', 'locks', 'required', 'final_components')
OBSERVATION = ('app_member', 'payload', 'transport')
STRUCTURE_RESULT = {'schema': SCHEMA, 'structure_validated': True, 'macos_verification_required': True, 'release_accepted': False}
LIMITS = [
    ('Structural success means consistency only. Notarized artifact acceptance requires a fresh macOS verification '
     '(bind-notarized-materials.py) wherever it is consumed; a serialized report is audit evidence, never a capability.'),
    ('The signed binding is unchanged and keeps its exact file closure; this envelope adds only the stapled ticket at '
     'Contents/CodeResources. Its size, header and digest are not authentication: actual Apple validation of the exact bytes is.'),
    ('The retained notary log is provenance consistency only. A stapled ticket does not authenticate a local log\'s '
     'submission id or chronology, and no submission history was fetched.'),
    (f'{METHOD} covers one thin arm64 outer executable with one SHA-256 CodeDirectory on darwin-arm64; other targets '
     'and architectures are refused until reviewed and proven.'),
    ('Gatekeeper and stapler results are current-host assessments; they do not establish another OS version, Intel, '
     'quarantined pristine-account installation, revocation status or release acceptance. release_accepted is always false.'),
]
OPEN_GATES = [
    'Public corresponding-source hosting/co-delivery.',
    'Final shipping branding and bundle identity.',
    'Quarantined pristine-account installation, GUI first-run/import and acquisition.',
    'Offered-platform execution and overall release acceptance.',
]


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- shared strict loader

def _depth(text):
    """Deepest object/array nesting, counted outside strings (also on invalid text)."""
    depth = deepest = 0
    quoted = escaped = False
    for c in text:
        if quoted:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in '{[':
            depth += 1
            deepest = max(deepest, depth)
        elif c in '}]':
            depth -= 1
    return deepest


def load_strict(raw):
    """Strict JSON from raw bytes, identical to loadStrict in the desktop: UTF-8 without a
    BOM, at most 16 MiB and 64 levels, standard JSON only (no NaN or Infinity literals),
    syntax checked before duplicate keys, which are refused at every level."""
    need(isinstance(raw, (bytes, bytearray)), 'Invalid JSON')
    need(len(raw) <= MAX_JSON_BYTES, 'JSON input exceeds the size bound')
    try:
        text = bytes(raw).decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('Invalid JSON') from None
    need(not text.startswith('﻿') and _depth(text) <= MAX_JSON_DEPTH, 'Invalid JSON')

    def constant(_):
        raise ValueError('Invalid JSON')

    def number(text):
        # Very long integer literals become floats (infinite), as in JavaScript; they then
        # fail every safe-integer check instead of hitting Python's digit limit.
        return int(text) if len(text) <= 4000 else float(text)

    try:
        json.loads(text, parse_constant=constant, parse_int=number)
    except ValueError:
        raise ValueError('Invalid JSON') from None

    def pairs(items):
        need(len({k for k, _ in items}) == len(items), 'Duplicate JSON key')
        return dict(items)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_int=number)


# ---------------------------------------------------------------- shared structural contract

def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _keys(obj, wanted):
    return isinstance(obj, dict) and set(obj) == set(wanted)


def _integer(value):
    # JSON safe-integer semantics shared with JavaScript: integral numbers through 2^53-1;
    # booleans, fractions and larger magnitudes are refused.
    return type(value) in (int, float) and abs(value) <= MAX_SAFE and value % 1 == 0


def _identity(value, positive=True):
    return (_keys(value, ('bytes', 'sha256')) and _integer(value['bytes']) and (value['bytes'] > 0 if positive else value['bytes'] >= 0)
            and _hex(value['sha256']))


def same(a, b):
    """JSON value equality: numbers compare numerically, booleans never equal numbers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return set(a) == set(b) and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def inventory_digest(files):
    """The canonical app inventory digest, with integral sizes serialized as integers."""
    canonical = {p: {'bytes': int(r['bytes']), 'sha256': r['sha256']} for p, r in files.items()}
    return sha(json.dumps(canonical, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())


def _files(value, what, empty=False):
    need(isinstance(value, dict) and (empty or bool(value)), f'Invalid {what} inventory')
    folded = set()
    for path in sorted(value):
        final.final_path(path)
        need(path.lower() not in folded, f'Duplicate or colliding {what} path')
        folded.add(path.lower())
        need(_identity(value[path], positive=False), f'Invalid {what} inventory')
        need(path.split('/')[-1] != NAME, 'Notarized materials must stay outside the payloads, archives and evidence')


def appledouble(entry):
    """The sequestered AppleDouble member that carries one archive entry's metadata."""
    parent, _, base = entry.rpartition('/')
    return TRANSPORT_ROOT + '/' + (parent + '/' if parent else '') + '._' + base


def described(app, files):
    """AppleDouble members that may describe the app root, a payload file or its ancestors."""
    entries = {app}
    for path in files:
        parts = path.split('/')
        for i in range(1, len(parts) + 1):
            entries.add(app + '/' + '/'.join(parts[:i]))
    return {appledouble(e) for e in entries}


def validate_notarized(doc, signed_binding_bytes, initial_bytes, signed_payload, stapled_payload, delivery, archive_identities, evidence_identities, expect):
    """Structural validation of a notarized materials envelope against the raw signed binding
    bytes, the initial review bytes, the actual signed and stapled payload inventories, the
    delivery inventory, archive observations ({uploaded, distribution}: app_member, payload,
    transport), evidence identities ({locator: {bytes, sha256}}) and caller-pinned
    expectations. Mirrors validateNotarized in notarized-materials-contract.mjs. It never
    proves Apple acceptance: a fresh macOS verification is always required."""
    need(_keys(doc, TOP), 'Unknown/missing notarized materials fields')
    need(not any(x in json.dumps(doc, ensure_ascii=False, separators=(',', ':')) for x in LOCAL), 'Machine-local notarized materials metadata')
    need(doc['schema'] == SCHEMA, 'Wrong notarized materials schema')
    need(doc['method'] == METHOD, 'Unknown notarization method')
    need(doc['release_accepted'] is False, 'Notarized materials never accept a release')
    need(_keys(expect, EXPECT) and _hex(expect['binding_sha256']) and isinstance(expect['team_id'], str) and TEAM.fullmatch(expect['team_id']) is not None
         and all(isinstance(expect[k], str) and bool(expect[k]) for k in ('target', 'version', 'purpose'))
         and all(isinstance(expect[k], dict) for k in ('locks', 'required', 'final_components')), 'Invalid caller-pinned notarization expectations')
    need(isinstance(doc['target'], str) and doc['target'] in TARGETS, f'{METHOD} supports only the darwin-arm64 target')
    need(doc['purpose'] == PURPOSE, 'Private-validation output is never a distribution candidate')
    need(doc['target'] == expect['target'] and doc['version'] == expect['version'] and doc['purpose'] == expect['purpose'],
         'Envelope differs from the caller-pinned target, version or purpose')
    s = doc['signing']
    need(_keys(s, SIGNING) and s['mode'] == 'developer-id' and isinstance(s['team_id'], str) and TEAM.fullmatch(s['team_id']) is not None
         and isinstance(s['bundle_id'], str) and bool(s['bundle_id']), 'Invalid envelope signing identity')
    need(s['team_id'] == expect['team_id'], 'Envelope Team differs from the caller-pinned Team')
    sub, dist, ref = doc['submission'], doc['distribution_archive'], doc['signed_binding']
    need(_keys(sub, SUBMISSION), 'Invalid notarization submission binding')
    need(_keys(dist, DISTRIBUTION), 'Invalid distribution archive binding')
    need(_keys(ref, BINDING_REF), 'Invalid signed binding reference')
    need(ref['schema'] in BINDING_SCHEMAS, 'The signed binding must be omd-final-materials-v1 or omd-final-materials-v2')
    refs = (('signed binding', ref), ('submission log', sub['log']), ('uploaded archive', sub['uploaded_archive']), ('distribution archive', dist['artifact']))
    folded = set()
    for what, r in refs:
        need(_keys(r, BINDING_REF if r is ref else REF) and isinstance(r['locator'], str) and r['locator'].startswith('evidence:')
             and _identity({'bytes': r['bytes'], 'sha256': r['sha256']}), f'Invalid {what} evidence reference')
        path = r['locator'][len('evidence:'):]
        final.final_path(path)
        need(path.split('/')[-1] != NAME, 'Notarized materials cannot reference themselves')
        need(r['locator'].lower() not in folded, 'Duplicate evidence locator')
        folded.add(r['locator'].lower())
    need(isinstance(evidence_identities, dict) and set(evidence_identities) == {r['locator'] for _, r in refs},
         'Evidence identities differ from the envelope evidence references')
    for what, r in refs:
        need(same(evidence_identities[r['locator']], {'bytes': r['bytes'], 'sha256': r['sha256']}), f'The {what} differs from its bound evidence identity')
    need(ref['sha256'] == expect['binding_sha256'], 'The signed binding differs from the caller-pinned binding digest')
    need(isinstance(signed_binding_bytes, (bytes, bytearray)) and sha(signed_binding_bytes) == ref['sha256'] and len(signed_binding_bytes) == ref['bytes'],
         'Signed binding bytes differ from the bound signed binding')
    binding = load_strict(signed_binding_bytes)
    need(isinstance(binding, dict) and binding.get('schema') == ref['schema'], 'The signed binding schema differs from its reference')
    # The unchanged original contract on the exact signed payload; it also pins the binding's
    # target, version, locks and components to the caller's expectations.
    final.validate_final(binding, initial_bytes, signed_payload, delivery, {k: expect[k] for k in ('target', 'version', 'locks', 'required', 'final_components')})
    need(all(p.split('/')[-1] != NAME for p in delivery), 'Notarized materials must stay outside the payloads, archives and evidence')
    bs = binding['signing']
    need(s['mode'] == bs['mode'] and s['team_id'] == bs['team_id'] and s['bundle_id'] == bs['bundle_id'], 'Envelope signing identity differs from the signed binding')
    sp, st = doc['signed_payload'], doc['stapled_payload']
    need(_keys(sp, INVENTORY), 'Invalid signed payload inventory')
    _files(sp['files'], 'signed payload')
    need(sp['inventory_sha256'] == inventory_digest(sp['files']), 'Invalid signed payload inventory')
    need(same(sp['files'], binding['payload']['files']) and sp['inventory_sha256'] == binding['payload']['inventory_sha256'],
         'The signed payload differs from the signed binding payload')
    need(same(sp['files'], signed_payload), 'The signed app differs from the bound signed payload')
    t = doc['ticket']
    need(_keys(t, TICKET_FIELDS) and _integer(t['bytes']) and _hex(t['sha256']), 'Invalid stapled ticket binding')
    need(t['path'] == TICKET, 'The stapled ticket must be exactly Contents/CodeResources')
    need(0 < t['bytes'] <= TICKET_MAX, 'The stapled ticket size is outside the method bound')
    need(all(p.lower() != TICKET.lower() for p in sp['files']), 'The signed payload already contains the ticket path')
    need(_keys(st, INVENTORY), 'Invalid stapled payload inventory')
    _files(st['files'], 'stapled payload')
    need(st['inventory_sha256'] == inventory_digest(st['files']), 'Invalid stapled payload inventory')
    for path in sorted(sp['files']):
        need(path in st['files'], 'Stapling removed a signed payload file: ' + path)
        need(same(st['files'][path], sp['files'][path]), 'Stapling changed a signed payload file: ' + path)
    for path in sorted(st['files']):
        need(path in sp['files'] or path == TICKET, 'Stapling added a file other than the ticket: ' + path)
    need(TICKET in st['files'] and same(st['files'][TICKET], {'bytes': t['bytes'], 'sha256': t['sha256']}), 'The stapled ticket differs from the stapled payload')
    need(same(st['files'], stapled_payload), 'The stapled app differs from the bound stapled payload')
    o = doc['outer_code']
    need(_keys(o, ('path', 'slices')) and o['path'] == 'Contents/MacOS/' + binding['layout']['executable'] and isinstance(o['slices'], list),
         'Invalid outer code identity')
    need(len(o['slices']) == 1, f'{METHOD} supports exactly one outer code slice')
    x = o['slices'][0]
    need(_keys(x, SLICE), 'Invalid outer code identity')
    need(x['arch'] == TARGETS[doc['target']] and x['algorithm'] == 'sha256', f'{METHOD} supports only one arm64 SHA-256 outer slice')
    need(isinstance(x['cdhash'], str) and CDHASH.fullmatch(x['cdhash']) is not None and _hex(x['code_directory_hash'])
         and x['cdhash'] == x['code_directory_hash'][:40], 'Invalid outer CodeDirectory identity')
    need(isinstance(sub['id'], str) and UUID.fullmatch(sub['id']) is not None, 'The submission id must be a canonical lowercase UUID')
    need(sub['status'] == ACCEPTED and _integer(sub['status_code']) and sub['status_code'] == 0,
         'The retained submission log binding does not record an accepted submission')
    app = sub['app_member']
    need(isinstance(app, str) and '/' not in app and app.endswith('.app') and len(app) > 4 and not app.startswith('.'), 'Invalid archive app member')
    final.final_path(app)
    need(dist['app_member'] == app, 'The uploaded and distribution archives must contain the same app')
    need(dist['payload_inventory_sha256'] == st['inventory_sha256'], 'The distribution archive payload differs from the stapled payload')
    transports = (('uploaded archive', 'uploaded', sub['transport'], sp['files']), ('distribution archive', 'distribution', dist['transport'], st['files']))
    for what, _, transport, files in transports:
        need(_keys(transport, INVENTORY), f'Invalid {what} transport inventory')
        _files(transport['files'], what + ' transport', empty=True)
        need(transport['inventory_sha256'] == inventory_digest(transport['files']), f'Invalid {what} transport inventory')
        allowed = described(app, files)
        for member in sorted(transport['files']):
            need(member in allowed, f'Unbound {what} transport member: {member}')
    need(_keys(archive_identities, ('uploaded', 'distribution')), 'Invalid archive observations')
    for what, key, transport, files in transports:
        seen = archive_identities[key]
        need(_keys(seen, OBSERVATION), 'Invalid archive observations')
        need(seen['app_member'] == app, f'The {what} contains a different app')
        need(same(seen['payload'], files), f'The {what} app differs from its bound payload')
        need(same(seen['transport'], transport['files']), f'The {what} transport members differ from their binding')
    return dict(STRUCTURE_RESULT)


# ---------------------------------------------------------------- native verification (macOS only)

CODESIGN = '/usr/bin/codesign'
XCRUN = '/usr/bin/xcrun'
SPCTL = '/usr/sbin/spctl'
DITTO = '/usr/bin/ditto'
SW_VERS = '/usr/bin/sw_vers'
XCODEBUILD = '/usr/bin/xcodebuild'
# Reviewed bounds. A caller may lower the workflow bound; nothing here can raise or disable them.
TIMEOUTS = {'codesign': 45, 'stapler': 60, 'spctl': 60, 'ditto': 60, 'info': 45}
OUTPUT_LIMIT = 1048576
WORKFLOW_SECONDS = 600
MAX_TREE_FILES = 8192
MAX_TREE_BYTES = 2 * 1024**3
MAX_ARCHIVE_BYTES = 1024**3
MAX_ARCHIVE_MEMBERS = 4096
MAX_UNCOMPRESSED = 2 * 1024**3
MAX_TRANSPORT_MEMBER = 65536
MAX_EXTRA_FIELD = 256
MAX_LOG_BYTES = 1048576
# Sequestered transport metadata reviewed for this method: the system provenance attribute only.
TRANSPORT_ATTRIBUTES = ('com.apple.provenance',)
ARM64 = 0x0100000c


class Unverified(Exception):
    """A required check could not run to completion (platform, tool, network, timeout,
    output overflow or a resource bound). It is never a pass."""


def _signing():
    return final._signing()


def now():
    return datetime.now(timezone.utc).isoformat()


def _allowed(argv):
    """Read-only verification commands only: nothing signs, staples, submits or reads credentials."""
    tool, rest = argv[0], argv[1:]
    if tool == CODESIGN:
        return (('--verify' in rest) != ('-d' in rest)) and not {'-s', '--sign', '-f', '--force', '--remove-signature'} & set(rest)
    if tool == XCRUN:
        return (len(rest) == 3 and rest[:2] == ['stapler', 'validate']) or rest == ['--show-sdk-version']
    if tool == SPCTL:
        return rest[:3] == ['--assess', '--type', 'execute']
    if tool == DITTO:
        return len(rest) == 4 and rest[:2] == ['-x', '-k']
    if tool == SW_VERS:
        return rest == []
    if tool == XCODEBUILD:
        return rest == ['-version']
    return False


def tool_environment(temp):
    """A minimal environment: no inherited DYLD, Apple, notary or codesign variables."""
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'TMPDIR': str(temp)}
    if os.environ.get('HOME'):
        env['HOME'] = os.environ['HOME']
    return env


def run_bounded(argv, timeout, env, limit):
    """One tool invocation without a shell, in its own new process group. Combined stdout and
    stderr are capped at `limit` bytes. On timeout or overflow only that owned group is killed,
    before its leader is reaped (so the group id cannot be recycled). Exit is the integer status,
    or 'missing', 'timeout' or 'overflow'. Never retried."""
    argv = [str(a) for a in argv]
    started = time.monotonic()
    record = {'argv': argv, 'timeout': round(timeout, 3), 'limit': limit}
    if not (os.path.isabs(argv[0]) and os.access(argv[0], os.X_OK)):
        return {**record, 'exit': 'missing', 'seconds': 0.0, 'stdout': '', 'stderr': '', 'output_bytes': 0}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                   start_new_session=True, close_fds=True)
    except OSError as error:
        return {**record, 'exit': 'missing', 'error': str(error), 'seconds': 0.0, 'stdout': '', 'stderr': '', 'output_bytes': 0}
    deadline = started + timeout
    chunks = {process.stdout: bytearray(), process.stderr: bytearray()}
    total, outcome = 0, None
    selector = selectors.DefaultSelector()
    try:
        for stream in chunks:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map() and outcome is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = 'timeout'
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                if total > limit:
                    outcome = 'overflow'
                    break
                chunks[key.fileobj].extend(data)
        while outcome is None:
            # Wait for the leader's exit without reaping it.
            try:
                if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                    break
            except ChildProcessError:
                break
            if time.monotonic() >= deadline:
                outcome = 'timeout'
                break
            time.sleep(0.01)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return {**record, 'exit': outcome or process.returncode, 'seconds': round(time.monotonic() - started, 3),
            'stdout': chunks[process.stdout].decode(errors='replace'), 'stderr': chunks[process.stderr].decode(errors='replace'), 'output_bytes': total}


class Run:
    """One verification: its private workspace, deadline, tool environment and records."""

    def __init__(self, seconds=WORKFLOW_SECONDS, temp_root=None, timeouts=None):
        need(isinstance(seconds, (int, float)) and 0 < seconds <= WORKFLOW_SECONDS, f'The workflow bound must be 1 to {WORKFLOW_SECONDS} seconds')
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds
        self.timeouts = {k: min(v, (timeouts or {}).get(k, v)) for k, v in TIMEOUTS.items()}
        self.records = []
        self.temp = Path(tempfile.mkdtemp(prefix='omd-notarized-', dir=temp_root)).resolve()
        self.env = tool_environment(self.temp)

    def cleanup(self):
        shutil.rmtree(self.temp, ignore_errors=True)

    def check(self, what):
        if time.monotonic() >= self.deadline:
            raise Unverified(f'The {self.seconds}-second workflow bound expired before {what}')

    def tool(self, kind, argv, label):
        need(_allowed([str(a) for a in argv]), f'{label}: outside the read-only verification command policy')
        self.check(label)
        record = run_bounded(argv, min(self.timeouts[kind], max(self.deadline - time.monotonic(), 0.001)), self.env, OUTPUT_LIMIT)
        record['label'] = label
        self.records.append(record)
        if record['exit'] in ('missing', 'timeout', 'overflow'):
            raise Unverified(f"{label}: {record['exit']}")
        return record

    def passes(self, kind, argv, label):
        record = self.tool(kind, argv, label)
        reason = ' '.join((record['stderr'] or record['stdout']).split())[-300:]
        need(record['exit'] == 0, f"{label} failed (exit {record['exit']}): {reason}")
        return record


# ------------------------------------------------------------ stable inputs

def read_stable(path, what, limit):
    """Whole-file bytes through one no-follow descriptor; no symlink ancestors."""
    path = _signing().no_link_ancestors(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode), f'{what} is not a regular file')
        if info.st_size > limit:
            raise Unverified(f'{what} exceeds its {limit}-byte bound')
        data = stream.read(limit + 1)
        need(len(data) == info.st_size == os.fstat(stream.fileno()).st_size, f'{what} changed while it was read')
    return data


def copy_stable(path, destination, what, limit):
    """A private copy written and hashed from one no-follow descriptor: later checks read the copy."""
    path = _signing().no_link_ancestors(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode), f'{what} is not a regular file')
        if info.st_size > limit:
            raise Unverified(f'{what} exceeds its {limit}-byte bound')
        digest, count = hashlib.sha256(), 0
        with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
            while chunk := stream.read(1 << 20):
                count += len(chunk)
                need(count <= info.st_size, f'{what} changed while it was read')
                digest.update(chunk)
                out.write(chunk)
        after = os.fstat(stream.fileno())
    need(count == info.st_size == after.st_size and after.st_mtime_ns == info.st_mtime_ns, f'{what} changed while it was read')
    return {'bytes': count, 'sha256': digest.hexdigest()}


def walk_tree(root, copy_to=None):
    """Regular files and directories only, read through no-follow descriptors: no symlinks,
    hard links, special files, special permission bits, unportable or colliding names, within
    the tree budget. Returns {files: {rel: identity}, modes: {rel: mode}, dirs: {rel: mode}}
    (dirs[''] is the root). With `copy_to` (a new path), the bytes read are also written to a
    private copy with the same permission bits."""
    signing = _signing()
    root = signing.no_link_ancestors(root)
    result = {'files': {}, 'modes': {}, 'dirs': {}}
    state = {'seen': {}, 'bytes': 0}
    top = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    out = None
    try:
        info = os.fstat(top)
        need(stat.S_ISDIR(info.st_mode) and info.st_mode & 0o7000 == 0, f'Not a plain directory: {root}')
        result['dirs'][''] = stat.S_IMODE(info.st_mode)
        if copy_to is not None:
            os.mkdir(copy_to, 0o700)
            out = os.open(copy_to, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        _walk(top, '', out, result, state)
    finally:
        os.close(top)
        if out is not None:
            os.close(out)
    if copy_to is not None:
        for rel in sorted(result['dirs'], key=lambda r: -r.count('/') - (r != '')):
            os.chmod(Path(copy_to) / rel if rel else copy_to, result['dirs'][rel])
    return {k: dict(sorted(v.items())) for k, v in result.items()}


def _walk(fd, prefix, out, result, state):
    signing = _signing()
    for name in sorted(os.listdir(fd)):
        rel = prefix + name
        final.final_path(rel)
        need(state['seen'].setdefault(signing.fold(rel), rel) == rel, f'Case/normalization collision in the app tree: {rel}')
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(not stat.S_ISLNK(info.st_mode), f'Symlink in the app tree: {rel}')
        need(info.st_mode & 0o7000 == 0, f'Special permission bits in the app tree: {rel}')
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            sub = None
            try:
                opened = os.fstat(child)
                need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), f'The app tree changed while it was read: {rel}')
                result['dirs'][rel] = stat.S_IMODE(info.st_mode)
                if out is not None:
                    os.mkdir(name, 0o700, dir_fd=out)
                    sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=out)
                _walk(child, rel + '/', sub, result, state)
            finally:
                os.close(child)
                if sub is not None:
                    os.close(sub)
            continue
        need(stat.S_ISREG(info.st_mode), f'Special file in the app tree: {rel}')
        need(info.st_nlink == 1, f'Hard-linked file in the app tree: {rel}')
        state['bytes'] += info.st_size
        if len(result['files']) >= MAX_TREE_FILES or state['bytes'] > MAX_TREE_BYTES:
            raise Unverified('The app tree exceeds the verification budget')
        with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            need((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size), f'The app tree changed while it was read: {rel}')
            digest, count = hashlib.sha256(), 0
            copy = None
            if out is not None:
                copy = os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=out), 'wb')
            try:
                while chunk := stream.read(1 << 20):
                    count += len(chunk)
                    need(count <= info.st_size, f'The app tree changed while it was read: {rel}')
                    digest.update(chunk)
                    if copy is not None:
                        copy.write(chunk)
                if copy is not None:
                    os.fchmod(copy.fileno(), stat.S_IMODE(info.st_mode))
            finally:
                if copy is not None:
                    copy.close()
            after = os.fstat(stream.fileno())
        need(count == info.st_size == after.st_size and after.st_mtime_ns == info.st_mtime_ns, f'The app tree changed while it was read: {rel}')
        result['files'][rel] = {'bytes': count, 'sha256': digest.hexdigest()}
        result['modes'][rel] = stat.S_IMODE(info.st_mode)


def closure(signed, stapled):
    """The exact ticket-only closure between two independently observed trees: the signed
    files, plus exactly one new regular file at Contents/CodeResources; no removal, no other
    addition, no byte, permission or directory change."""
    sf, tf = signed['files'], stapled['files']
    need(all(p.lower() != TICKET.lower() for p in sf), 'The signed app already contains a file at the ticket path')
    removed, added = sorted(set(sf) - set(tf)), sorted(set(tf) - set(sf))
    need(not removed, 'Stapling removed signed payload files: ' + ', '.join(removed[:5]))
    need(added == [TICKET], 'Stapling must add exactly Contents/CodeResources; added: ' + ', '.join(added[:5]))
    changed = sorted(p for p in sf if tf[p] != sf[p])
    need(not changed, 'Stapling changed signed payload files: ' + ', '.join(changed[:5]))
    need(stapled['dirs'] == signed['dirs'], 'Stapling changed the directory closure or directory permissions')
    modes = sorted(p for p in sf if stapled['modes'][p] != signed['modes'][p])
    need(not modes, 'Stapling changed file permissions: ' + ', '.join(modes[:5]))
    ticket = tf[TICKET]
    need(0 < ticket['bytes'] <= TICKET_MAX, 'The stapled ticket size is outside the method bound')
    need(stapled['modes'][TICKET] & 0o111 == 0, 'The stapled ticket must not be executable')
    return dict(ticket)


# ------------------------------------------------------------ code identities

def outer_identity(data):
    """The outer CodeDirectory identity from verified bytes: one thin arm64 slice with exactly
    one SHA-256 CodeDirectory; its full hash and its 20-byte CDHash."""
    signing = _signing()
    need(data[:4] == b'\xcf\xfa\xed\xfe', f'{METHOD} supports only a thin 64-bit outer executable')
    endian, cpu, _, _, commands = signing.load_commands(data)
    need(cpu == ARM64, f'{METHOD} supports only the arm64 outer architecture')
    found = [o for cmd, o, _ in commands if cmd == 0x1d]
    need(len(found) == 1, 'The outer executable is not signed')
    dataoff, datasize = struct.unpack_from(endian + 'II', data, found[0] + 8)
    need(dataoff + datasize <= len(data) and datasize >= 12, 'Invalid outer code signature')
    blob = data[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from('>III', blob, 0)
    need(magic == 0xfade0cc0 and 12 + 8 * count <= length <= len(blob) and count <= 64, 'Invalid outer code signature')
    directories = []
    for i in range(count):
        kind, offset = struct.unpack_from('>II', blob, 12 + 8 * i)
        if kind == 0 or 0x1000 <= kind < 0x1005:
            need(offset + 44 <= length, 'Invalid outer CodeDirectory')
            cd_magic, cd_length = struct.unpack_from('>II', blob, offset)
            need(cd_magic == 0xfade0c02 and offset + cd_length <= length, 'Invalid outer CodeDirectory')
            hash_size, hash_type = struct.unpack_from('>BB', blob, offset + 36)
            directories.append((kind, hash_size, hash_type, blob[offset:offset + cd_length]))
    need(len(directories) == 1 and directories[0][0] == 0, f'{METHOD} supports exactly one outer CodeDirectory')
    _, hash_size, hash_type, directory = directories[0]
    need(hash_type == 2 and hash_size == 32, f'{METHOD} supports only a SHA-256 outer CodeDirectory')
    full = sha(directory)
    return {'arch': 'arm64', 'algorithm': 'sha256', 'cdhash': full[:40], 'code_directory_hash': full}


def display_identity(record):
    """The CodeDirectory candidates codesign reports for one verified bundle."""
    lines = (record['stderr'] + '\n' + record['stdout']).splitlines()
    value = lambda prefix: [line[len(prefix):] for line in lines if line.startswith(prefix)]
    full, candidates = value('CandidateCDHashFull sha256='), value('CandidateCDHashFull ')
    cdhash, choices = value('CDHash='), value('Hash choices=')
    need(len(full) == 1 and len(candidates) == 1 and choices == ['sha256'] and len(cdhash) == 1 and _hex(full[0]) and cdhash[0] == full[0][:40],
         'codesign does not report exactly one SHA-256 outer CodeDirectory')
    return {'code_directory_hash': full[0], 'cdhash': cdhash[0], 'team': (value('TeamIdentifier=') or [None])[0], 'identifier': (value('Identifier=') or [None])[0],
            'format': (value('Format=') or [None])[0], 'ticket_display': (value('Notarization Ticket=') or [None])[0]}


def apple_checks(run, app, team, label, roles=None, bundle_id=None, stapled=True):
    """Actual codesign (Developer ID CA, leaf and Team requirement, strict, all architectures)
    on the whole bundle and, with `roles` ({path: policy role}), on every explicit code object
    plus the static role check; the outer CodeDirectory identity from codesign and from the
    verified bytes; and, for a stapled tree, actual `xcrun stapler validate` and Gatekeeper
    assessment. The tree is hashed before and after."""
    signing = _signing()
    requirement = signing.developer_id_requirement(team)
    before = walk_tree(app)
    result = {'tree_inventory_sha256': inventory_digest(before['files']), 'files': len(before['files'])}
    run.passes('codesign', [CODESIGN, '--verify', '--deep', '--strict', '--all-architectures', f'--test-requirement=={requirement}', app], f'{label}: codesign bundle')
    if roles is not None:
        for path in sorted(roles):
            run.passes('codesign', [CODESIGN, '--verify', '--strict', '--all-architectures', f'--test-requirement=={requirement}', app / path], f'{label}: codesign {path}')
            data = (app / path).read_bytes()
            need(sha(data) == before['files'][path]['sha256'], f'{label}: {path} changed during verification')
            final.check_signature(path, roles[path], data, 'developer-id', team, final.expected_identifier(roles[path], path, bundle_id))
        result['code_objects'] = len(roles)
    display = display_identity(run.passes('codesign', [CODESIGN, '-d', '-vvvv', '--arch', 'arm64', app], f'{label}: outer CodeDirectory'))
    executable = signing.strict_plist(app / final.INFO)['CFBundleExecutable']
    outer = outer_identity((app / 'Contents/MacOS' / executable).read_bytes())
    need(display['code_directory_hash'] == outer['code_directory_hash'] and display['cdhash'] == outer['cdhash'] and display['team'] == team,
         f'{label}: codesign and the verified bytes disagree on the outer CodeDirectory identity')
    result.update(outer=outer, display=display)
    if stapled:
        run.passes('stapler', [XCRUN, 'stapler', 'validate', app], f'{label}: stapler validate')
        gatekeeper = run.passes('spctl', [SPCTL, '--assess', '--type', 'execute', '--verbose=4', app], f'{label}: Gatekeeper assessment')
        result['gatekeeper'] = ' '.join((gatekeeper['stderr'] + gatekeeper['stdout']).split())[-300:]
    need(walk_tree(app) == before, f'{label}: the verified tree changed during the Apple checks')
    return result


# ------------------------------------------------------------ archives

def appledouble_attributes(data):
    """Attribute names of one sequestered AppleDouble member as written by ditto: an all-zero
    Finder info entry carrying the extended attributes, an empty resource fork and only
    reviewed attribute names."""
    need(len(data) >= 50 and struct.unpack_from('>II', data, 0) == (0x00051607, 0x00020000) and data[8:24] == b'Mac OS X        ', 'Invalid AppleDouble transport member')
    count, = struct.unpack_from('>H', data, 24)
    need(count == 2, 'Unexpected AppleDouble entries')
    entries = {}
    for i in range(count):
        kind, offset, length = struct.unpack_from('>III', data, 26 + 12 * i)
        need(kind not in entries and offset + length <= len(data), 'Invalid AppleDouble entry')
        entries[kind] = (offset, length)
    need(set(entries) == {9, 2} and entries[2][1] == 0, 'AppleDouble transport members may carry only extended attributes')
    offset, length = entries[9]
    need(offset == 50 and entries[2][0] == offset + length == len(data), 'Unaccounted AppleDouble transport bytes')
    need(length >= 32 and data[offset:offset + 32] == bytes(32), 'AppleDouble Finder information must be empty')
    names = []
    if length > 32:
        base = offset + 34
        need(length >= 70 and data[offset + 32:base] == b'\0\0' and data[base:base + 4] == b'ATTR', 'Invalid AppleDouble attribute header')
        total, start, size = struct.unpack_from('>III', data, base + 8)
        flags, attributes = struct.unpack_from('>HH', data, base + 32)
        need(total == len(data) == offset + length and start + size == total and data[base + 20:base + 32] == bytes(12) and flags == 0,
             'Invalid AppleDouble attribute header')
        need(data[base + 4:base + 8] == bytes(4) and attributes > 0, 'Invalid AppleDouble attribute header')
        at, spans = base + 36, []
        for _ in range(attributes):
            need(at + 11 <= len(data), 'Invalid AppleDouble attribute entry')
            value_offset, value_length, entry_flags, name_length = struct.unpack_from('>IIHB', data, at)
            raw = data[at + 11:at + 11 + name_length]
            need(len(raw) == name_length and name_length > 1 and raw.endswith(b'\0') and b'\0' not in raw[:-1]
                 and entry_flags == 0 and start <= value_offset and value_offset + value_length <= start + size, 'Invalid AppleDouble attribute entry')
            name = raw[:-1].decode('utf-8')
            need(name not in names, 'Duplicate AppleDouble attribute name')
            names.append(name)
            spans.append((value_offset, value_length))
            end = at + 11 + name_length
            at = (end + 3) & ~3
            need(at <= start and data[end:at] == bytes(at - end), 'Invalid AppleDouble attribute padding')
        need(at == start, 'Unaccounted AppleDouble attribute table bytes')
        cursor = start
        for value_offset, value_length in sorted(spans):
            need(value_offset == cursor, 'Overlapping or unaccounted AppleDouble value bytes')
            cursor += value_length
        need(cursor == total, 'Unaccounted AppleDouble value bytes')
    unknown = sorted(set(names) - set(TRANSPORT_ATTRIBUTES))
    need(not unknown, 'Unreviewed AppleDouble transport attributes: ' + ', '.join(unknown))
    return names


def _zip_extra(data, local):
    """Only the reviewed ditto Unix timestamp/uid/gid extra record, or no extras."""
    if not data:
        return b''
    size = 12 if local else 8
    need(len(data) == size + 4 and struct.unpack_from('<HH', data) == (0x5855, size), 'Unsupported ZIP extra fields')
    return data[4:12]


def _zip_layout(path, infos):
    """Every archive byte is accounted for: local records are contiguous from offset 0 (with
    exact data descriptors), the central directory follows them, and the end record (no
    comment, no zip64) ends the file."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        need(size >= 22, 'Invalid ZIP end record')
        stream.seek(size - 22)
        end = stream.read(22)
        signature, disk, start_disk, here, entries, cd_size, cd_offset, comment = struct.unpack('<IHHHHIIH', end)
        need(signature == 0x06054b50 and disk == start_disk == 0 and here == entries and comment == 0, 'Unsupported ZIP end record or archive comment')
        need(entries == len(infos) and entries < 0xffff and cd_offset < 0xffffffff and cd_offset + cd_size == size - 22, 'Unsupported or inconsistent ZIP central directory')
        at = 0
        for info in sorted(infos, key=lambda i: i.header_offset):
            need(info.header_offset == at, f'Unaccounted bytes before ZIP member {info.filename}')
            stream.seek(at)
            header = stream.read(30)
            need(len(header) == 30 and header[:4] == b'PK\x03\x04', f'Invalid local ZIP header: {info.filename}')
            name_length, extra_length = struct.unpack_from('<HH', header, 26)
            need(extra_length <= MAX_EXTRA_FIELD and stream.read(name_length) == info.filename.encode('ascii'), f'Local ZIP header differs from the directory: {info.filename}')
            version, flags, method, _, _, crc, compressed, unpacked = struct.unpack_from('<HHHHHIII', header, 4)
            need(version == info.extract_version and version in (10, 20) and (method != zipfile.ZIP_DEFLATED or version == 20)
                 and flags == info.flag_bits and method == info.compress_type, f'Local ZIP header differs from the directory: {info.filename}')
            values = (info.CRC, info.compress_size, info.file_size)
            # This non-ZIP64 method accepts zero descriptor placeholders or the exact
            # final values, never sentinels or conflicting mixed local declarations.
            need((crc, compressed, unpacked) in ((0, 0, 0), values) if flags & 8 else (crc, compressed, unpacked) == values,
                 f'Local ZIP header differs from the directory: {info.filename}')
            local_extra = stream.read(extra_length)
            need(_zip_extra(local_extra, True) == _zip_extra(info.extra, False), 'Local ZIP extra fields differ from the directory')
            at += 30 + name_length + extra_length + info.compress_size
            if info.flag_bits & 0x8:
                stream.seek(at)
                tail = stream.read(16)
                values = (info.CRC, info.compress_size, info.file_size)
                if tail[:4] == b'PK\x07\x08' and struct.unpack_from('<III', tail, 4) == values:
                    at += 16
                else:
                    need(struct.unpack_from('<III', tail, 0) == values, f'Invalid ZIP data descriptor: {info.filename}')
                    at += 12
        need(at == cd_offset, 'Unaccounted bytes before the ZIP central directory')


def read_archive(path, tree, app):
    try:
        return _read_archive(path, tree, app)
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError) as error:
        raise ValueError(f'Invalid ZIP archive: {error}') from error


def _read_archive(path, tree, app):
    """Strict read of one ditto-style app archive against an observed app tree ({files, modes,
    dirs}): exactly one app subtree named `app` plus sequestered AppleDouble transport members
    for that app's own entries, every byte accounted for, regular files and directories only,
    no traversal, duplicates or collisions, every member streamed within its declared size and
    the archive budget. Returns {app_member, payload, transport, attributes, members}."""
    signing = _signing()
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise Unverified('The archive exceeds the member bound')
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
            raise Unverified('The archive exceeds the uncompressed byte bound')
        names, folded = set(), {}
        for info in infos:
            name = info.filename
            need(info.orig_filename == name and name not in names, f'Duplicate or truncated ZIP member name: {name!r}')
            names.add(name)
            need(all(0x20 <= ord(c) < 0x7f for c in name), f'Unportable ZIP member name: {name!r}')
            final.final_path(name[:-1] if name.endswith('/') else name)
            need(folded.setdefault(signing.fold(name), name) == name, f'Colliding ZIP member names: {name}')
            mode = info.external_attr >> 16
            need(info.create_system == 3 and info.flag_bits & ~0x808 == 0 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                 and len(info.extra) <= MAX_EXTRA_FIELD and mode & 0o7000 == 0, f'Unsupported ZIP member: {name}')
            need(stat.S_ISDIR(mode) if name.endswith('/') else stat.S_ISREG(mode), f'ZIP members must be regular files or directories: {name}')
            need(not name.endswith('/') or (info.file_size == 0 and info.compress_size == 0), f'Invalid ZIP directory member: {name}')
        _zip_layout(Path(path), infos)
        tops = {i.filename.split('/')[0] for i in infos}
        need(tops <= {app, TRANSPORT_ROOT} and app in tops, 'The archive must contain exactly the expected app and its transport metadata; found: ' + ', '.join(sorted(tops - {TRANSPORT_ROOT})))
        payload, transport, attributes, dirs = {}, {}, {}, {}
        allowed = described(app, tree['files'])
        mirrors = {TRANSPORT_ROOT + '/'} | {TRANSPORT_ROOT + '/' + app + '/' + (rel + '/' if rel else '') for rel in tree['dirs']}
        for info in infos:
            name, mode = info.filename, (info.external_attr >> 16) & 0o777
            if name.startswith(TRANSPORT_ROOT + '/'):
                if name.endswith('/'):
                    need(name in mirrors, f'Unexpected transport directory: {name}')
                    continue
                need(name in allowed, f'Unbound transport member: {name}')
                need(info.file_size <= MAX_TRANSPORT_MEMBER, f'Transport member exceeds its bound: {name}')
                data = _member(archive, info)
                attributes[name] = appledouble_attributes(data)
                transport[name] = {'bytes': len(data), 'sha256': sha(data)}
                continue
            rel = name[len(app) + 1:]
            if name.endswith('/'):
                rel = rel[:-1]
                need(rel in tree['dirs'] and mode == tree['dirs'][rel], f'Unexpected archive directory or directory permissions: {name}')
                dirs[rel] = mode
                continue
            need(rel in tree['files'], f'Unexpected archive member: {name}')
            need(mode == tree['modes'][rel], f'Archive permissions differ from the app: {name}')
            digest, count = hashlib.sha256(), 0
            for chunk in _member_chunks(archive, info):
                count += len(chunk)
                digest.update(chunk)
            need(count == info.file_size, f'Archive member is shorter than declared: {name}')
            payload[rel] = {'bytes': count, 'sha256': digest.hexdigest()}
        need(payload == tree['files'], 'The archive app differs from the expected payload')
        need(dirs == tree['dirs'], 'The archive directory closure differs from the app')
    return {'app_member': app, 'payload': dict(sorted(payload.items())), 'transport': dict(sorted(transport.items())),
            'attributes': sorted({a for names in attributes.values() for a in names}), 'members': len(infos)}


def _member_chunks(archive, info):
    """Consume exactly the declared raw span, including DEFLATE EOF and CRC checks.
    ZipExtFile intentionally tolerates bytes after DEFLATE EOF; this method does not.
    Each yielded block and each decompressor allocation is bounded to one MiB.
    """
    stream = archive.fp
    stream.seek(info.header_offset + 26)
    name_length, extra_length = struct.unpack('<HH', stream.read(4))
    stream.seek(info.header_offset + 30 + name_length + extra_length)
    remaining, count, crc = info.compress_size, 0, 0
    decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
    need(decoder is not None or info.compress_size == info.file_size, 'Stored ZIP member sizes differ')
    while remaining:
        raw = stream.read(min(65536, remaining))
        need(raw, 'Truncated ZIP compressed span')
        remaining -= len(raw)
        while raw:
            block = decoder.decompress(raw, min(1 << 20, info.file_size - count + 1)) if decoder else raw
            count += len(block)
            need(count <= info.file_size, 'Archive member exceeds its declared size')
            crc = zlib.crc32(block, crc)
            if block:
                yield block
            if decoder:
                need(not decoder.unused_data and not (decoder.eof and remaining), 'Trailing ZIP compressed bytes')
                raw = decoder.unconsumed_tail
            else:
                raw = b''
    need(decoder is None or decoder.eof, 'Incomplete ZIP compressed stream')
    need(count == info.file_size and crc == info.CRC, 'ZIP member size or CRC differs from its declaration')


def _member(archive, info):
    return b''.join(_member_chunks(archive, info))


# ------------------------------------------------------------ the retained notary log

def log_consistency(log, submission_id, uploaded_sha256, archive_name, app, outer_path, outer):
    """The retained log must name this submission, status, uploaded archive and outer CDHash.
    This is provenance consistency, not authenticated job history."""
    need(isinstance(log, dict), 'The retained notary log is not a JSON object')
    need(log.get('jobId') == submission_id, 'The retained notary log names a different submission id')
    need(log.get('status') == ACCEPTED and _integer(log.get('statusCode')) and log.get('statusCode') == 0, 'The retained notary log does not record an accepted submission')
    need(log.get('sha256') == uploaded_sha256, 'The retained notary log names a different uploaded archive digest')
    need(log.get('archiveFilename') == archive_name, 'The retained notary log names a different uploaded archive file')
    contents = log.get('ticketContents')
    prefix = archive_name + '/' + app
    need(isinstance(contents, list) and bool(contents) and all(isinstance(e, dict) and isinstance(e.get('path'), str) for e in contents),
         'The retained notary log has no ticket contents')
    need(all(e['path'] == prefix or e['path'].startswith(prefix + '/') for e in contents), 'The retained notary log names code outside the submitted app')
    outer_rows = [e for e in contents if e['path'] in (prefix, prefix + '/' + outer_path)]
    need(len(outer_rows) == 2 and all(e.get('arch') == 'arm64' and e.get('digestAlgorithm') == 'SHA-256' and e.get('cdhash') == outer['cdhash'] for e in outer_rows),
         'The retained notary log does not name the verified outer arm64 CDHash')
    return {'job_id': submission_id, 'status': ACCEPTED, 'status_code': 0, 'uploaded_sha256': uploaded_sha256, 'archive_filename': archive_name,
            'ticket_contents': len(contents), 'outer_cdhash': outer['cdhash'],
            'scope': 'retained provenance consistency only; not cryptographically authenticated submission history'}


# ------------------------------------------------------------ derivation

def evidence_locator(path, roots):
    """`evidence:NAME/REST` for a file under exactly one caller-declared evidence root."""
    path = _signing().no_link_ancestors(path)
    hits = [name for name, root in roots.items() if str(path).startswith(str(root).rstrip('/') + '/')]
    need(len(hits) == 1, f'Evidence must lie under exactly one --evidence-root: {path}')
    rel = str(path)[len(str(roots[hits[0]]).rstrip('/')) + 1:]
    final.final_path(rel)
    return 'evidence:' + hits[0] + '/' + rel


def final_expectations(input_app, binding):
    """The original binder's staging expectations, recomputed from the snapshotted input app
    as final_materials.Derivation computes them (a disagreement can only refuse)."""
    signing = _signing()
    res, version = binding['layout']['resources'], binding['version']
    tools = final.strict((input_app / res / 'tools/tools-v2.json').read_bytes(), 'tools-v2.json')
    browser = final.strict((input_app / res / 'browser/browser-tools-v2.json').read_bytes(), 'browser-tools-v2.json')
    engine = sorted(p[len(res) + 5:] for p in binding['layout']['code'] if p.startswith(res + '/bin/'))
    required = {n: {'version': version, 'prefix': 'bin/' + n} for n in engine}
    for name in ('yt_dlp', 'ffmpeg', 'ffprobe', 'node'):
        required[name] = {'version': tools[name]['version'], 'prefix': 'tools/' + name + '/'}
    required['browser'] = {'version': browser['version'], 'prefix': 'browser/content/'}
    shell = 'Contents/MacOS/' + binding['layout']['executable']
    return {'target': binding['target'], 'version': version, 'locks': binding['locks'], 'required': required,
            'final_components': {name: {'version': version, 'artifact': shell} for name in signing.TWO_PHASE_DEFERRED}}


def host_record(run):
    """Host and tool versions for the report; informational (a failure is unverified)."""
    rows = {}
    for label, argv in (('sw_vers', [SW_VERS]), ('xcodebuild', [XCODEBUILD, '-version']), ('sdk', [XCRUN, '--show-sdk-version'])):
        record = run.tool('info', argv, f'host: {label}')
        rows[label] = ' '.join(record['stdout'].split()) if record['exit'] == 0 else f"exit {record['exit']}"
    return {'platform': platform.platform(), 'machine': platform.machine(), 'python': platform.python_version(), **rows}


def derive(spec, run=None):
    """(envelope, report) re-derived from actual bytes, or ValueError (refused) / Unverified.

    `spec`: contract, signed_binding + signed_binding_sha256, signed_app, stapled_app,
    expected {team_id, target, version, purpose}, uploaded_archive (+ _sha256), notary_log
    (+ _sha256), submission_id, distribution_archive (+ _sha256), evidence_roots {NAME: DIR},
    final_spec(contract) -> the original binder spec for that contract, seconds, temp_root."""
    need(spec.get('contract') == SCHEMA, f"Unknown notarized materials contract {spec.get('contract')!r}")
    if platform.system() != 'Darwin':
        raise Unverified('Notarized materials verification requires a macOS host')
    owned = run is None
    run = run or Run(spec.get('seconds', WORKFLOW_SECONDS), spec.get('temp_root'))
    try:
        return _derive(spec, run)
    finally:
        if owned:
            run.cleanup()


def _derive(spec, run):
    signing = _signing()
    expected = spec['expected']
    started = now()
    need(expected['target'] in TARGETS, f'{METHOD} supports only the darwin-arm64 target')
    need(expected['purpose'] == PURPOSE, 'Private-validation output is never a distribution candidate')
    need(isinstance(expected['team_id'], str) and TEAM.fullmatch(expected['team_id']) is not None, 'The expected Team ID must be 10 uppercase letters or digits')
    need(isinstance(expected['version'], str) and bool(expected['version']), 'The expected version is required')
    need(isinstance(spec['submission_id'], str) and UUID.fullmatch(spec['submission_id']) is not None, 'The submission id must be a canonical lowercase UUID')
    for key in ('signed_binding', 'notary_log', 'uploaded_archive', 'distribution_archive'):
        need(_hex(spec[key + '_sha256']), f'--{key.replace("_", "-")}-sha256 must be 64 lowercase hex characters')
    roots = spec['evidence_roots']
    locators = {key: evidence_locator(spec[key], roots) for key in ('signed_binding', 'notary_log', 'uploaded_archive', 'distribution_archive')}
    need(len({v.lower() for v in locators.values()}) == 4, 'Each evidence file needs its own locator')
    # 1. The caller-pinned signed binding, strictly parsed; its schema selects the original contract.
    binding_bytes = read_stable(spec['signed_binding'], 'Signed binding', MAX_JSON_BYTES)
    need(sha(binding_bytes) == spec['signed_binding_sha256'], 'The signed binding differs from the caller-pinned digest')
    binding = load_strict(binding_bytes)
    need(isinstance(binding, dict) and binding.get('schema') in BINDING_SCHEMAS, 'The signed binding must be omd-final-materials-v1 or omd-final-materials-v2')
    need(binding.get('purpose') == PURPOSE, 'Private-validation output is never a distribution candidate')
    need(binding.get('target') == expected['target'] and binding.get('version') == expected['version'], 'The signed binding differs from the expected target or version')
    need(isinstance(binding.get('signing'), dict) and binding['signing'].get('mode') == 'developer-id' and binding['signing'].get('team_id') == expected['team_id'],
         'The signed binding Team differs from the expected Developer ID Team')
    # 2. The retained notary log (provenance consistency only).
    log_bytes = read_stable(spec['notary_log'], 'Notary log', MAX_LOG_BYTES)
    need(sha(log_bytes) == spec['notary_log_sha256'], 'The notary log differs from the caller-pinned digest')
    log = load_strict(log_bytes)
    archive_name = Path(spec['uploaded_archive']).name
    need(isinstance(log, dict) and log.get('jobId') == spec['submission_id'], 'The retained notary log names a different submission id')
    need(log.get('sha256') == spec['uploaded_archive_sha256'], 'The retained notary log names a different uploaded archive digest')
    for tool in (CODESIGN, XCRUN, SPCTL, DITTO):
        if not os.access(tool, os.X_OK):
            raise Unverified(f'Required tool is unavailable: {tool}')
    host = host_record(run)
    # 3. Archives: private copies bound to the caller-pinned raw digests.
    archives = {}
    for key, what in (('uploaded_archive', 'Uploaded archive'), ('distribution_archive', 'Distribution archive')):
        run.check(what)
        archives[key] = copy_stable(spec[key], run.temp / (key + '.zip'), what, MAX_ARCHIVE_BYTES)
        need(archives[key]['sha256'] == spec[key + '_sha256'], f'The {what.lower()} differs from the caller-pinned digest')
    # 4. Private snapshots of the original, signed and stapled apps (descriptor-safe copies).
    final_spec = spec['final_spec'](binding['schema'])
    apps = {'input': final_spec['input_app'], 'signed': spec['signed_app'], 'stapled': spec['stapled_app']}
    app = Path(spec['stapled_app']).name
    need(Path(spec['signed_app']).name == app and app.endswith('.app'), 'The signed and stapled apps must have the same bundle name')
    trees, snapshots = {}, {}
    for key, source in apps.items():
        run.check(f'the {key} app snapshot')
        (run.temp / key).mkdir(mode=0o700)
        snapshots[key] = run.temp / key / Path(source).name
        trees[key] = walk_tree(source, copy_to=snapshots[key])
    need(trees['signed']['files'] == binding['payload']['files'], 'The signed app differs from the signed binding payload')
    ticket = closure(trees['signed'], trees['stapled'])
    head = (snapshots['stapled'] / TICKET).read_bytes()
    need(sha(head) == ticket['sha256'] and not signing.is_macho(head[:8]) and not head.startswith(b'OMDP2\0'), 'The stapled ticket must be non-code data')
    # 5. The unchanged original binder on the true pre-staple signed app, cryptographic and complete.
    final_spec = {**final_spec, 'input_app': snapshots['input'], 'final_app': snapshots['signed'], 'cryptographic': True, 'temp_root': run.temp / 'final',
                  'contract': binding['schema']}
    (run.temp / 'final').mkdir(mode=0o700)
    inputs = {}
    for key in ('plan', 'report', 'prepared_extractor', 'review'):
        if final_spec.get(key):
            inputs[key] = signing.file_identity(signing.regular_input(str(final_spec[key]), key))
    for key in ('report', 'evidence', 'bootloader'):
        if final_spec.get('extractor_source'):
            inputs['source-' + key] = signing.file_identity(signing.regular_input(str(final_spec['extractor_source'][key]), key))
    if final_spec.get('locks'):
        for name in sorted(os.listdir(final_spec['locks'])):
            inputs['locks/' + name] = signing.file_identity(signing.regular_input(str(Path(final_spec['locks']) / name), name))
    run.check('the original binder verification')
    started_final = time.monotonic()
    original = final.verify(final_spec, binding_bytes)
    need(original.get('rederived_equal') is True and original.get('status') == 'final-materials-validated' and original.get('coverage_validated') is True
         and original.get('distribution_candidate') is True and original.get('distribution_validation') == {'pass': True} and original.get('gaps') == {}
         and original.get('release_accepted') is False and original.get('final_sha256') == sha(binding_bytes),
         'The original signed binding does not fully re-derive as a validated distribution candidate')
    original = {**original, 'seconds': round(time.monotonic() - started_final, 3), 'cryptographic': True, 'contract': binding['schema']}
    # 6. Actual Apple checks on the private snapshots.
    policy, policy_identity = signing.load_policy()
    res, exe, bundle_id, team = binding['layout']['resources'], binding['layout']['executable'], binding['layout']['bundle_id'], expected['team_id']
    roles_all = {signing.expand(r['path'], res, exe): r for r in policy['roles']}
    need(set(roles_all) == set(binding['layout']['code']), 'The current signing policy differs from the signed binding layout')
    signed_checks = apple_checks(run, snapshots['signed'], team, 'signed app', roles_all, bundle_id, stapled=False)
    stapled_checks = apple_checks(run, snapshots['stapled'], team, 'stapled app', roles_all, bundle_id, stapled=True)
    outer = stapled_checks['outer']
    need(signed_checks['outer'] == outer, 'Stapling changed the outer CodeDirectory identity')
    # 7. Archives: the exact uploaded app and the exact stapled app, with explicit transport members.
    uploaded = read_archive(run.temp / 'uploaded_archive.zip', trees['signed'], app)
    distribution = read_archive(run.temp / 'distribution_archive.zip', trees['stapled'], app)
    readback_root = run.temp / 'readback'
    readback_root.mkdir(mode=0o700)
    run.passes('ditto', [DITTO, '-x', '-k', run.temp / 'distribution_archive.zip', readback_root], 'distribution archive readback')
    need(sorted(os.listdir(readback_root)) == [app], 'The distribution archive readback contains other top-level entries')
    readback_tree = walk_tree(readback_root / app)
    need(readback_tree == trees['stapled'], 'The distribution archive readback differs from the stapled app (files, permissions or directories)')
    readback_checks = apple_checks(run, readback_root / app, team, 'distribution readback', stapled=True)
    need(readback_checks['outer'] == outer, 'The distribution readback has a different outer CodeDirectory identity')
    # 8. The retained log, for consistency only.
    submission = log_consistency(log, spec['submission_id'], spec['uploaded_archive_sha256'], archive_name, app, 'Contents/MacOS/' + exe, outer)
    # 9. Everything verified is still what is on disk.
    run.check('the final rehash')
    for key, source in apps.items():
        need(walk_tree(source) == trees[key], f'The {key} app changed during verification')
    for key, what, limit in (('signed_binding', 'Signed binding', MAX_JSON_BYTES), ('notary_log', 'Notary log', MAX_LOG_BYTES)):
        need(sha(read_stable(spec[key], what, limit)) == spec[key + '_sha256'], f'{what} changed during verification')
    for key in ('uploaded_archive', 'distribution_archive'):
        need(signing.file_identity(signing.regular_input(str(spec[key]), key)) == archives[key], f'The {key.replace("_", " ")} changed during verification')
    after = {}
    for key in inputs:
        source = (final_spec['extractor_source'][key[7:]] if key.startswith('source-') else Path(final_spec['locks']) / key[6:] if key.startswith('locks/')
                  else final_spec[key])
        after[key] = signing.file_identity(signing.regular_input(str(source), key))
    need(after == inputs, 'An original binder input changed during verification')
    delivery = binding['delivery']['files']
    for path, identity in delivery.items():
        need(signing.file_identity(final.resolve_delivery(path, final_spec['delivery_roots'])) == identity, f'Delivery material changed during verification: {path}')
    # 10. The envelope, checked by the shared structural contract against these observations.
    sf, tf = trees['signed']['files'], trees['stapled']['files']
    ref = lambda key, identity: {'locator': locators[key], 'bytes': identity['bytes'], 'sha256': identity['sha256']}
    envelope = {
        'schema': SCHEMA, 'method': METHOD, 'target': binding['target'], 'version': binding['version'], 'purpose': binding['purpose'],
        'signing': {'mode': binding['signing']['mode'], 'team_id': binding['signing']['team_id'], 'bundle_id': binding['signing']['bundle_id']},
        'signed_binding': {'schema': binding['schema'], **ref('signed_binding', {'bytes': len(binding_bytes), 'sha256': sha(binding_bytes)})},
        'signed_payload': {'inventory_sha256': inventory_digest(sf), 'files': sf},
        'stapled_payload': {'inventory_sha256': inventory_digest(tf), 'files': tf},
        'ticket': {'path': TICKET, **ticket},
        'outer_code': {'path': 'Contents/MacOS/' + exe, 'slices': [outer]},
        'submission': {'id': spec['submission_id'], 'status': ACCEPTED, 'status_code': 0, 'app_member': app,
                       'log': ref('notary_log', {'bytes': len(log_bytes), 'sha256': sha(log_bytes)}), 'uploaded_archive': ref('uploaded_archive', archives['uploaded_archive']),
                       'transport': {'inventory_sha256': inventory_digest(uploaded['transport']), 'files': uploaded['transport']}},
        'distribution_archive': {'app_member': app, 'artifact': ref('distribution_archive', archives['distribution_archive']),
                                 'payload_inventory_sha256': inventory_digest(tf),
                                 'transport': {'inventory_sha256': inventory_digest(distribution['transport']), 'files': distribution['transport']}},
        'release_accepted': False,
    }
    initial_bytes = (snapshots['signed'] / binding['initial_review']['path']).read_bytes()
    evidence = {locators['signed_binding']: {'bytes': len(binding_bytes), 'sha256': sha(binding_bytes)}, locators['notary_log']: {'bytes': len(log_bytes), 'sha256': sha(log_bytes)},
                locators['uploaded_archive']: archives['uploaded_archive'], locators['distribution_archive']: archives['distribution_archive']}
    observations = {key: {k: value[k] for k in OBSERVATION} for key, value in (('uploaded', uploaded), ('distribution', distribution))}
    expect = {'binding_sha256': spec['signed_binding_sha256'], 'team_id': team, 'target': expected['target'], 'version': expected['version'],
              'purpose': expected['purpose'], **{k: v for k, v in final_expectations(snapshots['input'], binding).items() if k not in ('target', 'version')}}
    structure = validate_notarized(envelope, binding_bytes, initial_bytes, sf, tf, delivery, observations, evidence, expect)
    report = {
        'schema': REPORT_SCHEMA, 'status': 'notarized-materials-verified', 'contract': SCHEMA, 'method': METHOD, 'started_at': started, 'finished_at': now(),
        'release_accepted': False, 'structure': structure,
        'macos_verification': {'performed': True, 'host': host, 'scope': 'fresh actual checks on this host at this time; audit evidence, never a portable acceptance capability'},
        'signed_binding': {'schema': binding['schema'], 'locator': locators['signed_binding'], 'bytes': len(binding_bytes), 'sha256': sha(binding_bytes)},
        'original_binding_verification': original,
        'closure': {'signed_files': len(sf), 'stapled_files': len(tf), 'directories': len(trees['signed']['dirs']), 'ticket': {'path': TICKET, **ticket},
                    'ticket_header_hex': head[:4].hex(), 'header_is_not_authentication': True,
                    'unchanged': 'every signed payload file (outer executable, Info.plist, seal, manifests, build inventory and receipts included), '
                                 'every permission bit and the directory closure are identical'},
        'apple': {'requirement': signing.developer_id_requirement(team), 'policy': policy_identity, 'signed': signed_checks, 'stapled': stapled_checks,
                  'readback': readback_checks},
        'archives': {key: {'locator': locators[key], **archives[key], 'members': seen['members'], 'payload_files': len(seen['payload']),
                           'transport_members': len(seen['transport']), 'transport_attributes': seen['attributes']}
                     for key, seen in (('uploaded_archive', uploaded), ('distribution_archive', distribution))},
        'submission_log': {'locator': locators['notary_log'], 'bytes': len(log_bytes), 'sha256': sha(log_bytes), **submission},
        'rehash': {'apps': {k: inventory_digest(v['files']) for k, v in trees.items()}, 'original_inputs': len(inputs), 'delivery_files': len(delivery),
                   'unchanged': True},
        'bounds': {'deadline_kind': 'cooperative; legacy verifier and synchronous IO are not interrupted',
                   'tool_limits_scope': 'new wrapper invocations only; legacy verifier keeps its existing timeouts, uncapped capture and cleanup',
                   'seconds': run.seconds, 'timeouts': run.timeouts, 'output_limit': OUTPUT_LIMIT, 'tree_files': MAX_TREE_FILES, 'tree_bytes': MAX_TREE_BYTES,
                   'archive_bytes': MAX_ARCHIVE_BYTES, 'archive_members': MAX_ARCHIVE_MEMBERS, 'uncompressed_bytes': MAX_UNCOMPRESSED, 'ticket_bytes': TICKET_MAX,
                   'transport_member_bytes': MAX_TRANSPORT_MEMBER},
        'commands': run.records, 'limits': LIMITS, 'open_gates': OPEN_GATES,
    }
    run.check('completed verification')
    return envelope, report


def compare(given_bytes, given_sha256, envelope):
    """Verify: the caller-pinned envelope bytes must equal the freshly re-derived envelope."""
    need(_hex(given_sha256) and sha(given_bytes) == given_sha256, 'The envelope differs from the caller-pinned digest')
    given = load_strict(given_bytes)
    need(_keys(given, TOP) and given.get('schema') == SCHEMA, 'Not an omd-notarized-materials-v1 envelope')
    differences = sorted(k for k in TOP if not same(given.get(k), envelope[k]))
    need(not differences, 'The envelope differs from the envelope re-derived from actual bytes: ' + ', '.join(differences))
    return given
