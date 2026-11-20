"""Two-phase final materials binding (omd-final-materials-v1 and -v2).

Phase one is the unchanged omd-materials-v1 initial review: it binds reviewed
source/material facts to the original, pre-signature artifact digests and is
validated when resources are staged. Signing then changes code bytes, manifests,
the build inventory, the engine receipt and the seal. Phase two, here, binds the
final signed payload outside the app:

* `validate_final` is the shared contract, implemented identically in the desktop
  (scripts/final-materials-contract.mjs) and exercised by shared fixtures. It checks
  coverage, statuses, routes, receipts and relation shapes against the actual final
  payload and delivery inventories. It does not read Mach-O bytes.
* `prepare`/`verify` re-derive every relation from actual before/after bytes with the
  reviewed signing validators (paired signature-only layout check, the full prepared
  extractor proof, manifest/inventory/receipt/seal recomputation) and never trust a
  report's claims. Only an explicit reviewed final input plus verified relations can
  yield coverage_validated; release_accepted is always false.

Contract versions are explicit. omd-final-materials-v1 (the default) is unchanged: its
prepared-extractor relation pins the stock-bootloader method and it refuses the
controlled-source route. omd-final-materials-v2 has the same rules plus a typed
`extractor` section and a route label on that relation. Its stock route is v1's proof; its
controlled-source route repeats the source preparation proof (macos_extractor.check_report
with the digest-bound evidence, kit and compiled bootloader against the input producer
bytes), cryptographically verifies every packed member and binds the kit as a delivery
source material of the initial-review extractor component. A route never borrows the
other's proof, and the evidence is a digest root of trust, never a review status.

Nothing here signs, notarizes, publishes, reads credentials or decides compliance.
"""
import copy
import hashlib
import json
import os
import plistlib
import posixpath
import re
import struct
import tempfile
from pathlib import Path

import materials_contract

FINAL_SCHEMA = 'omd-final-materials-v1'
FINAL_SCHEMA_V2 = 'omd-final-materials-v2'
REVIEW_SCHEMA = 'omd-final-review-v1'
REPORT_SCHEMA = 'omd-final-materials-report-v1'
REPORT_SCHEMA_V2 = 'omd-final-materials-report-v2'
VERIFICATION_SCHEMA = 'omd-final-materials-verification-v1'
VERIFICATION_SCHEMA_V2 = 'omd-final-materials-verification-v2'
FINAL_NAME = 'final-materials-v1.json'
FINAL_NAME_V2 = 'final-materials-v2.json'
V1_SCHEMA = 'omd-materials-v1'
V1_NAME = 'third-party/materials-v1.json'
SEAL = 'Contents/_CodeSignature/CodeResources'
INFO = 'Contents/Info.plist'
PURPOSES = ('distribution-candidate', 'private-validation')
BINDING = 'two-phase'
SIGNED_STATUS = 'signed-awaiting-final-materials'
TRIPLES = {'darwin-arm64': 'aarch64-apple-darwin', 'darwin-x64': 'x86_64-apple-darwin'}
LAYOUT_VERSION = 'omd-macho-signature-layout-v2'
EXTRACTOR_METHOD = 'omd-pyinstaller-6.22.0-onefile-signature-only-v1'
# v2 only: the controlled-source route (macos_extractor_source.py) and the method/route pairs.
SOURCE_EXTRACTOR_METHOD = 'omd-pyinstaller-6.22.0-source-bootloader-onefile-signature-only-v1'
EXTRACTOR_ROUTES = {EXTRACTOR_METHOD: 'upstream-stock', SOURCE_EXTRACTOR_METHOD: 'controlled-source'}
SOURCE_EVIDENCE_SCHEMA = 'omd-macos-extractor-source-evidence-v1'
SOURCE_PROFILE_FILE = 'distribution/yt-dlp-source-curl/profile.json'
STOCK_BOOTLOADER_SHA256 = 'ca3cc654cebdb7a005872a4ff4fad10bfe34926f6f6425946b0dc6285289a879'
EXTRACTOR_COMPONENT = 'yt_dlp'
EXTRACTOR_ARCHES = ('universal2', 'arm64', 'x86_64')
TARGET_ARCH = {'darwin-arm64': 'arm64', 'darwin-x64': 'x86_64'}
KINDS = tuple(materials_contract.KINDS)
BASES = ('initial-review', 'final-review')
ROUTES = ('payload', 'delivery')
LOCAL = ('/Users/', '/Volumes/', '/private/', '/home/', '/tmp/', ':\\\\')
HEX = re.compile(r'[a-f0-9]{64}')
TEAM = re.compile(r'[A-Z0-9]{10}')
EXECUTABLE = re.compile(r'[A-Za-z0-9._-]{1,128}')
ROLE = re.compile(r'[a-z0-9-]{1,64}')
COMPONENT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
TOP = ('schema', 'purpose', 'target', 'version', 'locks', 'layout', 'signing', 'initial_review', 'input', 'payload', 'relations', 'receipts',
       'components', 'delivery', 'pending', 'reviewed', 'coverage_validated', 'distribution_candidate', 'release_accepted', 'limits')
SIGNING_FIELDS = ('mode', 'team_id', 'purpose', 'materials_binding', 'status', 'plan_sha256', 'report_sha256', 'bundle_id')
RECEIPT_FIELDS = ('receipt', 'notices', 'binaries', 'artifacts', 'lock_sha256', 'target', 'version', 'findings', 'spans', 'spans_in_payload', 'pending', 'release_accepted')
COMPONENT_FIELDS = ('id', 'version', 'basis', 'initial_component', 'status', 'pending', 'artifacts', 'materials')
METHODS = {'signature-only': 'paired-structure', 'prepared-extractor': EXTRACTOR_METHOD, 'managed-manifest': 'digest-fields-only',
           'build-inventory': 'digests-and-signing-record', 'engine-receipt': 'artifact-only-rebinding', 'outer-seal': 'code-resources-hash2',
           'nested-seal': 'code-resources-hash2'}
RELATION_FIELDS = {
    'identical': {'kind', 'before', 'after'},
    'signature-only': {'kind', 'before', 'after', 'method', 'layout', 'signature_independent_sha256'},
    'prepared-extractor': {'kind', 'before', 'after', 'method', 'prepared', 'signature_only_natives', 'identical_non_natives', 'signature_independent_sha256'},
    'managed-manifest': {'kind', 'before', 'after', 'method'},
    'build-inventory': {'kind', 'before', 'after', 'method'},
    'engine-receipt': {'kind', 'before', 'after', 'method'},
    'outer-seal': {'kind', 'before', 'after', 'method', 'sealed_files'},
    'nested-seal': {'kind', 'before', 'after', 'method', 'sealed_files'},
}
# A nested application bundle under the resources (the macOS sign-in window): its main
# executable is a code object, and signing adds exactly its Contents/_CodeSignature seal.
NESTED_CODE = re.compile(r'(.+\.app)/Contents/MacOS/[A-Za-z0-9._-]{1,128}')
NESTED_SEAL = '/Contents/_CodeSignature/CodeResources'


def nested_bundles(code, res):
    """{bundle root: main executable} for code objects inside a nested .app under the resources."""
    found = {}
    for path in code:
        match = NESTED_CODE.fullmatch(path) if path.startswith(res + '/') else None
        if match:
            found[match[1]] = path
    return found


def engine_binaries(code, res):
    """{receipt name: payload path} of the engine binaries among a layout's code paths.
    A binding is checked against the layout it recorded, not the current one: an
    earlier macOS layout installed the sign-in window as a bare bin/omd-signin."""
    found = {}
    for path in sorted(code):
        if path.startswith(res + '/bin/'):
            name = materials_contract.binary_name(path[len(res) + 1:])
            need(name is not None and name not in found, 'Invalid final payload layout')
            found[name] = path
    return found
# omd-final-materials-v2: every v1 field plus the typed extractor route; the prepared-extractor
# relation gains a route label that must pair with its method.
TOP_V2 = (*TOP[:TOP.index('receipts')], 'extractor', *TOP[TOP.index('receipts'):])
RELATION_FIELDS_V2 = {**RELATION_FIELDS, 'prepared-extractor': RELATION_FIELDS['prepared-extractor'] | {'route'}}
EXTRACTOR_FIELDS = ('path', 'component', 'route', 'method', 'version', 'target_arch', 'producer', 'prepared', 'members_verified', 'report', 'source')
SOURCE_FIELDS = ('evidence', 'kit', 'bootloader', 'profile', 'plan_sha256', 'receipt_sha256', 'members', 'natives')
CONTRACT_TOP = {FINAL_SCHEMA: TOP, FINAL_SCHEMA_V2: TOP_V2}
FINAL_NAMES = {FINAL_SCHEMA: FINAL_NAME, FINAL_SCHEMA_V2: FINAL_NAME_V2}
REPORT_SCHEMAS = {FINAL_SCHEMA: REPORT_SCHEMA, FINAL_SCHEMA_V2: REPORT_SCHEMA_V2}
VERIFICATION_SCHEMAS = {FINAL_SCHEMA: VERIFICATION_SCHEMA, FINAL_SCHEMA_V2: VERIFICATION_SCHEMA_V2}
LIMITS = [
    'Factual binding only: no legal, compliance, notarization or release decision. release_accepted is always false.',
    'Relations prove that signing changed only code signatures, digest fields, receipt artifact bindings and the seal; they never create material coverage.',
    'Initial-review facts carry only through verified relations from the original artifact digests they were reviewed against.',
    'Delivery materials are bound by digest; how and where they are offered to recipients is part of the reviewed component materials.',
]
LIMITS_V2 = [
    *LIMITS,
    'The extractor route is typed: the stock route carries no source evidence, and the controlled-source route is re-proven from the input producer bytes, '
    'its digest-bound evidence, kit, compiled bootloader and preparation report on every prepare and verify.',
    'Source evidence is a digest root of trust, not a legal, source or materials acceptance; compilation from the kit sources, source and terms sufficiency, '
    'and runtime capability stay build and review evidence. Component statuses come only from the reviewed final input.',
]
OPEN_GATES = [
    'Notarization, stapling and Gatekeeper acceptance of the exact final artifact.',
    'Quarantined, pristine-account installation, GUI first-run/import and offered-platform execution acceptance.',
    'Live acquisition, engine-brokered browser sessions and runtime loading of every packed native.',
    'Publishing the delivery set at its reviewed route and final release acceptance.',
]


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_inventory(files):
    """Same canonical form as the signer's app inventories ({path: {bytes, sha256}})."""
    return sha(json.dumps(files, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())


def final_path(value):
    """Portable relative path restricted to printable ASCII (identical sorting/serialization in Python and JS)."""
    materials_contract.portable(value)
    need(all(0x20 <= ord(c) < 0x7f for c in value), 'Invalid portable path')
    return value


# ---------------------------------------------------------------- shared contract

def validate_final(doc, initial_bytes, payload, delivery, expect):
    """Distribution validation of a final binding against the actual final payload and
    delivery inventories ({path: {bytes, sha256}}), the initial review bytes and the
    expected target/version/locks/components. Mirrors final-materials-contract.mjs.
    The document schema selects the rules: omd-final-materials-v2 adds the typed extractor
    route; anything else is held to the unchanged omd-final-materials-v1 rules."""
    v2 = isinstance(doc, dict) and isinstance(doc.get('schema'), str) and doc['schema'] == FINAL_SCHEMA_V2
    top, names = (TOP_V2, (FINAL_NAME, FINAL_NAME_V2)) if v2 else (TOP, (FINAL_NAME,))

    def hexdigest(x):
        return isinstance(x, str) and HEX.fullmatch(x) is not None

    def keys(obj, wanted):
        return isinstance(obj, dict) and set(obj) == set(wanted)

    def integer(value):
        # JSON numbers have no distinct integer/float wire types. Match JS safe integers
        # for the v2 extractor fields; keep the v1 validation rules unchanged.
        return type(value) in (int, float) and abs(value) <= 9007199254740991 and value % 1 == 0

    def identity(value):
        return keys(value, ('bytes', 'sha256')) and integer(value['bytes']) and value['bytes'] > 0 and hexdigest(value['sha256'])

    def files_map(value, what):
        need(isinstance(value, dict) and bool(value), f'Invalid {what} inventory')
        folded = set()
        for path, row in value.items():
            final_path(path)
            need(path.lower() not in folded, f'Duplicate or colliding {what} path')
            folded.add(path.lower())
            need(keys(row, ('bytes', 'sha256')) and type(row['bytes']) is int and row['bytes'] >= 0 and hexdigest(row['sha256']), f'Invalid {what} inventory')
            need(path.split('/')[-1] not in names, 'Final materials must stay outside the signed payload and delivery set')

    need(isinstance(doc, dict) and set(doc) == set(top), 'Unknown/missing final materials fields')
    need(not any(x in json.dumps(doc) for x in LOCAL), 'Machine-local final materials metadata')
    need(doc['schema'] == (FINAL_SCHEMA_V2 if v2 else FINAL_SCHEMA), 'Wrong final materials schema')
    need(doc['release_accepted'] is False, 'Final materials never accept a release')
    need(doc['purpose'] in PURPOSES, 'Unknown final materials purpose')
    need(doc['purpose'] == 'distribution-candidate', 'Private-validation output is never a distribution candidate')
    s = doc['signing']
    need(keys(s, SIGNING_FIELDS) and s['purpose'] == doc['purpose'] and s['mode'] == 'developer-id' and s['materials_binding'] == BINDING
         and s['status'] == SIGNED_STATUS and isinstance(s['team_id'], str) and TEAM.fullmatch(s['team_id']) is not None
         and hexdigest(s['plan_sha256']) and hexdigest(s['report_sha256']),
         'Final binding requires a fresh two-phase Developer ID distribution-candidate signing run')
    need(isinstance(doc['target'], str) and doc['target'] in TRIPLES and doc['target'] == expect['target'] and doc['version'] == expect['version'],
         'Wrong final materials target/version')
    need(isinstance(doc['locks'], dict) and bool(doc['locks']) and doc['locks'] == expect['locks'], 'Stale/missing final materials locks')
    need(doc['pending'] == [] and doc['reviewed'] is True and doc['coverage_validated'] is True and doc['distribution_candidate'] is True,
         'Pending final materials coverage')
    need(isinstance(doc['limits'], list) and bool(doc['limits']) and all(isinstance(x, str) and x.strip() for x in doc['limits']), 'Invalid final materials limits')
    layout = doc['layout']
    need(keys(layout, ('resources', 'executable', 'bundle_id', 'code')) and isinstance(layout['executable'], str)
         and EXECUTABLE.fullmatch(layout['executable']) is not None and layout['bundle_id'] == s['bundle_id'] and isinstance(layout['code'], dict),
         'Invalid final payload layout')
    res = final_path(layout['resources'])
    shell = 'Contents/MacOS/' + layout['executable']
    code = layout['code']
    need(code.get(shell) == 'desktop-shell' and list(code.values()).count('yt-dlp') == 1
         and all(isinstance(r, str) and ROLE.fullmatch(r) is not None for r in code.values()), 'Invalid final payload layout')
    for path in code:
        final_path(path)
        need(path == shell or path.startswith(res + '/'), 'Invalid final payload layout')
    for name in ('input', 'payload'):
        need(keys(doc[name], ('inventory_sha256', 'files')), f'Invalid {name} inventory')
        files_map(doc[name]['files'], name)
        need(doc[name]['inventory_sha256'] == canonical_inventory(doc[name]['files']), f'Invalid {name} inventory')
    need(keys(doc['delivery'], ('files',)), 'Invalid delivery inventory')
    files_map(doc['delivery']['files'], 'delivery')
    need(doc['payload']['files'] == payload, 'Final payload differs from the bound payload inventory')
    need(doc['delivery']['files'] == delivery, 'Delivery set differs from the bound delivery inventory')
    before, after, shipped = doc['input']['files'], doc['payload']['files'], doc['delivery']['files']
    bundles = nested_bundles(code, res)
    seals = {root + NESTED_SEAL: root for root in bundles}
    need(set(before) <= set(after), 'Unexpected removal of an input file')
    need(set(after) - set(before) <= {SEAL} | set(seals), 'Unexpected new payload file')
    need(INFO in after and SEAL in after and all(p in after for p in code) and all(p.startswith('Contents/') for p in after), 'Invalid final payload layout')
    need(all(p in after and p not in before for p in seals), 'A nested bundle is not freshly sealed')
    relations = doc['relations']
    need(isinstance(relations, dict) and set(relations) == set(after), 'Relations must cover exactly the final payload')
    fixed = {res + '/tools/tools-v2.json': 'managed-manifest', res + '/browser/browser-tools-v2.json': 'managed-manifest',
             res + '/build-inventory.json': 'build-inventory', res + '/third-party/native-receipt.json': 'engine-receipt', SEAL: 'outer-seal',
             **dict.fromkeys(seals, 'nested-seal')}
    fields = RELATION_FIELDS_V2 if v2 else RELATION_FIELDS
    for path, r in relations.items():
        kind = ('prepared-extractor' if code[path] == 'yt-dlp' else 'signature-only') if path in code else fixed.get(path, 'identical')
        need(isinstance(r, dict) and r.get('kind') == kind and set(r) == fields[kind], 'Unexpected relation for ' + path)
        need(r['before'] == (before[path]['sha256'] if path in before else None) and r['after'] == after[path]['sha256'],
             'Relation does not bind input and final bytes: ' + path)
        if kind == 'identical':
            need(r['before'] == r['after'], 'Unexpected payload change: ' + path)
            continue
        if v2 and kind == 'prepared-extractor':
            # A known method with exactly its own route label; v1 pins the stock method instead.
            method = isinstance(r['method'], str) and r['method'] in EXTRACTOR_ROUTES and EXTRACTOR_ROUTES[r['method']] == r['route']
        else:
            method = r['method'] == METHODS[kind]
        need(method and (r['before'] is not None or kind in ('outer-seal', 'nested-seal')), 'Unexpected relation for ' + path)
        if path in code:
            need(r['before'] != r['after'], 'Code object was not re-signed: ' + path)
            need(hexdigest(r['signature_independent_sha256']), 'Unexpected relation for ' + path)
            if kind == 'signature-only':
                need(r['layout'] == LAYOUT_VERSION, 'Unexpected relation for ' + path)
            else:
                need(hexdigest(r['prepared']) and r['prepared'] not in (r['before'], r['after']) and type(r['signature_only_natives']) is int
                     and r['signature_only_natives'] > 0 and type(r['identical_non_natives']) is int and r['identical_non_natives'] >= 0,
                     'Unexpected relation for ' + path)
        if kind == 'outer-seal':
            need(type(r['sealed_files']) is int and r['sealed_files'] == len(after) - 3, 'Unexpected relation for ' + path)
        if kind == 'nested-seal':
            root = seals[path]
            inside = [p for p in after if p.startswith(root + '/') and p not in (root + '/' + INFO, bundles[root], path)]
            need(r['before'] is None and type(r['sealed_files']) is int and r['sealed_files'] == len(inside), 'Unexpected relation for ' + path)
    if v2:
        # The typed extractor route: it must restate the relation it explains, and the stock
        # and controlled-source routes can never carry each other's proof.
        x = doc['extractor']
        extractor = next(p for p, role in code.items() if role == 'yt-dlp')
        r = relations[extractor]
        ok = (keys(x, EXTRACTOR_FIELDS) and x['path'] == extractor and isinstance(x['component'], str) and isinstance(x['method'], str)
              and x['method'] in EXTRACTOR_ROUTES and EXTRACTOR_ROUTES[x['method']] == x['route'] and x['method'] == r['method'] and x['route'] == r['route'])
        want = expect['required'].get(x['component']) if ok else None
        ok = (ok and isinstance(want, dict) and isinstance(want.get('prefix'), str)
              and (extractor.startswith(res + '/' + want['prefix']) if want['prefix'].endswith('/') else extractor == res + '/' + want['prefix'])
              and x['version'] == want.get('version') and identity(x['producer']) and x['producer'] == before[extractor]
              and identity(x['prepared']) and x['prepared']['sha256'] == r['prepared']
              and integer(x['members_verified']) and x['members_verified'] == r['signature_only_natives']
              and x['target_arch'] in EXTRACTOR_ARCHES and x['target_arch'] in ('universal2', TARGET_ARCH[doc['target']]))
        need(ok, 'Invalid extractor route binding')
        kit = None
        if x['route'] == 'upstream-stock':
            need(x['report'] is None and x['source'] is None, 'Stock extractor route cannot carry controlled-source evidence')
        else:
            need(x['report'] is not None and x['source'] is not None, 'Controlled-source route requires its source evidence and preparation report')
            source = x['source']
            ok = (identity(x['report']) and keys(source, SOURCE_FIELDS) and keys(source['evidence'], ('schema', 'bytes', 'sha256')) and source['evidence']['schema'] == SOURCE_EVIDENCE_SCHEMA
                  and identity({k: source['evidence'][k] for k in ('bytes', 'sha256')}) and identity(source['bootloader']) and source['bootloader']['sha256'] != STOCK_BOOTLOADER_SHA256
                  and keys(source['profile'], ('file', 'id', 'sha256')) and source['profile']['file'] == SOURCE_PROFILE_FILE and isinstance(source['profile']['id'], str)
                  and bool(source['profile']['id']) and hexdigest(source['profile']['sha256']) and hexdigest(source['plan_sha256']) and hexdigest(source['receipt_sha256'])
                  and integer(source['natives']) and source['natives'] == r['signature_only_natives']
                  and integer(source['members']) and source['members'] == source['natives'] + r['identical_non_natives']
                  and x['target_arch'] == 'arm64' and doc['target'] == 'darwin-arm64'
                  and keys(source['kit'], ('locator', 'bytes', 'sha256')) and isinstance(source['kit']['locator'], str))
            need(ok, 'Invalid controlled-source evidence binding')
            kit = source['kit']
            route, _, kit_path = kit['locator'].partition(':')
            need(route == 'delivery' and integer(kit['bytes']) and shipped.get(kit_path) == {'bytes': kit['bytes'], 'sha256': kit['sha256']},
                 'Controlled-source kit is not a bound delivery file')
    review = doc['initial_review']
    need(review is not None, 'Missing initial omd-materials-v1 review')
    v1path = res + '/' + V1_NAME
    need(keys(review, ('schema', 'path', 'sha256', 'bytes')) and review['schema'] == V1_SCHEMA and review['path'] == v1path, 'Invalid initial review binding')
    need(isinstance(initial_bytes, bytes) and sha(initial_bytes) == review['sha256'] and len(initial_bytes) == review['bytes'],
         'Initial review bytes differ from the bound initial review')
    need(after.get(v1path, {}).get('sha256') == review['sha256'] and relations[v1path]['kind'] == 'identical', 'Initial review is not the unchanged in-app manifest')
    initial = json.loads(initial_bytes)
    staged = {p[len(res) + 1:]: row['sha256'] for p, row in before.items()
              if p.startswith(res + '/') and p not in (res + '/build-inventory.json', v1path)}
    materials_contract.validate(initial, staged, expect['required'], doc['target'], doc['version'], doc['locks'])
    receipts = doc['receipts']
    need(keys(receipts, ('engine', 'desktop')) and receipts['engine'] is not None and receipts['desktop'] is not None, 'Missing final native receipt binding')
    triple = TRIPLES[doc['target']]
    engine_paths = engine_binaries(code, res)
    binaries = sorted(engine_paths)

    def bound(r, names, artifacts, lock):
        return (keys(r, RECEIPT_FIELDS) and r['binaries'] == names and r['artifacts'] == artifacts and isinstance(lock, str) and r['lock_sha256'] == lock
                and r['target'] == triple and r['version'] == doc['version'] and type(r['findings']) is int and r['findings'] > 0
                and type(r['spans']) is int and r['spans'] > 0 and r['spans_in_payload'] == r['spans'] and r['pending'] == [] and r['release_accepted'] is False)
    engine, receipt_path, notices_path = receipts['engine'], res + '/third-party/native-receipt.json', res + '/third-party/native-NOTICES.txt'
    need(bool(binaries) and receipt_path in after and notices_path in after
         and bound(engine, binaries, {n: after[p]['sha256'] for n, p in engine_paths.items()}, doc['locks'].get('Cargo.lock'))
         and engine['receipt'] == {'path': receipt_path, 'sha256': after[receipt_path]['sha256']}
         and engine['notices'] == {'path': notices_path, 'sha256': after[notices_path]['sha256']},
         'Engine receipt does not bind the final payload')
    desktop = receipts['desktop']
    detached = [desktop.get('receipt'), desktop.get('notices')] if isinstance(desktop, dict) else []
    need(bound(desktop, [layout['executable']], {layout['executable']: after[shell]['sha256']}, doc['locks'].get('desktop-Cargo.lock'))
         and all(keys(x, ('path', 'sha256')) and isinstance(x['path'], str) and x['path'] in shipped and shipped[x['path']]['sha256'] == x['sha256'] for x in detached),
         'Desktop receipt does not bind the final executable')
    components = doc['components']
    need(isinstance(components, list) and bool(components), 'Empty final component coverage')
    initial_components = {c['id']: c for c in initial['components']}
    ids, covered, delivered = {}, set(), {x['path'] for x in detached}
    for c in components:
        need(keys(c, COMPONENT_FIELDS) and isinstance(c['id'], str) and COMPONENT_ID.fullmatch(c['id']) is not None and c['id'] not in ids
             and isinstance(c['version'], str) and bool(c['version']) and c['basis'] in BASES, 'Duplicate/invalid final component')
        ids[c['id']] = c
        need(c['status'] == 'reviewed' and c['pending'] == [], 'Unresolved final component')
        need(isinstance(c['artifacts'], dict) and bool(c['artifacts']), 'Missing final component artifacts')
        for path, a in c['artifacts'].items():
            need(keys(a, ('initial', 'final')) and path in after and a['final'] == after[path]['sha256'] and a['initial'] == relations[path]['before'],
                 'Final component artifact is not bound: ' + path)
            covered.add(path)
        need(isinstance(c['materials'], dict) and set(c['materials']) == set(KINDS), 'Missing required material kinds')
        for kind in KINDS:
            group = c['materials'][kind]
            need(isinstance(group, dict) and bool(group), 'Empty final material coverage')
            for locator, digest in group.items():
                route, _, path = locator.partition(':')
                need(route in ROUTES and bool(path), 'Unknown material route')
                final_path(path)
                table = after if route == 'payload' else shipped
                need(hexdigest(digest) and table.get(path, {}).get('sha256') == digest, 'Missing/changed final material: ' + locator)
                (covered if route == 'payload' else delivered).add(path)
        if c['basis'] == 'initial-review':
            source = initial_components.get(c['initial_component']) if isinstance(c['initial_component'], str) else None
            carried = (c['initial_component'] == c['id'] and source is not None and source['version'] == c['version']
                       and set(c['artifacts']) == {res + '/' + p for p in source['artifacts']}
                       and all(c['artifacts'][res + '/' + p]['initial'] == h for p, h in source['artifacts'].items())
                       and all(relations.get(res + '/' + p, {}).get('before') == h and 'payload:' + res + '/' + p in c['materials'][kind]
                               for kind in KINDS for p, h in source['materials'][kind].items()))
            need(carried, 'Initial review facts do not carry to the final payload: ' + c['id'])
        else:
            need(c['initial_component'] is None and c['id'] not in initial_components, 'Final review cannot replace initial review facts: ' + c['id'])
    for name in expect['required']:
        need(name in ids and ids[name]['basis'] == 'initial-review', 'Missing required final components')
    for name, want in expect['final_components'].items():
        need(name in ids and ids[name]['basis'] == 'final-review' and ids[name]['version'] == want['version'] and want['artifact'] in ids[name]['artifacts'],
             'Missing required final components')
    if v2:
        # The route explains the reviewed initial extractor component, and a controlled-source
        # kit is that component's typed source material (never another component's, never a waiver).
        owner = ids.get(x['component'])
        need(owner is not None and owner['basis'] == 'initial-review' and extractor in owner['artifacts'], 'Extractor route is not bound to its initial-review component')
        need(kit is None or owner['materials']['source'].get(kit['locator']) == kit['sha256'], 'Controlled-source kit is not a source material of the extractor component')
    need(set(after) <= covered, 'Uncovered final payload files')
    need(set(shipped) <= delivered, 'Unreferenced delivery file')
    return {'schema': FINAL_SCHEMA_V2 if v2 else FINAL_SCHEMA, 'coverage_validated': True, 'distribution_candidate': True, 'release_accepted': False}


# ---------------------------------------------------------------- byte-level derivation

def _signing():
    import macos_signing
    need(macos_signing.LAYOUT_VERSION == LAYOUT_VERSION, 'Signature layout version changed; update the final materials contract')
    return macos_signing


def serialize(value):
    """The signer's JSON serialization for rewritten manifests and inventories."""
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def strict(data, what):
    try:
        return _signing().strict_json(data)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(f'{what}: {error}') from error


def code_directories(data):
    """Special-slot hashes of every SHA-256 code directory in every slice."""
    signing = _signing()
    found = []
    for off, length in signing.slice_regions(data):
        image = data[off:off + length]
        endian, _, _, _, commands = signing.load_commands(image)
        at = [o for cmd, o, _ in commands if cmd == 0x1d]
        need(len(at) == 1, 'Outer executable is not signed')
        dataoff, datasize = struct.unpack_from(endian + 'II', image, at[0] + 8)
        blob = image[dataoff:dataoff + datasize]
        magic, length_, count = struct.unpack_from('>III', blob, 0)
        need(magic == 0xfade0cc0 and 12 + 8 * count <= length_ <= len(blob), 'Invalid outer code signature')
        directories = []
        for i in range(count):
            kind, offset = struct.unpack_from('>II', blob, 12 + 8 * i)
            if kind == 0 or 0x1000 <= kind < 0x1005:
                need(offset + 44 <= length_, 'Invalid outer code directory')
                cd_magic, cd_length, _, _, hash_offset, _, special, _, _, hash_size, hash_type = struct.unpack_from('>IIIIIIIIIBB', blob, offset)
                need(cd_magic == 0xfade0c02 and offset + cd_length <= length_, 'Invalid outer code directory')
                cd = blob[offset:offset + cd_length]
                if hash_type == 2 and hash_size == 32:
                    need(special >= 3 and hash_offset - special * 32 >= 0 and hash_offset <= len(cd), 'Outer code directory lacks resource slots')
                    directories.append({k: cd[hash_offset - k * 32:hash_offset - (k - 1) * 32].hex() for k in range(1, special + 1)})
        need(directories, 'No SHA-256 outer code directory')
        found += directories
    return found


def expected_identifier(role, path, bundle_id):
    return _signing().role_identifier(role, path, bundle_id)


def check_signature(path, role, data, mode, team, identifier):
    """Static checks of the final signature against the reviewed role (as at signing)."""
    developer = mode == 'developer-id'
    for image in _signing().signature(data):
        need(image['signed'] and image['identifier'] == identifier, f'{path}: unexpected signing identifier')
        need(image['adhoc'] is not developer and image['certificates'] is developer and image['team'] == team, f'{path}: signature mode/team mismatch')
        need(image['runtime'] is _signing().hardened(role) and not image['linker_signed'], f'{path}: hardened runtime flag mismatch')
        need((image['entitlements'] or {}) == role['entitlements'], f'{path}: entitlements differ from the reviewed role')


def cryptographic(app, paths, mode, team, temp_root):
    """Read-only codesign verification of every code object and the sealed bundle."""
    signing = _signing()
    requirement = signing.developer_id_requirement(team) if mode == 'developer-id' else None
    extra = [f'--test-requirement=={requirement}'] if requirement else []
    env = {k: v for k, v in os.environ.items() if not k.startswith(('APPLE_', 'NOTARY', 'CODESIGN_'))}
    if temp_root:
        env['TMPDIR'] = str(temp_root)
    rows = []
    for path in paths:
        code, err = signing.codesign_check([signing.CODESIGN, '--verify', '--strict', '--all-architectures', *extra, str(app / path)], env)
        rows.append({'path': path, 'exit': code, 'reason': ' '.join(err.split())[-300:]})
    code, err = signing.codesign_check([signing.CODESIGN, '--verify', '--deep', '--strict', *extra, str(app)], env)
    rows.append({'path': '.', 'exit': code, 'reason': ' '.join(err.split())[-300:]})
    failed = [r for r in rows if r['exit'] != 0]
    need(not failed, 'Cryptographic signature verification failed: ' + ', '.join(f"{r['path']}: {r['reason']}" for r in failed[:4]))
    return {'method': 'codesign --verify --strict' + (' --test-requirement (Developer ID Application, Team ID)' if requirement else ''),
            'requirement': requirement, 'objects': len(paths), 'bundle_deep': True, 'failed': 0}


def resolve_delivery(path, roots):
    """A delivery path is NAME/REST where --delivery-root NAME=DIR; bytes stay in place."""
    final_path(path)
    name, _, rest = path.partition('/')
    need(bool(rest) and name in roots, f'Delivery path {path} is outside every declared delivery root')
    file = _signing().no_link_ancestors(roots[name] / rest)
    need(file.is_file() and not file.is_symlink(), f'Delivery material is not a regular file: {path}')
    return file


def load_review(path):
    signing = _signing()
    raw = signing.regular_input(str(path), 'Final review').read_bytes()
    review = strict(raw, 'Final review')
    need(isinstance(review, dict) and set(review) == {'schema', 'target', 'version', 'input_inventory_sha256', 'initial_review_sha256', 'components', 'delivery'},
         'Unknown/missing final review fields')
    need(not any(x in json.dumps(review) for x in LOCAL), 'Machine-local final review metadata')
    need(review['schema'] == REVIEW_SCHEMA, 'Wrong final review schema')
    need(isinstance(review['input_inventory_sha256'], str) and HEX.fullmatch(review['input_inventory_sha256']) is not None
         and (review['initial_review_sha256'] is None or HEX.fullmatch(str(review['initial_review_sha256'])) is not None), 'Invalid final review binding')
    statements = lambda x: isinstance(x, list) and all(isinstance(s, str) and s.strip() for s in x)
    ids = set()
    need(isinstance(review['components'], list) and bool(review['components']), 'Final review has no components')
    for c in review['components']:
        need(isinstance(c, dict) and set(c) == {'id', 'version', 'basis', 'status', 'pending', 'artifacts', 'materials', 'facts', 'limits'},
             'Unknown/missing final review component fields')
        need(isinstance(c['id'], str) and COMPONENT_ID.fullmatch(c['id']) is not None and c['id'] not in ids, 'Duplicate/invalid final review component')
        ids.add(c['id'])
        need(isinstance(c['version'], str) and bool(c['version']) and c['basis'] in BASES and c['status'] in ('reviewed', 'pending'),
             f"Invalid final review component: {c['id']}")
        need(statements(c['pending']) and statements(c['facts']) and bool(c['facts']) and statements(c['limits']) and bool(c['limits']),
             f"Final review component needs facts, limits and pending statements: {c['id']}")
        need(isinstance(c['artifacts'], list) and all(isinstance(x, str) for x in c['artifacts']) and len(set(c['artifacts'])) == len(c['artifacts'])
             and (c['basis'] == 'final-review' or not c['artifacts']), f"Invalid final review artifacts: {c['id']}")
        need(isinstance(c['materials'], dict) and set(c['materials']) <= set(KINDS)
             and all(isinstance(v, list) and all(isinstance(x, str) for x in v) and len(set(v)) == len(v) for v in c['materials'].values()),
             f"Invalid final review materials: {c['id']}")
    entries, folded = {}, set()
    need(isinstance(review['delivery'], list), 'Invalid final review delivery')
    for entry in review['delivery']:
        need(isinstance(entry, dict) and set(entry) == {'path', 'sha256', 'bytes'} and isinstance(entry['sha256'], str) and HEX.fullmatch(entry['sha256']) is not None
             and type(entry['bytes']) is int and entry['bytes'] >= 0, 'Invalid final review delivery entry')
        final_path(entry['path'])
        need(entry['path'].lower() not in folded, 'Duplicate or colliding delivery path')
        need(entry['path'].split('/')[-1] != FINAL_NAME, 'Final materials must stay outside the signed payload and delivery set')
        folded.add(entry['path'].lower())
        entries[entry['path']] = {'bytes': entry['bytes'], 'sha256': entry['sha256']}
    return review, entries, {'bytes': len(raw), 'sha256': sha(raw)}


def prove_source_extractor(producer_path, prepared_path, version, target, mode, team, inputs, report_sha256, evidence_sha256, prepared_sha256, temp_root=None):
    """The controlled-source route proof for a digest-bound producer/prepared pair, from bytes.

    `inputs` are private files: the preparation `report`, the source `evidence` with the
    operator's reviewed `evidence_sha256`, the `kit` (resolved from its delivery path, with
    `kit_locator`) and the compiled `bootloader`. `report_sha256` and `evidence_sha256` are what
    the signing plan inspected; the operator's evidence digest must equal the plan's.

    macos_extractor.check_report binds the report to these exact producer and prepared bytes,
    mode and Team, then repeats the whole source route from the bytes: evidence, kit (recipient
    verifier), pinned profile, kit plan and receipt, the receipt's description of every producer
    member and native and of the outer onefile policy, the compiled bootloader structure, the
    replayed PyInstaller sources, and the signature-only transformation. Every packed member and
    the outer prepared file are then verified with codesign (Developer ID: the Team
    requirement). Report statements are never used in place of these checks.
    Returns the proof, the codesign results, and digest-only report/source records."""
    import macos_extractor
    import macos_extractor_source
    signing = _signing()
    need(macos_extractor_source.EVIDENCE_SCHEMA == SOURCE_EVIDENCE_SCHEMA and macos_extractor_source.PROFILE_FILE == SOURCE_PROFILE_FILE
         and macos_extractor.STOCK_BOOTLOADER['sha256'] == STOCK_BOOTLOADER_SHA256, 'Controlled-source route constants changed; update the final materials contract')
    need(isinstance(inputs, dict) and set(inputs) == {'report', 'evidence', 'evidence_sha256', 'kit', 'kit_locator', 'bootloader'},
         'Controlled-source inputs need report, evidence, evidence_sha256, kit, kit_locator and bootloader')
    need(isinstance(inputs['evidence_sha256'], str) and HEX.fullmatch(inputs['evidence_sha256']) is not None, 'Source evidence digest must be 64 lowercase hex characters')
    need(inputs['evidence_sha256'] == evidence_sha256, 'The source evidence differs from the evidence the signing plan inspected')
    need(isinstance(report_sha256, str) and HEX.fullmatch(report_sha256) is not None, 'The signing plan does not bind a preparation report digest')
    producer = signing.regular_input(str(producer_path), 'Producer extractor').read_bytes()
    prepared = signing.regular_input(str(prepared_path), 'Prepared extractor').read_bytes()
    need(sha(producer) != sha(prepared), 'The prepared extractor is the producer itself')
    need(isinstance(prepared_sha256, str) and HEX.fullmatch(prepared_sha256) is not None and sha(prepared) == prepared_sha256,
         'Prepared extractor changed before the source proof')
    source = {'evidence': {'path': str(inputs['evidence']), 'sha256': inputs['evidence_sha256']}, 'kit': str(inputs['kit']), 'bootloader': str(inputs['bootloader'])}
    proof = macos_extractor.check_report({'path': str(inputs['report']), 'sha256': report_sha256},
                                         {'path': str(prepared_path), 'sha256': sha(prepared), 'version': version, 'arch': target},
                                         Path(producer_path), sha(producer), mode, team, temp_root, source=source)
    need(proof['method'] == SOURCE_EXTRACTOR_METHOD and proof['target_arch'] == 'arm64' and isinstance(proof.get('source'), dict),
         'The preparation proof is not a controlled-source arm64 proof')
    natives, others = proof['signature_only_natives'], proof['identical_non_natives']
    with tempfile.TemporaryDirectory(prefix='omd-final-extractor-', dir=temp_root) as folder:
        private = Path(folder) / 'prepared-extractor'
        signing.write_private(private, prepared)
        checks = macos_extractor.cryptographic(private, mode, team, folder)
    member_checks = checks['members']
    need(member_checks['failed'] == 0 and member_checks['native_members'] == natives == member_checks['verified'] and checks['outer']['exit'] == 0,
         'prepared extractor members failed cryptographic verification')
    found = proof['source']
    binding = found['producer_binding']
    need(binding['natives'] == natives and binding['members'] == natives + others, 'The evidence receipt and the transformation proof disagree on the packed members')
    identities = {}
    for key, what, expected in (('evidence', 'Source evidence', found['evidence_sha256']), ('kit', 'Source kit', found['kit_sha256']),
                                ('bootloader', 'Compiled bootloader', found['bootloader_sha256'])):
        identities[key] = signing.file_identity(signing.regular_input(str(inputs[key]), what))
        need(identities[key]['sha256'] == expected, f'{what} changed during the binding')
    profile = {k: found['profile'][k] for k in ('file', 'id', 'sha256')}
    need(profile['file'] == SOURCE_PROFILE_FILE and identities['bootloader']['sha256'] != STOCK_BOOTLOADER_SHA256, 'The source proof names an unexpected profile or bootloader')
    record = {'evidence': {'schema': SOURCE_EVIDENCE_SCHEMA, **identities['evidence']}, 'kit': {'locator': inputs['kit_locator'], **identities['kit']},
              'bootloader': identities['bootloader'], 'profile': profile, 'plan_sha256': found['plan_sha256'], 'receipt_sha256': found['receipt_sha256'],
              'members': binding['members'], 'natives': binding['natives']}
    return {'proof': proof, 'prepared_sha256': sha(prepared), 'cryptographic': checks, 'report': {k: proof['report'][k] for k in ('bytes', 'sha256')},
            'source': record, 'kit': identities['kit']}


class Derivation:
    """Every relation and receipt summary recomputed from actual bytes."""

    def __init__(self, spec):
        self.spec = spec
        self.contract = spec.get('contract', FINAL_SCHEMA)
        need(self.contract in CONTRACT_TOP, f'Unknown final materials contract {self.contract!r}')
        self.gaps = []
        self.facts = {}
        # Delivery files bound by the derivation itself (the controlled-source kit), and the
        # typed v2 extractor route.
        self.bound_delivery = {}
        self.extractor_section = None

    def gap(self, category, message):
        self.gaps.append((category, message))

    def run(self):
        signing = _signing()
        spec = self.spec
        policy, policy_identity = signing.load_policy()
        res = self.res = policy['resources']
        apps = {}
        for name in ('input', 'final'):
            app = signing.no_link_ancestors(spec[name + '_app'])
            need(app.suffix == '.app' and app.is_dir(), f'{name} must be an existing .app directory')
            files, _ = signing.walk_bundle(app)
            identities, heads = signing.read_identities(files)
            apps[name] = (app, files, identities, heads)
        need(not signing.within(apps['input'][0], apps['final'][0]) and not signing.within(apps['final'][0], apps['input'][0]), 'Input and final apps overlap')
        _, in_files, before, in_heads = apps['input']
        final_app, fin_files, after, fin_heads = apps['final']
        self.final_app, self.before, self.after = final_app, before, after
        info = signing.strict_plist(fin_files.get(INFO))
        exe, bundle_id, version = info['CFBundleExecutable'], info['CFBundleIdentifier'], info.get('CFBundleShortVersionString')
        need(isinstance(version, str) and version, 'Final Info.plist lacks a version')
        shell = 'Contents/MacOS/' + exe
        roles = signing.role_paths(policy, res, exe)
        self.engine_paths = engine_binaries(roles, res)
        self.seals = {signing.bundle_root(r, p) + NESTED_SEAL: (p, r) for p, r in roles.items() if r['filetype'] == 'app-bundle'}
        for label, heads in (('input', in_heads), ('final', fin_heads)):
            for path, head in heads.items():
                need(not signing.is_macho(head) or path in roles, f'Unrecognized code in the {label} payload: {path}')
                need(not head.startswith(b'OMDP2\0'), f'Plugin package in the {label} payload: {path}')
        need(set(roles) <= set(before) and set(roles) <= set(after), 'Reviewed code objects are missing')
        # Signing evidence: identities and purpose only, cross-checked against sealed bytes.
        plan_bytes = signing.regular_input(str(spec['plan']), 'Signing plan').read_bytes()
        report_bytes = signing.regular_input(str(spec['report']), 'Signing report').read_bytes()
        plan, report = strict(plan_bytes, 'Signing plan'), strict(report_bytes, 'Signing report')
        need(isinstance(plan, dict) and plan.get('schema') == signing.PLAN_SCHEMA, 'Not a signing plan')
        need(isinstance(report, dict) and report.get('schema') == signing.REPORT_SCHEMA, 'Not a signing report')
        need(report.get('plan', {}).get('sha256') == sha(plan_bytes), 'The signing report was not produced from this plan')
        need(plan['input']['inventory_sha256'] == canonical_inventory(before), 'The signing plan did not inspect this input app')
        need(plan['policy'] == policy_identity, 'The signing policy changed since the plan')
        need({o['path']: o['role'] for o in plan['code_objects']} == {p: r['id'] for p, r in roles.items()}, 'The signing plan code objects differ from the reviewed policy')
        rows = {row['path']: row for row in report.get('objects', [])}
        for path in roles:
            need(rows.get(path, {}).get('payload', {}).get('sha256') == after[path]['sha256'], 'The signing report does not bind this final payload: ' + path)
        need(report.get('status') not in ('running', 'failed', 'blocked'), f"The signing run did not complete: {report.get('status')}")
        mode, team, purpose = plan['mode'], plan['team_id'], plan['purpose']
        binding = plan.get('materials_binding', 'single-phase')
        need(report.get('purpose') == purpose and report.get('mode') == mode and report.get('materials_binding', 'single-phase') == binding,
             'Signing report and plan disagree on purpose, mode or materials binding')
        self.plan, self.report_status = plan, report['status']
        # Relations, file by file.
        relations, comparisons = {}, {}
        need(set(before) <= set(after), 'Unexpected removal of input files: ' + ', '.join(sorted(set(before) - set(after))[:5]))
        need(set(after) - set(before) <= {SEAL} | set(self.seals), 'Unexpected new payload files: ' + ', '.join(sorted(set(after) - set(before) - {SEAL} - set(self.seals))[:5]))
        need(all(p in after and p not in before for p in self.seals), 'A nested bundle is not freshly sealed: ' + ', '.join(sorted(self.seals)))
        transforms = {res + '/tools/tools-v2.json': self.manifest, res + '/browser/browser-tools-v2.json': self.manifest,
                      res + '/build-inventory.json': self.inventory, res + '/third-party/native-receipt.json': self.receipt}
        self.record = None
        for path in sorted(after):
            b, a = before.get(path), after[path]
            if path == SEAL:
                relations[path] = self.seal(fin_files, b, a, exe)
            elif path in self.seals:
                relations[path] = self.nested_seal(path, a)
            elif path in roles:
                relations[path], comparisons[path] = self.code(path, roles[path], in_files[path], fin_files[path], bundle_id, mode, team)
            elif path in transforms:
                relations[path] = transforms[path](path, in_files[path].read_bytes(), fin_files[path].read_bytes())
            else:
                need(b == a, 'Unexpected payload change: ' + path)
                relations[path] = {'kind': 'identical', 'before': b['sha256'], 'after': a['sha256']}
        record = self.record
        need(record is not None, 'Final build inventory lacks its signing record')
        need(self.contract != FINAL_SCHEMA_V2 or self.extractor_section is not None, 'No extractor route was derived')
        need(record['mode'] == mode and record['purpose'] == purpose and record.get('materials_binding', 'single-phase') == binding,
             'The sealed signing record disagrees with the signing plan')
        crypto = None
        if spec.get('cryptographic', True):
            crypto = cryptographic(final_app, sorted(roles) + sorted(p[:-len(NESTED_SEAL)] for p in self.seals), mode, team, spec.get('temp_root'))
        else:
            self.gap('signature-binding', 'cryptographic codesign verification was not requested; only static signature checks ran')
        self.facts.update(relation_counts={k: sum(r['kind'] == k for r in relations.values()) for k in sorted({r['kind'] for r in relations.values()})},
                          cryptographic=crypto, comparisons=comparisons)
        # Expectations derived from the pre-signature input, as the stager derives them.
        tools_in = strict(in_files[res + '/tools/tools-v2.json'].read_bytes(), 'tools-v2.json')
        browser_in = strict(in_files[res + '/browser/browser-tools-v2.json'].read_bytes(), 'browser-tools-v2.json')
        inventory_in = strict(in_files[res + '/build-inventory.json'].read_bytes(), 'build-inventory.json')
        arch = {'arm64': 'arm64', 'x86_64': 'x64'}.get(inventory_in.get('arch'))
        need(arch is not None and inventory_in.get('platform') == 'darwin', 'Unsupported final payload platform')
        target = 'darwin-' + arch
        engine = sorted(self.engine_paths)
        required = {n: {'version': version, 'prefix': p[len(res) + 1:]} for n, p in self.engine_paths.items()}
        for name in ('yt_dlp', 'ffmpeg', 'ffprobe', 'node'):
            required[name] = {'version': tools_in[name]['version'], 'prefix': 'tools/' + name + '/'}
        required['browser'] = {'version': browser_in['version'], 'prefix': 'browser/content/'}
        self.expect = {'target': target, 'version': version, 'locks': {}, 'required': required,
                       'final_components': {name: {'version': version, 'artifact': shell} for name in signing.TWO_PHASE_DEFERRED}}
        locks = self.locks(spec.get('locks'), after)
        self.expect['locks'] = locks
        engine_receipt = self.engine_receipt(fin_files, engine, locks, target, version)
        desktop_receipt = self.desktop_receipt(spec, exe, after[shell]['sha256'], locks, target, version, final_app / res)
        initial_review, initial_bytes = self.initial(in_files, inventory_in, before, required, target, version, locks)
        if purpose != 'distribution-candidate':
            self.gap('signing-run', f'{purpose} output is never a distribution candidate; sign a fresh two-phase release-staged input with --purpose distribution-candidate')
        elif mode != 'developer-id' or binding != BINDING or report['status'] != SIGNED_STATUS:
            self.gap('signing-run', f'the signing run is {mode}/{binding}/{report["status"]}, not a two-phase Developer ID distribution-candidate run')
        self.initial_bytes = initial_bytes
        sections = {'extractor': self.extractor_section} if self.contract == FINAL_SCHEMA_V2 else {}
        return {
            **sections,
            'schema': self.contract, 'purpose': purpose, 'target': target, 'version': version, 'locks': locks,
            'layout': {'resources': res, 'executable': exe, 'bundle_id': bundle_id, 'code': {p: r['id'] for p, r in sorted(roles.items())}},
            'signing': {'mode': mode, 'team_id': team, 'purpose': purpose, 'materials_binding': binding, 'status': report['status'],
                        'plan_sha256': sha(plan_bytes), 'report_sha256': sha(report_bytes), 'bundle_id': bundle_id},
            'initial_review': initial_review,
            'input': {'inventory_sha256': canonical_inventory(before), 'files': before},
            'payload': {'inventory_sha256': canonical_inventory(after), 'files': after},
            'relations': dict(sorted(relations.items())),
            'receipts': {'engine': engine_receipt, 'desktop': desktop_receipt},
        }

    # ------------------------------------------------------------ relations

    def code(self, path, role, before_path, after_path, bundle_id, mode, team):
        signing = _signing()
        before_bytes, after_bytes = before_path.read_bytes(), after_path.read_bytes()
        b, a = sha(before_bytes), sha(after_bytes)
        need(b != a, 'Code object was not re-signed: ' + path)
        identifier = expected_identifier(role, path, bundle_id)
        if role['sign'] == 'prepared-extractor':
            return self.extractor(path, before_path, before_bytes, after_bytes, mode, team, identifier, role)
        try:
            layout, independent = signing.macho_layout(before_bytes)
        except ValueError as error:
            raise ValueError(f'{path}: unsupported code structure: {error}') from error
        try:
            comparison = signing.signature_change(independent, layout, after_bytes)
        except ValueError as error:
            raise ValueError(f'{path}: not a signature-only change: {error}') from error
        check_signature(path, role, after_bytes, mode, team, identifier)
        return ({'kind': 'signature-only', 'before': b, 'after': a, 'method': METHODS['signature-only'], 'layout': LAYOUT_VERSION,
                 'signature_independent_sha256': independent}, comparison)

    def extractor(self, path, producer_path, producer, after_bytes, mode, team, identifier, role):
        """Producer -> prepared: the full pinned PyInstaller proof of the plan's route (every
        native signature-only, every other member identical, bootloader identical outside
        PKG-derived fields, every member verified). Prepared -> final: paired signature-only
        check of the outer file. v1 knows only the stock route; v2 also proves the
        controlled-source route from its digest-bound inputs."""
        import macos_extractor
        signing = _signing()
        need(macos_extractor.METHOD == EXTRACTOR_METHOD and macos_extractor.SOURCE_METHOD == SOURCE_EXTRACTOR_METHOD,
             'Extractor method changed; update the final materials contract')
        spec = self.spec.get('prepared_extractor')
        need(spec is not None, f'{path}: the prepared extractor is required to prove the yt-dlp transformation')
        prepared_path = signing.regular_input(str(spec), 'Prepared extractor')
        prepared = prepared_path.read_bytes()
        planned = next(o for o in self.plan['code_objects'] if o['path'] == path)
        need(planned.get('action') == 'replace-and-sign' and planned['replacement']['sha256'] == sha(prepared),
             'The prepared extractor differs from the one bound by the signing plan')
        requested = (self.plan.get('request') or {}).get('prepared_extractor') or {}
        transformation = planned['replacement'].get('transformation') or {}
        given = self.spec.get('extractor_source')
        if self.contract == FINAL_SCHEMA:
            # v1 pins the stock method in its relation and in the shared desktop contract. Refuse the
            # controlled-source route outright instead of proving it with the stock route (which
            # would also fail) or relabelling it.
            need('source' not in requested and transformation.get('method', EXTRACTOR_METHOD) == EXTRACTOR_METHOD,
                 f'{path}: the controlled-source extractor route is not supported by {FINAL_SCHEMA}; its prepared-extractor relation and the shared '
                 f'desktop contract pin {EXTRACTOR_METHOD}. Bind it with --contract {FINAL_SCHEMA_V2} and its source inputs; nothing was bound')
            need(given is None, f'{FINAL_SCHEMA} has no controlled-source extractor route; its source inputs need --contract {FINAL_SCHEMA_V2}')
        # The route comes from what the signing plan inspected, and its method must agree. The
        # proof below is re-derived from bytes; neither label is trusted for it.
        route = 'controlled-source' if 'source' in requested else 'upstream-stock'
        method = transformation.get('method', EXTRACTOR_METHOD)
        need(isinstance(method, str) and EXTRACTOR_ROUTES.get(method) == route,
             f'{path}: the signing plan extractor route ({route}) and its transformation method ({method!r}) disagree')
        layout = signing.macho_layout(producer)[0]
        target = 'universal2' if layout['container']['format'] != 'thin' else signing.payload_arch(layout['slices'][0]['cpu'])
        tools = strict(Path(producer_path).parent.parent.joinpath('tools-v2.json').read_bytes(), 'tools-v2.json')
        version = tools['yt_dlp']['version']
        report, source = None, None
        if route == 'upstream-stock':
            need(given is None, f'{path}: the signing plan uses the stock extractor route; controlled-source inputs cannot relabel it')
            proof = macos_extractor.verify_pair({'path': str(producer_path), 'sha256': sha(producer)}, {'path': str(prepared_path), 'sha256': sha(prepared)},
                                                version, target, mode, team, self.spec.get('temp_root'), crypto=True)
            need(proof['pass'], f"{path}: prepared extractor members failed cryptographic verification")
            rows, members = proof['structural_equivalence'], proof['cryptographic']['members']
        else:
            need(given is not None, f'{path}: the signing plan uses the controlled-source extractor route; supply its preparation report, the source evidence '
                                    'with its reviewed digest, the kit (as a delivery path) and the compiled bootloader')
            need(isinstance(requested.get('report'), dict) and isinstance(requested['source'], dict) and isinstance(requested['source'].get('evidence'), dict),
                 f'{path}: the signing plan has a malformed controlled-source request')
            kit_file = resolve_delivery(given['kit'], self.spec.get('delivery_roots', {}))
            result = prove_source_extractor(producer_path, prepared_path, version, target, mode, team,
                                            {**given, 'kit': kit_file, 'kit_locator': 'delivery:' + given['kit']},
                                            requested['report'].get('sha256'), requested['source']['evidence'].get('sha256'), sha(prepared), self.spec.get('temp_root'))
            need(result['proof']['producer_sha256'] == sha(producer), f'{path}: the source proof covers different producer bytes')
            need(result['prepared_sha256'] == sha(prepared), f'{path}: the source proof covers different prepared bytes')
            rows, members, report, source = result['proof'], result['cryptographic']['members'], result['report'], result['source']
            self.bound_delivery[given['kit']] = result['kit']
        playout, pindependent = signing.macho_layout(prepared)
        try:
            comparison = signing.signature_change(pindependent, playout, after_bytes)
        except ValueError as error:
            raise ValueError(f'{path}: not a signature-only change of the prepared extractor: {error}') from error
        check_signature(path, role, after_bytes, mode, team, identifier)
        self.facts['extractor'] = {'method': method, 'target_arch': target, 'producer_sha256': sha(producer), 'prepared_sha256': sha(prepared),
                                   'signature_only_natives': rows['signature_only_natives'], 'identical_non_natives': rows['identical_non_natives'],
                                   'members_verified': members['verified'], 'requirement': members['requirement']}
        relation = {'kind': 'prepared-extractor', 'before': sha(producer), 'after': sha(after_bytes), 'method': method, 'prepared': sha(prepared),
                    'signature_only_natives': rows['signature_only_natives'], 'identical_non_natives': rows['identical_non_natives'],
                    'signature_independent_sha256': pindependent}
        if self.contract == FINAL_SCHEMA_V2:
            relation['route'] = route
            self.facts['extractor'].update(route=route, source=source)
            self.extractor_section = {'path': path, 'component': EXTRACTOR_COMPONENT, 'route': route, 'method': method, 'version': version, 'target_arch': target,
                                      'producer': {'bytes': len(producer), 'sha256': sha(producer)}, 'prepared': {'bytes': len(prepared), 'sha256': sha(prepared)},
                                      'members_verified': members['verified'], 'report': report, 'source': source}
        return relation, comparison

    def manifest(self, path, before_bytes, after_bytes):
        res, after = self.res, self.after
        old, new = strict(before_bytes, path), strict(after_bytes, path)
        need(after_bytes == serialize(new), f'{path}: not in the signer serialization')
        expected = copy.deepcopy(old)
        try:
            if path.endswith('/tools/tools-v2.json'):
                for row in expected.values():
                    row['sha256'] = after[res + '/tools/' + row['path']]['sha256']
            else:
                node = posixpath.normpath(posixpath.join(res + '/browser', expected['node']['path']))
                expected['node']['sha256'] = after[node]['sha256']
                for rel in expected['files']:
                    expected['files'][rel] = dict(after[res + '/browser/content/' + rel])
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError(f'{path}: references a file outside the final payload: {error}') from error
        need(new == expected, f'{path}: changed beyond its digest fields')
        return {'kind': 'managed-manifest', 'before': sha(before_bytes), 'after': sha(after_bytes), 'method': METHODS['managed-manifest']}

    def inventory(self, path, before_bytes, after_bytes):
        signing, res, after = _signing(), self.res, self.after
        old, new = strict(before_bytes, path), strict(after_bytes, path)
        need(after_bytes == serialize(new), f'{path}: not in the signer serialization')
        need(isinstance(old, dict) and 'signing' not in old and isinstance(new, dict) and isinstance(new.get('signing'), dict), f'{path}: invalid signing record')
        record = dict(new['signing'])
        body = {k: v for k, v in new.items() if k != 'signing'}
        expected = copy.deepcopy(old)
        try:
            # The signer appends each new nested bundle seal, in sorted order, after the staged rows.
            expected['files'] = [{'path': row['path'], 'sha256': after[res + '/' + row['path']]['sha256'], 'size': after[res + '/' + row['path']]['bytes']}
                                 for row in [*old['files'], *({'path': p[len(res) + 1:]} for p in sorted(self.seals))]]
        except (KeyError, TypeError) as error:
            raise ValueError(f'{path}: lists a file outside the final payload: {error}') from error
        need(body == expected, f'{path}: changed beyond its digests and signing record')
        need({row['path'] for row in old['files']} | {p[len(res) + 1:] for p in self.seals} == {p[len(res) + 1:] for p in after if p.startswith(res + '/')} - {'build-inventory.json'},
             f'{path}: does not inventory exactly the final resources')
        need(set(record) - {'materials_binding'} == {'schema', 'mode', 'purpose', 'payload_digests', 'source_build_inventory_sha256', 'engine_receipt', 'release_accepted'}
             and record['schema'] == signing.INVENTORY_SIGNING_SCHEMA and record['payload_digests'] == 'post-signature'
             and record['source_build_inventory_sha256'] == sha(before_bytes) and record['release_accepted'] is False
             and record['engine_receipt'] == 'fresh-post-signature' and record['purpose'] in PURPOSES
             and record.get('materials_binding', 'single-phase') in signing.BINDINGS, f'{path}: invalid signing record')
        self.record = record
        return {'kind': 'build-inventory', 'before': sha(before_bytes), 'after': sha(after_bytes), 'method': METHODS['build-inventory']}

    def receipt(self, path, before_bytes, after_bytes):
        res, before, after = self.res, self.before, self.after
        old, new = strict(before_bytes, path), strict(after_bytes, path)

        def strip(r):
            need(isinstance(r, dict) and isinstance(r.get('review'), dict) and isinstance(r.get('artifacts'), list), f'{path}: invalid native receipt')
            return {**{k: v for k, v in r.items() if k != 'artifacts'}, 'review': {k: v for k, v in r['review'].items() if k != 'input_sha256'}}
        need(strip(old) == strip(new), f'{path}: changed beyond its artifact-only rebinding')
        old_bound = {x.get('name'): x.get('sha256') for x in old['artifacts']}
        need(old_bound == {n: before.get(self.engine_paths.get(n, ''), {}).get('sha256') for n in old_bound}, f'{path}: the input receipt did not bind the pre-signature engine binaries')
        need({x.get('name'): {'bytes': x.get('bytes'), 'sha256': x.get('sha256')} for x in new['artifacts']}
             == {n: after.get(self.engine_paths.get(n, '')) for n in old_bound}, f'{path}: the final receipt does not bind the signed engine binaries')
        return {'kind': 'engine-receipt', 'before': sha(before_bytes), 'after': sha(after_bytes), 'method': METHODS['engine-receipt']}

    def nested_seal(self, path, after):
        """A nested bundle's new seal: it covers exactly the bundle resources and the main
        executable's code directory binds it and the nested Info.plist (re-derived from bytes)."""
        executable, role = self.seals[path]
        root = self.final_app / path[:-len(NESTED_SEAL)]
        proof = _signing().nested_seal(root, role['bundle'])
        need(proof['sha256'] == after['sha256'], f'{path}: the nested seal changed during the binding')
        return {'kind': 'nested-seal', 'before': None, 'after': after['sha256'], 'method': METHODS['nested-seal'], 'sealed_files': proof['sealed_files']}

    def seal(self, files, before, after, exe):
        data = files[SEAL].read_bytes()
        try:
            seal = plistlib.loads(data)
        except Exception as error:  # plistlib raises several types for malformed input
            raise ValueError(f'Invalid CodeResources seal: {error}') from error
        need(isinstance(seal, dict) and isinstance(seal.get('files2'), dict), 'Invalid CodeResources seal')
        expected = {p[len('Contents/'):]: row['sha256'] for p, row in self.after.items() if p not in (INFO, 'Contents/MacOS/' + exe, SEAL)}
        need(all(p.startswith('Contents/') for p in self.after), 'Payload outside Contents/')
        need(set(seal['files2']) == set(expected), 'The CodeResources seal does not cover exactly the final payload')
        for rel, row in seal['files2'].items():
            need(isinstance(row, dict) and set(row) == {'hash2'} and isinstance(row['hash2'], bytes) and row['hash2'].hex() == expected[rel],
                 'CodeResources seal entry differs from the final payload: ' + rel)
        shell = files['Contents/MacOS/' + exe].read_bytes()
        for slots in code_directories(shell):
            need(slots.get(1) == self.after[INFO]['sha256'] and slots.get(3) == after['sha256'], 'The outer code signature does not bind Info.plist and the seal')
        return {'kind': 'outer-seal', 'before': before['sha256'] if before else None, 'after': after['sha256'], 'method': METHODS['outer-seal'], 'sealed_files': len(expected)}

    # ------------------------------------------------------------ receipts and initial review

    def locks(self, folder, after):
        signing = _signing()
        if folder is None:
            self.gap('locks', 'no --materials-locks directory: lock digests are unbound and the initial review cannot be validated')
            return {}
        locks = {}
        for name in ('Cargo.lock', 'browser-package-lock.json', 'desktop-Cargo.lock', 'desktop-package-lock.json'):
            locks[name] = signing.file_identity(signing.regular_input(str(Path(folder) / name), f'Lock {name}'))['sha256']
        need(locks['browser-package-lock.json'] == after.get(self.res + '/browser/content/adapter/package-lock.json', {}).get('sha256'), 'Stale browser lock')
        return locks

    def engine_receipt(self, files, engine, locks, target, version):
        signing = _signing()
        res = self.res
        receipt = strict(files[res + '/third-party/native-receipt.json'].read_bytes(), 'native-receipt.json')
        notices = files[res + '/third-party/native-NOTICES.txt'].read_bytes()
        lock = locks.get('Cargo.lock', receipt.get('lock_sha256'))
        resources = {p[len(res) + 1:]: row['sha256'] for p, row in self.after.items() if p.startswith(res + '/')}
        materials_contract.validate_native_receipt(receipt, resources, engine, lock, TRIPLES[target], notices, version)
        spans = sum(len(p['texts']) for p in receipt['packages']) + len(receipt['runtime_materials'])
        return {'receipt': {'path': res + '/third-party/native-receipt.json', 'sha256': self.after[res + '/third-party/native-receipt.json']['sha256']},
                'notices': {'path': res + '/third-party/native-NOTICES.txt', 'sha256': sha(notices)}, 'binaries': engine,
                'artifacts': {n: self.after[self.engine_paths[n]]['sha256'] for n in engine}, 'lock_sha256': lock, 'target': TRIPLES[target],
                'version': version, 'findings': len(receipt['review']['findings']), 'spans': spans, 'spans_in_payload': spans, 'pending': [], 'release_accepted': False}

    def desktop_receipt(self, spec, exe, executable, locks, target, version, resources):
        signing = _signing()
        paths = spec.get('desktop_receipt')
        if not paths:
            self.gap('receipts', 'no detached desktop receipt: the final desktop executable is not bound to native notices')
            self.desktop_files = {}
            return None
        roots = spec.get('delivery_roots', {})
        files = {key: resolve_delivery(paths[key], roots) for key in ('receipt', 'notices')}
        receipt = strict(files['receipt'].read_bytes(), 'Desktop receipt')
        notices = files['notices'].read_bytes()
        lock = locks.get('desktop-Cargo.lock', receipt.get('lock_sha256'))
        materials_contract.validate_native_receipt(receipt, {'bin/' + exe: executable, 'third-party/native-NOTICES.txt': sha(notices)},
                                                   [exe], lock, TRIPLES[target], notices, version)
        spans, missing = signing.text_span_coverage(receipt, notices, resources)
        need(not missing, f'{len(missing)} desktop receipt text spans are absent from the final payload resources')
        self.desktop_files = {paths[k]: signing.file_identity(files[k]) for k in ('receipt', 'notices')}
        return {'receipt': {'path': paths['receipt'], 'sha256': self.desktop_files[paths['receipt']]['sha256']},
                'notices': {'path': paths['notices'], 'sha256': sha(notices)}, 'binaries': [exe], 'artifacts': {exe: executable},
                'lock_sha256': lock, 'target': TRIPLES[target], 'version': version, 'findings': len(receipt['review']['findings']),
                'spans': spans, 'spans_in_payload': spans, 'pending': [], 'release_accepted': False}

    def initial(self, files, inventory, before, required, target, version, locks):
        res = self.res
        path = res + '/' + V1_NAME
        if path not in files:
            self.gap('initial-review', f"no in-app omd-materials-v1 initial review (input staging mode: {inventory.get('staging_mode')}); stage with --staging-mode release --materials-binding two-phase")
            return None, None
        data = files[path].read_bytes()
        record = {'schema': V1_SCHEMA, 'path': path, 'sha256': sha(data), 'bytes': len(data)}
        materials = inventory.get('materials') if isinstance(inventory.get('materials'), dict) else {}
        if inventory.get('staging_mode') != 'release' or materials.get('binding') != BINDING or materials.get('deferred') != _signing().TWO_PHASE_DEFERRED:
            self.gap('initial-review', 'the input build inventory does not record two-phase release staging')
        if locks:
            staged = {p[len(res) + 1:]: row['sha256'] for p, row in before.items() if p.startswith(res + '/') and p not in (res + '/build-inventory.json', path)}
            try:
                materials_contract.validate(strict(data, 'materials-v1.json'), staged, required, target, version, locks)
            except ValueError as error:
                self.gap('initial-review', f'the initial review does not validate against the pre-signature input: {error}')
        return record, data


def build_components(derived, review, gaps, payload, delivery, res):
    """Final components from an explicit reviewed input. Nothing is marked reviewed
    unless that input says so and every carried fact and material verifies."""
    initial = derived['initial']
    by_v1 = {c['id']: c for c in initial['components']} if initial else {}
    relations, components = derived['relations'], []
    extractor = derived.get('extractor')
    covered, delivered = set(), set()
    addressed = set()

    def locator(value, cid):
        route, _, path = value.partition(':')
        need(route in ROUTES and bool(path), f'{cid}: unknown material route {value!r}')
        final_path(path)
        table = payload if route == 'payload' else delivery
        need(path in table, f'{cid}: {route} material is not in the bound {route} inventory: {path}')
        (covered if route == 'payload' else delivered).add(path)
        return value, table[path]['sha256']
    for c in (review or {}).get('components', []):
        cid, pending = c['id'], list(c['pending'])
        materials = {k: {} for k in KINDS}
        if c['basis'] == 'initial-review':
            source = by_v1.get(cid)
            need(source is not None and source['version'] == c['version'], f'{cid}: not a component of the initial review at this version')
            artifacts = {}
            for p, h in source['artifacts'].items():
                need(relations.get(res + '/' + p, {}).get('before') == h, f'{cid}: initial artifact {p} is not the reviewed input')
                artifacts[res + '/' + p] = {'initial': h, 'final': payload[res + '/' + p]['sha256']}
            for kind in KINDS:
                for p, h in source['materials'][kind].items():
                    need(relations.get(res + '/' + p, {}).get('before') == h, f'{cid}: initial material {p} is not the reviewed input')
                    materials[kind].update([locator('payload:' + res + '/' + p, cid)])
        else:
            need(cid not in by_v1, f'{cid}: the final review cannot replace initial review facts')
            artifacts = {}
            for entry in c['artifacts']:
                if entry.startswith('prefix:'):
                    prefix = entry[len('prefix:'):]
                    need(prefix.endswith('/') and bool(prefix.strip('/')), f'{cid}: invalid artifact prefix {entry!r}')
                    matched = [p for p in payload if p.startswith(prefix)]
                    need(bool(matched), f'{cid}: artifact prefix matches no final payload file: {prefix}')
                else:
                    final_path(entry)
                    need(entry in payload, f'{cid}: artifact is not in the final payload: {entry}')
                    matched = [entry]
                for p in matched:
                    artifacts[p] = {'initial': relations[p]['before'], 'final': payload[p]['sha256']}
            need(bool(artifacts), f'{cid}: final-review components need artifacts')
        for kind, values in c['materials'].items():
            for value in values:
                materials[kind].update([locator(value, cid)])
        covered.update(artifacts)
        empty = [k for k in KINDS if not materials[k]]
        if empty:
            pending.append('no ' + ', '.join(empty) + ' material bound')
        if extractor is not None and cid == extractor['component']:
            # v2: the route must explain this reviewed initial component's artifact, and a
            # controlled-source kit must be its typed source material. Otherwise it stays pending.
            if c['basis'] != 'initial-review' or extractor['path'] not in artifacts:
                pending.append(f"the extractor {extractor['path']} is not an artifact of this initial-review component")
            kit = (extractor['source'] or {}).get('kit')
            if kit is not None and materials['source'].get(kit['locator']) != kit['sha256']:
                pending.append(f"the controlled-source kit {kit['locator']} is not bound as a source material")
        if c['status'] == 'pending' and not pending:
            pending.append('marked pending without a stated reason')
        status = 'reviewed' if c['status'] == 'reviewed' and not pending else 'pending'
        if c['status'] == 'reviewed' and pending:
            pending.insert(0, 'ambiguous review: marked reviewed with unresolved statements; kept pending')
        for statement in pending:
            gaps.append(('component-materials', f'{cid}: {statement}'))
        addressed.add(cid)
        components.append({'id': cid, 'version': c['version'], 'basis': c['basis'], 'initial_component': cid if c['basis'] == 'initial-review' else None,
                           'status': status, 'pending': pending, 'artifacts': dict(sorted(artifacts.items())),
                           'materials': {k: dict(sorted(materials[k].items())) for k in KINDS}})
    for cid in sorted(set(by_v1) - addressed):
        gaps.append(('component-materials', f'{cid}: initial-review component not carried by the final review input'))
    expect = derived['expect']
    for name in [*expect['required'], *expect['final_components']]:
        if name not in addressed:
            gaps.append(('component-materials', f'{name}: required component is absent from the final review input'))
    uncovered = sorted(set(payload) - covered)
    if uncovered:
        gaps.append(('coverage', f'{len(uncovered)} final payload files are not covered by any component: ' + ', '.join(uncovered[:6])))
    unreferenced = sorted(set(delivery) - delivered - set(derived['bound_files']))
    need(not unreferenced, 'Delivery entries not referenced by any component: ' + ', '.join(unreferenced[:6]))
    return components


def prepare(spec):
    """(status, doc or None, report). Nothing is written here; refusals raise."""
    derivation = Derivation(spec)
    sections = derivation.run()
    gaps = derivation.gaps
    contract = derivation.contract
    names = (FINAL_NAME, FINAL_NAME_V2) if contract == FINAL_SCHEMA_V2 else (FINAL_NAME,)
    payload = sections['payload']['files']
    review, entries, review_identity = (None, {}, None)
    if spec.get('review'):
        review, entries, review_identity = load_review(spec['review'])
        need(review['target'] == sections['target'] and review['version'] == sections['version'], 'The final review names a different target/version')
        need(review['input_inventory_sha256'] == sections['input']['inventory_sha256'], 'The final review is stale: it reviewed a different pre-signature input')
        need(review['initial_review_sha256'] == (sections['initial_review'] or {}).get('sha256'), 'The final review is stale: it reviewed a different initial review')
    else:
        gaps.append(('review-input', 'no omd-final-review-v1 input: no component status, route or delivery material is reviewed'))
    signing = _signing()
    roots = spec.get('delivery_roots', {})
    delivery = {}
    for path, want in entries.items():
        actual = signing.file_identity(resolve_delivery(path, roots))
        need(actual == want, f'Stale/changed delivery material: {path}')
        delivery[path] = actual
    bound = dict(derivation.desktop_files)
    for path, identity in derivation.bound_delivery.items():
        need(path not in bound, f'A delivery file cannot be bound twice: {path}')
        bound[path] = identity
    for path, identity in bound.items():
        need(path not in delivery or delivery[path] == identity, f'Stale/changed delivery material: {path}')
        delivery[path] = identity
    delivery = dict(sorted(delivery.items()))
    for path in delivery:
        need(path.split('/')[-1] not in names, 'Final materials must stay outside the signed payload and delivery set')
    initial = json.loads(derivation.initial_bytes) if derivation.initial_bytes else None
    derived = {'initial': initial, 'relations': sections['relations'], 'expect': derivation.expect, 'desktop_files': derivation.desktop_files,
               'bound_files': set(bound), 'extractor': sections.get('extractor')}
    components = build_components(derived, review, gaps, payload, delivery, derivation.res)
    pending = [f'{category}: {message}' for category, message in gaps]
    reviewed = review is not None and bool(components) and all(c['status'] == 'reviewed' for c in components)
    doc = {**sections, 'components': components, 'delivery': {'files': delivery}, 'pending': pending, 'reviewed': reviewed,
           'coverage_validated': not pending, 'distribution_candidate': not pending and sections['purpose'] == 'distribution-candidate',
           'release_accepted': False, 'limits': LIMITS_V2 if contract == FINAL_SCHEMA_V2 else LIMITS}
    doc = {k: doc[k] for k in CONTRACT_TOP[contract]}
    try:
        validate_final(doc, derivation.initial_bytes, payload, delivery, derivation.expect)
        validation = {'pass': True}
    except ValueError as error:
        validation = {'pass': False, 'error': str(error)}
    if doc['coverage_validated']:
        # Never emit a validated binding that the shared contract rejects.
        need(validation['pass'], f"Internal inconsistency: the shared contract rejects a complete binding: {validation.get('error')}")
    categories = {}
    for category, message in gaps:
        categories.setdefault(category, []).append(message)
    report = {'schema': REPORT_SCHEMAS[contract], 'status': 'final-materials-validated' if doc['coverage_validated'] else 'final-materials-incomplete',
              'purpose': doc['purpose'], 'signing_status': doc['signing']['status'], 'coverage_validated': doc['coverage_validated'],
              'distribution_candidate': doc['distribution_candidate'], 'reviewed': reviewed, 'release_accepted': False,
              'distribution_validation': validation, 'review_input': review_identity,
              'payload': {'files': len(payload), 'bytes': sum(r['bytes'] for r in payload.values()), 'inventory_sha256': doc['payload']['inventory_sha256']},
              'input': {'files': len(doc['input']['files']), 'inventory_sha256': doc['input']['inventory_sha256']},
              'relations': derivation.facts['relation_counts'], 'extractor': derivation.facts.get('extractor'),
              'cryptographic': derivation.facts['cryptographic'], 'signature_comparisons': derivation.facts['comparisons'], 'receipts': doc['receipts'],
              'components': {c['id']: {'status': c['status'], 'basis': c['basis'], 'artifacts': len(c['artifacts']),
                                       'materials': {k: len(c['materials'][k]) for k in KINDS}, 'pending': c['pending']} for c in components},
              'gaps': categories, 'open_gates': OPEN_GATES, 'limits': doc['limits']}
    if contract == FINAL_SCHEMA_V2:
        report['contract'] = contract
        report['extractor_route'] = doc['extractor']
    return report['status'], doc, report


def verify(spec, doc_bytes):
    """Re-derive a binding from actual bytes and require exact equality, then validate it.
    The document must be of the requested contract (default omd-final-materials-v1)."""
    contract = spec.get('contract', FINAL_SCHEMA)
    need(contract in CONTRACT_TOP, f'Unknown final materials contract {contract!r}')
    top = CONTRACT_TOP[contract]
    given = strict(doc_bytes, 'Final materials')
    need(isinstance(given, dict) and given.get('schema') == contract, f'The final binding is not an {contract} document')
    need(set(given) == set(top), 'Unknown/missing final materials fields')
    status, fresh, report = prepare(spec)
    differences = sorted(k for k in top if json.dumps(given.get(k), sort_keys=True) != json.dumps(fresh[k], sort_keys=True))
    need(not differences, 'The final binding differs from the binding re-derived from actual bytes: ' + ', '.join(differences))
    return {'schema': VERIFICATION_SCHEMAS[contract], 'final_sha256': sha(doc_bytes), 'rederived_equal': True, 'status': status,
            'distribution_validation': report['distribution_validation'], 'coverage_validated': fresh['coverage_validated'],
            'distribution_candidate': fresh['distribution_candidate'], 'gaps': report['gaps'], 'release_accepted': False}
