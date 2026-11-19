# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Inspect, then explicitly sign, a staged plugin-free OMD macOS application.

`inspect` is read-only and writes a new plan. `execute` re-derives that exact plan
and signs a new independent copy. The input app is never modified. Nothing here
notarizes, reads credentials or accepts a release (release_accepted stays false).
`--purpose private-validation` (Developer ID only, repeated at execute) signs a
never-distributable copy despite release-material gaps; it is never a candidate.
`--materials-binding two-phase` (Developer ID distribution-candidate only, repeated at
execute) signs two-phase release staging; the output awaits bind-final-materials.py.
"""
import argparse
import json
import platform
import struct
import sys
from pathlib import Path

import macos_signing as signing

# 0 only for a candidate. Private validation is never a candidate: 3 when every step
# passed, 2 (like an incomplete rehearsal) when a release gap remains in the output.
# A two-phase output is signed but not a candidate until its final materials binding.
EXIT = {'signed-development-candidate': 0, 'signed-developer-id-candidate': 0, 'incomplete-development': 2,
        'private-validation-incomplete': 2, 'private-validation-signed': 3, signing.TWO_PHASE_STATUS: 2}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    i = sub.add_parser('inspect', help='validate an app and write a new signing plan (read-only)')
    i.add_argument('--app', type=Path, required=True)
    i.add_argument('--mode', choices=signing.MODES, required=True)
    i.add_argument('--identity', required=True, help='"-" for development-adhoc; "Developer ID Application: NAME (TEAMID)" or a SHA-1 hash')
    i.add_argument('--team-id')
    i.add_argument('--purpose', choices=signing.PURPOSES, default='distribution-candidate',
                   help='private-validation (developer-id only) signs a never-distributable copy despite release-material gaps; it must be repeated at execute')
    i.add_argument('--materials-binding', choices=signing.BINDINGS, default='single-phase',
                   help='two-phase (developer-id distribution-candidate only) signs two-phase release staging for a later final materials binding; repeat at execute')
    i.add_argument('--arch', choices=sorted(signing.TRIPLES), default='arm64')
    i.add_argument('--plan', type=Path, required=True, help='new plan JSON path')
    i.add_argument('--expected-inventory', type=Path, help='exact {path: {bytes, sha256}} inventory of the whole app')
    i.add_argument('--receipts', type=Path, help='omd-macos-signing-receipts-v1 inputs for fresh native receipts')
    i.add_argument('--prepared-extractor', type=Path)
    i.add_argument('--prepared-extractor-sha256')
    i.add_argument('--prepared-extractor-version')
    i.add_argument('--prepared-extractor-arch', choices=sorted(signing.TRIPLES))
    i.add_argument('--prepared-extractor-report', type=Path, help='optional prepare-macos-extractor.py report; the transformation proof is repeated')
    i.add_argument('--prepared-extractor-report-sha256')
    i.add_argument('--prepared-extractor-source-evidence', type=Path,
                   help='controlled-source route (with the report and the three options below): operator-reviewed omd-macos-extractor-source-evidence-v1 JSON')
    i.add_argument('--prepared-extractor-source-evidence-sha256')
    i.add_argument('--prepared-extractor-source-kit', type=Path, help='the reviewed source kit named by the evidence')
    i.add_argument('--prepared-extractor-source-bootloader', type=Path, help='the compiled bootloader named by the evidence')
    e = sub.add_parser('execute', help='sign a new copy exactly as a reviewed plan describes')
    e.add_argument('--plan', type=Path, required=True)
    e.add_argument('--output', type=Path, required=True, help='new .app path')
    e.add_argument('--work', type=Path, required=True, help='new directory for the report, receipts and evidence')
    e.add_argument('--purpose', choices=signing.PURPOSES, default='distribution-candidate', help='must equal the purpose bound in the plan')
    e.add_argument('--materials-binding', choices=signing.BINDINGS, default='single-phase', help='must equal the materials binding bound in the plan')
    e.add_argument('--allow-incomplete-development', action='store_true',
                   help='development-adhoc only: emit a clearly incomplete rehearsal instead of stopping on release blockers')
    return p


def inspect(a):
    app = signing.absolute(a.app)
    plan_path = signing.new_file(a.plan, 'Plan')
    signing.need(not signing.within(plan_path, app), 'Plan cannot be written inside the input app')
    prepared = [a.prepared_extractor, a.prepared_extractor_sha256, a.prepared_extractor_version, a.prepared_extractor_arch]
    signing.need(all(x is None for x in prepared) or all(x is not None for x in prepared), 'A prepared extractor needs path, sha256, version and arch')
    request = {'app': str(app), 'mode': a.mode, 'identity': a.identity, 'team_id': a.team_id, 'arch': a.arch, 'purpose': a.purpose,
               'materials_binding': a.materials_binding,
               'prepared_extractor': None if a.prepared_extractor is None else {
                   'path': str(signing.absolute(a.prepared_extractor)), 'sha256': a.prepared_extractor_sha256,
                   'version': a.prepared_extractor_version, 'arch': a.prepared_extractor_arch},
               'receipts': str(signing.absolute(a.receipts)) if a.receipts else None,
               'expected_inventory': None}
    report = [a.prepared_extractor_report, a.prepared_extractor_report_sha256]
    signing.need(all(x is None for x in report) or (all(x is not None for x in report) and a.prepared_extractor is not None),
                 'A prepared extractor report needs its sha256 and a prepared extractor')
    if a.prepared_extractor_report is not None:
        request['prepared_extractor']['report'] = {'path': str(signing.absolute(a.prepared_extractor_report)), 'sha256': a.prepared_extractor_report_sha256}
    source = [a.prepared_extractor_source_evidence, a.prepared_extractor_source_evidence_sha256, a.prepared_extractor_source_kit, a.prepared_extractor_source_bootloader]
    signing.need(all(x is None for x in source) or (all(x is not None for x in source) and a.prepared_extractor_report is not None),
                 'The controlled-source route needs all four --prepared-extractor-source-* options and a prepared extractor report')
    if a.prepared_extractor_source_evidence is not None:
        request['prepared_extractor']['source'] = {
            'evidence': {'path': str(signing.absolute(a.prepared_extractor_source_evidence)), 'sha256': a.prepared_extractor_source_evidence_sha256},
            'kit': str(signing.absolute(a.prepared_extractor_source_kit)), 'bootloader': str(signing.absolute(a.prepared_extractor_source_bootloader))}
    if a.expected_inventory:
        path = signing.absolute(a.expected_inventory)
        request['expected_inventory'] = {'path': str(path), 'sha256': signing.file_identity(signing.regular_input(str(path), 'Expected inventory'))['sha256']}
    plan = signing.inspect(request)
    plan['created_at'] = signing.now()
    signing.write_new(plan_path, signing.json_bytes(plan))
    summary = {'plan': str(plan_path), 'purpose': plan['purpose'], 'materials_binding': plan['materials_binding'], 'ready_for_execution': plan['ready_for_execution'], 'complete_without_blockers': plan['complete_without_blockers'],
               'code_objects': len(plan['code_objects']), 'blockers': [f"{b['severity']}:{b['id']}" for b in plan['blockers']], 'release_accepted': False}
    print(json.dumps(summary, indent=2))
    return 0 if plan['complete_without_blockers'] else 2


def main(argv=None):
    a = parser().parse_args(argv)
    if platform.system() != 'Darwin':
        print('macOS signing preparation requires a macOS host', file=sys.stderr)
        return 1
    try:
        if a.command == 'inspect':
            return inspect(a)
        status, report = signing.execute(a.plan, a.output, a.work, a.allow_incomplete_development, purpose=a.purpose, materials_binding=a.materials_binding)
    except (ValueError, OSError, KeyError, struct.error) as error:
        print(json.dumps({'refused': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({'status': status, 'purpose': a.purpose, 'materials_binding': a.materials_binding, 'report': str(report), 'release_accepted': False}, indent=2))
    return EXIT.get(status, 1)


if __name__ == '__main__':
    raise SystemExit(main())
