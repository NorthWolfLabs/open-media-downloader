# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Inspect, then explicitly prepare, a PyInstaller 6.22.0 macOS onefile extractor whose
packed native members are re-signed with only their code signatures changed.

`inspect` is read-only and writes a new plan. `execute` re-derives that exact plan and
writes a new extractor plus a report; `verify` repeats the equivalence proof for an
existing producer/prepared pair. The producer is never modified. Nothing here
notarizes, reads credentials or accepts a release (release_accepted stays false).

The default route accepts only the stock universal2 bootloader. The four --source-*
options together select the separate controlled-source route: an operator-reviewed
omd-macos-extractor-source-evidence-v1 file (bound by its digest), the reviewed source
kit and the compiled bootloader it names. There is no fallback between routes.
"""
import argparse
import json
import platform
import struct
import sys
from pathlib import Path

import macos_extractor as extractor
import macos_signing as signing


def source_options(command):
    g = command.add_argument_group('controlled-source route (all four or none)')
    g.add_argument('--source-evidence', type=Path, help='operator-reviewed omd-macos-extractor-source-evidence-v1 JSON')
    g.add_argument('--source-evidence-sha256', help='reviewed SHA-256 of the evidence file')
    g.add_argument('--source-kit', type=Path, help='the reviewed source kit named by the evidence')
    g.add_argument('--source-bootloader', type=Path, help='the compiled PyInstaller run bootloader named by the evidence')


def source_spec(a):
    """None (default stock route) or the explicit controlled-source evidence spec."""
    values = [a.source_evidence, a.source_evidence_sha256, a.source_kit, a.source_bootloader]
    signing.need(all(x is None for x in values) or all(x is not None for x in values),
                 'The controlled-source route needs --source-evidence, --source-evidence-sha256, --source-kit and --source-bootloader together')
    if a.source_evidence is None:
        return None
    return {'evidence': {'path': str(signing.absolute(a.source_evidence)), 'sha256': a.source_evidence_sha256},
            'kit': str(signing.absolute(a.source_kit)), 'bootloader': str(signing.absolute(a.source_bootloader))}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    i = sub.add_parser('inspect', help='validate a producer and write a new preparation plan (read-only)')
    i.add_argument('--producer', type=Path, required=True)
    i.add_argument('--producer-sha256', required=True)
    i.add_argument('--version', required=True, help='expected yt-dlp version embedded in the producer')
    i.add_argument('--target-arch', choices=sorted(extractor.TARGETS), required=True, help='PyInstaller target architecture of the producer')
    i.add_argument('--mode', choices=signing.MODES, required=True)
    i.add_argument('--identity', required=True, help='"-" for development-adhoc; "Developer ID Application: NAME (TEAMID)" or a SHA-1 hash')
    i.add_argument('--team-id')
    i.add_argument('--plan', type=Path, required=True, help='new plan JSON path')
    source_options(i)
    e = sub.add_parser('execute', help='prepare a new extractor exactly as a reviewed plan describes')
    e.add_argument('--plan', type=Path, required=True)
    e.add_argument('--output', type=Path, required=True, help='new extractor path')
    e.add_argument('--work', type=Path, required=True, help='new directory for the report and intermediate evidence')
    v = sub.add_parser('verify', help='repeat the equivalence proof for a producer and a prepared extractor')
    v.add_argument('--producer', type=Path, required=True)
    v.add_argument('--producer-sha256', required=True)
    v.add_argument('--prepared', type=Path, required=True)
    v.add_argument('--prepared-sha256', required=True)
    v.add_argument('--version', required=True)
    v.add_argument('--target-arch', choices=sorted(extractor.TARGETS), required=True)
    v.add_argument('--mode', choices=signing.MODES, required=True)
    v.add_argument('--team-id')
    v.add_argument('--output', type=Path, required=True, help='new verification JSON path')
    source_options(v)
    return p


def main(argv=None):
    a = parser().parse_args(argv)
    if platform.system() != 'Darwin':
        print('macOS extractor preparation requires a macOS host', file=sys.stderr)
        return 1
    try:
        if a.command == 'inspect':
            plan_path = signing.new_file(a.plan, 'Plan')
            request = {'producer': str(signing.absolute(a.producer)), 'producer_sha256': a.producer_sha256, 'version': a.version,
                       'target_arch': a.target_arch, 'mode': a.mode, 'identity': a.identity, 'team_id': a.team_id}
            source = source_spec(a)
            if source is not None:
                request['source'] = source
            need_outside = signing.absolute(a.producer).parent
            signing.need(not signing.within(plan_path, need_outside), 'Plan must be independent of the producer directory')
            for folder in extractor.source_input_dirs(request):
                signing.need(not signing.within(plan_path, folder), 'Plan must be independent of the source evidence, kit and bootloader directories')
            plan = extractor.inspect(request)
            plan['created_at'] = signing.now()
            signing.write_new(plan_path, signing.json_bytes(plan))
            print(json.dumps({'plan': str(plan_path), 'method': plan['method'], 'ready_for_execution': plan['ready_for_execution'], 'native_members': plan['producer']['archive']['native_members'],
                              'blockers': [b['id'] for b in plan['blockers']], 'signature_kind': plan['signature_kind'], 'release_accepted': False}, indent=2))
            return 0 if plan['ready_for_execution'] else 2
        if a.command == 'verify':
            if a.mode == 'development-adhoc':
                signing.need(a.team_id is None, 'development-adhoc verification has no Team ID')
            else:
                signing.need(a.team_id and signing.TEAM.fullmatch(a.team_id), 'developer-id verification needs --team-id')
            out = signing.new_file(a.output, 'Verification')
            result = extractor.verify_pair({'path': str(signing.absolute(a.producer)), 'sha256': a.producer_sha256},
                                           {'path': str(signing.absolute(a.prepared)), 'sha256': a.prepared_sha256},
                                           a.version, a.target_arch, a.mode, a.team_id, source=source_spec(a))
            result['created_at'] = signing.now()
            signing.write_new(out, signing.json_bytes(result))
            print(json.dumps({'verification': str(out), 'method': result['method'], 'pass': result['pass'], 'release_accepted': False}, indent=2))
            return 0 if result['pass'] else 1
        status, report = extractor.execute(a.plan, a.output, a.work)
    except (ValueError, OSError, KeyError, struct.error) as error:
        print(json.dumps({'refused': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({'status': status, 'report': str(report), 'release_accepted': False}, indent=2))
    return 0 if status in extractor.DONE else 1


if __name__ == '__main__':
    raise SystemExit(main())
