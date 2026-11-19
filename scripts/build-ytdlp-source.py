# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Controlled-source macOS arm64 yt-dlp prototype builder.

fetch       copy pinned inputs from retained directories (by digest) or download them
plan        verify inputs, the profile's lock and the toolchain; write a portable plan
build       re-derive the plan, build everything from source into a new directory
kit         write a deterministic source/rebuild kit for a built prototype
verify-kit  verify a kit against its index, plan and profile
split-kit   write companion-delivery parts (at most 256 MiB each) and their manifest
join-kit    reassemble a kit from verified parts

--profile selects distribution/yt-dlp-source/profile.json (default, declared [default]
extras) or distribution/yt-dlp-source-curl/profile.json (curl_cffi impersonation built
from source). A plan names its profile; build and kit follow the plan.

The PyInstaller dependency is the pinned 6.22.0 archive reader used for verification;
the shipped PyInstaller is built from its sdist. Nothing here uses a signing identity,
notarizes, publishes or accepts a release: prototypes stay unpromotable.
"""
import argparse
import json
import sys
from pathlib import Path

import ytdlp_source as source


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    profiles = sorted(source.PROFILES)
    fetch = commands.add_parser('fetch')
    fetch.add_argument('--profile', choices=profiles, default=source.PROFILE_REL)
    fetch.add_argument('--output', required=True, help='new sources directory')
    fetch.add_argument('--retained', action='append', default=[], help='retained directory searched by file name, size and digest')
    fetch.add_argument('--report', required=True, help='new JSON report file (outside the sources directory)')
    plan = commands.add_parser('plan')
    plan.add_argument('--profile', choices=profiles, default=source.PROFILE_REL)
    plan.add_argument('--sources', required=True)
    plan.add_argument('--plan', required=True, help='new plan file')
    build = commands.add_parser('build')
    build.add_argument('--plan', required=True)
    build.add_argument('--sources', required=True)
    build.add_argument('--output', required=True, help='new output directory')
    kit = commands.add_parser('kit')
    kit.add_argument('--plan', required=True)
    kit.add_argument('--sources', required=True)
    kit.add_argument('--build', required=True, help='a built output directory')
    kit.add_argument('--output', required=True, help='new .tar.gz file')
    verify = commands.add_parser('verify-kit')
    verify.add_argument('--kit', required=True)
    verify.add_argument('--sha256')
    split = commands.add_parser('split-kit')
    split.add_argument('--kit', required=True)
    split.add_argument('--output', required=True, help='new parts directory')
    split.add_argument('--part-mib', type=int, default=128)
    join = commands.add_parser('join-kit')
    join.add_argument('--parts', required=True, help='parts directory with PARTS.json')
    join.add_argument('--output', required=True, help='new .tar.gz file')
    args = parser.parse_args(argv)
    try:
        if args.command == 'fetch':
            report_path = source.signing.new_file(args.report, 'Report')
            report = source.fetch(source.REPO, args.output, args.retained, profile_rel=args.profile)
            report_path.write_bytes(source.json_bytes(report))
            result = {'inputs': len(report['inputs']), 'npm': len(report['npm']),
                      'downloaded': sum(r['origin'] == 'download' for r in report['inputs'] + report['npm'])}
        elif args.command == 'plan':
            path = source.signing.new_file(args.plan, 'Plan')
            plan_data = source.make_plan(source.REPO, Path(args.sources), args.profile)
            path.write_bytes(source.json_bytes(plan_data))
            result = {'plan': path.name, 'sha256': source.file_sha(path), 'inputs': len(plan_data['inputs']), 'npm': len(plan_data['npm'])}
        elif args.command == 'build':
            record = source.build(source.REPO, Path(args.plan), Path(args.sources), Path(args.output))
            result = {'status': record['status'], **record['output']}
        elif args.command == 'kit':
            result = source.make_kit(source.REPO, Path(args.plan), Path(args.sources), Path(args.build), Path(args.output))
        elif args.command == 'verify-kit':
            result = source.verify_kit(Path(args.kit), args.sha256)
        elif args.command == 'split-kit':
            result = source.split_kit(Path(args.kit), Path(args.output), args.part_mib * 1024**2)
        else:
            result = source.join_kit(Path(args.parts), Path(args.output))
    except (ValueError, OSError, source.BuildFailed) as error:
        print(json.dumps({'status': 'refused' if isinstance(error, ValueError) else 'failed', 'error': str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
