# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Bind a stapled, notarized OMD macOS app to its unchanged signed final-materials binding.

`prepare` re-derives everything from actual bytes and, only after every check passes, writes
`notarized-materials-v1.json` (schema omd-notarized-materials-v1, method
omd-apple-stapled-app-ticket-v1) and `verification-report.json` into a NEW directory outside
every input. A failed or unverified run writes only a refusal report. `verify` requires the
caller-pinned envelope digest and re-derives the envelope from bytes (it never replays a
report), then writes a new verification JSON file.

The original binder runs unchanged and cryptographically on a private snapshot of the true
pre-staple signed app with every original input (the same options as bind-final-materials.py;
its contract comes from the pinned binding). Actual codesign, `xcrun stapler validate` and
`spctl` checks run on private snapshots and on a private readback of the distribution archive.

Exit 0: fresh macOS verification passed (release_accepted stays false). Exit 1: refused,
invalid or a failed cryptographic or Apple check. Exit 2: unavailable platform, tool or
network, timeout, output overflow or a resource bound: unverified, never accepted.
Nothing here signs, staples, submits, reads credentials or profiles, or accepts a release.
"""
import argparse
import json
import platform
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import final_materials as final
import macos_signing as signing
import notarized_materials as notarized

REFUSALS = (ValueError, OSError, KeyError, struct.error, zipfile.BadZipFile, zlib.error, NotImplementedError)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for name, text in (('prepare', 'verify and write a new envelope into a new directory'), ('verify', 're-derive and compare a caller-pinned envelope')):
        c = sub.add_parser(name, help=text)
        c.add_argument('--contract', required=True, choices=(notarized.SCHEMA,), help='the explicit envelope contract version')
        c.add_argument('--signed-binding', type=Path, required=True, help='the exact omd-final-materials-v1/-v2 binding of the pre-staple signed app')
        c.add_argument('--signed-binding-sha256', required=True, metavar='HEX', help='its independently pinned SHA-256')
        c.add_argument('--signed-app', type=Path, required=True, help='the exact pre-staple signed app (the original --final-app)')
        c.add_argument('--stapled-app', type=Path, required=True, help='the stapled app')
        c.add_argument('--expected-team-id', required=True, metavar='TEAM', help='the caller-pinned Developer ID Team ID')
        c.add_argument('--expected-target', required=True, metavar='TARGET', help=f'the caller-pinned target ({", ".join(notarized.TARGETS)} only for this method)')
        c.add_argument('--expected-version', required=True, metavar='VERSION', help='the caller-pinned release version')
        c.add_argument('--expected-purpose', required=True, metavar='PURPOSE', help=f'the caller-pinned purpose ({notarized.PURPOSE} only)')
        c.add_argument('--uploaded-archive', type=Path, required=True, help='the exact ZIP submitted to Apple')
        c.add_argument('--uploaded-archive-sha256', required=True, metavar='HEX')
        c.add_argument('--notary-log', type=Path, required=True, help='the retained notary log JSON (provenance consistency only)')
        c.add_argument('--notary-log-sha256', required=True, metavar='HEX')
        c.add_argument('--submission-id', required=True, metavar='UUID')
        c.add_argument('--distribution-archive', type=Path, required=True, help='the ZIP of the stapled app')
        c.add_argument('--distribution-archive-sha256', required=True, metavar='HEX')
        c.add_argument('--evidence-root', action='append', default=[], metavar='NAME=DIR', help='evidence files are recorded as evidence:NAME/... (required)')
        c.add_argument('--max-seconds', type=float, default=notarized.WORKFLOW_SECONDS, help=f'lower the cooperative deadline; legacy proof and synchronous IO are not interrupted (at most {notarized.WORKFLOW_SECONDS})')
        # The original binder inputs, exactly as bind-final-materials.py takes them.
        c.add_argument('--input-app', type=Path, required=True, help='the exact pre-signature app the signing plan inspected')
        c.add_argument('--plan', type=Path, required=True)
        c.add_argument('--report', type=Path, required=True, help='the signing report')
        c.add_argument('--prepared-extractor', type=Path)
        c.add_argument('--prepared-extractor-report', type=Path)
        c.add_argument('--prepared-extractor-source-evidence', type=Path)
        c.add_argument('--prepared-extractor-source-evidence-sha256', metavar='HEX')
        c.add_argument('--prepared-extractor-source-kit', metavar='DELIVERY_PATH')
        c.add_argument('--prepared-extractor-source-bootloader', type=Path)
        c.add_argument('--materials-locks', type=Path)
        c.add_argument('--delivery-root', action='append', default=[], metavar='NAME=DIR')
        c.add_argument('--desktop-receipt', metavar='DELIVERY_PATH')
        c.add_argument('--desktop-notices', metavar='DELIVERY_PATH')
        c.add_argument('--review', type=Path)
        c.add_argument('--output', type=Path, required=True, help='prepare: a new directory; verify: a new JSON file')
        if name == 'verify':
            c.add_argument('--envelope', type=Path, required=True)
            c.add_argument('--envelope-sha256', required=True, metavar='HEX')
    return p


def spec(a):
    roots = {}
    for value in a.evidence_root:
        name, sep, folder = value.partition('=')
        signing.need(sep and final.COMPONENT_ID.fullmatch(name) and name not in roots, f'Invalid --evidence-root {value!r}')
        path = signing.no_link_ancestors(folder)
        signing.need(path.is_dir(), f'Evidence root is not a directory: {folder}')
        roots[name] = path
    signing.need(roots, 'At least one --evidence-root is required')
    bind = signing.load_script('omd_bind_final_cli', 'bind-final-materials.py')

    def final_spec(contract):
        # The unchanged original binder argument handling, for the contract the pinned binding names.
        fields = ('input_app', 'plan', 'report', 'prepared_extractor', 'prepared_extractor_report', 'prepared_extractor_source_evidence',
                  'prepared_extractor_source_evidence_sha256', 'prepared_extractor_source_kit', 'prepared_extractor_source_bootloader',
                  'materials_locks', 'delivery_root', 'desktop_receipt', 'desktop_notices', 'review')
        namespace = argparse.Namespace(**{k: getattr(a, k) for k in fields}, final_app=a.signed_app, contract=contract, skip_cryptographic=False)
        return bind.spec(namespace)

    absolute = signing.absolute
    return {'contract': a.contract, 'signed_binding': absolute(a.signed_binding), 'signed_binding_sha256': a.signed_binding_sha256,
            'signed_app': absolute(a.signed_app), 'stapled_app': absolute(a.stapled_app),
            'expected': {'team_id': a.expected_team_id, 'target': a.expected_target, 'version': a.expected_version, 'purpose': a.expected_purpose},
            'uploaded_archive': absolute(a.uploaded_archive), 'uploaded_archive_sha256': a.uploaded_archive_sha256,
            'notary_log': absolute(a.notary_log), 'notary_log_sha256': a.notary_log_sha256, 'submission_id': a.submission_id,
            'distribution_archive': absolute(a.distribution_archive), 'distribution_archive_sha256': a.distribution_archive_sha256,
            'evidence_roots': roots, 'final_spec': final_spec, 'seconds': a.max_seconds, 'temp_root': None}


def outside(path, a, s):
    """No output inside any app, evidence root, delivery root or private source input directory."""
    folders = [s['signed_app'], s['stapled_app'], signing.absolute(a.input_app), *s['evidence_roots'].values()]
    for value in a.delivery_root:
        folders.append(signing.absolute(value.partition('=')[2]))
    for value in (a.prepared_extractor, a.prepared_extractor_report, a.prepared_extractor_source_evidence, a.prepared_extractor_source_bootloader):
        if value is not None:
            folders.append(signing.absolute(value).parent)
    for folder in folders:
        signing.need(not signing.within(path, folder), f'Outputs must stay outside every app, evidence, delivery and source input directory: {folder}')


def failure(error):
    unverified = isinstance(error, notarized.Unverified)
    return (2 if unverified else 1), {'status': 'unverified' if unverified else 'refused', 'reason': f'{type(error).__name__}: {error}', 'release_accepted': False}


def prepare(a, s):
    out = signing.no_link_ancestors(a.output)
    outside(out, a, s)
    signing.need(not out.exists() and out.parent.is_dir(), 'Output must be a new directory in an existing directory')
    try:
        envelope, report = notarized.derive(s)
    except (notarized.Unverified, *REFUSALS) as error:
        code, refusal = failure(error)
        out.mkdir()
        # Refusal: a report only, never an envelope.
        signing.write_new(out / notarized.REPORT_NAME, signing.json_bytes({'schema': notarized.REPORT_SCHEMA, 'contract': notarized.SCHEMA, **refusal}))
        print(json.dumps(refusal, indent=2), file=sys.stderr)
        return code
    out.mkdir()
    signing.write_new(out / notarized.NAME, signing.json_bytes(envelope))
    report['envelope'] = signing.file_identity(out / notarized.NAME)
    signing.write_new(out / notarized.REPORT_NAME, signing.json_bytes(report))
    print(json.dumps({'status': report['status'], 'envelope': str(out / notarized.NAME), **report['envelope'], 'structure': report['structure'],
                      'release_accepted': False}, indent=2))
    return 0


def verify(a, s):
    out = signing.new_file(a.output, 'Verification output')
    outside(out, a, s)
    try:
        given = notarized.read_stable(signing.absolute(a.envelope), 'Envelope', notarized.MAX_JSON_BYTES)
        # The pinned digest and strict shape are checked before any re-derivation work.
        signing.need(notarized.sha(given) == a.envelope_sha256, 'The envelope differs from the caller-pinned digest')
        notarized.load_strict(given)
        envelope, report = notarized.derive(s)
        notarized.compare(given, a.envelope_sha256, envelope)
    except (notarized.Unverified, *REFUSALS) as error:
        code, refusal = failure(error)
        signing.write_new(out, signing.json_bytes({'schema': notarized.VERIFICATION_SCHEMA, 'contract': notarized.SCHEMA, **refusal}))
        print(json.dumps(refusal, indent=2), file=sys.stderr)
        return code
    result = {**report, 'schema': notarized.VERIFICATION_SCHEMA, 'status': 'notarized-materials-rederived-equal', 'rederived_equal': True,
              'envelope': {'bytes': len(given), 'sha256': a.envelope_sha256}}
    signing.write_new(out, signing.json_bytes(result))
    print(json.dumps({'status': result['status'], 'rederived_equal': True, 'envelope': result['envelope'], 'structure': report['structure'], 'release_accepted': False},
                     indent=2))
    return 0


def main(argv=None):
    a = parser().parse_args(argv)
    if platform.system() != 'Darwin':
        print(json.dumps({'status': 'unverified', 'reason': 'Notarized materials verification requires a macOS host', 'release_accepted': False}), file=sys.stderr)
        return 2
    try:
        s = spec(a)
        return prepare(a, s) if a.command == 'prepare' else verify(a, s)
    except (ValueError, OSError) as error:
        print(json.dumps({'status': 'refused', 'reason': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
