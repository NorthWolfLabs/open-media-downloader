# /// script
# requires-python = ">=3.12"
# dependencies = ["pyinstaller==6.22.0"]
# ///
"""Bind a signed OMD macOS payload to its reviewed release materials (phase two).

`prepare` re-derives every relation between the pre-signature input app and the
signed output from actual bytes and writes, into a NEW directory outside both apps,
`final-materials-v1.json` (or `-v2.json`) plus `binding-report.json` with categorized
gaps. `verify` re-derives the binding and requires exact agreement with a given document.
`--contract` selects the explicit contract version: omd-final-materials-v1 (default,
unchanged, stock extractor route only) or omd-final-materials-v2 (typed extractor route;
the controlled-source route needs its preparation report and the four
--prepared-extractor-source-* inputs, which are private: only digests and the kit's
delivery locator are serialized).
Exit 0: coverage validated (still release_accepted false). Exit 2: a binding with
explicit pending gaps. Exit 1: refused (no binding document is written).
Nothing here signs, notarizes, publishes, reads credentials or decides compliance.
"""
import argparse
import json
import platform
import struct
import sys
from pathlib import Path

import final_materials as final
import macos_signing as signing

EXIT = {'final-materials-validated': 0, 'final-materials-incomplete': 2}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for name, text in (('prepare', 'derive a final binding and write it to a new directory'), ('verify', 're-derive and compare an existing final binding')):
        c = sub.add_parser(name, help=text)
        c.add_argument('--input-app', type=Path, required=True, help='the exact pre-signature app the signing plan inspected')
        c.add_argument('--final-app', type=Path, required=True, help='the signed output app')
        c.add_argument('--plan', type=Path, required=True, help='the executed signing plan')
        c.add_argument('--report', type=Path, required=True, help='its signing-report.json (identities and purpose only; every claim is re-derived)')
        c.add_argument('--contract', choices=(final.FINAL_SCHEMA, final.FINAL_SCHEMA_V2), default=final.FINAL_SCHEMA,
                       help='final materials contract version (default %(default)s, which refuses the controlled-source extractor route)')
        c.add_argument('--prepared-extractor', type=Path, help='the prepared yt-dlp extractor bound by the plan')
        c.add_argument('--prepared-extractor-report', type=Path, help='v2 controlled-source route: its preparation report, as bound by the signing plan (private input)')
        c.add_argument('--prepared-extractor-source-evidence', type=Path, help='v2 controlled-source route: the operator-reviewed source evidence (private input)')
        c.add_argument('--prepared-extractor-source-evidence-sha256', metavar='HEX', help='its reviewed SHA-256; must equal the digest the signing plan inspected')
        c.add_argument('--prepared-extractor-source-kit', metavar='DELIVERY_PATH', help='the evidence-bound source kit, as a delivery path NAME/... (bound as a delivery file)')
        c.add_argument('--prepared-extractor-source-bootloader', type=Path, help='the evidence-bound compiled bootloader (private input)')
        c.add_argument('--materials-locks', type=Path, help='directory with Cargo.lock, browser-package-lock.json, desktop-Cargo.lock and desktop-package-lock.json')
        c.add_argument('--delivery-root', action='append', default=[], metavar='NAME=DIR', help='resolve delivery paths NAME/... under DIR (bytes are hashed in place)')
        c.add_argument('--desktop-receipt', metavar='DELIVERY_PATH', help='detached desktop receipt.json, as a delivery path')
        c.add_argument('--desktop-notices', metavar='DELIVERY_PATH', help='its native-NOTICES.txt, as a delivery path')
        c.add_argument('--review', type=Path, help='omd-final-review-v1 reviewed input (portable paths; never inferred)')
        c.add_argument('--skip-cryptographic', action='store_true', help='static checks only; recorded as a signature-binding gap')
        c.add_argument('--output', type=Path, required=True, help='prepare: new directory; verify: new JSON file')
        if name == 'verify':
            c.add_argument('--final', type=Path, required=True, help='final-materials-v1.json or final-materials-v2.json to verify (its schema must be --contract)')
    return p


def spec(a):
    roots = {}
    for value in a.delivery_root:
        name, sep, folder = value.partition('=')
        signing.need(sep and final.COMPONENT_ID.fullmatch(name) and name not in roots, f'Invalid --delivery-root {value!r}')
        path = signing.absolute(folder)
        signing.need(path.is_dir(), f'Delivery root is not a directory: {folder}')
        roots[name] = path
    receipt = [a.desktop_receipt, a.desktop_notices]
    signing.need(all(x is None for x in receipt) or all(x is not None for x in receipt), 'A detached desktop receipt needs both --desktop-receipt and --desktop-notices')
    absolute = lambda x: signing.absolute(x) if x else None
    source = [a.prepared_extractor_report, a.prepared_extractor_source_evidence, a.prepared_extractor_source_evidence_sha256,
              a.prepared_extractor_source_kit, a.prepared_extractor_source_bootloader]
    signing.need(all(x is None for x in source) or all(x is not None for x in source),
                 'The controlled-source extractor route needs --prepared-extractor-report and all four --prepared-extractor-source-* options together')
    signing.need(source[0] is None or a.contract == final.FINAL_SCHEMA_V2, f'Controlled-source extractor inputs need --contract {final.FINAL_SCHEMA_V2}')
    signing.need(source[2] is None or signing.HEX64.fullmatch(source[2]), '--prepared-extractor-source-evidence-sha256 must be 64 lowercase hex characters')
    extractor_source = None
    if source[0] is not None:
        extractor_source = {'report': absolute(source[0]), 'evidence': absolute(source[1]), 'evidence_sha256': source[2], 'kit': source[3], 'bootloader': absolute(source[4])}
    return {'input_app': signing.absolute(a.input_app), 'final_app': signing.absolute(a.final_app), 'plan': signing.absolute(a.plan),
            'report': signing.absolute(a.report), 'prepared_extractor': absolute(a.prepared_extractor), 'locks': absolute(a.materials_locks),
            'delivery_roots': roots, 'desktop_receipt': {'receipt': a.desktop_receipt, 'notices': a.desktop_notices} if a.desktop_receipt else None,
            'review': absolute(a.review), 'cryptographic': not a.skip_cryptographic, 'temp_root': None, 'contract': a.contract,
            'extractor_source': extractor_source}


def outside(path, s):
    for app in (s['input_app'], s['final_app']):
        signing.need(not signing.within(path, app), 'Outputs must stay outside the input and signed apps')
    for root in s['delivery_roots'].values():
        signing.need(not signing.within(path, root), 'Outputs must stay outside every delivery root (no self-reference)')
    for key in ('report', 'evidence', 'bootloader'):
        if s.get('extractor_source'):
            signing.need(not signing.within(path, s['extractor_source'][key].parent), 'Outputs must stay outside the controlled-source input directories')


def prepare(a, s):
    out = signing.no_link_ancestors(a.output)
    outside(out, s)
    signing.need(not out.exists() and out.parent.is_dir(), 'Output must be a new directory in an existing directory')
    try:
        status, doc, report = final.prepare(s)
    except (ValueError, OSError, KeyError, struct.error) as error:
        # Refusal: only a refusal report, never a binding document.
        out.mkdir()
        signing.write_new(out / 'binding-report.json', signing.json_bytes({'schema': final.REPORT_SCHEMAS[s['contract']], 'status': 'refused',
                                                                           'refused': f'{type(error).__name__}: {error}',
                                                                           'coverage_validated': False, 'distribution_candidate': False, 'release_accepted': False}))
        print(json.dumps({'status': 'refused', 'refused': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1
    out.mkdir()
    name = final.FINAL_NAMES[s['contract']]
    signing.write_new(out / name, signing.json_bytes(doc))
    report['final'] = signing.file_identity(out / name)
    signing.write_new(out / 'binding-report.json', signing.json_bytes(report))
    print(json.dumps({'status': status, 'contract': s['contract'], 'final': str(out / name), 'coverage_validated': doc['coverage_validated'],
                      'distribution_candidate': doc['distribution_candidate'], 'gaps': {k: len(v) for k, v in report['gaps'].items()}, 'release_accepted': False}, indent=2))
    return EXIT[status]


def verify(a, s):
    out = signing.new_file(a.output, 'Verification output')
    outside(out, s)
    data = signing.regular_input(str(signing.absolute(a.final)), 'Final materials').read_bytes()
    try:
        result = final.verify(s, data)
    except (ValueError, OSError, KeyError, struct.error) as error:
        signing.write_new(out, signing.json_bytes({'schema': final.VERIFICATION_SCHEMAS[s['contract']], 'status': 'refused', 'refused': f'{type(error).__name__}: {error}',
                                                   'release_accepted': False}))
        print(json.dumps({'status': 'refused', 'refused': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1
    signing.write_new(out, signing.json_bytes(result))
    print(json.dumps({k: result[k] for k in ('status', 'rederived_equal', 'coverage_validated', 'distribution_candidate', 'distribution_validation', 'release_accepted')}, indent=2))
    return 0 if result['distribution_validation']['pass'] else 2


def main(argv=None):
    a = parser().parse_args(argv)
    if platform.system() != 'Darwin':
        print('Final macOS materials binding requires a macOS host', file=sys.stderr)
        return 1
    try:
        s = spec(a)
        return prepare(a, s) if a.command == 'prepare' else verify(a, s)
    except (ValueError, OSError) as error:
        print(json.dumps({'refused': f'{type(error).__name__}: {error}', 'release_accepted': False}, indent=2), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
