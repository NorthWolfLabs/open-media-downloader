# /// script
# requires-python = ">=3.12"
# ///
"""The macOS native sign-in window application bundle (OMD Sign-In.app).

The engine launches `<engine dir>/OMD Sign-In.app/Contents/MacOS/omd-signin`
directly, so the process takes this bundle's identifier, name and icon. This module
is the single definition of that bundle: its members, its deterministic Info.plist
and the input checks every packaging step applies. Assembly only arranges bytes;
signing, notarization and release acceptance remain separate steps.

The icon is an explicit, digest-pinned packaging input. The desktop project owns
the product artwork and supplies its reviewed ICNS; the engine source carries none.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import sys
import tomllib
from pathlib import Path

import materials_contract as mc

SCRIPTS = Path(__file__).resolve().parent
BUNDLE = mc.SIGN_IN_BUNDLE
INFO = 'Contents/Info.plist'
EXECUTABLE = 'Contents/MacOS/' + mc.SIGN_IN_BINARY
ICON = 'Contents/Resources/AppIcon.icns'
SEAL = 'Contents/_CodeSignature/CodeResources'
MEMBERS = (INFO, EXECUTABLE, ICON)
IDENTIFIER = 'labs.northwolf.omd.signin'
NAME = 'OMD Sign-In'
ARCHES = {'darwin-arm64': 'arm64', 'darwin-x64': 'x86_64'}
VERSION = re.compile(r'(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,2}')
HEX64 = re.compile(r'[a-f0-9]{64}')
MAX_ICON_BYTES = 16 * 1024 * 1024
MH_EXECUTE = 2
_payload = None


def need(ok, why):
    if not ok:
        raise ValueError(why)


def payload():
    """The read-only payload gate's Mach-O reader (no PyInstaller import at load)."""
    global _payload
    if _payload is None:
        spec = importlib.util.spec_from_file_location('omd_check_macos_payload', SCRIPTS / 'check-macos-payload.py')
        _payload = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_payload)
    return _payload


def info_plist(version, minimum):
    """Canonical Info.plist bytes: XML, sorted keys, engine version, executable minimum.
    No LSUIElement: the window is a regular foreground application (tao's default)."""
    need(isinstance(version, str) and VERSION.fullmatch(version) is not None,
         'The sign-in bundle needs a numeric engine version of at most three dot-separated integers')
    payload().version(minimum)
    return plistlib.dumps({
        'CFBundleDisplayName': NAME, 'CFBundleExecutable': mc.SIGN_IN_BINARY, 'CFBundleIconFile': 'AppIcon',
        'CFBundleIdentifier': IDENTIFIER, 'CFBundleInfoDictionaryVersion': '6.0', 'CFBundleName': NAME,
        'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': version, 'CFBundleVersion': version,
        'LSMinimumSystemVersion': minimum, 'NSHighResolutionCapable': True}, fmt=plistlib.FMT_XML, sort_keys=True)


def check_icon(data):
    """A complete ICNS container: header length equals the file and entries tile it."""
    need(isinstance(data, bytes) and 16 <= len(data) <= MAX_ICON_BYTES and data[:4] == b'icns'
         and int.from_bytes(data[4:8], 'big') == len(data), 'The sign-in icon must be a complete ICNS file')
    offset = 8
    while offset < len(data):
        size = int.from_bytes(data[offset + 4:offset + 8], 'big') if offset + 8 <= len(data) else 0
        need(size >= 8 and offset + size <= len(data), 'The sign-in icon must be a complete ICNS file')
        offset += size
    return data


def executable_minimum(data, target):
    """The deployment minimum of the target slice of a Mach-O executable."""
    need(target in ARCHES, f'The sign-in app bundle is macOS-only, not {target}')
    try:
        found = payload().component(data, EXECUTABLE, ARCHES[target])
    except ValueError as error:
        raise ValueError(f'The sign-in window is not a macOS {ARCHES[target]} executable: {error}') from error
    need(all(row['filetype'] == MH_EXECUTE for row in found['slices']), 'The sign-in window is not a Mach-O executable')
    return found['minimum']


def members(binary, icon, version, target):
    """{bundle-relative path: (bytes, mode)} for the exact bundle, in member order."""
    return {INFO: (info_plist(version, executable_minimum(binary, target)), 0o644), EXECUTABLE: (binary, 0o755), ICON: (check_icon(icon), 0o644)}


def engine_version(root=SCRIPTS.parent):
    return tomllib.loads((root / 'Cargo.toml').read_text())['workspace']['package']['version']


def main(argv=None):
    """Assemble a new bundle directory (development integration and local checks)."""
    parser = argparse.ArgumentParser(description='Assemble the macOS sign-in window app bundle from explicit inputs.')
    parser.add_argument('--binary', type=Path, required=True, help='compiled omd-signin for the target')
    parser.add_argument('--icon', type=Path, required=True, help='reviewed ICNS supplied by the desktop project')
    parser.add_argument('--icon-sha256', required=True)
    parser.add_argument('--target', choices=sorted(ARCHES), required=True)
    parser.add_argument('--version', help='engine version (default: this checkout)')
    parser.add_argument('--output', type=Path, required=True, help=f'new absolute path ending in {BUNDLE}')
    args = parser.parse_args(argv)
    output = Path(os.path.abspath(args.output))
    need(output.name == BUNDLE and not os.path.lexists(output) and output.parent.is_dir(), f'Use a new --output path named {BUNDLE} in an existing directory')
    need(HEX64.fullmatch(args.icon_sha256) is not None, '--icon-sha256 must be 64 lowercase hex characters')
    icon = args.icon.read_bytes()
    need(hashlib.sha256(icon).hexdigest() == args.icon_sha256, 'The sign-in icon differs from its pinned digest')
    files = members(args.binary.read_bytes(), icon, args.version or engine_version(), args.target)
    output.mkdir()
    for rel, (data, mode) in files.items():
        path = output / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'xb') as stream:
            stream.write(data)
        path.chmod(mode)
    return {'bundle': str(output), 'files': {rel: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mode': oct(mode)} for rel, (data, mode) in files.items()},
            'identifier': IDENTIFIER, 'signed': False, 'release_accepted': False}


if __name__ == '__main__':
    try:
        print(json.dumps(main(), indent=2))
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(2)
