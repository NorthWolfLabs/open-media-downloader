# /// script
# requires-python = ">=3.12"
# ///
"""Build the SDK's WASI transformer without embedding builder paths.

Writes an unapproved candidate only. Reviewing and updating the SDK's digest is
a separate step; this command never changes the installed/vendored build tool.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def rebuild(project, target_dir, output):
    project = project.resolve(strict=True)
    target_dir = target_dir.resolve()
    output = output.absolute()
    if output.exists():
        raise ValueError('Output must be a new file')
    home = Path.home().resolve()
    cargo_home = Path(os.environ.get('CARGO_HOME', home / '.cargo')).resolve()
    rustup_home = Path(os.environ.get('RUSTUP_HOME', home / '.rustup')).resolve()
    # Specific mappings follow the broad home mapping. The last matching Rust
    # prefix wins. Use encoded flags so paths containing spaces stay one argument.
    mappings = [(home, '/builder'), (cargo_home, '/cargo'),
                (rustup_home, '/rust-toolchain'), (project, '/omd/sdk')]
    env = dict(os.environ)
    env.pop('RUSTFLAGS', None)
    env['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(
        f'--remap-path-prefix={source}={destination}' for source, destination in mappings)
    subprocess.run(['cargo', 'build', '--locked', '-p', 'omd-component-snapshot',
                    '--target', 'wasm32-wasip1', '--release', '--target-dir', str(target_dir)],
                   cwd=project, env=env, check=True)
    built = target_dir / 'wasm32-wasip1/release/omd-component-snapshot.wasm'
    data = built.read_bytes()
    forbidden = [str(p).encode() for p, _ in mappings] + [b'/Users/', b'/home/', b'/Volumes/']
    if any(value in data for value in forbidden) or re.search(rb'[A-Z]:[\\/]Users[\\/]', data, re.I):
        raise ValueError('Transformer still embeds a builder path')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(data)
    print(json.dumps({'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest(),
                      'release_accepted':False}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rebuild(Path(__file__).resolve().parents[1], args.target_dir, args.output)
