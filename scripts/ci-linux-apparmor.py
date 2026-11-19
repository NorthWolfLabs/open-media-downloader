# /// script
# requires-python = ">=3.12"
# ///
"""Generate an executable-specific guardian policy on disposable GitHub runners.

The workflow loads and removes this policy. Never disables the system-wide
unprivileged-user-namespace restriction. Installed builds use their root-owned
package policy instead of this development-only path.
"""
import os
import platform
from pathlib import Path

if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
    raise SystemExit('This fixture is restricted to disposable GitHub Linux runners')
workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
if Path.cwd().resolve() != workspace:
    raise SystemExit('Run from the checked-out GitHub workspace')
guardian = (workspace / 'target/debug/omd-helper-guardian').resolve(strict=True)
if not guardian.is_relative_to(workspace) or not guardian.is_file():
    raise SystemExit('Guardian must be the built executable inside this workspace')
# AppArmor attachment metacharacters must never change an exact path into a glob.
if any(c in str(guardian) for c in '\\"*?[]{}\n\r'):
    raise SystemExit('Unsupported AppArmor attachment path')
policy = ('abi <abi/4.0>,\ninclude <tunables/global>\n'
          f'profile omd_ci_helper "{guardian}" flags=(unconfined) {{\n  userns,\n}}\n')
(workspace / 'target/omd-ci-helper.apparmor').write_text(policy)
