# /// script
# requires-python = ">=3.12"
# ///
"""Assemble a new kit from reviewed adapter inputs and a verified retained runtime."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from public_inputs import identity, inventory, regular, relative, write_json, new_directory

PRODUCTION = ('adapter.mjs', 'protocol.mjs', 'package.json', 'package-lock.json', 'LICENSE')


def adapter_inputs(adapter, policy):
    rules = json.loads(regular(policy).read_text())
    production = {}
    for name in PRODUCTION:
        with regular(adapter / name).open('rb') as stream:
            data = stream.read(4 * 1024**2 + 1)
        if len(data) > 4 * 1024**2:
            raise ValueError('adapter production input exceeds budget')
        production[name] = data
    identities = {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in production.items()}
    lock = json.loads(production['package-lock.json'])
    package = json.loads(production['package.json'])
    version = rules['version']
    if identities['package-lock.json']['sha256'] != rules['lock_sha256'] or package['dependencies'] != {'playwright-core': version} or set(lock['packages']) != {'', 'node_modules/playwright-core'}:
        raise ValueError('incompatible adapter lock/dependencies')
    dependency = adapter / 'node_modules/playwright-core'
    installed = json.loads(regular(dependency / 'package.json').read_text())
    if installed['name'] != 'playwright-core' or installed['version'] != version or lock['packages']['node_modules/playwright-core']['version'] != version:
        raise ValueError('incompatible installed runtime identity')
    if inventory(dependency) != rules['files']:
        raise ValueError('unreviewed or changed Playwright package contents')
    for required in ('LICENSE', 'NOTICE', 'ThirdPartyNotices.txt', 'browsers.json'):
        if required not in rules['files']:
            raise ValueError('missing runtime license/identity input')
    result = {name: (adapter / name, identities[name]) for name in PRODUCTION}
    result.update({'node_modules/playwright-core/' + name: (regular(dependency / relative(name)), info) for name, info in rules['files'].items()})
    return result, rules


def package(runtime, browser, node, node_version, version, output, adapter, policy, verified):
    browser = relative(browser)
    inputs, rules = adapter_inputs(adapter, policy)
    retained = json.loads(regular(verified).read_text())
    expected = {k.removeprefix('browser/'): v for k, v in retained['files'].items() if k.startswith('browser/')}
    if inventory(runtime) != expected or retained['browser'] != 'browser/' + browser:
        raise ValueError('runtime differs from retained verified inventory')
    node_identity = identity(node)
    if node_identity['sha256'] != retained['node']['sha256'] or node_version != retained['node']['version']:
        raise ValueError('Node differs from verified input')
    browsers = json.loads(regular(adapter / 'node_modules/playwright-core/browsers.json').read_text())['browsers']
    revision = next(b['revision'] for b in browsers if b['name'] == 'chromium-headless-shell')
    if f'playwright-{rules["version"]}-chromium-{revision}-' not in retained['version'] or f'playwright-{rules["version"]}-chromium-{revision}-' not in version:
        raise ValueError('incompatible lock/Chromium runtime identity')
    new_directory(output)
    selected = {**{'browser/' + k: (runtime / k, info) for k, info in expected.items()}, **{'adapter/' + k: v for k, v in inputs.items()}}
    approved = {name: info for name, (_, info) in selected.items()}
    for name, (source, expected_identity) in selected.items():
        target = output / 'content' / relative(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(regular(source), target)
        target.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        if identity(target) != expected_identity:
            raise ValueError('input differs from approved identity while copying')
    files = inventory(output / 'content')
    if files != approved:
        raise ValueError('browser output differs from approved inventory')
    if identity(node) != node_identity:
        raise ValueError('Node changed while packaging')
    write_json(output / 'browser-tools-v2.json', {'root': 'content', 'version': version, 'browser': 'browser/' + browser, 'adapter': 'adapter/adapter.mjs', 'node': {'path': str(node.absolute()), 'sha256': node_identity['sha256'], 'version': node_version}, 'files': files})
    write_json(output / 'build-inputs.json', {'release_accepted': False, 'retained_manifest': str(verified.absolute()), 'retained_identity': identity(verified), 'policy': identity(policy)})

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime', 'node', 'output', 'verified-runtime'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('browser', 'node-version', 'version'):
        p.add_argument('--' + name, required=True)
    root = Path(__file__).absolute().parents[1]
    p.add_argument('--adapter', type=Path, default=root / 'adapters/browser')
    p.add_argument('--policy', type=Path, default=root / 'distribution/browser-runtime-inputs.json')
    a = p.parse_args()
    package(a.runtime, a.browser, a.node, a.node_version, a.version, a.output, a.adapter, a.policy, a.verified_runtime)
