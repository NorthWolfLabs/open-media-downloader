"""Controlled-source macOS arm64 yt-dlp prototype (omd-ytdlp-source-profile-v1).

`fetch` copies pinned inputs from retained kits or downloads them by digest into a new
directory. `plan` verifies every pinned input, the legacy lock and the local toolchain,
and writes a portable plan. `build` re-derives that plan and refuses any difference. It
then builds the native libraries, CPython, the PyInstaller bootloader and every Python
package from source in a new output directory, packages an ad-hoc signed onefile
prototype and verifies it. `kit` writes a deterministic source/rebuild kit and
`verify-kit` checks one. Nothing here uses a signing identity, notarizes, publishes,
promotes a prototype or accepts a release.
"""
import ast
import base64
import gzip
import hashlib
import io
import json
import marshal
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
import zlib
from pathlib import Path, PurePosixPath

import macos_extractor as extractor
import macos_signing as signing
import public_inputs
from macos_signing import need, sha

payload = signing.payload

PROFILE_SCHEMA = 'omd-ytdlp-source-profile-v1'
PROFILE_SCHEMA_V2 = 'omd-ytdlp-source-profile-v2'
PLAN_SCHEMA = 'omd-ytdlp-source-plan-v1'
RECEIPT_SCHEMA = 'omd-ytdlp-source-receipt-v1'
KIT_SCHEMA = 'omd-ytdlp-source-kit-v1'
PARTS_SCHEMA = 'omd-ytdlp-source-kit-parts-v1'
SCRIPTS = Path(__file__).resolve().parent
REPO = SCRIPTS.parent
PROFILE_REL = 'distribution/yt-dlp-source/profile.json'
README_REL = 'distribution/yt-dlp-source/README.md'
CURL_PROFILE_REL = 'distribution/yt-dlp-source-curl/profile.json'
# Known profiles and their READMEs. A plan names its profile; nothing else is accepted.
PROFILES = {PROFILE_REL: README_REL, CURL_PROFILE_REL: 'distribution/yt-dlp-source-curl/README.md'}
# The kit's first-party tooling; it must be closed under first-party imports (macos_signing
# imports signin_bundle since 0.2.3), so a recipient can run it from the kit alone.
TOOLING = ['ytdlp_source.py', 'ytdlp_source_replay.py', 'ytdlp_source_fixture.py', 'build-ytdlp-source.py', 'macos_signing.py', 'macos_extractor.py',
           'check-macos-payload.py', 'public_inputs.py', 'materials_contract.py', 'native_review.py', 'signin_bundle.py']
KIT_TOOLING = TOOLING + ['test-build-ytdlp-source.py']
KIT_PREFIX = 'omd-ytdlp-source-kit-v1'
CPU_ARM64 = 0x100000c
HEX = re.compile(r'[0-9a-f]{64}')
FILE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,200}')
PLACEHOLDER = re.compile(r'\{([a-z]+)\}')
PLACEHOLDERS = {'deps', 'root', 'prefix', 'jobs', 'tools', 'recipe', 'superbuild', 'impersonate', 'minimum'}
KINDS = {'cpython', 'native', 'sdist', 'wheel', 'node', 'tool-source', 'curl-recipe', 'curl-dep'}
V2_KINDS = {'tool-source', 'curl-recipe', 'curl-dep'}
ROLES = {'shipped-source', 'packaging-source', 'build-tool'}
SOURCE_KINDS = {'cpython', 'native', 'sdist', 'curl-recipe', 'curl-dep'}
# Inputs extracted before the build; curl-dep archives are extracted by the curl-impersonate recipe itself.
EXTRACTED_KINDS = {'cpython', 'native', 'sdist', 'node', 'tool-source', 'curl-recipe'}
INPUT_KEYS = {'id', 'kind', 'role', 'package', 'version', 'file', 'url', 'sha256', 'bytes'}
INPUT_OPTIONAL = {'upstream_check'}
PROFILE_KEYS = {'schema', 'id', 'status', 'release_accepted', 'promotable', 'target', 'extractor', 'legacy_profile', 'launcher',
                'logical_prefix', 'source_date_epoch', 'jobs', 'inputs', 'build_tools_resolution', 'npm', 'native', 'cpython',
                'packages', 'pyinstaller', 'expected'}
# v2 keeps every v1 section, names its own explicit lock, and adds source-built tools and curl-impersonate.
PROFILE_KEYS_V2 = (PROFILE_KEYS - {'legacy_profile'}) | {'lock_profile', 'tools', 'impersonate'}
SYSTEM_LIBRARY = re.compile(r'/(usr/lib|System/Library)/[A-Za-z0-9_.+/-]+')
HOST_PATH = re.compile(r'/(Users|Volumes|home)/|/private/var/folders/|/var/folders/|/opt/homebrew')
MAX_DOWNLOAD = 128 * 1024**2
MAX_KIT_BYTES = 1024**3
MAX_PART_BYTES = 256 * 1024**2
STEP_TIMEOUT = 3 * 3600
# Build steps that compile pinned sources whose build scripts can download (CMake
# ExternalProject, curl_cffi's scripts/build.py) run with all networking denied.
BUILD_SANDBOX = '(version 1)(allow default)(deny network*)'
COMMON_LIMITS = [
    'Prototype only: never promoted, release-accepted, notarized or Developer ID signed by this tool.',
    'Native code is compiled from the pinned sources here; Apple OS libraries and the Xcode SDK/toolchain are host prerequisites recorded by version, not shipped sources.',
    'Build tools (pure-Python build backends, pip bundled in the CPython source, Node/npm and npm packages for the EJS bundle) are recorded by digest. '
    'Their templates can contribute shipped generated source; those contributions record generator, input, output and license identities in the receipt and source kit.',
    'Output bytes depend on the toolchain and the absolute build directory; this kit does not claim bit-identical rebuilds elsewhere.',
    'No equivalence to the upstream yt-dlp_macos producer binary is claimed.',
]
PROOF_LIMITS = [
    "Closure proof: PyInstaller 6.22.0's own binary processing and onefile assembly are replayed from the source-built runtime with the host "
    'install_name_tool and codesign, and must reproduce every packed native and the executable byte for byte. Every packed Python code object '
    'must equal its attributed source compiled by the built CPython, compared as marshal version 2 data; marshal reference and interning flags '
    'are not compared. Packed code is never executed or imported.',
    'The static closure proof and the network-denied runtime smoke are separate evidence.',
]
LIMITS = COMMON_LIMITS + [
    'This profile follows the declared yt-dlp[default] extras and omits curl_cffi impersonation. The owner requires the public profile to keep '
    'that capability (decision of 2026-11-02), so this profile is not the public profile and is never promotable.',
] + PROOF_LIMITS
CURL_LIMITS = COMMON_LIMITS + [
    'This profile adds the curl_cffi impersonation capability (owner decision of 2026-11-02) from pinned sources: curl-impersonate v2.3.1, its '
    'nine hash-pinned dependency archives and five hash-pinned patches, built by its own CMake superbuild with source-built CMake and Ninja and '
    'networking denied. No prebuilt libcurl-impersonate archive or platform wheel is used. It is still an unaccepted, unpromotable prototype.',
    'CMake, Ninja and pkgconf are compiled here from pinned official source archives and are not shipped; Apple OS libraries they link are host '
    'prerequisites. The source-built pkgconf serves as pkg-config only for the recipe release step that writes libcurl-impersonate.pc and for '
    "curl_cffi's scripts/build.py, which reads that file.",
    'The curl_cffi extension links Apple OS frameworks explicitly. Its dynamic lookups are limited to the Python C API. TLS ClientHello and '
    'HTTP/2 observations come from a loopback fixture with a throwaway CA; they are not a claim of fingerprint equality with real browsers.',
] + PROOF_LIMITS


def limits_for(profile):
    return CURL_LIMITS if profile['schema'] == PROFILE_SCHEMA_V2 else LIMITS


def is_v2(profile):
    return profile['schema'] == PROFILE_SCHEMA_V2


def lock_section(profile):
    """The profile's lock: v1 cross-checks the legacy recipe lock, v2 names its own explicit lock."""
    return profile['lock_profile'] if is_v2(profile) else profile['legacy_profile']


class Refused(ValueError):
    pass


class Stale(Refused):
    pass


class BuildFailed(RuntimeError):
    def __init__(self, step, message):
        super().__init__(f'{step}: {message}')
        self.step = step


# ---------------------------------------------------------------- basics

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()


def identity(path):
    return public_inputs.identity(path)


def file_sha(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def by_id(profile, ident):
    rows = [row for row in profile['inputs'] if row['id'] == ident]
    need(len(rows) == 1, f'Profile input not found: {ident}')
    return rows[0]


def sdist_for(profile, package):
    return by_id(profile, 'sdist:' + package)


def version_tuple(text):
    return payload.version(text)


def strict_load(path):
    return signing.strict_json(Path(path).read_bytes())


def new_output_directory(path, forbidden):
    """A new directory in an existing link-free parent, outside every forbidden tree."""
    need(isinstance(path, (str, Path)) and os.path.isabs(path), 'Output must be an absolute path')
    path = signing.no_link_ancestors(path)
    need(not os.path.lexists(path), f'Output already exists: {path}')
    need(path.parent.is_dir(), f'Output parent does not exist: {path.parent}')
    for tree in forbidden:
        if tree is not None:
            tree = Path(os.path.abspath(tree))
            need(not signing.within(path, tree) and not signing.within(tree, path), f'Output must be outside {tree}')
    path.mkdir(mode=0o755)
    return path


def substitute(value, values):
    def replace(match):
        need(match.group(1) in values, f'Unknown placeholder {{{match.group(1)}}}')
        return str(values[match.group(1)])
    return PLACEHOLDER.sub(replace, value)


# ---------------------------------------------------------------- profile

def check_steps(steps, what):
    need(isinstance(steps, list) and steps, f'{what} needs steps')
    for step in steps:
        need(isinstance(step, list) and step and all(isinstance(a, str) and a and '\0' not in a for a in step), f'{what} has an invalid step')
        for arg in step:
            need(set(PLACEHOLDER.findall(arg)) <= PLACEHOLDERS, f'{what} uses an unknown placeholder')


def load_profile(path):
    profile = strict_load(path)
    need(isinstance(profile, dict), 'Profile fields differ from the schema')
    keys = {PROFILE_SCHEMA: PROFILE_KEYS, PROFILE_SCHEMA_V2: PROFILE_KEYS_V2}.get(profile.get('schema'))
    need(keys is not None, 'Unsupported profile schema')
    need(set(profile) == keys, 'Profile fields differ from the schema')
    need(profile['release_accepted'] is False and profile['promotable'] is False and profile['status'] == 'prototype', 'A source-build profile is always an unaccepted prototype')
    target = profile['target']
    need(target.get('os') == 'macos' and target.get('arch') == 'arm64' and set(target) == {'os', 'arch', 'macos_minimum'}, 'Only the explicit macOS arm64 target is supported')
    need(version_tuple(target['macos_minimum']) >= (13, 5, 0), 'The macOS minimum may not be below 13.5')
    need(type(profile['jobs']) is int and 1 <= profile['jobs'] <= 4, 'Build jobs must be between 1 and 4')
    need(type(profile['source_date_epoch']) is int and profile['source_date_epoch'] > 0, 'Invalid SOURCE_DATE_EPOCH')
    need(re.fullmatch(r'(/[a-z0-9][a-z0-9._-]*)+', profile['logical_prefix'] or '') and not HOST_PATH.search(profile['logical_prefix']), 'Invalid logical install prefix')
    ids, files = set(), set()
    for row in profile['inputs']:
        need(isinstance(row, dict) and INPUT_KEYS <= set(row) <= INPUT_KEYS | INPUT_OPTIONAL, f'Input fields differ from the schema: {row.get("id")}')
        need(row['id'] not in ids, f'Duplicate input id: {row["id"]}')
        ids.add(row['id'])
        need(row['kind'] in KINDS and row['role'] in ROLES, f'Unknown input kind or role: {row["id"]}')
        need(isinstance(row['file'], str) and FILE.fullmatch(row['file']) and row['file'].casefold() not in files, f'Unsafe or duplicate input file: {row["file"]}')
        files.add(row['file'].casefold())
        need(isinstance(row['sha256'], str) and HEX.fullmatch(row['sha256']), f'Invalid sha256: {row["id"]}')
        need(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_DOWNLOAD, f'Invalid size: {row["id"]}')
        need(isinstance(row['url'], str) and row['url'].startswith('https://') and row['url'].rsplit('/', 1)[1] == row['file'], f'Input URL must be https and name the file: {row["id"]}')
        if row['kind'] == 'wheel':
            need(row['role'] == 'build-tool', f'Wheels may only be build tools: {row["id"]}')
            need(row['file'].endswith('-py3-none-any.whl') or row['file'].endswith('-py2.py3-none-any.whl'), f'Prebuilt platform wheel refused: {row["file"]}')
        if row['role'] != 'build-tool':
            need(row['kind'] in SOURCE_KINDS, f'Shipped and packaging inputs must be source archives: {row["id"]}')
        if row['kind'] == 'sdist':
            need(row['id'] == 'sdist:' + row['package'] and row['file'].endswith('.tar.gz'), f'Invalid sdist input: {row["id"]}')
        if row['kind'] in V2_KINDS:
            need(is_v2(profile), f'Input kind {row["kind"]} needs the v2 profile schema: {row["id"]}')
        if row['kind'] == 'tool-source':
            need(row['role'] == 'build-tool' and row['file'].endswith('.tar.gz'), f'Invalid build-tool source: {row["id"]}')
        if row['kind'] in ('curl-recipe', 'curl-dep'):
            need(row['role'] == 'shipped-source', f'curl-impersonate inputs are shipped sources: {row["id"]}')
    by_id(profile, 'cpython')
    by_id(profile, 'sdist:pyinstaller')
    by_id(profile, 'tool:node')
    for recipe in profile['native']:
        need(set(recipe) == {'id', 'input', 'official_recipe', 'steps', 'products'} and by_id(profile, recipe['input'])['kind'] == 'native', 'Invalid native recipe')
        check_steps(recipe['steps'], recipe['id'])
    need({r['input'] for r in profile['native']} == {r['id'] for r in profile['inputs'] if r['kind'] == 'native'}, 'Every native input needs exactly one recipe')
    cpython = profile['cpython']
    need(set(cpython) == {'input', 'official_recipe', 'steps', 'allowed_missing_modules', 'disabled_modules', 'required_modules'} and cpython['input'] == 'cpython', 'Invalid CPython recipe')
    check_steps(cpython['steps'], 'cpython')
    packages = profile['packages']
    need(set(packages) == {'build_order', 'environment', 'native'}, 'Invalid packages section')
    sdists = {r['package'] for r in profile['inputs'] if r['kind'] == 'sdist'}
    need(sorted(packages['build_order']) == sorted(sdists) and len(set(packages['build_order'])) == len(sdists), 'build_order must list every sdist exactly once')
    need(set(packages['environment']) <= sdists and set(packages['native']) <= sdists, 'Package settings name unknown packages')
    for env in packages['environment'].values():
        need(all(re.fullmatch(r'[A-Z][A-Z0-9_]*', k) and isinstance(v, str) for k, v in env.items()), 'Invalid package environment')
    npm = profile['npm']
    need(set(npm) == {'from', 'lock', 'os', 'cpu', 'registry'} and npm['registry'].startswith('https://'), 'Invalid npm section')
    need(by_id(profile, npm['from'])['kind'] == 'sdist', 'npm lock must come from a pinned sdist')
    lock = lock_section(profile)
    need(isinstance(lock, dict) and set(lock) == {'pyproject', 'lock', 'python_version_file', 'lock_adjustments'}, 'Invalid lock section')
    need(public_inputs.relative(profile['launcher']) and all(public_inputs.relative(lock[k]) for k in ('pyproject', 'lock', 'python_version_file')), 'Invalid profile paths')
    expected = profile['expected']
    need(expected.get('version') == profile['extractor']['version'] and type(expected.get('list_extractors_lines')) is int, 'Invalid expected values')
    # CPython's _sysconfigdata is remapped to logical paths after make (neutral_sysconfigdata),
    # so no packed member may keep a build path.
    need(expected.get('build_path_members') == [], 'No packed member may record a build path: build_path_members must be empty')
    if is_v2(profile):
        check_v2_sections(profile, sdists)
    return profile


TOOL_KEYS = {'id', 'input', 'official_recipe', 'steps', 'products'}
# A tool may also install recorded relative symlinks to one of its products (pkgconf's
# pkg-config name, which pkgconf leaves to the installer).
TOOL_OPTIONAL = {'links'}
IMPERSONATE_KEYS = {'input', 'official_recipe', 'recipe_files', 'dependencies', 'patches', 'unused_patches', 'environment', 'steps', 'release', 'check', 'binding',
                    'pkg_config'}
RELEASE_KEYS = {'tool', 'archives', 'output', 'headers', 'pkgconfig'}
PKGCONFIG_KEYS = {'script', 'template', 'input', 'dependency_prefix', 'output', 'libs_private'}
BINDING_KEYS = {'package', 'build_requires', 'environment', 'native', 'linked', 'lookup_prefixes', 'curl_version'}
# Libs.private of the release pkg-config file: OS frameworks and libraries only, never a
# search path, an archive path or a bundled archive.
PRIVATE_LIB = re.compile(r'-l[A-Za-z0-9_+.-]+')
FRAMEWORK = re.compile(r'[A-Za-z][A-Za-z0-9_]*')
V2_EXPECTED = {'version', 'list_extractors_lines', 'ejs', 'build_path_members', 'request_handlers', 'optional_libraries', 'impersonate_targets', 'fixture'}
FIXTURE_ENCODINGS = {'identity', 'gzip', 'deflate', 'br', 'zstd'}


def check_v2_sections(profile, sdists):
    """Source-built tools, the curl-impersonate recipe and the curl_cffi binding."""
    tools = profile['tools']
    need(isinstance(tools, list) and tools, 'A v2 profile needs source-built tools')
    links = {}
    for recipe in tools:
        need(isinstance(recipe, dict) and TOOL_KEYS <= set(recipe) <= TOOL_KEYS | TOOL_OPTIONAL and by_id(profile, recipe['input'])['kind'] == 'tool-source',
             'Invalid tool recipe')
        check_steps(recipe['steps'], recipe['id'])
        need(isinstance(recipe['products'], list) and recipe['products'] and all(public_inputs.relative(p) for p in recipe['products']), 'Invalid tool products')
        for link, target in recipe.get('links', {}).items():
            need(public_inputs.relative(link) and isinstance(target, str) and FILE.fullmatch(target)
                 and (PurePosixPath(link).parent / target).as_posix() in recipe['products'] and link not in recipe['products'] and link not in links,
                 'A tool link must name a product of the same tool in its own directory')
            links[link] = target
    need(sorted(r['input'] for r in tools) == sorted(r['id'] for r in profile['inputs'] if r['kind'] == 'tool-source'), 'Every tool source needs exactly one recipe')
    cur = profile['impersonate']
    need(isinstance(cur, dict) and set(cur) == IMPERSONATE_KEYS, 'Invalid impersonate section')
    # pkg-config is exposed only as a recorded link of a source-built tool, by its private directory.
    pkg_dir = cur['pkg_config']
    need(isinstance(pkg_dir, str) and re.fullmatch(r'\{tools\}/[a-z0-9][a-z0-9._/-]*', pkg_dir) and pkg_dir[len('{tools}/'):] + '/pkg-config' in links
         and public_inputs.relative(pkg_dir[len('{tools}/'):]), 'pkg-config must be a recorded link of a source-built tool')
    need([r['id'] for r in profile['inputs'] if r['kind'] == 'curl-recipe'] == [cur['input']], 'Exactly one curl-impersonate recipe input is required')
    deps = cur['dependencies']
    need(isinstance(deps, list) and sorted(d.get('input', '') for d in deps) == sorted(r['id'] for r in profile['inputs'] if r['kind'] == 'curl-dep'),
         'Every curl dependency input needs exactly one recipe entry')
    for d in deps:
        need(set(d) == {'input', 'project', 'url_variable', 'hash_variable'} and re.fullmatch(r'[a-z0-9]+', d['project'])
             and re.fullmatch(r'[A-Z0-9]+_URL', d['url_variable']) and d['hash_variable'] == d['url_variable'] + '_HASH', 'Invalid curl dependency entry')
    need(len({d['project'] for d in deps}) == len(deps), 'Duplicate curl dependency project')
    for table in ('patches', 'unused_patches', 'recipe_files'):
        need(isinstance(cur[table], dict) and all(public_inputs.relative(k) and isinstance(v, str) and HEX.fullmatch(v) for k, v in cur[table].items()),
             f'Invalid {table} table')
    need(cur['patches'] and all(PurePosixPath(k).parent.as_posix() == 'patches' and k.endswith('.patch') for k in [*cur['patches'], *cur['unused_patches']]),
         'Patches must be pinned patches/*.patch files')
    need({PurePosixPath(k).stem for k in cur['patches']} <= {d['project'] for d in deps}, 'Applied patches must belong to a pinned dependency')
    need('CMakeLists.txt' in cur['recipe_files'], 'The superbuild CMakeLists.txt must be pinned')
    check_steps(cur['steps'], 'impersonate')
    # Only compiler flags that remap recorded source paths may be added to the superbuild's environment.
    need(isinstance(cur['environment'], dict) and set(cur['environment']) <= {'CFLAGS', 'CXXFLAGS'}
         and all(isinstance(v, str) and re.fullmatch(r'-ffile-prefix-map=\{superbuild\}/deps/src/=', v) for v in cur['environment'].values()),
         'The superbuild environment may only remap source paths')
    release = cur['release']
    need(isinstance(release, dict) and set(release) == RELEASE_KEYS and release['tool'] == '/usr/bin/libtool', 'Invalid release section')
    check_steps([release['archives'], [release['output'], release['headers']]], 'impersonate release')
    need(all(re.fullmatch(r'lib[A-Za-z0-9_+-]+\.a', PurePosixPath(a).name) for a in release['archives'])
         and len({PurePosixPath(a).name for a in release['archives']}) == len(release['archives']), 'Release archives must be distinct lib*.a files')
    pkgconfig = release['pkgconfig']
    need(isinstance(pkgconfig, dict) and set(pkgconfig) == PKGCONFIG_KEYS, 'Invalid release pkg-config section')
    need(pkgconfig['script'] in cur['recipe_files'] and pkgconfig['template'] in cur['recipe_files'], 'The release pkg-config script and template must be pinned recipe files')
    check_steps([[pkgconfig['input'], pkgconfig['dependency_prefix'], pkgconfig['output']]], 'impersonate release pkg-config')
    need(PurePosixPath(pkgconfig['output']).parent == PurePosixPath(release['output']).parent and PurePosixPath(pkgconfig['output']).name == 'libcurl-impersonate.pc',
         'The release pkg-config file must sit beside the release archive')
    check_private_libs(pkgconfig['libs_private'], release['archives'])
    check = cur['check']
    need(isinstance(check, dict) and set(check) == {'binary', 'version_components', 'features'} and public_inputs.relative(check['binary'])
         and all(isinstance(v, str) and v for v in check['version_components'] + check['features']), 'Invalid curl check section')
    binding = cur['binding']
    need(isinstance(binding, dict) and set(binding) == BINDING_KEYS, 'Invalid curl binding section')
    order = profile['packages']['build_order']
    need(binding['package'] in sdists and binding['package'] in profile['packages']['native'], 'The curl binding must be a native sdist package')
    need(all(p in sdists and order.index(p) < order.index(binding['package']) for p in binding['build_requires']), 'curl binding build requirements must be built first')
    need(all(re.fullmatch(r'[A-Z][A-Z0-9_]*', k) and isinstance(v, str) and set(PLACEHOLDER.findall(v)) <= PLACEHOLDERS for k, v in binding['environment'].items())
         and 'IMPERSONATE_BUILD_DIR' in binding['environment'], 'Invalid curl binding environment')
    need(isinstance(binding['native'], str) and public_inputs.relative(binding['native']) and binding['native'].endswith('.so'), 'Invalid curl binding native')
    need(binding['linked'] and all(isinstance(p, str) and SYSTEM_LIBRARY.fullmatch(p) for p in binding['linked']), 'The curl binding may link only OS libraries')
    need(binding['lookup_prefixes'] and all(isinstance(p, str) and re.fullmatch(r'_+Py', p) for p in binding['lookup_prefixes']),
         'Dynamic lookups may only be allowed for the Python C API')
    need(isinstance(binding['curl_version'], str) and binding['curl_version'], 'Invalid expected curl version')
    expected = profile['expected']
    need(set(expected) == V2_EXPECTED, 'v2 expected values differ from the schema')
    need(all(isinstance(v, str) and v for v in expected['request_handlers'] + expected['optional_libraries']), 'Invalid expected handlers or libraries')
    need(isinstance(expected['impersonate_targets'], list) and expected['impersonate_targets']
         and all(isinstance(t, list) and len(t) == 2 and all(isinstance(v, str) and v for v in t) for t in expected['impersonate_targets'])
         and len({tuple(t) for t in expected['impersonate_targets']}) == len(expected['impersonate_targets']), 'Invalid expected impersonate targets')
    need(isinstance(expected['fixture'], list) and expected['fixture']
         and all(isinstance(f, dict) and set(f) == {'target', 'encoding'} and f['encoding'] in FIXTURE_ENCODINGS for f in expected['fixture']), 'Invalid fixture cases')


def check_private_libs(tokens, archives):
    """Expected `Libs.private` of the release pkg-config file: `-framework NAME` pairs and
    `-lNAME` OS libraries only. Search paths, file paths and the bundled archives (which the
    merged release archive already holds) are refused."""
    bundled = {'curl-impersonate'} | {PurePosixPath(a).name[3:-2] for a in archives}
    need(isinstance(tokens, list) and tokens and all(isinstance(t, str) for t in tokens), 'Invalid expected Libs.private')
    at = 0
    while at < len(tokens):
        token = tokens[at]
        if token == '-framework':
            need(at + 1 < len(tokens) and FRAMEWORK.fullmatch(tokens[at + 1]), 'Libs.private may name only OS frameworks and libraries')
            at += 2
            continue
        need(PRIVATE_LIB.fullmatch(token) and token[2:] not in bundled, f'Libs.private may name only OS frameworks and libraries, not {token!r}')
        at += 1


# ---------------------------------------------------------------- legacy lock

def marker_environment(python_version):
    return {'implementation_name': 'cpython', 'platform_python_implementation': 'CPython', 'sys_platform': 'darwin',
            'platform_system': 'Darwin', 'platform_machine': 'arm64', 'os_name': 'posix', 'python_version': '.'.join(python_version.split('.')[:2]),
            'python_full_version': python_version, 'implementation_version': python_version, 'platform_release': '', 'platform_version': '', 'extra': ''}


def lock_closure(lock, roots, environment):
    from packaging.markers import Marker
    from packaging.utils import canonicalize_name
    packages = {canonicalize_name(p['name']): p for p in lock['package']}
    seen, queue = {}, list(roots)
    while queue:
        name, extras = queue.pop()
        name = canonicalize_name(name)
        need(name in packages, f'Locked package missing: {name}')
        entry = packages[name]
        rows = list(entry.get('dependencies', []))
        for extra in extras:
            need(extra in entry.get('optional-dependencies', {}), f'Locked extra missing: {name}[{extra}]')
            rows += entry['optional-dependencies'][extra]
        seen.setdefault(name, entry)
        for dep in rows:
            if dep.get('marker') and not Marker(dep['marker']).evaluate(environment):
                continue
            queue.append((dep['name'], dep.get('extra', [])))
    return seen


def lock_check(profile, repo):
    """Every runtime and packaging sdist must be the exact legacy-locked sdist,
    except explicitly declared lock adjustments."""
    import tomllib
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
    legacy = lock_section(profile)
    word = 'explicit profile' if is_v2(profile) else 'legacy'
    lock = tomllib.loads(public_inputs.regular(repo / legacy['lock']).read_text())
    project = tomllib.loads(public_inputs.regular(repo / legacy['pyproject']).read_text())['project']
    python_version = public_inputs.regular(repo / legacy['python_version_file']).read_text().strip()
    cpython = by_id(profile, 'cpython')
    need(cpython['version'] == python_version, f'CPython {cpython["version"]} differs from the {word} profile {python_version}')
    need(SpecifierSet(project['requires-python']).contains(python_version), f'CPython version is outside the {word} requires-python')
    requirements = {canonicalize_name(r.name): r for r in map(Requirement, project['dependencies'])}
    extractor = profile['extractor']
    ytdlp = requirements.get(canonicalize_name(extractor['package']))
    need(ytdlp is not None and str(ytdlp.specifier) == '==' + extractor['package_version'] and sorted(ytdlp.extras) == sorted(extractor['extras']),
         f'Extractor version or extras differ from the {word} profile')
    if is_v2(profile):
        pyinstaller = requirements.get('pyinstaller')
        need(pyinstaller is not None and str(pyinstaller.specifier) == '==' + by_id(profile, 'sdist:pyinstaller')['version'],
             'The explicit profile must pin the profile PyInstaller version directly')
    adjustments = {canonicalize_name(a['package']): a for a in legacy['lock_adjustments']}
    environment = marker_environment(python_version)
    runtime = lock_closure(lock, [(extractor['package'], extractor['extras'])], environment)
    analysis = lock_closure(lock, [('pyinstaller', [])], environment)
    used = set()

    def compare(name, entry, role):
        row = sdist_for(profile, name)
        need(row['role'] == role, f'{name} must have role {role}')
        version = entry['version']
        if name in adjustments:
            adjustment = adjustments[name]
            need(adjustment['lock_version'] == version and row['version'] == adjustment['profile_version'], f'Lock adjustment for {name} does not match')
            used.add(name)
            return {'package': name, 'lock_version': version, 'profile_version': row['version'], 'adjusted': True}
        sdist = entry.get('sdist') or {}
        need(row['version'] == version, f'{name} {row["version"]} differs from the {word} lock {version}')
        need('sha256:' + row['sha256'] == sdist.get('hash') and row['bytes'] == sdist.get('size') and sdist.get('url', '').endswith('/' + row['file']),
             f'{name} sdist differs from the {word} lock')
        return {'package': name, 'version': version, 'sha256': row['sha256'], 'adjusted': False}

    rows = [compare(n, e, 'shipped-source') for n, e in sorted(runtime.items())]
    rows.append(compare('pyinstaller', analysis.pop('pyinstaller'), 'shipped-source'))
    rows += [compare(n, e, 'packaging-source') for n, e in sorted(analysis.items()) if n not in runtime]
    declared = {canonicalize_name(r['package']) for r in profile['inputs'] if r['kind'] == 'sdist'}
    need(declared == {r['package'] for r in rows}, f'Profile sdists differ from the locked closure: {sorted(declared ^ {r["package"] for r in rows})}')
    need(used == set(adjustments), 'Unused lock adjustment')
    return {'lock_sha256': file_sha(repo / legacy['lock']), 'python_version': python_version, 'packages': rows}


# ---------------------------------------------------------------- inputs

def sdist_member(path, member_name):
    with tarfile.open(path) as archive:
        members = [m for m in archive.getmembers() if m.isfile() and len(PurePosixPath(m.name).parts) == 2 and PurePosixPath(m.name).name == member_name]
        need(len(members) == 1, f'{member_name} not found once at the root of {Path(path).name}')
        return archive.extractfile(members[0]).read()


def npm_file(name, version):
    stem = name[1:].replace('/', '__') if name.startswith('@') else name
    need(re.fullmatch(r'[a-z0-9][a-z0-9._-]*(__[a-z0-9][a-z0-9._-]*)?', stem) and re.fullmatch(r'[0-9A-Za-z.+-]+', version), f'Unsafe npm package name: {name}')
    return f'npm/{stem}-{version}.tgz'


def platform_allowed(values, actual):
    if not values:
        return True
    positive = [v for v in values if not v.startswith('!')]
    return '!' + actual not in values and (not positive or actual in positive)


def npm_requirements(profile, sources):
    spec = profile['npm']
    lock = signing.strict_json(sdist_member(Path(sources) / by_id(profile, spec['from'])['file'], spec['lock']))
    need(lock.get('lockfileVersion') == 3, 'Unsupported npm lockfile version')
    rows = {}
    for key, entry in sorted(lock['packages'].items()):
        if not key:
            continue
        need(key.startswith('node_modules/') and not entry.get('link'), f'Unsupported npm lock entry: {key}')
        if not (platform_allowed(entry.get('os'), spec['os']) and platform_allowed(entry.get('cpu'), spec['cpu'])):
            continue
        name = key.rsplit('node_modules/', 1)[1]
        need(entry.get('resolved', '').startswith(spec['registry']) and entry.get('integrity', '').startswith('sha512-'), f'npm entry must be a registry tarball with sha512 integrity: {key}')
        file = npm_file(name, entry['version'])
        row = {'name': name, 'version': entry['version'], 'file': file, 'url': entry['resolved'], 'integrity': entry['integrity'], 'install_script': bool(entry.get('hasInstallScript'))}
        need(rows.get(file, row)['integrity'] == row['integrity'], f'Conflicting npm integrity for {file}')
        rows[file] = row
    return [rows[k] for k in sorted(rows)]


def sha512_integrity(path):
    with open(path, 'rb') as stream:
        return 'sha512-' + base64.b64encode(hashlib.file_digest(stream, 'sha512').digest()).decode()


def check_sources(profile, sources, npm):
    """The sources directory must contain exactly the pinned inputs, byte for byte."""
    sources = signing.no_link_ancestors(sources)
    need(sources.is_dir(), f'Sources directory does not exist: {sources}')
    expected = {row['file']: row for row in profile['inputs']}
    expected.update({row['file']: row for row in npm})
    actual = set()
    for parent, dirs, names in os.walk(sources, followlinks=False):
        here = Path(parent)
        for name in dirs:
            need(not (here / name).is_symlink(), f'Symlink in sources: {here / name}')
            need((here / name).relative_to(sources).as_posix() == 'npm', f'Unexpected directory in sources: {name}')
        for name in names:
            path = here / name
            need(stat.S_ISREG(path.lstat().st_mode), f'Sources entries must be regular files: {path}')
            actual.add(path.relative_to(sources).as_posix())
    need(actual == set(expected), f'Sources differ from the pinned inputs: missing {sorted(set(expected) - actual)[:5]}, unexpected {sorted(actual - set(expected))[:5]}')
    rows = []
    for row in profile['inputs']:
        found = identity(sources / row['file'])
        need(found == {'bytes': row['bytes'], 'sha256': row['sha256']}, f'Input digest or size mismatch: {row["file"]}')
        rows.append({'id': row['id'], 'file': row['file'], **found})
    npm_rows = []
    for row in npm:
        need(sha512_integrity(sources / row['file']) == row['integrity'], f'npm integrity mismatch: {row["file"]}')
        npm_rows.append({'file': row['file'], 'integrity': row['integrity'], **identity(sources / row['file'])})
    return rows, npm_rows


def download(url, target, limit, expected_sha256=None):
    need(url.startswith('https://'), 'Only https downloads are permitted')
    digest = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=120) as response, open(target, 'xb') as stream:
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            need(total <= limit, f'Download exceeds its pinned size: {url}')
            digest.update(chunk)
            stream.write(chunk)
    if expected_sha256:
        need(digest.hexdigest() == expected_sha256, f'Downloaded digest mismatch: {url}')


def retained_index(retained):
    """Retained regular files by file name and by size. Retained materials may name an
    archive differently (for example with a recipe-variable prefix); a size match is
    only a candidate, and every candidate must still match the pinned digest."""
    index = {}
    for root in retained:
        root = signing.no_link_ancestors(root)
        need(root.is_dir(), f'Retained directory does not exist: {root}')
        for parent, _, names in os.walk(root, followlinks=False):
            for name in names:
                path = Path(parent) / name
                if path.is_file() and not path.is_symlink():
                    index.setdefault(name, []).append(path)
                    index.setdefault(('size', path.stat().st_size), []).append(path)
    return index


def fetch(repo, output, retained=(), downloader=download, profile_rel=PROFILE_REL):
    """Copy pinned inputs from retained directories (by digest) or download them."""
    need(profile_rel in PROFILES, f'Unknown profile: {profile_rel}')
    profile = load_profile(repo / profile_rel)
    output = new_output_directory(output, [repo])
    index = retained_index(retained)
    report = {'schema': 'omd-ytdlp-source-fetch-v1', 'profile_file': profile_rel, 'inputs': [], 'npm': []}

    def obtain(file, url, size_limit, check, record, size=None):
        target = output / file
        target.parent.mkdir(exist_ok=True)
        candidates = index.get(PurePosixPath(file).name, []) + (index.get(('size', size), []) if size else [])
        for candidate in candidates:
            if check(candidate):
                shutil.copyfile(candidate, target)
                need(check(target), f'Copy changed: {file}')
                record.append({'file': file, 'origin': 'retained'})
                return
        partial = output / (file + '.part')
        downloader(url, partial, size_limit)
        need(check(partial), f'Downloaded input does not match its pin: {file}')
        partial.rename(target)
        record.append({'file': file, 'origin': 'download', 'url': url})

    for row in profile['inputs']:
        want = {'bytes': row['bytes'], 'sha256': row['sha256']}
        obtain(row['file'], row['url'], row['bytes'], lambda p, want=want: identity(p) == want, report['inputs'], row['bytes'])
    for row in npm_requirements(profile, output):
        obtain(row['file'], row['url'], MAX_DOWNLOAD, lambda p, row=row: sha512_integrity(p) == row['integrity'], report['npm'])
    check_sources(profile, output, npm_requirements(profile, output))
    return report


# ---------------------------------------------------------------- toolchain and plan

def host_env():
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': os.environ.get('HOME', '/var/empty')}


def command_output(*argv, stderr=False):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120, env=host_env())
    need(result.returncode == 0, f'Toolchain query failed: {argv[0]}')
    return (result.stderr if stderr else result.stdout).strip()


def toolchain(curl=False):
    """Portable toolchain identity (no host paths) and the private paths used to build."""
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'An arm64 macOS build host is required')
    sdk = command_output('/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path')
    developer = command_output('/usr/bin/xcode-select', '-p')
    settings = Path(sdk) / 'SDKSettings.json'
    need(settings.is_file(), 'The macOS SDK has no SDKSettings.json')
    portable = {
        'host_arch': platform.machine(),
        'macos': command_output('/usr/bin/sw_vers', '-productVersion'),
        'macos_build': command_output('/usr/bin/sw_vers', '-buildVersion'),
        'xcode': command_output('/usr/bin/xcodebuild', '-version').splitlines(),
        'sdk_version': command_output('/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'),
        'sdk_build': command_output('/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-build-version'),
        'sdk_settings_sha256': file_sha(settings),
        'clang': command_output('/usr/bin/clang', '--version').splitlines()[0],
        'ld': command_output('/usr/bin/ld', '-v', stderr=True).splitlines()[0],
        'make': command_output('/usr/bin/make', '--version').splitlines()[0],
        'perl': command_output('/usr/bin/perl', '-e', 'print $^V'),
    }
    if curl:
        # Host tools the curl-impersonate route uses directly: the recipe's PATCH_EXE, the
        # release-archive merge, the linkage audit and the fixture's throwaway certificates.
        portable.update({'patch': command_output('/usr/bin/patch', '--version').splitlines()[0],
                         'libtool': command_output('/usr/bin/libtool', '-V').splitlines()[0],
                         'nm': command_output('/usr/bin/nm', '--version').splitlines()[0],
                         'openssl': command_output('/usr/bin/openssl', 'version')})
    return portable, {'sdk': sdk, 'developer_dir': developer}


def profile_files(profile_rel, profile):
    lock = lock_section(profile)
    return [profile_rel, profile['launcher'], lock['pyproject'], lock['lock'], lock['python_version_file']]


def plan_files(repo, profile_rel=PROFILE_REL, profile=None):
    profile = profile or load_profile(repo / profile_rel)
    files = {f'engine/{rel}': file_sha(public_inputs.regular(repo / rel)) for rel in profile_files(profile_rel, profile)}
    files.update({f'engine/scripts/{name}': file_sha(public_inputs.regular(SCRIPTS / name)) for name in TOOLING})
    return dict(sorted(files.items()))


def archive_files(archive, wanted=None, prefix=None):
    """Regular members of a one-directory source tarball, keyed by path below that directory.
    With `wanted`, only those paths are read; with `prefix`, every member below it is listed."""
    found, tops = {}, set()
    with tarfile.open(archive) as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if not parts or member.name in ('.', './'):
                continue
            tops.add(parts[0])
            rel = '/'.join(parts[1:])
            if member.isfile() and rel and ((wanted is not None and rel in wanted) or (prefix and rel.startswith(prefix))):
                need(rel not in found, f'Duplicate archive member: {rel}')
                found[rel] = tar.extractfile(member).read()
    need(len(tops) == 1, f'{Path(archive).name} must have one top-level directory')
    return found


def cmake_variables(text):
    """Plain `set(NAME "value")` assignments of the superbuild, with ${NAME} expanded."""
    values = dict(re.findall(r'^set\((\w+) "([^"$]*(?:\$\{\w+\}[^"$]*)*)"\)\s*$', text, re.M))
    for _ in range(4):
        values = {k: re.sub(r'\$\{(\w+)\}', lambda m: values.get(m.group(1), m.group(0)), v) for k, v in values.items()}
    return values


def recipe_check(profile, sources):
    """The pinned curl-impersonate recipe, read from its immutable archive: pinned recipe files
    and patches by SHA-256, no other patch file, and every dependency URL and URL_HASH the
    superbuild declares equal to a pinned input. A recipe that adds, drops or re-pins a
    dependency or patch is refused."""
    cur = profile['impersonate']
    row = by_id(profile, cur['input'])
    archive = Path(sources) / row['file']
    need(identity(archive) == {'bytes': row['bytes'], 'sha256': row['sha256']}, 'curl-impersonate recipe archive differs from its pin')
    pinned = {**cur['recipe_files'], **cur['patches'], **cur['unused_patches']}
    files = archive_files(archive, set(pinned), 'patches/')
    for rel, digest in pinned.items():
        need(rel in files and sha(files[rel]) == digest, f'curl-impersonate recipe file differs from its pin: {rel}')
    present = {rel for rel in files if rel.startswith('patches/')}
    need(present == set(cur['patches']) | set(cur['unused_patches']), f'Unpinned curl-impersonate patch files: {sorted(present ^ (set(cur["patches"]) | set(cur["unused_patches"])))}')
    cmake = files['CMakeLists.txt'].decode()
    variables = cmake_variables(cmake)
    declared = sorted(k[:-len('_URL_HASH')] for k in variables if k.endswith('_URL_HASH'))
    need(declared == sorted(d['url_variable'][:-len('_URL')] for d in cur['dependencies']), f'Superbuild dependencies differ from the profile: {declared}')
    dependencies = []
    for d in sorted(cur['dependencies'], key=lambda d: d['project']):
        dep = by_id(profile, d['input'])
        need(variables.get(d['url_variable']) == dep['url'], f'{d["project"]}: the recipe URL differs from the pinned input')
        need(variables.get(d['hash_variable']) == 'SHA256=' + dep['sha256'], f'{d["project"]}: the recipe URL_HASH differs from the pinned input')
        need(re.search(r'ExternalProject_Add\(' + d['project'] + r'\s', cmake), f'{d["project"]}: no ExternalProject in the recipe')
        dependencies.append({'project': d['project'], 'input': d['input'], 'file': dep['file'], 'sha256': dep['sha256'], 'url': dep['url']})
    tracked = sorted(set(re.findall(r'_track_external_project_patch\(\s*(\w+)', cmake)))
    need(tracked == sorted(PurePosixPath(k).stem for k in cur['patches']), f'Patched projects differ from the pinned patches: {tracked}')
    patches = {rel: {'sha256': cur['patches'][rel], 'files': len(re.findall(rb'^diff --git ', files[rel], re.M))} for rel in sorted(cur['patches'])}
    need(all(v['files'] for v in patches.values()), 'A pinned patch has no file sections')
    return {'recipe': {'input': row['id'], 'file': row['file'], 'sha256': row['sha256']}, 'recipe_files': dict(sorted(cur['recipe_files'].items())),
            'patches': patches, 'unused_patches': dict(sorted(cur['unused_patches'].items())), 'dependencies': dependencies}


def make_plan(repo, sources, profile_rel=PROFILE_REL):
    repo = Path(os.path.abspath(repo))
    need(profile_rel in PROFILES, f'Unknown profile: {profile_rel}')
    profile = load_profile(repo / profile_rel)
    need(profile['launcher'] == 'distribution/yt-dlp-source/launcher.py', 'Unexpected launcher path')
    lock = lock_check(profile, repo)
    npm = npm_requirements(profile, sources)
    inputs, npm_rows = check_sources(profile, sources, npm)
    portable, _ = toolchain(is_v2(profile))
    plan = {'schema': PLAN_SCHEMA, 'profile': profile['id'], 'profile_file': profile_rel, 'profile_sha256': file_sha(repo / profile_rel),
            'release_accepted': False, 'promotable': False, 'target': profile['target'], 'files': plan_files(repo, profile_rel, profile), 'lock': lock,
            'inputs': inputs, 'npm': npm_rows, 'toolchain': portable, 'status': 'ready'}
    if is_v2(profile):
        plan['impersonate'] = recipe_check(profile, sources)
    return plan


def plan_profile(plan):
    """The known profile a plan names (plans without a name predate v2 and mean the v1 profile)."""
    rel = plan.get('profile_file', PROFILE_REL)
    need(rel in PROFILES, f'Plan names an unknown profile: {rel}')
    return rel


def check_plan(plan_path, repo, sources):
    plan = strict_load(public_inputs.regular(plan_path))
    need(isinstance(plan, dict) and plan.get('schema') == PLAN_SCHEMA, 'Not a source-build plan')
    current = make_plan(repo, sources, plan_profile(plan))
    if canonical(plan) != canonical(current):
        changed = sorted(k for k in set(plan) | set(current) if canonical(plan.get(k)) != canonical(current.get(k)))
        raise Stale(f'Stale plan: re-run plan ({", ".join(changed)} changed)')
    return plan


# ---------------------------------------------------------------- Mach-O facts

def thin_images(data):
    return [data[off:off + length] for off, length in signing.slice_regions(data)]


def macho_facts(data):
    """Architecture, deployment and linkage facts of every slice."""
    facts = []
    for image in thin_images(data):
        endian, cpu, subtype, filetype, commands = signing.load_commands(image)
        row = {'cpu': cpu, 'subtype': subtype & 0xffffff, 'filetype': filetype, 'dylibs': [], 'rpaths': [], 'id': None, 'sdk': None}
        for cmd, off, size in commands:
            if cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0xd):  # LOAD/WEAK/REEXPORT/LAZY dylib, ID
                name_off, = struct.unpack_from(endian + 'I', image, off + 8)
                name = image[off + name_off:off + size].split(b'\0', 1)[0].decode('utf-8')
                if cmd == 0xd:
                    row['id'] = name
                else:
                    row['dylibs'].append(name)
            elif cmd == 0x8000001c:
                name_off, = struct.unpack_from(endian + 'I', image, off + 8)
                row['rpaths'].append(image[off + name_off:off + size].split(b'\0', 1)[0].decode('utf-8'))
            elif cmd == 0x32:
                _, minimum, sdk, _ = struct.unpack_from(endian + 'IIII', image, off + 8)
                row['minimum'] = f'{minimum >> 16}.{(minimum >> 8) & 255}.{minimum & 255}'
                row['sdk'] = f'{sdk >> 16}.{(sdk >> 8) & 255}.{sdk & 255}'
        facts.append(row)
    return facts


def check_target_macho(data, name, minimum):
    """Exactly one arm64 macOS slice whose deployment minimum does not exceed the profile's."""
    slices = payload.slices(data)
    need(len(slices) == 1 and slices[0]['cpu'] == CPU_ARM64 and slices[0]['subtype'] & 0xffffff == 0, f'{name}: must be a thin arm64 Mach-O')
    need(slices[0]['platform'] == 1, f'{name}: not a macOS Mach-O')
    need(version_tuple(slices[0]['minimum']) <= version_tuple(minimum),
         f'{name}: requires macOS {slices[0]["minimum"]}, above the profile minimum {minimum}; raise the profile minimum explicitly')
    return slices[0]['minimum']


def check_linkage(facts, name, allowed_prefixes):
    for row in facts:
        for dylib in row['dylibs']:
            ok = SYSTEM_LIBRARY.fullmatch(dylib) or any(dylib.startswith(p) for p in allowed_prefixes)
            need(ok, f'{name}: links outside the OS and the bundle: {dylib}')
            need('/opt/homebrew' not in dylib and not dylib.startswith('/usr/local'), f'{name}: links a package-manager library: {dylib}')
        for rpath in row['rpaths']:
            need(rpath.startswith(('@loader_path', '@executable_path')), f'{name}: non-relative LC_RPATH {rpath}')


# ---------------------------------------------------------------- Mach-O structure and PyInstaller policies

MH_MAGIC_64 = b'\xcf\xfa\xed\xfe'
LC_SYMTAB, LC_DYSYMTAB, LC_ID_DYLIB, LC_LOAD_DYLINKER, LC_SEGMENT_64, LC_UUID, LC_CODE_SIGNATURE = 0x2, 0xb, 0xd, 0xe, 0x19, 0x1b, 0x1d
LC_BUILD_VERSION, LC_RPATH, LC_DYLD_INFO_ONLY = 0x32, 0x8000001c, 0x80000022
# The only load commands accepted in packed natives, the bootloader and the executable.
LOAD_COMMANDS = {
    0x19: 'LC_SEGMENT_64', 0x2: 'LC_SYMTAB', 0xb: 'LC_DYSYMTAB', 0xe: 'LC_LOAD_DYLINKER', 0x1b: 'LC_UUID', 0x32: 'LC_BUILD_VERSION',
    0x2a: 'LC_SOURCE_VERSION', 0x80000028: 'LC_MAIN', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB', 0x80000018: 'LC_LOAD_WEAK_DYLIB',
    0x8000001f: 'LC_REEXPORT_DYLIB', 0x80000023: 'LC_LOAD_UPWARD_DYLIB', 0x8000001c: 'LC_RPATH', 0x26: 'LC_FUNCTION_STARTS',
    0x29: 'LC_DATA_IN_CODE', 0x1d: 'LC_CODE_SIGNATURE', 0x80000022: 'LC_DYLD_INFO_ONLY', 0x80000034: 'LC_DYLD_CHAINED_FIXUPS',
    0x80000033: 'LC_DYLD_EXPORTS_TRIE'}
DYLIB_COMMANDS = {0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023}
# PyInstaller osx._set_dylib_dependency_paths _RELOCATABLE; LC_PREBOUND_DYLIB is refused above.
RELOCATABLE = {0xc, 0x80000018, 0x8000001f, 0x80000023}
STRING_MINIMUM = {**{c: 24 for c in DYLIB_COMMANDS}, LC_RPATH: 12, LC_LOAD_DYLINKER: 12}
LINKEDIT_DATA = {0x1d, 0x26, 0x29, 0x80000034, 0x80000033}
FIXED_SIZES = {0x2: 24, 0xb: 80, 0x1b: 24, 0x2a: 16, 0x80000028: 24, 0x80000022: 48, **{c: 16 for c in LINKEDIT_DATA}}
# (offset field, count or size field, entry size; 0 = byte size) pairs inside __LINKEDIT.
LINKEDIT_RANGES = {LC_DYSYMTAB: [(32, 36, 8), (40, 44, 56), (48, 52, 4), (56, 60, 4), (64, 68, 8), (72, 76, 8)],
                   LC_DYLD_INFO_ONLY: [(8, 12, 0), (16, 20, 0), (24, 28, 0), (32, 36, 0), (40, 44, 0)],
                   LC_SYMTAB: [(8, 12, 16), (16, 20, 0)]}
ZEROFILL = {0x1, 0xc, 0x12}
MAX_LOAD_COMMANDS = 1024
TCLTK_EXEMPT = ('/Library/Frameworks/Tcl.framework/', '/Library/Frameworks/Tk.framework/')


def command_string(raw, minimum, what):
    """A load command string: in bounds, NUL-terminated, zero padded, UTF-8."""
    offset, = struct.unpack_from('<I', raw, 8)
    need(minimum <= offset < len(raw), f'{what}: string offset outside its load command')
    end = raw.find(b'\0', offset)
    need(end >= 0 and not any(raw[end:]), f'{what}: unterminated string or nonzero load command padding')
    try:
        return raw[offset:end].decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError(f'{what}: invalid load command string') from error


def macho_structure(image, name):
    """Strict structure of one thin little-endian 64-bit Mach-O image.

    Every load command must be in LOAD_COMMANDS and fully decoded. Strings and the
    padding after the load commands must be clean. Segments, sections, link-edit data
    and the code signature must lie in bounds, and __LINKEDIT and the signature must end
    the image. Unknown commands or stray bytes fail closed."""
    need(len(image) >= 32 and image[:4] == MH_MAGIC_64, f'{name}: not a thin 64-bit Mach-O image')
    cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from('<IIIIIII', image, 4)
    end = 32 + sizeofcmds
    need(ncmds <= MAX_LOAD_COMMANDS and end <= len(image), f'{name}: load commands exceed the image')
    commands, segments, starts, at = [], [], [], 32
    for _ in range(ncmds):
        need(at + 8 <= end, f'{name}: truncated load command')
        cmd, size = struct.unpack_from('<II', image, at)
        need(cmd in LOAD_COMMANDS, f'{name}: unknown or unsupported load command 0x{cmd:x}')
        label = LOAD_COMMANDS[cmd]
        need(size >= 8 and size % 8 == 0 and at + size <= end, f'{name}: invalid {label} size')
        need(size == FIXED_SIZES.get(cmd, size), f'{name}: unexpected {label} size')
        raw = image[at:at + size]
        row = {'cmd': cmd, 'name': label, 'raw': raw, 'offset': at}
        if cmd in STRING_MINIMUM:
            need(size >= STRING_MINIMUM[cmd], f'{name}: truncated {label}')
            row['path'] = command_string(raw, STRING_MINIMUM[cmd], f'{name} {label}')
            if cmd in DYLIB_COMMANDS:
                row['dylib'] = struct.unpack_from('<III', raw, 12)
        elif cmd == LC_BUILD_VERSION:
            need(size >= 24 and size == 24 + 8 * struct.unpack_from('<I', raw, 20)[0], f'{name}: invalid LC_BUILD_VERSION')
        elif cmd == LC_SEGMENT_64:
            need(size >= 72, f'{name}: truncated LC_SEGMENT_64')
            segname = raw[8:24].rstrip(b'\0')
            need(not any(raw[8 + len(segname):24]), f'{name}: segment name padding is not zero')
            _, vmsize, fileoff, filesize, _, _, nsects, _ = struct.unpack_from('<QQQQiiII', raw, 24)
            need(size == 72 + 80 * nsects and fileoff + filesize <= len(image) and filesize <= vmsize, f'{name}: invalid segment {segname!r}')
            row['segment'] = segname.decode('ascii', 'replace')
            segments.append({'name': row['segment'], 'fileoff': fileoff, 'filesize': filesize, 'vmsize': vmsize, 'row': row})
            for i in range(nsects):
                section = raw[72 + 80 * i:152 + 80 * i]
                need(section[16:32].rstrip(b'\0') == segname, f'{name}: section outside its segment command')
                _, length, offset, _, reloff, nreloc, sflags = struct.unpack_from('<QQIIIII', section, 32)
                need(reloff == 0 and nreloc == 0, f'{name}: relocation entries in a linked image')
                if (sflags & 0xff) not in ZEROFILL and length:
                    need(fileoff <= offset and offset + length <= fileoff + filesize, f'{name}: section outside its segment')
                    starts.append(offset)
        commands.append(row)
        at += size
    need(at == end, f'{name}: load command sizes differ from sizeofcmds')
    linkedit = [s for s in segments if s['name'] == '__LINKEDIT']
    need(len(linkedit) == 1 and linkedit[0]['fileoff'] + linkedit[0]['filesize'] == len(image), f'{name}: __LINKEDIT must be unique and end the image')
    low = linkedit[0]['fileoff']
    signature, data_end = None, low
    for row in commands:
        for off_at, count_at, unit in ([(8, 12, 0)] if row['cmd'] in LINKEDIT_DATA else LINKEDIT_RANGES.get(row['cmd'], [])):
            offset, count = struct.unpack_from('<II', row['raw'], off_at)[0], struct.unpack_from('<I', row['raw'], count_at)[0]
            if count:
                need(low <= offset and offset + count * (unit or 1) <= len(image), f'{name}: {row["name"]} data outside __LINKEDIT')
                if row['cmd'] != LC_CODE_SIGNATURE:
                    data_end = max(data_end, offset + count * (unit or 1))
        if row['cmd'] == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from('<II', row['raw'], 8)
            need(signature is None and datasize and dataoff + datasize == len(image), f'{name}: the code signature must be unique and end the image')
            signature = (dataoff, datasize)
    need(starts, f'{name}: no file-backed sections')
    content = min(starts)
    need(content >= end and not any(image[end:content]), f'{name}: nonzero bytes between the load commands and the first section')
    return {'header': (cpu, subtype, filetype, flags, reserved), 'commands': commands, 'segments': segments, 'linkedit': linkedit[0],
            'signature': signature, 'content_start': content, 'commands_end': end, 'linkedit_data_end': data_end}


def command_record(row, structure):
    """Comparable value of one load command; the __LINKEDIT sizes and the code signature
    size depend on the signature and are validated separately."""
    if 'dylib' in row:
        return ('dylib', row['cmd'], *row['dylib'], row['path'])
    if 'path' in row:
        return ('string', row['cmd'], row['path'])
    if row['cmd'] == LC_CODE_SIGNATURE:
        return ('signature',)
    if row is structure['linkedit']['row']:
        masked = bytearray(row['raw'])
        masked[32:40] = masked[48:56] = bytes(8)
        return ('linkedit', bytes(masked))
    return ('raw', row['raw'])


def system_library(path):
    """PyInstaller's in_system_path (macholib 1.16.4) without the host realpath:
    /usr/ and /System/, except /usr/local/. The byte-identical replay covers the host."""
    return path.startswith(('/usr/', '/System/')) and not path.startswith('/usr/local/')


def linkedit_vmsize_ok(cpu, before, after):
    pages = signing.LINKEDIT_PAGES.get(cpu, (0x1000, 0x4000))
    return after['vmsize'] in {before['vmsize']} | {-(-after['filesize'] // page) * page for page in pages}


def relocation_policy(product, packed, dest_name):
    """Independent check of PyInstaller 6.22.0 onefile binary processing
    (process_collected_binary: set_dylib_dependency_paths, then sign_binary) against
    the recorded build product. The install name and non-system dependency paths may
    become @rpath/<basename>. LC_RPATH entries other than the target are removed, and
    the target is appended when needed. The code signature and the __LINKEDIT sizes
    may change with it. Everything else must be identical: header, every other load
    command, and every byte from the first section to the signature."""
    a, b = macho_structure(product, f'{dest_name} (build product)'), macho_structure(packed, dest_name)
    need(a['header'] == b['header'], f'{dest_name}: Mach-O header differs from the build product')
    target_rpath = str(PurePosixPath('@loader_path', *['..' for _ in PurePosixPath(dest_name).parent.parts]))
    rpaths = [r['path'] for r in a['commands'] if r['cmd'] == LC_RPATH]
    required = False
    expected, changes = [], []
    for row in a['commands']:
        record = command_record(row, a)
        if row['cmd'] == LC_ID_DYLIB:
            new = str(PurePosixPath('@rpath') / PurePosixPath(row['path']).name)
            record = record[:-1] + (new,)
            if new != row['path']:
                changes.append({'command': 'LC_ID_DYLIB', 'from': row['path'], 'to': new})
        elif row['cmd'] in RELOCATABLE:
            if not system_library(row['path']) and not any(x in row['path'] for x in TCLTK_EXEMPT):
                required = True
                new = str(PurePosixPath('@rpath') / PurePosixPath(row['path']).name)
                record = record[:-1] + (new,)
                if new != row['path']:
                    changes.append({'command': row['name'], 'from': row['path'], 'to': new})
        elif row['cmd'] == LC_RPATH and row['path'] != target_rpath:
            changes.append({'command': 'LC_RPATH', 'from': row['path'], 'to': None})
            continue
        expected.append(record)
    if required and target_rpath not in rpaths:
        expected.append(('string', LC_RPATH, target_rpath))
        changes.append({'command': 'LC_RPATH', 'from': None, 'to': target_rpath})
    if a['signature'] is None:
        expected.append(('signature',))
    actual = [command_record(r, b) for r in b['commands']]
    if actual != expected:
        index = next((i for i, (x, y) in enumerate(zip(expected, actual)) if x != y), min(len(expected), len(actual)))
        raise Refused(f'{dest_name}: load commands differ from the build product beyond the PyInstaller relocation (command {index})')
    need(b['signature'] is not None, f'{dest_name}: packed native is unsigned')
    end = a['signature'][0] if a['signature'] else len(product)
    need(a['content_start'] == b['content_start'] and (a['signature'] is None or b['signature'][0] == end),
         f'{dest_name}: section or signature placement differs from the build product')
    need(product[a['content_start']:end] == packed[b['content_start']:b['signature'][0]], f'{dest_name}: section, data or link-edit bytes differ from the build product')
    need(linkedit_vmsize_ok(b['header'][0], a['linkedit'], b['linkedit']), f'{dest_name}: __LINKEDIT vmsize changed beyond page-rounded signature growth')
    return {'changes': changes, 'commands': len(b['commands']), 'compared_bytes': end - a['content_start'], 'signature_offset': b['signature'][0]}


def onefile_policy(exe, bootloader, start, end, python_library):
    """Independent check of PyInstaller 6.22.0's macOS onefile assembly against the
    compiled bootloader. The reviewed extractor's bootloader_view masks only the
    PKG-derived LC_UUID, LC_SYMTAB strsize and signature offset, plus the
    signature-sized fields, and cuts the PKG. Everything else must be byte-identical,
    with the SDK rule applied. The masked values are then derived from the PKG."""
    b, e = macho_structure(bootloader, 'compiled bootloader'), macho_structure(exe, 'executable')
    need(b['signature'] is not None, 'The compiled bootloader must carry its linker signature')
    # codesign --remove (remove_signature_from_binary) truncates to the end of the last
    # non-signature link-edit data; only zero alignment padding may be dropped.
    base = b['linkedit_data_end']
    need(base <= b['signature'][0] and not any(bootloader[base:b['signature'][0]]), 'Unexpected bytes before the bootloader signature')
    need(start == base and start < end <= e['signature'][0], 'The PKG must start where the unsigned bootloader ends and precede the signature')
    expected = bytearray(extractor.bootloader_view(bootloader, (base, base)))
    pylib, boot_sdk = extractor.sdk_of(python_library), extractor.sdk_of(bootloader)
    rewritten = pylib < boot_sdk
    if rewritten:
        version = next(r for r in b['commands'] if r['cmd'] == LC_BUILD_VERSION)
        struct.pack_into('<I', expected, version['offset'] + 16, pylib[0] << 16 | pylib[1] << 8 | pylib[2])
    view = extractor.bootloader_view(exe, (start, end))
    need(bytes(expected) == view, 'Executable header, load commands or bootloader bytes differ from the compiled bootloader beyond the PyInstaller onefile fields')
    need(extractor.uuid_of(exe) == extractor.pkg_uuid(exe[start:end], extractor.uuid_of(bootloader)), "LC_UUID is not PyInstaller's PKG-derived UUID for the compiled bootloader")
    symtab = next(r for r in e['commands'] if r['cmd'] == LC_SYMTAB)
    stroff, strsize = struct.unpack_from('<II', symtab['raw'], 16)
    need(stroff <= start and stroff + strsize == end, 'The LC_SYMTAB string table must end exactly at the PKG (fix_exe_for_code_signing)')
    sig = e['signature'][0]
    need(sig % extractor.SIGNATURE_ALIGN == 0 and sig - end < extractor.SIGNATURE_ALIGN and not any(exe[end:sig]), 'Unexpected bytes between the PKG and the code signature')
    need(linkedit_vmsize_ok(e['header'][0], {'vmsize': -1}, e['linkedit']), '__LINKEDIT vmsize is not its page-rounded file size')
    return {'compared_bytes': len(view), 'view_sha256': sha(view), 'uuid': extractor.uuid_of(exe).hex(), 'bootloader_uuid': extractor.uuid_of(bootloader).hex(),
            'sdk': {'python_library': list(pylib), 'bootloader': list(boot_sdk), 'rewritten': rewritten}, 'signature_padding': sig - end}


def is_macho_file(path):
    with open(path, 'rb') as stream:
        return signing.is_macho(stream.read(4))


# ---------------------------------------------------------------- wheels

def wheel_platform(minimum):
    """Wheel tags for macOS 11 and later name only the major version; the natives'
    actual minimum is checked separately."""
    major, minor, _ = version_tuple(minimum)
    return f'macosx_{major}_0_arm64' if major >= 11 else f'macosx_{major}_{minor}_arm64'


def wheel_facts(path, package, version, native_expected, minimum):
    """A locally built wheel: exact name/version, allowed tags, and only target natives."""
    from packaging.utils import canonicalize_name, parse_wheel_filename
    name, wheel_version, _, tags = parse_wheel_filename(Path(path).name)
    need(name == canonicalize_name(package) and str(wheel_version) == str(type(wheel_version)(version)), f'Wheel name or version differs: {Path(path).name}')
    platforms = {t.platform for t in tags}
    expected_platform = wheel_platform(minimum)
    need(len(platforms) == 1 and platforms <= {'any', expected_platform}, f'Wheel tag is not this build target: {Path(path).name}')
    natives, files = [], {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            public_inputs.relative(info.filename)
            data = archive.read(info)
            files[info.filename] = sha(data)
            if signing.is_macho(data[:4]):
                need(installed_path(info.filename) is not None, f'Native code outside the import tree: {Path(path).name}!{info.filename}')
                found = check_target_macho(data, f'{Path(path).name}!{info.filename}', minimum)
                natives.append({'path': info.filename, 'sha256': sha(data), 'bytes': len(data), 'minimum': found})
    if native_expected:
        need(natives, f'{package} was expected to contain native code but has none')
    else:
        need(not natives and platforms == {'any'}, f'{package} must be pure Python; refusing native or platform content')
    return {'file': Path(path).name, 'sha256': file_sha(path), 'bytes': Path(path).stat().st_size, 'tags': sorted(str(t) for t in tags), 'natives': natives}, files


PIP_ADDED = ('INSTALLER', 'REQUESTED', 'direct_url.json', 'RECORD')


def check_installed(site_packages, wheels):
    """Every installed file comes from a built wheel (natives byte-identical);
    pip may add only byte-compiled files and its own dist-info records."""
    site_packages = Path(site_packages)
    expected, outside = {}, 0
    for files in wheels.values():
        for rel, digest in files.items():
            installed = installed_path(rel)
            if installed is None:
                outside += 1
                continue
            need(installed not in expected, f'Two wheels install the same path: {installed}')
            expected[installed] = digest
    dists = {p.name for p in site_packages.iterdir() if p.name.endswith('.dist-info')}
    wheel_dists = set()
    for package, files in wheels.items():
        tops = {r.split('/', 1)[0] for r in files if r.split('/', 1)[0].endswith('.dist-info')}
        need(len(tops) == 1, f'{package} wheel must have exactly one top-level .dist-info')
        wheel_dists |= tops
    need(dists == wheel_dists, f'Installed distributions differ from the built wheels: {sorted(dists ^ wheel_dists)}')
    recorded = set()
    for dist in dists:
        for line in (site_packages / dist / 'RECORD').read_text().splitlines():
            if line:
                recorded.add(line.split(',', 1)[0])
    seen = set()
    for parent, dirs, names in os.walk(site_packages, followlinks=False):
        for name in names:
            path = Path(parent) / name
            rel = path.relative_to(site_packages).as_posix()
            need(stat.S_ISREG(path.lstat().st_mode), f'Unexpected installed entry: {rel}')
            need(rel in recorded, f'Installed file is not recorded by any built wheel: {rel}')
            if rel in expected and not rel.endswith('.dist-info/RECORD'):
                need(file_sha(path) == expected[rel], f'Installed file differs from its built wheel: {rel}')
            else:
                need(rel.endswith('.pyc') and '/__pycache__/' in '/' + rel or rel.rsplit('/', 1)[-1] in PIP_ADDED,
                     f'Installed file is not part of any built wheel: {rel}')
                need(not is_macho_file(path), f'Unknown native in the installed environment: {rel}')
            seen.add(rel)
    missing = {r for r in expected if not r.endswith('.dist-info/RECORD')} - seen
    need(not missing, f'Built wheel files missing after install: {sorted(missing)[:5]}')
    return {'distributions': sorted(dists), 'files': len(seen), 'wheel_data_files_outside_site_packages': outside}


def installed_path(rel):
    """Where a wheel member lands relative to site-packages; None for .data/ scheme
    entries (scripts, data, headers) that install outside it."""
    parts = rel.split('/')
    if parts[0].endswith('.data') and len(parts) > 2:
        return '/'.join(parts[2:]) if parts[1] in ('purelib', 'platlib') else None
    return rel


# ---------------------------------------------------------------- packed Python code

REPLAY = SCRIPTS / 'ytdlp_source_replay.py'
REPLAY_SCHEMA = 'omd-ytdlp-source-replay-v1'
PROOF_SCHEMA = 'omd-ytdlp-source-closure-proof-v2'
FINGERPRINTS = 'closure-fingerprints.json'
FINGERPRINTS_SCHEMA = 'omd-ytdlp-source-fingerprints-v1'
# PyInstaller 6.22.0 sources whose functions the replay calls or whose steps it
# transcribes (sdist and wheel bytes). The build refuses a PyInstaller whose files differ.
PYINSTALLER_REPLAYED = {
    'building/api.py': '4abd2fc48433dbe0a10233e7776ae9f73d05b2d1b89d829e6c2f062c3aa318f1',
    'building/build_main.py': '701c95d373196018ed99a22d2ba3f184b3252fa8b440f36ed966f62c91fe58cb',
    'building/utils.py': 'a6ebe3ebed9433a60fa62f188a290ddfbecadb76b9b2e6d3bf8104559472568c',
    'utils/osx.py': '1d6a43c4af39802c125e389c89509513975e329f2ccfdd696eb3ab9ff244abb7',
    'archive/writers.py': 'cc82056869995c1012b08c8f0bf7eecef6b5ec8bc6e28e9e8b548e40b0d92e61',
    'lib/modulegraph/modulegraph.py': '8b0e7c2a455c859a910e8c69fb44180680c549e9326290d3f406d8c67b975cb4',
}
REPLAY_OPTIONS = {'use_strip': False, 'use_upx': False, 'upx_exclude': [], 'codesign_identity': None, 'entitlements_file': None}
PYZ_KINDS = {0: 'module', 1: 'package', 3: 'namespace'}
PYZ_HEADER = 17
MAX_PYZ_TOC = 64 * 1024**2
MAX_CODE_BYTES = 32 * 1024**2
MAX_EXPANDED_CODE = 1024**3
MAX_CODE_ENTRIES = 65536
MAX_RECORD_BYTES = 64 * 1024**2
# Components may contain '-': PyInstaller stores collected hook files (hook-yt_dlp) under their file names.
DOTTED = re.compile(r'[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*')
BASE_MEMBER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z_][A-Za-z0-9_]*)*\.pyc')
PKG_TYPES = {'BINARY': 'b', 'EXTENSION': 'b', 'DATA': 'x', 'PYSOURCE': 's', 'PYMODULE': 'm', 'OPTION': 'o', 'PYZ': 'z', 'ZIPFILE': 'Z', 'SYMLINK': 'n'}


def pyz_entries(blob, magic):
    """Strict PyInstaller 6.22.0 PYZ: the header with the built CPython's bytecode magic,
    then a marshalled TOC of plain tuples that consumes the rest of the archive. Names
    must be unique and in PyInstaller's sorted order, entries contiguous, and every
    zlib stream bounded and consumed exactly. Module code is not unmarshalled here."""
    need(len(blob) >= PYZ_HEADER and blob[:4] == b'PYZ\0', 'Invalid PYZ header')
    need(blob[4:8] == bytes.fromhex(magic), 'PYZ bytecode magic differs from the built CPython')
    toc_offset, = struct.unpack_from('!i', blob, 8)
    need(not any(blob[12:PYZ_HEADER]), 'PYZ header padding is not zero')
    need(PYZ_HEADER <= toc_offset < len(blob) and len(blob) - toc_offset <= MAX_PYZ_TOC, 'Invalid PYZ TOC offset')
    stream = io.BytesIO(blob[toc_offset:])
    try:
        toc = marshal.load(stream)
    except (EOFError, ValueError, TypeError) as error:
        raise ValueError(f'Unreadable PYZ TOC: {error}') from error
    need(stream.tell() == len(blob) - toc_offset, 'Trailing bytes after the PYZ TOC')
    need(type(toc) is list and len(toc) <= MAX_CODE_ENTRIES, 'Invalid PYZ TOC')
    rows, cursor, total, previous = [], PYZ_HEADER, 0, None
    for item in toc:
        need(type(item) is tuple and len(item) == 2 and type(item[0]) is str and type(item[1]) is tuple and len(item[1]) == 3
             and all(type(v) is int for v in item[1]), 'Malformed PYZ TOC entry')
        name, (kind, offset, length) = item
        need(DOTTED.fullmatch(name), f'Invalid PYZ module name: {name!r}')
        need(previous is None or name > previous, f'Duplicate or unsorted PYZ module: {name}')
        need(kind in PYZ_KINDS, f'Unsupported PYZ entry type {kind}: {name}')
        need(offset == cursor and length >= 0 and offset + length <= toc_offset, f'PYZ entry is not contiguous: {name}')
        data = None
        if kind == 3:
            need(length == 0, f'Namespace package carries data: {name}')
        else:
            decoder = zlib.decompressobj()
            try:
                data = decoder.decompress(blob[offset:offset + length], MAX_CODE_BYTES + 1)
            except zlib.error as error:
                raise ValueError(f'Invalid compressed PYZ module: {name}') from error
            need(length and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and len(data) <= MAX_CODE_BYTES,
                 f'Truncated, trailing or oversized PYZ module: {name}')
            total += len(data)
            need(total <= MAX_EXPANDED_CODE, 'PYZ expansion exceeds its budget')
        rows.append((name, PYZ_KINDS[kind], data))
        cursor, previous = offset + length, name
    need(cursor == toc_offset, 'PYZ entry data does not end at its TOC')
    return rows


def base_library_members(blob):
    """(name, bytes) of base_library.zip members in archive order. The container, the
    .pyc headers and the writer are re-checked under the built CPython."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            infos = archive.infolist()
            need(infos and len(infos) <= MAX_CODE_ENTRIES and len({i.filename for i in infos}) == len(infos), 'Empty or duplicate base_library.zip members')
            for info in infos:
                need(BASE_MEMBER.fullmatch(info.filename) and info.file_size <= MAX_CODE_BYTES, f'Unexpected base_library.zip member: {info.filename}')
            return [(info.filename, archive.read(info)) for info in infos]
    except zipfile.BadZipFile as error:
        raise ValueError(f'Invalid base_library.zip: {error}') from error


def resolve_module(name, roots, suffixes):
    """Path-based import resolution of `name` over the import-order roots: a package
    directory with __init__ before a module file (extension, source, then bytecode),
    namespace portions only when nothing else is found, and submodules searched only
    in their parent package's path. Returns (kind, root label, file or portions)."""
    search = list(roots)
    for depth, part in enumerate(name.split('.')):
        found, portions = None, []
        for label, folder in search:
            base = Path(folder) / part
            if base.is_dir():
                init = next((base / f'__init__{s}' for s in (*suffixes, '.py', '.pyc') if (base / f'__init__{s}').is_file()), None)
                if init is not None:
                    found = ('package' if init.suffix == '.py' else 'unsupported', label, init)
                    break
            module = next((Path(folder) / f'{part}{s}' for s in (*suffixes, '.py', '.pyc') if (Path(folder) / f'{part}{s}').is_file()), None)
            if module is not None:
                found = ('module' if module.suffix == '.py' and not module.name.endswith(tuple(suffixes)) else 'unsupported', label, module)
                break
            if base.is_dir():
                portions.append((label, base))
        if found is None:
            if not portions:
                return None
            found = ('namespace', None, portions)
        if depth < name.count('.'):
            if found[0] == 'package':
                search = [(found[1], found[2].parent)]
            elif found[0] == 'namespace':
                search = found[2]
            else:
                return None
    if found[0] != 'namespace' and found[2].is_symlink():
        return None
    return found


def attribute_module(name, kind, context):
    found = resolve_module(name, context['roots'], context['interpreter']['extension_suffixes'])
    if found is None or found[0] != kind:
        raise Refused(f'Unattributable {kind} (the import roots resolve it to {found[0] if found else "nothing"}): {name}')
    return found


def script_source(name, context):
    """PYSOURCE entries: PyInstaller's bootstrap script, its run-time hooks or the launcher."""
    site = context['site_packages']
    candidates = [('site-packages', site / 'PyInstaller' / 'loader' / f'{name}.py'), ('site-packages', site / 'PyInstaller' / 'hooks' / 'rthooks' / f'{name}.py'),
                  ('site-packages', site / '_pyinstaller_hooks_contrib' / 'rthooks' / f'{name}.py')]
    if name == context['launcher'].stem:
        candidates.append(('engine', context['launcher']))
    found = [c for c in candidates if c[1].is_file() and not c[1].is_symlink()]
    need(len(found) == 1, f'Unattributable or ambiguous packed script: {name}')
    return found[0]


def bootstrap_source(name, context):
    """PYMODULE CArchive entries: PyInstaller's loader modules, or an import-path module."""
    loader = context['site_packages'] / 'PyInstaller' / 'loader' / f'{name}.py'
    found = resolve_module(name, context['roots'], context['interpreter']['extension_suffixes'])
    module = found if found and found[0] == 'module' else None
    need((loader.is_file() and not loader.is_symlink()) != (module is not None), f'Unattributable or ambiguous bootstrap module: {name}')
    return ('site-packages', loader) if module is None else module[1:]


def source_record(label, path, context):
    """Root-relative identity and provenance of one expected source file."""
    path = Path(path)
    root = context['root_paths'][label]
    rel = path.relative_to(root).as_posix()
    digest = file_sha(path)
    return {'root': label, 'path': rel, 'sha256': digest, 'provenance': context['provenance'](label, rel, digest)}


def run_python_proof(items, base, context, folder):
    """Write the packed code and the job, run the code replay under the built CPython,
    and return {id: result row}."""
    job = {'schema': REPLAY_SCHEMA, 'interpreter': {k: context['interpreter'][k] for k in ('version', 'magic', 'cache_tag')},
           'pyinstaller': context['replay_pins'], 'items': items}
    if base:
        job['base_library'] = base
    result = context['replay']('code', job)
    need(result.get('schema') == REPLAY_SCHEMA and result.get('command') == 'code', 'Unexpected code replay result')
    rows = result['rows'] + (result.get('base_library') or {}).get('rows', [])
    want = [i['id'] for i in items] + ([base['sources'][m]['id'] for m in base['members']] if base else [])
    need([r['id'] for r in rows] == want, 'Code replay rows differ from the job')
    return result, {r['id']: r for r in rows}


def scan(data, patterns):
    return sorted(label for label, needle in patterns.items() if needle and needle in data)


def carchive_layout(data, archive, entries, python_version):
    """PyInstaller 6.22.0 CArchive layout, as the reviewed extractor checks it:
    contiguous entries, the pinned TOC serialization and the cookie, which must end
    the archive and name the packed Python library and version."""
    start, end = archive._start_offset, archive._end_offset
    need(0 < start < end <= len(data) and data.rfind(extractor.MAGIC) == end - extractor.COOKIE_BYTES, 'The CArchive cookie must be the last archive magic')
    _, length, toc_offset, toc_length, pyvers, pylib = struct.unpack(extractor.COOKIE, data[end - extractor.COOKIE_BYTES:end])
    need(length == end - start and toc_length <= signing.MAX_TOC_BYTES, 'Cookie archive length differs from its placement')
    cursor = 0
    for member, (offset, stored, expanded, flag, code) in entries:
        need(offset == cursor, f'CArchive entry {member!r} is not contiguous with the previous entry')
        need(flag in (0, 1) and (flag or stored == expanded), f'Invalid compression metadata for {member!r}')
        need(code != 'o' or stored == expanded == flag == 0, f'Option entry {member!r} carries data')
        cursor += stored
    need(toc_offset == cursor and toc_offset + toc_length + extractor.COOKIE_BYTES == length, 'The TOC and cookie must immediately follow the entry data')
    toc = data[start + toc_offset:start + toc_offset + toc_length]
    need(extractor.serialize_toc([(o, s, e, f, c, n) for n, (o, s, e, f, c) in entries]) == toc, 'The CArchive TOC differs from the pinned PyInstaller serialization')
    name, _, tail = pylib.partition(b'\0')
    major, minor = (int(x) for x in python_version.split('.')[:2])
    library = f'libpython{major}.{minor}.dylib'
    need(name == library.encode() and not any(tail) and pyvers == major * 100 + minor, 'Cookie Python library or version differs from the built CPython')
    need(any(n == library and e[4] == 'b' for n, e in entries), 'The cookie Python library is not a packed native member')
    return {'start': start, 'end': end, 'toc_sha256': sha(toc), 'pkg_sha256': sha(data[start:end]), 'entries': len(entries),
            'cookie': {'python_version': pyvers, 'python_library': library}}


PKG_GUTS = ('name', 'cdict', 'toc', 'python_lib_name', 'exclude_binaries', 'strip_binaries', 'upx_binaries', 'upx_exclude', 'target_arch',
            'codesign_identity', 'entitlements_file')  # building/api.py PKG._GUTS


def pyinstaller_records(folder):
    """PyInstaller's own PYZ-00.toc (PYZ._GUTS: name, toc) and PKG-00.toc (PKG._GUTS)
    for this build, read as Python literals. PKG-00.toc also records the binary
    processing options the replay must use."""
    import ast
    found = {}
    for name, fields in (('PYZ-00.toc', ('name', 'toc')), ('PKG-00.toc', PKG_GUTS)):
        path = public_inputs.regular(Path(folder) / name)
        need(path.stat().st_size <= MAX_RECORD_BYTES, f'{name} exceeds its size limit')
        value = ast.literal_eval(path.read_text())
        need(type(value) is tuple and len(value) == len(fields), f'Unexpected {name} structure')
        value = dict(zip(fields, value))
        rows = value['toc']
        need(type(rows) is list and all(type(r) is tuple and len(r) == 3 and all(type(x) is str for x in r) for r in rows), f'Unexpected {name} entry')
        found[name] = {'sha256': file_sha(path), 'rows': rows}
        if name == 'PKG-00.toc':
            found[name]['options'] = {k: value[k] for k in PKG_GUTS[3:]}
    return found


def analyse_executable(exe, context, folder):
    """Static closure proof of the packed executable against recorded build products.

    - Natives: PyInstaller's binary processing is replayed on each recorded build
      product and must reproduce the packed member byte for byte. An independent
      relocation policy explains every changed load command.
    - Executable: the onefile assembly is replayed on the compiled bootloader and must
      reproduce the executable byte for byte. The onefile policy binds every other
      bootloader byte.
    - Python: every PYZ module, packed script, bootstrap module and base_library.zip
      member must equal its attributed source, compiled under the built CPython.
    - CArchive layout, data members and PyInstaller's own TOC records are checked too.
    Nothing from the executable is executed or imported."""
    exe, folder = Path(exe), Path(folder)
    profile, minimum = context['profile'], context['profile']['target']['macos_minimum']
    data = exe.read_bytes()
    outer_minimum = check_target_macho(data, 'executable', minimum)
    outer_facts = macho_facts(data)
    check_linkage(outer_facts, 'executable', ())
    archive, entries = signing.archive_entries(exe)
    links = signing.check_archive_names(exe, archive, entries)
    layout = carchive_layout(data, archive, entries, context['interpreter']['version'])
    patterns, allowed_paths = context['patterns'], set(profile['expected']['build_path_members'])
    members, modules, problems, path_hits, fingerprints = [], {}, [], [], []
    code_items, native_items, base, attributed, packed_digests = [], [], None, {}, {}
    code_dir, native_dir = folder / 'code', folder / 'natives'
    code_dir.mkdir()
    native_dir.mkdir()

    def hit(name, blob):
        found = scan(blob, patterns)
        if found:
            path_hits.append({'member': name, 'patterns': found})
            if found != ['build-root'] or name not in allowed_paths:
                problems.append(f'Host path in {name}: {found}')

    def code_item(kind, name, packed, label, path, co_filename, modes):
        ident = f'{kind}:{name}'
        record = source_record(label, path, context)
        row = {'id': ident, 'source': str(path), 'source_sha256': record['sha256'], 'filename': co_filename, 'modes': modes}
        if packed is not None:
            target = code_dir / f'{len(code_items):05d}'
            signing.write_private(target, packed)
            row.update(packed=str(target), packed_sha256=sha(packed))
            packed_digests[ident] = row['packed_sha256']
            code_items.append(row)
        attributed[ident] = {'kind': kind, 'name': name, 'co_filename': co_filename, 'source': record, 'path': str(path)}
        return row

    hit('bootloader', data[:archive._start_offset])
    for index, (name, entry) in enumerate(entries):
        code = entry[4]
        row = {'name': name, 'type': code}
        members.append(row)
        if code == 'o':
            row['origin'] = 'pyinstaller-option'
            continue
        blob = payload.extract_member(exe, archive._start_offset, entry)
        row.update(bytes=len(blob), sha256=sha(blob))
        if signing.is_macho(blob[:4]) != (code == 'b'):
            problems.append(f'{name}: Mach-O content must be exactly the binary (b) entries')
            continue
        try:
            if code == 'b':
                found = check_target_macho(blob, name, minimum)
                facts = macho_facts(blob)
                check_linkage(facts, name, ('@rpath/', '@loader_path/', '@executable_path/'))
                product = context['natives'].get(name)
                if product is None:
                    raise Refused(f'Unknown packed native member (no recorded build product): {name}')
                native_items.append({'name': name, 'blob': blob, 'product': product, 'minimum': found, 'facts': facts})
                row['origin'] = product['origin']
                hit(name, blob)
            elif code == 'z':
                for module, kind, raw in pyz_entries(blob, context['interpreter']['magic']):
                    found = attribute_module(module, kind, context)
                    if kind == 'namespace':
                        portions = [{'root': label, 'path': Path(p).relative_to(context['root_paths'][label]).as_posix()} for label, p in found[2]]
                        fingerprints.append({'kind': 'namespace', 'name': module, 'portions': portions})
                        attributed[f'namespace:{module}'] = {'path': '-'}
                        modules[module] = 'namespace:' + ','.join(sorted({p['root'] for p in portions}))
                        continue
                    filename = '/'.join(module.split('.')) + ('/__init__.py' if kind == 'package' else '.py')
                    code_item('pyz', module, raw, found[1], found[2], filename, ['modulegraph', 'compile-bytes'])
                    modules[module] = found[1]
                    hit(module, raw)
                row['origin'] = 'pyinstaller-pyz'
            elif code == 's':
                label, path = script_source(name, context)
                code_item('script', name, blob, label, path, os.path.splitext(name)[0] + '.py', ['compile-bytes'])
                row['origin'] = f'{label}:script'
                hit(name, blob)
            elif code in ('m', 'M'):
                label, path = bootstrap_source(name, context)
                code_item('bootstrap', name, blob, label, path, name + '.py', ['modulegraph', 'compile-bytes'])
                row['origin'] = f'{label}:bootstrap'
                hit(name, blob)
            elif code == 'n':
                row['origin'] = 'link'
            elif name == 'base_library.zip' and code == 'x':
                contents = base_library_members(blob)
                target = folder / 'base_library.zip'
                signing.write_private(target, blob)
                base = {'path': str(target), 'sha256': sha(blob), 'members': [m for m, _ in contents], 'sources': {}}
                for member, content in contents:
                    dotted = member[:-4].replace('/', '.')
                    kind = 'package' if dotted.endswith('.__init__') or dotted == '__init__' else 'module'
                    dotted = dotted[:-len('.__init__')] if kind == 'package' else dotted
                    found = attribute_module(dotted, kind, context)
                    if found[1] != 'stdlib':
                        raise Refused(f'base_library.zip member is not attributed to the CPython stdlib: {member}')
                    base['sources'][member] = code_item('base', member, None, found[1], found[2], member[:-1], ['modulegraph', 'compile-bytes'])
                    packed_digests[f'base:{member}'] = sha(content[16:])
                row['origin'] = 'pyinstaller-base-library'
                hit(name, blob)
            else:
                origin = context['data'].get(name, {}).get(sha(blob))
                if origin is None:
                    raise Refused(f'Unknown packed data member: {name}')
                row['origin'] = origin
                hit(name, blob)
        except (ValueError, struct.error) as error:
            problems.append(f'{name}: {error}')

    # Python code: one replay under the built CPython, from attributed sources.
    python = {'items': len(code_items) + (len(base['members']) if base else 0)}
    if code_items or base:
        result, rows = run_python_proof(code_items, base, context, folder)
        matched = 0
        for ident, info in attributed.items():
            if ident.startswith('namespace:'):
                continue
            result_row = rows[ident]
            if not result_row['equal']:
                problems.append(f'Packed code differs from its attributed source: {ident} ({result_row.get("difference")})')
                continue
            matched += 1
            fingerprints.append({'kind': info['kind'], 'name': info['name'], 'co_filename': info['co_filename'], 'source': info['source'],
                                 'mode': result_row['mode'], 'code_sha256': result_row['code_sha256'], 'packed_sha256': packed_digests[ident]})
        python.update(matched=matched, interpreter=result['interpreter'], pyinstaller=result['pyinstaller'],
                      base_library={k: v for k, v in (result.get('base_library') or {}).items() if k != 'rows'})

    # Natives: PyInstaller's own processing replayed on each recorded build product.
    natives = []
    if native_items:
        items = []
        for i, item in enumerate(native_items):
            product = item['product']
            source = Path(product['path'])
            need(file_sha(source) == product['sha256'], f'Build product changed since it was recorded: {item["name"]}')
            copy = native_dir / f'{i:05d}' / PurePosixPath(item['name']).name
            copy.parent.mkdir()
            shutil.copyfile(source, copy)
            items.append({'id': item['name'], 'source': str(copy), 'source_sha256': product['sha256'], 'dest': item['name'], 'strict': product['strict']})
        cache = folder / 'native-cache'
        cache.mkdir()
        result = context['replay']('natives', {'schema': REPLAY_SCHEMA, 'pyinstaller': context['replay_pins'], 'cachedir': str(cache),
                                               'target_arch': profile['target']['arch'], 'options': REPLAY_OPTIONS, 'items': items})
        need([r['id'] for r in result['rows']] == [i['id'] for i in items], 'Native replay rows differ from the job')
        for item, replayed in zip(native_items, result['rows']):
            name, blob = item['name'], item['blob']
            row = {'name': name, 'sha256': sha(blob), 'bytes': len(blob), 'minimum': item['minimum'], 'sdk': item['facts'][0]['sdk'],
                   'linked': item['facts'][0]['dylibs'], 'signature': signing.producer_summary(signing.signature(blob))[0],
                   'product': {'origin': item['product']['origin'], 'sha256': item['product']['sha256']}}
            if Path(replayed['output']).read_bytes() != blob:
                problems.append(f'{name}: packed native differs from PyInstaller processing of its build product')
                row['replay'] = 'differs'
            else:
                row['replay'] = 'identical'
            try:
                row['relocation'] = relocation_policy(Path(item['product']['path']).read_bytes(), blob, name)['changes']
            except ValueError as error:
                problems.append(str(error))
            natives.append(row)

    # Executable: the onefile assembly replayed on the compiled bootloader.
    outer = {}
    boot, pylib = context['bootloader'], context['python_library']
    try:
        outer['policy'] = onefile_policy(data, boot['bytes'], archive._start_offset, archive._end_offset, pylib['bytes'])
    except ValueError as error:
        problems.append(f'executable: {error}')
    onefile = folder / 'onefile'
    (onefile / 'out').mkdir(parents=True)
    for file, content in (('run', boot['bytes']), ('pkg', data[archive._start_offset:archive._end_offset]), (pylib['name'], pylib['bytes'])):
        signing.write_private(onefile / file, content)
    result = context['replay']('onefile', {'schema': REPLAY_SCHEMA, 'pyinstaller': context['replay_pins'], 'target_arch': profile['target']['arch'],
                                           'bootloader': str(onefile / 'run'), 'bootloader_sha256': boot['sha256'], 'pkg': str(onefile / 'pkg'),
                                           'pkg_sha256': layout['pkg_sha256'], 'python_library': str(onefile / pylib['name']),
                                           'python_library_sha256': pylib['sha256'], 'output': str(onefile / 'out' / exe.name)})
    outer['replay'] = 'identical' if Path(result['output']).read_bytes() == data else 'differs'
    if outer['replay'] != 'identical':
        problems.append('executable: differs from the PyInstaller onefile assembly of the compiled bootloader and its own PKG')
    outer.update(bootloader={'origin': boot['origin'], 'sha256': boot['sha256'], 'bytes': len(boot['bytes'])},
                 python_library={'origin': pylib['origin'], 'sha256': pylib['sha256']}, sdk=result['sdk'])

    # PyInstaller's own build records must name exactly these members and sources.
    records = context.get('records')
    if records is not None:
        problems += record_problems(records, entries, modules, attributed, context, exe, archive)

    summary = {}
    for origin in list(modules.values()) + [m.get('origin') for m in members]:
        parts = str(origin).split(':')
        key = ':'.join(parts[:2]) if parts[0] in ('wheel', 'namespace') else parts[0]
        summary[key] = summary.get(key, 0) + 1
    fingerprints.sort(key=lambda r: (r['kind'], r['name']))
    return {'schema': PROOF_SCHEMA,
            'executable': {'sha256': sha(data), 'bytes': len(data), 'minimum': outer_minimum, 'sdk': outer_facts[0]['sdk'],
                           'linked': outer_facts[0]['dylibs'], 'signature': signing.producer_summary(signing.signature(data))[0]},
            'outer': outer, 'archive': layout, 'members': members, 'natives': natives, 'python': python, 'pyz_modules': dict(sorted(modules.items())),
            'fingerprints': fingerprints, 'links_validated': links, 'origin_summary': dict(sorted(summary.items())), 'host_path_hits': path_hits,
            'problems': problems}


def record_problems(records, entries, modules, attributed, context, exe, archive):
    """Cross-check against PyInstaller's PYZ-00.toc and PKG-00.toc: the same names, and the
    same sources the independent attribution found."""
    problems = []
    pyz = {name: src for name, src, _ in records['PYZ-00.toc']['rows']}
    if set(pyz) != set(modules):
        problems.append(f'PYZ modules differ from PyInstaller PYZ-00.toc: {sorted(set(pyz) ^ set(modules))[:5]}')
    for name in sorted(set(pyz) & set(modules)):
        mine = attributed.get(f'pyz:{name}', attributed.get(f'namespace:{name}', {})).get('path')
        if pyz[name] != mine:
            problems.append(f'PyInstaller recorded another source for {name}')
    pkg = {}
    for dest, src, typecode in records['PKG-00.toc']['rows']:
        code = PKG_TYPES.get(typecode)
        dest = 'PYZ.pyz' if code == 'z' else dest
        if code is None or dest in pkg:
            problems.append(f'Unexpected PKG-00.toc entry: {dest} ({typecode})')
        pkg[dest] = (src, code)
    packed = {name: entry for name, entry in entries}
    if set(pkg) != set(packed):
        problems.append(f'CArchive members differ from PyInstaller PKG-00.toc: {sorted(set(pkg) ^ set(packed))[:5]}')
    for name in sorted(set(pkg) & set(packed)):
        src, code = pkg[name]
        if packed[name][4] != code:
            problems.append(f'{name}: CArchive type differs from PKG-00.toc')
        elif code == 'b' and src != context['natives'].get(name, {}).get('path'):
            problems.append(f'{name}: PyInstaller collected another native file')
        elif code == 's' and src != attributed.get(f'script:{name}', {}).get('path'):
            problems.append(f'{name}: PyInstaller recorded another script source')
        elif code == 'x' and not (Path(src).is_file() and file_sha(src) == sha(payload.extract_member(exe, archive._start_offset, packed[name]))):
            problems.append(f'{name}: data member differs from the file PyInstaller recorded')
    return problems


# ---------------------------------------------------------------- build

class Runner:
    """Runs one logged step. Tests substitute failures; nothing is retried."""

    def __init__(self, logs, record, save):
        self.logs, self.record, self.save, self.count = Path(logs), record, save, 0

    def run(self, name, argv, cwd, env, timeout=STEP_TIMEOUT):
        self.count += 1
        log = self.logs / f'{self.count:03d}-{name}.log'
        started = time.monotonic()
        with open(log, 'xb') as stream:
            try:
                result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, timeout=timeout)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 'timeout'
            except OSError as error:
                stream.write(f'{error}\n'.encode())
                code = 'oserror'
        self.record['steps'].append({'name': name, 'argv': [str(a) for a in argv], 'cwd': str(cwd), 'exit': code,
                                     'seconds': round(time.monotonic() - started, 2), 'log': log.name, 'log_sha256': file_sha(log)})
        self.save()
        if code != 0:
            raise BuildFailed(name, f'exit {code}; see {log.name}')
        return log

    def output(self, name, argv, cwd, env, timeout=STEP_TIMEOUT):
        return self.run(name, argv, cwd, env, timeout).read_text(errors='replace')


def safe_extract(archive, destination):
    destination.mkdir(parents=True)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        tops = {PurePosixPath(m.name).parts[0] for m in members if m.name not in ('.', './')}
        need(len(tops) == 1, f'{archive.name} must have one top-level directory')
        tar.extractall(destination, filter='data')
    root = destination / tops.pop()
    need(root.is_dir() and not root.is_symlink(), f'{archive.name} has no top-level directory')
    return root, len(members)


def portable(value, roots):
    text = canonical(value)
    for path, token in sorted(roots.items(), key=lambda item: -len(item[0])):
        if path:
            text = text.replace(json.dumps(path)[1:-1], token)
    need(not HOST_PATH.search(text), 'Portable metadata still contains a host path')
    return json.loads(text)


class Context:
    def __init__(self, repo, sources, output, profile, plan, private):
        self.repo, self.sources, self.output, self.profile, self.plan = repo, sources, output, profile, plan
        self.work, self.logs = output / 'work', output / 'logs'
        self.home, self.tmp = self.work / 'home', self.work / 'tmp'
        self.src, self.deps, self.root = self.work / 'src', self.work / 'deps', self.work / 'root'
        self.prefix = profile['logical_prefix']
        self.stage = Path(str(self.root) + self.prefix + '/python')
        self.python = self.stage / 'bin' / 'python3.13'
        self.buildenv, self.runtime = self.work / 'buildenv', self.work / 'runtime'
        self.wheels, self.npm_cache = self.work / 'wheels', self.work / 'npm-cache'
        self.sdk, self.developer = private['sdk'], private['developer_dir']
        # v2: source-built CMake/Ninja, the curl-impersonate superbuild tree and its install prefix.
        self.tools, self.superbuild, self.impersonate = self.work / 'tools', self.work / 'superbuild', self.work / 'impersonate'
        self.values = {'deps': self.deps, 'root': self.root, 'prefix': self.prefix, 'jobs': profile['jobs'], 'tools': self.tools,
                       'superbuild': self.superbuild, 'impersonate': self.impersonate, 'minimum': profile['target']['macos_minimum'],
                       'recipe': self.src / 'curl-impersonate-recipe'}
        self.roots = {str(output): '$BUILD', str(sources): '$SOURCES', str(repo): '$ENGINE', self.sdk: '$SDKROOT',
                      self.developer: '$DEVELOPER_DIR', str(Path.home()): '$HOME'}

    def env(self, extra=None, path=None):
        env = {'PATH': ':'.join([*(path or []), '/usr/bin', '/bin', '/usr/sbin', '/sbin']), 'HOME': str(self.home), 'TMPDIR': str(self.tmp),
               'LANG': 'C', 'LC_ALL': 'C', 'SDKROOT': self.sdk, 'DEVELOPER_DIR': self.developer,
               'MACOSX_DEPLOYMENT_TARGET': self.profile['target']['macos_minimum'], 'CC': '/usr/bin/clang', 'CXX': '/usr/bin/clang++',
               'ARCHFLAGS': '-arch arm64', 'SOURCE_DATE_EPOCH': str(self.profile['source_date_epoch']), 'ZERO_AR_DATE': '1',
               'PYTHONHASHSEED': '0', 'PYTHONNOUSERSITE': '1', 'PIP_CONFIG_FILE': os.devnull, 'PIP_NO_INPUT': '1',
               'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_CACHE_DIR': '1', 'PIP_NO_INDEX': '1'}
        env.update(extra or {})
        return env


def build(repo, plan_path, sources, output, runner_factory=Runner):
    """Re-derive the plan, then build into a new output directory. Only a fully
    verified build writes bin/omd-yt-dlp and a receipt with status 'built'."""
    repo, sources = Path(os.path.abspath(repo)), signing.no_link_ancestors(sources)
    plan = check_plan(plan_path, repo, sources)
    profile = load_profile(repo / plan_profile(plan))
    _, private = toolchain(is_v2(profile))
    output = new_output_directory(output, [repo, sources])
    ctx = Context(repo, sources, output, profile, plan, private)
    for folder in (ctx.work, ctx.logs, ctx.home, ctx.tmp, ctx.src, ctx.wheels, ctx.npm_cache):
        folder.mkdir(parents=True)
    record = {'schema': RECEIPT_SCHEMA, 'status': 'building', 'release_accepted': False, 'promotable': False, 'prototype': True,
              'profile': profile['id'], 'profile_file': plan_profile(plan), 'plan_sha256': file_sha(plan_path), 'target': profile['target'],
              'toolchain': plan['toolchain'], 'host_python': sys.version.split()[0], 'steps': [], 'limits': limits_for(profile)}
    receipt = output / 'receipt.json'

    def save():
        receipt.write_bytes(json_bytes(portable(record, ctx.roots)))

    save()
    runner = runner_factory(ctx.logs, record, save)
    started = time.monotonic()
    try:
        build_steps(ctx, runner, record, save)
        executable = output / 'bin' / profile['extractor']['name']
        executable.parent.mkdir()
        shutil.copyfile(ctx.work / 'dist' / profile['extractor']['name'], executable)
        executable.chmod(0o755)
        need(file_sha(executable) == record['closure']['executable']['sha256'], 'Final copy differs from the verified executable')
        record['output'] = {'path': f'bin/{executable.name}', **identity(executable)}
        record['status'] = 'built'
    except BaseException as error:
        record['status'] = 'failed'
        record['failure'] = {'step': getattr(error, 'step', None), 'error': f'{type(error).__name__}: {error}'}
        raise
    finally:
        record['seconds'] = round(time.monotonic() - started, 1)
        record['disk_bytes'] = disk_usage(output)
        save()
    return record


def disk_usage(path):
    total = 0
    for parent, _, names in os.walk(path, followlinks=False):
        for name in names:
            with_stat = (Path(parent) / name).lstat()
            total += with_stat.st_blocks * 512
    return total


def sources_of(ctx, ident):
    return ctx.sources / by_id(ctx.profile, ident)['file']


def sandboxed(argv):
    """argv under sandbox-exec with all networking denied."""
    return ['/usr/bin/sandbox-exec', '-p', BUILD_SANDBOX, *argv]


def build_tools(ctx, runner, extracted):
    """CMake and Ninja from their pinned source archives into a private prefix (v2)."""
    minimum = ctx.profile['target']['macos_minimum']
    ctx.tools.mkdir()
    rows = {}
    for recipe in ctx.profile['tools']:
        source = by_id(ctx.profile, recipe['input'])
        for index, step in enumerate(recipe['steps']):
            runner.run(f'tool-{recipe["id"]}-{index}', sandboxed([substitute(a, ctx.values) for a in step]), extracted[recipe['input']], ctx.env())
        for product in recipe['products']:
            path = ctx.tools / product
            need(path.is_file() and not path.is_symlink(), f'Missing tool product {product}')
            data = path.read_bytes()
            found = check_target_macho(data, f'tool {product}', minimum)
            facts = macho_facts(data)
            check_linkage(facts, f'tool {product}', ())
            version = runner.output(f'tool-{recipe["id"]}-version', [path, '--version'], ctx.work, ctx.env()).strip().splitlines()[0]
            need(source['version'] in version.split(), f'{product} reports {version!r}, not the pinned {source["version"]}')
            rows[product] = {'input': recipe['input'], 'version': version, 'sha256': sha(data), 'bytes': len(data), 'minimum': found, 'linked': facts[0]['dylibs']}
        for link, target in sorted(recipe.get('links', {}).items()):
            check_tool_link(ctx.tools, link, target, rows)
            version = runner.output(f'tool-{recipe["id"]}-link-version', [ctx.tools / link, '--version'], ctx.work, ctx.env()).strip().splitlines()[0]
            need(version == rows[(PurePosixPath(link).parent / target).as_posix()]['version'], f'{link} reports {version!r}, not its product version')
            rows[link] = {'input': recipe['input'], 'link_to': target, 'version': version}
    return rows


def check_tool_link(tools, link, target, products):
    """A recorded tool link: a relative symlink, in the product's own directory, to exactly
    that verified product file (nothing else may stand at the name the recipe calls)."""
    path = Path(tools) / link
    need(path.is_symlink() and os.readlink(path) == target, f'Tool link {link} must be a symlink to {target}')
    product = (PurePosixPath(link).parent / target).as_posix()
    need(product in products and (Path(tools) / product).is_file() and not (Path(tools) / product).is_symlink(), f'Tool link {link} does not name a verified product')
    need(file_sha(path) == products[product]['sha256'], f'Tool link {link} does not resolve to the verified product')


AR_MAGIC = b'!<arch>\n'


def ar_members(path):
    """(name, bytes) of every member of a BSD `ar` archive, without its symbol table."""
    data = Path(path).read_bytes()
    need(data[:8] == AR_MAGIC, f'{Path(path).name}: not an ar archive')
    at, rows = 8, []
    while at < len(data):
        header = data[at:at + 60]
        need(len(header) == 60 and header[58:60] == b'`\n', f'{Path(path).name}: invalid ar member header')
        name, size = header[:16].decode('ascii').rstrip(' '), int(header[48:58].decode('ascii').strip())
        body = data[at + 60:at + 60 + size]
        need(len(body) == size, f'{Path(path).name}: truncated ar member')
        if name.startswith('#1/'):
            length = int(name[3:])
            name, body = body[:length].split(b'\0', 1)[0].decode('utf-8'), body[length:]
        if not name.startswith('__.SYMDEF'):
            rows.append((name, body))
        at += 60 + size + (size & 1)
    return rows


def check_release_archive(output, archives, minimum):
    """The merged archive holds exactly the members of the recorded static archives (byte for
    byte, as a multiset) and nothing else; each member is a thin arm64 macOS object
    whose deployment minimum does not exceed the profile's."""
    from collections import Counter
    inputs, sources = Counter(), {}
    for archive in archives:
        rows = ar_members(archive)
        need(rows, f'{Path(archive).name} has no members')
        sources[Path(archive).name] = {'sha256': file_sha(archive), 'members': len(rows)}
        inputs.update(sha(body) for _, body in rows)
    merged = ar_members(output)
    found = Counter(sha(body) for _, body in merged)
    need(found == inputs, f'The release archive members differ from its recorded inputs ({sum((found - inputs).values())} extra, {sum((inputs - found).values())} missing)')
    for name, body in merged:
        need(body[:4] == MH_MAGIC_64, f'Release archive member is not a 64-bit Mach-O object: {name}')
        cpu, _, filetype = struct.unpack_from('<III', body, 4)
        need(cpu == CPU_ARM64 and filetype == 1, f'Release archive member is not an arm64 object: {name}')
        minimums = [f'{m >> 16}.{(m >> 8) & 255}.{m & 255}' for m in object_minimums(body)]
        need(minimums and all(version_tuple(m) <= version_tuple(minimum) for m in minimums), f'Release archive member targets another macOS minimum: {name} {minimums}')
    return {'sha256': file_sha(output), 'bytes': Path(output).stat().st_size, 'members': len(merged), 'inputs': sources}


def object_minimums(body):
    """LC_BUILD_VERSION (macOS) minimums of one object file."""
    ncmds, sizeofcmds = struct.unpack_from('<II', body, 16)
    at, found = 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', body, at)
        need(size >= 8 and at + size <= 32 + sizeofcmds, 'Invalid object load command')
        if cmd == LC_BUILD_VERSION:
            platform_id, minos = struct.unpack_from('<II', body, at + 8)
            need(platform_id == 1, 'Object is not built for macOS')
            found.append(minos)
        at += size
    return found


PATCH_STEP = re.compile(r"^\[\d+/\d+\] Performing patch step for '(\w+)'$")
NINJA_LINE = re.compile(r'^\[\d+/\d+\] ')


def check_patch_log(text, patches):
    """The ExternalProject patch steps applied every pinned patch exactly: one `patching
    file` line per file section of the patch, and no Hunk offset, fuzz or failure, no
    reversed-patch prompt and no reject file. Ninja prints each step's output right after
    its description, and the superbuild runs one step at a time."""
    found, current = {}, None
    for line in text.splitlines():
        match = PATCH_STEP.match(line)
        if match:
            need(match.group(1) not in found, f'Patch step ran twice: {match.group(1)}')
            current = found.setdefault(match.group(1), [])
        elif NINJA_LINE.match(line):
            current = None
        elif current is not None:
            current.append(line)
    expected = {PurePosixPath(rel).stem: info for rel, info in patches.items()}
    need(sorted(found) == sorted(expected), f'Patched projects differ from the pinned patches: {sorted(found)}')
    report = {}
    for project, lines in sorted(found.items()):
        bad = [line for line in lines if re.search(r'^Hunk #|Reversed|\.rej\b|FAILED|fuzz|offset', line)]
        need(not bad, f'{project}: the pinned patch did not apply exactly: {bad[:2]}')
        patched = [line for line in lines if line.startswith('patching file ')]
        need(len(patched) == expected[project]['files'], f'{project}: {len(patched)} files patched, {expected[project]["files"]} pinned')
        report[project] = {'files': len(patched), 'sha256': expected[project]['sha256']}
    return report


def check_curl_version(text, check):
    """`curl-impersonate -V`: the exact pinned component list and feature set."""
    lines = text.strip().splitlines()
    need(lines and lines[0].startswith('curl ') and ' (Darwin) ' in lines[0], 'Unexpected curl -V output')
    components = lines[0].split(' (Darwin) ', 1)[1].split()
    need(components == check['version_components'], f'curl components differ from the profile: {components}')
    features = next((l.split(':', 1)[1].split() for l in lines if l.startswith('Features:')), None)
    need(features is not None and sorted(features) == sorted(check['features']), f'curl features differ from the profile: {features}')
    protocols = next((l.split(':', 1)[1].split() for l in lines if l.startswith('Protocols:')), [])
    return {'version_line': lines[0], 'components': components, 'features': features, 'protocols': protocols}


def build_impersonate(ctx, runner):
    """The pinned curl-impersonate CMake superbuild with networking denied. ExternalProject
    finds each pinned dependency archive already staged (by digest) at its download path;
    it verifies URL_HASH and applies the pinned patches. Then the upstream CI's macOS
    release step is replayed: the recipe's ReleasePkgConfig.cmake with the source-built
    pkg-config, and the libtool archive merge. The merged members and the release
    pkg-config file are proven."""
    profile, cur, planned = ctx.profile, ctx.profile['impersonate'], ctx.plan['impersonate']
    minimum = profile['target']['macos_minimum']
    recipe = ctx.values['recipe']
    for rel, digest in {**cur['recipe_files'], **cur['patches']}.items():
        need(file_sha(public_inputs.regular(recipe / rel)) == digest, f'Extracted recipe file differs from its pin: {rel}')
    ctx.superbuild.mkdir()
    staged = {}
    for dep in planned['dependencies']:
        target = ctx.superbuild / f'{dep["project"]}-prefix' / 'src' / dep['file']
        target.parent.mkdir(parents=True)
        shutil.copyfile(ctx.sources / dep['file'], target)
        need(file_sha(target) == dep['sha256'], f'Staged archive differs from its pin: {dep["file"]}')
        staged[dep['project']] = target
    path = [str(ctx.tools / 'bin')]
    environment = ctx.env({k: substitute(v, ctx.values) for k, v in cur['environment'].items()}, path)
    logs = []
    for index, step in enumerate(cur['steps']):
        logs.append(runner.run(f'impersonate-{index}', sandboxed([substitute(a, ctx.values) for a in step]), ctx.work, environment))
        if index == 0:
            for dep in planned['dependencies']:
                script = ctx.superbuild / f'{dep["project"]}-prefix' / 'src' / f'{dep["project"]}-stamp' / f'download-{dep["project"]}.cmake'
                text = public_inputs.regular(script).read_text()
                need(f'if(EXISTS "{staged[dep["project"]]}")' in text and dep['sha256'] in text,
                     f'{dep["project"]}: ExternalProject does not use the staged pinned archive')
    patches = check_patch_log(''.join(log.read_text(errors='replace') for log in logs), planned['patches'])
    for dep in planned['dependencies']:
        need(file_sha(staged[dep['project']]) == dep['sha256'], f'Staged archive changed during the build: {dep["file"]}')
    release = cur['release']
    archives = [Path(substitute(a, ctx.values)) for a in release['archives']]
    output, headers = Path(substitute(release['output'], ctx.values)), Path(substitute(release['headers'], ctx.values))
    need(all(a.is_file() and not a.is_symlink() for a in archives), 'A recorded static archive is missing')
    need(not output.parent.exists(), 'The release directory must be new')
    output.parent.mkdir(parents=True)
    # "Create tar release files" on macOS: the recipe's ReleasePkgConfig.cmake resolves curl's
    # generated libcurl.pc with pkg-config against the dependency .pc files and writes the
    # release libcurl-impersonate.pc (system libraries only), then libtool merges the archives.
    pkgconfig = release['pkgconfig']
    pkg_dir = Path(substitute(cur['pkg_config'], ctx.values))
    pc_file = Path(substitute(pkgconfig['output'], ctx.values))
    need(pc_file.parent == output.parent, 'The release pkg-config file must sit beside the release archive')
    runner.run('impersonate-release-pkgconfig', sandboxed([ctx.tools / 'bin' / 'cmake', f'-DPKG_CONFIG={pkg_dir / "pkg-config"}',
                                                           f'-DINPUT_PC={substitute(pkgconfig["input"], ctx.values)}',
                                                           f'-DDEPENDENCY_PREFIX={substitute(pkgconfig["dependency_prefix"], ctx.values)}',
                                                           f'-DLIBRARY_DIR={output.parent}', f'-DARCHIVES={";".join(str(a) for a in archives)}',
                                                           '-P', recipe / pkgconfig['script']]), ctx.work, ctx.env(path=[str(pkg_dir)]))
    runner.run('impersonate-release', [release['tool'], '-static', '-o', output, *archives], ctx.work, ctx.env())
    header_rows = {}
    (output.parent / 'include' / 'curl').mkdir(parents=True)
    for header in sorted(headers.iterdir()):
        need(header.is_file() and not header.is_symlink() and header.suffix == '.h', f'Unexpected installed header: {header.name}')
        shutil.copyfile(header, output.parent / 'include' / 'curl' / header.name)
        header_rows[header.name] = file_sha(header)
    need(sorted(p.name for p in output.parent.iterdir()) == sorted(['include', output.name, pc_file.name]),
         'The release directory holds more than the archive, its pkg-config file and headers')
    membership = check_release_archive(output, archives, minimum)
    version = cur['check']['version_components'][0].split('/', 1)[1]
    pc_text = check_release_pkgconfig(public_inputs.regular(pc_file).read_text(), (recipe / pkgconfig['template']).read_text(), version, pkgconfig['libs_private'])
    # What curl_cffi's scripts/build.py will ask: `pkg-config --static --libs libcurl-impersonate`
    # with PKG_CONFIG_PATH at the release directory.
    resolved = runner.output('impersonate-release-pkgconfig-libs', sandboxed([pkg_dir / 'pkg-config', '--static', '--libs', 'libcurl-impersonate']), ctx.work,
                             ctx.env({'PKG_CONFIG_PATH': str(output.parent)}, [str(pkg_dir)]))
    link_flags = resolved_link_flags(resolved, output.parent, pkgconfig['libs_private'])
    binary = ctx.impersonate / cur['check']['binary']
    data = binary.read_bytes()
    check_target_macho(data, cur['check']['binary'], minimum)
    facts = macho_facts(data)
    check_linkage(facts, cur['check']['binary'], ())
    check = check_curl_version(runner.output('impersonate-check', sandboxed([binary, '-V']), ctx.work, ctx.env()), cur['check'])
    membership['pkgconfig'] = {'file': pc_file.name, 'sha256': sha(pc_text.encode()), 'bytes': len(pc_text.encode()), 'text': pc_text,
                               'script': {'path': pkgconfig['script'], 'sha256': cur['recipe_files'][pkgconfig['script']]},
                               'template': {'path': pkgconfig['template'], 'sha256': cur['recipe_files'][pkgconfig['template']]},
                               'pkg_config': cur['pkg_config'] + '/pkg-config', 'libs_private': pkgconfig['libs_private'], 'resolved_link_flags': link_flags}
    return {'sandbox': BUILD_SANDBOX, 'environment': cur['environment'], 'staged': {d['project']: {'file': d['file'], 'sha256': d['sha256']} for d in planned['dependencies']},
            'patches': patches, 'archives': {a.name: identity(a) for a in archives}, 'release': membership, 'headers': header_rows,
            'binary': {'path': cur['check']['binary'], 'sha256': sha(data), 'linked': facts[0]['dylibs'], **check}}


def check_release_pkgconfig(text, template, version, libs_private):
    """The release libcurl-impersonate.pc must be exactly the recipe template configured with
    the pinned curl version and the expected system libraries: the relocatable
    `${pcfiledir}` prefix, `-lcurl-impersonate`, no search path or archive path from the
    build, and nothing else."""
    need(set(re.findall(r'@([A-Z_]+)@', template)) == {'CURL_VERSION', 'CURL_SYSTEM_LIBS'}, 'Unexpected release pkg-config template')
    expected = template.replace('@CURL_VERSION@', version).replace('@CURL_SYSTEM_LIBS@', ' '.join(libs_private))
    if text != expected:
        found = next((l.split(':', 1)[1].strip() for l in text.splitlines() if l.startswith('Libs.private:')), None)
        raise Refused(f'The release pkg-config file differs from the pinned template and expected values (Libs.private: {found!r})')
    need(not HOST_PATH.search(text) and '/' not in text.split('Libs.private:', 1)[1].splitlines()[0], 'The release pkg-config file names a build path')
    return text


def resolved_link_flags(text, release, libs_private):
    """`pkg-config --static --libs libcurl-impersonate` on the release file: the release
    directory, the bundled archive name (which curl_cffi drops in favour of force-loading the
    archive) and the expected system libraries (pkg-config may drop repeated -l entries)."""
    import shlex
    tokens = shlex.split(text.strip())
    need(tokens[:2] == [f'-L{release}', '-lcurl-impersonate'], f'pkg-config resolved other release flags: {tokens[:2]}')
    rest = tokens[2:]
    deduplicated = [t for i, t in enumerate(libs_private) if not (t.startswith('-l') and t in libs_private[i + 1:])]
    need(rest in (libs_private, deduplicated) or rest == [t for i, t in enumerate(libs_private) if not (t.startswith('-l') and t in libs_private[:i])],
         f'pkg-config resolved other system flags: {rest}')
    return [tokens[0], *rest]


COMMAND_LINE = re.compile(r'^\s*(/usr/bin/clang\s.*)$')
LOOKUP_LINE = re.compile(r'^\s+\(undefined\) (?:weak )?external (\S+) \((?:dynamically looked up|from (\S+))\)$')
CURL_PROBE = r"""
import json, curl_cffi
from curl_cffi import Curl
print(json.dumps({"curl_cffi": curl_cffi.__version__, "libcurl": curl_cffi.__curl_version__, "handle_version": Curl().version().decode()}))
"""


def binding_commands(text):
    """The compile and link commands setuptools logged (pip -v) for the cffi extension."""
    import shlex
    commands = []
    for line in text.splitlines():
        match = COMMAND_LINE.match(line)
        if match:
            need('"' not in match.group(1) and "'" not in match.group(1), 'Quoted arguments in a logged compiler command')
            commands.append(shlex.split(match.group(1)))
    compiles = [c for c in commands if '-c' in c and '-o' in c]
    links = [c for c in commands if '-bundle' in c and '-o' in c]
    need(len(compiles) == 2 and len(links) == 1 and len(commands) == 3, f'Expected two compiles and one link, found {len(commands)} commands')
    return compiles, links[0]


def dynamic_lookups(text):
    """`nm -m -u`: symbols bound to a named library, and flat (dynamic_lookup) symbols."""
    bound, flat = {}, []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = LOOKUP_LINE.match(line)
        need(match, f'Unparsed undefined-symbol line: {line.strip()[:120]}')
        if match.group(2):
            bound[match.group(2)] = bound.get(match.group(2), 0) + 1
        else:
            flat.append(match.group(1))
    return dict(sorted(bound.items())), sorted(flat)


def binding_log_facts(text, archive, native, link_flags):
    """What the curl_cffi wheel step logged (pip -v): scripts/build.py found the source-built
    archive and never ran its download fallback; cffi generated the wrapper once; the two
    compiles are the generated wrapper and the sdist shim; the one link force-loads the
    archive into the expected extension, directly followed by exactly the flags the
    source-built pkg-config resolved from the release pkg-config file."""
    need(f'libcurl-impersonate: {archive} already downloaded.' in text, 'curl_cffi did not find the source-built release archive')
    need('Downloading libcurl-impersonate' not in text and 'urlretrieve' not in text, 'curl_cffi attempted its prebuilt-archive download fallback')
    need('Missing libcurl-impersonate.pc' not in text and 'Install pkg-config' not in text, 'curl_cffi did not find the release pkg-config file or pkg-config')
    compiles, link = binding_commands(text)
    sources = [c[c.index('-c') + 1] for c in compiles]
    generated = [s for s in sources if PurePosixPath(s).name.endswith('._wrapper.c') and s.startswith('build/temp.')]
    need(len(generated) == 1 and f"generating cffi module '{generated[0]}'" in text, 'The cffi-generated wrapper source was not found once')
    others = [s for s in sources if s not in generated]
    need(others == ['ffi/shim.c'], f'Unexpected compiled sources: {others}')
    need(f'-Wl,-force_load,{archive}' in link and '-undefined' in link, 'The extension link does not force-load the release archive')
    at = link.index(f'-Wl,-force_load,{archive}') + 1
    need(link[at:at + len(link_flags)] == link_flags, f'The extension link does not use the resolved pkg-config flags: {link[at:at + len(link_flags) + 1]}')
    product = link[link.index('-o') + 1]
    need(product.startswith('build/lib.') and product.endswith('/' + native), f'Unexpected link output: {product}')
    return compiles, link, generated[0], product


def check_binding(ctx, runner, log, src_root, wheel, wheel_files, binding, release, env):
    """The curl_cffi extension in its built wheel is exactly the link of the cffi-generated
    wrapper, the sdist shim and the source-built release archive:
    - scripts/build.py found the release archive (its download fallback never ran, and the
      step had networking denied);
    - both logged compiles are replayed and reproduce their objects, and the logged link,
      replayed on those objects, reproduces the packaged extension byte for byte;
    - the link force-loads the release archive followed by the flags the source-built
      pkg-config resolved from the release pkg-config file, links only the profile's OS
      libraries, and leaves only Python C-API symbols to dynamic lookup."""
    archive = release / 'libcurl-impersonate.a'
    need(file_sha(archive) == ctx.record['impersonate']['release']['sha256'], 'The release archive changed before linking')
    need(file_sha(release / 'libcurl-impersonate.pc') == ctx.record['impersonate']['release']['pkgconfig']['sha256'],
         'The release pkg-config file changed before linking')
    compiles, link, generated, product = binding_log_facts(log.read_text(errors='replace'), archive, binding['native'],
                                                           ctx.record['impersonate']['release']['pkgconfig']['resolved_link_flags'])
    need(file_sha(src_root / product) == wheel_files[binding['native']], 'The wheel extension differs from the linked build product')
    replay = ctx.work / 'binding-replay'
    replay.mkdir()
    objects, compiled = {}, []
    for index, command in enumerate(compiles):
        original = command[command.index('-o') + 1]
        target = replay / f'{index}-{PurePosixPath(original).name}'
        argv = list(command)
        argv[argv.index('-o') + 1] = str(target)
        runner.run(f'binding-replay-compile-{index}', sandboxed(argv), src_root, env)
        need(file_sha(target) == file_sha(src_root / original), f'Recompiling {command[command.index("-c") + 1]} does not reproduce its object')
        objects[original] = str(target)
        source = command[command.index('-c') + 1]
        compiled.append({'source': source, 'source_sha256': file_sha(src_root / source), 'object_sha256': file_sha(target)})
    out = replay / 'link' / PurePosixPath(product).name
    out.parent.mkdir()
    argv = [objects.get(a, a) for a in link]
    need(sum(a in objects.values() for a in argv) == len(objects), 'The logged link does not use both compiled objects')
    argv[argv.index('-o') + 1] = str(out)
    runner.run('binding-replay-link', sandboxed(argv), src_root, env)
    need(file_sha(out) == wheel_files[binding['native']], 'Relinking the replayed objects does not reproduce the packaged extension')
    data = out.read_bytes()
    minimum = check_target_macho(data, binding['native'], ctx.profile['target']['macos_minimum'])
    facts = macho_facts(data)
    need(sorted(facts[0]['dylibs']) == sorted(binding['linked']), f'The extension links other libraries than the profile: {facts[0]["dylibs"]}')
    bound, flat = dynamic_lookups(runner.output('binding-symbols', ['/usr/bin/nm', '-m', '-u', out], ctx.work, ctx.env()))
    need(flat and all(s.startswith(tuple(binding['lookup_prefixes'])) for s in flat), f'Non-Python dynamic lookups: {[s for s in flat if not s.startswith(tuple(binding["lookup_prefixes"]))][:5]}')
    generated_path = src_root / generated
    with zipfile.ZipFile(ctx.wheels_built['cffi']['path']) as cffi_wheel:
        recompiler = sha(cffi_wheel.read('cffi/recompiler.py'))
        cffi_terms = {n: sha(cffi_wheel.read(n)) for n in cffi_wheel.namelist() if '/licenses/' in n or n.endswith('/LICENSE')}
    need(cffi_terms, 'The cffi generator wheel has no license file')
    return {'native': binding['native'], 'sha256': sha(data), 'bytes': len(data), 'minimum': minimum, 'linked': facts[0]['dylibs'],
            'bound_symbols': bound, 'dynamic_lookups': flat, 'release_archive': {'sha256': file_sha(archive), 'force_loaded': True},
            'download_fallback': 'not used (archive found; networking denied)',
            'generated_source': {'path': generated, **identity(generated_path), 'generator': {'package': 'cffi', 'wheel_sha256': ctx.wheels_built['cffi']['sha256'],
                                 'member': 'cffi/recompiler.py', 'member_sha256': recompiler, 'terms': cffi_terms},
                                 'inputs': {'cdef': {'path': 'ffi/cdef.c', 'sha256': file_sha(src_root / 'ffi/cdef.c')},
                                            'build_script': {'path': 'scripts/build.py', 'sha256': file_sha(src_root / 'scripts/build.py')}}},
            'compiles': compiled, 'replay': 'identical'}


def build_steps(ctx, runner, record, save):
    profile = ctx.profile
    minimum = profile['target']['macos_minimum']
    extracted = {}
    for row in profile['inputs']:
        if row['kind'] in EXTRACTED_KINDS:
            root, count = safe_extract(ctx.sources / row['file'], ctx.src / row['id'].replace(':', '-'))
            extracted[row['id']] = root
    record['extracted'] = {k: {'root': v.name} for k, v in sorted(extracted.items())}
    save()
    ctx.record, ctx.wheels_built = record, {}

    # v2: CMake and Ninja from source, then the curl-impersonate superbuild and release archive.
    if is_v2(profile):
        ctx.values['recipe'] = extracted[profile['impersonate']['input']]
        record['tools'] = build_tools(ctx, runner, extracted)
        save()
        record['impersonate'] = build_impersonate(ctx, runner)
        save()

    # Native static libraries, in profile order.
    products = {}
    for recipe in profile['native']:
        for index, step in enumerate(recipe['steps']):
            runner.run(f'native-{recipe["id"]}-{index}', [substitute(a, ctx.values) for a in step], extracted[recipe['input']], ctx.env())
        for product in recipe['products']:
            path = Path(substitute(product, ctx.values)) if product.startswith('{root}') else ctx.deps / product
            need(path.is_file(), f'Missing native product {product}')
            archs = runner.output(f'native-{recipe["id"]}-archs', ['/usr/bin/lipo', '-archs', path], ctx.work, ctx.env()).split()
            need(archs == ['arm64'], f'{product} is not arm64-only: {archs}')
            products[f'{recipe["id"]}:{path.name}'] = identity(path)
    record['native_products'] = products
    save()

    # CPython.
    cpython_src = extracted['cpython']
    for index, step in enumerate(profile['cpython']['steps']):
        log = runner.run(f'cpython-{index}', [substitute(a, ctx.values) for a in step], cpython_src, ctx.env())
        if step[:1] == ['make'] and len(step) == 2:
            record['cpython_modules'] = check_missing_modules(log.read_text(errors='replace'), profile['cpython']['allowed_missing_modules'], profile['cpython']['disabled_modules'])
            record['cpython_sysconfig'] = neutral_sysconfigdata(cpython_src, logical_build_roots(ctx), host_patterns(ctx))
            record['cpython_generated'] = capture_generated(cpython_src, f'cpython-{index}')
    libpython = ctx.stage / 'lib' / 'libpython3.13.dylib'
    original = f'{ctx.prefix}/python/lib/libpython3.13.dylib'
    before = identity(ctx.python)
    runner.run('cpython-relocate', ['/usr/bin/install_name_tool', '-change', original, '@executable_path/../lib/libpython3.13.dylib', ctx.python], ctx.work, ctx.env())
    runner.run('cpython-resign', ['/usr/bin/codesign', '--force', '--sign', '-', ctx.python], ctx.work, ctx.env())
    record['cpython_relocation'] = {'file': 'bin/python3.13', 'from': original, 'to': '@executable_path/../lib/libpython3.13.dylib',
                                    'before_sha256': before['sha256'], 'after_sha256': file_sha(ctx.python), 'signature': 'ad-hoc'}
    probe = runner.output('cpython-probe', [ctx.python, '-I', '-c', CPYTHON_PROBE, *profile['cpython']['required_modules']], ctx.work, ctx.env())
    record['cpython'] = json.loads(probe.strip().splitlines()[-1])
    need(record['cpython']['version'] == by_id(profile, 'cpython')['version'] and record['cpython']['deployment_target'] == minimum, 'CPython probe differs from the profile')
    need(not record['cpython']['missing_required'], f'Required CPython modules missing: {record["cpython"]["missing_required"]}')
    need(record.get('cpython_generated'), 'The generated _sysconfigdata module was not captured after make')
    for name, generated in record['cpython_generated'].items():
        need(file_sha(ctx.stage / 'lib' / 'python3.13' / name) == generated['sha256'], f'Installed {name} differs from the captured build output')
    stage_natives = audit_tree(ctx.stage, minimum, (f'{ctx.prefix}/python/lib/libpython3.13.dylib', '@executable_path/../lib/'))
    record['cpython_natives'] = stage_natives
    save()

    # Build-tool environment (pip from the CPython source's bundled wheel, offline).
    runner.run('buildenv', [ctx.python, '-I', '-m', 'venv', ctx.buildenv], ctx.work, ctx.env())
    tools = ctx.work / 'build-tools.txt'
    tools.write_text(''.join(f'{ctx.sources / r["file"]} --hash=sha256:{r["sha256"]}\n' for r in profile['inputs'] if r['kind'] == 'wheel'))
    bpython = ctx.buildenv / 'bin' / 'python'
    runner.run('build-tools', [bpython, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps', '--require-hashes', '--only-binary', ':all:', '-r', tools], ctx.work, ctx.env())
    listed = json.loads(runner.output('build-tools-list', [bpython, '-I', '-m', 'pip', 'list', '--format', 'json'], ctx.work, ctx.env()))
    record['build_tools'] = sorted(f'{r["name"]}=={r["version"]}' for r in listed)
    expected_tools = {(r['package'].replace('_', '-').lower(), r['version']) for r in profile['inputs'] if r['kind'] == 'wheel'}
    got = {(r['name'].replace('_', '-').lower(), r['version']) for r in listed if r['name'] != 'pip'}
    need(got == expected_tools, f'Build-tool environment differs from the pinned wheels: {sorted(got ^ expected_tools)}')
    save()

    # PyInstaller bootloader from its own source; the sdist's prebuilt binaries are removed first.
    pyi = extracted['sdist:pyinstaller']
    for rel, digest in PYINSTALLER_REPLAYED.items():
        need(file_sha(public_inputs.regular(pyi / 'PyInstaller' / rel)) == digest, f'PyInstaller sdist file differs from the replay pin: {rel}')
    boot = profile['pyinstaller']['bootloader']
    prebuilt_dir = pyi / 'PyInstaller' / 'bootloader' / boot['platform']
    prebuilt = {p.name: file_sha(p) for p in sorted(prebuilt_dir.iterdir())} if prebuilt_dir.is_dir() else {}
    shutil.rmtree(prebuilt_dir, ignore_errors=True)
    # waf imports its waflib from the script directory, so -s (not -I) is used here.
    runner.run('bootloader', [bpython, '-s', './waf', *boot['waf']], pyi / 'bootloader', ctx.env())
    compiled = {}
    for name in boot['outputs']:
        path = prebuilt_dir / name
        need(path.is_file(), f'Bootloader {name} was not compiled')
        check_target_macho(path.read_bytes(), f'bootloader {name}', minimum)
        compiled[name] = file_sha(path)
        need(compiled[name] != prebuilt.get(name), f'Bootloader {name} equals the sdist prebuilt binary')
    record['bootloader'] = {'removed_prebuilt': prebuilt, 'compiled': compiled}
    bootloader_run = (prebuilt_dir / 'run').read_bytes()
    save()

    # Python packages from their sdists, never from an index or a prebuilt wheel.
    built, wheel_files = {}, {}
    binding = profile['impersonate']['binding'] if is_v2(profile) else None
    for package in profile['packages']['build_order']:
        row = sdist_for(profile, package)
        extra = dict(profile['packages']['environment'].get(package, {}))
        path = []
        if row['id'] == profile['npm']['from']:
            path = [str(extracted['tool:node'] / 'bin')]
            extra.update(npm_environment(ctx))
            populate_npm_cache(ctx, runner, path)
        curl = binding is not None and package in [*binding['build_requires'], binding['package']]
        if binding is not None and package == binding['package']:
            # Its build backend imports cffi and pycparser: install the wheels built above, by hash.
            requires = ctx.work / 'binding-build-requires.txt'
            requires.write_text(''.join(f'{built[p]["path"]} --hash=sha256:{built[p]["sha256"]}\n' for p in binding['build_requires']))
            runner.run(f'buildenv-{package}-requires', [bpython, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps', '--require-hashes', '-r', requires],
                       ctx.work, ctx.env())
            extra.update({k: substitute(v, ctx.values) for k, v in binding['environment'].items()})
            release = Path(extra['IMPERSONATE_BUILD_DIR'])
            need((release / 'libcurl-impersonate.a').is_file() and file_sha(release / 'libcurl-impersonate.a') == record['impersonate']['release']['sha256'],
                 'The source-built release archive is missing; refusing the prebuilt-download fallback')
            # scripts/build.py runs `pkg-config --static --libs libcurl-impersonate`: only the
            # source-built pkg-config (a recorded pkgconf link) is put on PATH, for this step only.
            path = [substitute(profile['impersonate']['pkg_config'], ctx.values)]
        out = ctx.wheels / package
        out.mkdir()
        argv = [bpython, '-I', '-m', 'pip', 'wheel', *(['-v'] if is_v2(profile) else []), '--no-index', '--no-deps', '--no-build-isolation',
                '--no-binary', ':all:', '--wheel-dir', out, extracted[row['id']]]
        log = runner.run(f'wheel-{package}', sandboxed(argv) if curl else argv, ctx.work, ctx.env(extra, path))
        produced = sorted(out.glob('*.whl'))
        need(len(produced) == 1, f'{package} produced {len(produced)} wheels')
        facts, files = wheel_facts(produced[0], package, row['version'], package in profile['packages']['native'], minimum)
        built[package], wheel_files[package] = {'path': produced[0], **facts}, files
        ctx.wheels_built = built
        if binding is not None and package == binding['package']:
            record['curl_binding'] = check_binding(ctx, runner, log, extracted[row['id']], produced[0], files, binding, release, ctx.env(extra, path))
            save()
    for member, digest in profile['expected']['ejs'].items():
        need(wheel_files['yt-dlp-ejs'].get(member) == digest, f'EJS output {member} differs from the expected upstream bytes')
    for name, digest in compiled.items():
        need(wheel_files['pyinstaller'].get(f'PyInstaller/bootloader/{boot["platform"]}/{name}') == digest, f'PyInstaller wheel does not carry the compiled {name}')
    need(not [r for r in wheel_files['pyinstaller'] if r.startswith('PyInstaller/bootloader/') and '/' in r[len('PyInstaller/bootloader/'):]
              and not r.startswith(f'PyInstaller/bootloader/{boot["platform"]}/') and not r.startswith('PyInstaller/bootloader/images/')], 'Foreign bootloaders in the PyInstaller wheel')
    record['wheels'] = {k: {kk: vv for kk, vv in v.items() if kk != 'path'} for k, v in built.items()}
    save()

    # Analysis environment: only the wheels built above, installed by hash.
    # A local wheelhouse (not direct file URLs) keeps pip from writing direct_url.json,
    # which would record the build path and be collected with the metadata.
    runner.run('runtime-env', [ctx.python, '-I', '-m', 'venv', '--without-pip', ctx.runtime], ctx.work, ctx.env())
    wheelhouse = ctx.work / 'wheelhouse'
    wheelhouse.mkdir()
    for wheel in built.values():
        shutil.copyfile(wheel['path'], wheelhouse / wheel['file'])
        need(file_sha(wheelhouse / wheel['file']) == wheel['sha256'], 'Wheel changed while copying')
    requirements = ctx.work / 'built-wheels.txt'
    requirements.write_text(''.join(f'{package}=={sdist_for(profile, package)["version"]} --hash=sha256:{w["sha256"]}\n' for package, w in built.items()))
    runner.run('runtime-install', [bpython, '-I', '-m', 'pip', '--python', ctx.runtime / 'bin' / 'python', 'install', '--no-index', '--find-links', wheelhouse,
                                   '--no-deps', '--require-hashes', '-r', requirements], ctx.work, ctx.env())
    site_packages = ctx.runtime / 'lib' / 'python3.13' / 'site-packages'
    record['installed'] = check_installed(site_packages, wheel_files)
    save()
    if binding is not None:
        probe = json.loads(runner.output('curl-cffi-probe', sandboxed([ctx.runtime / 'bin' / 'python', '-I', '-c', CURL_PROBE]), ctx.work, ctx.env()).strip().splitlines()[-1])
        need(probe['curl_cffi'] == sdist_for(profile, binding['package'])['version'], 'Installed curl_cffi version differs from the pinned sdist')
        need(probe['libcurl'] == probe['handle_version'] == binding['curl_version'], f'curl_cffi reports another libcurl: {probe["libcurl"]}')
        record['curl_binding']['runtime_probe'] = probe
        save()

    # PyInstaller with the stock bootloader compiled above.
    launcher = ctx.repo / profile['launcher']
    package = lambda dist, work: runner.run(f'pyinstaller-{dist}', [ctx.runtime / 'bin' / 'python', '-s', '-m', 'PyInstaller', *profile['pyinstaller']['arguments'],
                                                                  '--distpath', ctx.work / dist, '--workpath', ctx.work / work, '--specpath', ctx.work / (work + '-spec'), launcher],
                                            ctx.work, ctx.env({'PYINSTALLER_CONFIG_DIR': str(ctx.work / (work + '-config')), 'PYTHONSAFEPATH': '1'}))
    package('dist', 'pyi-work')
    exe = ctx.work / 'dist' / profile['extractor']['name']
    need(exe.is_file(), 'PyInstaller produced no executable')

    # Static verification of the packed result: every member and the executable itself are
    # proven against recorded build products by replaying PyInstaller (see analyse_executable).
    runner.run('outer-verify', [signing.CODESIGN, '--verify', '--strict', '--all-architectures', exe], ctx.work, ctx.env())
    with tempfile.TemporaryDirectory(dir=ctx.tmp) as folder:
        packed = signing.verify_packed_natives(exe, 'development-adhoc', None, folder)
    need(packed['failed'] == 0 and packed['verified'] == packed['native_members'] > 0, f'Packed native verification failed: {packed["failures"][:3]}')
    proof = ctx.work / 'proof'
    proof.mkdir()
    context = closure_context(ctx, site_packages, record, extracted, wheel_files, bootloader_run, compiled['run'], runner, proof)
    closure = analyse_executable(exe, context, proof)
    fingerprints = closure.pop('fingerprints')
    fingerprint_bytes = json_bytes({'schema': FINGERPRINTS_SCHEMA, 'profile': profile['id'], 'executable_sha256': closure['executable']['sha256'],
                                    'interpreter': closure['python'].get('interpreter'), 'pyinstaller': closure['python'].get('pyinstaller'),
                                    'generated_sources': record['cpython_generated'], 'rows': fingerprints})
    need(not HOST_PATH.search(fingerprint_bytes.decode()), 'Closure fingerprints contain a host path')
    (ctx.output / FINGERPRINTS).write_bytes(fingerprint_bytes)
    closure['python']['fingerprints'] = {'file': FINGERPRINTS, 'sha256': sha(fingerprint_bytes), 'bytes': len(fingerprint_bytes), 'rows': len(fingerprints)}
    closure['packed_verification'] = packed
    record['closure'] = closure
    save()
    need(not closure['problems'], f'Closure problems: {closure["problems"][:5]}')

    # Isolated runtime smoke without network, URLs, configs or plugins.
    record['runtime'] = runtime_probes(ctx, runner, exe)
    save()
    need(record['runtime']['version'] == profile['expected']['version'], 'Unexpected extractor version')
    need(record['runtime']['list_extractors_lines'] == profile['expected']['list_extractors_lines'], 'Unexpected extractor count')

    # Repeat packaging from the same environment to measure packaging determinism.
    package('dist-repeat', 'pyi-work-repeat')
    repeat = file_sha(ctx.work / 'dist-repeat' / profile['extractor']['name'])
    record['packaging_repeat'] = {'sha256': repeat, 'identical': repeat == closure['executable']['sha256']}
    save()


CPYTHON_PROBE = r'''
import importlib.machinery, importlib.util, json, sys, sysconfig
missing = [m for m in sys.argv[1:] if m not in sys.builtin_module_names and importlib.util.find_spec(m) is None]
import ssl, sqlite3, lzma, decimal, zlib, bz2, pyexpat
print(json.dumps({"version": sys.version.split()[0], "implementation": sys.implementation.name, "machine": sysconfig.get_platform(),
  "deployment_target": sysconfig.get_config_var("MACOSX_DEPLOYMENT_TARGET"), "openssl": ssl.OPENSSL_VERSION,
  "sqlite": sqlite3.sqlite_version, "lzma_check_crc64": lzma.is_check_supported(lzma.CHECK_CRC64),
  "libmpdec": decimal.__libmpdec_version__, "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION, "expat": pyexpat.EXPAT_VERSION,
  "magic": importlib.util.MAGIC_NUMBER.hex(), "cache_tag": sys.implementation.cache_tag,
  "extension_suffixes": importlib.machinery.EXTENSION_SUFFIXES, "missing_required": missing}))
'''


MODULE_LINE = re.compile(r'[_A-Za-z][\w.]*( +[_A-Za-z][\w.]*)*')
DISABLED_MARKER = 'The following modules are *disabled* in configure script:'
MISSING_MARKERS = ('The necessary bits to build these optional modules were not found:',
                   'Following modules built successfully but were removed because they could not be imported:', 'Failed to build these modules:')
SUMMARY = re.compile(r'Checked (\d+) modules \((\d+) built-in, (\d+) shared, (\d+) n/a on [^,]+, (\d+) disabled, (\d+) missing, (\d+) failed on import\)')


def module_section(lines, marker):
    found = []
    for i, line in enumerate(lines):
        if line.strip() == marker:
            for row in lines[i + 1:]:
                if not MODULE_LINE.fullmatch(row.strip()):
                    break
                found += row.split()
    return sorted(set(found))


def check_missing_modules(log, allowed, disabled):
    """CPython's own module report: exactly the expected disabled (test-only) modules,
    and nothing missing or failed beyond the explicitly allowed modules."""
    lines = log.splitlines()
    need('Could not build the ssl module!' not in log, 'CPython could not build the ssl module')
    summary = [m for m in map(SUMMARY.search, lines) if m]
    need(len(summary) == 1, 'CPython module summary not found')
    found = sorted({m for marker in MISSING_MARKERS for m in module_section(lines, marker)})
    unexpected = sorted(set(found) - set(allowed))
    need(not unexpected, f'CPython modules missing or failed: {unexpected}')
    off = module_section(lines, DISABLED_MARKER)
    need(off == sorted(disabled), f'CPython disabled modules differ from the profile: {sorted(set(off) ^ set(disabled))}')
    total, builtin, shared, unavailable, disabled_count, missing, failed = map(int, summary[0].groups())
    return {'checked': total, 'builtin': builtin, 'shared': shared, 'not_applicable': unavailable, 'disabled': off, 'missing_or_failed': found}


def audit_tree(root, minimum, allowed):
    rows = []
    for path in sorted(Path(root).rglob('*')):
        if path.is_symlink() or not path.is_file() or not is_macho_file(path):
            continue
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        found = check_target_macho(data, rel, minimum)
        facts = macho_facts(data)
        check_linkage(facts, rel, allowed)
        rows.append({'path': rel, 'sha256': sha(data), 'minimum': found, 'linked': facts[0]['dylibs']})
    need(rows, 'No native files found')
    return rows


def npm_environment(ctx):
    return {'npm_config_cache': str(ctx.npm_cache), 'npm_config_offline': 'true', 'npm_config_ignore_scripts': 'true', 'npm_config_audit': 'false',
            'npm_config_fund': 'false', 'npm_config_update_notifier': 'false', 'npm_config_userconfig': str(ctx.work / 'npmrc-user'),
            'npm_config_globalconfig': str(ctx.work / 'npmrc-global')}


def populate_npm_cache(ctx, runner, path):
    """An offline npm cache holding only the integrity-verified pinned tarballs."""
    for name in ('npmrc-user', 'npmrc-global'):
        (ctx.work / name).write_bytes(b'')
    files = sorted(str(p) for p in (ctx.sources / 'npm').glob('*.tgz'))
    for start in range(0, len(files), 50):
        runner.run(f'npm-cache-{start // 50}', ['npm', 'cache', 'add', *files[start:start + 50]], ctx.tmp, ctx.env(npm_environment(ctx), path))


def generated_sysconfigdata(cpython_src):
    """The build directory named by pybuilddir.txt and the one _sysconfigdata module in it."""
    builddir = public_inputs.regular(cpython_src / 'pybuilddir.txt').read_text().strip()
    need(re.fullmatch(r'build/lib\.[A-Za-z0-9._-]+', builddir), 'Unexpected pybuilddir.txt')
    found = sorted((cpython_src / builddir).glob('_sysconfigdata_*.py'))
    need(len(found) == 1, 'Expected exactly one generated _sysconfigdata module')
    return builddir, public_inputs.regular(found[0])


def capture_generated(cpython_src, step):
    """CPython's generated _sysconfigdata module, hashed straight after `make` in the build
    directory named by pybuilddir.txt (Makefile target pybuilddir.txt runs
    `python -m sysconfig --generate-posix-vars`) and the build-root remapping
    (neutral_sysconfigdata). `make install` copies it unchanged."""
    builddir, path = generated_sysconfigdata(cpython_src)
    return {path.name: {'generator': 'CPython Makefile target pybuilddir.txt: sysconfig --generate-posix-vars; build roots remapped to the logical prefix',
                        'step': step, 'build_output': f'{builddir}/{path.name}', **identity(path)}}


def host_patterns(ctx):
    """Byte patterns of this build's host directories that no shipped byte may contain."""
    home = str(Path.home()).encode()
    return {'build-root': str(ctx.output).encode(), 'sources': str(ctx.sources).encode(), 'engine': str(ctx.repo).encode(),
            'home': home if len(home) > 1 else b'', 'homebrew': b'/opt/homebrew/'}


def logical_build_roots(ctx):
    """Host directories that CPython's configure arguments name, most specific first, with the
    logical location each stands for: the staged install tree under DESTDIR is the profile's
    logical prefix itself, and everything else in the work directory (the dependency prefix
    and the extracted sources) is `<logical prefix>/build`."""
    return [(str(ctx.root) + ctx.prefix, ctx.prefix), (str(ctx.work), ctx.prefix + '/build')]


def neutral_sysconfigdata(cpython_src, roots, patterns):
    """Rewrite the build-host directories in CPython's generated _sysconfigdata module to their
    logical locations, straight after `make` and before `make install` copies it. The module
    records configure arguments and build-tree variables (the OpenSSL prefix, dependency
    include/library flags, the source tree), which the packaged interpreter never uses but
    would otherwise ship. Only those directory strings change, and the build fails if any host
    directory or host-path pattern remains."""
    builddir, path = generated_sysconfigdata(cpython_src)
    original = path.read_bytes()
    text = original.decode('utf-8')
    replacements = []
    for host, logical in roots:
        # A quote or backslash would be escaped in the generated literal and missed below.
        need(os.path.isabs(host) and host.isprintable() and not set(host) & set('\'"\\'), f'Build directory cannot be remapped in {path.name}: {host}')
        need(re.fullmatch(r'(/[a-z0-9][a-z0-9._-]*)+', logical) and not HOST_PATH.search(logical), f'Invalid logical location: {logical}')
        replacements.append({'from': host, 'to': logical, 'count': text.count(host)})
        text = text.replace(host, logical)
    data = text.encode('utf-8')
    found = scan(data, patterns)
    need(not found and not HOST_PATH.search(text), f'{path.name} still names a host path after remapping: {found or "host path pattern"}')
    try:
        tree = ast.parse(data, path.name)
    except SyntaxError:
        raise Refused(f'{path.name} is not valid Python after remapping') from None
    need(len(tree.body) == 1 and isinstance(tree.body[0], ast.Assign) and isinstance(tree.body[0].value, ast.Dict), f'Unexpected {path.name} layout')
    if data != original:
        path.write_bytes(data)
    return {'module': path.name, 'build_output': f'{builddir}/{path.name}', 'generated_sha256': sha(original), 'sha256': sha(data),
            'replacements': replacements}


def sdist_index(archive, expected_sha256):
    """Immutable archive member hashes, never a tree a build backend can rewrite."""
    need(file_sha(archive) == expected_sha256, 'Source archive changed since planning')
    index = {}
    with tarfile.open(archive) as source:
        for member in source:
            if not member.isfile():
                continue
            parts = PurePosixPath(member.name).parts
            with source.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            for i in range(1, len(parts)):
                index.setdefault('/'.join(parts[i:]), []).append({'member': member.name, 'sha256': digest})
    return index


def generated_provenance(profile, sources, package, rel, digest, originals, owner):
    """A packed site-packages source that is not an sdist member: only the reviewed
    generated output (EJS's vcs-versioning `_version.py`) is accepted, with its pinned
    generator, template, license, inputs and output. Anything else fails closed."""
    if package == 'yt-dlp-ejs' and rel == 'yt_dlp_ejs/_version.py':
        generators = [r for r in profile['inputs'] if r.get('package') == 'vcs-versioning' and r['kind'] == 'wheel']
        need(len(generators) == 1, 'Generated EJS version source needs its pinned vcs-versioning generator')
        generator = generators[0]
        wheel = Path(sources) / generator['file']
        need(file_sha(wheel) == generator['sha256'], 'Version generator changed since planning')
        with zipfile.ZipFile(wheel) as archive:
            template_member = 'vcs_versioning/_dump_version.py'
            template = archive.read(template_member)
            terms = {name: sha(archive.read(name)) for name in archive.namelist() if name.endswith('/LICENSE.txt')}
        need(terms, 'Version generator has no retained license')
        return {'kind': 'wheel-build-generated', 'package': package, 'step': f'wheel-{package}',
                'generator': {'package': generator['package'], 'version': generator['version'], 'sha256': generator['sha256'],
                              'member': template_member, 'member_sha256': sha(template), 'template': "DEFAULT_TEMPLATES['.py']", 'terms': terms},
                'inputs': {'version': owner['version'], 'sdist_sha256': owner['sha256'], 'original_members': originals},
                'output_sha256': digest}
    # Fail closed: a packed source that is neither an immutable sdist member nor a
    # reviewed generated output above is unattributed, whatever its name.
    raise Refused(f'Packed source is neither an sdist member nor a reviewed generated output: {package}:{rel}')


def closure_context(ctx, site_packages, record, extracted, wheel_files, bootloader, bootloader_sha256, runner, folder):
    stdlib = ctx.stage / 'lib' / 'python3.13'
    launcher = ctx.repo / ctx.profile['launcher']
    staged = {row['path']: row['sha256'] for row in record['cpython_natives']}
    records = pyinstaller_records(ctx.work / 'pyi-work' / ctx.profile['extractor']['name'])
    options = records['PKG-00.toc']['options']
    need(options == {'python_lib_name': 'libpython3.13.dylib', 'exclude_binaries': False, 'strip_binaries': False, 'upx_binaries': False, 'upx_exclude': [],
                     'target_arch': ctx.profile['target']['arch'], 'codesign_identity': None, 'entitlements_file': None},
         f'PyInstaller recorded PKG options other than the replayed onefile options: {options}')
    typecodes = {dest: typecode for dest, _, typecode in records['PKG-00.toc']['rows']}

    def native(origin, path):
        return {'origin': origin, 'path': str(path), 'sha256': file_sha(path)}

    natives = {'libpython3.13.dylib': {**native('cpython:lib/libpython3.13.dylib', ctx.stage / 'lib' / 'libpython3.13.dylib')}}
    need(natives['libpython3.13.dylib']['sha256'] == staged['lib/libpython3.13.dylib'], 'libpython changed since the CPython audit')
    for path in (stdlib / 'lib-dynload').glob('*.so'):
        row = native(f'cpython:lib/python3.13/lib-dynload/{path.name}', path)
        need(row['sha256'] == staged[f'lib/python3.13/lib-dynload/{path.name}'], f'{path.name} changed since the CPython audit')
        natives[f'python3.13/lib-dynload/{path.name}'] = row
    data, installed = {}, {}
    for package, files in wheel_files.items():
        for member, digest in files.items():
            rel = installed_path(member)
            if rel is None:
                continue
            installed[rel] = (package, digest)
            if rel.endswith(('.so', '.dylib')):
                row = native(f'wheel:{package}:{rel}', site_packages / rel)
                need(row['sha256'] == digest, f'{rel} differs from its built wheel')
                natives[rel] = row
            data.setdefault(rel, {})[digest] = f'wheel:{package}'
    for name, row in natives.items():
        row['strict'] = typecodes.get(name, 'EXTENSION' if name.endswith('.so') else 'BINARY') == 'EXTENSION'
    for dist in site_packages.glob('*.dist-info'):
        for name in PIP_ADDED:
            if (dist / name).is_file():
                data.setdefault(f'{dist.name}/{name}', {})[file_sha(dist / name)] = 'pip-install-metadata'
    for path in stdlib.rglob('*'):
        if path.is_file() and '/site-packages/' not in path.as_posix() and '__pycache__' not in path.parts:
            data.setdefault(f'python3.13/{path.relative_to(stdlib).as_posix()}', {})[file_sha(path)] = 'cpython'
    cpython_sources = sdist_index(sources_of(ctx, 'cpython'), by_id(ctx.profile, 'cpython')['sha256'])
    generated = record['cpython_generated']
    owners = {r['package']: r for r in ctx.profile['inputs'] if r['kind'] == 'sdist'}
    indexes = {}

    def provenance(label, rel, digest):
        if label == 'engine':
            need(rel == ctx.profile['launcher'], f'Unexpected engine source: {rel}')
            return {'kind': 'engine-file'}
        if label == 'stdlib':
            if rel in generated:
                need(generated[rel]['sha256'] == digest, f'{rel} differs from the captured CPython build output')
                return {'kind': 'cpython-build-generated', 'build_output': generated[rel]['build_output'], 'step': generated[rel]['step']}
            need(any(row['sha256'] == digest for row in cpython_sources.get('Lib/' + rel, [])), f'stdlib {rel} differs from the immutable CPython source Lib/{rel}')
            return {'kind': 'cpython-source', 'member': f'Lib/{rel}'}
        need(label == 'site-packages' and installed.get(rel, (None, None))[1] == digest, f'Source is not a built wheel file: {label}/{rel}')
        package = installed[rel][0]
        if package not in indexes:
            row = owners[package]
            indexes[package] = sdist_index(ctx.sources / row['file'], row['sha256'])
        originals = indexes[package].get(rel, [])
        matches = sorted((row for row in originals if row['sha256'] == digest), key=lambda row: (len(PurePosixPath(row['member']).parts), row['member']))
        if matches:
            return {'kind': 'sdist-file', 'package': package, 'member': matches[0]['member']}
        return generated_provenance(ctx.profile, ctx.sources, package, rel, digest, originals, owners[package])

    def replay(command, job):
        job_path, result_path = folder / f'replay-{command}.json', folder / f'replay-{command}-result.json'
        signing.write_private(job_path, json_bytes(job))
        config = folder / f'pyi-config-{command}'
        config.mkdir()
        runner.run(f'replay-{command}', [ctx.runtime / 'bin' / 'python', '-s', '-P', '-B', REPLAY, command, job_path, result_path], folder,
                   ctx.env({'PYINSTALLER_CONFIG_DIR': str(config), 'PYTHONSAFEPATH': '1'}))
        return json.loads(public_inputs.regular(result_path).read_text())

    patterns = host_patterns(ctx)
    libpython = ctx.stage / 'lib' / 'libpython3.13.dylib'
    return {'profile': ctx.profile, 'natives': natives, 'data': data, 'patterns': patterns, 'records': records,
            'interpreter': {k: record['cpython'][k] for k in ('version', 'magic', 'cache_tag', 'extension_suffixes')},
            'roots': [('engine', launcher.parent), ('stdlib', stdlib), ('lib-dynload', stdlib / 'lib-dynload'), ('site-packages', site_packages)],
            'root_paths': {'engine': ctx.repo, 'stdlib': stdlib, 'lib-dynload': stdlib / 'lib-dynload', 'site-packages': site_packages},
            'site_packages': site_packages, 'launcher': launcher, 'provenance': provenance, 'replay': replay,
            'replay_pins': {'version': by_id(ctx.profile, 'sdist:pyinstaller')['version'], 'site_packages': str(site_packages), 'sources': PYINSTALLER_REPLAYED},
            'bootloader': {'bytes': bootloader, 'sha256': bootloader_sha256, 'origin': 'sdist:pyinstaller bootloader compiled from source (step bootloader)'},
            'python_library': {'name': libpython.name, 'bytes': libpython.read_bytes(), 'sha256': staged['lib/libpython3.13.dylib'], 'origin': 'cpython:lib/libpython3.13.dylib'}}


SANDBOX = '(version 1)(allow default)(deny network*)'


def runtime_probes(ctx, runner, exe):
    probe = ctx.work / 'probe'
    home, tmp = probe / 'home', probe / 'tmp'
    home.mkdir(parents=True)
    tmp.mkdir()
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(tmp), 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
           'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_CACHE_HOME': str(home / 'cache')}
    base = ['/usr/bin/sandbox-exec', '-p', SANDBOX, exe, '--ignore-config', '--no-plugin-dirs']
    version = runner.output('probe-version', [*base, '--version'], probe, env, 300).strip()
    listing = runner.output('probe-list-extractors', [*base, '--list-extractors'], probe, env, 300).splitlines()
    verbose = verbose_header(ctx, [*base, '--no-cache-dir', '-v'], probe, env)
    targets = runner.output('probe-impersonate-targets', [*base, '--list-impersonate-targets'], probe, env, 300).splitlines()
    leftovers = sorted(p.relative_to(probe).as_posix() for p in probe.rglob('*') if p.is_file())
    result = {'sandbox': SANDBOX, 'version': version, 'list_extractors_lines': len(listing), 'list_extractors_sha256': sha('\n'.join(listing).encode()),
              'verbose': verbose, 'impersonate_targets': [l for l in targets if l.strip()], 'leftover_files': leftovers}
    if is_v2(ctx.profile):
        result['capabilities'] = check_capabilities(ctx.profile['expected'], targets, verbose)
        result['fixture'] = fixture_probes(ctx, exe)
    return result


def impersonate_rows(lines):
    """`--list-impersonate-targets` rows as (client, os, source)."""
    rows, table = [], False
    for line in lines:
        if line.startswith('-----'):
            table = True
            continue
        if table and line.strip():
            parts = re.split(r'\s{2,}', line.strip())
            need(len(parts) == 3, f'Unparsed impersonate target row: {line.strip()}')
            rows.append(parts)
    need(rows, 'No impersonate target table')
    return rows


def check_capabilities(expected, targets, verbose):
    """Every expected impersonate target is available through curl_cffi, in the expected
    order, with nothing unavailable, plus the expected request handlers and libraries."""
    rows = impersonate_rows(targets)
    unavailable = [r for r in rows if r[2] != 'curl_cffi']
    need(not unavailable, f'Unavailable impersonate targets: {unavailable[:3]}')
    available = [[client, system] for client, system, _ in rows]
    missing = [t for t in expected['impersonate_targets'] if t not in available]
    need(not missing, f'Missing impersonate targets: {missing[:5]}')
    need(available == expected['impersonate_targets'], 'Impersonate targets differ from the expected list')
    need(verbose.get('Request Handlers') == expected['request_handlers'], f'Request handlers differ: {verbose.get("Request Handlers")}')
    need(verbose.get('Optional libraries') == expected['optional_libraries'], f'Optional libraries differ: {verbose.get("Optional libraries")}')
    families = sorted({client.split('-', 1)[0] for client, _ in available})
    return {'targets': len(available), 'families': families, 'request_handlers': verbose['Request Handlers']}


def error_line(tail):
    """The yt-dlp ERROR line of a failed run (its start carries the curl error code)."""
    line = next((l for l in reversed(tail) if l.startswith('ERROR:')), ' '.join(tail))
    return line[:400]


def check_refusal(row, what):
    """A request that must fail certificate validation: no success, no extraction, and curl's
    peer-verification error 60 rather than some other failure."""
    need(row['exit'] != 0 and not row['found_video'], f'{what} was accepted')
    need('curl: (60)' in row['error'], f'{what} failed for another reason: {row["error"][:200]}')


def fixture_probes(ctx, exe):
    """The frozen executable against the loopback fixture: each expected target completes
    TLS with normal validation against a throwaway CA, negotiates HTTP/2 and decodes the
    expected content encoding; without the CA, and with a wrong-name certificate, the
    request must fail certificate validation."""
    import ytdlp_source_fixture as fixture
    folder = ctx.work / 'fixture'
    folder.mkdir()
    pki = fixture.pki(folder / 'pki')
    rows = []

    def case(spec, index, verify=True, wrong=False):
        found = fixture.extractor_case(exe, spec['target'], spec['encoding'], pki, folder / f'home-{index}', verify=verify, wrong=wrong)
        hellos = [c['client_hello'] for c in found['connections'] if 'client_hello' in c]
        row = {'target': spec['target'], 'encoding': spec['encoding'], 'verify_file': verify, 'wrong_name': wrong, 'exit': found['exit'],
               'found_video': found['found_video'], 'alpn': [c.get('alpn') for c in found['connections']],
               'client_hello': [{k: h[k] for k in ('sni', 'alpn', 'fingerprint_sha256', 'order_sha256', 'cipher_suites', 'extensions', 'key_shares') if k in h} for h in hellos],
               'h2': [c['h2'] for c in found['connections'] if 'h2' in c], 'error': error_line(found['stderr_tail']) if found['exit'] else ''}
        need(not HOST_PATH.search(canonical(row)), 'Fixture result contains a host path')
        rows.append(row)
        return row

    for index, spec in enumerate(ctx.profile['expected']['fixture']):
        row = case(spec, index)
        need(row['exit'] == 0 and row['found_video'], f'Fixture {spec["target"]}/{spec["encoding"]} failed: {row["error"]}')
        need(row['alpn'] and all(a == 'h2' for a in row['alpn']) and row['h2'], f'Fixture {spec["target"]} did not negotiate HTTP/2')
        need(all(h.get('sni') == 'localhost' and 'h2' in h.get('alpn', []) for h in row['client_hello']), f'Fixture {spec["target"]} sent an unexpected ClientHello')
        need(any(f['type'] == 'SETTINGS' for f in row['h2'][0]['frames']) and row['h2'][0]['requests'], f'Fixture {spec["target"]} sent no HTTP/2 request')
    first = ctx.profile['expected']['fixture'][0]
    check_refusal(case(first, 'untrusted', verify=False), 'An untrusted certificate')
    check_refusal(case(first, 'mismatch', wrong=True), 'A certificate for another host name')
    return {'schema': fixture.SCHEMA, 'sandbox': fixture.SANDBOX, 'ca': 'throwaway, created per build, trusted only through SSL_CERT_FILE', 'cases': rows}


def verbose_header(ctx, argv, cwd, env):
    """`-v` with no URL prints the debug header and exits 2 without network access."""
    result = subprocess.run([str(a) for a in argv], cwd=cwd, env=env, capture_output=True, text=True, timeout=300, stdin=subprocess.DEVNULL)
    text = result.stdout + result.stderr
    (ctx.logs / 'probe-verbose.log').write_text(text)
    need(result.returncode == 2 and 'You must provide at least one URL' in text, f'Unexpected -v result {result.returncode}')
    return parse_verbose(text)


def parse_verbose(text):
    fields = {}
    for line in text.splitlines():
        if line.startswith('[debug] ') and ': ' in line:
            key, value = line[8:].split(': ', 1)
            if key in ('Optional libraries', 'Request Handlers', 'JS runtimes', 'exe versions', 'Plugin directories', 'Python version'):
                fields[key] = [v.strip() for v in value.split(',')] if key in ('Optional libraries', 'Request Handlers') else value
        elif line.startswith('[debug] Python '):
            fields['Python'] = line[len('[debug] '):]
    return fields


# ---------------------------------------------------------------- kit

LICENSE_NAME = re.compile(r'(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT)([._-].*)?', re.I)


def license_members(archive_path):
    """Top-level-ish license files of a source archive (tar or zip), byte-identical."""
    rows = []
    if str(archive_path).endswith(('.zip', '.whl')):
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                parts = PurePosixPath(info.filename).parts
                if not info.is_dir() and 2 <= len(parts) <= 3 and LICENSE_NAME.fullmatch(parts[-1]) and info.file_size <= 4 * 1024**2:
                    rows.append((info.filename, archive.read(info)))
        return rows
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if member.isfile() and 2 <= len(parts) <= 3 and LICENSE_NAME.fullmatch(parts[-1]) and member.size <= 4 * 1024**2:
                rows.append((member.name, archive.extractfile(member).read()))
    return rows


def generator_terms(profile, receipt, fingerprints, sources):
    """Build tools whose templates contributed shipped generated source (named by the
    receipt and the fingerprints) keep their notices next to the other terms."""
    packages = {r['source']['provenance']['generator']['package'] for r in fingerprints['rows']
                if (r.get('source') or {}).get('provenance', {}).get('kind') == 'wheel-build-generated'}
    rows = []
    for row in profile['inputs']:
        if row['kind'] == 'wheel' and row['role'] == 'build-tool' and row['package'] in packages:
            with zipfile.ZipFile(Path(sources) / row['file']) as archive:
                for name in archive.namelist():
                    parts = PurePosixPath(name).parts
                    if parts[0].endswith('.dist-info') and LICENSE_NAME.fullmatch(parts[-1]):
                        rows.append((row, name, archive.read(name)))
    need({r['package'] for r, _, _ in rows} == packages, f'Generator build tools without retained notices: {sorted(packages - {r["package"] for r, _, _ in rows})}')
    return rows


def generated_sources(receipt, fingerprints, build_output):
    """Generated sources compiled or packed into the executable, from the build tree, each
    bound to the digest the receipt or fingerprints recorded."""
    rows = []
    binding = receipt.get('curl_binding')
    if binding:
        found = sorted(Path(build_output, 'work', 'src').glob(f'sdist-*/*/{binding["generated_source"]["path"]}'))
        need(len(found) == 1 and file_sha(found[0]) == binding['generated_source']['sha256'], 'The generated curl_cffi wrapper differs from the receipt')
        rows.append((f'generated/curl_cffi/{PurePosixPath(binding["generated_source"]["path"]).name}', found[0].read_bytes()))
    site = Path(build_output, 'work', 'runtime', 'lib', 'python3.13', 'site-packages')
    for row in fingerprints['rows']:
        provenance = (row.get('source') or {}).get('provenance', {})
        if provenance.get('kind') == 'wheel-build-generated':
            path = public_inputs.regular(site / row['source']['path'])
            need(file_sha(path) == provenance['output_sha256'], f'Generated source differs from the fingerprints: {row["source"]["path"]}')
            rows.append((f'generated/{row["source"]["path"]}', path.read_bytes()))
    return rows


def make_kit(repo, plan_path, sources, build_output, output):
    """Deterministic source/rebuild kit of a built prototype."""
    repo, sources, build_output = Path(os.path.abspath(repo)), signing.no_link_ancestors(sources), signing.no_link_ancestors(build_output)
    plan = check_plan(plan_path, repo, sources)
    profile_rel = plan_profile(plan)
    profile = load_profile(repo / profile_rel)
    receipt = strict_load(build_output / 'receipt.json')
    need(receipt.get('status') == 'built' and receipt.get('plan_sha256') == file_sha(plan_path), 'Kit requires a built receipt for this exact plan')
    need(not HOST_PATH.search(canonical(receipt)) and not HOST_PATH.search(canonical(plan)), 'Authored metadata contains a host path')
    output = signing.new_file(output, 'Kit')
    need(not signing.within(output, sources) and not signing.within(output, repo) and not signing.within(output, build_output), 'Kit must be outside sources, the engine and the build')
    entries = {}

    def add(name, data, role):
        public_inputs.relative(name)
        need(name not in entries, f'Duplicate kit member: {name}')
        entries[name] = (data, role)

    rels = [*profile_files(profile_rel, profile), PROFILES[profile_rel], 'LICENSE']
    if profile_rel != PROFILE_REL:
        # The bundled guard tests load both profiles, so a curl kit also carries the lean profile files.
        rels += [rel for rel in [*profile_files(PROFILE_REL, load_profile(repo / PROFILE_REL)), README_REL] if rel not in rels]
    for rel in rels:
        add(f'engine/{rel}', public_inputs.regular(repo / rel).read_bytes(), 'first-party' if rel == 'LICENSE' or 'yt-dlp-source' in rel else 'legacy-profile')
    for name in KIT_TOOLING:
        add(f'engine/scripts/{name}', public_inputs.regular(SCRIPTS / name).read_bytes(), 'first-party-tooling')
    roles = {row['file']: row['role'] for row in profile['inputs']}
    for row in plan['inputs'] + plan['npm']:
        data = (sources / row['file']).read_bytes()
        need(sha(data) == row['sha256'], f'Source changed: {row["file"]}')
        add(f'sources/{row["file"]}', data, roles.get(row['file'], 'build-tool'))
    terms = []
    for row in profile['inputs']:
        if row['role'] != 'build-tool':
            for member, data in license_members(sources / row['file']):
                name = f'terms/{row["id"].replace(":", "-")}/{member}'
                add(name, data, 'third-party-terms')
                terms.append({'input': row['id'], 'archive_member': member, 'path': name, 'sha256': sha(data)})
    add('receipt/plan.json', public_inputs.regular(plan_path).read_bytes(), 'receipt')
    add('receipt/build-receipt.json', (build_output / 'receipt.json').read_bytes(), 'receipt')
    fingerprints = public_inputs.regular(build_output / FINGERPRINTS).read_bytes()
    need(sha(fingerprints) == receipt.get('closure', {}).get('python', {}).get('fingerprints', {}).get('sha256'), 'Closure fingerprints differ from the receipt')
    need(not HOST_PATH.search(fingerprints.decode()), 'Closure fingerprints contain a host path')
    add(f'receipt/{FINGERPRINTS}', fingerprints, 'receipt')
    fingerprint_rows = signing.strict_json(fingerprints)
    for tool, member, data in generator_terms(profile, receipt, fingerprint_rows, sources):
        name = f'terms/{tool["id"].replace(":", "-")}/{member}'
        add(name, data, 'generator-terms')
        terms.append({'input': tool['id'], 'archive_member': member, 'path': name, 'sha256': sha(data), 'reason': 'template contributes shipped generated source'})
    generated = []
    for name, data in generated_sources(receipt, fingerprint_rows, build_output):
        add(name, data, 'generated-source')
        generated.append({'path': name, 'sha256': sha(data)})
    patches = []
    if is_v2(profile):
        recipe = by_id(profile, profile['impersonate']['input'])
        for rel, data in sorted(archive_files(sources / recipe['file'], set(profile['impersonate']['patches'])).items()):
            need(sha(data) == profile['impersonate']['patches'][rel], f'Recipe patch changed: {rel}')
            add(f'patches/curl-impersonate/{PurePosixPath(rel).name}', data, 'recipe-patch')
            patches.append({'path': f'patches/curl-impersonate/{PurePosixPath(rel).name}', 'archive_member': rel, 'sha256': sha(data)})
    add('README.md', public_inputs.regular(repo / PROFILES[profile_rel]).read_bytes(), 'first-party')
    index = {'schema': KIT_SCHEMA, 'profile': profile['id'], 'profile_file': profile_rel, 'release_accepted': False, 'promotable': False,
             'plan_sha256': file_sha(plan_path), 'executable_sha256': receipt['output']['sha256'], 'fingerprints_sha256': sha(fingerprints), 'terms': terms,
             'generated_sources': generated, 'patches': patches,
             'files': [{'path': n, 'role': r, 'bytes': len(d), 'sha256': sha(d)} for n, (d, r) in sorted(entries.items())],
             'limits': limits_for(profile) + ['The kit carries every pinned input unchanged; terms/, patches/ and generated/ copies are byte-identical '
                                              'archive members or recorded build outputs, for convenience.']}
    need(not HOST_PATH.search(canonical(index)), 'Kit index contains a host path')
    add('KIT-INDEX.json', json_bytes(index), 'index')
    total = sum(len(d) for d, _ in entries.values())
    need(total <= MAX_KIT_BYTES, 'Kit exceeds its size budget')
    epoch = profile['source_date_epoch']
    with open(output, 'xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=9) as compressed, \
            tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, (data, _) in sorted(entries.items()):
            info = tarfile.TarInfo(f'{KIT_PREFIX}/{name}')
            info.size, info.mtime, info.mode, info.uid, info.gid, info.uname, info.gname = len(data), epoch, 0o644, 0, 0, '', ''
            tar.addfile(info, io.BytesIO(data))
    return {'kit': output.name, **identity(output), 'files': len(entries), 'payload_bytes': total}


def verify_kit(path, expected_sha256=None):
    path = public_inputs.regular(path)
    found = identity(path)
    if expected_sha256:
        need(found['sha256'] == expected_sha256, 'Kit digest differs from the expected value')
    members, folded, total = {}, set(), 0
    with tarfile.open(path, 'r:gz') as tar:
        for info in tar:
            need(info.isfile(), f'Kit members must be regular files: {info.name}')
            need(info.name.startswith(KIT_PREFIX + '/'), f'Kit member outside the kit root: {info.name}')
            name = public_inputs.relative(info.name[len(KIT_PREFIX) + 1:])
            need(name.casefold() not in folded, f'Duplicate or colliding kit member: {name}')
            folded.add(name.casefold())
            total += info.size
            need(total <= MAX_KIT_BYTES, 'Kit exceeds its size budget')
            members[name] = tar.extractfile(info).read()
    need('KIT-INDEX.json' in members, 'Kit has no index')
    index = signing.strict_json(members.pop('KIT-INDEX.json'))
    need(index.get('schema') == KIT_SCHEMA and index.get('release_accepted') is False, 'Invalid kit index')
    listed = {row['path']: row for row in index['files']}
    need(set(listed) == set(members), f'Kit index and members differ: {sorted(set(listed) ^ set(members))[:5]}')
    for name, data in members.items():
        need(listed[name]['sha256'] == sha(data) and listed[name]['bytes'] == len(data), f'Kit member differs from its index: {name}')
    for category, prefix in (('generated_sources', 'generated/'), ('patches', 'patches/'), ('terms', 'terms/')):
        seen = set()
        for row in index.get(category, []):
            name = public_inputs.relative(row['path'])
            need(name.startswith(prefix) and name not in seen, f'Invalid or duplicate delivery member: {name}')
            seen.add(name)
            need(name in members, f'Missing delivery member: {name}')
            need(sha(members[name]) == row['sha256'], f'Changed delivery member: {name}')
    for name in ['receipt/plan.json', 'receipt/build-receipt.json', f'receipt/{FINGERPRINTS}']:
        need(name in members and not HOST_PATH.search(members[name].decode()), f'Missing receipt file or host path: {name}')
    profile_rel = index.get('profile_file', PROFILE_REL)
    need(profile_rel in PROFILES, f'Kit names an unknown profile: {profile_rel}')
    profile = signing.strict_json(members[f'engine/{profile_rel}'])
    for row in profile['inputs']:
        need(sha(members.get(f'sources/{row["file"]}', b'')) == row['sha256'], f'Kit lacks the pinned input {row["file"]}')
    plan = signing.strict_json(members['receipt/plan.json'])
    receipt = signing.strict_json(members['receipt/build-receipt.json'])
    need(receipt.get('status') == 'built' and receipt.get('plan_sha256') == sha(members['receipt/plan.json']) == index['plan_sha256'], 'Kit receipt does not bind its plan')
    fingerprints = sha(members[f'receipt/{FINGERPRINTS}'])
    need(fingerprints == index.get('fingerprints_sha256') == receipt.get('closure', {}).get('python', {}).get('fingerprints', {}).get('sha256'),
         'Kit closure fingerprints do not match the receipt')
    for rel, digest in plan['files'].items():
        need(sha(members.get(rel, b'')) == digest, f'Kit tooling or profile differs from the plan: {rel}')
    for row in plan['npm']:
        need(sha(members.get(f'sources/{row["file"]}', b'')) == row['sha256'], f'Kit lacks npm input {row["file"]}')
    fingerprint_rows = signing.strict_json(members[f'receipt/{FINGERPRINTS}'])
    want = {r['source']['provenance']['output_sha256'] for r in fingerprint_rows['rows'] if (r.get('source') or {}).get('provenance', {}).get('kind') == 'wheel-build-generated'}
    if receipt.get('curl_binding'):
        want.add(receipt['curl_binding']['generated_source']['sha256'])
    need({row['sha256'] for row in index.get('generated_sources', [])} == want, 'Kit generated sources differ from the receipt and fingerprints')
    if profile['schema'] == PROFILE_SCHEMA_V2:
        pinned = profile['impersonate']['patches']
        need(sorted(row['sha256'] for row in index.get('patches', [])) == sorted(pinned.values()), 'Kit recipe patches differ from the profile pins')
        release = receipt.get('impersonate', {}).get('release', {})
        need(release.get('sha256') and release.get('pkgconfig', {}).get('sha256') and receipt.get('curl_binding', {}).get('replay') == 'identical',
             'Kit receipt lacks the curl-impersonate release, release pkg-config and binding proof')
    return {'kit': path.name, **found, 'files': len(members) + 1, 'payload_bytes': total, 'executable_sha256': index['executable_sha256'], 'verified': True}


def split_kit(kit, output, part_bytes=128 * 1024**2):
    """Companion-delivery parts of a kit: a new directory with numbered parts no larger
    than `part_bytes` (at most 256 MiB) and a manifest binding each part and the whole."""
    kit = public_inputs.regular(kit)
    need(type(part_bytes) is int and 1024**2 <= part_bytes <= MAX_PART_BYTES, 'Part size must be between 1 MiB and 256 MiB')
    output = new_output_directory(output, [])
    whole, rows = hashlib.sha256(), []
    with open(kit, 'rb') as stream:
        while chunk := stream.read(part_bytes):
            name = f'{kit.name}.part{len(rows) + 1:03d}'
            (output / name).write_bytes(chunk)
            whole.update(chunk)
            rows.append({'file': name, 'bytes': len(chunk), 'sha256': sha(chunk)})
    need(whole.hexdigest() == file_sha(kit), 'Kit changed while splitting')
    manifest = {'schema': PARTS_SCHEMA, 'kit': kit.name, 'bytes': kit.stat().st_size, 'sha256': whole.hexdigest(), 'part_bytes': part_bytes, 'parts': rows,
                'release_accepted': False}
    (output / 'PARTS.json').write_bytes(json_bytes(manifest))
    return {'parts': len(rows), 'manifest_sha256': file_sha(output / 'PARTS.json'), 'kit_sha256': manifest['sha256']}


def join_kit(parts_dir, output):
    """Reassemble a kit from its parts after checking every part and the whole digest."""
    parts_dir = signing.no_link_ancestors(parts_dir)
    manifest = strict_load(public_inputs.regular(parts_dir / 'PARTS.json'))
    need(manifest.get('schema') == PARTS_SCHEMA and manifest['parts'], 'Not a kit parts manifest')
    need(sorted(p.name for p in parts_dir.iterdir()) == sorted(['PARTS.json', *[r['file'] for r in manifest['parts']]]), 'Unexpected files beside the kit parts')
    output = signing.new_file(output, 'Kit')
    whole = hashlib.sha256()
    with open(output, 'xb') as stream:
        for row in manifest['parts']:
            need(FILE.fullmatch(row['file']) and row['bytes'] <= MAX_PART_BYTES, 'Invalid part entry')
            data = public_inputs.regular(parts_dir / row['file']).read_bytes()
            need(len(data) == row['bytes'] and sha(data) == row['sha256'], f'Kit part differs from its manifest: {row["file"]}')
            whole.update(data)
            stream.write(data)
    need(whole.hexdigest() == manifest['sha256'] and output.stat().st_size == manifest['bytes'], 'Reassembled kit differs from the manifest')
    return {'kit': output.name, 'sha256': manifest['sha256'], 'parts': len(manifest['parts'])}
