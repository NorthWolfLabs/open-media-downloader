# /// script
# requires-python = ">=3.12"
# ///
"""Exact-scope native review evidence (omd-native-review-v1).

A review records factual findings against specific generator pending items. It
never decides legal compliance, never trusts SPDX metadata and never accepts a
release. Anything not covered by a validated finding stays pending.
"""
import hashlib
import json
import re
import stat
import tarfile
import tomllib
import zipfile
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from materials_contract import portable, sha

SCHEMA = 'omd-native-review-v1'
SCOPE_KEYS = ('target', 'toolchain', 'lock_sha256', 'requested_features', 'default_features', 'roots', 'binaries', 'binary_roots', 'artifacts', 'packages')
# Executable binding is deliberately absent: only a supplied artifact clears it.
CATEGORIES = ('missing-packaged-texts', 'native-applicability', 'upstream-text-applicability', 'toolchain-runtime')
KINDS = ('legal-text', 'source-notice', 'attribution')
ROLES = ('crate-archive', 'published-archive', 'distribution-archive', 'inspection', 'upstream-document')
ARCHIVES = ('crate-archive', 'published-archive', 'distribution-archive')
REGISTRY = ('registry+', 'sparse+')
LOCAL = ('/Users/', '/Volumes/', '/home/', ':\\')
ID = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}')
HEX40 = re.compile(r'[a-f0-9]{40}')
LEGAL = re.compile(r'(^|[-_.])(licen[cs]e|copying|copyright|notice|unlicense)([-_.]|$)', re.I)
MAX_ARCHIVE_BYTES = 2 * 1024**3


def need(ok, why):
    if not ok:
        raise ValueError(why)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def strict_json(text):
    def pairs(items):
        need(len({k for k, _ in items}) == len(items), 'Duplicate key in review evidence')
        return dict(items)
    def constant(_):
        raise ValueError('Non-finite number in review evidence')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def fields(value, required, optional=(), what='review entry'):
    need(isinstance(value, dict) and set(required) <= set(value) <= {*required, *optional}, 'Unknown/missing fields in ' + what)


def statements(value, why):
    need(isinstance(value, list) and bool(value) and all(isinstance(x, str) and x.strip() for x in value), why)
    return list(value)


def https(url):
    need(isinstance(url, str) and re.fullmatch(r'https://[^\s/]+/\S+', url) is not None, 'Provenance URL must be an absolute https URL')
    return url


def legal_name(path):
    parts = PurePosixPath(path).parts
    return bool(LEGAL.search(parts[-1])) or any(x.casefold() in ('licenses', 'licences') for x in parts[:-1])


def scope_of(receipt):
    """Exact review scope for a native receipt (v1 or v2 field layout)."""
    scope = {k: receipt[k] for k in SCOPE_KEYS if k != 'packages'}
    # Freeze pre-review materials too. A changed upstream document must not
    # inherit an earlier applicability review, and appending reviewed materials
    # below must not mutate the scope we validated.
    scope['packages'] = [{**{k: p[k] for k in ('name', 'version', 'source', 'features')}, 'texts': [dict(t) for t in p['texts']]} for p in receipt['packages']]
    return scope


def distribution_component(url, release, host, target):
    parsed = urlsplit(url)
    need(parsed.scheme == 'https' and parsed.netloc == 'static.rust-lang.org' and not parsed.query and not parsed.fragment, 'Runtime requires an official distribution URL')
    for component, triple in (('rustc', host), ('rust-std', target)):
        name = re.escape(component + '-' + release + '-' + triple)
        if re.fullmatch(r'/dist/(?:\d{4}-\d{2}-\d{2}/)?' + name + r'\.tar\.(?:xz|gz)', parsed.path):
            return component
    raise ValueError('Runtime requires exact release/target distribution components')


def lock_checksums(lock):
    return {(p['name'], p['version'], p.get('source')): p.get('checksum') for p in tomllib.loads(lock.decode()).get('package', [])}


def review_file(base, rel):
    portable(rel)
    path = base
    for part in rel.split('/'):
        path = path / part
        need(not path.is_symlink(), 'Symlinked review input: ' + rel)
    need(path.is_file(), 'Missing review input: ' + rel)
    return path


class Archive:
    """Read-only member access; nothing is extracted to disk."""
    def __init__(self, path, strict):
        self.zip = zipfile.is_zipfile(path)
        try:
            self.container = zipfile.ZipFile(path) if self.zip else tarfile.open(path, 'r:*')
        except (tarfile.TarError, zipfile.BadZipFile) as error:
            raise ValueError('Unreadable review archive') from error
        self.members = {}
        try:
            self._index(strict)
        except BaseException:
            self.container.close()
            raise

    def _index(self, strict):
        total = 0
        for member in self.container.infolist() if self.zip else self.container.getmembers():
            name = member.filename if self.zip else member.name
            try:
                portable(name.rstrip('/') if (member.is_dir() if self.zip else member.isdir()) else name)
            except ValueError:
                need(not strict, 'Unsafe archive member')
                continue
            if member.is_dir() if self.zip else member.isdir():
                continue
            mode = member.external_attr >> 16 if self.zip else 0
            regular = (stat.S_IFMT(mode) in (0, stat.S_IFREG)) if self.zip else member.isreg()
            if not regular:
                need(not strict, 'Non-regular published archive member')
                continue
            need(name not in self.members, 'Duplicate archive member')
            total += member.file_size if self.zip else member.size
            need(total <= MAX_ARCHIVE_BYTES, 'Archive exceeds review budget')
            self.members[name] = member

    def read(self, name):
        need(isinstance(name, str) and name in self.members, 'Archive member missing: ' + str(name))
        return self.container.read(self.members[name]) if self.zip else self.container.extractfile(self.members[name]).read()


def verify_crate(archive, prefix, home):
    """Local package source must be byte-identical to the published archive."""
    need(all(x.startswith(prefix + '/') for x in archive.members), 'Crate archive layout mismatch')
    published = {x[len(prefix) + 1:]: sha(archive.read(x)) for x in archive.members}
    local = {}
    for path in sorted(home.rglob('*')):
        need(not path.is_symlink(), 'Symlink in local package source')
        if path.is_file():
            rel = path.relative_to(home).as_posix()
            if rel != '.cargo-ok':
                local[rel] = sha(path.read_bytes())
    need(local == published, 'Local package source differs from its published archive')


def ingest(review_path, scope, pending, homes, checksums):
    """Validate review evidence against one exact generator scope.

    pending: reviewable (category, subject) keys; homes/checksums: package
    identity -> local source directory / Cargo.lock checksum. Returns input
    bytes, applied findings, materials to retain and resolved keys.
    """
    data = review_path.read_bytes()
    text = data.decode('utf-8')
    need(not any(x in text for x in LOCAL), 'Machine-local path in review evidence')
    review = strict_json(text)
    fields(review, ('schema', 'scope', 'findings'), what='review evidence')
    need(review['schema'] == SCHEMA, 'Wrong review evidence schema')
    need(isinstance(review['scope'], dict) and set(review['scope']) == set(SCOPE_KEYS), 'Incomplete review scope')
    stale = [k for k in SCOPE_KEYS if canonical(review['scope'][k]) != canonical(scope[k])]
    need(not stale, 'Stale review scope: ' + ', '.join(stale))
    need(isinstance(review['findings'], list) and bool(review['findings']), 'Empty review findings')
    release = re.search(r'^release: (\S+)$', scope['toolchain'], re.M)
    host = re.search(r'^host: (\S+)$', scope['toolchain'], re.M)
    identities = [(p['name'], p['version'], p['source']) for p in scope['packages']]
    base, archives, verified = review_path.parent, {}, set()
    applied, retained, resolved, ids = [], [], set(), set()

    def archive(rel, role):
        # Strict and lenient parses of one file are never shared.
        key = (rel, role != 'distribution-archive')
        if key not in archives:
            archives[key] = Archive(review_file(base, rel), key[1])
        return archives[key]

    try:
        for finding in review['findings']:
            fields(finding, ('id', 'category', 'subject', 'facts', 'limits', 'evidence', 'materials'), ('copied_sources',), 'review finding')
            fid, category, subject = finding['id'], finding['category'], finding['subject']
            need(isinstance(fid, str) and ID.fullmatch(fid) is not None and fid not in ids, 'Duplicate/invalid finding id')
            ids.add(fid)
            need(category in CATEGORIES, 'Unknown finding category')
            if category == 'toolchain-runtime':
                fields(subject, ('toolchain',), what='runtime subject')
                need(isinstance(subject['toolchain'], str), 'Invalid runtime subject')
                ident, key = None, (category, subject['toolchain'])
            else:
                fields(subject, ('name', 'version', 'source'), what='package subject')
                ident = (subject['name'], subject['version'], subject['source'])
                need(all(isinstance(x, str) and x for x in ident), 'Ambiguous package subject')
                need(identities.count(ident) == 1, 'Finding subject is not an exact scoped package')
                key = (category, ident)
            need(key not in resolved, 'Duplicate finding for one pending item')
            need(key in pending, 'Unknown finding: no matching pending item')
            statements(finding['facts'], 'Finding requires factual reasons')
            statements(finding['limits'], 'Finding requires stated limits')

            need(isinstance(finding['evidence'], list), 'Invalid finding evidence')
            evidence = {}
            for entry in finding['evidence']:
                fields(entry, ('path', 'sha256', 'bytes', 'role'), ('url',), 'evidence entry')
                need(entry['role'] in ROLES, 'Unknown evidence role')
                path = review_file(base, entry['path'])
                need(entry['path'] not in evidence, 'Duplicate evidence path')
                with path.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                need(type(entry['bytes']) is int and (digest, path.stat().st_size) == (entry['sha256'], entry['bytes']), 'Stale/changed review evidence: ' + entry['path'])
                if 'url' in entry:
                    https(entry['url'])
                need(entry['role'] in ('crate-archive', 'inspection') or 'url' in entry, 'Evidence requires its provenance URL')
                evidence[entry['path']] = entry
            crates = [p for p, e in evidence.items() if e['role'] == 'crate-archive']
            if ident is None:
                need(not crates, 'Runtime finding cannot bind a crate archive')
                dists = [e for e in evidence.values() if e['role'] == 'distribution-archive']
                need(release and host and dists, 'Runtime finding requires exact toolchain distribution archives')
                components = [distribution_component(e['url'], release[1], host[1], scope['target']) for e in dists]
                need(sorted(components) == ['rust-std', 'rustc'], 'Runtime requires compiler-host and standard-library-target distributions')
            else:
                need(ident[2].startswith(REGISTRY), 'Unsupported reviewed package source')
                need(len(crates) == 1, 'Package finding requires exactly one published crate archive')
                need(checksums.get(ident) == evidence[crates[0]]['sha256'], 'Crate archive does not match Cargo.lock checksum')
                if (ident, crates[0]) not in verified:
                    verify_crate(archive(crates[0], 'crate-archive'), ident[0] + '-' + ident[1], homes[ident])
                    verified.add((ident, crates[0]))

            need(isinstance(finding['materials'], list), 'Invalid finding materials')
            materials, dests = {}, {}
            for material in finding['materials']:
                fields(material, ('path', 'sha256', 'bytes', 'kind', 'reason', 'origin'), what='material entry')
                need(material['kind'] in KINDS, 'Unknown material kind')
                statements([material['reason']], 'Material requires an explicit reason')
                path = review_file(base, material['path'])
                need(material['path'] not in materials, 'Duplicate material')
                content = path.read_bytes()
                need(bool(content) and type(material['bytes']) is int and (sha(content), len(content)) == (material['sha256'], material['bytes']), 'Stale/changed review material: ' + material['path'])
                origin = material['origin']
                need(isinstance(origin, dict), 'Material requires provenance')
                if origin.get('type') == 'archive-member':
                    fields(origin, ('type', 'archive', 'member'), what='material origin')
                    need(isinstance(origin['archive'], str) and origin['archive'] in evidence and evidence[origin['archive']]['role'] in ARCHIVES, 'Material archive is not hash-bound evidence')
                    role = evidence[origin['archive']]['role']
                    need(archive(origin['archive'], role).read(origin['member']) == content, 'Material differs from its archive member')
                    need(material['kind'] != 'legal-text' or legal_name(origin['member']), 'Legal text must be a license document, not arbitrary source')
                    need(material['kind'] != 'source-notice' or role in ('crate-archive', 'published-archive'), 'Source notice must come from a published source archive')
                    need(material['kind'] != 'attribution' or role == 'distribution-archive' or ident is not None, 'Runtime attribution must come from its distribution')
                    origin = {**origin, 'archive_sha256': evidence[origin['archive']]['sha256']}
                elif origin.get('type') == 'upstream-revision':
                    fields(origin, ('type', 'url', 'revision'), what='material origin')
                    need(isinstance(origin['revision'], str) and HEX40.fullmatch(origin['revision']) is not None and origin['revision'] in https(origin['url']), 'Upstream material requires an immutable revision URL')
                    need(material['kind'] != 'attribution', 'Runtime attribution must come from its distribution')
                    need(material['kind'] != 'legal-text' or legal_name(origin['url'].rsplit('/', 1)[-1]), 'Legal text must be a license document, not arbitrary source')
                elif origin.get('type') == 'published-terms':
                    fields(origin, ('type', 'url'), what='material origin')
                    https(origin['url'])
                    need(material['kind'] == 'legal-text', 'Only full legal terms may use a steward publication')
                else:
                    need(False, 'Unknown material origin')
                dest = 'review/' + fid + '/' + material['sha256'][:16] + '-' + material['path'].rsplit('/', 1)[-1]
                materials[material['path']], dests[material['path']] = {**material, 'origin': origin}, dest
                retained.append({'finding': fid, 'ident': ident, 'path': dest, 'data': content, 'kind': material['kind'], 'reason': material['reason'], 'origin': origin})
            kinds = {m['kind'] for m in materials.values()}
            if category == 'missing-packaged-texts':
                need('legal-text' in kinds, 'Missing legal text: no full applicable terms supplied')
            if category == 'toolchain-runtime':
                need(any(m['origin']['type'] == 'archive-member' and evidence[m['origin']['archive']]['role'] == 'distribution-archive' for m in materials.values()), 'Runtime finding requires distribution materials')

            copied = []
            need(isinstance(finding.get('copied_sources', []), list), 'Invalid copied sources')
            for source in finding.get('copied_sources', []):
                fields(source, ('name', 'version', 'archive', 'members', 'materials', 'facts'), what='copied source')
                need(ident is not None and all(isinstance(source[k], str) and source[k] for k in ('name', 'version')), 'Copied source must attach to a package finding')
                need(isinstance(source['archive'], str) and source['archive'] in evidence and evidence[source['archive']]['role'] == 'published-archive', 'Copied source requires its published archive')
                prefix = source['name'] + '-' + source['version'] + '/'
                for member in statements(source['members'], 'Copied source requires its original files'):
                    need(member.startswith(prefix), 'Copied source member outside its archive')
                    archive(source['archive'], 'published-archive').read(member)
                selected = statements(source['materials'], 'Copied source requires materials')
                need(len(set(selected)) == len(selected) and set(selected) <= set(materials), 'Copied source material is not a finding material')
                statements(source['facts'], 'Copied source requires factual reasons')
                picked = [materials[x] for x in selected]
                need(any(m['kind'] == 'legal-text' and (m['origin']['type'] == 'upstream-revision' or m['origin'].get('archive') == source['archive']) for m in picked), 'Copied source requires its exact full terms')
                need(any(m['kind'] == 'source-notice' and m['origin'].get('archive') == crates[0] for m in picked), 'Copied source requires the retained adaptation notice')
                copied.append({'name': source['name'], 'version': source['version'], 'archive': source['archive'], 'archive_sha256': evidence[source['archive']]['sha256'], 'members': source['members'], 'materials': [dests[x] for x in selected], 'facts': source['facts']})

            record = {'id': fid, 'category': category, 'subject': subject, 'facts': finding['facts'], 'limits': finding['limits'], 'evidence': list(evidence.values()), 'materials': list(dests.values())}
            if copied:
                record['copied_sources'] = copied
            applied.append(record)
            resolved.add(key)
    finally:
        for value in archives.values():
            value.container.close()
    return data, applied, retained, resolved
