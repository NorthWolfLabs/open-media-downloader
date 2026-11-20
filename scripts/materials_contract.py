# /// script
# requires-python = ">=3.12"
# ///
"""Release materials contract v1. No SPDX-based acceptance decisions."""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

KINDS = ['notices', 'source', 'instructions', 'provenance']
# macOS installs the native sign-in window as an application bundle beside the
# engine, so the launched process has its own bundle identity. Every other engine
# binary, and every binary on Linux and Windows, is a plain bin/ file.
SIGN_IN_BINARY = 'omd-signin'
SIGN_IN_BUNDLE = 'OMD Sign-In.app'
SIGN_IN_EXECUTABLE = f'bin/{SIGN_IN_BUNDLE}/Contents/MacOS/{SIGN_IN_BINARY}'
def macos(target): return isinstance(target, str) and (target.startswith('darwin-') or target.endswith('-apple-darwin'))
def binary_path(name, target):
    """Installed path of an engine binary relative to the runtime/resources root."""
    if name == SIGN_IN_BINARY and macos(target): return SIGN_IN_EXECUTABLE
    return 'bin/' + name + ('.exe' if isinstance(target, str) and (target.startswith('win32-') or 'windows' in target) else '')
def binary_name(path):
    """Receipt name of an installed engine binary path, or None for other files."""
    if path == SIGN_IN_EXECUTABLE: return SIGN_IN_BINARY
    rest = path[4:] if isinstance(path, str) and path.startswith('bin/') else ''
    return rest if rest and '/' not in rest else None
def sha(data): return hashlib.sha256(data).hexdigest()
def portable(value):
    if not isinstance(value, str) or not value or value.startswith('/') or any(ord(c)<32 for c in value) or any(c in value for c in '\\:') or any(p in ('', '.', '..') or p.endswith((' ', '.')) for p in value.split('/')):
        raise ValueError('Invalid portable path')
    return value

def validate(manifest, files, required, target, version, locks):
    def need(ok, why):
        if not ok: raise ValueError(why)
    need(not any(x in json.dumps(manifest) for x in ('/Users/', '/Volumes/', ':\\\\')), 'Machine-local material metadata')
    need(manifest.get('schema') == 'omd-materials-v1', 'Wrong materials schema')
    need(manifest.get('reviewed') is True and manifest.get('pending') == [], 'Materials review/pending coverage')
    need(manifest.get('target') == target and manifest.get('version') == version, 'Wrong materials target/version')
    need(manifest.get('locks') == locks and bool(locks), 'Stale/missing materials locks')
    need(isinstance(manifest.get('components'), list) and bool(manifest['components']), 'Empty component coverage')
    seen=set(); covered=set()
    for c in manifest['components']:
        name=c.get('id'); need(isinstance(name,str) and name not in seen, 'Duplicate/invalid component'); seen.add(name)
        need(isinstance(c.get('version'),str) and bool(c['version']), 'Missing component version')
        need(c.get('status') == 'reviewed' and c.get('pending') == [], 'Unresolved component')
        need(set(c.get('materials',{})) == set(KINDS), 'Missing required material kinds')
        need(isinstance(c.get('artifacts'),dict) and bool(c['artifacts']), 'Missing component artifacts')
        for group in [c['artifacts'], *c['materials'].values()]:
            need(isinstance(group,dict) and bool(group), 'Empty material coverage')
            for p,h in group.items():
                portable(p); need(isinstance(h,str) and re.fullmatch('[a-f0-9]{64}',h) and files.get(p)==h, 'Missing/changed material or artifact')
        if name in required and isinstance(required, dict):
            expected = required[name]
            need(c['version'] == expected['version'], 'Wrong component version')
            need(any(p.startswith(expected['prefix']) if expected['prefix'].endswith('/') else p == expected['prefix'] for p in c['artifacts']), 'Wrong component artifact')
        covered.update(c['artifacts'])
        for group in c['materials'].values(): covered.update(group)
    need(set(required) <= seen, 'Missing required components')
    need(set(files) <= covered, 'Uncovered installed files')
    return {'schema':'omd-materials-v1','coverage_validated':True,'release_accepted':False}

NATIVE_SCHEMA = 'omd-native-notices-v2'
REVIEW_SCHEMA = 'omd-native-review-v1'
CATEGORIES = ('missing-packaged-texts', 'native-applicability', 'upstream-text-applicability', 'toolchain-runtime')
MATERIAL_KINDS = ('legal-text', 'source-notice', 'attribution')
EVIDENCE_ROLES = ('crate-archive', 'published-archive', 'distribution-archive', 'inspection', 'upstream-document')

def validate_native_receipt(receipt, files, names, lock, target, notices, version):
    if receipt.get('schema') != NATIVE_SCHEMA or receipt.get('pending') != [] or receipt.get('lock_sha256') != lock or receipt.get('target') != target:
        raise ValueError('Stale/unresolved native receipt')
    def need(ok):
        if not ok:raise ValueError('Incomplete/unbound native notice evidence')
    def hexdigest(x): return isinstance(x,str) and re.fullmatch('[a-f0-9]{64}',x) is not None
    def statements(x): return isinstance(x,list) and bool(x) and all(isinstance(s,str) and s.strip() for s in x)
    def https(value):
        need(isinstance(value,str))
        parsed=urlsplit(value);need(parsed.scheme=='https' and bool(parsed.netloc) and not parsed.username and not parsed.password)
        return parsed
    def runtime_component(value):
        parsed=https(value);release=re.search(r'^release: (\S+)$',receipt['toolchain'],re.M);host=re.search(r'^host: (\S+)$',receipt['toolchain'],re.M)
        need(release and host and parsed.netloc=='static.rust-lang.org' and not parsed.query and not parsed.fragment)
        for component,triple in [('rustc',host[1]),('rust-std',target)]:
            if re.fullmatch(r'/dist/(?:\d{4}-\d{2}-\d{2}/)?'+re.escape(component+'-'+release[1]+'-'+triple)+r'\.tar\.(?:xz|gz)',parsed.path):return component
        need(False)
    need(receipt.get('release_accepted') is False)
    roots=receipt.get('roots');binaries=receipt.get('binaries');owners=receipt.get('binary_roots');packages=receipt.get('packages')
    need(isinstance(roots,list) and bool(roots) and all(isinstance(x,str) and x for x in roots) and len(set(roots))==len(roots))
    need(isinstance(binaries,list) and all(isinstance(x,str) for x in binaries) and len(binaries)==len(set(binaries)) and set(binaries)==set(names))
    need(isinstance(owners,dict) and set(owners)==set(names) and all(x in roots for x in owners.values()))
    need(isinstance(receipt.get('toolchain'),str) and bool(receipt['toolchain']) and isinstance(receipt.get('coverage'),str) and bool(receipt['coverage']))
    need(isinstance(receipt.get('requested_features'),str) and isinstance(receipt.get('default_features'),bool))
    descriptor=receipt.get('notices',{})
    need(isinstance(notices,bytes) and bool(notices) and isinstance(descriptor,dict) and type(descriptor.get('bytes')) is int and descriptor=={'path':'native-NOTICES.txt','sha256':sha(notices),'bytes':len(notices)} and files.get('third-party/native-NOTICES.txt')==sha(notices))
    need(isinstance(packages,list) and bool(packages))
    tagged={}
    def span(text, owner):
        # Every retained text, packaged or review-supplied, is bound to its bytes.
        need(isinstance(text,dict));portable(text.get('path'))
        start=text.get('offset');size=text.get('bytes')
        need(type(start) is int and type(size) is int and start>=0 and size>=0 and start+size<=len(notices))
        need(hexdigest(text.get('sha256')) and sha(notices[start:start+size])==text['sha256'])
        reviewed='review_finding' in text
        if reviewed:
            need(size>0 and isinstance(text['review_finding'],str) and text.get('kind') in MATERIAL_KINDS and isinstance(text.get('reason'),str) and text['reason'].strip() and isinstance(text.get('origin'),dict))
            tagged.setdefault(text['review_finding'],[]).append((owner,text['path'],text['kind'],text))
        need(reviewed or owner is not None)
        return size,reviewed,text.get('kind')
    seen=set();root_versions={}
    for package in packages:
        need(isinstance(package,dict) and {'name','version','source','license_metadata','features','texts'}<=set(package))
        need(package['source'] is None or isinstance(package['source'],str))
        need(package['license_metadata'] is None or isinstance(package['license_metadata'],str))
        name=package.get('name');pv=package.get('version');texts=package.get('texts');features=package.get('features')
        need(isinstance(name,str) and bool(name) and isinstance(pv,str) and bool(pv) and (name,pv) not in seen);seen.add((name,pv))
        need(isinstance(features,list) and all(isinstance(x,str) for x in features))
        need(isinstance(texts,list) and bool(texts))
        if name in roots:
            need(package.get('source') is None and name not in root_versions);root_versions[name]=pv
        spans=[span(text,(name,pv,package['source'])) for text in texts]
        need(sum(x[0] for x in spans)>0)
        # Review materials only replace missing packaged terms with full legal text.
        need(any(not reviewed or kind=='legal-text' for _,reviewed,kind in spans))
    need(set(root_versions)==set(roots) and all(pv==version for pv in root_versions.values()))
    runtime=receipt.get('runtime_materials')
    need(isinstance(runtime,list))
    for text in runtime:span(text,None)
    review=receipt.get('review')
    need(isinstance(review,dict) and review.get('schema')==REVIEW_SCHEMA and hexdigest(review.get('input_sha256')) and isinstance(review.get('findings'),list) and bool(review['findings']))
    identities={(p['name'],p['version'],p['source']) for p in packages}
    ids=set();keys=set();runtime_findings=0
    for finding in review['findings']:
        need(isinstance(finding,dict) and isinstance(finding.get('id'),str) and re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,127}',finding['id']) and finding['id'] not in ids)
        ids.add(finding['id']);category=finding.get('category');subject=finding.get('subject')
        need(category in CATEGORIES and isinstance(subject,dict))
        if category=='toolchain-runtime':
            need(subject=={'toolchain':receipt['toolchain']});owner=None;runtime_findings+=1
        else:
            need(set(subject)=={'name','version','source'} and all(isinstance(subject[k],str) for k in subject))
            owner=(subject['name'],subject['version'],subject['source']);need(owner in identities)
        need((category,owner) not in keys);keys.add((category,owner))
        need(statements(finding.get('facts')) and statements(finding.get('limits')))
        need(isinstance(finding.get('evidence'),list))
        evidence={}
        for entry in finding['evidence']:
            need(isinstance(entry,dict) and entry.get('role') in EVIDENCE_ROLES and hexdigest(entry.get('sha256')) and type(entry.get('bytes')) is int and entry['bytes']>=0);portable(entry.get('path'))
            need(entry['path'] not in evidence);evidence[entry['path']]=entry
            if entry['role'] not in ('crate-archive','inspection'):https(entry.get('url'))
            if entry['role'] in ('crate-archive','published-archive','distribution-archive'):need(entry['bytes']>0)
        crates=[path for path,e in evidence.items() if e['role']=='crate-archive']
        if owner is None:
            need(not crates)
            need(sorted(runtime_component(e.get('url')) for e in evidence.values() if e['role']=='distribution-archive')==['rust-std','rustc'])
        else:need(len(crates)==1)
        materials=finding.get('materials')
        need(isinstance(materials,list) and all(isinstance(x,str) for x in materials) and len(set(materials))==len(materials))
        spans=tagged.get(finding['id'],[])
        need(sorted(materials)==sorted(path for _,path,_,_ in spans) and all(o==owner for o,_,_,_ in spans))
        kinds={path:kind for _,path,kind,_ in spans}
        origins={}
        for _,path,kind,text in spans:
            origin=text['origin'];origins[path]=origin;typ=origin.get('type')
            if typ=='archive-member':
                need(set(origin)=={'type','archive','member','archive_sha256'});portable(origin['member']);portable(origin['archive'])
                entry=evidence.get(origin['archive']);need(entry is not None and entry['role'] in ('crate-archive','published-archive','distribution-archive') and origin['archive_sha256']==entry['sha256'])
                need(kind!='source-notice' or entry['role'] in ('crate-archive','published-archive'))
                need(owner is not None or entry['role']=='distribution-archive')
            elif typ=='upstream-revision':
                need(set(origin)=={'type','url','revision'} and isinstance(origin['revision'],str) and re.fullmatch('[a-f0-9]{40}',origin['revision']) and origin['revision'] in origin['url']);https(origin['url'])
                need(kind!='attribution' and owner is not None)
            elif typ=='published-terms':
                need(set(origin)=={'type','url'} and kind=='legal-text' and owner is not None);https(origin['url'])
            else:need(False)
        need(category!='missing-packaged-texts' or 'legal-text' in kinds.values())
        need(category!='toolchain-runtime' or bool(materials))
        copied=finding.get('copied_sources',[])
        need(isinstance(copied,list) and (not copied or owner is not None))
        for source in copied:
            need(isinstance(source,dict) and all(isinstance(source.get(k),str) and source[k] for k in ('name','version')) and hexdigest(source.get('archive_sha256')) and statements(source.get('members')) and statements(source.get('facts')) and statements(source.get('materials')))
            portable(source.get('archive'))
            for member in source['members']:portable(member)
            need(set(source['materials'])<=set(materials) and {'legal-text','source-notice'}<={kinds[x] for x in source['materials']})
            entry=evidence.get(source['archive']);need(entry is not None and entry['role']=='published-archive' and entry['sha256']==source['archive_sha256'])
            need(any(kinds[p]=='legal-text' and (origins[p]['type']=='upstream-revision' or origins[p].get('archive')==source['archive']) for p in source['materials']))
            need(any(kinds[p]=='source-notice' and origins[p].get('archive')==crates[0] for p in source['materials']))
    need(set(tagged)<=ids and runtime_findings==1)
    artifacts = {x['name']: x['sha256'] for x in receipt.get('artifacts', [])}
    if len(artifacts) != len(receipt.get('artifacts', [])) or set(artifacts) != set(names) or any(files.get(binary_path(n, target)) != artifacts[n] for n in names):
        raise ValueError('Native receipt artifact mismatch')
