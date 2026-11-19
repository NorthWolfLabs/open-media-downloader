# /// script
# requires-python = ">=3.12"
# ///
"""Prepare conservative locked Cargo notices; pending materials return exit 2."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
import native_review

SCHEMA='omd-native-notices-v2'
RUNTIME_PENDING='Rust standard library/compiler runtime materials are outside Cargo metadata; version-specific coverage review pending'
def sha(b): return hashlib.sha256(b).hexdigest()
def collect(home):
    return sorted(p for p in home.rglob('*') if p.is_file() and not p.is_symlink() and (re.search(r'(^|[-_.])(licen[cs]e|copying|copyright|notice|authors)([-_.]|$)',p.name,re.I) or any(part.casefold() in ('licenses','licences') for part in p.relative_to(home).parts[:-1]) or p.name=='sqlite3.c'))
def artifact_bindings(binaries, supplied):
    if not binaries or len(set(binaries))!=len(binaries):raise ValueError('Missing/duplicate declared native binaries')
    artifacts=[];seen=set()
    for value in supplied:
        name,file=value.split('=',1)
        if name not in binaries or name in seen:raise ValueError('Undeclared/duplicate supplied native binary')
        seen.add(name);data=Path(file).read_bytes()
        artifacts.append({'name':name,'sha256':sha(data),'bytes':len(data)})
    missing=sorted(set(binaries)-seen)
    return artifacts, (['Incomplete native executable binding; missing: '+', '.join(missing)] if missing else [])
def generate(a):
    artifacts,binding_pending=artifact_bindings(a.binary,a.artifact)
    cmd=['cargo','metadata','--locked','--format-version','1','--filter-platform',a.target,'--manifest-path',str(a.manifest)]
    if a.features: cmd+=['--features',a.features]
    m=json.loads(subprocess.check_output(cmd)); ps={p['id']:p for p in m['packages']}; ns={n['id']:n for n in m['resolve']['nodes']}; selected=set(); roots=[]
    def visit(i):
        if i in selected:return
        selected.add(i)
        for dep in ns[i]['dependencies']:visit(dep)
    for name in a.root:
        matches=[p for p in ps.values() if p['name']==name and p['source'] is None]
        if len(matches)!=1:raise ValueError('Missing/ambiguous root '+name)
        roots.append(matches[0]['id']);visit(roots[-1])
    ownership={t['name']:ps[i]['name'] for i in roots for t in ps[i]['targets'] if 'bin' in t['kind']}
    if any(name not in ownership for name in a.binary):raise ValueError('Binary not owned by explicit roots')
    toolchain=subprocess.check_output(['rustc','--version','--verbose'],text=True).strip()
    lock=(a.manifest.parent/'Cargo.lock').read_bytes()
    # Everything is validated and held in memory first: rejected evidence must
    # not leave a partial preparation behind.
    files={};rows=[];homes={}
    def keep(rel,data):
        if files.setdefault(rel,data)!=data:raise ValueError('Conflicting retained material identity')
        return {'path':rel,'sha256':sha(data)}
    # Pending items are keyed by category and exact identity; reviews address
    # keys, never message strings.
    pending=[(('toolchain-runtime',toolchain),RUNTIME_PENDING)]
    for i in sorted(selected,key=lambda i:(ps[i]['name'],ps[i]['version'])):
        p=ps[i];home=Path(p['manifest_path']).parent;key=p['name']+'-'+p['version'];ident=(p['name'],p['version'],p['source']);homes[ident]=home;texts=[]
        materials=collect(home)
        if p['source'] is None and not materials:
            candidate=a.manifest.parent/'LICENSE'
            if not candidate.exists():candidate=a.manifest.parent.parent/'LICENSE'
            if candidate.is_file():texts.append(keep('texts/'+key+'/LICENSE',candidate.read_bytes()))
        for f in materials:texts.append(keep('texts/'+key+'/'+f.relative_to(home).as_posix(),f.read_bytes()))
        if not texts:pending.append((('missing-packaged-texts',ident),key+': no packaged texts; exact-version upstream evidence required'))
        if p['source'] and any(x in p['name'] for x in ('sys','ring','wasmtime','cranelift')):pending.append((('native-applicability',ident),key+': embedded/native applicability review pending; full packaged texts retained'))
        rows.append({'name':p['name'],'version':p['version'],'source':p['source'],'license_metadata':p['license'],'features':ns[i]['features'],'texts':texts})
    if a.upstream_materials:
        evidence=json.loads(a.upstream_materials.read_text())
        for item in evidence:
            matches=[x for x in rows if x['name']==item['name'] and x['version']==item['version']]
            if len(matches)!=1:raise ValueError('Upstream material does not identify one package in the selected graph: '+item['name']+'@'+item['version'])
            row=matches[0]
            f=a.upstream_materials.parent/item['file'];data=f.read_bytes()
            if sha(data)!=item['sha256'] or not re.fullmatch('[a-f0-9]{40}',item['revision']):raise ValueError('Invalid upstream evidence')
            # Upstream workspaces can have multiple distinct LICENSE files, and
            # packaged terms must never be overwritten by an added source.
            text=keep('texts/'+item['name']+'-'+item['version']+'/upstream/'+item['revision']+'-'+item['sha256'][:16]+'-'+f.name,data)
            row['texts'].append({**text,'url':item['url'],'revision':item['revision']})
            ident=(row['name'],row['version'],row['source'])
            pending=[x for x in pending if x[0]!=('missing-packaged-texts',ident)]
            if ('upstream-text-applicability',ident) not in dict(pending):pending.append((('upstream-text-applicability',ident),item['name']+'-'+item['version']+': exact revision text retained; applicability review pending'))
    v={'schema':SCHEMA,'toolchain':toolchain,'coverage':'conservative target-filtered reachable graph including build/dev edges and workspace-unified features; not exact minimal shipped graph','target':a.target,'requested_features':a.features,'default_features':True,'roots':a.root,'binaries':a.binary,'binary_roots':{name:ownership[name] for name in a.binary},'lock_sha256':sha(lock),'artifacts':artifacts,'packages':rows,'review':None,'runtime_materials':[],'release_accepted':False}
    scope=native_review.scope_of(v);review_input=None
    if a.review_evidence:
        review_input,findings,retained,resolved=native_review.ingest(a.review_evidence,scope,{k for k,_ in pending},homes,native_review.lock_checksums(lock))
        for item in retained:
            text={**keep(item['path'],item['data']),'review_finding':item['finding'],'kind':item['kind'],'reason':item['reason'],'origin':item['origin']}
            if item['ident'] is None:v['runtime_materials'].append(text)
            else:next(r for r in rows if (r['name'],r['version'],r['source'])==item['ident'])['texts'].append(text)
        pending=[x for x in pending if x[0] not in resolved]
        v['review']={'schema':native_review.SCHEMA,'input':'review-input.json','input_sha256':sha(review_input),'findings':findings}
    v['pending']=[message for _,message in pending]+binding_pending
    a.output.mkdir(parents=True,exist_ok=False)
    for rel,data in files.items():
        dest=a.output/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
    if review_input is not None:(a.output/'review-input.json').write_bytes(review_input)
    # Retain full texts in one installable asset. Offsets bind every recorded
    # source text to actual bytes, without relying on an uninspected tarball.
    aggregate=bytearray()
    for label,texts in [*((row['name']+'@'+row['version'],row['texts']) for row in rows),('rust-toolchain',v['runtime_materials'])]:
        for text in texts:
            data=(a.output/text['path']).read_bytes()
            if sha(data)!=text['sha256']:raise ValueError('Retained native text changed')
            aggregate.extend(('===== '+label+' / '+text['path']+' =====\n').encode())
            text.update(offset=len(aggregate),bytes=len(data))
            aggregate.extend(data);aggregate.extend(b'\n\n')
    (a.output/'native-NOTICES.txt').write_bytes(aggregate)
    v['notices']={'path':'native-NOTICES.txt','sha256':sha(aggregate),'bytes':len(aggregate)}
    # The exact scope a review must restate; separate engine/desktop runs differ.
    (a.output/'review-scope.json').write_text(json.dumps(scope,indent=2,sort_keys=True)+'\n')
    (a.output/'receipt.json').write_text(json.dumps(v,indent=2,sort_keys=True)+'\n');return 2 if v['pending'] else 0
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--upstream-materials',type=Path);p.add_argument('--review-evidence',type=Path);p.add_argument('--target',required=True);p.add_argument('--root',action='append',required=True);p.add_argument('--binary',action='append',default=[]);p.add_argument('--artifact',action='append',default=[]);p.add_argument('--features',default='')
    raise SystemExit(generate(p.parse_args()))
