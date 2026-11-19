# /// script
# requires-python = ">=3.12"
# ///
import argparse, copy, hashlib, importlib.util, io, json, unittest
from unittest.mock import patch
from pathlib import Path
from materials_contract import validate, validate_native_receipt
class PublishedZip(unittest.TestCase):
 def test_original_members_and_rejected_unsafe_archives(self):
  import native_review, stat, tempfile, warnings, zipfile
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'sdk.nupkg'
   def write(entries):
    with warnings.catch_warnings():
     warnings.simplefilter('ignore',UserWarning)
     with zipfile.ZipFile(p,'w') as z:
      for name,data in entries:z.writestr(name,data)
   write([('build/',b''),('build/LICENSE.txt',b'Original full terms')])
   archive=native_review.Archive(p,True)
   try:self.assertEqual(archive.read('build/LICENSE.txt'),b'Original full terms')
   finally:archive.container.close()
   link=zipfile.ZipInfo('link');link.create_system=3;link.external_attr=(stat.S_IFLNK|0o777)<<16
   for entries,why in [([('../LICENSE',b'x')],'Unsafe'),([('LICENSE',b'x'),('LICENSE',b'y')],'Duplicate'),([(link,b'outside')],'Non-regular')]:
    write(entries)
    with self.assertRaisesRegex(ValueError,why):native_review.Archive(p,True)
   write([('LICENSE',b'long')])
   with patch.object(native_review,'MAX_ARCHIVE_BYTES',3):
    with self.assertRaisesRegex(ValueError,'budget'):native_review.Archive(p,True)
class Contract(unittest.TestCase):
 def test_shared_contract(self):
  f=json.loads((Path(__file__).resolve().parent.parent/'distribution/materials-contract-fixtures-v1.json').read_text())
  for c in f['cases']:
   with self.subTest(c['name']):
    args=(c['manifest'],c['files'],f['required'],f['target'],f['version'],f['locks'])
    if c['valid']:self.assertTrue(validate(*args)['coverage_validated'])
    else:
     with self.assertRaises(ValueError):validate(*args)
 def test_native_receipt_correspondence(self):
  f=json.loads((Path(__file__).resolve().parent.parent/'distribution/materials-contract-fixtures-v1.json').read_text())['native']
  for case in f['cases']:
   with self.subTest(case['name']):
    receipt=copy.deepcopy(f['receipt'])
    for key in case.get('remove',[]):receipt.pop(key)
    for key,value in case.get('set',{}).items():
     current=receipt;parts=key.split('.')
     for part in parts[:-1]:current=current[int(part)] if isinstance(current,list) else current[part]
     last=int(parts[-1]) if isinstance(current,list) else parts[-1];current[last]=value
    args=(receipt,f['files'],f['names'],f['lock'],f['target'],case.get('notice_text',f['notice_text']).encode(),f['version'])
    if case['valid']:validate_native_receipt(*args)
    else:
     with self.assertRaises(ValueError):validate_native_receipt(*args)
 def test_partial_and_duplicate_artifact_binding(self):
  import tempfile
  spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('generate-native-notices.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'fixture';p.write_bytes(b'fixture')
   artifacts,pending=m.artifact_bindings(['one','two'],['one='+str(p)])
   self.assertEqual(len(artifacts),1);self.assertTrue(any('two' in x for x in pending))
   self.assertEqual(m.artifact_bindings(['one'],['one='+str(p)])[1],[])
   with self.assertRaises(ValueError):m.artifact_bindings(['one'],['one='+str(p),'one='+str(p)])
 def test_full_embedded_material_selection(self):
  import tempfile
  spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('generate-native-notices.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp);(p/'embedded').mkdir()
   for n in ['LICENSE_MIT','NOTICE','sqlite3.c','ordinary.rs']:(p/'embedded'/n).write_text(n)
   (p/'LICENSES').mkdir()
   for n in ['MIT.txt','Apache-2.0.txt']:(p/'LICENSES'/n).write_text(n)
   self.assertEqual({x.relative_to(p).as_posix() for x in m.collect(p)},{'embedded/LICENSE_MIT','embedded/NOTICE','embedded/sqlite3.c','LICENSES/MIT.txt','LICENSES/Apache-2.0.txt'})
 def test_upstream_license_basenames_do_not_overwrite_retained_terms(self):
  import tempfile
  spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('generate-native-notices.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);project=root/'project';project.mkdir();manifest=project/'Cargo.toml';manifest.write_text('fixture');(project/'Cargo.lock').write_text('fixture lock');(project/'LICENSE').write_bytes(b'packaged terms')
   executable=root/'fixture';executable.write_bytes(b'fixture')
   evidence=[]
   for name,data in [('one',b'first upstream terms'),('two',b'second upstream terms')]:
    f=root/name/'LICENSE';f.parent.mkdir();f.write_bytes(data)
    evidence.append({'name':'org-example-root','version':'1','file':name+'/LICENSE','sha256':hashlib.sha256(data).hexdigest(),'revision':'f'*40,'url':'https://example.org/immutable/LICENSE'})
   upstream=root/'upstream.json';upstream.write_text(json.dumps(evidence))
   metadata={'packages':[{'id':'fixture','name':'org-example-root','version':'1','manifest_path':str(manifest),'source':None,'license':'MIT','targets':[{'name':'fixture','kind':['bin']}]}],'resolve':{'nodes':[{'id':'fixture','dependencies':[],'features':[]}]}}
   a=argparse.Namespace(manifest=manifest,output=root/'output',root=['org-example-root'],binary=['fixture'],artifact=['fixture='+str(executable)],features='',target='aarch64-apple-darwin',upstream_materials=upstream,review_evidence=None)
   with patch.object(m.subprocess,'check_output',side_effect=lambda cmd,**kw: 'synthetic toolchain' if cmd[0]=='rustc' else json.dumps(metadata).encode()):
    self.assertEqual(m.generate(a),2)
   receipt=json.loads((a.output/'receipt.json').read_text());data=(a.output/'native-NOTICES.txt').read_bytes();texts=receipt['packages'][0]['texts']
   self.assertEqual(len({x['path'] for x in texts}),3)
   self.assertEqual({data[x['offset']:x['offset']+x['bytes']] for x in texts},{b'packaged terms',b'first upstream terms',b'second upstream terms'})
   # A narrower binary graph must reject stale upstream entries clearly, before
   # creating any output or reading the irrelevant material file.
   upstream.write_text(json.dumps([{'name':'outside-graph','version':'1','file':'missing/LICENSE'}]))
   a.output=root/'invalid-output'
   with patch.object(m.subprocess,'check_output',side_effect=lambda cmd,**kw: 'synthetic toolchain' if cmd[0]=='rustc' else json.dumps(metadata).encode()):
    with self.assertRaisesRegex(ValueError,'selected graph: outside-graph@1'):m.generate(a)
   self.assertFalse(a.output.exists())

REGISTRY='registry+https://github.com/rust-lang/crates.io-index'
TOOLCHAIN='rustc 1.0.0 (synthetic)\nbinary: rustc\nhost: aarch64-apple-darwin\nrelease: 1.0.0'
def digest(data): return hashlib.sha256(data).hexdigest()
class ReviewEvidence(unittest.TestCase):
 """Synthetic exact-scope review: one registry crate with no packaged terms,
 embedded copied source, and the Rust runtime; all bytes are hash-bound."""
 def setUp(self):
  import tarfile, tempfile
  spec=importlib.util.spec_from_file_location('native',Path(__file__).with_name('generate-native-notices.py'));self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=self.root=Path(self.tmp.name)
  self.evidence=root/'evidence'
  def put(path,data):
   path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return path
  def archive(rel,prefix,members):
   path=self.evidence/rel;path.parent.mkdir(parents=True,exist_ok=True)
   with tarfile.open(path,'w:gz') as tar:
    for name,data in members.items():
     info=tarfile.TarInfo(prefix+'/'+name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
   return path
  self.put=put
  sys_files={'Cargo.toml':b'[package]\nname="fixture-sys"\n','src/lib.rs':b'pub mod chaos;\n','src/chaos.rs':b'// Adapted from copied 1.0.0 shuffle; see LICENSE-MIT there.\n'}
  self.home=root/'registry/fixture-sys-1.0.0'
  for name,data in sys_files.items():put(self.home/name,data)
  put(self.home/'.cargo-ok',b'{"v":1}')
  plain=root/'registry/plain-1.0.0';put(plain/'Cargo.toml',b'[package]\nname="plain"\n');put(plain/'LICENSE',b'plain packaged terms')
  crate=archive('crates/fixture-sys-1.0.0.crate','fixture-sys-1.0.0',sys_files)
  archive('crates/copied-1.0.0.crate','copied-1.0.0',{'LICENSE-MIT':b'copied full MIT terms','src/shuffle.rs':b'fn shuffle() {}\n'})
  archive('dist/rust-std-1.0.0-aarch64-apple-darwin.tar.gz','rust-std-1.0.0-aarch64-apple-darwin',{'COPYRIGHT':b'synthetic runtime copyright','LICENSE-MIT':b'synthetic runtime MIT'})
  archive('dist/rustc-1.0.0-aarch64-apple-darwin.tar.gz','rustc-1.0.0-aarch64-apple-darwin',{'LICENSE-MIT':b'synthetic compiler MIT'})
  put(self.evidence/'terms/LICENSE',b'full synthetic upstream terms for fixture-sys')
  put(self.evidence/'notices/chaos.rs',sys_files['src/chaos.rs']);put(self.evidence/'notices/LICENSE-MIT',b'copied full MIT terms')
  put(self.evidence/'notices/COPYRIGHT',b'synthetic runtime copyright');put(self.evidence/'inspection/fixture-sys.txt',b'inspection notes (hash reference only)')
  project=root/'project';self.manifest=put(project/'Cargo.toml',b'fixture');put(project/'LICENSE',b'first-party MIT terms')
  self.write_lock(digest(crate.read_bytes()))
  self.executable=put(root/'bin/fixture',b'fixture executable')
  self.toolchain=TOOLCHAIN
  pkg=lambda i,name,home,source:{'id':i,'name':name,'version':'1.0.0' if source else '1','manifest_path':str(home/'Cargo.toml'),'source':source,'license':'MIT','targets':[{'name':'fixture','kind':['bin']}] if not source else []}
  self.metadata={'packages':[pkg('root','org-example-root',project,None),pkg('sys','fixture-sys',self.home,REGISTRY),pkg('plain','plain',plain,REGISTRY)],'resolve':{'nodes':[{'id':'root','dependencies':['sys','plain'],'features':[]},{'id':'sys','dependencies':[],'features':['default']},{'id':'plain','dependencies':[],'features':[]}]}}
  code=self.generate(None,'scope-run');self.assertEqual(code,2)
  pending=json.loads((root/'scope-run/receipt.json').read_text())['pending']
  self.assertEqual(len(pending),3);self.assertIn('fixture-sys-1.0.0: no packaged texts; exact-version upstream evidence required',pending)
  scope=json.loads((root/'scope-run/review-scope.json').read_text())
  sys_subject={'name':'fixture-sys','version':'1.0.0','source':REGISTRY}
  crate_ev=self.entry('crates/fixture-sys-1.0.0.crate',role='crate-archive')
  self.review={'schema':'omd-native-review-v1','scope':scope,'findings':[
   {'id':'fixture-sys-terms','category':'missing-packaged-texts','subject':sys_subject,'facts':['Published archive contains no license document; exact upstream revision supplies full terms'],'limits':['Factual record only; no compliance determination'],'evidence':[crate_ev],
    'materials':[self.entry('terms/LICENSE',kind='legal-text',reason='Full terms at the exact upstream revision',origin={'type':'upstream-revision','url':'https://example.org/fixture/raw/'+'a'*40+'/LICENSE','revision':'a'*40})]},
   {'id':'fixture-sys-native','category':'native-applicability','subject':sys_subject,'facts':['Name matched the native heuristic; chaos.rs adapts copied 1.0.0 shuffle'],'limits':['Copied-source coverage only; not a Cargo dependency'],
    'evidence':[crate_ev,self.entry('crates/copied-1.0.0.crate',role='published-archive',url='https://static.crates.io/crates/copied/copied-1.0.0.crate'),self.entry('inspection/fixture-sys.txt',role='inspection')],
    'materials':[self.entry('notices/chaos.rs',kind='source-notice',reason='Retained adaptation notice',origin={'type':'archive-member','archive':'crates/fixture-sys-1.0.0.crate','member':'fixture-sys-1.0.0/src/chaos.rs'}),
                 self.entry('notices/LICENSE-MIT',kind='legal-text',reason='Exact terms of the copied source',origin={'type':'archive-member','archive':'crates/copied-1.0.0.crate','member':'copied-1.0.0/LICENSE-MIT'})],
    'copied_sources':[{'name':'copied','version':'1.0.0','archive':'crates/copied-1.0.0.crate','members':['copied-1.0.0/src/shuffle.rs'],'materials':['notices/chaos.rs','notices/LICENSE-MIT'],'facts':['chaos.rs adapts shuffle.rs']}]},
   {'id':'rust-runtime','category':'toolchain-runtime','subject':{'toolchain':TOOLCHAIN},'facts':['Attribution matches the exact official distribution'],'limits':['Historical link inputs are not reconstructed'],
    'evidence':[self.entry('dist/rust-std-1.0.0-aarch64-apple-darwin.tar.gz',role='distribution-archive',url='https://static.rust-lang.org/dist/rust-std-1.0.0-aarch64-apple-darwin.tar.gz'),self.entry('dist/rustc-1.0.0-aarch64-apple-darwin.tar.gz',role='distribution-archive',url='https://static.rust-lang.org/dist/rustc-1.0.0-aarch64-apple-darwin.tar.gz')],
    'materials':[self.entry('notices/COPYRIGHT',kind='attribution',reason='Runtime attribution',origin={'type':'archive-member','archive':'dist/rust-std-1.0.0-aarch64-apple-darwin.tar.gz','member':'rust-std-1.0.0-aarch64-apple-darwin/COPYRIGHT'})]}]}
 def write_lock(self,checksum,extra=''):
  self.manifest.with_name('Cargo.lock').write_text(f'version = 4\n{extra}\n[[package]]\nname = "fixture-sys"\nversion = "1.0.0"\nsource = "{REGISTRY}"\nchecksum = "{checksum}"\n\n[[package]]\nname = "plain"\nversion = "1.0.0"\nsource = "{REGISTRY}"\nchecksum = "{"0"*64}"\n')
 def entry(self,rel,**extra):
  data=(self.evidence/rel).read_bytes();return {'path':rel,'sha256':digest(data),'bytes':len(data),**extra}
 def generate(self,review,output,artifact=True,upstream=None):
  path=None
  if review is not None:
   path=self.evidence/'review.json';path.write_text(json.dumps(review) if not isinstance(review,str) else review)
  a=argparse.Namespace(manifest=self.manifest,output=self.root/output,root=['org-example-root'],binary=['fixture'],artifact=['fixture='+str(self.executable)] if artifact else [],features='',target='aarch64-apple-darwin',upstream_materials=upstream,review_evidence=path)
  with patch.object(self.m.subprocess,'check_output',side_effect=lambda cmd,**kw: self.toolchain if cmd[0]=='rustc' else json.dumps(self.metadata).encode()):
   return self.m.generate(a)
 def rejected(self,change,why=None,review=None,**kw):
  review=copy.deepcopy(self.review if review is None else review);change(review)
  self.attempt=getattr(self,'attempt',0)+1;output='rejected-'+str(self.attempt)
  with self.assertRaisesRegex(ValueError,why or '.') as caught:self.generate(review,output,**kw)
  self.assertFalse((self.root/output).exists(),'rejected review must not leave output')
  return caught.exception
 def test_exact_scope_closure_is_bound_and_validates(self):
  self.assertEqual(self.generate(self.review,'out'),0)
  out=self.root/'out';receipt=json.loads((out/'receipt.json').read_text());notices=(out/'native-NOTICES.txt').read_bytes()
  self.assertEqual(receipt['schema'],'omd-native-notices-v2');self.assertEqual(receipt['pending'],[]);self.assertIs(receipt['release_accepted'],False)
  self.assertEqual(receipt['review']['input_sha256'],digest((self.evidence/'review.json').read_bytes()));self.assertEqual((out/'review-input.json').read_bytes(),(self.evidence/'review.json').read_bytes())
  self.assertEqual([f['id'] for f in receipt['review']['findings']],['fixture-sys-terms','fixture-sys-native','rust-runtime'])
  self.assertNotIn(str(self.root),json.dumps(receipt))
  sys_texts=[t for p in receipt['packages'] if p['name']=='fixture-sys' for t in p['texts']]
  span=lambda t:notices[t['offset']:t['offset']+t['bytes']]
  self.assertEqual({t['kind']:span(t) for t in sys_texts if t['kind']!='legal-text'},{'source-notice':(self.home/'src/chaos.rs').read_bytes()})
  self.assertEqual(sorted(span(t) for t in sys_texts if t['kind']=='legal-text'),[b'copied full MIT terms',b'full synthetic upstream terms for fixture-sys'])
  self.assertEqual([span(t) for t in receipt['runtime_materials']],[b'synthetic runtime copyright'])
  copied=receipt['review']['findings'][1]['copied_sources'][0];self.assertEqual((copied['name'],copied['version']),('copied','1.0.0'))
  self.assertNotIn('copied',[p['name'] for p in receipt['packages']])
  files={'bin/fixture':digest(self.executable.read_bytes()),'third-party/native-NOTICES.txt':digest(notices)}
  validate_native_receipt(receipt,files,['fixture'],digest(self.manifest.with_name('Cargo.lock').read_bytes()),'aarch64-apple-darwin',notices,'1')
  # Anything not covered by a finding stays pending with its original wording.
  partial=copy.deepcopy(self.review);partial['findings']=partial['findings'][2:]
  self.assertEqual(self.generate(partial,'partial'),2)
  self.assertEqual(json.loads((self.root/'partial/receipt.json').read_text())['pending'],['fixture-sys-1.0.0: no packaged texts; exact-version upstream evidence required','fixture-sys-1.0.0: embedded/native applicability review pending; full packaged texts retained'])
 def test_stale_scope_rejects(self):
  self.write_lock(self.entry('crates/fixture-sys-1.0.0.crate')['sha256'],'# changed');self.rejected(lambda r:None,'Stale review scope: lock_sha256')
  self.setUp();self.toolchain=TOOLCHAIN+'\nLLVM version: 0';self.rejected(lambda r:None,'Stale review scope: toolchain')
  self.setUp();self.metadata['resolve']['nodes'][1]['features']=['default','extra'];self.rejected(lambda r:None,'Stale review scope: packages')
  self.setUp();self.executable.write_bytes(b'rebuilt executable');self.rejected(lambda r:None,'Stale review scope: artifacts')
  self.setUp();self.rejected(lambda r:r['scope']['packages'].append({'name':'extra','version':'1','source':REGISTRY,'features':[]}),'Stale review scope: packages')
 def test_upstream_material_scope_cannot_reuse_old_applicability(self):
  upstream=self.evidence/'upstream.json'
  def write(data,revision='a',host='example.org'):
   self.put(self.evidence/'upstream/LICENSE',data)
   upstream.write_text(json.dumps([{'name':'fixture-sys','version':'1.0.0','file':'upstream/LICENSE','sha256':digest(data),'revision':revision*40,'url':'https://'+host+'/'+revision*40+'/LICENSE'}]))
  write(b'original terms');self.generate(None,'upstream-scope',upstream=upstream)
  review=copy.deepcopy(self.review);review['scope']=json.loads((self.root/'upstream-scope/review-scope.json').read_text())
  review['findings'][0].update(category='upstream-text-applicability',materials=[])
  self.assertEqual(self.generate(review,'upstream-reviewed',upstream=upstream),0)
  self.assertEqual(json.loads((self.root/'upstream-reviewed/review-scope.json').read_text()),review['scope'])
  for index,args in enumerate([(b'changed terms',),(b'original terms','b'),(b'original terms','a','other.example')]):
   write(*args)
   self.rejected(lambda r:None,'Stale review scope: packages',review=review,upstream=upstream)
 def test_changed_bytes_reject(self):
  self.put(self.evidence/'inspection/fixture-sys.txt',b'edited notes');self.rejected(lambda r:None,'Stale/changed review evidence')
  self.setUp();self.put(self.evidence/'terms/LICENSE',b'edited terms');self.rejected(lambda r:None,'Stale/changed review material')
  self.setUp();self.put(self.home/'src/lib.rs',b'locally modified source');self.rejected(lambda r:None,'differs from its published archive')
  # A file planted beside the published bytes is caught by the archive comparison.
  self.setUp();self.put(self.home/'LICENSE',b'planted terms')
  self.rejected(lambda r:r['findings'].pop(0),'Stale review scope: packages')
  self.setUp();self.write_lock('1'*64);lock=digest(self.manifest.with_name('Cargo.lock').read_bytes())
  self.rejected(lambda r:r['scope'].update(lock_sha256=lock),'does not match Cargo.lock checksum')
  self.setUp();self.put(self.evidence/'notices/chaos.rs',b'// not the archive bytes\n')
  self.rejected(lambda r:r['findings'][1]['materials'][0].update(self.entry('notices/chaos.rs')),'differs from its archive member')
 def test_malformed_findings_reject(self):
  f=lambda i:(lambda r:r['findings'][i])
  cases=[
   (lambda r:f(0)(r).update(category='executable-binding'),'Unknown finding category'),
   (lambda r:f(0)(r).update(subject={'name':'plain','version':'1.0.0','source':REGISTRY}),'Unknown finding'),
   (lambda r:f(1)(r).update(id='fixture-sys-terms'),'Duplicate/invalid finding id'),
   (lambda r:f(1)(r).update(category='missing-packaged-texts'),'Duplicate finding'),
   (lambda r:f(0)(r)['subject'].pop('source'),'Unknown/missing fields'),
   (lambda r:f(0)(r).update(facts=[]),'factual reasons'),
   (lambda r:f(0)(r).update(limits=[' ']),'stated limits'),
   (lambda r:r.update(release_accepted=True),'Unknown/missing fields'),
   (lambda r:f(0)(r).update(clear=['fixture-sys-1.0.0: no packaged texts']),'Unknown/missing fields'),
   (lambda r:f(0)(r)['facts'].append('reviewed at /Users/someone/cache'),'Machine-local'),
   (lambda r:f(0)(r)['materials'][0].update(kind='source-notice'),'Missing legal text|Source notice'),
   (lambda r:f(0)(r).update(materials=[self.entry('notices/chaos.rs',kind='legal-text',reason='relabelled source',origin={'type':'archive-member','archive':'crates/fixture-sys-1.0.0.crate','member':'fixture-sys-1.0.0/src/chaos.rs'})]),'not arbitrary source'),
   (lambda r:f(0)(r).update(materials=[{**f(0)(r)['materials'][0],'path':'terms/MISSING'}]),'Missing review input'),
   (lambda r:f(0)(r).update(materials=[]),'Missing legal text'),
   (lambda r:f(1)(r)['copied_sources'][0].update(materials=['notices/chaos.rs']),'exact full terms'),
   (lambda r:f(1)(r)['copied_sources'][0].update(members=['copied-1.0.0/src/absent.rs']),'Archive member missing'),
   (lambda r:f(0)(r).update(evidence=[]),'exactly one published crate archive'),
   (lambda r:f(2)(r)['evidence'][0].update(url='https://static.rust-lang.org/dist/rust-std-9.9.9-aarch64-apple-darwin.tar.gz'),'exact release/target'),
   (lambda r:f(2)(r)['evidence'][0].update(url='https://static.rust-lang.org/dist/rust-std-11.0.0-aarch64-apple-darwin.tar.gz'),'exact release/target'),
   (lambda r:f(2)(r)['evidence'][0].update(url='https://unrelated.example/dist/rust-std-1.0.0-aarch64-apple-darwin.tar.gz'),'official distribution'),
   (lambda r:f(2)(r)['evidence'][0].update(url='https://static.rust-lang.org/dist/rust-std-1.0.0-x86_64-unknown-linux-gnu.tar.gz'),'exact release/target'),
   (lambda r:f(2)(r)['evidence'].pop(),'compiler-host and standard-library-target'),
   (lambda r:f(0)(r)['materials'][0]['origin'].update(url='https://example.org/fixture/raw/main/LICENSE'),'immutable revision'),
  ]
  for bad in ['../evidence/terms/LICENSE','/tmp/LICENSE','C:/LICENSE','terms\\LICENSE','terms/./LICENSE','']:
   cases.append((lambda r,bad=bad:f(0)(r)['materials'][0].update(path=bad),'Invalid portable path'))
   cases.append((lambda r,bad=bad:f(0)(r)['evidence'][0].update(path=bad),'Invalid portable path'))
  for change,why in cases:
   with self.subTest(why=why):self.rejected(change,why)
  with self.subTest('duplicate JSON key'):
   text=json.dumps(self.review);text=text.replace('"schema": "omd-native-review-v1"','"schema": "omd-native-review-v1", "schema": "omd-native-review-v1"',1)
   with self.assertRaisesRegex(ValueError,'Duplicate key'):self.generate(text,'rejected')
  with self.subTest('symlinked evidence'):
   (self.evidence/'linked').symlink_to(self.evidence/'terms')
   self.rejected(lambda r:f(0)(r)['materials'][0].update(path='linked/LICENSE'),'Symlinked review input')
 def test_missing_final_executable_stays_pending(self):
  self.assertEqual(self.generate(None,'desktop-scope',artifact=False),2)
  desktop=copy.deepcopy(self.review);desktop['scope']=json.loads((self.root/'desktop-scope/review-scope.json').read_text())
  self.assertEqual(desktop['scope']['artifacts'],[])
  self.assertEqual(self.generate(desktop,'desktop',artifact=False),2)
  receipt=json.loads((self.root/'desktop/receipt.json').read_text());notices=(self.root/'desktop/native-NOTICES.txt').read_bytes()
  self.assertEqual(receipt['pending'],['Incomplete native executable binding; missing: fixture'])
  with self.assertRaises(ValueError):validate_native_receipt(receipt,{'bin/fixture':digest(self.executable.read_bytes()),'third-party/native-NOTICES.txt':digest(notices)},['fixture'],receipt['lock_sha256'],'aarch64-apple-darwin',notices,'1')
  # An empty artifact scope is never a wildcard for a later executable.
  self.rejected(lambda r:None,'Stale review scope: artifacts',review=desktop)
  binding=copy.deepcopy(desktop);binding['findings'].append({**binding['findings'][2],'id':'bind-final-executable','category':'executable-binding'})
  self.rejected(lambda r:None,'Unknown finding category',review=binding,artifact=False)
if __name__=='__main__':unittest.main()
