# /// script
# requires-python = ">=3.12"
# ///
"""Exercise real engine processes using disposable profiles; never downloads media.

Use --engine with the new six-binary runtime. --old-engine additionally exercises
a prior runtime. Test artifacts/profiles are temporary and removed on completion.
"""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--engine',type=Path)
parser.add_argument('--old-engine',type=Path)
args,unknown=parser.parse_known_args()
if args.engine is None:
    import os
    target=Path(os.environ.get('CARGO_TARGET_DIR',ROOT/'target'))
    args.engine=target/'debug'/('omd-engine.exe' if os.name=='nt' else 'omd-engine')
ENGINE=args.engine.resolve(strict=True)
OLD=(args.old_engine or ENGINE).resolve(strict=True)


class Updates(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='omd-update-test-')
        self.root=Path(self.directory.name)
        self.profile=self.root/'profile'
        self.children=[]
        self.logs=[]
    def tearDown(self):
        # Only the processes spawned by this test; never kill by name or PID read
        # from an untrusted file. A failed test must not leave a waiting service.
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:child.wait(timeout=15)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        for log in self.logs:log.close()
        self.directory.cleanup()
    def start(self,binary=ENGINE,service=False):
        log=(self.root/f'engine-{len(self.children)}.log').open('wb');self.logs.append(log)
        worker=binary.with_name('omd-plugin-worker-v2'+binary.suffix)
        if not worker.is_file():worker=ENGINE.with_name('omd-plugin-worker-v2'+ENGINE.suffix)
        command=[str(binary),'--profile',str(self.profile),'--worker',str(worker)]
        if service:command.append('--service')
        child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        self.children.append(child)
        return child
    def ready(self,child):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if child.poll() is not None:self.fail('Engine exited before readiness; see the disposable runtime check')
            try:
                instance=json.loads((self.profile/'instance.json').read_text())
                info=self.call(instance,'GET','/v2/service')
                return instance,info
            except (OSError,ValueError):time.sleep(.05)
        self.fail('Engine readiness timed out')
    def call(self,instance,method,path,body=None):
        request=urllib.request.Request(instance['endpoint']+path,data=json.dumps(body).encode() if body is not None else None,method=method,
            headers={'Authorization':'Bearer '+instance['token' if method=='GET' else 'admin_token'],'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5) as response:return json.load(response)
    def prepare(self):
        result=subprocess.run([str(ENGINE),'--profile',str(self.profile),'--prepare-update'],stdin=subprocess.DEVNULL,capture_output=True,timeout=140)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
    def test_identity_matches_the_actual_file_without_creating_a_profile(self):
        result=subprocess.run([str(ENGINE),'--identity','--profile',str(self.profile)],capture_output=True,check=True,timeout=20)
        value=json.loads(result.stdout)
        bare=subprocess.run([str(ENGINE),'--identity'],capture_output=True,check=True,timeout=20)
        self.assertEqual(json.loads(bare.stdout),value)
        self.assertEqual(value['api'],'v2')
        self.assertEqual(value['executable_sha256'],hashlib.sha256(ENGINE.read_bytes()).hexdigest())
        self.assertFalse(self.profile.exists())
    def test_preparing_an_unused_installation_does_not_create_profile_data(self):
        self.prepare();self.assertFalse(self.profile.exists())
    def test_replacement_preserves_preferences_and_external_files(self):
        old=self.start(OLD);instance,_=self.ready(old)
        preferences={'background':False,'bandwidth_bytes_per_second':65536,'languages':['ja','fr'],'onboarding_complete':True}
        self.call(instance,'PATCH','/v2/settings',preferences)
        media=self.root/'kept-media.txt';media.write_text('user file')
        self.prepare();self.assertEqual(old.wait(timeout=15),0)
        new=self.start();instance,info=self.ready(new)
        self.assertEqual(info['executable_sha256'],hashlib.sha256(ENGINE.read_bytes()).hexdigest())
        saved=self.call(instance,'GET','/v2/settings')
        for key,value in preferences.items():self.assertEqual(saved[key],value)
        self.assertEqual(media.read_text(),'user file')
        self.prepare();self.assertEqual(new.wait(timeout=15),0)
    def test_a_waiting_service_cannot_adopt_the_profile_during_an_update(self):
        active=self.start();self.ready(active)
        # Set only fixture database state, avoiding creation of any OS login job.
        # A broken waiter would see background=true and start serving instead of
        # exiting. The successful path suspends only the unused fixture label.
        with closing(sqlite3.connect(self.profile/'acquisitions-v2.sqlite3')) as db:
            db.execute("INSERT INTO settings VALUES('preferences',?) ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json",(json.dumps({'background':True,'languages':['en']}),))
            db.commit()
        waiting=self.start(service=True);time.sleep(.3)
        self.assertIsNone(waiting.poll())
        self.prepare()
        self.assertEqual(active.wait(timeout=15),0)
        self.assertEqual(waiting.wait(timeout=15),0)
        self.assertTrue((self.profile/'update.pending').is_file())
        with closing(sqlite3.connect(self.profile/'acquisitions-v2.sqlite3')) as db:
            self.assertTrue(json.loads(db.execute("SELECT value_json FROM settings WHERE key='preferences'").fetchone()[0])['background'])
    def test_newer_profile_schema_is_refused_and_retained(self):
        child=self.start();self.ready(child);self.prepare();self.assertEqual(child.wait(timeout=15),0)
        database=self.profile/'acquisitions-v2.sqlite3'
        with closing(sqlite3.connect(database)) as db:
            db.execute("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(9999,'future',1,X'00',0)")
            db.commit()
        result=subprocess.run([str(ENGINE),'--profile',str(self.profile)],capture_output=True,timeout=30)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('newer or incompatible',result.stderr.decode(errors='replace'))
        with closing(sqlite3.connect(database)) as db:self.assertEqual(db.execute('SELECT count(*) FROM _sqlx_migrations WHERE version=9999').fetchone()[0],1)

if __name__=='__main__':unittest.main(argv=[__file__,*unknown])
