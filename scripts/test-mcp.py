# /// script
# requires-python = ">=3.12"
# ///
import http.server
import copy
import subprocess
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from mcp_stdio import MCP

ROOT=Path(__file__).resolve().parents[1]
def discover_binary():
    if os.environ.get('OMD_MCP_BINARY'):
        return Path(os.environ['OMD_MCP_BINARY'])
    metadata=json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--locked','--offline','--format-version','1'],cwd=ROOT))
    return Path(metadata['target_directory'])/'debug'/('omd-mcp.exe' if os.name=='nt' else 'omd-mcp')
BIN=discover_binary()
class Fixture:
    def __init__(self):
        self.log=[]; self.mode='ok'; self.replays={}; self.fail_heartbeat=False; self.slow_started=threading.Event(); self.slow_finished=threading.Event()
        self.plan=json.loads((ROOT/'tests/fixtures/v2-plan.json').read_text(encoding='utf-8'))
        for reference in (self.plan['release']['reference'],self.plan['release']['collection'],self.plan['collection']['reference']): reference['provider']='org.example.source'
        self.plan.update(metadata={name:dict.fromkeys(['title','description','chapter','volume']) for name in ('collection','release')},media=None,credential_profile=None,generation=1)
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self): self.run_request()
            def do_POST(self): self.run_request()
            def do_DELETE(self): self.run_request()
            def do_PUT(self): self.run_request()
            def do_PATCH(self): self.run_request()
            def run_request(self):
                body=self.rfile.read(int(self.headers.get('Content-Length',0)))
                owner.log.append((self.command,self.path,dict(self.headers),json.loads(body) if body else None))
                code=200; slow=False
                if self.path in ('/v2/clients','/v2/clients?finish_downloads=true'): value={'id':'org.example.lease','heartbeat_seconds':1,'lease_seconds':5}
                elif self.path.startswith('/v2/clients/'):
                    if self.command=='POST' and owner.fail_heartbeat: code=503; value={'code':'lease_lost','message':'Fixture lease lost','retryable':False,'actions':[]}
                    else: value={}
                elif owner.mode=='image':
                    import base64
                    data=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aV1cAAAAASUVORK5CYII=')
                    self.send_response(200);self.send_header('Content-Type','image/png');self.end_headers();self.wfile.write(data);return
                elif owner.mode.startswith('events'):
                    self.send_response(200);self.send_header('Content-Type','text/event-stream');self.end_headers()
                    if owner.mode=='events_idle': time.sleep(1.5);return
                    if owner.mode=='events_resync': self.wfile.write(b'event: resync_required\ndata: expired\n\n')
                    else:
                        data=b': keepalive\r\n\r\n'
                        for i in range(1,4):data+=('id: '+str(i)+'\r\nevent: job.changed\r\ndata: '+json.dumps({'id':i,'kind':'job.changed','resource_id':'org.example.job','created_at':'2026-11-09T00:00:00Z'})+'\r\n\r\n').encode()
                        try:
                            for i in range(0,len(data),7):self.wfile.write(data[i:i+7]);self.wfile.flush()
                        except ConnectionError:
                            # Bounded event reads deliberately close the stream early.
                            return
                    return
                elif owner.mode=='echo_secret':
                    code=400;value={'code':'bad_input','message':'normal-secret admin-secret org.example.cookie org.example.password','retryable':False,'actions':[]}
                elif owner.mode=='sign_in': value={'ready':False,'frame':{'png':'YWJj','width':1,'height':1,'origin':'https://example.com','controls':[],'controls_truncated':False}}
                elif owner.mode=='redirect':
                    self.send_response(302);self.send_header('Location',owner.endpoint+'/forbidden');self.end_headers();return
                elif owner.mode=='error':
                    code=409; value={'code':'org.example.retry','message':'normal-secret Authorization normal-secret','retryable':True,'actions':['retry','inspect_job']}
                elif owner.mode=='array': value=[{'id':'org.example.value'}]
                elif owner.mode=='secret': value={'session':{'bytes':'org.example.secret'}}
                elif owner.mode=='slow_install' and self.path=='/v2/sources/install': time.sleep(31); value={'installed':True}
                elif owner.mode=='slow': slow=True; owner.slow_started.set(); time.sleep(2); value={}
                elif owner.mode=='large': value={'data':'x'*(2*1024*1024)}
                elif self.path=='/v2/preparations':
                    value=owner.preparation() if owner.mode=='contract' else {'id':'org.example.prep','expires_at':'later','destination':{},'items':[{'output':'review.cbz'}]}
                elif self.path=='/v2/jobs' and self.command=='POST':
                    key=self.headers.get('Idempotency-Key'); value={'group_id':'org.example.group','items':[{'job':owner.job(),'created':True}]} if owner.mode=='contract' else {'jobs':['org.example.job']}
                    if key in owner.replays and owner.replays[key]!=body:
                        code=409;value={'code':'idempotency_conflict','message':'Request differs','retryable':False,'actions':['inspect_job']}
                    else: owner.replays[key]=body
                elif owner.mode=='contract' and self.path.startswith('/v2/jobs?'): value={'items':[owner.job()],'next_cursor':None}
                elif owner.mode=='contract' and self.path.startswith('/v2/jobs/'):
                    action=self.path.rsplit('/',1)[-1]
                    value=owner.job({'pause':'paused','resume':'queued','retry':'queued','cancel':'canceled'}.get(action,'queued'))
                elif self.path.startswith('/v2/sources?'): value={'items':[{'id':'org.example.source'}],'next_cursor':'opaque+/='}
                else: value={'api':'v2','id':'org.example.job'}
                data=json.dumps(value).encode()
                try:
                    self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError): pass
                finally:
                    if slow: owner.slow_finished.set()
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.endpoint=f'http://127.0.0.1:{self.server.server_port}'
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
    def job(self,state='queued'):
        return {'id':'org.example.job','group_id':'org.example.group','acquisition_key':'0'*64,'title':'Fixture chapter','destination_id':'org.example.destination','state':state,'plan':copy.deepcopy(self.plan),'bytes_done':0,'bytes_total':None,'attempt':0,'issue':None,'created_at':'2026-11-01T00:00:00Z','updated_at':'2026-11-01T00:00:00Z'}
    def preparation(self):
        return {'id':'org.example.prep','expires_at':'2027-01-01T00:00:00Z','destination':{'id':'org.example.destination','label':'Fixture','root':'/org.example/downloads','available':True,'storage_operation':None},'items':[{'plan':copy.deepcopy(self.plan),'outcome':'download','files':['chapter.cbz','ComicInfo.xml','provenance.json'],'estimated_bytes':None}]}
    def close(self): self.server.shutdown();self.server.server_close()
class Tests(unittest.TestCase):
    def setUp(self):
        self.f=Fixture();self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'instance.json';self.write(self.f.endpoint)
        self.clients=[]
    def tearDown(self):
        for c in self.clients:
            if c.process.poll() is None: c.close()
        self.f.close();self.tmp.cleanup()
    def write(self, endpoint):self.path.write_text(json.dumps({'endpoint':endpoint,'token':'normal-secret','admin_token':'admin-secret'}))
    def client(self, access=None):
        env={**os.environ,'HTTP_PROXY':'http://127.0.0.1:1','ALL_PROXY':'http://127.0.0.1:1','NO_PROXY':''}
        c=MCP(BIN,self.path,env, ["--access",access] if access else []);self.clients.append(c);c.initialize();return c
    def test_access_modes_and_admin_authority(self):
        read=self.client('read');manage=self.client();full=self.client('full')
        def names(c):return {t['name'] for t in c.request('tools/list',{})['result']['tools']}
        r,m,f=map(names,(read,manage,full))
        self.assertLess(r,m);self.assertLess(m,f)
        self.assertIn('install_source',f);self.assertNotIn('install_source',m)
        self.assertIn('create_subscription',m);self.assertNotIn('create_subscription',r)
        self.assertIn('error',read.call('create_subscription',{}))
        self.assertIn('error',manage.call('install_source',{'request':{'package_path':'/example.omdp'}}))
        full.call('install_source',{'request':{'package_path':'/example.omdp'}})
        entry=next(row for row in reversed(self.f.log) if row[1]=='/v2/sources/install')
        self.assertEqual(entry[3],{'package_path':'/example.omdp'})
        self.assertEqual({k.lower():v for k,v in entry[2].items()}['authorization'],'Bearer admin-secret')
        full.call('service_status');entry=next(row for row in reversed(self.f.log) if row[1]=='/v2/service')
        self.assertEqual({k.lower():v for k,v in entry[2].items()}['authorization'],'Bearer normal-secret')
        self.path.write_text(json.dumps({'endpoint':self.f.endpoint,'token':'normal-secret'}))
        missing=MCP(BIN,self.path,args=['--access','full']);self.clients.append(missing);missing.close()
        self.assertNotEqual(missing.process.returncode,0)
    def test_source_install_can_outlast_the_ordinary_request_timeout(self):
        client=self.client('full');self.f.mode='slow_install'
        result=client.call('install_source',{'request':{'package_path':'/example.omdp','approve_digest':'0'*64}})['result']
        self.assertFalse(result.get('isError'),result)
        self.assertEqual(result['structuredContent'],{'installed':True})
        self.assertTrue(any(row[1].startswith('/v2/clients/') and row[0]=='POST' for row in self.f.log))
    def test_resources_prompts_are_embedded_and_bounded(self):
        c=self.client();r=c.request('resources/list',{})['result']['resources'];self.assertEqual(len(r),7)
        for entry in r:
            result=c.request('resources/read',{'uri':entry['uri']})['result']['contents'][0]
            self.assertEqual(len(result['text'].encode()),entry['size'])
            self.assertNotIn('normal-secret',result['text'])
            topic=entry['uri'].rsplit('/',1)[-1];guide=c.call('get_guidance',{'topic':topic})['result']['structuredContent'];self.assertEqual(guide['text'],result['text'])
        self.assertIn('error',c.request('resources/read',{'uri':'file:///etc/passwd'}))
        self.assertIn('error',c.request('resources/list',{'cursor':'unknown'}))
        prompts=c.request('prompts/list',{})['result']['prompts'];self.assertEqual(len(prompts),3)
        for p in prompts:self.assertTrue(c.request('prompts/get',{'name':p['name']})['result']['messages'])
        self.assertIn('error',c.request('prompts/get',{'name':'author_plugin','arguments':{'shell':'bad'}}))
    def test_owned_sign_in_secret_redaction_and_images(self):
        c=self.client();c.call('start_source_sign_in',{'id':'org.example.source','request':{'profile':'main','label':'Main'}})
        self.assertEqual(self.f.log[-1][3]['client'],'org.example.lease')
        self.assertIn('error',c.call('start_source_sign_in',{'id':'org.example.source','request':{'profile':'main','label':'Main','client':'other'}}))
        self.f.mode='sign_in';r=c.call('source_sign_in_status',{'id':'org.example.signin'})['result']
        self.assertEqual(r['content'][0]['type'],'image');self.assertNotIn('png',r['structuredContent']['frame'])
        self.assertEqual(self.f.log[-1][3],{'client':'org.example.lease'})
        self.f.mode='echo_secret'
        r=c.call('interact_with_sign_in',{'id':'org.example.signin','request':{'action':{'op':'type','text':'org.example.password'}}})['result']
        text=json.dumps(r);self.assertNotIn('org.example.password',text);self.assertNotIn('admin-secret',text);self.assertNotIn('normal-secret',text)
        r=c.call('save_source_account',{'id':'org.example.source','profile':'main','request':{'label':'Main','session':{'headers':[{'origin':'https://example.com','name':'Authorization','value':'org.example.password'}],'cookies':[{'domain':'example.com','path':'/','name':'session','value':'org.example.cookie','host_only':True}]}}})['result']
        self.assertNotIn('org.example.cookie',json.dumps(r));self.assertNotIn('org.example.password',json.dumps(r))
        self.f.mode='image';r=c.call('get_artwork',{'id':'org.example.source','url':'https://example.com/art.png'})['result']
        self.assertFalse(r['isError']);self.assertEqual(r['content'][0]['type'],'image');self.assertEqual(r['structuredContent']['mime_type'],'image/png');self.assertNotIn('data',r['structuredContent'])
    def test_event_windows_and_resynchronization(self):
        c=self.client();self.f.mode='events'
        r=c.call('follow_events',{'cursor':0,'limit':2})['result']['structuredContent']
        self.assertEqual([e['id'] for e in r['events']],[1,2]);self.assertEqual(r['next_cursor'],2);self.assertTrue(r['limit_reached'])
        self.assertIn('error',c.call('follow_events',{'cursor':-1}))
        self.assertIn('error',c.call('follow_events',{'cursor':0,'wait_ms':10001}))
        self.f.mode='events_resync';r=c.call('follow_events',{'cursor':0})['result'];self.assertTrue(r['isError']);self.assertEqual(r['structuredContent']['code'],'resync_required')
    def test_quiet_event_stream_returns_on_deadline(self):
        c=self.client();self.f.mode='events_idle';start=time.monotonic()
        r=c.call('follow_events',{'cursor':7,'wait_ms':50})['result'];elapsed=time.monotonic()-start
        self.assertFalse(r['isError']);self.assertEqual(r['structuredContent'],{'events':[],'next_cursor':7,'limit_reached':False})
        self.assertLess(elapsed,1.0)
        self.f.mode='ok';self.assertFalse(c.call('service_status')['result']['isError'])
    def test_every_public_operation_is_accounted_for(self):
        spec=json.loads((ROOT/'schemas/v2/openapi.json').read_text(encoding='utf-8'))
        coverage=json.loads((ROOT/'crates/omd-mcp/src/coverage.json').read_text(encoding='utf-8'))
        ids={op['operationId'] for path in spec['paths'].values() for op in path.values()}
        self.assertEqual(ids,set(coverage))
        self.assertEqual({k for k,v in coverage.items() if v['kind']=='internal'},{'attachClient','heartbeatClient','detachClient'})
        self.assertEqual({k for k,v in coverage.items() if v['kind']=='resource'},{'getContract'})
    def test_entire_tool_catalog_routes_with_typed_arguments(self):
        from urllib.parse import quote, urlsplit, parse_qs
        c=self.client('full')
        spec=json.loads((ROOT/'schemas/v2/openapi.json').read_text(encoding='utf-8'))
        coverage=json.loads((ROOT/'crates/omd-mcp/src/coverage.json').read_text(encoding='utf-8'))
        tools={t['name']:t for t in c.request('tools/list',{})['result']['tools']}
        def sample(schema):
            if 'const' in schema:return schema['const']
            if 'enum' in schema:return schema['enum'][0]
            for key in ('anyOf','oneOf'):
                if key in schema:return sample(next(v for v in schema[key] if v.get('type')!='null'))
            kind=schema.get('type','object');kind=next(v for v in kind if v!='null') if isinstance(kind,list) else kind
            if kind=='object':return {k:sample(schema['properties'][k]) for k in schema.get('required',[])}
            if kind=='array':return [sample(schema['items']) for _ in range(max(1,schema.get('minItems',0)))]
            if kind=='boolean':return False
            if kind in ('integer','number'):return schema.get('minimum',0)
            return 'org.example.value'
        for path,methods in spec['paths'].items():
            for method,op in methods.items():
                binding=coverage[op['operationId']]
                if binding['kind']!='tool':continue
                name=binding['name'];args=sample(tools[name]['inputSchema'])
                self.f.mode='image' if name=='get_artwork' else 'events' if name=='follow_events' else 'ok'
                expected_path=path
                for p in op.get('parameters',[]):
                    if p['in']=='path':
                        key='provider' if name=='source_query' and p['name']=='id' else p['name']
                        if 'enum' not in tools[name]['inputSchema']['properties'][key]:args[key]='org.example/value ?'
                        expected_path=expected_path.replace('{'+p['name']+'}',quote(str(args[key]),safe=''))
                if name=='follow_events':args.update(wait_ms=100,limit=2)
                with self.subTest(tool=name):
                    r=c.call(name,args);self.assertNotIn('error',r);self.assertFalse(r['result']['isError'],r)
                    entry=next(row for row in reversed(self.f.log) if row[1].split('?')[0]==expected_path)
                    self.assertEqual(entry[0],method.upper())
                    self.assertEqual({k.lower():v for k,v in entry[2].items()}['authorization'],'Bearer '+('admin-secret' if op['x-omd-scope']=='admin' else 'normal-secret'))
                    if op.get('requestBody'):
                        expected=args.get('request',{}) if name not in ('prepare_releases','submit_preparation') else {k:v for k,v in args.items() if k!='idempotency_key'}
                        if 'SignIn' in op['operationId']:expected={**expected,'client':'org.example.lease'}
                        self.assertEqual(entry[3],expected)
                    else:self.assertIsNone(entry[3])
                    if name=='submit_preparation':self.assertEqual({k.lower():v for k,v in entry[2].items()}['idempotency-key'],args['idempotency_key'])
        self.assertEqual(len(tools),96)
    def test_array_results_and_configuration_output(self):
        self.f.mode='array';c=self.client()
        result=c.call('list_operations')['result'];self.assertEqual(result['structuredContent'],{'items':[{'id':'org.example.value'}]})
        self.assertEqual(json.loads(result['content'][0]['text']),result['structuredContent'])
        nonexistent=Path(self.tmp.name)/'does-not-exist.json'
        p=subprocess.run([str(BIN),'--instance',str(nonexistent),'--access','full','--print-config'],capture_output=True,check=True)
        config=json.loads(p.stdout)['mcpServers']['omd'];self.assertEqual(config['args'],['--instance',str(nonexistent),'--access','full'])
        self.assertNotIn(b'secret',p.stdout);self.assertEqual(p.stderr,b'')
    def test_source_specific_filters_and_provider_are_preserved(self):
        c=self.client()
        request={'operation':'search','query':'test','page_size':20,'cursor':'opaque+/=', 'credential_profile':'main','discovery':{'feed':'latest','sort':'popular','filters':{'media':['audio','video'],'language':['en']}}}
        c.call('source_query',{'provider':'org.example.second','request':request})
        self.assertEqual(self.f.log[-1][1],'/v2/sources/org.example.second/invoke');self.assertEqual(self.f.log[-1][3],request)
        self.assertIn('error',c.call('source_query',{'provider':'org.example.second','request':{**request,'discovery':{'filters':{'media':'video'}}}}))
    def test_transport_mapping_lifecycle(self):
        c=self.client();tools=c.request('tools/list',{})['result']['tools'];self.assertGreater(len(tools),75)
        self.assertFalse(next(t for t in tools if t['name']=='submit_preparation')['annotations']['readOnlyHint'])
        a=c.call('list_sources',{'limit':2})['result']['structuredContent'];self.assertEqual(a['next_cursor'],'opaque+/=')
        c.call('list_sources',{'limit':2,'cursor':a['next_cursor']});self.assertIn('cursor=opaque%2B%2F%3D',self.f.log[-1][1])
        before=len(self.f.log);self.assertIn('error',c.call('list_sources',{'limit':201}));self.assertEqual(before,len(self.f.log))
        request={'operation':'releases','reference':{'provider':'org.example.source','id':'release/1'},'cursor':'opaque+/=','page_size':2}
        c.call('source_query',{'provider':'org.example.source','request':request});self.assertEqual(self.f.log[-1][3],request)
        self.assertIn('error',c.call('source_query',{'provider':'org.example.source','request':{'operation':'resolve'}}))
        prep={'releases':[{'provider':'org.example.source','id':'release/1'}],'destination_id':'org.example.destination','recipe':'cbz','policy':{},'duplicate_behavior':'skip_satisfied'}
        r=c.call('prepare_releases',prep)['result'];self.assertFalse(r['isError']);self.assertEqual(r['structuredContent']['items'],[{'output':'review.cbz'}]);self.assertEqual(self.f.log[-1][3],prep)
        self.assertIn('error',c.call('submit_preparation',{'preparation_id':'org.example.prep'}))
        args={'preparation_id':'org.example.prep','idempotency_key':'org.example.replay'}
        self.assertEqual(c.call('submit_preparation',args)['result'],c.call('submit_preparation',args)['result'])
        for row in [r for r in self.f.log if r[1]=='/v2/jobs']:
            self.assertEqual({k.lower():v for k,v in row[2].items()}['idempotency-key'],'org.example.replay');self.assertEqual(row[3],{'preparation_id':'org.example.prep'})
        self.assertEqual(c.call('submit_preparation',{**args,'preparation_id':'org.example.other'})['result']['structuredContent']['code'],'idempotency_conflict')
        c.call('list_jobs',{'limit':1});self.assertTrue(self.f.log[-1][1].startswith('/v2/jobs?'))
        c.call('inspect_job',{'id':'org.example.job'});self.assertEqual(self.f.log[-1][1],'/v2/jobs/org.example.job')
        for action in ['pause','resume','retry','cancel']:
            c.call('job_action',{'id':'org.example.job','action':action});self.assertEqual(self.f.log[-1][:2],('POST','/v2/jobs/org.example.job/'+action))
        self.write('http://127.0.0.1:1');c.call('service_status');time.sleep(1.2)
        err=c.close();self.assertEqual(c.process.returncode,0);self.assertNotIn(b'secret',err)
        self.assertTrue(any(r[:2]==('POST','/v2/clients/org.example.lease') for r in self.f.log))
        self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))
        # An agent can submit downloads and disconnect: the lease asks the engine to finish them.
        self.assertEqual([r[1] for r in self.f.log if r[0]=='POST' and r[1].startswith('/v2/clients') and 'org.example' not in r[1]],['/v2/clients?finish_downloads=true'])
        self.assertTrue(all({k.lower():v for k,v in r[2].items()}['authorization']=='Bearer normal-secret' for r in self.f.log))
    def test_errors_redirect_bounds(self):
        c=self.client()
        self.f.mode='error';r=c.call('service_status')['result'];self.assertTrue(r['isError']);p=r['structuredContent'];self.assertEqual(p['code'],'org.example.retry');self.assertTrue(p['retryable']);self.assertEqual(p['actions'],['retry','inspect_job']);self.assertNotIn('normal-secret',json.dumps(r))
        self.f.mode='redirect';self.assertTrue(c.call('service_status')['result']['isError']);self.assertFalse(any(r[1]=='/forbidden' for r in self.f.log))
        self.f.mode='secret';self.assertEqual(c.call('service_status')['result']['structuredContent']['code'],'unsafe_response')
        self.f.mode='large';self.assertEqual(c.call('service_status')['result']['structuredContent']['code'],'response_too_large')
    def test_endpoint_boundary(self):
        for endpoint in ['https://127.0.0.1:1','http://example.com','http://localhost:1','http://user:pass@127.0.0.1','http://127.0.0.1/path','http://127.0.0.1/?q=a','http://127.0.0.1/#a']:
            self.write(endpoint);c=MCP(BIN,self.path);self.clients.append(c);err=c.close();self.assertNotEqual(c.process.returncode,0);self.assertNotIn(b'secret',err)
        self.assertEqual(self.f.log,[])
    def test_disconnect_during_call_and_signal(self):
        c=self.client();self.f.mode='slow'
        c.send({'jsonrpc':'2.0','id':99,'method':'tools/call','params':{'name':'service_status','arguments':{}}})
        c.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':99,'reason':'org.example.cancel'}})
        c.close();self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))
        if os.name=='nt': return
        self.f.mode='ok';c=self.client();c.process.terminate();c.process.wait(timeout=5);c.close()
        self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))
    def test_schema_generation_is_current(self):
        import subprocess
        files=[ROOT/f'crates/omd-mcp/src/{name}.json' for name in ('tools','routes','coverage')];before=[f.read_bytes() for f in files]
        subprocess.run(['uv','run',str(ROOT/'scripts/generate-mcp.py')],check=True)
        self.assertEqual(before,[f.read_bytes() for f in files])
    def test_disconnect_before_initialization(self):
        c=MCP(BIN,self.path);self.clients.append(c);c.close();self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))
    def test_contract_preparation_and_jobs_preserve_safe_locator_headers(self):
        self.f.mode='contract';c=self.client()
        prep={'releases':[{'provider':'org.example.source','id':'chapter:110.5-special'}],'destination_id':'org.example.destination','recipe':'cbz','policy':{},'duplicate_behavior':'skip_satisfied'}
        for headers in ({},{'Accept':'image/png','Referer':'https://example.com/series'}):
            self.f.plan['outputs'][0]['locator']['headers']=headers
            result=c.call('prepare_releases',prep)['result'];self.assertFalse(result['isError']);self.assertEqual(result['structuredContent'],self.f.preparation())
            result=c.call('submit_preparation',{'preparation_id':'org.example.prep','idempotency_key':'org.example.contract'})['result'];self.assertFalse(result['isError']);self.assertEqual(result['structuredContent']['items'],[{'job':self.f.job(),'created':True}])
            result=c.call('list_jobs',{'limit':1})['result'];self.assertFalse(result['isError']);self.assertEqual(result['structuredContent']['items'],[self.f.job()])
            result=c.call('inspect_job',{'id':'org.example.job'})['result'];self.assertFalse(result['isError']);self.assertEqual(result['structuredContent'],self.f.job())
            for action,state in [('pause','paused'),('resume','queued'),('retry','queued'),('cancel','canceled')]:
                result=c.call('job_action',{'id':'org.example.job','action':action})['result'];self.assertFalse(result['isError']);self.assertEqual(result['structuredContent'],self.f.job(state))
        for headers in ({'Authorization':'Bearer org.example.secret'},{'Cookie':'session=org.example.secret'},{'X-Unreviewed':'org.example.secret'},{'Referer':'https://user:password@example.com/'}):
            self.f.plan['outputs'][0]['locator']['headers']=headers
            result=c.call('inspect_job',{'id':'org.example.job'})['result'];self.assertTrue(result['isError']);self.assertEqual(result['structuredContent']['code'],'unsafe_response');self.assertNotIn('org.example.secret',json.dumps(result))

    def test_cancellation_keeps_connection_usable(self):
        c=self.client();self.f.mode='slow'
        c.send({'jsonrpc':'2.0','id':99,'method':'tools/call','params':{'name':'service_status','arguments':{}}})
        self.assertTrue(self.f.slow_started.wait(timeout=2))
        c.send({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':99,'reason':'org.example.cancel'}})
        # MCP cancellation is fire-and-forget; the SDK suppresses the cancelled reply.
        self.assertTrue(self.f.slow_finished.wait(timeout=3))
        self.f.mode='ok'
        self.assertFalse(c.call('service_status')['result']['isError'])
        self.assertIsNone(c.process.poll())
        self.assertFalse(any(r.get('id')==99 for r in c.received))
        c.close();self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))

    def test_failed_heartbeat_terminates_and_detaches(self):
        c=self.client();self.f.fail_heartbeat=True
        c.process.wait(timeout=6)
        self.assertNotEqual(c.process.returncode,0)
        err=c.close();self.assertNotIn(b'secret',err)
        self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))

    def test_oversized_instance_is_rejected_before_attach(self):
        self.path.write_text(json.dumps({'endpoint':self.f.endpoint,'token':'normal-secret','padding':'x'*65536}))
        c=MCP(BIN,self.path);self.clients.append(c);err=c.close()
        self.assertNotEqual(c.process.returncode,0);self.assertEqual(self.f.log,[]);self.assertNotIn(b'secret',err)

    def test_oversized_stdio_line_terminates_and_detaches(self):
        c=MCP(BIN,self.path);self.clients.append(c)
        message={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'x'*(2*1024*1024),'version':'1'}}}
        try: c.send(message)
        except BrokenPipeError: pass
        c.process.wait(timeout=6)
        self.assertNotEqual(c.process.returncode,0);c.close()
        self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))

    def test_initialization_deadline_terminates_without_eof(self):
        c=MCP(BIN,self.path);self.clients.append(c)
        c.process.wait(timeout=35)
        self.assertNotEqual(c.process.returncode,0);c.close()
        self.assertEqual(self.f.log[-1][:2],('DELETE','/v2/clients/org.example.lease'))

    def test_binary_discovery_honors_external_cargo_target(self):
        from unittest.mock import patch
        target=Path(self.tmp.name)/'external-target'
        with patch.dict(os.environ,{'CARGO_TARGET_DIR':str(target)}):
            os.environ.pop('OMD_MCP_BINARY',None)
            self.assertEqual(discover_binary(),target/'debug'/('omd-mcp.exe' if os.name=='nt' else 'omd-mcp'))
if __name__=='__main__':unittest.main()
