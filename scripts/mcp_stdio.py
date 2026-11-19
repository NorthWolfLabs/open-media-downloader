"""Bounded development harness for the native MCP stdio transport."""
import json
import queue
import subprocess
import threading

class MCP:
    def __init__(self, binary, instance, env=None, args=()):
        self.process = subprocess.Popen([str(binary), '--instance', str(instance), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.lines = queue.Queue()
        def read():
            for line in self.process.stdout:
                self.lines.put(line)
            self.lines.put(None)
        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        self.seq = 0
        self.received = []
    def send(self, value):
        self.process.stdin.write(json.dumps(value).encode()+b'\n')
        self.process.stdin.flush()
    def request(self, method, params):
        self.seq += 1
        self.send({'jsonrpc':'2.0','id':self.seq,'method':method,'params':params})
        return self.receive(self.seq)
    def receive(self, request_id):
        for _ in range(20):
            line = self.lines.get(timeout=45)
            assert line is not None, 'MCP transport ended early'
            assert len(line) <= 8*1024*1024, 'Oversized protocol output'
            response = json.loads(line)
            self.received.append(response)
            assert response['jsonrpc'] == '2.0', 'Non-protocol stdout'
            if response.get('id') == request_id: return response
        raise AssertionError('Too many unsolicited messages')
    def initialize(self):
        r = self.request('initialize', {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'org.example.fixture','version':'1'}})
        assert 'tools' in r['result']['capabilities']
        assert r['result']['serverInfo']['name'] == 'omd-mcp'
        assert r['result']['protocolVersion'] == '2025-11-25'
        self.send({'jsonrpc':'2.0','method':'notifications/initialized'})
        return r
    def call(self, name, arguments={}):
        return self.request('tools/call', {'name':name,'arguments':arguments})
    def close(self):
        if not self.process.stdin.closed:
            try: self.process.stdin.close()
            except BrokenPipeError: pass
        try: self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(); raise
        self.reader.join(timeout=2)
        for line in iter(self.lines.get_nowait, None):
            assert json.loads(line).get('jsonrpc') == '2.0', 'Non-protocol stdout'
        error = self.process.stderr.read()
        self.process.stdout.close(); self.process.stderr.close()
        return error

def smoke(binary, instance, env=None):
    client = MCP(binary, instance, env)
    try:
        client.initialize()
        tools = client.request('tools/list', {})['result']['tools']
        assert {t['name'] for t in tools} >= {'service_status','prepare_releases','submit_preparation'}
        result = client.call('service_status')['result']
        assert not result['isError'] and result['structuredContent']['api'] == 'v2'
    finally:
        client.close()
    assert client.process.returncode == 0
