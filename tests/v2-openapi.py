# /// script
# dependencies = ["openapi-spec-validator==0.7.2"]
# ///
"""Validate the published contract and optional read-only live response shapes.
Run with UV; --instance must point to a disposable acceptance profile.
"""
import argparse,json,sys,urllib.request
from pathlib import Path
from urllib.parse import urlparse
from openapi_spec_validator import validate
from jsonschema import Draft202012Validator
root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--instance',type=Path);args=parser.parse_args()
document=json.loads((root/'schemas/v2/openapi.json').read_text(encoding='utf-8'));validate(document)
report={'status':'passed','openapi':document['openapi'],'operations':sum(len(value) for value in document['paths'].values()),'schemas':len(document['components']['schemas']),'live_responses':[]}
if args.instance:
    connection=json.loads(args.instance.read_text(encoding='utf-8'));base=connection['endpoint'];url=urlparse(base)
    if url.scheme!='http' or url.hostname not in ('127.0.0.1','::1') or url.path not in ('','/') or url.username or url.password:raise ValueError('Use a test-profile loopback descriptor')
    def request(path,method='GET'):
        with urllib.request.urlopen(urllib.request.Request(base+path,method=method,headers={'Authorization':'Bearer '+connection['token']}),timeout=15) as response:return json.load(response)
    lease=request('/v2/clients','POST')['id']
    try:
        live=request('/v2/openapi.json');validate(live)
        for path in ['/v2/service','/v2/summary','/v2/operations','/v2/naming','/v2/settings','/v2/destinations','/v2/groups','/v2/jobs','/v2/selections','/v2/subscriptions','/v2/inbox','/v2/relocations','/v2/file-operations','/v2/destination-checks','/v2/sources','/v2/source-removals','/v2/notifications','/v2/notifications/history','/v2/tools','/v2/tools/status','/v2/browser-tools','/v2/browser-tools/status']:
            value=request(path);operation=live['paths'][path]['get'];schema=operation['responses']['200']['content']['application/json']['schema']
            Draft202012Validator({**schema,'components':live['components']}).validate(value);report['live_responses'].append(operation['operationId'])
        for check in request('/v2/destination-checks')['items'][:1]:
            for suffix in ['', '/files']:
                operation=live['paths']['/v2/destination-checks/{id}'+suffix]['get'];value=request('/v2/destination-checks/'+check['id']+suffix)
                schema=operation['responses']['200']['content']['application/json']['schema'];Draft202012Validator({**schema,'components':live['components']}).validate(value);report['live_responses'].append(operation['operationId'])
    finally:request('/v2/clients/'+lease,'DELETE')
(root/'artifacts').mkdir(exist_ok=True)
(root/'artifacts/v2-openapi-validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
