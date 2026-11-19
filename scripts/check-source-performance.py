# /// script
# requires-python = ">=3.12"
# ///
"""Measure source preparation, prepared calls and cache reuse after an executable timestamp change.
Uses a disposable cache and never opens a user profile. Run with UV against the packaged release worker.
"""
import argparse,json,os,shutil,struct,subprocess,tempfile,time
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--worker',type=Path,required=True)
parser.add_argument('--component',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--prepared-budget-ms',type=float,default=250)
args=parser.parse_args()
worker=args.worker.resolve();component=args.component.resolve()
info=json.loads(subprocess.check_output([str(worker),'--build-info']))
if info['profile']!='OMD_WORKER_PROFILE=release':raise SystemExit('Performance acceptance requires a release worker')
rows=[]
with tempfile.TemporaryDirectory(prefix='omd-performance-') as folder:
 root=Path(folder);cache=root/'cache.toml';cache.write_text('[cache]\ndirectory = '+json.dumps(str(root/'compiled'))+'\n')
 for launch in ['prepare','prepared','repacked']:
  binary=worker
  if launch=='repacked':
   binary=root/worker.name;shutil.copy2(worker,binary);os.utime(binary,(time.time()+5,time.time()+5))
  process=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   for invocation in range(3):
    start=time.perf_counter();request=json.dumps({'component':str(component),'cache_config':str(cache),'reuse':True,'inspect':True,'payload':'{}'}).encode()
    process.stdin.write(struct.pack('<I',len(request))+request);process.stdin.flush()
    size=process.stdout.read(4)
    if len(size)!=4:raise RuntimeError('Worker stopped before returning a frame')
    size=struct.unpack('<I',size)[0];data=bytearray()
    while len(data)<size:
     chunk=process.stdout.read(size-len(data))
     if not chunk:raise RuntimeError('Truncated worker frame')
     data.extend(chunk)
    value=json.loads(data)
    if 'error' in value:raise RuntimeError(value['error'])
    rows.append({'launch':launch,'invocation':invocation,'ms':round((time.perf_counter()-start)*1000,2),**value.get('timing',{})})
  finally:
   process.stdin.close();process.wait(timeout=5)
report={'worker':str(worker),'component':str(component),'build':info,'samples':rows,'prepared_budget_ms':args.prepared_budget_ms}
args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
for row in rows:print(json.dumps(row))
if any(row['ms']>args.prepared_budget_ms for row in rows if row['launch']!='prepare'):
 raise SystemExit('Prepared source runtime exceeded its budget; inspect the timing report before packaging')
