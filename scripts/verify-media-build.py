# /// script
# requires-python = ">=3.12"
# ///
"""Attach successful, exact-byte native execution evidence to a media source build."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--runtime-evidence',type=Path,required=True);a=p.parse_args()
record_path=a.build/'build.json';original=record_path.read_bytes();record=json.loads(original);raw=a.runtime_evidence.read_bytes();evidence=json.loads(raw)
assert record['status']=='built_requires_target_verification','Use an unverified cross-build and retain its original identity'
assert evidence['status']=='passed','Native runtime checks must all pass'
for name in ['ffmpeg','ffprobe']:
 assert evidence['tools'][name]['sha256']==record['outputs'][name]['sha256'],'Runtime used different executable bytes'
 assert evidence['tool_architectures'][name]=='x86_64','Unexpected runtime architecture'
 path=a.build/'bin'/(name+'.exe' if 'windows' in record.get('target','') else name)
 assert hashlib.file_digest(path.open('rb'),'sha256').hexdigest()==record['outputs'][name]['sha256'],'Source output changed after verification'
checks=set(evidence['checks']);required={'FFmpeg exposes only file and pipe protocols','Unrelated input remains inaccessible and unchanged'}
required.update('Confined WAV conversion and probe: '+item for item in ['mp3/mp3','m4a/aac','opus/opus','webm/opus','mkv/aac','mp4/aac'])
assert required<=checks,'Incomplete native conversion/policy evidence'
for name,data in [('build-before-runtime-verification.json',original),('runtime-verification.json',raw)]:
 with (a.build/name).open('xb') as f:f.write(data)
record['status']='passed';record['runtime_verification']={'report_sha256':hashlib.sha256(raw).hexdigest(),'source_report_sha256':hashlib.sha256(original).hexdigest(),'architecture':evidence['architecture'],'kernel':evidence['kernel'],'checks':sorted(required)}
assert record_path.read_bytes()==original,'Build changed while attaching evidence'
temporary=a.build/'build-verified.json'
with temporary.open('x') as f:f.write(json.dumps(record,indent=2)+'\n')
temporary.replace(record_path)
print(json.dumps({'status':'passed','build':str(a.build),'runtime_report_sha256':record['runtime_verification']['report_sha256']}))
