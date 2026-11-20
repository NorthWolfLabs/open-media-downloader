# /// script
# requires-python = ">=3.12"
# ///
"""Build the locked upstream media executable, including signed embedded libraries."""
import argparse,hashlib,json,os,platform,subprocess,time
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True);parser.add_argument("--identity");parser.add_argument("--architecture",choices=["native","x86_64"],default="native");args=parser.parse_args()
root=Path(__file__).resolve().parents[1];project=root/"distribution/yt-dlp";output=args.output.resolve()
if platform.system()=="Darwin" and not args.identity:raise SystemExit("Supply the macOS Developer ID signing identity")
if platform.system()!="Darwin" and args.identity:raise SystemExit("--identity is only used by the macOS build")
output.mkdir(parents=True,exist_ok=False)
if args.architecture!='native' and platform.system()!='Darwin':raise SystemExit("Explicit architecture selection currently requires macOS")
machine=platform.machine() if args.architecture=='native' else args.architecture
interpreter='3.13.14' if args.architecture=='native' else 'cpython-3.13.14-macos-x86_64-none'
environment={**os.environ,"PYTHONHASHSEED":"0","SOURCE_DATE_EPOCH":"1787097600","UV_PROJECT_ENVIRONMENT":str(output/"venv"),"UV_PYTHON":interpreter}
environment.pop("VIRTUAL_ENV",None)
environment["UV_LINK_MODE"]="copy"
record={"format":1,"platform":platform.platform(),"architecture":machine,"build_host_architecture":platform.machine(),"status":"building","source_inputs":{},"steps":[]}
for name in ["pyproject.toml","uv.lock",".python-version","launcher.py"]:record["source_inputs"][name]=hashlib.sha256((project/name).read_bytes()).hexdigest()
def save(): (output/"build.json").write_text(json.dumps(record,indent=2)+"\n")
def run(name,command):
    started=time.monotonic()
    with (output/(name+".log")).open("wb") as log:result=subprocess.run(command,cwd=project,stdout=log,stderr=subprocess.STDOUT,timeout=1200,env=environment)
    record["steps"].append({"name":name,"exit_code":result.returncode,"seconds":round(time.monotonic()-started,2)});save()
    if result.returncode:raise RuntimeError(name+" failed; inspect "+str(output/(name+".log")))
try:
    run("locked-dependencies",["uv","sync","--locked"])
    run("interpreter",["uv","run","--locked","python","-VV"])
    run("architecture",["uv","run","--locked","python","-c","import platform; print(platform.machine())"])
    if (output/"architecture.log").read_text().strip().lower()!=machine.lower():raise RuntimeError("Build interpreter architecture does not match the requested target")
    command=["uv","run","--locked","pyinstaller","--noconfirm","--clean","--onefile","--name","omd-yt-dlp","--distpath",str(output/"bin"),"--workpath",str(output/"work"),"--specpath",str(output/"spec"),"--collect-all","yt_dlp","--collect-all","yt_dlp_ejs"]
    if args.identity:command += ["--codesign-identity",args.identity]
    if platform.system()=="Windows":
        # The supported Windows 10+ systems supply their own Universal CRT/API
        # sets. Do not sweep compatibility DLLs from the build host into the app.
        # Keep Python's two VC runtime DLLs and actual package extensions.
        make=["uv","run","--locked","pyi-makespec","--onefile","--name","omd-yt-dlp","--specpath",str(output/"spec"),"--collect-all","yt_dlp","--collect-all","yt_dlp_ejs",str(project/"launcher.py")]
        run("spec",make)
        spec=output/"spec/omd-yt-dlp.spec";text=spec.read_text();marker="\npyz = PYZ("
        if text.count(marker)!=1:raise RuntimeError("The pinned PyInstaller spec format changed")
        text=text.replace(marker, "\na.binaries = [row for row in a.binaries if not (row[0].replace('\\\\', '/').rsplit('/', 1)[-1].lower().startswith('api-ms-win-') or row[0].replace('\\\\', '/').rsplit('/', 1)[-1].lower() == 'ucrtbase.dll')]\n"+marker)
        spec.write_text(text)
        record["windows_system_runtime"]={"minimum":"Windows 10","provided_by_os":["Universal CRT","Windows API-set forwarders"],"bundled":"Python and package extensions plus VC runtime DLLs; retain their complete redistribution terms"}
        run("package",["uv","run","--locked","pyinstaller","--noconfirm","--clean","--distpath",str(output/"bin"),"--workpath",str(output/"work"),str(spec)])
    else:
        run("package",command+[str(project/"launcher.py")])
    executable=output/"bin"/("omd-yt-dlp.exe" if os.name=="nt" else "omd-yt-dlp")
    run("version",[str(executable),"--ignore-config","--no-plugin-dirs","--version"])
    if (output/"version.log").read_text().strip()!="2026.10.26":raise RuntimeError("Unexpected extractor version")
    if args.identity:
        run("signature",["/usr/bin/codesign","--verify","--strict",str(executable)])
        run("entitlements",["/usr/bin/codesign","-d","--entitlements","-",str(executable)])
        if "disable-library-validation" in (output/"entitlements.log").read_text():raise RuntimeError("Library validation must remain enabled")
    record["executable"]={"path":str(executable),"sha256":hashlib.sha256(executable.read_bytes()).hexdigest(),"bytes":executable.stat().st_size,"version":"2026.10.26"};record["status"]="passed";save();print(json.dumps(record["executable"],indent=2))
except BaseException as error:
    record["status"]="failed";record["failure"]=str(error);save();raise
