# /// script
# requires-python = ">=3.12"
# ///
"""Attach complete media-library source inputs and rebuild instructions to a build."""
import argparse,gzip,hashlib,io,json,re,tarfile
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build",type=Path,required=True)
parser.add_argument("--sources",type=Path,required=True)
parser.add_argument("--output",type=Path,required=True)
parser.add_argument("--zig-root",type=Path,help="Exact Zig distribution used by a cross build; retain its libc/compiler runtime sources and terms")
args=parser.parse_args();report=json.loads((args.build/"build.json").read_text())
if report["status"]!="passed":raise SystemExit("Use a successful, verified source build")
original=(args.build/"build.json").read_bytes()
logical={"build":"/omd/media-build","sources":"/omd/media-sources","home":"/build-home","compiler":"/toolchain/cc","pkg-config":"/toolchain/pkg-config","zig":"/toolchain/zig","objcopy":"/toolchain/objcopy"}
roots=[(row["path"],logical[row["role"]]) for row in report.pop("builder_roots",[])]
roots += [(str(args.build.resolve()),logical["build"]),(str(args.sources.resolve()),logical["sources"]),(str(Path.home()),logical["home"])]
def portable(value):
    if isinstance(value,dict):return {key:portable(item) for key,item in value.items()}
    if isinstance(value,list):return [portable(item) for item in value]
    if isinstance(value,str):
        for host,prefix in sorted(roots,key=lambda row:len(row[0]),reverse=True):
            if len(host)>1:
                for spelling in {host,host.replace('\\','/')}:
                    value=re.sub(re.escape(spelling),lambda _:prefix,value,flags=re.I)
        return value
    return value
report=portable(report)
report["public_projection"]={"original_report_sha256":hashlib.sha256(original).hexdigest(),"paths":"Builder roots are logical prefixes; original private evidence is retained by the producer."}
files={"build-media.py":Path(__file__).with_name("build-media.py").read_bytes()}
if report.get("runtime_verification"):
    runtime=(args.build/"runtime-verification.json").read_bytes()
    if hashlib.sha256(runtime).hexdigest()!=report["runtime_verification"]["report_sha256"]:raise SystemExit("Runtime evidence digest mismatch")
    runtime_record=json.loads(runtime)
    # Native verification may run on a different host from the compiler. Its
    # absolute executable paths are private evidence, not a portable build input.
    for name,tool in runtime_record.get("tools",{}).items():
        tool["path"]="/omd/runtime/bin/"+name
    public_runtime=(json.dumps(portable(runtime_record),indent=2)+'\n').encode()
    report["runtime_verification"]["original_report_sha256"]=hashlib.sha256(runtime).hexdigest()
    report["runtime_verification"]["report_sha256"]=hashlib.sha256(public_runtime).hexdigest()
    files["runtime-verification.json"]=public_runtime
files["build.json"]=(json.dumps(report,indent=2)+'\n').encode()
for name,value in report["sources"].items():
    data=(args.sources/value["archive"]).read_bytes()
    if hashlib.sha256(data).hexdigest()!=value["sha256"]:raise SystemExit("Source digest mismatch: "+name)
    files["sources/"+value["archive"]]=data
if report.get("cross_compiler",{}).get("name")=="zig":
    if not args.zig_root:raise SystemExit("A Zig cross build requires --zig-root for its linked runtime sources and terms")
    zig=args.zig_root.resolve(strict=True)
    if hashlib.file_digest((zig/"zig").open("rb"),"sha256").hexdigest()!=report["cross_compiler"]["sha256"]:raise SystemExit("Zig distribution differs from the compiler used")
    for path in sorted((zig/"lib").rglob("*")):
        if path.is_symlink():raise SystemExit("Unexpected Zig source symlink")
        if path.is_file():files["toolchain/zig/lib/"+path.relative_to(zig/"lib").as_posix()]=path.read_bytes()
    files["licenses/zig-LICENSE"]=(zig/"LICENSE").read_bytes()
    libc="mingw" if "windows" in report["target"] else "musl"
    terms="COPYING" if libc=="mingw" else "COPYRIGHT"
    files["licenses/"+libc+"-"+terms]=(zig/"lib/libc"/libc/terms).read_bytes()
    files["toolchain/zig-source-inventory.json"]=(json.dumps({"zig_version":report["cross_compiler"]["version"],"compiler_sha256":report["cross_compiler"]["sha256"],"files":{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items()) if name.startswith("toolchain/zig/lib/")}},indent=2)+'\n').encode()
for source in (args.build/"licenses").iterdir(): files["licenses/"+source.name]=source.read_bytes()
files["REBUILD.md"]=b'''# OMD media tools: complete source and rebuild kit

The enclosed unmodified source archives contain FFmpeg 9.0.1, Opus 1.6.1,
LAME 3.100 and zlib 1.3.1, including their copyright notices. Their respective
licenses are included in licenses/. FFmpeg was configured without GPL
components, network protocols, playback, or host-library autodetection. Its
only video codecs are the JPEG and PNG still-picture decoders and encoders,
which re-encode cover art; PNG uses zlib. The audio libraries and zlib are
statically linked; the source for all four libraries is included. zlib's
in-memory compression files are compiled directly, as build-media.py lists.

On a macOS or Linux build host, install UV, a C compiler, make and pkg-config.
Extract this kit and run:

    uv run build-media.py --sources sources --output rebuilt

Use --cc and --pkg-config to select build tools. build.json records the
compiler, source identities, configuration and output hashes from the original
build. For a Linux cross build, install Zig 0.16.0 and pass the recorded target,
for example --target x86_64-linux-musl --zig /path/to/zig. For Windows use
--target x86_64-windows-gnu with the same pinned Zig version. The build script
records and asserts any target-specific configure adjustments. A cross build requires
separate execution on its target; compilation alone does not verify it.
Linux cross builds also require GNU/LLVM objcopy (binutils or llvm); use --objcopy
to choose it. It removes Zig's bundled-libc DWARF from the shipping executables.
Zig cross-build kits also retain the exact compiler distribution's lib/ sources,
including the linked MinGW or musl runtime and compiler_rt, their source notices,
and complete top-level runtime license texts. toolchain/zig-source-inventory.json
pins these files and the compiler executable used. Install that pinned Zig release
to rebuild; the compiler executable itself is a build prerequisite.
Other compiler/OS versions can produce different bytes.
Builder paths in build.json and runtime evidence use logical prefixes; the
producer retains the original private reports under their recorded hashes.
No build tools are needed by installed OMD users.

To rebuild with a modified library, change its source archive and expected hash
in build-media.py before rebuilding. Review and install the resulting new tool
manifest through OMD's normal managed-tool review workflow. The original tool
set remains available for existing jobs and rollback. OMD source plugins cannot
replace these executables or alter their launch arguments.
'''
args.output.parent.mkdir(parents=True,exist_ok=True)
with args.output.open("xb") as raw,gzip.GzipFile(fileobj=raw,mode="wb",filename="",mtime=0) as compressed,tarfile.open(fileobj=compressed,mode="w") as archive:
    for name,data in sorted(files.items()):
        info=tarfile.TarInfo("omd-media-source/"+name);info.size=len(data);info.mode=0o644;info.mtime=0
        archive.addfile(info,io.BytesIO(data))
print(json.dumps({"path":str(args.output),"sha256":hashlib.sha256(args.output.read_bytes()).hexdigest(),"files":len(files)},indent=2))
