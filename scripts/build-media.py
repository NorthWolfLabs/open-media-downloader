# /// script
# requires-python = ">=3.12"
# ///
"""Build file/pipe-only FFmpeg, its audio libraries and zlib from locked source inputs.

Run with UV. Build tools are required only on the packaging host. Existing
source archives and published executables are never overwritten.

Besides audio, FFmpeg decodes and re-encodes still JPEG/PNG cover pictures so
OMD can keep a verified cover in saved audio. PNG needs zlib's inflate and
deflate; zlib is compiled from its pinned source into the same static prefix.
"""
import argparse, hashlib, json, os, platform, shlex, shutil, struct, subprocess, tarfile, time
from pathlib import Path

SOURCES = {
    "ffmpeg": {"version": "9.0.1", "archive": "ffmpeg-9.0.1.tar.xz", "sha256": "cf38e0e28c7e5605942c4a77755349b0145804a397af37eb1fb4c77cb237f635", "url": "https://ffmpeg.org/releases/ffmpeg-9.0.1.tar.xz"},
    "opus": {"version": "1.6.1", "archive": "opus-1.6.1.tar.gz", "sha256": "6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1", "url": "https://downloads.xiph.org/releases/opus/opus-1.6.1.tar.gz"},
    "lame": {"version": "3.100", "archive": "lame-3.100.tar.gz", "sha256": "ddfe36cab873794038ae2c1210557ad34857a4b6bdc515785d1da9e175b1da1e", "url": "https://downloads.sourceforge.net/project/lame/lame/3.100/lame-3.100.tar.gz"},
    "zlib": {"version": "1.3.1", "archive": "zlib-1.3.1.tar.gz", "sha256": "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23", "url": "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"},
}
# zlib's in-memory inflate/deflate core. Its gz* file helpers are not used by
# FFmpeg and are not built. Compiling the files directly, rather than through
# zlib's configure script, behaves identically for native and every cross target.
ZLIB_SOURCES = ("adler32", "compress", "crc32", "deflate", "infback", "inffast", "inflate", "inftrees", "trees", "uncompr", "zutil")
# Still cover pictures only: decoded and re-encoded (never stream-copied), so
# a published cover holds only bytes FFmpeg's own encoder wrote. The sidedata
# filter drops decoded ICC/EXIF side data, which the encoders would otherwise
# write back verbatim; scale/format convert pixel layouts for the encoders.
IMAGE_CODECS = "mjpeg,png"

def sha(path):
    with path.open("rb") as source: return hashlib.file_digest(source, "sha256").hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="/usr/bin/clang" if platform.system()=="Darwin" else "/usr/bin/cc")
    parser.add_argument("--pkg-config", default=shutil.which("pkg-config"))
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 2))
    parser.add_argument("--target", choices=["native", "x86_64-linux-musl", "aarch64-linux-musl", "x86_64-apple-darwin", "x86_64-windows-gnu"], default="native")
    parser.add_argument("--zig", type=Path, help="Zig 0.16.0 executable for a Linux or Windows cross build")
    parser.add_argument("--objcopy", type=Path, default=shutil.which("llvm-objcopy") or shutil.which("objcopy"), help="GNU/LLVM objcopy for stripping cross-built Linux DWARF")
    args = parser.parse_args()
    if platform.system() not in ("Darwin", "Linux"): raise SystemExit("Run this native source build on macOS or Linux; Windows requires a separately validated native build.")
    if not args.pkg_config or not 1 <= args.jobs <= 32: raise SystemExit("pkg-config and a job count from 1 to 32 are required")
    cross = args.target != "native"
    cross_linux = cross and args.target.endswith("linux-musl")
    cross_macos = args.target == "x86_64-apple-darwin"
    cross_windows = args.target == "x86_64-windows-gnu"
    if cross_linux and not args.objcopy:
        raise SystemExit("Linux cross builds require GNU/LLVM objcopy (binutils or llvm)")
    if cross_macos and platform.system() != "Darwin":
        raise SystemExit("The macOS x86-64 build requires the Apple SDK on macOS")
    if (cross_linux or cross_windows) and (not args.zig or subprocess.check_output([str(args.zig), "version"], text=True).strip() != "0.16.0"):
        raise SystemExit("Linux/Windows cross builds require an explicit Zig 0.16.0 executable")
    sources=args.sources.resolve(); output=args.output.resolve()
    for value in SOURCES.values():
        if sha(sources/value["archive"]) != value["sha256"]: raise SystemExit("Source integrity mismatch: "+value["archive"])
    output.mkdir(parents=True, exist_ok=False)
    (output/"src").mkdir(); (output/"logs").mkdir(); (output/"bin").mkdir(); (output/"licenses").mkdir()
    target_system = "Windows" if cross_windows else "Linux" if cross_linux else platform.system()
    target_machine = args.target.split('-')[0] if cross else platform.machine()
    report={"format":1,"status":"building","system":target_system,"architecture":target_machine,"build_host":{"system":platform.system(),"architecture":platform.machine()},"target":args.target,"sources":SOURCES,"steps":[],"outputs":{}}
    report["builder_roots"]=[{"role":"build","path":str(output)},{"role":"sources","path":str(sources)},{"role":"home","path":str(Path.home())},{"role":"compiler","path":str(Path(args.cc).resolve())},{"role":"pkg-config","path":str(Path(args.pkg_config).resolve())}]
    if args.zig: report["builder_roots"].append({"role":"zig","path":str(args.zig.resolve().parent)})
    if cross_linux: report["builder_roots"].append({"role":"objcopy","path":str(args.objcopy.resolve())})
    def save(): (output/"build.json").write_text(json.dumps(report, indent=2)+"\n")
    # All library detection is restricted to the freshly built static prefix.
    # /omd is the recorded install prefix; DESTDIR keeps actual writes in output.
    env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "HOME":str(Path.home()), "TMPDIR":str(output), "LC_ALL":"C", "TZ":"UTC", "SOURCE_DATE_EPOCH":"1787097600", "ZERO_AR_DATE":"1", "CC":str(Path(args.cc).resolve()), "CFLAGS":"-O2", "PKG_CONFIG":str(Path(args.pkg_config).resolve()), "PKG_CONFIG_LIBDIR":str(output/"prefix/omd/lib/pkgconfig"), "PKG_CONFIG_PATH":""}
    wrappers=output/"toolchain";wrappers.mkdir()
    # FFmpeg embeds configure arguments in the executable. Keep launcher names
    # relative, and put actual compiler paths/remapping inside private launchers.
    maps=[f"-ffile-prefix-map={output}=/omd/media-build",f"-fdebug-prefix-map={output}=/omd/media-build"]
    def launcher(name, command):
        file=wrappers/name
        file.write_text('#!/bin/sh\nexec '+shlex.join(command)+' "$@"\n')
        file.chmod(0o755)
        return str(file)
    env["PKG_CONFIG"]=launcher("pkg-config",[env["PKG_CONFIG"]])
    if target_system=="Darwin":
        env["MACOSX_DEPLOYMENT_TARGET"]="13.0"
        env["SDKROOT"]=subprocess.check_output(["/usr/bin/xcrun","--sdk","macosx","--show-sdk-path"],text=True).strip()
    if cross_linux or cross_windows:
        for name, command in {"CC":["cc","-target",args.target],"AR":["ar"],"RANLIB":["ranlib"]}.items():
            flags=maps+[f"-ffile-prefix-map={args.zig.resolve().parent}=/toolchain/zig"] if name=="CC" else []
            env[name]=launcher(name.lower(),[str(args.zig.resolve()),*command,*flags])
        env["ZIG_GLOBAL_CACHE_DIR"]=str(output/"zig-cache")
        if cross_windows:
            linker=wrappers/"ld"
            linker.write_text('#!/bin/sh\nexec '+shlex.join([str(args.zig.resolve()),"ld.lld"] )+' "$@"\n')
            linker.chmod(0o755);env["LD"]=str(linker)
        report["cross_compiler"]={"name":"zig","version":"0.16.0","sha256":sha(args.zig)}
    elif cross_macos:
        env["CC"]=launcher("cc",[env["CC"],"-arch","x86_64",*maps])
        env["AR"]="/usr/bin/ar";env["RANLIB"]="/usr/bin/ranlib"
        report["apple_sdk"]=subprocess.check_output(["/usr/bin/xcrun","--sdk","macosx","--show-sdk-version"],text=True).strip()
    else:
        env["CC"]=launcher("cc",[env["CC"],*maps])
    report["compiler"]=subprocess.check_output([env["CC"],"--version"],text=True).strip()
    report["pkg_config"]=subprocess.check_output([env["PKG_CONFIG"],"--version"],text=True).strip()
    def run(label, command, cwd):
        print(label,flush=True); started=time.monotonic()
        with (output/"logs"/(label+".log")).open("wb") as log:
            result=subprocess.run(command,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=1200)
        report["steps"].append({"name":label,"command":command,"exit_code":result.returncode,"seconds":round(time.monotonic()-started,2)});save()
        if result.returncode: raise RuntimeError(label+" failed; inspect "+str(output/"logs"/(label+".log")))
    try:
        for name,value in SOURCES.items():
            with tarfile.open(sources/value["archive"]) as archive:
                archive.extractall(output/"src",filter="data")
        prefix=output/"prefix"
        machine="aarch64" if target_machine in ("arm64","aarch64") else "x86_64"
        build_machine="aarch64" if platform.machine() in ("arm64","aarch64") else "x86_64"
        host=build_machine+("-apple-darwin" if platform.system()=="Darwin" else "-unknown-linux-gnu")
        source=output/"src"/("zlib-"+SOURCES["zlib"]["version"])
        objects=[]
        for name in ZLIB_SOURCES:
            run("zlib-compile-"+name,[env["CC"],*env["CFLAGS"].split(),"-c",name+".c","-o",name+".o"],source)
            objects.append(name+".o")
        run("zlib-archive",[env.get("AR","ar"),"rc","libz.a",*objects],source)
        run("zlib-ranlib",[env.get("RANLIB","ranlib"),"libz.a"],source)
        (prefix/"omd/include").mkdir(parents=True,exist_ok=True);(prefix/"omd/lib/pkgconfig").mkdir(parents=True,exist_ok=True)
        for header in ("zlib.h","zconf.h"): shutil.copyfile(source/header,prefix/"omd/include"/header)
        shutil.copyfile(source/"libz.a",prefix/"omd/lib/libz.a")
        (prefix/"omd/lib/pkgconfig/zlib.pc").write_text("prefix=/omd\nexec_prefix=${prefix}\nlibdir=${exec_prefix}/lib\nincludedir=${prefix}/include\n\nName: zlib\nDescription: zlib compression library\nVersion: "+SOURCES["zlib"]["version"]+"\nLibs: -L${libdir} -lz\nCflags: -I${includedir}\n")
        shutil.copyfile(source/"LICENSE",output/"licenses"/"zlib-LICENSE")
        for name in ("opus","lame"):
            source=output/"src"/(name+"-"+SOURCES[name]["version"])
            options=["./configure","--prefix=/omd","--disable-shared","--enable-static","--disable-dependency-tracking","--build="+host]
            if cross: options.append("--host="+machine+("-apple-darwin" if cross_macos else "-w64-mingw32" if cross_windows else "-unknown-linux-gnu"))
            if name=="opus": options += ["--disable-extra-programs","--disable-doc"]
            else: options += ["--disable-frontend","--disable-decoder","--disable-analyzer-hooks","--disable-nasm"]
            run(name+"-configure",options,source)
            run(name+"-build",["make","-j"+str(args.jobs)],source)
            run(name+"-install",["make","DESTDIR="+str(prefix),"install"],source)
            shutil.copyfile(source/"COPYING",output/"licenses"/(name+"-COPYING"))
        # Relocatable pkg-config metadata keeps host paths out of final binaries.
        for pc in (prefix/"omd/lib/pkgconfig").glob("*.pc"):
            pc.write_text(pc.read_text().replace("prefix=/omd", "prefix=${pcfiledir}/../.."))
        source=output/"src/ffmpeg-9.0.1"
        if cross_windows:
            # This upstream switch works around GNU binutils dropping PE base
            # relocations. Zig uses LLD, retains them, and rejects this GNU alias.
            # Verify the actual PE relocation table and security flags below.
            configure=source/"configure"
            before="disabled debug && add_ldexeflags -Wl,--pic-executable,-e,mainCRTStartup"
            after="disabled debug && add_ldexeflags -Wl,-e,mainCRTStartup"
            text=configure.read_text()
            if text.count(before)!=1: raise RuntimeError("The pinned FFmpeg linker adjustment no longer matches")
            configure.write_text(text.replace(before,after))
            report["source_adjustments"]=[{"path":"ffmpeg/configure","before":before,"after":after,"reason":"LLD already retains PE base relocations; output security flags and relocation directory are verified"}]
        options=["./configure","--prefix=/omd","--disable-autodetect","--disable-network","--disable-doc","--disable-debug","--disable-shared","--enable-static","--disable-ffplay","--disable-everything","--enable-small","--enable-ffmpeg","--enable-ffprobe","--enable-libmp3lame","--enable-libopus","--enable-zlib","--enable-protocol=file,pipe","--enable-demuxer=mov,matroska,mp3,ogg,aac,wav,flac,mpegts,concat,webvtt,srt","--enable-muxer=mp4,matroska,webm,mp3,ogg,ipod,opus,srt,webvtt,ffmetadata,null","--enable-parser=aac,aac_latm,h264,hevc,vp8,vp9,av1,opus,mpegaudio,flac","--enable-decoder=aac,mp3,opus,vorbis,flac,pcm_s16le,webvtt,subrip,"+IMAGE_CODECS,"--enable-encoder=aac,libmp3lame,libopus,webvtt,subrip,"+IMAGE_CODECS,"--enable-filter=aresample,anull,atrim,aformat,null,format,scale,sidedata","--enable-bsf=aac_adtstoasc,extract_extradata,h264_mp4toannexb,vp9_superframe","--extra-cflags=-I../../prefix/omd/include","--extra-ldflags=-L../../prefix/omd/lib","--cc=../../toolchain/cc","--pkg-config=../../toolchain/pkg-config","--pkg-config-flags=--static"]
        if machine=="x86_64": options.append("--disable-x86asm")
        if cross_linux or cross_windows:
            options += ["--enable-cross-compile","--target-os="+("mingw32" if cross_windows else "linux"),"--arch="+machine,"--ar=../../toolchain/ar","--ranlib=../../toolchain/ranlib","--disable-stripping","--extra-ldflags=-static"]
        elif cross_macos:
            options += ["--enable-cross-compile","--target-os=darwin","--arch=x86_64","--ar="+env["AR"],"--ranlib="+env["RANLIB"]]
        run("ffmpeg-configure",options,source)
        run("ffmpeg-build",["make","-j"+str(args.jobs)],source)
        for name in ("ffmpeg","ffprobe"):
            file=output/"bin"/(name+(".exe" if cross_windows else ""));shutil.copy2(source/file.name,file)
            if cross_linux:
                # Zig's bundled musl assembly carries its own DWARF paths, which
                # do not inherit the consuming C compiler's prefix-map flags.
                stripped=file.with_suffix('.stripped')
                subprocess.run([str(args.objcopy),"--strip-debug",str(file),str(stripped)],check=True)
                stripped.chmod(0o755);stripped.replace(file)
                report.setdefault("postprocessing",[]).append({"binary":name,"operation":"objcopy --strip-debug","tool_version":subprocess.check_output([str(args.objcopy),"--version"],text=True).splitlines()[0]})
            data=file.read_bytes()
            for root in [output,sources,Path.home()]:
                needle=str(root).encode()
                if len(needle)>1 and needle.lower() in data.lower():
                    raise RuntimeError("Builder path remains in "+name)
            report["outputs"][name]={"sha256":sha(file),"bytes":file.stat().st_size,"version":SOURCES["ffmpeg"]["version"]}
            report["outputs"][name]["builder_paths"]=0
            if cross_windows:
                data=file.read_bytes();pe=struct.unpack_from('<I',data,0x3c)[0]
                if data[pe:pe+4]!=b'PE\0\0' or struct.unpack_from('<H',data,pe+4)[0]!=0x8664: raise RuntimeError("Unexpected Windows machine type")
                optional=pe+24
                if struct.unpack_from('<H',data,optional)[0]!=0x20b: raise RuntimeError("Expected PE32+ executable")
                flags=struct.unpack_from('<H',data,optional+70)[0]
                reloc=struct.unpack_from('<II',data,optional+112+5*8)
                if flags & 0x160 != 0x160 or not all(reloc): raise RuntimeError("Windows ASLR, high entropy, NX or base relocations are missing")
                report["outputs"][name]["pe_security"]={"nx":True,"aslr":True,"high_entropy":True,"relocations":True}
            if not cross: run(name+"-version",[str(file),"-version"],output)
            if target_system=="Darwin":
                libraries=subprocess.check_output(["/usr/bin/otool","-L",str(file)],text=True)
                if any(line.strip().startswith("/") and not line.strip().startswith(("/usr/lib/","/System/Library/")) for line in libraries.splitlines()[1:]): raise RuntimeError("Non-system dynamic library in "+name)
                if "libz." in libraries: raise RuntimeError("zlib must be linked statically from the pinned source into "+name)
                (output/"logs"/(name+"-libraries.log")).write_text(libraries)
        if not cross:
            protocols=subprocess.check_output([str(output/"bin/ffmpeg"),"-hide_banner","-protocols"],text=True)
            if set(protocols.split()) != {"Supported","file","protocols:","Input:","Output:","pipe"}: raise RuntimeError("Unexpected FFmpeg protocol: "+protocols)
            for kind in ("decoders","encoders"):
                # Rows after the "------" legend separator: flags, name, description.
                rows=subprocess.check_output([str(output/"bin/ffmpeg"),"-hide_banner","-"+kind],text=True).split("------\n",1)[1]
                listed={line.split()[1] for line in rows.splitlines() if line.startswith(" V")}
                if listed!=set(IMAGE_CODECS.split(",")): raise RuntimeError("Unexpected FFmpeg video "+kind+": "+" ".join(sorted(listed)))
        for license in source.glob("COPYING.*"): shutil.copyfile(license,output/"licenses"/("ffmpeg-"+license.name))
        report["status"]="built_requires_target_verification" if cross else "passed"
        save();print(json.dumps(report["outputs"],indent=2),flush=True)
    except BaseException as error:
        report["status"]="failed";report["failure"]=str(error);save();raise

if __name__=="__main__": main()
