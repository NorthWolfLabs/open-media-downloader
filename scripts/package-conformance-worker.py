# /// script
# requires-python = ">=3.12"
# ///
"""Package the exact Rust conformance worker sources for independent provider CI."""
import argparse,gzip,hashlib,json,re,shutil,subprocess,tarfile,tempfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];output=args.output.resolve()
    if output.exists():raise SystemExit("Refusing to replace a published source kit")
    with tempfile.TemporaryDirectory(prefix="omd-conformance-source-") as temporary:
        stage=Path(temporary)/"omd-conformance";stage.mkdir()
        for name in ("Cargo.toml","Cargo.lock","rust-toolchain.toml"):
            shutil.copyfile(root/name,stage/name)
        if (root/"LICENSE").is_file(): shutil.copyfile(root/"LICENSE",stage/"LICENSE")
        manifest=(stage/"Cargo.toml").read_text()
        manifest=re.sub(r'^members = .*$', 'members = ["crates/omd-domain", "crates/omd-plugin-worker"]',manifest,flags=re.M)
        manifest=re.sub(r'^exclude = .*\n', '',manifest,flags=re.M)
        (stage/"Cargo.toml").write_text(manifest)
        for crate in ("omd-domain","omd-plugin-worker"):
            (stage/"crates"/crate).mkdir(parents=True)
            shutil.copyfile(root/"crates"/crate/"Cargo.toml",stage/"crates"/crate/"Cargo.toml")
            shutil.copytree(root/"crates"/crate/"src",stage/"crates"/crate/"src")
        shutil.copytree(root/"sdk/provider/wit",stage/"sdk/provider/wit")
        # Retained domain unit tests include this synthetic fixture at compile time.
        (stage/"tests/fixtures").mkdir(parents=True)
        shutil.copyfile(root/"tests/fixtures/v2-plan.json",stage/"tests/fixtures/v2-plan.json")
        # Keep selected dependency versions, pruning engine-only workspace entries.
        subprocess.run(["cargo","metadata","--offline","--format-version","1"],cwd=stage,stdout=subprocess.DEVNULL,check=True)
        files=[]
        for path in sorted(stage.rglob("*")):
            if path.is_file():files.append({"path":path.relative_to(stage).as_posix(),"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
        (stage/"source-inventory.json").write_text(json.dumps({"format":1,"purpose":"OMD v2 provider fixture worker; no acquisition service","license_file":"LICENSE" if (stage/"LICENSE").is_file() else None,"files":files},indent=2)+"\n")
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("xb") as raw,gzip.GzipFile(fileobj=raw,mode="wb",filename="",mtime=0) as compressed,tarfile.open(fileobj=compressed,mode="w") as archive:
            for path in sorted(stage.rglob("*")):
                if not path.is_file():continue
                info=archive.gettarinfo(str(path),arcname="omd-conformance/"+path.relative_to(stage).as_posix())
                info.uid=info.gid=info.mtime=0;info.uname=info.gname="";info.mode=0o644
                with path.open("rb") as source:archive.addfile(info,source)
    print(json.dumps({"path":str(output),"sha256":hashlib.sha256(output.read_bytes()).hexdigest(),"bytes":output.stat().st_size},indent=2))

if __name__=="__main__":main()
