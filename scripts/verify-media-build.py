# /// script
# requires-python = ">=3.12"
# ///
"""Attach successful, exact-byte native execution evidence to a media source build.

A cross build is verified by running its exact executables on the target. The
runtime evidence (JSON) must report:

- status "passed", the target's kernel and architecture, and for ffmpeg and
  ffprobe the executed bytes' sha256 and architecture. Every architecture must
  be the build target's (x86_64 or aarch64; arm64 counts as aarch64).
- max_pixels_default: {"ffmpeg": N, "ffprobe": N}, the max_pixels default each
  executable's `-h full` reports, equal to build.json's pixel_budget.
- vp9_stream_copy: the confined `ffmpeg -i <input> -map 0 -c copy -movflags
  +faststart <output>.mp4` of tests/fixtures/media/vp9-7680x4320-fragmented.mp4
  (a synthetic 8K VP9 fragmented MP4), then a confined ffprobe of the output:
  {"input_sha256", "output_sha256", "vpcc": hex payload of the output's vpcC
  box, "codec_name", "width", "height", "pix_fmt"}. The vpcC box must be complete
  and agree with the pixel format, which only the VP9 decoder can supply.
- checks: every name in required_checks(). The WAV conversions exercise the
  audio codecs and confinement; only the VP9 copy exercises the video decoder.
"""
import argparse, hashlib, json, re
from pathlib import Path

# The synthetic fixture the VP9 stream copy must use (tests/fixtures/media/README.md).
VP9_FIXTURE = "tests/fixtures/media/vp9-7680x4320-fragmented.mp4"
VP9_FIXTURE_SHA256 = "814f14522d80a6004c69b5d0c550e11ba6e620ca51f811fd5943c5c988bbc3fd"
VP9_FIXTURE_SIZE = (7680, 4320)
ARCHITECTURES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
HEX64 = re.compile(r"[0-9a-f]{64}")
CONVERSIONS = ["mp3/mp3", "m4a/aac", "opus/opus", "webm/opus", "mkv/aac", "mp4/aac"]
VP9_CHECK = "Confined VP9 stream copy into MP4: vpcC and pixel format"
BUDGET_CHECK = "FFmpeg and FFprobe decoders default to the OMD pixel budget"


class Refused(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Refused(why)


def required_checks():
    return {"FFmpeg exposes only file and pipe protocols", "Unrelated input remains inaccessible and unchanged", VP9_CHECK, BUDGET_CHECK} | {
        "Confined WAV conversion and probe: " + item for item in CONVERSIONS}


def architecture(name):
    need(isinstance(name, str) and name in ARCHITECTURES, f"Unknown architecture: {name!r}")
    return ARCHITECTURES[name]


def target_architecture(record):
    """The architecture a cross build targets, from its recorded target triple."""
    target = record.get("target")
    need(isinstance(target, str) and "-" in target, "The build records no cross target")
    expected = architecture(target.split("-", 1)[0])
    need(architecture(record.get("architecture")) == expected, "The build's architecture differs from its target")
    return expected


def vpcc_format(payload):
    """The pixel format a complete VP Codec Configuration box (version 1) describes."""
    need(len(payload) == 12, f"The vpcC box holds {len(payload)} bytes, not 12")
    version, flags, profile = payload[0], payload[1:4], payload[4]
    depth, chroma = payload[6] >> 4, (payload[6] >> 1) & 7
    need(version == 1 and flags == b"\0\0\0" and profile <= 3, "Unexpected vpcC version, flags or profile")
    need(depth in (8, 10, 12) and chroma <= 3, "Unexpected vpcC bit depth or chroma subsampling")
    need(payload[10:12] == b"\0\0", "VP9 has no codec initialization data")
    base = {0: "yuv420p", 1: "yuv420p", 2: "yuv422p", 3: "yuv444p"}[chroma]
    return base if depth == 8 else f"{base}{depth}le"


def check_vp9_copy(copy):
    need(isinstance(copy, dict) and set(copy) == {"input_sha256", "output_sha256", "vpcc", "codec_name", "width", "height", "pix_fmt"},
         "vp9_stream_copy must hold input_sha256, output_sha256, vpcc, codec_name, width, height and pix_fmt")
    need(copy["input_sha256"] == VP9_FIXTURE_SHA256, "The VP9 copy did not use the pinned fixture " + VP9_FIXTURE)
    need(isinstance(copy["output_sha256"], str) and HEX64.fullmatch(copy["output_sha256"]), "Invalid VP9 copy output digest")
    need(isinstance(copy["vpcc"], str) and re.fullmatch(r"(?:[0-9a-f]{2})*", copy["vpcc"]), "The vpcC payload must be lowercase hex")
    expected = vpcc_format(bytes.fromhex(copy["vpcc"]))
    need(copy["codec_name"] == "vp9" and (copy["width"], copy["height"]) == VP9_FIXTURE_SIZE, "The copied stream is not the fixture's 7680x4320 VP9")
    need(copy["pix_fmt"] == expected, f"ffprobe reports pixel format {copy['pix_fmt']!r}, but the vpcC box describes {expected}")


def check_evidence(record, evidence):
    """Refuse runtime evidence that does not cover the build's exact executables."""
    need(record.get("status") == "built_requires_target_verification", "Use an unverified cross-build and retain its original identity")
    need(evidence.get("status") == "passed", "Native runtime checks must all pass")
    expected = target_architecture(record)
    need(architecture(evidence.get("architecture")) == expected, f"The runtime architecture is not the build target's {expected}")
    budget = record.get("pixel_budget")
    need(type(budget) is int and budget > 0, "The build records no pixel budget")
    for name in ("ffmpeg", "ffprobe"):
        need(evidence["tools"][name]["sha256"] == record["outputs"][name]["sha256"], "Runtime used different executable bytes")
        need(architecture(evidence["tool_architectures"][name]) == expected, f"Unexpected runtime architecture for {name}")
        need(evidence.get("max_pixels_default", {}).get(name) == budget, f"{name} does not default to the pixel budget {budget}")
    check_vp9_copy(evidence.get("vp9_stream_copy"))
    required = required_checks()
    need(required <= set(evidence.get("checks", [])), "Incomplete native conversion/policy evidence: " + ", ".join(sorted(required - set(evidence.get("checks", [])))))
    return required


def attach(build, runtime_evidence):
    record_path = build / "build.json"
    original = record_path.read_bytes()
    record = json.loads(original)
    raw = runtime_evidence.read_bytes()
    evidence = json.loads(raw)
    required = check_evidence(record, evidence)
    for name in ("ffmpeg", "ffprobe"):
        path = build / "bin" / (name + ".exe" if "windows" in record.get("target", "") else name)
        with path.open("rb") as file:
            need(hashlib.file_digest(file, "sha256").hexdigest() == record["outputs"][name]["sha256"], "Source output changed after verification")
    for name, data in (("build-before-runtime-verification.json", original), ("runtime-verification.json", raw)):
        with (build / name).open("xb") as file:
            file.write(data)
    record["status"] = "passed"
    record["runtime_verification"] = {"report_sha256": hashlib.sha256(raw).hexdigest(), "source_report_sha256": hashlib.sha256(original).hexdigest(),
                                      "architecture": evidence["architecture"], "kernel": evidence["kernel"], "checks": sorted(required),
                                      "max_pixels_default": evidence["max_pixels_default"], "vp9_stream_copy": evidence["vp9_stream_copy"]}
    need(record_path.read_bytes() == original, "Build changed while attaching evidence")
    temporary = build / "build-verified.json"
    with temporary.open("x") as file:
        file.write(json.dumps(record, indent=2) + "\n")
    temporary.replace(record_path)
    return {"status": "passed", "build": str(build), "runtime_report_sha256": record["runtime_verification"]["report_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--runtime-evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(attach(args.build, args.runtime_evidence)))
    except Refused as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()
