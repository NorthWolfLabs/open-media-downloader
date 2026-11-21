# /// script
# requires-python = ">=3.12"
# ///
"""Tests for verify-media-build.py: target evidence must match the cross build's
architecture, report the built-in pixel budget, and show a VP9 stream copy into
MP4 with a complete vpcC box. No media tools run here."""
import copy, hashlib, importlib.util, json, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("verify_media_build", ROOT / "scripts" / "verify-media-build.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)

BUDGET = 132710400
# The vpcC payload and digest of the fixture copied by an FFmpeg built with this
# configuration (8-bit 4:2:0, level 6.0).
VPCC = "01000000003c820202020000"


def build_record(target, ffmpeg=b"ffmpeg", ffprobe=b"ffprobe"):
    return {"status": "built_requires_target_verification", "target": target, "architecture": target.split("-")[0], "pixel_budget": BUDGET,
            "outputs": {"ffmpeg": {"sha256": hashlib.sha256(ffmpeg).hexdigest()}, "ffprobe": {"sha256": hashlib.sha256(ffprobe).hexdigest()}}}


def evidence(record, arch=None):
    arch = arch or record["architecture"]
    return {"status": "passed", "architecture": arch, "kernel": "6.8.0",
            "tools": {name: {"sha256": record["outputs"][name]["sha256"]} for name in ("ffmpeg", "ffprobe")},
            "tool_architectures": {"ffmpeg": arch, "ffprobe": arch},
            "max_pixels_default": {"ffmpeg": BUDGET, "ffprobe": BUDGET},
            "vp9_stream_copy": {"input_sha256": verify.VP9_FIXTURE_SHA256, "output_sha256": "ab" * 32, "vpcc": VPCC,
                                "codec_name": "vp9", "width": 7680, "height": 4320, "pix_fmt": "yuv420p"},
            "checks": sorted(verify.required_checks())}


class EvidenceTests(unittest.TestCase):
    def refused(self, pattern, record, data):
        with self.assertRaisesRegex(verify.Refused, pattern):
            verify.check_evidence(record, data)

    def test_every_cross_target_needs_its_own_architecture(self):
        for target in ("x86_64-linux-musl", "aarch64-linux-musl", "x86_64-windows-gnu", "x86_64-apple-darwin"):
            with self.subTest(target=target):
                record = build_record(target)
                self.assertEqual(verify.check_evidence(record, evidence(record)), verify.required_checks())
        record = build_record("aarch64-linux-musl")
        verify.check_evidence(record, evidence(record, "arm64"))
        self.refused("runtime architecture is not the build target's aarch64", record, evidence(record, "x86_64"))
        mixed = evidence(record)
        mixed["tool_architectures"]["ffprobe"] = "x86_64"
        self.refused("Unexpected runtime architecture for ffprobe", record, mixed)
        record["architecture"] = "x86_64"
        self.refused("architecture differs from its target", record, evidence(record, "aarch64"))
        self.refused("no cross target", {**build_record("x86_64-linux-musl"), "target": "native"}, evidence(build_record("x86_64-linux-musl")))

    def test_a_vp9_copy_must_keep_a_complete_vpcc_box_and_its_pixel_format(self):
        record = build_record("x86_64-linux-musl")
        cases = [
            # An FFmpeg without the VP9 decoder writes an empty box (the 0.2.3 failure).
            (lambda e: e["vp9_stream_copy"].update(vpcc=""), "holds 0 bytes"),
            (lambda e: e["vp9_stream_copy"].update(pix_fmt="unknown"), "pixel format 'unknown'"),
            (lambda e: e["vp9_stream_copy"].update(width=0, height=0), "7680x4320 VP9"),
            (lambda e: e["vp9_stream_copy"].update(input_sha256="00" * 32), "pinned fixture"),
            (lambda e: e["vp9_stream_copy"].update(vpcc="02" + VPCC[2:]), "version"),
            (lambda e: e["vp9_stream_copy"].update(vpcc=VPCC[:12] + "a2" + VPCC[14:]), "pixel format 'yuv420p', but the vpcC box describes yuv420p10le"),
            (lambda e: e["vp9_stream_copy"].update(vpcc=VPCC[:-4] + "0001"), "initialization data"),
            (lambda e: e["vp9_stream_copy"].pop("vpcc"), "must hold"),
            (lambda e: e.pop("vp9_stream_copy"), "must hold"),
            (lambda e: e["checks"].remove(verify.VP9_CHECK), "Incomplete native"),
        ]
        for mutate, pattern in cases:
            with self.subTest(pattern=pattern):
                data = copy.deepcopy(evidence(record))
                mutate(data)
                self.refused(pattern, record, data)
        self.assertEqual(verify.vpcc_format(bytes.fromhex(VPCC)), "yuv420p")
        self.assertEqual(verify.vpcc_format(bytes.fromhex("010000000228a20202020000")), "yuv420p10le")

    def test_both_executables_must_default_to_the_recorded_pixel_budget(self):
        record = build_record("x86_64-windows-gnu")
        for mutate, pattern in [
            (lambda e: e["max_pixels_default"].update(ffprobe=2147483647), "ffprobe does not default to the pixel budget"),
            (lambda e: e.pop("max_pixels_default"), "ffmpeg does not default"),
            (lambda e: e["checks"].remove(verify.BUDGET_CHECK), "Incomplete native"),
        ]:
            with self.subTest(pattern=pattern):
                data = copy.deepcopy(evidence(record))
                mutate(data)
                self.refused(pattern, record, data)
        self.refused("no pixel budget", {k: v for k, v in record.items() if k != "pixel_budget"}, evidence(record))
        self.refused("unverified cross-build", {**record, "status": "passed"}, evidence(record))
        other = evidence(record)
        other["tools"]["ffmpeg"]["sha256"] = "00" * 32
        self.refused("different executable bytes", record, other)

    def test_the_pinned_fixture_is_the_committed_and_exported_file(self):
        fixture = ROOT / verify.VP9_FIXTURE
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(), verify.VP9_FIXTURE_SHA256)
        inputs = json.loads((ROOT / "distribution/public-source-inputs.json").read_text())
        rows = [row for group in inputs.values() if isinstance(group, list) for row in group if isinstance(row, dict) and row.get("source") == verify.VP9_FIXTURE]
        self.assertEqual([row.get("sha256") for row in rows], [verify.VP9_FIXTURE_SHA256])
        build = (ROOT / "scripts/build-media.py").read_text()
        self.assertIn(f"VIDEO_PIXEL_BUDGET = {BUDGET}\n", build)

    def test_attach_records_the_evidence_or_leaves_the_build_unchanged(self):
        with tempfile.TemporaryDirectory() as folder:
            build = Path(folder) / "build"
            (build / "bin").mkdir(parents=True)
            (build / "bin" / "ffmpeg").write_bytes(b"ffmpeg")
            (build / "bin" / "ffprobe").write_bytes(b"ffprobe")
            record = build_record("aarch64-linux-musl")
            (build / "build.json").write_text(json.dumps(record))
            bad = Path(folder) / "bad.json"
            data = evidence(record)
            data["vp9_stream_copy"]["vpcc"] = ""
            bad.write_text(json.dumps(data))
            before = (build / "build.json").read_bytes()
            with self.assertRaises(verify.Refused):
                verify.attach(build, bad)
            self.assertEqual((build / "build.json").read_bytes(), before)
            self.assertFalse((build / "runtime-verification.json").exists())
            good = Path(folder) / "good.json"
            good.write_text(json.dumps(evidence(record)))
            result = verify.attach(build, good)
            self.assertEqual(result["status"], "passed")
            verified = json.loads((build / "build.json").read_text())
            self.assertEqual(verified["status"], "passed")
            self.assertEqual(verified["runtime_verification"]["vp9_stream_copy"]["vpcc"], VPCC)
            self.assertEqual(verified["runtime_verification"]["max_pixels_default"], {"ffmpeg": BUDGET, "ffprobe": BUDGET})
            self.assertEqual((build / "build-before-runtime-verification.json").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
