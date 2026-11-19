"""Signature-only relation for Authenticode-signed PE files (omd-pe-authenticode-layout-v1).

Signing a PE image with signtool changes exactly three things: the optional-header
CheckSum, the IMAGE_DIRECTORY_ENTRY_SECURITY data directory (file offset + size of the
attribute certificate table) and the bytes appended at the end of the file (up to 7 bytes
of zero alignment padding, then the WIN_CERTIFICATE table). Authenticode's own image hash
excludes the same fields. This module proves that relation from bytes: an unsigned input U
and a signed output S are `signature-only` when S starts with U except those two header
fields, the gap is zero padding to an 8-byte boundary and the certificate table ends the
file.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

LAYOUT = "omd-pe-authenticode-layout-v1"


def parse(data: bytes) -> dict:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("not an MZ image")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, = struct.unpack_from("<H", data, pe + 4)
    opt_size, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    if magic == 0x20B:
        dirs = opt + 112
    elif magic == 0x10B:
        dirs = opt + 96
    else:
        raise ValueError("unknown optional header magic")
    count, = struct.unpack_from("<I", data, dirs - 4)
    if count < 5 or dirs + 8 * 5 > opt + opt_size:
        raise ValueError("no security data directory")
    sec = dirs + 8 * 4
    sec_off, sec_size = struct.unpack_from("<II", data, sec)
    return {"machine": machine, "magic": magic, "checksum_offset": opt + 64,
            "security_entry_offset": sec, "security_offset": sec_off, "security_size": sec_size}


def certificates(data: bytes, info: dict) -> list[dict]:
    off, size = info["security_offset"], info["security_size"]
    out, pos = [], off
    while pos < off + size:
        length, revision, kind = struct.unpack_from("<IHH", data, pos)
        if length < 8 or pos + length > off + size:
            raise ValueError("malformed WIN_CERTIFICATE")
        out.append({"length": length, "revision": revision, "type": kind})
        pos += (length + 7) & ~7
    return out


def relation(unsigned: bytes, signed: bytes) -> dict:
    u, s = parse(unsigned), parse(signed)
    problems = []
    if u["security_size"] or u["security_offset"]:
        problems.append("input already carries a certificate table")
    if not s["security_size"]:
        problems.append("output has no certificate table")
    for key in ("machine", "magic", "checksum_offset", "security_entry_offset"):
        if u[key] != s[key]:
            problems.append(f"header layout differs: {key}")
    n = len(unsigned)
    off, size = s["security_offset"], s["security_size"]
    if not problems:
        if off % 8 or off < n or off - n > 7:
            problems.append("certificate table is not at the 8-byte aligned end of the input")
        elif any(signed[n:off]):
            problems.append("non-zero bytes between image and certificate table")
        if off + size != len(signed):
            problems.append("certificate table does not end the signed file")
        a, b = bytearray(unsigned), bytearray(signed[:n])
        for blob in (a, b):
            blob[u["checksum_offset"]:u["checksum_offset"] + 4] = b"\0\0\0\0"
            blob[u["security_entry_offset"]:u["security_entry_offset"] + 8] = b"\0" * 8
        if a != b:
            first = next(i for i in range(n) if a[i] != b[i])
            problems.append(f"image bytes differ at offset {first}")
    certs = certificates(signed, s) if not problems else []
    if certs and not all(c["revision"] == 0x0200 and c["type"] == 0x0002 for c in certs):
        problems.append("unexpected WIN_CERTIFICATE revision/type")
    return {
        "layout": LAYOUT,
        "relation": "signature-only" if not problems else "refused",
        "problems": problems,
        "unsigned_sha256": hashlib.sha256(unsigned).hexdigest(), "unsigned_bytes": n,
        "signed_sha256": hashlib.sha256(signed).hexdigest(), "signed_bytes": len(signed),
        "padding_bytes": off - n if not problems else None,
        "certificate_table": {"offset": off, "size": size, "entries": certs},
        "checksum": {"unsigned": struct.unpack_from("<I", unsigned, u["checksum_offset"])[0],
                     "signed": struct.unpack_from("<I", signed, s["checksum_offset"])[0]},
    }


def main(argv: list[str]) -> int:
    pairs = json.loads(Path(argv[1]).read_text())
    rows = []
    for row in pairs:
        r = relation(Path(row["unsigned"]).read_bytes(), Path(row["signed"]).read_bytes())
        if row.get("unsigned_sha256") and r["unsigned_sha256"] != row["unsigned_sha256"]:
            r["problems"].append("unsigned input differs from its expected digest"); r["relation"] = "refused"
        rows.append({"name": row["name"], **r})
    Path(argv[2]).write_text(json.dumps(rows, indent=2) + "\n")
    bad = [r["name"] for r in rows if r["relation"] != "signature-only"]
    print(json.dumps({"checked": len(rows), "refused": bad}))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
