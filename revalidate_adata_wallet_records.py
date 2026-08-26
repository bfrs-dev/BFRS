#!/usr/bin/env python3
"""
Bulk independent revalidation of Bitcoin Core wallet-record anchors from a BFRS report.

This DOES NOT rescan the disk image. It:
1. loads target_findings from an existing BFRS JSON report,
2. selects artifact_kind == "wallet_record",
3. reads only a small number of bytes at each recorded physical_start,
4. identifies key / ckey / wkey from the raw image bytes,
5. validates CompactSize framing,
6. validates a 33/65-byte secp256k1 public key mathematically,
7. writes one JSON report.

No private/encrypted key payload is written to the output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from typing import Optional

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def decode_compact_size(data: bytes, pos: int):
    if pos >= len(data):
        return None, None, False, "out_of_bounds"

    first = data[pos]
    if first < 253:
        return first, 1, True, None

    if first == 253:
        if pos + 3 > len(data):
            return None, None, False, "truncated_uint16"
        value = int.from_bytes(data[pos + 1:pos + 3], "little")
        return value, 3, value >= 253, None

    if first == 254:
        if pos + 5 > len(data):
            return None, None, False, "truncated_uint32"
        value = int.from_bytes(data[pos + 1:pos + 5], "little")
        return value, 5, value > 0xFFFF, None

    if pos + 9 > len(data):
        return None, None, False, "truncated_uint64"
    value = int.from_bytes(data[pos + 1:pos + 9], "little")
    return value, 9, value > 0xFFFFFFFF, None


def is_valid_secp256k1_pubkey(pub: bytes) -> tuple[bool, str]:
    if len(pub) == 33:
        if pub[0] not in (2, 3):
            return False, "compressed_prefix_invalid"
        x = int.from_bytes(pub[1:], "big")
        if x >= P:
            return False, "x_out_of_range"
        rhs = (pow(x, 3, P) + 7) % P
        y = pow(rhs, (P + 1) // 4, P)
        if pow(y, 2, P) != rhs:
            return False, "x_not_on_curve"
        if (y & 1) != (pub[0] & 1):
            y = P - y
        if (y & 1) != (pub[0] & 1):
            return False, "compressed_parity_invalid"
        return True, "valid_compressed"

    if len(pub) == 65:
        if pub[0] != 4:
            return False, "uncompressed_prefix_invalid"
        x = int.from_bytes(pub[1:33], "big")
        y = int.from_bytes(pub[33:65], "big")
        if x >= P or y >= P:
            return False, "coordinate_out_of_range"
        if (y * y - (pow(x, 3, P) + 7)) % P != 0:
            return False, "point_not_on_curve"
        return True, "valid_uncompressed"

    return False, "length_not_33_or_65"


def classify_prefix(buf: bytes) -> tuple[Optional[str], int]:
    patterns = [
        (b"\x03key", "key"),
        (b"\x04ckey", "ckey"),
        (b"\x04wkey", "wkey"),
        (b"\x04mkey", "mkey"),
        (b"\x07keymeta", "keymeta"),
        (b"\x0adefaultkey", "defaultkey"),
    ]
    for prefix, name in patterns:
        if buf.startswith(prefix):
            return name, len(prefix)
    return None, 0


def inspect_anchor(fh, offset: int, image_size: int) -> dict:
    read_len = 160
    if offset < 0 or offset >= image_size:
        return {
            "offset": offset,
            "status": "OFFSET_OUT_OF_RANGE",
        }

    fh.seek(offset, os.SEEK_SET)
    buf = fh.read(min(read_len, image_size - offset))

    record_type, prefix_len = classify_prefix(buf)

    result = {
        "offset": offset,
        "record_type": record_type,
        "status": "PREFIX_NOT_RECOGNIZED",
        "pubkey_length": None,
        "pubkey_valid": False,
        "pubkey_validation": None,
        "pubkey_fingerprint_sha256_16": None,
    }

    if record_type not in {"key", "ckey", "wkey"}:
        return result

    value, cs_len, canonical, err = decode_compact_size(buf, prefix_len)
    result["next_compactsize_value"] = value
    result["next_compactsize_length"] = cs_len
    result["next_compactsize_canonical"] = canonical
    result["next_compactsize_error"] = err

    if err is not None:
        result["status"] = "COMPACTSIZE_INVALID"
        return result

    if not canonical:
        result["status"] = "COMPACTSIZE_NONCANONICAL"
        return result

    result["pubkey_length"] = value

    if value not in (33, 65):
        result["status"] = "PUBKEY_LENGTH_INVALID"
        result["pubkey_validation"] = "length_not_33_or_65"
        return result

    start = prefix_len + cs_len
    end = start + value
    if end > len(buf):
        result["status"] = "PUBKEY_TRUNCATED"
        return result

    pub = buf[start:end]
    valid, reason = is_valid_secp256k1_pubkey(pub)
    result["pubkey_valid"] = valid
    result["pubkey_validation"] = reason
    result["pubkey_fingerprint_sha256_16"] = hashlib.sha256(pub).hexdigest()[:16]
    result["status"] = "VALID_KEY_SIDE" if valid else "PUBKEY_INVALID"

    return result


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Revalidate BFRS Bitcoin wallet_record offsets without rescanning the image."
    )
    ap.add_argument("--input", required=True, help="Disk image path")
    ap.add_argument("--report", required=True, help="Existing BFRS JSON report")
    ap.add_argument("--output", required=True, help="Output JSON path")
    args = ap.parse_args()

    with open(args.report, "r", encoding="utf-8-sig") as f:
        report = json.load(f)

    findings = report.get("target_findings", [])
    wallet_findings = [
        x for x in findings
        if x.get("artifact_kind") == "wallet_record"
        and isinstance(x.get("physical_start"), int)
    ]

    offsets = sorted({int(x["physical_start"]) for x in wallet_findings})
    image_size = os.path.getsize(args.input)

    results = []
    with open(args.input, "rb", buffering=0) as fh:
        total = len(offsets)
        for i, offset in enumerate(offsets, 1):
            results.append(inspect_anchor(fh, offset, image_size))
            if i == total or i % 100 == 0:
                print(f"\rChecked {i}/{total}", end="", flush=True)
    print()

    status_counts = Counter(r["status"] for r in results)
    type_counts = Counter((r.get("record_type") or "unrecognized") for r in results)

    valid = [r for r in results if r["status"] == "VALID_KEY_SIDE"]

    by_fingerprint = defaultdict(list)
    for r in valid:
        fp = r.get("pubkey_fingerprint_sha256_16")
        if fp:
            by_fingerprint[fp].append(r["offset"])

    duplicate_groups = [
        {
            "pubkey_fingerprint_sha256_16": fp,
            "occurrence_count": len(offs),
            "offsets": offs,
        }
        for fp, offs in sorted(by_fingerprint.items())
        if len(offs) > 1
    ]

    output = {
        "tool": "bfrs_wallet_record_bulk_revalidator_v1",
        "source_image": os.path.abspath(args.input),
        "source_report": os.path.abspath(args.report),
        "method": "targeted_read_only_no_full_scan",
        "wallet_record_findings_in_report": len(wallet_findings),
        "unique_offsets_checked": len(offsets),
        "record_type_counts": dict(type_counts),
        "status_counts": dict(status_counts),
        "valid_key_side_count": len(valid),
        "unique_valid_pubkey_fingerprints": len(by_fingerprint),
        "duplicate_valid_pubkey_groups": duplicate_groups,
        "valid_candidates": valid,
        "all_results": results,
        "notes": [
            "A valid candidate requires canonical record-name framing plus a 33/65-byte mathematically valid secp256k1 public key.",
            "No private key or encrypted private-key payload is exported.",
            "VALID_KEY_SIDE confirms only the database-key side; surviving candidates require deeper record/value validation.",
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"wallet_record findings: {len(wallet_findings)}")
    print(f"unique offsets checked: {len(offsets)}")
    print(f"types: {dict(type_counts)}")
    print(f"statuses: {dict(status_counts)}")
    print(f"VALID_KEY_SIDE: {len(valid)}")
    print(f"output: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
