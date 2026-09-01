"""Synthetic 2 MiB benchmark for anchored Electrum JSON boundary scans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from bfrs.recovery.electrum_raw_recovery import (  # noqa: E402
    ElectrumCandidateAssembler,
    MAX_SCANNER_CANDIDATE_WINDOW,
)


def legacy_json_objects(data: bytes, counters: dict[str, int]):
    """Reference copy of the pre-optimization brace walker."""
    for start, byte in enumerate(data):
        if byte != 0x7B:
            continue
        depth, in_string, escaped = 0, False, False
        for end in range(start, len(data)):
            counters["boundary_bytes"] += 1
            current = data[end]
            if in_string:
                if escaped:
                    escaped = False
                elif current == 0x5C:
                    escaped = True
                elif current == 0x22:
                    in_string = False
                continue
            if current == 0x22:
                in_string = True
            elif current == 0x7B:
                depth += 1
            elif current == 0x7D:
                depth -= 1
                if depth == 0:
                    raw = data[start:end + 1]
                    try:
                        value = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        break
                    if isinstance(value, dict):
                        yield start, end + 1, value
                    break


def fixture(opening_braces: int) -> tuple[bytes, int]:
    wallet = json.dumps({
        "seed_version": 71,
        "wallet_type": "standard",
        "keystore": {"type": "bip32", "xpub": "synthetic-public-only"},
    }, separators=(",", ":")).encode()
    midpoint = MAX_SCANNER_CANDIDATE_WINDOW // 2
    unrelated = b"{}" * 4096
    hostile = b"{" * opening_braces
    prefix = unrelated + hostile
    prefix += b"X" * (midpoint - len(prefix))
    remaining = MAX_SCANNER_CANDIDATE_WINDOW - len(prefix) - len(wallet)
    data = prefix + wallet + b"}" * opening_braces
    data += b"Z" * (remaining - opening_braces)
    return data, data.index(b'"seed_version"')


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--opening-braces", type=int, default=128)
    arguments = parser.parse_args()
    data, anchor = fixture(arguments.opening_braces)

    legacy_stats = {"boundary_bytes": 0}
    started = time.perf_counter()
    legacy = tuple(
        item for item in legacy_json_objects(data, legacy_stats)
        if item[0] <= anchor < item[1]
    )
    legacy_seconds = time.perf_counter() - started

    optimized_stats: dict[str, int] = {}
    started = time.perf_counter()
    optimized = tuple(ElectrumCandidateAssembler._json_objects_containing(
        data, anchor, scan_stats=optimized_stats))
    optimized_seconds = time.perf_counter() - started

    print(json.dumps({
        "window_bytes": len(data),
        "opening_braces": arguments.opening_braces,
        "legacy_candidates_containing_anchor": len(legacy),
        "optimized_candidates_containing_anchor": len(optimized),
        "legacy_boundary_bytes": legacy_stats["boundary_bytes"],
        "optimized_boundary_bytes": optimized_stats["boundary_bytes"],
        "boundary_visit_reduction": (
            legacy_stats["boundary_bytes"] / optimized_stats["boundary_bytes"]),
        "legacy_seconds": legacy_seconds,
        "optimized_seconds": optimized_seconds,
        "wall_clock_speedup": legacy_seconds / optimized_seconds,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
