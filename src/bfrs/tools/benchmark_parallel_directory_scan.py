"""Benchmark bounded folder-file concurrency on synthetic regular files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time

from bfrs.cli import main
from bfrs.scanners.target_registry import (
    ARMORY_SIGNATURES,
    ELECTRUM_ONLY_SIGNATURES_V1,
    MULTIBIT_SIGNATURES,
)


def _positive(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _finding_digest(findings: list[dict]) -> str:
    encoded = json.dumps(
        findings, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_fixture(root: Path, count: int, size: int) -> int:
    patterns = (
        ELECTRUM_ONLY_SIGNATURES_V1[-1].pattern,
        MULTIBIT_SIGNATURES[1].pattern,
        ARMORY_SIGNATURES[0].pattern,
        b"ordinary recovered file bytes",
    )
    total = 0
    for index in range(count):
        pattern = patterns[index % len(patterns)]
        prefix = bytes((index % 251,)) * min(31, max(0, size - len(pattern)))
        payload = (prefix + pattern).ljust(size, b"\x00")
        path = root / f"recovered-{index:07d}"
        path.write_bytes(payload)
        total += len(payload)
    return total


def main_benchmark(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=_positive, default=300)
    parser.add_argument("--bytes-per-file", type=_positive, default=4096)
    arguments = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="bfrs-folder-benchmark-") as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        total_bytes = _write_fixture(
            source, arguments.files, arguments.bytes_per_file)
        rows = []
        baseline_digest = None
        baseline_count = None
        baseline_elapsed = None
        for workers in (1, 2, 4):
            report = work / f"report-{workers}.json"
            started = time.perf_counter()
            code = main([
                "--input", str(source),
                "--source-type", "folder",
                "--output", str(report),
                "--targets", "all",
                "--skip-mnemonic",
                "--file-workers", str(workers),
                "--workers", "1",
            ])
            elapsed = time.perf_counter() - started
            if code != 0:
                raise RuntimeError(f"benchmark scan failed for file_workers={workers}")
            payload = json.loads(report.read_text(encoding="utf-8"))
            findings = payload["target_findings"]
            digest = _finding_digest(findings)
            if baseline_digest is None:
                baseline_digest = digest
                baseline_count = len(findings)
                baseline_elapsed = elapsed
            identical = digest == baseline_digest and len(findings) == baseline_count
            rows.append({
                "file_workers": workers,
                "seconds": elapsed,
                "files_per_second": arguments.files / elapsed,
                "mib_per_second": total_bytes / 2**20 / elapsed,
                "speedup": baseline_elapsed / elapsed,
                "findings": len(findings),
                "finding_digest": digest,
                "identical_to_file_workers_1": identical,
            })
        print(json.dumps({
            "files": arguments.files,
            "bytes": total_bytes,
            "results": rows,
        }, indent=2, sort_keys=True))
        return 0 if all(row["identical_to_file_workers_1"] for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main_benchmark())
