"""Small-file benchmark; synthetic public markers, no keys/seeds.

Run from an editable installation: python -m bfrs.tools.benchmark_folder_small_files
Each sample runs in a fresh process. Retain --work-dir to reuse identical inputs
before/after. Timings include instrument overhead equally in both versions.
"""
from __future__ import annotations

import argparse
import contextlib
import cProfile
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import pstats
import sqlite3
import statistics
import subprocess
import sys
import threading
import time


def memory():
    if os.name == "nt":
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in (
                    "peak_rss", "rss", "peak_paged", "paged", "peak_nonpaged",
                    "nonpaged", "pagefile", "peak_pagefile")]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if ctypes.windll.psapi.GetProcessMemoryInfo(
                wintypes.HANDLE(-1), ctypes.byref(counters), counters.cb):
            return {"peak_rss_bytes": counters.peak_rss, "rss_bytes": counters.rss}
    else:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {"peak_rss_bytes": peak * (1 if sys.platform == "darwin" else 1024)}
    return {"peak_rss_bytes": None}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in {"elapsed_seconds"}}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


def fixture(root, count, size, mixed=False):
    from bfrs.scanners.target_registry import (
        ARMORY_SIGNATURES, BITCOIN_CORE_SIGNATURES_V1, ELECTRUM_ONLY_SIGNATURES_V1,
        MULTIBIT_SIGNATURES)
    patterns = [b"synthetic ordinary bytes", BITCOIN_CORE_SIGNATURES_V1[-1].pattern,
        ELECTRUM_ONLY_SIGNATURES_V1[-1].pattern, MULTIBIT_SIGNATURES[1].pattern,
        ARMORY_SIGNATURES[0].pattern]
    manifest = []
    for index in range(count):
        relative = Path(f"bucket-{index // 256:05d}") / f"file-{index:07d}.bin"
        file_size = (2 * 1024**2 + 257) if mixed and index % 64 == 0 else size
        data = (b"\0" * 32 + patterns[index % len(patterns)]).ljust(file_size, b"\0")
        path = root / relative
        path.parent.mkdir(exist_ok=True, parents=True)
        if path.exists():
            if path.read_bytes() != data:
                raise ValueError(f"existing benchmark fixture differs: {path}")
        else:
            path.write_bytes(data)
        info = path.stat()
        manifest.append([relative.as_posix(), len(data), info.st_mtime_ns,
                         hashlib.sha256(data).hexdigest()])
    return digest(manifest), sum(row[1] for row in manifest)


def trial(args):
    from bfrs.cli import main
    import bfrs.cli as cli
    from bfrs.scanners.folder_scan_checkpoint import FolderScanCheckpoint
    from bfrs.scanners import folder_source_scanner
    folder_source_scanner._CHECKPOINT_BATCH_SIZE = args.batch_size
    folder_source_scanner._BATCH_FILE_LIMIT = getattr(args, "batch_file_limit", 32)
    work = Path(args.work_dir)
    checkpoint_path = work / f"{args.label}-{args.sample}-{args.workers}.sqlite"
    report_path = checkpoint_path.with_suffix(".json")
    if checkpoint_path.exists() or report_path.exists():
        raise ValueError("sample output already exists; choose a new label")
    stats = {"save_calls": 0, "save_call_thread_seconds": 0.,
             "checkpoint_commit_seconds": 0., "checkpoint_context_exits": 0,
             "detector_initialization_thread_seconds": 0., "detector_initializations": 0}
    lock = threading.Lock()
    def add(**values):
        with lock:
            for key, value in values.items():
                stats[key] += value
    class TimedConnection(sqlite3.Connection):
        def __exit__(self, *exc):
            began = time.perf_counter()
            try:
                return super().__exit__(*exc)
            finally:
                add(checkpoint_commit_seconds=time.perf_counter() - began,
                    checkpoint_context_exits=1)
    connect = sqlite3.connect
    def timed_connect(path, *a, **kw):
        if Path(path) == checkpoint_path.resolve():
            kw["factory"] = TimedConnection
        return connect(path, *a, **kw)
    sqlite3.connect = timed_connect
    save = FolderScanCheckpoint.save_outcome
    def timed_save(self, **kw):
        began = time.perf_counter()
        try:
            return save(self, **kw)
        finally:
            add(save_calls=1, save_call_thread_seconds=time.perf_counter()-began)
    FolderScanCheckpoint.save_outcome = timed_save
    selection = cli._selection
    def timed_selection(*a, **kw):
        began = time.perf_counter()
        try:
            return selection(*a, **kw)
        finally:
            add(detector_initializations=1,
                detector_initialization_thread_seconds=time.perf_counter()-began)
    cli._selection = timed_selection
    if args.batch_size:
        # Also works against the unchanged baseline (which has no set_batching).
        configure = getattr(FolderScanCheckpoint, "set_batching", None)
        if configure is None and args.batch_size != 1:
            raise ValueError("this revision does not implement batching")
        if configure:
            for name in ("create", "resume"):
                original = getattr(FolderScanCheckpoint, name)
                def configured(*a, _original=original, **kw):
                    result = _original(*a, **kw)
                    result.set_batching(args.batch_size, 1.0)
                    return result
                setattr(FolderScanCheckpoint, name, configured)
    stages = {}
    def progress(update):
        stages.setdefault(update.stage, time.perf_counter())
    began = time.perf_counter()
    cpu = time.process_time()
    # Redirect all scanner output, keeping the worker's stdout machine-readable.
    with (checkpoint_path.with_suffix(".log")).open("x", encoding="utf-8") as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            code = main(["--input", str(work / "source"), "--output", str(report_path),
                "--targets", "all", "--workers", "1", "--file-workers", str(args.workers),
                "--chunk-mib", "1", "--padding-mib", "1", "--checkpoint", str(checkpoint_path)],
                _scan_progress=progress)
    elapsed = time.perf_counter()-began
    cpu = time.process_time()-cpu
    if code:
        raise RuntimeError(f"scan exited {code}; see sample .log")
    rss = memory()  # Before loading report for correctness comparison.
    report = json.loads(report_path.read_text(encoding="utf-8"))
    with connect(checkpoint_path) as db:
        durable = db.execute("SELECT count(*) FROM outcomes").fetchone()[0]
    return dict(stats, **rss, file_workers=args.workers, sample=args.sample,
        batch_size=args.batch_size, seconds=elapsed, cpu_seconds=cpu,
        cpu_percent_one_core=100*cpu/elapsed, files_per_second=report["files_scanned"]/elapsed,
        mib_per_second=report["bytes_scanned"]/2**20/elapsed,
        initialization_seconds=stages["folder-scan"]-began,
        scan_seconds=stages["folder-report"]-stages["folder-scan"],
        report_and_finalize_seconds=began+elapsed-stages["folder-report"],
        files_scanned=report["files_scanned"], durable_files=durable,
        finding_digest=digest(report["target_findings"]),
        file_report_digest=digest(stable(report["files"])))


def discovery_trial(args):
    from bfrs.scanners.folder_source_scanner import discover_regular_files
    from bfrs.scanners.folder_scan_checkpoint import folder_snapshot_digest
    root = Path(args.work_dir) / "source"
    began, cpu = time.perf_counter(), time.process_time()
    files, skipped = discover_regular_files(root)
    discovered = time.perf_counter()
    snapshot = folder_snapshot_digest(root, files)
    ended = time.perf_counter()
    return dict(files=len(files), skipped=len(skipped), snapshot_sha256=snapshot,
        discovery_seconds=discovered-began, snapshot_seconds=ended-discovered,
        initialization_seconds=ended-began, cpu_seconds=time.process_time()-cpu, **memory())


def main_benchmark(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--files", type=int, default=1024)
    parser.add_argument("--bytes-per-file", type=int, default=4096)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--batch-size", type=int, choices=(1, 32), default=1)
    parser.add_argument("--workers", type=int, choices=(1, 2, 4), default=1)
    parser.add_argument("--sample", type=int, default=0)
    parser.add_argument("--trial", action="store_true")
    parser.add_argument("--mixed", action="store_true", help="every 64th file is 2 MiB + 257 bytes")
    parser.add_argument("--batch-file-limit", type=int, choices=(8, 32), default=32,
        help="scheduling experiment; does not change checkpoint transaction limit")
    parser.add_argument("--profile", action="store_true", help="separate cProfile run, one file worker; not a throughput sample")
    parser.add_argument("--discovery-only", action="store_true",
        help="profile discovery/snapshot at larger scale; does not measure detection throughput")
    args = parser.parse_args(argv)
    if args.trial:
        print(json.dumps(discovery_trial(args) if args.discovery_only else trial(args), ensure_ascii=True))
        return 0
    if args.files < 1 or args.bytes_per_file < 128 or args.repeats < 1:
        parser.error("positive file/repeat count and size >= 128 required")
    work = Path(args.work_dir).resolve()
    work.mkdir(parents=True, exist_ok=True)
    manifest, total = fixture(work / "source", args.files, args.bytes_per_file, args.mixed)
    if args.profile:
        profile = cProfile.Profile()
        profile.enable()
        row = trial(args)
        profile.disable()
        profile.dump_stats(str(work / f"{args.label}.prof"))
        stats = pstats.Stats(profile)
        functions = [dict(file=key[0], line=key[1], name=key[2], calls=value[1],
            self_seconds=value[2], cumulative_seconds=value[3]) for key,value in stats.stats.items()]
        functions.sort(key=lambda value: value['cumulative_seconds'], reverse=True)
        (work / f"{args.label}-profile.json").write_text(json.dumps(
            dict(sample=row, functions=functions), indent=2)+"\n", encoding="utf-8")
        return 0
    output = work / f"{args.label}-results.json"
    if output.exists():
        raise ValueError("result already exists; choose another label")
    rows = []
    if args.discovery_only:
        for _ in range(args.repeats):
            command = [sys.executable, "-m", "bfrs.tools.benchmark_folder_small_files",
                "--trial", "--discovery-only", "--work-dir", str(work), "--label", args.label]
            rows.append(json.loads(subprocess.check_output(command, text=True, encoding="utf-8")))
        output.write_text(json.dumps(dict(label=args.label, discovery_only=True,
            platform=platform.platform(), python=sys.version, files=args.files, bytes=total,
            corpus_sha256=manifest, results=rows), indent=2)+"\n", encoding="utf-8")
        print(json.dumps(rows, indent=2), flush=True)
        return 0 if all(row["files"] == args.files and not row["skipped"] for row in rows) else 2
    for sample in range(args.repeats):
        # Alternate order to reduce a systematic warm-cache/order advantage.
        for workers in ((1, 2, 4) if sample % 2 == 0 else (4, 2, 1)):
            command = [sys.executable, "-m", "bfrs.tools.benchmark_folder_small_files",
                "--trial", "--work-dir", str(work), "--label", args.label,
                "--sample", str(sample), "--workers", str(workers),
                "--batch-size", str(args.batch_size), "--batch-file-limit", str(args.batch_file_limit)]
            row = json.loads(subprocess.check_output(command, text=True, encoding="utf-8"))
            rows.append(row)
            print(f"{args.label} workers={workers} sample={sample}: "
                f"{row['seconds']:.3f}s {row['files_per_second']:.1f} files/s", flush=True)
    equivalent = len({(row["finding_digest"], row["file_report_digest"]) for row in rows}) == 1
    payload = dict(label=args.label, platform=platform.platform(), python=sys.version,
        files=args.files, bytes=total, corpus_sha256=manifest, batch_size=args.batch_size,
        mixed=args.mixed, batch_file_limit=args.batch_file_limit,
        cache_policy="OS cache not flushed; fresh process per sample; alternating worker order",
        metric_notes={"checkpoint_context_exits": "Connection context exits, including schema setup with no active DML transaction; not an SQL transaction census",
                      "checkpoint_commit_seconds": "Time in checkpoint connection context exits, including FULL commits and negligible no-op schema context exit"},
        equivalent_results=equivalent, results=rows,
        medians={str(w): {k: statistics.median(row[k] for row in rows if row["file_workers"] == w)
            for k in ("seconds", "files_per_second", "mib_per_second", "checkpoint_commit_seconds",
                "initialization_seconds", "report_and_finalize_seconds", "cpu_seconds", "peak_rss_bytes")}
            for w in (1, 2, 4)})
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    return 0 if equivalent else 2


if __name__ == "__main__":
    raise SystemExit(main_benchmark())
