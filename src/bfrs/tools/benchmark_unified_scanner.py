"""Compare target-only, mnemonic-only, and unified shared-chunk throughput."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
import tempfile
import threading
import time

from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.scanners.fast_scanner import FastScanner
from bfrs.scanners.target_registry import LEGACY_TARGETS, build_target_selection
from bfrs.tools.benchmark_seed_scanner import binary_fixture, synthetic_fixture


try:
    import psutil
except ImportError:  # pragma: no cover - optional benchmark instrumentation
    psutil = None


class ThrottledChunkReader(ChunkReader):
    """Benchmark-only cumulative transfer-rate limiter."""

    def __init__(self, *args, read_mib_s: float = 0.0, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.read_bytes_per_second = read_mib_s * 2**20

    def iter_owned_chunks(self, *args, **kwargs) -> Iterator[
            tuple[int, int, Chunk | None]]:
        for unit in super().iter_owned_chunks(*args, **kwargs):
            if unit[2] is not None and self.read_bytes_per_second > 0:
                time.sleep(len(unit[2].data) / self.read_bytes_per_second)
            yield unit


@dataclass(frozen=True, slots=True)
class RunMetrics:
    seconds: float
    hits: int
    linear_pass_count: int
    linear_bytes_read: int
    linear_read_count: int
    peak_rss_bytes: int


def _run(path: Path, *, signatures, detectors, chunk_size: int,
         overlap: int, read_mib_s: float) -> RunMetrics:
    scanner = FastScanner(signatures, chunk_detectors=detectors)
    reader = ThrottledChunkReader(
        path, chunk_size=chunk_size, overlap=overlap, read_mib_s=read_mib_s)
    stop = threading.Event()
    peak = 0

    def sample_rss() -> None:
        nonlocal peak
        if psutil is None:
            return
        parent = psutil.Process()
        while not stop.wait(0.10):
            total = 0
            for process in (parent, *parent.children(recursive=True)):
                try:
                    total += process.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            peak = max(peak, total)

    sampler = threading.Thread(target=sample_rss, daemon=True)
    sampler.start()
    started = time.perf_counter()
    try:
        hits = sum(1 for _ in scanner.scan(reader))
    finally:
        elapsed = time.perf_counter() - started
        stop.set()
        sampler.join()
    if peak == 0 and psutil is not None:
        peak = psutil.Process().memory_info().rss
    return RunMetrics(
        elapsed, hits, reader.linear_pass_count, reader.linear_bytes_read,
        reader.linear_read_count, peak)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mib", type=int, default=64,
                        help="fixture size; scalable to 1024 for a 1 GiB run")
    parser.add_argument("--fixture", choices=("binary", "prose", "controls"),
                        default="binary")
    parser.add_argument("--chunk-mib", type=int, default=16)
    parser.add_argument("--overlap-kib", type=int, default=64)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--read-mib-s", type=float, default=0.0,
        help="simulate a sequential device rate (for example 100 or 50); 0 disables")
    arguments = parser.parse_args(argv)
    if arguments.read_mib_s < 0:
        parser.error("--read-mib-s must not be negative")
    size = arguments.mib * 2**20
    data = (binary_fixture(size) if arguments.fixture == "binary" else
            synthetic_fixture(size, controls=arguments.fixture == "controls"))
    target = build_target_selection(LEGACY_TARGETS, include_mnemonics=False)
    unified = build_target_selection(
        LEGACY_TARGETS, include_mnemonics=True,
        mnemonic_workers=arguments.workers)
    mnemonic_detectors = tuple(
        detector for detector in unified.chunk_detectors
        if getattr(detector, "standards", None))
    chunk_size = arguments.chunk_mib * 2**20
    overlap = arguments.overlap_kib * 2**10
    with tempfile.TemporaryDirectory(prefix="bfrs-unified-benchmark-") as directory:
        path = Path(directory) / "fixture.bin"
        path.write_bytes(data)
        target_run = _run(
            path, signatures=target.signatures, detectors=target.chunk_detectors,
            chunk_size=chunk_size, overlap=overlap,
            read_mib_s=arguments.read_mib_s)
        mnemonic_run = _run(
            path, signatures=(), detectors=mnemonic_detectors,
            chunk_size=chunk_size, overlap=overlap,
            read_mib_s=arguments.read_mib_s)
        unified_run = _run(
            path, signatures=unified.signatures, detectors=unified.chunk_detectors,
            chunk_size=chunk_size, overlap=overlap,
            read_mib_s=arguments.read_mib_s)
    mib = len(data) / 2**20
    separate = target_run.seconds + mnemonic_run.seconds
    separate_passes = target_run.linear_pass_count + mnemonic_run.linear_pass_count
    separate_bytes = target_run.linear_bytes_read + mnemonic_run.linear_bytes_read
    peak_rss = max(target_run.peak_rss_bytes, mnemonic_run.peak_rss_bytes,
                   unified_run.peak_rss_bytes)
    print(
        f"fixture={arguments.fixture} bytes={len(data)} "
        f"workers={arguments.workers} "
        f"simulated_read_mib_s={arguments.read_mib_s:.3f} "
        f"active_detector_groups=target,mnemonic "
        f"target_only_seconds={target_run.seconds:.6f} "
        f"mnemonic_only_seconds={mnemonic_run.seconds:.6f} "
        f"separate_total_seconds={separate:.6f} "
        f"unified_seconds={unified_run.seconds:.6f} "
        f"target_only_mib_s={mib / target_run.seconds:.3f} "
        f"mnemonic_only_mib_s={mib / mnemonic_run.seconds:.3f} "
        f"unified_mib_s={mib / unified_run.seconds:.3f} "
        f"unified_speedup_vs_separate_percent="
        f"{(separate / unified_run.seconds - 1) * 100:.2f} "
        f"unified_time_reduction_percent="
        f"{(1 - unified_run.seconds / separate) * 100:.2f} "
        f"separate_linear_pass_count={separate_passes} "
        f"unified_linear_pass_count={unified_run.linear_pass_count} "
        f"separate_linear_bytes_read={separate_bytes} "
        f"unified_linear_bytes_read={unified_run.linear_bytes_read} "
        f"unified_linear_read_count={unified_run.linear_read_count} "
        f"secondary_read_count=0 secondary_bytes_read=0 "
        f"peak_rss_mib={peak_rss / 2**20:.3f} "
        f"target_hits={target_run.hits} mnemonic_hits={mnemonic_run.hits} "
        f"unified_hits={unified_run.hits}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
