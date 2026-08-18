"""Deterministic, secret-free benchmark for the raw mnemonic scanner."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import tempfile
import threading
import time
import tracemalloc

from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner

try:
    import psutil
except ImportError:  # pragma: no cover - optional benchmark instrumentation
    psutil = None


def synthetic_phrase() -> str:
    validator = BIP39Validator()
    entropy = bytes(range(16))
    bits = "".join(f"{byte:08b}" for byte in entropy)
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[:4]
    words = sorted(validator.indices["english"],
                   key=validator.indices["english"].get)
    return " ".join(words[int(bits[index:index + 11], 2)]
                    for index in range(0, len(bits), 11))


def synthetic_fixture(size: int) -> bytes:
    prose = (b"deterministic scanner benchmark prose 0123456789; "
             b"tokens outside mnemonic dictionaries.\n")
    data = bytearray((prose * (size // len(prose) + 1))[:size])
    phrase = synthetic_phrase()
    bad = phrase.rsplit(" ", 1)[0] + " abandon"
    controls = [(":" + phrase + ":").encode(), (":" + bad + ":").encode(),
                (":" + phrase + ":").encode("utf-16-le"),
                (":" + phrase + ":").encode("utf-16-be")]
    for position, control in zip((size // 8, size // 3, size // 2, 3 * size // 4),
                                 controls, strict=True):
        if control.startswith((b":\x00", b"\x00:")):
            position -= position % 2
        data[position:position + len(control)] = control
    return bytes(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mib", type=int, default=8)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--work-mib", type=int, default=1)
    parser.add_argument("--memory", action="store_true",
                        help="enable tracemalloc (substantially distorts wall time)")
    arguments = parser.parse_args(argv)
    data = synthetic_fixture(arguments.mib * 1024 * 1024)
    scanner = RawMnemonicScanner(chunk_size=arguments.work_mib * 2**20,
                                 overlap=64 * 2**10)
    if arguments.memory:
        tracemalloc.start()
    stop_sampling = threading.Event()
    metrics = {"peak_rss": 0, "cpu_seconds": 0.0}

    def sample_process_tree() -> None:
        if psutil is None:
            return
        parent = psutil.Process()
        baseline_cpu = 0.0
        while not stop_sampling.wait(0.05):
            processes = [parent, *parent.children(recursive=True)]
            rss = cpu = 0.0
            for process in processes:
                try:
                    rss += process.memory_info().rss
                    times = process.cpu_times()
                    cpu += times.user + times.system
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            if baseline_cpu == 0.0:
                baseline_cpu = cpu
            metrics["peak_rss"] = max(metrics["peak_rss"], int(rss))
            metrics["cpu_seconds"] = max(metrics["cpu_seconds"], cpu - baseline_cpu)

    sampler = threading.Thread(target=sample_process_tree, daemon=True)
    sampler.start()
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="bfrs-seed-benchmark-") as directory:
        source = Path(directory) / "synthetic.bin"
        source.write_bytes(data)
        result = scanner.scan_path(source, workers=arguments.workers)
    elapsed = time.perf_counter() - started
    stop_sampling.set()
    sampler.join()
    peak = tracemalloc.get_traced_memory()[1] if arguments.memory else 0
    cpu_percent = metrics["cpu_seconds"] / elapsed * 100.0
    print(f"bytes={len(data)} wall_seconds={elapsed:.6f} "
          f"mib_per_second={len(data) / elapsed / 2**20:.3f} "
          f"cpu_percent={cpu_percent:.1f} peak_rss_mib={metrics['peak_rss'] / 2**20:.3f} "
          f"tracemalloc_peak_mib={peak / 2**20:.3f} workers={arguments.workers} "
          f"occurrences={len(result.occurrences)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
