"""Command-line entry point for BFRS filesystem and wallet recovery."""

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Sequence

from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import resolve_worker_count
from bfrs.recovery.mnemonic.seed_scan_checkpoint import (
    CheckpointError,
    SeedScanCheckpoint,
)
from bfrs.reporting.json_report import write_json_report
from bfrs.reporting.json_report import serialize_full_image_result
from bfrs.scanners.target_registry import (
    AVAILABLE_TARGETS,
    BITCOIN_CORE_SIGNATURES_V1,
    ELECTRUM_ONLY_SIGNATURES_V1,
    LEGACY_TARGETS,
    build_target_selection,
    parse_targets,
)
from bfrs.validators.candidate_policy import CandidatePolicy
from bfrs.version import APP_NAME, VERSION


DEFAULT_CHUNK_MIB = 64
DEFAULT_OVERLAP_KIB = 64
DEFAULT_CLUSTER_MIB = 2
DEFAULT_PADDING_MIB = 1
DEFAULT_MINIMUM_HITS = 1
DEFAULT_MINIMUM_DISTINCT_TYPES = 1


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.cli",
        description="BFRS filesystem and wallet recovery scan",
    )
    parser.add_argument("--input", required=True, type=Path, help="source image path")
    parser.add_argument("--output", required=True, type=Path, help="JSON report path")
    parser.add_argument("--start", type=_integer, default=0, help="inclusive byte offset")
    parser.add_argument("--end", type=_integer, help="exclusive byte offset")
    parser.add_argument("--chunk-mib", type=_integer, default=DEFAULT_CHUNK_MIB)
    parser.add_argument("--overlap-kib", type=_integer, default=DEFAULT_OVERLAP_KIB)
    parser.add_argument(
        "--targets",
        help=("comma-separated targets: " + ",".join(AVAILABLE_TARGETS) +
              "; use 'all' for every target"),
    )
    parser.add_argument(
        "--electrum-only",
        action="store_true",
        help="run only Electrum raw recovery and required NTFS correlation",
    )
    parser.add_argument(
        "--seed-scan-only", action="store_true",
        help="run only BIP39/Electrum mnemonic raw and document recovery",
    )
    parser.add_argument("--workers", type=_integer, default=1,
                        help="seed scan worker processes; 0 selects up to 4 automatically")
    parser.add_argument("--checkpoint", type=Path,
                        help="create a new seed-scan checkpoint (must not exist)")
    parser.add_argument("--resume-checkpoint", type=Path,
                        help="load and continue a compatible seed-scan checkpoint")
    parser.add_argument("--cluster-mib", type=_integer, default=DEFAULT_CLUSTER_MIB)
    parser.add_argument("--padding-mib", type=_integer, default=DEFAULT_PADDING_MIB)
    parser.add_argument(
        "--minimum-hits", type=_integer, default=DEFAULT_MINIMUM_HITS
    )
    parser.add_argument(
        "--minimum-distinct-types",
        type=_integer,
        default=DEFAULT_MINIMUM_DISTINCT_TYPES,
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return parser


def _validate_arguments(parser: argparse.ArgumentParser, arguments) -> None:
    if arguments.targets and (arguments.electrum_only or arguments.seed_scan_only):
        parser.error("--targets cannot be combined with legacy only-mode flags")
    if arguments.electrum_only and arguments.seed_scan_only:
        parser.error("--electrum-only and --seed-scan-only are mutually exclusive")
    if arguments.checkpoint and arguments.resume_checkpoint:
        parser.error("--checkpoint and --resume-checkpoint are mutually exclusive")
    if (arguments.checkpoint or arguments.resume_checkpoint) and not arguments.seed_scan_only:
        parser.error("checkpoint options require --seed-scan-only")
    if arguments.start < 0:
        parser.error("--start must be nonnegative")
    if arguments.end is not None and arguments.end <= arguments.start:
        parser.error("--end must be greater than --start")
    for name in ("chunk_mib", "cluster_mib", "padding_mib"):
        minimum = 0 if name == "padding_mib" else 1
        if getattr(arguments, name) < minimum:
            parser.error(f"--{name.replace('_', '-')} must be at least {minimum}")
    if arguments.overlap_kib < 0:
        parser.error("--overlap-kib must be nonnegative")
    if arguments.workers < 0:
        parser.error("--workers must be nonnegative")
    if arguments.minimum_hits < 1:
        parser.error("--minimum-hits must be at least 1")
    if arguments.minimum_distinct_types < 1:
        parser.error("--minimum-distinct-types must be at least 1")
    chunk_bytes = arguments.chunk_mib * 1024 * 1024
    if arguments.overlap_kib * 1024 >= chunk_bytes:
        parser.error("--overlap-kib must be smaller than --chunk-mib")


def _selection(parser: argparse.ArgumentParser, arguments):
    try:
        targets = (parse_targets(arguments.targets) if arguments.targets else
                   (frozenset({"electrum"}) if arguments.electrum_only else
                    LEGACY_TARGETS))
    except ValueError as error:
        parser.error(str(error))
    return build_target_selection(
        targets, include_mnemonics=arguments.targets is not None)


def _configuration(arguments, selection=None) -> dict[str, object]:
    if selection is None:
        targets = (frozenset({"electrum"}) if arguments.electrum_only else
                   LEGACY_TARGETS)
        selection = build_target_selection(targets, include_mnemonics=False)
    return {
        "chunk_mib": arguments.chunk_mib,
        "overlap_kib": arguments.overlap_kib,
        "cluster_mib": arguments.cluster_mib,
        "padding_mib": arguments.padding_mib,
        "minimum_hits": arguments.minimum_hits,
        "minimum_distinct_types": arguments.minimum_distinct_types,
        "electrum_only": arguments.electrum_only,
        "seed_scan_only": arguments.seed_scan_only,
        "workers": arguments.workers,
        "targets": sorted(selection.targets),
        "signature_set": [signature.name for signature in selection.signatures],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    selection = _selection(parser, arguments)
    try:
        file_size = arguments.input.stat().st_size
    except OSError as error:
        print(f"input error: {error}", file=sys.stderr)
        return 3
    if arguments.end is not None and arguments.end > file_size:
        parser.error("--end must not exceed input size")
    if arguments.start > file_size:
        parser.error("--start must not exceed input size")

    if arguments.seed_scan_only:
        started = time.monotonic()
        last_progress = [0.0]
        range_end = file_size if arguments.end is None else arguments.end
        worker_count = resolve_worker_count(arguments.workers)
        progress_rendered = [False]
        chunk_size = arguments.chunk_mib * 1024 * 1024
        overlap = arguments.overlap_kib * 1024
        checkpoint = None
        try:
            if arguments.resume_checkpoint:
                checkpoint = SeedScanCheckpoint.resume(
                    arguments.resume_checkpoint, arguments.input,
                    start=arguments.start, end=range_end,
                    chunk_size=chunk_size, overlap=overlap)
            elif arguments.checkpoint:
                checkpoint = SeedScanCheckpoint.create(
                    arguments.checkpoint, arguments.input,
                    start=arguments.start, end=range_end,
                    chunk_size=chunk_size, overlap=overlap)
        except (OSError, CheckpointError) as error:
            print(f"checkpoint error: {error}", file=sys.stderr)
            return 3
        resumed_bytes = checkpoint.completed_bytes if arguments.resume_checkpoint else 0

        def report_progress(processed: int, total: int) -> None:
            now = time.monotonic()
            if processed < total and now - last_progress[0] < 0.5:
                return
            last_progress[0] = now
            elapsed = max(now - started, 1e-9)
            percent = 100.0 if not total else processed * 100.0 / total
            newly_processed = max(0, processed - resumed_bytes)
            rate = newly_processed / 2**20 / elapsed
            filled = min(20, int(percent / 5))
            if elapsed < 2.0 or processed == 0 or rate <= 0:
                eta = "calculating..."
            else:
                remaining = max(0.0, (total - processed) / 2**20 / rate)
                hours, remainder = divmod(int(remaining), 3600)
                minutes, seconds = divmod(remainder, 60)
                eta = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            label = "Seed scan RESUMED" if arguments.resume_checkpoint else "Seed scan"
            print(f"\r{label} [{'#' * filled}{'-' * (20 - filled)}] {percent:5.1f}%  "
                  f"{processed / 2**30:.1f}/{total / 2**30:.1f} GiB  {rate:.1f} MiB/s  "
                  f"ETA {eta}  workers={worker_count}", end="", file=sys.stderr,
                  flush=True)
            progress_rendered[0] = True

        try:
            result = MnemonicRecoveryPipeline(
                chunk_size=chunk_size,
                overlap=overlap,
            ).scan(arguments.input, start=arguments.start, end=arguments.end,
                   progress=report_progress, workers=arguments.workers,
                   resume_results=(checkpoint.completed_results if checkpoint else None),
                   unit_complete=(checkpoint.record if checkpoint else None))
        except KeyboardInterrupt:
            if checkpoint is not None:
                checkpoint.save(force=True)
            if progress_rendered[0]:
                print(file=sys.stderr)
            print("scan interrupted by user", file=sys.stderr)
            return 130
        except (OSError, ValueError) as error:
            print(f"input error: {error}", file=sys.stderr)
            return 3
        if checkpoint is not None:
            checkpoint.mark_complete()
        if progress_rendered[0]:
            print(file=sys.stderr)
        payload = {
            "application": {"name": APP_NAME, "version": VERSION},
            "source": result.source,
            "range": {"start": result.start_offset, "end": result.end_offset},
            "configuration": _configuration(arguments, selection),
            "mnemonic_recovery": result.recovery.safe_dict(),
        }
        try:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(json.dumps(payload, indent=2, sort_keys=True),
                                        encoding="utf-8")
        except OSError as error:
            print(f"report error: {error}", file=sys.stderr)
            return 4
        summary = result.recovery
        print(f"source: {result.source}")
        print(f"range: {result.start_offset}..{result.end_offset}")
        print(f"mnemonic candidates: {summary.candidates_total}")
        print(f"BIP39 valid: {summary.bip39_valid}")
        print(f"Electrum valid: {summary.electrum_valid}")
        print(f"duplicate occurrences: {summary.duplicate_occurrences}")
        print(f"report path: {arguments.output.resolve()}")
        return 0

    policy = CandidatePolicy(
        min_hits=arguments.minimum_hits,
        min_distinct_types=arguments.minimum_distinct_types,
    )
    coordinator = FullImageRecoveryCoordinator(
        selection.signatures,
        policy,
        chunk_detectors=selection.chunk_detectors,
        chunk_size=arguments.chunk_mib * 1024 * 1024,
        overlap=arguments.overlap_kib * 1024,
        cluster_gap=arguments.cluster_mib * 1024 * 1024,
        hotspot_padding=arguments.padding_mib * 1024 * 1024,
    )
    try:
        result = coordinator.scan(
            arguments.input,
            start=arguments.start,
            end=arguments.end,
            electrum_only=arguments.electrum_only,
            targets=selection.targets,
        )
    except OSError as error:
        print(f"input error: {error}", file=sys.stderr)
        return 3

    try:
        report_path = write_json_report(
            arguments.output,
            result,
            _configuration(arguments, selection),
        )
    except OSError as error:
        print(f"report error: {error}", file=sys.stderr)
        return 4

    print(f"source: {result.source}")
    print(f"range: {result.start_offset}..{result.end_offset}")
    print(f"raw hits: {result.raw_hit_count}")
    print(f"hotspots: {result.hotspot_count}")
    print(f"accepted hotspots: {result.accepted_hotspot_count}")
    print(f"direct results: {len(result.direct_results)}")
    print(f"reconstructed results: {len(result.reconstructed_wallet_results)}")
    print(f"structural results: {result.structural_wallet_count}")
    print(f"fragment results: {result.fragment_wallet_count}")
    if arguments.electrum_only:
        electrum = result.electrum_raw_recovery
        print(f"electrum candidates: {electrum.candidates_total}")
        print(f"electrum complete: {electrum.complete_candidates}")
        print(f"electrum active duplicates: {electrum.known_active_duplicates}")
        print(f"report path: {report_path}")
        return 0
    legacy = serialize_full_image_result(result, _configuration(arguments, selection))[
        "legacy_wallet_recovery"
    ]
    summary = legacy["summary"]
    print(f"legacy wallet candidates: {summary['wallet_candidates']}")
    print(
        "legacy priorities: "
        f"CRITICAL={summary['critical_candidates']} "
        f"HIGH={summary['high_candidates']} "
        f"MEDIUM={summary['medium_candidates']} "
        f"LOW={summary['low_candidates']}"
    )
    print(
        "crypto-valid key occurrences: "
        f"{summary['crypto_valid_key_occurrences']}"
    )
    print(
        "unique crypto-valid private keys: "
        f"{summary['unique_crypto_valid_private_keys']}"
    )
    print(f"report path: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
