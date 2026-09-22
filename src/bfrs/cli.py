"""Command-line entry point for BFRS filesystem and wallet recovery."""

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Sequence

from bfrs.core.path_safety import paths_refer_to_same_file
from bfrs.core.source_types import SourceType, detect_source_type
from bfrs.core.worker_control import WorkerControlError
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.automatic_wallet_recovery import (
    recover_intact_wallet,
    recover_wallets,
    recovery_not_requested,
    validate_recovery_destination,
)
from bfrs.recovery.physical_berkeley_reconstructor import ExportRefused
from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSMFTIndexProgress
from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import resolve_worker_count
from bfrs.recovery.mnemonic.seed_scan_checkpoint import (
    CheckpointError,
    SeedScanCheckpoint,
)
from bfrs.recovery.unified_scan_checkpoint import (
    UnifiedCheckpointError,
    UnifiedScanCheckpoint,
    build_scanner_identity,
)
from bfrs.reporting.recovery_support import print_recovery_support_message
from bfrs.reporting.json_report import write_json_report
from bfrs.reporting.json_report import serialize_full_image_result
from bfrs.scanners.fast_scanner import ScanProgress
from bfrs.scanners.target_registry import (
    AVAILABLE_TARGETS,
    BITCOIN_CORE_SIGNATURES_V1,
    ELECTRUM_ONLY_SIGNATURES_V1,
    LEGACY_TARGETS,
    build_target_selection,
    parse_targets,
)
from bfrs.tools.revalidate_wallet_records import (
    revalidate_wallet_records,
    write_wallet_record_revalidation_report,
)
from bfrs.validators.candidate_policy import CandidatePolicy
from bfrs.version import APP_NAME, VERSION


DEFAULT_CHUNK_MIB = 64
DEFAULT_OVERLAP_KIB = 64
DEFAULT_CLUSTER_MIB = 2
DEFAULT_PADDING_MIB = 1
DEFAULT_MINIMUM_HITS = 1
DEFAULT_MINIMUM_DISTINCT_TYPES = 1


class _ProgressLine:
    """Render throttled aggregate scan progress on one stderr line."""

    def __init__(
        self,
        label: str,
        *,
        targets: frozenset[str] = frozenset(),
        rate_base: int = 0,
        workers: int | None = None,
        display_gib: bool = False,
    ) -> None:
        self._label = label
        self._targets = tuple(
            target for target in AVAILABLE_TARGETS if target in targets)
        self._rate_base = rate_base
        self._workers = workers
        self._display_gib = display_gib
        self._started = time.monotonic()
        self._last_rendered = 0.0
        self._rendered = False

    def __call__(self, update: ScanProgress) -> None:
        self.update(
            update.scanned_bytes,
            update.total_bytes,
            raw_hits=update.raw_hits,
            raw_by_target=update.raw_by_target,
            rejected_by_target=update.rejected_by_target,
            pending_validation_by_target=update.pending_validation_by_target,
            validated_occurrences_by_target=(
                update.validated_occurrences_by_target),
            validated_unique_by_target=update.validated_unique_by_target,
            anchors_total=update.anchors_total,
            stage=update.stage,
            complete=update.complete,
        )

    def update(
        self,
        processed: int,
        total: int,
        *,
        raw_hits: int | None = None,
        raw_by_target: dict[str, int] | None = None,
        rejected_by_target: dict[str, int] | None = None,
        pending_validation_by_target: dict[str, int] | None = None,
        validated_occurrences_by_target: dict[str, int] | None = None,
        validated_unique_by_target: dict[str, int] | None = None,
        anchors_total: int | None = None,
        stage: str | None = None,
        complete: bool | None = None,
    ) -> None:
        now = time.monotonic()
        is_complete = (total == 0 or processed >= total
                       if complete is None else complete)
        if not is_complete and now - self._last_rendered < 0.5:
            return
        self._last_rendered = now
        elapsed = max(now - self._started, 1e-9)
        rate = max(0, processed - self._rate_base) / 2**20 / elapsed
        percent = 100.0 if total == 0 else min(100.0, processed * 100.0 / total)
        if is_complete:
            eta = "00:00:00"
        elif processed == 0 or rate <= 0:
            eta = "calculating..."
        else:
            remaining = max(
                0.0,
                (total - processed) / 2**20 / rate,
            )
            hours, remainder = divmod(int(remaining), 3600)
            minutes, seconds = divmod(remainder, 60)
            eta = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        def target_counts(values: dict[str, int] | None) -> str:
            rendered = " ".join(
                f"{target}={values.get(target, 0)}"
                for target in self._targets
                if values and values.get(target, 0)
            )
            return rendered or "none"

        details = []
        if raw_hits is not None:
            details.append(f"raw_hits={raw_hits}")
        if anchors_total is not None:
            details.append(f"anchors={anchors_total}")
        if raw_by_target is not None:
            details.append(f"raw_by_target[{target_counts(raw_by_target)}]")
            details.append(
                f"rejected_by_target[{target_counts(rejected_by_target)}]")
            details.append(
                "pending_validation_by_target["
                f"{target_counts(pending_validation_by_target)}]")
            details.append(
                "validated_occurrences_by_target["
                f"{target_counts(validated_occurrences_by_target)}]")
            details.append(
                "validated_unique_by_target["
                f"{target_counts(validated_unique_by_target)}]")
        if self._workers is not None:
            details.append(f"workers={self._workers}")
        if stage is not None:
            details.append(f"phase={stage}")
        suffix = f"  {'  '.join(details)}" if details else ""
        byte_progress = (
            f"{processed / 2**30:.1f}/{total / 2**30:.1f} GiB"
            if self._display_gib else f"{processed}/{total} bytes"
        )
        print(
            f"\r{self._label} {percent:5.1f}%  {byte_progress}  "
            f"{rate:.1f} MiB/s  ETA {eta}{suffix}",
            end="",
            file=sys.stderr,
            flush=True,
        )
        self._rendered = True

    def finish(self) -> None:
        if self._rendered:
            print(file=sys.stderr)
            self._rendered = False


class _NTFSProgressLine:
    """Render the independent global NTFS metadata pre-pass."""

    def __init__(self) -> None:
        self._rendered = False

    def __call__(self, update: NTFSMFTIndexProgress) -> None:
        if update.total_records is None:
            progress = "records=" + str(update.records_processed)
        else:
            percent = (100.0 if update.total_records == 0 else
                       min(100.0, update.records_processed * 100.0
                           / update.total_records))
            progress = (
                f"{percent:5.1f}%  records={update.records_processed}/"
                f"{update.total_records}"
            )
        status = "  complete" if update.complete else ""
        print(
            f"\rNTFS index {progress}  phase={update.phase}{status}",
            end="\n" if update.complete else "",
            file=sys.stderr,
            flush=True,
        )
        self._rendered = not update.complete

    def finish(self) -> None:
        if self._rendered:
            print(file=sys.stderr)
            self._rendered = False


class _ElectrumProgressLine:
    """Render secret-free progress for Electrum hit postprocessing."""

    def __call__(self, completed: int, total: int, elapsed: float) -> None:
        percent = 100.0 if total == 0 else min(100.0, completed * 100.0 / total)
        if completed >= total:
            eta = "00:00:00"
        elif completed == 0 or elapsed <= 0:
            eta = "calculating..."
        else:
            remaining = max(0.0, elapsed * (total - completed) / completed)
            hours, remainder = divmod(int(remaining), 3600)
            minutes, seconds = divmod(remainder, 60)
            eta = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        print(
            f"\rElectrum recovery {completed}/{total}  {percent:5.1f}%  ETA {eta}",
            end="\n" if completed >= total else "",
            file=sys.stderr,
            flush=True,
        )


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.cli",
        description="BFRS filesystem and wallet recovery scan",
        epilog=(
            "Input is auto-detected as an image, regular file, or folder. "
            "Folder scans recurse through regular files without following "
            "symlinks or junctions; folder checkpoint/resume is not supported."
        ),
    )
    parser.add_argument("--input", required=True, type=Path, help="source image, file, or directory path")
    parser.add_argument("--output", required=True, type=Path, help="JSON report path")
    parser.add_argument(
        "--source-type", choices=("image", "file", "folder"),
        help="optional source override; normally detected automatically",
    )
    parser.add_argument(
        "--recover-wallets",
        action="store_true",
        help=("copy or reconstruct fully validated wallets in --recovery-dir; "
              "opt-in and may write private wallet material"),
    )
    parser.add_argument(
        "--recovery-dir",
        type=Path,
        help="private output root for --recover-wallets (must be outside Git)",
    )
    parser.add_argument(
        "--revalidate-wallet-records",
        type=Path,
        metavar="OLD_REPORT_JSON",
        help=("revalidate wallet_record offsets from an existing BFRS report "
              "without a full image scan"),
    )
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
    parser.add_argument(
        "--include-mnemonic",
        action="store_true",
        help=("include BIP39/Electrum mnemonic detection in the shared target "
              "scan and final report"),
    )
    parser.add_argument(
        "--include-bitcoin-context",
        action="store_true",
        help=("include textual Bitcoin Base58/Bech32 address and SEC public-key "
              "context detection in the shared target scan"),
    )
    parser.add_argument(
        "--skip-mnemonic",
        action="store_true",
        help=("skip raw BIP39/Electrum mnemonic detection while keeping all "
              "selected wallet, secret, and filesystem detectors"),
    )
    parser.add_argument("--workers", type=_integer, default=1,
                        help=("mnemonic worker processes; target scans parallelize "
                              "encoding phases; 0 selects up to 4 automatically"))
    parser.add_argument("--checkpoint", type=Path,
                        help="create a new scan checkpoint (must not exist)")
    parser.add_argument("--resume-checkpoint", type=Path,
                        help="load and continue a compatible scan checkpoint")
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
    if arguments.revalidate_wallet_records is not None:
        if any((
            arguments.targets,
            arguments.electrum_only,
            arguments.seed_scan_only,
            arguments.skip_mnemonic,
            arguments.checkpoint,
            arguments.resume_checkpoint,
            arguments.start != 0,
            arguments.end is not None,
            arguments.recover_wallets,
            arguments.recovery_dir is not None,
        )):
            parser.error(
                "--revalidate-wallet-records cannot be combined with scan modes, "
                "targets, checkpoints, --start, or --end"
            )
    if arguments.targets and (arguments.electrum_only or arguments.seed_scan_only):
        parser.error("--targets cannot be combined with legacy only-mode flags")
    if arguments.electrum_only and arguments.seed_scan_only:
        parser.error("--electrum-only and --seed-scan-only are mutually exclusive")
    if arguments.seed_scan_only and arguments.skip_mnemonic:
        parser.error("--skip-mnemonic cannot be combined with --seed-scan-only")
    if arguments.include_mnemonic and arguments.skip_mnemonic:
        parser.error("--include-mnemonic and --skip-mnemonic are mutually exclusive")
    if arguments.include_mnemonic and arguments.seed_scan_only:
        parser.error("--include-mnemonic is redundant with --seed-scan-only")
    if arguments.recover_wallets and arguments.recovery_dir is None:
        parser.error("--recover-wallets requires --recovery-dir")
    if arguments.recovery_dir is not None and not arguments.recover_wallets:
        parser.error("--recovery-dir requires --recover-wallets")
    if arguments.recover_wallets and arguments.seed_scan_only:
        parser.error("--recover-wallets cannot be combined with --seed-scan-only")
    if arguments.checkpoint and arguments.resume_checkpoint:
        parser.error("--checkpoint and --resume-checkpoint are mutually exclusive")
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
    try:
        resolve_worker_count(arguments.workers)
    except ValueError as error:
        parser.error(str(error))
    if arguments.minimum_hits < 1:
        parser.error("--minimum-hits must be at least 1")
    if arguments.minimum_distinct_types < 1:
        parser.error("--minimum-distinct-types must be at least 1")
    chunk_bytes = arguments.chunk_mib * 1024 * 1024
    if arguments.overlap_kib * 1024 >= chunk_bytes:
        parser.error("--overlap-kib must be smaller than --chunk-mib")


def _validate_path_collisions(
    parser: argparse.ArgumentParser, arguments,
) -> None:
    if paths_refer_to_same_file(arguments.output, arguments.input):
        parser.error("output path resolves to input path")
    checkpoint = arguments.checkpoint or arguments.resume_checkpoint
    if checkpoint is not None:
        if paths_refer_to_same_file(checkpoint, arguments.input):
            parser.error("checkpoint path resolves to input path")
        if paths_refer_to_same_file(checkpoint, arguments.output):
            parser.error("checkpoint path resolves to report output path")
    if (arguments.revalidate_wallet_records is not None and
            paths_refer_to_same_file(
                arguments.output, arguments.revalidate_wallet_records)):
        parser.error("output path resolves to source report path")
    if arguments.recovery_dir is not None:
        if paths_refer_to_same_file(arguments.recovery_dir, arguments.output):
            parser.error("recovery directory resolves to report output path")
        try:
            validate_recovery_destination(arguments.input, arguments.recovery_dir)
        except ExportRefused as error:
            parser.error(f"unsafe recovery directory: {error}")


def _selection(parser: argparse.ArgumentParser, arguments):
    try:
        targets = (parse_targets(arguments.targets) if arguments.targets else
                   (frozenset({"electrum"}) if arguments.electrum_only else
                    LEGACY_TARGETS))
    except ValueError as error:
        parser.error(str(error))
    return build_target_selection(
        targets,
        include_mnemonics=(
            (arguments.include_mnemonic or arguments.targets is not None)
            and not arguments.skip_mnemonic),
        include_bitcoin_context=arguments.include_bitcoin_context,
        mnemonic_workers=arguments.workers,
    )


def _configuration(arguments, selection=None) -> dict[str, object]:
    if selection is None:
        targets = (frozenset({"electrum"}) if arguments.electrum_only else
                   LEGACY_TARGETS)
        selection = build_target_selection(targets, include_mnemonics=False)
    mnemonic_standards = sorted({
        standard
        for detector in selection.chunk_detectors
        for standard in getattr(detector, "standards", ())
    })
    mnemonic_scan_requested = bool(mnemonic_standards)
    return {
        "chunk_mib": arguments.chunk_mib,
        "overlap_kib": arguments.overlap_kib,
        "cluster_mib": arguments.cluster_mib,
        "padding_mib": arguments.padding_mib,
        "minimum_hits": arguments.minimum_hits,
        "minimum_distinct_types": arguments.minimum_distinct_types,
        "electrum_only": arguments.electrum_only,
        "seed_scan_only": arguments.seed_scan_only,
        "include_mnemonic": mnemonic_scan_requested,
        "mnemonic_scan_requested": mnemonic_scan_requested,
        "mnemonic_standards_requested": mnemonic_standards,
        "skip_mnemonic": arguments.skip_mnemonic,
        "workers": arguments.workers,
        "targets": sorted(selection.targets),
        "signature_set": [signature.name for signature in selection.signatures],
        "source_type": detect_source_type(
            arguments.input, arguments.source_type
        ).value,
        "source_root": str(arguments.input.resolve(strict=False)),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    _validate_path_collisions(parser, arguments)
    try:
        source_type = detect_source_type(arguments.input, arguments.source_type)
    except ValueError as error:
        parser.error(str(error))
    if source_type is SourceType.FOLDER:
        if arguments.revalidate_wallet_records is not None:
            parser.error("wallet-record revalidation requires a regular file source")
        if arguments.start != 0 or arguments.end is not None:
            parser.error("--start/--end are not supported for FOLDER sources")
        if arguments.checkpoint or arguments.resume_checkpoint:
            parser.error(
                "FOLDER checkpoint/resume is deferred to P2.7.1; IMAGE resume is unchanged"
            )
        root = arguments.input.resolve(strict=False)
        output = arguments.output.resolve(strict=False)
        if root == output or root in output.parents:
            parser.error("folder report output must be outside the source root")
        from bfrs.scanners.folder_source_scanner import scan_folder_source
        return scan_folder_source(arguments, main)
    if arguments.revalidate_wallet_records is not None:
        try:
            old_report = json.loads(
                arguments.revalidate_wallet_records.read_text(
                    encoding="utf-8-sig"
                )
            )
            if not isinstance(old_report, dict):
                raise ValueError("report root must be an object")
            payload = revalidate_wallet_records(
                old_report,
                arguments.input,
                source_report=arguments.revalidate_wallet_records,
            )
        except (OSError, UnicodeError, ValueError) as error:
            print(f"wallet-record revalidation error: {error}", file=sys.stderr)
            return 3
        try:
            report_path = write_wallet_record_revalidation_report(
                payload, arguments.output
            )
        except OSError as error:
            print(f"report error: {error}", file=sys.stderr)
            return 4
        print(f"source: {payload['source_image']}")
        print(f"source report: {payload['source_report']}")
        print(f"wallet_record findings: {payload['findings_input_count']}")
        print(f"unique offsets: {payload['unique_offsets_count']}")
        print(f"duplicate offsets: {payload['duplicate_offset_count']}")
        print(f"valid key sides: {payload['valid_key_side_count']}")
        print(f"invalid key sides: {payload['invalid_key_side_count']}")
        print(f"source bytes read: {payload['source_bytes_read']}")
        print(f"report path: {report_path}")
        return 0

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
        range_end = file_size if arguments.end is None else arguments.end
        worker_count = resolve_worker_count(arguments.workers)
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
        seed_progress = _ProgressLine(
            "Seed scan RESUMED" if arguments.resume_checkpoint else "Seed scan",
            rate_base=resumed_bytes,
            workers=worker_count,
            display_gib=True,
        )

        try:
            result = MnemonicRecoveryPipeline(
                chunk_size=chunk_size,
                overlap=overlap,
            ).scan(arguments.input, start=arguments.start, end=arguments.end,
                   progress=seed_progress.update, workers=arguments.workers,
                   resume_results=(checkpoint.completed_results if checkpoint else None),
                   unit_complete=(checkpoint.record if checkpoint else None))
        except KeyboardInterrupt:
            if checkpoint is not None:
                checkpoint.save(force=True)
            seed_progress.finish()
            print("scan interrupted by user", file=sys.stderr)
            return 130
        except WorkerControlError as error:
            if checkpoint is not None:
                checkpoint.save(force=True)
            seed_progress.finish()
            print(f"worker error: {error}", file=sys.stderr)
            return 3
        except (OSError, ValueError) as error:
            print(f"input error: {error}", file=sys.stderr)
            return 3
        if checkpoint is not None:
            checkpoint.mark_complete()
        seed_progress.finish()
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
        print(f"Electrum 2+ valid: {summary.electrum_2_plus_valid}")
        print(f"Electrum V1 valid: {summary.electrum_v1_valid}")
        print(f"duplicate occurrences: {summary.duplicate_occurrences}")
        print(f"crypto-valid occurrences: {summary.crypto_valid_occurrences}")
        print("mnemonic independent candidates: "
              f"{summary.independent_candidate_occurrences}")
        print("mnemonic overlap-cluster occurrences: "
              f"{summary.overlap_cluster_occurrences}")
        print("mnemonic likely-wordlist occurrences: "
              f"{summary.likely_wordlist_occurrences}")
        print(f"report path: {arguments.output.resolve()}")
        print_recovery_support_message(payload)
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
    range_end = file_size if arguments.end is None else arguments.end
    unified_checkpoint = None
    scanner_identity = build_scanner_identity(
        targets=selection.targets,
        signatures=selection.signatures,
        mnemonic_enabled=bool(
            (arguments.include_mnemonic or arguments.targets is not None)
            and not arguments.skip_mnemonic),
        bitcoin_context_enabled=arguments.include_bitcoin_context,
    )
    try:
        if arguments.resume_checkpoint:
            unified_checkpoint = UnifiedScanCheckpoint.resume(
                arguments.resume_checkpoint, arguments.input,
                start=arguments.start, end=range_end,
                chunk_size=arguments.chunk_mib * 1024 * 1024,
                overlap=arguments.overlap_kib * 1024,
                scanner_identity=scanner_identity)
        elif arguments.checkpoint:
            unified_checkpoint = UnifiedScanCheckpoint.create(
                arguments.checkpoint, arguments.input,
                start=arguments.start, end=range_end,
                chunk_size=arguments.chunk_mib * 1024 * 1024,
                overlap=arguments.overlap_kib * 1024,
                scanner_identity=scanner_identity)
    except (OSError, UnifiedCheckpointError) as error:
        print(f"checkpoint error: {error}", file=sys.stderr)
        return 3
    ntfs_progress = _NTFSProgressLine()
    scan_progress = _ProgressLine(
        "Target scan",
        targets=selection.targets,
        rate_base=(unified_checkpoint.completed_bytes
                   if unified_checkpoint is not None else 0),
    )
    electrum_progress = _ElectrumProgressLine()
    try:
        result = coordinator.scan(
            arguments.input,
            start=arguments.start,
            end=arguments.end,
            electrum_only=arguments.electrum_only,
            intact_file_mode=(source_type is SourceType.FILE),
            targets=selection.targets,
            progress=scan_progress,
            ntfs_progress=ntfs_progress,
            electrum_progress=electrum_progress,
            resume_results=(unified_checkpoint.completed_results
                            if unified_checkpoint else None),
            unit_complete=(unified_checkpoint.record
                           if unified_checkpoint else None),
        )
    except KeyboardInterrupt:
        if unified_checkpoint is not None:
            unified_checkpoint.save(force=True)
        ntfs_progress.finish()
        scan_progress.finish()
        print("scan interrupted by user", file=sys.stderr)
        return 130
    except WorkerControlError as error:
        if unified_checkpoint is not None:
            unified_checkpoint.save(force=True)
        ntfs_progress.finish()
        scan_progress.finish()
        print(f"worker error: {error}", file=sys.stderr)
        return 3
    except OSError as error:
        if unified_checkpoint is not None:
            unified_checkpoint.close()
        ntfs_progress.finish()
        scan_progress.finish()
        print(f"input error: {error}", file=sys.stderr)
        return 3
    except BaseException:
        if unified_checkpoint is not None:
            unified_checkpoint.close()
        raise
    ntfs_progress.finish()
    scan_progress.finish()
    if unified_checkpoint is not None:
        unified_checkpoint.mark_complete()

    configuration = _configuration(arguments, selection)
    public_report = serialize_full_image_result(result, configuration)
    wallet_recovery = recovery_not_requested()
    if arguments.recover_wallets:
        try:
            if (source_type is SourceType.FILE
                    and public_report.get("intact_wallet", {}).get("detected")):
                wallet_recovery = recover_intact_wallet(
                    arguments.input, public_report, arguments.recovery_dir
                )
            else:
                wallet_recovery = recover_wallets(
                    arguments.input, public_report, arguments.recovery_dir)
        except ExportRefused as error:
            wallet_recovery = {
                "requested": True,
                "eligible_candidates": 0,
                "recovered_wallets": 0,
                "failed_wallets": 1,
                "outputs": [],
                "reason_code": str(error),
            }
    try:
        report_path = write_json_report(
            arguments.output,
            result,
            configuration,
            wallet_recovery,
        )
    except OSError as error:
        print(f"report error: {error}", file=sys.stderr)
        return 4

    print(f"source: {result.source}")
    print(f"range: {result.start_offset}..{result.end_offset}")
    public_report = serialize_full_image_result(result, configuration, wallet_recovery)
    public_summary = public_report["finding_summary"]
    print(f"Raw discovery: {result.raw_hit_count} (raw hits: diagnostic)")
    print(f"Accepted candidates: {public_summary['accepted_candidates']}")
    print(f"Review candidates: {public_summary['review_candidates']}")
    print(f"Rejected: {public_summary['rejected']}")
    print(f"Structurally complete: {public_summary['structurally_complete']} artifacts")
    print(f"Crypto-valid occurrences: {public_summary['crypto_valid_occurrences']}")
    print(f"Unique crypto-valid secrets: {public_summary['crypto_valid_unique_secrets']} identified fingerprints")
    print(f"Crypto-valid secrets without fingerprint: {public_summary['crypto_valid_secrets_without_fingerprint']}")
    print("Summary scope: target findings; overlapping recovery views below are not additive")
    print("Structurally complete reconstructed wallets: "
          f"{public_report['recovery_state_summaries']['reconstructed_wallet_results']['structurally_complete']}")
    print(f"hotspots: {result.hotspot_count}")
    print(f"accepted hotspots: {result.accepted_hotspot_count}")
    print(f"direct results: {len(result.direct_results)}")
    print(f"reconstructed results: {len(result.reconstructed_wallet_results)}")
    print(f"structural results: {result.structural_wallet_count}")
    print(f"fragment results: {result.fragment_wallet_count}")
    coverage = result.evidence.get("mnemonic_coverage", {})
    io_metrics = result.evidence.get("io_metrics", {})
    print(f"mnemonic coverage: {'performed' if coverage.get('performed') else 'skipped'}")
    print(f"linear passes: {io_metrics.get('linear_pass_count', 0)}")
    print(f"linear bytes read: {io_metrics.get('linear_bytes_read', 0)}")
    print(f"secondary reads: {io_metrics.get('secondary_read_count', 0)}")
    print(f"secondary bytes read: {io_metrics.get('secondary_bytes_read', 0)}")
    if arguments.electrum_only:
        electrum = result.electrum_raw_recovery
        print(f"electrum candidates: {electrum.candidates_total}")
        print(f"electrum complete: {electrum.complete_candidates}")
        print(f"electrum active duplicates: {electrum.known_active_duplicates}")
        print(f"report path: {report_path}")
        print_recovery_support_message(public_report)
        return 0
    legacy = public_report["legacy_wallet_recovery"]
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
    if arguments.recover_wallets:
        print("Bitcoin Core wallet recovery")
        print("----------------------------")
        print(f"Eligible candidates:       {wallet_recovery['eligible_candidates']}")
        print(f"Recovered wallets:         {wallet_recovery['recovered_wallets']}")
        print(f"Failed reconstructions:    {wallet_recovery['failed_wallets']}")
        for recovered in wallet_recovery["outputs"]:
            if recovered["status"] == "RECOVERED":
                print("Recovered:")
                print((arguments.recovery_dir /
                       Path(recovered["relative_recovery_path"])).resolve())
    print_recovery_support_message(public_report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
