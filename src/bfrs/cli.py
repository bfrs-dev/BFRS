"""Command-line entry point for BFRS filesystem and wallet recovery."""

import argparse
from pathlib import Path
import sys
from typing import Sequence

from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.metadata_less_fragments import FRAMED_BITCOIN_RECORD_PATTERNS
from bfrs.recovery.orphan_private_key_der import (
    HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
    HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
)
from bfrs.recovery.ntfs_stale_file import (
    NTFS_FILE_RECORD_PATTERN,
    NTFS_FILE_RECORD_SIGNATURE,
)
from bfrs.recovery.ntfs_stale_indx import (
    NTFS_INDX_RECORD_PATTERN,
    NTFS_INDX_RECORD_SIGNATURE,
)
from bfrs.recovery.ntfs_detached_volume import (
    NTFS_BOOT_SECTOR_PATTERN,
    NTFS_BOOT_SECTOR_SIGNATURE,
)
from bfrs.recovery.electrum_raw_recovery import ELECTRUM_SIGNATURE_PATTERNS
from bfrs.reporting.json_report import write_json_report
from bfrs.reporting.json_report import serialize_full_image_result
from bfrs.scanners.fast_scanner import Signature
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.candidate_policy import CandidatePolicy
from bfrs.version import APP_NAME, VERSION


DEFAULT_CHUNK_MIB = 64
DEFAULT_OVERLAP_KIB = 64
DEFAULT_CLUSTER_MIB = 2
DEFAULT_PADDING_MIB = 1
DEFAULT_MINIMUM_HITS = 1
DEFAULT_MINIMUM_DISTINCT_TYPES = 1


BITCOIN_CORE_SIGNATURES_V1 = (
    Signature(
        NTFS_BOOT_SECTOR_SIGNATURE,
        NTFS_BOOT_SECTOR_PATTERN,
        "ntfs_boot_sector",
    ),
    Signature(
        NTFS_FILE_RECORD_SIGNATURE,
        NTFS_FILE_RECORD_PATTERN,
        "ntfs_file_record",
    ),
    Signature(
        NTFS_INDX_RECORD_SIGNATURE,
        NTFS_INDX_RECORD_PATTERN,
        "ntfs_indx_record",
    ),
    Signature(
        "berkeley_metadata_little_endian",
        BTREE_MAGIC.to_bytes(4, "little"),
        "berkeley_metadata",
    ),
    Signature(
        "berkeley_metadata_big_endian",
        BTREE_MAGIC.to_bytes(4, "big"),
        "berkeley_metadata",
    ),
    Signature(
        HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
        HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
        "historical_private_key_der",
    ),
    *(
        Signature(name, pattern, "bitcoin_record")
        for name, pattern in FRAMED_BITCOIN_RECORD_PATTERNS
    ),
    *(
        Signature(name, pattern, "electrum_raw_anchor")
        for name, pattern in ELECTRUM_SIGNATURE_PATTERNS
    ),
)

ELECTRUM_ONLY_SIGNATURES_V1 = (
    Signature(
        NTFS_BOOT_SECTOR_SIGNATURE,
        NTFS_BOOT_SECTOR_PATTERN,
        "ntfs_boot_sector",
    ),
    *(
        Signature(name, pattern, "electrum_raw_anchor")
        for name, pattern in ELECTRUM_SIGNATURE_PATTERNS
    ),
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
    )
    parser.add_argument("--input", required=True, type=Path, help="source image path")
    parser.add_argument("--output", required=True, type=Path, help="JSON report path")
    parser.add_argument("--start", type=_integer, default=0, help="inclusive byte offset")
    parser.add_argument("--end", type=_integer, help="exclusive byte offset")
    parser.add_argument("--chunk-mib", type=_integer, default=DEFAULT_CHUNK_MIB)
    parser.add_argument("--overlap-kib", type=_integer, default=DEFAULT_OVERLAP_KIB)
    parser.add_argument(
        "--electrum-only",
        action="store_true",
        help="run only Electrum raw recovery and required NTFS correlation",
    )
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
    if arguments.minimum_hits < 1:
        parser.error("--minimum-hits must be at least 1")
    if arguments.minimum_distinct_types < 1:
        parser.error("--minimum-distinct-types must be at least 1")
    chunk_bytes = arguments.chunk_mib * 1024 * 1024
    if arguments.overlap_kib * 1024 >= chunk_bytes:
        parser.error("--overlap-kib must be smaller than --chunk-mib")


def _configuration(arguments) -> dict[str, object]:
    signatures = (
        ELECTRUM_ONLY_SIGNATURES_V1
        if arguments.electrum_only else BITCOIN_CORE_SIGNATURES_V1
    )
    return {
        "chunk_mib": arguments.chunk_mib,
        "overlap_kib": arguments.overlap_kib,
        "cluster_mib": arguments.cluster_mib,
        "padding_mib": arguments.padding_mib,
        "minimum_hits": arguments.minimum_hits,
        "minimum_distinct_types": arguments.minimum_distinct_types,
        "electrum_only": arguments.electrum_only,
        "signature_set": [signature.name for signature in signatures],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    try:
        file_size = arguments.input.stat().st_size
    except OSError as error:
        print(f"input error: {error}", file=sys.stderr)
        return 3
    if arguments.end is not None and arguments.end > file_size:
        parser.error("--end must not exceed input size")
    if arguments.start > file_size:
        parser.error("--start must not exceed input size")

    policy = CandidatePolicy(
        min_hits=arguments.minimum_hits,
        min_distinct_types=arguments.minimum_distinct_types,
    )
    signatures = (
        ELECTRUM_ONLY_SIGNATURES_V1
        if arguments.electrum_only else BITCOIN_CORE_SIGNATURES_V1
    )
    coordinator = FullImageRecoveryCoordinator(
        signatures,
        policy,
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
        )
    except OSError as error:
        print(f"input error: {error}", file=sys.stderr)
        return 3

    try:
        report_path = write_json_report(
            arguments.output,
            result,
            _configuration(arguments),
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
    legacy = serialize_full_image_result(result, _configuration(arguments))[
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
