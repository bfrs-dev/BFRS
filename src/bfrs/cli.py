"""Command-line entry point for the Bitcoin Core / Berkeley recovery scan."""

import argparse
from pathlib import Path
import sys
from typing import Sequence

from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.reporting.json_report import write_json_report
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
        "berkeley_metadata_little_endian",
        BTREE_MAGIC.to_bytes(4, "little"),
        "berkeley_metadata",
    ),
    Signature(
        "berkeley_metadata_big_endian",
        BTREE_MAGIC.to_bytes(4, "big"),
        "berkeley_metadata",
    ),
    Signature("bitcoin_key", b"\x03key", "bitcoin_record"),
    Signature("bitcoin_wkey", b"\x04wkey", "bitcoin_record"),
    Signature("bitcoin_defaultkey", b"\x0adefaultkey", "bitcoin_record"),
    Signature("bitcoin_ckey", b"\x04ckey", "bitcoin_record"),
    Signature("bitcoin_mkey", b"\x04mkey", "bitcoin_record"),
    Signature("bitcoin_keymeta", b"\x07keymeta", "bitcoin_record"),
)


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.cli",
        description="BFRS Bitcoin Core / Berkeley recovery scan",
    )
    parser.add_argument("--input", required=True, type=Path, help="source image path")
    parser.add_argument("--output", required=True, type=Path, help="JSON report path")
    parser.add_argument("--start", type=_integer, default=0, help="inclusive byte offset")
    parser.add_argument("--end", type=_integer, help="exclusive byte offset")
    parser.add_argument("--chunk-mib", type=_integer, default=DEFAULT_CHUNK_MIB)
    parser.add_argument("--overlap-kib", type=_integer, default=DEFAULT_OVERLAP_KIB)
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
    return {
        "chunk_mib": arguments.chunk_mib,
        "overlap_kib": arguments.overlap_kib,
        "cluster_mib": arguments.cluster_mib,
        "padding_mib": arguments.padding_mib,
        "minimum_hits": arguments.minimum_hits,
        "minimum_distinct_types": arguments.minimum_distinct_types,
        "signature_set": [signature.name for signature in BITCOIN_CORE_SIGNATURES_V1],
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
    coordinator = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
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
    print(f"report path: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
