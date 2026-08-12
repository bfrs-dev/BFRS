"""Explicit offline export of strictly validated legacy plaintext wallet keys."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
from typing import Sequence

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_database_pipeline import BerkeleyDatabaseRecoveryPipeline
from bfrs.recovery.berkeley_records import BerkeleyLeafRecordExtractor
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import BTREE_LEAF
from bfrs.validators.berkeley_page_locator import BerkeleyPageLocator
from bfrs.validators.bitcoin_plain_key import (
    HistoricalPlainKeyValidator,
    _extract_validated_public_key,
    _parse_ec_private_key,
)
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordTypeDecoder,
    decode_compact_size,
)


CSV_HEADER = (
    "index", "private_key_hex", "wif", "pubkey_encoding", "bitcoin_address"
)
MANIFEST_FILENAME = "private_keys_manifest.json"


class _PrivateRow:
    """Secret-bearing row with a deliberately non-secret repr."""

    __slots__ = ("private_bytes", "public_key", "compressed")

    def __init__(self, private_bytes: bytes, public_key: bytes) -> None:
        self.private_bytes = private_bytes
        self.public_key = public_key
        self.compressed = len(public_key) == 33

    def __repr__(self) -> str:
        return "_PrivateRow(<redacted>)"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.tools.export_legacy_plaintext_keys",
        description="Offline export of strict structural legacy plaintext keys",
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-private-key-export", action="store_true")
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest().upper()


def _read_wallet(path: Path) -> bytes:
    with path.open("rb") as source:
        return source.read()


def _structural_rows(path: Path) -> tuple[int, tuple[_PrivateRow, ...]]:
    data = _read_wallet(path)
    context = ValidationContext(str(path.resolve()), 0, data)
    pipeline = BerkeleyDatabaseRecoveryPipeline()
    metadata = pipeline._metadata_results(context)
    anchors = tuple(
        sorted(
            {
                pipeline._anchor(result)
                for result in metadata
                if result.status is ValidationStatus.STRUCTURAL
            },
            key=pipeline._anchor_sort_key,
        )
    )
    validator = HistoricalPlainKeyValidator()
    decoder = BitcoinRecordTypeDecoder()
    structural_records = 0
    unique: dict[bytes, _PrivateRow] = {}
    seen_pairs: set[tuple[int, int]] = set()
    for anchor in anchors:
        for page_result in BerkeleyPageLocator(anchor).locate(context):
            if (
                page_result.status is not ValidationStatus.STRUCTURAL
                or page_result.evidence.get("page_type") != BTREE_LEAF
            ):
                continue
            page_number = (
                page_result.start_offset - anchor.database_base_offset
            ) // anchor.page_size
            page_context = pipeline._page_context(
                context, page_result, anchor.page_size
            )
            extraction = BerkeleyLeafRecordExtractor(
                anchor.page_size,
                anchor.byte_order,
                expected_page_number=page_number,
            ).extract(page_context)
            if extraction.page_status is not ValidationStatus.STRUCTURAL:
                continue
            for pair in extraction.pairs:
                identity = (pair.key.absolute_offset, pair.value.absolute_offset)
                if identity in seen_pairs:
                    continue
                seen_pairs.add(identity)
                validation = validator.validate(pair)
                if not validation.valid:
                    continue
                decoded = decoder.decode(pair.key.payload)
                length = decode_compact_size(pair.value.payload)
                if decoded is None or decoded.name != "key" or length is None:
                    raise RuntimeError("validated plaintext key lost strict framing")
                public_key = _extract_validated_public_key(decoded.remaining_key)
                der_start = length.encoded_length
                der_end = der_start + length.value
                parsed = _parse_ec_private_key(pair.value.payload[der_start:der_end])
                structural_records += 1
                unique.setdefault(
                    parsed.private_bytes,
                    _PrivateRow(parsed.private_bytes, public_key),
                )
    return structural_records, tuple(unique.values())


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58check(payload: bytes) -> str:
    value = int.from_bytes(payload + _hash256(payload)[:4], "big")
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = alphabet[remainder] + encoded
    leading_zeroes = len(payload) - len(payload.lstrip(b"\x00"))
    return "1" * leading_zeroes + (encoded or "1")


def _wif(row: _PrivateRow) -> str:
    suffix = b"\x01" if row.compressed else b""
    return _base58check(b"\x80" + row.private_bytes + suffix)


def _address(row: _PrivateRow) -> str:
    sha = hashlib.sha256(row.public_key).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    return _base58check(b"\x00" + ripe)


def _write_outputs(
    output: Path,
    source: Path,
    source_size: int,
    source_sha256: str,
    structural_count: int,
    rows: tuple[_PrivateRow, ...],
) -> tuple[Path, str, Path]:
    manifest_path = output.with_name(MANIFEST_FILENAME)
    if output.exists() or manifest_path.exists():
        raise FileExistsError("output or manifest already exists")
    if not output.parent.is_dir():
        raise FileNotFoundError("output directory does not exist")
    with output.open("x", encoding="utf-8", newline="") as destination:
        writer = csv.writer(destination, lineterminator="\n")
        writer.writerow(CSV_HEADER)
        for index, row in enumerate(rows, start=1):
            writer.writerow((
                index,
                row.private_bytes.hex(),
                _wif(row),
                "compressed" if row.compressed else "uncompressed",
                _address(row),
            ))
    csv_sha256 = _sha256(output)
    compressed = sum(row.compressed for row in rows)
    manifest = {
        "source_wallet": str(source.resolve()),
        "source_wallet_size": source_size,
        "source_wallet_sha256": source_sha256,
        "structural_key_record_count": structural_count,
        "unique_private_key_count": len(rows),
        "duplicate_record_count": structural_count - len(rows),
        "compressed_count": compressed,
        "uncompressed_count": len(rows) - compressed,
        "csv_filename": output.name,
        "csv_sha256": csv_sha256,
    }
    with manifest_path.open("x", encoding="utf-8", newline="\n") as destination:
        json.dump(manifest, destination, indent=2, sort_keys=True)
        destination.write("\n")
    return output.resolve(), csv_sha256, manifest_path.resolve()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if not arguments.allow_private_key_export:
        print("refusing private-key export: --allow-private-key-export is required", file=sys.stderr)
        return 2
    source = arguments.input.resolve()
    output = arguments.output.resolve()
    try:
        source_size = source.stat().st_size
        source_sha256 = _sha256(source)
        structural_count, rows = _structural_rows(source)
        if not rows:
            print("refusing private-key export: no strict structural plaintext keys", file=sys.stderr)
            return 3
        output_path, csv_sha256, manifest_path = _write_outputs(
            output, source, source_size, source_sha256, structural_count, rows
        )
        source_sha256_after = _sha256(source)
        if source_sha256_after != source_sha256:
            print("source wallet changed during export", file=sys.stderr)
            return 4
    except (OSError, ValueError, RuntimeError) as error:
        print(f"export error: {error}", file=sys.stderr)
        return 3
    compressed = sum(row.compressed for row in rows)
    print(f"input path: {source}")
    print(f"input SHA-256: {source_sha256}")
    print(f"wallet size: {source_size}")
    print(f"structural records: {structural_count}")
    print(f"unique key count: {len(rows)}")
    print(f"duplicate count: {structural_count - len(rows)}")
    print(f"compressed count: {compressed}")
    print(f"uncompressed count: {len(rows) - compressed}")
    print(f"output path: {output_path}")
    print(f"output SHA-256: {csv_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
