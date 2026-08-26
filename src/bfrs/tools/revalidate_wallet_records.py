"""Targeted, secret-safe revalidation of Bitcoin raw wallet-record offsets."""

from collections import Counter, defaultdict
import json
import os
from pathlib import Path
from typing import Any, Mapping

from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
    MAX_RAW_KEY_SIDE_BYTES,
    RawBitcoinRecordKeySideValidator,
)
from bfrs.version import APP_NAME, VERSION


MODE = "wallet_record_revalidation"
VALID_KEY_SIDE = "VALID_KEY_SIDE"
REJECTED = "REJECTED"
OFFSET_OUT_OF_RANGE = "OFFSET_OUT_OF_RANGE"
SOURCE_READ_TRUNCATED = "SOURCE_READ_TRUNCATED"
RECORD_PREFIX_NOT_SUPPORTED = "RECORD_PREFIX_NOT_SUPPORTED"
UNRECOGNIZED_RECORD_TYPE = "unsupported/unrecognized"
_SUPPORTED_FAMILY = "bitcoin-core"


def _selected_offsets(report: Mapping[str, Any]) -> tuple[tuple[int, ...], int]:
    findings = report.get("target_findings", ())
    if not isinstance(findings, list):
        raise ValueError("target_findings must be a list")

    offsets: list[int] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if finding.get("artifact_kind") != "wallet_record":
            continue
        declared_families = tuple(
            value
            for value in (
                finding.get("target"),
                finding.get("wallet_family"),
            )
            if isinstance(value, str) and value
        )
        if declared_families and _SUPPORTED_FAMILY not in declared_families:
            continue
        offset = finding.get("physical_start")
        if not isinstance(offset, int) or isinstance(offset, bool):
            continue
        offsets.append(offset)

    return tuple(sorted(set(offsets))), len(offsets)


def _result(
    offset: int,
    *,
    record_type: str = UNRECOGNIZED_RECORD_TYPE,
    validation_status: str = REJECTED,
    reason_codes: tuple[str, ...],
    pubkey_length: int | None = None,
    safe_pubkey_fingerprint: str | None = None,
) -> dict[str, Any]:
    return {
        "physical_start": offset,
        "record_type": record_type,
        "validation_status": validation_status,
        "reason_codes": list(reason_codes),
        "pubkey_length": pubkey_length,
        "safe_pubkey_fingerprint": safe_pubkey_fingerprint,
        "structural_wallet_status": "NOT_EVALUATED",
    }


def revalidate_wallet_records(
    report: Mapping[str, Any],
    source_image: str | Path,
    *,
    source_report: str | Path | None = None,
) -> dict[str, Any]:
    """Revalidate deduplicated report offsets using bounded read-only reads."""
    if not isinstance(report, Mapping):
        raise ValueError("report root must be an object")

    offsets, findings_input_count = _selected_offsets(report)
    image_path = Path(source_image).resolve()
    report_path = None if source_report is None else str(Path(source_report).resolve())
    validator = RawBitcoinRecordKeySideValidator()
    results: list[dict[str, Any]] = []
    source_read_count = 0
    source_bytes_read = 0

    # One read-only source handle is shared by every targeted offset.
    with image_path.open("rb") as source:
        image_size = os.fstat(source.fileno()).st_size
        for offset in offsets:
            if offset < 0 or offset >= image_size:
                results.append(
                    _result(offset, reason_codes=(OFFSET_OUT_OF_RANGE,))
                )
                continue

            source.seek(offset, os.SEEK_SET)
            data = source.read(min(MAX_RAW_KEY_SIDE_BYTES, image_size - offset))
            source_read_count += 1
            source_bytes_read += len(data)
            validation = validator.validate_detected(data)
            if validation is None:
                results.append(
                    _result(
                        offset,
                        reason_codes=(RECORD_PREFIX_NOT_SUPPORTED,),
                    )
                )
                continue

            pubkey_length = validation.evidence.get("pubkey_length")
            if not isinstance(pubkey_length, int):
                pubkey_length = None
            if validation.valid:
                fingerprint = validation.evidence.get("safe_pubkey_fingerprint")
                if not isinstance(fingerprint, str):
                    raise RuntimeError("key-side validator omitted safe fingerprint")
                results.append(
                    _result(
                        offset,
                        record_type=validation.record_type,
                        validation_status=VALID_KEY_SIDE,
                        reason_codes=validation.reason_codes,
                        pubkey_length=pubkey_length,
                        safe_pubkey_fingerprint=fingerprint,
                    )
                )
                continue

            reasons = validation.reason_codes
            required = validation.evidence.get("required_record_key_bytes")
            if (
                reasons == (BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,)
                and isinstance(required, int)
                and required > len(data)
            ):
                reasons = (SOURCE_READ_TRUNCATED, *reasons)
            results.append(
                _result(
                    offset,
                    record_type=validation.record_type,
                    reason_codes=reasons,
                    pubkey_length=pubkey_length,
                )
            )

    record_type_counter = Counter(item["record_type"] for item in results)
    status_counter = Counter(item["validation_status"] for item in results)
    by_fingerprint: defaultdict[str, list[int]] = defaultdict(list)
    for item in results:
        fingerprint = item["safe_pubkey_fingerprint"]
        if isinstance(fingerprint, str):
            by_fingerprint[fingerprint].append(item["physical_start"])
    duplicate_groups = [
        {
            "safe_pubkey_fingerprint": fingerprint,
            "occurrence_count": len(grouped_offsets),
            "physical_starts": grouped_offsets,
        }
        for fingerprint, grouped_offsets in sorted(by_fingerprint.items())
        if len(grouped_offsets) > 1
    ]
    valid_count = status_counter[VALID_KEY_SIDE]

    return {
        "application": {"name": APP_NAME, "version": VERSION},
        "mode": MODE,
        "validation_scope": "BITCOIN_RECORD_KEY_SIDE_ONLY",
        "structural_wallet_confirmation": "NOT_EVALUATED",
        "source_image": str(image_path),
        "source_report": report_path,
        "source_image_size": image_size,
        "maximum_bytes_per_offset": MAX_RAW_KEY_SIDE_BYTES,
        "source_read_count": source_read_count,
        "source_bytes_read": source_bytes_read,
        "findings_input_count": findings_input_count,
        "unique_offsets_count": len(offsets),
        "duplicate_offset_count": findings_input_count - len(offsets),
        "record_type_counts": {
            name: record_type_counter[name]
            for name in ("key", "ckey", "wkey", UNRECOGNIZED_RECORD_TYPE)
        },
        "status_counts": {
            VALID_KEY_SIDE: status_counter[VALID_KEY_SIDE],
            REJECTED: status_counter[REJECTED],
        },
        "valid_key_side_count": valid_count,
        "invalid_key_side_count": len(results) - valid_count,
        "unique_valid_pubkey_fingerprint_count": len(by_fingerprint),
        "duplicate_valid_pubkey_groups": duplicate_groups,
        "results": results,
    }


def write_wallet_record_revalidation_report(
    payload: Mapping[str, Any],
    output: str | Path,
) -> Path:
    """Write deterministic UTF-8 JSON without exposing raw record bytes."""
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    path.write_text(serialized + "\n", encoding="utf-8", newline="\n")
    return path
