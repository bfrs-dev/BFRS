import json
from pathlib import Path

import pytest

import bfrs.cli as cli_module
from bfrs.cli import main
from bfrs.tools.revalidate_wallet_records import (
    OFFSET_OUT_OF_RANGE,
    RECORD_PREFIX_NOT_SUPPORTED,
    SOURCE_READ_TRUNCATED,
    VALID_KEY_SIDE,
    revalidate_wallet_records,
    write_wallet_record_revalidation_report,
)
from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
    BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,
    MAX_RAW_KEY_SIDE_BYTES,
)
from tests.test_raw_bitcoin_record_key_side import (
    ADATA_FALSE_POSITIVE_KEY_SIDES,
    COMPRESSED_PUBLIC_KEY,
    UNCOMPRESSED_PUBLIC_KEY,
    framed,
    public_key_vector,
)


def finding(offset: int, *, include_family: bool = True) -> dict[str, object]:
    result: dict[str, object] = {
        "artifact_kind": "wallet_record",
        "physical_start": offset,
    }
    if include_family:
        result["target"] = "bitcoin-core"
        result["wallet_family"] = "bitcoin-core"
    return result


def report_for(*offsets: int, include_family: bool = True) -> dict[str, object]:
    return {
        "target_findings": [
            finding(offset, include_family=include_family) for offset in offsets
        ]
    }


def placed(parts: dict[int, bytes]) -> bytes:
    result = bytearray(max(offset + len(value) for offset, value in parts.items()))
    for offset, value in parts.items():
        result[offset : offset + len(value)] = value
    return bytes(result)


def test_batch_revalidates_valid_key_invalid_length_and_valid_ckey(tmp_path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(
        placed(
            {
                0: framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)),
                100: framed("key", b"\x07" + b"x" * 7),
                200: framed("ckey", public_key_vector(COMPRESSED_PUBLIC_KEY)),
            }
        )
    )

    payload = revalidate_wallet_records(
        report_for(0, 100, 200), source, source_report=tmp_path / "old.json"
    )

    assert payload["valid_key_side_count"] == 2
    assert payload["invalid_key_side_count"] == 1
    assert payload["status_counts"] == {"VALID_KEY_SIDE": 2, "REJECTED": 1}
    assert payload["record_type_counts"] == {
        "key": 2,
        "ckey": 1,
        "wkey": 0,
        "unsupported/unrecognized": 0,
    }
    assert [item["validation_status"] for item in payload["results"]] == [
        VALID_KEY_SIDE,
        "REJECTED",
        VALID_KEY_SIDE,
    ]
    assert payload["unique_valid_pubkey_fingerprint_count"] == 1
    assert payload["duplicate_valid_pubkey_groups"][0]["physical_starts"] == [
        0,
        200,
    ]
    assert payload["structural_wallet_confirmation"] == "NOT_EVALUATED"
    assert COMPRESSED_PUBLIC_KEY.hex() not in json.dumps(payload)


def test_duplicate_offsets_are_opened_once_and_read_once(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "deduplicated.bin"
    source.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    resolved_source = source.resolve()
    original_open = Path.open
    open_count = 0

    def tracked_open(path, mode="r", *args, **kwargs):
        nonlocal open_count
        if path.resolve() == resolved_source and mode == "rb":
            open_count += 1
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", tracked_open)
    payload = revalidate_wallet_records(report_for(0, 0), source)

    assert payload["findings_input_count"] == 2
    assert payload["unique_offsets_count"] == 1
    assert payload["duplicate_offset_count"] == 1
    assert payload["source_read_count"] == 1
    assert open_count == 1


def test_offset_out_of_range_is_controlled(tmp_path) -> None:
    source = tmp_path / "short.bin"
    source.write_bytes(b"abc")

    payload = revalidate_wallet_records(report_for(999), source)

    assert payload["results"][0]["reason_codes"] == [OFFSET_OUT_OF_RANGE]
    assert payload["source_read_count"] == 0


def test_truncated_source_is_controlled(tmp_path) -> None:
    source = tmp_path / "truncated.bin"
    source.write_bytes(framed("key", b"\x21" + COMPRESSED_PUBLIC_KEY[:8]))

    payload = revalidate_wallet_records(report_for(0), source)

    assert payload["results"][0]["reason_codes"] == [
        SOURCE_READ_TRUNCATED,
        BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
    ]


def test_unsupported_record_prefix_is_controlled(tmp_path) -> None:
    source = tmp_path / "mkey.bin"
    source.write_bytes(framed("mkey", (1).to_bytes(4, "little")))

    payload = revalidate_wallet_records(report_for(0), source)

    assert payload["results"][0]["record_type"] == "unsupported/unrecognized"
    assert payload["results"][0]["reason_codes"] == [
        RECORD_PREFIX_NOT_SUPPORTED
    ]


@pytest.mark.parametrize(
    ("record_type", "public_key"),
    [
        ("key", COMPRESSED_PUBLIC_KEY),
        ("wkey", UNCOMPRESSED_PUBLIC_KEY),
    ],
)
def test_compressed_and_uncompressed_points_are_validated(
    tmp_path,
    record_type: str,
    public_key: bytes,
) -> None:
    source = tmp_path / f"{record_type}.bin"
    source.write_bytes(framed(record_type, public_key_vector(public_key)))

    payload = revalidate_wallet_records(report_for(0), source)

    result = payload["results"][0]
    assert result["validation_status"] == VALID_KEY_SIDE
    assert result["pubkey_length"] == len(public_key)
    assert len(result["safe_pubkey_fingerprint"]) == 64


def test_invalid_curve_point_is_rejected(tmp_path) -> None:
    source = tmp_path / "invalid-point.bin"
    source.write_bytes(framed("key", public_key_vector(b"\x02" + bytes(32))))

    payload = revalidate_wallet_records(report_for(0), source)

    assert payload["results"][0]["reason_codes"] == [
        BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE
    ]


def test_legacy_report_without_optional_family_fields_is_supported(tmp_path) -> None:
    source = tmp_path / "legacy.bin"
    source.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    legacy_report = report_for(0, include_family=False)
    legacy_report["target_findings"].extend(
        [
            {"artifact_kind": "other", "physical_start": 0},
            {"artifact_kind": "wallet_record", "physical_start": "0"},
            {
                "artifact_kind": "wallet_record",
                "physical_start": 0,
                "target": "electrum",
            },
        ]
    )

    payload = revalidate_wallet_records(legacy_report, source)

    assert payload["findings_input_count"] == 1
    assert payload["valid_key_side_count"] == 1


@pytest.mark.parametrize(
    ("record_type", "suffix"),
    ADATA_FALSE_POSITIVE_KEY_SIDES,
)
def test_adata_false_positive_fixtures_use_shared_batch_validator(
    tmp_path,
    record_type: str,
    suffix: bytes,
) -> None:
    source = tmp_path / f"adata-{record_type}.bin"
    source.write_bytes(framed(record_type, suffix))

    payload = revalidate_wallet_records(report_for(0), source)

    assert payload["valid_key_side_count"] == 0
    assert payload["results"][0]["reason_codes"] == [
        BITCOIN_RECORD_PUBKEY_LENGTH_INVALID
    ]


def test_revalidation_cli_bypasses_selection_and_full_scan(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    old_report = tmp_path / "old.json"
    old_report.write_text(json.dumps(report_for(0)), encoding="utf-8")
    output = tmp_path / "new.json"

    def forbidden(*args, **kwargs):
        raise AssertionError("full scan path must not run")

    monkeypatch.setattr(cli_module, "_selection", forbidden)
    monkeypatch.setattr(cli_module, "FullImageRecoveryCoordinator", forbidden)

    assert main(
        [
            "--input",
            str(source),
            "--revalidate-wallet-records",
            str(old_report),
            "--output",
            str(output),
        ]
    ) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mode"] == "wallet_record_revalidation"
    assert payload["valid_key_side_count"] == 1


def test_output_is_deterministic_and_reads_are_bounded(tmp_path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    source_report = tmp_path / "old.json"
    report = report_for(0)
    source_report.write_text(json.dumps(report), encoding="utf-8")

    first = revalidate_wallet_records(report, source, source_report=source_report)
    second = revalidate_wallet_records(report, source, source_report=source_report)
    first_path = write_wallet_record_revalidation_report(
        first, tmp_path / "first.json"
    )
    second_path = write_wallet_record_revalidation_report(
        second, tmp_path / "second.json"
    )

    assert first == second
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first["maximum_bytes_per_offset"] == MAX_RAW_KEY_SIDE_BYTES == 79
    assert first["source_bytes_read"] <= first["source_read_count"] * 79
