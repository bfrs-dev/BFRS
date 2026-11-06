import importlib.util
import json
from pathlib import Path

import pytest

from tests.sparse_files import sparse_file

from tests.test_orphan_private_key_der import private_der

spec = importlib.util.spec_from_file_location(
    "verify_der_findings", Path(__file__).parents[1] / "scripts" / "verify_der_findings.py"
)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def verify(tmp_path, data, *, offset=None, records=None):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "sample.bin"
    source.write_bytes(data)
    if offset is None:
        offset = data.index(verifier.ANCHOR)
    findings = tmp_path / "keys.jsonl"
    rows = records or [{"artifact_kind": "ec_private_key_der", "relative_path": "sample.bin",
                        "file_offset_start": offset, "private_key": "SYNTHETIC_PRIVATE_DO_NOT_EXPORT"}]
    findings.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8-sig")
    output = tmp_path / "verified"
    before = source.read_bytes()
    summary = verifier.verify_findings(findings, root, output)
    assert source.read_bytes() == before
    assert {p.name for p in output.iterdir()} == {"podsumowanie_der.json", "weryfikacja_der.jsonl"}
    for p in output.iterdir():
        assert "SYNTHETIC_PRIVATE_DO_NOT_EXPORT" not in p.read_text()
        assert "private_bytes" not in p.read_text()
    return summary, [json.loads(line) for line in (output / "weryfikacja_der.jsonl").read_text().splitlines()]


def test_valid_historical_key_is_confirmed_without_exporting_bytes(tmp_path):
    summary, rows = verify(tmp_path, b"prefix" + private_der(7) + bytes(1500))
    assert rows[0]["status"] == "VALID_COMPLETE_DER"
    assert rows[0]["anchor_matches_report"] is True
    assert rows[0]["complete_locations"][0]["validation_strength"] == "embedded_pubkey_match"
    assert summary["counts"]["bytes_read"] == 1028


def test_inner_fragment_after_outer_header_loss_is_confirmed(tmp_path):
    der = private_der(7)
    inner = der[der.index(verifier.ANCHOR):]
    _, rows = verify(tmp_path, b"prefix" + inner + bytes(1500))
    assert rows[0]["status"] == "VALID_INNER_FRAGMENT"
    assert rows[0]["outer_der_candidates"] == 0


def test_curve_or_public_key_mismatch_has_actual_rejection_reasons(tmp_path):
    from bfrs.core.secp256k1 import encode_sec_public_key, scalar_multiply
    der = private_der(7, embedded_public_key=encode_sec_public_key(scalar_multiply(8), compressed=False))
    summary, rows = verify(tmp_path, b"prefix" + der + bytes(1500))
    assert rows[0]["status"] == "NOT_CONFIRMED"
    assert rows[0]["complete_rejection_counts"]["embedded_public_key_mismatch"] == 1
    assert summary["rejection_counts"]["fragment_rejection_counts:embedded_public_key_mismatch"] == 1


@pytest.mark.parametrize("offset,status", [(0, "ANCHOR_MISMATCH"), (9999, "OFFSET_OUT_OF_RANGE")])
def test_wrong_source_or_offset_is_not_presented_as_rejected_key(tmp_path, offset, status):
    _, rows = verify(tmp_path, b"ordinary data", offset=offset)
    assert rows[0]["status"] == status


def test_duplicate_locations_missing_files_and_escaping_paths(tmp_path):
    row = {"artifact_kind": "ec_private_key_der", "relative_path": "sample.bin", "file_offset_start": 6}
    summary, rows = verify(tmp_path, b"prefix" + verifier.ANCHOR + bytes(80), records=[
        row, row, {**row, "relative_path": "missing.bin"}, {**row, "relative_path": "..\\outside.bin"},
        {**row, "relative_path": "C:\\Windows\\other.bin"},
    ])
    assert summary["counts"]["duplicate_locations_skipped"] == 1
    assert summary["counts"]["SOURCE_FILE_MISSING"] == 1
    assert summary["counts"]["UNSAFE_SOURCE_PATH"] == 2
    assert len(rows) == 4


def test_sparse_large_file_uses_only_one_bounded_read(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "pagefile.sys"
    der = private_der(7)
    offset = 1329425220
    with sparse_file(source) as stream:
        stream.seek(offset - der.index(verifier.ANCHOR))
        stream.write(der)
        stream.seek(offset + 2000)
        stream.write(b"\0")
    row = verifier.verify_one(source, offset)
    assert row["status"] == "VALID_COMPLETE_DER"
    assert row["bytes_read"] == 1028
    assert row["complete_locations"][0]["absolute_der_offset"] == offset - 4


def test_invalid_input_does_not_publish_partial_output(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    findings = tmp_path / "keys.jsonl"
    findings.write_text('{"artifact_kind":"ec_private_key_der","relative_path":"missing","file_offset_start":1}\nBROKEN')
    output = tmp_path / "verified"
    with pytest.raises(ValueError):
        verifier.verify_findings(findings, root, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".bfrs-der-*"))


def test_existing_output_and_source_folder_output_are_refused(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    findings = tmp_path / "keys.jsonl"
    findings.write_text("")
    with pytest.raises(verifier.VerificationError):
        verifier.verify_findings(findings, root, root / "output")
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep").write_text("preserve")
    with pytest.raises(verifier.VerificationError):
        verifier.verify_findings(findings, root, output)
    assert (output / "keep").read_text() == "preserve"
