import importlib.util
import json
from pathlib import Path

import pytest

from tests.test_cli import structural_metadata
from tests.test_electrum_raw_recovery import _plaintext, SYNTHETIC_SEED, SYNTHETIC_XPRV
from tests.test_raw_bitcoin_record_key_side import COMPRESSED_PUBLIC_KEY, framed, public_key_vector

spec = importlib.util.spec_from_file_location(
    "verify_wallet_findings", Path(__file__).parents[1] / "scripts" / "verify_wallet_findings.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


def finding(kind, offset, relative="sample.bin"):
    return {"artifact_kind": kind, "relative_path": relative, "file_offset_start": offset,
            "validation_status": "UNVALIDATED", "private_key": "SYNTHETIC_DO_NOT_EXPORT",
            "safe_metadata": {"seed": "SYNTHETIC_DO_NOT_EXPORT"}}


def run(tmp_path, data, rows):
    root = tmp_path / "source"
    root.mkdir()
    (root / "sample.bin").write_bytes(data)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"files": [{"report": {"target_findings": rows}}],
                                  "target_findings": rows}), encoding="utf-8-sig")
    output = tmp_path / "verified"
    result = verifier.verify_report(report, root, output)
    assert (root / "sample.bin").read_bytes() == data
    assert {p.name for p in output.iterdir()} == {"podsumowanie_portfeli.json", "weryfikacja_portfeli.jsonl"}
    for path in output.iterdir():
        public = path.read_text()
        for secret in ("SYNTHETIC_DO_NOT_EXPORT", SYNTHETIC_SEED, SYNTHETIC_XPRV):
            assert secret not in public
    return result, [json.loads(line) for line in (output / "weryfikacja_portfeli.jsonl").read_text().splitlines()]


def test_only_canonical_wallet_locations_are_counted_and_deduplicated(tmp_path):
    row = finding("wallet_record", 0)
    result, rows = run(tmp_path, framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)) + bytes(100),
                       [row, row, finding("mnemonic", 0), finding("ec_private_key_der", 0)])
    assert result["counts"]["input_wallet_rows"] == 2
    assert result["counts"]["duplicate_locations_skipped"] == 1
    assert result["counts"]["processed_locations"] == 1
    assert result["counts"]["bytes_read"] == 79
    assert rows[0]["status"] == "VALID_PUBLIC_KEY_SIDE"
    assert rows[0]["safe_pubkey_fingerprint"]


@pytest.mark.parametrize("name", ["key", "ckey", "wkey", "keymeta"])
def test_public_key_records_are_checked_but_not_called_private_keys(tmp_path, name):
    _, rows = run(tmp_path, framed(name, public_key_vector(COMPRESSED_PUBLIC_KEY)) + bytes(100),
                  [finding("wallet_record", 0)])
    assert rows[0]["status"] == "VALID_PUBLIC_KEY_SIDE"
    assert rows[0]["record_type"] == name


@pytest.mark.parametrize("name", ["mkey", "defaultkey"])
def test_weak_record_names_remain_unconfirmed(tmp_path, name):
    _, rows = run(tmp_path, framed(name, bytes(100)), [finding("wallet_record", 0)])
    assert rows[0]["status"] == "RECORD_NAME_ONLY"


def test_false_record_public_key_is_rejected(tmp_path):
    _, rows = run(tmp_path, b"\x03key\x07xxxxxxx", [finding("wallet_record", 0)])
    assert rows[0]["status"] == "RECORD_KEY_SIDE_REJECTED"


def test_metadata_checks_exact_reported_magic_not_nearby_good_page(tmp_path):
    invalid = bytearray(structural_metadata())
    invalid[16:20] = (0).to_bytes(4, "little")
    result, rows = run(tmp_path, bytes(invalid) + structural_metadata(),
                       [finding("berkeley_metadata", 12), finding("berkeley_metadata", 524)])
    assert [row["status"] for row in rows] == ["BDB_METADATA_REJECTED", "BDB_METADATA_STRUCTURAL"]
    assert rows[1]["metadata"]["absolute_offset"] == 512
    assert result["counts"]["processed_locations"] == 2


def test_truncated_metadata_is_fragment_and_large_file_read_is_bounded(tmp_path):
    source = tmp_path / "sparse.bin"
    offset = 1329425220
    with source.open("wb") as stream:
        stream.seek(offset - 12)
        stream.write(structural_metadata())
        stream.seek(offset + 100000)
        stream.write(b"\0")
    result = verifier.verify_one(source, "berkeley_metadata", offset)
    assert result["status"] == "BDB_METADATA_STRUCTURAL"
    assert result["bytes_read"] == 65536
    source.write_bytes(structural_metadata()[:100])
    result = verifier.verify_one(source, "berkeley_metadata", 12)
    assert result["status"] == "BDB_METADATA_FRAGMENT"


def test_electrum_checks_only_object_containing_anchor_and_redacts_secrets(tmp_path):
    data = b'ordinary "wallet_type" marker\0' + _plaintext()
    _, rows = run(tmp_path, data, [finding("electrum_wallet_anchor", data.index(b'"wallet_type"')),
                                  finding("electrum_wallet_anchor", data.index(b'"seed_version"'))])
    assert rows[0]["status"] != "ELECTRUM_COMPLETE_STRUCTURE"
    assert rows[1]["status"] == "ELECTRUM_COMPLETE_STRUCTURE"
    assert rows[1]["candidates"][0]["file_offset_start"] == data.index(b"{")


@pytest.mark.parametrize("kind,offset,status", [
    ("berkeley_metadata", 0, "METADATA_PREFIX_UNAVAILABLE"),
    ("wallet_record", 999, "OFFSET_OUT_OF_RANGE"),
    ("electrum_wallet_anchor", 0, "ANCHOR_MISMATCH"),
])
def test_wrong_offsets_are_unresolved(tmp_path, kind, offset, status):
    _, rows = run(tmp_path, b"ordinary file", [finding(kind, offset)])
    assert rows[0]["status"] == status


def test_missing_and_unsafe_paths_are_explicit(tmp_path):
    result, rows = run(tmp_path, b"ordinary file", [
        finding("wallet_record", 0, "missing.bin"), finding("wallet_record", 0, "..\\outside.bin"),
        finding("wallet_record", 0, "C:\\Windows\\other.bin")])
    assert [row["status"] for row in rows].count("UNSAFE_SOURCE_PATH") == 2
    assert result["status_counts"]["wallet_record:SOURCE_FILE_MISSING"] == 1


def test_invalid_json_never_publishes_partial_result(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    report = tmp_path / "report.json"
    report.write_text('{"target_findings": [' + json.dumps(finding("wallet_record", 0)))
    output = tmp_path / "verified"
    with pytest.raises(Exception):
        verifier.verify_report(report, root, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".wallet-verification-*"))


def test_image_report_and_source_output_are_refused(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"target_findings": [{"artifact_kind": "wallet_record", "physical_start": 0}]}))
    with pytest.raises(verifier.VerificationError, match="relative_path"):
        verifier.verify_report(report, root, tmp_path / "output")
    with pytest.raises(verifier.VerificationError, match="zrodlowym"):
        verifier.verify_report(report, root, root / "output")


def test_symlink_source_is_not_read(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    external = tmp_path / "external.bin"
    external.write_bytes(framed("key", public_key_vector(COMPRESSED_PUBLIC_KEY)))
    try:
        (root / "sample.bin").symlink_to(external)
    except OSError:
        pytest.skip("symlinks unavailable")
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"target_findings": [finding("wallet_record", 0)]}))
    result = verifier.verify_report(report, root, tmp_path / "output")
    assert result["status_counts"] == {"wallet_record:UNSAFE_SOURCE_PATH": 1}
    assert result["counts"]["bytes_read"] == 0
