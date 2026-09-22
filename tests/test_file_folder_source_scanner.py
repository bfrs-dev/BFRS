import json
import os
from pathlib import Path

import pytest

from bfrs.cli import main
from bfrs.core.source_types import SourceType, detect_source_type
from bfrs.scanners.folder_source_scanner import discover_regular_files, scan_folder_source
from tests.test_cli import basic_arguments, valid_wif
from tests.test_export_reconstructed_wallet import case
from tests.test_logical_berkeley_database_pipeline import private_der


def intact_wallet_bytes(case) -> bytes:
    return b"".join(case[4][number] for number in range(7))


def test_source_type_auto_detection_preserves_image_extensions(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    image = tmp_path / "disk.img"
    image.write_bytes(b"")
    ordinary = tmp_path / "wallet.dat"
    ordinary.write_bytes(b"")
    assert detect_source_type(folder) is SourceType.FOLDER
    assert detect_source_type(image) is SourceType.IMAGE
    assert detect_source_type(ordinary) is SourceType.FILE


def test_single_intact_wallet_file_uses_file_locations_and_fast_path(case, tmp_path):
    wallet = tmp_path / "wallet.dat"
    wallet.write_bytes(intact_wallet_bytes(case))
    report = tmp_path / "single.json"
    assert main(basic_arguments(wallet, report)) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["source_type"] == "FILE"
    assert payload["location_model"] == {
        "offset_kind": "file_offset", "file_path": str(wallet.resolve())
    }
    assert payload["intact_wallet"] == {
        "detected": True,
        "wallet_family": "BITCOIN_CORE",
        "format": "BDB",
        "fast_path_used": True,
    }
    assert payload["reconstructed_databases"] == []
    assert payload["reconstructed_wallet_results"] == []


def test_folder_scans_wallet_names_nested_paths_and_identical_files(case, tmp_path):
    root = tmp_path / "source"
    nested = root / "nested"
    nested.mkdir(parents=True)
    data = intact_wallet_bytes(case)
    paths = [root / "wallet.dat", root / "file001", nested / "random.bin"]
    for path in paths:
        path.write_bytes(data)
    report = tmp_path / "folder.json"
    assert main(basic_arguments(root, report) + ["--targets", "all"]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["report_schema_version"] == 5
    assert payload["source_type"] == "FOLDER"
    assert payload["files_discovered"] == payload["files_scanned"] == 3
    assert payload["files_skipped"] == 0
    assert payload["bytes_scanned"] == 3 * len(data)
    assert sum(row["wallet_detected"] for row in payload["files"]) == 3
    assert {row["file_path"] for row in payload["files"]} == {
        str(path.resolve()) for path in paths
    }
    assert all(row["intact_wallet"]["fast_path_used"] for row in payload["files"])
    assert payload["target_findings"]
    assert all("file_path" in row for row in payload["target_findings"])
    assert all("physical_start" not in row for row in payload["target_findings"])


def test_folder_default_scan_writes_no_wallet_and_opt_in_copies_intact(case, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "backup.dat"
    source.write_bytes(intact_wallet_bytes(case))
    report = tmp_path / "default.json"
    recovery = tmp_path / "private-recovery"
    assert main(basic_arguments(root, report)) == 0
    assert not recovery.exists()
    recovered_report = tmp_path / "recovered.json"
    assert main(basic_arguments(root, recovered_report) + [
        "--recover-wallets", "--recovery-dir", str(recovery),
    ]) == 0
    payload = json.loads(recovered_report.read_text(encoding="utf-8"))
    summary = payload["wallet_recovery"]
    assert (summary["eligible_candidates"], summary["recovered_wallets"],
            summary["failed_wallets"]) == (1, 1, 0)
    output = recovery / summary["outputs"][0]["relative_recovery_path"]
    assert output.read_bytes() == source.read_bytes()
    manifest = json.loads(output.with_name("recovery_manifest.json").read_text())
    assert manifest["reconstruction_method"] == "EXACT_INTACT_FILE_COPY"
    assert manifest["post_copy_validation"] == "HASH_AND_BDB_HEADER_VALID"
    encoded = json.dumps(payload) + json.dumps(manifest)
    assert private_der(1).hex() not in encoded
    assert (1).to_bytes(32, "big").hex() not in encoded


def test_discovery_does_not_follow_junction_loop(monkeypatch, tmp_path):
    root = tmp_path / "source"
    loop = root / "loop"
    loop.mkdir(parents=True)
    (root / "regular").write_bytes(b"data")
    (loop / "must-not-be-scanned").write_bytes(b"data")
    monkeypatch.setattr(
        Path, "is_junction", lambda self: self.name == "loop", raising=False
    )
    files, skipped = discover_regular_files(root)
    assert [path.name for path, _, _ in files] == ["regular"]
    assert {row["reason"] for row in skipped} == {"LINK_NOT_FOLLOWED"}


def test_broken_file_does_not_abort_other_file(monkeypatch, tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    good = root / "good"
    bad = root / "bad"
    good.write_bytes(b"good")
    bad.write_bytes(b"bad")
    report = tmp_path / "report.json"
    parser_args = [*basic_arguments(root, report)]
    from bfrs.cli import build_parser
    arguments = build_parser().parse_args(parser_args)

    def child(argv):
        source = Path(argv[argv.index("--input") + 1])
        output = Path(argv[argv.index("--output") + 1])
        if source.name == "bad":
            return 3
        output.write_text(json.dumps({
            "target_findings": [], "intact_wallet": {"detected": False},
            "finding_summary": {"accepted_candidates": 0},
        }), encoding="utf-8")
        return 0

    assert scan_folder_source(arguments, child) == 0
    payload = json.loads(report.read_text())
    assert payload["files_scanned"] == 1
    assert payload["files_skipped"] == 1
    assert {row["status"] for row in payload["files"]} == {"SCANNED", "SKIPPED"}


def test_folder_checkpoint_is_explicitly_deferred(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(SystemExit) as raised:
        main(basic_arguments(root, tmp_path / "report.json") + [
            "--checkpoint", str(tmp_path / "checkpoint.sqlite")
        ])
    assert raised.value.code == 2
    assert "deferred to P2.7.1" in capsys.readouterr().err


def test_image_source_regression_remains_image(tmp_path):
    image = tmp_path / "source.img"
    image.write_bytes(b"no wallet")
    report = tmp_path / "image.json"
    assert main(basic_arguments(image, report)) == 0
    payload = json.loads(report.read_text())
    assert payload["source_type"] == "IMAGE"
    assert payload["location_model"] == {"offset_kind": "physical_offset"}



def test_folder_large_file_preserves_chunk_boundary_finding(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    boundary = 1024 * 1024
    secret = valid_wif()
    payload = bytearray(boundary * 2)
    start = boundary - len(secret) // 2
    payload[start:start + len(secret)] = secret
    source = root / "recovered_12345"
    source.write_bytes(payload)
    report = tmp_path / "boundary.json"
    assert main(basic_arguments(root, report) + [
        "--targets", "secrets", "--chunk-mib", "1", "--overlap-kib", "64",
    ]) == 0
    result = json.loads(report.read_text())
    findings = result["target_findings"]
    assert any(row["file_path"] == str(source.resolve()) for row in findings)
    assert any(row.get("artifact_kind") == "WIF_PRIVATE_KEY" for row in findings)
    assert all("physical_start" not in row for row in findings)
    assert any(row.get("file_offset_start") == start for row in findings)



def test_single_file_opt_in_recovery_uses_intact_copy(case, tmp_path):
    source = tmp_path / "old-wallet"
    source.write_bytes(intact_wallet_bytes(case))
    report = tmp_path / "single-recovery.json"
    recovery = tmp_path / "single-private-recovery"
    assert main(basic_arguments(source, report) + [
        "--recover-wallets", "--recovery-dir", str(recovery),
    ]) == 0
    payload = json.loads(report.read_text())
    assert payload["wallet_recovery"]["recovered_wallets"] == 1
    relative = payload["wallet_recovery"]["outputs"][0]["relative_recovery_path"]
    recovered = recovery / relative
    assert recovered.read_bytes() == source.read_bytes()


def test_access_denied_directory_is_skipped(monkeypatch, tmp_path):
    root = tmp_path / "source"
    allowed = root / "allowed"
    denied = root / "denied"
    allowed.mkdir(parents=True)
    denied.mkdir()
    (allowed / "file").write_bytes(b"data")
    real_scandir = os.scandir

    def guarded(path):
        if Path(path).name == "denied":
            raise PermissionError("synthetic denial")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", guarded)
    files, skipped = discover_regular_files(root)
    assert [path.name for path, _, _ in files] == ["file"]
    assert any(row["reason"] == "PermissionError" for row in skipped)



def test_individual_file_checkpoint_and_resume_remain_supported(tmp_path):
    source = tmp_path / "ordinary-file"
    source.write_bytes(b"ordinary data")
    checkpoint = tmp_path / "file.checkpoint.sqlite"
    first = tmp_path / "first.json"
    resumed = tmp_path / "resumed.json"
    assert main(basic_arguments(source, first) + [
        "--checkpoint", str(checkpoint),
    ]) == 0
    assert main(basic_arguments(source, resumed) + [
        "--resume-checkpoint", str(checkpoint),
    ]) == 0
    assert json.loads(resumed.read_text())["source_type"] == "FILE"


def test_intact_recovery_never_overwrites_existing_output(case, tmp_path):
    source = tmp_path / "wallet-file"
    source.write_bytes(intact_wallet_bytes(case))
    report = tmp_path / "first.json"
    recovery = tmp_path / "recovery"
    args = basic_arguments(source, report) + [
        "--recover-wallets", "--recovery-dir", str(recovery),
    ]
    assert main(args) == 0
    first = json.loads(report.read_text())
    relative = first["wallet_recovery"]["outputs"][0]["relative_recovery_path"]
    output = recovery / relative
    original = output.read_bytes()
    assert main(args) == 0
    second = json.loads(report.read_text())
    assert second["wallet_recovery"]["recovered_wallets"] == 0
    assert second["wallet_recovery"]["failed_wallets"] == 1
    assert second["wallet_recovery"]["outputs"][0]["reason_code"] == "OUTPUT_EXISTS"
    assert output.read_bytes() == original
