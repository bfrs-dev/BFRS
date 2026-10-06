import json
import os
from pathlib import Path
import threading
import time
import sqlite3

import pytest

from bfrs.cli import main
from bfrs.core.source_types import SourceType, detect_source_type
from bfrs.scanners.folder_source_scanner import discover_regular_files, scan_folder_source
from tests.test_cli import (
    armory_wallet,
    basic_arguments,
    encrypted_electrum,
    multibit_classic_wallet,
    structural_metadata,
    valid_wif,
)
from tests.test_export_reconstructed_wallet import case
from tests.test_logical_berkeley_database_pipeline import private_der
from tests.test_mnemonic_recovery_v1 import bip39_phrase


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


def _write_empty_child_report(output: Path) -> None:
    output.write_text(json.dumps({
        "raw_hit_count": 0,
        "target_findings": [],
        "intact_wallet": {"detected": False},
        "finding_summary": {"accepted_candidates": 0},
    }), encoding="utf-8")


def test_folder_checkpoint_resume_skips_completed_files(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(5):
        (root / f"file-{index}.bin").write_bytes(
            f"payload-{index}".encode("ascii")
        )

    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    first_report = tmp_path / "first.json"

    from bfrs.cli import build_parser
    first_arguments = build_parser().parse_args(
        basic_arguments(root, first_report) + [
            "--source-type", "folder",
            "--targets", "secrets",
            "--file-workers", "1",
            "--checkpoint", str(checkpoint),
        ]
    )

    first_seen = []

    def first_child(argv):
        source = Path(argv[argv.index("--input") + 1])
        output = Path(argv[argv.index("--output") + 1])
        first_seen.append(source.name)
        if len(first_seen) == 3:
            return 130
        _write_empty_child_report(output)
        return 0

    assert scan_folder_source(first_arguments, first_child) == 130
    assert first_seen == ["file-0.bin", "file-1.bin", "file-2.bin"]
    assert checkpoint.is_file()
    assert not first_report.exists()

    resumed_report = tmp_path / "resumed.json"
    resumed_arguments = build_parser().parse_args(
        basic_arguments(root, resumed_report) + [
            "--source-type", "folder",
            "--targets", "secrets",
            "--file-workers", "1",
            "--resume-checkpoint", str(checkpoint),
        ]
    )

    resumed_seen = []

    def resumed_child(argv):
        source = Path(argv[argv.index("--input") + 1])
        output = Path(argv[argv.index("--output") + 1])
        resumed_seen.append(source.name)
        _write_empty_child_report(output)
        return 0

    assert scan_folder_source(resumed_arguments, resumed_child) == 0
    assert resumed_seen == ["file-2.bin", "file-3.bin", "file-4.bin"]

    payload = json.loads(resumed_report.read_text(encoding="utf-8"))
    assert payload["files_discovered"] == 5
    assert payload["files_scanned"] == 5
    assert payload["checkpoint"]["supported"] is True
    assert payload["checkpoint"]["schema_version"] == 1
    assert payload["checkpoint"]["resumed_files"] == 2


def test_folder_resume_rejects_changed_source_snapshot(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "file.bin"
    source.write_bytes(b"before")
    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    report = tmp_path / "first.json"

    assert main(basic_arguments(root, report) + [
        "--source-type", "folder",
        "--targets", "secrets",
        "--checkpoint", str(checkpoint),
    ]) == 0

    source.write_bytes(b"after-change")
    resumed = tmp_path / "resumed.json"
    assert main(basic_arguments(root, resumed) + [
        "--source-type", "folder",
        "--targets", "secrets",
        "--resume-checkpoint", str(checkpoint),
    ]) == 3
    assert "folder contents changed" in capsys.readouterr().err
    assert not resumed.exists()


def test_folder_checkpoint_must_be_outside_source_root(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    (root / "file.bin").write_bytes(b"data")

    with pytest.raises(SystemExit) as raised:
        main(basic_arguments(root, tmp_path / "report.json") + [
            "--source-type", "folder",
            "--targets", "secrets",
            "--checkpoint", str(root / "checkpoint.sqlite"),
        ])

    assert raised.value.code == 2
    assert "folder checkpoint must be outside" in capsys.readouterr().err


def test_completed_folder_checkpoint_cannot_be_resumed(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    (root / "file.bin").write_bytes(b"data")
    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    report = tmp_path / "first.json"

    assert main(basic_arguments(root, report) + [
        "--source-type", "folder",
        "--targets", "secrets",
        "--checkpoint", str(checkpoint),
    ]) == 0

    second = tmp_path / "second.json"
    assert main(basic_arguments(root, second) + [
        "--source-type", "folder",
        "--targets", "secrets",
        "--resume-checkpoint", str(checkpoint),
    ]) == 3

    assert "already complete" in capsys.readouterr().err
    assert not second.exists()


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


def _semantic_findings(payload):
    return payload["target_findings"]


def _scan_fixture_with_file_workers(root, report, workers):
    assert main(basic_arguments(root, report) + [
        "--source-type", "folder",
        "--targets", "all",
        "--file-workers", str(workers),
        "--workers", "1",
        "--chunk-mib", "1",
        "--overlap-kib", "64",
    ]) == 0
    return json.loads(report.read_text(encoding="utf-8"))


def test_parallel_folder_scan_matches_sequential_for_every_target(tmp_path):
    root = tmp_path / "source"
    nested = root / "nested"
    nested.mkdir(parents=True)
    fixtures = {
        "bitcoin-core.bin": structural_metadata(),
        "electrum.dat": encrypted_electrum(),
        "multibit.wallet": multibit_classic_wallet(),
        "suspicious.exe": armory_wallet(),
        "no-extension": valid_wif(),
        "mnemonic.txt": bip39_phrase("english").encode(),
    }
    for name, data in fixtures.items():
        (nested / name).write_bytes(data)
    boundary = 1024 * 1024
    secret = valid_wif()
    large = bytearray(boundary + 256)
    start = boundary - len(secret) // 2
    large[start:start + len(secret)] = secret
    (root / "large.bin").write_bytes(large)

    sequential = _scan_fixture_with_file_workers(
        root, tmp_path / "sequential.json", 1)
    parallel_two = _scan_fixture_with_file_workers(
        root, tmp_path / "parallel-2.json", 2)
    parallel_four = _scan_fixture_with_file_workers(
        root, tmp_path / "parallel-4.json", 4)

    expected = _semantic_findings(sequential)
    assert _semantic_findings(parallel_two) == expected
    assert _semantic_findings(parallel_four) == expected
    assert {row["target"] for row in expected} >= {
        "bitcoin-core", "electrum", "multibit", "armory", "secrets"
    }
    assert any(row.get("artifact_kind") == "mnemonic" for row in expected)
    assert parallel_two["scanner_semantics"]["file_workers"] == 2
    assert parallel_four["scanner_semantics"]["maximum_queued_batches"] == 8
    assert [row["relative_path"] for row in parallel_four["files"]] == sorted(
        row["relative_path"] for row in parallel_four["files"])


def test_parallel_scan_keeps_identical_occurrences_per_source_file(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    payload = valid_wif()
    (root / "first").write_bytes(payload)
    (root / "second").write_bytes(payload)
    report = tmp_path / "report.json"
    assert main(basic_arguments(root, report) + [
        "--targets", "secrets", "--file-workers", "2",
    ]) == 0
    findings = [
        row for row in json.loads(report.read_text())["target_findings"]
        if row.get("artifact_kind") == "WIF_PRIVATE_KEY"
    ]
    assert len({row["file_path"] for row in findings}) == 2


def test_parallel_scan_never_matches_across_file_boundary(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    payload = valid_wif()
    split = len(payload) // 2
    (root / "part-a").write_bytes(payload[:split])
    (root / "part-b").write_bytes(payload[split:])
    report = tmp_path / "report.json"
    assert main(basic_arguments(root, report) + [
        "--targets", "secrets", "--file-workers", "2",
    ]) == 0
    findings = json.loads(report.read_text())["target_findings"]
    assert not any(row.get("artifact_kind") == "WIF_PRIVATE_KEY"
                   for row in findings)


def test_parallel_progress_reports_file_and_byte_rates(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(40):
        (root / f"file-{index:03d}").write_bytes(b"data")
    report = tmp_path / "report.json"
    assert main(basic_arguments(root, report) + [
        "--targets", "secrets", "--file-workers", "4",
    ]) == 0
    stderr = capsys.readouterr().err
    assert "files=40/40 (100.0%)" in stderr
    assert "bytes=160/160 (100.0%)" in stderr
    assert "files/s=" in stderr
    assert "MiB/s=" in stderr
    assert "raw_hits=" in stderr
    assert "validated=" in stderr
    assert "current=" in stderr


def test_file_workers_rejected_for_single_file_and_image(tmp_path):
    for name in ("ordinary.dat", "disk.img"):
        source = tmp_path / name
        source.write_bytes(b"data")
        with pytest.raises(SystemExit) as raised:
            main(basic_arguments(source, tmp_path / f"{name}.json") + [
                "--file-workers", "2",
            ])
        assert raised.value.code == 2


def test_unexpected_parallel_worker_failure_is_controlled(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(40):
        (root / f"file-{index:03d}").write_bytes(b"data")
    report = tmp_path / "report.json"
    from bfrs.cli import build_parser
    arguments = build_parser().parse_args(
        basic_arguments(root, report) + ["--file-workers", "2"])

    def child(_argv):
        raise RuntimeError("synthetic worker failure")

    assert scan_folder_source(arguments, child) == 3
    assert "folder worker error" in capsys.readouterr().err
    assert not report.exists()


def test_file_workers_run_concurrently_with_bounded_worker_count(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(20):
        (root / f"file-{index:03d}").write_bytes(b"data")
    report = tmp_path / "report.json"
    from bfrs.cli import build_parser
    arguments = build_parser().parse_args(
        basic_arguments(root, report) + ["--file-workers", "4"])
    lock = threading.Lock()
    active = maximum_active = 0

    def child(argv):
        nonlocal active, maximum_active
        output = Path(argv[argv.index("--output") + 1])
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
        try:
            time.sleep(0.02)
            output.write_text(json.dumps({
                "target_findings": [],
                "intact_wallet": {"detected": False},
                "finding_summary": {"crypto_valid_occurrences": 0},
                "raw_hit_count": 0,
            }), encoding="utf-8")
            return 0
        finally:
            with lock:
                active -= 1

    assert scan_folder_source(arguments, child) == 0
    assert 2 <= maximum_active <= 4


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("workers,file_workers", [(4, 2), (0, 4)])
def test_resume_can_change_worker_counts_without_repeating_completed_files(
    tmp_path, capsys, legacy, workers, file_workers,
):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(5):
        (root / f"file-{index}").write_bytes(valid_wif())
    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    first = tmp_path / "first.json"
    stopped = False

    def stop_after_one(update):
        nonlocal stopped
        if update.scanned_bytes > 0:
            stopped = True

    options = ["--targets", "all", "--workers", "1", "--file-workers", "1"]
    assert main(basic_arguments(root, first) + options + [
        "--checkpoint", str(checkpoint),
    ], _scan_progress=stop_after_one, _scan_should_stop=lambda: stopped) == 130
    if legacy:
        # Reproduce the original v1 schema with runtime fields in semantics.
        with sqlite3.connect(checkpoint) as connection:
            settings = json.loads(connection.execute(
                "SELECT value FROM metadata WHERE key = 'semantics_json'"
            ).fetchone()[0])
            settings.update(workers=1, file_workers=1)
            connection.execute("UPDATE metadata SET value=? WHERE key='semantics_json'",
                               (json.dumps(settings),))
            connection.execute("DELETE FROM metadata WHERE key='runtime_json'")

    resumed = tmp_path / "resumed.json"
    assert main(basic_arguments(root, resumed) + [
        "--targets", "all", "--workers", str(workers),
        "--file-workers", str(file_workers),
        "--resume-checkpoint", str(checkpoint),
    ]) == 0
    payload = json.loads(resumed.read_text())
    assert payload["checkpoint"]["resumed_files"] == 1
    assert payload["files_scanned"] == 5
    assert len({row["file_path"] for row in payload["target_findings"]
                if row.get("artifact_kind") == "WIF_PRIVATE_KEY"}) == 5
    assert "Checkpoint compatible. Runtime parameters changed:" in capsys.readouterr().err


def test_resume_still_rejects_changed_detection_settings(tmp_path, capsys):
    root = tmp_path / "source"
    root.mkdir()
    (root / "file").write_bytes(valid_wif())
    checkpoint = tmp_path / "folder.checkpoint.sqlite"
    from bfrs.cli import build_parser
    arguments = build_parser().parse_args(basic_arguments(root, tmp_path / "first.json") + [
        "--targets", "all", "--checkpoint", str(checkpoint),
    ])
    assert scan_folder_source(arguments, lambda argv: 130) == 130
    assert main(basic_arguments(root, tmp_path / "resumed.json") + [
        "--targets", "secrets", "--resume-checkpoint", str(checkpoint),
        "--workers", "4", "--file-workers", "2",
    ]) == 3
    assert "scanner settings mismatch: targets" in capsys.readouterr().err


def test_reused_folder_detectors_match_individual_full_file_scans(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    phrase = bip39_phrase("english")
    fixtures = [
        b"unrelated content\n" * 8000 + phrase.encode() + b"\n" + valid_wif(),
        b"ordinary prefix\n" + phrase.encode("utf-16le"),
        valid_wif(),
    ]
    expected = {}
    for index, data in enumerate(fixtures):
        source = root / f"file-{index}"
        source.write_bytes(data)
        report = tmp_path / f"single-{index}.json"
        assert main(basic_arguments(source, report) + [
            "--targets", "all", "--workers", "1",
        ]) == 0
        expected[str(source.resolve())] = json.loads(report.read_text())

    # Small folder files must not create mnemonic process pools or child reports.
    def unexpected(*args, **kwargs):
        raise AssertionError("per-file process pool or disk report")

    monkeypatch.setattr("bfrs.scanners.target_registry.ProcessPoolExecutor", unexpected)
    monkeypatch.setattr("bfrs.recovery.mnemonic.raw_mnemonic_scanner.ProcessPoolExecutor", unexpected)
    monkeypatch.setattr("bfrs.cli.write_json_report", unexpected)
    report = tmp_path / "folder.json"
    assert main(basic_arguments(root, report) + [
        "--targets", "all", "--workers", "4", "--file-workers", "1",
    ]) == 0
    payload = json.loads(report.read_text())
    for row in payload["files"]:
        before = expected[row["file_path"]]
        assert row["report"]["target_findings"] == before["target_findings"]
        assert row["report"]["raw_hit_count"] == before["raw_hit_count"]
        assert row["report"]["finding_summary"] == before["finding_summary"]
    assert any(row.get("artifact_kind") == "mnemonic"
               for row in payload["target_findings"])


def test_seed_only_folder_reuses_pipeline_with_local_small_file_decode(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    for index in range(2):
        (root / f"file-{index}").write_text(bip39_phrase("english"))

    def unexpected(*args, **kwargs):
        raise AssertionError("small seed-only file started a process pool")

    monkeypatch.setattr("bfrs.recovery.mnemonic.raw_mnemonic_scanner.ProcessPoolExecutor", unexpected)
    report = tmp_path / "folder.json"
    assert main(basic_arguments(root, report) + [
        "--seed-scan-only", "--workers", "4",
    ]) == 0
    payload = json.loads(report.read_text())
    assert payload["files_scanned"] == 2
    assert all(row["report"]["mnemonic_recovery"]["bip39_valid"] > 0
               for row in payload["files"])


def test_resumed_folder_rates_count_only_newly_scanned_data(tmp_path, monkeypatch, capsys):
    from bfrs.scanners.folder_source_scanner import _FolderProgress, _ScanOutcome
    clock = iter((100.0, 101.0))
    monkeypatch.setattr("bfrs.scanners.folder_source_scanner.time.monotonic",
                        lambda: next(clock))
    progress = _FolderProgress(tmp_path, files=4, total_bytes=4 * 2**20)
    progress.restore([
        _ScanOutcome(index, tmp_path / f"file-{index}", 2**20, 0, report={})
        for index in (1, 2)
    ])
    progress.update(_ScanOutcome(3, tmp_path / "file-3", 2**20, 0, report={}))
    assert "files/s=1.0 MiB/s=1.0" in capsys.readouterr().err
