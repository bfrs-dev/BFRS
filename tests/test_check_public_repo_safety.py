from scripts import check_public_repo_safety as safety
from scripts.check_public_repo_safety import (
    Finding,
    LARGE_RECOVERY_BLOB_BYTES,
    classify_tracked_path,
)


def test_safe_python_file_is_allowed() -> None:
    assert classify_tracked_path("src/bfrs/cli.py", 4096) is None


def test_report_is_forbidden() -> None:
    assert classify_tracked_path("reports/result.json") == "forensic report directory"


def test_checkpoint_directory_is_forbidden() -> None:
    assert (
        classify_tracked_path("checkpoints/test.checkpoint.json")
        == "scan checkpoint directory"
    )


def test_wallet_dat_is_forbidden() -> None:
    assert classify_tracked_path("wallet.dat") == "wallet.dat"


def test_disk_image_is_forbidden() -> None:
    assert classify_tracked_path("evidence/disk.img") == "disk image"


def test_recovered_database_is_forbidden() -> None:
    assert (
        classify_tracked_path("recovered/test.db")
        == "recovered material directory"
    )


def test_ordinary_binary_outside_recovery_is_allowed() -> None:
    assert classify_tracked_path("fixtures/protocol.bin", 8 * 1024 * 1024) is None


def test_large_recovery_binary_outside_standard_directories_is_forbidden() -> None:
    assert (
        classify_tracked_path(
            "fixtures/wallet_recovery_payload.bin", LARGE_RECOVERY_BLOB_BYTES
        )
        == "large recovery binary/database"
    )


def test_small_recovery_named_binary_is_allowed() -> None:
    assert (
        classify_tracked_path(
            "fixtures/wallet_recovery_payload.bin", LARGE_RECOVERY_BLOB_BYTES - 1
        )
        is None
    )


def test_checkpoint_temp_file_is_forbidden_outside_checkpoint_directory() -> None:
    assert (
        classify_tracked_path("tmp/scan.checkpoint.json.tmp-123")
        == "checkpoint temporary file"
    )


def test_main_returns_zero_and_prints_nothing_for_safe_repo(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(safety, "find_tracked_risks", lambda: [])

    assert safety.main() == 0
    assert capsys.readouterr().out == ""


def test_main_returns_one_and_prints_only_path_and_category(
    monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        safety,
        "find_tracked_risks",
        lambda: [Finding("reports/result.json", "forensic report directory")],
    )

    assert safety.main() == 1
    assert capsys.readouterr().out == (
        "reports/result.json\tforensic report directory\n"
    )
