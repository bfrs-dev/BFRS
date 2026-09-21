"""Synthetic-only tests for opt-in automatic physical wallet recovery."""
import copy
import json
from pathlib import Path

import pytest

from bfrs.cli import main
from bfrs.recovery.automatic_wallet_recovery import (
    recover_wallets,
    validate_recovery_destination,
)
from bfrs.recovery.physical_berkeley_reconstructor import ExportRefused
from bfrs.recovery.logical_berkeley_database_pipeline import (
    LogicalBerkeleyDatabaseRecoveryPipeline,
)
from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap, LogicalPageLocation
from tests.test_cli import basic_arguments
from tests.test_export_reconstructed_wallet import case
from tests.test_logical_berkeley_database_pipeline import (
    MemoryRangeReader,
    ckey_pair,
    leaf,
    mkey_pair,
    private_der,
)


def recovery_root(case) -> Path:
    return case[0].parent / "private-recovery"


def test_recover_wallets_disabled_writes_no_artifact(tmp_path):
    source = tmp_path / "source.img"
    source.write_bytes(b"no wallet")
    report = tmp_path / "report.json"
    assert main(basic_arguments(source, report)) == 0
    assert json.loads(report.read_text())["wallet_recovery"] == {
        "requested": False,
        "eligible_candidates": 0,
        "recovered_wallets": 0,
        "failed_wallets": 0,
        "outputs": [],
    }
    assert not list(tmp_path.rglob("wallet.dat"))


def test_recover_wallets_requires_directory(tmp_path):
    source = tmp_path / "source.img"
    source.write_bytes(b"")
    with pytest.raises(SystemExit) as raised:
        main(basic_arguments(source, tmp_path / "report.json") + ["--recover-wallets"])
    assert raised.value.code == 2


def test_complete_wallet_is_recovered_and_secret_free(case):
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert (summary["eligible_candidates"], summary["recovered_wallets"],
            summary["failed_wallets"]) == (1, 1, 0)
    entry = summary["outputs"][0]
    wallet = recovery_root(case) / entry["relative_recovery_path"]
    manifest = wallet.with_name("recovery_manifest.json")
    assert wallet.read_bytes() == b"".join(case[4][n] for n in range(7))
    manifest_text = manifest.read_text()
    assert json.loads(manifest_text)["reconstruction_method"] == "EXACT_VALIDATED_PAGE_COPY"
    secret = private_der(1).hex()
    assert secret not in manifest_text + json.dumps(summary)
    assert "private_key" not in manifest_text.lower()


def test_in_memory_report_empty_tuples_are_accepted(case):
    locations = case[6]["reconstructed_wallet_results"][0]["safe_locations"]
    locations["read_failure_page_numbers"] = ()
    locations["rejected_extraction_page_numbers"] = ()
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert summary["recovered_wallets"] == 1


@pytest.mark.parametrize("change,reason", [
    ("incomplete", "DATABASE_INCOMPLETE"),
    ("ambiguous", "AMBIGUOUS_PAGE"),
    ("missing", "MISSING_PAGE"),
])
def test_ineligible_structure_creates_no_wallet(case, change, reason):
    report = case[6]
    database = report["reconstructed_databases"][1]
    if change == "incomplete":
        database["normalized_state"]["structural_state"] = "FRAGMENT"
    elif change == "ambiguous":
        database["ambiguous_page_numbers"] = [4]
    else:
        database["selected_pages"].pop()
    summary = recover_wallets(case[0], report, recovery_root(case))
    assert summary["recovered_wallets"] == 0
    assert summary["outputs"][0]["reason_code"] == reason
    assert not list(recovery_root(case).rglob("wallet.dat"))


def test_likely_false_positive_is_not_attempted(case):
    candidate = case[6]["legacy_wallet_recovery"]["candidates"][0]
    candidate["normalized_state"]["recovery_relevance"] = "LIKELY_FALSE_POSITIVE"
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert summary["outputs"] == []
    assert summary["recovered_wallets"] == summary["failed_wallets"] == 0
    assert not recovery_root(case).exists()


def test_encrypted_complete_candidate_is_allowed(case):
    encrypted = bytearray(leaf(4, ckey_pair() + mkey_pair()))
    encrypted[16:20] = (5).to_bytes(4, "little")
    case[4][4] = bytes(encrypted)
    with case[0].open("r+b") as stream:
        stream.seek(case[5][4])
        stream.write(encrypted)
    logical = f"reconstructed-{case[5][2]:x}-3"
    page_map = LogicalBerkeleyPageMap(
        str(case[0]), 512, "little",
        [LogicalPageLocation(n, case[5][n], 512, str(case[0])) for n in case[4]],
    )
    recovered = LogicalBerkeleyDatabaseRecoveryPipeline(
        page_map,
        logical_file_id=logical,
        range_reader=MemoryRangeReader({case[5][n]: p for n, p in case[4].items()}),
    ).run()
    candidate = recovered.wallet_candidate_reports[0]
    candidate["normalized_state"] = {
        "discovery_state": "ACCEPTED",
        "recovery_relevance": "INDEPENDENT",
    }
    case[6]["legacy_wallet_recovery"]["candidates"] = [candidate]
    case[6]["reconstructed_wallet_results"][0]["record_pair_count"] = 6
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert summary["outputs"][0]["encrypted"] is True
    assert summary["recovered_wallets"] == 1
    wallet = recovery_root(case) / summary["outputs"][0]["relative_recovery_path"]
    assert wallet.read_bytes() == b"".join(case[4][n] for n in range(7))


def test_post_write_validation_failure_has_no_final_wallet(case, monkeypatch):
    def fail(*args, **kwargs):
        raise ExportRefused("WALLET_INVALID")

    monkeypatch.setattr(
        "bfrs.recovery.automatic_wallet_recovery.export_wallet_from_report", fail)
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert summary["outputs"][0]["reason_code"] == "WALLET_INVALID"
    assert not list(recovery_root(case).rglob("wallet.dat"))


def test_existing_output_is_never_overwritten(case):
    target = recovery_root(case) / "bitcoin-core" / "candidate_001" / "wallet.dat"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"keep")
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert summary["eligible_candidates"] == 1
    assert summary["outputs"][0]["reason_code"] == "OUTPUT_EXISTS"
    assert target.read_bytes() == b"keep"


def test_source_output_collision_is_refused(case):
    with pytest.raises(ExportRefused, match="PATH_COLLISION"):
        validate_recovery_destination(case[0], case[0])


def test_recovery_inside_git_worktree_is_refused(case, tmp_path):
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    with pytest.raises(ExportRefused, match="RECOVERY_DIRECTORY_INSIDE_GIT_WORKTREE"):
        validate_recovery_destination(case[0], repository / "recovered")


def test_multiple_wallets_use_deterministic_physical_order(case, monkeypatch):
    first = case[6]["legacy_wallet_recovery"]["candidates"][0]
    second = copy.deepcopy(first)
    first["candidate_id"] = "legacy-wallet-0000000000000001"
    second["candidate_id"] = "legacy-wallet-0000000000000002"
    first["physical_image_ranges"] = [[900, 950]]
    second["physical_image_ranges"] = [[100, 150]]
    case[6]["legacy_wallet_recovery"]["candidates"] = [first, second]
    calls = []

    def export(source, report, candidate_id, output, **options):
        calls.append((candidate_id, output.parent.name))
        output.write_bytes(candidate_id.encode())
        options["manifest_path"].write_text("{}")
        candidate = next(item for item in (first, second)
                         if item["candidate_id"] == candidate_id)
        return {
            "sha256": "0" * 64, "size": output.stat().st_size,
            "page_size": 512, "page_count": 1,
            "structural_validation_status": "BFRS_PHYSICAL_RECONSTRUCTION_VALID",
            "record_counts": candidate["record_counts"],
            "crypto_summary": candidate["crypto_summary"],
        }

    monkeypatch.setattr(
        "bfrs.recovery.automatic_wallet_recovery.export_wallet_from_report", export)
    summary = recover_wallets(case[0], case[6], recovery_root(case))
    assert calls == [
        (second["candidate_id"], "candidate_001"),
        (first["candidate_id"], "candidate_002"),
    ]
    assert [row["relative_recovery_path"] for row in summary["outputs"]] == [
        "bitcoin-core/candidate_001/wallet.dat",
        "bitcoin-core/candidate_002/wallet.dat",
    ]


def test_cli_summary_and_support_message_are_secret_free_once(tmp_path, monkeypatch, capsys):
    source = tmp_path / "source.img"
    source.write_bytes(b"no wallet")
    report = tmp_path / "report.json"
    recovery = tmp_path / "recovery"
    secret = "SYNTHETIC_PRIVATE_MATERIAL"

    def recovered(*args):
        return {
            "requested": True, "eligible_candidates": 1,
            "recovered_wallets": 1, "failed_wallets": 0,
            "outputs": [{
                "candidate_id": "legacy-wallet-0000000000000001",
                "relative_recovery_path": "bitcoin-core/candidate_001/wallet.dat",
                "status": "RECOVERED", "format": "BDB", "encrypted": False,
                "sha256": "0" * 64, "record_counts": {"key": 1},
            }],
        }

    monkeypatch.setattr("bfrs.cli.recover_wallets", recovered)
    assert main(basic_arguments(source, report) + [
        "--recover-wallets", "--recovery-dir", str(recovery)]) == 0
    stdout = capsys.readouterr().out
    report_text = report.read_text()
    assert "Recovered wallets:         1" in stdout
    assert stdout.count("RECOVERY SUCCESS") == 1
    assert secret not in stdout + report_text
    assert '"private_key":' not in report_text.lower()
