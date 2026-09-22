import json
from pathlib import Path

import pytest

from bfrs.reporting.finding_state import normalized_row
from bfrs.reporting.recovery_support import (
    BTC_DONATION_ADDRESS, print_recovery_support_message,
    recovery_support_findings, render_recovery_support_message,
    should_show_recovery_support_message,
)


@pytest.mark.parametrize("row,expected", [
    ({"status": "RAW"}, False),
    ({"artifact_kind": "private_key", "structural_status": "REJECTED",
      "validation_status": "CRYPTO_VALID"}, False),
    ({"artifact_kind": "electrum_wallet_anchor", "status": "ANCHOR_ONLY"}, False),
    ({"artifact_kind": "mnemonic", "validation_status": "BIP39_VALID",
      "recovery_relevance": "LIKELY_WORDLIST_FALSE_POSITIVE"}, False),
    *[({"artifact_kind": kind, "validation_status": "CRYPTO_VALID"}, True)
      for kind in ("WIF_PRIVATE_KEY", "private_key", "ec_private_key_der", "mnemonic")],
    ({"artifact_kind": "electrum_wallet", "status": "COMPLETE"}, True),
    ({"artifact_kind": "electrum_wallet", "status": "STRUCTURAL"}, False),
    ({"artifact_kind": "electrum_wallet", "status": "COMPLETE",
      "recovery_relevance": "LIKELY_FALSE_POSITIVE"}, False),
    ({"artifact_kind": "wallet_record", "status": "COMPLETE"}, False),
    ({"artifact_kind": "berkeley_metadata", "status": "COMPLETE"}, False),
    ({"artifact_kind": "bitcoin_address", "validation_status": "CHECKSUM_VALID"}, False),
    ({"artifact_kind": "private_key", "status": "COMPLETE"}, False),
])
@pytest.mark.parametrize("normalized", [False, True])
def test_trigger(row, expected, normalized):
    if normalized:
        row = normalized_row(row)
    assert should_show_recovery_support_message([row]) is expected


def test_empty_and_counters_do_not_trigger(capsys):
    print_recovery_support_message({"raw_hit_count": 100, "anchors_found": 50,
                                    "finding_summary": {"accepted_candidates": 100}})
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("section,kind", [
    ("electrum_raw_recovery", "electrum_wallet"),
    ("mnemonic_recovery", "mnemonic"),
])
def test_recovery_views(section, kind):
    row = normalized_row({"status": "COMPLETE", "validation_status": "CRYPTO_VALID"})
    findings = list(recovery_support_findings({section: {"candidates": [row]}}))
    assert findings[0]["artifact_kind"] == kind
    assert should_show_recovery_support_message(findings)


def test_reconstructed_wallet_and_legacy_key_views():
    complete = normalized_row({"status": "STRUCTURAL"}, completeness="COMPLETE")
    assert should_show_recovery_support_message(recovery_support_findings(
        {"reconstructed_wallet_results": [complete]}))
    assert not should_show_recovery_support_message(recovery_support_findings(
        {"reconstructed_databases": [complete]}))
    key = normalized_row({"validation_status": "CRYPTO_VALID"})
    wallet = normalized_row({"status": "FRAGMENT"})
    wallet["crypto_validation_results"] = [key]
    report = {"legacy_wallet_recovery": {"candidates": [wallet]}}
    assert should_show_recovery_support_message(recovery_support_findings(report))
    wallet["normalized_state"]["discovery_state"] = "REJECTED"
    assert not should_show_recovery_support_message(recovery_support_findings(report))


def test_static_message_once_no_secret_and_exact_public_address(capsys):
    secret = "SYNTHETIC-RECOVERY-SECRET-NOT-FOR-OUTPUT"
    row = {"artifact_kind": "private_key", "validation_status": "CRYPTO_VALID",
           "private_key": secret, "seed": secret, "mnemonic": secret}
    print_recovery_support_message({"target_findings": [row, row, row]})
    output = capsys.readouterr().out
    assert output.count("RECOVERY SUCCESS") == 1
    assert output.count(BTC_DONATION_ADDRESS) == 1
    assert secret not in output
    assert output.strip() == render_recovery_support_message()
    assert BTC_DONATION_ADDRESS == "bc1qw4yrk7dhc2xcnpneh392xzdp9ey05saaxq8dav"
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    assert readme.count(BTC_DONATION_ADDRESS) == 1
    assert "PUBLIC_DONATION_ADDRESS" in readme


@pytest.mark.parametrize("mode", ["secrets", "electrum", "seed"])
def test_cli_success_once_after_report_and_no_donation_in_json(tmp_path, capsys, mode):
    from bfrs.cli import main
    from tests.test_cli import basic_arguments, valid_wif, historical_electrum_wallet
    source = tmp_path / "synthetic.txt"
    output = tmp_path / "result.json"
    if mode == "secrets":
        material = valid_wif()
        options = ["--targets", "secrets"]
    elif mode == "electrum":
        material = historical_electrum_wallet()
        options = ["--electrum-only"]
    else:
        from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator
        material = " ".join(ElectrumV1Validator().mn_encode("11" * 16)).encode()
        options = ["--seed-scan-only", "--workers", "1"]
    source.write_bytes(material)
    assert main(basic_arguments(source, output) + options) == 0
    stdout = capsys.readouterr().out
    assert stdout.count("RECOVERY SUCCESS") == 1
    assert stdout.index("report path:") < stdout.index("RECOVERY SUCCESS")
    assert material.decode() not in stdout
    report = output.read_text(encoding="utf-8")
    assert BTC_DONATION_ADDRESS not in report
    assert "donation" not in report.lower()
    if mode != "seed":
        assert json.loads(report)["report_schema_version"] == 5


def test_cli_weak_anchor_no_message(tmp_path, capsys):
    from bfrs.cli import main
    from tests.test_cli import basic_arguments
    source = tmp_path / "anchor.txt"
    source.write_bytes(b"BIE1")
    assert main(basic_arguments(source, tmp_path / "out.json") + ["--targets", "electrum"]) == 0
    assert "RECOVERY SUCCESS" not in capsys.readouterr().out
