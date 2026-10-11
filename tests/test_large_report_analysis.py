import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("ijson")

spec = importlib.util.spec_from_file_location(
    "analyze_large_report", Path(__file__).parents[1] / "scripts" / "analyze_large_report.py"
)
analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyzer)


def finding(*, path="E:\\HP\\wallet.dat", kind="WIF_PRIVATE_KEY", relevance="INDEPENDENT",
            discovery="ACCEPTED", crypto="VALID", fingerprint="a" * 64):
    return {
        "target": "secrets", "artifact_kind": kind, "file_path": path,
        "file_offset_start": 123, "file_offset_end": 175,
        "safe_fingerprint": fingerprint,
        "normalized_state": {
            "discovery_state": discovery, "structural_state": "COMPLETE",
            "crypto_state": crypto, "recovery_relevance": relevance,
        },
        "seed": "SYNTHETIC_SECRET_DO_NOT_EXPORT",
        "safe_metadata": {"seed": "SYNTHETIC_SECRET_DO_NOT_EXPORT", "word_count": 12},
    }


def run_report(tmp_path, payload, *, bom=False):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8-sig" if bom else "utf-8")
    before = source.read_bytes()
    output = tmp_path / "analysis"
    result = analyzer.analyze_report(source, output)
    assert source.read_bytes() == before
    assert {p.name for p in output.iterdir()} == {
        "podsumowanie.txt", "podsumowanie.json", "najwazniejsze_pliki.jsonl",
        "wyniki_do_sprawdzenia.jsonl", "seedy_prawdopodobnie_przypadkowe.jsonl",
        "kandydaci_seedow.jsonl",
        "sygnatury_kluczy.jsonl", "diagnostyka_kluczy.jsonl",
    }
    return result, output


def test_only_canonical_findings_are_counted_and_keys_deduplicated_on_disk(tmp_path):
    rows = [finding(path=f"E:\\HP\\file-{index}") for index in range(2)]
    files = [{"file_path": row["file_path"], "report": {
        "target_findings": [row], "finding_summary": {
            "crypto_valid_secret_occurrences": 1, "crypto_valid_unique_secrets": 1,
            "accepted_candidates": 1,
        },
    }} for row in rows]
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "files": files, "target_findings": rows,
    })
    counts = result["retained_finding_counts"]
    assert counts["retained_findings"] == 2
    assert counts["retained_valid_secret_occurrences"] == 2
    assert counts["retained_unique_valid_secret_fingerprints"] == 1
    assert result["reported_finding_counts"]["crypto_valid_secret_occurrences"] == 2
    assert "crypto_valid_unique_secrets" not in result["reported_finding_counts"]
    assert result["file_priority_counts"]["SECRET_REVIEW"] == 2
    assert len((output / "wyniki_do_sprawdzenia.jsonl").read_text().splitlines()) == 2
    for path in output.iterdir():
        assert "SYNTHETIC_SECRET_DO_NOT_EXPORT" not in path.read_text()


def test_likely_wordlist_seeds_are_separate_but_not_lost(tmp_path):
    noise = finding(kind="mnemonic", relevance="LIKELY_FALSE_POSITIVE")
    accepted = finding(kind="mnemonic", fingerprint="b" * 64)
    rejected = finding(discovery="REJECTED", fingerprint="c" * 64)
    result, output = run_report(tmp_path, {"source_type": "FILE", "target_findings": [noise, accepted, rejected]})
    counts = result["retained_finding_counts"]
    assert counts["retained_unique_valid_secret_fingerprints"] == 2
    assert counts["retained_unique_valid_secret_fingerprints_excluding_likely_noise"] == 1
    assert counts["retained_valid_secret_occurrences"] == 2
    assert counts["likely_false_positive_rows"] == 1
    assert counts["exported_review_rows"] == 1
    assert len((output / "seedy_prawdopodobnie_przypadkowe.jsonl").read_text().splitlines()) == 1


def test_file_with_only_aggregated_seed_noise_is_not_prioritized_as_real_secret(tmp_path):
    result, output = run_report(tmp_path, {"source_type": "FOLDER", "files": [{
        "file_path": "E:\\HP\\wordlist.txt", "report": {
            "finding_summary": {"crypto_valid_secret_occurrences": 500, "accepted_candidates": 500},
            "mnemonic_recovery": {"likely_wordlist_occurrences": 500, "independent_candidate_occurrences": 0},
        },
    }], "target_findings": []})
    assert result["file_priority_counts"] == {"SEED_NOISE": 1}
    assert "SEED_NOISE" in (output / "najwazniejsze_pliki.jsonl").read_text()


def test_file_metadata_after_report_bom_unicode_and_wallet_modules(tmp_path):
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "files": [
            {"report": {"intact_wallet": {"detected": True, "wallet_family": "BITCOIN_CORE"}}, "file_path": "E:\\HP\\portfel-żółty.dat"},
            {"report": {"orphan_private_key_recovery": {"valid_secp256k1_der_count": 2}}, "file_path": "E:\\HP\\klucze.bin"},
            {"report": {"electrum_raw_recovery": {"fragment_candidates": 1}}, "file_path": "E:\\HP\\fragment"},
            {"report": {"finding_summary": {"accepted_candidates": 0}}, "wallet_detected": True, "file_path": "E:\\HP\\sam-marker"},
        ], "target_findings": [],
    }, bom=True)
    assert result["retained_finding_counts"]["files_processed"] == 4
    assert result["file_priority_counts"] == {
        "WALLET_STRUCTURE": 1, "SECRET_REVIEW": 1, "OTHER_REVIEW": 1,
    }
    assert "portfel-żółty.dat" in (output / "najwazniejsze_pliki.jsonl").read_text()
    assert "sam-marker" not in (output / "najwazniejsze_pliki.jsonl").read_text()


def test_unknown_legacy_validation_is_reviewable_not_claimed_valid(tmp_path):
    row = {"artifact_kind": "private_key", "validation_status": "FUTURE_VALIDATION", "file_offset_start": 42}
    result, output = run_report(tmp_path, {"source_type": "IMAGE", "target_findings": [row]})
    assert result["retained_finding_counts"]["retained_valid_secret_occurrences"] == 0
    assert result["retained_finding_counts"]["exported_review_rows"] == 1
    projected = json.loads((output / "wyniki_do_sprawdzenia.jsonl").read_text())
    assert projected["normalized_state"]["discovery_state"] == "UNCLASSIFIED"


def test_seed_only_candidate_view_remains_non_additive(tmp_path):
    candidate = {
        "validation_status": "BIP39_VALID", "recovery_relevance": "INDEPENDENT_CANDIDATE",
        "fingerprint": "a" * 64, "word_count": 12, "physical_start": 3, "physical_end": 84,
    }
    result, output = run_report(tmp_path, {
        "source": "E:\\HP\\file", "mnemonic_recovery": {"candidates": [candidate]},
    })
    assert result["retained_finding_counts"]["mnemonic_candidate_rows"] == 1
    assert result["retained_finding_counts"]["retained_valid_secret_occurrences"] == 0
    exported = json.loads((output / "kandydaci_seedow.jsonl").read_text())
    assert exported["source_view"] == "mnemonic_candidates"
    assert exported["normalized_state"]["crypto_state"] == "VALID"
    assert result["retained_finding_counts"]["mnemonic_candidate_unique_valid_fingerprints"] == 1


def test_truncated_report_does_not_publish_partial_analysis(tmp_path):
    source = tmp_path / "broken.json"
    source.write_bytes(b'{"source_type":"FOLDER","files":[],"target_findings":[')
    output = tmp_path / "analysis"
    with pytest.raises(Exception):
        analyzer.analyze_report(source, output)
    assert not output.exists()
    assert not list(tmp_path.glob(".bfrs-analysis-*"))
    assert source.read_bytes().endswith(b'[')


def test_existing_output_is_not_overwritten(tmp_path):
    source = tmp_path / "report.json"
    source.write_text('{"source_type":"FOLDER","files":[]}')
    output = tmp_path / "analysis"
    output.mkdir()
    (output / "existing.txt").write_text("preserve")
    with pytest.raises(analyzer.ReportAnalysisError, match="juz istnieje"):
        analyzer.analyze_report(source, output)
    assert (output / "existing.txt").read_text() == "preserve"


def test_unrelated_json_is_not_presented_as_zero_findings(tmp_path):
    source = tmp_path / "other.json"
    source.write_text('{"unrelated": 123}')
    with pytest.raises(analyzer.ReportAnalysisError, match="Nie rozpoznano"):
        analyzer.analyze_report(source, tmp_path / "analysis")


def test_streaming_discards_large_per_file_diagnostics_without_json_loads(tmp_path, monkeypatch):
    source = tmp_path / "report.json"
    diagnostic = json.dumps("ordinary diagnostic " * 1000)
    with source.open("w", encoding="utf-8") as stream:
        stream.write('{"source_type":"FOLDER","files":[')
        for index in range(500):
            if index:
                stream.write(',')
            stream.write('{"file_path":"file-' + str(index) + '","report":{"diagnostics":{"unused":' + diagnostic + '}}}')
        stream.write('],"target_findings":[]}')

    def forbidden(*args, **kwargs):
        raise AssertionError("loaded a JSON object instead of streaming")

    monkeypatch.setattr(json, "loads", forbidden)
    result = analyzer.analyze_report(source, tmp_path / "analysis")
    assert result["retained_finding_counts"]["files_processed"] == 500
    assert source.stat().st_size > 8 * 1024**2
    assert (tmp_path / "analysis" / "podsumowanie.json").stat().st_size < 10_000


def test_against_real_bfrs_folder_report(tmp_path):
    from bfrs.cli import main
    from tests.test_cli import basic_arguments, valid_wif
    root = tmp_path / "source"
    root.mkdir()
    (root / "first").write_bytes(valid_wif())
    (root / "second").write_bytes(valid_wif())
    report = tmp_path / "folder.json"
    assert main(basic_arguments(root, report) + ["--targets", "secrets", "--skip-mnemonic"]) == 0
    summary = analyzer.analyze_report(report, tmp_path / "analysis")
    assert summary["retained_finding_counts"]["retained_valid_secret_occurrences"] == 2
    assert summary["retained_finding_counts"]["retained_unique_valid_secret_fingerprints"] == 1
    assert summary["retained_finding_counts"]["files_processed"] == 2
    assert summary["reported_finding_counts"]["crypto_valid_secret_occurrences"] == 2


def test_raw_der_is_exported_with_existing_rejection_diagnostics_and_late_file_path(tmp_path):
    row = finding(kind="ec_private_key_der", crypto="UNCHECKED", discovery="RAW")
    row["normalized_state"]["structural_state"] = "NONE"
    row["reason_codes"] = ["DER_ANCHOR_ONLY"]
    module = {
        "raw_der_anchor_count": 1, "candidate_der_count": 1,
        "valid_secp256k1_der_count": 0, "reasons": ["no_valid_historical_secp256k1_der"],
        "diagnostics": {"read_failure_count": 0, "truncated_read_count": 1,
                        "rejection_counts": [["embedded_public_key_mismatch", 1]],
                        "private_key": "SYNTHETIC_SECRET_DO_NOT_EXPORT"},
        "locations": [{"private_bytes": "SYNTHETIC_SECRET_DO_NOT_EXPORT"}],
    }
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "files": [{"report": {
            "target_findings": [row], "orphan_private_key_recovery": module,
        }, "file_path": "E:\\HP\\żółty.bin", "relative_path": "żółty.bin"}],
        "target_findings": [row],
    })
    keys = [json.loads(line) for line in (output / "sygnatury_kluczy.jsonl").read_text().splitlines()]
    assert len(keys) == 1
    assert keys[0]["reason_codes"] == ["DER_ANCHOR_ONLY"]
    assert keys[0]["normalized_state"]["crypto_state"] == "UNCHECKED"
    diagnostics = json.loads((output / "diagnostyka_kluczy.jsonl").read_text())
    assert diagnostics["file_path"] == "E:\\HP\\żółty.bin"
    assert diagnostics["rejection_counts"] == {"embedded_public_key_mismatch": 1}
    assert result["key_diagnostics"]["counts"]["canonical_key_rows"] == 1
    assert result["retained_finding_counts"]["retained_valid_secret_occurrences"] == 0
    for path in output.iterdir():
        assert "SYNTHETIC_SECRET_DO_NOT_EXPORT" not in path.read_text()


def test_root_and_file_key_diagnostics_are_separate_non_additive_views(tmp_path):
    module = {"raw_der_anchor_count": 4, "candidate_der_count": 0,
              "valid_secp256k1_der_count": 0,
              "diagnostics": {"rejection_counts": {"der_invalid": 2}}}
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "orphan_private_key_recovery": module,
        "files": [{"file_path": "file.bin", "report": {"orphan_private_key_recovery": module}}],
        "target_findings": [],
    })
    counts = result["key_diagnostics"]["counts"]
    assert counts["root:orphan_private_key_recovery:raw_der_anchor_count"] == 4
    assert counts["files:orphan_private_key_recovery:raw_der_anchor_count"] == 4
    assert len((output / "diagnostyka_kluczy.jsonl").read_text().splitlines()) == 2


def test_fragment_diagnostics_and_zero_module_presence_are_retained(tmp_path):
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "files": [
            {"file_path": "empty", "report": {"orphan_private_key_recovery": {
                "raw_der_anchor_count": 0, "candidate_der_count": 0, "valid_secp256k1_der_count": 0}}},
            {"file_path": "fragment.bin", "report": {"orphan_private_key_fragment_recovery": {
                "raw_inner_anchor_count": 1, "candidate_inner_fragment_count": 0,
                "valid_inner_fragment_count": 0, "diagnostics": {"read_failure_count": 1}}}},
        ], "target_findings": [],
    })
    counts = result["key_diagnostics"]["counts"]
    assert counts["files:orphan_private_key_recovery:reports_present"] == 1
    assert counts["files:orphan_private_key_fragment_recovery:read_failure_count"] == 1
    rows = (output / "diagnostyka_kluczy.jsonl").read_text().splitlines()
    assert len(rows) == 1 and json.loads(rows[0])["file_path"] == "fragment.bin"


def test_key_diagnostics_from_real_folder_scan(tmp_path):
    from bfrs.cli import main
    from tests.test_cli import basic_arguments
    from tests.test_orphan_private_key_der import private_der
    root = tmp_path / "source"
    root.mkdir()
    (root / "valid.bin").write_bytes(private_der(7))
    (root / "anchor-only.bin").write_bytes(b"noise\x02\x01\x01\x04\x20" + bytes(32))
    source = tmp_path / "folder.json"
    assert main(basic_arguments(root, source) + ["--targets", "secrets", "--skip-mnemonic", "--padding-mib", "1"]) == 0
    summary = analyzer.analyze_report(source, tmp_path / "analysis")
    counts = summary["key_diagnostics"]["counts"]
    assert counts["kind:ec_private_key_der"] == 2
    original = json.loads(source.read_text())
    modules = [item["report"]["orphan_private_key_recovery"] for item in original["files"]]
    assert counts["files:orphan_private_key_recovery:raw_der_anchor_count"] == sum(item["raw_der_anchor_count"] for item in modules)
    assert counts["files:orphan_private_key_recovery:valid_secp256k1_der_count"] == 1
    diagnostics = [json.loads(line) for line in (tmp_path / "analysis" / "diagnostyka_kluczy.jsonl").read_text().splitlines()]
    assert any(row["file_path"].endswith("valid.bin") and row.get("valid_secp256k1_der_count") == 1 for row in diagnostics)
    assert any(row["file_path"].endswith("anchor-only.bin") and row.get("raw_der_anchor_count") == 0 and row["file_der_finding_rows"] == 1 for row in diagnostics)


def test_der_file_without_recovery_module_is_explicitly_marked_not_reported(tmp_path):
    row = finding(kind="ec_private_key_der", discovery="RAW", crypto="UNCHECKED")
    row["normalized_state"]["structural_state"] = "NONE"
    result, output = run_report(tmp_path, {
        "source_type": "FOLDER", "files": [{"file_path": "unknown.bin", "report": {
            "target_findings": [row]}}], "target_findings": [row],
    })
    diagnostic = json.loads((output / "diagnostyka_kluczy.jsonl").read_text())
    assert diagnostic["module"] == "NOT_REPORTED"
    assert result["key_diagnostics"]["counts"]["files_with_der_findings_but_no_recovery_modules"] == 1
