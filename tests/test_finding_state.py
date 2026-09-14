from dataclasses import replace

import pytest

from bfrs.core.models import RawHit, ValidationResult, ValidationStatus
from bfrs.reporting.finding_state import normalize_finding, summarize_findings
from bfrs.reporting.json_report import _aggregate_rejected_findings


@pytest.mark.parametrize("target,structural,validation,artifact,expected", [
    ("bitcoin-core", "REJECTED", "REJECTED", "wallet_record", ("REJECTED", "NONE", "UNCHECKED", "CONTEXT_REVIEW")),
    ("bitcoin-core", "ANCHOR_ONLY", "UNVALIDATED", "berkeley_metadata", ("RAW", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("bitcoin-core", "STRUCTURAL", "BERKELEY_METADATA_STRUCTURAL_VALID", "berkeley_metadata", ("ACCEPTED", "FRAGMENT", "UNCHECKED", "INDEPENDENT")),
    ("bitcoin-core", "FRAGMENT", "BERKELEY_METADATA_FRAGMENT", "berkeley_metadata", ("CANDIDATE", "FRAGMENT", "UNCHECKED", "CONTEXT_REVIEW")),
    ("bitcoin-core", "ANCHOR_ONLY", "BITCOIN_RECORD_KEY_SIDE_VALID", "wallet_record", ("ACCEPTED", "NONE", "NOT_APPLICABLE", "INDEPENDENT")),
    ("bitcoin-core", "REJECTED", "REJECTED", "bitcoin_address", ("REJECTED", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("bitcoin-core", "REJECTED", "REJECTED", "bitcoin_public_key", ("REJECTED", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("secrets", "COMPLETE", "BASE58CHECK_AND_SECP256K1_VALID", "WIF_PRIVATE_KEY", ("ACCEPTED", "COMPLETE", "VALID", "INDEPENDENT")),
    ("secrets", "ANCHOR_ONLY", "SECP256K1_VALID", "ec_private_key_der", ("ACCEPTED", "NONE", "VALID", "INDEPENDENT")),
    ("electrum", "ANCHOR_ONLY", "UNVALIDATED", "electrum_wallet_anchor", ("RAW", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("electrum", "CANDIDATE", "UNVALIDATED", "wallet", ("CANDIDATE", "NONE", "UNCHECKED", "CONTEXT_REVIEW")),
    ("electrum", "STRONG", "UNVALIDATED", "wallet", ("ACCEPTED", "COMPLETE", "UNCHECKED", "INDEPENDENT")),
    ("electrum", "STRUCTURAL", "ELECTRUM_CONTAINER_STRUCTURAL_VALID", "wallet", ("ACCEPTED", "COMPLETE", "UNCHECKED", "INDEPENDENT")),
    ("multibit", "REJECTED", "INSUFFICIENT_PROTOBUF_STRUCTURE", "wallet", ("REJECTED", "NONE", "UNCHECKED", "CONTEXT_REVIEW")),
    ("multibit", "FRAGMENT", "PROTOBUF_FRAGMENT_VALID", "wallet", ("CANDIDATE", "FRAGMENT", "UNCHECKED", "CONTEXT_REVIEW")),
    ("multibit", "STRONG", "PROTOBUF_STRUCTURAL_VALID", "wallet", ("ACCEPTED", "COMPLETE", "UNCHECKED", "INDEPENDENT")),
    ("armory", "CONTEXT_ONLY", "UNVALIDATED", "ARMORY_PAPER_BACKUP", ("RAW", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("armory", "FRAGMENT", "ARMORY_FRAGMENT_VALID", "wallet", ("CANDIDATE", "FRAGMENT", "UNCHECKED", "CONTEXT_REVIEW")),
    ("armory", "STRONG", "ARMORY_HEADER_STRUCTURAL_VALID", "wallet", ("ACCEPTED", "COMPLETE", "UNCHECKED", "INDEPENDENT")),
    ("unknown", "RAW", "UNVALIDATED", "unknown", ("RAW", "NONE", "NOT_APPLICABLE", "CONTEXT_REVIEW")),
    ("unknown", "VALIDATED", "UNVALIDATED", "unknown", ("ACCEPTED", "NONE", "UNCHECKED", "INDEPENDENT")),
    ("secrets", "FRAGMENT", "CRYPTO_VALID", "private_key", ("ACCEPTED", "FRAGMENT", "VALID", "INDEPENDENT")),
    ("secrets", "COMPLETE", "CHECKSUM_INVALID", "private_key", ("REJECTED", "COMPLETE", "INVALID", "CONTEXT_REVIEW")),
])
def test_mapping(target, structural, validation, artifact, expected):
    hit = RawHit(10, 20, "fixture", 0.5, "synthetic", target=target,
                 artifact_kind=artifact, structural_status=structural,
                 validation_status=validation)
    original = hit.safe_dict()
    state = normalize_finding(hit).safe_dict()
    assert tuple(state.values()) == expected
    assert normalize_finding(hit).safe_dict() == state
    assert hit.safe_dict() == original


@pytest.mark.parametrize("validation", ["BIP39_VALID", "ELECTRUM_SEED_VALID", "ELECTRUM_V1_STRICT_VALID"])
def test_valid_mnemonic_false_positive_is_independent_dimension(validation):
    hit = RawHit(1, 9, "mnemonic", .8, "synthetic", artifact_kind="mnemonic",
                 structural_status="COMPLETE", validation_status=validation,
                 safe_fingerprint="synthetic-fingerprint",
                 safe_metadata={"recovery_relevance": "LIKELY_WORDLIST_FALSE_POSITIVE"})
    assert normalize_finding(hit).crypto_state == "VALID"
    assert normalize_finding(hit).recovery_relevance == "LIKELY_FALSE_POSITIVE"
    summary = summarize_findings([hit, replace(hit, start_offset=12)])
    assert summary["rejected"] == 0
    assert summary["crypto_valid_occurrences"] == 2
    assert summary["crypto_valid_unique_secrets"] == 1
    rows, aggregates = _aggregate_rejected_findings([hit])
    assert rows == []
    assert aggregates["groups"][0]["normalized_state"]["crypto_state"] == "VALID"


@pytest.mark.parametrize("field", ["structural_status", "validation_status", "completeness", "recovery_relevance"])
def test_unknown_status_fails_explicitly(field):
    with pytest.raises(ValueError, match="unknown legacy"):
        normalize_finding({field: "FUTURE_STATUS"})


def test_validator_enum_and_no_missing_fingerprint_identity():
    result = ValidationResult(0, 10, "Berkeley", ValidationStatus.FRAGMENT, "synthetic")
    assert normalize_finding(result).structural_state == "FRAGMENT"
    rows = [{"artifact_kind": "ec_private_key_der", "validation_status": "SECP256K1_VALID"},
            {"artifact_kind": "bitcoin_public_key", "validation_status": "SECP256K1_VALID"}]
    summary = summarize_findings(rows)
    assert summary["crypto_valid_occurrences"] == 2
    assert summary["crypto_valid_unique_secrets"] == 0
    assert summary["crypto_valid_secrets_without_fingerprint"] == 1


def test_report_recovery_normalization_and_legacy_reader_compatibility(tmp_path):
    import copy
    from tests.test_json_report import historical_wallet_result, CONFIGURATION
    from bfrs.reporting.json_report import serialize_full_image_result
    from bfrs.tools.revalidate_wallet_records import _selected_offsets
    from bfrs.tools.revalidate_electrum_candidates import _extract_candidates

    result = historical_wallet_result(tmp_path)
    before = copy.deepcopy(result)
    report = serialize_full_image_result(result, CONFIGURATION)
    assert result == before
    assert report == serialize_full_image_result(result, CONFIGURATION)
    wallet = report["reconstructed_wallet_results"][0]
    assert wallet["normalized_state"]["structural_state"] == "COMPLETE"
    key = report["legacy_wallet_recovery"]["candidates"][0]["crypto_validation_results"][0]
    assert key["normalized_state"]["crypto_state"] == "VALID"
    assert report["recovery_state_summaries"]["reconstructed_wallet_results"]["structurally_complete"] == 1
    assert report["recovery_state_summaries"]["reconstructed_wallet_results"]["scope"].startswith("reconstructed_wallet_results;")
    v2 = {"report_schema_version": 2, "target_findings": [hit.safe_dict() for hit in result.target_findings]}
    assert _selected_offsets(v2) == _selected_offsets(report)
    mnemonic = {"mnemonic_standard": "ELECTRUM", "source_kind": "RAW_BYTES",
                "physical_start": 10, "physical_end": 20,
                "validation_status": "ELECTRUM_SEED_VALID", "completeness": "COMPLETE"}
    from bfrs.reporting.finding_state import normalized_row
    old = _extract_candidates({"report_schema_version": 2, "mnemonic_recovery": {"candidates": [mnemonic]}})
    new = _extract_candidates({"report_schema_version": 3, "mnemonic_recovery": {"candidates": [normalized_row(mnemonic)]}})
    assert old[0].occurrences == new[0].occurrences


@pytest.mark.parametrize("target,fixture", [
    ("multibit", "multibit"), ("armory", "armory"),
])
def test_real_synthetic_target_positive_controls(tmp_path, target, fixture):
    from tests.test_target_registry import _scan, _multibit_wallet, _armory_wallet
    data = _multibit_wallet() if fixture == "multibit" else _armory_wallet()
    hits = _scan(tmp_path, data, {target}, chunk_size=4096)
    accepted = [normalize_finding(hit) for hit in hits]
    assert any(state.discovery_state == "ACCEPTED" and state.structural_state == "COMPLETE"
               and state.crypto_state == "UNCHECKED" for state in accepted)


@pytest.mark.parametrize("encrypted", [False, True])
def test_parsed_electrum_complete_does_not_infer_crypto(encrypted):
    from dataclasses import asdict
    from tests.test_electrum_raw_recovery import _analyze, _plaintext, _encrypted
    candidate = _analyze(_encrypted() if encrypted else _plaintext())[0]
    state = normalize_finding({**asdict(candidate), "structural_status": candidate.structural_status})
    assert state.discovery_state == "ACCEPTED"
    assert state.structural_state == "COMPLETE"
    assert state.crypto_state == "UNCHECKED"


def test_summary_separates_raw_rejected_review_and_accepted():
    rows = [
        {"structural_status": "RAW"},
        {"structural_status": "REJECTED"},
        {"structural_status": "CANDIDATE"},
        {"structural_status": "FRAGMENT"},
        {"structural_status": "COMPLETE"},
    ]
    summary = summarize_findings(iter(rows))
    assert summary["rejected"] == 1
    assert summary["review_candidates"] == 2
    assert summary["accepted_candidates"] == 1
    assert summary["structurally_complete"] == 1
    assert summary["crypto_valid_occurrences"] == 0
    assert summary["crypto_valid_unique_secrets"] == 0
