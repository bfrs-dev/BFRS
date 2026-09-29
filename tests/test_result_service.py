import json

import pytest

from bfrs.application.result_service import ResultService, ResultServiceError


def image_report():
    return {
        "report_schema_version": 5,
        "application": {"name": "BFRS", "version": "2.0.1"},
        "source_type": "IMAGE",
        "source": r"C:\\images\\disk.img",
        "status": "rejected",
        "finding_summary": {"accepted_candidates": 1, "rejected": 1},
        "target_findings": [
            {
                "target": "bitcoin-core",
                "artifact_kind": "wallet_record",
                "physical_start": 100,
                "physical_end": 120,
                "confidence": 0.3,
                "structural_status": "REJECTED",
                "validation_status": "BITCOIN_RECORD_KEY_SIDE_REJECTED",
                "reason_codes": ["BITCOIN_RECORD_PUBKEY_LENGTH_INVALID"],
                "correlated_evidence": [],
                "safe_metadata": {"record_type": "ckey"},
                "recommended_recovery_action": "REVIEW_CONTEXT",
                "normalized_state": {
                    "discovery_state": "REJECTED",
                    "structural_state": "NONE",
                    "crypto_state": "UNCHECKED",
                    "recovery_relevance": "CONTEXT_REVIEW",
                },
            },
            {
                "target": "secrets",
                "artifact_kind": "WIF_PRIVATE_KEY",
                "physical_start": 500,
                "physical_end": 552,
                "confidence": 1.0,
                "structural_status": "COMPLETE",
                "validation_status": "BASE58CHECK_AND_SECP256K1_VALID",
                "reason_codes": ["BASE58CHECK_VALID"],
                "safe_fingerprint": "abc",
                "safe_metadata": {},
                "recommended_recovery_action": "RECOVER_SECRET",
                "normalized_state": {
                    "discovery_state": "ACCEPTED",
                    "structural_state": "COMPLETE",
                    "crypto_state": "VALID",
                    "recovery_relevance": "INDEPENDENT",
                },
            },
        ],
    }


def write_report(tmp_path, payload):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_public_report_summary_and_findings(tmp_path):
    report = ResultService().load(write_report(tmp_path, image_report()))

    assert report.schema_version == 5
    assert report.application_version == "2.0.1"
    assert report.source_type == "IMAGE"
    assert report.finding_count == 2
    assert report.targets == ("bitcoin-core", "secrets")
    assert report.findings[0].display_location == "100..120"


def test_folder_location_uses_file_path_and_file_offset(tmp_path):
    payload = image_report()
    payload["source_type"] = "FOLDER"
    payload["source_root"] = r"C:\\recovered"
    payload.pop("source")
    payload["target_findings"] = [{
        **payload["target_findings"][0],
        "file_path": r"C:\\recovered\\nested\\wallet.dat",
        "relative_path": "nested/wallet.dat",
        "file_offset_start": 42,
        "file_offset_end": 47,
    }]
    payload["target_findings"][0].pop("physical_start")
    payload["target_findings"][0].pop("physical_end")

    report = ResultService().load(write_report(tmp_path, payload))
    finding = report.findings[0]

    assert finding.location_kind == "file_offset"
    assert finding.start_offset == 42
    assert finding.display_location.endswith("wallet.dat @ 42")


def test_filters_by_target_discovery_crypto_and_search(tmp_path):
    service = ResultService()
    report = service.load(write_report(tmp_path, image_report()))

    accepted = service.filter(
        report,
        targets={"secrets"},
        discovery_states={"accepted"},
        crypto_states={"valid"},
    )
    assert len(accepted) == 1
    assert accepted[0].artifact_kind == "WIF_PRIVATE_KEY"

    searched = service.filter(report, search="pubkey_length_invalid")
    assert len(searched) == 1
    assert searched[0].target == "bitcoin-core"


def test_legacy_row_without_normalized_state_is_adapted(tmp_path):
    payload = image_report()
    row = payload["target_findings"][0]
    row.pop("normalized_state")

    report = ResultService().load(write_report(tmp_path, payload))

    assert report.findings[0].discovery_state == "REJECTED"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"target_findings": {}},
        {"target_findings": ["not-an-object"]},
        {
            "target_findings": [{
                "target": "bitcoin-core",
                "normalized_state": {"discovery_state": "REJECTED"},
            }]
        },
    ],
)
def test_malformed_reports_are_rejected(tmp_path, payload):
    path = write_report(tmp_path, payload)
    with pytest.raises(ResultServiceError):
        ResultService().load(path)


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{broken", encoding="utf-8")

    with pytest.raises(ResultServiceError, match="valid UTF-8 JSON"):
        ResultService().load(path)


def test_result_summary_prefers_canonical_report_counts(tmp_path):
    payload = image_report()
    payload["finding_summary"] = {
        "accepted_candidates": 7,
        "review_candidates": 3,
        "rejected": 11,
        "crypto_valid_occurrences": 5,
    }
    service = ResultService()
    report = service.load(write_report(tmp_path, payload))

    summary = service.summary(report)

    assert summary.displayed_findings == 2
    assert summary.accepted == 7
    assert summary.review == 3
    assert summary.rejected == 11
    assert summary.crypto_valid == 5


def test_result_summary_falls_back_to_visible_findings(tmp_path):
    payload = image_report()
    payload["finding_summary"] = {}
    service = ResultService()
    report = service.load(write_report(tmp_path, payload))

    summary = service.summary(report)

    assert summary.displayed_findings == 2
    assert summary.accepted == 1
    assert summary.review == 0
    assert summary.rejected == 1
    assert summary.crypto_valid == 1


@pytest.mark.parametrize(
    ("profile", "expected_target"),
    [
        ("accepted", "secrets"),
        ("rejected", "bitcoin-core"),
        ("crypto-valid", "secrets"),
    ],
)
def test_quick_filter_profiles(tmp_path, profile, expected_target):
    service = ResultService()
    report = service.load(write_report(tmp_path, image_report()))

    result = service.filter(report, profile=profile)

    assert len(result) == 1
    assert result[0].target == expected_target


def test_review_profile_includes_candidate_and_context_review_accepted(tmp_path):
    payload = image_report()
    accepted = payload["target_findings"][1]
    accepted["normalized_state"]["recovery_relevance"] = "CONTEXT_REVIEW"
    candidate = {
        **payload["target_findings"][0],
        "target": "electrum",
        "normalized_state": {
            "discovery_state": "CANDIDATE",
            "structural_state": "FRAGMENT",
            "crypto_state": "UNCHECKED",
            "recovery_relevance": "CONTEXT_REVIEW",
        },
    }
    payload["target_findings"].append(candidate)
    service = ResultService()
    report = service.load(write_report(tmp_path, payload))

    result = service.filter(report, profile="review")

    assert {item.target for item in result} == {"secrets", "electrum"}


def test_unknown_quick_filter_profile_is_rejected(tmp_path):
    service = ResultService()
    report = service.load(write_report(tmp_path, image_report()))

    with pytest.raises(ValueError, match="unknown result filter profile"):
        service.filter(report, profile="surprise")


def test_review_priority_orders_crypto_valid_before_accepted_review_and_rejected(tmp_path):
    payload = image_report()
    accepted = payload["target_findings"][1]
    accepted["normalized_state"]["crypto_state"] = "UNCHECKED"

    crypto_valid = {
        **accepted,
        "target": "electrum",
        "physical_start": 50,
        "confidence": 0.2,
        "normalized_state": {
            "discovery_state": "CANDIDATE",
            "structural_state": "FRAGMENT",
            "crypto_state": "VALID",
            "recovery_relevance": "CONTEXT_REVIEW",
        },
    }
    review = {
        **payload["target_findings"][0],
        "target": "armory",
        "physical_start": 200,
        "normalized_state": {
            "discovery_state": "CANDIDATE",
            "structural_state": "FRAGMENT",
            "crypto_state": "UNCHECKED",
            "recovery_relevance": "CONTEXT_REVIEW",
        },
    }
    payload["target_findings"].extend([crypto_valid, review])

    service = ResultService()
    report = service.load(write_report(tmp_path, payload))
    ordered = service.prioritize(report.findings)

    assert [item.review_priority_label for item in ordered] == [
        "CRYPTO_VALID",
        "ACCEPTED",
        "REVIEW",
        "REJECTED",
    ]


def test_review_priority_uses_confidence_then_location_for_stable_order(tmp_path):
    payload = image_report()
    template = payload["target_findings"][1]
    payload["target_findings"] = [
        {
            **template,
            "target": "electrum",
            "physical_start": 300,
            "confidence": 0.8,
        },
        {
            **template,
            "target": "bitcoin-core",
            "physical_start": 100,
            "confidence": 0.9,
        },
        {
            **template,
            "target": "armory",
            "physical_start": 50,
            "confidence": 0.9,
        },
    ]

    service = ResultService()
    report = service.load(write_report(tmp_path, payload))
    ordered = service.prioritize(report.findings)

    assert [item.target for item in ordered] == [
        "armory",
        "bitcoin-core",
        "electrum",
    ]
