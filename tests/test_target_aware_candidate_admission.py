from bfrs.core.models import Hotspot, RawHit
from bfrs.scanners.hotspot_builder import HotspotBuilder
from bfrs.validators.candidate_policy import CandidatePolicy
from bfrs.validators.evidence_strength import (
    EvidenceStrength,
    classify_raw_hit,
)


SOURCE = "synthetic.img"


def hit(
    offset: int,
    hit_type: str,
    *,
    target: str = "bitcoin-core",
    artifact_kind: str = "wallet_record",
    structural_status: str = "ANCHOR_ONLY",
    validation_status: str = "UNVALIDATED",
) -> RawHit:
    return RawHit(
        offset,
        offset + 4,
        hit_type,
        0.0,
        SOURCE,
        {},
        target=target,
        artifact_kind=artifact_kind,
        structural_status=structural_status,
        validation_status=validation_status,
    )


def decision(*hits: RawHit):
    hotspot = HotspotBuilder(cluster_gap=1024, padding=0).build(
        hits, source_size=max(item.end_offset for item in hits) + 1
    )[0]
    return CandidatePolicy(min_hits=1, min_distinct_types=1).evaluate(hotspot)


def test_weak_single_anchor_is_not_a_candidate() -> None:
    result = decision(hit(10, "bitcoin_mkey"))

    assert not result.accepted
    assert "weak_evidence_requires_independent_corroboration" in result.reasons


def test_weak_plus_strong_bitcoin_evidence_is_accepted() -> None:
    result = decision(
        hit(10, "bitcoin_mkey"),
        hit(
            20,
            "berkeley_metadata_little_endian",
            artifact_kind="berkeley_metadata",
            structural_status="STRUCTURAL",
            validation_status="BERKELEY_METADATA_STRUCTURAL_VALID",
        ),
    )

    assert result.accepted


def test_two_independent_weak_bitcoin_types_are_correlated() -> None:
    assert decision(
        hit(10, "bitcoin_mkey"), hit(20, "bitcoin_keymeta")
    ).accepted


def test_duplicate_weak_markers_are_not_independent() -> None:
    result = decision(*(
        hit(index * 10, "bitcoin_mkey") for index in range(20)
    ))

    assert not result.accepted
    assert result.distinct_types == ("bitcoin_mkey",)


def test_cross_target_weak_signals_do_not_corroborate_each_other() -> None:
    result = decision(
        hit(10, "bitcoin_mkey"),
        hit(
            20,
            "electrum_wallet_type_anchor",
            target="electrum",
            artifact_kind="electrum_wallet_anchor",
        ),
    )

    assert not result.accepted


def test_single_strong_and_crypto_valid_evidence_are_admitted() -> None:
    strong = hit(
        10,
        "bitcoin_ckey",
        structural_status="STRUCTURAL",
        validation_status="BITCOIN_RECORD_STRUCTURAL_VALID",
    )
    wif = hit(
        20,
        "validated_wif",
        target="secrets",
        artifact_kind="wif_private_key",
        structural_status="COMPLETE",
        validation_status="BASE58CHECK_AND_SECP256K1_VALID",
    )

    assert decision(strong).accepted
    assert decision(wif).accepted
    assert classify_raw_hit(wif).strength is EvidenceStrength.CRYPTO_VALID


def test_address_and_public_key_without_wallet_structure_remain_weak() -> None:
    address = hit(
        10,
        "bitcoin_base58_address",
        artifact_kind="bitcoin_address",
        validation_status="CHECKSUM_VALID",
    )
    public_key = hit(
        20,
        "bitcoin_sec_public_key",
        artifact_kind="bitcoin_public_key",
        validation_status="SECP256K1_VALID",
    )

    assert classify_raw_hit(address).strength is EvidenceStrength.WEAK
    assert classify_raw_hit(public_key).strength is EvidenceStrength.WEAK


def test_synthetic_weak_marker_workload_preserves_raws_and_suppresses_candidates() -> None:
    weak = (
        *(hit(index * 10, "bitcoin_mkey") for index in range(10_000)),
        *(hit(200_000 + index * 10, "berkeley_metadata_little_endian",
              artifact_kind="berkeley_metadata") for index in range(1_000)),
        *(hit(400_000 + index * 10, "electrum_wallet_type_anchor",
              target="electrum", artifact_kind="electrum_wallet_anchor")
          for index in range(1_000)),
    )
    positives = (
        hit(600_000, "validated_wif", target="secrets",
            artifact_kind="wif_private_key", structural_status="COMPLETE",
            validation_status="BASE58CHECK_AND_SECP256K1_VALID"),
        hit(600_010, "bitcoin_ckey", structural_status="STRUCTURAL",
            validation_status="BITCOIN_RECORD_STRUCTURAL_VALID"),
        hit(600_020, "electrum_seed_version_anchor", target="electrum",
            artifact_kind="electrum_wallet_anchor", structural_status="STRUCTURAL",
            validation_status="ELECTRUM_CONTAINER_STRUCTURAL_VALID"),
    )
    workload = (*weak, *positives)
    policy = CandidatePolicy(min_hits=1, min_distinct_types=1)

    accepted_before = sum(policy.evaluate(Hotspot(
        item.start_offset,
        item.end_offset,
        0.0,
        item.source,
        {
            "hit_count": 1,
            "hit_types": (item.hit_type,),
            "hit_offsets": (item.start_offset,),
        },
    )).accepted for item in workload)
    accepted_after = sum(decision(item).accepted for item in workload)

    assert len(workload) == 12_003
    assert accepted_before == 12_003
    assert accepted_after == len(positives) == 3
    assert all(policy.evaluate(HotspotBuilder(padding=0).build(
        (item,), source_size=item.end_offset + 1
    )[0]).accepted for item in positives)
