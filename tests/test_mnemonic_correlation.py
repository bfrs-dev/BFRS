"""Secret-free regression tests for post-validation mnemonic correlation."""

from __future__ import annotations

from bfrs.core.models import RawHit
from bfrs.recovery.mnemonic.mnemonic_correlation import (
    CONTEXT_REVIEW,
    INDEPENDENT_CANDIDATE,
    LIKELY_WORDLIST_FALSE_POSITIVE,
    MNEMONIC_DENSE_SLIDING_WINDOWS,
    MNEMONIC_OVERLAP_CLUSTER,
    MNEMONIC_SAME_END_MULTIPLE_LENGTHS,
    MNEMONIC_SAME_START_MULTIPLE_LENGTHS,
    MNEMONIC_WORDLIST_REGION_LIKELY,
    CorrelationOccurrence,
    correlate_mnemonic_occurrences,
    correlation_statistics,
)
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator


def occurrence(start, end, fingerprint, *, standard="BIP39", words=12,
               language="english", encoding="utf-8"):
    return CorrelationOccurrence(
        start, end, fingerprint, standard, words, language, encoding)


def raw_hit(start, end, fingerprint, *, standard="BIP39", words=12,
            encoding="utf-8"):
    return RawHit(
        start, end, "mnemonic", 0.85, "synthetic",
        artifact_kind="mnemonic", structural_status="COMPLETE",
        validation_status=("BIP39_VALID" if standard == "BIP39"
                           else "ELECTRUM_SEED_VALID"),
        safe_fingerprint=fingerprint,
        safe_metadata={
            "mnemonic_standard": standard,
            "word_count": words,
            "language": "chinese_simplified",
            "encoding": encoding,
        },
    )


def test_single_crypto_valid_mnemonic_remains_independent():
    annotations = correlate_mnemonic_occurrences((
        occurrence(10_000, 10_090, "fp-single"),
    ))
    assert annotations[0].recovery_relevance == INDEPENDENT_CANDIDATE
    assert annotations[0].reason_codes == ()
    assert annotations[0].cluster_id is None


def test_case_a_mixed_standard_same_end_is_context_overlap_cluster():
    items = (
        occurrence(15_586_828_603, 15_586_828_693, "fp-electrum",
                   standard="ELECTRUM", words=23,
                   language="chinese_simplified", encoding="utf-16-le"),
        occurrence(15_586_828_647, 15_586_828_693, "fp-bip39", words=12,
                   language="chinese_simplified", encoding="utf-16-le"),
    )
    annotations = correlate_mnemonic_occurrences(items)
    assert {item.recovery_relevance for item in annotations} == {CONTEXT_REVIEW}
    assert len({item.cluster_id for item in annotations}) == 1
    assert all(MNEMONIC_OVERLAP_CLUSTER in item.reason_codes
               for item in annotations)
    assert all(MNEMONIC_SAME_END_MULTIPLE_LENGTHS in item.reason_codes
               for item in annotations)
    assert all(MNEMONIC_WORDLIST_REGION_LIKELY not in item.reason_codes
               for item in annotations)


def test_case_b_same_start_plus_nearby_valid_is_dense_wordlist_region():
    items = (
        occurrence(53_172_166_176, 53_172_166_222, "fp-12a", words=12,
                   language="chinese_simplified", encoding="utf-16-le"),
        occurrence(53_172_166_176, 53_172_166_234, "fp-15", words=15,
                   language="chinese_simplified", encoding="utf-16-le"),
        occurrence(53_172_166_716, 53_172_166_762, "fp-12b", words=12,
                   language="chinese_simplified", encoding="utf-16-le"),
    )
    annotations = correlate_mnemonic_occurrences(items)
    assert all(item.recovery_relevance == LIKELY_WORDLIST_FALSE_POSITIVE
               for item in annotations)
    assert all(MNEMONIC_DENSE_SLIDING_WINDOWS in item.reason_codes
               for item in annotations)
    assert all(MNEMONIC_WORDLIST_REGION_LIKELY in item.reason_codes
               for item in annotations)
    assert MNEMONIC_SAME_START_MULTIPLE_LENGTHS in annotations[0].reason_codes
    assert MNEMONIC_SAME_START_MULTIPLE_LENGTHS in annotations[1].reason_codes


def test_many_ascii_sliding_windows_form_one_cluster():
    items = tuple(
        occurrence(40_000 + index * 8, 40_090 + index * 8, f"fp-{index}",
                   standard="BIP39" if index % 2 == 0 else "ELECTRUM",
                   encoding="utf-8")
        for index in range(100)
    )
    annotations = correlate_mnemonic_occurrences(items)
    assert len({item.cluster_id for item in annotations}) == 1
    assert all(item.cluster_size == 100 for item in annotations)
    assert all(item.recovery_relevance == LIKELY_WORDLIST_FALSE_POSITIVE
               for item in annotations)


def test_two_distant_real_mnemonics_remain_independent():
    annotations = correlate_mnemonic_occurrences((
        occurrence(1_000, 1_090, "fp-left"),
        occurrence(1_000_000, 1_000_090, "fp-right", standard="ELECTRUM"),
    ))
    assert all(item.recovery_relevance == INDEPENDENT_CANDIDATE
               for item in annotations)


def test_two_nearby_nonoverlapping_valid_mnemonics_are_not_degraded():
    annotations = correlate_mnemonic_occurrences((
        occurrence(2_000, 2_090, "fp-left"),
        occurrence(2_300, 2_390, "fp-right", standard="ELECTRUM"),
    ))
    assert all(item.recovery_relevance == INDEPENDENT_CANDIDATE
               for item in annotations)


def test_deterministic_under_input_reordering_for_utf16_mixed_standards():
    items = tuple(
        occurrence(80_000 + index * 12, 80_100 + index * 12, f"mixed-{index}",
                   standard="BIP39" if index % 2 else "ELECTRUM",
                   words=12 if index % 3 else 15,
                   language="chinese_simplified", encoding="utf-16-le")
        for index in range(12)
    )
    forward = correlate_mnemonic_occurrences(items)
    reversed_items = tuple(reversed(items))
    backward = correlate_mnemonic_occurrences(reversed_items)
    by_fingerprint = {
        item.fingerprint: annotation for item, annotation in zip(items, forward)
    }
    reversed_by_fingerprint = {
        item.fingerprint: annotation
        for item, annotation in zip(reversed_items, backward)
    }
    assert by_fingerprint == reversed_by_fingerprint


def test_statistics_keep_crypto_valid_and_relevance_counts_separate():
    items = (
        occurrence(10, 100, "review-a", standard="ELECTRUM", words=23),
        occurrence(50, 100, "review-b"),
        occurrence(10_000, 10_090, "independent"),
    )
    annotations = correlate_mnemonic_occurrences(items)
    stats = correlation_statistics(items, annotations)
    assert stats == {
        "crypto_valid_occurrences": 3,
        "independent_candidate_occurrences": 1,
        "overlap_cluster_occurrences": 2,
        "likely_wordlist_occurrences": 0,
        "likely_wordlist_unique_fingerprints": 0,
        "review_required_unique_fingerprints": 3,
    }


def test_full_image_summary_exposes_classification_without_changing_validity():
    findings = (
        raw_hit(10_000, 10_046, "fp-a", words=12, encoding="utf-16-le"),
        raw_hit(10_000, 10_058, "fp-b", words=15, encoding="utf-16-le"),
        raw_hit(10_540, 10_586, "fp-c", standard="ELECTRUM", words=12,
                encoding="utf-16-le"),
    )
    summary = FullImageRecoveryCoordinator._mnemonic_summary(findings)
    assert summary["candidates_total"] == 3
    assert summary["crypto_valid_occurrences"] == 3
    assert summary["likely_wordlist_occurrences"] == 3
    assert summary["likely_wordlist_unique_fingerprints"] == 3
    assert summary["review_required_unique_fingerprints"] == 0
    assert {item["validation_status"] for item in summary["candidates"]} == {
        "BIP39_VALID", "ELECTRUM_SEED_VALID",
    }
    assert all(item["safe_metadata"]["recovery_relevance"]
               == LIKELY_WORDLIST_FALSE_POSITIVE
               for item in summary["candidates"])


def test_large_dense_input_finishes_without_pairwise_comparison_pressure():
    items = tuple(
        occurrence(index * 8, index * 8 + 90, f"large-{index}")
        for index in range(10_000)
    )
    annotations = correlate_mnemonic_occurrences(items)
    assert len(annotations) == 10_000
    assert all(item.recovery_relevance == LIKELY_WORDLIST_FALSE_POSITIVE
               for item in annotations)
