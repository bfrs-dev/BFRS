"""Deterministic, secret-free post-validation mnemonic correlation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable


INDEPENDENT_CANDIDATE = "INDEPENDENT_CANDIDATE"
CONTEXT_REVIEW = "CONTEXT_REVIEW"
LIKELY_WORDLIST_FALSE_POSITIVE = "LIKELY_WORDLIST_FALSE_POSITIVE"

MNEMONIC_OVERLAP_CLUSTER = "MNEMONIC_OVERLAP_CLUSTER"
MNEMONIC_SAME_START_MULTIPLE_LENGTHS = "MNEMONIC_SAME_START_MULTIPLE_LENGTHS"
MNEMONIC_SAME_END_MULTIPLE_LENGTHS = "MNEMONIC_SAME_END_MULTIPLE_LENGTHS"
MNEMONIC_DENSE_SLIDING_WINDOWS = "MNEMONIC_DENSE_SLIDING_WINDOWS"
MNEMONIC_WORDLIST_REGION_LIKELY = "MNEMONIC_WORDLIST_REGION_LIKELY"

_NEARBY_GAP = 1024
_COMPACT_REGION_BYTES = 4096


@dataclass(frozen=True, slots=True)
class CorrelationOccurrence:
    physical_start: int | None
    physical_end: int | None
    fingerprint: str
    standard: str
    word_count: int
    language: str | None = None
    encoding: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelationAnnotation:
    recovery_relevance: str = INDEPENDENT_CANDIDATE
    reason_codes: tuple[str, ...] = ()
    cluster_id: str | None = None
    cluster_size: int = 1
    cluster_start: int | None = None
    cluster_end: int | None = None

    def safe_metadata(self) -> dict[str, object]:
        if self.cluster_id is None:
            return {"recovery_relevance": self.recovery_relevance}
        return {
            "recovery_relevance": self.recovery_relevance,
            "mnemonic_cluster_id": self.cluster_id,
            "mnemonic_cluster_size": self.cluster_size,
            "mnemonic_cluster_start": self.cluster_start,
            "mnemonic_cluster_end": self.cluster_end,
        }


def _cluster_id(items: list[tuple[int, CorrelationOccurrence]]) -> str:
    safe_key = tuple(
        (item.physical_start, item.physical_end, item.standard, item.word_count,
         item.fingerprint, item.language, item.encoding)
        for _, item in items
    )
    digest = hashlib.sha256(repr(safe_key).encode("utf-8")).hexdigest()[:16]
    return f"mnemonic-cluster-{digest}"


def _regular_starts(items: list[tuple[int, CorrelationOccurrence]]) -> bool:
    starts = sorted({item.physical_start for _, item in items
                     if item.physical_start is not None})
    deltas = [right - left for left, right in zip(starts, starts[1:])]
    if len(deltas) < 2 or min(deltas) <= 0:
        return False
    ordered = sorted(deltas)
    median = ordered[len(ordered) // 2]
    return sum(delta <= median * 2 for delta in deltas) * 5 >= len(deltas) * 4


def _physical_regions(
    indexed: list[tuple[int, CorrelationOccurrence]],
) -> list[list[tuple[int, CorrelationOccurrence]]]:
    regions: list[list[tuple[int, CorrelationOccurrence]]] = []
    current: list[tuple[int, CorrelationOccurrence]] = []
    furthest_end = -1
    for pair in indexed:
        item = pair[1]
        assert item.physical_start is not None and item.physical_end is not None
        if current and item.physical_start - furthest_end > _NEARBY_GAP:
            regions.append(current)
            current = []
            furthest_end = -1
        current.append(pair)
        furthest_end = max(furthest_end, item.physical_end)
    if current:
        regions.append(current)
    return regions


def correlate_mnemonic_occurrences(
    occurrences: Iterable[CorrelationOccurrence],
) -> tuple[CorrelationAnnotation, ...]:
    """Classify crypto-valid occurrences in O(n log n), without phrase access."""
    values = tuple(occurrences)
    annotations = [CorrelationAnnotation() for _ in values]
    indexed = [
        (index, item) for index, item in enumerate(values)
        if item.physical_start is not None and item.physical_end is not None
    ]
    indexed.sort(key=lambda pair: (
        pair[1].physical_start, pair[1].physical_end, pair[1].standard,
        pair[1].word_count, pair[1].fingerprint, pair[1].language or "",
        pair[1].encoding or ""))

    for region in _physical_regions(indexed):
        if len(region) < 2:
            continue
        starts: dict[int, list[tuple[int, CorrelationOccurrence]]] = {}
        ends: dict[int, list[tuple[int, CorrelationOccurrence]]] = {}
        for pair in region:
            starts.setdefault(pair[1].physical_start, []).append(pair)
            ends.setdefault(pair[1].physical_end, []).append(pair)

        overlap_members: set[int] = set()
        component: list[tuple[int, CorrelationOccurrence]] = []
        component_max_end = -1
        for pair in region:
            start = pair[1].physical_start
            end = pair[1].physical_end
            assert start is not None and end is not None
            if component and start >= component_max_end:
                if len(component) > 1:
                    overlap_members.update(item[0] for item in component)
                component = []
                component_max_end = -1
            component.append(pair)
            component_max_end = max(component_max_end, end)
        if len(component) > 1:
            overlap_members.update(item[0] for item in component)

        same_start_members = {
            pair[0] for group in starts.values() if len(group) > 1 for pair in group
            if len({item[1].word_count for item in group}) > 1
        }
        same_end_members = {
            pair[0] for group in ends.values() if len(group) > 1 for pair in group
            if len({item[1].word_count for item in group}) > 1
        }
        start = min(item.physical_start for _, item in region)
        end = max(item.physical_end for _, item in region)
        assert start is not None and end is not None
        compact = end - start <= max(_COMPACT_REGION_BYTES, len(region) * 512)
        fingerprints = {item.fingerprint for _, item in region}
        word_counts = {item.word_count for _, item in region}
        distinct_starts = len(starts)
        boundary_variant = bool(same_start_members or same_end_members)
        dense = (
            len(region) >= 3 and compact and boundary_variant and
            (len(word_counts) > 1 or len(fingerprints) > 1)
        ) or (
            len(region) >= 4 and compact and distinct_starts >= 3 and
            len(fingerprints) >= 3 and _regular_starts(region)
        )
        classified = set(range(len(region))) if dense else {
            position for position, pair in enumerate(region)
            if pair[0] in overlap_members or pair[0] in same_start_members
            or pair[0] in same_end_members
        }
        if not classified:
            continue
        cluster_items = region if dense else [region[position] for position in classified]
        cluster = _cluster_id(cluster_items)
        cluster_start = min(item.physical_start for _, item in cluster_items)
        cluster_end = max(item.physical_end for _, item in cluster_items)
        for position, (original_index, _) in enumerate(region):
            if position not in classified:
                continue
            reasons: list[str] = []
            if original_index in overlap_members:
                reasons.append(MNEMONIC_OVERLAP_CLUSTER)
            if original_index in same_start_members:
                reasons.append(MNEMONIC_SAME_START_MULTIPLE_LENGTHS)
            if original_index in same_end_members:
                reasons.append(MNEMONIC_SAME_END_MULTIPLE_LENGTHS)
            if dense:
                reasons.extend((MNEMONIC_DENSE_SLIDING_WINDOWS,
                                MNEMONIC_WORDLIST_REGION_LIKELY))
            annotations[original_index] = CorrelationAnnotation(
                recovery_relevance=(LIKELY_WORDLIST_FALSE_POSITIVE
                                    if dense else CONTEXT_REVIEW),
                reason_codes=tuple(dict.fromkeys(reasons)),
                cluster_id=cluster,
                cluster_size=len(cluster_items),
                cluster_start=cluster_start,
                cluster_end=cluster_end,
            )
    return tuple(annotations)


def correlation_statistics(
    occurrences: Iterable[CorrelationOccurrence],
    annotations: Iterable[CorrelationAnnotation],
) -> dict[str, int]:
    pairs = tuple(zip(occurrences, annotations))
    likely_fingerprints = {
        item.fingerprint for item, annotation in pairs
        if annotation.recovery_relevance == LIKELY_WORDLIST_FALSE_POSITIVE
    }
    review_fingerprints = {
        item.fingerprint for item, annotation in pairs
        if annotation.recovery_relevance != LIKELY_WORDLIST_FALSE_POSITIVE
    }
    return {
        "crypto_valid_occurrences": len(pairs),
        "independent_candidate_occurrences": sum(
            annotation.recovery_relevance == INDEPENDENT_CANDIDATE
            for _, annotation in pairs),
        "overlap_cluster_occurrences": sum(
            MNEMONIC_OVERLAP_CLUSTER in annotation.reason_codes
            or MNEMONIC_SAME_START_MULTIPLE_LENGTHS in annotation.reason_codes
            or MNEMONIC_SAME_END_MULTIPLE_LENGTHS in annotation.reason_codes
            for _, annotation in pairs),
        "likely_wordlist_occurrences": sum(
            annotation.recovery_relevance == LIKELY_WORDLIST_FALSE_POSITIVE
            for _, annotation in pairs),
        "likely_wordlist_unique_fingerprints": len(likely_fingerprints),
        "review_required_unique_fingerprints": len(review_fingerprints),
    }
