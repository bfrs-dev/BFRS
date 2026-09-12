"""Hard admission rules for hotspots entering structural validation."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from bfrs.core.models import Hotspot
from bfrs.validators.evidence_strength import EvidenceStrength


@dataclass(frozen=True, slots=True)
class CandidateDecision:
    accepted: bool
    reasons: tuple[str, ...]
    hit_count: int
    distinct_types: tuple[str, ...]
    signal_span: int


class CandidatePolicy:
    def __init__(
        self,
        min_hits: int = 2,
        min_distinct_types: int = 2,
        max_signal_span: int | None = None,
        required_groups: Iterable[Iterable[str]] = (),
    ) -> None:
        if min_hits < 1:
            raise ValueError("min_hits must be at least one")
        if min_distinct_types < 1:
            raise ValueError("min_distinct_types must be at least one")
        if max_signal_span is not None and max_signal_span < 0:
            raise ValueError("max_signal_span must not be negative")

        groups: list[frozenset[str]] = []
        for group in required_groups:
            if isinstance(group, (str, bytes)):
                raise ValueError("required groups must contain signal type names")
            try:
                names = tuple(group)
            except TypeError as error:
                raise ValueError("required groups must be iterable") from error
            if not names:
                raise ValueError("required groups must not be empty")
            if any(not isinstance(name, str) or not name for name in names):
                raise ValueError("required group names must be non-empty strings")
            groups.append(frozenset(names))

        self.min_hits = min_hits
        self.min_distinct_types = min_distinct_types
        self.max_signal_span = max_signal_span
        self.required_groups = tuple(groups)

    def evaluate(self, hotspot: Hotspot) -> CandidateDecision:
        hit_count, hit_types, hit_offsets = self._validated_evidence(hotspot)
        distinct_types = tuple(sorted(set(hit_types)))
        signal_span = max(hit_offsets) - min(hit_offsets) if hit_offsets else 0

        target_aware = self._target_aware_evidence(hotspot, hit_types)
        strongest = max(
            (item[3] for item in target_aware),
            default=EvidenceStrength.WEAK,
        )
        independent_by_target: dict[str, set[tuple[str, str]]] = {}
        for target, artifact_kind, hit_type, _ in target_aware:
            independent_by_target.setdefault(target, set()).add(
                (artifact_kind, hit_type)
            )
        correlated_target = any(
            len(identities) >= 2
            for target, identities in independent_by_target.items()
            if target != "unknown"
        )

        reasons: list[str] = []
        strong_single = strongest >= EvidenceStrength.STRONG
        if hit_count < self.min_hits and not strong_single:
            reasons.append("insufficient_hits")
        if len(distinct_types) < self.min_distinct_types and not strong_single:
            reasons.append("insufficient_distinct_types")
        if target_aware and not strong_single and not correlated_target:
            reasons.append("weak_evidence_requires_independent_corroboration")
        if any(group.isdisjoint(distinct_types) for group in self.required_groups):
            reasons.append("missing_required_group")
        if self.max_signal_span is not None and signal_span > self.max_signal_span:
            reasons.append("signal_span_too_large")

        return CandidateDecision(
            accepted=not reasons,
            reasons=tuple(reasons),
            hit_count=hit_count,
            distinct_types=distinct_types,
            signal_span=signal_span,
        )

    @staticmethod
    def _target_aware_evidence(
        hotspot: Hotspot,
        hit_types: tuple[str, ...],
    ) -> tuple[tuple[str, str, str, EvidenceStrength], ...]:
        evidence = hotspot.evidence
        keys = (
            "hit_targets",
            "hit_artifact_kinds",
            "hit_evidence_strengths",
        )
        if not any(key in evidence for key in keys):
            return ()
        if not all(key in evidence for key in keys):
            raise ValueError("target-aware evidence fields must be complete")
        targets = evidence["hit_targets"]
        artifact_kinds = evidence["hit_artifact_kinds"]
        strengths = evidence["hit_evidence_strengths"]
        for name, values in (
            ("hit_targets", targets),
            ("hit_artifact_kinds", artifact_kinds),
            ("hit_evidence_strengths", strengths),
        ):
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                raise ValueError(f"evidence {name} must be a sequence")
            if len(values) != len(hit_types):
                raise ValueError(f"evidence {name} count does not match hits")
            if any(not isinstance(value, str) or not value for value in values):
                raise ValueError(f"evidence {name} values must be non-empty strings")
        try:
            normalized_strengths = tuple(EvidenceStrength[name] for name in strengths)
        except KeyError as error:
            raise ValueError("unknown evidence strength") from error
        if all(target == "unknown" for target in targets):
            return ()
        return tuple(zip(
            tuple(targets), tuple(artifact_kinds), hit_types,
            normalized_strengths, strict=True,
        ))

    @staticmethod
    def _validated_evidence(
        hotspot: Hotspot,
    ) -> tuple[int, tuple[str, ...], tuple[int, ...]]:
        evidence = hotspot.evidence
        if not isinstance(evidence, Mapping):
            raise ValueError("hotspot evidence must be a mapping")
        hit_count = evidence.get("hit_count")
        hit_types = evidence.get("hit_types")
        hit_offsets = evidence.get("hit_offsets")

        if type(hit_count) is not int or hit_count < 0:
            raise ValueError("evidence hit_count must be a non-negative integer")
        if not isinstance(hit_types, Sequence) or isinstance(hit_types, (str, bytes)):
            raise ValueError("evidence hit_types must be a sequence")
        if not isinstance(hit_offsets, Sequence) or isinstance(
            hit_offsets, (str, bytes)
        ):
            raise ValueError("evidence hit_offsets must be a sequence")

        normalized_types = tuple(hit_types)
        normalized_offsets = tuple(hit_offsets)
        if any(not isinstance(name, str) or not name for name in normalized_types):
            raise ValueError("evidence hit types must be non-empty strings")
        if any(type(offset) is not int or offset < 0 for offset in normalized_offsets):
            raise ValueError("evidence hit offsets must be non-negative integers")
        if len(normalized_types) != len(normalized_offsets):
            raise ValueError("evidence hit type and offset counts must match")
        if hit_count != len(normalized_types):
            raise ValueError("evidence hit_count does not match its entries")

        return hit_count, normalized_types, normalized_offsets
