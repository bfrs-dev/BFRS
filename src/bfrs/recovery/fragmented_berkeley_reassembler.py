"""Reassemble Berkeley B-trees from validated physical page candidates."""

from collections.abc import Iterable
from dataclasses import dataclass, field
import ntpath
from typing import Any

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.recovery.berkeley_internal import BerkeleyInternalPageExtractor
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReader
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import BerkeleyMetadataValidator
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    BerkeleyPageValidator,
)


def _normalized_source(source: str) -> str:
    if not source:
        raise ValueError("source must not be empty")
    return ntpath.normcase(ntpath.normpath(source))


def _evidence_integer(
    validation: ValidationResult,
    name: str,
) -> int:
    value = validation.evidence.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"validation evidence {name} must be nonnegative integer")
    return value


def _evidence_string(
    validation: ValidationResult,
    name: str,
) -> str:
    value = validation.evidence.get(name)
    if not isinstance(value, str):
        raise ValueError(f"validation evidence {name} must be string")
    return value


@dataclass(frozen=True, slots=True)
class PhysicalBerkeleyPageCandidate:
    source: str
    physical_offset: int
    page_size: int
    byte_order: str
    validation: ValidationResult
    page_number: int = field(init=False)
    page_type: int = field(init=False)
    level: int = field(init=False)

    def __post_init__(self) -> None:
        normalized_source = _normalized_source(self.source)
        object.__setattr__(self, "source", normalized_source)
        if self.physical_offset < 0:
            raise ValueError("physical_offset must not be negative")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        if self.byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")
        if self.validation.validator != BerkeleyPageValidator.name:
            raise ValueError("validation must come from berkeley_page")
        if _normalized_source(self.validation.source) != normalized_source:
            raise ValueError("validation source does not match candidate source")
        if self.validation.start_offset != self.physical_offset:
            raise ValueError("validation offset does not match physical_offset")
        if not (
            self.physical_offset
            <= self.validation.end_offset
            <= self.physical_offset + self.page_size
        ):
            raise ValueError("validation range is outside candidate page")
        if _evidence_integer(self.validation, "page_size") != self.page_size:
            raise ValueError("validation page_size does not match candidate")
        if _evidence_string(self.validation, "byte_order") != self.byte_order:
            raise ValueError("validation byte_order does not match candidate")
        object.__setattr__(
            self,
            "page_number",
            _evidence_integer(self.validation, "page_number"),
        )
        object.__setattr__(
            self,
            "page_type",
            _evidence_integer(self.validation, "page_type"),
        )
        object.__setattr__(
            self,
            "level",
            _evidence_integer(self.validation, "level"),
        )


@dataclass(frozen=True, slots=True)
class PhysicalBerkeleyMetadataCandidate:
    source: str
    physical_offset: int
    metadata_page_number: int
    page_size: int
    byte_order: str
    root_page: int
    validation: ValidationResult

    def __post_init__(self) -> None:
        normalized_source = _normalized_source(self.source)
        object.__setattr__(self, "source", normalized_source)
        if self.physical_offset < 0:
            raise ValueError("physical_offset must not be negative")
        if self.metadata_page_number < 0:
            raise ValueError("metadata_page_number must not be negative")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        if self.byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")
        if self.root_page <= 0:
            raise ValueError("root_page must be positive")
        if self.validation.validator != BerkeleyMetadataValidator.name:
            raise ValueError("validation must come from berkeley_metadata")
        if _normalized_source(self.validation.source) != normalized_source:
            raise ValueError("validation source does not match metadata source")
        if self.validation.start_offset != self.physical_offset:
            raise ValueError("validation offset does not match physical_offset")
        if _evidence_integer(
            self.validation, "page_number"
        ) != self.metadata_page_number:
            raise ValueError("metadata page number does not match validation")
        if _evidence_integer(self.validation, "page_size") != self.page_size:
            raise ValueError("metadata page_size does not match validation")
        if _evidence_string(self.validation, "byte_order") != self.byte_order:
            raise ValueError("metadata byte_order does not match validation")
        if _evidence_integer(self.validation, "root_page") != self.root_page:
            raise ValueError("metadata root_page does not match validation")


@dataclass(frozen=True, slots=True)
class ReconstructedBerkeleyDatabaseIdentity:
    source: str
    metadata_physical_offset: int
    metadata_page_number: int
    root_page_number: int
    page_size: int
    byte_order: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _normalized_source(self.source))
        if self.metadata_physical_offset < 0:
            raise ValueError("metadata_physical_offset must not be negative")
        if self.metadata_page_number < 0:
            raise ValueError("metadata_page_number must not be negative")
        if self.root_page_number <= 0:
            raise ValueError("root_page_number must be positive")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        if self.byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")


@dataclass(frozen=True, slots=True)
class ReconstructedBerkeleyPage:
    page_number: int
    physical_offset: int
    page_size: int
    page_type: int
    level: int
    validation_status: ValidationStatus


@dataclass(frozen=True, slots=True)
class ReconstructedBerkeleyDatabase:
    identity: ReconstructedBerkeleyDatabaseIdentity
    status: ValidationStatus
    selected_pages: tuple[ReconstructedBerkeleyPage, ...]
    internal_page_numbers: tuple[int, ...]
    leaf_page_numbers: tuple[int, ...]
    missing_page_numbers: tuple[int, ...]
    ambiguous_page_numbers: tuple[int, ...]
    rejected_page_numbers: tuple[int, ...]
    confirmed_edge_count: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _CandidateResolution:
    kind: str
    selected: PhysicalBerkeleyPageCandidate | None = None
    offsets: tuple[int, ...] = ()


class FragmentedBerkeleyPageReassembler:
    """Traverse reconstructed trees without a physical database grid."""

    def __init__(
        self,
        page_candidates: Iterable[PhysicalBerkeleyPageCandidate],
        *,
        range_reader: PhysicalRangeReader,
    ) -> None:
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        candidates = tuple(page_candidates)
        if any(
            not isinstance(candidate, PhysicalBerkeleyPageCandidate)
            for candidate in candidates
        ):
            raise ValueError(
                "page_candidates must contain PhysicalBerkeleyPageCandidate"
            )
        self.range_reader = range_reader
        self.page_index = self._build_index(candidates)

    def reconstruct(
        self,
        metadata_candidates: Iterable[PhysicalBerkeleyMetadataCandidate],
    ) -> tuple[ReconstructedBerkeleyDatabase, ...]:
        metadata = tuple(metadata_candidates)
        if any(
            not isinstance(candidate, PhysicalBerkeleyMetadataCandidate)
            for candidate in metadata
        ):
            raise ValueError(
                "metadata_candidates must contain metadata candidates"
            )
        unique_metadata = self._deduplicate_metadata(metadata)
        structural = tuple(
            candidate
            for candidate in unique_metadata
            if candidate.validation.status is ValidationStatus.STRUCTURAL
        )
        return tuple(
            self._reconstruct_one(candidate)
            for candidate in sorted(structural, key=self._metadata_sort_key)
        )

    def run(
        self,
        metadata_candidates: Iterable[PhysicalBerkeleyMetadataCandidate],
    ) -> tuple[ReconstructedBerkeleyDatabase, ...]:
        return self.reconstruct(metadata_candidates)

    def reassemble(
        self,
        metadata_candidates: Iterable[PhysicalBerkeleyMetadataCandidate],
    ) -> tuple[ReconstructedBerkeleyDatabase, ...]:
        return self.reconstruct(metadata_candidates)

    def _reconstruct_one(
        self,
        metadata: PhysicalBerkeleyMetadataCandidate,
    ) -> ReconstructedBerkeleyDatabase:
        identity = ReconstructedBerkeleyDatabaseIdentity(
            source=metadata.source,
            metadata_physical_offset=metadata.physical_offset,
            metadata_page_number=metadata.metadata_page_number,
            root_page_number=metadata.root_page,
            page_size=metadata.page_size,
            byte_order=metadata.byte_order,
        )
        root_resolution = self._resolve_candidate(
            metadata.root_page,
            identity,
            expected_level=None,
        )
        if root_resolution.kind == "ambiguous":
            return self._result(
                identity,
                ValidationStatus.FRAGMENT,
                selected={},
                internal=set(),
                leaves=set(),
                missing=set(),
                ambiguous={metadata.root_page: root_resolution.offsets},
                rejected=set(),
                edges=set(),
                fragments=set(),
                reasons=("ambiguous_root_page",),
            )
        if root_resolution.kind == "missing":
            return self._result(
                identity,
                ValidationStatus.REJECTED,
                selected={},
                internal=set(),
                leaves=set(),
                missing={metadata.root_page},
                ambiguous={},
                rejected=set(),
                edges=set(),
                fragments=set(),
                reasons=("root_page_missing",),
            )
        if root_resolution.kind == "rejected":
            return self._result(
                identity,
                ValidationStatus.REJECTED,
                selected={},
                internal=set(),
                leaves=set(),
                missing=set(),
                ambiguous={},
                rejected={metadata.root_page},
                edges=set(),
                fragments=set(),
                reasons=("root_page_rejected",),
            )
        root = root_resolution.selected
        if root is None:
            raise RuntimeError("selected root resolution omitted candidate")

        selected: dict[int, PhysicalBerkeleyPageCandidate] = {
            root.page_number: root
        }
        internal: set[int] = set()
        leaves: set[int] = set()
        missing: set[int] = set()
        ambiguous: dict[int, tuple[int, ...]] = {}
        rejected: set[int] = set()
        fragments: set[int] = set()
        edges: set[tuple[int, int]] = set()
        hard_reasons: set[str] = set()
        parents: dict[int, int | None] = {root.page_number: None}
        processed: set[int] = set()
        stack: list[
            tuple[PhysicalBerkeleyPageCandidate, int, tuple[int, ...]]
        ] = [(root, root.level, ())]

        while stack:
            candidate, expected_level, ancestors = stack.pop()
            page_number = candidate.page_number
            if page_number in processed:
                continue
            processed.add(page_number)
            if candidate.validation.status is ValidationStatus.FRAGMENT:
                fragments.add(page_number)
            if candidate.level != expected_level:
                hard_reasons.add("page_level_mismatch")
                rejected.add(page_number)
                continue
            if candidate.page_type == BTREE_LEAF:
                if candidate.level != 1:
                    hard_reasons.add("leaf_level_invalid")
                    rejected.add(page_number)
                else:
                    leaves.add(page_number)
                continue
            if candidate.page_type != BTREE_INTERNAL:
                hard_reasons.add("unexpected_reachable_page_type")
                rejected.add(page_number)
                continue

            internal.add(page_number)
            extraction = self._extract_internal(candidate, identity)
            if extraction is None:
                hard_reasons.add("internal_page_read_failed")
                rejected.add(page_number)
                continue
            if extraction.page_status is ValidationStatus.REJECTED:
                hard_reasons.add("internal_page_extraction_rejected")
                rejected.add(page_number)
                continue
            if extraction.page_level != candidate.level:
                hard_reasons.add("internal_page_level_mismatch")
                rejected.add(page_number)
                continue
            if extraction.page_status is ValidationStatus.FRAGMENT:
                fragments.add(page_number)

            child_numbers = tuple(
                sorted(set(extraction.active_child_page_numbers), reverse=True)
            )
            for child in child_numbers:
                edges.add((page_number, child))
                if child == page_number:
                    hard_reasons.add("self_reference")
                    continue
                if child in ancestors:
                    hard_reasons.add("cycle_detected")
                    continue
                existing_parent = parents.get(child)
                if child in parents:
                    if existing_parent != page_number:
                        hard_reasons.add("multiple_parents")
                    continue
                parents[child] = page_number

                resolution = self._resolve_candidate(
                    child,
                    identity,
                    expected_level=candidate.level - 1,
                )
                if resolution.kind == "missing":
                    missing.add(child)
                    continue
                if resolution.kind == "ambiguous":
                    ambiguous[child] = resolution.offsets
                    continue
                if resolution.kind == "rejected":
                    rejected.add(child)
                    continue
                child_candidate = resolution.selected
                if child_candidate is None:
                    raise RuntimeError("selected resolution omitted candidate")
                selected[child] = child_candidate
                stack.append(
                    (
                        child_candidate,
                        candidate.level - 1,
                        ancestors + (page_number,),
                    )
                )

        if hard_reasons:
            status = ValidationStatus.REJECTED
            reasons = tuple(sorted(hard_reasons))
        elif missing or ambiguous or rejected or fragments:
            status = ValidationStatus.FRAGMENT
            reason_list: list[str] = []
            if missing:
                reason_list.append("referenced_page_missing")
            if ambiguous:
                reason_list.append("referenced_page_ambiguous")
            if rejected:
                reason_list.append("referenced_page_rejected")
            if fragments:
                reason_list.append("selected_page_fragment")
            reasons = tuple(reason_list)
        elif not leaves:
            status = ValidationStatus.REJECTED
            reasons = ("no_reachable_leaf",)
        else:
            status = ValidationStatus.STRUCTURAL
            reasons = ()

        return self._result(
            identity,
            status,
            selected=selected,
            internal=internal,
            leaves=leaves,
            missing=missing,
            ambiguous=ambiguous,
            rejected=rejected,
            edges=edges,
            fragments=fragments,
            reasons=reasons,
        )

    def _resolve_candidate(
        self,
        page_number: int,
        identity: ReconstructedBerkeleyDatabaseIdentity,
        *,
        expected_level: int | None,
    ) -> _CandidateResolution:
        candidates = tuple(
            candidate
            for candidate in self.page_index.get(page_number, ())
            if candidate.source == identity.source
            and candidate.page_size == identity.page_size
            and candidate.byte_order == identity.byte_order
            and self._level_and_type_match(candidate, expected_level)
        )
        structural = tuple(
            candidate
            for candidate in candidates
            if candidate.validation.status is ValidationStatus.STRUCTURAL
        )
        if len(structural) == 1:
            return _CandidateResolution("selected", structural[0])
        if len(structural) > 1:
            return _CandidateResolution(
                "ambiguous",
                offsets=tuple(
                    sorted(candidate.physical_offset for candidate in structural)
                ),
            )
        fragments = tuple(
            candidate
            for candidate in candidates
            if candidate.validation.status is ValidationStatus.FRAGMENT
        )
        if len(fragments) == 1:
            return _CandidateResolution("selected", fragments[0])
        if len(fragments) > 1:
            return _CandidateResolution(
                "ambiguous",
                offsets=tuple(
                    sorted(candidate.physical_offset for candidate in fragments)
                ),
            )
        if any(
            candidate.validation.status is ValidationStatus.REJECTED
            for candidate in candidates
        ):
            return _CandidateResolution("rejected")
        return _CandidateResolution("missing")

    def _extract_internal(
        self,
        candidate: PhysicalBerkeleyPageCandidate,
        identity: ReconstructedBerkeleyDatabaseIdentity,
    ):
        try:
            data = self.range_reader.read_at(
                candidate.physical_offset,
                candidate.page_size,
            )
        except OSError:
            return None
        if not isinstance(data, bytes) or len(data) > candidate.page_size:
            return None
        context = ValidationContext(
            source=identity.source,
            start_offset=candidate.physical_offset,
            data=data,
        )
        return BerkeleyInternalPageExtractor(
            candidate.page_size,
            candidate.byte_order,
            expected_page_number=candidate.page_number,
        ).extract(context)

    @staticmethod
    def _level_and_type_match(
        candidate: PhysicalBerkeleyPageCandidate,
        expected_level: int | None,
    ) -> bool:
        if expected_level is None:
            return candidate.page_type in (BTREE_INTERNAL, BTREE_LEAF)
        if expected_level == 1:
            return candidate.level == 1 and candidate.page_type == BTREE_LEAF
        if expected_level > 1:
            return (
                candidate.level == expected_level
                and candidate.page_type == BTREE_INTERNAL
            )
        return False

    @classmethod
    def _build_index(
        cls,
        candidates: tuple[PhysicalBerkeleyPageCandidate, ...],
    ) -> dict[int, tuple[PhysicalBerkeleyPageCandidate, ...]]:
        by_physical: dict[
            tuple[str, int, int, str], PhysicalBerkeleyPageCandidate
        ] = {}
        for candidate in candidates:
            identity = (
                candidate.source,
                candidate.physical_offset,
                candidate.page_size,
                candidate.byte_order,
            )
            existing = by_physical.setdefault(identity, candidate)
            if existing != candidate:
                raise ValueError("conflicting candidate at physical location")
        index: dict[int, list[PhysicalBerkeleyPageCandidate]] = {}
        for candidate in by_physical.values():
            index.setdefault(candidate.page_number, []).append(candidate)
        return {
            page_number: tuple(sorted(items, key=cls._candidate_sort_key))
            for page_number, items in sorted(index.items())
        }

    @staticmethod
    def _deduplicate_metadata(
        metadata: Iterable[PhysicalBerkeleyMetadataCandidate],
    ) -> tuple[PhysicalBerkeleyMetadataCandidate, ...]:
        unique: dict[
            tuple[str, int, int, str],
            PhysicalBerkeleyMetadataCandidate,
        ] = {}
        for candidate in metadata:
            physical_identity = (
                candidate.source,
                candidate.physical_offset,
                candidate.page_size,
                candidate.byte_order,
            )
            existing = unique.setdefault(physical_identity, candidate)
            if existing != candidate:
                raise ValueError(
                    "conflicting metadata candidate at physical location"
                )
        return tuple(unique.values())

    @staticmethod
    def _candidate_sort_key(
        candidate: PhysicalBerkeleyPageCandidate,
    ) -> tuple[int, str, int, int, str]:
        status_rank = {
            ValidationStatus.STRUCTURAL: 0,
            ValidationStatus.FRAGMENT: 1,
            ValidationStatus.REJECTED: 2,
        }[candidate.validation.status]
        return (
            candidate.physical_offset,
            candidate.source,
            status_rank,
            candidate.level,
            candidate.byte_order,
        )

    @staticmethod
    def _metadata_sort_key(
        candidate: PhysicalBerkeleyMetadataCandidate,
    ) -> tuple[str, int, int, int]:
        return (
            candidate.source,
            candidate.metadata_page_number,
            candidate.root_page,
            candidate.physical_offset,
        )

    @staticmethod
    def _result(
        identity: ReconstructedBerkeleyDatabaseIdentity,
        status: ValidationStatus,
        *,
        selected: dict[int, PhysicalBerkeleyPageCandidate],
        internal: set[int],
        leaves: set[int],
        missing: set[int],
        ambiguous: dict[int, tuple[int, ...]],
        rejected: set[int],
        edges: set[tuple[int, int]],
        fragments: set[int],
        reasons: tuple[str, ...],
    ) -> ReconstructedBerkeleyDatabase:
        selected_pages = tuple(
            ReconstructedBerkeleyPage(
                page_number=candidate.page_number,
                physical_offset=candidate.physical_offset,
                page_size=candidate.page_size,
                page_type=candidate.page_type,
                level=candidate.level,
                validation_status=candidate.validation.status,
            )
            for candidate in sorted(
                selected.values(),
                key=lambda item: (item.page_number, item.physical_offset),
            )
        )
        return ReconstructedBerkeleyDatabase(
            identity=identity,
            status=status,
            selected_pages=selected_pages,
            internal_page_numbers=tuple(sorted(internal)),
            leaf_page_numbers=tuple(sorted(leaves)),
            missing_page_numbers=tuple(sorted(missing)),
            ambiguous_page_numbers=tuple(sorted(ambiguous)),
            rejected_page_numbers=tuple(sorted(rejected)),
            confirmed_edge_count=len(edges),
            reasons=reasons,
            evidence={
                "confirmed_edges": tuple(sorted(edges)),
                "fragment_page_numbers": tuple(sorted(fragments)),
                "ambiguous_candidate_offsets": tuple(
                    (page_number, tuple(sorted(offsets)))
                    for page_number, offsets in sorted(ambiguous.items())
                ),
            },
        )
