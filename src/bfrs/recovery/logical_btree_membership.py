"""Resolve logical Berkeley subdatabase membership from B-tree topology."""

from dataclasses import dataclass
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_internal import BerkeleyInternalPageExtractor
from bfrs.recovery.logical_berkeley_reader import (
    LogicalBerkeleyDatabaseIdentity,
    LogicalBerkeleyMetadataAnchor,
    LogicalBerkeleyPageReader,
)
from bfrs.validators.berkeley_page import BTREE_INTERNAL, BTREE_LEAF


@dataclass(frozen=True, slots=True)
class LogicalBerkeleySubdatabaseIdentity:
    database: LogicalBerkeleyDatabaseIdentity
    metadata_page_number: int
    root_page_number: int
    page_size: int
    byte_order: str

    def __post_init__(self) -> None:
        if self.metadata_page_number < 0:
            raise ValueError("metadata_page_number must not be negative")
        if self.root_page_number <= 0:
            raise ValueError("root_page_number must be positive")
        if self.page_size != self.database.page_size:
            raise ValueError("page_size must match database identity")
        if self.byte_order != self.database.byte_order:
            raise ValueError("byte_order must match database identity")


@dataclass(frozen=True, slots=True)
class LogicalBtreeMembership:
    identity: LogicalBerkeleySubdatabaseIdentity
    status: ValidationStatus
    root_page_number: int
    reachable_page_numbers: tuple[int, ...]
    internal_page_numbers: tuple[int, ...]
    leaf_page_numbers: tuple[int, ...]
    overflow_page_numbers: tuple[int, ...]
    missing_page_numbers: tuple[int, ...]
    rejected_page_numbers: tuple[int, ...]
    confirmed_edge_count: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


class LogicalBtreeMembershipResolver:
    """Traverse one mapped logical B-tree from its validated metadata root."""

    def __init__(
        self,
        anchor: LogicalBerkeleyMetadataAnchor,
        page_reader: LogicalBerkeleyPageReader,
    ) -> None:
        if anchor.identity != page_reader.identity:
            raise ValueError("metadata anchor and page reader identities differ")
        self.anchor = anchor
        self.page_reader = page_reader
        self.identity = LogicalBerkeleySubdatabaseIdentity(
            database=anchor.identity,
            metadata_page_number=anchor.metadata_page_number,
            root_page_number=anchor.root_page,
            page_size=anchor.page_size,
            byte_order=anchor.byte_order,
        )

    def resolve(self) -> LogicalBtreeMembership:
        validated = {
            page.page_number: page
            for page in self.page_reader.validate_pages()
        }
        root = validated.get(self.anchor.root_page)
        if root is None:
            return self._result(
                ValidationStatus.REJECTED,
                reachable=(),
                internal=(),
                leaves=(),
                missing=(self.anchor.root_page,),
                rejected=(),
                edges=(),
                reasons=("root_page_missing",),
                fragments=(),
            )
        if root.validation.status is not ValidationStatus.STRUCTURAL:
            return self._result(
                ValidationStatus.REJECTED,
                reachable=(),
                internal=(),
                leaves=(),
                missing=(),
                rejected=(self.anchor.root_page,),
                edges=(),
                reasons=("root_page_invalid",),
                fragments=(),
            )

        root_level = self._evidence_integer(root.validation.evidence, "level")
        if root_level is None:
            return self._result(
                ValidationStatus.REJECTED,
                reachable=(),
                internal=(),
                leaves=(),
                missing=(),
                rejected=(self.anchor.root_page,),
                edges=(),
                reasons=("root_page_evidence_invalid",),
                fragments=(),
            )

        reachable: set[int] = set()
        internal: set[int] = set()
        leaves: set[int] = set()
        missing: set[int] = set()
        rejected: set[int] = set()
        fragments: set[int] = set()
        edges: set[tuple[int, int]] = set()
        hard_reasons: set[str] = set()
        parents: dict[int, int | None] = {self.anchor.root_page: None}
        stack: list[tuple[int, int, tuple[int, ...]]] = [
            (self.anchor.root_page, root_level, ())
        ]

        while stack:
            page_number, expected_level, ancestors = stack.pop()
            page = validated.get(page_number)
            if page is None:
                missing.add(page_number)
                continue
            if page.validation.status is ValidationStatus.REJECTED:
                rejected.add(page_number)
                continue
            if page.validation.status is ValidationStatus.FRAGMENT:
                fragments.add(page_number)

            level = self._evidence_integer(page.validation.evidence, "level")
            page_type = self._evidence_integer(
                page.validation.evidence,
                "page_type",
            )
            if level is None or page_type is None:
                hard_reasons.add("page_evidence_invalid")
                rejected.add(page_number)
                continue
            if level != expected_level:
                hard_reasons.add("page_level_mismatch")
                rejected.add(page_number)
                continue

            reachable.add(page_number)
            if page_type == BTREE_LEAF:
                if level != 1:
                    hard_reasons.add("leaf_level_invalid")
                    rejected.add(page_number)
                    leaves.discard(page_number)
                else:
                    leaves.add(page_number)
                continue
            if page_type != BTREE_INTERNAL:
                hard_reasons.add("unexpected_reachable_page_type")
                rejected.add(page_number)
                continue

            internal.add(page_number)
            context = self.page_reader.read_page_context(page_number)
            if context is None:
                rejected.add(page_number)
                fragments.add(page_number)
                continue
            extraction = BerkeleyInternalPageExtractor(
                self.identity.page_size,
                self.identity.byte_order,
                expected_page_number=page_number,
            ).extract(context)
            if extraction.page_status is ValidationStatus.REJECTED:
                hard_reasons.add("internal_page_extraction_rejected")
                rejected.add(page_number)
                continue
            if extraction.page_status is ValidationStatus.FRAGMENT:
                fragments.add(page_number)

            child_numbers = tuple(
                sorted(set(extraction.active_child_page_numbers), reverse=True)
            )
            for child in child_numbers:
                edge = (page_number, child)
                edges.add(edge)
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

                child_page = validated.get(child)
                if child_page is None:
                    missing.add(child)
                    continue
                if child_page.validation.status is ValidationStatus.REJECTED:
                    rejected.add(child)
                    continue
                stack.append(
                    (
                        child,
                        level - 1,
                        ancestors + (page_number,),
                    )
                )

        reasons: list[str] = sorted(hard_reasons)
        if hard_reasons:
            status = ValidationStatus.REJECTED
        elif missing or rejected or fragments:
            status = ValidationStatus.FRAGMENT
            if missing:
                reasons.append("referenced_page_missing")
            if rejected:
                reasons.append("referenced_page_rejected")
            if fragments:
                reasons.append("reachable_page_fragment")
        elif not leaves:
            status = ValidationStatus.REJECTED
            reasons.append("no_reachable_leaf")
        else:
            status = ValidationStatus.STRUCTURAL

        return self._result(
            status,
            reachable=tuple(sorted(reachable)),
            internal=tuple(sorted(internal)),
            leaves=tuple(sorted(leaves)),
            missing=tuple(sorted(missing)),
            rejected=tuple(sorted(rejected)),
            edges=tuple(sorted(edges)),
            reasons=tuple(reasons),
            fragments=tuple(sorted(fragments)),
        )

    def _result(
        self,
        status: ValidationStatus,
        *,
        reachable: tuple[int, ...],
        internal: tuple[int, ...],
        leaves: tuple[int, ...],
        missing: tuple[int, ...],
        rejected: tuple[int, ...],
        edges: tuple[tuple[int, int], ...],
        reasons: tuple[str, ...],
        fragments: tuple[int, ...],
    ) -> LogicalBtreeMembership:
        return LogicalBtreeMembership(
            identity=self.identity,
            status=status,
            root_page_number=self.anchor.root_page,
            reachable_page_numbers=reachable,
            internal_page_numbers=internal,
            leaf_page_numbers=leaves,
            overflow_page_numbers=(),
            missing_page_numbers=missing,
            rejected_page_numbers=rejected,
            confirmed_edge_count=len(edges),
            reasons=reasons,
            evidence={
                "confirmed_edges": edges,
                "fragment_page_numbers": fragments,
                "metadata_page_number": self.anchor.metadata_page_number,
            },
        )

    @staticmethod
    def _evidence_integer(evidence: dict[str, Any], name: str) -> int | None:
        value = evidence.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None
