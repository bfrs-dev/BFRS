"""Cross-check links between previously validated Berkeley DB pages."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.validators.berkeley_page import BerkeleyPageValidator
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor


_REASON_ORDER = (
    "no_valid_pages",
    "evidence_invalid",
    "grid_mismatch",
    "duplicate_page_number",
    "next_previous_mismatch",
    "previous_next_mismatch",
)


@dataclass(frozen=True, slots=True)
class BerkeleyChainResult:
    status: ValidationStatus
    page_count: int
    structural_page_count: int
    fragment_page_count: int
    confirmed_links: int
    missing_links: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _ActivePage:
    page_number: int
    previous_page: int
    next_page: int
    start_offset: int
    grid_valid: bool


class BerkeleyPageChainValidator:
    """Validate page geometry and reciprocal links without reading source bytes."""

    def __init__(self, anchor: BerkeleyAnchor) -> None:
        if anchor.database_base_offset < 0:
            raise ValueError("database_base_offset must not be negative")
        self.anchor = anchor

    def validate(
        self,
        results: Iterable[ValidationResult],
    ) -> BerkeleyChainResult:
        inputs = tuple(results)
        if any(not isinstance(result, ValidationResult) for result in inputs):
            raise ValueError("results must contain ValidationResult instances")
        if any(
            result.validator != BerkeleyPageValidator.name for result in inputs
        ):
            raise ValueError("all results must come from berkeley_page")
        if len({result.source for result in inputs}) > 1:
            raise ValueError("all results must have the same source")

        structural_count = sum(
            result.status is ValidationStatus.STRUCTURAL for result in inputs
        )
        fragment_count = sum(
            result.status is ValidationStatus.FRAGMENT for result in inputs
        )
        rejected_count = sum(
            result.status is ValidationStatus.REJECTED for result in inputs
        )
        active_inputs = tuple(
            result
            for result in inputs
            if result.status in (
                ValidationStatus.STRUCTURAL,
                ValidationStatus.FRAGMENT,
            )
        )

        reason_set: set[str] = set()
        if len(active_inputs) + rejected_count != len(inputs):
            reason_set.add("evidence_invalid")
        if not active_inputs:
            reason_set.add("no_valid_pages")

        parsed_pages: list[_ActivePage] = []
        for result in active_inputs:
            if not isinstance(result.evidence, dict):
                reason_set.add("evidence_invalid")
                continue
            page_number = self._nonnegative_integer(
                result.evidence.get("page_number")
            )
            previous_page = self._nonnegative_integer(
                result.evidence.get("previous_page")
            )
            next_page = self._nonnegative_integer(
                result.evidence.get("next_page")
            )
            if None in (page_number, previous_page, next_page):
                reason_set.add("evidence_invalid")
                continue

            expected_offset = (
                self.anchor.database_base_offset
                + page_number * self.anchor.page_size
            )
            grid_valid = result.start_offset == expected_offset
            if not grid_valid:
                reason_set.add("grid_mismatch")
            parsed_pages.append(
                _ActivePage(
                    page_number=page_number,
                    previous_page=previous_page,
                    next_page=next_page,
                    start_offset=result.start_offset,
                    grid_valid=grid_valid,
                )
            )

        page_number_counts = Counter(
            page.page_number for page in parsed_pages
        )
        if any(count > 1 for count in page_number_counts.values()):
            reason_set.add("duplicate_page_number")

        pages = {
            page.page_number: page
            for page in parsed_pages
            if page.grid_valid and page_number_counts[page.page_number] == 1
        }
        confirmed_link_pairs: set[tuple[int, int]] = set()
        missing_link_targets: set[int] = set()
        missing_link_count = 0

        for page_number, page in sorted(pages.items()):
            if page.next_page != 0:
                target = pages.get(page.next_page)
                if target is None:
                    missing_link_count += 1
                    missing_link_targets.add(page.next_page)
                elif target.previous_page != page_number:
                    reason_set.add("next_previous_mismatch")
                else:
                    confirmed_link_pairs.add((page_number, page.next_page))

            if page.previous_page != 0:
                target = pages.get(page.previous_page)
                if target is None:
                    missing_link_count += 1
                    missing_link_targets.add(page.previous_page)
                elif target.next_page != page_number:
                    reason_set.add("previous_next_mismatch")
                else:
                    confirmed_link_pairs.add((page.previous_page, page_number))

        reasons = tuple(
            reason for reason in _REASON_ORDER if reason in reason_set
        )
        if reasons:
            status = ValidationStatus.REJECTED
        elif structural_count >= 2 and confirmed_link_pairs:
            status = ValidationStatus.STRUCTURAL
        else:
            status = ValidationStatus.FRAGMENT

        evidence: dict[str, Any] = {
            "page_numbers": tuple(
                sorted(page.page_number for page in parsed_pages)
            ),
            "confirmed_links": tuple(sorted(confirmed_link_pairs)),
            "missing_link_targets": tuple(sorted(missing_link_targets)),
            "rejected_input_count": rejected_count,
        }
        return BerkeleyChainResult(
            status=status,
            page_count=len(inputs),
            structural_page_count=structural_count,
            fragment_page_count=fragment_count,
            confirmed_links=len(confirmed_link_pairs),
            missing_links=missing_link_count,
            reasons=reasons,
            evidence=evidence,
        )

    @staticmethod
    def _nonnegative_integer(value: object) -> int | None:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return None
