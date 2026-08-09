"""Locate Berkeley DB pages on a grid established by metadata."""

from dataclasses import dataclass

from bfrs.core.models import ValidationResult
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import is_valid_page_size
from bfrs.validators.berkeley_page import BerkeleyPageValidator


@dataclass(frozen=True, slots=True)
class BerkeleyAnchor:
    metadata_absolute_offset: int
    metadata_page_number: int
    page_size: int
    byte_order: str

    def __post_init__(self) -> None:
        if self.metadata_absolute_offset < 0:
            raise ValueError("metadata_absolute_offset must not be negative")
        if self.metadata_page_number < 0:
            raise ValueError("metadata_page_number must not be negative")
        if not is_valid_page_size(self.page_size):
            raise ValueError("page_size must be a power of two from 512 to 65536")
        if self.byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")

    @property
    def database_base_offset(self) -> int:
        return (
            self.metadata_absolute_offset
            - self.metadata_page_number * self.page_size
        )


class BerkeleyPageLocator:
    """Validate page slices only at positions implied by a metadata anchor."""

    def __init__(self, anchor: BerkeleyAnchor) -> None:
        if anchor.database_base_offset < 0:
            raise ValueError("database_base_offset must not be negative")
        self.anchor = anchor

    def locate(self, context: ValidationContext) -> tuple[ValidationResult, ...]:
        base_offset = self.anchor.database_base_offset
        first_candidate_offset = max(context.start_offset, base_offset)
        distance_from_base = first_candidate_offset - base_offset
        pages_from_base = (
            distance_from_base + self.anchor.page_size - 1
        ) // self.anchor.page_size
        page_start = base_offset + pages_from_base * self.anchor.page_size

        results: list[ValidationResult] = []
        while page_start < context.end_offset:
            page_number = self._page_number_at(page_start)
            is_metadata_anchor = (
                page_start == self.anchor.metadata_absolute_offset
                and page_number == self.anchor.metadata_page_number
            )
            if not is_metadata_anchor:
                local_start = page_start - context.start_offset
                page_data = context.data[
                    local_start : local_start + self.anchor.page_size
                ]
                page_context = ValidationContext(
                    source=context.source,
                    start_offset=page_start,
                    data=page_data,
                )
                validator = BerkeleyPageValidator(
                    page_size=self.anchor.page_size,
                    byte_order=self.anchor.byte_order,
                    expected_page_number=page_number,
                )
                results.append(validator.validate(page_context))
            page_start += self.anchor.page_size

        return tuple(results)

    def _page_number_at(self, absolute_offset: int) -> int:
        distance_from_base = absolute_offset - self.anchor.database_base_offset
        if distance_from_base < 0 or distance_from_base % self.anchor.page_size:
            raise ValueError("absolute_offset is not on the Berkeley page grid")
        return distance_from_base // self.anchor.page_size
