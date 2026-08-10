"""Pure logical-to-physical mapping for Berkeley database pages."""

from collections.abc import Iterable
from dataclasses import dataclass
import ntpath

from bfrs.validators.berkeley_page_locator import BerkeleyAnchor


def _normalized_source(source: str) -> str:
    if not source:
        raise ValueError("source must not be empty")
    return ntpath.normcase(ntpath.normpath(source))


@dataclass(frozen=True, slots=True)
class LogicalPageLocation:
    page_number: int
    physical_offset: int
    page_size: int
    source: str

    def __post_init__(self) -> None:
        if self.page_number < 0:
            raise ValueError("page_number must not be negative")
        if self.physical_offset < 0:
            raise ValueError("physical_offset must not be negative")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        object.__setattr__(self, "source", _normalized_source(self.source))


@dataclass(frozen=True, slots=True)
class LogicalFileExtent:
    logical_start: int
    physical_start: int
    length: int

    def __post_init__(self) -> None:
        if self.logical_start < 0:
            raise ValueError("logical_start must not be negative")
        if self.physical_start < 0:
            raise ValueError("physical_start must not be negative")
        if self.length <= 0:
            raise ValueError("length must be positive")

    @property
    def logical_end(self) -> int:
        return self.logical_start + self.length


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyPageMapSummary:
    mapped_page_count: int
    missing_page_count: int
    first_page_number: int | None
    last_page_number: int | None
    physical_extent_count: int


@dataclass(frozen=True, slots=True, init=False)
class LogicalBerkeleyPageMap:
    source: str
    page_size: int
    byte_order: str
    _pages: tuple[LogicalPageLocation, ...]
    _missing_pages: tuple[int, ...]
    summary: LogicalBerkeleyPageMapSummary

    def __init__(
        self,
        source: str,
        page_size: int,
        byte_order: str,
        locations: Iterable[LogicalPageLocation],
    ) -> None:
        normalized_source = _normalized_source(source)
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        if byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")

        unique: dict[int, LogicalPageLocation] = {}
        for location in locations:
            if not isinstance(location, LogicalPageLocation):
                raise ValueError("locations must contain LogicalPageLocation instances")
            if location.source != normalized_source:
                raise ValueError("location source does not match map source")
            if location.page_size != page_size:
                raise ValueError("location page_size does not match map page_size")
            existing = unique.get(location.page_number)
            if existing is None:
                unique[location.page_number] = location
            elif existing != location:
                raise ValueError("conflicting physical location for logical page")

        pages = tuple(unique[number] for number in sorted(unique))
        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "page_size", page_size)
        object.__setattr__(self, "byte_order", byte_order)
        object.__setattr__(self, "_pages", pages)
        object.__setattr__(self, "_missing_pages", ())
        object.__setattr__(
            self,
            "summary",
            self._build_summary(pages, (), self._physical_run_count(pages)),
        )

    def locate(self, page_number: int) -> LogicalPageLocation | None:
        if page_number < 0:
            raise ValueError("page_number must not be negative")
        for location in self._pages:
            if location.page_number == page_number:
                return location
            if location.page_number > page_number:
                break
        return None

    def pages(self) -> tuple[LogicalPageLocation, ...]:
        return self._pages

    def missing_pages(self) -> tuple[int, ...]:
        return self._missing_pages

    @classmethod
    def from_anchor(
        cls,
        anchor: BerkeleyAnchor,
        page_numbers: Iterable[int],
        source: str,
    ) -> "LogicalBerkeleyPageMap":
        locations = (
            LogicalPageLocation(
                page_number=page_number,
                physical_offset=(
                    anchor.database_base_offset + page_number * anchor.page_size
                ),
                page_size=anchor.page_size,
                source=source,
            )
            for page_number in page_numbers
        )
        return cls(source, anchor.page_size, anchor.byte_order, locations)

    @classmethod
    def from_extents(
        cls,
        source: str,
        page_size: int,
        byte_order: str,
        extents: Iterable[LogicalFileExtent],
        logical_file_size: int | None = None,
    ) -> "LogicalBerkeleyPageMap":
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        input_extents = tuple(extents)
        if any(not isinstance(extent, LogicalFileExtent) for extent in input_extents):
            raise ValueError("extents must contain LogicalFileExtent instances")
        extent_tuple = tuple(
            sorted(set(input_extents), key=cls._extent_sort_key)
        )
        inferred_size = max((extent.logical_end for extent in extent_tuple), default=0)
        if logical_file_size is None:
            logical_file_size = inferred_size
        if logical_file_size < 0:
            raise ValueError("logical_file_size must not be negative")

        complete_page_count = logical_file_size // page_size
        locations: list[LogicalPageLocation] = []
        missing: list[int] = []
        for page_number in range(complete_page_count):
            logical_start = page_number * page_size
            logical_end = logical_start + page_size
            candidates = tuple(
                extent
                for extent in extent_tuple
                if extent.logical_start <= logical_start
                and logical_end <= extent.logical_end
            )
            physical_offsets = {
                extent.physical_start + logical_start - extent.logical_start
                for extent in candidates
            }
            if len(physical_offsets) > 1:
                raise ValueError("conflicting extent mapping for logical page")
            if not physical_offsets:
                missing.append(page_number)
                continue
            locations.append(
                LogicalPageLocation(
                    page_number,
                    physical_offsets.pop(),
                    page_size,
                    source,
                )
            )

        result = cls(source, page_size, byte_order, locations)
        missing_tuple = tuple(missing)
        object.__setattr__(result, "_missing_pages", missing_tuple)
        object.__setattr__(
            result,
            "summary",
            cls._build_summary(
                result._pages,
                missing_tuple,
                len(extent_tuple),
            ),
        )
        return result

    @staticmethod
    def _extent_sort_key(extent: LogicalFileExtent) -> tuple[int, int, int]:
        return (extent.logical_start, extent.physical_start, extent.length)

    @staticmethod
    def _physical_run_count(pages: tuple[LogicalPageLocation, ...]) -> int:
        if not pages:
            return 0
        return 1 + sum(
            current.physical_offset != previous.physical_offset + previous.page_size
            for previous, current in zip(pages, pages[1:])
        )

    @staticmethod
    def _build_summary(
        pages: tuple[LogicalPageLocation, ...],
        missing_pages: tuple[int, ...],
        physical_extent_count: int,
    ) -> LogicalBerkeleyPageMapSummary:
        all_page_numbers = tuple(page.page_number for page in pages) + missing_pages
        return LogicalBerkeleyPageMapSummary(
            mapped_page_count=len(pages),
            missing_page_count=len(missing_pages),
            first_page_number=min(all_page_numbers, default=None),
            last_page_number=max(all_page_numbers, default=None),
            physical_extent_count=physical_extent_count,
        )
