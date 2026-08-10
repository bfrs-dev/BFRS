"""Read and validate Berkeley pages through a logical-to-physical map."""

from dataclasses import dataclass, field
import ntpath
from typing import Any, Protocol

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.recovery.logical_page_map import (
    LogicalBerkeleyPageMap,
    LogicalPageLocation,
)
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import BerkeleyMetadataValidator
from bfrs.validators.berkeley_page import BerkeleyPageValidator


class PhysicalRangeReader(Protocol):
    def read_at(self, offset: int, length: int) -> bytes: ...


class PhysicalRangeReadError(OSError):
    """Controlled physical-range read failure."""


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyDatabaseIdentity:
    source: str
    page_size: int
    byte_order: str
    logical_file_id: str

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("source must not be empty")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        if self.byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")
        if not self.logical_file_id or not self.logical_file_id.strip():
            raise ValueError("logical_file_id must not be empty")
        object.__setattr__(
            self,
            "source",
            ntpath.normcase(ntpath.normpath(self.source)),
        )


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyMetadataAnchor:
    identity: LogicalBerkeleyDatabaseIdentity
    metadata_page_number: int
    page_size: int
    byte_order: str
    root_page: int
    metadata_physical_offset: int = field(compare=False)

    def __post_init__(self) -> None:
        if self.metadata_page_number < 0:
            raise ValueError("metadata_page_number must not be negative")
        if self.page_size != self.identity.page_size:
            raise ValueError("page_size must match logical database identity")
        if self.byte_order != self.identity.byte_order:
            raise ValueError("byte_order must match logical database identity")
        if self.root_page <= 0:
            raise ValueError("root_page must be positive")
        if self.metadata_physical_offset < 0:
            raise ValueError("metadata_physical_offset must not be negative")


@dataclass(frozen=True, slots=True)
class MappedBerkeleyPage:
    identity: LogicalBerkeleyDatabaseIdentity
    page_number: int
    physical_offset: int
    page_size: int
    mapped_complete: bool
    validation: ValidationResult


@dataclass(frozen=True, slots=True)
class LogicalBerkeleyReadSummary:
    mapped_page_count: int
    validated_structural_count: int
    validated_fragment_count: int
    validated_rejected_count: int
    missing_page_count: int
    metadata_structural_count: int
    metadata_fragment_count: int
    logical_anchor_count: int


class LogicalBerkeleyPageReader:
    """Validate mapped pages without assuming physical contiguity."""

    def __init__(
        self,
        page_map: LogicalBerkeleyPageMap,
        *,
        logical_file_id: str,
        range_reader: PhysicalRangeReader,
    ) -> None:
        if not isinstance(page_map, LogicalBerkeleyPageMap):
            raise ValueError("page_map must be LogicalBerkeleyPageMap")
        if not hasattr(range_reader, "read_at"):
            raise ValueError("range_reader must provide read_at")
        self.page_map = page_map
        self.range_reader = range_reader
        self.identity = LogicalBerkeleyDatabaseIdentity(
            source=page_map.source,
            page_size=page_map.page_size,
            byte_order=page_map.byte_order,
            logical_file_id=logical_file_id,
        )

    def validate_pages(self) -> tuple[MappedBerkeleyPage, ...]:
        results: list[MappedBerkeleyPage] = []
        for location in self.page_map.pages():
            page_data, read_error = self._read(location)
            if read_error is not None:
                validation = self._read_rejected(location, read_error)
            else:
                validation = BerkeleyPageValidator(
                    page_size=self.page_map.page_size,
                    byte_order=self.page_map.byte_order,
                    expected_page_number=location.page_number,
                ).validate(
                    ValidationContext(
                        source=self.identity.source,
                        start_offset=location.physical_offset,
                        data=page_data,
                    )
                )
            results.append(
                self._mapped_page(location, page_data, validation)
            )
        return tuple(results)

    def validate_metadata_pages(self) -> tuple[MappedBerkeleyPage, ...]:
        results: list[MappedBerkeleyPage] = []
        for location in self.page_map.pages():
            page_data, read_error = self._read(location)
            if read_error is not None:
                validation = self._read_rejected(
                    location,
                    read_error,
                    BerkeleyMetadataValidator.name,
                )
            else:
                validation = BerkeleyMetadataValidator().validate(
                    ValidationContext(
                        source=self.identity.source,
                        start_offset=location.physical_offset,
                        data=page_data,
                    )
                )
                validation = self._enforce_metadata_identity(
                    location,
                    validation,
                )
            results.append(
                self._mapped_page(location, page_data, validation)
            )
        return tuple(results)

    def find_metadata_pages(
        self,
    ) -> tuple[LogicalBerkeleyMetadataAnchor, ...]:
        anchors = [
            LogicalBerkeleyMetadataAnchor(
                identity=self.identity,
                metadata_page_number=page.page_number,
                page_size=self.page_map.page_size,
                byte_order=self.page_map.byte_order,
                root_page=int(page.validation.evidence["root_page"]),
                metadata_physical_offset=page.physical_offset,
            )
            for page in self.validate_metadata_pages()
            if page.validation.status is ValidationStatus.STRUCTURAL
        ]
        return tuple(
            sorted(
                anchors,
                key=lambda anchor: anchor.metadata_page_number,
            )
        )

    def read_page_context(
        self,
        page_number: int,
    ) -> ValidationContext | None:
        location = self.page_map.locate(page_number)
        if location is None:
            return None
        page_data, read_error = self._read(location)
        if read_error is not None:
            return None
        return ValidationContext(
            source=self.identity.source,
            start_offset=location.physical_offset,
            data=page_data,
        )

    def summarize(self) -> LogicalBerkeleyReadSummary:
        pages = self.validate_pages()
        metadata = self.validate_metadata_pages()
        anchors = tuple(
            page
            for page in metadata
            if page.validation.status is ValidationStatus.STRUCTURAL
        )
        return LogicalBerkeleyReadSummary(
            mapped_page_count=len(pages),
            validated_structural_count=self._status_count(
                pages, ValidationStatus.STRUCTURAL
            ),
            validated_fragment_count=self._status_count(
                pages, ValidationStatus.FRAGMENT
            ),
            validated_rejected_count=self._status_count(
                pages, ValidationStatus.REJECTED
            ),
            missing_page_count=len(self.page_map.missing_pages()),
            metadata_structural_count=self._status_count(
                metadata, ValidationStatus.STRUCTURAL
            ),
            metadata_fragment_count=self._status_count(
                metadata, ValidationStatus.FRAGMENT
            ),
            logical_anchor_count=len(anchors),
        )

    def _read(
        self,
        location: LogicalPageLocation,
    ) -> tuple[bytes, str | None]:
        try:
            data = self.range_reader.read_at(
                location.physical_offset,
                self.page_map.page_size,
            )
        except PhysicalRangeReadError:
            return b"", "physical_read_error"
        if not isinstance(data, bytes):
            return b"", "physical_reader_returned_non_bytes"
        if len(data) > self.page_map.page_size:
            return b"", "physical_reader_returned_too_many_bytes"
        return data, None

    def _mapped_page(
        self,
        location: LogicalPageLocation,
        data: bytes,
        validation: ValidationResult,
    ) -> MappedBerkeleyPage:
        return MappedBerkeleyPage(
            identity=self.identity,
            page_number=location.page_number,
            physical_offset=location.physical_offset,
            page_size=self.page_map.page_size,
            mapped_complete=len(data) == self.page_map.page_size,
            validation=validation,
        )

    def _read_rejected(
        self,
        location: LogicalPageLocation,
        reason: str,
        validator: str = BerkeleyPageValidator.name,
    ) -> ValidationResult:
        return ValidationResult(
            start_offset=location.physical_offset,
            end_offset=location.physical_offset,
            validator=validator,
            status=ValidationStatus.REJECTED,
            source=self.identity.source,
            evidence={"reasons": (reason,)},
        )

    def _enforce_metadata_identity(
        self,
        location: LogicalPageLocation,
        validation: ValidationResult,
    ) -> ValidationResult:
        if validation.status is not ValidationStatus.STRUCTURAL:
            return validation
        evidence = validation.evidence
        contradictions: list[str] = []
        if validation.start_offset != location.physical_offset:
            contradictions.append("metadata_not_page_aligned")
        if evidence.get("page_number") != location.page_number:
            contradictions.append("metadata_page_number_mismatch")
        if evidence.get("page_size") != self.page_map.page_size:
            contradictions.append("metadata_page_size_mismatch")
        if evidence.get("byte_order") != self.page_map.byte_order:
            contradictions.append("metadata_byte_order_mismatch")
        if not contradictions:
            return validation
        rejected_evidence: dict[str, Any] = dict(evidence)
        rejected_evidence["reasons"] = tuple(contradictions)
        return ValidationResult(
            start_offset=validation.start_offset,
            end_offset=validation.end_offset,
            validator=validation.validator,
            status=ValidationStatus.REJECTED,
            source=validation.source,
            evidence=rejected_evidence,
        )

    @staticmethod
    def _status_count(
        pages: tuple[MappedBerkeleyPage, ...],
        status: ValidationStatus,
    ) -> int:
        return sum(page.validation.status is status for page in pages)
