"""Validation of one Bitcoin-compatible Berkeley DB B-tree data page."""

from dataclasses import asdict, dataclass

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import is_valid_page_size


PAGE_HEADER_SIZE = 26
RECORD_HEADER_SIZE = 3
INTERNAL_FIXED_SIZE = 9
OVERFLOW_REFERENCE_SIZE = 9

BTREE_INTERNAL = 3
BTREE_LEAF = 5
OVERFLOW_DATA = 7
SUPPORTED_PAGE_TYPES = (BTREE_INTERNAL, BTREE_LEAF, OVERFLOW_DATA)

KEYDATA = 1
OVERFLOW_RECORD = 3
DELETE_FLAG = 0x80


@dataclass(frozen=True, slots=True)
class BerkeleyPageInfo:
    page_number: int
    previous_page: int
    next_page: int
    entries: int
    hf_offset: int
    level: int
    page_type: int
    byte_order: str
    page_size: int
    parsed_record_count: int = 0
    deleted_record_count: int = 0
    inline_record_count: int = 0
    overflow_record_count: int = 0


@dataclass(frozen=True, slots=True)
class _ParseOutcome:
    status: ValidationStatus
    reasons: tuple[str, ...]
    parsed_record_count: int = 0
    deleted_record_count: int = 0
    inline_record_count: int = 0
    overflow_record_count: int = 0
    internal_references: tuple[tuple[int, int], ...] = ()


class BerkeleyPageValidator:
    name = "berkeley_page"

    def __init__(
        self,
        page_size: int,
        byte_order: str,
        expected_page_number: int | None = None,
    ) -> None:
        if not is_valid_page_size(page_size):
            raise ValueError("page_size must be a power of two from 512 to 65536")
        if byte_order not in ("little", "big"):
            raise ValueError("byte_order must be 'little' or 'big'")
        if expected_page_number is not None and expected_page_number < 0:
            raise ValueError("expected_page_number must not be negative")

        self.page_size = page_size
        self.byte_order = byte_order
        self.expected_page_number = expected_page_number

    def validate(self, context: ValidationContext) -> ValidationResult:
        if len(context.data) < PAGE_HEADER_SIZE:
            return self._result(
                context,
                ValidationStatus.REJECTED,
                ("page_header_too_short",),
                evidence={},
            )

        page = context.data[: self.page_size]
        decode32 = lambda start: int.from_bytes(
            page[start : start + 4], self.byte_order
        )
        page_number = decode32(8)
        previous_page = decode32(12)
        next_page = decode32(16)
        entries = int.from_bytes(page[20:22], self.byte_order)
        hf_offset = int.from_bytes(page[22:24], self.byte_order)
        level = page[24]
        page_type = page[25]

        header_reasons: list[str] = []
        if (
            self.expected_page_number is not None
            and page_number != self.expected_page_number
        ):
            header_reasons.append("page_number_mismatch")
        if page_type not in SUPPORTED_PAGE_TYPES:
            header_reasons.append("page_type_unsupported")
        elif page_type == BTREE_LEAF and level != 1:
            header_reasons.append("page_level_invalid")
        elif page_type == BTREE_INTERNAL and level < 2:
            header_reasons.append("page_level_invalid")
        elif page_type == OVERFLOW_DATA and level != 0:
            header_reasons.append("page_level_invalid")

        base_info = BerkeleyPageInfo(
            page_number=page_number,
            previous_page=previous_page,
            next_page=next_page,
            entries=entries,
            hf_offset=hf_offset,
            level=level,
            page_type=page_type,
            byte_order=self.byte_order,
            page_size=self.page_size,
        )
        if header_reasons:
            return self._result(
                context,
                ValidationStatus.REJECTED,
                tuple(header_reasons),
                asdict(base_info),
            )

        if page_type == OVERFLOW_DATA:
            outcome = self._validate_overflow(len(page), hf_offset)
        else:
            outcome = self._validate_records_page(page, entries, hf_offset, page_type)

        info = BerkeleyPageInfo(
            page_number=page_number,
            previous_page=previous_page,
            next_page=next_page,
            entries=entries,
            hf_offset=hf_offset,
            level=level,
            page_type=page_type,
            byte_order=self.byte_order,
            page_size=self.page_size,
            parsed_record_count=outcome.parsed_record_count,
            deleted_record_count=outcome.deleted_record_count,
            inline_record_count=outcome.inline_record_count,
            overflow_record_count=outcome.overflow_record_count,
        )
        evidence = asdict(info)
        evidence["internal_references"] = outcome.internal_references
        return self._result(
            context, outcome.status, outcome.reasons, evidence
        )

    def _validate_overflow(self, available: int, data_length: int) -> _ParseOutcome:
        data_end = PAGE_HEADER_SIZE + data_length
        if data_end > self.page_size:
            return _ParseOutcome(
                ValidationStatus.REJECTED, ("overflow_bounds_invalid",)
            )
        if available < self.page_size:
            if data_end > available:
                return _ParseOutcome(
                    ValidationStatus.FRAGMENT, ("page_truncated",)
                )
            return _ParseOutcome(ValidationStatus.FRAGMENT, ("page_truncated",))
        return _ParseOutcome(ValidationStatus.STRUCTURAL, ())

    def _validate_records_page(
        self,
        page: bytes,
        entries: int,
        hf_offset: int,
        page_type: int,
    ) -> _ParseOutcome:
        directory_end = PAGE_HEADER_SIZE + entries * 2
        if directory_end > self.page_size:
            return _ParseOutcome(
                ValidationStatus.REJECTED, ("slot_directory_invalid",)
            )
        if hf_offset < directory_end or hf_offset > self.page_size:
            return _ParseOutcome(
                ValidationStatus.REJECTED, ("slot_directory_invalid",)
            )
        if len(page) < directory_end:
            return _ParseOutcome(ValidationStatus.FRAGMENT, ("page_truncated",))

        slots = tuple(
            int.from_bytes(page[PAGE_HEADER_SIZE + i * 2 : PAGE_HEADER_SIZE + i * 2 + 2], self.byte_order)
            for i in range(entries)
        )
        if any(slot < hf_offset or slot >= self.page_size for slot in slots):
            return _ParseOutcome(
                ValidationStatus.REJECTED, ("slot_offset_invalid",)
            )

        parsed = deleted = inline = overflow = 0
        references: list[tuple[int, int]] = []
        spans: list[tuple[int, int]] = []
        for slot in slots:
            if slot + RECORD_HEADER_SIZE > self.page_size:
                return _ParseOutcome(
                    ValidationStatus.REJECTED, ("record_header_invalid",)
                )
            if slot + RECORD_HEADER_SIZE > len(page):
                return _ParseOutcome(
                    ValidationStatus.FRAGMENT,
                    ("page_truncated",),
                    parsed,
                    deleted,
                    inline,
                    overflow,
                    tuple(references),
                )

            length = int.from_bytes(page[slot : slot + 2], self.byte_order)
            raw_type = page[slot + 2]
            record_type = raw_type & ~DELETE_FLAG
            is_deleted = bool(raw_type & DELETE_FLAG)

            if page_type == BTREE_INTERNAL:
                if record_type != KEYDATA:
                    return _ParseOutcome(
                        ValidationStatus.REJECTED,
                        ("record_type_unsupported",),
                    )
                record_end = slot + RECORD_HEADER_SIZE + INTERNAL_FIXED_SIZE + length
                if record_end > self.page_size:
                    return _ParseOutcome(
                        ValidationStatus.REJECTED, ("record_bounds_invalid",)
                    )
                if record_end > len(page):
                    return _ParseOutcome(
                        ValidationStatus.FRAGMENT, ("page_truncated",)
                    )
                fixed = slot + RECORD_HEADER_SIZE
                referenced_page = int.from_bytes(
                    page[fixed + 1 : fixed + 5], self.byte_order
                )
                subtree_records = int.from_bytes(
                    page[fixed + 5 : fixed + 9], self.byte_order
                )
                references.append((referenced_page, subtree_records))
                inline += 1
            elif record_type == KEYDATA:
                record_end = slot + RECORD_HEADER_SIZE + length
                if record_end > self.page_size:
                    return _ParseOutcome(
                        ValidationStatus.REJECTED, ("record_bounds_invalid",)
                    )
                if record_end > len(page):
                    return _ParseOutcome(
                        ValidationStatus.FRAGMENT, ("page_truncated",)
                    )
                inline += 1
            elif record_type == OVERFLOW_RECORD:
                record_end = slot + RECORD_HEADER_SIZE + OVERFLOW_REFERENCE_SIZE
                if record_end > self.page_size:
                    return _ParseOutcome(
                        ValidationStatus.REJECTED, ("record_bounds_invalid",)
                    )
                if record_end > len(page):
                    return _ParseOutcome(
                        ValidationStatus.FRAGMENT, ("page_truncated",)
                    )
                overflow += 1
            else:
                return _ParseOutcome(
                    ValidationStatus.REJECTED, ("record_type_unsupported",)
                )

            spans.append((slot, record_end))
            parsed += 1
            deleted += is_deleted

        ordered_spans = sorted(spans)
        if any(left[1] > right[0] for left, right in zip(ordered_spans, ordered_spans[1:])):
            return _ParseOutcome(
                ValidationStatus.REJECTED, ("record_bounds_invalid",)
            )
        if page_type == BTREE_LEAF and entries % 2:
            return _ParseOutcome(
                ValidationStatus.REJECTED,
                ("leaf_record_pairing_invalid",),
                parsed,
                deleted,
                inline,
                overflow,
            )
        if len(page) < self.page_size:
            return _ParseOutcome(
                ValidationStatus.FRAGMENT,
                ("page_truncated",),
                parsed,
                deleted,
                inline,
                overflow,
                tuple(references),
            )
        return _ParseOutcome(
            ValidationStatus.STRUCTURAL,
            (),
            parsed,
            deleted,
            inline,
            overflow,
            tuple(references),
        )

    def _result(
        self,
        context: ValidationContext,
        status: ValidationStatus,
        reasons: tuple[str, ...],
        evidence: dict[str, object],
    ) -> ValidationResult:
        evidence["reasons"] = reasons
        return ValidationResult(
            start_offset=context.start_offset,
            end_offset=context.start_offset + min(len(context.data), self.page_size),
            validator=self.name,
            status=status,
            source=context.source,
            evidence=evidence,
        )
