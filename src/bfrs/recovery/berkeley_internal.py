"""Extract validated child references from Berkeley B-tree internal pages."""

from dataclasses import dataclass

from bfrs.core.models import ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    DELETE_FLAG,
    INTERNAL_FIXED_SIZE,
    KEYDATA,
    PAGE_HEADER_SIZE,
    RECORD_HEADER_SIZE,
    BerkeleyPageValidator,
)


@dataclass(frozen=True, slots=True)
class BerkeleyInternalRecord:
    slot_index: int
    local_offset: int
    child_page_number: int
    subtree_record_count: int
    key_length: int
    deleted: bool


@dataclass(frozen=True, slots=True)
class BerkeleyInternalPageExtraction:
    page_number: int
    page_status: ValidationStatus
    page_level: int
    records: tuple[BerkeleyInternalRecord, ...]
    active_child_page_numbers: tuple[int, ...]
    deleted_record_count: int
    incomplete_slot_count: int
    reasons: tuple[str, ...]


class BerkeleyInternalPageExtractor:
    """Extract exact InternalRecord geometry after page validation."""

    def __init__(
        self,
        page_size: int,
        byte_order: str,
        expected_page_number: int | None = None,
    ) -> None:
        self.page_size = page_size
        self.byte_order = byte_order
        self.expected_page_number = expected_page_number
        self._validator = BerkeleyPageValidator(
            page_size,
            byte_order,
            expected_page_number,
        )

    def extract(
        self,
        context: ValidationContext,
    ) -> BerkeleyInternalPageExtraction:
        page_result = self._validator.validate(context)
        page_number = self._integer(
            page_result.evidence.get("page_number"),
            self.expected_page_number or 0,
        )
        page_level = self._integer(page_result.evidence.get("level"), 0)
        if page_result.status is ValidationStatus.REJECTED:
            return self._empty(
                page_number,
                page_level,
                ValidationStatus.REJECTED,
                ("page_rejected",),
            )
        if page_result.evidence.get("page_type") != BTREE_INTERNAL:
            return self._empty(
                page_number,
                page_level,
                page_result.status,
                ("not_internal_page",),
            )

        entries = self._integer(page_result.evidence.get("entries"), 0)
        page = context.data[: self.page_size]
        available_slots = min(
            entries,
            max(0, (len(page) - PAGE_HEADER_SIZE) // 2),
        )
        validated_records = self._integer(
            page_result.evidence.get("parsed_record_count"),
            0,
        )
        parse_slots = min(available_slots, validated_records)
        incomplete_slots = entries - parse_slots
        records: list[BerkeleyInternalRecord] = []
        for slot_index in range(parse_slots):
            slot_position = PAGE_HEADER_SIZE + slot_index * 2
            local_offset = int.from_bytes(
                page[slot_position : slot_position + 2],
                self.byte_order,
            )
            header_end = local_offset + RECORD_HEADER_SIZE
            if header_end > len(page):
                incomplete_slots += 1
                continue
            key_length = int.from_bytes(
                page[local_offset : local_offset + 2],
                self.byte_order,
            )
            raw_type = page[local_offset + 2]
            if raw_type & ~DELETE_FLAG != KEYDATA:
                raise RuntimeError(
                    "BerkeleyPageValidator and internal extractor disagree"
                )
            record_end = (
                header_end + INTERNAL_FIXED_SIZE + key_length
            )
            if record_end > len(page):
                incomplete_slots += 1
                continue
            fixed_start = header_end
            records.append(
                BerkeleyInternalRecord(
                    slot_index=slot_index,
                    local_offset=local_offset,
                    child_page_number=int.from_bytes(
                        page[fixed_start + 1 : fixed_start + 5],
                        self.byte_order,
                    ),
                    subtree_record_count=int.from_bytes(
                        page[fixed_start + 5 : fixed_start + 9],
                        self.byte_order,
                    ),
                    key_length=key_length,
                    deleted=bool(raw_type & DELETE_FLAG),
                )
            )

        if page_result.status is ValidationStatus.STRUCTURAL:
            if len(records) != entries:
                raise RuntimeError(
                    "BerkeleyPageValidator and internal extractor disagree"
                )
            reasons: tuple[str, ...] = ()
        else:
            reason_list = ["page_fragment"]
            if incomplete_slots:
                reason_list.append("incomplete_internal_record")
            reasons = tuple(reason_list)
        record_tuple = tuple(records)
        return BerkeleyInternalPageExtraction(
            page_number=page_number,
            page_status=page_result.status,
            page_level=page_level,
            records=record_tuple,
            active_child_page_numbers=tuple(
                record.child_page_number
                for record in record_tuple
                if not record.deleted
            ),
            deleted_record_count=sum(record.deleted for record in record_tuple),
            incomplete_slot_count=incomplete_slots,
            reasons=reasons,
        )

    @staticmethod
    def _integer(value: object, fallback: int) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) else fallback

    @staticmethod
    def _empty(
        page_number: int,
        page_level: int,
        page_status: ValidationStatus,
        reasons: tuple[str, ...],
    ) -> BerkeleyInternalPageExtraction:
        return BerkeleyInternalPageExtraction(
            page_number=page_number,
            page_status=page_status,
            page_level=page_level,
            records=(),
            active_child_page_numbers=(),
            deleted_record_count=0,
            incomplete_slot_count=0,
            reasons=reasons,
        )
