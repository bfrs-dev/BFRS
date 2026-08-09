"""Extract raw key/value records from validated Berkeley DB leaf pages."""

from dataclasses import dataclass

from bfrs.core.models import ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_LEAF,
    DELETE_FLAG,
    KEYDATA,
    OVERFLOW_RECORD,
    OVERFLOW_REFERENCE_SIZE,
    PAGE_HEADER_SIZE,
    RECORD_HEADER_SIZE,
    BerkeleyPageValidator,
)


@dataclass(frozen=True, slots=True)
class BerkeleyRecord:
    slot_index: int
    local_offset: int
    absolute_offset: int
    length: int
    record_type: int
    deleted: bool
    payload: bytes


@dataclass(frozen=True, slots=True)
class BerkeleyLeafPair:
    pair_index: int
    key: BerkeleyRecord
    value: BerkeleyRecord


@dataclass(frozen=True, slots=True)
class BerkeleyRecordExtraction:
    page_number: int
    page_status: ValidationStatus
    records: tuple[BerkeleyRecord, ...]
    pairs: tuple[BerkeleyLeafPair, ...]
    complete_record_count: int
    deleted_record_count: int
    incomplete_slot_count: int
    reasons: tuple[str, ...]


class BerkeleyLeafRecordExtractor:
    """Extract complete records without interpreting Bitcoin wallet semantics."""

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
            page_size=page_size,
            byte_order=byte_order,
            expected_page_number=expected_page_number,
        )

    def extract(self, context: ValidationContext) -> BerkeleyRecordExtraction:
        page_result = self._validator.validate(context)
        page_number = self._page_number(page_result.evidence)
        if page_result.status is ValidationStatus.REJECTED:
            return self._empty_extraction(
                page_number,
                ValidationStatus.REJECTED,
                ("page_rejected",),
            )

        if page_result.evidence["page_type"] != BTREE_LEAF:
            return self._empty_extraction(
                page_number,
                page_result.status,
                ("not_leaf_page",),
            )

        entries = page_result.evidence["entries"]
        hf_offset = page_result.evidence["hf_offset"]
        if not isinstance(entries, int) or not isinstance(hf_offset, int):
            raise RuntimeError("BerkeleyPageValidator returned invalid evidence")

        page = context.data[: self.page_size]
        available_slot_entries = min(
            entries,
            max(0, (len(page) - PAGE_HEADER_SIZE) // 2),
        )
        incomplete_slots = entries - available_slot_entries
        incomplete_directory = available_slot_entries < entries
        incomplete_record = False
        records: list[BerkeleyRecord] = []
        known_spans: list[tuple[int, int]] = []

        for slot_index in range(available_slot_entries):
            slot_entry = PAGE_HEADER_SIZE + slot_index * 2
            local_offset = int.from_bytes(
                page[slot_entry : slot_entry + 2], self.byte_order
            )
            if local_offset < hf_offset or local_offset >= self.page_size:
                self._raise_consistency_error()

            header_end = local_offset + RECORD_HEADER_SIZE
            if header_end > self.page_size:
                self._raise_consistency_error()
            if header_end > len(page):
                incomplete_slots += 1
                incomplete_record = True
                continue

            length = int.from_bytes(
                page[local_offset : local_offset + 2], self.byte_order
            )
            raw_type = page[local_offset + 2]
            record_type = raw_type & ~DELETE_FLAG
            if record_type == KEYDATA:
                body_size = length
            elif record_type == OVERFLOW_RECORD:
                body_size = OVERFLOW_REFERENCE_SIZE
            else:
                self._raise_consistency_error()

            record_end = header_end + body_size
            if record_end > self.page_size:
                self._raise_consistency_error()
            known_spans.append((local_offset, record_end))
            if record_end > len(page):
                incomplete_slots += 1
                incomplete_record = True
                continue

            records.append(
                BerkeleyRecord(
                    slot_index=slot_index,
                    local_offset=local_offset,
                    absolute_offset=context.start_offset + local_offset,
                    length=length,
                    record_type=record_type,
                    deleted=bool(raw_type & DELETE_FLAG),
                    payload=bytes(page[header_end:record_end]),
                )
            )

        ordered_spans = sorted(known_spans)
        if any(
            left[1] > right[0]
            for left, right in zip(ordered_spans, ordered_spans[1:])
        ):
            self._raise_consistency_error()

        records_by_slot = {record.slot_index: record for record in records}
        pairs = tuple(
            BerkeleyLeafPair(
                pair_index=slot_index // 2,
                key=records_by_slot[slot_index],
                value=records_by_slot[slot_index + 1],
            )
            for slot_index in range(0, entries, 2)
            if slot_index in records_by_slot
            and slot_index + 1 in records_by_slot
        )

        if page_result.status is ValidationStatus.STRUCTURAL:
            if len(records) != entries or len(pairs) != entries // 2:
                self._raise_consistency_error()
            reasons: tuple[str, ...] = ()
        else:
            reason_list = ["page_fragment"]
            if incomplete_directory:
                reason_list.append("incomplete_slot_directory")
            if incomplete_record:
                reason_list.append("incomplete_record")
            if not pairs:
                reason_list.append("no_complete_pairs")
            reasons = tuple(reason_list)

        record_tuple = tuple(records)
        return BerkeleyRecordExtraction(
            page_number=page_number,
            page_status=page_result.status,
            records=record_tuple,
            pairs=pairs,
            complete_record_count=len(record_tuple),
            deleted_record_count=sum(record.deleted for record in record_tuple),
            incomplete_slot_count=incomplete_slots,
            reasons=reasons,
        )

    def _page_number(self, evidence: dict[str, object]) -> int:
        page_number = evidence.get("page_number")
        if isinstance(page_number, int) and not isinstance(page_number, bool):
            return page_number
        if self.expected_page_number is not None:
            return self.expected_page_number
        return 0

    @staticmethod
    def _empty_extraction(
        page_number: int,
        page_status: ValidationStatus,
        reasons: tuple[str, ...],
    ) -> BerkeleyRecordExtraction:
        return BerkeleyRecordExtraction(
            page_number=page_number,
            page_status=page_status,
            records=(),
            pairs=(),
            complete_record_count=0,
            deleted_record_count=0,
            incomplete_slot_count=0,
            reasons=reasons,
        )

    @staticmethod
    def _raise_consistency_error() -> None:
        raise RuntimeError("BerkeleyPageValidator and record extractor disagree")
