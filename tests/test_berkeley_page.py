from collections.abc import Iterable

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    DELETE_FLAG,
    KEYDATA,
    OVERFLOW_DATA,
    OVERFLOW_RECORD,
    PAGE_HEADER_SIZE,
    BerkeleyPageValidator,
)


PAGE_SIZE = 512


def record(payload: bytes, *, record_type: int = KEYDATA, deleted: bool = False) -> bytes:
    raw_type = record_type | (DELETE_FLAG if deleted else 0)
    return len(payload).to_bytes(2, "little") + bytes((raw_type,)) + payload


def overflow_reference(page_number: int = 7, item_length: int = 100) -> bytes:
    body = b"\x00" + page_number.to_bytes(4, "little") + item_length.to_bytes(4, "little")
    return (0).to_bytes(2, "little") + bytes((OVERFLOW_RECORD,)) + body


def internal_record(
    key: bytes = b"key", referenced_page: int = 7, subtree_records: int = 2
) -> bytes:
    fixed = b"\x00" + referenced_page.to_bytes(4, "little") + subtree_records.to_bytes(4, "little")
    return len(key).to_bytes(2, "little") + bytes((KEYDATA,)) + fixed + key


def page_with_records(
    records: Iterable[bytes],
    *,
    page_type: int = BTREE_LEAF,
    level: int = 1,
    page_number: int = 4,
    previous_page: int = 3,
    next_page: int = 5,
    byte_order: str = "little",
) -> bytes:
    items = list(records)
    page = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    slots = []
    for item in items:
        cursor -= len(item)
        page[cursor : cursor + len(item)] = item
        slots.append(cursor)

    put32 = lambda offset, value: page.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, byte_order)
    )
    put16 = lambda offset, value: page.__setitem__(
        slice(offset, offset + 2), value.to_bytes(2, byte_order)
    )
    put32(8, page_number)
    put32(12, previous_page)
    put32(16, next_page)
    put16(20, len(items))
    put16(22, min(slots, default=PAGE_SIZE))
    page[24] = level
    page[25] = page_type
    for index, slot in enumerate(slots):
        put16(PAGE_HEADER_SIZE + index * 2, slot)
    return bytes(page)


def endian_record(payload: bytes, byte_order: str) -> bytes:
    return len(payload).to_bytes(2, byte_order) + bytes((KEYDATA,)) + payload


def validate(
    data: bytes,
    *,
    page_size: int = PAGE_SIZE,
    byte_order: str = "little",
    expected_page_number: int | None = None,
    start_offset: int = 1000,
):
    validator = BerkeleyPageValidator(page_size, byte_order, expected_page_number)
    return validator.validate(ValidationContext("source.img", start_offset, data))


def test_minimal_empty_leaf_page_is_structural() -> None:
    result = validate(page_with_records([]))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["parsed_record_count"] == 0


def test_leaf_with_multiple_key_value_records_is_structural() -> None:
    records = [record(value) for value in (b"key1", b"value1", b"key2", b"value2")]

    result = validate(page_with_records(records))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["parsed_record_count"] == 4
    assert result.evidence["inline_record_count"] == 4


def test_deleted_record_is_counted_but_accepted() -> None:
    records = [record(b"key", deleted=True), record(b"value")]

    result = validate(page_with_records(records))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["deleted_record_count"] == 1


def test_leaf_overflow_reference_is_structural() -> None:
    result = validate(page_with_records([record(b"key"), overflow_reference()]))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["overflow_record_count"] == 1


def test_internal_page_is_structural_and_preserves_reference() -> None:
    data = page_with_records(
        [internal_record()], page_type=BTREE_INTERNAL, level=2
    )

    result = validate(data)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["internal_references"] == ((7, 2),)


def test_overflow_data_page_is_structural() -> None:
    page = bytearray(page_with_records([], page_type=OVERFLOW_DATA, level=0))
    page[20:22] = (1).to_bytes(2, "little")
    page[22:24] = (20).to_bytes(2, "little")
    page[PAGE_HEADER_SIZE : PAGE_HEADER_SIZE + 20] = b"x" * 20

    result = validate(bytes(page))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["hf_offset"] == 20


@pytest.mark.parametrize("byte_order", ["little", "big"])
def test_explicit_byte_orders_are_supported(byte_order: str) -> None:
    records = [endian_record(b"key", byte_order), endian_record(b"value", byte_order)]
    data = page_with_records(records, byte_order=byte_order)

    assert validate(data, byte_order=byte_order).status is ValidationStatus.STRUCTURAL


def test_expected_page_number_match_is_structural() -> None:
    result = validate(page_with_records([], page_number=17), expected_page_number=17)

    assert result.status is ValidationStatus.STRUCTURAL


def test_unknown_expected_page_number_does_not_reject() -> None:
    result = validate(page_with_records([], page_number=99), expected_page_number=None)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["page_number"] == 99


def test_validation_result_has_absolute_page_range() -> None:
    result = validate(page_with_records([]), start_offset=5000)

    assert (result.start_offset, result.end_offset) == (5000, 5512)


def test_evidence_is_deterministic() -> None:
    data = page_with_records([record(b"key"), record(b"value")])

    assert validate(data).evidence == validate(data).evidence


def test_short_header_is_rejected() -> None:
    assert validate(b"\x00" * 25).evidence["reasons"] == ("page_header_too_short",)


def test_metadata_page_is_rejected() -> None:
    data = bytearray(page_with_records([]))
    data[25] = 9

    assert validate(bytes(data)).evidence["reasons"] == ("page_type_unsupported",)


def test_other_page_type_is_rejected() -> None:
    data = bytearray(page_with_records([]))
    data[25] = 13

    assert validate(bytes(data)).status is ValidationStatus.REJECTED


def test_leaf_level_must_be_one() -> None:
    assert validate(page_with_records([], level=2)).evidence["reasons"] == (
        "page_level_invalid",
    )


def test_internal_level_must_be_above_one() -> None:
    data = page_with_records([], page_type=BTREE_INTERNAL, level=1)

    assert validate(data).status is ValidationStatus.REJECTED


def test_overflow_level_must_be_zero() -> None:
    data = page_with_records([], page_type=OVERFLOW_DATA, level=1)

    assert validate(data).status is ValidationStatus.REJECTED


def test_expected_page_number_mismatch_is_rejected() -> None:
    result = validate(page_with_records([], page_number=4), expected_page_number=5)

    assert result.evidence["reasons"] == ("page_number_mismatch",)


def test_slot_directory_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([]))
    page[20:22] = (300).to_bytes(2, "little")

    assert validate(bytes(page)).evidence["reasons"] == ("slot_directory_invalid",)


def test_slot_before_record_area_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"a"), record(b"b")]))
    page[26:28] = (29).to_bytes(2, "little")

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_slot_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"a"), record(b"b")]))
    page[26:28] = (600).to_bytes(2, "little")

    assert validate(bytes(page)).evidence["reasons"] == ("slot_offset_invalid",)


def test_record_header_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"a"), record(b"b")]))
    page[22:24] = (511).to_bytes(2, "little")
    page[26:28] = (511).to_bytes(2, "little")
    page[28:30] = (511).to_bytes(2, "little")

    assert validate(bytes(page)).evidence["reasons"] == ("record_header_invalid",)


def test_unsupported_record_type_is_rejected() -> None:
    assert validate(page_with_records([record(b"a", record_type=2), record(b"b")])).status is ValidationStatus.REJECTED


def test_inline_record_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"a"), record(b"b")]))
    slot = int.from_bytes(page[26:28], "little")
    page[slot : slot + 2] = (PAGE_SIZE).to_bytes(2, "little")

    assert validate(bytes(page)).evidence["reasons"] == ("record_bounds_invalid",)


def test_overflow_reference_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"key"), overflow_reference()]))
    page[28:30] = (506).to_bytes(2, "little")
    page[22:24] = (506).to_bytes(2, "little")

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_internal_record_outside_page_is_rejected() -> None:
    page = bytearray(page_with_records([internal_record()], page_type=BTREE_INTERNAL, level=2))
    slot = int.from_bytes(page[26:28], "little")
    page[slot : slot + 2] = (PAGE_SIZE).to_bytes(2, "little")

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_odd_complete_leaf_record_count_is_rejected() -> None:
    result = validate(page_with_records([record(b"orphan")]))

    assert result.evidence["reasons"] == ("leaf_record_pairing_invalid",)


def test_overflow_data_cannot_exceed_page() -> None:
    page = bytearray(page_with_records([], page_type=OVERFLOW_DATA, level=0))
    page[22:24] = (PAGE_SIZE).to_bytes(2, "little")

    assert validate(bytes(page)).evidence["reasons"] == ("overflow_bounds_invalid",)


def test_random_zero_block_is_rejected() -> None:
    assert validate(b"\x00" * PAGE_SIZE).status is ValidationStatus.REJECTED


def test_valid_header_with_impossible_slot_is_false_positive_regression() -> None:
    page = bytearray(page_with_records([record(b"key"), record(b"value")]))
    page[26:28] = (1).to_bytes(2, "little")

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_valid_empty_header_with_truncated_page_is_fragment() -> None:
    data = page_with_records([])[:PAGE_HEADER_SIZE]

    assert validate(data).status is ValidationStatus.FRAGMENT


def test_record_cut_after_valid_header_is_fragment() -> None:
    data = page_with_records([record(b"key"), record(b"value")])[:500]

    assert validate(data).status is ValidationStatus.FRAGMENT


def test_truncated_record_with_impossible_declared_length_is_rejected() -> None:
    page = bytearray(page_with_records([record(b"key"), record(b"value")]))
    slot = int.from_bytes(page[26:28], "little")
    page[slot : slot + 2] = (PAGE_SIZE).to_bytes(2, "little")

    assert validate(bytes(page[: slot + 3])).status is ValidationStatus.REJECTED


def test_valid_records_with_truncated_page_are_fragment() -> None:
    page = page_with_records([record(b"key"), record(b"value")])

    assert validate(page[:510]).status is ValidationStatus.FRAGMENT


@pytest.mark.parametrize("page_size", [0, 511, 513, 131072])
def test_invalid_page_size_is_rejected_at_construction(page_size: int) -> None:
    with pytest.raises(ValueError):
        BerkeleyPageValidator(page_size, "little")


def test_invalid_byte_order_is_rejected() -> None:
    with pytest.raises(ValueError):
        BerkeleyPageValidator(PAGE_SIZE, "native")
