from dataclasses import FrozenInstanceError

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_internal import BerkeleyInternalPageExtractor
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    DELETE_FLAG,
    KEYDATA,
    PAGE_HEADER_SIZE,
)


PAGE_SIZE = 512


def internal_record(
    child: int,
    *,
    subtree_records: int = 1,
    key: bytes = b"key",
    deleted: bool = False,
    byte_order: str = "little",
    record_type: int = KEYDATA,
) -> bytes:
    raw_type = record_type | (DELETE_FLAG if deleted else 0)
    return (
        len(key).to_bytes(2, byte_order)
        + bytes((raw_type, 0))
        + child.to_bytes(4, byte_order)
        + subtree_records.to_bytes(4, byte_order)
        + key
    )


def page(
    records: tuple[bytes, ...],
    *,
    page_number: int = 10,
    level: int = 2,
    page_type: int = BTREE_INTERNAL,
    byte_order: str = "little",
) -> bytes:
    data = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    slots: list[int] = []
    for record in records:
        cursor -= len(record)
        data[cursor : cursor + len(record)] = record
        slots.append(cursor)
    data[8:12] = page_number.to_bytes(4, byte_order)
    data[20:22] = len(records).to_bytes(2, byte_order)
    data[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, byte_order)
    data[24] = level
    data[25] = page_type
    for index, offset in enumerate(slots):
        start = PAGE_HEADER_SIZE + index * 2
        data[start : start + 2] = offset.to_bytes(2, byte_order)
    return bytes(data)


def extract(
    data: bytes,
    *,
    page_number: int = 10,
    byte_order: str = "little",
):
    return BerkeleyInternalPageExtractor(
        PAGE_SIZE,
        byte_order,
        expected_page_number=page_number,
    ).extract(ValidationContext("image.img", 1_000_000, data))


def test_extracts_exact_internal_record_layout_without_key_bytes() -> None:
    result = extract(page((internal_record(20, subtree_records=7, key=b"abc"),)))
    record = result.records[0]
    assert result.page_status is ValidationStatus.STRUCTURAL
    assert result.page_level == 2
    assert record.slot_index == 0
    assert record.child_page_number == 20
    assert record.subtree_record_count == 7
    assert record.key_length == 3
    assert not hasattr(record, "key")


def test_deleted_internal_record_is_preserved_but_not_active() -> None:
    result = extract(
        page(
            (
                internal_record(20, deleted=True),
                internal_record(30),
            )
        )
    )
    assert tuple(record.child_page_number for record in result.records) == (20, 30)
    assert result.deleted_record_count == 1
    assert result.active_child_page_numbers == (30,)


def test_big_endian_internal_fields_are_decoded_explicitly() -> None:
    result = extract(
        page(
            (internal_record(0x01020304, subtree_records=0x05060708, byte_order="big"),),
            byte_order="big",
        ),
        byte_order="big",
    )
    assert result.records[0].child_page_number == 0x01020304
    assert result.records[0].subtree_record_count == 0x05060708


@pytest.mark.parametrize("page_type", [BTREE_LEAF, 7])
def test_non_internal_page_is_not_interpreted(page_type: int) -> None:
    level = 1 if page_type == BTREE_LEAF else 0
    page_bytes = bytearray(page((), page_type=page_type, level=level))
    if page_type == 7:
        page_bytes[22:24] = (0).to_bytes(2, "little")
    result = extract(bytes(page_bytes))
    assert result.records == ()
    assert result.reasons == ("not_internal_page",)


def test_wrong_expected_page_number_is_rejected_before_extraction() -> None:
    result = extract(page((internal_record(20),), page_number=11))
    assert result.page_status is ValidationStatus.REJECTED
    assert result.records == ()
    assert result.reasons == ("page_rejected",)


def test_invalid_internal_record_type_never_yields_child_reference() -> None:
    result = extract(page((internal_record(20, record_type=3),)))
    assert result.page_status is ValidationStatus.REJECTED
    assert result.active_child_page_numbers == ()


def test_truncated_internal_page_returns_fragment_without_guessing() -> None:
    full = page((internal_record(20),),)
    result = extract(full[:500])
    assert result.page_status is ValidationStatus.FRAGMENT
    assert result.records == ()
    assert result.incomplete_slot_count >= 1


def test_models_are_immutable() -> None:
    result = extract(page((internal_record(20),)))
    with pytest.raises(FrozenInstanceError):
        result.records[0].child_page_number = 30  # type: ignore[misc]


def test_extractor_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    assert extract(page((internal_record(20),))).active_child_page_numbers == (20,)
