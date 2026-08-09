import builtins
from collections.abc import Iterable

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import BerkeleyLeafRecordExtractor
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    DELETE_FLAG,
    KEYDATA,
    OVERFLOW_DATA,
    OVERFLOW_RECORD,
    PAGE_HEADER_SIZE,
)


PAGE_SIZE = 512
PAGE_NUMBER = 4


def raw_record(
    payload: bytes,
    *,
    record_type: int = KEYDATA,
    deleted: bool = False,
    declared_length: int | None = None,
    byte_order: str = "little",
) -> bytes:
    length = len(payload) if declared_length is None else declared_length
    raw_type = record_type | (DELETE_FLAG if deleted else 0)
    return length.to_bytes(2, byte_order) + bytes((raw_type,)) + payload


def overflow_record(
    *,
    page_number: int = 20,
    total_length: int = 1000,
    deleted: bool = False,
    byte_order: str = "little",
) -> bytes:
    body = (
        b"\x00"
        + page_number.to_bytes(4, byte_order)
        + total_length.to_bytes(4, byte_order)
    )
    return raw_record(
        body,
        record_type=OVERFLOW_RECORD,
        deleted=deleted,
        declared_length=0,
        byte_order=byte_order,
    )


def records_page(
    records: Iterable[bytes],
    *,
    offsets: Iterable[int] | None = None,
    page_number: int = PAGE_NUMBER,
    page_type: int = BTREE_LEAF,
    level: int = 1,
    byte_order: str = "little",
) -> bytes:
    items = list(records)
    if offsets is None:
        cursor = PAGE_SIZE
        positions = []
        for item in items:
            cursor -= len(item)
            positions.append(cursor)
    else:
        positions = list(offsets)
    if len(items) != len(positions):
        raise ValueError("records and offsets must have the same length")

    page = bytearray(PAGE_SIZE)
    for item, offset in zip(items, positions):
        page[offset : offset + len(item)] = item

    put32 = lambda offset, value: page.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, byte_order)
    )
    put16 = lambda offset, value: page.__setitem__(
        slice(offset, offset + 2), value.to_bytes(2, byte_order)
    )
    put32(8, page_number)
    put16(20, len(items))
    put16(22, min(positions, default=PAGE_SIZE))
    page[24] = level
    page[25] = page_type
    for slot_index, offset in enumerate(positions):
        put16(PAGE_HEADER_SIZE + slot_index * 2, offset)
    return bytes(page)


def overflow_page(*, page_number: int = PAGE_NUMBER) -> bytes:
    page = bytearray(
        records_page(
            [],
            page_number=page_number,
            page_type=OVERFLOW_DATA,
            level=0,
        )
    )
    page[22:24] = (0).to_bytes(2, "little")
    return bytes(page)


def extract(
    data: bytes,
    *,
    page_size: int = PAGE_SIZE,
    byte_order: str = "little",
    expected_page_number: int | None = PAGE_NUMBER,
    start_offset: int = 0,
):
    extractor = BerkeleyLeafRecordExtractor(
        page_size,
        byte_order,
        expected_page_number,
    )
    return extractor.extract(ValidationContext("source.img", start_offset, data))


def test_minimal_leaf_pair_is_extracted() -> None:
    result = extract(records_page([raw_record(b"key"), raw_record(b"value")]))

    assert result.page_status is ValidationStatus.STRUCTURAL
    assert [record.payload for record in result.records] == [b"key", b"value"]
    assert len(result.pairs) == 1
    assert result.reasons == ()


def test_two_leaf_pairs_are_extracted() -> None:
    payloads = (b"key0", b"value0", b"key1", b"value1")
    result = extract(records_page(raw_record(payload) for payload in payloads))

    assert [pair.pair_index for pair in result.pairs] == [0, 1]
    assert [pair.key.payload for pair in result.pairs] == [b"key0", b"key1"]
    assert [pair.value.payload for pair in result.pairs] == [b"value0", b"value1"]


def test_records_follow_slot_order_not_physical_offset() -> None:
    payloads = (b"slot0", b"slot1", b"slot2", b"slot3")
    page = records_page(
        (raw_record(payload) for payload in payloads),
        offsets=(400, 300, 450, 200),
    )

    result = extract(page)

    assert [record.slot_index for record in result.records] == [0, 1, 2, 3]
    assert [record.payload for record in result.records] == list(payloads)
    assert [record.local_offset for record in result.records] == [400, 300, 450, 200]


def test_absolute_offset_points_to_record_header() -> None:
    page = records_page(
        [raw_record(b"key"), raw_record(b"value")],
        offsets=(100, 120),
    )

    result = extract(page, start_offset=1_000_000)

    assert result.records[0].local_offset == 100
    assert result.records[0].absolute_offset == 1_000_100
    assert result.records[1].absolute_offset == 1_000_120


def test_payload_excludes_record_header_and_preserves_declared_length() -> None:
    result = extract(records_page([raw_record(b"abc"), raw_record(b"12345")]))

    assert result.records[0].payload == b"abc"
    assert result.records[0].length == 3
    assert result.records[1].payload == b"12345"
    assert result.records[1].length == 5


@pytest.mark.parametrize("deleted_slot", [0, 1])
def test_deleted_key_or_value_is_preserved_in_pair(deleted_slot: int) -> None:
    records = [
        raw_record(b"key", deleted=deleted_slot == 0),
        raw_record(b"value", deleted=deleted_slot == 1),
    ]

    result = extract(records_page(records))

    assert result.records[deleted_slot].deleted is True
    assert result.records[deleted_slot].payload in (b"key", b"value")
    assert result.deleted_record_count == 1
    assert len(result.pairs) == 1


def test_overflow_reference_record_is_preserved_as_raw_body() -> None:
    reference = overflow_record(page_number=20, total_length=1000)
    result = extract(records_page([raw_record(b"key"), reference]))

    value = result.pairs[0].value
    assert value.record_type == OVERFLOW_RECORD
    assert value.length == 0
    assert value.payload == reference[3:]
    assert len(value.payload) == 9


def test_structural_counts_match_declared_entries_and_pairs() -> None:
    payloads = (b"k0", b"v0", b"k1", b"v1", b"k2", b"v2")
    result = extract(records_page(raw_record(payload) for payload in payloads))

    assert result.complete_record_count == 6
    assert len(result.records) == 6
    assert len(result.pairs) == 3
    assert result.incomplete_slot_count == 0


def test_valid_big_endian_leaf_is_extracted() -> None:
    records = [
        raw_record(b"key", byte_order="big"),
        raw_record(b"value", byte_order="big"),
    ]
    page = records_page(records, byte_order="big")

    assert extract(page, byte_order="big").pairs[0].value.payload == b"value"


def test_rejected_page_does_not_produce_records() -> None:
    result = extract(bytes(PAGE_SIZE))

    assert result.page_status is ValidationStatus.REJECTED
    assert result.records == ()
    assert result.pairs == ()
    assert result.reasons == ("page_rejected",)


def test_internal_page_is_not_interpreted_as_leaf() -> None:
    page = records_page([], page_type=BTREE_INTERNAL, level=2)

    result = extract(page)

    assert result.page_status is ValidationStatus.STRUCTURAL
    assert result.reasons == ("not_leaf_page",)
    assert result.records == ()


def test_overflow_page_is_not_interpreted_as_leaf() -> None:
    result = extract(overflow_page())

    assert result.page_status is ValidationStatus.STRUCTURAL
    assert result.reasons == ("not_leaf_page",)
    assert result.pairs == ()


def test_expected_page_number_mismatch_rejects_before_extraction() -> None:
    page = records_page([raw_record(b"key"), raw_record(b"value")])

    result = extract(page, expected_page_number=99)

    assert result.page_status is ValidationStatus.REJECTED
    assert result.reasons == ("page_rejected",)
    assert result.records == ()


def test_wrong_endian_is_not_automatically_corrected() -> None:
    page = records_page([raw_record(b"key"), raw_record(b"value")])

    result = extract(page, byte_order="big")

    assert result.page_status is ValidationStatus.REJECTED
    assert result.records == ()


def test_invalid_slot_does_not_recover_garbage() -> None:
    page = bytearray(records_page([raw_record(b"key"), raw_record(b"value")]))
    page[PAGE_HEADER_SIZE : PAGE_HEADER_SIZE + 2] = (1).to_bytes(2, "little")

    result = extract(bytes(page))

    assert result.page_status is ValidationStatus.REJECTED
    assert result.records == ()


def test_impossible_record_length_does_not_return_partial_payload() -> None:
    page = bytearray(
        records_page(
            [raw_record(b"key"), raw_record(b"value")],
            offsets=(100, 120),
        )
    )
    page[100:102] = PAGE_SIZE.to_bytes(2, "little")

    result = extract(bytes(page))

    assert result.page_status is ValidationStatus.REJECTED
    assert result.records == ()


def test_fragment_keeps_first_complete_pair_and_skips_truncated_second() -> None:
    records = [
        raw_record(b"key0"),
        raw_record(b"value0"),
        raw_record(b"key1"),
        raw_record(b"value1"),
    ]
    page = records_page(records, offsets=(100, 120, 480, 495))[:200]

    result = extract(page)

    assert result.page_status is ValidationStatus.FRAGMENT
    assert [pair.pair_index for pair in result.pairs] == [0]
    assert result.complete_record_count == 2
    assert result.incomplete_slot_count == 2
    assert result.reasons == ("page_fragment", "incomplete_record")


def test_complete_key_with_truncated_value_does_not_form_pair() -> None:
    page = records_page(
        [raw_record(b"key"), raw_record(b"value")],
        offsets=(100, 480),
    )[:485]

    result = extract(page)

    assert [record.slot_index for record in result.records] == [0]
    assert result.pairs == ()
    assert result.reasons == (
        "page_fragment",
        "incomplete_record",
        "no_complete_pairs",
    )


def test_truncated_key_does_not_shift_value_into_another_pair() -> None:
    page = records_page(
        [raw_record(b"key0"), raw_record(b"value0"), raw_record(b"key1"), raw_record(b"value1")],
        offsets=(480, 100, 120, 140),
    )[:200]

    result = extract(page)

    assert [record.slot_index for record in result.records] == [1, 2, 3]
    assert [pair.pair_index for pair in result.pairs] == [1]
    assert result.pairs[0].key.payload == b"key1"


def test_later_complete_pair_keeps_its_logical_pair_index() -> None:
    page = records_page(
        [raw_record(b"key0"), raw_record(b"value0"), raw_record(b"key1"), raw_record(b"value1")],
        offsets=(480, 495, 100, 120),
    )[:200]

    result = extract(page)

    assert [pair.pair_index for pair in result.pairs] == [1]
    assert result.pairs[0].key.slot_index == 2
    assert result.pairs[0].value.slot_index == 3


def test_deleted_complete_record_is_preserved_in_fragment() -> None:
    page = records_page(
        [
            raw_record(b"deleted-key", deleted=True),
            raw_record(b"value"),
            raw_record(b"later-key"),
            raw_record(b"later-value"),
        ],
        offsets=(100, 120, 480, 495),
    )[:200]

    result = extract(page)

    assert result.records[0].deleted is True
    assert result.records[0].payload == b"deleted-key"
    assert result.deleted_record_count == 1
    assert [pair.pair_index for pair in result.pairs] == [0]


def test_fragment_without_complete_pair_has_stable_reason() -> None:
    page = records_page(
        [raw_record(b"key"), raw_record(b"value")],
        offsets=(100, 480),
    )[:485]

    result = extract(page)

    assert "no_complete_pairs" in result.reasons


def test_incomplete_slot_directory_is_counted_without_guessing() -> None:
    page = records_page(
        [raw_record(b"k0"), raw_record(b"v0"), raw_record(b"k1"), raw_record(b"v1")],
        offsets=(100, 120, 140, 160),
    )[:PAGE_HEADER_SIZE + 5]

    result = extract(page)

    assert result.page_status is ValidationStatus.FRAGMENT
    assert result.complete_record_count == 0
    assert result.incomplete_slot_count == 4
    assert "incomplete_slot_directory" in result.reasons


def test_forensic_overwrite_recovers_pairs_zero_and_two_only() -> None:
    records = [
        raw_record(b"key0"),
        raw_record(b"value0"),
        raw_record(b"key1"),
        raw_record(b"value1"),
        raw_record(b"key2"),
        raw_record(b"value2"),
    ]
    page = records_page(records, offsets=(100, 120, 480, 495, 140, 160))[:200]

    result = extract(page)

    assert result.page_status is ValidationStatus.FRAGMENT
    assert [pair.pair_index for pair in result.pairs] == [0, 2]
    assert [pair.key.payload for pair in result.pairs] == [b"key0", b"key2"]
    assert [pair.value.payload for pair in result.pairs] == [b"value0", b"value2"]
    assert result.incomplete_slot_count == 2


def test_extractor_uses_context_bytes_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("extractor attempted I/O")

    monkeypatch.setattr(builtins, "open", fail_open)
    page = records_page([raw_record(b"key"), raw_record(b"value")])

    assert extract(page).complete_record_count == 2
