import builtins
from dataclasses import FrozenInstanceError, replace

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor
from bfrs.validators.encrypted_wallet_aggregator import (
    EncryptedWalletAggregation,
    EncryptedWalletEvidenceAggregator,
)
from bfrs.validators.encrypted_wallet_evidence import BerkeleyRecordPageContext


PAGE_SIZE = 512
BASE_OFFSET = 1_000_000
GENERATOR_X = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
GENERATOR_Y = bytes.fromhex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)
PUBLIC_KEY = b"\x04" + GENERATOR_X + GENERATOR_Y
CRYPTED_SECRET = bytes(range(48))
ENCRYPTED_MASTER_KEY = bytes(reversed(range(48)))
SALT = bytes.fromhex("0011223344556677")


def compact_size(value: int) -> bytes:
    if value < 253:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


def serialized_string(value: str) -> bytes:
    payload = value.encode("ascii")
    return compact_size(len(payload)) + payload


def serialized_vector(payload: bytes) -> bytes:
    return compact_size(len(payload)) + payload


def anchor(
    *,
    base_offset: int = BASE_OFFSET,
    metadata_page_number: int = 0,
) -> BerkeleyAnchor:
    return BerkeleyAnchor(
        metadata_absolute_offset=(
            base_offset + metadata_page_number * PAGE_SIZE
        ),
        metadata_page_number=metadata_page_number,
        page_size=PAGE_SIZE,
        byte_order="little",
    )


def raw_record(
    payload: bytes,
    page_number: int,
    local_offset: int,
    slot_index: int,
    *,
    base_offset: int,
) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=local_offset,
        absolute_offset=base_offset + page_number * PAGE_SIZE + local_offset,
        length=len(payload),
        record_type=1,
        deleted=False,
        payload=payload,
    )


def ckey_pair(
    page_number: int,
    selected_anchor: BerkeleyAnchor,
    *,
    local_offset: int = 50,
) -> BerkeleyLeafPair:
    key_payload = serialized_string("ckey") + serialized_vector(PUBLIC_KEY)
    value_payload = serialized_vector(CRYPTED_SECRET)
    base_offset = selected_anchor.database_base_offset
    return BerkeleyLeafPair(
        pair_index=local_offset,
        key=raw_record(
            key_payload,
            page_number,
            local_offset,
            0,
            base_offset=base_offset,
        ),
        value=raw_record(
            value_payload,
            page_number,
            local_offset + 100,
            1,
            base_offset=base_offset,
        ),
    )


def mkey_pair(
    page_number: int,
    selected_anchor: BerkeleyAnchor,
    *,
    master_key_id: int = 1,
) -> BerkeleyLeafPair:
    key_payload = serialized_string("mkey") + master_key_id.to_bytes(4, "little")
    value_payload = (
        serialized_vector(ENCRYPTED_MASTER_KEY)
        + serialized_vector(SALT)
        + (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
        + serialized_vector(b"")
    )
    base_offset = selected_anchor.database_base_offset
    return BerkeleyLeafPair(
        pair_index=250,
        key=raw_record(
            key_payload,
            page_number,
            250,
            0,
            base_offset=base_offset,
        ),
        value=raw_record(
            value_payload,
            page_number,
            350,
            1,
            base_offset=base_offset,
        ),
    )


def context(
    page_number: int,
    selected_anchor: BerkeleyAnchor,
    *pairs: BerkeleyLeafPair,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
    source: str = "image.img",
) -> BerkeleyRecordPageContext:
    records = tuple(record for pair in pairs for record in (pair.key, pair.value))
    extraction = BerkeleyRecordExtraction(
        page_number=page_number,
        page_status=status,
        records=records,
        pairs=tuple(pairs),
        complete_record_count=len(records),
        deleted_record_count=0,
        incomplete_slot_count=0,
        reasons=(),
    )
    return BerkeleyRecordPageContext(source, selected_anchor, extraction)


def aggregate(*contexts: BerkeleyRecordPageContext) -> EncryptedWalletAggregation:
    return EncryptedWalletEvidenceAggregator().aggregate(contexts)


def test_empty_input() -> None:
    result = aggregate()

    assert result.groups == ()
    assert result.database_count == 0
    assert result.context_count == 0
    assert result.structural_database_count == 0
    assert result.fragment_database_count == 0
    assert result.rejected_database_count == 0


def test_one_database_with_one_ckey_is_fragment() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(100, selected_anchor, ckey_pair(100, selected_anchor))
    )

    assert result.database_count == 1
    assert result.fragment_database_count == 1
    assert result.groups[0].evidence.status is ValidationStatus.FRAGMENT
    assert result.groups[0].context_count == 1
    assert result.groups[0].page_count == 1


def test_cross_hotspot_contexts_form_one_structural_database() -> None:
    selected_anchor = anchor(metadata_page_number=7)
    hotspot_a_context = context(
        100,
        selected_anchor,
        ckey_pair(100, selected_anchor),
    )
    hotspot_b_context = context(
        900,
        selected_anchor,
        mkey_pair(900, selected_anchor),
    )

    result = aggregate(hotspot_a_context, hotspot_b_context)

    assert result.database_count == 1
    assert result.structural_database_count == 1
    assert result.groups[0].page_count == 2
    assert result.groups[0].evidence.status is ValidationStatus.STRUCTURAL


def test_many_discovery_ranges_form_one_database() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(100, selected_anchor, ckey_pair(100, selected_anchor)),
        context(200, selected_anchor, ckey_pair(200, selected_anchor)),
        context(300, selected_anchor, ckey_pair(300, selected_anchor)),
        context(900, selected_anchor, mkey_pair(900, selected_anchor)),
    )

    group = result.groups[0]
    assert result.database_count == 1
    assert group.evidence.valid_ckey_count == 3
    assert group.evidence.valid_mkey_count == 1


def test_two_different_database_bases_form_two_groups() -> None:
    anchor_a = anchor(base_offset=BASE_OFFSET)
    anchor_b = anchor(base_offset=2_000_000)
    result = aggregate(
        context(10, anchor_a, ckey_pair(10, anchor_a)),
        context(20, anchor_b, mkey_pair(20, anchor_b)),
    )

    assert result.database_count == 2
    assert result.fragment_database_count == 2
    assert {group.anchor for group in result.groups} == {anchor_a, anchor_b}


def test_input_order_does_not_change_result_or_group_order() -> None:
    anchor_a = anchor(base_offset=BASE_OFFSET)
    anchor_b = anchor(base_offset=2_000_000)
    contexts = (
        context(20, anchor_b, mkey_pair(20, anchor_b), source="z.img"),
        context(12, anchor_a, mkey_pair(12, anchor_a), source="a.img"),
        context(10, anchor_a, ckey_pair(10, anchor_a), source="a.img"),
    )

    forward = aggregate(*contexts)
    reverse = aggregate(*reversed(contexts))

    assert forward == reverse
    assert [group.source for group in forward.groups] == ["a.img", "z.img"]


def test_same_base_with_different_metadata_anchors_forms_two_groups() -> None:
    anchor_a = anchor(metadata_page_number=0)
    anchor_b = anchor(metadata_page_number=7)
    result = aggregate(
        context(10, anchor_a, ckey_pair(10, anchor_a)),
        context(12, anchor_b, mkey_pair(12, anchor_b)),
    )

    assert anchor_a.database_base_offset == anchor_b.database_base_offset
    assert anchor_a != anchor_b
    assert result.database_count == 2
    assert result.fragment_database_count == 2
    assert all(
        group.evidence.status is ValidationStatus.FRAGMENT
        for group in result.groups
    )


def test_same_anchor_geometry_from_different_sources_forms_two_groups() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(
            10,
            selected_anchor,
            ckey_pair(10, selected_anchor),
            source="image-a.img",
        ),
        context(
            12,
            selected_anchor,
            mkey_pair(12, selected_anchor),
            source="image-b.img",
        ),
    )

    assert result.database_count == 2
    assert result.fragment_database_count == 2
    assert {group.source for group in result.groups} == {
        "image-a.img",
        "image-b.img",
    }


def test_windows_source_aliases_are_normalized_before_grouping() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(
            10,
            selected_anchor,
            ckey_pair(10, selected_anchor),
            source=r"C:\Images\DISK.img",
        ),
        context(
            12,
            selected_anchor,
            mkey_pair(12, selected_anchor),
            source="c:/images/disk.img",
        ),
    )

    assert result.database_count == 1
    assert result.groups[0].source == r"c:\images\disk.img"
    assert result.groups[0].evidence.status is ValidationStatus.STRUCTURAL


def test_identical_duplicate_context_is_counted_once() -> None:
    selected_anchor = anchor()
    duplicate = context(
        10,
        selected_anchor,
        ckey_pair(10, selected_anchor),
    )

    result = aggregate(duplicate, duplicate)

    assert result.context_count == 1
    assert result.groups[0].context_count == 1
    assert result.groups[0].page_count == 1
    assert result.groups[0].evidence.valid_ckey_count == 1


def test_conflicting_duplicate_context_raises_value_error() -> None:
    selected_anchor = anchor()
    original = context(
        10,
        selected_anchor,
        ckey_pair(10, selected_anchor),
    )
    conflicting = replace(
        original,
        extraction=replace(original.extraction, reasons=("different",)),
    )

    with pytest.raises(ValueError, match="conflicting duplicate context"):
        aggregate(original, conflicting)


def test_structural_evidence_is_not_downgraded_by_fragment() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(10, selected_anchor, ckey_pair(10, selected_anchor)),
        context(12, selected_anchor, mkey_pair(12, selected_anchor)),
        context(
            13,
            selected_anchor,
            ckey_pair(13, selected_anchor),
            status=ValidationStatus.FRAGMENT,
        ),
    )

    evidence = result.groups[0].evidence
    assert evidence.status is ValidationStatus.STRUCTURAL
    assert evidence.structural_ckey_count == 1
    assert evidence.structural_mkey_count == 1
    assert evidence.fragment_ckey_count == 1


def test_partially_overwritten_database_remains_one_structural_group() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(10, selected_anchor, ckey_pair(10, selected_anchor)),
        context(11, selected_anchor, status=ValidationStatus.REJECTED),
        context(12, selected_anchor, mkey_pair(12, selected_anchor)),
        context(
            13,
            selected_anchor,
            ckey_pair(13, selected_anchor),
            status=ValidationStatus.FRAGMENT,
        ),
    )

    group = result.groups[0]
    assert result.database_count == 1
    assert group.context_count == 4
    assert group.page_count == 4
    assert group.evidence.status is ValidationStatus.STRUCTURAL
    assert group.evidence.evidence["rejected_page_numbers"] == (11,)


def test_rejected_database_group_is_preserved_and_counted() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(10, selected_anchor, status=ValidationStatus.REJECTED)
    )

    assert result.database_count == 1
    assert result.rejected_database_count == 1
    assert result.groups[0].evidence.status is ValidationStatus.REJECTED


def test_aggregation_models_are_immutable() -> None:
    selected_anchor = anchor()
    result = aggregate(
        context(10, selected_anchor, ckey_pair(10, selected_anchor))
    )

    with pytest.raises(FrozenInstanceError):
        result.context_count = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.groups[0].page_count = 2  # type: ignore[misc]


def test_aggregator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("aggregator attempted file I/O")

    monkeypatch.setattr(builtins, "open", fail_open)
    selected_anchor = anchor()

    result = aggregate(
        context(10, selected_anchor, ckey_pair(10, selected_anchor))
    )

    assert result.database_count == 1
