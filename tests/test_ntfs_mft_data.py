from dataclasses import FrozenInstanceError
from typing import Callable

import pytest

from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap
from bfrs.recovery.ntfs_mft_data import NtfsMftDataExtractor, NtfsMftRecordError


RECORD_SIZE = 1024
SECTOR_SIZE = 512
CLUSTER_SIZE = 4096
FIRST_ATTRIBUTE_OFFSET = 56
USA_OFFSET = 48
USN = b"\xA5\x5A"
SOURCE = r"C:\Images\Hp.img"


def align8(value: int) -> int:
    return (value + 7) & ~7


def unsigned_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little")


def signed_bytes(value: int) -> bytes:
    for size in range(1, 9):
        try:
            return value.to_bytes(size, "little", signed=True)
        except OverflowError:
            continue
    raise ValueError("test delta is too large")


def allocated(cluster_count: int, delta: int) -> bytes:
    length = unsigned_bytes(cluster_count)
    lcn_delta = signed_bytes(delta)
    return bytes(((len(lcn_delta) << 4) | len(length),)) + length + lcn_delta


def sparse(cluster_count: int) -> bytes:
    length = unsigned_bytes(cluster_count)
    return bytes((len(length),)) + length


def nonresident_data(
    pairs: bytes,
    *,
    lowest_vcn: int = 0,
    highest_vcn: int,
    name: str = "",
    mapping_pairs_offset: int | None = None,
    allocated_size: int = 16_384,
    file_size: int = 16_384,
    valid_data_length: int = 16_384,
) -> bytes:
    encoded_name = name.encode("utf-16-le")
    name_offset = 64 if encoded_name else 0
    minimum_mapping_offset = align8(64 + len(encoded_name))
    if mapping_pairs_offset is None:
        mapping_pairs_offset = minimum_mapping_offset
    record_length = align8(max(minimum_mapping_offset, mapping_pairs_offset + len(pairs)))
    attribute = bytearray(record_length)
    attribute[0:4] = (0x80).to_bytes(4, "little")
    attribute[4:8] = record_length.to_bytes(4, "little")
    attribute[8] = 1
    attribute[9] = len(name)
    attribute[10:12] = name_offset.to_bytes(2, "little")
    attribute[16:24] = lowest_vcn.to_bytes(8, "little")
    attribute[24:32] = highest_vcn.to_bytes(8, "little")
    attribute[32:34] = mapping_pairs_offset.to_bytes(2, "little")
    attribute[40:48] = allocated_size.to_bytes(8, "little")
    attribute[48:56] = file_size.to_bytes(8, "little")
    attribute[56:64] = valid_data_length.to_bytes(8, "little")
    if encoded_name:
        attribute[name_offset : name_offset + len(encoded_name)] = encoded_name
    if mapping_pairs_offset < record_length:
        end = min(record_length, mapping_pairs_offset + len(pairs))
        attribute[mapping_pairs_offset:end] = pairs[: end - mapping_pairs_offset]
    return bytes(attribute)


def resident_data(value: bytes = b"resident") -> bytes:
    record_length = align8(24 + len(value))
    attribute = bytearray(record_length)
    attribute[0:4] = (0x80).to_bytes(4, "little")
    attribute[4:8] = record_length.to_bytes(4, "little")
    attribute[16:20] = len(value).to_bytes(4, "little")
    attribute[20:22] = (24).to_bytes(2, "little")
    attribute[24 : 24 + len(value)] = value
    return bytes(attribute)


def unknown_attribute(length: int = 16, type_code: int = 0x10) -> bytes:
    assert length >= 16 and length % 8 == 0
    attribute = bytearray(length)
    attribute[0:4] = type_code.to_bytes(4, "little")
    attribute[4:8] = length.to_bytes(4, "little")
    return bytes(attribute)


def file_record(
    attributes: tuple[bytes, ...],
    *,
    in_use: bool = True,
    directory: bool = False,
    first_attribute_offset: int = FIRST_ATTRIBUTE_OFFSET,
    record_number: int = 1234,
    mutate_fixed: Callable[[bytearray], None] | None = None,
) -> bytes:
    fixed = bytearray(RECORD_SIZE)
    fixed[:4] = b"FILE"
    fixed[4:6] = USA_OFFSET.to_bytes(2, "little")
    fixed[6:8] = (3).to_bytes(2, "little")
    fixed[20:22] = first_attribute_offset.to_bytes(2, "little")
    flags = (1 if in_use else 0) | (2 if directory else 0)
    fixed[22:24] = flags.to_bytes(2, "little")
    fixed[28:32] = RECORD_SIZE.to_bytes(4, "little")
    fixed[44:48] = record_number.to_bytes(4, "little")
    cursor = first_attribute_offset
    for attribute in attributes:
        fixed[cursor : cursor + len(attribute)] = attribute
        cursor += len(attribute)
    fixed[cursor : cursor + 4] = (0xFFFFFFFF).to_bytes(4, "little")
    fixed[24:28] = (cursor + 4).to_bytes(4, "little")
    if mutate_fixed:
        mutate_fixed(fixed)

    replacements = (bytes(fixed[510:512]), bytes(fixed[1022:1024]))
    fixed[USA_OFFSET : USA_OFFSET + 2] = USN
    fixed[USA_OFFSET + 2 : USA_OFFSET + 4] = replacements[0]
    fixed[USA_OFFSET + 4 : USA_OFFSET + 6] = replacements[1]
    fixed[510:512] = USN
    fixed[1022:1024] = USN
    return bytes(fixed)


def extract(record: bytes):
    return NtfsMftDataExtractor().extract(
        record,
        bytes_per_sector=SECTOR_SIZE,
        cluster_size=CLUSTER_SIZE,
        partition_offset=10_000,
    )


def basic_pairs() -> bytes:
    return allocated(2, 256) + allocated(2, 12_207 - 256) + b"\x00"


def test_fixup_restores_nonresident_header_crossing_sector_boundary() -> None:
    data = nonresident_data(basic_pairs(), highest_vcn=3)
    record = file_record((unknown_attribute(424), data))
    result = extract(record)
    assert result is not None
    assert result.highest_vcn == 3
    assert result.evidence["selected_attribute_offset"] == 480
    assert len(result.extent_mapping.extents) == 2


def test_fixup_mismatch_rejects_record_before_attribute_parsing() -> None:
    record = bytearray(file_record((nonresident_data(basic_pairs(), highest_vcn=3),)))
    record[510:512] = b"XX"
    with pytest.raises(NtfsMftRecordError, match="update_sequence_mismatch"):
        extract(bytes(record))


def test_invalid_usa_offset_is_rejected() -> None:
    record = bytearray(file_record((nonresident_data(basic_pairs(), highest_vcn=3),)))
    record[4:6] = (1020).to_bytes(2, "little")
    with pytest.raises(NtfsMftRecordError, match="update_sequence_array_invalid"):
        extract(bytes(record))


def test_invalid_signature_and_first_attribute_offset_are_rejected() -> None:
    record = bytearray(file_record((nonresident_data(basic_pairs(), highest_vcn=3),)))
    record[:4] = b"BAAD"
    with pytest.raises(NtfsMftRecordError, match="file_signature_invalid"):
        extract(bytes(record))
    invalid_offset = bytearray(file_record((nonresident_data(basic_pairs(), highest_vcn=3),)))
    invalid_offset[20:22] = (1024).to_bytes(2, "little")
    with pytest.raises(NtfsMftRecordError, match="first_attribute_offset_invalid"):
        extract(bytes(invalid_offset))


def test_valid_nonresident_data_and_logical_page_map_integration() -> None:
    result = extract(file_record((unknown_attribute(), nonresident_data(basic_pairs(), highest_vcn=3))))
    assert result is not None
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        4096,
        "little",
        result.extent_mapping.extents,
        logical_file_size=result.file_size,
    )
    assert tuple(page.physical_offset for page in page_map.pages()) == (
        10_000 + 256 * CLUSTER_SIZE,
        10_000 + 257 * CLUSTER_SIZE,
        10_000 + 12_207 * CLUSTER_SIZE,
        10_000 + 12_208 * CLUSTER_SIZE,
    )


def test_deleted_file_record_still_returns_mapping() -> None:
    result = extract(file_record((nonresident_data(basic_pairs(), highest_vcn=3),), in_use=False))
    assert result is not None
    assert result.in_use is False
    assert result.directory is False
    assert result.record_number == 1234


def test_named_ads_is_ignored_and_unnamed_data_is_selected() -> None:
    named = nonresident_data(allocated(1, 99) + b"\x00", highest_vcn=0, name="ads")
    unnamed = nonresident_data(basic_pairs(), highest_vcn=3)
    result = extract(file_record((named, unknown_attribute(), unnamed)))
    assert result is not None
    assert result.extent_mapping.runs[0].lcn_start == 256
    assert result.evidence["named_data_attribute_count"] == 1


def test_mapping_pairs_slice_excludes_following_attribute() -> None:
    data = nonresident_data(basic_pairs(), highest_vcn=3)
    following = unknown_attribute(32, type_code=0xB0)
    result = extract(file_record((data, following), record_number=0))
    assert result is not None
    assert result.record_number == 0
    assert result.evidence["selected_attribute_length"] == len(data)
    assert result.evidence["mapping_pairs_input_length"] == len(basic_pairs())
    assert result.evidence["mapping_pairs_region_length"] < (
        len(data) + len(following)
    )
    assert result.evidence["attribute_boundary_ok"] is True


def test_zero_alignment_padding_is_trimmed_before_decoder() -> None:
    result = extract(
        file_record((nonresident_data(basic_pairs(), highest_vcn=3),))
    )
    assert result is not None
    assert result.evidence["mapping_pairs_terminator_offset"] == 8
    assert result.evidence["mapping_pairs_trailing_byte_count"] == 7
    assert result.evidence["mapping_pairs_trailing_nonzero_count"] == 0
    assert result.evidence["mapping_pairs_trailing_classification"] == (
        "zero_attribute_alignment_padding"
    )


def test_bounded_nonzero_attribute_alignment_slack_is_trimmed() -> None:
    pairs = basic_pairs() + bytes.fromhex("ca44860060608a")
    result = extract(file_record((nonresident_data(pairs, highest_vcn=3),)))
    assert result is not None
    assert result.evidence["mapping_pairs_input_length"] == len(basic_pairs())
    assert result.evidence["mapping_pairs_trailing_byte_count"] == 7
    assert result.evidence["mapping_pairs_trailing_nonzero_count"] == 6
    assert result.evidence["mapping_pairs_trailing_classification"] == (
        "nonzero_attribute_alignment_slack"
    )


def test_nonzero_trailing_beyond_alignment_slack_is_rejected() -> None:
    pairs = basic_pairs() + b"\x99" * 8
    data = nonresident_data(pairs, highest_vcn=3)
    with pytest.raises(NtfsMftRecordError, match="mapping_pairs_trailing_data"):
        extract(file_record((data,)))


def test_resident_unnamed_data_returns_none() -> None:
    assert extract(file_record((resident_data(),))) is None


def test_two_unnamed_data_attributes_are_ambiguous() -> None:
    data = nonresident_data(basic_pairs(), highest_vcn=3)
    with pytest.raises(NtfsMftRecordError, match="unnamed_data_attribute_ambiguous"):
        extract(file_record((data, data)))


def test_attribute_record_length_beyond_file_is_rejected() -> None:
    def corrupt(fixed: bytearray) -> None:
        fixed[FIRST_ATTRIBUTE_OFFSET + 4 : FIRST_ATTRIBUTE_OFFSET + 8] = (2048).to_bytes(4, "little")

    with pytest.raises(NtfsMftRecordError, match="attribute_record_length_invalid"):
        extract(file_record((unknown_attribute(),), mutate_fixed=corrupt))


def test_attribute_must_end_within_file_record_bytes_in_use() -> None:
    data = nonresident_data(basic_pairs(), highest_vcn=3)

    def shorten_bytes_in_use(fixed: bytearray) -> None:
        boundary = FIRST_ATTRIBUTE_OFFSET + len(data) - 8
        fixed[24:28] = boundary.to_bytes(4, "little")

    with pytest.raises(
        NtfsMftRecordError,
        match="attribute_record_length_invalid",
    ):
        extract(file_record((data,), mutate_fixed=shorten_bytes_in_use))


@pytest.mark.parametrize("before_header", [True, False])
def test_mapping_pairs_offset_outside_nonresident_payload_is_rejected(before_header: bool) -> None:
    data = bytearray(nonresident_data(basic_pairs(), highest_vcn=3))
    mapping_offset = 56 if before_header else len(data)
    data[32:34] = mapping_offset.to_bytes(2, "little")
    with pytest.raises(NtfsMftRecordError, match="mapping_pairs_offset_invalid"):
        extract(file_record((bytes(data),)))


def test_truncated_mapping_pairs_are_rejected() -> None:
    data = nonresident_data(
        b"\x21\x01\x01",
        highest_vcn=0,
        mapping_pairs_offset=69,
    )
    with pytest.raises(NtfsMftRecordError, match="mapping_pairs_invalid"):
        extract(file_record((data,)))


def test_complete_mapping_pair_without_terminator_is_rejected() -> None:
    data = nonresident_data(
        b"\x11\x01\x01",
        highest_vcn=0,
        mapping_pairs_offset=69,
    )
    with pytest.raises(
        NtfsMftRecordError,
        match="mapping_pairs_terminator_missing",
    ):
        extract(file_record((data,)))


def test_nonzero_lowest_vcn_is_preserved_and_marked_partial() -> None:
    data = nonresident_data(
        allocated(2, 500) + b"\x00",
        lowest_vcn=10,
        highest_vcn=11,
        file_size=12 * CLUSTER_SIZE,
    )
    result = extract(file_record((data,)))
    assert result is not None
    assert result.partial_extent_mapping is True
    assert result.extent_mapping.runs[0].vcn_start == 10
    assert result.extent_mapping.extents[0].logical_start == 10 * CLUSTER_SIZE


def test_attribute_list_is_reported_as_partial_without_reconstruction() -> None:
    attribute_list = unknown_attribute(type_code=0x20)
    data = nonresident_data(basic_pairs(), highest_vcn=3)
    result = extract(file_record((attribute_list, data)))
    assert result is not None
    assert result.partial_extent_mapping is True
    assert result.evidence["attribute_list_present"] is True


def test_highest_vcn_mismatch_is_rejected_not_repaired() -> None:
    data = nonresident_data(allocated(2, 100) + b"\x00", highest_vcn=5)
    with pytest.raises(NtfsMftRecordError, match="highest_vcn_mismatch"):
        extract(file_record((data,)))


def test_sparse_run_remains_missing_in_logical_page_map() -> None:
    pairs = allocated(1, 100) + sparse(2) + allocated(1, 50) + b"\x00"
    result = extract(file_record((nonresident_data(pairs, highest_vcn=3),)))
    assert result is not None
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        CLUSTER_SIZE,
        "little",
        result.extent_mapping.extents,
        logical_file_size=4 * CLUSTER_SIZE,
    )
    assert result.extent_mapping.sparse_ranges[0].logical_start == CLUSTER_SIZE
    assert page_map.missing_pages() == (1, 2)


def test_sparse_run_does_not_change_lcn_base_for_following_negative_delta() -> None:
    pairs = (
        allocated(1, 100)
        + allocated(1, 50)
        + sparse(1)
        + allocated(1, -120)
        + b"\x00"
    )
    result = extract(file_record((nonresident_data(pairs, highest_vcn=3),)))
    assert result is not None
    assert tuple(run.lcn_start for run in result.extent_mapping.runs) == (
        100,
        150,
        None,
        30,
    )


def test_result_is_immutable_and_contains_no_fixed_record() -> None:
    result = extract(file_record((nonresident_data(basic_pairs(), highest_vcn=3),)))
    assert result is not None
    with pytest.raises(FrozenInstanceError):
        result.in_use = False  # type: ignore[misc]
    assert not any(isinstance(value, bytes) for value in result.evidence.values())


def test_extractor_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    assert extract(file_record((nonresident_data(basic_pairs(), highest_vcn=3),))) is not None
