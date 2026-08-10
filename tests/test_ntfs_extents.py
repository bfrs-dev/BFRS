from dataclasses import FrozenInstanceError

import pytest

from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap
from bfrs.recovery.ntfs_extents import (
    NtfsMappingPairsDecoder,
    NtfsMappingPairsError,
)


CLUSTER_SIZE = 4096
SOURCE = r"C:\Images\Hp.img"


def unsigned_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little")


def signed_bytes(value: int) -> bytes:
    for size in range(1, 9):
        try:
            encoded = value.to_bytes(size, "little", signed=True)
        except OverflowError:
            continue
        if int.from_bytes(encoded, "little", signed=True) == value:
            return encoded
    raise ValueError("test delta does not fit in eight bytes")


def allocated(cluster_count: int, lcn_delta: int) -> bytes:
    length = unsigned_bytes(cluster_count)
    delta = signed_bytes(lcn_delta)
    return bytes(((len(delta) << 4) | len(length),)) + length + delta


def sparse(cluster_count: int) -> bytes:
    length = unsigned_bytes(cluster_count)
    return bytes((len(length),)) + length


def decode(
    data: bytes,
    *,
    lowest_vcn: int = 0,
    highest_vcn: int | None = None,
    cluster_size: int = CLUSTER_SIZE,
    partition_offset: int = 0,
):
    return NtfsMappingPairsDecoder().decode(
        data,
        lowest_vcn=lowest_vcn,
        highest_vcn=highest_vcn,
        cluster_size=cluster_size,
        partition_offset=partition_offset,
    )


def test_single_allocated_run_uses_cluster_size_and_partition_offset() -> None:
    result = decode(
        allocated(8, 128) + b"\x00",
        highest_vcn=7,
        cluster_size=1024,
        partition_offset=10_000,
    )
    assert result.runs[0].vcn_start == 0
    assert result.runs[0].vcn_end == 8
    assert result.runs[0].logical_cluster_end == 8
    assert result.extents[0].logical_start == 0
    assert result.extents[0].physical_start == 10_000 + 128 * 1024
    assert result.extents[0].length == 8 * 1024


def test_lowest_vcn_starts_first_run_and_highest_vcn_is_inclusive() -> None:
    result = decode(allocated(3, 10) + b"\x00", lowest_vcn=7, highest_vcn=9)
    assert result.runs[0].vcn_start == 7
    assert result.runs[0].vcn_end == 10
    assert result.highest_vcn == 9
    assert result.extents[0].logical_start == 7 * CLUSTER_SIZE


def test_negative_lcn_delta_preserves_vcn_order() -> None:
    pairs = allocated(1, 100) + allocated(1, 50) + allocated(1, -120) + b"\x00"
    result = decode(pairs, highest_vcn=2)
    assert tuple(run.vcn_start for run in result.runs) == (0, 1, 2)
    assert tuple(run.lcn_start for run in result.runs) == (100, 150, 30)
    assert tuple(extent.physical_start for extent in result.extents) == (
        100 * CLUSTER_SIZE,
        150 * CLUSTER_SIZE,
        30 * CLUSTER_SIZE,
    )


def test_fragmented_wallet_mapping_integrates_with_logical_page_map() -> None:
    first_lcn = 256
    second_lcn = 12_207
    pairs = allocated(2, first_lcn) + allocated(2, second_lcn - first_lcn) + b"\x00"
    mapping = decode(pairs, highest_vcn=3)
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        page_size=4096,
        byte_order="little",
        extents=mapping.extents,
        logical_file_size=4 * 4096,
    )
    assert tuple(page.physical_offset for page in page_map.pages()) == (
        first_lcn * CLUSTER_SIZE,
        (first_lcn + 1) * CLUSTER_SIZE,
        second_lcn * CLUSTER_SIZE,
        (second_lcn + 1) * CLUSTER_SIZE,
    )


def test_sparse_run_becomes_missing_pages_not_zero_filled_extent() -> None:
    pairs = allocated(2, 100) + sparse(2) + allocated(2, 50) + b"\x00"
    mapping = decode(pairs, highest_vcn=5)
    assert tuple(run.sparse for run in mapping.runs) == (False, True, False)
    assert len(mapping.extents) == 2
    assert mapping.sparse_ranges[0].logical_start == 2 * CLUSTER_SIZE
    assert mapping.sparse_ranges[0].length == 2 * CLUSTER_SIZE
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        4096,
        "little",
        mapping.extents,
        logical_file_size=6 * CLUSTER_SIZE,
    )
    assert page_map.missing_pages() == (2, 3)
    assert tuple(page.page_number for page in page_map.pages()) == (0, 1, 4, 5)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"\x11", "mapping_pair_truncated"),
        (b"\x21\x01\x01", "mapping_pair_truncated"),
        (b"\x11\x00\x01\x00", "run_length_zero"),
        (b"\x11\x01\x01", "mapping_pairs_terminator_missing"),
        (b"\x19", "mapping_pair_field_too_large"),
    ],
)
def test_malformed_or_truncated_mapping_pairs_are_controlled(
    data: bytes,
    reason: str,
) -> None:
    with pytest.raises(NtfsMappingPairsError, match=reason):
        decode(data)


def test_nonzero_data_after_terminator_is_rejected() -> None:
    with pytest.raises(NtfsMappingPairsError, match="trailing_data"):
        decode(allocated(1, 1) + b"\x00\x01")


def test_highest_vcn_mismatch_is_not_repaired() -> None:
    with pytest.raises(NtfsMappingPairsError, match="highest_vcn_mismatch"):
        decode(allocated(2, 10) + b"\x00", highest_vcn=5)


def test_allocated_lcn_must_not_become_negative() -> None:
    with pytest.raises(NtfsMappingPairsError, match="lcn_negative"):
        decode(allocated(1, -1) + b"\x00")


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"lowest_vcn": -1}, "lowest_vcn"),
        ({"lowest_vcn": 2, "highest_vcn": 1}, "highest_vcn"),
        ({"cluster_size": 0}, "cluster_size"),
        ({"partition_offset": -1}, "partition_offset"),
    ],
)
def test_invalid_api_configuration_raises_value_error(
    changes: dict[str, int],
    reason: str,
) -> None:
    arguments = {
        "lowest_vcn": 0,
        "highest_vcn": None,
        "cluster_size": CLUSTER_SIZE,
        "partition_offset": 0,
    }
    arguments.update(changes)
    with pytest.raises(ValueError, match=reason):
        NtfsMappingPairsDecoder().decode(b"\x00", **arguments)  # type: ignore[arg-type]


def test_runs_and_mapping_are_immutable() -> None:
    result = decode(allocated(1, 10) + b"\x00")
    with pytest.raises(FrozenInstanceError):
        result.cluster_size = 512  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.runs[0].cluster_count = 2  # type: ignore[misc]


def test_decoder_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    assert decode(allocated(1, 10) + b"\x00").runs[0].lcn_start == 10
