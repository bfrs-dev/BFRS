from dataclasses import FrozenInstanceError, fields, is_dataclass

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.logical_berkeley_reader import (
    LogicalBerkeleyDatabaseIdentity,
    LogicalBerkeleyMetadataAnchor,
    LogicalBerkeleyPageReader,
    PhysicalRangeReadError,
)
from bfrs.recovery.logical_page_map import (
    LogicalBerkeleyPageMap,
    LogicalPageLocation,
)
from bfrs.recovery.ntfs_extents import NtfsMappingPairsDecoder
from bfrs.validators.berkeley_metadata import BTREE_MAGIC


SOURCE = r"C:\Images\Hp.img"


class MemoryRangeReader:
    def __init__(self, ranges: dict[int, bytes]) -> None:
        self.ranges = ranges
        self.calls: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        if offset not in self.ranges:
            raise PhysicalRangeReadError("unmapped test range")
        return self.ranges[offset][:length]


def empty_leaf(page_number: int, page_size: int = 4096) -> bytes:
    page = bytearray(page_size)
    page[8:12] = page_number.to_bytes(4, "little")
    page[22:24] = page_size.to_bytes(2, "little")
    page[24] = 1
    page[25] = 5
    return bytes(page)


def metadata_page(page_number: int, page_size: int = 512) -> bytes:
    page = bytearray(page_size)
    put = lambda offset, value: page.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, "little")
    )
    put(8, page_number)
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, page_size)
    page[25] = 9
    put(32, max(page_number + 1, 10))
    put(48, 0x20)
    put(88, 1)
    return bytes(page)


def page_map(
    mappings: tuple[tuple[int, int], ...],
    *,
    page_size: int = 4096,
) -> LogicalBerkeleyPageMap:
    return LogicalBerkeleyPageMap(
        SOURCE,
        page_size,
        "little",
        (
            LogicalPageLocation(number, offset, page_size, SOURCE)
            for number, offset in mappings
        ),
    )


def reader(
    mappings: tuple[tuple[int, int], ...],
    ranges: dict[int, bytes],
    *,
    page_size: int = 4096,
) -> tuple[LogicalBerkeleyPageReader, MemoryRangeReader]:
    physical = MemoryRangeReader(ranges)
    logical = LogicalBerkeleyPageReader(
        page_map(mappings, page_size=page_size),
        logical_file_id="mft:record-1234:$DATA",
        range_reader=physical,
    )
    return logical, physical


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if is_dataclass(value) and not isinstance(value, type):
        return any(contains_bytes(getattr(value, field.name)) for field in fields(value))
    if isinstance(value, dict):
        return any(contains_bytes(key) or contains_bytes(item) for key, item in value.items())
    if isinstance(value, (tuple, list)):
        return any(contains_bytes(item) for item in value)
    return False


def test_physically_fragmented_pages_validate_by_logical_number() -> None:
    mappings = ((10, 1_000_000), (11, 50_000_000))
    logical, physical = reader(
        mappings,
        {
            1_000_000: empty_leaf(10),
            50_000_000: empty_leaf(11),
        },
    )
    pages = logical.validate_pages()
    assert tuple(page.page_number for page in pages) == (10, 11)
    assert all(page.validation.status is ValidationStatus.STRUCTURAL for page in pages)
    assert physical.calls == [(1_000_000, 4096), (50_000_000, 4096)]


def test_reversed_physical_order_keeps_logical_order() -> None:
    mappings = ((12, 30_000_000), (10, 50_000_000), (11, 1_000_000))
    logical, _ = reader(
        mappings,
        {offset: empty_leaf(number) for number, offset in mappings},
    )
    pages = logical.validate_pages()
    assert tuple(page.page_number for page in pages) == (10, 11, 12)
    assert tuple(page.physical_offset for page in pages) == (
        50_000_000,
        1_000_000,
        30_000_000,
    )


def test_logical_page_number_mismatch_is_rejected_without_remapping() -> None:
    logical, _ = reader(((100, 2_000_000),), {2_000_000: empty_leaf(101)})
    page = logical.validate_pages()[0]
    assert page.page_number == 100
    assert page.validation.status is ValidationStatus.REJECTED
    assert page.validation.evidence["reasons"] == ("page_number_mismatch",)


def test_short_read_is_passed_unpadded_to_existing_validator() -> None:
    logical, _ = reader(((5, 1000),), {1000: empty_leaf(5)[:3000]})
    page = logical.validate_pages()[0]
    assert page.mapped_complete is False
    assert page.validation.status is ValidationStatus.FRAGMENT
    assert page.validation.end_offset == 4000


def test_zero_read_and_controlled_error_cannot_be_structural() -> None:
    zero, _ = reader(((5, 1000),), {1000: b""})
    assert zero.validate_pages()[0].validation.status is ValidationStatus.REJECTED
    failed, _ = reader(((5, 2000),), {})
    result = failed.validate_pages()[0]
    assert result.validation.status is ValidationStatus.REJECTED
    assert result.validation.evidence["reasons"] == ("physical_read_error",)


def test_missing_pages_are_not_read() -> None:
    logical_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        4096,
        "little",
        (),
        logical_file_size=2 * 4096,
    )
    physical = MemoryRangeReader({})
    logical = LogicalBerkeleyPageReader(
        logical_map,
        logical_file_id="missing-file",
        range_reader=physical,
    )
    assert logical.validate_pages() == ()
    assert physical.calls == []
    assert logical.summarize().missing_page_count == 2


def test_duplicate_physical_offset_does_not_make_two_pages_valid() -> None:
    shared = 1_000_000
    logical, _ = reader(
        ((10, shared), (11, shared)),
        {shared: empty_leaf(10)},
    )
    pages = logical.validate_pages()
    assert pages[0].validation.status is ValidationStatus.STRUCTURAL
    assert pages[1].validation.status is ValidationStatus.REJECTED


def test_random_non_berkeley_bytes_are_rejected_normally() -> None:
    logical, _ = reader(((5, 1000),), {1000: b"random" * 600})
    assert logical.validate_pages()[0].validation.status is ValidationStatus.REJECTED


def test_main_fragmented_wallet_regression_across_two_distant_extents() -> None:
    two_gib = 2 * 1024**3
    forty_four_gib = 44 * 1024**3
    mappings = (
        (10, two_gib),
        (11, two_gib + 4096),
        (12, forty_four_gib),
        (13, forty_four_gib + 4096),
    )
    logical, _ = reader(
        mappings,
        {offset: empty_leaf(number) for number, offset in mappings},
    )
    pages = logical.validate_pages()
    assert tuple(page.page_number for page in pages) == (10, 11, 12, 13)
    assert all(page.validation.status is ValidationStatus.STRUCTURAL for page in pages)


def test_ntfs_extents_to_page_map_to_reader_integration() -> None:
    pairs = b"\x21\x02\x00\x01\x21\x02\xAF\x2E\x00"
    mapping = NtfsMappingPairsDecoder().decode(
        pairs,
        lowest_vcn=0,
        highest_vcn=3,
        cluster_size=4096,
    )
    logical_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        4096,
        "little",
        mapping.extents,
        logical_file_size=4 * 4096,
    )
    ranges = {
        location.physical_offset: empty_leaf(location.page_number)
        for location in logical_map.pages()
    }
    logical = LogicalBerkeleyPageReader(
        logical_map,
        logical_file_id="ntfs-extents-integration",
        range_reader=MemoryRangeReader(ranges),
    )
    pages = logical.validate_pages()
    assert tuple(page.page_number for page in pages) == (0, 1, 2, 3)
    assert all(page.validation.status is ValidationStatus.STRUCTURAL for page in pages)


def test_structural_metadata_creates_logical_anchor_without_base_offset() -> None:
    logical, _ = reader(
        ((0, 50_000_000), (7, 1_000_000)),
        {
            50_000_000: metadata_page(0),
            1_000_000: metadata_page(7),
        },
        page_size=512,
    )
    anchors = logical.find_metadata_pages()
    assert tuple(anchor.metadata_page_number for anchor in anchors) == (0, 7)
    assert all(not hasattr(anchor, "database_base_offset") for anchor in anchors)
    assert anchors[0].identity == anchors[1].identity
    relocated = LogicalBerkeleyMetadataAnchor(
        identity=anchors[0].identity,
        metadata_page_number=anchors[0].metadata_page_number,
        page_size=anchors[0].page_size,
        byte_order=anchors[0].byte_order,
        root_page=anchors[0].root_page,
        metadata_physical_offset=999_999_999,
    )
    assert relocated == anchors[0]


def test_metadata_page_number_mismatch_is_rejected() -> None:
    logical, _ = reader(
        ((5, 1_000_000),),
        {1_000_000: metadata_page(6)},
        page_size=512,
    )
    metadata = logical.validate_metadata_pages()[0]
    assert metadata.validation.status is ValidationStatus.REJECTED
    assert "metadata_page_number_mismatch" in metadata.validation.evidence["reasons"]
    assert logical.find_metadata_pages() == ()


def test_fragment_metadata_is_diagnostic_but_creates_no_anchor() -> None:
    data = metadata_page(5, page_size=4096)[:512]
    logical, _ = reader(((5, 1000),), {1000: data}, page_size=4096)
    metadata = logical.validate_metadata_pages()[0]
    assert metadata.validation.status is ValidationStatus.FRAGMENT
    assert logical.find_metadata_pages() == ()
    assert logical.summarize().metadata_fragment_count == 1


def test_identity_and_public_results_are_immutable_and_byte_free() -> None:
    logical, _ = reader(((1, 1000),), {1000: empty_leaf(1)})
    page = logical.validate_pages()[0]
    assert contains_bytes(page) is False
    with pytest.raises(FrozenInstanceError):
        page.page_number = 2  # type: ignore[misc]
    with pytest.raises(ValueError, match="logical_file_id"):
        LogicalBerkeleyDatabaseIdentity(SOURCE, 4096, "little", " ")


def test_summary_counts_page_and_metadata_statuses() -> None:
    logical, _ = reader(
        ((1, 1000), (2, 10_000)),
        {1000: empty_leaf(1), 10_000: b""},
    )
    summary = logical.summarize()
    assert summary.mapped_page_count == 2
    assert summary.validated_structural_count == 1
    assert summary.validated_rejected_count == 1
    assert summary.logical_anchor_count == 0


def test_reader_performs_no_direct_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    logical, _ = reader(((1, 1000),), {1000: empty_leaf(1)})
    assert logical.validate_pages()[0].validation.status is ValidationStatus.STRUCTURAL
