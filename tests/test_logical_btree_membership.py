from dataclasses import FrozenInstanceError

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.logical_berkeley_reader import (
    LogicalBerkeleyMetadataAnchor,
    LogicalBerkeleyPageReader,
    PhysicalRangeReadError,
)
from bfrs.recovery.logical_btree_membership import LogicalBtreeMembershipResolver
from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap, LogicalPageLocation
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.berkeley_page import BTREE_INTERNAL, BTREE_LEAF, DELETE_FLAG, PAGE_HEADER_SIZE


PAGE_SIZE = 512
SOURCE = r"C:\Images\Hp.img"


class MemoryReader:
    def __init__(self, pages: dict[int, bytes]) -> None:
        self.pages = pages

    def read_at(self, offset: int, length: int) -> bytes:
        try:
            return self.pages[offset][:length]
        except KeyError as exc:
            raise PhysicalRangeReadError("missing") from exc


def internal_record(
    child: int,
    *,
    deleted: bool = False,
    key: bytes = b"k",
) -> bytes:
    record_type = 1 | (DELETE_FLAG if deleted else 0)
    return (
        len(key).to_bytes(2, "little")
        + bytes((record_type, 0))
        + child.to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + key
    )


def data_page(
    page_number: int,
    *,
    level: int,
    page_type: int,
    records: tuple[bytes, ...] = (),
) -> bytes:
    page = bytearray(PAGE_SIZE)
    cursor = PAGE_SIZE
    slots: list[int] = []
    for record in records:
        cursor -= len(record)
        page[cursor : cursor + len(record)] = record
        slots.append(cursor)
    page[8:12] = page_number.to_bytes(4, "little")
    page[20:22] = len(records).to_bytes(2, "little")
    page[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, "little")
    page[24] = level
    page[25] = page_type
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + index * 2
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page)


def leaf(page_number: int) -> bytes:
    return data_page(page_number, level=1, page_type=BTREE_LEAF)


def internal(page_number: int, level: int, *children: int) -> bytes:
    return data_page(
        page_number,
        level=level,
        page_type=BTREE_INTERNAL,
        records=tuple(internal_record(child) for child in children),
    )


def metadata(page_number: int, root: int) -> bytes:
    page = bytearray(PAGE_SIZE)
    put = lambda offset, value: page.__setitem__(
        slice(offset, offset + 4), value.to_bytes(4, "little")
    )
    put(8, page_number)
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, PAGE_SIZE)
    page[25] = 9
    put(32, max(root, page_number) + 1000)
    put(48, 0x20)
    put(88, root)
    return bytes(page)


def make_reader(
    logical_to_physical: dict[int, int],
    physical_pages: dict[int, bytes],
) -> LogicalBerkeleyPageReader:
    page_map = LogicalBerkeleyPageMap(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            LogicalPageLocation(number, offset, PAGE_SIZE, SOURCE)
            for number, offset in logical_to_physical.items()
        ),
    )
    return LogicalBerkeleyPageReader(
        page_map,
        logical_file_id="mft:1234:data",
        range_reader=MemoryReader(physical_pages),
    )


def anchor(reader: LogicalBerkeleyPageReader, metadata_page: int, root: int):
    return LogicalBerkeleyMetadataAnchor(
        identity=reader.identity,
        metadata_page_number=metadata_page,
        page_size=PAGE_SIZE,
        byte_order="little",
        root_page=root,
        metadata_physical_offset=999,
    )


def resolve(reader: LogicalBerkeleyPageReader, metadata_page: int, root: int):
    return LogicalBtreeMembershipResolver(anchor(reader, metadata_page, root), reader).resolve()


def test_root_as_leaf_is_structural() -> None:
    reader = make_reader({10: 1_000_000}, {1_000_000: leaf(10)})
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.reachable_page_numbers == (10,)
    assert result.leaf_page_numbers == (10,)
    assert result.confirmed_edge_count == 0


def test_level_two_root_reaches_structural_leaf_children() -> None:
    reader = make_reader(
        {10: 100, 20: 200, 21: 300},
        {100: internal(10, 2, 20, 21), 200: leaf(20), 300: leaf(21)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.internal_page_numbers == (10,)
    assert result.leaf_page_numbers == (20, 21)
    assert result.confirmed_edge_count == 2


def test_multilevel_tree_propagates_expected_levels() -> None:
    reader = make_reader(
        {10: 100, 50: 200, 900: 300},
        {100: internal(10, 3, 50), 200: internal(50, 2, 900), 300: leaf(900)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.internal_page_numbers == (10, 50)
    assert result.leaf_page_numbers == (900,)


def test_level_contradiction_is_rejected() -> None:
    reader = make_reader(
        {10: 100, 20: 200},
        {100: internal(10, 3, 20), 200: leaf(20)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.REJECTED
    assert "page_level_mismatch" in result.reasons


@pytest.mark.parametrize(
    ("root_page", "child_page", "reason"),
    [(10, 10, "self_reference"), (10, 20, "cycle_detected")],
)
def test_self_reference_and_cycle_are_rejected(
    root_page: int,
    child_page: int,
    reason: str,
) -> None:
    if child_page == root_page:
        mappings = {10: 100}
        pages = {100: internal(10, 2, 10)}
    else:
        mappings = {10: 100, 20: 200}
        pages = {100: internal(10, 3, 20), 200: internal(20, 2, 10)}
    result = resolve(make_reader(mappings, pages), 5, root_page)
    assert result.status is ValidationStatus.REJECTED
    assert reason in result.reasons


def test_multiple_parents_are_hard_contradiction() -> None:
    reader = make_reader(
        {10: 100, 20: 200, 30: 300, 40: 400},
        {
            100: internal(10, 3, 20, 30),
            200: internal(20, 2, 40),
            300: internal(30, 2, 40),
            400: leaf(40),
        },
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.REJECTED
    assert "multiple_parents" in result.reasons


def test_duplicate_identical_edge_is_counted_once() -> None:
    reader = make_reader(
        {10: 100, 20: 200},
        {100: internal(10, 2, 20, 20), 200: leaf(20)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.confirmed_edge_count == 1


def test_missing_and_rejected_children_preserve_other_reachable_branches() -> None:
    reader = make_reader(
        {10: 100, 20: 200, 40: 400},
        {
            100: internal(10, 2, 20, 30, 40),
            200: leaf(20),
            400: leaf(40),
        },
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.FRAGMENT
    assert result.missing_page_numbers == (30,)
    assert result.leaf_page_numbers == (20, 40)

    rejected_reader = make_reader(
        {10: 100, 20: 200, 30: 300},
        {100: internal(10, 2, 20, 30), 200: leaf(20), 300: b"garbage"},
    )
    rejected = resolve(rejected_reader, 5, 10)
    assert rejected.status is ValidationStatus.FRAGMENT
    assert rejected.rejected_page_numbers == (30,)
    assert rejected.leaf_page_numbers == (20,)


def test_orphan_leaf_is_not_assigned_to_subdatabase() -> None:
    reader = make_reader(
        {10: 100, 20: 200, 500: 500},
        {100: internal(10, 2, 20), 200: leaf(20), 500: leaf(500)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.leaf_page_numbers == (20,)
    assert 500 not in result.reachable_page_numbers


def test_deleted_internal_edge_does_not_assign_child() -> None:
    root = data_page(
        10,
        level=2,
        page_type=BTREE_INTERNAL,
        records=(internal_record(20), internal_record(500, deleted=True)),
    )
    reader = make_reader(
        {10: 100, 20: 200, 500: 500},
        {100: root, 200: leaf(20), 500: leaf(500)},
    )
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.leaf_page_numbers == (20,)
    assert result.confirmed_edge_count == 1


def test_two_subdatabases_remain_topologically_separate() -> None:
    reader = make_reader(
        {10: 10, 20: 20, 21: 21, 100: 100, 200: 200, 201: 201},
        {
            10: internal(10, 2, 20, 21),
            20: leaf(20),
            21: leaf(21),
            100: internal(100, 2, 200, 201),
            200: leaf(200),
            201: leaf(201),
        },
    )
    result_a = resolve(reader, 5, 10)
    result_b = resolve(reader, 6, 100)
    assert result_a.leaf_page_numbers == (20, 21)
    assert result_b.leaf_page_numbers == (200, 201)
    assert result_a.identity != result_b.identity


def test_physical_fragmentation_does_not_affect_logical_traversal() -> None:
    two_gib = 2 * 1024**3
    four_gib = 4 * 1024**3
    forty_gib = 40 * 1024**3
    forty_four_gib = 44 * 1024**3
    mappings = {5: two_gib, 10: forty_gib, 50: four_gib, 900: forty_four_gib}
    pages = {
        two_gib: metadata(5, 10),
        forty_gib: internal(10, 3, 50),
        four_gib: internal(50, 2, 900),
        forty_four_gib: leaf(900),
    }
    reader = make_reader(mappings, pages)
    discovered = reader.find_metadata_pages()
    assert len(discovered) == 1
    result = LogicalBtreeMembershipResolver(discovered[0], reader).resolve()
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.reachable_page_numbers == (10, 50, 900)


def test_invalid_internal_framing_cannot_supply_child_reference() -> None:
    malformed = bytearray(internal(10, 2, 20))
    malformed[-13 + 2] = 3
    reader = make_reader({10: 100}, {100: bytes(malformed)})
    result = resolve(reader, 5, 10)
    assert result.status is ValidationStatus.REJECTED
    assert result.confirmed_edge_count == 0


def test_result_is_immutable_and_contains_no_physical_base() -> None:
    reader = make_reader({10: 100}, {100: leaf(10)})
    result = resolve(reader, 5, 10)
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]
    assert not hasattr(result.identity, "database_base_offset")


def test_resolver_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    reader = make_reader({10: 100}, {100: leaf(10)})
    assert resolve(reader, 5, 10).status is ValidationStatus.STRUCTURAL
