from dataclasses import FrozenInstanceError, fields, is_dataclass

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.fragmented_berkeley_reassembler import (
    FragmentedBerkeleyPageReassembler,
    PhysicalBerkeleyMetadataCandidate,
    PhysicalBerkeleyPageCandidate,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import (
    BTREE_MAGIC,
    BerkeleyMetadataValidator,
)
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    DELETE_FLAG,
    KEYDATA,
    PAGE_HEADER_SIZE,
    BerkeleyPageValidator,
)


PAGE_SIZE = 512
SOURCE = r"E:\images\lost-runlist.img"
OTHER_SOURCE = r"E:\images\other.img"
ONE_GIB = 1024**3
TWO_GIB = 2 * 1024**3
FOUR_GIB = 4 * 1024**3
FIVE_GIB = 5 * 1024**3
TWENTY_FIVE_GIB = 25 * 1024**3
THIRTY_GIB = 30 * 1024**3
FORTY_GIB = 40 * 1024**3
FORTY_FOUR_GIB = 44 * 1024**3
FIFTY_GIB = 50 * 1024**3
PUBLIC_KEY = bytes.fromhex(
    "04"
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)


class MemoryRangeReader:
    def __init__(self, ranges: dict[int, bytes]) -> None:
        self.ranges = ranges

    def read_at(self, offset: int, length: int) -> bytes:
        try:
            return self.ranges[offset][:length]
        except KeyError as exc:
            raise PhysicalRangeReadError("missing test candidate") from exc


def compact_size(value: int) -> bytes:
    if value < 253:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


def vector(value: bytes) -> bytes:
    return compact_size(len(value)) + value


def string(value: str) -> bytes:
    return vector(value.encode("ascii"))


def ckey_pair() -> tuple[bytes, bytes]:
    return string("ckey") + vector(PUBLIC_KEY), vector(bytes(range(48)))


def raw_leaf_record(payload: bytes, *, deleted: bool = False) -> bytes:
    raw_type = KEYDATA | (DELETE_FLAG if deleted else 0)
    return len(payload).to_bytes(2, "little") + bytes((raw_type,)) + payload


def internal_record(child: int, *, deleted: bool = False) -> bytes:
    key = b"k"
    raw_type = KEYDATA | (DELETE_FLAG if deleted else 0)
    return (
        len(key).to_bytes(2, "little")
        + bytes((raw_type, 0))
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
    fragment: bool = False,
) -> bytes:
    page = bytearray(PAGE_SIZE)
    slots: list[int] = []
    if fragment:
        cursor = 64
        for record in records:
            slots.append(cursor)
            page[cursor : cursor + len(record)] = record
            cursor += len(record)
        end = cursor
    else:
        cursor = PAGE_SIZE
        for record in records:
            cursor -= len(record)
            page[cursor : cursor + len(record)] = record
            slots.append(cursor)
        end = PAGE_SIZE
    page[8:12] = page_number.to_bytes(4, "little")
    page[20:22] = len(records).to_bytes(2, "little")
    page[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, "little")
    page[24] = level
    page[25] = page_type
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + index * 2
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page[:end])


def internal(
    page_number: int,
    level: int,
    *children: int,
    deleted_children: tuple[int, ...] = (),
) -> bytes:
    records = tuple(
        internal_record(child, deleted=child in deleted_children)
        for child in children
    )
    return data_page(
        page_number,
        level=level,
        page_type=BTREE_INTERNAL,
        records=records,
    )


def leaf(
    page_number: int,
    payloads: tuple[bytes, ...] = (),
    *,
    fragment: bool = False,
) -> bytes:
    return data_page(
        page_number,
        level=1,
        page_type=BTREE_LEAF,
        records=tuple(raw_leaf_record(payload) for payload in payloads),
        fragment=fragment,
    )


def metadata(page_number: int, root_page: int) -> bytes:
    page = bytearray(PAGE_SIZE)

    def put(offset: int, value: int) -> None:
        page[offset : offset + 4] = value.to_bytes(4, "little")

    put(8, page_number)
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, PAGE_SIZE)
    page[25] = 9
    put(32, max(page_number, root_page) + 1000)
    put(48, 0x20)
    put(88, root_page)
    return bytes(page)


def page_candidate(
    data: bytes,
    physical_offset: int,
    *,
    source: str = SOURCE,
) -> PhysicalBerkeleyPageCandidate:
    validation = BerkeleyPageValidator(PAGE_SIZE, "little").validate(
        ValidationContext(source, physical_offset, data)
    )
    return PhysicalBerkeleyPageCandidate(
        source=source,
        physical_offset=physical_offset,
        page_size=PAGE_SIZE,
        byte_order="little",
        validation=validation,
    )


def metadata_candidate(
    data: bytes,
    physical_offset: int,
    *,
    source: str = SOURCE,
) -> PhysicalBerkeleyMetadataCandidate:
    validation = BerkeleyMetadataValidator().validate(
        ValidationContext(source, physical_offset, data)
    )
    return PhysicalBerkeleyMetadataCandidate(
        source=source,
        physical_offset=physical_offset,
        metadata_page_number=int(validation.evidence["page_number"]),
        page_size=int(validation.evidence["page_size"]),
        byte_order=str(validation.evidence["byte_order"]),
        root_page=int(validation.evidence["root_page"]),
        validation=validation,
    )


def reconstruct(
    metadata_items: tuple[tuple[int, bytes], ...],
    page_items: tuple[tuple[int, bytes], ...],
    *,
    reverse_input: bool = False,
):
    metadata_candidates = tuple(
        metadata_candidate(data, offset) for offset, data in metadata_items
    )
    page_candidates = tuple(
        page_candidate(data, offset) for offset, data in page_items
    )
    if reverse_input:
        metadata_candidates = tuple(reversed(metadata_candidates))
        page_candidates = tuple(reversed(page_candidates))
    ranges = {offset: data for offset, data in page_items}
    reassembler = FragmentedBerkeleyPageReassembler(
        page_candidates,
        range_reader=MemoryRangeReader(ranges),
    )
    return reassembler.reconstruct(metadata_candidates)


def test_main_fragmented_tree_is_structural_without_physical_grid() -> None:
    metadata_items = ((TWO_GIB, metadata(5, 10)),)
    page_items = (
        (FORTY_GIB, internal(10, 3, 50)),
        (FOUR_GIB, internal(50, 2, 900)),
        (FORTY_FOUR_GIB, leaf(900)),
    )

    result = reconstruct(metadata_items, page_items)[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.internal_page_numbers == (10, 50)
    assert result.leaf_page_numbers == (900,)
    assert tuple(page.page_number for page in result.selected_pages) == (
        10,
        50,
        900,
    )
    assert result.confirmed_edge_count == 2


def test_reversed_physical_order_and_input_order_are_irrelevant() -> None:
    metadata_items = ((TWO_GIB, metadata(5, 10)),)
    page_items = (
        (FIFTY_GIB, internal(10, 3, 50)),
        (ONE_GIB, internal(50, 2, 900)),
        (THIRTY_GIB, leaf(900)),
    )

    forward = reconstruct(metadata_items, page_items)
    reverse = reconstruct(
        metadata_items,
        page_items,
        reverse_input=True,
    )

    assert forward == reverse
    assert forward[0].status is ValidationStatus.STRUCTURAL


def test_missing_child_preserves_other_branches_as_fragment() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 20, 30, 40)),
            (FOUR_GIB, leaf(20)),
            (FORTY_FOUR_GIB, leaf(40)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.leaf_page_numbers == (20, 40)
    assert result.missing_page_numbers == (30,)


def test_ambiguous_structural_child_is_not_selected() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 30)),
            (FIVE_GIB, leaf(30)),
            (TWENTY_FIVE_GIB, leaf(30)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.ambiguous_page_numbers == (30,)
    assert result.leaf_page_numbers == ()
    assert tuple(page.page_number for page in result.selected_pages) == (10,)
    assert result.evidence["ambiguous_candidate_offsets"] == (
        (30, (FIVE_GIB, TWENTY_FIVE_GIB)),
    )


def test_ckey_bait_cannot_break_berkeley_ambiguity() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 100)),
            (FIVE_GIB, leaf(100, (b"ordinary", b"records"))),
            (TWENTY_FIVE_GIB, leaf(100, ckey_pair())),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.ambiguous_page_numbers == (100,)
    assert result.leaf_page_numbers == ()


def test_expected_level_uniquely_filters_duplicate_page_number() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 30)),
            (FIVE_GIB, leaf(30)),
            (TWENTY_FIVE_GIB, internal(30, 2, 99)),
        ),
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.leaf_page_numbers == (30,)
    assert result.ambiguous_page_numbers == ()
    selected = {page.page_number: page for page in result.selected_pages}
    assert selected[30].physical_offset == FIVE_GIB


def test_wrong_header_page_number_cannot_supply_reference() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 30)),
            (FIVE_GIB, leaf(31)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.missing_page_numbers == (30,)
    assert tuple(page.page_number for page in result.selected_pages) == (10,)


def test_unique_fragment_candidate_is_selected_but_caps_status() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 20)),
            (FOUR_GIB, leaf(20, fragment=True)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.leaf_page_numbers == (20,)
    assert result.evidence["fragment_page_numbers"] == (20,)


def test_ambiguous_root_is_never_selected() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FIVE_GIB, leaf(10)),
            (TWENTY_FIVE_GIB, leaf(10)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.selected_pages == ()
    assert result.ambiguous_page_numbers == (10,)
    assert result.reasons == ("ambiguous_root_page",)


def test_root_as_leaf_is_a_structural_small_tree() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        ((FORTY_GIB, leaf(10)),),
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.internal_page_numbers == ()
    assert result.leaf_page_numbers == (10,)


@pytest.mark.parametrize(
    ("root", "reason"),
    [
        (internal(10, 2, 10), "self_reference"),
        (internal(10, 3, 20), "cycle_detected"),
    ],
    ids=("self-reference", "cycle"),
)
def test_self_reference_and_cycle_are_rejected(
    root: bytes,
    reason: str,
) -> None:
    page_items = [(FORTY_GIB, root)]
    if reason == "cycle_detected":
        page_items.append((FOUR_GIB, internal(20, 2, 10)))
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        tuple(page_items),
    )[0]

    assert result.status is ValidationStatus.REJECTED
    assert reason in result.reasons


def test_multiple_parents_are_rejected() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 3, 20, 30)),
            (FOUR_GIB, internal(20, 2, 40)),
            (FIVE_GIB, internal(30, 2, 40)),
            (FORTY_FOUR_GIB, leaf(40)),
        ),
    )[0]

    assert result.status is ValidationStatus.REJECTED
    assert "multiple_parents" in result.reasons


def test_deleted_internal_record_does_not_create_edge() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (
                FORTY_GIB,
                internal(10, 2, 20, 30, deleted_children=(20,)),
            ),
            (FOUR_GIB, leaf(20)),
            (FORTY_FOUR_GIB, leaf(30)),
        ),
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.leaf_page_numbers == (30,)
    assert tuple(page.page_number for page in result.selected_pages) == (10, 30)
    assert result.evidence["confirmed_edges"] == ((10, 30),)


def test_orphan_leaf_is_not_selected() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 20)),
            (FOUR_GIB, leaf(20)),
            (FORTY_FOUR_GIB, leaf(500, ckey_pair())),
        ),
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.leaf_page_numbers == (20,)
    assert tuple(page.page_number for page in result.selected_pages) == (10, 20)


def test_two_metadata_candidates_are_reconstructed_independently() -> None:
    results = reconstruct(
        (
            (TWO_GIB, metadata(5, 10)),
            (THIRTY_GIB, metadata(6, 100)),
        ),
        (
            (FORTY_GIB, internal(10, 2, 20)),
            (FOUR_GIB, leaf(20)),
            (FIFTY_GIB, internal(100, 2, 200)),
            (ONE_GIB, leaf(200)),
        ),
    )

    assert len(results) == 2
    assert tuple(result.identity.root_page_number for result in results) == (
        10,
        100,
    )
    assert tuple(result.leaf_page_numbers for result in results) == (
        (20,),
        (200,),
    )


def test_old_version_duplicate_page_remains_ambiguous() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 3, 50)),
            (FOUR_GIB, internal(50, 2, 900)),
            (THIRTY_GIB, internal(50, 2, 901)),
            (FORTY_FOUR_GIB, leaf(900)),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.ambiguous_page_numbers == (50,)
    assert tuple(page.page_number for page in result.selected_pages) == (10,)


def test_identical_physical_page_duplicate_is_deduplicated() -> None:
    root_data = internal(10, 2, 50)
    child_data = leaf(50)
    root_candidate = page_candidate(root_data, FORTY_GIB)
    first_child = page_candidate(child_data, FOUR_GIB)
    second_child = page_candidate(child_data, FOUR_GIB)
    reassembler = FragmentedBerkeleyPageReassembler(
        (root_candidate, first_child, second_child),
        range_reader=MemoryRangeReader(
            {FORTY_GIB: root_data, FOUR_GIB: child_data}
        ),
    )

    result = reassembler.reconstruct(
        (metadata_candidate(metadata(5, 10), TWO_GIB),)
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.ambiguous_page_numbers == ()
    assert tuple(page.page_number for page in result.selected_pages) == (10, 50)
    assert result.confirmed_edge_count == 1


def test_overlapping_scan_duplicates_do_not_duplicate_tree() -> None:
    root_data = internal(10, 3, 50)
    child_data = internal(50, 2, 900)
    leaf_data = leaf(900)
    unique_candidates = (
        page_candidate(root_data, FORTY_GIB),
        page_candidate(child_data, FOUR_GIB),
        page_candidate(leaf_data, FORTY_FOUR_GIB),
    )
    duplicated_candidates = tuple(
        candidate
        for item in unique_candidates
        for candidate in (item, item)
    )
    reassembler = FragmentedBerkeleyPageReassembler(
        duplicated_candidates,
        range_reader=MemoryRangeReader(
            {
                FORTY_GIB: root_data,
                FOUR_GIB: child_data,
                FORTY_FOUR_GIB: leaf_data,
            }
        ),
    )

    result = reassembler.reconstruct(
        (metadata_candidate(metadata(5, 10), TWO_GIB),)
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert tuple(page.page_number for page in result.selected_pages) == (
        10,
        50,
        900,
    )
    assert result.confirmed_edge_count == 2


def test_identical_metadata_duplicate_creates_one_database() -> None:
    metadata_data = metadata(5, 10)
    first = metadata_candidate(metadata_data, TWO_GIB)
    second = metadata_candidate(metadata_data, TWO_GIB)
    root_data = leaf(10)
    reassembler = FragmentedBerkeleyPageReassembler(
        (page_candidate(root_data, FORTY_GIB),),
        range_reader=MemoryRangeReader({FORTY_GIB: root_data}),
    )

    results = reassembler.reconstruct((first, second))

    assert len(results) == 1
    assert results[0].status is ValidationStatus.STRUCTURAL


def test_same_physical_page_with_conflicting_metadata_is_rejected() -> None:
    leaf_candidate = page_candidate(leaf(50), FOUR_GIB)
    internal_candidate = page_candidate(internal(50, 2, 900), FOUR_GIB)

    with pytest.raises(ValueError, match="conflicting candidate"):
        FragmentedBerkeleyPageReassembler(
            (leaf_candidate, internal_candidate),
            range_reader=MemoryRangeReader({FOUR_GIB: leaf(50)}),
        )


def test_same_physical_metadata_with_conflicting_root_is_rejected() -> None:
    first = metadata_candidate(metadata(5, 10), TWO_GIB)
    second = metadata_candidate(metadata(5, 100), TWO_GIB)
    reassembler = FragmentedBerkeleyPageReassembler(
        (),
        range_reader=MemoryRangeReader({}),
    )

    with pytest.raises(ValueError, match="conflicting metadata candidate"):
        reassembler.reconstruct((first, second))


def test_metadata_less_pool_does_not_create_database() -> None:
    candidates = (page_candidate(leaf(10), FORTY_GIB),)
    reassembler = FragmentedBerkeleyPageReassembler(
        candidates,
        range_reader=MemoryRangeReader({FORTY_GIB: leaf(10)}),
    )

    assert reassembler.reconstruct(()) == ()


def test_page_candidate_from_other_source_cannot_supply_child() -> None:
    root_data = internal(10, 2, 20)
    foreign_leaf = leaf(20)
    candidates = (
        page_candidate(root_data, FORTY_GIB),
        page_candidate(foreign_leaf, FOUR_GIB, source=OTHER_SOURCE),
    )
    reassembler = FragmentedBerkeleyPageReassembler(
        candidates,
        range_reader=MemoryRangeReader(
            {FORTY_GIB: root_data, FOUR_GIB: foreign_leaf}
        ),
    )
    result = reassembler.reconstruct(
        (metadata_candidate(metadata(5, 10), TWO_GIB),)
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.missing_page_numbers == (20,)
    assert result.leaf_page_numbers == ()


def test_hard_rejected_child_candidate_is_not_selected() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 20)),
            (FOUR_GIB, leaf(20, (b"unpaired-record",))),
        ),
    )[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.rejected_page_numbers == (20,)
    assert tuple(page.page_number for page in result.selected_pages) == (10,)


def test_fragment_metadata_does_not_create_reconstructed_identity() -> None:
    full = metadata(5, 10)
    fragment_data = full[:100]
    fragment = metadata_candidate(fragment_data, TWO_GIB)
    assert fragment.validation.status is ValidationStatus.FRAGMENT
    reassembler = FragmentedBerkeleyPageReassembler(
        (page_candidate(leaf(10), FORTY_GIB),),
        range_reader=MemoryRangeReader({FORTY_GIB: leaf(10)}),
    )

    assert reassembler.reconstruct((fragment,)) == ()


def test_public_models_are_immutable_and_secret_free() -> None:
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        ((FORTY_GIB, leaf(10, ckey_pair())),),
    )[0]

    assert not contains_bytes(result)
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]
    assert not hasattr(result.identity, "database_base_offset")


def test_reassembler_performs_no_direct_file_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "builtins.open",
        lambda *args, **kwargs: pytest.fail("direct file I/O"),
    )
    result = reconstruct(
        ((TWO_GIB, metadata(5, 10)),),
        (
            (FORTY_GIB, internal(10, 2, 20)),
            (FOUR_GIB, leaf(20)),
        ),
    )[0]
    assert result.status is ValidationStatus.STRUCTURAL


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if is_dataclass(value) and not isinstance(value, type):
        return any(
            contains_bytes(getattr(value, item.name)) for item in fields(value)
        )
    if isinstance(value, dict):
        return any(
            contains_bytes(key) or contains_bytes(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(contains_bytes(item) for item in value)
    return False
