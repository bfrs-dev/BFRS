import builtins

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_page import BTREE_LEAF, PAGE_HEADER_SIZE
from bfrs.validators.berkeley_page_locator import (
    BerkeleyAnchor,
    BerkeleyPageLocator,
)


PAGE_SIZE = 512


def anchor(
    *,
    base_offset: int = 0,
    metadata_page_number: int = 100,
    page_size: int = PAGE_SIZE,
    byte_order: str = "little",
) -> BerkeleyAnchor:
    return BerkeleyAnchor(
        metadata_absolute_offset=(
            base_offset + metadata_page_number * page_size
        ),
        metadata_page_number=metadata_page_number,
        page_size=page_size,
        byte_order=byte_order,
    )


def empty_leaf_page(
    page_number: int,
    *,
    page_size: int = PAGE_SIZE,
    byte_order: str = "little",
) -> bytes:
    page = bytearray(page_size)
    page[8:12] = page_number.to_bytes(4, byte_order)
    page[20:22] = (0).to_bytes(2, byte_order)
    page[22:24] = page_size.to_bytes(2, byte_order)
    page[24] = 1
    page[25] = BTREE_LEAF
    return bytes(page)


def locate(
    data: bytes,
    *,
    locator_anchor: BerkeleyAnchor | None = None,
    start_offset: int = 0,
    source: str = "source.img",
):
    selected_anchor = locator_anchor or anchor()
    context = ValidationContext(source, start_offset, data)
    return BerkeleyPageLocator(selected_anchor).locate(context)


def test_anchor_page_number_zero() -> None:
    selected = BerkeleyAnchor(1_000_000, 0, 4096, "little")

    assert selected.database_base_offset == 1_000_000


def test_inner_metadata_anchor_and_next_page_geometry() -> None:
    selected = anchor(
        base_offset=1_000_000,
        metadata_page_number=17,
        page_size=4096,
    )
    page_18_start = 1_000_000 + 18 * 4096
    results = locate(
        empty_leaf_page(18, page_size=4096),
        locator_anchor=selected,
        start_offset=page_18_start,
    )

    assert selected.metadata_absolute_offset == 17 * 4096 + 1_000_000
    assert selected.database_base_offset == 1_000_000
    assert results[0].start_offset == page_18_start
    assert results[0].evidence["page_number"] == 18


def test_database_base_uses_exact_anchor_geometry() -> None:
    selected = BerkeleyAnchor(12_288, 2, 4096, "little")

    assert selected.database_base_offset == 4096


def test_negative_database_base_is_rejected_by_locator() -> None:
    selected = BerkeleyAnchor(511, 1, PAGE_SIZE, "little")

    assert selected.database_base_offset == -1
    with pytest.raises(ValueError, match="database_base_offset"):
        BerkeleyPageLocator(selected)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ((-1, 0, PAGE_SIZE, "little"), "metadata_absolute_offset"),
        ((0, -1, PAGE_SIZE, "little"), "metadata_page_number"),
        ((0, 0, 513, "little"), "page_size"),
        ((0, 0, PAGE_SIZE, "native"), "byte_order"),
    ],
)
def test_anchor_rejects_invalid_fields(
    arguments: tuple[int, int, int, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        BerkeleyAnchor(*arguments)


def test_context_starting_on_grid_includes_that_page() -> None:
    results = locate(empty_leaf_page(2), start_offset=2 * PAGE_SIZE)

    assert [result.start_offset for result in results] == [2 * PAGE_SIZE]


def test_context_starting_mid_page_uses_next_grid_boundary() -> None:
    start_offset = 100
    padding = b"x" * (PAGE_SIZE - start_offset)
    results = locate(padding + empty_leaf_page(1), start_offset=start_offset)

    assert [result.start_offset for result in results] == [PAGE_SIZE]
    assert results[0].status is ValidationStatus.STRUCTURAL


def test_context_ending_on_grid_excludes_page_start_at_end() -> None:
    results = locate(empty_leaf_page(1), start_offset=PAGE_SIZE)

    assert [result.start_offset for result in results] == [PAGE_SIZE]


def test_context_ending_mid_page_includes_trailing_page_start() -> None:
    data = empty_leaf_page(1) + empty_leaf_page(2)[:PAGE_HEADER_SIZE]
    results = locate(data, start_offset=PAGE_SIZE)

    assert [result.start_offset for result in results] == [PAGE_SIZE, 2 * PAGE_SIZE]
    assert results[1].status is ValidationStatus.FRAGMENT


def test_first_boundary_is_computed_for_far_context() -> None:
    base_offset = 1_000_000
    selected = anchor(base_offset=base_offset, metadata_page_number=1)
    start_offset = base_offset + 50 * PAGE_SIZE + 37
    padding = b"x" * (PAGE_SIZE - 37)
    results = locate(
        padding + empty_leaf_page(51),
        locator_anchor=selected,
        start_offset=start_offset,
    )

    assert [result.start_offset for result in results] == [
        base_offset + 51 * PAGE_SIZE
    ]


def test_grid_page_number_is_passed_as_expected_page_number() -> None:
    result = locate(empty_leaf_page(7), start_offset=7 * PAGE_SIZE)[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["page_number"] == 7


def test_child_context_produces_absolute_result_range() -> None:
    start_offset = 9 * PAGE_SIZE
    result = locate(empty_leaf_page(9), start_offset=start_offset)[0]

    assert (result.start_offset, result.end_offset) == (
        start_offset,
        start_offset + PAGE_SIZE,
    )
    assert result.source == "source.img"


def test_metadata_anchor_is_skipped_without_rejected_result() -> None:
    selected = anchor(base_offset=1_000_000, metadata_page_number=17, page_size=4096)
    metadata_offset = selected.metadata_absolute_offset
    data = bytes(4096) + empty_leaf_page(18, page_size=4096)
    results = locate(data, locator_anchor=selected, start_offset=metadata_offset)

    assert [result.start_offset for result in results] == [metadata_offset + 4096]
    assert results[0].status is ValidationStatus.STRUCTURAL


def test_two_valid_data_pages_are_structural() -> None:
    data = empty_leaf_page(3) + empty_leaf_page(4)
    results = locate(data, start_offset=3 * PAGE_SIZE)

    assert [result.status for result in results] == [
        ValidationStatus.STRUCTURAL,
        ValidationStatus.STRUCTURAL,
    ]


def test_valid_page_followed_by_false_grid_page_is_not_filtered() -> None:
    data = empty_leaf_page(3) + bytes(PAGE_SIZE)
    results = locate(data, start_offset=3 * PAGE_SIZE)

    assert [result.status for result in results] == [
        ValidationStatus.STRUCTURAL,
        ValidationStatus.REJECTED,
    ]


def test_off_grid_page_header_is_not_a_separate_candidate() -> None:
    data = bytearray(empty_leaf_page(0) + bytes(PAGE_SIZE))
    off_grid_start = PAGE_SIZE + 37
    pseudo_page = empty_leaf_page(1)
    data[off_grid_start : off_grid_start + PAGE_HEADER_SIZE] = pseudo_page[
        :PAGE_HEADER_SIZE
    ]

    results = locate(bytes(data))

    assert [result.start_offset for result in results] == [0, PAGE_SIZE]
    assert off_grid_start not in {result.start_offset for result in results}


def test_header_page_number_mismatching_grid_is_rejected() -> None:
    result = locate(empty_leaf_page(99), start_offset=2 * PAGE_SIZE)[0]

    assert result.status is ValidationStatus.REJECTED
    assert result.evidence["reasons"] == ("page_number_mismatch",)


def test_trailing_partial_page_is_delegated_to_page_validator() -> None:
    data = empty_leaf_page(6)[:PAGE_HEADER_SIZE]
    result = locate(data, start_offset=6 * PAGE_SIZE)[0]

    assert result.status is ValidationStatus.FRAGMENT
    assert result.evidence["reasons"] == ("page_truncated",)


@pytest.mark.parametrize("byte_order", ["little", "big"])
def test_anchor_byte_order_is_used_for_page_validation(byte_order: str) -> None:
    selected = anchor(byte_order=byte_order)
    result = locate(
        empty_leaf_page(5, byte_order=byte_order),
        locator_anchor=selected,
        start_offset=5 * PAGE_SIZE,
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["byte_order"] == byte_order


def test_results_are_deterministically_ordered_by_start_offset() -> None:
    data = empty_leaf_page(8) + bytes(PAGE_SIZE) + empty_leaf_page(10)

    first = locate(data, start_offset=8 * PAGE_SIZE)
    second = locate(data, start_offset=8 * PAGE_SIZE)

    assert [result.start_offset for result in first] == [
        8 * PAGE_SIZE,
        9 * PAGE_SIZE,
        10 * PAGE_SIZE,
    ]
    assert first == second


def test_empty_context_returns_empty_tuple() -> None:
    assert locate(b"", start_offset=123) == ()


def test_locator_uses_context_bytes_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("locator attempted I/O")

    monkeypatch.setattr(builtins, "open", fail_open)
    result = locate(
        empty_leaf_page(1),
        start_offset=PAGE_SIZE,
        source="file-that-does-not-exist.img",
    )[0]

    assert result.status is ValidationStatus.STRUCTURAL


def test_off_grid_offset_is_not_rounded_to_page_number() -> None:
    locator = BerkeleyPageLocator(anchor())

    with pytest.raises(ValueError, match="not on the Berkeley page grid"):
        locator._page_number_at(PAGE_SIZE + 37)
