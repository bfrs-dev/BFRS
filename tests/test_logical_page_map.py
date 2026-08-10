from dataclasses import FrozenInstanceError

import pytest

from bfrs.recovery.logical_page_map import (
    LogicalBerkeleyPageMap,
    LogicalFileExtent,
    LogicalPageLocation,
)
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor


PAGE_SIZE = 4096
SOURCE = r"C:\Images\Wallet.img"


def location(page_number: int, physical_offset: int, **changes: object) -> LogicalPageLocation:
    values: dict[str, object] = {
        "page_number": page_number,
        "physical_offset": physical_offset,
        "page_size": PAGE_SIZE,
        "source": SOURCE,
    }
    values.update(changes)
    return LogicalPageLocation(**values)  # type: ignore[arg-type]


def test_from_anchor_maps_exact_contiguous_offsets() -> None:
    anchor = BerkeleyAnchor(1_000_000, 0, PAGE_SIZE, "little")
    page_map = LogicalBerkeleyPageMap.from_anchor(anchor, (0, 1, 2, 100), SOURCE)
    assert tuple((page.page_number, page.physical_offset) for page in page_map.pages()) == (
        (0, 1_000_000),
        (1, 1_004_096),
        (2, 1_008_192),
        (100, 1_409_600),
    )


def test_physically_fragmented_extents_map_one_logical_file() -> None:
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            LogicalFileExtent(0, 1_000_000, 8192),
            LogicalFileExtent(8192, 50_000_000, 8192),
        ),
    )
    assert tuple(page.physical_offset for page in page_map.pages()) == (
        1_000_000,
        1_004_096,
        50_000_000,
        50_004_096,
    )
    assert page_map.summary.mapped_page_count == 4
    assert page_map.summary.physical_extent_count == 2


def test_physical_order_does_not_change_logical_order() -> None:
    page_map = LogicalBerkeleyPageMap(
        SOURCE,
        PAGE_SIZE,
        "big",
        (location(2, 20_000_000_000), location(0, 30_000_000_000), location(1, 5_000_000_000)),
    )
    assert tuple(page.page_number for page in page_map.pages()) == (0, 1, 2)
    assert tuple(page.physical_offset for page in page_map.pages()) == (
        30_000_000_000,
        5_000_000_000,
        20_000_000_000,
    )


def test_conflicting_location_for_same_page_is_rejected() -> None:
    with pytest.raises(ValueError, match="conflicting physical location"):
        LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (location(5, 100), location(5, 200)))


def test_identical_duplicate_is_deduplicated() -> None:
    duplicate = location(5, 100)
    page_map = LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (duplicate, duplicate))
    assert page_map.pages() == (duplicate,)


def test_gap_leaves_page_missing_without_synthetic_mapping() -> None:
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            LogicalFileExtent(0, 1_000_000, 3 * PAGE_SIZE),
            LogicalFileExtent(4 * PAGE_SIZE, 2_000_000, PAGE_SIZE),
        ),
        logical_file_size=5 * PAGE_SIZE,
    )
    assert page_map.locate(3) is None
    assert page_map.missing_pages() == (3,)
    assert page_map.summary.missing_page_count == 1


def test_page_crossing_extent_boundary_is_missing() -> None:
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            LogicalFileExtent(0, 1_000_000, 2048),
            LogicalFileExtent(2048, 50_000_000, 2048),
        ),
        logical_file_size=PAGE_SIZE,
    )
    assert page_map.pages() == ()
    assert page_map.missing_pages() == (0,)


def test_unaligned_extent_maps_pages_by_logical_offsets() -> None:
    page_map = LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        PAGE_SIZE,
        "little",
        (LogicalFileExtent(1000, 8_000_000, 10_000),),
        logical_file_size=3 * PAGE_SIZE,
    )
    assert page_map.missing_pages() == (0, 2)
    assert page_map.locate(1) == location(1, 8_000_000 + PAGE_SIZE - 1000)


def test_different_source_is_rejected_after_windows_normalization() -> None:
    with pytest.raises(ValueError, match="source"):
        LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (location(0, 100, source="Acer.img"),))
    alias = location(0, 100, source=r"c:\images\wallet.img")
    assert LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (alias,)).locate(0) == alias


def test_different_page_size_is_rejected() -> None:
    with pytest.raises(ValueError, match="page_size"):
        LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (location(0, 100, page_size=512),))


def test_distant_extents_still_form_one_logical_map() -> None:
    two_gib = 2 * 1024**3
    forty_four_gib = 44 * 1024**3
    page_map = LogicalBerkeleyPageMap(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            location(13, forty_four_gib + PAGE_SIZE),
            location(10, two_gib),
            location(12, forty_four_gib),
            location(11, two_gib + PAGE_SIZE),
        ),
    )
    assert tuple(page.page_number for page in page_map.pages()) == (10, 11, 12, 13)
    assert page_map.summary.physical_extent_count == 2


def test_input_order_does_not_change_extent_result() -> None:
    extents = (
        LogicalFileExtent(0, 1_000_000, 8192),
        LogicalFileExtent(8192, 50_000_000, 8192),
    )
    forward = LogicalBerkeleyPageMap.from_extents(SOURCE, PAGE_SIZE, "little", extents)
    reverse = LogicalBerkeleyPageMap.from_extents(SOURCE, PAGE_SIZE, "little", reversed(extents))
    assert forward == reverse


def test_models_are_immutable_and_validate_arguments() -> None:
    page_map = LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "little", (location(0, 100),))
    with pytest.raises(FrozenInstanceError):
        page_map.page_size = 512  # type: ignore[misc]
    with pytest.raises(ValueError, match="page_number"):
        location(-1, 0)
    with pytest.raises(ValueError, match="physical_offset"):
        location(0, -1)
    with pytest.raises(ValueError, match="length"):
        LogicalFileExtent(0, 0, 0)
    with pytest.raises(ValueError, match="byte_order"):
        LogicalBerkeleyPageMap(SOURCE, PAGE_SIZE, "native", ())
    with pytest.raises(ValueError, match="page_size"):
        LogicalBerkeleyPageMap.from_extents(SOURCE, 0, "little", ())
    with pytest.raises(ValueError, match="extents"):
        LogicalBerkeleyPageMap.from_extents(
            SOURCE,
            PAGE_SIZE,
            "little",
            ("not-an-extent",),  # type: ignore[arg-type]
        )


def test_page_map_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    assert LogicalBerkeleyPageMap.from_extents(
        SOURCE,
        PAGE_SIZE,
        "little",
        (LogicalFileExtent(0, 100, PAGE_SIZE),),
    ).locate(0) == location(0, 100)
