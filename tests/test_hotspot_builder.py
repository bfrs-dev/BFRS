import pytest

from bfrs.core.models import RawHit
from bfrs.scanners.hotspot_builder import HotspotBuilder


def make_hit(
    offset: int,
    *,
    length: int = 4,
    hit_type: str = "alpha",
    source: str = "missing-source.img",
) -> RawHit:
    return RawHit(
        start_offset=offset,
        end_offset=offset + length,
        hit_type=hit_type,
        confidence=0.0,
        source=source,
        evidence={"category": "test"},
    )


def test_empty_hits_return_empty_list() -> None:
    assert HotspotBuilder().build([], source_size=100) == []


def test_one_hit_creates_one_hotspot() -> None:
    hotspots = HotspotBuilder(cluster_gap=10, padding=5).build(
        [make_hit(20)], source_size=100
    )

    assert len(hotspots) == 1
    assert (hotspots[0].start_offset, hotspots[0].end_offset) == (15, 29)
    assert hotspots[0].score == 0.0


def test_two_near_hits_create_one_hotspot() -> None:
    hotspots = HotspotBuilder(cluster_gap=10, padding=0).build(
        [make_hit(10), make_hit(20)], source_size=100
    )

    assert len(hotspots) == 1


def test_two_distant_hits_create_two_hotspots() -> None:
    hotspots = HotspotBuilder(cluster_gap=10, padding=0).build(
        [make_hit(10), make_hit(21)], source_size=100
    )

    assert [(item.start_offset, item.end_offset) for item in hotspots] == [
        (10, 14),
        (21, 25),
    ]


def test_several_clusters_are_returned_in_order() -> None:
    hits = [make_hit(205), make_hit(10), make_hit(100), make_hit(200)]

    hotspots = HotspotBuilder(cluster_gap=5, padding=0).build(hits, source_size=300)

    assert [item.start_offset for item in hotspots] == [10, 100, 200]


def test_unsorted_hits_produce_deterministic_evidence() -> None:
    hits = [make_hit(30, hit_type="third"), make_hit(10), make_hit(20, hit_type="second")]

    hotspot = HotspotBuilder(cluster_gap=10, padding=0).build(
        hits, source_size=100
    )[0]

    assert hotspot.evidence == {
        "hit_count": 3,
        "hit_types": ("alpha", "second", "third"),
        "hit_offsets": (10, 20, 30),
    }


def test_cluster_gap_at_boundary_joins_hits() -> None:
    hotspots = HotspotBuilder(cluster_gap=100, padding=0).build(
        [make_hit(1000), make_hit(1100)], source_size=2000
    )

    assert len(hotspots) == 1


def test_cluster_gap_exceeded_by_one_splits_hits() -> None:
    hotspots = HotspotBuilder(cluster_gap=100, padding=0).build(
        [make_hit(1000), make_hit(1101)], source_size=2000
    )

    assert len(hotspots) == 2


def test_left_padding_is_clamped_to_zero() -> None:
    hotspot = HotspotBuilder(padding=20).build([make_hit(5)], source_size=100)[0]

    assert hotspot.start_offset == 0


def test_right_padding_is_clamped_to_source_size() -> None:
    hotspot = HotspotBuilder(padding=20).build([make_hit(95)], source_size=100)[0]

    assert hotspot.end_offset == 100


def test_zero_padding_uses_raw_hit_bounds() -> None:
    hotspot = HotspotBuilder(padding=0).build(
        [make_hit(10, length=7)], source_size=100
    )[0]

    assert (hotspot.start_offset, hotspot.end_offset) == (10, 17)


def test_zero_cluster_gap_joins_hits_at_same_offset() -> None:
    hotspots = HotspotBuilder(cluster_gap=0, padding=0).build(
        [make_hit(10, hit_type="alpha"), make_hit(10, hit_type="beta")],
        source_size=100,
    )

    assert len(hotspots) == 1
    assert hotspots[0].evidence["hit_types"] == ("alpha", "beta")


def test_identical_duplicate_does_not_change_hotspot() -> None:
    hit = make_hit(10)
    builder = HotspotBuilder(padding=0)

    assert builder.build([hit, hit], source_size=100) == builder.build(
        [hit], source_size=100
    )


def test_mixed_sources_are_rejected() -> None:
    with pytest.raises(ValueError, match="same source"):
        HotspotBuilder().build(
            [make_hit(10, source="one.img"), make_hit(20, source="two.img")],
            source_size=100,
        )


@pytest.mark.parametrize(
    ("cluster_gap", "padding"), [(-1, 0), (0, -1)]
)
def test_negative_constructor_parameters_are_rejected(
    cluster_gap: int, padding: int
) -> None:
    with pytest.raises(ValueError):
        HotspotBuilder(cluster_gap=cluster_gap, padding=padding)


def test_negative_source_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        HotspotBuilder().build([], source_size=-1)


def test_result_is_independent_of_input_order() -> None:
    hits = [make_hit(30, hit_type="third"), make_hit(10), make_hit(20, hit_type="second")]
    builder = HotspotBuilder(cluster_gap=10, padding=3)

    assert builder.build(hits, source_size=100) == builder.build(
        reversed(hits), source_size=100
    )


def test_builder_does_not_access_source_file() -> None:
    hotspot = HotspotBuilder(padding=0).build(
        [make_hit(10, source="file-that-does-not-exist.img")], source_size=100
    )[0]

    assert hotspot.source == "file-that-does-not-exist.img"


def test_dense_cluster_creates_one_hotspot_with_all_evidence() -> None:
    hits = [make_hit(offset) for offset in (1000, 1050, 1100, 1150, 1200)]

    hotspot = HotspotBuilder(cluster_gap=50, padding=100).build(
        hits, source_size=2000
    )[0]

    assert (hotspot.start_offset, hotspot.end_offset) == (900, 1304)
    assert hotspot.evidence["hit_count"] == 5
    assert hotspot.evidence["hit_offsets"] == (1000, 1050, 1100, 1150, 1200)


def test_two_large_separate_clusters_have_padded_bounds() -> None:
    hits = [make_hit(offset) for offset in (1000, 1100, 5_000_000, 5_000_100)]

    hotspots = HotspotBuilder(cluster_gap=100, padding=50).build(
        hits, source_size=6_000_000
    )

    assert [(item.start_offset, item.end_offset) for item in hotspots] == [
        (950, 1154),
        (4_999_950, 5_000_154),
    ]
