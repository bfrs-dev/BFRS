import pytest

from bfrs.core.ranges import intersects


@pytest.mark.parametrize(
    "left,right,expected",
    (
        ((0, 10), (0, 10), True),
        ((0, 10), (5, 15), True),
        ((5, 15), (0, 10), True),
        ((0, 10), (10, 20), False),
        ((10, 20), (0, 10), False),
        ((0, 0), (0, 10), False),
    ),
)
def test_intersects_uses_half_open_ranges(left, right, expected):
    assert intersects(*left, *right) is expected


@pytest.mark.parametrize("ranges", ((-1, 1, 0, 1), (1, 0, 0, 1)))
def test_intersects_rejects_invalid_ranges(ranges):
    with pytest.raises(ValueError):
        intersects(*ranges)
