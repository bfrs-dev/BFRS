"""Validate continuity of ownership ranges in a checkpoint stream."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


START_PATTERN = re.compile(rb'"ownership_start"\s*:\s*(\d+)')
END_PATTERN = re.compile(rb'"ownership_end"\s*:\s*(\d+)')


def non_negative_int(value: str) -> int:
    parsed = int(value, 0)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check that checkpoint ownership ranges are contiguous."
    )
    parser.add_argument("--input", type=Path, required=True, help="Checkpoint file to inspect")
    parser.add_argument(
        "--expected-start",
        type=non_negative_int,
        default=0,
        help="Expected first ownership offset (default: 0)",
    )
    parser.add_argument(
        "--expected-end",
        type=non_negative_int,
        help="Optional expected final ownership offset",
    )
    return parser.parse_args()


def read_ranges(path: Path) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    with path.open("rb") as stream:
        for line in stream:
            start_match = START_PATTERN.search(line)
            if start_match:
                starts.append(int(start_match.group(1)))
            end_match = END_PATTERN.search(line)
            if end_match:
                ends.append(int(end_match.group(1)))
    return starts, ends


def main() -> int:
    args = parse_args()
    starts, ends = read_ranges(args.input)

    print("START_COUNT =", len(starts))
    print("END_COUNT   =", len(ends))
    if len(starts) != len(ends):
        print("RANGE_COUNTS_MATCH = NO")
        return 1

    ranges = list(zip(starts, ends))
    gaps: list[tuple[int, int, int]] = []
    overlaps: list[tuple[int, int, int]] = []
    previous_end = args.expected_start

    for index, (start, end) in enumerate(ranges):
        if start > previous_end:
            gaps.append((index, previous_end, start))
        elif start < previous_end:
            overlaps.append((index, start, previous_end))
        previous_end = max(previous_end, end)

    start_matches = not ranges or ranges[0][0] == args.expected_start
    end_matches = args.expected_end is None or previous_end == args.expected_end
    complete = bool(ranges) and start_matches and end_matches and not gaps and not overlaps

    print("UNITS       =", len(ranges))
    print("GAPS        =", len(gaps))
    print("OVERLAPS    =", len(overlaps))
    print("COVERED_END =", previous_end)
    print("LINEAR_SCAN_COMPLETE =", "YES" if complete else "NO")
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
