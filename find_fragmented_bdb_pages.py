"""Search a binary image for structurally plausible Berkeley DB leaf pages."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def non_negative_int(value: str) -> int:
    parsed = int(value, 0)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def positive_int(value: str) -> int:
    parsed = non_negative_int(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def expected_link(value: str) -> tuple[int, str, int]:
    parts = value.split(":")
    if len(parts) != 3 or parts[1] not in {"prev", "next"}:
        raise argparse.ArgumentTypeError("expected PAGE:prev|next:VALUE")
    return non_negative_int(parts[0]), parts[1], non_negative_int(parts[2])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search aligned offsets for selected Berkeley DB leaf page numbers."
    )
    parser.add_argument("--image", type=Path, required=True, help="Disk image or binary input")
    parser.add_argument(
        "--page",
        type=non_negative_int,
        action="append",
        required=True,
        help="Page number to locate; repeat for multiple pages",
    )
    parser.add_argument(
        "--expected-link",
        type=expected_link,
        action="append",
        default=[],
        metavar="PAGE:prev|next:VALUE",
        help="Optional reciprocal-link requirement",
    )
    parser.add_argument("--volume-start", type=non_negative_int, default=0)
    parser.add_argument("--cluster-size", type=positive_int, default=4096)
    parser.add_argument("--page-size", type=positive_int, default=8192)
    parser.add_argument("--max-page", type=non_negative_int)
    parser.add_argument("--chunk-size", type=positive_int, default=64 * 1024 * 1024)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.chunk_size % args.cluster_size:
        raise SystemExit("chunk-size must be a multiple of cluster-size")

    targets = set(args.page)
    links = {page: (direction, value) for page, direction, value in args.expected_link}
    unknown_links = set(links) - targets
    if unknown_links:
        raise SystemExit("expected-link references a page not provided with --page")

    size = args.image.stat().st_size
    if args.volume_start > size:
        raise SystemExit("volume-start is beyond end of input")

    hits = 0
    strong = 0
    with args.image.open("rb", buffering=0) as stream:
        stream.seek(args.volume_start)
        absolute = args.volume_start
        while absolute < size:
            data = stream.read(min(args.chunk_size, size - absolute))
            if not data:
                break
            for relative in range(0, max(0, len(data) - 25), args.cluster_size):
                page = struct.unpack_from("<I", data, relative + 8)[0]
                if page not in targets:
                    continue
                previous = struct.unpack_from("<I", data, relative + 12)[0]
                following = struct.unpack_from("<I", data, relative + 16)[0]
                entries = struct.unpack_from("<H", data, relative + 20)[0]
                high_free = struct.unpack_from("<H", data, relative + 22)[0]
                level = data[relative + 24]
                page_type = data[relative + 25]

                links_in_range = args.max_page is None or (
                    (previous == 0 or previous <= args.max_page)
                    and (following == 0 or following <= args.max_page)
                )
                structural = (
                    page_type == 5
                    and level == 1
                    and high_free <= args.page_size
                    and links_in_range
                )
                reciprocal = True
                if page in links:
                    direction, expected = links[page]
                    reciprocal = (previous if direction == "prev" else following) == expected

                offset = absolute + relative
                hits += 1
                strong += int(structural and reciprocal)
                print(
                    f"offset={offset} page={page} prev={previous} next={following} "
                    f"entries={entries} highfree={high_free} level={level} "
                    f"type={page_type} structural={structural} reciprocal={reciprocal}"
                )
            absolute += len(data)

    print("MATCHES =", hits)
    print("STRONG_MATCHES =", strong)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
