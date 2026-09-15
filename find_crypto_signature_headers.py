"""Locate generic crypto signature headers without printing recovered content."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import BinaryIO, Iterator


PATTERNS = {
    "script_header": re.compile(rb"!#SCPT:[\x20-\x7e]{1,100}"),
    "address_header": re.compile(rb"Addr/[\x20-\x7e]{1,100}"),
    "named_signature": re.compile(rb"CryptoSteal[\x20-\x7e]{0,80}"),
}
OVERLAP = 256


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search an image range for known crypto application headers."
    )
    parser.add_argument("--image", type=Path, required=True, help="Disk image or binary input")
    parser.add_argument("--start", type=non_negative_int, default=0, help="Start offset")
    parser.add_argument("--length", type=positive_int, help="Bytes to scan; default: to end of input")
    parser.add_argument(
        "--chunk-size",
        type=positive_int,
        default=4 * 1024 * 1024,
        help="Streaming read size",
    )
    return parser.parse_args()


def chunks(
    stream: BinaryIO, start: int, end: int, chunk_size: int
) -> Iterator[tuple[int, bytes]]:
    stream.seek(start)
    position = start
    carry = b""
    while position < end:
        block = stream.read(min(chunk_size, end - position))
        if not block:
            break
        data = carry + block
        yield position - len(carry), data
        position += len(block)
        carry = data[-OVERLAP:]


def main() -> int:
    args = parse_args()
    size = args.image.stat().st_size
    if args.start > size:
        raise SystemExit("start offset is beyond end of input")
    end = size if args.length is None else min(size, args.start + args.length)
    seen: set[tuple[str, int]] = set()

    with args.image.open("rb") as stream:
        for base, data in chunks(stream, args.start, end, args.chunk_size):
            for label, pattern in PATTERNS.items():
                for match in pattern.finditer(data):
                    offset = base + match.start()
                    if offset < args.start or offset >= end or (label, offset) in seen:
                        continue
                    seen.add((label, offset))
                    print(f"type={label} offset={offset} length={len(match.group())}")

    print("MATCHES =", len(seen))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
