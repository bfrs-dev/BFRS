"""Read the Windows PE machine type of an executable."""

from __future__ import annotations

import argparse
from pathlib import Path
import struct


PE_MACHINES = {
    0x8664: "x64",
    0xAA64: "arm64",
}


def pe_machine(path: str | Path) -> str:
    executable = Path(path)
    with executable.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("missing DOS MZ signature")
        stream.seek(0x3C)
        raw_offset = stream.read(4)
        if len(raw_offset) != 4:
            raise ValueError("truncated DOS header")
        pe_offset = struct.unpack("<I", raw_offset)[0]
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("missing PE signature")
        raw_machine = stream.read(2)
        if len(raw_machine) != 2:
            raise ValueError("truncated PE header")
        machine = struct.unpack("<H", raw_machine)[0]
    try:
        return PE_MACHINES[machine]
    except KeyError as error:
        raise ValueError(f"unsupported PE machine 0x{machine:04X}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--expect", choices=("x64", "arm64"))
    arguments = parser.parse_args()

    actual = pe_machine(arguments.executable)
    print(actual)
    if arguments.expect and arguments.expect != actual:
        print(
            f"architecture mismatch: expected {arguments.expect}, got {actual}",
            file=__import__("sys").stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
