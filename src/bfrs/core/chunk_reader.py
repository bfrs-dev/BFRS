"""Chunked binary file reading for large forensic sources."""

from collections.abc import Collection, Iterator
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Chunk:
    offset: int
    data: bytes

    @property
    def end_offset(self) -> int:
        return self.offset + len(self.data)


class ChunkReader:
    def __init__(
        self,
        path: str | Path,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        overlap: int = 0,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than zero")
        if overlap < 0:
            raise ValueError("overlap must not be negative")
        if overlap >= chunk_size:
            raise ValueError("overlap must be smaller than chunk_size")

        self.path = Path(path)
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.linear_pass_count = 0
        self.linear_bytes_read = 0
        self.linear_read_count = 0

    @property
    def file_size(self) -> int:
        return self.path.stat().st_size

    def iter_chunks(self, start: int = 0, end: int | None = None) -> Iterator[Chunk]:
        for _, _, chunk in self.iter_owned_chunks(start=start, end=end):
            if chunk is not None:
                yield chunk

    def iter_owned_chunks(
        self,
        start: int = 0,
        end: int | None = None,
        *,
        skip_ownership_ranges: Collection[tuple[int, int]] = (),
    ) -> Iterator[tuple[int, int, Chunk | None]]:
        """Yield planned ownership units, omitting I/O for completed ranges."""
        file_size = self.file_size
        range_end = file_size if end is None else end

        if start < 0:
            raise ValueError("start must not be negative")
        if range_end > file_size:
            raise ValueError("end must not exceed file size")
        if start > range_end:
            raise ValueError("start must not exceed end")

        if start == range_end:
            return

        step = self.chunk_size - self.overlap
        plans: list[tuple[int, int, int]] = []
        offset = start
        while offset < range_end:
            scan_end = min(offset + self.chunk_size, range_end)
            ownership_end = (range_end if scan_end >= range_end else
                             min(offset + step, range_end))
            plans.append((offset, scan_end, ownership_end))
            offset = ownership_end

        skipped = set(skip_ownership_ranges)
        pending = any((offset, ownership_end) not in skipped
                      for offset, _, ownership_end in plans)
        source = self.path.open("rb") if pending else None
        if source is not None:
            self.linear_pass_count += 1
        try:
            for offset, scan_end, ownership_end in plans:
                if (offset, ownership_end) in skipped:
                    yield offset, ownership_end, None
                    continue
                assert source is not None
                source.seek(offset)
                data = source.read(scan_end - offset)
                self.linear_read_count += 1
                self.linear_bytes_read += len(data)
                if not data:
                    break
                yield offset, ownership_end, Chunk(offset=offset, data=data)
        finally:
            if source is not None:
                source.close()
