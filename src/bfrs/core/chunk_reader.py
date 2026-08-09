"""Chunked binary file reading for large forensic sources."""

from collections.abc import Iterator
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

    @property
    def file_size(self) -> int:
        return self.path.stat().st_size

    def iter_chunks(self, start: int = 0, end: int | None = None) -> Iterator[Chunk]:
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
        offset = start

        with self.path.open("rb") as source:
            while offset < range_end:
                source.seek(offset)
                data = source.read(min(self.chunk_size, range_end - offset))
                if not data:
                    break

                chunk = Chunk(offset=offset, data=data)
                yield chunk

                if chunk.end_offset >= range_end:
                    break
                offset += step
