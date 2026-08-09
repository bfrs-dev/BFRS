"""Generic single-pass scanner for fixed binary signatures."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from bfrs.core.chunk_reader import ChunkReader
from bfrs.core.models import RawHit


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    pattern: bytes
    category: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("signature name must not be empty")
        if not self.pattern:
            raise ValueError("signature pattern must not be empty")
        if not self.category:
            raise ValueError("signature category must not be empty")


class FastScanner:
    def __init__(self, signatures: Iterable[Signature]) -> None:
        collected = tuple(signatures)
        if not collected:
            raise ValueError("at least one signature is required")

        identities = {(signature.name, signature.pattern) for signature in collected}
        if len(identities) != len(collected):
            raise ValueError("duplicate signature name and pattern")

        self.signatures = collected
        self._max_pattern_length = max(len(signature.pattern) for signature in collected)

    def scan(
        self,
        reader: ChunkReader,
        start: int = 0,
        end: int | None = None,
    ) -> Iterator[RawHit]:
        file_size = reader.file_size
        range_end = file_size if end is None else end

        if start < 0:
            raise ValueError("start must not be negative")
        if range_end > file_size:
            raise ValueError("end must not exceed file size")
        if start > range_end:
            raise ValueError("start must not exceed end")

        if range_end - start > reader.chunk_size:
            required_overlap = self._max_pattern_length - 1
            if reader.overlap < required_overlap:
                raise ValueError(
                    f"reader overlap must be at least {required_overlap} bytes"
                )

        source = str(reader.path.resolve())
        seen: set[tuple[Signature, int]] = set()

        for chunk in reader.iter_chunks(start=start, end=range_end):
            for signature in self.signatures:
                local_offset = chunk.data.find(signature.pattern)
                while local_offset != -1:
                    absolute_offset = chunk.offset + local_offset
                    identity = (signature, absolute_offset)

                    if identity not in seen:
                        seen.add(identity)
                        yield RawHit(
                            start_offset=absolute_offset,
                            end_offset=absolute_offset + len(signature.pattern),
                            hit_type=signature.name,
                            confidence=0.0,
                            source=source,
                            evidence={"category": signature.category},
                        )

                    local_offset = chunk.data.find(
                        signature.pattern, local_offset + 1
                    )
