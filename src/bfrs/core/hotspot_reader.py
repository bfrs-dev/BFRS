"""Read an exact hotspot range into a validation context."""

import os
from pathlib import Path

from bfrs.core.models import Hotspot
from bfrs.validators.base import ValidationContext


class HotspotReader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read(self, hotspot: Hotspot) -> ValidationContext:
        reader_source = self._normalized_source(self.path)
        hotspot_source = self._normalized_source(Path(hotspot.source))
        if hotspot_source != reader_source:
            raise ValueError("hotspot source does not match reader source")

        file_size = self.path.stat().st_size
        if hotspot.start_offset < 0:
            raise ValueError("hotspot start_offset must not be negative")
        if hotspot.end_offset < hotspot.start_offset:
            raise ValueError("hotspot end_offset must not precede start_offset")
        if hotspot.end_offset > file_size:
            raise ValueError("hotspot end_offset must not exceed file size")

        length = hotspot.end_offset - hotspot.start_offset
        with self.path.open("rb") as source:
            source.seek(hotspot.start_offset)
            data = source.read(length)

        if len(data) != length:
            raise OSError(
                f"short read: expected {length} bytes, received {len(data)}"
            )

        return ValidationContext(
            source=str(self.path.resolve()),
            start_offset=hotspot.start_offset,
            data=data,
        )

    @staticmethod
    def _normalized_source(path: Path) -> str:
        return os.path.normcase(str(path.resolve()))
