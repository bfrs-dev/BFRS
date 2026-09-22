"""Source classification for image, regular-file, and directory scans."""

from enum import Enum
from pathlib import Path


class SourceType(str, Enum):
    IMAGE = "IMAGE"
    FILE = "FILE"
    FOLDER = "FOLDER"


_IMAGE_SUFFIXES = frozenset({".img", ".dd", ".bin", ".raw"})


def detect_source_type(path: str | Path, explicit: str | None = None) -> SourceType:
    """Classify a source without inspecting or filtering its contents."""
    source = Path(path)
    if explicit is not None:
        selected = SourceType(explicit.upper())
        if selected is SourceType.FOLDER and not source.is_dir():
            raise ValueError("FOLDER source type requires a directory")
        if selected is not SourceType.FOLDER and source.is_dir():
            raise ValueError(f"{selected.value} source type requires a regular file")
        return selected
    if source.is_dir():
        return SourceType.FOLDER
    if source.suffix.lower() in _IMAGE_SUFFIXES:
        return SourceType.IMAGE
    return SourceType.FILE
