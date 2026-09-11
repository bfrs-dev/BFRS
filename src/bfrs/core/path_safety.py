"""Filesystem path identity checks for write-target safety."""

from __future__ import annotations

import os
from pathlib import Path


StrPath = str | os.PathLike[str]


def normalized_path_identity(path: StrPath) -> str:
    """Return a deterministic, platform-aware identity without creating a path."""

    resolved = Path(path).resolve(strict=False)
    return os.path.normcase(os.path.normpath(str(resolved)))


def paths_refer_to_same_file(left: StrPath, right: StrPath) -> bool:
    """Compare existing files by identity and other paths by normalization."""

    try:
        return os.path.samefile(left, right)
    except OSError:
        return normalized_path_identity(left) == normalized_path_identity(right)
