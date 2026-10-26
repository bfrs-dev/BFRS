"""Atomic JSON writing and optional no-clobber report publication."""
from __future__ import annotations
import json
import os
from pathlib import Path
import uuid


def publish(temporary: Path, destination: Path, *, overwrite: bool = True) -> None:
    if overwrite:
        os.replace(temporary, destination)
    elif os.name == "nt":
        # Windows rename fails if the destination appeared after preflight.
        os.rename(temporary, destination)
    else:
        # Atomic exclusive publication on POSIX; never fall back to replace.
        os.link(temporary, destination)
        temporary.unlink()


def write_json(path: Path, payload: dict, *, overwrite: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        publish(temporary, path, overwrite=overwrite)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return path
