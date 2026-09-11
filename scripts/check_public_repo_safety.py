"""Fail when Git tracks private forensic or recovery artifacts.

Only paths and blob sizes from the Git index are inspected. File contents and
untracked files are never opened or scanned.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import subprocess
import sys


FORBIDDEN_DIRECTORIES = {
    "reports": "forensic report directory",
    "checkpoints": "scan checkpoint directory",
    "carves": "forensic carve directory",
    "recovered": "recovered material directory",
}
DISK_IMAGE_SUFFIXES = {
    ".img",
    ".dd",
    ".raw",
    ".e01",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".gho",
    ".ghs",
}
RECOVERY_BINARY_SUFFIXES = {".bin", ".db"}
RECOVERY_PATH_MARKERS = {
    "artifact",
    "carve",
    "checkpoint",
    "context",
    "forensic",
    "hotspot",
    "key",
    "mnemonic",
    "recover",
    "recovery",
    "seed",
    "wallet",
}
LARGE_RECOVERY_BLOB_BYTES = 1024 * 1024


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    category: str


def classify_tracked_path(path: str, blob_size: int = 0) -> str | None:
    """Return a risk category using only a tracked path and blob size."""

    normalized = path.replace("\\", "/").lstrip("./")
    parsed = PurePosixPath(normalized)
    lower_parts = tuple(part.lower() for part in parsed.parts)
    lower_name = parsed.name.lower()
    lower_suffix = parsed.suffix.lower()

    if lower_parts and lower_parts[0] in FORBIDDEN_DIRECTORIES:
        return FORBIDDEN_DIRECTORIES[lower_parts[0]]
    if lower_name == "wallet.dat":
        return "wallet.dat"
    if lower_suffix == ".wallet":
        return "wallet file"
    if lower_suffix in DISK_IMAGE_SUFFIXES:
        return "disk image"
    if lower_name.endswith(".checkpoint.json.tmp-") or ".checkpoint.json.tmp-" in lower_name:
        return "checkpoint temporary file"
    if lower_name.endswith(".checkpoint.json"):
        return "scan checkpoint file"
    if (
        lower_suffix in RECOVERY_BINARY_SUFFIXES
        and blob_size >= LARGE_RECOVERY_BLOB_BYTES
        and _has_recovery_marker(lower_parts)
    ):
        return "large recovery binary/database"
    return None


def _has_recovery_marker(parts: tuple[str, ...]) -> bool:
    tokens = {
        token
        for part in parts
        for token in part.replace("-", "_").replace(".", "_").split("_")
    }
    return bool(tokens & RECOVERY_PATH_MARKERS)


def tracked_index_entries() -> list[tuple[str, str]]:
    """Return ``(path, object_id)`` entries using Git index metadata only."""

    result = subprocess.run(
        ["git", "ls-files", "-z", "--stage"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    entries: list[tuple[str, str]] = []
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        _mode, object_id, stage = metadata.decode("ascii").split()
        if stage == "0":
            entries.append((raw_path.decode("utf-8", "surrogateescape"), object_id))
    return entries


def git_blob_sizes(object_ids: set[str]) -> dict[str, int]:
    """Read blob sizes from Git's object database without reading blob data."""

    if not object_ids:
        return {}
    ordered_ids = sorted(object_ids)
    result = subprocess.run(
        ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        input=("\n".join(ordered_ids) + "\n").encode("ascii"),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    sizes: dict[str, int] = {}
    for line in result.stdout.decode("ascii").splitlines():
        object_id, object_type, raw_size = line.split()
        if object_type == "blob":
            sizes[object_id] = int(raw_size)
    return sizes


def find_tracked_risks() -> list[Finding]:
    entries = tracked_index_entries()
    candidate_ids = {
        object_id
        for path, object_id in entries
        if PurePosixPath(path.lower()).suffix in RECOVERY_BINARY_SUFFIXES
    }
    sizes = git_blob_sizes(candidate_ids)
    return sorted(
        Finding(path, category)
        for path, object_id in entries
        if (category := classify_tracked_path(path, sizes.get(object_id, 0)))
    )


def main() -> int:
    try:
        findings = find_tracked_risks()
    except (OSError, subprocess.CalledProcessError, ValueError):
        print("<repository>\tgit metadata unavailable")
        return 1
    for finding in findings:
        print(f"{finding.path}\t{finding.category}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
