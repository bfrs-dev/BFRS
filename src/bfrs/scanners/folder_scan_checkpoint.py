"""Durable per-file checkpoint storage for recursive folder scans."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Mapping, Sequence


_SCHEMA_VERSION = 1
_RUNTIME_SETTINGS = frozenset({"workers", "file_workers"})


def _scan_semantics(settings: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in settings.items()
            if key not in _RUNTIME_SETTINGS}


def _runtime_settings(settings: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in settings.items()
            if key in _RUNTIME_SETTINGS}


class FolderCheckpointError(RuntimeError):
    """A folder checkpoint cannot be created, loaded, or updated safely."""


@dataclass(frozen=True, slots=True)
class FolderCheckpointRecord:
    relative_path: str
    size: int
    mtime_ns: int
    report: dict | None
    error_reason: str | None


def folder_snapshot_digest(
    root: Path,
    files: Sequence[tuple[Path, int, int]],
) -> str:
    """Hash the deterministic discovered-file identity for resume validation."""
    digest = hashlib.sha256()
    for source, size, mtime_ns in files:
        relative = source.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(str(mtime_ns).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class FolderScanCheckpoint:
    """SQLite checkpoint with one durable transaction per completed source file."""

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._lock = threading.Lock()
        self.runtime_changes: dict[str, tuple[object, object]] = {}

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        root: Path,
        snapshot_sha256: str,
        semantics: Mapping[str, object],
    ) -> "FolderScanCheckpoint":
        path = path.resolve(strict=False)
        if path.exists():
            raise FolderCheckpointError(
                f"folder checkpoint already exists: {path}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            connection = sqlite3.connect(
                path,
                timeout=30.0,
                check_same_thread=False,
            )
            checkpoint = cls(path, connection)
            checkpoint._configure()
            checkpoint._create_schema()
            checkpoint._write_metadata({
                "schema_version": str(_SCHEMA_VERSION),
                "source_root": str(root.resolve(strict=False)),
                "snapshot_sha256": snapshot_sha256,
                "semantics_json": _canonical_json(_scan_semantics(semantics)),
                "runtime_json": _canonical_json(_runtime_settings(semantics)),
                "state": "IN_PROGRESS",
            })
            return checkpoint
        except (OSError, sqlite3.Error) as error:
            try:
                connection.close()
            except (UnboundLocalError, sqlite3.Error):
                pass
            path.unlink(missing_ok=True)
            raise FolderCheckpointError(
                f"cannot create folder checkpoint: {error}"
            ) from error

    @classmethod
    def resume(
        cls,
        path: Path,
        *,
        root: Path,
        snapshot_sha256: str,
        semantics: Mapping[str, object],
    ) -> "FolderScanCheckpoint":
        path = path.resolve(strict=False)
        if not path.is_file():
            raise FolderCheckpointError(
                f"folder checkpoint does not exist: {path}"
            )
        try:
            connection = sqlite3.connect(
                path,
                timeout=30.0,
                check_same_thread=False,
            )
            checkpoint = cls(path, connection)
            checkpoint._configure()
            metadata = checkpoint._read_metadata()
        except sqlite3.Error as error:
            try:
                connection.close()
            except (UnboundLocalError, sqlite3.Error):
                pass
            raise FolderCheckpointError(
                f"cannot read folder checkpoint: {error}"
            ) from error

        # Version 1 checkpoints originally included worker counts in semantics.
        # Normalize both sides so existing in-progress scans remain resumable.
        try:
            stored_semantics = json.loads(metadata["semantics_json"])
            stored_runtime = json.loads(metadata.get(
                "runtime_json", _canonical_json(_runtime_settings(stored_semantics))
            ))
            if not isinstance(stored_semantics, dict) or not isinstance(stored_runtime, dict):
                raise ValueError("settings must be objects")
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            checkpoint.close()
            raise FolderCheckpointError("invalid checkpoint scanner settings") from error

        expected = {
            "schema_version": str(_SCHEMA_VERSION),
            "source_root": str(root.resolve(strict=False)),
            "snapshot_sha256": snapshot_sha256,
            "semantics_json": _canonical_json(_scan_semantics(semantics)),
        }
        for key, value in expected.items():
            actual = (_canonical_json(_scan_semantics(stored_semantics))
                      if key == "semantics_json" else metadata.get(key))
            if actual != value:
                checkpoint.close()
                if key == "source_root":
                    reason = "source root mismatch"
                elif key == "snapshot_sha256":
                    reason = "folder contents changed since checkpoint creation"
                elif key == "semantics_json":
                    requested = _scan_semantics(semantics)
                    stored = _scan_semantics(stored_semantics)
                    changed = sorted(key for key in stored.keys() | requested.keys()
                                     if stored.get(key) != requested.get(key)
                                     or (key in stored) != (key in requested))
                    reason = "scanner settings mismatch: " + ", ".join(changed)
                else:
                    reason = "checkpoint schema mismatch"
                raise FolderCheckpointError(reason)
        if metadata.get("state") == "COMPLETE":
            checkpoint.close()
            raise FolderCheckpointError(
                "folder checkpoint is already complete"
            )
        checkpoint.runtime_changes = {
            key: (stored_runtime[key], value)
            for key, value in _runtime_settings(semantics).items()
            if key in stored_runtime and stored_runtime[key] != value
        }
        return checkpoint

    def _configure(self) -> None:
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")

    def _create_schema(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE outcomes (
                    relative_path TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    report_json TEXT,
                    error_reason TEXT
                )
                """
            )

    def _write_metadata(self, values: Mapping[str, str]) -> None:
        with self._connection:
            self._connection.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                tuple(values.items()),
            )

    def _read_metadata(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT key, value FROM metadata"
        ).fetchall()
        return {str(key): str(value) for key, value in rows}

    def save_outcome(
        self,
        *,
        relative_path: str,
        size: int,
        mtime_ns: int,
        report: dict | None,
        error_reason: str | None,
    ) -> None:
        report_json = (
            json.dumps(
                report,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            if report is not None
            else None
        )
        try:
            with self._lock, self._connection:
                self._connection.execute(
                    """
                    INSERT OR REPLACE INTO outcomes(
                        relative_path, size, mtime_ns, report_json, error_reason
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        relative_path,
                        int(size),
                        int(mtime_ns),
                        report_json,
                        error_reason,
                    ),
                )
        except sqlite3.Error as error:
            raise FolderCheckpointError(
                f"cannot save folder checkpoint outcome: {error}"
            ) from error

    def records(self) -> tuple[FolderCheckpointRecord, ...]:
        try:
            rows = self._connection.execute(
                """
                SELECT relative_path, size, mtime_ns, report_json, error_reason
                FROM outcomes
                ORDER BY relative_path COLLATE NOCASE, relative_path
                """
            ).fetchall()
        except sqlite3.Error as error:
            raise FolderCheckpointError(
                f"cannot load folder checkpoint outcomes: {error}"
            ) from error

        records: list[FolderCheckpointRecord] = []
        for relative_path, size, mtime_ns, report_json, error_reason in rows:
            report = None
            if report_json is not None:
                try:
                    value = json.loads(report_json)
                except json.JSONDecodeError as error:
                    raise FolderCheckpointError(
                        "folder checkpoint contains invalid report JSON"
                    ) from error
                if not isinstance(value, dict):
                    raise FolderCheckpointError(
                        "folder checkpoint report payload is not an object"
                    )
                report = value
            records.append(FolderCheckpointRecord(
                relative_path=str(relative_path),
                size=int(size),
                mtime_ns=int(mtime_ns),
                report=report,
                error_reason=(
                    None if error_reason is None else str(error_reason)
                ),
            ))
        return tuple(records)

    def mark_complete(self) -> None:
        self._write_metadata({"state": "COMPLETE"})

    def close(self) -> None:
        try:
            self._connection.close()
        except sqlite3.Error as error:
            raise FolderCheckpointError(
                f"cannot close folder checkpoint: {error}"
            ) from error

    def __enter__(self) -> "FolderScanCheckpoint":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
