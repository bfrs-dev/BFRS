"""Durable per-file checkpoint storage for recursive folder scans."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
from typing import Iterator, Mapping, Sequence


_SCHEMA_VERSION = 1
_RUNTIME_SETTINGS = frozenset({"workers", "file_workers"})
_MAX_PENDING_REPORT_BYTES = 8 * 1024**2


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
    """FULL-synchronous outcomes; optional bounded, timed transaction batching.

    Direct callers retain synchronous saves until set_batching() is called.
    In batched mode save_outcome() accepts a result; only flush()/close() or a
    successful automatic commit makes it durable. A failed commit is latched.
    """

    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._batch_size = 1
        self._flush_interval = 1.0
        self._pending: dict[str, tuple] = {}
        self._pending_bytes = 0
        self._deadline = 0.0
        self._writer: threading.Thread | None = None
        self._stopping = False
        self._closed = False
        self._failure: FolderCheckpointError | None = None
        self._durable_files: int | None = None
        self._durable_bytes = 0
        self._accepted = 0
        self._commits = 0
        self._commit_seconds = 0.0
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
        self._connection.execute("PRAGMA cache_size=-2048")
        self._connection.execute("PRAGMA temp_store=FILE")

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

    def _check_locked(self) -> None:
        if self._failure is not None:
            raise self._failure
        if self._closed or self._stopping:
            raise FolderCheckpointError("folder checkpoint is closed")

    def _load_counts_locked(self) -> None:
        if self._durable_files is None:
            try:
                self._durable_files, self._durable_bytes = self._connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM outcomes"
                ).fetchone()
            except sqlite3.Error as error:
                self._failure = FolderCheckpointError(
                    f"cannot read folder checkpoint counters: {error}")
                self._condition.notify_all()
                raise self._failure from error

    def set_batching(self, max_outcomes: int = 32, flush_interval: float = 1.0) -> None:
        """Set runtime-only write policy before accepting any new outcomes."""
        if not 1 <= max_outcomes <= 32 or not 0 < flush_interval <= 1.0:
            raise ValueError("batch size must be 1..32 and interval must be (0, 1] seconds")
        with self._condition:
            self._check_locked()
            if self._accepted:
                raise FolderCheckpointError("cannot change batching after saving outcomes")
            self._batch_size = max_outcomes
            self._flush_interval = flush_interval

    @property
    def durability(self) -> dict[str, int | float]:
        """Committed rows only; pending rows are never advertised as durable."""
        with self._condition:
            if not self._closed:
                self._load_counts_locked()
            return {"durable_files": self._durable_files or 0,
                    "durable_bytes": self._durable_bytes,
                    "pending_files": len(self._pending), "accepted_outcomes": self._accepted,
                    "commits": self._commits, "commit_seconds": self._commit_seconds}

    def _flush_locked(self) -> None:
        if self._failure is not None:
            raise self._failure
        if not self._pending:
            return
        began = time.perf_counter()
        try:
            self._load_counts_locked()
            added = byte_delta = 0
            with self._connection:
                # Keep the count exact for INSERT OR REPLACE without retaining
                # a Python set of every completed path or recounting the table.
                for path, row in self._pending.items():
                    previous = self._connection.execute(
                        "SELECT size FROM outcomes WHERE relative_path=?", (path,)
                    ).fetchone()
                    added += previous is None
                    byte_delta += row[1] - (previous[0] if previous else 0)
                self._connection.executemany(
                    """INSERT OR REPLACE INTO outcomes(
                        relative_path, size, mtime_ns, report_json, error_reason
                    ) VALUES (?, ?, ?, ?, ?)""", self._pending.values())
            # __exit__ has successfully committed at synchronous=FULL.
            self._durable_files += added
            self._durable_bytes += byte_delta
            self._pending.clear()
            self._pending_bytes = 0
            self._commits += 1
            self._commit_seconds += time.perf_counter() - began
        except sqlite3.Error as error:
            self._failure = FolderCheckpointError(
                f"cannot save folder checkpoint outcome: {error}")
            self._condition.notify_all()
            raise self._failure from error

    def _timed_flush(self) -> None:
        # The deadline belongs to the oldest pending result, not the last
        # arrival. Condition.wait releases the lock even if no worker returns.
        with self._condition:
            while not self._stopping and self._failure is None:
                if not self._pending:
                    self._condition.wait()
                    continue
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                try:
                    self._flush_locked()
                except FolderCheckpointError:
                    return

    def flush(self) -> None:
        with self._condition:
            self._check_locked()
            self._flush_locked()

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
        with self._condition:
            self._check_locked()
            if not self._pending:
                self._deadline = time.monotonic() + self._flush_interval
            previous = self._pending.get(relative_path)
            if previous and previous[3]:
                self._pending_bytes -= sys.getsizeof(previous[3])
            self._pending[relative_path] = (
                relative_path, int(size), int(mtime_ns), report_json, error_reason)
            self._pending_bytes += sys.getsizeof(report_json) if report_json else 0
            self._accepted += 1
            # Limit large reports too; a single oversized outcome is committed
            # immediately. The schema and JSON representation do not change.
            if len(self._pending) >= self._batch_size or self._pending_bytes >= _MAX_PENDING_REPORT_BYTES:
                self._flush_locked()
            elif self._writer is None:
                self._writer = threading.Thread(target=self._timed_flush,
                    name="bfrs-folder-checkpoint", daemon=True)
                self._writer.start()
            self._condition.notify_all()

    def record_count(self) -> int:
        with self._condition:
            self._check_locked()
            return int(self._connection.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0])

    def records(self) -> Iterator[FolderCheckpointRecord]:
        """Stream committed outcomes, serializing cursor access with writes."""
        try:
            for relative_path, size, mtime_ns, report_json, error_reason in self._record_rows():
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
                yield FolderCheckpointRecord(
                    relative_path=str(relative_path), size=int(size), mtime_ns=int(mtime_ns),
                    report=report, error_reason=None if error_reason is None else str(error_reason))
        except sqlite3.Error as error:
            raise FolderCheckpointError(f"cannot load folder checkpoint outcomes: {error}") from error

    def _record_rows(self) -> Iterator[tuple]:
        try:
            with self._condition:
                self._check_locked()
                rows = self._connection.execute(
                    """SELECT relative_path, size, mtime_ns, report_json, error_reason
                    FROM outcomes ORDER BY relative_path""")
        except sqlite3.Error as error:
            raise FolderCheckpointError(
                f"cannot load folder checkpoint outcomes: {error}"
            ) from error

        try:
            while True:
                with self._condition:
                    self._check_locked()
                    row = rows.fetchone()
                if row is None:
                    break
                yield row
        finally:
            with self._condition:
                rows.close()

    def mark_complete(self) -> None:
        with self._condition:
            self._check_locked()
            self._flush_locked()
            try:
                self._write_metadata({"state": "COMPLETE"})
            except sqlite3.Error as error:
                self._failure = FolderCheckpointError(
                    f"cannot complete folder checkpoint: {error}")
                raise self._failure from error

    def close(self) -> None:
        try:
            with self._condition:
                if self._closed:
                    return
                self._stopping = True
                self._condition.notify_all()
                try:
                    self._flush_locked()
                finally:
                    self._connection.close()
                    self._closed = True
        except sqlite3.Error as error:
            raise FolderCheckpointError(f"cannot close folder checkpoint: {error}") from error
        finally:
            if self._writer is not None:
                self._writer.join()

    def __enter__(self) -> "FolderScanCheckpoint":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
