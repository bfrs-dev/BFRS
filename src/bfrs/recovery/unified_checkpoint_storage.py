"""Incremental SQLite storage for unified scan checkpoints."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from bfrs.core.models import RawHit
from bfrs.recovery.mnemonic.seed_scan_checkpoint import source_identity
from bfrs.validators.evidence_strength import EvidenceStrength, classify_raw_hit
from bfrs.version import APP_NAME, VERSION


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_PERSISTED_HITS_PER_UNIT = 256


def _owner():
    # Deferred import avoids a cycle while unified_scan_checkpoint aliases this
    # backend after defining the scanner-identity contract.
    from bfrs.recovery import unified_scan_checkpoint as owner

    return owner


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=30.0)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA wal_autocheckpoint = 1000")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


@contextmanager
def _session(path: Path):
    """Open a transaction and always release its Windows file handle."""
    connection = _connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def _read_metadata(connection: sqlite3.Connection) -> dict[str, object]:
    try:
        return {
            key: json.loads(value)
            for key, value in connection.execute(
                "SELECT key, value FROM metadata"
            )
        }
    except (sqlite3.DatabaseError, json.JSONDecodeError, TypeError) as error:
        raise _owner().UnifiedCheckpointError(
            "corrupted unified checkpoint metadata"
        ) from error


def _is_rejected_noise(hit: RawHit) -> bool:
    validation = hit.validation_status.upper()
    return (
        hit.structural_status.upper() == "REJECTED"
        or validation == "REJECTED"
        or any(
            marker in validation
            for marker in ("REJECTED", "INVALID", "INSUFFICIENT", "OUT_OF_SCOPE")
        )
    )


def _requires_replay(hits: tuple[RawHit, ...]) -> bool:
    """Bound persistence while preserving exact results by rescanning a unit."""

    return (
        len(hits) > MAX_PERSISTED_HITS_PER_UNIT
        or any(
            _is_rejected_noise(hit)
            or classify_raw_hit(hit).strength is EvidenceStrength.WEAK
            for hit in hits
        )
    )


class _CompletedResults(Mapping[tuple[int, int], tuple[RawHit, ...]]):
    """Lazy mapping that materializes results for only one unit at a time."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __iter__(self) -> Iterator[tuple[int, int]]:
        try:
            with _session(self.path) as connection:
                rows = connection.execute(
                    "SELECT ownership_start, ownership_end FROM work_units "
                    "WHERE replay_required = 0 ORDER BY ownership_start, ownership_end"
                ).fetchall()
            yield from ((int(start), int(end)) for start, end in rows)
        except sqlite3.DatabaseError as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership ranges"
            ) from error

    def __len__(self) -> int:
        try:
            with _session(self.path) as connection:
                row = connection.execute(
                    "SELECT COUNT(*) FROM work_units WHERE replay_required = 0"
                ).fetchone()
            return int(row[0])
        except sqlite3.DatabaseError as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership ranges"
            ) from error

    def __getitem__(self, unit: tuple[int, int]) -> tuple[RawHit, ...]:
        start, end = unit
        try:
            with _session(self.path) as connection:
                state = connection.execute(
                    "SELECT replay_required FROM work_units "
                    "WHERE ownership_start = ? AND ownership_end = ?",
                    (start, end),
                ).fetchone()
                if state is None or int(state[0]):
                    raise KeyError(unit)
                rows = connection.execute(
                    "SELECT payload FROM results "
                    "WHERE unit_start = ? AND unit_end = ? ORDER BY ordinal",
                    (start, end),
                ).fetchall()
            return tuple(
                _owner()._restore_hit(json.loads(payload))
                for (payload,) in rows
            )
        except KeyError:
            raise
        except (sqlite3.DatabaseError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership range"
            ) from error


class SQLiteUnifiedScanCheckpoint:
    """One small durable transaction per successfully processed work unit."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._connection: sqlite3.Connection | None = None
        self.full_rewrite_count = 0

    @classmethod
    def create(
        cls,
        checkpoint: str | Path,
        source: str | Path,
        *,
        start: int,
        end: int,
        chunk_size: int,
        overlap: int,
        scanner_identity: Mapping[str, object],
    ) -> "SQLiteUnifiedScanCheckpoint":
        owner = _owner()
        path = Path(checkpoint).resolve()
        identity = owner._validate_scanner_identity(
            scanner_identity, checkpoint=False
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as error:
            raise owner.UnifiedCheckpointError("checkpoint already exists") from error
        else:
            os.close(descriptor)
        try:
            with _session(path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    ) WITHOUT ROWID;
                    CREATE TABLE work_units (
                        ownership_start INTEGER NOT NULL,
                        ownership_end INTEGER NOT NULL,
                        hit_count INTEGER NOT NULL,
                        replay_required INTEGER NOT NULL
                            CHECK (replay_required IN (0, 1)),
                        result_digest TEXT NOT NULL,
                        PRIMARY KEY (ownership_start, ownership_end)
                    ) WITHOUT ROWID;
                    CREATE TABLE results (
                        unit_start INTEGER NOT NULL,
                        unit_end INTEGER NOT NULL,
                        result_key TEXT NOT NULL,
                        ordinal INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        PRIMARY KEY (unit_start, unit_end, result_key),
                        FOREIGN KEY (unit_start, unit_end)
                            REFERENCES work_units (ownership_start, ownership_end)
                            ON DELETE CASCADE
                    ) WITHOUT ROWID;
                    CREATE INDEX results_unit_order
                        ON results (unit_start, unit_end, ordinal);
                    """
                )
                connection.execute(
                    f"PRAGMA user_version = {owner.UNIFIED_CHECKPOINT_SCHEMA_VERSION}"
                )
                metadata = {
                    "format": owner.UNIFIED_CHECKPOINT_FORMAT,
                    "format_version": owner.UNIFIED_CHECKPOINT_FORMAT_VERSION,
                    "application": {"name": APP_NAME, "version": VERSION},
                    "source": source_identity(source),
                    "range": {"start": start, "end": end},
                    "geometry": {"chunk_size": chunk_size, "overlap": overlap},
                    "scanner_identity": identity,
                    "complete": False,
                }
                connection.executemany(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ((key, _json(value)) for key, value in metadata.items()),
                )
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return cls(path)

    @classmethod
    def resume(
        cls,
        checkpoint: str | Path,
        source: str | Path,
        *,
        start: int,
        end: int,
        chunk_size: int,
        overlap: int,
        scanner_identity: Mapping[str, object],
    ) -> "SQLiteUnifiedScanCheckpoint":
        owner = _owner()
        path = Path(checkpoint).resolve()
        try:
            with path.open("rb") as stream:
                header = stream.read(len(SQLITE_HEADER))
        except OSError as error:
            raise owner.UnifiedCheckpointError(
                "unable to open unified checkpoint"
            ) from error
        if header != SQLITE_HEADER:
            if header.lstrip().startswith((b"{", b"[")):
                raise owner.UnifiedCheckpointError(
                    "legacy JSON checkpoint storage format rejected: start a new "
                    "checkpoint; automatic migration is not supported"
                )
            raise owner.UnifiedCheckpointError(
                "checkpoint format mismatch: unsupported unified checkpoint storage"
            )
        try:
            with _session(path) as connection:
                schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if schema != owner.UNIFIED_CHECKPOINT_SCHEMA_VERSION:
                    raise owner.UnifiedCheckpointError(
                        "checkpoint format mismatch: unsupported SQLite schema version "
                        f"(expected {owner.UNIFIED_CHECKPOINT_SCHEMA_VERSION})"
                    )
                payload = _read_metadata(connection)
                if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise owner.UnifiedCheckpointError("corrupted unified checkpoint")
            if (
                payload.get("format") != owner.UNIFIED_CHECKPOINT_FORMAT
                or payload.get("format_version")
                != owner.UNIFIED_CHECKPOINT_FORMAT_VERSION
            ):
                raise owner.UnifiedCheckpointError(
                    "checkpoint format mismatch: unsupported unified checkpoint "
                    f"format/version (expected {owner.UNIFIED_CHECKPOINT_FORMAT_VERSION})"
                )
            saved_identity = payload.get("scanner_identity")
            if not isinstance(saved_identity, Mapping):
                raise owner.UnifiedCheckpointError(
                    "legacy unified checkpoint rejected: checkpoint has no scanner "
                    "semantics version; start a new checkpoint for safe resume"
                )
            if payload.get("source") != source_identity(source):
                raise owner.UnifiedCheckpointError(
                    "checkpoint source mismatch: source identity differs"
                )
            if payload.get("range") != {"start": start, "end": end}:
                raise owner.UnifiedCheckpointError(
                    "checkpoint range/chunk configuration mismatch: scan range differs"
                )
            if payload.get("geometry") != {
                "chunk_size": chunk_size,
                "overlap": overlap,
            }:
                raise owner.UnifiedCheckpointError(
                    "checkpoint range/chunk configuration mismatch: "
                    "chunk size or overlap differs"
                )
            saved_identity = owner._validate_scanner_identity(
                saved_identity, checkpoint=True
            )
            expected_identity = owner._validate_scanner_identity(
                scanner_identity, checkpoint=False
            )
            mismatch = owner._scanner_mismatch_reason(
                saved_identity, expected_identity
            )
            if mismatch is not None:
                raise owner.UnifiedCheckpointError(
                    f"checkpoint scanner semantic mismatch: {mismatch}"
                )
        except owner.UnifiedCheckpointError:
            raise
        except (sqlite3.DatabaseError, TypeError, ValueError) as error:
            raise owner.UnifiedCheckpointError(
                "corrupted unified checkpoint"
            ) from error
        manager = cls(path)
        len(manager.completed_results)
        return manager

    def _database(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = _connect(self.path)
        return self._connection

    @property
    def payload(self) -> dict[str, object]:
        """Compact diagnostic metadata; results remain in normalized tables."""
        with _session(self.path) as connection:
            return _read_metadata(connection)

    @property
    def completed_results(self) -> Mapping[tuple[int, int], tuple[RawHit, ...]]:
        return _CompletedResults(self.path)

    @property
    def completed_bytes(self) -> int:
        try:
            with _session(self.path) as connection:
                row = connection.execute(
                    "SELECT COALESCE(SUM(ownership_end - ownership_start), 0) "
                    "FROM work_units WHERE replay_required = 0"
                ).fetchone()
            return int(row[0])
        except sqlite3.DatabaseError as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership ranges"
            ) from error

    @property
    def replay_required_units(self) -> tuple[tuple[int, int], ...]:
        with _session(self.path) as connection:
            return tuple(
                (int(start), int(end))
                for start, end in connection.execute(
                    "SELECT ownership_start, ownership_end FROM work_units "
                    "WHERE replay_required = 1 ORDER BY ownership_start, ownership_end"
                )
            )

    def record(
        self,
        unit: tuple[int, int],
        hits: tuple[RawHit, ...],
        completed: int,
        total: int,
    ) -> None:
        owner = _owner()
        start, end = unit
        if start < 0 or end <= start or completed < 0 or total < completed:
            raise owner.UnifiedCheckpointError("invalid completed ownership range")
        replay_required = _requires_replay(hits)
        serialized: list[tuple[str, int, str]] = []
        digest = hashlib.sha256()
        if replay_required:
            digest.update(f"replay:{len(hits)}".encode("ascii"))
        else:
            for ordinal, hit in enumerate(hits):
                payload = owner._canonical_json(owner._serialize_hit(hit))
                result_key = hashlib.sha256(payload.encode("ascii")).hexdigest()
                digest.update(result_key.encode("ascii"))
                serialized.append((result_key, ordinal, payload))
        result_digest = digest.hexdigest()
        connection = self._database()
        try:
            with connection:
                existing = connection.execute(
                    "SELECT hit_count, replay_required, result_digest FROM work_units "
                    "WHERE ownership_start = ? AND ownership_end = ?",
                    (start, end),
                ).fetchone()
                expected = (len(hits), int(replay_required), result_digest)
                if existing is not None:
                    if tuple(existing) != expected:
                        raise owner.UnifiedCheckpointError(
                            "duplicate completed ownership range has different results"
                        )
                    return
                connection.execute(
                    "INSERT INTO work_units "
                    "(ownership_start, ownership_end, hit_count, replay_required, "
                    "result_digest) VALUES (?, ?, ?, ?, ?)",
                    (start, end, *expected),
                )
                connection.executemany(
                    "INSERT OR IGNORE INTO results "
                    "(unit_start, unit_end, result_key, ordinal, payload) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        (start, end, result_key, ordinal, payload)
                        for result_key, ordinal, payload in serialized
                    ),
                )
        except sqlite3.DatabaseError as error:
            raise owner.UnifiedCheckpointError(
                "unable to persist completed unit"
            ) from error

    def mark_complete(self) -> None:
        connection = self._database()
        with connection:
            connection.execute(
                "UPDATE metadata SET value = 'true' WHERE key = 'complete'"
            )
        self.save(force=True)

    def save(self, *, force: bool = False, create_only: bool = False) -> None:
        """Commit and close handles; unit records are already durable."""
        del force, create_only
        if self._connection is not None:
            self._connection.commit()
            self._connection.close()
            self._connection = None

    def close(self) -> None:
        self.save(force=True)

    def __enter__(self) -> "SQLiteUnifiedScanCheckpoint":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            connection.close()
