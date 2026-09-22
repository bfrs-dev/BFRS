"""Incremental SQLite storage for unified scan checkpoints."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import zlib

from bfrs.core.models import RawHit
from bfrs.recovery.mnemonic.seed_scan_checkpoint import source_identity
from bfrs.version import APP_NAME, VERSION


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_PERSISTED_HITS_PER_UNIT = 256  # Historical v3 replay threshold.
RESULT_CODEC = "json-zlib-v1"


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


def _unit_summary(hits: tuple[RawHit, ...]) -> dict[str, object]:
    """Return secret-free counters committed with a unit's exact hit state."""

    raw_by_target: Counter[str] = Counter()
    rejected_by_target: Counter[str] = Counter()
    pending_by_target: Counter[str] = Counter()
    validated_by_target: Counter[str] = Counter()
    fingerprints: dict[str, set[str]] = {}
    anchors = 0
    for hit in hits:
        raw_by_target[hit.target] += 1
        if hit.target == "internal":
            anchors += 1
        elif hit.validation_status == "REJECTED" or hit.structural_status == "REJECTED":
            rejected_by_target[hit.target] += 1
        elif hit.validation_status == "UNVALIDATED":
            pending_by_target[hit.target] += 1
        else:
            validated_by_target[hit.target] += 1
            if hit.safe_fingerprint is not None:
                fingerprints.setdefault(hit.target, set()).add(hit.safe_fingerprint)
    return {
        "raw_hits": len(hits),
        "anchors": anchors,
        "raw_by_target": dict(sorted(raw_by_target.items())),
        "rejected_by_target": dict(sorted(rejected_by_target.items())),
        "pending_by_target": dict(sorted(pending_by_target.items())),
        "validated_by_target": dict(sorted(validated_by_target.items())),
        "validated_fingerprints": {
            target: sorted(values) for target, values in sorted(fingerprints.items())
        },
    }


def _encode_hits(hits: tuple[RawHit, ...]) -> tuple[bytes, str, str]:
    owner = _owner()
    raw = _json([owner._serialize_hit(hit) for hit in hits]).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    return zlib.compress(raw, level=1), digest, _json(_unit_summary(hits))


def _decode_hits(
    payload: bytes, expected_digest: str, expected_count: int,
) -> tuple[RawHit, ...]:
    owner = _owner()
    try:
        raw = zlib.decompress(payload)
        if hashlib.sha256(raw).hexdigest() != expected_digest:
            raise ValueError("result digest mismatch")
        decoded = json.loads(raw)
        if not isinstance(decoded, list) or len(decoded) != expected_count:
            raise ValueError("result count mismatch")
        hits = tuple(owner._restore_hit(item) for item in decoded)
        return hits
    except (zlib.error, json.JSONDecodeError, TypeError, ValueError) as error:
        raise owner.UnifiedCheckpointError(
            "corrupted persisted state for completed ownership range"
        ) from error


class _CompletedResults(Mapping[tuple[int, int], tuple[RawHit, ...]]):
    """Lazy mapping that materializes results for only one unit at a time."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __iter__(self) -> Iterator[tuple[int, int]]:
        try:
            with _session(self.path) as connection:
                rows = connection.execute(
                    "SELECT ownership_start, ownership_end FROM work_units "
                    "ORDER BY ownership_start, ownership_end"
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
                    "SELECT COUNT(*) FROM work_units"
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
                    "SELECT hit_count, result_digest, summary_payload FROM work_units "
                    "WHERE ownership_start = ? AND ownership_end = ?",
                    (start, end),
                ).fetchone()
                if state is None:
                    raise KeyError(unit)
                row = connection.execute(
                    "SELECT codec, payload FROM results "
                    "WHERE unit_start = ? AND unit_end = ?",
                    (start, end),
                ).fetchone()
            if row is None or row[0] != RESULT_CODEC:
                raise _owner().UnifiedCheckpointError(
                    "missing or unsupported persisted state for completed ownership range"
                )
            hits = _decode_hits(bytes(row[1]), str(state[1]), int(state[0]))
            if _json(_unit_summary(hits)) != str(state[2]):
                raise _owner().UnifiedCheckpointError(
                    "corrupted persisted counters for completed ownership range"
                )
            return hits
        except KeyError:
            raise
        except _owner().UnifiedCheckpointError:
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
                        result_digest TEXT NOT NULL,
                        summary_payload TEXT NOT NULL,
                        state_bytes INTEGER NOT NULL CHECK (state_bytes >= 0),
                        PRIMARY KEY (ownership_start, ownership_end)
                    ) WITHOUT ROWID;
                    CREATE TABLE results (
                        unit_start INTEGER NOT NULL,
                        unit_end INTEGER NOT NULL,
                        codec TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (unit_start, unit_end),
                        FOREIGN KEY (unit_start, unit_end)
                            REFERENCES work_units (ownership_start, ownership_end)
                            ON DELETE CASCADE
                    ) WITHOUT ROWID;
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
                payload = _read_metadata(connection)
                if schema == 1 and payload.get("format_version") == 3:
                    raise owner.UnifiedCheckpointError(
                        "checkpoint v3 requires legacy replay and cannot provide true "
                        "resume; start a new v4 checkpoint"
                    )
                if schema != owner.UNIFIED_CHECKPOINT_SCHEMA_VERSION:
                    raise owner.UnifiedCheckpointError(
                        "checkpoint format mismatch: unsupported SQLite schema version "
                        f"(expected {owner.UNIFIED_CHECKPOINT_SCHEMA_VERSION})"
                    )
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
        manager._validate_completed_prefix(payload)
        manager._validate_completed_ranges()
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
                    "FROM work_units"
                ).fetchone()
            return int(row[0])
        except sqlite3.DatabaseError as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership ranges"
            ) from error

    @property
    def replay_required_units(self) -> tuple[tuple[int, int], ...]:
        return ()

    def _validate_completed_ranges(self) -> None:
        for unit in self.completed_results:
            self.completed_results[unit]

    def _validate_completed_prefix(self, metadata: Mapping[str, object]) -> None:
        try:
            scan_range = metadata["range"]
            geometry = metadata["geometry"]
            cursor = int(scan_range["start"])
            range_end = int(scan_range["end"])
            step = int(geometry["chunk_size"]) - int(geometry["overlap"])
            for unit_start, unit_end in self.completed_results:
                scan_end = min(cursor + int(geometry["chunk_size"]), range_end)
                expected_end = range_end if scan_end >= range_end else min(
                    cursor + step, range_end
                )
                if (unit_start, unit_end) != (cursor, expected_end):
                    raise ValueError("non-contiguous ownership range")
                cursor = unit_end
        except (KeyError, TypeError, ValueError) as error:
            raise _owner().UnifiedCheckpointError(
                "corrupted completed ownership prefix"
            ) from error

    @property
    def storage_statistics(self) -> dict[str, float | int]:
        with _session(self.path) as connection:
            units, findings, payload_bytes = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(hit_count), 0), "
                "COALESCE(SUM(state_bytes), 0) FROM work_units"
            ).fetchone()
        file_bytes = self.path.stat().st_size
        return {
            "work_units": int(units),
            "findings": int(findings),
            "payload_bytes": int(payload_bytes),
            "file_bytes": file_bytes,
            "bytes_per_work_unit": file_bytes / units if units else 0.0,
            "bytes_per_finding": file_bytes / findings if findings else 0.0,
        }

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
        payload, result_digest, summary_payload = _encode_hits(hits)
        connection = self._database()
        try:
            with connection:
                existing = connection.execute(
                    "SELECT hit_count, result_digest, summary_payload, state_bytes "
                    "FROM work_units "
                    "WHERE ownership_start = ? AND ownership_end = ?",
                    (start, end),
                ).fetchone()
                expected = (len(hits), result_digest, summary_payload, len(payload))
                if existing is not None:
                    if tuple(existing) != expected:
                        raise owner.UnifiedCheckpointError(
                            "duplicate completed ownership range has different results"
                        )
                    return
                connection.execute(
                    "INSERT INTO work_units "
                    "(ownership_start, ownership_end, hit_count, result_digest, "
                    "summary_payload, state_bytes) VALUES (?, ?, ?, ?, ?, ?)",
                    (start, end, *expected),
                )
                connection.execute(
                    "INSERT INTO results "
                    "(unit_start, unit_end, codec, payload) VALUES (?, ?, ?, ?)",
                    (start, end, RESULT_CODEC, sqlite3.Binary(payload)),
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
