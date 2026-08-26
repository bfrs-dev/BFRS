"""Atomic, secret-safe checkpoints for raw mnemonic ownership units."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time

from .mnemonic_candidate import MnemonicCandidate
from .raw_mnemonic_scanner import (
    MnemonicOccurrence,
    MnemonicSecret,
    RawMnemonicScanResult,
)


# Completed units bypass validation during resume, so every scanner-semantic
# change must use a new format.  V2 introduced contiguous BIP39, V3 added the
# separately identified strict Electrum V1 standard, and V4 makes Electrum 2+
# tokenization contiguous.  V5 scans both byte phases for each UTF-16 endian;
# V6 records results produced by the bytes-prefiltered candidate-window scanner.
# Older completed units can contain invalid hits or omit newly covered hits.
FORMAT = "BFRS_SEED_SCAN_CHECKPOINT_V6"
IDENTITY_BYTES = 64 * 1024


class CheckpointError(ValueError):
    """A checkpoint is corrupt or incompatible with the requested scan."""


def source_identity(source: str | Path) -> dict[str, object]:
    path = Path(source).resolve()
    stat = path.stat()
    digest = hashlib.sha256()
    digest.update(b"BFRS-SEED-SOURCE-IDENTITY-V1\0")
    with path.open("rb") as stream:
        digest.update(stream.read(IDENTITY_BYTES))
        if stat.st_size > IDENTITY_BYTES:
            stream.seek(max(0, stat.st_size - IDENTITY_BYTES))
            digest.update(stream.read(IDENTITY_BYTES))
    return {
        "path": str(path),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "edge_sha256": digest.hexdigest(),
    }


def _serialize_result(result: RawMnemonicScanResult) -> dict[str, object]:
    return {
        "anchors_found": result.anchors_found,
        "checksum_invalid": result.checksum_invalid,
        "failures": list(result.failures),
        "prefilter_windows": result.prefilter_windows,
        "expensive_validations": result.expensive_validations,
        "bip39_validations": result.bip39_validations,
        "electrum_validations": result.electrum_validations,
        "electrum_v1_validations": result.electrum_v1_validations,
        "occurrences": [item.candidate.safe_dict() for item in result.occurrences],
    }


def _restore_candidate(payload: dict[str, object]) -> MnemonicCandidate:
    values = dict(payload)
    for name in ("reason_codes", "correlated_sources", "provenance"):
        values[name] = tuple(values.get(name, ()))
    return MnemonicCandidate(**values)


def _restore_result(payload: dict[str, object]) -> RawMnemonicScanResult:
    occurrences = tuple(
        MnemonicOccurrence(_restore_candidate(item), MnemonicSecret(""))
        for item in payload.get("occurrences", [])
    )
    return RawMnemonicScanResult(
        occurrences=occurrences,
        anchors_found=int(payload.get("anchors_found", 0)),
        checksum_invalid=int(payload.get("checksum_invalid", 0)),
        failures=tuple(str(item) for item in payload.get("failures", [])),
        prefilter_windows=int(payload.get("prefilter_windows", 0)),
        expensive_validations=int(payload.get("expensive_validations", 0)),
        bip39_validations=int(payload.get("bip39_validations", 0)),
        electrum_validations=int(payload.get("electrum_validations", 0)),
        electrum_v1_validations=int(payload.get("electrum_v1_validations", 0)),
    )


class SeedScanCheckpoint:
    def __init__(self, path: str | Path, payload: dict[str, object]) -> None:
        self.path = Path(path).resolve()
        self.payload = payload
        self._last_write = 0.0
        self._dirty = True

    @classmethod
    def create(cls, checkpoint: str | Path, source: str | Path, *, start: int,
               end: int, chunk_size: int, overlap: int) -> SeedScanCheckpoint:
        path = Path(checkpoint).resolve()
        if path.exists():
            raise CheckpointError(
                "checkpoint already exists; use --resume-checkpoint to continue it"
            )
        payload: dict[str, object] = {
            "format": FORMAT,
            "source": source_identity(source),
            "range": {"start": start, "end": end},
            "geometry": {"chunk_size": chunk_size, "overlap": overlap},
            "completed_units": [],
            "complete": False,
        }
        manager = cls(path, payload)
        manager.save(force=True, create_only=True)
        return manager

    @classmethod
    def resume(cls, checkpoint: str | Path, source: str | Path, *, start: int,
               end: int, chunk_size: int, overlap: int) -> SeedScanCheckpoint:
        path = Path(checkpoint).resolve()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("format") != FORMAT:
                raise CheckpointError("unsupported checkpoint format")
            expected_identity = source_identity(source)
            saved_identity = payload["source"]
            if saved_identity != expected_identity:
                raise CheckpointError("checkpoint source identity mismatch")
            if payload["range"] != {"start": start, "end": end}:
                raise CheckpointError("checkpoint scan range mismatch")
            if payload["geometry"] != {"chunk_size": chunk_size, "overlap": overlap}:
                raise CheckpointError("checkpoint scanner geometry mismatch")
            if not isinstance(payload.get("completed_units"), list):
                raise CheckpointError("invalid completed ownership ranges")
        except CheckpointError:
            raise
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise CheckpointError("corrupted checkpoint") from error
        manager = cls(path, payload)
        manager._dirty = False
        # Fully validate serialized unit results before the CLI starts progress.
        manager.completed_results
        return manager

    @property
    def completed_results(self) -> dict[tuple[int, int], RawMnemonicScanResult]:
        restored = {}
        try:
            for unit in self.payload["completed_units"]:
                key = (int(unit["ownership_start"]), int(unit["ownership_end"]))
                if key in restored:
                    raise CheckpointError("duplicate completed ownership range")
                restored[key] = _restore_result(unit["result"])
        except CheckpointError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise CheckpointError("corrupted completed ownership range") from error
        return restored

    @property
    def completed_bytes(self) -> int:
        return sum(end - start for start, end in self.completed_results)

    def record(self, unit: tuple[str, int, int, int, int],
               result: RawMnemonicScanResult, completed: int, total: int) -> None:
        ownership_start, ownership_end = unit[3], unit[4]
        existing = {(int(item["ownership_start"]), int(item["ownership_end"]))
                    for item in self.payload["completed_units"]}
        if (ownership_start, ownership_end) not in existing:
            self.payload["completed_units"].append({
                "ownership_start": ownership_start,
                "ownership_end": ownership_end,
                "result": _serialize_result(result),
            })
            self.payload["completed_units"].sort(
                key=lambda item: (item["ownership_start"], item["ownership_end"]))
            self._dirty = True
        if completed == total or time.monotonic() - self._last_write >= 5.0:
            self.save()

    def mark_complete(self) -> None:
        self.payload["complete"] = True
        self._dirty = True
        self.save(force=True)

    def save(self, *, force: bool = False, create_only: bool = False) -> None:
        if not self._dirty and not force:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f"{self.path.name}.tmp-{os.getpid()}")
        serialized = json.dumps(self.payload, indent=2, sort_keys=True)
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            if create_only:
                try:
                    os.link(temporary, self.path)
                except FileExistsError as error:
                    raise CheckpointError(
                        "checkpoint already exists; use --resume-checkpoint to continue it"
                    ) from error
            else:
                os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
        self._last_write = time.monotonic()
        self._dirty = False
