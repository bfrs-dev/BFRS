"""Atomic, secret-safe checkpoints for the unified raw chunk stream."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Mapping

from bfrs.core.models import RawHit
from bfrs.recovery.mnemonic.seed_scan_checkpoint import source_identity


FORMAT = "BFRS_UNIFIED_SCAN_CHECKPOINT_V1"


class UnifiedCheckpointError(ValueError):
    pass


def _serialize_hit(hit: RawHit) -> dict[str, object]:
    return {
        "start_offset": hit.start_offset,
        "end_offset": hit.end_offset,
        "hit_type": hit.hit_type,
        "confidence": hit.confidence,
        "source": hit.source,
        "evidence": hit.evidence,
        "target": hit.target,
        "artifact_kind": hit.artifact_kind,
        "source_kind": hit.source_kind,
        "allocation_state": hit.allocation_state,
        "structural_status": hit.structural_status,
        "validation_status": hit.validation_status,
        "reason_codes": list(hit.reason_codes),
        "correlated_evidence": list(hit.correlated_evidence),
        "safe_fingerprint": hit.safe_fingerprint,
        "safe_metadata": hit.safe_metadata,
        "recommended_recovery_action": hit.recommended_recovery_action,
    }


def _restore_hit(payload: Mapping[str, object]) -> RawHit:
    values = dict(payload)
    values["reason_codes"] = tuple(values.get("reason_codes", ()))
    values["correlated_evidence"] = tuple(values.get("correlated_evidence", ()))
    return RawHit(**values)


class UnifiedScanCheckpoint:
    def __init__(self, path: Path, payload: dict[str, object]) -> None:
        self.path = path.resolve()
        self.payload = payload
        self._dirty = True
        self._last_write = 0.0

    @classmethod
    def create(
        cls, checkpoint: str | Path, source: str | Path, *, start: int, end: int,
        chunk_size: int, overlap: int, scanner_identity: Mapping[str, object],
    ) -> "UnifiedScanCheckpoint":
        path = Path(checkpoint).resolve()
        if path.exists():
            raise UnifiedCheckpointError("checkpoint already exists")
        manager = cls(path, {
            "format": FORMAT,
            "source": source_identity(source),
            "range": {"start": start, "end": end},
            "geometry": {"chunk_size": chunk_size, "overlap": overlap},
            "scanner_identity": dict(scanner_identity),
            "completed_units": [],
            "complete": False,
        })
        manager.save(force=True, create_only=True)
        return manager

    @classmethod
    def resume(
        cls, checkpoint: str | Path, source: str | Path, *, start: int, end: int,
        chunk_size: int, overlap: int, scanner_identity: Mapping[str, object],
    ) -> "UnifiedScanCheckpoint":
        path = Path(checkpoint).resolve()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if payload.get("format") != FORMAT:
                raise UnifiedCheckpointError("unsupported unified checkpoint format")
            if payload.get("source") != source_identity(source):
                raise UnifiedCheckpointError("checkpoint source identity mismatch")
            if payload.get("range") != {"start": start, "end": end}:
                raise UnifiedCheckpointError("checkpoint scan range mismatch")
            if payload.get("geometry") != {"chunk_size": chunk_size, "overlap": overlap}:
                raise UnifiedCheckpointError("checkpoint scanner geometry mismatch")
            if payload.get("scanner_identity") != dict(scanner_identity):
                raise UnifiedCheckpointError("checkpoint detector selection mismatch")
            if not isinstance(payload.get("completed_units"), list):
                raise UnifiedCheckpointError("invalid completed ownership ranges")
        except UnifiedCheckpointError:
            raise
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise UnifiedCheckpointError("corrupted unified checkpoint") from error
        manager = cls(path, payload)
        manager._dirty = False
        manager.completed_results
        return manager

    @property
    def completed_results(self) -> dict[tuple[int, int], tuple[RawHit, ...]]:
        restored: dict[tuple[int, int], tuple[RawHit, ...]] = {}
        try:
            for unit in self.payload["completed_units"]:
                key = (int(unit["ownership_start"]), int(unit["ownership_end"]))
                if key in restored:
                    raise UnifiedCheckpointError("duplicate completed ownership range")
                restored[key] = tuple(_restore_hit(item) for item in unit["hits"])
        except UnifiedCheckpointError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise UnifiedCheckpointError("corrupted completed ownership range") from error
        return restored

    @property
    def completed_bytes(self) -> int:
        return sum(end - start for start, end in self.completed_results)

    def record(self, unit: tuple[int, int], hits: tuple[RawHit, ...],
               completed: int, total: int) -> None:
        existing = {(int(item["ownership_start"]), int(item["ownership_end"]))
                    for item in self.payload["completed_units"]}
        if unit not in existing:
            self.payload["completed_units"].append({
                "ownership_start": unit[0],
                "ownership_end": unit[1],
                "hits": [_serialize_hit(hit) for hit in hits],
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
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as stream:
                json.dump(self.payload, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if create_only:
                try:
                    os.link(temporary, self.path)
                except FileExistsError as error:
                    raise UnifiedCheckpointError("checkpoint already exists") from error
            else:
                os.replace(temporary, self.path)
        finally:
            if temporary.exists():
                temporary.unlink()
        self._dirty = False
        self._last_write = time.monotonic()
