"""Atomic, secret-safe checkpoints for the unified raw chunk stream."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import time
from typing import Iterable, Mapping, Protocol

from bfrs.core.models import RawHit
from bfrs.recovery.mnemonic.seed_scan_checkpoint import source_identity
from bfrs.version import APP_NAME, VERSION


UNIFIED_CHECKPOINT_FORMAT = "BFRS_UNIFIED_SCAN_CHECKPOINT"
UNIFIED_CHECKPOINT_FORMAT_VERSION = 2
UNIFIED_SCANNER_SEMANTICS_VERSION = 2
LEGACY_UNIFIED_CHECKPOINT_FORMAT = "BFRS_UNIFIED_SCAN_CHECKPOINT_V1"


class ScannerSignature(Protocol):
    name: str
    pattern: bytes
    category: str
    target: str
    artifact_kind: str


class UnifiedCheckpointError(ValueError):
    pass


def _canonical_json(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"),
                      sort_keys=True)


def build_scanner_identity(
    *,
    targets: Iterable[str],
    signatures: Iterable[ScannerSignature],
    mnemonic_enabled: bool,
    bitcoin_context_enabled: bool,
    semantics_version: int = UNIFIED_SCANNER_SEMANTICS_VERSION,
) -> dict[str, object]:
    """Build a canonical identity from public scanner configuration only."""

    signature_identities = sorted(
        ({
            "name": signature.name,
            "pattern_sha256": hashlib.sha256(signature.pattern).hexdigest(),
            "pattern_length": len(signature.pattern),
            "category": signature.category,
            "target": signature.target,
            "artifact_kind": signature.artifact_kind,
        } for signature in signatures),
        key=lambda item: _canonical_json(item),
    )
    canonical: dict[str, object] = {
        "scanner_semantics_version": semantics_version,
        "targets": sorted(set(targets)),
        "mnemonic_enabled": bool(mnemonic_enabled),
        "bitcoin_context_enabled": bool(bitcoin_context_enabled),
        "signatures": signature_identities,
    }
    return {
        **canonical,
        "identity_sha256": hashlib.sha256(
            _canonical_json(canonical).encode("ascii")
        ).hexdigest(),
    }


def _validate_scanner_identity(
    identity: Mapping[str, object], *, checkpoint: bool,
) -> dict[str, object]:
    prefix = "checkpoint scanner semantic mismatch" if checkpoint else "invalid scanner identity"
    required = {
        "scanner_semantics_version",
        "targets",
        "mnemonic_enabled",
        "bitcoin_context_enabled",
        "signatures",
        "identity_sha256",
    }
    if not required.issubset(identity):
        raise UnifiedCheckpointError(f"{prefix}: incomplete canonical identity")
    canonical = {key: identity[key] for key in required - {"identity_sha256"}}
    expected_digest = hashlib.sha256(
        _canonical_json(canonical).encode("ascii")
    ).hexdigest()
    if identity.get("identity_sha256") != expected_digest:
        raise UnifiedCheckpointError(f"{prefix}: identity digest is invalid")
    return dict(identity)


def _scanner_mismatch_reason(
    saved: Mapping[str, object], expected: Mapping[str, object],
) -> str | None:
    comparisons = (
        ("scanner_semantics_version", "scanner semantics version differs"),
        ("targets", "selected targets differ"),
        ("mnemonic_enabled", "mnemonic enablement differs"),
        ("bitcoin_context_enabled", "bitcoin context enablement differs"),
        ("signatures", "active signature definitions differ"),
        ("identity_sha256", "canonical identity digest differs"),
    )
    return next((reason for field, reason in comparisons
                 if saved.get(field) != expected.get(field)), None)


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
        canonical_identity = _validate_scanner_identity(
            scanner_identity, checkpoint=False)
        manager = cls(path, {
            "format": UNIFIED_CHECKPOINT_FORMAT,
            "format_version": UNIFIED_CHECKPOINT_FORMAT_VERSION,
            "application": {"name": APP_NAME, "version": VERSION},
            "source": source_identity(source),
            "range": {"start": start, "end": end},
            "geometry": {"chunk_size": chunk_size, "overlap": overlap},
            "scanner_identity": canonical_identity,
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
            saved_format = payload.get("format")
            if saved_format == LEGACY_UNIFIED_CHECKPOINT_FORMAT:
                raise UnifiedCheckpointError(
                    "legacy unified checkpoint rejected: checkpoint uses the V1 "
                    "compatibility contract without scanner semantics version; "
                    "start a new checkpoint for safe resume")
            if (saved_format != UNIFIED_CHECKPOINT_FORMAT or
                    payload.get("format_version") !=
                    UNIFIED_CHECKPOINT_FORMAT_VERSION):
                raise UnifiedCheckpointError(
                    "checkpoint format mismatch: unsupported unified checkpoint "
                    f"format/version (expected {UNIFIED_CHECKPOINT_FORMAT_VERSION})")
            saved_identity = payload.get("scanner_identity")
            if (not isinstance(saved_identity, Mapping) or
                    "scanner_semantics_version" not in saved_identity):
                raise UnifiedCheckpointError(
                    "legacy unified checkpoint rejected: checkpoint has no scanner "
                    "semantics version; start a new checkpoint for safe resume")
            if payload.get("source") != source_identity(source):
                raise UnifiedCheckpointError(
                    "checkpoint source mismatch: source identity differs")
            if payload.get("range") != {"start": start, "end": end}:
                raise UnifiedCheckpointError(
                    "checkpoint range/chunk configuration mismatch: scan range differs")
            if payload.get("geometry") != {"chunk_size": chunk_size, "overlap": overlap}:
                raise UnifiedCheckpointError(
                    "checkpoint range/chunk configuration mismatch: "
                    "chunk size or overlap differs")
            saved_identity = _validate_scanner_identity(
                saved_identity, checkpoint=True)
            expected_identity = _validate_scanner_identity(
                scanner_identity, checkpoint=False)
            mismatch = _scanner_mismatch_reason(saved_identity, expected_identity)
            if mismatch is not None:
                raise UnifiedCheckpointError(
                    f"checkpoint scanner semantic mismatch: {mismatch}")
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
