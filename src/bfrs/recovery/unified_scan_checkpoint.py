"""Unified scanner identity contract and checkpoint storage facade."""

from __future__ import annotations

import json
import hashlib
from typing import Iterable, Mapping, Protocol

from bfrs.core.models import RawHit


UNIFIED_CHECKPOINT_FORMAT = "BFRS_UNIFIED_SCAN_CHECKPOINT"
UNIFIED_CHECKPOINT_FORMAT_VERSION = 3
UNIFIED_CHECKPOINT_SCHEMA_VERSION = 1
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


# The format-v3 implementation lives separately so the canonical scanner
# identity contract above stays independent from the storage backend.
from bfrs.recovery.unified_checkpoint_storage import (  # noqa: E402
    SQLiteUnifiedScanCheckpoint as UnifiedScanCheckpoint,
)
