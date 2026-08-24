"""Basic data models passed between BFRS pipeline stages."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanRange:
    start_offset: int
    end_offset: int
    source: str


@dataclass(frozen=True, slots=True)
class RawHit:
    start_offset: int
    end_offset: int
    hit_type: str
    confidence: float
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)
    target: str = "unknown"
    artifact_kind: str = "unknown"
    source_kind: str = "RAW_BYTES"
    allocation_state: str = "UNKNOWN_ALLOCATION"
    structural_status: str = "UNVALIDATED"
    validation_status: str = "UNVALIDATED"
    reason_codes: tuple[str, ...] = ()
    correlated_evidence: tuple[str, ...] = ()
    safe_fingerprint: str | None = None
    safe_metadata: dict[str, Any] = field(default_factory=dict)
    recommended_recovery_action: str = "REVIEW_CONTEXT"

    def safe_dict(self) -> dict[str, Any]:
        """Return the normalized finding contract without raw candidate bytes."""
        return {
            "target": self.target,
            "wallet_family": self.target,
            "artifact_kind": self.artifact_kind,
            "physical_start": self.start_offset,
            "physical_end": self.end_offset,
            "source_kind": self.source_kind,
            "allocation_state": self.allocation_state,
            "structural_status": self.structural_status,
            "validation_status": self.validation_status,
            "confidence": self.confidence,
            "reason_codes": list(self.reason_codes),
            "correlated_evidence": list(self.correlated_evidence),
            "safe_fingerprint": self.safe_fingerprint,
            "safe_metadata": dict(self.safe_metadata),
            "recommended_recovery_action": self.recommended_recovery_action,
        }


@dataclass(frozen=True, slots=True)
class Hotspot:
    start_offset: int
    end_offset: int
    score: float
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)


class ValidationStatus(str, Enum):
    STRUCTURAL = "structural"
    FRAGMENT = "fragment"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class ValidationResult:
    start_offset: int
    end_offset: int
    validator: str
    status: ValidationStatus
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)
