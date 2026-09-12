"""Target-aware evidence strength used before expensive recovery work."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from bfrs.core.models import RawHit


class EvidenceStrength(IntEnum):
    """Ordered strength of one independently discovered signal."""

    WEAK = 1
    CORROBORATING = 2
    STRONG = 3
    CRYPTO_VALID = 4


@dataclass(frozen=True, slots=True)
class EvidenceSignal:
    target: str
    artifact_kind: str
    hit_type: str
    strength: EvidenceStrength

    @property
    def independent_identity(self) -> tuple[str, str, str]:
        return self.target, self.artifact_kind, self.hit_type


_CRYPTO_VALID_STATUSES = frozenset({
    "BASE58CHECK_AND_SECP256K1_VALID",
    "ELECTRUM_SEED_VALID",
    "ELECTRUM_V1_STRICT_VALID",
    "BIP39_VALID",
})
_STRONG_VALIDATION_STATUSES = frozenset({
    "BITCOIN_RECORD_KEY_SIDE_VALID",
    "BITCOIN_RECORD_STRUCTURAL_VALID",
    "BERKELEY_METADATA_STRUCTURAL_VALID",
    "PROTOBUF_STRUCTURAL_VALID",
    "ARMORY_HEADER_STRUCTURAL_VALID",
    "ELECTRUM_CONTAINER_STRUCTURAL_VALID",
})
_REJECTED_MARKERS = ("REJECTED", "INVALID", "INSUFFICIENT", "OUT_OF_SCOPE")
_STRONG_STRUCTURAL_STATUSES = frozenset({"STRONG", "STRUCTURAL", "COMPLETE"})
_CORROBORATING_STRUCTURAL_STATUSES = frozenset({"FRAGMENT"})


def classify_raw_hit(hit: RawHit) -> EvidenceSignal:
    """Classify a RawHit without inspecting source bytes or secret material."""

    validation = hit.validation_status.upper()
    structural = hit.structural_status.upper()
    if (
        validation in _CRYPTO_VALID_STATUSES
        or validation == "SECP256K1_VALID" and hit.target == "secrets"
    ):
        strength = EvidenceStrength.CRYPTO_VALID
    elif validation in _STRONG_VALIDATION_STATUSES:
        strength = EvidenceStrength.STRONG
    elif any(marker in validation for marker in _REJECTED_MARKERS):
        strength = EvidenceStrength.WEAK
    elif structural in _STRONG_STRUCTURAL_STATUSES and validation != "UNVALIDATED":
        strength = EvidenceStrength.STRONG
    elif structural in _CORROBORATING_STRUCTURAL_STATUSES:
        strength = EvidenceStrength.CORROBORATING
    elif hit.target == "unknown":
        # Preserve the generic CandidatePolicy contract for custom signatures.
        strength = EvidenceStrength.CORROBORATING
    else:
        strength = EvidenceStrength.WEAK
    return EvidenceSignal(
        target=hit.target,
        artifact_kind=hit.artifact_kind,
        hit_type=hit.hit_type,
        strength=strength,
    )
