"""Conservative era estimation from decoded logical legacy wallet records."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from bfrs.core.models import ValidationStatus
from bfrs.recovery.logical_wallet_record_decoder import (
    DecodedLogicalWalletRecord,
    LogicalWalletRecordProvenance,
    LogicalWalletRecordState,
)


WALLETCRYPT_VERSION = 40_000
HD_FEATURE_VERSION = 130_000


class LegacyWalletEra(Enum):
    EARLY_2009_2010 = "EARLY_2009_2010"
    LEGACY_2010_2011 = "LEGACY_2010_2011"
    LEGACY_ENCRYPTED_2011_PLUS = "LEGACY_ENCRYPTED_2011_PLUS"
    PRE_HD_LEGACY = "PRE_HD_LEGACY"
    HD_CAPABLE_LEGACY = "HD_CAPABLE_LEGACY"
    UNKNOWN = "UNKNOWN"


class EraConfidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True, slots=True)
class EraEvidence:
    finding: str
    record_type: str | None
    provenance: LogicalWalletRecordProvenance


@dataclass(frozen=True, slots=True)
class LegacyWalletEraEstimate:
    estimated_era: LegacyWalletEra
    minimum_compatible_version: int | None
    maximum_plausible_version: int | None
    confidence: EraConfidence
    positive_evidence: tuple[EraEvidence, ...]
    conflicting_evidence: tuple[EraEvidence, ...]
    missing_evidence: tuple[str, ...]
    exact_version_determinable: bool


class LegacyBitcoinWalletEraEstimatorV1:
    """Estimate broad eras; never convert wallet feature values into a release claim."""

    def estimate(
        self, records: Iterable[DecodedLogicalWalletRecord]
    ) -> LegacyWalletEraEstimate:
        items = tuple(records)
        if any(not isinstance(item, DecodedLogicalWalletRecord) for item in items):
            raise TypeError("records must contain decoded logical wallet records")

        valid = tuple(item for item in items if item.state is LogicalWalletRecordState.VALID)
        types = {item.record_type for item in valid}
        version_records = tuple(item for item in valid if item.record_type == "version")
        minversion_records = tuple(item for item in valid if item.record_type == "minversion")
        versions = tuple(item.wallet_version for item in version_records if item.wallet_version is not None)
        minversions = tuple(item.wallet_version for item in minversion_records if item.wallet_version is not None)
        minimum = max(minversions, default=None)
        maximum = max(versions, default=None)

        positive: list[EraEvidence] = []
        conflicts: list[EraEvidence] = []
        for item in valid:
            if item.record_type in {"version", "minversion", "key", "ckey", "mkey", "keymeta", "defaultkey"}:
                detail = (
                    f"{item.record_type}={item.wallet_version}"
                    if item.record_type in {"version", "minversion"}
                    else f"valid_{item.record_type}_record"
                )
                positive.append(EraEvidence(detail, item.record_type, item.provenance))

        if len(set(versions)) > 1:
            conflicts.extend(
                EraEvidence("conflicting_version_value", item.record_type, item.provenance)
                for item in version_records
            )
        if len(set(minversions)) > 1:
            conflicts.extend(
                EraEvidence("conflicting_minversion_value", item.record_type, item.provenance)
                for item in minversion_records
            )
        if minimum is not None and maximum is not None and minimum > maximum:
            conflicts.extend(
                EraEvidence("minversion_exceeds_version", item.record_type, item.provenance)
                for item in (*version_records, *minversion_records)
            )

        extended_keymeta = tuple(
            item for item in items
            if item.record_type == "keymeta" and "keymeta_layout_unsupported" in item.findings
        )
        conflicts.extend(
            EraEvidence("extended_keymeta_not_interpreted", item.record_type, item.provenance)
            for item in extended_keymeta
        )

        encrypted = "ckey" in types or "mkey" in types
        paired_encryption = "ckey" in types and "mkey" in types
        hd_metadata = any(
            item.record_type == "keymeta"
            and item.keymeta_version is not None
            and item.keymeta_version >= 10
            and item.keymeta_hd_path is not None
            and item.keymeta_hd_seed_id not in (None, bytes(20))
            for item in valid
        )
        hd_capable = hd_metadata or any(
            value >= HD_FEATURE_VERSION for value in (*versions, *minversions)
        )
        if hd_metadata:
            positive.extend(
                EraEvidence("deterministic_hd_keymeta", item.record_type, item.provenance)
                for item in valid
                if item.record_type == "keymeta"
                and item.keymeta_version is not None
                and item.keymeta_version >= 10
                and item.keymeta_hd_path is not None
                and item.keymeta_hd_seed_id not in (None, bytes(20))
            )
        if hd_capable:
            era = LegacyWalletEra.HD_CAPABLE_LEGACY
            confidence = EraConfidence.HIGH
        elif encrypted:
            era = LegacyWalletEra.LEGACY_ENCRYPTED_2011_PLUS
            confidence = EraConfidence.HIGH if paired_encryption else EraConfidence.MEDIUM
        elif versions and max(versions) < 30_000:
            era = LegacyWalletEra.EARLY_2009_2010
            confidence = EraConfidence.HIGH
        elif versions and max(versions) < WALLETCRYPT_VERSION:
            era = LegacyWalletEra.LEGACY_2010_2011
            confidence = EraConfidence.HIGH
        elif "defaultkey" in types and ("key" in types or "keymeta" in types):
            era = LegacyWalletEra.EARLY_2009_2010
            confidence = EraConfidence.MEDIUM
        elif types & {"key", "keymeta", "defaultkey"}:
            era = LegacyWalletEra.PRE_HD_LEGACY
            confidence = EraConfidence.LOW
        else:
            era = LegacyWalletEra.UNKNOWN
            confidence = EraConfidence.LOW

        fragmentary = any(
            item.provenance.page_validation_status is ValidationStatus.FRAGMENT
            or item.state is LogicalWalletRecordState.PARTIAL
            for item in items
        )
        if fragmentary or conflicts:
            confidence = self._lower(confidence)

        missing: list[str] = []
        if not version_records:
            missing.append("version_record_missing")
        if not minversion_records:
            missing.append("minversion_record_missing")
        if not encrypted:
            missing.append("encryption_state_not_proven_by_absence")
        elif not paired_encryption:
            missing.append("complete_ckey_mkey_pair_missing")
        if not hd_capable:
            missing.append("deterministic_hd_metadata_missing")
        if fragmentary:
            missing.append("complete_database_evidence_missing")

        return LegacyWalletEraEstimate(
            era, minimum, maximum, confidence, tuple(positive), tuple(conflicts),
            tuple(missing), False,
        )

    @staticmethod
    def _lower(confidence: EraConfidence) -> EraConfidence:
        if confidence is EraConfidence.HIGH:
            return EraConfidence.MEDIUM
        return EraConfidence.LOW
