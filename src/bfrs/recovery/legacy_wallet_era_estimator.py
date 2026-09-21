"""Conservative format and generation-time estimation for legacy wallets."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from bfrs.core.models import ValidationStatus
from bfrs.recovery.logical_wallet_record_decoder import (
    DecodedLogicalWalletRecord,
    LogicalWalletRecordProvenance,
    LogicalWalletRecordState,
)


HD_FEATURE_VERSION = 130_000
_GENESIS_TIMESTAMP = 1_231_006_505
_MAX_REASONABLE_TIMESTAMP = 4_102_444_800  # 2100-01-01 UTC
_KEY_TIME_CLUSTER_SECONDS = 7 * 24 * 60 * 60


class LegacyWalletEra(Enum):
    """Wallet format family, deliberately independent from creation date."""

    LEGACY_PRE_HD = "LEGACY_PRE_HD"
    HD_LEGACY = "HD_LEGACY"
    DESCRIPTOR = "DESCRIPTOR"
    UNKNOWN = "UNKNOWN"

    # Source-compatible aliases for callers that imported the former names.
    PRE_HD_LEGACY = "LEGACY_PRE_HD"
    HD_CAPABLE_LEGACY = "HD_LEGACY"
    EARLY_2009_2010 = "LEGACY_PRE_HD"
    LEGACY_2010_2011 = "LEGACY_PRE_HD"
    LEGACY_ENCRYPTED_2011_PLUS = "LEGACY_PRE_HD"


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
    wallet_generation_time: int | None
    wallet_generation_time_iso_utc: str | None
    generation_time_confidence: EraConfidence | None
    earliest_key_time: int | None
    latest_key_time: int | None
    unique_key_timestamps: int
    timestamp_span_seconds: int | None
    valid_key_timestamps: int
    invalid_key_timestamps: int
    outlier_key_timestamps: int
    client_version_observed: int | None
    client_version_semantics: str = (
        "wallet/client version record; not wallet creation date"
    )

    @property
    def wallet_format_era(self) -> LegacyWalletEra:
        return self.estimated_era


class LegacyBitcoinWalletEraEstimatorV1:
    """Estimate wallet format and generation time without dating by version."""

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
        client_version = max(versions, default=None)

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
        if minimum is not None and client_version is not None and minimum > client_version:
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

        keymeta = tuple(item for item in valid if item.record_type == "keymeta")
        timed = tuple(
            item for item in keymeta
            if self._valid_creation_time(item.keymeta_creation_time)
        )
        invalid_key_times = sum(
            item.keymeta_creation_time is not None
            and not self._valid_creation_time(item.keymeta_creation_time)
            for item in keymeta
        )
        generation_time, generation_confidence, outliers = self._generation_time(timed)
        outlier_ids = {id(item) for item in outliers}
        conflicts.extend(
            EraEvidence("keymeta_creation_time_outlier", item.record_type, item.provenance)
            for item in outliers
        )
        for item in timed:
            detail = (
                "keymeta_generation_time_cluster"
                if id(item) not in outlier_ids else "keymeta_generation_time_outlier"
            )
            positive.append(EraEvidence(detail, item.record_type, item.provenance))

        key_times = tuple(sorted(int(item.keymeta_creation_time) for item in timed))
        earliest_key_time = key_times[0] if key_times else None
        latest_key_time = key_times[-1] if key_times else None
        timestamp_span = (
            latest_key_time - earliest_key_time if key_times else None
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
        hd_required = any(value >= HD_FEATURE_VERSION for value in minversions)
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
        if hd_metadata or hd_required:
            era = LegacyWalletEra.HD_LEGACY
            confidence = EraConfidence.HIGH if hd_metadata else EraConfidence.MEDIUM
        elif types & {"key", "ckey", "mkey", "keymeta", "defaultkey"}:
            era = LegacyWalletEra.LEGACY_PRE_HD
            confidence = EraConfidence.HIGH if paired_encryption else EraConfidence.MEDIUM
        else:
            era = LegacyWalletEra.UNKNOWN
            confidence = EraConfidence.LOW

        fragmentary = any(
            item.provenance.page_validation_status is ValidationStatus.FRAGMENT
            or item.state is LogicalWalletRecordState.PARTIAL
            for item in items
        )
        format_conflicts = tuple(
            item for item in conflicts
            if item.finding in {"extended_keymeta_not_interpreted"}
        )
        if fragmentary or format_conflicts:
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
        if not (hd_metadata or hd_required):
            missing.append("deterministic_hd_metadata_missing")
        if not timed:
            missing.append("valid_keymeta_creation_time_missing")
        if fragmentary:
            missing.append("complete_database_evidence_missing")

        return LegacyWalletEraEstimate(
            era, minimum, client_version, confidence, tuple(positive), tuple(conflicts),
            tuple(missing), False, generation_time,
            self._iso_utc(generation_time), generation_confidence,
            earliest_key_time, latest_key_time, len(set(key_times)), timestamp_span,
            len(key_times), invalid_key_times, len(outliers), client_version,
        )

    @classmethod
    def _generation_time(
        cls, records: tuple[DecodedLogicalWalletRecord, ...]
    ) -> tuple[int | None, EraConfidence | None, tuple[DecodedLogicalWalletRecord, ...]]:
        if not records:
            return None, None, ()
        ordered = tuple(sorted(records, key=lambda item: int(item.keymeta_creation_time)))
        if len(ordered) == 1:
            return int(ordered[0].keymeta_creation_time), EraConfidence.MEDIUM, ()
        best_start = best_end = 0
        start = 0
        for end, item in enumerate(ordered):
            current = int(item.keymeta_creation_time)
            while current - int(ordered[start].keymeta_creation_time) > _KEY_TIME_CLUSTER_SECONDS:
                start += 1
            if end - start > best_end - best_start:
                best_start, best_end = start, end
        cluster = ordered[best_start:best_end + 1]
        if len(cluster) * 2 <= len(ordered):
            return None, None, ordered
        outliers = tuple(item for item in ordered if item not in cluster)
        ratio = len(cluster) / len(ordered)
        confidence = EraConfidence.HIGH if ratio >= 0.8 else EraConfidence.MEDIUM
        return int(cluster[0].keymeta_creation_time), confidence, outliers

    @staticmethod
    def _valid_creation_time(value: int | None) -> bool:
        return (
            isinstance(value, int)
            and _GENESIS_TIMESTAMP <= value <= _MAX_REASONABLE_TIMESTAMP
        )

    @staticmethod
    def _iso_utc(value: int | None) -> str | None:
        if value is None:
            return None
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _lower(confidence: EraConfidence) -> EraConfidence:
        if confidence is EraConfidence.HIGH:
            return EraConfidence.MEDIUM
        return EraConfidence.LOW
