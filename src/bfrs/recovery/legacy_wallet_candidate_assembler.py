"""Assemble coherent legacy wallet candidates from decoded logical records."""

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
import hashlib
from typing import Any

from bfrs.core.models import ValidationStatus
from bfrs.recovery.legacy_wallet_era_estimator import (
    LegacyBitcoinWalletEraEstimatorV1,
    LegacyWalletEraEstimate,
)
from bfrs.recovery.legacy_plaintext_key_crypto_validator import (
    LegacyPlaintextKeyCryptoSummary,
    LegacyPlaintextKeyCryptographicValidatorV1,
    PlaintextKeyCryptoState,
    PlaintextKeyCryptoValidation,
)
from bfrs.recovery.logical_btree_membership import (
    LogicalBerkeleySubdatabaseIdentity,
)
from bfrs.recovery.logical_wallet_record_decoder import (
    DecodedLogicalWalletRecord,
    LogicalWalletRecordProvenance,
    LogicalWalletRecordState,
    SUPPORTED_RECORD_TYPES,
)


class RecoveryPriority(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    REJECTED = "REJECTED"


class EncryptionEvidenceState(Enum):
    ENCRYPTED_COMPLETE_EVIDENCE = "ENCRYPTED_COMPLETE_EVIDENCE"
    ENCRYPTED_KEYS_WITHOUT_MASTER_KEY = "ENCRYPTED_KEYS_WITHOUT_MASTER_KEY"
    MASTER_KEY_WITHOUT_CKEY = "MASTER_KEY_WITHOUT_CKEY"
    NO_ENCRYPTION_EVIDENCE = "NO_ENCRYPTION_EVIDENCE"


@dataclass(frozen=True, slots=True)
class CandidateRecordReference:
    record_type: str
    provenance: LogicalWalletRecordProvenance


@dataclass(frozen=True, slots=True)
class CandidateRelationship:
    relationship: str
    left: CandidateRecordReference
    right: CandidateRecordReference


@dataclass(frozen=True, slots=True)
class CandidateConflict:
    finding: str
    records: tuple[CandidateRecordReference, ...]


@dataclass(frozen=True, slots=True)
class LegacyWalletCandidate:
    candidate_id: str
    identity: LogicalBerkeleySubdatabaseIdentity
    records: tuple[DecodedLogicalWalletRecord, ...]
    physical_ranges: tuple[tuple[int, int], ...]
    logical_page_ranges: tuple[tuple[int, tuple[int, int], tuple[int, int]], ...]
    record_counts: tuple[tuple[str, int], ...]
    plain_key_records: int
    encrypted_key_records: int
    master_key_records: int
    structurally_recoverable_private_key_payloads: int
    matched_key_metadata: int
    unmatched_key_metadata: int
    matched_relationships: tuple[CandidateRelationship, ...]
    unmatched_records: tuple[CandidateRecordReference, ...]
    conflicting_records: tuple[CandidateConflict, ...]
    encryption_evidence: EncryptionEvidenceState
    era_estimate: LegacyWalletEraEstimate
    recovery_priority: RecoveryPriority
    fragmentary: bool
    crypto_summary: LegacyPlaintextKeyCryptoSummary
    crypto_validation_results: tuple[PlaintextKeyCryptoValidation, ...]
    provenance: tuple[LogicalWalletRecordProvenance, ...]

    @property
    def priority(self) -> RecoveryPriority:
        return self.recovery_priority

    @property
    def era(self) -> str:
        return self.era_estimate.estimated_era.value

    @property
    def era_confidence(self) -> str:
        return self.era_estimate.confidence.value

    @property
    def encryption_state(self) -> EncryptionEvidenceState:
        return self.encryption_evidence

    @property
    def conflicts(self) -> tuple[CandidateConflict, ...]:
        return self.conflicting_records

    @property
    def crypto_valid_plain_keys(self) -> int:
        return self.crypto_summary.crypto_valid_plain_keys

    @property
    def unique_crypto_valid_plain_keys(self) -> int:
        return self.crypto_summary.unique_crypto_valid_plain_keys

    @property
    def crypto_invalid_plain_records(self) -> int:
        return self.crypto_summary.crypto_invalid_plain_records

    @property
    def crypto_duplicate_occurrences(self) -> int:
        return self.crypto_summary.crypto_duplicate_occurrences

    def to_report_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible V1 candidate report."""
        return {
            "candidate_id": self.candidate_id,
            "priority": self.priority.value,
            "era": self.era,
            "era_confidence": self.era_confidence,
            "encryption_state": self.encryption_state.value,
            "record_counts": dict(self.record_counts),
            "crypto_summary": {
                "crypto_valid_plain_keys": self.crypto_valid_plain_keys,
                "unique_crypto_valid_plain_keys": self.unique_crypto_valid_plain_keys,
                "crypto_invalid_plain_records": self.crypto_invalid_plain_records,
                "crypto_duplicate_occurrences": self.crypto_duplicate_occurrences,
            },
            "crypto_validation_results": [
                {
                    "state": result.state.value,
                    "recovery_classification": result.recovery_classification.value,
                    "original_public_key": self._hex(result.original_public_key),
                    "original_private_value_payload": self._hex(
                        result.original_private_value_payload
                    ),
                    "serialization_layout": result.serialization_layout,
                    "private_key_bytes": self._hex(result.private_key_bytes),
                    "checksum_present": result.checksum_present,
                    "checksum_valid": result.checksum_valid,
                    "public_key_compressed": result.public_key_compressed,
                    "findings": list(result.findings),
                    "provenance": self._provenance_dict(result.provenance),
                }
                for result in self.crypto_validation_results
            ],
            "conflicts": [
                {
                    "finding": conflict.finding,
                    "records": [
                        {
                            "record_type": reference.record_type,
                            "provenance": self._provenance_dict(reference.provenance),
                        }
                        for reference in conflict.records
                    ],
                }
                for conflict in self.conflicts
            ],
            "provenance": [
                self._provenance_dict(item) for item in self.provenance
            ],
        }

    @staticmethod
    def _hex(value: bytes | None) -> str | None:
        return None if value is None else value.hex()

    @staticmethod
    def _provenance_dict(
        provenance: LogicalWalletRecordProvenance,
    ) -> dict[str, Any]:
        identity, page_number = provenance.logical_page_identity
        database = identity.database
        return {
            "source": provenance.source,
            "logical_file_id": database.logical_file_id,
            "metadata_page_number": identity.metadata_page_number,
            "root_page_number": identity.root_page_number,
            "logical_page_number": page_number,
            "physical_key_range": list(provenance.physical_key_range),
            "physical_value_range": list(provenance.physical_value_range),
            "logical_key_range": list(provenance.logical_key_range),
            "logical_value_range": list(provenance.logical_value_range),
            "key_length": provenance.key_length,
            "value_length": provenance.value_length,
            "page_validation_status": provenance.page_validation_status.value,
        }


class LegacyBitcoinWalletCandidateAssemblerV1:
    """Group records by exact logical subdatabase identity, never proximity."""

    _COUNT_ORDER = (
        "key", "ckey", "mkey", "keymeta", "defaultkey", "version", "minversion"
    )

    def __init__(self) -> None:
        self._estimator = LegacyBitcoinWalletEraEstimatorV1()
        self._crypto_validator = LegacyPlaintextKeyCryptographicValidatorV1()

    def assemble(
        self, records: Iterable[DecodedLogicalWalletRecord]
    ) -> tuple[LegacyWalletCandidate, ...]:
        items = tuple(records)
        if any(not isinstance(item, DecodedLogicalWalletRecord) for item in items):
            raise TypeError("records must contain decoded logical wallet records")

        groups: dict[LogicalBerkeleySubdatabaseIdentity, list[DecodedLogicalWalletRecord]] = defaultdict(list)
        for item in items:
            if (
                item.state is not LogicalWalletRecordState.VALID
                or item.record_type not in SUPPORTED_RECORD_TYPES
            ):
                continue
            identity = item.provenance.logical_page_identity[0]
            if not isinstance(identity, LogicalBerkeleySubdatabaseIdentity):
                raise ValueError("record provenance lacks a logical subdatabase identity")
            groups[identity].append(item)

        candidates = [
            self._candidate(identity, tuple(group))
            for identity, group in groups.items()
        ]
        return tuple(sorted(candidates, key=lambda candidate: candidate.candidate_id))

    def _candidate(
        self,
        identity: LogicalBerkeleySubdatabaseIdentity,
        records: tuple[DecodedLogicalWalletRecord, ...],
    ) -> LegacyWalletCandidate:
        ordered = tuple(sorted(records, key=self._record_sort_key))
        counts = Counter(item.record_type for item in ordered)
        relationships, matched, conflicts = self._correlate(ordered)
        unmatched = tuple(
            self._reference(item)
            for index, item in enumerate(ordered)
            if index not in matched
        )
        fragmentary = any(
            item.provenance.page_validation_status is ValidationStatus.FRAGMENT
            for item in ordered
        )
        encryption = self._encryption_state(counts)
        era = self._estimator.estimate(ordered)
        candidate_id = self._candidate_id(identity)
        crypto = self._crypto_validator.validate_records(
            candidate_id, identity, ordered
        )
        private_payloads = sum(
            item.record_type == "key" and item.private_key_payload is not None
            for item in ordered
        )
        matched_metadata = len(
            {
                relationship.right.provenance
                for relationship in relationships
                if relationship.relationship in {"key_keymeta", "ckey_keymeta"}
            }
        )
        priority = self._priority(
            counts, private_payloads, encryption, fragmentary, conflicts, crypto
        )
        return LegacyWalletCandidate(
            candidate_id=candidate_id,
            identity=identity,
            records=ordered,
            physical_ranges=self._physical_ranges(ordered),
            logical_page_ranges=tuple(
                (
                    item.provenance.logical_page_identity[1],
                    item.provenance.logical_key_range,
                    item.provenance.logical_value_range,
                )
                for item in ordered
            ),
            record_counts=tuple((name, counts[name]) for name in self._COUNT_ORDER),
            plain_key_records=counts["key"],
            encrypted_key_records=counts["ckey"],
            master_key_records=counts["mkey"],
            structurally_recoverable_private_key_payloads=private_payloads,
            matched_key_metadata=matched_metadata,
            unmatched_key_metadata=counts["keymeta"] - matched_metadata,
            matched_relationships=relationships,
            unmatched_records=unmatched,
            conflicting_records=conflicts,
            encryption_evidence=encryption,
            era_estimate=era,
            recovery_priority=priority,
            fragmentary=fragmentary,
            crypto_summary=crypto,
            crypto_validation_results=crypto.validations,
            provenance=tuple(item.provenance for item in ordered),
        )

    def _correlate(
        self, records: tuple[DecodedLogicalWalletRecord, ...]
    ) -> tuple[
        tuple[CandidateRelationship, ...], set[int], tuple[CandidateConflict, ...]
    ]:
        by_type: dict[str, list[tuple[int, DecodedLogicalWalletRecord]]] = defaultdict(list)
        for index, item in enumerate(records):
            if item.record_type is not None:
                by_type[item.record_type].append((index, item))

        relationships: list[CandidateRelationship] = []
        matched: set[int] = set()
        for metadata_index, metadata in by_type["keymeta"]:
            for key_type in ("key", "ckey"):
                for key_index, key_record in by_type[key_type]:
                    if key_record.public_key == metadata.public_key:
                        relationships.append(
                            CandidateRelationship(
                                f"{key_type}_keymeta",
                                self._reference(key_record),
                                self._reference(metadata),
                            )
                        )
                        matched.update((key_index, metadata_index))

        for default_index, default in by_type["defaultkey"]:
            for key_type in ("key", "ckey"):
                for key_index, key_record in by_type[key_type]:
                    if key_record.public_key == default.public_key:
                        relationships.append(
                            CandidateRelationship(
                                f"defaultkey_{key_type}",
                                self._reference(default),
                                self._reference(key_record),
                            )
                        )
                        matched.update((default_index, key_index))

        if by_type["ckey"] and by_type["mkey"]:
            for ckey_index, ckey in by_type["ckey"]:
                for mkey_index, mkey in by_type["mkey"]:
                    relationships.append(
                        CandidateRelationship(
                            "encrypted_key_master_key_evidence",
                            self._reference(ckey),
                            self._reference(mkey),
                        )
                    )
                    matched.update((ckey_index, mkey_index))

        # These singleton records apply to the containing logical database,
        # not to another payload. A self-reference records that defensible
        # context association without inventing a second record endpoint.
        for record_type in ("version", "minversion"):
            for record_index, record in by_type[record_type]:
                reference = self._reference(record)
                relationships.append(
                    CandidateRelationship(
                        f"{record_type}_database_context", reference, reference
                    )
                )
                matched.add(record_index)

        conflicts: list[CandidateConflict] = []
        for record_type in ("version", "minversion"):
            entries = by_type[record_type]
            values = {item.wallet_version for _, item in entries}
            if len(values) > 1:
                conflicts.append(
                    CandidateConflict(
                        f"conflicting_{record_type}_values",
                        tuple(self._reference(item) for _, item in entries),
                    )
                )
        defaults = by_type["defaultkey"]
        if len({item.public_key for _, item in defaults}) > 1:
            conflicts.append(
                CandidateConflict(
                    "conflicting_default_keys",
                    tuple(self._reference(item) for _, item in defaults),
                )
            )

        plain_by_public_key: dict[bytes, list[DecodedLogicalWalletRecord]] = defaultdict(list)
        for _, item in by_type["key"]:
            if item.public_key is not None:
                plain_by_public_key[item.public_key].append(item)
        for _public_key, entries in plain_by_public_key.items():
            if len({item.private_key_payload for item in entries}) > 1:
                conflicts.append(
                    CandidateConflict(
                        "conflicting_plain_private_payloads_for_public_key",
                        tuple(self._reference(item) for item in entries),
                    )
                )

        return (
            tuple(sorted(relationships, key=self._relationship_sort_key)),
            matched,
            tuple(sorted(conflicts, key=lambda item: item.finding)),
        )

    @staticmethod
    def _encryption_state(counts: Counter[str]) -> EncryptionEvidenceState:
        if counts["ckey"] and counts["mkey"]:
            return EncryptionEvidenceState.ENCRYPTED_COMPLETE_EVIDENCE
        if counts["ckey"]:
            return EncryptionEvidenceState.ENCRYPTED_KEYS_WITHOUT_MASTER_KEY
        if counts["mkey"]:
            return EncryptionEvidenceState.MASTER_KEY_WITHOUT_CKEY
        return EncryptionEvidenceState.NO_ENCRYPTION_EVIDENCE

    @staticmethod
    def _priority(
        counts: Counter[str],
        private_payloads: int,
        encryption: EncryptionEvidenceState,
        fragmentary: bool,
        conflicts: tuple[CandidateConflict, ...],
        crypto: LegacyPlaintextKeyCryptoSummary,
    ) -> RecoveryPriority:
        if crypto.crypto_valid_plain_keys and not conflicts:
            return RecoveryPriority.CRITICAL
        if encryption is EncryptionEvidenceState.ENCRYPTED_COMPLETE_EVIDENCE:
            return RecoveryPriority.MEDIUM if fragmentary or conflicts else RecoveryPriority.HIGH
        if counts["key"]:
            explicitly_truncated = any(
                result.state is PlaintextKeyCryptoState.TRUNCATED
                for result in crypto.validations
            )
            if private_payloads and (fragmentary or explicitly_truncated) and not conflicts:
                return RecoveryPriority.HIGH
            return RecoveryPriority.MEDIUM
        if counts["ckey"] or counts["mkey"]:
            return RecoveryPriority.MEDIUM
        return RecoveryPriority.LOW

    @staticmethod
    def _reference(item: DecodedLogicalWalletRecord) -> CandidateRecordReference:
        if item.record_type is None:
            raise RuntimeError("valid candidate record has no record type")
        return CandidateRecordReference(item.record_type, item.provenance)

    @staticmethod
    def _record_sort_key(item: DecodedLogicalWalletRecord) -> tuple[Any, ...]:
        provenance = item.provenance
        return (
            provenance.logical_page_identity[1],
            provenance.logical_key_range,
            provenance.logical_value_range,
            item.record_type or "",
        )

    @staticmethod
    def _relationship_sort_key(item: CandidateRelationship) -> tuple[Any, ...]:
        return (
            item.relationship,
            item.left.provenance.logical_page_identity[1],
            item.left.provenance.logical_key_range,
            item.right.provenance.logical_page_identity[1],
            item.right.provenance.logical_key_range,
        )

    @staticmethod
    def _physical_ranges(
        records: tuple[DecodedLogicalWalletRecord, ...]
    ) -> tuple[tuple[int, int], ...]:
        ranges = {
            value
            for item in records
            for value in (
                item.provenance.physical_key_range,
                item.provenance.physical_value_range,
            )
        }
        return tuple(sorted(ranges))

    @staticmethod
    def _candidate_id(identity: LogicalBerkeleySubdatabaseIdentity) -> str:
        database = identity.database
        material = "\x00".join(
            (
                database.source,
                database.logical_file_id,
                str(database.page_size),
                database.byte_order,
                str(identity.metadata_page_number),
                str(identity.root_page_number),
            )
        ).encode("utf-8")
        return f"legacy-wallet-{hashlib.sha256(material).hexdigest()[:16]}"
