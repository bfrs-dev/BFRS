"""Cryptographically validate plaintext keys in assembled legacy candidates."""

from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

from bfrs.core.secp256k1 import (
    GROUP_ORDER,
    decode_sec_public_key,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.legacy_wallet_candidate_assembler import LegacyWalletCandidate
from bfrs.recovery.logical_btree_membership import LogicalBerkeleySubdatabaseIdentity
from bfrs.recovery.logical_wallet_record_decoder import (
    DecodedLogicalWalletRecord,
    LogicalWalletRecordProvenance,
    LogicalWalletRecordState,
)
from bfrs.validators.bitcoin_plain_key import (
    decode_historical_ec_private_key,
    historical_plain_key_checksum,
)
from bfrs.validators.bitcoin_record_type import decode_compact_size


class PlaintextKeyCryptoState(Enum):
    CRYPTO_VALID = "CRYPTO_VALID"
    CHECKSUM_INVALID = "CHECKSUM_INVALID"
    PRIVATE_SCALAR_INVALID = "PRIVATE_SCALAR_INVALID"
    PUBLIC_KEY_MISMATCH = "PUBLIC_KEY_MISMATCH"
    SERIALIZATION_UNSUPPORTED = "SERIALIZATION_UNSUPPORTED"
    TRUNCATED = "TRUNCATED"
    REJECTED = "REJECTED"


class PrivateKeyRecoveryClassification(Enum):
    RECOVERED_PRIVATE_KEY = "RECOVERED_PRIVATE_KEY"
    DIAGNOSTIC_EVIDENCE = "DIAGNOSTIC_EVIDENCE"


@dataclass(frozen=True, slots=True)
class PlaintextKeyCryptoValidation:
    candidate_id: str
    identity: LogicalBerkeleySubdatabaseIdentity
    state: PlaintextKeyCryptoState
    recovery_classification: PrivateKeyRecoveryClassification
    provenance: LogicalWalletRecordProvenance
    original_public_key: bytes | None
    original_private_value_payload: bytes | None
    serialization_layout: str | None
    private_key_bytes: bytes | None
    checksum_present: bool
    checksum_valid: bool | None
    public_key_compressed: bool | None
    findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DuplicatePrivateKeyGroup:
    private_key_bytes: bytes
    occurrences: tuple[PlaintextKeyCryptoValidation, ...]


@dataclass(frozen=True, slots=True)
class LegacyPlaintextKeyCryptoSummary:
    candidate_id: str
    identity: LogicalBerkeleySubdatabaseIdentity
    validations: tuple[PlaintextKeyCryptoValidation, ...]
    total_crypto_valid_records: int
    unique_crypto_valid_private_keys: int
    duplicate_occurrences: int
    crypto_invalid_plain_records: int
    duplicate_groups: tuple[DuplicatePrivateKeyGroup, ...]

    @property
    def crypto_valid_plain_keys(self) -> int:
        return self.total_crypto_valid_records

    @property
    def unique_crypto_valid_plain_keys(self) -> int:
        return self.unique_crypto_valid_private_keys


class LegacyPlaintextKeyCryptographicValidatorV1:
    """Validate strict K1/K2 DER values already decoded as logical key records."""

    def validate_candidate(
        self, candidate: LegacyWalletCandidate
    ) -> LegacyPlaintextKeyCryptoSummary:
        if not isinstance(candidate, LegacyWalletCandidate):
            raise TypeError("candidate must be LegacyWalletCandidate")
        validations = tuple(
            self.validate_record(candidate.candidate_id, candidate.identity, record)
            for record in candidate.records
            if record.record_type == "key"
        )
        valid = tuple(
            item for item in validations
            if item.state is PlaintextKeyCryptoState.CRYPTO_VALID
        )
        by_key: dict[bytes, list[PlaintextKeyCryptoValidation]] = defaultdict(list)
        for item in valid:
            if item.private_key_bytes is None:
                raise RuntimeError("crypto-valid result omitted private key bytes")
            by_key[item.private_key_bytes].append(item)
        duplicates = tuple(
            DuplicatePrivateKeyGroup(key, tuple(occurrences))
            for key, occurrences in sorted(by_key.items(), key=lambda item: item[0])
            if len(occurrences) > 1
        )
        return LegacyPlaintextKeyCryptoSummary(
            candidate_id=candidate.candidate_id,
            identity=candidate.identity,
            validations=validations,
            total_crypto_valid_records=len(valid),
            unique_crypto_valid_private_keys=len(by_key),
            duplicate_occurrences=sum(len(group.occurrences) - 1 for group in duplicates),
            crypto_invalid_plain_records=len(validations) - len(valid),
            duplicate_groups=duplicates,
        )

    def validate_record(
        self,
        candidate_id: str,
        identity: LogicalBerkeleySubdatabaseIdentity,
        record: DecodedLogicalWalletRecord,
    ) -> PlaintextKeyCryptoValidation:
        if not candidate_id:
            raise ValueError("candidate_id must not be empty")
        if not isinstance(identity, LogicalBerkeleySubdatabaseIdentity):
            raise TypeError("identity must be LogicalBerkeleySubdatabaseIdentity")
        if not isinstance(record, DecodedLogicalWalletRecord):
            raise TypeError("record must be DecodedLogicalWalletRecord")
        if record.provenance.logical_page_identity[0] != identity:
            raise ValueError("record identity does not match candidate identity")
        if (
            record.state is not LogicalWalletRecordState.VALID
            or record.record_type != "key"
        ):
            return self._result(
                candidate_id, identity, record, PlaintextKeyCryptoState.REJECTED,
                finding="record_not_valid_plaintext_key",
            )
        public_key = record.public_key
        value = record.private_key_payload
        if public_key is None or value is None:
            return self._result(
                candidate_id, identity, record, PlaintextKeyCryptoState.REJECTED,
                finding="decoded_key_material_missing",
            )
        if decode_sec_public_key(public_key) is None:
            return self._result(
                candidate_id, identity, record, PlaintextKeyCryptoState.REJECTED,
                finding="record_public_key_invalid",
            )

        length = decode_compact_size(value)
        if length is None:
            return self._result(
                candidate_id, identity, record, PlaintextKeyCryptoState.TRUNCATED,
                finding="private_value_length_truncated",
            )
        if not length.canonical:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.SERIALIZATION_UNSUPPORTED,
                finding="private_value_length_noncanonical",
            )
        der_start = length.encoded_length
        der_end = der_start + length.value
        if der_end > len(value):
            return self._result(
                candidate_id, identity, record, PlaintextKeyCryptoState.TRUNCATED,
                finding="private_value_payload_truncated",
            )
        der = value[der_start:der_end]
        remainder = value[der_end:]
        if not remainder:
            layout = "K1_DER"
            checksum: bytes | None = None
        elif len(remainder) == 32:
            layout = "K2_DER_CHECKSUM"
            checksum = remainder
        else:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.SERIALIZATION_UNSUPPORTED,
                finding="private_value_layout_unsupported",
            )

        parsed = decode_historical_ec_private_key(der)
        if parsed is None:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.SERIALIZATION_UNSUPPORTED,
                layout=layout, checksum_present=checksum is not None,
                finding="legacy_ec_private_key_der_invalid",
            )
        private_bytes, embedded_public_key = parsed
        if checksum is not None and historical_plain_key_checksum(public_key, der) != checksum:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.CHECKSUM_INVALID,
                layout=layout, private_key_bytes=private_bytes,
                checksum_present=True, checksum_valid=False,
                finding="historical_checksum_invalid",
            )
        if len(private_bytes) != 32:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.PRIVATE_SCALAR_INVALID,
                layout=layout, private_key_bytes=private_bytes,
                checksum_present=checksum is not None,
                checksum_valid=True if checksum is not None else None,
                finding="private_scalar_width_invalid",
            )
        scalar = int.from_bytes(private_bytes, "big")
        if not 1 <= scalar < GROUP_ORDER:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.PRIVATE_SCALAR_INVALID,
                layout=layout, private_key_bytes=private_bytes,
                checksum_present=checksum is not None,
                checksum_valid=True if checksum is not None else None,
                finding="private_scalar_out_of_range",
            )

        compressed = len(public_key) == 33
        derived = encode_sec_public_key(scalar_multiply(scalar), compressed=compressed)
        if embedded_public_key != derived or derived != public_key:
            return self._result(
                candidate_id, identity, record,
                PlaintextKeyCryptoState.PUBLIC_KEY_MISMATCH,
                layout=layout, private_key_bytes=private_bytes,
                checksum_present=checksum is not None,
                checksum_valid=True if checksum is not None else None,
                compressed=compressed,
                finding="private_key_public_key_mismatch",
            )
        return self._result(
            candidate_id, identity, record, PlaintextKeyCryptoState.CRYPTO_VALID,
            layout=layout, private_key_bytes=private_bytes,
            checksum_present=checksum is not None,
            checksum_valid=True if checksum is not None else None,
            compressed=compressed, finding="private_key_public_key_match",
        )

    @staticmethod
    def _result(
        candidate_id: str,
        identity: LogicalBerkeleySubdatabaseIdentity,
        record: DecodedLogicalWalletRecord,
        state: PlaintextKeyCryptoState,
        *,
        layout: str | None = None,
        private_key_bytes: bytes | None = None,
        checksum_present: bool = False,
        checksum_valid: bool | None = None,
        compressed: bool | None = None,
        finding: str,
    ) -> PlaintextKeyCryptoValidation:
        classification = (
            PrivateKeyRecoveryClassification.RECOVERED_PRIVATE_KEY
            if state is PlaintextKeyCryptoState.CRYPTO_VALID
            else PrivateKeyRecoveryClassification.DIAGNOSTIC_EVIDENCE
        )
        return PlaintextKeyCryptoValidation(
            candidate_id, identity, state, classification, record.provenance,
            record.public_key, record.private_key_payload, layout,
            private_key_bytes, checksum_present, checksum_valid, compressed,
            (finding,),
        )
