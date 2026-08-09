"""Validate historical Bitcoin ``mkey`` Berkeley records."""

from dataclasses import dataclass
from typing import Any

from bfrs.recovery.berkeley_records import BerkeleyLeafPair
from bfrs.validators.bitcoin_record_key import BitcoinRecordKeyValidator
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordTypeDecoder,
    decode_compact_size,
)


_ENCRYPTED_MASTER_KEY_LENGTH = 48
_SALT_LENGTH = 8
_WRITER_DERIVATION_METHOD = 0
_MINIMUM_WRITER_ITERATIONS = 25_000


@dataclass(frozen=True, slots=True)
class MasterKeyValidation:
    valid: bool
    canonical_framing: bool
    master_key_id: int | None
    encrypted_master_key_length: int | None
    salt_length: int | None
    derivation_method: int | None
    derivation_iterations: int | None
    other_parameters_length: int | None
    evidence: dict[str, Any]
    reasons: tuple[str, ...]


class HistoricalMasterKeyValidator:
    """Confirm standard 2011--2014 ``CMasterKey`` writer output."""

    def __init__(self) -> None:
        self._type_decoder = BitcoinRecordTypeDecoder()
        self._record_key_validator = BitcoinRecordKeyValidator()

    def validate(self, pair: BerkeleyLeafPair) -> MasterKeyValidation:
        evidence: dict[str, Any] = {
            "key_deleted": pair.key.deleted,
            "value_deleted": pair.value.deleted,
        }
        decoded = self._type_decoder.decode(pair.key.payload)
        if decoded is None:
            return self._invalid("record_key_invalid", evidence=evidence)

        evidence["record_type"] = decoded.name
        if decoded.name != "mkey":
            return self._invalid(
                "wrong_record_type",
                canonical_framing=decoded.canonical_framing,
                evidence=evidence,
            )

        key_validation = self._record_key_validator.validate(decoded)
        if not key_validation.valid:
            return self._invalid(
                "record_key_invalid",
                canonical_framing=key_validation.canonical_framing,
                evidence=evidence,
            )

        master_key_id = key_validation.evidence.get("mkey_id")
        if not isinstance(master_key_id, int) or isinstance(master_key_id, bool):
            raise RuntimeError("record key validator omitted the master key ID")
        evidence.update(
            {
                "master_key_id": master_key_id,
                "record_key_canonical": key_validation.canonical_framing,
            }
        )

        value = pair.value.payload
        if not value:
            return self._invalid(
                "value_empty",
                canonical_framing=False,
                evidence=evidence,
            )

        canonical = key_validation.canonical_framing
        offset = 0

        encrypted_header = decode_compact_size(value, offset)
        if encrypted_header is None:
            return self._invalid(
                "encrypted_master_key_framing_invalid",
                canonical_framing=False,
                evidence=evidence,
            )
        canonical = canonical and encrypted_header.canonical
        encrypted_start = offset + encrypted_header.encoded_length
        encrypted_end = encrypted_start + encrypted_header.value
        evidence.update(
            {
                "encrypted_master_key_length": encrypted_header.value,
                "encrypted_master_key_framing_canonical": (
                    encrypted_header.canonical
                ),
                "encrypted_master_key_aes_block_aligned": (
                    encrypted_header.value > 0
                    and encrypted_header.value % 16 == 0
                ),
            }
        )
        if encrypted_end > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=evidence,
            )
        if encrypted_header.value != _ENCRYPTED_MASTER_KEY_LENGTH:
            return self._invalid(
                "encrypted_master_key_length_invalid",
                canonical_framing=canonical,
                evidence=evidence,
            )
        offset = encrypted_end

        salt_header = decode_compact_size(value, offset)
        if salt_header is None:
            return self._invalid(
                "salt_framing_invalid",
                canonical_framing=False,
                evidence=evidence,
            )
        canonical = canonical and salt_header.canonical
        salt_start = offset + salt_header.encoded_length
        salt_end = salt_start + salt_header.value
        evidence.update(
            {
                "salt_length": salt_header.value,
                "salt_framing_canonical": salt_header.canonical,
            }
        )
        if salt_end > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=evidence,
            )
        if salt_header.value != _SALT_LENGTH:
            return self._invalid(
                "salt_length_invalid",
                canonical_framing=canonical,
                evidence=evidence,
            )
        offset = salt_end

        if offset + 4 > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=evidence,
            )
        derivation_method = int.from_bytes(value[offset : offset + 4], "little")
        offset += 4
        evidence.update(
            {
                "derivation_method": derivation_method,
                "derivation_method_writer_compatible": (
                    derivation_method == _WRITER_DERIVATION_METHOD
                ),
            }
        )
        if derivation_method != _WRITER_DERIVATION_METHOD:
            return self._invalid(
                "derivation_method_invalid",
                canonical_framing=canonical,
                evidence=evidence,
            )

        if offset + 4 > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=evidence,
            )
        derivation_iterations = int.from_bytes(
            value[offset : offset + 4], "little"
        )
        offset += 4
        evidence.update(
            {
                "derivation_iterations": derivation_iterations,
                "derivation_iterations_writer_compatible": (
                    derivation_iterations >= _MINIMUM_WRITER_ITERATIONS
                ),
            }
        )
        if derivation_iterations < _MINIMUM_WRITER_ITERATIONS:
            return self._invalid(
                "derivation_iterations_invalid",
                canonical_framing=canonical,
                evidence=evidence,
            )

        other_header = decode_compact_size(value, offset)
        if other_header is None:
            return self._invalid(
                "other_parameters_framing_invalid",
                canonical_framing=False,
                evidence=evidence,
            )
        canonical = canonical and other_header.canonical
        other_start = offset + other_header.encoded_length
        other_end = other_start + other_header.value
        evidence.update(
            {
                "other_parameters_length": other_header.value,
                "other_parameters_framing_canonical": other_header.canonical,
            }
        )
        if other_end > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=evidence,
            )
        if other_end < len(value):
            return self._invalid(
                "trailing_value_data",
                canonical_framing=canonical,
                evidence=evidence,
            )
        if other_header.value != 0:
            return self._invalid(
                "other_parameters_invalid",
                canonical_framing=canonical,
                evidence=evidence,
            )

        evidence["canonical_framing"] = canonical
        return self._result(
            valid=True,
            canonical_framing=canonical,
            evidence=evidence,
        )

    @classmethod
    def _invalid(
        cls,
        reason: str,
        *,
        canonical_framing: bool = False,
        evidence: dict[str, Any],
    ) -> MasterKeyValidation:
        full_evidence = {**evidence, "canonical_framing": canonical_framing}
        return cls._result(
            valid=False,
            canonical_framing=canonical_framing,
            evidence=full_evidence,
            reason=reason,
        )

    @staticmethod
    def _result(
        *,
        valid: bool,
        canonical_framing: bool,
        evidence: dict[str, Any],
        reason: str | None = None,
    ) -> MasterKeyValidation:
        return MasterKeyValidation(
            valid=valid,
            canonical_framing=canonical_framing,
            master_key_id=_evidence_int(evidence, "master_key_id"),
            encrypted_master_key_length=_evidence_int(
                evidence, "encrypted_master_key_length"
            ),
            salt_length=_evidence_int(evidence, "salt_length"),
            derivation_method=_evidence_int(evidence, "derivation_method"),
            derivation_iterations=_evidence_int(
                evidence, "derivation_iterations"
            ),
            other_parameters_length=_evidence_int(
                evidence, "other_parameters_length"
            ),
            evidence=evidence,
            reasons=() if reason is None else (reason,),
        )


def _evidence_int(evidence: dict[str, Any], name: str) -> int | None:
    value = evidence.get(name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None
