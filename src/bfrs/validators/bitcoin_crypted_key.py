"""Validate historical encrypted Bitcoin ``ckey`` Berkeley records."""

from dataclasses import dataclass
from typing import Any

from bfrs.recovery.berkeley_records import BerkeleyLeafPair
from bfrs.validators.bitcoin_record_key import BitcoinRecordKeyValidator
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordTypeDecoder,
    decode_compact_size,
)


_AES_BLOCK_SIZE = 16
_CRYPTED_SECRET_LENGTH = 48


@dataclass(frozen=True, slots=True)
class CryptedKeyValidation:
    valid: bool
    canonical_framing: bool
    encrypted_length: int | None
    evidence: dict[str, Any]
    reasons: tuple[str, ...]


class HistoricalCryptedKeyValidator:
    """Confirm historical ``ckey`` framing without decrypting its value."""

    def __init__(self) -> None:
        self._type_decoder = BitcoinRecordTypeDecoder()
        self._record_key_validator = BitcoinRecordKeyValidator()

    def validate(self, pair: BerkeleyLeafPair) -> CryptedKeyValidation:
        evidence: dict[str, Any] = {
            "key_deleted": pair.key.deleted,
            "value_deleted": pair.value.deleted,
        }
        decoded = self._type_decoder.decode(pair.key.payload)
        if decoded is None:
            return self._invalid("record_key_invalid", evidence=evidence)

        evidence["record_type"] = decoded.name
        if decoded.name != "ckey":
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

        pubkey_length = key_validation.evidence.get("pubkey_length")
        pubkey_compressed = key_validation.evidence.get("compressed")
        if not isinstance(pubkey_length, int) or not isinstance(
            pubkey_compressed, bool
        ):
            raise RuntimeError("record key validator omitted SEC key metadata")
        evidence.update(
            {
                "pubkey_length": pubkey_length,
                "pubkey_compressed": pubkey_compressed,
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

        vector_length = decode_compact_size(value)
        if vector_length is None:
            return self._invalid(
                "value_framing_invalid",
                canonical_framing=False,
                evidence=evidence,
            )

        encrypted_length = vector_length.value
        canonical = key_validation.canonical_framing and vector_length.canonical
        encrypted_start = vector_length.encoded_length
        encrypted_end = encrypted_start + encrypted_length
        block_aligned = (
            encrypted_length > 0 and encrypted_length % _AES_BLOCK_SIZE == 0
        )
        evidence.update(
            {
                "value_framing_canonical": vector_length.canonical,
                "encrypted_length": encrypted_length,
                "aes_block_aligned": block_aligned,
            }
        )

        if encrypted_end > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                encrypted_length=encrypted_length,
                evidence=evidence,
            )
        if encrypted_end < len(value):
            return self._invalid(
                "trailing_value_data",
                canonical_framing=canonical,
                encrypted_length=encrypted_length,
                evidence=evidence,
            )
        if encrypted_length == 0:
            return self._invalid(
                "encrypted_length_invalid",
                canonical_framing=canonical,
                encrypted_length=encrypted_length,
                evidence=evidence,
            )
        if not block_aligned:
            return self._invalid(
                "encrypted_block_geometry_invalid",
                canonical_framing=canonical,
                encrypted_length=encrypted_length,
                evidence=evidence,
            )
        if encrypted_length != _CRYPTED_SECRET_LENGTH:
            return self._invalid(
                "encrypted_length_invalid",
                canonical_framing=canonical,
                encrypted_length=encrypted_length,
                evidence=evidence,
            )

        evidence["canonical_framing"] = canonical
        return CryptedKeyValidation(
            valid=True,
            canonical_framing=canonical,
            encrypted_length=encrypted_length,
            evidence=evidence,
            reasons=(),
        )

    @staticmethod
    def _invalid(
        reason: str,
        *,
        canonical_framing: bool = False,
        encrypted_length: int | None = None,
        evidence: dict[str, Any],
    ) -> CryptedKeyValidation:
        full_evidence = {**evidence, "canonical_framing": canonical_framing}
        return CryptedKeyValidation(
            valid=False,
            canonical_framing=canonical_framing,
            encrypted_length=encrypted_length,
            evidence=full_evidence,
            reasons=(reason,),
        )
