"""Validate historical Bitcoin wallet Berkeley key suffix framing."""

from dataclasses import dataclass
from typing import Any

from bfrs.core.secp256k1 import FIELD_PRIME, decode_sec_public_key
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordType,
    decode_compact_size,
)


SECP256K1_FIELD_PRIME = FIELD_PRIME
_PUBLIC_KEY_RECORD_TYPES = frozenset({"key", "wkey", "ckey", "keymeta"})
_SUPPORTED_RECORD_TYPES = _PUBLIC_KEY_RECORD_TYPES | {"mkey", "defaultkey"}


@dataclass(frozen=True, slots=True)
class BitcoinRecordKeyValidation:
    record_type: str
    valid: bool
    canonical_framing: bool
    variant: str | None
    evidence: dict[str, Any]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _SecPublicKeyValidation:
    valid: bool
    compressed: bool
    reason: str | None


class BitcoinRecordKeyValidator:
    """Validate only the type-specific suffix of a decoded Berkeley key."""

    def validate(self, decoded: BitcoinRecordType) -> BitcoinRecordKeyValidation:
        if decoded.name not in _SUPPORTED_RECORD_TYPES:
            return self._result(
                decoded,
                valid=False,
                canonical_framing=decoded.canonical_framing,
                variant=None,
                evidence={},
                reason="record_type_unsupported",
            )
        if decoded.name in _PUBLIC_KEY_RECORD_TYPES:
            return self._validate_public_key_suffix(decoded)
        if decoded.name == "mkey":
            return self._validate_mkey_suffix(decoded)
        return self._validate_defaultkey_suffix(decoded)

    def _validate_public_key_suffix(
        self,
        decoded: BitcoinRecordType,
    ) -> BitcoinRecordKeyValidation:
        suffix = decoded.remaining_key
        vector_length = decode_compact_size(suffix)
        if vector_length is None:
            return self._result(
                decoded,
                valid=False,
                canonical_framing=False,
                variant=decoded.name,
                evidence={"pubkey_framing_canonical": False},
                reason="key_suffix_truncated",
            )

        canonical = decoded.canonical_framing and vector_length.canonical
        evidence: dict[str, Any] = {
            "pubkey_length": vector_length.value,
            "pubkey_framing_canonical": vector_length.canonical,
        }
        if vector_length.value not in (33, 65):
            return self._result(
                decoded,
                valid=False,
                canonical_framing=canonical,
                variant=decoded.name,
                evidence=evidence,
                reason="pubkey_length_invalid",
            )

        pubkey_start = vector_length.encoded_length
        pubkey_end = pubkey_start + vector_length.value
        if pubkey_end > len(suffix):
            return self._result(
                decoded,
                valid=False,
                canonical_framing=canonical,
                variant=decoded.name,
                evidence=evidence,
                reason="key_suffix_truncated",
            )
        if pubkey_end < len(suffix):
            return self._result(
                decoded,
                valid=False,
                canonical_framing=canonical,
                variant=decoded.name,
                evidence=evidence,
                reason="trailing_key_data",
            )

        public_key = suffix[pubkey_start:pubkey_end]
        sec_result = _validate_sec_public_key(public_key)
        evidence["compressed"] = sec_result.compressed
        if not sec_result.valid:
            if sec_result.reason is None:
                raise RuntimeError("invalid SEC validation result")
            return self._result(
                decoded,
                valid=False,
                canonical_framing=canonical,
                variant=decoded.name,
                evidence=evidence,
                reason=sec_result.reason,
            )

        return self._result(
            decoded,
            valid=True,
            canonical_framing=canonical,
            variant=decoded.name,
            evidence=evidence,
        )

    def _validate_mkey_suffix(
        self,
        decoded: BitcoinRecordType,
    ) -> BitcoinRecordKeyValidation:
        suffix = decoded.remaining_key
        if len(suffix) < 4:
            return self._result(
                decoded,
                valid=False,
                canonical_framing=decoded.canonical_framing,
                variant="mkey",
                evidence={},
                reason="mkey_id_invalid",
            )
        if len(suffix) > 4:
            return self._result(
                decoded,
                valid=False,
                canonical_framing=decoded.canonical_framing,
                variant="mkey",
                evidence={},
                reason="trailing_key_data",
            )

        return self._result(
            decoded,
            valid=True,
            canonical_framing=decoded.canonical_framing,
            variant="mkey",
            evidence={"mkey_id": int.from_bytes(suffix, "little")},
        )

    def _validate_defaultkey_suffix(
        self,
        decoded: BitcoinRecordType,
    ) -> BitcoinRecordKeyValidation:
        if decoded.remaining_key:
            return self._result(
                decoded,
                valid=False,
                canonical_framing=decoded.canonical_framing,
                variant="defaultkey",
                evidence={},
                reason="trailing_key_data",
            )
        return self._result(
            decoded,
            valid=True,
            canonical_framing=decoded.canonical_framing,
            variant="defaultkey",
            evidence={},
        )

    @staticmethod
    def _result(
        decoded: BitcoinRecordType,
        *,
        valid: bool,
        canonical_framing: bool,
        variant: str | None,
        evidence: dict[str, Any],
        reason: str | None = None,
    ) -> BitcoinRecordKeyValidation:
        full_evidence = {
            "record_type": decoded.name,
            "variant": variant,
            "record_type_framing_canonical": decoded.canonical_framing,
            **evidence,
        }
        return BitcoinRecordKeyValidation(
            record_type=decoded.name,
            valid=valid,
            canonical_framing=canonical_framing,
            variant=variant,
            evidence=full_evidence,
            reasons=() if reason is None else (reason,),
        )


def _validate_sec_public_key(public_key: bytes) -> _SecPublicKeyValidation:
    compressed = len(public_key) == 33
    prefix = public_key[0]
    if compressed and prefix not in (2, 3):
        return _SecPublicKeyValidation(False, True, "pubkey_prefix_invalid")
    if not compressed and prefix != 4:
        return _SecPublicKeyValidation(False, False, "pubkey_prefix_invalid")
    if decode_sec_public_key(public_key) is None:
        return _SecPublicKeyValidation(False, compressed, "pubkey_point_invalid")
    return _SecPublicKeyValidation(True, compressed, None)
