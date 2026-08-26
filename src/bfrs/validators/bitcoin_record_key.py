"""Validate historical Bitcoin wallet Berkeley key suffix framing."""

from dataclasses import dataclass
import hashlib
from typing import Any

from bfrs.core.secp256k1 import FIELD_PRIME, decode_sec_public_key
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordType,
    BitcoinRecordTypeDecoder,
    decode_compact_size,
)


SECP256K1_FIELD_PRIME = FIELD_PRIME
_PUBLIC_KEY_RECORD_TYPES = frozenset({"key", "wkey", "ckey", "keymeta"})
_SUPPORTED_RECORD_TYPES = _PUBLIC_KEY_RECORD_TYPES | {"mkey", "defaultkey"}
RAW_KEY_SIDE_RECORD_TYPES = frozenset({"key", "wkey", "ckey"})
MAX_RAW_KEY_SIDE_BYTES = 5 + 9 + 65

BITCOIN_RECORD_KEY_SIDE_VALID = "BITCOIN_RECORD_KEY_SIDE_VALID"
BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID = (
    "BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID"
)
BITCOIN_RECORD_PUBKEY_LENGTH_INVALID = "BITCOIN_RECORD_PUBKEY_LENGTH_INVALID"
BITCOIN_RECORD_PUBKEY_PREFIX_INVALID = "BITCOIN_RECORD_PUBKEY_PREFIX_INVALID"
BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE = "BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE"


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


@dataclass(frozen=True, slots=True)
class RawBitcoinRecordKeySideValidation:
    """Safe admission result for a raw framed ``key``/``ckey``/``wkey`` hit."""

    record_type: str
    valid: bool
    reason_codes: tuple[str, ...]
    evidence: dict[str, Any]


class RawBitcoinRecordKeySideValidator:
    """Qualify raw record-name hits without changing legacy record semantics.

    Raw scanning deliberately matches only the framed name.  This adapter
    requires canonical writer framing for the following CPubKey and delegates
    the SEC point validation to :class:`BitcoinRecordKeyValidator`.
    """

    def __init__(self) -> None:
        self._decoder = BitcoinRecordTypeDecoder(RAW_KEY_SIDE_RECORD_TYPES)
        self._record_key_validator = BitcoinRecordKeyValidator()

    def validate_detected(
        self,
        data: bytes,
    ) -> RawBitcoinRecordKeySideValidation | None:
        """Detect a supported framed type from bytes and validate its key side."""
        decoded = self._decoder.decode(data)
        if decoded is None:
            return None
        return self.validate(data, expected_record_type=decoded.name)

    def validate(
        self,
        data: bytes,
        *,
        expected_record_type: str,
    ) -> RawBitcoinRecordKeySideValidation:
        if expected_record_type not in RAW_KEY_SIDE_RECORD_TYPES:
            raise ValueError("raw key-side validation supports key, ckey, and wkey")

        decoded = self._decoder.decode(data)
        if decoded is None or decoded.name != expected_record_type:
            return self._invalid(
                expected_record_type,
                BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID,
                {},
            )

        length = decode_compact_size(decoded.remaining_key)
        if length is None or not length.canonical:
            return self._invalid(
                expected_record_type,
                BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID,
                {
                    "pubkey_framing_canonical": (
                        None if length is None else length.canonical
                    ),
                },
            )

        evidence: dict[str, Any] = {
            "pubkey_length": length.value,
            "pubkey_framing_canonical": True,
        }
        if length.value not in (33, 65):
            return self._invalid(
                expected_record_type,
                BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
                evidence,
            )

        key_side_length = length.encoded_length + length.value
        if len(decoded.remaining_key) < key_side_length:
            evidence.update(
                {
                    "available_record_key_bytes": len(data),
                    "required_record_key_bytes": (
                        decoded.prefix_length + key_side_length
                    ),
                }
            )
            return self._invalid(
                expected_record_type,
                BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
                evidence,
            )

        exact_end = decoded.prefix_length + key_side_length
        exact = self._decoder.decode(data[:exact_end])
        if exact is None or exact.name != expected_record_type:
            return self._invalid(
                expected_record_type,
                BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID,
                evidence,
            )
        validation = self._record_key_validator.validate(exact)
        if not validation.valid:
            reason = validation.reasons[0] if validation.reasons else None
            mapped = {
                "key_suffix_truncated": BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
                "pubkey_length_invalid": BITCOIN_RECORD_PUBKEY_LENGTH_INVALID,
                "pubkey_prefix_invalid": BITCOIN_RECORD_PUBKEY_PREFIX_INVALID,
                "pubkey_point_invalid": BITCOIN_RECORD_PUBKEY_NOT_ON_CURVE,
            }.get(reason)
            if mapped is None:
                raise RuntimeError("unexpected Bitcoin record key rejection reason")
            return self._invalid(expected_record_type, mapped, evidence)

        evidence["compressed"] = validation.evidence["compressed"]
        public_key_start = length.encoded_length
        public_key_end = public_key_start + length.value
        evidence["public_key_offset"] = decoded.prefix_length + public_key_start
        public_key = exact.remaining_key[public_key_start:public_key_end]
        evidence["safe_pubkey_fingerprint"] = hashlib.sha256(
            public_key
        ).hexdigest()
        return RawBitcoinRecordKeySideValidation(
            record_type=expected_record_type,
            valid=True,
            reason_codes=(BITCOIN_RECORD_KEY_SIDE_VALID,),
            evidence=evidence,
        )

    @staticmethod
    def _invalid(
        record_type: str,
        reason: str,
        evidence: dict[str, Any],
    ) -> RawBitcoinRecordKeySideValidation:
        return RawBitcoinRecordKeySideValidation(
            record_type=record_type,
            valid=False,
            reason_codes=(reason,),
            evidence=evidence,
        )


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
