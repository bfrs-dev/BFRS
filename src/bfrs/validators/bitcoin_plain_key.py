"""Validate historical plaintext Bitcoin ``key`` Berkeley records."""

from dataclasses import dataclass
import hashlib
from typing import Any

from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    decode_sec_public_key,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.berkeley_records import BerkeleyLeafPair
from bfrs.validators.bitcoin_record_key import BitcoinRecordKeyValidator
from bfrs.validators.bitcoin_record_type import (
    BitcoinRecordTypeDecoder,
    decode_compact_size,
)


_PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")  # 1.2.840.10045.1.1


@dataclass(frozen=True, slots=True)
class PlainKeyValidation:
    valid: bool
    variant: str | None
    canonical_framing: bool
    public_key_match: bool
    private_scalar_valid: bool
    der_valid: bool
    evidence: dict[str, Any]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ParsedECPrivateKey:
    version: int
    private_bytes: bytes
    embedded_public_key: bytes


class _DerError(ValueError):
    def __init__(self, reason: str = "der_invalid") -> None:
        super().__init__(reason)
        self.reason = reason


class _DerReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    @property
    def at_end(self) -> bool:
        return self.offset == len(self.data)

    def read(self, expected_tag: int) -> bytes:
        if self.offset >= len(self.data) or self.data[self.offset] != expected_tag:
            raise _DerError()
        self.offset += 1
        length = self._read_length()
        end = self.offset + length
        if end > len(self.data):
            raise _DerError()
        content = self.data[self.offset:end]
        self.offset = end
        return content

    def require_end(self) -> None:
        if not self.at_end:
            raise _DerError()

    def _read_length(self) -> int:
        if self.offset >= len(self.data):
            raise _DerError()
        first = self.data[self.offset]
        self.offset += 1
        if first < 0x80:
            return first
        count = first & 0x7F
        if count == 0 or self.offset + count > len(self.data):
            raise _DerError()
        encoded = self.data[self.offset : self.offset + count]
        self.offset += count
        if encoded[0] == 0:
            raise _DerError()
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            raise _DerError()
        return length


class HistoricalPlainKeyValidator:
    """Confirm a plaintext key record without exporting its secret material."""

    def __init__(self) -> None:
        self._type_decoder = BitcoinRecordTypeDecoder()
        self._record_key_validator = BitcoinRecordKeyValidator()

    def validate(self, pair: BerkeleyLeafPair) -> PlainKeyValidation:
        base_evidence: dict[str, Any] = {
            "key_deleted": pair.key.deleted,
            "value_deleted": pair.value.deleted,
        }
        decoded = self._type_decoder.decode(pair.key.payload)
        if decoded is None:
            return self._invalid(
                "record_key_invalid",
                evidence=base_evidence,
            )
        base_evidence["record_type"] = decoded.name
        if decoded.name != "key":
            return self._invalid(
                "wrong_record_type",
                canonical_framing=decoded.canonical_framing,
                evidence=base_evidence,
            )

        key_validation = self._record_key_validator.validate(decoded)
        if not key_validation.valid:
            return self._invalid(
                "record_key_invalid",
                canonical_framing=key_validation.canonical_framing,
                evidence=base_evidence,
            )

        public_key = _extract_validated_public_key(decoded.remaining_key)
        public_key_compressed = len(public_key) == 33
        base_evidence.update(
            {
                "pubkey_compressed": public_key_compressed,
                "record_key_canonical": key_validation.canonical_framing,
            }
        )

        value = pair.value.payload
        vector_length = decode_compact_size(value)
        if vector_length is None:
            return self._invalid(
                "value_framing_invalid",
                canonical_framing=False,
                evidence=base_evidence,
            )
        der_start = vector_length.encoded_length
        der_end = der_start + vector_length.value
        canonical = key_validation.canonical_framing and vector_length.canonical
        base_evidence.update(
            {
                "value_framing_canonical": vector_length.canonical,
                "der_length": vector_length.value,
            }
        )
        if der_end > len(value):
            return self._invalid(
                "value_truncated",
                canonical_framing=canonical,
                evidence=base_evidence,
            )

        der = value[der_start:der_end]
        remainder = value[der_end:]
        if not remainder:
            variant = "K1"
            checksum: bytes | None = None
        elif len(remainder) == 32:
            variant = "K2"
            checksum = remainder
        else:
            return self._invalid(
                "trailing_value_data",
                canonical_framing=canonical,
                evidence=base_evidence,
            )

        base_evidence.update(
            {
                "variant": variant,
                "checksum_present": checksum is not None,
            }
        )
        try:
            parsed = _parse_ec_private_key(der)
        except _DerError as exc:
            return self._invalid(
                exc.reason,
                variant=variant,
                canonical_framing=canonical,
                evidence=base_evidence,
            )

        base_evidence.update(
            {
                "der_version": parsed.version,
                "curve": "secp256k1",
                "embedded_public_key_present": True,
            }
        )
        if len(parsed.private_bytes) != 32:
            return self._invalid(
                "private_scalar_invalid",
                variant=variant,
                canonical_framing=canonical,
                der_valid=True,
                evidence=base_evidence,
            )
        scalar = int.from_bytes(parsed.private_bytes, "big")
        if not 1 <= scalar < GROUP_ORDER:
            return self._invalid(
                "private_scalar_invalid",
                variant=variant,
                canonical_framing=canonical,
                der_valid=True,
                evidence=base_evidence,
            )
        base_evidence["private_scalar_valid"] = True

        embedded_point = decode_sec_public_key(parsed.embedded_public_key)
        if embedded_point is None:
            return self._invalid(
                "embedded_public_key_invalid",
                variant=variant,
                canonical_framing=canonical,
                private_scalar_valid=True,
                der_valid=True,
                evidence=base_evidence,
            )

        derived_point = scalar_multiply(scalar)
        if embedded_point != derived_point:
            base_evidence["embedded_public_key_match"] = False
            return self._invalid(
                "embedded_public_key_mismatch",
                variant=variant,
                canonical_framing=canonical,
                private_scalar_valid=True,
                der_valid=True,
                evidence=base_evidence,
            )
        base_evidence["embedded_public_key_match"] = True

        expected_public_key = encode_sec_public_key(
            derived_point,
            compressed=public_key_compressed,
        )
        if expected_public_key != public_key:
            base_evidence["derived_public_key_match"] = False
            return self._invalid(
                "public_key_mismatch",
                variant=variant,
                canonical_framing=canonical,
                private_scalar_valid=True,
                der_valid=True,
                evidence=base_evidence,
            )
        base_evidence["derived_public_key_match"] = True

        checksum_valid: bool | None = None
        if checksum is not None:
            checksum_valid = _hash256(public_key + der) == checksum
            base_evidence["checksum_valid"] = checksum_valid
            if not checksum_valid:
                return self._invalid(
                    "checksum_invalid",
                    variant=variant,
                    canonical_framing=canonical,
                    public_key_match=True,
                    private_scalar_valid=True,
                    der_valid=True,
                    evidence=base_evidence,
                )
        else:
            base_evidence["checksum_valid"] = None

        return PlainKeyValidation(
            valid=True,
            variant=variant,
            canonical_framing=canonical,
            public_key_match=True,
            private_scalar_valid=True,
            der_valid=True,
            evidence=base_evidence,
            reasons=(),
        )

    @staticmethod
    def _invalid(
        reason: str,
        *,
        variant: str | None = None,
        canonical_framing: bool = False,
        public_key_match: bool = False,
        private_scalar_valid: bool = False,
        der_valid: bool = False,
        evidence: dict[str, Any],
    ) -> PlainKeyValidation:
        return PlainKeyValidation(
            valid=False,
            variant=variant,
            canonical_framing=canonical_framing,
            public_key_match=public_key_match,
            private_scalar_valid=private_scalar_valid,
            der_valid=der_valid,
            evidence=evidence,
            reasons=(reason,),
        )


def _extract_validated_public_key(suffix: bytes) -> bytes:
    length = decode_compact_size(suffix)
    if length is None:
        raise RuntimeError("validated record key lost its public key framing")
    start = length.encoded_length
    return suffix[start : start + length.value]


def _parse_ec_private_key(der: bytes) -> _ParsedECPrivateKey:
    outer = _DerReader(der)
    sequence = outer.read(0x30)
    outer.require_end()
    body = _DerReader(sequence)

    version = _read_positive_integer(body)
    if version != 1:
        raise _DerError("der_version_invalid")
    private_bytes = body.read(0x04)
    parameters = body.read(0xA0)
    _parse_explicit_secp256k1_parameters(parameters)
    public_container = body.read(0xA1)
    body.require_end()

    public_reader = _DerReader(public_container)
    bit_string = public_reader.read(0x03)
    public_reader.require_end()
    if len(bit_string) < 2 or bit_string[0] != 0:
        raise _DerError("embedded_public_key_invalid")
    return _ParsedECPrivateKey(
        version=version,
        private_bytes=private_bytes,
        embedded_public_key=bit_string[1:],
    )


def _parse_explicit_secp256k1_parameters(encoded: bytes) -> None:
    try:
        wrapper = _DerReader(encoded)
        sequence = wrapper.read(0x30)
        wrapper.require_end()
        parameters = _DerReader(sequence)
        if _read_positive_integer(parameters) != 1:
            raise _DerError("curve_invalid")

        field_sequence = parameters.read(0x30)
        field = _DerReader(field_sequence)
        if field.read(0x06) != _PRIME_FIELD_OID:
            raise _DerError("curve_invalid")
        if _read_positive_integer(field) != FIELD_PRIME:
            raise _DerError("curve_invalid")
        field.require_end()

        curve_sequence = parameters.read(0x30)
        curve = _DerReader(curve_sequence)
        if curve.read(0x04) != b"\x00" or curve.read(0x04) != b"\x07":
            raise _DerError("curve_invalid")
        curve.require_end()

        base = parameters.read(0x04)
        if decode_sec_public_key(base) != GENERATOR:
            raise _DerError("curve_invalid")
        if _read_positive_integer(parameters) != GROUP_ORDER:
            raise _DerError("curve_invalid")
        if _read_positive_integer(parameters) != 1:
            raise _DerError("curve_invalid")
        parameters.require_end()
    except _DerError as exc:
        if exc.reason == "curve_invalid":
            raise
        raise _DerError("curve_invalid") from exc


def _read_positive_integer(reader: _DerReader) -> int:
    encoded = reader.read(0x02)
    if not encoded or encoded[0] & 0x80:
        raise _DerError()
    if len(encoded) > 1 and encoded[0] == 0 and encoded[1] < 0x80:
        raise _DerError()
    return int.from_bytes(encoded, "big")


def _hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
