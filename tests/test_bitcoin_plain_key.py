from dataclasses import FrozenInstanceError
import hashlib

import pytest

from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord
from bfrs.validators.bitcoin_plain_key import HistoricalPlainKeyValidator


PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(content)) + content


def der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("test integers must be non-negative")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return tlv(0x02, encoded)


def explicit_parameters(
    *,
    compressed: bool,
    field_oid: bytes = PRIME_FIELD_OID,
) -> bytes:
    field = tlv(0x30, tlv(0x06, field_oid) + der_integer(FIELD_PRIME))
    curve = tlv(0x30, tlv(0x04, b"\x00") + tlv(0x04, b"\x07"))
    base = tlv(0x04, encode_sec_public_key(GENERATOR, compressed=compressed))
    content = (
        der_integer(1)
        + field
        + curve
        + base
        + der_integer(GROUP_ORDER)
        + der_integer(1)
    )
    return tlv(0x30, content)


def ec_private_key_der(
    scalar: int,
    *,
    compressed: bool,
    version: int = 1,
    private_bytes: bytes | None = None,
    embedded_public_key: bytes | None = None,
    field_oid: bytes = PRIME_FIELD_OID,
) -> bytes:
    if private_bytes is None:
        private_bytes = scalar.to_bytes(32, "big")
    if embedded_public_key is None:
        embedded_public_key = encode_sec_public_key(
            scalar_multiply(scalar),
            compressed=compressed,
        )
    content = (
        der_integer(version)
        + tlv(0x04, private_bytes)
        + tlv(
            0xA0,
            explicit_parameters(compressed=compressed, field_oid=field_oid),
        )
        + tlv(0xA1, tlv(0x03, b"\x00" + embedded_public_key))
    )
    return tlv(0x30, content)


def compact_size(value: int, *, canonical: bool = True) -> bytes:
    if canonical:
        if value < 253:
            return bytes((value,))
        if value <= 0xFFFF:
            return b"\xfd" + value.to_bytes(2, "little")
        return b"\xfe" + value.to_bytes(4, "little")
    if value < 253:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def serialized_string(name: str, *, canonical: bool = True) -> bytes:
    encoded = name.encode("ascii")
    return compact_size(len(encoded), canonical=canonical) + encoded


def serialized_vector(payload: bytes, *, canonical: bool = True) -> bytes:
    return compact_size(len(payload), canonical=canonical) + payload


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def record(payload: bytes, slot_index: int, *, deleted: bool = False) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=100 + slot_index * 50,
        absolute_offset=10_000 + slot_index * 50,
        length=len(payload),
        record_type=1,
        deleted=deleted,
        payload=payload,
    )


def plain_key_pair(
    scalar: int = 1,
    *,
    key_scalar: int | None = None,
    compressed: bool = False,
    variant: str = "K1",
    der: bytes | None = None,
    type_canonical: bool = True,
    pubkey_canonical: bool = True,
    value_canonical: bool = True,
    key_deleted: bool = False,
    value_deleted: bool = False,
) -> BerkeleyLeafPair:
    public_key = encode_sec_public_key(
        scalar_multiply(scalar if key_scalar is None else key_scalar),
        compressed=compressed,
    )
    if der is None:
        der = ec_private_key_der(scalar, compressed=compressed)
    key_payload = serialized_string("key", canonical=type_canonical) + serialized_vector(
        public_key,
        canonical=pubkey_canonical,
    )
    value_payload = serialized_vector(der, canonical=value_canonical)
    if variant == "K2":
        value_payload += hash256(public_key + der)
    elif variant != "K1":
        raise ValueError("unsupported test variant")
    return BerkeleyLeafPair(
        pair_index=0,
        key=record(key_payload, 0, deleted=key_deleted),
        value=record(value_payload, 1, deleted=value_deleted),
    )


def validate(pair: BerkeleyLeafPair):
    return HistoricalPlainKeyValidator().validate(pair)


def test_oldest_k1_uncompressed_scalar_one_is_valid() -> None:
    pair = plain_key_pair(1)

    result = validate(pair)

    assert result.valid is True
    assert result.variant == "K1"
    assert result.canonical_framing is True
    assert result.public_key_match is True
    assert result.private_scalar_valid is True
    assert result.der_valid is True
    assert result.evidence["der_length"] == 279
    assert result.evidence["pubkey_compressed"] is False
    assert result.evidence["embedded_public_key_match"] is True
    assert result.evidence["checksum_present"] is False
    assert result.reasons == ()


def test_k1_compressed_scalar_two_is_valid() -> None:
    pair = plain_key_pair(2, compressed=True)

    result = validate(pair)

    assert result.valid is True
    assert result.variant == "K1"
    assert result.evidence["der_length"] == 214
    assert result.evidence["pubkey_compressed"] is True


def test_k2_compressed_key_and_hash_are_valid() -> None:
    result = validate(plain_key_pair(3, compressed=True, variant="K2"))

    assert result.valid is True
    assert result.variant == "K2"
    assert result.evidence["checksum_present"] is True
    assert result.evidence["checksum_valid"] is True


def test_deleted_complete_pair_remains_valid_and_is_diagnostic() -> None:
    result = validate(
        plain_key_pair(1, key_deleted=True, value_deleted=True)
    )

    assert result.valid is True
    assert result.evidence["key_deleted"] is True
    assert result.evidence["value_deleted"] is True


def test_validation_does_not_modify_pair_or_offsets() -> None:
    pair = plain_key_pair(2)
    before = pair

    assert validate(pair).valid is True
    assert pair == before
    assert pair.key.absolute_offset == 10_000
    assert pair.value.absolute_offset == 10_050


@pytest.mark.parametrize("name", ["ckey", "mkey", "wkey", "keymeta", "defaultkey"])
def test_other_record_types_return_wrong_record_type(name: str) -> None:
    pair = plain_key_pair(1)
    key_payload = serialized_string(name) + pair.key.payload[4:]
    wrong_pair = BerkeleyLeafPair(
        pair_index=0,
        key=record(key_payload, 0),
        value=pair.value,
    )

    result = validate(wrong_pair)

    assert result.valid is False
    assert result.reasons == ("wrong_record_type",)


def test_invalid_key_framing_does_not_parse_value() -> None:
    pair = plain_key_pair(1)
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=record(serialized_string("key"), 0),
        value=pair.value,
    )

    result = validate(invalid)

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)
    assert "der_length" not in result.evidence


def test_random_value_is_invalid() -> None:
    pair = plain_key_pair(1)
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(serialized_vector(b"random"), 1),
    )

    assert validate(invalid).reasons == ("der_invalid",)


def test_truncated_value_vector_is_invalid() -> None:
    pair = plain_key_pair(1)
    value = pair.value.payload
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(value[:-1], 1),
    )

    assert validate(invalid).reasons == ("value_truncated",)


def test_truncated_der_is_invalid() -> None:
    pair = plain_key_pair(1)
    der = ec_private_key_der(1, compressed=False)[:-1]
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(serialized_vector(der), 1),
    )

    assert validate(invalid).reasons == ("der_invalid",)


def test_wrong_der_sequence_tag_is_invalid() -> None:
    pair = plain_key_pair(1)
    der = bytearray(ec_private_key_der(1, compressed=False))
    der[0] = 0x31
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(serialized_vector(bytes(der)), 1),
    )

    assert validate(invalid).reasons == ("der_invalid",)


def test_wrong_der_length_is_invalid() -> None:
    pair = plain_key_pair(1)
    der = bytearray(ec_private_key_der(1, compressed=False))
    der[3] += 1
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(serialized_vector(bytes(der)), 1),
    )

    assert validate(invalid).reasons == ("der_invalid",)


def test_nonminimal_der_length_is_invalid() -> None:
    pair = plain_key_pair(1)
    der = ec_private_key_der(1, compressed=False)
    assert der[:2] == b"\x30\x82"
    nonminimal = b"\x30\x83\x00" + der[2:]
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(serialized_vector(nonminimal), 1),
    )

    assert validate(invalid).reasons == ("der_invalid",)


def test_der_version_must_be_one() -> None:
    der = ec_private_key_der(1, compressed=False, version=2)

    result = validate(plain_key_pair(1, der=der))

    assert result.valid is False
    assert result.reasons == ("der_version_invalid",)


def invalid_scalar_der(private_bytes: bytes) -> bytes:
    return ec_private_key_der(
        1,
        compressed=False,
        private_bytes=private_bytes,
        embedded_public_key=encode_sec_public_key(GENERATOR, compressed=False),
    )


@pytest.mark.parametrize(
    "private_bytes",
    [
        b"",
        bytes(32),
        GROUP_ORDER.to_bytes(32, "big"),
        (GROUP_ORDER + 1).to_bytes(32, "big"),
    ],
)
def test_invalid_private_scalar_is_not_reduced_or_repaired(
    private_bytes: bytes,
) -> None:
    result = validate(plain_key_pair(1, der=invalid_scalar_der(private_bytes)))

    assert result.valid is False
    assert result.private_scalar_valid is False
    assert result.reasons == ("private_scalar_invalid",)


def test_wrong_curve_oid_is_invalid() -> None:
    der = ec_private_key_der(
        1,
        compressed=False,
        field_oid=bytes.fromhex("2A8648CE3D0102"),
    )

    result = validate(plain_key_pair(1, der=der))

    assert result.valid is False
    assert result.reasons == ("curve_invalid",)


def test_embedded_public_key_outside_curve_is_invalid() -> None:
    invalid_public_key = b"\x02" + FIELD_PRIME.to_bytes(32, "big")
    der = ec_private_key_der(
        1,
        compressed=False,
        embedded_public_key=invalid_public_key,
    )

    result = validate(plain_key_pair(1, der=der))

    assert result.valid is False
    assert result.reasons == ("embedded_public_key_invalid",)


def test_embedded_public_key_must_match_private_scalar() -> None:
    scalar_two_public = encode_sec_public_key(
        scalar_multiply(2),
        compressed=False,
    )
    der = ec_private_key_der(
        1,
        compressed=False,
        embedded_public_key=scalar_two_public,
    )

    result = validate(plain_key_pair(1, der=der))

    assert result.valid is False
    assert result.reasons == ("embedded_public_key_mismatch",)


def test_scalar_one_der_with_scalar_two_berkeley_pubkey_is_invalid() -> None:
    pair = plain_key_pair(1, key_scalar=2)

    result = validate(pair)

    assert result.valid is False
    assert result.public_key_match is False
    assert result.reasons == ("public_key_mismatch",)


def test_trailing_value_garbage_is_invalid() -> None:
    pair = plain_key_pair(1)
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(pair.value.payload + b"garbage", 1),
    )

    assert validate(invalid).reasons == ("trailing_value_data",)


def test_k2_checksum_detects_one_changed_bit() -> None:
    pair = plain_key_pair(1, variant="K2")
    value = bytearray(pair.value.payload)
    value[-1] ^= 1
    invalid = BerkeleyLeafPair(
        pair_index=0,
        key=pair.key,
        value=record(bytes(value), 1),
    )

    result = validate(invalid)

    assert result.valid is False
    assert result.public_key_match is True
    assert result.reasons == ("checksum_invalid",)


@pytest.mark.parametrize(
    ("type_canonical", "pubkey_canonical", "value_canonical"),
    [
        (False, True, True),
        (True, False, True),
        (True, True, False),
    ],
)
def test_reader_compatible_noncanonical_framing_remains_valid(
    type_canonical: bool,
    pubkey_canonical: bool,
    value_canonical: bool,
) -> None:
    pair = plain_key_pair(
        1,
        type_canonical=type_canonical,
        pubkey_canonical=pubkey_canonical,
        value_canonical=value_canonical,
    )

    result = validate(pair)

    assert result.valid is True
    assert result.canonical_framing is False


def test_result_is_immutable_and_evidence_contains_no_key_material() -> None:
    result = validate(plain_key_pair(1))

    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]
    forbidden = {"private_scalar", "private_der", "public_key", "wif"}
    assert forbidden.isdisjoint(result.evidence)
    assert not any(isinstance(value, bytes) for value in result.evidence.values())


def test_validator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("validator attempted file I/O")

    monkeypatch.setattr("builtins.open", fail_open)

    assert validate(plain_key_pair(1)).valid is True
