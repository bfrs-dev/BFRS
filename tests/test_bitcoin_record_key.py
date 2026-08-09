from dataclasses import FrozenInstanceError

import pytest

from bfrs.validators.bitcoin_record_key import (
    SECP256K1_FIELD_PRIME,
    BitcoinRecordKeyValidation,
    BitcoinRecordKeyValidator,
)
from bfrs.validators.bitcoin_record_type import BitcoinRecordTypeDecoder


GENERATOR_X = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
GENERATOR_Y = bytes.fromhex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)
UNCOMPRESSED_PUBLIC_KEY = b"\x04" + GENERATOR_X + GENERATOR_Y
COMPRESSED_PUBLIC_KEY = b"\x02" + GENERATOR_X


def type_framing(name: str, suffix: bytes, *, canonical: bool = True) -> bytes:
    encoded = name.encode("ascii")
    if canonical:
        return bytes((len(encoded),)) + encoded + suffix
    return b"\xfd" + len(encoded).to_bytes(2, "little") + encoded + suffix


def vector_framing(
    payload: bytes,
    *,
    canonical: bool = True,
    declared_length: int | None = None,
) -> bytes:
    length = len(payload) if declared_length is None else declared_length
    if canonical:
        if length >= 253:
            raise ValueError("test helper only supports short canonical vectors")
        return bytes((length,)) + payload
    return b"\xfd" + length.to_bytes(2, "little") + payload


def validate(
    name: str,
    suffix: bytes,
    *,
    type_canonical: bool = True,
) -> BitcoinRecordKeyValidation:
    decoded = BitcoinRecordTypeDecoder().decode(
        type_framing(name, suffix, canonical=type_canonical)
    )
    assert decoded is not None
    return BitcoinRecordKeyValidator().validate(decoded)


@pytest.mark.parametrize("name", ["key", "wkey", "ckey", "keymeta"])
@pytest.mark.parametrize(
    ("public_key", "compressed"),
    [
        (UNCOMPRESSED_PUBLIC_KEY, False),
        (COMPRESSED_PUBLIC_KEY, True),
    ],
)
def test_public_key_record_shapes_accept_real_secp256k1_points(
    name: str,
    public_key: bytes,
    compressed: bool,
) -> None:
    result = validate(name, vector_framing(public_key))

    assert result.valid is True
    assert result.record_type == name
    assert result.variant == name
    assert result.canonical_framing is True
    assert result.evidence["pubkey_length"] == len(public_key)
    assert result.evidence["compressed"] is compressed
    assert result.evidence["pubkey_framing_canonical"] is True
    assert result.reasons == ()


@pytest.mark.parametrize("name", ["key", "ckey", "keymeta"])
def test_missing_public_key_suffix_is_invalid(name: str) -> None:
    result = validate(name, b"")

    assert result.valid is False
    assert result.canonical_framing is False
    assert result.reasons == ("key_suffix_truncated",)


@pytest.mark.parametrize("name", ["key", "ckey", "keymeta"])
def test_truncated_public_key_is_invalid(name: str) -> None:
    result = validate(
        name,
        vector_framing(COMPRESSED_PUBLIC_KEY[:10], declared_length=33),
    )

    assert result.valid is False
    assert result.reasons == ("key_suffix_truncated",)


@pytest.mark.parametrize(
    "suffix",
    [
        vector_framing(b"\x02" + bytes(31)),
        vector_framing(b"\x04" + bytes(63)),
        vector_framing(b"\x02" + bytes(33)),
    ],
)
def test_wrong_vector_length_is_invalid(suffix: bytes) -> None:
    result = validate("key", suffix)

    assert result.valid is False
    assert result.reasons == ("pubkey_length_invalid",)


@pytest.mark.parametrize(
    "public_key",
    [
        b"\x04" + GENERATOR_X,
        b"\x02" + GENERATOR_X + GENERATOR_Y,
        b"\x00" + GENERATOR_X,
        b"\x05" + GENERATOR_X + GENERATOR_Y,
    ],
)
def test_sec_prefix_must_match_declared_public_key_length(
    public_key: bytes,
) -> None:
    result = validate("key", vector_framing(public_key))

    assert result.valid is False
    assert result.reasons == ("pubkey_prefix_invalid",)


@pytest.mark.parametrize("name", ["key", "ckey", "keymeta", "wkey"])
def test_trailing_data_after_public_key_is_invalid(name: str) -> None:
    suffix = vector_framing(COMPRESSED_PUBLIC_KEY) + b"GARBAGE"

    result = validate(name, suffix)

    assert result.valid is False
    assert result.reasons == ("trailing_key_data",)


@pytest.mark.parametrize(
    "public_key",
    [
        b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big"),
        b"\x02" + SECP256K1_FIELD_PRIME.to_bytes(32, "big"),
    ],
)
def test_mathematically_invalid_secp256k1_point_is_rejected(
    public_key: bytes,
) -> None:
    result = validate("key", vector_framing(public_key))

    assert result.valid is False
    assert result.reasons == ("pubkey_point_invalid",)


def test_random_33_bytes_are_not_accepted_as_ckey_public_key() -> None:
    result = validate("ckey", vector_framing(b"R" * 33))

    assert result.valid is False
    assert result.reasons == ("pubkey_prefix_invalid",)


def test_key_with_pubkey_framing_and_garbage_is_invalid() -> None:
    result = validate(
        "key",
        vector_framing(UNCOMPRESSED_PUBLIC_KEY) + b"unexpected",
    )

    assert result.valid is False
    assert result.reasons == ("trailing_key_data",)


def test_wkey_key_shape_does_not_invent_value_variants() -> None:
    result = validate("wkey", vector_framing(UNCOMPRESSED_PUBLIC_KEY))

    assert result.valid is True
    assert result.variant == "wkey"
    assert "W1" not in result.evidence.values()
    assert "W2" not in result.evidence.values()


def test_mkey_id_is_exactly_little_endian_uint32() -> None:
    result = validate("mkey", b"\x04\x03\x02\x01")

    assert result.valid is True
    assert result.variant == "mkey"
    assert result.evidence["mkey_id"] == 0x01020304
    assert result.reasons == ()


def test_mkey_id_zero_is_structurally_valid() -> None:
    result = validate("mkey", bytes(4))

    assert result.valid is True
    assert result.evidence["mkey_id"] == 0


@pytest.mark.parametrize("suffix", [b"", b"\x01", b"\x01\x02", b"abc"])
def test_truncated_mkey_id_is_invalid(suffix: bytes) -> None:
    result = validate("mkey", suffix)

    assert result.valid is False
    assert result.reasons == ("mkey_id_invalid",)


@pytest.mark.parametrize("suffix", [b"12345", b"random text"])
def test_mkey_trailing_bytes_are_invalid(suffix: bytes) -> None:
    result = validate("mkey", suffix)

    assert result.valid is False
    assert result.reasons == ("trailing_key_data",)


def test_defaultkey_requires_an_empty_suffix() -> None:
    result = validate("defaultkey", b"")

    assert result.valid is True
    assert result.variant == "defaultkey"
    assert result.reasons == ()


@pytest.mark.parametrize(
    "suffix",
    [
        b"\x00",
        b"GARBAGE",
        vector_framing(COMPRESSED_PUBLIC_KEY),
    ],
)
def test_defaultkey_rejects_every_trailing_key_byte(suffix: bytes) -> None:
    result = validate("defaultkey", suffix)

    assert result.valid is False
    assert result.reasons == ("trailing_key_data",)


def test_noncanonical_public_key_vector_can_be_valid_but_not_canonical() -> None:
    result = validate(
        "ckey",
        vector_framing(COMPRESSED_PUBLIC_KEY, canonical=False),
    )

    assert result.valid is True
    assert result.canonical_framing is False
    assert result.evidence["record_type_framing_canonical"] is True
    assert result.evidence["pubkey_framing_canonical"] is False


def test_noncanonical_record_type_with_canonical_vector_is_not_canonical() -> None:
    result = validate(
        "keymeta",
        vector_framing(UNCOMPRESSED_PUBLIC_KEY),
        type_canonical=False,
    )

    assert result.valid is True
    assert result.canonical_framing is False
    assert result.evidence["record_type_framing_canonical"] is False
    assert result.evidence["pubkey_framing_canonical"] is True


def test_noncanonical_record_and_vector_framing_remain_structurally_valid() -> None:
    result = validate(
        "wkey",
        vector_framing(COMPRESSED_PUBLIC_KEY, canonical=False),
        type_canonical=False,
    )

    assert result.valid is True
    assert result.canonical_framing is False


def test_unsupported_custom_record_type_is_rejected() -> None:
    decoder = BitcoinRecordTypeDecoder(["custom"])
    decoded = decoder.decode(type_framing("custom", b""))
    assert decoded is not None

    result = BitcoinRecordKeyValidator().validate(decoded)

    assert result.valid is False
    assert result.variant is None
    assert result.reasons == ("record_type_unsupported",)


def test_validation_result_is_immutable() -> None:
    result = validate("defaultkey", b"")

    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]


def test_evidence_never_contains_public_key_bytes() -> None:
    result = validate("key", vector_framing(UNCOMPRESSED_PUBLIC_KEY))

    assert not any(isinstance(value, bytes) for value in result.evidence.values())
