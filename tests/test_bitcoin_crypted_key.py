from dataclasses import FrozenInstanceError

import pytest

from bfrs.core.secp256k1 import FIELD_PRIME
from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord
from bfrs.validators.bitcoin_crypted_key import HistoricalCryptedKeyValidator


GENERATOR_X = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
GENERATOR_Y = bytes.fromhex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)
UNCOMPRESSED_PUBLIC_KEY = b"\x04" + GENERATOR_X + GENERATOR_Y
COMPRESSED_PUBLIC_KEY = b"\x02" + GENERATOR_X
SYNTHETIC_CIPHERTEXT = bytes(range(48))


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
    payload = name.encode("ascii")
    return compact_size(len(payload), canonical=canonical) + payload


def serialized_vector(payload: bytes, *, canonical: bool = True) -> bytes:
    return compact_size(len(payload), canonical=canonical) + payload


def record(payload: bytes, slot_index: int, *, deleted: bool = False) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=100 + slot_index * 100,
        absolute_offset=10_000 + slot_index * 100,
        length=len(payload),
        record_type=1,
        deleted=deleted,
        payload=payload,
    )


def crypted_key_pair(
    *,
    public_key: bytes = UNCOMPRESSED_PUBLIC_KEY,
    ciphertext: bytes = SYNTHETIC_CIPHERTEXT,
    type_canonical: bool = True,
    pubkey_canonical: bool = True,
    value_canonical: bool = True,
    key_deleted: bool = False,
    value_deleted: bool = False,
) -> BerkeleyLeafPair:
    key_payload = serialized_string(
        "ckey", canonical=type_canonical
    ) + serialized_vector(public_key, canonical=pubkey_canonical)
    value_payload = serialized_vector(ciphertext, canonical=value_canonical)
    return BerkeleyLeafPair(
        pair_index=0,
        key=record(key_payload, 0, deleted=key_deleted),
        value=record(value_payload, 1, deleted=value_deleted),
    )


def replace_pair(
    pair: BerkeleyLeafPair,
    *,
    key_payload: bytes | None = None,
    value_payload: bytes | None = None,
) -> BerkeleyLeafPair:
    return BerkeleyLeafPair(
        pair_index=pair.pair_index,
        key=pair.key if key_payload is None else record(key_payload, 0),
        value=pair.value if value_payload is None else record(value_payload, 1),
    )


def validate(pair: BerkeleyLeafPair):
    return HistoricalCryptedKeyValidator().validate(pair)


@pytest.mark.parametrize(
    ("public_key", "compressed"),
    [
        (UNCOMPRESSED_PUBLIC_KEY, False),
        (COMPRESSED_PUBLIC_KEY, True),
    ],
)
def test_historical_ckey_with_valid_sec_public_key_is_valid(
    public_key: bytes,
    compressed: bool,
) -> None:
    result = validate(crypted_key_pair(public_key=public_key))

    assert result.valid is True
    assert result.canonical_framing is True
    assert result.encrypted_length == 48
    assert result.evidence["record_type"] == "ckey"
    assert result.evidence["pubkey_length"] == len(public_key)
    assert result.evidence["pubkey_compressed"] is compressed
    assert result.evidence["aes_block_aligned"] is True
    assert result.reasons == ()


def test_exact_48_byte_encrypted_secret_is_required_and_canonical() -> None:
    result = validate(crypted_key_pair())

    assert result.valid is True
    assert result.encrypted_length == 48
    assert result.evidence["value_framing_canonical"] is True
    assert result.evidence["canonical_framing"] is True


@pytest.mark.parametrize(
    ("type_canonical", "pubkey_canonical", "value_canonical"),
    [
        (False, True, True),
        (True, False, True),
        (True, True, False),
        (False, False, False),
    ],
)
def test_reader_compatible_noncanonical_framing_remains_valid(
    type_canonical: bool,
    pubkey_canonical: bool,
    value_canonical: bool,
) -> None:
    result = validate(
        crypted_key_pair(
            type_canonical=type_canonical,
            pubkey_canonical=pubkey_canonical,
            value_canonical=value_canonical,
        )
    )

    assert result.valid is True
    assert result.canonical_framing is False
    assert result.evidence["canonical_framing"] is False


def test_deleted_complete_ckey_remains_valid_and_is_diagnostic() -> None:
    result = validate(
        crypted_key_pair(key_deleted=True, value_deleted=True)
    )

    assert result.valid is True
    assert result.evidence["key_deleted"] is True
    assert result.evidence["value_deleted"] is True


def test_wrong_record_type_is_rejected_before_value_parsing() -> None:
    pair = crypted_key_pair()
    key_payload = serialized_string("key") + serialized_vector(
        UNCOMPRESSED_PUBLIC_KEY
    )
    result = validate(replace_pair(pair, key_payload=key_payload, value_payload=b""))

    assert result.valid is False
    assert result.reasons == ("wrong_record_type",)
    assert result.encrypted_length is None


def test_raw_ckey_without_berkeley_framing_is_invalid() -> None:
    result = validate(replace_pair(crypted_key_pair(), key_payload=b"ckey"))

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)


def test_ckey_type_without_public_key_is_invalid() -> None:
    result = validate(
        replace_pair(crypted_key_pair(), key_payload=serialized_string("ckey"))
    )

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)


def test_malformed_sec_public_key_is_invalid() -> None:
    malformed = b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    result = validate(crypted_key_pair(public_key=malformed))

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)


def test_empty_value_has_distinct_reason() -> None:
    result = validate(replace_pair(crypted_key_pair(), value_payload=b""))

    assert result.valid is False
    assert result.canonical_framing is False
    assert result.encrypted_length is None
    assert result.reasons == ("value_empty",)


@pytest.mark.parametrize("value", [b"\xfd", b"\xfe\x30\x00", b"\xff\x30\x00"])
def test_truncated_compact_size_is_value_framing_invalid(value: bytes) -> None:
    result = validate(replace_pair(crypted_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.encrypted_length is None
    assert result.reasons == ("value_framing_invalid",)


def test_declared_length_larger_than_available_value_is_truncated() -> None:
    value = compact_size(48) + SYNTHETIC_CIPHERTEXT[:-1]
    result = validate(replace_pair(crypted_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.encrypted_length == 48
    assert result.reasons == ("value_truncated",)


@pytest.mark.parametrize("length", [0, 16, 32, 64, 80])
def test_block_aligned_but_wrong_encrypted_length_is_invalid(length: int) -> None:
    result = validate(crypted_key_pair(ciphertext=bytes(length)))

    assert result.valid is False
    assert result.encrypted_length == length
    assert result.reasons == ("encrypted_length_invalid",)


@pytest.mark.parametrize("length", [1, 31, 47, 49, 63])
def test_non_aes_block_geometry_is_invalid(length: int) -> None:
    result = validate(crypted_key_pair(ciphertext=bytes(length)))

    assert result.valid is False
    assert result.encrypted_length == length
    assert result.evidence["aes_block_aligned"] is False
    assert result.reasons == ("encrypted_block_geometry_invalid",)


def test_trailing_garbage_after_complete_encrypted_vector_is_invalid() -> None:
    value = serialized_vector(SYNTHETIC_CIPHERTEXT) + b"garbage"
    result = validate(replace_pair(crypted_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.encrypted_length == 48
    assert result.reasons == ("trailing_value_data",)


def test_random_bytes_pretending_to_be_framed_value_are_invalid() -> None:
    value = serialized_vector(b"random!")
    result = validate(replace_pair(crypted_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.reasons == ("encrypted_block_geometry_invalid",)


def test_valid_key_framing_does_not_accept_random_wrong_length_blob() -> None:
    random_blob = bytes.fromhex(
        "8fc88de736b9a41f65f563b6380281e2ed7f62c5d82ef26d30e521828e53e8"
    )
    result = validate(crypted_key_pair(ciphertext=random_blob))

    assert result.valid is False
    assert result.encrypted_length == 31
    assert result.reasons == ("encrypted_block_geometry_invalid",)


def test_correct_value_does_not_override_mathematically_invalid_pubkey() -> None:
    invalid_public_key = b"\x02" + FIELD_PRIME.to_bytes(32, "big")
    result = validate(crypted_key_pair(public_key=invalid_public_key))

    assert result.valid is False
    assert result.encrypted_length is None
    assert result.reasons == ("record_key_invalid",)


def test_result_is_immutable_and_evidence_contains_no_sensitive_bytes() -> None:
    result = validate(crypted_key_pair())

    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]
    forbidden = {"ciphertext", "pubkey", "private_key", "iv", "passphrase"}
    assert forbidden.isdisjoint(result.evidence)
    assert not any(isinstance(value, bytes) for value in result.evidence.values())


def test_validator_does_not_modify_pair_or_offsets() -> None:
    pair = crypted_key_pair()
    before = pair

    assert validate(pair).valid is True
    assert pair == before
    assert pair.key.absolute_offset == 10_000
    assert pair.value.absolute_offset == 10_100


def test_validator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("validator attempted file I/O")

    monkeypatch.setattr("builtins.open", fail_open)

    assert validate(crypted_key_pair()).valid is True
