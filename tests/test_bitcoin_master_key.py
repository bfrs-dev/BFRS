from dataclasses import FrozenInstanceError

import pytest

from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord
from bfrs.validators.bitcoin_master_key import HistoricalMasterKeyValidator


SYNTHETIC_ENCRYPTED_MASTER_KEY = bytes(range(48))
SYNTHETIC_SALT = bytes.fromhex("0011223344556677")


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
        absolute_offset=20_000 + slot_index * 100,
        length=len(payload),
        record_type=1,
        deleted=deleted,
        payload=payload,
    )


def master_key_value(
    *,
    encrypted_master_key: bytes = SYNTHETIC_ENCRYPTED_MASTER_KEY,
    salt: bytes = SYNTHETIC_SALT,
    derivation_method: int = 0,
    derivation_iterations: int = 25_000,
    other_parameters: bytes = b"",
    encrypted_canonical: bool = True,
    salt_canonical: bool = True,
    other_canonical: bool = True,
) -> bytes:
    return (
        serialized_vector(encrypted_master_key, canonical=encrypted_canonical)
        + serialized_vector(salt, canonical=salt_canonical)
        + derivation_method.to_bytes(4, "little")
        + derivation_iterations.to_bytes(4, "little")
        + serialized_vector(other_parameters, canonical=other_canonical)
    )


def master_key_pair(
    *,
    master_key_id: int = 1,
    value: bytes | None = None,
    type_canonical: bool = True,
    key_deleted: bool = False,
    value_deleted: bool = False,
) -> BerkeleyLeafPair:
    key_payload = serialized_string(
        "mkey", canonical=type_canonical
    ) + master_key_id.to_bytes(4, "little")
    return BerkeleyLeafPair(
        pair_index=0,
        key=record(key_payload, 0, deleted=key_deleted),
        value=record(
            master_key_value() if value is None else value,
            1,
            deleted=value_deleted,
        ),
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
    return HistoricalMasterKeyValidator().validate(pair)


def test_v040_writer_compatible_master_key_is_valid() -> None:
    result = validate(master_key_pair(master_key_id=7))

    assert result.valid is True
    assert result.canonical_framing is True
    assert result.master_key_id == 7
    assert result.encrypted_master_key_length == 48
    assert result.salt_length == 8
    assert result.derivation_method == 0
    assert result.derivation_iterations == 25_000
    assert result.other_parameters_length == 0
    assert result.evidence["encrypted_master_key_aes_block_aligned"] is True
    assert result.reasons == ()


def test_zero_byte_fields_are_not_rejected_by_entropy_heuristics() -> None:
    value = master_key_value(
        encrypted_master_key=bytes(48),
        salt=bytes(8),
    )

    result = validate(master_key_pair(value=value))

    assert result.valid is True
    assert result.encrypted_master_key_length == 48
    assert result.salt_length == 8


@pytest.mark.parametrize("master_key_id", [0, 1, 0x01020304, 0xFFFFFFFF])
def test_master_key_id_is_preserved_from_existing_key_validator(
    master_key_id: int,
) -> None:
    result = validate(master_key_pair(master_key_id=master_key_id))

    assert result.valid is True
    assert result.master_key_id == master_key_id
    assert result.evidence["master_key_id"] == master_key_id


@pytest.mark.parametrize(
    ("type_canonical", "encrypted_canonical", "salt_canonical", "other_canonical"),
    [
        (False, True, True, True),
        (True, False, True, True),
        (True, True, False, True),
        (True, True, True, False),
        (False, False, False, False),
    ],
)
def test_legacy_reader_noncanonical_vectors_remain_valid_but_marked(
    type_canonical: bool,
    encrypted_canonical: bool,
    salt_canonical: bool,
    other_canonical: bool,
) -> None:
    value = master_key_value(
        encrypted_canonical=encrypted_canonical,
        salt_canonical=salt_canonical,
        other_canonical=other_canonical,
    )

    result = validate(
        master_key_pair(type_canonical=type_canonical, value=value)
    )

    assert result.valid is True
    assert result.canonical_framing is False
    assert result.evidence["canonical_framing"] is False


def test_deleted_complete_master_key_remains_valid() -> None:
    result = validate(
        master_key_pair(key_deleted=True, value_deleted=True)
    )

    assert result.valid is True
    assert result.evidence["key_deleted"] is True
    assert result.evidence["value_deleted"] is True


def test_wrong_record_type_is_rejected_before_value_parsing() -> None:
    pair = master_key_pair()
    key_payload = serialized_string("defaultkey")
    result = validate(replace_pair(pair, key_payload=key_payload, value_payload=b""))

    assert result.valid is False
    assert result.reasons == ("wrong_record_type",)
    assert result.master_key_id is None


def test_raw_mkey_without_serialized_string_framing_is_invalid() -> None:
    result = validate(replace_pair(master_key_pair(), key_payload=b"mkey"))

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)


@pytest.mark.parametrize("suffix", [b"", b"\x01", b"\x01\x02", b"\x01\x02\x03"])
def test_truncated_master_key_id_is_invalid(suffix: bytes) -> None:
    key_payload = serialized_string("mkey") + suffix
    result = validate(replace_pair(master_key_pair(), key_payload=key_payload))

    assert result.valid is False
    assert result.reasons == ("record_key_invalid",)


def test_empty_value_has_distinct_reason() -> None:
    result = validate(replace_pair(master_key_pair(), value_payload=b""))

    assert result.valid is False
    assert result.canonical_framing is False
    assert result.reasons == ("value_empty",)


@pytest.mark.parametrize("value", [b"\xfd", b"\xfe\x30\x00", b"\xff\x30\x00"])
def test_truncated_encrypted_key_vector_prefix_is_invalid(value: bytes) -> None:
    result = validate(replace_pair(master_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.reasons == ("encrypted_master_key_framing_invalid",)


def test_declared_encrypted_key_length_larger_than_available_is_truncated() -> None:
    value = compact_size(48) + SYNTHETIC_ENCRYPTED_MASTER_KEY[:-1]
    result = validate(replace_pair(master_key_pair(), value_payload=value))

    assert result.valid is False
    assert result.encrypted_master_key_length == 48
    assert result.reasons == ("value_truncated",)


@pytest.mark.parametrize("length", [0, 16, 32, 47, 49, 64])
def test_wrong_encrypted_master_key_length_is_invalid(length: int) -> None:
    result = validate(
        master_key_pair(value=master_key_value(encrypted_master_key=bytes(length)))
    )

    assert result.valid is False
    assert result.encrypted_master_key_length == length
    assert result.reasons == ("encrypted_master_key_length_invalid",)


@pytest.mark.parametrize("suffix", [b"", b"\xfd", b"\xfe\x08\x00"])
def test_truncated_salt_prefix_is_invalid(suffix: bytes) -> None:
    value = serialized_vector(SYNTHETIC_ENCRYPTED_MASTER_KEY) + suffix
    result = validate(master_key_pair(value=value))

    assert result.valid is False
    assert result.reasons == ("salt_framing_invalid",)


def test_declared_salt_length_larger_than_available_is_truncated() -> None:
    value = (
        serialized_vector(SYNTHETIC_ENCRYPTED_MASTER_KEY)
        + compact_size(8)
        + SYNTHETIC_SALT[:-1]
    )
    result = validate(master_key_pair(value=value))

    assert result.valid is False
    assert result.salt_length == 8
    assert result.reasons == ("value_truncated",)


@pytest.mark.parametrize("length", [0, 1, 7, 9, 16])
def test_nonhistorical_salt_length_is_invalid(length: int) -> None:
    result = validate(master_key_pair(value=master_key_value(salt=bytes(length))))

    assert result.valid is False
    assert result.salt_length == length
    assert result.reasons == ("salt_length_invalid",)


@pytest.mark.parametrize("method_bytes", [b"", b"\x00", b"\x00\x00", b"\x00\x00\x00"])
def test_truncated_derivation_method_is_invalid(method_bytes: bytes) -> None:
    value = (
        serialized_vector(SYNTHETIC_ENCRYPTED_MASTER_KEY)
        + serialized_vector(SYNTHETIC_SALT)
        + method_bytes
    )
    result = validate(master_key_pair(value=value))

    assert result.valid is False
    assert result.derivation_method is None
    assert result.reasons == ("value_truncated",)


@pytest.mark.parametrize("method", [1, 2, 0xFFFFFFFF])
def test_unimplemented_historical_derivation_methods_are_invalid(method: int) -> None:
    result = validate(
        master_key_pair(value=master_key_value(derivation_method=method))
    )

    assert result.valid is False
    assert result.derivation_method == method
    assert result.evidence["derivation_method_writer_compatible"] is False
    assert result.reasons == ("derivation_method_invalid",)


@pytest.mark.parametrize("iteration_bytes", [b"", b"\xa8", b"\xa8\x61", b"\xa8\x61\x00"])
def test_truncated_derivation_iterations_are_invalid(
    iteration_bytes: bytes,
) -> None:
    value = (
        serialized_vector(SYNTHETIC_ENCRYPTED_MASTER_KEY)
        + serialized_vector(SYNTHETIC_SALT)
        + (0).to_bytes(4, "little")
        + iteration_bytes
    )
    result = validate(master_key_pair(value=value))

    assert result.valid is False
    assert result.derivation_iterations is None
    assert result.reasons == ("value_truncated",)


@pytest.mark.parametrize("iterations", [0, 1, 24_999])
def test_iterations_below_standard_writer_minimum_are_invalid(
    iterations: int,
) -> None:
    result = validate(
        master_key_pair(
            value=master_key_value(derivation_iterations=iterations)
        )
    )

    assert result.valid is False
    assert result.derivation_iterations == iterations
    assert result.reasons == ("derivation_iterations_invalid",)


@pytest.mark.parametrize("iterations", [25_000, 100_000, 0xFFFFFFFF])
def test_writer_compatible_and_large_uint32_iterations_are_valid(
    iterations: int,
) -> None:
    result = validate(
        master_key_pair(
            value=master_key_value(derivation_iterations=iterations)
        )
    )

    assert result.valid is True
    assert result.derivation_iterations == iterations


@pytest.mark.parametrize("suffix", [b"", b"\xfd", b"\xfe\x00\x00"])
def test_malformed_other_parameters_vector_is_invalid(suffix: bytes) -> None:
    prefix = (
        serialized_vector(SYNTHETIC_ENCRYPTED_MASTER_KEY)
        + serialized_vector(SYNTHETIC_SALT)
        + (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
    )
    result = validate(master_key_pair(value=prefix + suffix))

    assert result.valid is False
    assert result.reasons == ("other_parameters_framing_invalid",)


@pytest.mark.parametrize("parameters", [b"\x00", b"scrypt", bytes(32)])
def test_nonempty_other_parameters_are_not_standard_writer_output(
    parameters: bytes,
) -> None:
    result = validate(
        master_key_pair(value=master_key_value(other_parameters=parameters))
    )

    assert result.valid is False
    assert result.other_parameters_length == len(parameters)
    assert result.reasons == ("other_parameters_invalid",)


def test_trailing_bytes_after_complete_master_key_are_invalid() -> None:
    result = validate(master_key_pair(value=master_key_value() + b"garbage"))

    assert result.valid is False
    assert result.reasons == ("trailing_value_data",)


def test_similar_length_random_blob_is_not_searched_for_embedded_fields() -> None:
    random_blob = (
        b"\x99"
        + SYNTHETIC_ENCRYPTED_MASTER_KEY
        + SYNTHETIC_SALT
        + (100_000).to_bytes(4, "little")
        + bytes(5)
    )
    result = validate(master_key_pair(value=random_blob))

    assert result.valid is False
    assert result.reasons == ("value_truncated",)


def test_result_is_immutable_and_evidence_contains_no_sensitive_bytes() -> None:
    result = validate(master_key_pair())

    with pytest.raises(FrozenInstanceError):
        result.valid = False  # type: ignore[misc]
    forbidden = {
        "encrypted_master_key",
        "salt",
        "other_parameters",
        "passphrase",
        "derived_key",
    }
    assert forbidden.isdisjoint(result.evidence)
    assert not any(isinstance(value, bytes) for value in result.evidence.values())


def test_validator_does_not_modify_pair_or_offsets() -> None:
    pair = master_key_pair(master_key_id=9)
    before = pair

    assert validate(pair).valid is True
    assert pair == before
    assert pair.key.absolute_offset == 20_000
    assert pair.value.absolute_offset == 20_100


def test_validator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("validator attempted file I/O")

    monkeypatch.setattr("builtins.open", fail_open)

    assert validate(master_key_pair()).valid is True
