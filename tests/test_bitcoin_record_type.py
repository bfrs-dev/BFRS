from dataclasses import FrozenInstanceError

import pytest

from bfrs.recovery.berkeley_records import BerkeleyLeafPair, BerkeleyRecord
from bfrs.validators.bitcoin_record_type import (
    DEFAULT_RECORD_TYPES,
    MAX_RECORD_TYPE_LENGTH,
    BitcoinRecordTypeDecoder,
    CompactSizeResult,
    decode_compact_size,
)


def framed(name: str, remaining: bytes = b"") -> bytes:
    encoded = name.encode("ascii")
    return bytes((len(encoded),)) + encoded + remaining


@pytest.mark.parametrize("name", sorted(DEFAULT_RECORD_TYPES))
def test_default_types_decode_with_canonical_framing(name: str) -> None:
    result = BitcoinRecordTypeDecoder().decode(framed(name))

    assert result is not None
    assert result.name == name
    assert result.name_length == len(name)
    assert result.prefix_length == len(name) + 1
    assert result.remaining_key == b""
    assert result.canonical_framing is True


def test_canonical_ckey_preserves_remaining_key_exactly() -> None:
    remaining = b"\x21\x02" + bytes(range(32))

    result = BitcoinRecordTypeDecoder().decode(framed("ckey", remaining))

    assert result is not None
    assert result.name == "ckey"
    assert result.canonical_framing is True
    assert result.prefix_length == 5
    assert result.remaining_key == remaining


def test_legacy_noncanonical_ckey_is_recognized_but_marked() -> None:
    payload = b"\xfd\x04\x00ckey"

    result = BitcoinRecordTypeDecoder().decode(payload)

    assert result is not None
    assert result.name == "ckey"
    assert result.name_length == 4
    assert result.prefix_length == 7
    assert result.remaining_key == b""
    assert result.canonical_framing is False


@pytest.mark.parametrize(
    "payload",
    [
        b"ckey",
        b"xxxxckeyxxxx",
        framed("CKEY"),
        framed("ckeyx"),
        b"",
        b"\xfd",
        b"\xfd\x04",
        b"\xfe\x04\x00\x00",
        b"\xff\x04\x00\x00\x00\x00\x00\x00",
        b"\x04key",
        b"\x00",
        b"\x04\xffkey",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x80random bytes",
        b"\x01\x00",
    ],
)
def test_false_positive_and_corrupt_payloads_do_not_match(payload: bytes) -> None:
    assert BitcoinRecordTypeDecoder().decode(payload) is None


def test_declared_name_over_safe_limit_does_not_require_large_buffer() -> None:
    payload = b"\xfd\x41\x00"

    assert MAX_RECORD_TYPE_LENGTH == 64
    assert BitcoinRecordTypeDecoder().decode(payload) is None


@pytest.mark.parametrize(
    ("encoded", "value", "encoded_length"),
    [
        (b"\x00", 0, 1),
        (b"\x01", 1, 1),
        (b"\xfc", 252, 1),
        (b"\xfd\xfd\x00", 253, 3),
        (b"\xfd\xff\xff", 65_535, 3),
        (b"\xfe\x00\x00\x01\x00", 65_536, 5),
    ],
)
def test_compact_size_canonical_boundaries(
    encoded: bytes,
    value: int,
    encoded_length: int,
) -> None:
    assert decode_compact_size(encoded) == CompactSizeResult(
        value=value,
        encoded_length=encoded_length,
        canonical=True,
    )


@pytest.mark.parametrize(
    ("encoded", "value", "encoded_length"),
    [
        (b"\xfd\x00\x00", 0, 3),
        (b"\xfd\x01\x00", 1, 3),
        (b"\xfd\xfc\x00", 252, 3),
        (b"\xfe\xfd\x00\x00\x00", 253, 5),
        (b"\xfe\xff\xff\x00\x00", 65_535, 5),
        (b"\xff\x00\x00\x01\x00\x00\x00\x00\x00", 65_536, 9),
    ],
)
def test_compact_size_legacy_noncanonical_encodings(
    encoded: bytes,
    value: int,
    encoded_length: int,
) -> None:
    assert decode_compact_size(encoded) == CompactSizeResult(
        value=value,
        encoded_length=encoded_length,
        canonical=False,
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\xfd",
        b"\xfd\x01",
        b"\xfe\x01\x00\x00",
        b"\xff\x01\x00\x00\x00\x00\x00\x00",
    ],
)
def test_compact_size_truncation_returns_none(payload: bytes) -> None:
    assert decode_compact_size(payload) is None


@pytest.mark.parametrize("offset", [-1, 1, 10])
def test_compact_size_out_of_range_offset_returns_none(offset: int) -> None:
    assert decode_compact_size(b"\x00", offset) is None


def test_compact_size_decodes_at_nonzero_offset() -> None:
    assert decode_compact_size(b"padding\xfd\xfd\x00", 7) == CompactSizeResult(
        value=253,
        encoded_length=3,
        canonical=True,
    )


def test_results_are_immutable() -> None:
    compact = decode_compact_size(b"\x04")
    record_type = BitcoinRecordTypeDecoder().decode(framed("key"))
    assert compact is not None
    assert record_type is not None

    with pytest.raises(FrozenInstanceError):
        compact.value = 5  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        record_type.name = "ckey"  # type: ignore[misc]


def test_custom_allowlist_is_used_exactly() -> None:
    decoder = BitcoinRecordTypeDecoder(["custom"])

    assert decoder.decode(framed("custom")) is not None
    assert decoder.decode(framed("key")) is None


@pytest.mark.parametrize(
    ("allowed_types", "error_type"),
    [
        (["key", "key"], ValueError),
        ([""], ValueError),
        (["żółć"], ValueError),
        (["x" * (MAX_RECORD_TYPE_LENGTH + 1)], ValueError),
        ([1], TypeError),
        ("key", TypeError),
    ],
)
def test_invalid_custom_allowlist_is_rejected(
    allowed_types: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        BitcoinRecordTypeDecoder(allowed_types)  # type: ignore[arg-type]


def record(payload: bytes, slot_index: int) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=100 + slot_index * 20,
        absolute_offset=1_000 + slot_index * 20,
        length=len(payload),
        record_type=1,
        deleted=False,
        payload=payload,
    )


def test_decode_pair_reads_key_payload_and_ignores_value_payload() -> None:
    remaining = b"\x01suffix"
    pair = BerkeleyLeafPair(
        pair_index=0,
        key=record(framed("mkey", remaining), 0),
        value=record(b"\x04ckey-secret-looking-value", 1),
    )

    result = BitcoinRecordTypeDecoder().decode_pair(pair)

    assert result is not None
    assert result.name == "mkey"
    assert result.remaining_key == remaining


def test_decode_pair_does_not_use_valid_type_from_value_payload() -> None:
    pair = BerkeleyLeafPair(
        pair_index=0,
        key=record(b"not-framed", 0),
        value=record(framed("ckey"), 1),
    )

    assert BitcoinRecordTypeDecoder().decode_pair(pair) is None
