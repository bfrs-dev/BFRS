from dataclasses import FrozenInstanceError

import pytest

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.models import RawHit, ValidationStatus
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.orphan_private_key_der import (
    HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
    HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
    MAX_ORPHAN_DER_READ_SIZE,
)
from bfrs.recovery.orphan_private_key_fragment import (
    INNER_FRAGMENT_VALIDATION_STRENGTH,
    OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline,
)
from bfrs.validators.candidate_policy import CandidatePolicy


SOURCE = "inner-fragment.img"
PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")


class MemoryRangeReader:
    def __init__(self, data: bytes, *, start: int = 0, end: int | None = None):
        self.data = data
        self.start = start
        self.end = len(data) if end is None else end
        self.calls: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        if offset < self.start or offset >= self.end:
            raise PhysicalRangeReadError("outside fragment test range")
        return self.data[offset : min(offset + length, self.end)]


def der_length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(content)) + content


def integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return tlv(2, encoded)


def explicit_parameters(*, compressed: bool, field_oid: bytes = PRIME_FIELD_OID) -> bytes:
    field = tlv(0x30, tlv(0x06, field_oid) + integer(FIELD_PRIME))
    curve = tlv(0x30, tlv(0x04, b"\x00") + tlv(0x04, b"\x07"))
    return tlv(
        0x30,
        integer(1)
        + field
        + curve
        + tlv(0x04, encode_sec_public_key(GENERATOR, compressed=compressed))
        + integer(GROUP_ORDER)
        + integer(1),
    )


def private_der(
    scalar: int,
    *,
    compressed: bool = False,
    private_bytes: bytes | None = None,
    embedded_public_key: bytes | None = None,
    field_oid: bytes = PRIME_FIELD_OID,
) -> bytes:
    if private_bytes is None:
        private_bytes = scalar.to_bytes(32, "big")
    if embedded_public_key is None:
        embedded_public_key = encode_sec_public_key(
            scalar_multiply(max(1, scalar)), compressed=compressed
        )
    content = (
        integer(1)
        + tlv(0x04, private_bytes)
        + tlv(
            0xA0,
            explicit_parameters(compressed=compressed, field_oid=field_oid),
        )
        + tlv(0xA1, tlv(0x03, b"\x00" + embedded_public_key))
    )
    return tlv(0x30, content)


def inner(der: bytes) -> bytes:
    first = der[1]
    header_length = 2 if first < 0x80 else 2 + (first & 0x7F)
    result = der[header_length:]
    assert result.startswith(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR)
    return result


def anchor_hit(data: bytes, *, start: int = 0) -> RawHit:
    offset = data.index(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR, start)
    return RawHit(
        offset,
        offset + len(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR),
        HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
        0.0,
        SOURCE,
    )


def run(data: bytes, hits: tuple[RawHit, ...]):
    reader = MemoryRangeReader(data)
    result = OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline(
        hits,
        source=SOURCE,
        range_start=0,
        range_end=len(data),
        range_reader=reader,
    ).run()
    return result, reader


def test_false_inner_anchor_with_random_suffix_is_rejected():
    data = HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR + bytes(range(32)) + b"random"
    result, _ = run(data, (anchor_hit(data),))
    assert result.raw_inner_anchor_count == 1
    assert result.candidate_inner_fragment_count == 1
    assert result.valid_inner_fragment_count == 0


@pytest.mark.parametrize("scalar", (1, 2))
def test_valid_inner_fragment_for_independent_scalars(scalar):
    fragment = inner(private_der(scalar))
    data = fragment + b"trailing-noise"
    result, _ = run(data, (anchor_hit(data),))
    assert result.valid_inner_fragment_count == 1
    location = result.locations[0]
    assert location.absolute_anchor_offset == 0
    assert location.recovered_fragment_length == len(fragment)
    assert location.validation_strength == INNER_FRAGMENT_VALIDATION_STRENGTH
    with pytest.raises(FrozenInstanceError):
        result.valid_inner_fragment_count = 0


def test_compressed_embedded_key_remains_supported():
    fragment = inner(private_der(1, compressed=True))
    result, _ = run(fragment, (anchor_hit(fragment),))
    assert result.valid_inner_fragment_count == 1
    assert result.locations[0].public_key_encoding == "compressed"


def test_embedded_public_key_mismatch_is_rejected():
    wrong = encode_sec_public_key(scalar_multiply(2), compressed=False)
    fragment = inner(private_der(1, embedded_public_key=wrong))
    result, _ = run(fragment, (anchor_hit(fragment),))
    assert result.valid_inner_fragment_count == 0
    assert ("embedded_public_key_mismatch", 1) in result.evidence[
        "rejection_counts"
    ]


def test_wrong_curve_is_rejected():
    fragment = inner(
        private_der(1, field_oid=bytes.fromhex("2A8648CE3D0102"))
    )
    result, _ = run(fragment, (anchor_hit(fragment),))
    assert result.valid_inner_fragment_count == 0
    assert ("curve_invalid", 1) in result.evidence["rejection_counts"]


def test_damaged_explicit_parameters_are_rejected():
    fragment = bytearray(inner(private_der(1)))
    coefficient = fragment.find(b"\x04\x01\x07")
    assert coefficient > 0
    fragment[coefficient + 2] = 8
    raw = bytes(fragment)
    result, _ = run(raw, (anchor_hit(raw),))
    assert result.valid_inner_fragment_count == 0
    assert ("curve_invalid", 1) in result.evidence["rejection_counts"]


@pytest.mark.parametrize(
    "private_bytes",
    (bytes(32), GROUP_ORDER.to_bytes(32, "big")),
)
def test_invalid_scalar_is_rejected(private_bytes):
    fragment = inner(private_der(1, private_bytes=private_bytes))
    result, _ = run(fragment, (anchor_hit(fragment),))
    assert result.valid_inner_fragment_count == 0
    assert ("private_scalar_invalid", 1) in result.evidence["rejection_counts"]


def test_truncated_fragment_is_controlled_and_range_bounded():
    fragment = inner(private_der(1))[:-20]
    result, reader = run(fragment, (anchor_hit(fragment),))
    assert result.valid_inner_fragment_count == 0
    assert all(
        offset >= 0
        and length <= MAX_ORPHAN_DER_READ_SIZE
        and offset + length <= len(fragment)
        for offset, length in reader.calls
    )


def test_exact_inner_end_excludes_trailing_noise():
    fragment = inner(private_der(1))
    data = fragment + b"\x00" * 300
    result, _ = run(data, (anchor_hit(data),))
    assert result.valid_inner_fragment_count == 1
    assert result.locations[0].recovered_fragment_length == len(fragment)


def test_duplicate_anchor_is_deduplicated_and_copy_remains_distinct():
    fragment = inner(private_der(1))
    second_offset = len(fragment) + 50
    data = fragment + b"x" * 50 + fragment
    first = anchor_hit(data)
    second = anchor_hit(data, start=second_offset)
    result, _ = run(data, (first, first, second))
    assert result.raw_inner_anchor_count == 3
    assert result.candidate_inner_fragment_count == 2
    assert result.valid_inner_fragment_count == 2
    assert {item.absolute_anchor_offset for item in result.locations} == {
        0,
        second_offset,
    }


def test_full_image_integration_uses_existing_anchor_and_preserves_status(tmp_path):
    fragment = inner(private_der(1))
    source = tmp_path / "inner-private-key-fragment.img"
    source.write_bytes(b"noise" * 20 + fragment + b"tail")
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=64,
        cluster_gap=0,
        hotspot_padding=1024,
    ).scan(source)
    assert result.orphan_private_key_recovery.candidate_der_count == 0
    fragment_result = result.orphan_private_key_fragment_recovery
    assert fragment_result.raw_inner_anchor_count == 1
    assert fragment_result.valid_inner_fragment_count == 1
    assert result.status is ValidationStatus.REJECTED
