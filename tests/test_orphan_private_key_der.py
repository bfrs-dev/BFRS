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
    OrphanHistoricalECPrivateKeyRecoveryPipeline,
)
from bfrs.validators.candidate_policy import CandidatePolicy


SOURCE = "orphan-der.img"
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
            raise PhysicalRangeReadError("outside DER test range")
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
    include_public_key: bool = True,
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
    )
    if include_public_key:
        content += tlv(0xA1, tlv(0x03, b"\x00" + embedded_public_key))
    return tlv(0x30, content)


def anchor_hit(data: bytes, *, start: int = 0) -> RawHit:
    offset = data.index(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR, start)
    return RawHit(
        offset,
        offset + len(HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR),
        HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
        0.0,
        SOURCE,
    )


def run(
    data: bytes,
    hits: tuple[RawHit, ...],
    *,
    start: int = 0,
    end: int | None = None,
):
    range_end = len(data) if end is None else end
    reader = MemoryRangeReader(data, start=start, end=range_end)
    result = OrphanHistoricalECPrivateKeyRecoveryPipeline(
        hits,
        source=SOURCE,
        range_start=start,
        range_end=range_end,
        range_reader=reader,
    ).run()
    return result, reader


def test_false_anchor_without_der_sequence_is_rejected():
    data = b"noise" + HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR + b"random"
    result, _ = run(data, (anchor_hit(data),))
    assert result.raw_der_anchor_count == 1
    assert result.valid_secp256k1_der_count == 0


@pytest.mark.parametrize("scalar", (1, 2))
def test_valid_historical_scalar_der_is_recovered(scalar):
    der = private_der(scalar)
    data = b"noise" + der + b"trailing-unrelated-bytes"
    result, _ = run(data, (anchor_hit(data),))
    assert result.candidate_der_count == 1
    assert result.valid_secp256k1_der_count == 1
    assert result.locations[0].absolute_der_offset == len(b"noise")
    assert result.locations[0].der_length == len(der)
    assert result.locations[0].public_key_encoding == "uncompressed"
    with pytest.raises(FrozenInstanceError):
        result.valid_secp256k1_der_count = 0


def test_compressed_historical_fixture_is_accepted_by_existing_parser():
    der = private_der(1, compressed=True)
    result, _ = run(der, (anchor_hit(der),))
    assert result.valid_secp256k1_der_count == 1
    assert result.locations[0].public_key_encoding == "compressed"


def test_wrong_explicit_curve_is_rejected():
    der = private_der(1, field_oid=bytes.fromhex("2A8648CE3D0102"))
    result, _ = run(der, (anchor_hit(der),))
    assert result.valid_secp256k1_der_count == 0
    assert ("curve_invalid", 1) in result.evidence["rejection_counts"]


def test_embedded_public_key_must_match_private_scalar():
    wrong = encode_sec_public_key(scalar_multiply(2), compressed=False)
    der = private_der(1, embedded_public_key=wrong)
    result, _ = run(der, (anchor_hit(der),))
    assert result.valid_secp256k1_der_count == 0
    assert ("embedded_public_key_mismatch", 1) in result.evidence[
        "rejection_counts"
    ]


@pytest.mark.parametrize(
    "private_bytes",
    (bytes(32), GROUP_ORDER.to_bytes(32, "big")),
)
def test_invalid_private_scalar_is_rejected(private_bytes):
    der = private_der(1, private_bytes=private_bytes)
    result, _ = run(der, (anchor_hit(der),))
    assert result.valid_secp256k1_der_count == 0
    assert ("private_scalar_invalid", 1) in result.evidence["rejection_counts"]


def test_missing_embedded_public_key_is_not_invented():
    der = private_der(1, include_public_key=False)
    result, _ = run(der, (anchor_hit(der),))
    assert result.valid_secp256k1_der_count == 0
    assert result.valid_without_embedded_pubkey_count == 0


def test_truncated_der_at_range_end_is_controlled_and_bounded():
    der = private_der(1)
    truncated = der[:-20]
    result, reader = run(truncated, (anchor_hit(truncated),))
    assert result.valid_secp256k1_der_count == 0
    assert all(
        offset >= 0
        and length <= MAX_ORPHAN_DER_READ_SIZE
        and offset + length <= len(truncated)
        for offset, length in reader.calls
    )


def test_declared_der_length_excludes_trailing_noise():
    der = private_der(1)
    data = der + b"\x00" * 200
    result, _ = run(data, (anchor_hit(data),))
    assert result.valid_secp256k1_der_count == 1
    assert result.locations[0].der_length == len(der)


def test_duplicate_anchor_is_deduplicated_but_physical_copy_is_not():
    der = private_der(1)
    second_offset = len(der) + 100
    data = der + b"x" * 100 + der
    first = anchor_hit(data)
    second = anchor_hit(data, start=second_offset)
    result, _ = run(data, (first, first, second))
    assert result.raw_der_anchor_count == 3
    assert result.candidate_der_count == 2
    assert result.valid_secp256k1_der_count == 2
    assert {item.absolute_der_offset for item in result.locations} == {
        0,
        second_offset,
    }


def test_full_image_integration_is_diagnostic_not_berkeley_structural(tmp_path):
    der = private_der(1)
    source = tmp_path / "orphan-private-key.img"
    source.write_bytes(b"noise" * 20 + der + b"tail")
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=64,
        cluster_gap=0,
        hotspot_padding=1024,
    ).scan(source)
    recovery = result.orphan_private_key_recovery
    assert recovery.raw_der_anchor_count == 1
    assert recovery.valid_secp256k1_der_count == 1
    assert result.status is ValidationStatus.REJECTED
    assert dict(result.evidence["raw_hit_counts_by_signature"])[
        HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE
    ] == 1
