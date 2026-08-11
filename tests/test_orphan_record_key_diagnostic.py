from dataclasses import FrozenInstanceError

import pytest

from bfrs.cli import BITCOIN_CORE_SIGNATURES_V1
from bfrs.core.models import RawHit, ValidationStatus
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    encode_sec_public_key,
)
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.orphan_record_key_diagnostic import (
    MAX_KEY_DIAGNOSTIC_BYTES,
    OrphanBitcoinRecordKeyDiagnosticPipeline,
)
from bfrs.validators.candidate_policy import CandidatePolicy


SOURCE = "diagnostic.img"


class MemoryRangeReader:
    def __init__(self, data: bytes, *, start: int = 0, end: int | None = None):
        self.data = data
        self.start = start
        self.end = len(data) if end is None else end
        self.calls: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        if offset < self.start or offset >= self.end:
            raise PhysicalRangeReadError("outside test range")
        return self.data[offset : min(offset + length, self.end)]


def vector(value: bytes, *, canonical: bool = True) -> bytes:
    if canonical and len(value) < 253:
        return bytes((len(value),)) + value
    return b"\xfd" + len(value).to_bytes(2, "little") + value


def framed(name: str, suffix: bytes, *, canonical: bool = True) -> bytes:
    encoded = name.encode("ascii")
    prefix = (
        bytes((len(encoded),))
        if canonical
        else b"\xfd" + len(encoded).to_bytes(2, "little")
    )
    return prefix + encoded + suffix


def hit(offset: int, length: int, hit_type: str) -> RawHit:
    return RawHit(offset, offset + length, hit_type, 0.0, SOURCE)


def run(
    data: bytes,
    hits: tuple[RawHit, ...],
    *,
    start: int = 0,
    end: int | None = None,
):
    range_end = len(data) if end is None else end
    reader = MemoryRangeReader(data, start=start, end=range_end)
    result = OrphanBitcoinRecordKeyDiagnosticPipeline(
        hits,
        source=SOURCE,
        range_start=start,
        range_end=range_end,
        range_reader=reader,
    ).run()
    return result, reader


def test_false_framed_key_with_random_suffix_is_invalid():
    data = b"\x03key" + b"random bytes"
    result, _ = run(data, (hit(0, 4, "bitcoin_key"),))
    assert result.raw_strong_hit_count == 1
    assert result.valid_record_key_count == 0
    assert result.valid_key_count == 0


def test_valid_compressed_key_side_is_diagnostic_only():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    data = framed("key", vector(public_key)) + b"trailing page bytes"
    result, _ = run(data, (hit(0, 4, "bitcoin_key"),))
    assert result.valid_key_count == 1
    assert result.canonical_framing_count == 1
    assert result.locations[0].absolute_offset == 0
    with pytest.raises(FrozenInstanceError):
        result.valid_key_count = 2


def test_valid_uncompressed_key_side_is_accepted():
    public_key = encode_sec_public_key(GENERATOR, compressed=False)
    data = framed("key", vector(public_key))
    result, _ = run(data, (hit(0, 4, "bitcoin_key"),))
    assert result.valid_key_count == 1


def test_sec_looking_invalid_curve_point_is_rejected():
    invalid = b"\x02" + FIELD_PRIME.to_bytes(32, "big")
    data = framed("key", vector(invalid))
    result, _ = run(data, (hit(0, 4, "bitcoin_key"),))
    assert result.valid_key_count == 0


def test_truncated_public_key_vector_is_controlled_invalid():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    data = framed("key", bytes((len(public_key),)) + public_key[:10])
    result, _ = run(data, (hit(0, 4, "bitcoin_key"),))
    assert result.valid_key_count == 0


def test_reader_compatible_noncanonical_framing_is_counted_separately():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    data = framed("key", vector(public_key, canonical=False), canonical=False)
    result, _ = run(data, (hit(0, 6, "bitcoin_key"),))
    assert result.valid_key_count == 1
    assert result.canonical_framing_count == 0
    assert result.noncanonical_framing_count == 1


def test_ckey_and_mkey_keyside_do_not_require_values():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    ckey = framed("ckey", vector(public_key))
    mkey_offset = len(ckey) + 20
    data = ckey + b"x" * 20 + framed("mkey", (7).to_bytes(4, "little"))
    hits = (
        hit(0, 5, "bitcoin_ckey"),
        hit(mkey_offset, 5, "bitcoin_mkey"),
    )
    result, _ = run(data, hits)
    assert result.valid_ckey_keyside_count == 1
    assert result.valid_mkey_keyside_count == 1
    assert result.locations[1].master_key_id == 7


def test_signature_label_must_match_decoded_record_type():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    data = framed("ckey", vector(public_key))
    result, _ = run(data, (hit(0, 5, "bitcoin_key"),))
    assert result.valid_record_key_count == 0
    assert result.evidence["record_type_mismatch_count"] == 1


def test_duplicate_hit_is_counted_once_and_read_is_bounded():
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    data = framed("key", vector(public_key)) + b"z" * 400
    repeated = hit(0, 4, "bitcoin_key")
    result, reader = run(data, (repeated, repeated))
    assert result.raw_strong_hit_count == 2
    assert result.valid_key_count == 1
    assert len(result.locations) == 1
    assert all(length <= MAX_KEY_DIAGNOSTIC_BYTES for _, length in reader.calls)


def test_range_end_produces_short_controlled_read_without_escape():
    data = b"x" * 20 + b"\x03key\x21\x02"
    range_start = 20
    result, reader = run(
        data,
        (hit(20, 4, "bitcoin_key"),),
        start=range_start,
        end=len(data),
    )
    assert result.valid_key_count == 0
    assert all(
        range_start <= offset and offset + length <= len(data)
        for offset, length in reader.calls
    )


def test_coordinator_exposes_diagnostic_without_changing_wallet_status(tmp_path):
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    source = tmp_path / "orphan-keyside.img"
    source.write_bytes(b"x" * 100 + framed("key", vector(public_key)))
    result = FullImageRecoveryCoordinator(
        BITCOIN_CORE_SIGNATURES_V1,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_size=64,
        cluster_gap=0,
        hotspot_padding=256,
    ).scan(source)
    assert result.orphan_record_key_diagnostic.valid_key_count == 1
    assert result.metadata_less_fragment_recovery.valid_plaintext_key_count == 0
    assert result.status is ValidationStatus.REJECTED
