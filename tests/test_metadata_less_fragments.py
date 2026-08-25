from dataclasses import FrozenInstanceError

import pytest

from bfrs.core.models import RawHit, ValidationStatus
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.metadata_less_fragments import (
    MetadataLessBerkeleyFragmentRecoveryPipeline,
)
from bfrs.validators.berkeley_page import BTREE_LEAF, KEYDATA, PAGE_HEADER_SIZE


PAGE_SIZE = 512
SOURCE = "orphan-image.img"
PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)
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
            raise PhysicalRangeReadError("outside allowed range")
        return self.data[offset : min(offset + length, self.end)]


def compact_size(value: int) -> bytes:
    return bytes((value,)) if value < 253 else b"\xfd" + value.to_bytes(2, "little")


def vector(value: bytes) -> bytes:
    return compact_size(len(value)) + value


def string(value: str) -> bytes:
    return vector(value.encode("ascii"))


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


def private_der(scalar: int) -> bytes:
    field = tlv(0x30, tlv(0x06, PRIME_FIELD_OID) + integer(FIELD_PRIME))
    curve = tlv(0x30, tlv(0x04, b"\x00") + tlv(0x04, b"\x07"))
    parameters = tlv(
        0x30,
        integer(1)
        + field
        + curve
        + tlv(0x04, PUBLIC_KEY)
        + integer(GROUP_ORDER)
        + integer(1),
    )
    body = (
        integer(1)
        + tlv(0x04, scalar.to_bytes(32, "big"))
        + tlv(0xA0, parameters)
        + tlv(
            0xA1,
            tlv(
                0x03,
                b"\x00"
                + encode_sec_public_key(scalar_multiply(scalar), compressed=False),
            ),
        )
    )
    return tlv(0x30, body)


def ckey_pair() -> tuple[bytes, bytes]:
    return string("ckey") + vector(PUBLIC_KEY), vector(bytes(range(48)))


def mkey_pair() -> tuple[bytes, bytes]:
    value = vector(bytes(reversed(range(48)))) + vector(bytes(8))
    value += (0).to_bytes(4, "little")
    value += (25_000).to_bytes(4, "little") + vector(b"")
    return string("mkey") + (1).to_bytes(4, "little"), value


def plain_pair(*, scalar: int = 1, public_scalar: int = 1) -> tuple[bytes, bytes]:
    public = encode_sec_public_key(scalar_multiply(public_scalar), compressed=False)
    return string("key") + vector(public), vector(private_der(scalar))


def raw_record(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "little") + bytes((KEYDATA,)) + payload


def leaf(
    page_number: int,
    payloads: tuple[bytes, ...],
    *,
    fragment: bool = False,
) -> bytes:
    records = tuple(raw_record(payload) for payload in payloads)
    page = bytearray(PAGE_SIZE)
    slots: list[int] = []
    if fragment:
        cursor = 64
        for record in records:
            slots.append(cursor)
            page[cursor : cursor + len(record)] = record
            cursor += len(record)
        end = cursor
    else:
        cursor = PAGE_SIZE
        for record in records:
            cursor -= len(record)
            page[cursor : cursor + len(record)] = record
            slots.append(cursor)
        end = PAGE_SIZE
    page[8:12] = page_number.to_bytes(4, "little")
    page[20:22] = len(records).to_bytes(2, "little")
    page[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, "little")
    page[24] = 1
    page[25] = BTREE_LEAF
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + 2 * index
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page[:end])


def image_with_page(page: bytes, offset: int = 123, suffix: bytes = b"") -> bytes:
    result = bytearray(offset + len(page) + len(suffix))
    result[offset : offset + len(page)] = page
    result[offset + len(page) :] = suffix
    return bytes(result)


def hit_for(data: bytes, name: str, pattern: bytes) -> RawHit:
    offset = data.index(pattern)
    return RawHit(offset, offset + len(pattern), name, 0.0, SOURCE)


def run(data: bytes, hits: tuple[RawHit, ...], *, start: int = 0, end: int | None = None):
    range_end = len(data) if end is None else end
    reader = MemoryRangeReader(data, start=start, end=range_end)
    result = MetadataLessBerkeleyFragmentRecoveryPipeline(
        hits,
        source=SOURCE,
        range_start=start,
        range_end=range_end,
        range_reader=reader,
    ).run()
    return result, reader


def test_valid_unaligned_orphan_ckey_is_fragment():
    data = image_with_page(leaf(20, ckey_pair()))
    result, _ = run(data, (hit_for(data, "bitcoin_ckey", b"\x04ckey"),))
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 0
    assert any(item.physical_offset == 123 for item in result.page_locations)
    assert result.evidence["candidate_page_starts_tested"] < 20


def test_valid_orphan_mkey_is_fragment():
    data = image_with_page(leaf(900, mkey_pair()))
    result, _ = run(data, (hit_for(data, "bitcoin_mkey", b"\x04mkey"),))
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_mkey_count == 1


def test_valid_orphan_plaintext_key_is_fragment_and_immutable():
    data = image_with_page(leaf(7, plain_pair()))
    result, _ = run(data, (hit_for(data, "bitcoin_key", b"\x03key"),))
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_plaintext_key_count == 1
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.STRUCTURAL


def test_wrong_plaintext_public_key_is_rejected():
    data = image_with_page(leaf(7, plain_pair(scalar=1, public_scalar=2)))
    result, _ = run(data, (hit_for(data, "bitcoin_key", b"\x03key"),))
    assert result.status is ValidationStatus.REJECTED
    assert result.valid_plaintext_key_count == 0


def test_random_framed_ckey_is_rejected():
    data = b"random\x04ckeybytes"
    result, _ = run(data, (hit_for(data, "bitcoin_ckey", b"\x04ckey"),))
    assert result.status is ValidationStatus.REJECTED
    assert result.candidate_page_count == 0


def test_generic_structural_leaf_near_unrelated_hit_is_rejected():
    generic = leaf(3, (b"generic", b"value"))
    data = image_with_page(generic, suffix=b"padding\x04ckey")
    result, _ = run(data, (hit_for(data, "bitcoin_ckey", b"\x04ckey"),))
    assert result.status is ValidationStatus.REJECTED
    assert result.valid_ckey_count == 0


@pytest.mark.parametrize("container_marker", [b"MZ\x90\x00", b"PK\x03\x04", b"Adobe"])
def test_empty_leaf_shape_in_unrelated_binary_context_is_insufficient(container_marker):
    empty = leaf(3, ())
    data = container_marker + image_with_page(
        empty, suffix=b"unrelated-padding\x04ckey-not-a-record"
    )
    result, _ = run(data, (hit_for(data, "bitcoin_ckey", b"\x04ckey"),))

    assert result.status is ValidationStatus.REJECTED
    assert result.candidate_page_count == 0
    assert result.structural_leaf_count == 0
    assert result.record_pair_count == 0
    assert "metadata_less_empty_leaf_without_independent_evidence" in result.reasons
    assert result.evidence["empty_leaf_rejection_count"] > 0


def test_hit_must_be_inside_recovered_key_record():
    valid_page = leaf(20, ckey_pair())
    data = image_with_page(valid_page, suffix=b"\x04ckey")
    outside_offset = len(data) - len(b"\x04ckey")
    outside = RawHit(
        outside_offset,
        len(data),
        "bitcoin_ckey",
        0.0,
        SOURCE,
    )
    result, _ = run(data, (outside,))
    assert result.status is ValidationStatus.REJECTED
    assert result.valid_ckey_count == 0


def test_duplicate_hits_do_not_duplicate_page_or_record_evidence():
    data = image_with_page(leaf(20, ckey_pair()))
    hit = hit_for(data, "bitcoin_ckey", b"\x04ckey")
    result, _ = run(data, (hit, hit))
    assert result.candidate_page_count == 1
    assert result.valid_ckey_count == 1
    assert len(result.record_locations) == 1
    physical_pages = {item.physical_offset for item in result.page_locations}
    assert physical_pages == {123}


def test_distant_orphan_ckey_and_mkey_are_not_promoted_or_correlated():
    first_offset = 123
    second_offset = 8192
    first_page = leaf(20, ckey_pair())
    second_page = leaf(900, mkey_pair())
    data = bytearray(second_offset + len(second_page))
    data[first_offset : first_offset + len(first_page)] = first_page
    data[second_offset : second_offset + len(second_page)] = second_page
    raw = bytes(data)
    hits = (
        hit_for(raw, "bitcoin_ckey", b"\x04ckey"),
        hit_for(raw, "bitcoin_mkey", b"\x04mkey"),
    )
    result, _ = run(raw, hits)
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 1
    assert result.candidate_page_count == 2
    assert {item.physical_page_offset for item in result.record_locations} == {
        first_offset,
        second_offset,
    }


def test_fragment_leaf_with_complete_pair_can_recover_ckey():
    data = image_with_page(leaf(20, ckey_pair(), fragment=True))
    result, _ = run(data, (hit_for(data, "bitcoin_ckey", b"\x04ckey"),))
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.fragment_leaf_count >= 1


def test_range_never_reads_before_start_or_after_end():
    page_offset = 123
    page = leaf(20, ckey_pair())
    data = image_with_page(page)
    hit = hit_for(data, "bitcoin_ckey", b"\x04ckey")
    range_start = page_offset + 100
    result, reader = run(data, (hit,), start=range_start, end=len(data))
    assert result.status is ValidationStatus.REJECTED
    assert all(
        range_start <= offset and offset + length <= len(data)
        for offset, length in reader.calls
    )
