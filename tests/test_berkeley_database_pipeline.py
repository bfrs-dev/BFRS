from dataclasses import FrozenInstanceError, fields, is_dataclass

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.berkeley_database_pipeline import BerkeleyDatabaseRecoveryPipeline
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.berkeley_page import KEYDATA, PAGE_HEADER_SIZE


PAGE_SIZE = 512
PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")
PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)


def compact_size(value: int) -> bytes:
    if value < 253:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


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
        + tlv(0xA1, tlv(0x03, b"\x00" + encode_sec_public_key(scalar_multiply(scalar), compressed=False)))
    )
    return tlv(0x30, body)


def metadata(*, page_number: int = 0, valid: bool = True) -> bytes:
    page = bytearray(PAGE_SIZE)
    put = lambda offset, value: page.__setitem__(slice(offset, offset + 4), value.to_bytes(4, "little"))
    put(8, page_number)
    put(12, BTREE_MAGIC)
    put(16, 9 if valid else 8)
    put(20, PAGE_SIZE)
    page[25] = 9
    put(32, 1000)
    put(48, 0x20)
    put(88, 1)
    return bytes(page)


def raw_record(payload: bytes, *, deleted: bool = False) -> bytes:
    record_type = KEYDATA | (0x80 if deleted else 0)
    return len(payload).to_bytes(2, "little") + bytes((record_type,)) + payload


def leaf(
    page_number: int,
    payloads: tuple[bytes, ...],
    *,
    fragment: bool = False,
    deleted: bool = False,
) -> bytes:
    records = [raw_record(payload, deleted=deleted) for payload in payloads]
    page = bytearray(PAGE_SIZE)
    slots: list[int] = []
    if fragment:
        cursor = 64
        for item in records:
            slots.append(cursor)
            page[cursor : cursor + len(item)] = item
            cursor += len(item)
        end = cursor
    else:
        cursor = PAGE_SIZE
        for item in records:
            cursor -= len(item)
            page[cursor : cursor + len(item)] = item
            slots.append(cursor)
        end = PAGE_SIZE
    page[8:12] = page_number.to_bytes(4, "little")
    page[20:22] = len(records).to_bytes(2, "little")
    page[22:24] = min(slots, default=PAGE_SIZE).to_bytes(2, "little")
    page[24] = 1
    page[25] = 5
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + 2 * index
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page[:end])


def plain_pair(*, scalar: int = 1, key_scalar: int | None = None) -> tuple[bytes, bytes]:
    public_key = encode_sec_public_key(
        scalar_multiply(scalar if key_scalar is None else key_scalar),
        compressed=False,
    )
    return string("key") + vector(public_key), vector(private_der(scalar))


def ckey_pair() -> tuple[bytes, bytes]:
    return string("ckey") + vector(PUBLIC_KEY), vector(bytes(range(48)))


def mkey_pair() -> tuple[bytes, bytes]:
    value = vector(bytes(reversed(range(48)))) + vector(bytes(8))
    value += (0).to_bytes(4, "little") + (25_000).to_bytes(4, "little") + vector(b"")
    return string("mkey") + (1).to_bytes(4, "little"), value


def run(data: bytes):
    return BerkeleyDatabaseRecoveryPipeline().run(ValidationContext("image.img", 0, data))


def database(*pages: bytes) -> bytes:
    return metadata() + b"".join(pages)


def sparse_database(pages: dict[int, bytes]) -> bytes:
    end = max(
        (page_number * PAGE_SIZE + len(page) for page_number, page in pages.items()),
        default=PAGE_SIZE,
    )
    data = bytearray(max(PAGE_SIZE, end))
    data[:PAGE_SIZE] = metadata()
    for page_number, page in pages.items():
        start = page_number * PAGE_SIZE
        data[start : start + len(page)] = page
    return bytes(data)


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if is_dataclass(value) and not isinstance(value, type):
        return any(contains_bytes(getattr(value, field.name)) for field in fields(value))
    if isinstance(value, dict):
        return any(contains_bytes(key) or contains_bytes(item) for key, item in value.items())
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(contains_bytes(item) for item in value)
    return False


def test_magic_and_record_names_without_valid_metadata_are_rejected() -> None:
    result = run(metadata(valid=False) + b"ckey mkey")
    assert result.status is ValidationStatus.REJECTED
    assert result.summary.anchor_count == 0
    assert result.summary.valid_plaintext_key_count == 0
    assert result.summary.encrypted_structural_database_count == 0


def test_valid_metadata_and_garbage_page_do_not_become_wallet_evidence() -> None:
    result = run(database(bytes(PAGE_SIZE)))
    assert result.summary.anchor_count == 1
    assert result.summary.page_rejected_count == 1
    assert result.status is ValidationStatus.REJECTED


def test_scalar_one_plaintext_key_is_structural_and_secret_free() -> None:
    key, value = plain_pair()
    result = run(database(leaf(1, (key, value))))
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.summary.valid_plaintext_key_count == 1
    assert result.summary.structural_plaintext_key_count == 1
    assert contains_bytes(result) is False
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]


def test_scalar_one_der_with_scalar_two_pubkey_is_not_counted() -> None:
    key, value = plain_pair(key_scalar=2)
    result = run(database(leaf(1, (key, value))))
    assert result.summary.valid_plaintext_key_count == 0
    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("berkeley_only_evidence",)


def test_non_bitcoin_berkeley_pairs_are_diagnostic_only() -> None:
    result = run(database(leaf(1, (b"arbitrary key", b"arbitrary value"))))
    assert result.summary.record_pair_count == 1
    assert result.summary.valid_plaintext_key_count == 0
    assert result.summary.encrypted_structural_database_count == 0
    assert result.summary.encrypted_fragment_database_count == 0
    assert result.evidence["berkeley_only_evidence"] is True
    assert result.status is ValidationStatus.REJECTED


def test_literal_key_without_valid_plaintext_record_is_rejected() -> None:
    result = run(database(leaf(1, (string("key"), b"not a DER private key"))))
    assert result.summary.record_pair_count == 1
    assert result.summary.valid_plaintext_key_count == 0
    assert result.status is ValidationStatus.REJECTED


def test_deleted_complete_plaintext_key_remains_valid() -> None:
    result = run(database(leaf(1, plain_pair(), deleted=True)))
    assert result.summary.valid_plaintext_key_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_valid_plaintext_key_from_fragment_page_stays_fragment() -> None:
    result = run(database(leaf(1, plain_pair(), fragment=True)))
    assert result.summary.fragment_plaintext_key_count == 1
    assert result.summary.structural_plaintext_key_count == 0
    assert result.status is ValidationStatus.FRAGMENT


def test_ckey_and_mkey_on_same_page_are_structural() -> None:
    result = run(database(leaf(1, ckey_pair() + mkey_pair())))
    assert result.summary.encrypted_structural_database_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_valid_ckey_without_mkey_makes_pipeline_fragment() -> None:
    result = run(database(leaf(1, ckey_pair())))
    assert result.summary.encrypted_fragment_database_count == 1
    assert result.summary.encrypted_structural_database_count == 0
    assert result.status is ValidationStatus.FRAGMENT


def test_structural_plaintext_key_is_not_downgraded_by_generic_pairs() -> None:
    result = run(
        database(
            leaf(1, plain_pair()),
            bytes(PAGE_SIZE),
            leaf(3, (b"generic", b"database value")),
        )
    )
    assert result.summary.valid_plaintext_key_count == 1
    assert result.summary.record_pair_count == 2
    assert result.summary.page_rejected_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_cross_page_ckey_and_mkey_form_one_database() -> None:
    result = run(
        sparse_database(
            {
                10: leaf(10, ckey_pair()),
                500: leaf(500, mkey_pair()),
            }
        )
    )
    assert result.summary.encrypted_database_count == 1
    assert result.summary.encrypted_structural_database_count == 1


def test_partial_overwrite_does_not_downgrade_encrypted_database() -> None:
    result = run(
        sparse_database(
            {
                10: leaf(10, ckey_pair()),
                11: bytes(PAGE_SIZE),
                12: leaf(12, mkey_pair()),
                13: leaf(13, ckey_pair(), fragment=True),
            }
        )
    )
    assert result.summary.page_rejected_count >= 1
    assert result.summary.encrypted_structural_database_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_two_anchors_do_not_cross_correlate_ckey_and_mkey() -> None:
    data = metadata() + leaf(1, ckey_pair()) + metadata() + leaf(1, mkey_pair())
    result = run(data)
    assert result.summary.anchor_count == 2
    assert result.summary.encrypted_database_count == 2
    assert result.summary.encrypted_fragment_database_count == 2
    assert result.summary.encrypted_structural_database_count == 0
    assert result.status is ValidationStatus.FRAGMENT


def test_fragment_metadata_never_creates_anchor() -> None:
    result = run(metadata()[:100])
    assert result.summary.metadata_fragment_count == 1
    assert result.summary.anchor_count == 0
    assert result.status is ValidationStatus.REJECTED


def test_pipeline_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: pytest.fail("file I/O"))
    assert run(database(leaf(1, plain_pair()))).status is ValidationStatus.STRUCTURAL
