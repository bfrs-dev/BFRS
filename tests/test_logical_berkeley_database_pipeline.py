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
from bfrs.recovery.logical_berkeley_database_pipeline import (
    LogicalBerkeleyDatabaseRecoveryPipeline,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.logical_page_map import (
    LogicalBerkeleyPageMap,
    LogicalPageLocation,
)
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.berkeley_page import (
    BTREE_INTERNAL,
    BTREE_LEAF,
    KEYDATA,
    PAGE_HEADER_SIZE,
)


PAGE_SIZE = 512
SOURCE = r"E:\images\fragmented-wallet.img"
LOGICAL_FILE_ID = "mft:42:$DATA"
TWO_GIB = 2 * 1024**3
THREE_GIB = 3 * 1024**3
FORTY_GIB = 40 * 1024**3
FORTY_FOUR_GIB = 44 * 1024**3
PRIME_FIELD_OID = bytes.fromhex("2A8648CE3D0101")
PUBLIC_KEY = encode_sec_public_key(GENERATOR, compressed=False)


class MemoryRangeReader:
    def __init__(self, ranges: dict[int, bytes]) -> None:
        self.ranges = ranges
        self.calls: list[tuple[int, int]] = []

    def read_at(self, offset: int, length: int) -> bytes:
        self.calls.append((offset, length))
        try:
            return self.ranges[offset][:length]
        except KeyError as exc:
            raise PhysicalRangeReadError("missing test range") from exc


def compact_size(value: int, *, canonical: bool = True) -> bytes:
    if canonical and value < 253:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


def vector(value: bytes, *, canonical: bool = True) -> bytes:
    return compact_size(len(value), canonical=canonical) + value


def string(value: str, *, canonical: bool = True) -> bytes:
    return vector(value.encode("ascii"), canonical=canonical)


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
                + encode_sec_public_key(
                    scalar_multiply(scalar), compressed=False
                ),
            ),
        )
    )
    return tlv(0x30, body)


def metadata(page_number: int, root: int) -> bytes:
    page = bytearray(PAGE_SIZE)

    def put(offset: int, value: int) -> None:
        page[offset : offset + 4] = value.to_bytes(4, "little")

    put(8, page_number)
    put(12, BTREE_MAGIC)
    put(16, 9)
    put(20, PAGE_SIZE)
    page[25] = 9
    put(32, max(page_number, root) + 1000)
    put(48, 0x20)
    put(88, root)
    return bytes(page)


def raw_record(payload: bytes, *, deleted: bool = False) -> bytes:
    record_type = KEYDATA | (0x80 if deleted else 0)
    return len(payload).to_bytes(2, "little") + bytes((record_type,)) + payload


def internal_record(child: int, key: bytes = b"k") -> bytes:
    return (
        len(key).to_bytes(2, "little")
        + bytes((KEYDATA, 0))
        + child.to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + key
    )


def data_page(
    page_number: int,
    *,
    level: int,
    page_type: int,
    records: tuple[bytes, ...] = (),
    fragment: bool = False,
) -> bytes:
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
    page[24] = level
    page[25] = page_type
    for index, slot in enumerate(slots):
        start = PAGE_HEADER_SIZE + 2 * index
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page[:end])


def internal(page_number: int, level: int, *children: int) -> bytes:
    return data_page(
        page_number,
        level=level,
        page_type=BTREE_INTERNAL,
        records=tuple(internal_record(child) for child in children),
    )


def leaf(
    page_number: int,
    payloads: tuple[bytes, ...],
    *,
    fragment: bool = False,
    deleted: bool = False,
) -> bytes:
    return data_page(
        page_number,
        level=1,
        page_type=BTREE_LEAF,
        records=tuple(
            raw_record(payload, deleted=deleted) for payload in payloads
        ),
        fragment=fragment,
    )


def plain_pair(
    *,
    scalar: int = 1,
    key_scalar: int | None = None,
    canonical: bool = True,
) -> tuple[bytes, bytes]:
    public_key = encode_sec_public_key(
        scalar_multiply(scalar if key_scalar is None else key_scalar),
        compressed=False,
    )
    return (
        string("key", canonical=canonical)
        + vector(public_key, canonical=canonical),
        vector(private_der(scalar), canonical=canonical),
    )


def ckey_pair() -> tuple[bytes, bytes]:
    return string("ckey") + vector(PUBLIC_KEY), vector(bytes(range(48)))


def mkey_pair() -> tuple[bytes, bytes]:
    value = vector(bytes(reversed(range(48)))) + vector(bytes(8))
    value += (
        (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
        + vector(b"")
    )
    return string("mkey") + (1).to_bytes(4, "little"), value


def make_pipeline(
    logical_to_physical: dict[int, int],
    pages: dict[int, bytes],
) -> tuple[LogicalBerkeleyDatabaseRecoveryPipeline, MemoryRangeReader]:
    page_map = LogicalBerkeleyPageMap(
        SOURCE,
        PAGE_SIZE,
        "little",
        (
            LogicalPageLocation(number, offset, PAGE_SIZE, SOURCE)
            for number, offset in logical_to_physical.items()
        ),
    )
    reader = MemoryRangeReader(
        {logical_to_physical[number]: data for number, data in pages.items()}
    )
    return (
        LogicalBerkeleyDatabaseRecoveryPipeline(
            page_map,
            logical_file_id=LOGICAL_FILE_ID,
            range_reader=reader,
        ),
        reader,
    )


def run(
    logical_to_physical: dict[int, int],
    pages: dict[int, bytes],
):
    pipeline, _ = make_pipeline(logical_to_physical, pages)
    return pipeline.run()


def test_fragmented_encrypted_wallet_is_structural() -> None:
    mappings = {5: 500_000, 10: 1_000_000, 20: TWO_GIB, 900: FORTY_FOUR_GIB}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20, 900),
            20: leaf(20, ckey_pair()),
            900: leaf(900, mkey_pair()),
        },
    )
    candidate = result.wallet_candidate_reports[0]
    assert candidate["priority"] == "HIGH"
    assert candidate["encryption_state"] == "ENCRYPTED_COMPLETE_EVIDENCE"

    subdatabase = result.subdatabases[0]
    assert subdatabase.status is ValidationStatus.STRUCTURAL
    assert result.status is ValidationStatus.STRUCTURAL
    assert subdatabase.encrypted_wallet_evidence.valid_ckey_count == 1
    assert subdatabase.encrypted_wallet_evidence.valid_mkey_count == 1
    assert subdatabase.identity.metadata_page_number == 5
    assert subdatabase.identity.root_page_number == 10


def test_reversed_physical_order_remains_structural() -> None:
    mappings = {5: 500_000, 10: 1_000_000, 20: FORTY_GIB, 900: THREE_GIB}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20, 900),
            20: leaf(20, ckey_pair()),
            900: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.subdatabases[0].status is ValidationStatus.STRUCTURAL


def test_orphan_ckey_cannot_join_reachable_mkey() -> None:
    mappings = {5: 500, 10: 1_000, 100: 2_000, 500: 3_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 100),
            100: leaf(100, mkey_pair()),
            500: leaf(500, ckey_pair()),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.status is ValidationStatus.FRAGMENT
    assert subdatabase.record_pair_count == 1
    assert subdatabase.encrypted_wallet_evidence.valid_ckey_count == 0
    assert subdatabase.encrypted_wallet_evidence.valid_mkey_count == 1


def test_two_subdatabases_never_cross_correlate() -> None:
    mappings = {
        5: 500,
        6: 600,
        10: 1_000,
        20: 2_000,
        100: 10_000,
        200: 20_000,
    }
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            6: metadata(6, 100),
            10: internal(10, 2, 20),
            20: leaf(20, ckey_pair()),
            100: internal(100, 2, 200),
            200: leaf(200, mkey_pair()),
        },
    )

    assert tuple(item.status for item in result.subdatabases) == (
        ValidationStatus.FRAGMENT,
        ValidationStatus.FRAGMENT,
    )
    assert result.status is ValidationStatus.FRAGMENT
    assert result.structural_subdatabase_count == 0


def test_structural_plaintext_key_is_structural() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair()),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.valid_plaintext_key_count == 1
    assert subdatabase.structural_plaintext_key_count == 1
    assert subdatabase.status is ValidationStatus.STRUCTURAL
    assert result.status is ValidationStatus.STRUCTURAL
    assert result.logical_records_examined == 1
    assert result.wallet_records_valid == 1
    candidate = result.wallet_candidate_reports[0]
    assert candidate["priority"] == "CRITICAL"
    assert candidate["crypto_summary"]["crypto_valid_plain_keys"] == 1
    assert candidate["provenance"][0]["source"] == SOURCE.lower()


def test_malformed_record_does_not_abort_valid_candidate() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(
                20,
                (
                    *plain_pair(),
                    string("version"),
                    b"\x01",
                ),
            ),
        },
    )

    assert result.logical_records_examined == 2
    assert result.wallet_records_valid == 1
    assert result.wallet_records_partial == 1
    assert result.wallet_candidate_reports[0]["priority"] == "CRITICAL"


def test_fragment_plaintext_key_stays_fragment() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair(), fragment=True),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.membership_status is ValidationStatus.FRAGMENT
    assert subdatabase.fragment_plaintext_key_count == 1
    assert subdatabase.structural_plaintext_key_count == 0
    assert subdatabase.status is ValidationStatus.FRAGMENT
    assert result.status is ValidationStatus.FRAGMENT


def test_deleted_plaintext_key_remains_structural() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair(), deleted=True),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.status is ValidationStatus.STRUCTURAL
    assert subdatabase.deleted_plaintext_key_count == 1


def test_wrong_plaintext_key_is_not_counted() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair(scalar=1, key_scalar=2)),
        },
    )

    assert result.subdatabases[0].valid_plaintext_key_count == 0
    assert result.subdatabases[0].status is ValidationStatus.REJECTED
    assert result.status is ValidationStatus.REJECTED


def test_generic_berkeley_tree_is_rejected() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, (b"arbitrary key", b"arbitrary value")),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.record_pair_count == 1
    assert subdatabase.status is ValidationStatus.REJECTED
    assert subdatabase.reasons == ("berkeley_only_evidence",)
    assert result.status is ValidationStatus.REJECTED


def test_missing_branch_caps_encrypted_wallet_at_fragment() -> None:
    mappings = {5: 500, 10: 1_000, 20: TWO_GIB, 900: FORTY_FOUR_GIB}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20, 30, 900),
            20: leaf(20, ckey_pair()),
            900: leaf(900, mkey_pair()),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.membership_status is ValidationStatus.FRAGMENT
    assert subdatabase.encrypted_wallet_evidence.valid_ckey_count == 1
    assert subdatabase.encrypted_wallet_evidence.valid_mkey_count == 1
    assert subdatabase.status is ValidationStatus.FRAGMENT
    assert result.status is ValidationStatus.FRAGMENT


def test_structural_subdatabase_is_not_downgraded_by_generic_subdatabase() -> None:
    mappings = {
        5: 500,
        6: 600,
        10: 1_000,
        20: 2_000,
        21: 2_100,
        100: 10_000,
        200: 20_000,
    }
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            6: metadata(6, 100),
            10: internal(10, 2, 20, 21),
            20: leaf(20, ckey_pair()),
            21: leaf(21, mkey_pair()),
            100: internal(100, 2, 200),
            200: leaf(200, (b"generic", b"value")),
        },
    )

    assert result.structural_subdatabase_count == 1
    assert result.rejected_subdatabase_count == 1
    assert result.status is ValidationStatus.STRUCTURAL


def test_fragment_metadata_is_diagnostic_and_creates_no_subdatabase() -> None:
    full_metadata = metadata(5, 10)
    result = run({5: 500}, {5: full_metadata[:100]})

    assert result.metadata_fragment_count == 1
    assert result.metadata_structural_count == 0
    assert result.subdatabases == ()
    assert result.status is ValidationStatus.REJECTED


def test_rejected_membership_does_not_extract_leaf_records() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 3, 20),
            20: leaf(20, plain_pair()),
        },
    )

    subdatabase = result.subdatabases[0]
    assert subdatabase.membership_status is ValidationStatus.REJECTED
    assert subdatabase.record_pair_count == 0
    assert subdatabase.valid_plaintext_key_count == 0
    assert subdatabase.status is ValidationStatus.REJECTED


def test_public_result_is_immutable_and_contains_no_raw_secrets() -> None:
    mappings = {5: 500, 10: 1_000, 20: 2_000}
    result = run(
        mappings,
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair()),
        },
    )

    assert not contains_bytes(result)
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]


def test_pipeline_performs_no_direct_file_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, _ = make_pipeline(
        {5: 500, 10: 1_000, 20: 2_000},
        {
            5: metadata(5, 10),
            10: internal(10, 2, 20),
            20: leaf(20, plain_pair()),
        },
    )
    monkeypatch.setattr(
        "builtins.open",
        lambda *args, **kwargs: pytest.fail("direct file I/O"),
    )

    assert pipeline.run().status is ValidationStatus.STRUCTURAL


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if is_dataclass(value) and not isinstance(value, type):
        return any(
            contains_bytes(getattr(value, field.name)) for field in fields(value)
        )
    if isinstance(value, dict):
        return any(
            contains_bytes(key) or contains_bytes(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(contains_bytes(item) for item in value)
    return False
