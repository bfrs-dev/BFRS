from dataclasses import FrozenInstanceError, fields, is_dataclass, replace

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.core.secp256k1 import (
    FIELD_PRIME,
    GENERATOR,
    GROUP_ORDER,
    encode_sec_public_key,
    scalar_multiply,
)
from bfrs.recovery.fragmented_berkeley_reassembler import (
    ReconstructedBerkeleyDatabase,
    ReconstructedBerkeleyDatabaseIdentity,
    ReconstructedBerkeleyPage,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.reconstructed_wallet_pipeline import (
    ReconstructedBerkeleyWalletPipeline,
)
from bfrs.validators.berkeley_page import (
    BTREE_LEAF,
    KEYDATA,
    PAGE_HEADER_SIZE,
)


PAGE_SIZE = 512
SOURCE = r"E:\images\lost-wallet.img"
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


def ckey_pair(*, canonical: bool = True) -> tuple[bytes, bytes]:
    return (
        string("ckey", canonical=canonical)
        + vector(PUBLIC_KEY, canonical=canonical),
        vector(bytes(range(48)), canonical=canonical),
    )


def mkey_pair(*, canonical: bool = True) -> tuple[bytes, bytes]:
    value = vector(bytes(reversed(range(48))), canonical=canonical)
    value += vector(bytes(8), canonical=canonical)
    value += (
        (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
        + vector(b"", canonical=canonical)
    )
    return (
        string("mkey", canonical=canonical) + (1).to_bytes(4, "little"),
        value,
    )


def raw_record(payload: bytes, *, deleted: bool = False) -> bytes:
    raw_type = KEYDATA | (0x80 if deleted else 0)
    return len(payload).to_bytes(2, "little") + bytes((raw_type,)) + payload


def leaf(
    page_number: int,
    payloads: tuple[bytes, ...],
    *,
    fragment: bool = False,
    deleted: bool = False,
) -> bytes:
    records = tuple(raw_record(payload, deleted=deleted) for payload in payloads)
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
        start = PAGE_HEADER_SIZE + index * 2
        page[start : start + 2] = slot.to_bytes(2, "little")
    return bytes(page[:end])


def identity(
    *,
    metadata_offset: int = 500_000,
    metadata_page: int = 5,
    root_page: int = 10,
) -> ReconstructedBerkeleyDatabaseIdentity:
    return ReconstructedBerkeleyDatabaseIdentity(
        source=SOURCE,
        metadata_physical_offset=metadata_offset,
        metadata_page_number=metadata_page,
        root_page_number=root_page,
        page_size=PAGE_SIZE,
        byte_order="little",
    )


def selected_leaf(
    page_number: int,
    physical_offset: int,
    *,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
) -> ReconstructedBerkeleyPage:
    return ReconstructedBerkeleyPage(
        page_number=page_number,
        physical_offset=physical_offset,
        page_size=PAGE_SIZE,
        page_type=BTREE_LEAF,
        level=1,
        validation_status=status,
    )


def database(
    *pages: ReconstructedBerkeleyPage,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
    selected_identity: ReconstructedBerkeleyDatabaseIdentity | None = None,
    missing: tuple[int, ...] = (),
    ambiguous: tuple[int, ...] = (),
    rejected: tuple[int, ...] = (),
) -> ReconstructedBerkeleyDatabase:
    return ReconstructedBerkeleyDatabase(
        identity=selected_identity or identity(),
        status=status,
        selected_pages=tuple(pages),
        internal_page_numbers=(),
        leaf_page_numbers=tuple(sorted(page.page_number for page in pages)),
        missing_page_numbers=missing,
        ambiguous_page_numbers=ambiguous,
        rejected_page_numbers=rejected,
        confirmed_edge_count=len(pages),
        reasons=(),
        evidence={},
    )


def run(
    selected_database: ReconstructedBerkeleyDatabase,
    ranges: dict[int, bytes],
):
    reader = MemoryRangeReader(ranges)
    result = ReconstructedBerkeleyWalletPipeline(
        selected_database,
        range_reader=reader,
    ).run()
    return result, reader


def test_distant_selected_ckey_and_mkey_are_structural() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(900, FORTY_FOUR_GIB),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair()),
            FORTY_FOUR_GIB: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 1
    assert result.structural_ckey_count == 1
    assert result.structural_mkey_count == 1


def test_reversed_physical_order_remains_structural() -> None:
    selected_database = database(
        selected_leaf(20, FORTY_GIB),
        selected_leaf(900, THREE_GIB),
    )
    result, _ = run(
        selected_database,
        {
            FORTY_GIB: leaf(20, ckey_pair()),
            THREE_GIB: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL


def test_ambiguous_unselected_mkey_is_never_read() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        status=ValidationStatus.FRAGMENT,
        ambiguous=(900,),
    )
    result, reader = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair()),
            FORTY_FOUR_GIB: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 0
    assert reader.calls == [(TWO_GIB, PAGE_SIZE)]


def test_orphan_ckey_and_bait_page_are_never_read() -> None:
    selected_database = database(selected_leaf(100, THREE_GIB))
    result, reader = run(
        selected_database,
        {
            THREE_GIB: leaf(100, mkey_pair()),
            TWO_GIB: leaf(500, ckey_pair()),
        },
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 0
    assert result.valid_mkey_count == 1
    assert reader.calls == [(THREE_GIB, PAGE_SIZE)]


def test_two_reconstructed_identities_never_cross_correlate() -> None:
    database_a = database(
        selected_leaf(20, TWO_GIB),
        selected_identity=identity(metadata_offset=100_000, root_page=10),
    )
    database_b = database(
        selected_leaf(200, FORTY_FOUR_GIB),
        selected_identity=identity(
            metadata_offset=200_000,
            metadata_page=6,
            root_page=100,
        ),
    )

    result_a, _ = run(database_a, {TWO_GIB: leaf(20, ckey_pair())})
    result_b, _ = run(
        database_b,
        {FORTY_FOUR_GIB: leaf(200, mkey_pair())},
    )

    assert result_a.status is ValidationStatus.FRAGMENT
    assert result_b.status is ValidationStatus.FRAGMENT
    assert result_a.identity != result_b.identity


def test_valid_plaintext_key_is_structural() -> None:
    selected_database = database(selected_leaf(20, TWO_GIB))
    result, _ = run(
        selected_database,
        {TWO_GIB: leaf(20, plain_pair())},
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_plaintext_key_count == 1
    assert result.structural_plaintext_key_count == 1


def test_wrong_plaintext_key_is_rejected() -> None:
    selected_database = database(selected_leaf(20, TWO_GIB))
    result, _ = run(
        selected_database,
        {TWO_GIB: leaf(20, plain_pair(scalar=1, key_scalar=2))},
    )

    assert result.valid_plaintext_key_count == 0
    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("berkeley_only_evidence",)


def test_generic_berkeley_pair_is_not_wallet_evidence() -> None:
    selected_database = database(selected_leaf(20, TWO_GIB))
    result, _ = run(
        selected_database,
        {TWO_GIB: leaf(20, (b"generic key", b"generic value"))},
    )

    assert result.record_pair_count == 1
    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("berkeley_only_evidence",)


def test_reconstructed_fragment_caps_structural_ckey_mkey_pair() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(900, FORTY_FOUR_GIB),
        status=ValidationStatus.FRAGMENT,
        missing=(30,),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair()),
            FORTY_FOUR_GIB: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == result.valid_mkey_count == 1
    assert result.structural_ckey_count == result.structural_mkey_count == 0
    assert result.fragment_ckey_count == result.fragment_mkey_count == 1


def test_plaintext_in_fragment_reconstruction_stays_fragment() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        status=ValidationStatus.FRAGMENT,
        missing=(30,),
    )
    result, _ = run(
        selected_database,
        {TWO_GIB: leaf(20, plain_pair())},
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_plaintext_key_count == 1
    assert result.structural_plaintext_key_count == 0
    assert result.fragment_plaintext_key_count == 1


def test_extra_fragment_ckey_does_not_downgrade_structural_pair() -> None:
    fragment_offset = THREE_GIB + PAGE_SIZE
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(21, fragment_offset),
        selected_leaf(900, FORTY_FOUR_GIB),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair()),
            fragment_offset: leaf(21, ckey_pair(), fragment=True),
            FORTY_FOUR_GIB: leaf(900, mkey_pair()),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 2
    assert result.structural_ckey_count == 1
    assert result.fragment_ckey_count == 1
    assert result.structural_mkey_count == 1


def test_short_read_is_not_zero_filled_and_caps_record_at_fragment() -> None:
    selected_database = database(selected_leaf(20, TWO_GIB))
    short_page = leaf(20, ckey_pair(), fragment=True)
    result, _ = run(selected_database, {TWO_GIB: short_page})

    assert len(short_page) < PAGE_SIZE
    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.fragment_ckey_count == 1


def test_deleted_plaintext_ckey_and_mkey_remain_valid() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(21, THREE_GIB),
        selected_leaf(900, FORTY_FOUR_GIB),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, plain_pair(), deleted=True),
            THREE_GIB: leaf(21, ckey_pair(), deleted=True),
            FORTY_FOUR_GIB: leaf(900, mkey_pair(), deleted=True),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_plaintext_key_count == 1
    assert result.valid_ckey_count == result.valid_mkey_count == 1
    assert result.deleted_valid_record_count == 3


def test_noncanonical_historical_records_remain_valid() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(900, FORTY_FOUR_GIB),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair(canonical=False)),
            FORTY_FOUR_GIB: leaf(900, mkey_pair(canonical=False)),
        },
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["canonical_valid_record_count"] == 0
    assert result.evidence["noncanonical_valid_record_count"] == 2


def test_rejected_reconstruction_is_not_read() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        status=ValidationStatus.REJECTED,
    )
    result, reader = run(
        selected_database,
        {TWO_GIB: leaf(20, plain_pair())},
    )

    assert result.status is ValidationStatus.REJECTED
    assert result.valid_plaintext_key_count == 0
    assert reader.calls == []


def test_selected_page_size_contradiction_is_a_hard_error() -> None:
    page = replace(selected_leaf(20, TWO_GIB), page_size=PAGE_SIZE * 2)
    selected_database = database(page)

    with pytest.raises(ValueError, match="page_size"):
        run(selected_database, {TWO_GIB: leaf(20, ckey_pair())})


def test_public_result_is_immutable_and_contains_no_raw_secrets() -> None:
    selected_database = database(
        selected_leaf(20, TWO_GIB),
        selected_leaf(900, FORTY_FOUR_GIB),
    )
    result, _ = run(
        selected_database,
        {
            TWO_GIB: leaf(20, ckey_pair()),
            FORTY_FOUR_GIB: leaf(900, mkey_pair()),
        },
    )

    assert not contains_bytes(result)
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]


def test_pipeline_performs_no_direct_file_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "builtins.open",
        lambda *args, **kwargs: pytest.fail("direct file I/O"),
    )
    selected_database = database(selected_leaf(20, TWO_GIB))
    result, _ = run(
        selected_database,
        {TWO_GIB: leaf(20, plain_pair())},
    )
    assert result.status is ValidationStatus.STRUCTURAL


def contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if is_dataclass(value) and not isinstance(value, type):
        return any(
            contains_bytes(getattr(value, item.name)) for item in fields(value)
        )
    if isinstance(value, dict):
        return any(
            contains_bytes(key) or contains_bytes(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(contains_bytes(item) for item in value)
    return False
