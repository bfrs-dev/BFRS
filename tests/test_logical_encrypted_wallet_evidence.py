from dataclasses import FrozenInstanceError, replace

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyDatabaseIdentity
from bfrs.recovery.logical_btree_membership import (
    LogicalBerkeleySubdatabaseIdentity,
    LogicalBtreeMembership,
)
from bfrs.validators.logical_encrypted_wallet_evidence import (
    LogicalBerkeleyRecordPageContext,
    LogicalEncryptedWalletEvidenceCorrelator,
)


PAGE_SIZE = 512
SOURCE = r"E:\images\fragmented.img"
TWO_GIB = 2 * 1024**3
FORTY_FOUR_GIB = 44 * 1024**3
GENERATOR_X = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
GENERATOR_Y = bytes.fromhex(
    "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
)
PUBLIC_KEY = b"\x04" + GENERATOR_X + GENERATOR_Y
CRYPTED_SECRET = bytes(range(48))
ENCRYPTED_MASTER_KEY = bytes(reversed(range(48)))
SALT = bytes.fromhex("0011223344556677")


def compact_size(value: int, *, canonical: bool = True) -> bytes:
    if canonical:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


def serialized_string(value: str, *, canonical: bool = True) -> bytes:
    payload = value.encode("ascii")
    return compact_size(len(payload), canonical=canonical) + payload


def serialized_vector(payload: bytes, *, canonical: bool = True) -> bytes:
    return compact_size(len(payload), canonical=canonical) + payload


def subdatabase_identity(
    *,
    logical_file_id: str = "mft-42",
    metadata_page: int = 5,
    root_page: int = 10,
) -> LogicalBerkeleySubdatabaseIdentity:
    database = LogicalBerkeleyDatabaseIdentity(
        source=SOURCE,
        page_size=PAGE_SIZE,
        byte_order="little",
        logical_file_id=logical_file_id,
    )
    return LogicalBerkeleySubdatabaseIdentity(
        database=database,
        metadata_page_number=metadata_page,
        root_page_number=root_page,
        page_size=PAGE_SIZE,
        byte_order="little",
    )


def membership(
    identity: LogicalBerkeleySubdatabaseIdentity,
    *leaf_pages: int,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
    missing: tuple[int, ...] = (),
) -> LogicalBtreeMembership:
    return LogicalBtreeMembership(
        identity=identity,
        status=status,
        root_page_number=identity.root_page_number,
        reachable_page_numbers=tuple(sorted({identity.root_page_number, *leaf_pages})),
        internal_page_numbers=(identity.root_page_number,),
        leaf_page_numbers=tuple(sorted(leaf_pages)),
        overflow_page_numbers=(),
        missing_page_numbers=missing,
        rejected_page_numbers=(),
        confirmed_edge_count=len(leaf_pages),
        reasons=(),
        evidence={},
    )


def raw_record(
    payload: bytes,
    physical_offset: int,
    local_offset: int,
    slot_index: int,
    *,
    deleted: bool = False,
) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=local_offset,
        absolute_offset=physical_offset + local_offset,
        length=len(payload),
        record_type=1,
        deleted=deleted,
        payload=payload,
    )


def ckey_pair(
    physical_offset: int,
    *,
    canonical: bool = True,
    deleted: bool = False,
) -> BerkeleyLeafPair:
    key = serialized_string("ckey", canonical=canonical) + serialized_vector(
        PUBLIC_KEY, canonical=canonical
    )
    value = serialized_vector(CRYPTED_SECRET, canonical=canonical)
    return BerkeleyLeafPair(
        pair_index=50,
        key=raw_record(key, physical_offset, 50, 0, deleted=deleted),
        value=raw_record(value, physical_offset, 150, 1, deleted=deleted),
    )


def mkey_pair(
    physical_offset: int,
    *,
    master_key_id: int = 1,
    canonical: bool = True,
    deleted: bool = False,
) -> BerkeleyLeafPair:
    key = serialized_string("mkey", canonical=canonical) + master_key_id.to_bytes(
        4, "little"
    )
    value = (
        serialized_vector(ENCRYPTED_MASTER_KEY, canonical=canonical)
        + serialized_vector(SALT, canonical=canonical)
        + (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
        + serialized_vector(b"", canonical=canonical)
    )
    return BerkeleyLeafPair(
        pair_index=250,
        key=raw_record(key, physical_offset, 250, 0, deleted=deleted),
        value=raw_record(value, physical_offset, 350, 1, deleted=deleted),
    )


def page_context(
    identity: LogicalBerkeleySubdatabaseIdentity,
    page_number: int,
    physical_offset: int,
    *pairs: BerkeleyLeafPair,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
) -> LogicalBerkeleyRecordPageContext:
    records = tuple(record for pair in pairs for record in (pair.key, pair.value))
    extraction = BerkeleyRecordExtraction(
        page_number=page_number,
        page_status=status,
        records=records,
        pairs=tuple(pairs),
        complete_record_count=len(records),
        deleted_record_count=sum(record.deleted for record in records),
        incomplete_slot_count=0,
        reasons=(),
    )
    return LogicalBerkeleyRecordPageContext(
        identity=identity,
        source=SOURCE,
        page_number=page_number,
        physical_offset=physical_offset,
        page_size=PAGE_SIZE,
        page_status=status,
        extraction=extraction,
    )


def correlate(
    selected_membership: LogicalBtreeMembership,
    *contexts: LogicalBerkeleyRecordPageContext,
):
    return LogicalEncryptedWalletEvidenceCorrelator().correlate(
        contexts, membership=selected_membership
    )


def test_distant_fragmented_pages_form_structural_evidence() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.page_numbers == (20, 900)
    assert result.valid_ckey_count == result.valid_mkey_count == 1


def test_reversed_physical_order_does_not_change_result() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    contexts = (
        page_context(identity, 20, FORTY_FOUR_GIB, ckey_pair(FORTY_FOUR_GIB)),
        page_context(identity, 900, TWO_GIB, mkey_pair(TWO_GIB)),
    )

    assert correlate(selected_membership, *contexts) == correlate(
        selected_membership, *reversed(contexts)
    )


def test_orphan_record_page_is_a_hard_input_error() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 900)

    with pytest.raises(ValueError, match="reachable membership leaf"):
        correlate(
            selected_membership,
            page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
            page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
        )


def test_two_logical_subdatabase_identities_cannot_correlate() -> None:
    first = subdatabase_identity(metadata_page=5, root_page=10)
    second = subdatabase_identity(metadata_page=6, root_page=11)
    selected_membership = membership(first, 20, 900)

    with pytest.raises(ValueError, match="different logical Berkeley"):
        correlate(
            selected_membership,
            page_context(first, 20, TWO_GIB, ckey_pair(TWO_GIB)),
            page_context(second, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
        )


@pytest.mark.parametrize("missing", [(), (77,)])
def test_fragment_membership_caps_valid_pair_at_fragment(
    missing: tuple[int, ...],
) -> None:
    identity = subdatabase_identity()
    selected_membership = membership(
        identity, 20, 900, status=ValidationStatus.FRAGMENT, missing=missing
    )
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert "membership_fragment" in result.reasons


def test_extra_fragment_ckey_does_not_downgrade_structural_pair() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 21, 900)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
        page_context(
            identity,
            21,
            TWO_GIB + PAGE_SIZE,
            ckey_pair(TWO_GIB + PAGE_SIZE),
            status=ValidationStatus.FRAGMENT,
        ),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.structural_ckey_count == 1
    assert result.fragment_ckey_count == 1


def test_bad_physical_geometry_is_a_hard_input_error() -> None:
    identity = subdatabase_identity()
    pair = ckey_pair(TWO_GIB)
    bad_pair = replace(
        pair,
        value=replace(pair.value, absolute_offset=FORTY_FOUR_GIB),
    )

    with pytest.raises(ValueError, match="absolute_offset"):
        page_context(identity, 20, TWO_GIB, bad_pair)


def test_in_range_but_wrong_absolute_offset_is_a_hard_input_error() -> None:
    identity = subdatabase_identity()
    physical_offset = 1_000_000
    record = raw_record(b"benign", physical_offset, 100, 0)
    wrong_record = replace(record, absolute_offset=physical_offset + 300)
    extraction = BerkeleyRecordExtraction(
        page_number=20,
        page_status=ValidationStatus.STRUCTURAL,
        records=(wrong_record,),
        pairs=(),
        complete_record_count=1,
        deleted_record_count=0,
        incomplete_slot_count=0,
        reasons=(),
    )

    with pytest.raises(ValueError, match="physical and local offsets"):
        LogicalBerkeleyRecordPageContext(
            identity=identity,
            source=SOURCE,
            page_number=20,
            physical_offset=physical_offset,
            page_size=PAGE_SIZE,
            page_status=ValidationStatus.STRUCTURAL,
            extraction=extraction,
        )


def test_deleted_valid_records_are_accepted_and_counted() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB, deleted=True)),
        page_context(
            identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB, deleted=True)
        ),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.deleted_valid_record_count == 2


def test_noncanonical_records_are_accepted_and_counted() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB, canonical=False)),
        page_context(
            identity,
            900,
            FORTY_FOUR_GIB,
            mkey_pair(FORTY_FOUR_GIB, canonical=False),
        ),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.canonical_record_count == 0
    assert result.noncanonical_record_count == 2


def test_identical_duplicate_pairs_are_deduplicated() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    duplicate = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))
    result = correlate(
        selected_membership,
        duplicate,
        duplicate,
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 1
    assert result.evidence["duplicate_pair_count"] == 1


def test_conflicting_duplicate_page_context_is_a_hard_error() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20)
    original = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))
    changed_pair = replace(
        original.extraction.pairs[0],
        key=replace(
            original.extraction.pairs[0].key,
            payload=original.extraction.pairs[0].key.payload + b"x",
            length=original.extraction.pairs[0].key.length + 1,
        ),
    )
    conflicting = page_context(identity, 20, TWO_GIB, changed_pair)

    with pytest.raises(ValueError, match="conflicting duplicate"):
        correlate(selected_membership, original, conflicting)


def test_pair_conflicting_with_extraction_record_is_a_hard_input_error() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20)
    context = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))
    pair = context.extraction.pairs[0]
    conflicting_record = replace(
        pair.key,
        payload=pair.key.payload + b"x",
        length=pair.key.length + 1,
    )
    contradictory_extraction = replace(
        context.extraction,
        records=(conflicting_record, pair.value),
    )
    with pytest.raises(ValueError, match="belong to extraction.records"):
        replace(context, extraction=contradictory_extraction)


def test_fabricated_pair_absent_from_extraction_records_is_rejected() -> None:
    identity = subdatabase_identity()
    context = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))
    benign_records = (
        raw_record(b"benign-key", TWO_GIB, 10, 0),
        raw_record(b"benign-value", TWO_GIB, 100, 1),
    )
    fabricated_extraction = replace(
        context.extraction,
        records=benign_records,
        complete_record_count=2,
    )

    with pytest.raises(ValueError, match="belong to extraction.records"):
        replace(context, extraction=fabricated_extraction)


def test_status_promotion_attack_is_rejected_by_context() -> None:
    identity = subdatabase_identity()
    fragment = page_context(
        identity,
        20,
        TWO_GIB,
        ckey_pair(TWO_GIB),
        status=ValidationStatus.FRAGMENT,
    )

    with pytest.raises(ValueError, match="page_status"):
        replace(fragment, page_status=ValidationStatus.STRUCTURAL)


def test_page_number_mismatch_is_rejected_by_context() -> None:
    identity = subdatabase_identity()
    context = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))

    with pytest.raises(ValueError, match="page_number"):
        replace(
            context,
            extraction=replace(context.extraction, page_number=21),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source", r"E:\images\other.img", "source"),
        ("page_size", PAGE_SIZE * 2, "page_size"),
    ],
)
def test_context_source_and_page_size_must_match_identity(
    field: str,
    value: object,
    message: str,
) -> None:
    identity = subdatabase_identity()
    context = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))

    with pytest.raises(ValueError, match=message):
        replace(context, **{field: value})


def test_membership_rejection_rejects_otherwise_valid_records() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(
        identity, 20, 900, status=ValidationStatus.REJECTED
    )
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
    )

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("membership_rejected",)


def test_safe_evidence_has_only_locations_and_master_key_id() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(
            identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB, master_key_id=9)
        ),
    )

    assert result.evidence["ckey_locations"] == (
        (20, TWO_GIB + 50, TWO_GIB + 150),
    )
    assert result.evidence["mkey_locations"] == (
        (900, FORTY_FOUR_GIB + 250, FORTY_FOUR_GIB + 350, 9),
    )
    assert not _contains_bytes(result.evidence)


def test_context_and_result_are_immutable() -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20)
    context = page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB))
    result = correlate(selected_membership, context)

    with pytest.raises(FrozenInstanceError):
        context.page_number = 21  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]


def test_correlator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = subdatabase_identity()
    selected_membership = membership(identity, 20, 900)

    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("correlator attempted file I/O or decryption")

    monkeypatch.setattr("builtins.open", fail_open)
    result = correlate(
        selected_membership,
        page_context(identity, 20, TWO_GIB, ckey_pair(TWO_GIB)),
        page_context(identity, 900, FORTY_FOUR_GIB, mkey_pair(FORTY_FOUR_GIB)),
    )
    assert result.status is ValidationStatus.STRUCTURAL


def _contains_bytes(value: object) -> bool:
    if isinstance(value, bytes):
        return True
    if isinstance(value, dict):
        return any(
            _contains_bytes(key) or _contains_bytes(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set)):
        return any(_contains_bytes(item) for item in value)
    return False
