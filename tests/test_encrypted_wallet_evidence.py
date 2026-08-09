from dataclasses import FrozenInstanceError, replace

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.recovery.berkeley_records import (
    BerkeleyLeafPair,
    BerkeleyRecord,
    BerkeleyRecordExtraction,
)
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor
from bfrs.validators.encrypted_wallet_evidence import (
    BerkeleyRecordPageContext,
    EncryptedWalletEvidenceCorrelator,
)


PAGE_SIZE = 512
BASE_OFFSET = 1_000_000
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
        if value < 253:
            return bytes((value,))
        return b"\xfd" + value.to_bytes(2, "little")
    return b"\xfd" + value.to_bytes(2, "little")


def serialized_string(value: str, *, canonical: bool = True) -> bytes:
    payload = value.encode("ascii")
    return compact_size(len(payload), canonical=canonical) + payload


def serialized_vector(payload: bytes, *, canonical: bool = True) -> bytes:
    return compact_size(len(payload), canonical=canonical) + payload


def anchor(
    *,
    source_base: int = BASE_OFFSET,
    page_size: int = PAGE_SIZE,
    byte_order: str = "little",
    metadata_page_number: int = 0,
) -> BerkeleyAnchor:
    return BerkeleyAnchor(
        metadata_absolute_offset=(
            source_base + metadata_page_number * page_size
        ),
        metadata_page_number=metadata_page_number,
        page_size=page_size,
        byte_order=byte_order,
    )


def raw_record(
    payload: bytes,
    page_number: int,
    local_offset: int,
    slot_index: int,
    *,
    deleted: bool = False,
    source_base: int = BASE_OFFSET,
) -> BerkeleyRecord:
    return BerkeleyRecord(
        slot_index=slot_index,
        local_offset=local_offset,
        absolute_offset=source_base + page_number * PAGE_SIZE + local_offset,
        length=len(payload),
        record_type=1,
        deleted=deleted,
        payload=payload,
    )


def ckey_pair(
    page_number: int,
    *,
    local_offset: int = 50,
    canonical: bool = True,
    deleted: bool = False,
    source_base: int = BASE_OFFSET,
) -> BerkeleyLeafPair:
    key_payload = serialized_string(
        "ckey", canonical=canonical
    ) + serialized_vector(PUBLIC_KEY, canonical=canonical)
    value_payload = serialized_vector(CRYPTED_SECRET, canonical=canonical)
    return BerkeleyLeafPair(
        pair_index=local_offset,
        key=raw_record(
            key_payload,
            page_number,
            local_offset,
            0,
            deleted=deleted,
            source_base=source_base,
        ),
        value=raw_record(
            value_payload,
            page_number,
            local_offset + 100,
            1,
            deleted=deleted,
            source_base=source_base,
        ),
    )


def mkey_pair(
    page_number: int,
    *,
    master_key_id: int = 1,
    local_offset: int = 250,
    canonical: bool = True,
    deleted: bool = False,
    source_base: int = BASE_OFFSET,
) -> BerkeleyLeafPair:
    key_payload = serialized_string(
        "mkey", canonical=canonical
    ) + master_key_id.to_bytes(4, "little")
    value_payload = (
        serialized_vector(ENCRYPTED_MASTER_KEY, canonical=canonical)
        + serialized_vector(SALT, canonical=canonical)
        + (0).to_bytes(4, "little")
        + (25_000).to_bytes(4, "little")
        + serialized_vector(b"", canonical=canonical)
    )
    return BerkeleyLeafPair(
        pair_index=local_offset,
        key=raw_record(
            key_payload,
            page_number,
            local_offset,
            0,
            deleted=deleted,
            source_base=source_base,
        ),
        value=raw_record(
            value_payload,
            page_number,
            local_offset + 100,
            1,
            deleted=deleted,
            source_base=source_base,
        ),
    )


def other_pair(
    page_number: int,
    record_type: str,
    *,
    local_offset: int,
) -> BerkeleyLeafPair:
    if record_type == "defaultkey":
        key_payload = serialized_string(record_type)
        value_payload = serialized_vector(PUBLIC_KEY)
    else:
        key_payload = serialized_string(record_type) + serialized_vector(PUBLIC_KEY)
        value_payload = bytes(20)
    return BerkeleyLeafPair(
        pair_index=local_offset,
        key=raw_record(key_payload, page_number, local_offset, 0),
        value=raw_record(value_payload, page_number, local_offset + 100, 1),
    )


def extraction(
    page_number: int,
    *pairs: BerkeleyLeafPair,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
) -> BerkeleyRecordExtraction:
    records = tuple(record for pair in pairs for record in (pair.key, pair.value))
    return BerkeleyRecordExtraction(
        page_number=page_number,
        page_status=status,
        records=records,
        pairs=tuple(pairs),
        complete_record_count=len(records),
        deleted_record_count=sum(record.deleted for record in records),
        incomplete_slot_count=0,
        reasons=(),
    )


def context(
    page_number: int,
    *pairs: BerkeleyLeafPair,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
    source: str = "disk.img",
    selected_anchor: BerkeleyAnchor | None = None,
) -> BerkeleyRecordPageContext:
    return BerkeleyRecordPageContext(
        source=source,
        anchor=selected_anchor or anchor(),
        extraction=extraction(page_number, *pairs, status=status),
    )


def correlate(*contexts: BerkeleyRecordPageContext):
    return EncryptedWalletEvidenceCorrelator().correlate(contexts)


def test_empty_input_is_rejected() -> None:
    result = correlate()

    assert result.status is ValidationStatus.REJECTED
    assert result.source == ""
    assert result.valid_ckey_count == 0
    assert result.valid_mkey_count == 0
    assert result.reasons == ("no_encrypted_wallet_records",)


def test_one_valid_crypted_key_is_fragment() -> None:
    result = correlate(context(10, ckey_pair(10)))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 0
    assert result.structural_ckey_count == 1
    assert result.reasons == ("only_crypted_keys",)


def test_many_valid_crypted_keys_without_master_key_are_fragment() -> None:
    result = correlate(
        context(10, ckey_pair(10, local_offset=50)),
        context(12, ckey_pair(12, local_offset=200)),
        context(14, ckey_pair(14, local_offset=300)),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 3
    assert result.valid_mkey_count == 0


def test_one_valid_master_key_is_fragment() -> None:
    result = correlate(context(11, mkey_pair(11, master_key_id=8)))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.valid_ckey_count == 0
    assert result.valid_mkey_count == 1
    assert result.structural_mkey_count == 1
    assert result.reasons == ("only_master_keys",)


def test_structural_pages_with_mkey_and_ckey_are_structural() -> None:
    result = correlate(
        context(10, ckey_pair(10)),
        context(12, mkey_pair(12, master_key_id=4)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 1
    assert result.page_numbers == (10, 12)
    assert result.reasons == ()


def test_several_ckeys_and_mkey_are_structural() -> None:
    result = correlate(
        context(8, ckey_pair(8)),
        context(9, ckey_pair(9)),
        context(10, ckey_pair(10)),
        context(12, mkey_pair(12)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 3
    assert result.valid_mkey_count == 1


def test_input_order_does_not_change_result() -> None:
    contexts = (
        context(8, ckey_pair(8)),
        context(10, mkey_pair(10, master_key_id=3)),
        context(12, ckey_pair(12)),
    )

    assert correlate(*contexts) == correlate(*reversed(contexts))


def test_duplicate_pair_is_counted_once_and_reported() -> None:
    duplicate = ckey_pair(10)
    result = correlate(
        context(10, duplicate),
        context(10, duplicate),
        context(12, mkey_pair(12)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 1
    assert result.evidence["duplicate_pair_count"] == 1
    assert result.reasons == ("duplicate_input",)


def test_conflicting_payload_at_same_physical_pair_is_rejected() -> None:
    original = ckey_pair(10)
    changed_key = replace(original.key, payload=original.key.payload + b"x")
    conflicting = replace(original, key=changed_key)

    result = correlate(context(10, original), context(10, conflicting))

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("duplicate_input",)


def test_partial_overwrite_does_not_destroy_complete_structural_evidence() -> None:
    rejected = context(11, status=ValidationStatus.REJECTED)
    result = correlate(
        context(10, ckey_pair(10)),
        rejected,
        context(12, mkey_pair(12)),
        context(13, ckey_pair(13), status=ValidationStatus.FRAGMENT),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.page_numbers == (10, 12, 13)
    assert result.structural_ckey_count == 1
    assert result.structural_mkey_count == 1
    assert result.fragment_ckey_count == 1
    assert result.evidence["rejected_page_numbers"] == (11,)


def test_fragment_ckey_and_structural_mkey_are_fragment() -> None:
    result = correlate(
        context(10, ckey_pair(10), status=ValidationStatus.FRAGMENT),
        context(12, mkey_pair(12)),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.fragment_ckey_count == 1
    assert result.structural_mkey_count == 1
    assert result.reasons == ("fragment_page_evidence",)


def test_extra_valid_fragment_ckey_does_not_downgrade_structural() -> None:
    result = correlate(
        context(10, ckey_pair(10)),
        context(11, mkey_pair(11)),
        context(12, ckey_pair(12), status=ValidationStatus.FRAGMENT),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 2
    assert result.valid_mkey_count == 1
    assert result.structural_ckey_count == 1
    assert result.structural_mkey_count == 1
    assert result.fragment_ckey_count == 1
    assert result.reasons == ()


def test_extra_valid_fragment_mkey_does_not_downgrade_structural() -> None:
    result = correlate(
        context(10, ckey_pair(10)),
        context(11, mkey_pair(11)),
        context(
            12,
            mkey_pair(12, master_key_id=2),
            status=ValidationStatus.FRAGMENT,
        ),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.valid_ckey_count == 1
    assert result.valid_mkey_count == 2
    assert result.structural_ckey_count == 1
    assert result.structural_mkey_count == 1
    assert result.fragment_mkey_count == 1
    assert result.reasons == ()


@pytest.mark.parametrize(
    "different_context",
    [
        context(
            12,
            mkey_pair(12, source_base=2_000_000),
            selected_anchor=anchor(source_base=2_000_000),
        ),
        context(12, mkey_pair(12), source="other.img"),
        context(
            12,
            mkey_pair(12),
            selected_anchor=anchor(page_size=1024),
        ),
        context(
            12,
            mkey_pair(12),
            selected_anchor=anchor(byte_order="big"),
        ),
    ],
)
def test_different_database_identity_raises_value_error(
    different_context: BerkeleyRecordPageContext,
) -> None:
    with pytest.raises(ValueError, match="different Berkeley databases"):
        correlate(context(10, ckey_pair(10)), different_context)


def test_same_base_with_different_metadata_anchor_raises_value_error() -> None:
    alternate_anchor = anchor(metadata_page_number=7)

    with pytest.raises(ValueError, match="different Berkeley databases"):
        correlate(
            context(10, ckey_pair(10)),
            context(12, mkey_pair(12), selected_anchor=alternate_anchor),
        )


def test_same_exact_anchor_correlates_very_distant_pages() -> None:
    selected_anchor = anchor(metadata_page_number=7)
    result = correlate(
        context(10, ckey_pair(10), selected_anchor=selected_anchor),
        context(5000, mkey_pair(5000), selected_anchor=selected_anchor),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.page_numbers == (10, 5000)
    assert result.structural_ckey_count == 1
    assert result.structural_mkey_count == 1


def test_record_outside_derived_page_geometry_rejects_correlation() -> None:
    pair = ckey_pair(10)
    bad_key = replace(
        pair.key,
        absolute_offset=BASE_OFFSET + 11 * PAGE_SIZE + 50,
    )
    bad_pair = replace(pair, key=bad_key)
    result = correlate(context(10, bad_pair))

    assert result.status is ValidationStatus.REJECTED
    assert result.valid_ckey_count == 0
    assert result.reasons == ("record_geometry_invalid",)


def test_pair_records_are_geometry_checked_even_if_records_tuple_is_empty() -> None:
    pair = ckey_pair(10)
    bad_value = replace(pair.value, absolute_offset=BASE_OFFSET + 20 * PAGE_SIZE)
    bad_pair = replace(pair, value=bad_value)
    incomplete_extraction = replace(
        extraction(10, bad_pair),
        records=(),
        complete_record_count=0,
    )
    page_context = BerkeleyRecordPageContext(
        "disk.img", anchor(), incomplete_extraction
    )

    assert correlate(page_context).reasons == ("record_geometry_invalid",)


def test_non_encrypted_wallet_record_types_are_ignored() -> None:
    result = correlate(
        context(
            10,
            other_pair(10, "key", local_offset=20),
            other_pair(10, "defaultkey", local_offset=180),
            other_pair(10, "keymeta", local_offset=340),
        )
    )

    assert result.status is ValidationStatus.REJECTED
    assert result.valid_ckey_count == 0
    assert result.valid_mkey_count == 0
    assert result.reasons == ("no_encrypted_wallet_records",)


def test_noncanonical_records_are_counted_without_rejection() -> None:
    result = correlate(
        context(10, ckey_pair(10, canonical=False)),
        context(12, mkey_pair(12, canonical=False)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.canonical_record_count == 0
    assert result.noncanonical_record_count == 2


def test_deleted_valid_records_are_correlated_and_counted() -> None:
    result = correlate(
        context(10, ckey_pair(10, deleted=True)),
        context(12, mkey_pair(12, deleted=True)),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["deleted_valid_record_count"] == 2


def test_evidence_is_sorted_and_contains_only_safe_metadata() -> None:
    result = correlate(
        context(12, mkey_pair(12, master_key_id=9)),
        context(10, ckey_pair(10)),
        context(11, ckey_pair(11)),
    )

    assert result.evidence["ckey_locations"] == (
        (10, BASE_OFFSET + 10 * PAGE_SIZE + 50, BASE_OFFSET + 10 * PAGE_SIZE + 150),
        (11, BASE_OFFSET + 11 * PAGE_SIZE + 50, BASE_OFFSET + 11 * PAGE_SIZE + 150),
    )
    assert result.evidence["mkey_locations"] == (
        (12, BASE_OFFSET + 12 * PAGE_SIZE + 250, BASE_OFFSET + 12 * PAGE_SIZE + 350, 9),
    )
    assert not _contains_bytes(result.evidence)
    forbidden = {"ciphertext", "salt", "pubkey", "passphrase", "private_key"}
    assert forbidden.isdisjoint(result.evidence)


def test_page_context_validates_source_and_page_number() -> None:
    with pytest.raises(ValueError, match="source"):
        BerkeleyRecordPageContext("", anchor(), extraction(1))
    with pytest.raises(ValueError, match="page_number"):
        BerkeleyRecordPageContext("disk.img", anchor(), extraction(-1))


def test_results_and_contexts_are_immutable() -> None:
    page_context = context(10, ckey_pair(10))
    result = correlate(page_context)

    with pytest.raises(FrozenInstanceError):
        page_context.source = "other.img"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.status = ValidationStatus.REJECTED  # type: ignore[misc]


def test_correlator_performs_no_file_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("correlator attempted file I/O")

    monkeypatch.setattr("builtins.open", fail_open)

    result = correlate(
        context(10, ckey_pair(10)),
        context(12, mkey_pair(12)),
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
