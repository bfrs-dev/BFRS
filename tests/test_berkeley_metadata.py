from collections.abc import Callable

import pytest

from bfrs.core.models import ValidationStatus
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import (
    BTREE_MAGIC,
    BTREE_METADATA_PAGE_TYPE,
    BTREE_VERSION,
    BerkeleyMetadataValidator,
)


def metadata_page(
    *,
    page_size: int = 512,
    byte_order: str = "little",
    page_number: int = 0,
    magic: int = BTREE_MAGIC,
    version: int = BTREE_VERSION,
    page_type: int = BTREE_METADATA_PAGE_TYPE,
    metadata_flags: int = 0,
    free_page: int = 0,
    last_page: int = 2,
    root_page: int = 1,
    btree_flags: int = 0x20,
) -> bytes:
    # Synthetic Oracle DBMETA/BTMETA: generic header plus B-tree root fields.
    page = bytearray(max(page_size, 512))
    put = lambda start, value: page.__setitem__(
        slice(start, start + 4), value.to_bytes(4, byte_order)
    )
    put(8, page_number)
    put(12, magic)
    put(16, version)
    put(20, page_size)
    page[25] = page_type
    page[26] = metadata_flags
    put(28, free_page)
    put(32, last_page)
    put(48, btree_flags)
    put(88, root_page)
    return bytes(page[:page_size])


def validate(data: bytes, start_offset: int = 0):
    context = ValidationContext("source.img", start_offset, data)
    return BerkeleyMetadataValidator().validate(context)


def test_valid_metadata_page_is_structural() -> None:
    result = validate(metadata_page())

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.validator == "berkeley_metadata"
    assert result.evidence["page_number"] == 0
    assert result.evidence["base_metadata"] is True


def test_inner_metadata_page_number_is_structural() -> None:
    result = validate(metadata_page(page_number=17, last_page=3, root_page=20))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["page_number"] == 17
    assert result.evidence["base_metadata"] is False


def test_stale_last_page_is_diagnostic_not_hard_reject() -> None:
    result = validate(
        metadata_page(page_number=17, free_page=25, last_page=3, root_page=20)
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["root_page"] == 20
    assert result.evidence["last_page_number"] == 3
    assert result.evidence["free_page"] == 25
    assert result.evidence["last_page_consistent_with_root"] is False
    assert result.evidence["free_page_within_last_page"] is False


def test_valid_metadata_can_start_after_context_padding() -> None:
    result = validate(b"padding" + metadata_page())

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["local_offset"] == 7


def test_absolute_offset_includes_context_start() -> None:
    result = validate(b"abc" + metadata_page(), start_offset=10_000)

    assert result.start_offset == 10_003
    assert result.evidence["absolute_offset"] == 10_003


def test_magic_offset_is_twelve_bytes_after_candidate_start() -> None:
    context_start = 50_000
    result = validate(b"P" * 100 + metadata_page(), start_offset=context_start)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["local_offset"] == 100
    assert result.evidence["absolute_offset"] == context_start + 100


@pytest.mark.parametrize("page_size", [512, 4096, 65536])
def test_supported_page_sizes_are_parsed(page_size: int) -> None:
    result = validate(metadata_page(page_size=page_size))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["page_size"] == page_size


def test_version_is_parsed_as_confirmed_version_nine() -> None:
    result = validate(metadata_page())

    assert result.evidence["version"] == 9


@pytest.mark.parametrize("byte_order", ["little", "big"])
def test_confirmed_byte_orders_are_supported(byte_order: str) -> None:
    result = validate(metadata_page(byte_order=byte_order))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["byte_order"] == byte_order


def test_metadata_flags_and_btree_flags_are_distinct() -> None:
    result = validate(metadata_page(metadata_flags=0x01, btree_flags=0x20))

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["metadata_flags"] == 0x01
    assert result.evidence["btree_flags"] == 0x20


@pytest.mark.parametrize("btree_flags", [0, 0x01, 0x21])
def test_only_bitcoin_subdatabase_btree_flag_is_accepted(btree_flags: int) -> None:
    result = validate(metadata_page(btree_flags=btree_flags))

    assert result.status is ValidationStatus.REJECTED
    assert "metadata_btree_flags_invalid" in result.evidence["reasons"]


def test_evidence_is_deterministic() -> None:
    page = metadata_page(page_size=4096)

    assert validate(page).evidence == validate(page).evidence


def test_magic_alone_with_random_fields_is_rejected() -> None:
    data = bytearray(b"X" * 128)
    data[12:16] = BTREE_MAGIC.to_bytes(4, "little")

    assert validate(bytes(data)).status is ValidationStatus.REJECTED


@pytest.mark.parametrize("page_size", [0, 511, 513, 131072])
def test_impossible_page_size_is_rejected(page_size: int) -> None:
    assert validate(metadata_page(page_size=page_size)).status is ValidationStatus.REJECTED


def test_unsupported_version_is_rejected() -> None:
    assert validate(metadata_page(version=8)).status is ValidationStatus.REJECTED


def test_wrong_metadata_page_type_is_rejected() -> None:
    assert validate(metadata_page(page_type=5)).status is ValidationStatus.REJECTED


@pytest.mark.parametrize(
    "mutation",
    [
        lambda page: page.__setitem__(26, 0x80),
        lambda page: page.__setitem__(slice(88, 92), (0).to_bytes(4, "little")),
        lambda page: page.__setitem__(slice(48, 52), (0x200).to_bytes(4, "little")),
    ],
)
def test_one_corrupted_structural_field_is_rejected(
    mutation: Callable[[bytearray], None],
) -> None:
    page = bytearray(metadata_page())
    mutation(page)

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_random_data_is_rejected() -> None:
    assert validate(bytes(range(256)) * 2).status is ValidationStatus.REJECTED


def test_text_markers_without_structure_are_rejected() -> None:
    assert validate(b"wallet ckey mkey Berkeley").status is ValidationStatus.REJECTED


def test_inconsistent_endianness_is_rejected() -> None:
    page = bytearray(metadata_page(byte_order="big"))
    page[12:16] = BTREE_MAGIC.to_bytes(4, "little")

    assert validate(bytes(page)).status is ValidationStatus.REJECTED


def test_confirmed_prefix_truncated_before_structural_fields_is_fragment() -> None:
    result = validate(metadata_page()[:40])

    assert result.status is ValidationStatus.FRAGMENT
    assert result.status is not ValidationStatus.STRUCTURAL


def test_complete_structural_fields_but_truncated_page_is_fragment() -> None:
    result = validate(metadata_page(page_size=4096)[:512])

    assert result.status is ValidationStatus.FRAGMENT
    assert result.evidence["reasons"] == ("metadata_page_truncated",)


def test_too_short_magic_prefix_is_rejected_not_fragment() -> None:
    result = validate(b"X" * 12 + BTREE_MAGIC.to_bytes(4, "little"))

    assert result.status is ValidationStatus.REJECTED


def test_old_magic_version_marker_heuristic_is_rejected() -> None:
    # BFRS 1.x detector could score magic + plausible version + nearby markers.
    data = bytearray(b"\x00" * 128)
    data[12:16] = BTREE_MAGIC.to_bytes(4, "little")
    data[16:20] = BTREE_VERSION.to_bytes(4, "little")
    data[40:64] = b"wallet ckey mkey".ljust(24, b"\x00")

    result = validate(bytes(data))

    assert result.status is ValidationStatus.REJECTED
    assert "metadata_page_size_invalid" in result.evidence["reasons"]


def test_structural_wins_over_earlier_fragment() -> None:
    fragment = metadata_page(page_size=65536)[:512]
    data = fragment + b"gap" + metadata_page()

    result = validate(data)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["candidate_count"] == 2
    assert result.evidence["fragment_candidates"] == 1
    assert result.evidence["structural_candidates"] == 1


def test_earliest_structural_candidate_is_selected() -> None:
    page = metadata_page()
    result = validate(page + b"gap" + page)

    assert result.start_offset == 0
    assert result.evidence["candidate_count"] == 2


def test_validator_uses_context_bytes_without_io() -> None:
    context = ValidationContext("file-that-does-not-exist.img", 0, metadata_page())

    assert BerkeleyMetadataValidator().validate(context).status is ValidationStatus.STRUCTURAL
