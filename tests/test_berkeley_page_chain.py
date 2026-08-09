import builtins
from copy import deepcopy

import pytest

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.validators.berkeley_page_chain import BerkeleyPageChainValidator
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor


PAGE_SIZE = 512
SOURCE = "source.img"
ANCHOR = BerkeleyAnchor(50 * PAGE_SIZE, 50, PAGE_SIZE, "little")


def page_result(
    page_number: int,
    *,
    previous_page: int = 0,
    next_page: int = 0,
    status: ValidationStatus = ValidationStatus.STRUCTURAL,
    start_offset: int | None = None,
    source: str = SOURCE,
    validator: str = "berkeley_page",
    evidence_overrides: dict[str, object] | None = None,
) -> ValidationResult:
    evidence: dict[str, object] = {
        "page_number": page_number,
        "previous_page": previous_page,
        "next_page": next_page,
        "page_type": 5,
        "reasons": (),
    }
    if evidence_overrides:
        evidence.update(evidence_overrides)
    absolute_offset = (
        page_number * PAGE_SIZE if start_offset is None else start_offset
    )
    return ValidationResult(
        start_offset=absolute_offset,
        end_offset=absolute_offset + PAGE_SIZE,
        validator=validator,
        status=status,
        source=source,
        evidence=evidence,
    )


def validate(*results: ValidationResult):
    return BerkeleyPageChainValidator(ANCHOR).validate(results)


def test_empty_input_is_rejected_without_exception() -> None:
    result = validate()

    assert result.status is ValidationStatus.REJECTED
    assert result.page_count == 0
    assert result.reasons == ("no_valid_pages",)


def test_one_structural_page_is_fragment_chain() -> None:
    result = validate(page_result(10))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.structural_page_count == 1


def test_two_unlinked_structural_pages_are_fragment_chain() -> None:
    result = validate(page_result(10), page_result(500))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.confirmed_links == 0


def test_reciprocal_next_previous_link_is_structural() -> None:
    result = validate(
        page_result(100, next_page=101),
        page_result(101, previous_page=100),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.confirmed_links == 1
    assert result.evidence["confirmed_links"] == ((100, 101),)


def test_three_page_reciprocal_chain_is_structural() -> None:
    result = validate(
        page_result(100, next_page=101),
        page_result(101, previous_page=100, next_page=102),
        page_result(102, previous_page=101),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.confirmed_links == 2
    assert result.evidence["confirmed_links"] == ((100, 101), (101, 102))


def test_confirmed_links_are_unique_and_deterministically_sorted() -> None:
    result = validate(
        page_result(11, previous_page=10, next_page=12),
        page_result(12, previous_page=11),
        page_result(10, next_page=11),
    )

    assert result.evidence["confirmed_links"] == ((10, 11), (11, 12))
    assert result.confirmed_links == 2


def test_random_input_order_produces_identical_result() -> None:
    pages = (
        page_result(100, next_page=101),
        page_result(101, previous_page=100, next_page=102),
        page_result(102, previous_page=101),
    )

    assert validate(*pages) == validate(pages[2], pages[0], pages[1])


def test_reciprocal_previous_next_link_is_structural() -> None:
    result = validate(
        page_result(40, previous_page=39),
        page_result(39, next_page=40),
    )

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.evidence["confirmed_links"] == ((39, 40),)


def test_next_previous_mismatch_rejects_chain() -> None:
    result = validate(
        page_result(100, next_page=101),
        page_result(101, previous_page=99),
    )

    assert result.status is ValidationStatus.REJECTED
    assert "next_previous_mismatch" in result.reasons


def test_previous_next_mismatch_rejects_chain() -> None:
    result = validate(
        page_result(100, previous_page=99),
        page_result(99, next_page=98),
    )

    assert result.status is ValidationStatus.REJECTED
    assert "previous_next_mismatch" in result.reasons


def test_duplicate_active_page_number_rejects_chain() -> None:
    result = validate(
        page_result(100, next_page=101),
        page_result(100, previous_page=99),
    )

    assert result.status is ValidationStatus.REJECTED
    assert "duplicate_page_number" in result.reasons
    assert result.evidence["page_numbers"] == (100, 100)


def test_page_number_inconsistent_with_anchor_grid_rejects_chain() -> None:
    result = validate(page_result(99, start_offset=100 * PAGE_SIZE))

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("grid_mismatch",)


def test_absolute_offset_off_grid_rejects_chain() -> None:
    result = validate(page_result(100, start_offset=100 * PAGE_SIZE + 37))

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("grid_mismatch",)


def test_missing_next_page_is_fragment_not_rejected() -> None:
    result = validate(page_result(100, next_page=101))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.missing_links == 1
    assert result.evidence["missing_link_targets"] == (101,)
    assert result.reasons == ()


def test_rejected_middle_page_does_not_reject_preserved_fragment() -> None:
    result = validate(
        page_result(100, next_page=101),
        page_result(101, status=ValidationStatus.REJECTED),
        page_result(102),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.page_count == 3
    assert result.structural_page_count == 2
    assert result.evidence["rejected_input_count"] == 1
    assert result.missing_links == 1
    assert result.evidence["missing_link_targets"] == (101,)


def test_zero_previous_and_next_are_not_missing_links() -> None:
    result = validate(page_result(100), page_result(101))

    assert result.status is ValidationStatus.FRAGMENT
    assert result.missing_links == 0
    assert result.evidence["missing_link_targets"] == ()


def test_different_sources_raise_value_error() -> None:
    with pytest.raises(ValueError, match="same source"):
        validate(page_result(1), page_result(2, source="other.img"))


def test_rejected_input_is_excluded_and_counted() -> None:
    result = validate(
        page_result(10),
        page_result(11, status=ValidationStatus.REJECTED),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.evidence["page_numbers"] == (10,)
    assert result.evidence["rejected_input_count"] == 1


def test_only_rejected_inputs_produce_no_valid_pages() -> None:
    result = validate(page_result(10, status=ValidationStatus.REJECTED))

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("no_valid_pages",)
    assert result.evidence["rejected_input_count"] == 1


def test_result_from_other_validator_raises_value_error() -> None:
    with pytest.raises(ValueError, match="berkeley_page"):
        validate(page_result(1, validator="berkeley_metadata"))


@pytest.mark.parametrize(
    "evidence_overrides",
    [
        {"page_number": None},
        {"page_number": True},
        {"page_number": -1},
        {"previous_page": "0"},
        {"next_page": None},
    ],
)
def test_invalid_active_evidence_rejects_chain(
    evidence_overrides: dict[str, object],
) -> None:
    result = validate(page_result(10, evidence_overrides=evidence_overrides))

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("evidence_invalid",)


def test_non_mapping_active_evidence_rejects_chain() -> None:
    malformed = ValidationResult(
        start_offset=10 * PAGE_SIZE,
        end_offset=11 * PAGE_SIZE,
        validator="berkeley_page",
        status=ValidationStatus.STRUCTURAL,
        source=SOURCE,
        evidence=None,
    )

    result = validate(malformed)

    assert result.status is ValidationStatus.REJECTED
    assert result.reasons == ("evidence_invalid",)


def test_fragment_page_counts_but_cannot_make_structural_chain() -> None:
    result = validate(
        page_result(20, next_page=21),
        page_result(
            21,
            previous_page=20,
            status=ValidationStatus.FRAGMENT,
        ),
    )

    assert result.status is ValidationStatus.FRAGMENT
    assert result.structural_page_count == 1
    assert result.fragment_page_count == 1
    assert result.confirmed_links == 1


def test_generator_input_is_supported() -> None:
    pages = (
        page_result(number, previous_page=number - 1 if number == 2 else 0)
        for number in (1, 2)
    )

    assert BerkeleyPageChainValidator(ANCHOR).validate(pages).page_count == 2


def test_validation_does_not_mutate_inputs_or_anchor() -> None:
    selected_anchor = BerkeleyAnchor(10 * PAGE_SIZE, 10, PAGE_SIZE, "little")
    pages = [page_result(10, next_page=11), page_result(11, previous_page=10)]
    evidence_before = [deepcopy(page.evidence) for page in pages]

    BerkeleyPageChainValidator(selected_anchor).validate(pages)

    assert [page.evidence for page in pages] == evidence_before
    assert selected_anchor == BerkeleyAnchor(10 * PAGE_SIZE, 10, PAGE_SIZE, "little")


def test_chain_validator_performs_no_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("chain validator attempted I/O")

    monkeypatch.setattr(builtins, "open", fail_open)

    assert validate(page_result(1)).status is ValidationStatus.FRAGMENT
