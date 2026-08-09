from dataclasses import FrozenInstanceError

import pytest

from bfrs.core.models import ValidationResult, ValidationStatus
from bfrs.validators.base import ValidationContext, Validator


class FakeValidator:
    name = "fake"

    def validate(self, context: ValidationContext) -> ValidationResult:
        if context.data == b"[HEADER][RECORD][INDEX][METADATA]":
            status = ValidationStatus.STRUCTURAL
            evidence = {"header_valid": True, "record_valid": True}
        elif b"[RECORD]" in context.data and b"[HEADER]" not in context.data:
            status = ValidationStatus.FRAGMENT
            evidence = {"fragment_type": "record"}
        else:
            status = ValidationStatus.REJECTED
            evidence = {"reason": "structure_not_confirmed"}

        return ValidationResult(
            start_offset=context.start_offset,
            end_offset=context.end_offset,
            validator=self.name,
            status=status,
            source=context.source,
            evidence=evidence,
        )


def run_validator(validator: Validator, context: ValidationContext) -> ValidationResult:
    return validator.validate(context)


def test_validation_context_preserves_source() -> None:
    context = ValidationContext("source.img", 10, b"abc")

    assert context.source == "source.img"


def test_validation_context_allows_zero_start_offset() -> None:
    assert ValidationContext("source.img", 0, b"abc").start_offset == 0


def test_validation_context_calculates_absolute_end_offset() -> None:
    context = ValidationContext("source.img", 100, b"abcdef")

    assert context.end_offset == 106


def test_validation_context_allows_empty_data() -> None:
    context = ValidationContext("source.img", 50, b"")

    assert context.end_offset == 50


def test_validation_context_rejects_negative_start_offset() -> None:
    with pytest.raises(ValueError, match="start_offset"):
        ValidationContext("source.img", -1, b"abc")


def test_validation_context_rejects_empty_source() -> None:
    with pytest.raises(ValueError, match="source"):
        ValidationContext("", 0, b"abc")


def test_validation_context_is_immutable() -> None:
    context = ValidationContext("source.img", 0, b"abc")

    with pytest.raises(FrozenInstanceError):
        context.start_offset = 1  # type: ignore[misc]


def test_fake_validator_returns_structural_for_complete_structure() -> None:
    context = ValidationContext(
        "source.img", 100, b"[HEADER][RECORD][INDEX][METADATA]"
    )

    result = run_validator(FakeValidator(), context)

    assert result.status is ValidationStatus.STRUCTURAL
    assert result.validator == "fake"
    assert result.evidence == {"header_valid": True, "record_valid": True}


def test_fake_validator_returns_fragment_for_valid_partial_data() -> None:
    context = ValidationContext("source.img", 100, b"XXXXXX[RECORD]XXXXXXXXXXXX")

    result = run_validator(FakeValidator(), context)

    assert result.status is ValidationStatus.FRAGMENT
    assert result.status is not ValidationStatus.STRUCTURAL
    assert result.evidence == {"fragment_type": "record"}


def test_fake_validator_returns_rejected_for_false_positive() -> None:
    context = ValidationContext("source.img", 100, b"HEADER RECORD INDEX")

    result = run_validator(FakeValidator(), context)

    assert result.status is ValidationStatus.REJECTED
    assert result.evidence == {"reason": "structure_not_confirmed"}


def test_validation_uses_only_in_memory_bytes() -> None:
    context = ValidationContext("file-that-does-not-exist.img", 0, b"[RECORD]")

    result = run_validator(FakeValidator(), context)

    assert result.status is ValidationStatus.FRAGMENT
    assert result.source == "file-that-does-not-exist.img"


@pytest.mark.parametrize(
    ("status", "value"),
    [
        (ValidationStatus.STRUCTURAL, "structural"),
        (ValidationStatus.FRAGMENT, "fragment"),
        (ValidationStatus.REJECTED, "rejected"),
    ],
)
def test_validation_status_has_stable_values(
    status: ValidationStatus, value: str
) -> None:
    assert status.value == value
