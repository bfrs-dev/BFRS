"""Minimal shared contract for byte-oriented candidate validators."""

from dataclasses import dataclass
from typing import Protocol

from bfrs.core.models import ValidationResult


@dataclass(frozen=True, slots=True)
class ValidationContext:
    source: str
    start_offset: int
    data: bytes

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("source must not be empty")
        if self.start_offset < 0:
            raise ValueError("start_offset must not be negative")

    @property
    def end_offset(self) -> int:
        return self.start_offset + len(self.data)


class Validator(Protocol):
    name: str

    def validate(self, context: ValidationContext) -> ValidationResult: ...
