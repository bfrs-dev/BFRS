"""Basic data models passed between BFRS pipeline stages."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ScanRange:
    start_offset: int
    end_offset: int
    source: str


@dataclass(frozen=True, slots=True)
class RawHit:
    start_offset: int
    end_offset: int
    hit_type: str
    confidence: float
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Hotspot:
    start_offset: int
    end_offset: int
    score: float
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ValidationResult:
    start_offset: int
    end_offset: int
    hit_type: str
    is_valid: bool
    confidence: float
    source: str
    evidence: dict[str, Any] = field(default_factory=dict)
