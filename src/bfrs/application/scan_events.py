"""GUI-independent event contract for BFRS scan front ends."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from bfrs.core.source_types import SourceType


TargetCounts = tuple[tuple[str, int], ...]


def freeze_counts(values: Mapping[str, int] | None = None) -> TargetCounts:
    """Return deterministic immutable target counters for event transport."""
    if not values:
        return ()
    result = []
    for target, count in sorted(values.items()):
        if count < 0:
            raise ValueError("target counts must be nonnegative")
        result.append((target, count))
    return tuple(result)


def thaw_counts(values: TargetCounts) -> dict[str, int]:
    """Return a mutable presentation copy of immutable event counters."""
    return dict(values)


@dataclass(frozen=True, slots=True)
class ScanStartedEvent:
    """A scan request has entered execution."""

    input_path: Path
    output_path: Path
    source_type: SourceType | None
    start: int = 0
    end: int | None = None


@dataclass(frozen=True, slots=True)
class ScanProgressEvent:
    """Secret-free aggregate progress suitable for CLI or GUI presentation."""

    scanned_bytes: int
    total_bytes: int
    raw_hits: int = 0
    anchors_total: int = 0
    stage: str | None = None
    complete: bool = False
    raw_by_target: TargetCounts = field(default_factory=tuple)
    rejected_by_target: TargetCounts = field(default_factory=tuple)
    pending_validation_by_target: TargetCounts = field(default_factory=tuple)
    validated_occurrences_by_target: TargetCounts = field(default_factory=tuple)
    validated_unique_by_target: TargetCounts = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("scanned_bytes", "total_bytes", "raw_hits", "anchors_total"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be nonnegative")
        for counts in (
            self.raw_by_target,
            self.rejected_by_target,
            self.pending_validation_by_target,
            self.validated_occurrences_by_target,
            self.validated_unique_by_target,
        ):
            for target, count in counts:
                if not target:
                    raise ValueError("target name must not be empty")
                if count < 0:
                    raise ValueError("target counts must be nonnegative")

    @property
    def percent_complete(self) -> float:
        if self.total_bytes == 0:
            return 100.0
        return min(100.0, self.scanned_bytes * 100.0 / self.total_bytes)


@dataclass(frozen=True, slots=True)
class ScanCheckpointSavedEvent:
    """A resumable checkpoint was persisted."""

    checkpoint_path: Path
    completed_bytes: int

    def __post_init__(self) -> None:
        if self.completed_bytes < 0:
            raise ValueError("completed_bytes must be nonnegative")


@dataclass(frozen=True, slots=True)
class ScanStoppedEvent:
    """Execution stopped cleanly before normal completion."""

    processed_bytes: int
    checkpoint_path: Path | None = None
    reason: str = "user_requested"

    def __post_init__(self) -> None:
        if self.processed_bytes < 0:
            raise ValueError("processed_bytes must be nonnegative")


@dataclass(frozen=True, slots=True)
class ScanCompletedEvent:
    """Execution completed and produced its public report."""

    report_path: Path
    status: str
    processed_bytes: int
    total_bytes: int

    def __post_init__(self) -> None:
        if not self.status:
            raise ValueError("status must not be empty")
        if self.processed_bytes < 0 or self.total_bytes < 0:
            raise ValueError("byte counts must be nonnegative")


@dataclass(frozen=True, slots=True)
class ScanFailedEvent:
    """Execution failed with a presentation-safe diagnostic."""

    message: str
    error_type: str
    recoverable: bool = False

    def __post_init__(self) -> None:
        if not self.message:
            raise ValueError("message must not be empty")
        if not self.error_type:
            raise ValueError("error_type must not be empty")


ScanEvent = (
    ScanStartedEvent
    | ScanProgressEvent
    | ScanCheckpointSavedEvent
    | ScanStoppedEvent
    | ScanCompletedEvent
    | ScanFailedEvent
)
