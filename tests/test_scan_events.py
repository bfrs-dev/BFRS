from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from bfrs.application.scan_events import (
    ScanCheckpointSavedEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
    ScanProgressEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
    freeze_counts,
    thaw_counts,
)
from bfrs.core.source_types import SourceType


def test_started_event_contains_only_request_metadata(tmp_path):
    event = ScanStartedEvent(
        input_path=tmp_path / "disk.img",
        output_path=tmp_path / "report.json",
        source_type=SourceType.IMAGE,
        start=1024,
        end=4096,
    )

    assert event.source_type is SourceType.IMAGE
    assert event.start == 1024
    assert event.end == 4096


def test_events_are_immutable(tmp_path):
    event = ScanStartedEvent(
        tmp_path / "disk.img",
        tmp_path / "report.json",
        SourceType.IMAGE,
    )

    with pytest.raises(FrozenInstanceError):
        event.start = 1


def test_freeze_counts_is_deterministic_and_round_trips():
    frozen = freeze_counts({"secrets": 2, "bitcoin-core": 5})

    assert frozen == (("bitcoin-core", 5), ("secrets", 2))
    assert thaw_counts(frozen) == {"bitcoin-core": 5, "secrets": 2}


def test_freeze_counts_rejects_negative_values():
    with pytest.raises(ValueError, match="nonnegative"):
        freeze_counts({"bitcoin-core": -1})


def test_progress_event_reports_percent_without_rate_or_secret_payload():
    event = ScanProgressEvent(
        scanned_bytes=25,
        total_bytes=100,
        raw_hits=7,
        anchors_total=4,
        stage="target-scan",
        raw_by_target=freeze_counts({"bitcoin-core": 3, "electrum": 4}),
    )

    assert event.percent_complete == 25.0
    assert thaw_counts(event.raw_by_target)["electrum"] == 4
    assert not hasattr(event, "secret")
    assert not hasattr(event, "payload")


def test_zero_length_progress_is_complete_percentage():
    event = ScanProgressEvent(scanned_bytes=0, total_bytes=0)

    assert event.percent_complete == 100.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"scanned_bytes": -1, "total_bytes": 1},
        {"scanned_bytes": 0, "total_bytes": -1},
        {"scanned_bytes": 0, "total_bytes": 1, "raw_hits": -1},
        {"scanned_bytes": 0, "total_bytes": 1, "anchors_total": -1},
    ],
)
def test_progress_rejects_negative_aggregate_counts(kwargs):
    with pytest.raises(ValueError, match="nonnegative"):
        ScanProgressEvent(**kwargs)


def test_progress_rejects_invalid_target_counters():
    with pytest.raises(ValueError, match="target name"):
        ScanProgressEvent(
            scanned_bytes=0,
            total_bytes=1,
            raw_by_target=(("", 1),),
        )

    with pytest.raises(ValueError, match="target counts"):
        ScanProgressEvent(
            scanned_bytes=0,
            total_bytes=1,
            raw_by_target=(("bitcoin-core", -1),),
        )


def test_checkpoint_event_is_safe_resume_metadata(tmp_path):
    event = ScanCheckpointSavedEvent(
        checkpoint_path=tmp_path / "scan.checkpoint.json",
        completed_bytes=4096,
    )

    assert event.completed_bytes == 4096


def test_checkpoint_event_rejects_negative_offset(tmp_path):
    with pytest.raises(ValueError, match="nonnegative"):
        ScanCheckpointSavedEvent(tmp_path / "checkpoint.json", -1)


def test_stopped_event_can_reference_resume_checkpoint(tmp_path):
    checkpoint = tmp_path / "scan.checkpoint.json"
    event = ScanStoppedEvent(
        processed_bytes=2048,
        checkpoint_path=checkpoint,
    )

    assert event.checkpoint_path == checkpoint
    assert event.reason == "user_requested"


def test_completed_event_requires_nonempty_status(tmp_path):
    with pytest.raises(ValueError, match="status"):
        ScanCompletedEvent(tmp_path / "report.json", "", 1, 1)


def test_completed_event_allows_unknown_byte_counts(tmp_path):
    event = ScanCompletedEvent(tmp_path / "report.json", "completed")
    assert event.processed_bytes is None
    assert event.total_bytes is None


def test_completed_event_rejects_negative_byte_counts(tmp_path):
    with pytest.raises(ValueError, match="byte counts"):
        ScanCompletedEvent(tmp_path / "report.json", "rejected", -1, 1)


def test_failed_event_uses_presentation_safe_diagnostic():
    event = ScanFailedEvent(
        message="checkpoint is incompatible with this scan",
        error_type="UnifiedCheckpointError",
        recoverable=True,
    )

    assert event.recoverable is True
    assert event.error_type == "UnifiedCheckpointError"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"message": "", "error_type": "OSError"},
        {"message": "failure", "error_type": ""},
    ],
)
def test_failed_event_requires_diagnostic_fields(kwargs):
    with pytest.raises(ValueError):
        ScanFailedEvent(**kwargs)
