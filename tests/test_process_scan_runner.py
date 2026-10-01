from __future__ import annotations

import multiprocessing
from pathlib import Path
import time

import pytest

from bfrs.application.process_scan_runner import (
    ProcessScanError,
    ProcessScanRunner,
)
from bfrs.application.scan_config import ScanConfig
from bfrs.application.scan_events import (
    ScanCompletedEvent,
    ScanFailedEvent,
    ScanProgressEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
)


def _config(tmp_path: Path, *, checkpoint: bool = False) -> ScanConfig:
    source = tmp_path / "source.img"
    source.write_bytes(b"x" * (4 * 1024 * 1024))
    checkpoint_path = (
        tmp_path / "scan.checkpoint.sqlite" if checkpoint else None
    )
    return ScanConfig(
        input_path=source,
        output_path=tmp_path / "report.json",
        chunk_mib=1,
        overlap_kib=64,
        checkpoint=checkpoint_path,
    )


def test_process_runner_completes_and_relays_events(tmp_path):
    events = []
    runner = ProcessScanRunner(event_sink=events.append, poll_seconds=0.01)

    result = runner.run(_config(tmp_path))

    assert result.completed is True
    assert result.report_path.exists()
    assert isinstance(events[0], ScanStartedEvent)
    assert any(isinstance(event, ScanProgressEvent) for event in events)
    assert isinstance(events[-1], ScanCompletedEvent)
    assert runner.state.running is False


def test_process_runner_cooperative_stop_preserves_checkpoint(tmp_path):
    events = []
    runner = ProcessScanRunner(event_sink=events.append, poll_seconds=0.01)
    config = _config(tmp_path, checkpoint=True)

    def collect(event):
        events.append(event)
        if (
            isinstance(event, ScanProgressEvent)
            and event.scanned_bytes > 0
            and not event.complete
        ):
            runner.request_stop()

    runner = ProcessScanRunner(event_sink=collect, poll_seconds=0.01)

    result = runner.run(config)

    assert result.status == "stopped"
    assert config.checkpoint is not None
    assert config.checkpoint.exists()
    assert any(isinstance(event, ScanStoppedEvent) for event in events)
    assert runner.state.running is False


def _crash_worker(config, messages, stop_event):
    raise SystemExit(7)


def test_process_runner_reports_unexpected_child_exit(tmp_path, monkeypatch):
    import bfrs.application.process_scan_runner as module

    monkeypatch.setattr(module, "_worker_entry", _crash_worker)
    events = []
    runner = ProcessScanRunner(event_sink=events.append, poll_seconds=0.01)

    with pytest.raises(ProcessScanError, match="exited unexpectedly"):
        runner.run(_config(tmp_path))

    failures = [event for event in events if isinstance(event, ScanFailedEvent)]
    assert failures
    assert failures[-1].error_type == "ProcessExit"
    assert runner.state.running is False


def test_process_runner_rejects_nonpositive_poll_interval():
    with pytest.raises(ValueError, match="greater than zero"):
        ProcessScanRunner(poll_seconds=0)


def test_process_runner_state_reports_child_pid_while_running(tmp_path):
    source = tmp_path / "large.img"
    source.write_bytes(b"x" * (16 * 1024 * 1024))
    config = ScanConfig(
        input_path=source,
        output_path=tmp_path / "report.json",
        chunk_mib=1,
        overlap_kib=64,
    )
    runner = ProcessScanRunner(poll_seconds=0.01)

    state_seen = []

    def observe(event):
        if isinstance(event, ScanProgressEvent):
            state_seen.append(runner.state)
            runner.request_stop()

    runner = ProcessScanRunner(event_sink=observe, poll_seconds=0.01)
    result = runner.run(config)

    assert result.status == "stopped"
    assert state_seen
    assert state_seen[0].running is True
    assert isinstance(state_seen[0].pid, int)
    assert state_seen[0].pid > 0
