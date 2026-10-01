from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from bfrs.application import ScanConfig, ScanController
from bfrs.application.scan_events import ScanCompletedEvent, ScanProgressEvent
from bfrs.gui.scan_worker import ScanWorker


def _config(tmp_path: Path) -> ScanConfig:
    source = tmp_path / "source.img"
    source.write_bytes(b"x" * (4 * 1024 * 1024))
    return ScanConfig(
        input_path=source,
        output_path=tmp_path / "report.json",
        chunk_mib=1,
        overlap_kib=64,
    )


def test_scan_worker_runs_process_isolated_scan(tmp_path):
    controller = ScanController()
    worker = ScanWorker(_config(tmp_path), controller)

    events = []
    results = []
    failures = []
    worker.event.connect(events.append)
    worker.finished.connect(results.append)
    worker.failed.connect(failures.append)

    worker.run()

    assert not failures
    assert len(results) == 1
    assert results[0].completed is True
    assert any(isinstance(event, ScanProgressEvent) for event in events)
    assert isinstance(events[-1], ScanCompletedEvent)


def test_scan_worker_observes_existing_stop_controller(tmp_path):
    config = _config(tmp_path)
    controller = ScanController()
    controller.request_stop()
    worker = ScanWorker(config, controller)

    results = []
    failures = []
    worker.finished.connect(results.append)
    worker.failed.connect(failures.append)

    worker.run()

    assert not failures
    assert len(results) == 1
    assert results[0].status == "stopped"
