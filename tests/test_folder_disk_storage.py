"""Regression coverage for folder resume/report memory amplification."""
import io
import json
import tracemalloc

import pytest

from bfrs.scanners.disk_list import DiskList
from bfrs.scanners.folder_scan_checkpoint import FolderScanCheckpoint, FolderCheckpointError


def test_disk_list_streams_json_and_sorts_with_numeric_offsets():
    rows = DiskList()
    try:
        rows.extend([{"path": "b", "offset": 2}, {"path": "a", "offset": 10},
                     {"path": "a", "offset": 2}])
        rows.sort(key=lambda row: (row["path"], row["offset"]))
        stream = io.StringIO()
        json.dump({"rows": rows}, stream, sort_keys=True, indent=2)
        assert json.loads(stream.getvalue())["rows"] == [
            {"path": "a", "offset": 2}, {"path": "a", "offset": 10},
            {"path": "b", "offset": 2}]
        assert len(rows) == 3
        assert list(rows) == list(rows)
        temporary = rows._temporary.name
    finally:
        rows.close()
    from pathlib import Path
    assert not Path(temporary).exists()


def test_checkpoint_reports_are_streamed_with_bounded_python_memory(tmp_path):
    checkpoint = FolderScanCheckpoint.create(tmp_path / "checkpoint.sqlite", root=tmp_path,
        snapshot_sha256="snapshot", semantics={})
    rows = DiskList()
    try:
        # 64 MiB of reports: eager fetchall + JSON objects formerly amplified this.
        report = {"padding": "x" * 65536, "target_findings": []}
        for index in range(1024):
            checkpoint.save_outcome(relative_path=f"{index:06}.bin", size=index,
                mtime_ns=1, report=report, error_reason=None)
        tracemalloc.start()
        try:
            records = checkpoint.records()
            assert iter(records) is records
            for record in records:
                rows.append(record.report)
            assert len(rows) == 1024
            for value in rows:
                assert value == report
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 8 * 1024 * 1024
        assert checkpoint.record_count() == 1024
    finally:
        rows.close()
        checkpoint.close()


def test_corrupt_checkpoint_report_is_rejected(tmp_path):
    checkpoint = FolderScanCheckpoint.create(tmp_path / "checkpoint.sqlite", root=tmp_path,
        snapshot_sha256="snapshot", semantics={})
    try:
        checkpoint.save_outcome(relative_path="a", size=1, mtime_ns=1,
                                report={}, error_reason=None)
        checkpoint._connection.execute("UPDATE outcomes SET report_json='broken'")
        with pytest.raises(FolderCheckpointError, match="invalid report JSON"):
            next(checkpoint.records())
    finally:
        checkpoint.close()


def test_folder_completion_does_not_read_report(tmp_path, monkeypatch):
    from pathlib import Path
    from bfrs.application.scan_service import _read_completion_metadata

    def forbidden(*args, **kwargs):
        raise AssertionError("folder report must not be loaded into memory")

    monkeypatch.setattr(Path, "read_text", forbidden)
    assert _read_completion_metadata(tmp_path / "report.json", folder_source=True) == ("completed", None, None)
