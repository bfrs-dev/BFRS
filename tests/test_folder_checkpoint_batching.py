"""Durability, crash recovery and multi-worker folder checkpoint contracts."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

import pytest

from bfrs.scanners.folder_scan_checkpoint import FolderCheckpointError, FolderScanCheckpoint


def create(tmp_path, *, interval=1.0, batch=32):
    checkpoint = FolderScanCheckpoint.create(tmp_path / "checkpoint.sqlite", root=tmp_path,
        snapshot_sha256="synthetic-snapshot", semantics={"file_workers": 1})
    checkpoint.set_batching(batch, interval)
    return checkpoint


def save(checkpoint, index):
    checkpoint.save_outcome(relative_path=f"file-{index:05d}", size=index+1, mtime_ns=1,
        report={"target_findings": [{"synthetic_occurrence": index}]}, error_reason=None)


def stored(checkpoint):
    with sqlite3.connect(checkpoint.path) as db:
        return db.execute("SELECT COUNT(*) FROM outcomes").fetchone()[0]


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            pytest.fail("timed checkpoint commit did not happen")
        time.sleep(0.01)


def test_full_commit_at_32_and_flush_on_close(tmp_path):
    checkpoint = create(tmp_path)
    try:
        assert checkpoint._connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        for index in range(31):
            save(checkpoint, index)
        assert stored(checkpoint) == 0
        assert checkpoint.durability["durable_files"] == 0
        assert checkpoint.durability["pending_files"] == 31
        save(checkpoint, 31)
        assert stored(checkpoint) == 32
        assert checkpoint.durability["durable_files"] == 32
        save(checkpoint, 32)
    finally:
        checkpoint.close()
    assert stored(checkpoint) == 33
    assert checkpoint.durability["durable_files"] == 33
    assert checkpoint.durability["pending_files"] == 0
    checkpoint.close()  # ExitStack and explicit cleanup may both close.
    assert checkpoint._writer is None or not checkpoint._writer.is_alive()


def test_timeout_flushes_when_no_more_results_arrive(tmp_path):
    checkpoint = create(tmp_path)  # Exercise the production one-second deadline.
    try:
        save(checkpoint, 0)
        wait_until(lambda: stored(checkpoint) == 1)
        assert checkpoint.durability["durable_files"] == 1
        assert checkpoint.durability["pending_files"] == 0
    finally:
        checkpoint.close()


def test_slow_arrivals_do_not_reset_oldest_result_deadline(tmp_path):
    checkpoint = create(tmp_path, interval=0.1)
    running = threading.Event()
    finish = threading.Event()
    errors = []
    def producer():
        try:
            running.set()
            for index in range(20):
                save(checkpoint, index)
                if finish.wait(0.04):
                    break
        except BaseException as error:
            errors.append(error)
    thread = threading.Thread(target=producer)
    thread.start()
    try:
        assert running.wait(2)
        wait_until(lambda: stored(checkpoint) > 0)
        assert thread.is_alive(), "commit must happen while slow arrivals continue"
    finally:
        finish.set()
        thread.join()
        checkpoint.close()
    assert not errors


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_workers_commit_bounded_batches_without_losing_or_duplicating_rows(tmp_path, workers):
    checkpoint = create(tmp_path)
    batches = []
    inserts = 0
    def trace(sql):
        nonlocal inserts
        if sql.lstrip().startswith("INSERT OR REPLACE INTO outcomes"):
            inserts += 1
        elif sql == "COMMIT":
            batches.append(inserts)
            inserts = 0
    checkpoint._connection.set_trace_callback(trace)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda index: save(checkpoint, index), range(129)))
        checkpoint.flush()
        assert checkpoint.durability["durable_files"] == 129
        assert checkpoint.durability["durable_bytes"] == sum(range(1, 130))
        assert sum(batches) == 129 and all(0 < count <= 32 for count in batches)
        records = list(checkpoint.records())
        assert len(records) == 129
        assert [row.report["target_findings"][0]["synthetic_occurrence"]
                for row in records] == list(range(129))
    finally:
        checkpoint.close()


def test_replaced_path_has_one_durable_row_and_correct_bytes(tmp_path):
    checkpoint = create(tmp_path)
    try:
        save(checkpoint, 0)
        save(checkpoint, 0)
        checkpoint.flush()
        checkpoint.save_outcome(relative_path="file-00000", size=7, mtime_ns=2,
            report=None, error_reason="SYNTHETIC_ERROR")
        checkpoint.mark_complete()
        assert checkpoint.durability["durable_files"] == 1
        assert checkpoint.durability["durable_bytes"] == 7
        assert list(checkpoint.records())[0].error_reason == "SYNTHETIC_ERROR"
        with sqlite3.connect(checkpoint.path) as db:
            assert db.execute("SELECT value FROM metadata WHERE key='state'").fetchone() == ("COMPLETE",)
    finally:
        checkpoint.close()


def test_large_report_flushes_before_count_limit(tmp_path):
    checkpoint = create(tmp_path)
    try:
        report = {"padding": "x" * (8 * 1024**2), "target_findings": []}
        checkpoint.save_outcome(relative_path="large", size=1, mtime_ns=1,
            report=report, error_reason=None)
        assert stored(checkpoint) == 1
        assert checkpoint.durability["pending_files"] == 0
        assert next(checkpoint.records()).report == report
    finally:
        checkpoint.close()


class CommitFailure:
    def __init__(self, connection):
        self.connection = connection
    def __getattr__(self, name):
        return getattr(self.connection, name)
    def __enter__(self):
        return self.connection.__enter__()
    def __exit__(self, *args):
        self.connection.rollback()
        raise sqlite3.OperationalError("synthetic disk full at COMMIT")


@pytest.mark.parametrize("failure", ["insert", "commit", "timer"])
def test_sqlite_error_is_latched_and_never_advertises_pending_rows_as_durable(tmp_path, failure):
    checkpoint = create(tmp_path, interval=0.05)
    if failure == "insert":
        checkpoint._connection.execute("""CREATE TRIGGER fail BEFORE INSERT ON outcomes
            BEGIN SELECT RAISE(ABORT, 'synthetic disk full at INSERT'); END""")
    else:
        checkpoint._connection = CommitFailure(checkpoint._connection)
    save(checkpoint, 0)
    if failure == "timer":
        wait_until(lambda: checkpoint._failure is not None)
    for operation in (checkpoint.flush, lambda: save(checkpoint, 1), checkpoint.mark_complete):
        with pytest.raises(FolderCheckpointError, match="synthetic disk full"):
            operation()
    assert checkpoint.durability["durable_files"] == 0
    assert checkpoint.durability["pending_files"] == 1
    assert stored(checkpoint) == 0
    with pytest.raises(FolderCheckpointError, match="synthetic disk full"):
        checkpoint.close()
    checkpoint.close()
    assert checkpoint._writer is None or not checkpoint._writer.is_alive()
    with sqlite3.connect(checkpoint.path) as db:
        assert db.execute("SELECT value FROM metadata WHERE key='state'").fetchone() == ("IN_PROGRESS",)


def test_failed_second_batch_keeps_first_batch_durable(tmp_path):
    checkpoint = create(tmp_path)
    for index in range(32):
        save(checkpoint, index)
    checkpoint._connection = CommitFailure(checkpoint._connection)
    save(checkpoint, 32)
    with pytest.raises(FolderCheckpointError, match="COMMIT"):
        checkpoint.flush()
    assert checkpoint.durability["durable_files"] == stored(checkpoint) == 32
    assert checkpoint.durability["pending_files"] == 1
    with pytest.raises(FolderCheckpointError):
        checkpoint.close()


def test_interrupted_commit_is_retried_by_controlled_close(tmp_path):
    checkpoint = create(tmp_path)
    class Interrupted(CommitFailure):
        once = True
        def __exit__(self, *args):
            if self.once:
                self.once = False
                self.connection.rollback()
                raise KeyboardInterrupt
            return self.connection.__exit__(*args)
    checkpoint._connection = Interrupted(checkpoint._connection)
    save(checkpoint, 0)
    with pytest.raises(KeyboardInterrupt):
        checkpoint.flush()
    assert checkpoint.durability["durable_files"] == 0
    assert checkpoint.durability["pending_files"] == 1
    checkpoint.close()
    assert stored(checkpoint) == checkpoint.durability["durable_files"] == 1


def test_legacy_schema_and_payload_survive_resume_without_migration(tmp_path):
    path = tmp_path / "checkpoint.sqlite"
    original = json.dumps({"target_findings": [], "path": "portfel-\u017c\u00f3\u0142ty.dat"}, ensure_ascii=False)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("""CREATE TABLE outcomes (relative_path TEXT PRIMARY KEY,
            size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, report_json TEXT, error_reason TEXT)""")
        db.executemany("INSERT INTO metadata VALUES (?, ?)", [
            ("schema_version", "1"), ("source_root", str(tmp_path.resolve())),
            ("snapshot_sha256", "synthetic-snapshot"), ("state", "IN_PROGRESS"),
            ("semantics_json", json.dumps({"file_workers": 1}))])
        db.execute("INSERT INTO outcomes VALUES ('legacy', 1, 1, ?, NULL)", (original,))
        schema = db.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
    checkpoint = FolderScanCheckpoint.resume(path, root=tmp_path,
        snapshot_sha256="synthetic-snapshot", semantics={"file_workers": 4})
    try:
        checkpoint.set_batching()
        save(checkpoint, 0)
        checkpoint.flush()
        assert checkpoint.record_count() == 2
    finally:
        checkpoint.close()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT report_json FROM outcomes WHERE relative_path='legacy'").fetchone()[0] == original
        assert db.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall() == schema


@pytest.mark.parametrize("crash", ["pending", "transaction"])
def test_process_crash_replays_only_uncommitted_batch(tmp_path, crash):
    # os._exit bypasses finally/context managers and Python shutdown handlers.
    code = '''
import os, sys
from pathlib import Path
from bfrs.scanners.folder_scan_checkpoint import FolderScanCheckpoint
root = Path(sys.argv[1])
c = FolderScanCheckpoint.create(root / 'checkpoint.sqlite', root=root,
    snapshot_sha256='synthetic-snapshot', semantics={'file_workers': 1})
c.set_batching(32, 1.0)
if sys.argv[2] == 'transaction':
    class Crash:
        commits = 0
        def __getattr__(self, name): return getattr(self.connection, name)
        def __enter__(self): return self.connection.__enter__()
        def __exit__(self, *args):
            self.commits += 1
            if self.commits == 2: os._exit(19)
            return self.connection.__exit__(*args)
    wrapper = Crash()
    wrapper.connection = c._connection
    c._connection = wrapper
for i in range(37 if sys.argv[2] == 'pending' else 64):
    c.save_outcome(relative_path=f'file-{i:05d}', size=i+1, mtime_ns=1,
        report={'target_findings': [{'synthetic_occurrence': i}]}, error_reason=None)
os._exit(19)
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path), crash],
        env=env, capture_output=True, timeout=20)
    assert result.returncode == 19, result.stderr.decode("utf-8", errors="replace")
    checkpoint = FolderScanCheckpoint.resume(tmp_path / "checkpoint.sqlite", root=tmp_path,
        snapshot_sha256="synthetic-snapshot", semantics={"file_workers": 4})
    checkpoint.set_batching()
    total = 37 if crash == "pending" else 64
    try:
        assert checkpoint.record_count() == 32
        existing = {row.relative_path for row in checkpoint.records()}
        for index in range(total):
            if f"file-{index:05d}" not in existing:
                save(checkpoint, index)
        checkpoint.flush()
        assert checkpoint.record_count() == total
        assert [row.report["target_findings"][0]["synthetic_occurrence"]
                for row in checkpoint.records()] == list(range(total))
        checkpoint.mark_complete()
    finally:
        checkpoint.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
@pytest.mark.parametrize("stop_kind", ["cooperative", "keyboard"])
def test_controlled_stop_flushes_completed_files_and_resume_has_exactly_one_occurrence(
    tmp_path, workers, stop_kind,
):
    from bfrs.cli import build_parser
    from bfrs.scanners.folder_source_scanner import scan_folder_source
    from tests.test_cli import basic_arguments
    source = tmp_path / "source"
    source.mkdir()
    for index in range(80):
        (source / f"file-{index:05d}").write_bytes(b"synthetic bytes")
    path = tmp_path / "checkpoint.sqlite"
    report = tmp_path / "report.json"
    stopped = threading.Event()
    progress = []
    def child(argv):
        if stopped.is_set():
            return 130
        file = Path(argv[argv.index("--input")+1])
        return {"target_findings": [{"file_path": str(file), "target": "secrets",
                "synthetic_occurrence": file.name}], "raw_hit_count": 1}
    def update(event):
        progress.append(event)
        if event.stage == "folder-scan" and event.scanned_files >= 11 and not stopped.is_set():
            stopped.set()
            if stop_kind == "keyboard":
                raise KeyboardInterrupt
    parser = build_parser()
    first = parser.parse_args(basic_arguments(source, report) + [
        "--file-workers", str(workers), "--checkpoint", str(path)])
    first._scan_should_stop = stopped.is_set
    assert scan_folder_source(first, child, progress_callback=update) == 130
    assert not report.exists()
    with sqlite3.connect(path) as db:
        durable = db.execute("SELECT count(*) FROM outcomes").fetchone()[0]
    assert 11 <= durable < 80
    assert any(event.checkpoint_pending_files and
        event.checkpoint_durable_files < event.scanned_files for event in progress)
    assert all(event.checkpoint_durable_files + event.checkpoint_pending_files == event.scanned_files
        for event in progress if event.stage == "folder-scan")
    final = [event for event in progress if event.stage == "folder-scan"][-1]
    assert final.checkpoint_durable_files == durable
    assert final.checkpoint_pending_files == 0
    stopped.clear()
    remaining = []
    def resumed(argv):
        remaining.append(argv[argv.index("--input")+1])
        return child(argv)
    second = parser.parse_args(basic_arguments(source, report) + [
        "--file-workers", str(workers), "--resume-checkpoint", str(path)])
    assert scan_folder_source(second, resumed) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert len(remaining) == 80-durable
    assert payload["checkpoint"]["resumed_files"] == durable
    assert payload["files_scanned"] == 80
    occurrences = [row["synthetic_occurrence"] for row in payload["target_findings"]]
    assert len(occurrences) == len(set(occurrences)) == 80


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_real_synthetic_target_findings_survive_batched_stop_resume(tmp_path, workers):
    from bfrs.cli import main
    from tests.test_cli import basic_arguments, structural_metadata, encrypted_electrum, valid_wif
    from tests.test_mnemonic_recovery_v1 import bip39_phrase
    source = tmp_path / "source"
    source.mkdir()
    fixtures = [structural_metadata(), encrypted_electrum(), valid_wif(),
                bip39_phrase("english").encode("utf-8")]
    for index in range(40):
        (source / f"file-{index:05d}").write_bytes(fixtures[index] if index < 4 else b"synthetic bytes")
    options = ["--targets", "all", "--workers", "1", "--file-workers", str(workers)]
    baseline = tmp_path / "baseline.json"
    assert main(basic_arguments(source, baseline) + options) == 0
    checkpoint = tmp_path / "checkpoint.sqlite"
    report = tmp_path / "resumed.json"
    stop = threading.Event()
    def update(event):
        if event.stage == "folder-scan" and event.scanned_files >= 5:
            stop.set()
    assert main(basic_arguments(source, report) + options + ["--checkpoint", str(checkpoint)],
        _scan_progress=update, _scan_should_stop=stop.is_set) == 130
    assert main(basic_arguments(source, report) + options + ["--resume-checkpoint", str(checkpoint)]) == 0
    expected = json.loads(baseline.read_text(encoding="utf-8"))
    actual = json.loads(report.read_text(encoding="utf-8"))
    assert actual["target_findings"] == expected["target_findings"]
    assert actual["files_scanned"] == expected["files_scanned"] == 40
    assert {row["target"] for row in actual["target_findings"]} >= {"bitcoin-core", "electrum", "secrets"}
    assert any(row.get("artifact_kind") == "mnemonic" for row in actual["target_findings"])


def test_service_stop_event_reports_durable_bytes_and_exposes_both_counters(tmp_path):
    from bfrs.application.scan_config import ScanConfig
    from bfrs.application.scan_events import ScanCheckpointSavedEvent, ScanProgressEvent
    from bfrs.application.scan_service import ScanController, ScanService
    source = tmp_path / "source"
    source.mkdir()
    for index in range(12):
        (source / f"file-{index:05d}").write_bytes(b"synthetic bytes")
    checkpoint = tmp_path / "checkpoint.sqlite"
    controller = ScanController()
    events = []
    def sink(event):
        events.append(event)
        if isinstance(event, ScanProgressEvent) and event.scanned_files and event.scanned_files >= 3:
            controller.request_stop()
    service = ScanService(controller=controller, event_sink=sink)
    result = service.run(ScanConfig(input_path=source, output_path=tmp_path / "report.json",
        checkpoint=checkpoint, targets=frozenset({"secrets"}), file_workers=2))
    assert result.exit_code == 130
    with sqlite3.connect(checkpoint) as db:
        count, size = db.execute("SELECT count(*), sum(size) FROM outcomes").fetchone()
    saved = [event for event in events if isinstance(event, ScanCheckpointSavedEvent)]
    progress = [event for event in events if isinstance(event, ScanProgressEvent) and event.scanned_files]
    assert saved[-1].completed_bytes == size
    assert progress[-1].checkpoint_durable_files == count
    assert progress[-1].checkpoint_pending_files == 0


def test_service_sqlite_failure_does_not_publish_report_or_saved_event(tmp_path, monkeypatch):
    from bfrs.application.scan_config import ScanConfig
    from bfrs.application.scan_events import ScanCheckpointSavedEvent, ScanFailedEvent, ScanCompletedEvent
    from bfrs.application.scan_service import ScanService
    original = FolderScanCheckpoint.create
    def failing(cls, *args, **kwargs):
        checkpoint = original(*args, **kwargs)
        checkpoint._connection.execute("""CREATE TRIGGER fail BEFORE INSERT ON outcomes
            BEGIN SELECT RAISE(ABORT, 'synthetic disk full'); END""")
        return checkpoint
    monkeypatch.setattr(FolderScanCheckpoint, "create", classmethod(failing))
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_bytes(b"synthetic bytes")
    report = tmp_path / "report.json"
    events = []
    result = ScanService(event_sink=events.append).run(ScanConfig(input_path=source,
        output_path=report, checkpoint=tmp_path / "checkpoint.sqlite", targets=frozenset({"secrets"})))
    assert result.exit_code == 3
    assert not report.exists()
    assert isinstance(events[-1], ScanFailedEvent)
    assert not any(isinstance(event, (ScanCheckpointSavedEvent, ScanCompletedEvent)) for event in events)


def test_interrupt_during_report_can_resume_without_rescanning(tmp_path):
    from bfrs.cli import build_parser
    from bfrs.scanners.folder_source_scanner import scan_folder_source
    from tests.test_cli import basic_arguments
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_bytes(b"synthetic bytes")
    path = tmp_path / "checkpoint.sqlite"
    report = tmp_path / "report.json"
    parser = build_parser()
    args = parser.parse_args(basic_arguments(source, report) + ["--checkpoint", str(path)])
    def interrupt(event):
        if event.stage == "folder-report":
            raise KeyboardInterrupt
    payload = {"target_findings": [], "raw_hit_count": 0}
    assert scan_folder_source(args, lambda argv: payload, progress_callback=interrupt) == 130
    assert not report.exists()
    args = parser.parse_args(basic_arguments(source, report) + ["--resume-checkpoint", str(path)])
    def forbidden(argv):
        raise AssertionError("committed outcomes must survive report interruption")
    assert scan_folder_source(args, forbidden) == 0
    assert json.loads(report.read_text(encoding="utf-8"))["checkpoint"]["resumed_files"] == 1


@pytest.mark.parametrize("count", [128, 130])
def test_stop_during_restore_does_not_report_record_count_as_durable_bytes(tmp_path, count):
    from bfrs.application.scan_config import ScanConfig
    from bfrs.application.scan_events import ScanCheckpointSavedEvent, ScanProgressEvent
    from bfrs.application.scan_service import ScanController, ScanService, build_cli_arguments
    from bfrs.cli import build_parser
    from bfrs.scanners.folder_source_scanner import discover_regular_files, _folder_checkpoint_semantics
    from bfrs.scanners.folder_scan_checkpoint import folder_snapshot_digest
    source = tmp_path / "source"
    source.mkdir()
    for index in range(count):
        (source / f"file-{index:05d}").write_bytes(b"")
    path = tmp_path / "checkpoint.sqlite"
    config = ScanConfig(input_path=source, output_path=tmp_path / "report.json",
        resume_checkpoint=path, targets=frozenset({"secrets"}))
    files, _ = discover_regular_files(source)
    args = build_parser().parse_args(build_cli_arguments(config))
    with FolderScanCheckpoint.create(path, root=source,
            snapshot_sha256=folder_snapshot_digest(source, files),
            semantics=_folder_checkpoint_semantics(args)) as checkpoint:
        checkpoint.set_batching()
        for file, size, mtime in files:
            checkpoint.save_outcome(relative_path=file.name, size=size, mtime_ns=mtime,
                report={"target_findings": []}, error_reason=None)
    events = []
    controller = ScanController()
    def sink(event):
        events.append(event)
        if isinstance(event, ScanProgressEvent) and event.stage == "folder-checkpoint-restore" and event.scanned_bytes >= 128:
            controller.request_stop()
    result = ScanService(controller=controller, event_sink=sink).run(config)
    assert result.exit_code == 130
    saved = [event for event in events if isinstance(event, ScanCheckpointSavedEvent)]
    assert saved[-1].completed_bytes == 0  # Durable empty files, not 128 bytes.
    assert events[-1].processed_bytes == 0
