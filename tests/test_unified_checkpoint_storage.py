import json
from pathlib import Path
import sqlite3

import pytest

from bfrs.cli import main
from bfrs.core.models import RawHit
from bfrs.recovery.unified_checkpoint_storage import MAX_PERSISTED_HITS_PER_UNIT
from bfrs.recovery.unified_scan_checkpoint import (
    UNIFIED_CHECKPOINT_FORMAT_VERSION,
    UNIFIED_CHECKPOINT_SCHEMA_VERSION,
    UNIFIED_SCANNER_SEMANTICS_VERSION,
    UnifiedCheckpointError,
    UnifiedScanCheckpoint,
    _serialize_hit,
    build_scanner_identity,
)
from bfrs.scanners.fast_scanner import Signature


def identity(*, semantics=UNIFIED_SCANNER_SEMANTICS_VERSION):
    return build_scanner_identity(
        targets=("bitcoin-core",),
        signatures=(
            Signature(
                "marker", b"marker", "test", "bitcoin-core", "wallet_record"
            ),
        ),
        mnemonic_enabled=False,
        bitcoin_context_enabled=False,
        semantics_version=semantics,
    )


def create(tmp_path, *, end=100_000):
    source = tmp_path / "source.bin"
    source.write_bytes(b"synthetic")
    checkpoint = UnifiedScanCheckpoint.create(
        tmp_path / "scan.checkpoint.json",
        source,
        start=0,
        end=end,
        chunk_size=10,
        overlap=0,
        scanner_identity=identity(),
    )
    return source, checkpoint


def resume(source: Path, checkpoint, *, identity_value=None, end=100_000):
    return UnifiedScanCheckpoint.resume(
        checkpoint.path,
        source,
        start=0,
        end=end,
        chunk_size=10,
        overlap=0,
        scanner_identity=identity_value or identity(),
    )


def strong_hit(offset=0):
    return RawHit(
        offset,
        offset + 6,
        "marker",
        0.9,
        "synthetic",
        {},
        target="bitcoin-core",
        artifact_kind="wallet_record",
        structural_status="STRUCTURAL",
        validation_status="BITCOIN_RECORD_STRUCTURAL_VALID",
    )


def rejected_hit(offset=0):
    return RawHit(
        offset,
        offset + 6,
        "marker",
        0.0,
        "synthetic",
        {},
        target="bitcoin-core",
        artifact_kind="wallet_record",
        structural_status="REJECTED",
        validation_status="REJECTED",
    )


def weak_hit(offset=0):
    return RawHit(
        offset,
        offset + 6,
        "marker",
        0.0,
        "synthetic",
        {},
        target="bitcoin-core",
        artifact_kind="wallet_record",
    )


def row_count(path, table):
    with sqlite3.connect(path) as connection:
        return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_sqlite_schema_versions_and_normal_resume(tmp_path):
    source, checkpoint = create(tmp_path)
    checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)
    checkpoint.close()

    reopened = resume(source, checkpoint)

    assert reopened.payload["format_version"] == UNIFIED_CHECKPOINT_FORMAT_VERSION
    with sqlite3.connect(checkpoint.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            UNIFIED_CHECKPOINT_SCHEMA_VERSION
        )
    assert tuple(reopened.completed_results) == ((0, 10),)
    assert reopened.completed_results[(0, 10)] == (strong_hit(),)


def test_format_v2_json_is_rejected_without_modification(tmp_path):
    source, checkpoint = create(tmp_path)
    checkpoint.close()
    checkpoint.path.write_text(
        json.dumps({
            "format": "BFRS_UNIFIED_SCAN_CHECKPOINT",
            "format_version": 2,
        }),
        encoding="utf-8",
    )
    original = checkpoint.path.read_bytes()

    with pytest.raises(UnifiedCheckpointError, match="legacy JSON checkpoint"):
        resume(source, checkpoint)

    assert checkpoint.path.read_bytes() == original


def test_committed_unit_survives_process_style_close_and_reopen(tmp_path):
    source, checkpoint = create(tmp_path)
    checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)
    checkpoint.save(force=True)

    assert resume(source, checkpoint).completed_bytes == 10


def test_failed_result_insert_rolls_back_entire_unit(tmp_path):
    source, checkpoint = create(tmp_path)
    with sqlite3.connect(checkpoint.path) as connection:
        connection.execute(
            "CREATE TRIGGER fail_result BEFORE INSERT ON results "
            "BEGIN SELECT RAISE(ABORT, 'simulated crash'); END"
        )

    with pytest.raises(UnifiedCheckpointError, match="persist completed unit"):
        checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)

    checkpoint.close()
    assert row_count(checkpoint.path, "work_units") == 0
    assert row_count(checkpoint.path, "results") == 0
    with sqlite3.connect(checkpoint.path) as connection:
        connection.execute("DROP TRIGGER fail_result")
    assert len(resume(source, checkpoint).completed_results) == 0


def test_uncommitted_final_transaction_is_ignored_on_reopen(tmp_path):
    source, checkpoint = create(tmp_path)
    connection = sqlite3.connect(checkpoint.path)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "INSERT INTO work_units VALUES (?, ?, ?, ?, ?)",
        (0, 10, 0, 0, "interrupted"),
    )
    connection.close()

    assert len(resume(source, checkpoint).completed_results) == 0


def test_duplicate_completion_is_idempotent_and_conflict_is_rejected(tmp_path):
    _source, checkpoint = create(tmp_path)
    checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)
    initial_size = checkpoint.path.stat().st_size
    checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)

    assert row_count(checkpoint.path, "work_units") == 1
    assert row_count(checkpoint.path, "results") == 1
    assert checkpoint.path.stat().st_size == initial_size
    with pytest.raises(UnifiedCheckpointError, match="different results"):
        checkpoint.record((0, 10), (), 10, 100_000)


@pytest.mark.parametrize("failure", [RuntimeError("worker"), KeyboardInterrupt()])
def test_failure_before_completion_does_not_complete_unit(tmp_path, failure):
    source, checkpoint = create(tmp_path)

    with pytest.raises(type(failure)):
        raise failure

    checkpoint.save(force=True)
    assert len(resume(source, checkpoint).completed_results) == 0


def test_rejected_and_unbounded_hit_units_are_replayed_not_persisted(tmp_path):
    source, checkpoint = create(tmp_path)
    checkpoint.record((0, 10), (rejected_hit(),), 10, 100_000)
    too_many = tuple(
        strong_hit(100 + index * 8)
        for index in range(MAX_PERSISTED_HITS_PER_UNIT + 1)
    )
    checkpoint.record((10, 20), too_many, 20, 100_000)
    checkpoint.record((20, 30), (weak_hit(20),), 30, 100_000)
    checkpoint.close()
    reopened = resume(source, checkpoint)

    assert reopened.replay_required_units == ((0, 10), (10, 20), (20, 30))
    assert len(reopened.completed_results) == 0
    assert row_count(checkpoint.path, "results") == 0


def test_close_releases_windows_file_handle(tmp_path):
    source, checkpoint = create(tmp_path)
    checkpoint.record((0, 10), (strong_hit(),), 10, 100_000)
    checkpoint.close()
    moved = checkpoint.path.with_suffix(".moved")

    checkpoint.path.rename(moved)
    moved.rename(checkpoint.path)

    assert resume(source, checkpoint).completed_bytes == 10


def test_cli_creates_and_resumes_sqlite_checkpoint(tmp_path):
    source = tmp_path / "cli-source.bin"
    source.write_bytes(b"synthetic input without wallet material")
    checkpoint = tmp_path / "cli.checkpoint.json"
    first_report = tmp_path / "first.json"
    resumed_report = tmp_path / "resumed.json"
    common = [
        "--input", str(source),
        "--targets", "bitcoin-core",
        "--skip-mnemonic",
        "--chunk-mib", "1",
        "--overlap-kib", "4",
    ]

    assert main([*common, "--output", str(first_report),
                 "--checkpoint", str(checkpoint)]) == 0
    assert checkpoint.read_bytes().startswith(b"SQLite format 3\0")
    assert main([*common, "--output", str(resumed_report),
                 "--resume-checkpoint", str(checkpoint)]) == 0
    first = json.loads(first_report.read_text(encoding="utf-8"))
    resumed = json.loads(resumed_report.read_text(encoding="utf-8"))
    assert first["raw_hit_counts_by_signature"] == (
        resumed["raw_hit_counts_by_signature"]
    )


def test_semantics_source_range_and_schema_mismatches_are_explicit(tmp_path):
    source, checkpoint = create(tmp_path)
    with pytest.raises(UnifiedCheckpointError, match="scanner semantics version differs"):
        resume(source, checkpoint, identity_value=identity(semantics=1))
    other = tmp_path / "other.bin"
    other.write_bytes(b"different")
    with pytest.raises(UnifiedCheckpointError, match="source mismatch"):
        resume(other, checkpoint)
    with pytest.raises(UnifiedCheckpointError, match="scan range differs"):
        resume(source, checkpoint, end=99_999)
    with sqlite3.connect(checkpoint.path) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(UnifiedCheckpointError, match="SQLite schema version"):
        resume(source, checkpoint)


def test_ten_thousand_unit_storage_is_bounded_by_units_not_rejected_hits(tmp_path):
    _source, checkpoint = create(tmp_path)
    noise_per_unit = 100
    rejected = (rejected_hit(),) * noise_per_unit
    accepted_findings = 10
    units = 10_000
    for index in range(units):
        start = index * 10
        hits = (strong_hit(start),) if index < accepted_findings else rejected
        checkpoint.record((start, start + 10), hits, start + 10, units * 10)
    checkpoint.close()

    rejected_count = (units - accepted_findings) * noise_per_unit
    serialized_noise_bytes = len(
        json.dumps(_serialize_hit(rejected_hit()), sort_keys=True).encode()
    )
    old_estimated_bytes = rejected_count * serialized_noise_bytes
    new_bytes = checkpoint.path.stat().st_size

    assert row_count(checkpoint.path, "work_units") == units
    assert row_count(checkpoint.path, "results") == accepted_findings
    assert rejected_count == 999_000
    assert checkpoint.full_rewrite_count == 0
    assert old_estimated_bytes / new_bytes > 100
