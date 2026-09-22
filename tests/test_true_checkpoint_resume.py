from __future__ import annotations

import sqlite3

import pytest

from bfrs.core.chunk_reader import ChunkReader
from bfrs.recovery.unified_scan_checkpoint import (
    UNIFIED_CHECKPOINT_FORMAT_VERSION,
    UnifiedCheckpointError,
    UnifiedScanCheckpoint,
    build_scanner_identity,
)
from bfrs.scanners.fast_scanner import FastScanner, ScanProgress, Signature


MIB = 1024 * 1024


def identity(signatures):
    return build_scanner_identity(
        targets=("bitcoin-core",), signatures=signatures,
        mnemonic_enabled=False, bitcoin_context_enabled=False,
    )


def create_checkpoint(tmp_path, source, signatures, chunk_size, overlap):
    return UnifiedScanCheckpoint.create(
        tmp_path / "true-resume.checkpoint.sqlite", source,
        start=0, end=source.stat().st_size,
        chunk_size=chunk_size, overlap=overlap,
        scanner_identity=identity(signatures),
    )


def test_512_mib_first_physical_resume_read_skips_five_completed_units(tmp_path):
    size = 512 * MIB
    chunk_size = 64 * MIB
    overlap = 64 * 1024
    source = tmp_path / "synthetic-512mib.img"
    with source.open("wb") as stream:
        stream.truncate(size)
    marker = b"BFRS-SYNTHETIC-MARKER"
    step = chunk_size - overlap
    with source.open("r+b") as stream:
        for index in range(7):
            stream.seek(index * step + 1024)
            stream.write(marker)
    signatures = (Signature(
        "synthetic", marker, "test", "bitcoin-core", "test-anchor"
    ),)
    scanner = FastScanner(signatures)
    checkpoint = create_checkpoint(tmp_path, source, signatures, chunk_size, overlap)
    completed = 0

    class Interrupted(Exception):
        pass

    def stop_after_five(unit, hits, done, total):
        nonlocal completed
        checkpoint.record(unit, hits, done, total)
        completed += 1
        if completed == 5:
            raise Interrupted

    with pytest.raises(Interrupted):
        list(scanner.scan(
            ChunkReader(source, chunk_size, overlap),
            unit_complete=stop_after_five,
        ))
    checkpoint.close()
    resumed = UnifiedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=size,
        chunk_size=chunk_size, overlap=overlap,
        scanner_identity=identity(signatures),
    )
    reads = []
    progress: list[ScanProgress] = []
    list(scanner.scan(
        ChunkReader(source, chunk_size, overlap,
                    read_observer=lambda offset, length: reads.append((offset, length))),
        resume_results=resumed.completed_results,
        unit_complete=resumed.record,
        progress=progress.append,
    ))
    first_unfinished = 5 * step
    assert resumed.completed_bytes == size
    assert reads[0][0] == first_unfinished
    assert reads[0][0] >= first_unfinished - overlap
    assert reads[0][0] != 0
    assert progress[0].scanned_bytes == first_unfinished
    assert progress[0].percent_complete == pytest.approx(
        first_unfinished * 100 / size
    )
    assert progress[0].raw_hits == 5
    assert progress[0].raw_by_target == {"bitcoin-core": 5}
    assert progress[0].pending_validation_by_target == {"bitcoin-core": 5}


def test_boundary_findings_survive_resume_once(tmp_path):
    chunk_size = 64
    overlap = 8
    step = chunk_size - overlap
    marker = b"ABCDE"
    offsets = (step - 6, 2 * step - 1, 3 * step, 4 * step + 1)
    payload = bytearray(b"." * (6 * step))
    for offset in offsets:
        payload[offset:offset + len(marker)] = marker
    source = tmp_path / "boundaries.img"
    source.write_bytes(payload)
    signatures = (Signature(
        "boundary", marker, "test", "bitcoin-core", "test-anchor"
    ),)
    scanner = FastScanner(signatures)
    clean = tuple(scanner.scan(ChunkReader(source, chunk_size, overlap)))
    checkpoint = create_checkpoint(tmp_path, source, signatures, chunk_size, overlap)
    calls = 0

    class Interrupted(Exception):
        pass

    def interrupt(unit, hits, done, total):
        nonlocal calls
        checkpoint.record(unit, hits, done, total)
        calls += 1
        if calls == 3:
            raise Interrupted

    with pytest.raises(Interrupted):
        tuple(scanner.scan(
            ChunkReader(source, chunk_size, overlap), unit_complete=interrupt
        ))
    checkpoint.close()
    resumed = UnifiedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=len(payload),
        chunk_size=chunk_size, overlap=overlap,
        scanner_identity=identity(signatures),
    )
    continued = tuple(scanner.scan(
        ChunkReader(source, chunk_size, overlap),
        resume_results=resumed.completed_results,
        unit_complete=resumed.record,
    ))
    clean_offsets = [hit.start_offset for hit in clean]
    resumed_offsets = [hit.start_offset for hit in continued]
    assert clean_offsets == list(offsets)
    assert resumed_offsets == clean_offsets
    assert len(resumed_offsets) == len(set(resumed_offsets))


def test_committed_unit_is_skipped_and_ctrl_c_checkpoint_remains_valid(tmp_path):
    source = tmp_path / "interrupt.img"
    source.write_bytes(b"marker" + b"." * 200)
    signatures = (Signature(
        "marker", b"marker", "test", "bitcoin-core", "test-anchor"
    ),)
    checkpoint = create_checkpoint(tmp_path, source, signatures, 64, 8)
    scanner = FastScanner(signatures)

    def interrupt(unit, hits, done, total):
        checkpoint.record(unit, hits, done, total)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        tuple(scanner.scan(
            ChunkReader(source, 64, 8), unit_complete=interrupt
        ))
    checkpoint.save(force=True)
    reopened = UnifiedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=source.stat().st_size,
        chunk_size=64, overlap=8, scanner_identity=identity(signatures),
    )
    reads = []
    tuple(scanner.scan(
        ChunkReader(source, 64, 8,
                    read_observer=lambda offset, length: reads.append(offset)),
        resume_results=reopened.completed_results,
        unit_complete=reopened.record,
    ))
    assert reads and reads[0] == 56


@pytest.mark.parametrize("mutation", ["corrupt", "missing"])
def test_corrupt_or_missing_persisted_payload_fails_closed(tmp_path, mutation):
    source = tmp_path / "corrupt.img"
    source.write_bytes(b"marker")
    signatures = (Signature(
        "marker", b"marker", "test", "bitcoin-core", "test-anchor"
    ),)
    checkpoint = create_checkpoint(tmp_path, source, signatures, 64, 8)
    tuple(FastScanner(signatures).scan(
        ChunkReader(source, 64, 8), unit_complete=checkpoint.record
    ))
    checkpoint.close()
    with sqlite3.connect(checkpoint.path) as connection:
        if mutation == "corrupt":
            connection.execute("UPDATE results SET payload = X'00'")
        else:
            connection.execute("DELETE FROM results")
    with pytest.raises(
        UnifiedCheckpointError,
        match=("corrupted persisted state" if mutation == "corrupt"
               else "missing or unsupported persisted state"),
    ):
        UnifiedScanCheckpoint.resume(
            checkpoint.path, source, start=0, end=source.stat().st_size,
            chunk_size=64, overlap=8, scanner_identity=identity(signatures),
        )


def test_v3_sqlite_is_explicitly_rejected_as_legacy_replay(tmp_path):
    source = tmp_path / "legacy.img"
    source.write_bytes(b"synthetic")
    signatures = (Signature(
        "marker", b"marker", "test", "bitcoin-core", "test-anchor"
    ),)
    checkpoint = create_checkpoint(tmp_path, source, signatures, 64, 8)
    checkpoint.close()
    with sqlite3.connect(checkpoint.path) as connection:
        connection.execute("PRAGMA user_version = 1")
        connection.execute(
            "UPDATE metadata SET value = '3' WHERE key = 'format_version'"
        )
    with pytest.raises(
        UnifiedCheckpointError, match="v3 requires legacy replay.*new v4"
    ):
        UnifiedScanCheckpoint.resume(
            checkpoint.path, source, start=0, end=source.stat().st_size,
            chunk_size=64, overlap=8, scanner_identity=identity(signatures),
        )


def test_checkpoint_v4_contract_and_compact_statistics(tmp_path):
    source = tmp_path / "storage.img"
    source.write_bytes((b"marker...." * 1000))
    signatures = (Signature(
        "marker", b"marker", "test", "bitcoin-core", "test-anchor"
    ),)
    checkpoint = create_checkpoint(tmp_path, source, signatures, 1024, 8)
    tuple(FastScanner(signatures).scan(
        ChunkReader(source, 1024, 8), unit_complete=checkpoint.record
    ))
    checkpoint.close()
    reopened = UnifiedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=source.stat().st_size,
        chunk_size=1024, overlap=8, scanner_identity=identity(signatures),
    )
    stats = reopened.storage_statistics
    assert reopened.payload["format_version"] == UNIFIED_CHECKPOINT_FORMAT_VERSION == 4
    assert stats["findings"] == 1000
    assert stats["bytes_per_finding"] < 100
    assert stats["bytes_per_work_unit"] < 8192
