from __future__ import annotations

from concurrent.futures import Future
import hashlib
import json

import pytest

from bfrs.cli import main
from bfrs.core.chunk_reader import Chunk, ChunkReader
from bfrs.core.secp256k1 import GENERATOR, encode_sec_public_key
from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
from bfrs.recovery.unified_scan_checkpoint import UnifiedScanCheckpoint
from bfrs.reporting.json_report import serialize_full_image_result
from bfrs.scanners.fast_scanner import FastScanner, Signature
from bfrs.scanners.target_registry import (
    LEGACY_TARGETS,
    MnemonicChunkDetector,
    build_target_selection,
)
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.candidate_policy import CandidatePolicy

from tests.test_electrum_v1_mnemonic import OFFICIAL_WORDS
from tests.test_mnemonic_recovery_v1 import bip39_phrase, electrum_phrase


CHUNK_SIZE = 8192
OVERLAP = 4096


def _base58check(payload: bytes) -> bytes:
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(alphabet[remainder])
    return alphabet[:1] * (len(raw) - len(raw.lstrip(b"\x00"))) + bytes(reversed(encoded))


def _fixture() -> tuple[bytes, dict[str, int]]:
    bip39 = bip39_phrase("english").encode()
    electrum_v1 = OFFICIAL_WORDS.encode()
    electrum_v2 = electrum_phrase().encode()
    address = _base58check(b"\x00" + b"\x11" * 20)
    public_key = encode_sec_public_key(GENERATOR, compressed=True)
    textual_pubkey = public_key.hex().encode()
    raw_record = b"\x04ckey" + bytes((len(public_key),)) + public_key
    parts = (
        (CHUNK_SIZE - len(bip39) // 2, bip39, "bip39"),
        (2 * CHUNK_SIZE - len(address) // 2, address, "address"),
        (3 * CHUNK_SIZE - len(raw_record) // 2, raw_record, "raw_record"),
        (4 * CHUNK_SIZE - len(electrum_v1) // 2, electrum_v1, "electrum_v1"),
        (5 * CHUNK_SIZE - len(electrum_v2) // 2, electrum_v2, "electrum_v2"),
        (6 * CHUNK_SIZE - len(textual_pubkey) // 2,
         textual_pubkey, "textual_pubkey"),
        (7 * CHUNK_SIZE - 2, BTREE_MAGIC.to_bytes(4, "little"), "berkeley"),
    )
    data = bytearray(hashlib.shake_256(b"unified-fixture").digest(8 * CHUNK_SIZE))
    offsets = {}
    for offset, value, name in parts:
        data[offset:offset + len(value)] = value
        offsets[name] = offset
    return bytes(data), offsets


def _selection():
    return build_target_selection(
        LEGACY_TARGETS,
        include_mnemonics=True,
        include_bitcoin_context=True,
    )


def _coordinator(selection, *, workers: int = 1):
    if workers != 1:
        selection = build_target_selection(
            LEGACY_TARGETS,
            include_mnemonics=True,
            include_bitcoin_context=True,
            mnemonic_workers=workers,
        )
    return FullImageRecoveryCoordinator(
        selection.signatures,
        CandidatePolicy(min_hits=1, min_distinct_types=1),
        chunk_detectors=selection.chunk_detectors,
        chunk_size=CHUNK_SIZE,
        overlap=OVERLAP,
        cluster_gap=0,
        hotspot_padding=0,
    )


def _logical(result):
    return (
        result.raw_hit_count,
        tuple((item.hit_type, item.start_offset, item.end_offset,
               item.validation_status, item.safe_fingerprint)
              for item in result.target_findings),
        result.evidence["raw_hit_counts_by_signature"],
        result.evidence["mnemonic_recovery"],
    )


def test_unified_run_finds_all_global_families_once_and_reports_coverage(tmp_path):
    payload, offsets = _fixture()
    source = tmp_path / "unified.img"
    source.write_bytes(payload)
    selection = _selection()

    result = _coordinator(selection).scan(source, targets=selection.targets)
    report = serialize_full_image_result(result, {
        "targets": sorted(selection.targets),
        "include_mnemonic": True,
        "skip_mnemonic": False,
    })

    mnemonics = [item for item in result.target_findings
                 if item.artifact_kind == "mnemonic"]
    assert {item.safe_metadata["mnemonic_standard"] for item in mnemonics} == {
        "BIP39", "ELECTRUM", "ELECTRUM_V1"}
    assert len([item for item in mnemonics
                if item.start_offset == offsets["bip39"]]) == 1
    assert len([item for item in result.target_findings
                if item.start_offset == offsets["address"]]) == 1
    assert len([item for item in result.target_findings
                if item.hit_type == "bitcoin_ckey" and
                item.start_offset == offsets["raw_record"]]) == 1
    assert any(item.start_offset == offsets["textual_pubkey"]
               for item in result.target_findings)
    assert dict(result.evidence["raw_hit_counts_by_signature"])[
        "berkeley_metadata_little_endian"] >= 1
    assert report["mnemonic_coverage"]["performed"] is True
    assert report["mnemonic_recovery"]["candidates_total"] == 3
    assert report["io_metrics"]["full_image_linear_pass_count"] == 1
    assert report["io_metrics"]["linear_pass_count"] == 1
    assert report["io_metrics"]["linear_bytes_read"] == len(payload)
    assert json.dumps(report).find(bip39_phrase("english")) == -1


def test_unified_workers_are_logically_identical(tmp_path):
    payload, _ = _fixture()
    source = tmp_path / "workers.img"
    source.write_bytes(payload)
    selection = _selection()
    one = _coordinator(selection, workers=1).scan(source, targets=selection.targets)
    two = _coordinator(selection, workers=2).scan(source, targets=selection.targets)
    assert _logical(one) == _logical(two)


def test_process_worker_scans_supplied_bytes_without_opening_source():
    phrase = bip39_phrase("english").encode()
    detector = MnemonicChunkDetector(frozenset({"BIP39"}), workers=2)
    try:
        hits = detector.submit_chunk(
            Chunk(100, b":" + phrase + b":"),
            source=r"Z:\path-that-does-not-exist\source.img",
            ownership_start=100, ownership_end=102 + len(phrase)).result()
    finally:
        detector.close()
    assert len(hits) == 1
    assert hits[0].safe_metadata["mnemonic_standard"] == "BIP39"


def test_checkpoint_callback_waits_for_target_and_mnemonic_branches(tmp_path):
    phrase = bip39_phrase("english").encode()
    payload = b"MARKER:" + phrase + b":"
    source = tmp_path / "both-branches.bin"
    source.write_bytes(payload)
    detector = MnemonicChunkDetector(frozenset({"BIP39"}), workers=2)
    completed = []
    scanner = FastScanner(
        (Signature("target_marker", b"MARKER", "test"),),
        chunk_detectors=(detector,))

    list(scanner.scan(
        ChunkReader(source, chunk_size=4096),
        unit_complete=lambda unit, hits, done, total: completed.append(hits)))

    assert len(completed) == 1
    assert {hit.hit_type for hit in completed[0]} == {
        "target_marker", "mnemonic_bip39"}


def test_unified_process_branch_has_one_chunk_backpressure(tmp_path):
    class TrackingFuture(Future):
        def __init__(self, owner):
            super().__init__()
            self.owner = owner
            self.set_result(())

        def result(self, timeout=None):
            value = super().result(timeout)
            self.owner.outstanding -= 1
            return value

    class TrackingDetector:
        required_overlap = 0
        branch_workers = 2

        def __init__(self):
            self.outstanding = 0
            self.maximum = 0

        def submit_chunk(self, chunk, **kwargs):
            self.outstanding += 1
            self.maximum = max(self.maximum, self.outstanding)
            return TrackingFuture(self)

        def detect_chunk(self, chunk, **kwargs):
            raise AssertionError("unified scan must use the submitted branch")

    source = tmp_path / "backpressure.bin"
    source.write_bytes(b"x" * 100)
    detector = TrackingDetector()
    scanner = FastScanner(
        (Signature("missing", b"never", "test"),),
        chunk_detectors=(detector,))

    assert list(scanner.scan(ChunkReader(source, chunk_size=32, overlap=4))) == []
    assert detector.maximum == 1
    assert detector.outstanding == 0


def test_unified_checkpoint_resume_skips_completed_ownership_and_matches_clean(tmp_path):
    payload, _ = _fixture()
    source = tmp_path / "resume.img"
    source.write_bytes(payload)
    selection = _selection()
    identity = {
        "targets": sorted(selection.targets),
        "signatures": [item.name for item in selection.signatures],
        "mnemonic_enabled": True,
    }
    checkpoint = UnifiedScanCheckpoint.create(
        tmp_path / "unified.checkpoint.json", source,
        start=0, end=len(payload), chunk_size=CHUNK_SIZE, overlap=OVERLAP,
        scanner_identity=identity)

    class Interrupted(Exception):
        pass

    calls = 0

    def stop_after_two(unit, hits, completed, total):
        nonlocal calls
        checkpoint.record(unit, hits, completed, total)
        calls += 1
        if calls == 2:
            raise Interrupted

    scanner = FastScanner(selection.signatures,
                          chunk_detectors=selection.chunk_detectors)
    with pytest.raises(Interrupted):
        list(scanner.scan(ChunkReader(source, CHUNK_SIZE, OVERLAP),
                          unit_complete=stop_after_two))
    checkpoint.save(force=True)
    resumed = UnifiedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=len(payload),
        chunk_size=CHUNK_SIZE, overlap=OVERLAP, scanner_identity=identity)

    clean = _coordinator(selection).scan(source, targets=selection.targets)
    continued = _coordinator(selection).scan(
        source, targets=selection.targets,
        resume_results=resumed.completed_results,
        unit_complete=resumed.record)
    assert _logical(continued) == _logical(clean)
    assert (continued.evidence["io_metrics"]["physical_linear_bytes_read"] <
            clean.evidence["io_metrics"]["physical_linear_bytes_read"])
    serialized = checkpoint.path.read_text(encoding="utf-8")
    assert bip39_phrase("english") not in serialized


def test_mnemonic_coverage_is_explicit_when_stage_is_skipped(tmp_path):
    payload, _ = _fixture()
    source = tmp_path / "skipped.img"
    source.write_bytes(payload)
    selection = build_target_selection(LEGACY_TARGETS, include_mnemonics=False)
    result = _coordinator(selection).scan(source, targets=selection.targets)
    assert result.evidence["mnemonic_coverage"] == {
        "performed": False, "standards": (),
    }
    assert result.evidence["mnemonic_recovery"]["candidates_total"] == 0


@pytest.mark.parametrize("flag,performed,count", [
    ("--include-mnemonic", True, 3),
    ("--skip-mnemonic", False, 0),
])
def test_unified_cli_coverage_and_one_report(tmp_path, flag, performed, count):
    payload, _ = _fixture()
    source = tmp_path / f"cli-{performed}.img"
    report_path = tmp_path / f"cli-{performed}.json"
    source.write_bytes(payload)
    assert main([
        "--input", str(source), "--output", str(report_path), flag,
        "--chunk-mib", "1", "--overlap-kib", "4",
    ]) == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["mnemonic_coverage"]["performed"] is performed
    assert report["mnemonic_recovery"]["candidates_total"] == count
    assert report["io_metrics"]["full_image_linear_pass_count"] == 1
    assert report["io_metrics"]["linear_pass_count"] == 1
    assert report["io_metrics"]["linear_bytes_read"] == len(payload)
