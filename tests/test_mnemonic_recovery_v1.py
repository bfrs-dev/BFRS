from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile

import pytest

from bfrs.cli import main
from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.document_seed_recovery import DocumentSeedRecovery
from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner
from bfrs.recovery.mnemonic.seed_scan_checkpoint import (
    CheckpointError,
    SeedScanCheckpoint,
)
from bfrs.tools.export_recovered_mnemonics import main as export_main
sys.path.insert(0, str(Path(__file__).parent))
from test_ntfs_bitcoin_artifacts import data_resident, file_record, filename, image_with


def bip39_phrase(language: str, entropy_bits: int = 128) -> str:
    validator = BIP39Validator()
    entropy = bytes(range(entropy_bits // 8))
    checksum_length = entropy_bits // 32
    bits = "".join(f"{byte:08b}" for byte in entropy)
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[:checksum_length]
    words = sorted(validator.indices[language], key=validator.indices[language].get)
    return " ".join(words[int(bits[index:index + 11], 2)]
                    for index in range(0, len(bits), 11))


@pytest.mark.parametrize("entropy_bits", [128, 160, 192, 224, 256])
def test_bip39_all_standard_lengths(entropy_bits):
    result = BIP39Validator().validate(bip39_phrase("english", entropy_bits))
    assert result.status == "BIP39_VALID"
    assert result.checksum_valid is True


@pytest.mark.parametrize("language", BIP39Validator().wordlists)
def test_bip39_all_official_languages(language):
    assert BIP39Validator().validate(bip39_phrase(language)).status == "BIP39_VALID"


def test_bip39_rejects_checksum_and_mixed_language():
    validator = BIP39Validator()
    phrase = bip39_phrase("english")
    words = phrase.split()
    ordered = sorted(validator.indices["english"], key=validator.indices["english"].get)
    original = validator.indices["english"][words[-1]]
    words[-1] = ordered[(original + 1) % len(ordered)]
    assert validator.validate(" ".join(words)).status == "BIP39_CHECKSUM_INVALID"
    words[0] = next(iter(validator.wordlists["czech"] - validator.wordlists["english"]))
    assert validator.validate(" ".join(words)).status == "BIP39_WORD_INVALID"
    assert validator.validate(" ".join(words[:11])).status == "BIP39_WORD_COUNT_INVALID"


def test_bip39_whitespace_newlines_and_ambiguous_language():
    phrase = bip39_phrase("english")
    assert BIP39Validator().validate(" \n\t".join(phrase.split())).status == "BIP39_VALID"
    validator = BIP39Validator()
    common = list(validator.wordlists["chinese_simplified"] &
                  validator.wordlists["chinese_traditional"])
    assert validator.validate(" ".join(common[:12])).status == "BIP39_LANGUAGE_AMBIGUOUS"


def test_bip39_validate_words_is_total_for_mojibake_and_wrong_language_hint():
    validator = BIP39Validator()
    words = tuple(["ç›Ş ŮŽ"] * 12)
    result = validator.validate_words(words, languages=("english", "missing"))
    assert result.status == "BIP39_WORD_INVALID"
    assert result.checksum_valid is None


def test_bip39_mixed_wordlists_have_no_common_language():
    validator = BIP39Validator()
    english = next(iter(validator.wordlists["english"] - validator.wordlists["czech"]))
    czech = next(iter(validator.wordlists["czech"] - validator.wordlists["english"]))
    words = tuple([english, czech] * 6)
    assert validator.validate_words(words).status == "BIP39_WORD_INVALID"
    hinted = validator.validate_words(words, languages=("english", "czech"))
    assert hinted.status == "BIP39_WORD_INVALID"


def electrum_phrase() -> str:
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    for number in range(100_000):
        phrase = " ".join([words[0]] * 11 + [words[number % len(words)]])
        if validator.validate(phrase).status == "ELECTRUM_SEED_VALID":
            return phrase
    raise AssertionError("deterministic Electrum fixture not found")


def test_electrum_version_prefix_and_normalization():
    phrase = electrum_phrase()
    validator = ElectrumSeedValidator()
    assert validator.validate(phrase.upper()).status == "ELECTRUM_SEED_VALID"
    assert phrase not in repr(validator.validate(phrase))
    assert validator.validate("ordinary prose cannot be an electrum seed phrase here today").status == "REJECTED"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_raw_scanner_offsets_encodings_and_no_repr_leak(encoding):
    phrase = bip39_phrase("english")
    prefix = "prefix: "
    payload = (prefix + phrase + " :suffix").encode(encoding)
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(payload)
    candidate = next(item.candidate for item in result.occurrences
                     if item.candidate.mnemonic_standard == "BIP39"
                     and item.candidate.encoding == encoding)
    assert candidate.physical_start == len(prefix.encode(encoding))
    assert candidate.physical_end == len((prefix + phrase).encode(encoding))
    assert phrase not in repr(result)
    assert phrase not in json.dumps(candidate.safe_dict())


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("placement", [17, 4096, 7900])
def test_raw_scanner_exact_offsets_at_chunk_positions(encoding, placement):
    phrase = bip39_phrase("english")
    prefix_text = "żółć/" if encoding == "utf-8" else "𝄞/"
    marker = prefix_text.encode(encoding)
    target = placement if encoding == "utf-8" else placement + placement % 2
    target = max(target, len(marker))
    prefix = b"\x00" * (target - len(marker)) + marker
    payload = prefix + phrase.encode(encoding) + ":tail".encode(encoding)
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(payload)
    candidate = next(item.candidate for item in result.occurrences
                     if item.candidate.mnemonic_standard == "BIP39"
                     and item.candidate.encoding == encoding)
    assert candidate.physical_start == len(prefix)
    assert candidate.physical_end == len(prefix) + len(phrase.encode(encoding))


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_raw_scanner_boundary_offsets_all_encodings(tmp_path, encoding):
    phrase = bip39_phrase("english")
    encoded = phrase.encode(encoding)
    start = 8192 - len(encoded) // 2
    if encoding != "utf-8":
        start -= start % 2
    separator = ":".encode(encoding)
    prefix = b"\x00" * (start - len(separator)) + separator
    source = tmp_path / f"boundary-{encoding}.bin"
    source.write_bytes(prefix + encoded + ":tail".encode(encoding))
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_path(source)
    candidate = next(item.candidate for item in result.occurrences
                     if item.candidate.mnemonic_standard == "BIP39"
                     and item.candidate.encoding == encoding)
    assert candidate.physical_start == start
    assert candidate.physical_end == start + len(encoded)


@pytest.mark.parametrize("delimiter", [" \r\n\t ", ", ; ", " / "])
def test_raw_scanner_multiline_and_punctuation_delimiters(delimiter):
    phrase = bip39_phrase("english")
    decorated = delimiter.join(phrase.split()).encode()
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(decorated)
    assert any(item.candidate.mnemonic_standard == "BIP39"
               for item in result.occurrences)


@pytest.mark.parametrize("payload", [
    "ç›Ş ŮŽ " * 12,
    "c\u0327 عربى 目 " * 12,
    "目 عربى " * 12,
])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_raw_scanner_rejects_malformed_multilingual_unicode(payload, encoding):
    data = payload.encode(encoding, errors="surrogatepass")
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(data)
    assert not result.occurrences


@pytest.mark.parametrize("payload", [
    b"\xff\xfe\xfa\x80abandon\xed\xa0\x80",
    b"\x00\xd8a\x00\xff",
    b"\xd8\x00\x00a\xff",
])
def test_raw_scanner_malformed_encoded_bytes_are_controlled(payload):
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(payload)
    assert not result.occurrences


def test_chunk_boundary_and_overlap_dedup(tmp_path):
    phrase = bip39_phrase("english")
    source = tmp_path / "image.bin"
    source.write_bytes(b"x" * 7999 + b":" + phrase.encode() + b":" + b"z" * 7999)
    result = RawMnemonicScanner(chunk_size=12_000, overlap=4096).scan_path(source)
    matches = [item for item in result.occurrences
               if item.candidate.mnemonic_standard == "BIP39"]
    assert len(matches) == 1
    assert matches[0].candidate.physical_start == 8000


def test_scan_path_progress_is_monotonic_and_reaches_end(tmp_path):
    source = tmp_path / "progress.bin"
    source.write_bytes(b"ordinary deterministic prose " * 1000)
    updates = []
    RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_path(
        source, progress=lambda processed, total: updates.append((processed, total)))
    assert updates
    assert [item[0] for item in updates] == sorted(item[0] for item in updates)
    assert updates[-1] == (source.stat().st_size, source.stat().st_size)


def test_parallel_scanner_matches_single_worker_at_ownership_boundaries(tmp_path):
    phrase = bip39_phrase("english").encode()
    payload = bytearray(b"\x00" * 20_000)
    # Before a boundary, crossing a boundary, exactly on a boundary, and later.
    starts = (3000, 4050, 8192, 12_500)
    for start in starts:
        payload[start - 1:start] = b":"
        payload[start:start + len(phrase)] = phrase
        payload[start + len(phrase):start + len(phrase) + 1] = b":"
    source = tmp_path / "parallel-boundaries.bin"
    source.write_bytes(payload)
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    single = scanner.scan_path(source, workers=1)
    parallel = scanner.scan_path(source, workers=4)

    def semantic(result):
        return ([(item.candidate.mnemonic_standard, item.candidate.fingerprint,
                  item.candidate.physical_start, item.candidate.physical_end,
                  item.candidate.validation_status)
                 for item in result.occurrences], result.anchors_found,
                result.checksum_invalid, result.failures)

    assert semantic(parallel) == semantic(single)
    bip39_starts = {item.candidate.physical_start for item in parallel.occurrences
                    if item.candidate.mnemonic_standard == "BIP39"
                    and item.candidate.encoding == "utf-8"}
    assert bip39_starts == set(starts)


def test_seed_cli_workers_one_and_four_have_identical_recovery(tmp_path):
    phrase = bip39_phrase("english")
    source = tmp_path / "parallel-cli.bin"
    source.write_bytes((":" + phrase + ":").encode())
    reports = []
    for workers in (1, 4):
        report = tmp_path / f"workers-{workers}.json"
        assert main(["--input", str(source), "--output", str(report),
                     "--seed-scan-only", "--chunk-mib", "1",
                     "--overlap-kib", "4", "--workers", str(workers)]) == 0
        reports.append(json.loads(report.read_text(encoding="utf-8")))
    assert reports[0]["mnemonic_recovery"] == reports[1]["mnemonic_recovery"]


def test_seed_cli_keyboard_interrupt_is_clean(tmp_path, monkeypatch, capsys):
    source = tmp_path / "interrupt.bin"
    report = tmp_path / "must-not-exist.json"
    checkpoint = tmp_path / "interrupted.checkpoint.json"
    source.write_bytes(b"synthetic")

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("bfrs.cli.MnemonicRecoveryPipeline.scan", interrupt)
    assert main(["--input", str(source), "--output", str(report),
                 "--seed-scan-only", "--overlap-kib", "4",
                 "--checkpoint", str(checkpoint)]) == 130
    assert "scan interrupted by user" in capsys.readouterr().err
    assert not report.exists()
    assert checkpoint.exists()
    assert json.loads(checkpoint.read_text(encoding="utf-8"))["complete"] is False


def _raw_semantic(result):
    return ([(item.candidate.mnemonic_standard, item.candidate.fingerprint,
              item.candidate.physical_start, item.candidate.physical_end,
              item.candidate.validation_status)
             for item in result.occurrences], result.anchors_found,
            result.checksum_invalid, result.failures)


def test_checkpoint_interrupt_resume_workers_one_to_four_matches_clean(tmp_path):
    phrase = bip39_phrase("english").encode()
    source = tmp_path / "resume-source.bin"
    payload = bytearray(b"\x00" * 30_000)
    for start in (2000, 8100, 16_384, 25_000):
        payload[start - 1:start] = b":"
        payload[start:start + len(phrase)] = phrase
        payload[start + len(phrase):start + len(phrase) + 1] = b":"
    source.write_bytes(payload)
    checkpoint_path = tmp_path / "seed.checkpoint.json"
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    checkpoint = SeedScanCheckpoint.create(
        checkpoint_path, source, start=0, end=len(payload),
        chunk_size=8192, overlap=4096)
    completed_units = 0

    def interrupt_near_thirty_percent(unit, result, completed, total):
        nonlocal completed_units
        checkpoint.record(unit, result, completed, total)
        completed_units += 1
        if completed_units == 2:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scanner.scan_path(source, workers=1, unit_complete=interrupt_near_thirty_percent)
    checkpoint.save(force=True)
    resumed = SeedScanCheckpoint.resume(
        checkpoint_path, source, start=0, end=len(payload),
        chunk_size=8192, overlap=4096)
    final = scanner.scan_path(source, workers=4,
                              resume_results=resumed.completed_results,
                              unit_complete=resumed.record)
    clean = scanner.scan_path(source, workers=1)
    assert _raw_semantic(final) == _raw_semantic(clean)


def test_checkpoint_out_of_order_ranges_preserve_gap_and_resume_four_to_two(tmp_path):
    phrase = bip39_phrase("english").encode()
    source = tmp_path / "out-of-order.bin"
    payload = bytearray(b"\x00" * 24_000)
    payload[5000:5000 + len(phrase)] = phrase
    source.write_bytes(payload)
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    units = scanner._plan_work_units(source.resolve(), 0, len(payload))
    checkpoint = SeedScanCheckpoint.create(
        tmp_path / "ranges.json", source, start=0, end=len(payload),
        chunk_size=8192, overlap=4096)
    # Simulate out-of-order completion: first and third are saved, second is a gap.
    for unit in (units[0], units[2]):
        result = scanner._scan_local_unit(unit)
        checkpoint.record(unit, result, 0, len(payload))
    checkpoint.save(force=True)
    restored = SeedScanCheckpoint.resume(
        checkpoint.path, source, start=0, end=len(payload),
        chunk_size=8192, overlap=4096)
    scanned = []

    def track(unit, result, completed, total):
        scanned.append((unit[3], unit[4]))
        restored.record(unit, result, completed, total)

    final = scanner.scan_path(source, workers=2,
                              resume_results=restored.completed_results,
                              unit_complete=track)
    assert (units[1][3], units[1][4]) in scanned
    assert _raw_semantic(final) == _raw_semantic(
        RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_path(source, workers=4))


def test_checkpoint_rejects_wrong_source_size_and_corruption(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"a" * 10_000)
    checkpoint = SeedScanCheckpoint.create(
        tmp_path / "checkpoint.json", source, start=0, end=10_000,
        chunk_size=8192, overlap=4096)
    other = tmp_path / "other.bin"
    other.write_bytes(b"b" * 10_000)
    with pytest.raises(CheckpointError, match="source identity"):
        SeedScanCheckpoint.resume(checkpoint.path, other, start=0, end=10_000,
                                  chunk_size=8192, overlap=4096)
    source.write_bytes(b"a" * 10_001)
    with pytest.raises(CheckpointError, match="source identity"):
        SeedScanCheckpoint.resume(checkpoint.path, source, start=0, end=10_001,
                                  chunk_size=8192, overlap=4096)
    checkpoint.path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(CheckpointError, match="corrupted"):
        SeedScanCheckpoint.resume(checkpoint.path, source, start=0, end=10_001,
                                  chunk_size=8192, overlap=4096)


def test_checkpoint_json_is_atomic_and_contains_no_mnemonic_words(tmp_path):
    phrase = bip39_phrase("english")
    source = tmp_path / "opaque.bin"
    source.write_bytes((":" + phrase + ":").encode())
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    checkpoint = SeedScanCheckpoint.create(
        tmp_path / "safe.json", source, start=0, end=source.stat().st_size,
        chunk_size=8192, overlap=4096)
    scanner.scan_path(source, workers=1, unit_complete=checkpoint.record)
    checkpoint.mark_complete()
    serialized = checkpoint.path.read_text(encoding="utf-8")
    assert phrase not in serialized
    for word in phrase.split():
        assert re.search(rf"(?<![\w]){re.escape(word)}(?![\w])", serialized) is None
    assert not list(tmp_path.glob("safe.json.tmp-*"))


def test_cli_resume_progress_starts_from_completed_canonical_bytes(tmp_path, capsys):
    phrase = bip39_phrase("english").encode()
    source = tmp_path / "cli-resume.bin"
    payload = bytearray(b"\x00" * (2 * 1024 * 1024 + 20_000))
    payload[1_500_000:1_500_000 + len(phrase)] = phrase
    source.write_bytes(payload)
    checkpoint = SeedScanCheckpoint.create(
        tmp_path / "cli-resume.json", source, start=0, end=len(payload),
        chunk_size=1024 * 1024, overlap=4096)
    scanner = RawMnemonicScanner(chunk_size=1024 * 1024, overlap=4096)
    first = scanner._plan_work_units(source.resolve(), 0, len(payload))[0]
    checkpoint.record(first, scanner._scan_local_unit(first),
                      first[4] - first[3], len(payload))
    checkpoint.save(force=True)
    report = tmp_path / "resumed-report.json"
    assert main(["--input", str(source), "--output", str(report),
                 "--seed-scan-only", "--chunk-mib", "1", "--overlap-kib", "4",
                 "--workers", "4", "--resume-checkpoint", str(checkpoint.path)]) == 0
    assert "Seed scan RESUMED" in capsys.readouterr().err
    assert json.loads(report.read_text(encoding="utf-8"))["mnemonic_recovery"][
        "bip39_valid"] == 1


def test_parallel_malformed_unicode_does_not_fail_worker(tmp_path):
    source = tmp_path / "malformed-workers.bin"
    source.write_bytes(("ç›Ş ŮŽ عربى 目 " * 2000).encode() + b"\xff\xed\xa0\x80")
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_path(
        source, workers=4)
    assert not result.occurrences


def test_docx_extraction_and_pdf_isolated_failure(tmp_path):
    phrase = bip39_phrase("english")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml",
                         f'<w:document xmlns:w="x"><w:t>{phrase}</w:t></w:document>')
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    recovery = DocumentSeedRecovery(scanner)
    result = recovery.scan_bytes(stream.getvalue(), source="fixture.docx", suffix=".docx")
    assert any(item.candidate.source_kind == "DOCUMENT_EXTRACTED_TEXT"
               for item in result.occurrences)
    assert all(item.candidate.physical_start is None for item in result.occurrences)
    assert recovery.scan_bytes(b"%PDF", source="x.pdf", suffix=".pdf").failures == (
        "PDF_TEXT_EXTRACTOR_UNAVAILABLE",)


def test_seed_only_cli_safe_report_and_explicit_export(tmp_path, capsys):
    phrase = bip39_phrase("english")
    source = tmp_path / "fixture.bin"
    report = tmp_path / "report.json"
    source.write_bytes(("noise " + phrase + " tail").encode())
    assert main(["--input", str(source), "--output", str(report),
                 "--seed-scan-only", "--chunk-mib", "1", "--overlap-kib", "4"]) == 0
    serialized = report.read_text(encoding="utf-8")
    assert phrase not in serialized
    assert json.loads(serialized)["mnemonic_recovery"]["bip39_valid"] == 1
    secret = tmp_path / "seeds.txt"
    assert export_main(["--input", str(source), "--output", str(secret),
                        "--overlap-kib", "4"]) == 2
    assert not secret.exists()
    assert export_main(["--input", str(source), "--output", str(secret),
                        "--overlap-kib", "4", "--allow-seed-export"]) == 0
    assert secret.read_text(encoding="utf-8").strip() == phrase
    assert phrase not in secret.with_suffix(".txt.manifest.json").read_text(encoding="utf-8")
    assert phrase not in capsys.readouterr().out


def test_pipeline_deduplicates_same_secret(tmp_path):
    phrase = bip39_phrase("english")
    source = tmp_path / "duplicates.bin"
    source.write_bytes((phrase + " separator " + phrase).encode())
    result = MnemonicRecoveryPipeline(chunk_size=8192, overlap=4096).scan(source)
    assert result.recovery.bip39_valid == 1
    assert result.recovery.duplicate_occurrences == 1


@pytest.mark.parametrize("allocated, expected", [(True, "ACTIVE_FILE"),
                                                   (False, "DELETED_FILE")])
def test_ntfs_resident_document_active_and_deleted_provenance(tmp_path, allocated, expected):
    phrase = bip39_phrase("english")
    image = image_with({6: file_record(
        6, (filename("seed.txt"), data_resident(phrase.encode())), allocated=allocated)})
    source = tmp_path / ("active.img" if allocated else "deleted.img")
    source.write_bytes(image)
    result = MnemonicRecoveryPipeline(chunk_size=256 * 1024, overlap=4096).scan(source)
    candidate = next(item for item in result.recovery.candidates
                     if item.mnemonic_standard == "BIP39")
    assert any(item["allocation_state"] == expected for item in candidate.provenance)
    assert any(item["source_kind"] == "KNOWN_FILE_CONTENT" for item in candidate.provenance)
    if not allocated:
        assert result.recovery.deleted_file_candidates <= 1  # secret is deduplicated globally


def test_seed_only_positive_control_combined_synthetic_image(tmp_path):
    phrase = bip39_phrase("english")
    bad = phrase.split()
    ordered = sorted(BIP39Validator().indices["english"],
                     key=BIP39Validator().indices["english"].get)
    bad[-1] = ordered[(BIP39Validator().indices["english"][bad[-1]] + 1) % 2048]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("word/document.xml",
                         f'<w:document xmlns:w="x"><w:t>{phrase}</w:t></w:document>')
    records = {
        5: file_record(5, (filename("notes.txt"), data_resident(
            (phrase + "\n123\n" + " ".join(bad) + "\nrandom prose").encode()))),
        6: file_record(6, (filename("unicode.txt"), data_resident(phrase.encode("utf-16-le")))),
        7: file_record(7, (filename("copy.docx"), data_resident(stream.getvalue()))),
    }
    image = bytearray(image_with(records))
    image.extend(b"\x00" * (2 * 1024 * 1024 - len(image)))
    boundary_start = 1024 * 1024 - len(phrase.encode()) // 2
    image[boundary_start - 1:boundary_start] = b":"
    image[boundary_start:boundary_start + len(phrase.encode())] = phrase.encode()
    image[boundary_start + len(phrase.encode()):boundary_start + len(phrase.encode()) + 1] = b":"
    source = tmp_path / "positive-control.img"
    report = tmp_path / "positive-control.json"
    source.write_bytes(image)
    assert main(["--input", str(source), "--output", str(report), "--seed-scan-only",
                 "--chunk-mib", "1", "--overlap-kib", "4"]) == 0
    payload = json.loads(report.read_text(encoding="utf-8"))
    summary = payload["mnemonic_recovery"]
    assert summary["bip39_valid"] == 1
    assert summary["duplicate_occurrences"] >= 3
    assert summary["checksum_invalid"] >= 1
    assert summary["known_file_candidates"] == 1
    assert summary["document_candidates"] == 1
    safe_text = report.read_text(encoding="utf-8")
    assert phrase not in safe_text
    for word in phrase.split():
        assert re.search(rf"(?<![\w]){re.escape(word)}(?![\w])", safe_text) is None
