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


@pytest.mark.parametrize("delimiter", [" \r\n\t ", ", ; ", " / "])
def test_raw_scanner_multiline_and_punctuation_delimiters(delimiter):
    phrase = bip39_phrase("english")
    decorated = delimiter.join(phrase.split()).encode()
    result = RawMnemonicScanner(chunk_size=8192, overlap=4096).scan_bytes(decorated)
    assert any(item.candidate.mnemonic_standard == "BIP39"
               for item in result.occurrences)


def test_chunk_boundary_and_overlap_dedup(tmp_path):
    phrase = bip39_phrase("english")
    source = tmp_path / "image.bin"
    source.write_bytes(b"x" * 7999 + b":" + phrase.encode() + b":" + b"z" * 7999)
    result = RawMnemonicScanner(chunk_size=12_000, overlap=4096).scan_path(source)
    matches = [item for item in result.occurrences
               if item.candidate.mnemonic_standard == "BIP39"]
    assert len(matches) == 1
    assert matches[0].candidate.physical_start == 8000


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
