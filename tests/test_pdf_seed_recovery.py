from __future__ import annotations

from io import BytesIO
import hashlib
import json
import sys
import zlib

import pytest
from pypdf import PdfReader, PdfWriter

from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.document_seed_recovery import (
    DocumentSeedRecovery,
    _pdf_text_units,
)
from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.mnemonic_recovery_pipeline import MnemonicRecoveryPipeline
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner


ELECTRUM_V1 = "hardly point goal hallway patience key stone difference ready caught listen fact"


def _bip39_phrase(entropy_bits: int = 128) -> str:
    validator = BIP39Validator()
    entropy = bytes(range(entropy_bits // 8))
    checksum_length = entropy_bits // 32
    bits = "".join(f"{byte:08b}" for byte in entropy)
    bits += f"{hashlib.sha256(entropy).digest()[0]:08b}"[:checksum_length]
    words = sorted(validator.indices["english"],
                   key=validator.indices["english"].get)
    return " ".join(words[int(bits[index:index + 11], 2)]
                    for index in range(0, len(bits), 11))


def _electrum_v2_phrase() -> str:
    validator = ElectrumSeedValidator()
    words = sorted(validator.wordlists["english"])
    for number in range(100_000):
        phrase = " ".join([words[0]] * 11 + [words[number % len(words)]])
        if validator.validate(phrase).status == "ELECTRUM_SEED_VALID":
            return phrase
    raise AssertionError("deterministic Electrum 2+ fixture not found")


def _pdf_literal(text: str) -> bytes:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode(
        "latin-1")


def pdf_fixture(pages: list[str | None], *, compressed: bool = True) -> bytes:
    """Build a small deterministic text PDF without relying on production parsing code."""
    objects: dict[int, bytes] = {}
    page_ids = [4 + index * 2 for index in range(len(pages))]
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = b" ".join(f"{page_id} 0 R".encode() for page_id in page_ids)
    objects[2] = b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(
        len(pages)).encode() + b" >>"
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    for index, text in enumerate(pages):
        page_id = page_ids[index]
        stream_id = page_id + 1
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>"
        ).encode()
        content = (b"" if text is None else
                   b"BT /F1 11 Tf 72 720 Td (" + _pdf_literal(text) + b") Tj ET")
        payload = zlib.compress(content) if compressed else content
        filter_value = b" /Filter /FlateDecode" if compressed else b""
        objects[stream_id] = (b"<< /Length " + str(len(payload)).encode() + filter_value +
                              b" >>\nstream\n" + payload + b"\nendstream")
    result = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id in range(1, max(objects, default=0) + 1):
        offsets.append(len(result))
        result.extend(f"{object_id} 0 obj\n".encode())
        result.extend(objects[object_id])
        result.extend(b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n".encode())
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend((f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
                   f"startxref\n{xref}\n%%EOF\n").encode())
    return bytes(result)


def _scan_pdf(data: bytes):
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    return DocumentSeedRecovery(scanner).scan_bytes(
        data, source="fixture.pdf", suffix=".pdf", path="fixture.pdf")


@pytest.mark.parametrize("phrase,standard", [
    (_bip39_phrase(128), "BIP39"),
    (_bip39_phrase(256), "BIP39"),
    (ELECTRUM_V1, "ELECTRUM_V1"),
    (_electrum_v2_phrase(), "ELECTRUM"),
])
def test_pdf_extracts_all_existing_mnemonic_standards(phrase, standard):
    result = _scan_pdf(pdf_fixture([phrase], compressed=True))
    match = next(item for item in result.occurrences
                 if item.candidate.mnemonic_standard == standard)
    candidate = match.candidate
    assert candidate.source_kind == "PDF_TEXT"
    assert candidate.confidence == "MEDIUM"
    assert candidate.physical_start is None
    assert candidate.physical_end is None
    assert candidate.safe_metadata["page_number"] == 1
    assert candidate.safe_metadata["extractor"] == "pypdf_page_extract_text"
    assert phrase not in json.dumps(candidate.safe_dict())
    assert result.failures == ()


def test_pdf_page_provenance_and_page_boundary_are_isolated():
    phrase = _bip39_phrase()
    pages = ["ordinary first page", phrase, "ordinary third page"]
    result = _scan_pdf(pdf_fixture(pages))
    matches = [item for item in result.occurrences
               if item.candidate.mnemonic_standard == "BIP39"]
    assert len(matches) == 1
    assert matches[0].candidate.safe_metadata["page_number"] == 2
    words = phrase.split()
    split = _scan_pdf(pdf_fixture([" ".join(words[:6]), " ".join(words[6:])]))
    assert not [item for item in split.occurrences
                if item.candidate.mnemonic_standard == "BIP39"]


@pytest.mark.parametrize("text", [
    "ordinary prose without any recovery material",
    "similar,term,lizard-like,lobster-like,mammal-like,abstract,ability,able,about,above,absent,absorb",
    ",".join(_bip39_phrase().split()),
    " intruder ".join(_bip39_phrase().split()),
])
def test_pdf_false_positive_controls(text):
    assert not _scan_pdf(pdf_fixture([text])).occurrences


def test_pdf_no_text_empty_malformed_and_truncated_fail_closed():
    assert _scan_pdf(pdf_fixture([None])).failures == ("PDF_NO_TEXT",)
    assert _scan_pdf(pdf_fixture([])).failures == ("PDF_NO_TEXT",)
    assert _scan_pdf(b"%PDF-1.4\nnot a pdf").failures == ("PDF_PARSE_FAILED",)
    truncated = pdf_fixture([_bip39_phrase()])[:100]
    assert _scan_pdf(truncated).failures == ("PDF_PARSE_FAILED",)


def test_pdf_encrypted_is_rejected_without_password_attempt():
    reader = PdfReader(BytesIO(pdf_fixture([_bip39_phrase()])))
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.encrypt("public-test-password")
    output = BytesIO()
    writer.write(output)
    result = _scan_pdf(output.getvalue())
    assert result.occurrences == ()
    assert result.failures == ("PDF_ENCRYPTED",)


def test_pdf_text_resource_limit_is_deterministic(monkeypatch):
    monkeypatch.setattr(
        "bfrs.recovery.mnemonic.document_seed_recovery.MAX_EXTRACTED_TEXT_BYTES", 100)
    result = _scan_pdf(pdf_fixture(["ordinary text " * 20]))
    assert result.occurrences == ()
    assert result.failures == ("PDF_TEXT_LIMIT",)


def test_pdf_missing_dependency_has_deterministic_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, "pypdf", None)
    units, failure = _pdf_text_units(pdf_fixture([_bip39_phrase()]))
    assert units == ()
    assert failure == "PDF_DEPENDENCY_UNAVAILABLE"


def test_checkpoint_v3_raw_resume_still_runs_pdf_document_phase(tmp_path):
    phrase = _bip39_phrase()
    source = tmp_path / "resumed.pdf"
    source.write_bytes(pdf_fixture([phrase], compressed=True))
    scanner = RawMnemonicScanner(chunk_size=8192, overlap=4096)
    raw = scanner.scan_path(source)
    size = source.stat().st_size
    result = MnemonicRecoveryPipeline(chunk_size=8192, overlap=4096).scan(
        source, resume_results={(0, size): raw})
    candidate = next(item for item in result.recovery.candidates
                     if item.mnemonic_standard == "BIP39")
    assert candidate.source_kind == "PDF_TEXT"
    assert result.recovery.document_candidates == 1


def test_pdf_and_raw_duplicate_preserve_correlated_provenance(tmp_path):
    phrase = _bip39_phrase()
    source = tmp_path / "duplicate.pdf"
    source.write_bytes(pdf_fixture([phrase], compressed=False))
    result = MnemonicRecoveryPipeline(chunk_size=8192, overlap=4096).scan(source)
    candidate = next(item for item in result.recovery.candidates
                     if item.mnemonic_standard == "BIP39")
    assert candidate.duplicate_count >= 2
    assert {"RAW_BYTES", "PDF_TEXT"} <= set(candidate.correlated_sources)
    pdf_provenance = next(item for item in candidate.provenance
                          if item["source_kind"] == "PDF_TEXT")
    assert pdf_provenance["document_page"] == 1
    assert pdf_provenance["physical_start"] is None
    assert result.recovery.document_candidates == 1
