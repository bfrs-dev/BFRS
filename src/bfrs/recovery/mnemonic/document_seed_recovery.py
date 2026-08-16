"""Conservative mnemonic recovery from known text/document file content."""

from __future__ import annotations

from dataclasses import dataclass, replace
from html import unescape
from io import BytesIO
from pathlib import Path
import re
import zipfile

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSBitcoinArtifactLocator

from .raw_mnemonic_scanner import MnemonicOccurrence, RawMnemonicScanner


PLAIN_EXTENSIONS = frozenset({".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".rtf"})
DOCUMENT_EXTENSIONS = PLAIN_EXTENSIONS | {".docx", ".pdf"}


@dataclass(frozen=True, slots=True)
class DocumentScanResult:
    occurrences: tuple[MnemonicOccurrence, ...]
    failures: tuple[str, ...]


def _docx_text(data: bytes) -> str:
    with zipfile.ZipFile(BytesIO(data)) as archive:
        names = set(archive.namelist())
        if "word/document.xml" not in names:
            raise ValueError("DOCX_DOCUMENT_XML_MISSING")
        parts = ["word/document.xml"] + sorted(
            name for name in names
            if re.fullmatch(r"word/(?:header|footer)\d+\.xml", name))
        text: list[str] = []
        for name in parts:
            info = archive.getinfo(name)
            if info.file_size > 64 * 1024 * 1024:
                raise ValueError("DOCX_XML_TOO_LARGE")
            payload = archive.read(info)
            decoded = payload.decode("utf-8", "strict")
            text.extend(unescape(item) for item in re.findall(
                r"<w:t(?:\s[^>]*)?>(.*?)</w:t>", decoded, re.DOTALL))
        return " ".join(text)


def extract_document_text(data: bytes, suffix: str) -> tuple[str | None, str | None]:
    suffix = suffix.lower()
    if suffix == ".docx":
        try:
            return _docx_text(data), None
        except (OSError, ValueError, UnicodeError, zipfile.BadZipFile, KeyError):
            return None, "DOCX_EXTRACTION_FAILED"
    if suffix == ".pdf":
        return None, "PDF_TEXT_EXTRACTOR_UNAVAILABLE"
    if suffix in PLAIN_EXTENSIONS:
        return None, None  # raw scanner preserves exact byte offsets and encodings
    return None, "DOCUMENT_TYPE_UNSUPPORTED"


class DocumentSeedRecovery:
    def __init__(self, scanner: RawMnemonicScanner) -> None:
        self.scanner = scanner

    def scan_bytes(self, data: bytes, *, source: str, suffix: str,
                   base_offset: int = 0, mft_record_number: int | None = None,
                   path: str | None = None, allocation_state: str = "UNKNOWN_ALLOCATION") -> DocumentScanResult:
        if suffix.lower() in PLAIN_EXTENSIONS:
            raw = self.scanner.scan_bytes(data, source=source, base_offset=base_offset,
                                          source_kind="KNOWN_FILE_CONTENT")
            occurrences = raw.occurrences
            failures = raw.failures
        else:
            text, failure = extract_document_text(data, suffix)
            if failure:
                return DocumentScanResult((), (failure,))
            raw = self.scanner.scan_bytes((text or "").encode("utf-8"), source=source,
                                          source_kind="DOCUMENT_EXTRACTED_TEXT")
            occurrences = tuple(
                MnemonicOccurrence(replace(item.candidate, physical_start=None,
                                           physical_end=None, encoding="utf-8",
                                           safe_metadata={
                                               "offset_space": "extracted_text_utf8_bytes",
                                               "logical_text_start": item.candidate.physical_start,
                                               "logical_text_end": item.candidate.physical_end,
                                               "extractor": "stdlib_docx_wordprocessingml",
                                           }),
                                   item.secret)
                for item in raw.occurrences)
            failures = raw.failures
        enriched = tuple(MnemonicOccurrence(replace(
            item.candidate, mft_record_number=mft_record_number, path=path,
            allocation_state=allocation_state), item.secret) for item in occurrences)
        return DocumentScanResult(enriched, tuple(failures))

    def scan_path(self, path: str | Path) -> DocumentScanResult:
        source = Path(path).resolve()
        suffix = source.suffix.lower()
        if suffix not in DOCUMENT_EXTENSIONS:
            return DocumentScanResult((), ("DOCUMENT_TYPE_UNSUPPORTED",))
        try:
            data = source.read_bytes()
        except OSError:
            return DocumentScanResult((), ("DOCUMENT_READ_FAILED",))
        return self.scan_bytes(data, source=str(source), suffix=suffix,
                               path=source.name, allocation_state="ACTIVE_FILE")

    def scan_ntfs_image(self, path: str | Path, *, maximum_file_size: int = 64 * 1024 * 1024) -> DocumentScanResult:
        """Read supported active/deleted files through validated MFT DATA mappings."""
        source = Path(path).resolve()
        locator = NTFSBitcoinArtifactLocator()
        try:
            locator.index(source)
        except (OSError, ValueError):
            return DocumentScanResult((), ("NTFS_INDEX_FAILED",))
        context = locator.stale_recovery_context
        if context is None:
            return DocumentScanResult((), ())
        occurrences: list[MnemonicOccurrence] = []
        failures: list[str] = []
        for record in context.current_records_by_number.values():
            if record.directory or not record.aliases or record.data is None:
                continue
            alias = next((item for item in record.aliases
                          if Path(item.filename).suffix.lower() in DOCUMENT_EXTENSIONS), None)
            if alias is None:
                continue
            size = record.data.logical_size
            if size < 0 or size > maximum_file_size:
                failures.append("DOCUMENT_SIZE_LIMIT")
                continue
            allocation = "ACTIVE_FILE" if record.allocated else "DELETED_FILE"
            try:
                if record.data.resident:
                    resident = context.read_resident_unnamed_data(record.number)
                    data = resident.value
                    base = resident.physical_mft_record_offset + resident.resident_value_offset
                else:
                    extents = [item for item in record.data.extents if not item.sparse]
                    if any(item.sparse for item in record.data.extents):
                        failures.append("SPARSE_DOCUMENT_UNSUPPORTED")
                        continue
                    chunks = []
                    with source.open("rb") as image:
                        for extent in extents:
                            length = min(size - sum(map(len, chunks)),
                                         (extent.physical_byte_end or 0) - (extent.physical_byte_start or 0))
                            if length <= 0 or extent.physical_byte_start is None:
                                continue
                            image.seek(extent.physical_byte_start)
                            chunks.append(image.read(length))
                    data = b"".join(chunks)[:size]
                    base = 0
                result = self.scan_bytes(data, source=str(source), suffix=Path(alias.filename).suffix,
                                         base_offset=base, mft_record_number=record.number,
                                         path=alias.filename, allocation_state=allocation)
                for item in result.occurrences:
                    candidate = item.candidate
                    if not record.data.resident and candidate.physical_start is not None:
                        logical_start, logical_end = candidate.physical_start, candidate.physical_end
                        mapped_start = mapped_end = None
                        for extent in record.data.extents:
                            extent_length = ((extent.physical_byte_end or 0) -
                                             (extent.physical_byte_start or 0))
                            logical_extent_start = extent.vcn_start * context.boot.cluster_size
                            logical_extent_end = logical_extent_start + extent_length
                            if (extent.physical_byte_start is not None and
                                    logical_extent_start <= logical_start and
                                    logical_end <= logical_extent_end):
                                mapped_start = extent.physical_byte_start + logical_start - logical_extent_start
                                mapped_end = mapped_start + logical_end - logical_start
                                break
                        candidate = replace(candidate, physical_start=mapped_start,
                                            physical_end=mapped_end,
                                            safe_metadata={"logical_start": logical_start,
                                                           "logical_end": logical_end,
                                                           "extent_mapping_exact": mapped_start is not None,
                                                           "deleted_content_may_be_overwritten": not record.allocated,
                                                           "file_extents": [{
                                                               "physical_start": extent.physical_byte_start,
                                                               "physical_end": extent.physical_byte_end,
                                                               "sparse": extent.sparse,
                                                           } for extent in record.data.extents]})
                    elif not record.allocated:
                        candidate = replace(candidate, safe_metadata={
                            **candidate.safe_metadata,
                            "deleted_content_may_be_overwritten": True,
                        })
                    occurrences.append(MnemonicOccurrence(candidate, item.secret))
                failures.extend(result.failures)
            except (OSError, ValueError):
                failures.append("DOCUMENT_DATA_READ_FAILED")
        return DocumentScanResult(tuple(occurrences), tuple(dict.fromkeys(failures)))
