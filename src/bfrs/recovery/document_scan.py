"""Bounded, read-only document text pass for intact file/folder target scans.

No Office automation, macros, embedded objects, external links or extraction to disk.
Offsets on returned hits refer ONLY to extracted UTF-8 text.
"""
from dataclasses import replace
from pathlib import Path
import zipfile
import zlib
import threading
import xml.etree.ElementTree as ET

from bfrs.recovery.rtf_text import RTFError
from bfrs.core.chunk_reader import Chunk
from bfrs.scanners.target_registry import (
    ValidatedSecretChunkDetector, _mnemonic_hits,
)
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner

_DOCUMENT_SLOT = threading.BoundedSemaphore(1)
DOCUMENT_SCAN_VERSION = 2
SUFFIXES = frozenset({'.docx', '.xlsx', '.rtf'})
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_PART_BYTES = 4 * 1024 * 1024
MAX_XML_BYTES = 16 * 1024 * 1024
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_MEMBERS = 4096
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
S = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'


class DocumentLimit(ValueError):
    pass


def extract_ooxml(path):
    """Read selected XML parts only, enforcing cumulative decompression limits."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_MEMBERS:
            raise DocumentLimit('DOCUMENT_MEMBER_LIMIT')
        names = {item.filename for item in infos}
        if len(names) != len(infos):
            raise DocumentLimit('DOCUMENT_DUPLICATE_MEMBERS')
        remaining = MAX_XML_BYTES
        def xml(name):
            nonlocal remaining
            info = archive.getinfo(name)
            if info.flag_bits & 1:
                raise DocumentLimit('DOCUMENT_ENCRYPTED')
            if info.file_size > min(MAX_PART_BYTES, remaining):
                raise DocumentLimit('DOCUMENT_XML_LIMIT')
            with archive.open(info) as stream:
                data = stream.read(min(MAX_PART_BYTES, remaining) + 1)
            if len(data) > min(MAX_PART_BYTES, remaining):
                raise DocumentLimit('DOCUMENT_XML_LIMIT')
            remaining -= len(data)
            if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper() or b'\x00' in data:
                raise DocumentLimit('DOCUMENT_XML_UNSUPPORTED')
            return ET.fromstring(data)

        fragments = []
        text_bytes = 0
        def add(value):
            nonlocal text_bytes
            text_bytes += len(value.encode('utf-8')) + 1
            if text_bytes > MAX_TEXT_BYTES:
                raise DocumentLimit('DOCUMENT_TEXT_LIMIT')
            fragments.append(value)

        if 'word/document.xml' in names:
            parts = ['word/document.xml'] + sorted(n for n in names if
                n.startswith(('word/header', 'word/footer')) and n.endswith('.xml'))
            for name in parts:
                root = xml(name)
                if not root.tag.startswith(W):
                    raise DocumentLimit('DOCUMENT_NAMESPACE_UNSUPPORTED')
                for paragraph in root.iter(W + 'p'):
                    # Preserve adjacent formatting runs; separate tabs/breaks.
                    add(''.join((node.text or '') if node.tag == W + 't' else ' '
                        for node in paragraph.iter()
                        if node.tag in {W + 't', W + 'tab', W + 'br', W + 'cr'}))
            kind = 'DOCX'
        elif 'xl/workbook.xml' in names:
            strings = []
            if 'xl/sharedStrings.xml' in names:
                strings = [''.join(t.text or '' for t in item.iter(S + 't'))
                           for item in xml('xl/sharedStrings.xml').iter(S + 'si')]
            for name in sorted(n for n in names if
                    n.startswith('xl/worksheets/') and n.endswith('.xml')):
                root = xml(name)
                if root.tag != S + 'worksheet':
                    raise DocumentLimit('DOCUMENT_NAMESPACE_UNSUPPORTED')
                for cell in root.iter(S + 'c'):
                    cell_type = cell.get('t')
                    value = cell.find(S + 'v')
                    if cell_type == 'inlineStr':
                        add(''.join(t.text or '' for t in cell.iter(S + 't')))
                    elif value is not None and value.text:
                        if cell_type == 's':
                            index = int(value.text)
                            if not 0 <= index < len(strings):
                                raise DocumentLimit('DOCUMENT_INVALID_SHARED_STRING')
                            add(strings[index])
                        else:
                            add(value.text)
            kind = 'XLSX'
        else:
            raise DocumentLimit('DOCUMENT_FORMAT_UNCONFIRMED')
        return '\n'.join(fragments).encode('utf-8'), kind, MAX_XML_BYTES - remaining


def _scan_document(path, *, targets, mnemonic_standards):
    """Return (hits, coverage). Non-document paths incur no extra file I/O."""
    path = Path(path)
    if path.suffix.lower() not in SUFFIXES or not (mnemonic_standards or 'secrets' in targets):
        return (), None
    is_rtf = path.suffix.lower() == '.rtf'
    coverage = {'version': DOCUMENT_SCAN_VERSION, 'status': 'SKIPPED',
                'findings': 0, 'xml_bytes': 0, 'scope': 'RTF_TEXT_ONLY' if is_rtf else 'OOXML_TEXT_ONLY'}
    try:
        file_size = path.stat().st_size
        if file_size > MAX_FILE_BYTES:
            raise DocumentLimit('DOCUMENT_FILE_LIMIT')
        if is_rtf:
            from bfrs.recovery.rtf_text import extract_rtf, MAX_RTF_BYTES
            if file_size > MAX_RTF_BYTES:
                raise DocumentLimit('RTF_FILE_LIMIT')
            with path.open('rb') as stream:
                source_bytes = stream.read(MAX_RTF_BYTES + 1)
            data = extract_rtf(source_bytes)
            kind, xml_bytes = 'RTF', 0
            coverage['rtf_bytes'] = len(source_bytes)
        else:
            with path.open('rb') as stream:
                prefix = stream.read(8)
            if prefix == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                raise DocumentLimit('OFFICE_OLE_OR_ENCRYPTED_UNSUPPORTED')
            if not prefix.startswith(b'PK\x03\x04'):
                raise DocumentLimit('DOCUMENT_FORMAT_UNCONFIRMED')
            data, kind, xml_bytes = extract_ooxml(path)
        hits = []
        if 'secrets' in targets:
            hits.extend(ValidatedSecretChunkDetector().detect_chunk(
                Chunk(0, data), source=str(path), ownership_start=0, ownership_end=len(data)))
        if mnemonic_standards:
            raw = RawMnemonicScanner(overlap=4096, phase_workers=1).scan_bytes(
                data, source=str(path), source_kind='DOCUMENT_EXTRACTED_TEXT')
            hits.extend(_mnemonic_hits(raw, frozenset(mnemonic_standards), str(path)))
        from bfrs.recovery.full_image_coordinator import FullImageRecoveryCoordinator
        hits = FullImageRecoveryCoordinator._correlate_mnemonic_findings(tuple(hits))
        enriched = tuple(replace(hit, source_kind='DOCUMENT_EXTRACTED_TEXT',
            allocation_state='ACTIVE_FILE', safe_metadata={**hit.safe_metadata,
                'offset_space': 'extracted_text_utf8_bytes',
                'logical_text_start': hit.start_offset, 'logical_text_end': hit.end_offset,
                'document_format': kind,
                'extractor': 'bounded_rtf_v1' if is_rtf else 'bounded_ooxml_v1'}) for hit in hits)
        coverage.update(status='SCANNED', findings=len(enriched), xml_bytes=xml_bytes,
                        text_bytes=len(data), document_format=kind,
                        mnemonic_recovery=FullImageRecoveryCoordinator._mnemonic_summary(enriched))
        return enriched, coverage
    except (DocumentLimit, RTFError) as error:
        coverage['reason'] = str(error)
    except (OSError, ValueError, KeyError, RuntimeError, NotImplementedError,
            zipfile.BadZipFile, zlib.error, ET.ParseError):
        coverage.update(status='FAILED', reason='DOCUMENT_EXTRACTION_FAILED')
    return (), coverage


def scan_document(path, *, targets, mnemonic_standards):
    # Bound aggregate parser memory even when many folder file workers are used.
    if Path(path).suffix.lower() not in SUFFIXES or not (mnemonic_standards or 'secrets' in targets):
        return (), None
    with _DOCUMENT_SLOT:
        return _scan_document(path, targets=targets, mnemonic_standards=mnemonic_standards)


def enrich_document_result(result, path, *, targets, mnemonic_standards):
    hits, coverage = scan_document(path, targets=targets, mnemonic_standards=mnemonic_standards)
    if coverage is None:
        return result
    return replace(result, target_findings=result.target_findings + hits,
                   evidence={**result.evidence, 'document_scan': coverage})
