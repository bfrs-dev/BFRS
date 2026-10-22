"""PDF inventory: real encrypted files, xref layouts and bounded failure cases."""
import re
import struct
import zlib

import pytest
from pypdf import PdfReader, PdfWriter

from bfrs.recovery import container_inventory as inventory
from bfrs.recovery import pdf_inventory as pdf


def classic_pdf(path, extra=b'', *, entries=4, payload_size=0):
    with path.open('wb') as stream:
        stream.write(b'%PDF-1.7\n')
        offsets = [0]
        for number, body in [(1, b'<< /Type /Catalog /Pages 2 0 R >>'),
                             (2, b'<< /Type /Pages /Kids [] /Count 0 >>')]:
            offsets.append(stream.tell())
            stream.write(f'{number} 0 obj\n'.encode()+body+b'\nendobj\n')
        offsets.append(stream.tell())
        stream.write(f'3 0 obj\n<< /Length {payload_size} >>\nstream\n'.encode())
        # A sparse, uncompressed stream makes size-independent I/O testable.
        stream.seek(payload_size, 1)
        stream.write(b'\nendstream\nendobj\n')
        xref = stream.tell()
        stream.write(f'xref\n0 {entries}\n'.encode())
        for number in range(entries):
            stream.write((f'{offsets[number]:010} 00000 n \n'.encode() if 0 < number < 4
                          else b'0000000000 65535 f \n'))
        stream.write(f'trailer\n<< /Size {entries} /Root 1 0 R '.encode()+extra+b' >>\n')
        stream.write(f'startxref\n{xref}\n%%EOF\n'.encode())
    return xref


def append_table(path, extra, *, empty=False, size=4):
    with path.open('ab') as stream:
        offset = stream.tell()
        stream.write(b'xref\n0 0\n' if empty else b'xref\n0 1\n0000000000 65535 f \n')
        stream.write(f'trailer\n<< /Size {size} '.encode()+extra+b' >>\n')
        stream.write(f'startxref\n{offset}\n%%EOF\n'.encode())
    return offset


@pytest.mark.parametrize('algorithm', ['RC4-40', 'RC4-128', 'AES-128', 'AES-256-R5', 'AES-256'])
@pytest.mark.parametrize('password', ['test-only-password', ''])
def test_real_encrypted_pdf_including_empty_user_password(tmp_path, algorithm, password):
    if algorithm.startswith('AES'):
        pytest.importorskip('cryptography')
    path = tmp_path/'renamed.res'
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt(password, owner_password='test-owner', algorithm=algorithm)
    writer.write(path)
    assert PdfReader(path).is_encrypted
    row = inventory.inspect_file(path)
    assert row['format'] == 'PDF' and row['encryption'] == 'ENCRYPTED'
    assert row['reason'] == 'PDF_ENCRYPT_ENTRY'
    assert row['pdf_password_required'] == 'NOT_CHECKED'


def test_real_plain_and_incremental_xref_stream_pdf(tmp_path, monkeypatch):
    path, updated = tmp_path/'plain.pdf', tmp_path/'updated.pdf'
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.write(path)
    assert inventory.inspect_file(path)['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    writer = PdfWriter(path, incremental=True)
    writer.add_metadata({'/Title': 'updated'})
    writer.write(updated)
    def forbidden(*args, **kwargs):
        raise AssertionError('inventory must not construct PdfReader or decompress')
    monkeypatch.setattr('pypdf.PdfReader', forbidden)
    monkeypatch.setattr(zlib, 'decompress', forbidden)
    monkeypatch.setattr(zlib, 'decompressobj', forbidden)
    row = inventory.inspect_file(updated)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['pdf_xref_sections'] == 2 and row['pdf_xref_streams'] == 1


def test_xref_stream_and_hybrid_encryption_marker(tmp_path, monkeypatch):
    # Structural marker fixture, not a claim of a truly encrypted payload.
    path = tmp_path/'stream.pdf'
    data = b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
    offset = len(data)
    payload = zlib.compress(struct.pack('>BIH', 0, 0, 65535))
    data += (b'4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [1 4 2] /Index [0 1] '
             b'/Filter /FlateDecode /Encrypt 3 0 R /Length '+str(len(payload)).encode()+
             b' >>\nstream\n'+payload+b'\nendstream\nendobj\n')
    path.write_bytes(data+f'startxref\n{offset}\n%%EOF\n'.encode())
    monkeypatch.setattr(zlib, 'decompress', lambda *_: pytest.fail('unexpected decompression'))
    assert inventory.inspect_file(path)['encryption'] == 'ENCRYPTED'
    append_table(path, f'/Root 1 0 R /XRefStm {offset}'.encode())
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['pdf_xref_sections'] == 2


@pytest.mark.parametrize('extra', [
    b'/Comment (/Encrypt 3 0 R and nested (text) and escaped \\( )',
    b'/Comment <2f456e6372797074>',
    b'/Custom << /Encrypt 3 0 R >>',
    b'/Custom [/Encrypt 3 0 R]',
    b'% /Encrypt 3 0 R\n',
    b'/Encrypt null',
])
def test_encrypt_text_or_nested_key_is_not_encryption(tmp_path, extra):
    path = tmp_path/'plain.pdf'
    classic_pdf(path, extra)
    assert inventory.inspect_file(path)['encryption'] == 'NO_ENCRYPTION_INDICATOR'


def test_escaped_key_and_previous_trailer(tmp_path):
    path = tmp_path/'history.pdf'
    previous = classic_pdf(path, b'/Encr#79pt 3 0 R')
    append_table(path, f'/Prev {previous}'.encode())
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['pdf_xref_sections'] == 2


@pytest.mark.parametrize('extra', [
    b'/Encrypt 123', b'/Encrypt ()', b'/Encrypt []', b'/Encrypt <<>>',
    b'/Encrypt 0 0 R', b'/Encrypt 3 65536 R', b'/Encrypt null /Encrypt 3 0 R',
    b'/Prev -1', b'/Prev 999999999999', b'/Prev 3 0 R',
    b'/Broken <xyz>', b'/Encr#zzpt 3 0 R',
])
def test_malformed_metadata_is_unknown(tmp_path, extra):
    path = tmp_path/'broken.pdf'
    classic_pdf(path, extra)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['structure'] == 'INVALID_OR_UNSUPPORTED_METADATA'


def test_bad_tail_offset_cycle_and_header_only(tmp_path):
    path = tmp_path/'broken.pdf'
    previous = classic_pdf(path)
    original = path.read_bytes()
    for data in [b'%PDF-1.7\n', original[:-10], original+b'not whitespace',
                 original.replace(str(previous).encode()+b'\n%%EOF', b'1\n%%EOF')]:
        path.write_bytes(data)
        assert inventory.inspect_file(path)['encryption'] == 'UNKNOWN'
    path.write_bytes(original)
    append_table(path, f'/Prev {len(original)}'.encode())
    assert inventory.inspect_file(path)['reason'] == 'PDF_XREF_CYCLE'


@pytest.mark.parametrize('limit,value,extra,reason', [
    ('MAX_DEPTH', 2, b'/Extra [[[[0]]]]', 'PDF_DEPTH_LIMIT'),
    ('MAX_STRING_BYTES', 4, b'/Extra (123456789)', 'PDF_STRING_LIMIT'),
    ('MAX_TOKENS', 4, b'', 'PDF_TOKEN_LIMIT'),
])
def test_parser_resource_limits(tmp_path, monkeypatch, limit, value, extra, reason):
    path = tmp_path/'limit.pdf'
    classic_pdf(path, extra)
    monkeypatch.setattr(pdf, limit, value)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason
    assert row['structure'] == 'LIMIT_OR_UNSUPPORTED'


def test_read_budget_and_section_limit(tmp_path, monkeypatch):
    path = tmp_path/'limit.pdf'
    previous = classic_pdf(path)
    append_table(path, f'/Prev {previous}'.encode())
    monkeypatch.setattr(pdf, 'MAX_SECTIONS', 1)
    assert inventory.inspect_file(path)['reason'] == 'PDF_XREF_SECTION_LIMIT'
    monkeypatch.setattr(inventory, 'MAX_READ_BYTES', 700)
    row = inventory.inspect_file(path)
    assert row['reason'] == 'METADATA_READ_LIMIT' and row['bytes_read'] <= 700


def test_large_payload_and_xref_use_bounded_reads(tmp_path):
    path = tmp_path/'large.pdf'
    classic_pdf(path, entries=25000, payload_size=100*1024*1024)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['bytes_read'] < 80*1024


def test_nonstandard_xref_width_is_unknown(tmp_path):
    path = tmp_path/'nonstandard.pdf'
    classic_pdf(path)
    path.write_bytes(path.read_bytes().replace(b'0000000000 65535 f \n', b'0 65535 f\n'))
    assert inventory.inspect_file(path)['encryption'] == 'UNKNOWN'


@pytest.mark.parametrize('encrypted', [False, True])
def test_empty_xref_subsection_follows_previous_encryption_metadata(tmp_path, encrypted):
    # Only the marker fixture is synthetic; no user document is stored in tests.
    path = tmp_path/'empty-update.pdf'
    previous = classic_pdf(path, b'/Encrypt 3 0 R' if encrypted else b'')
    append_table(path, f'/Prev {previous}'.encode(), empty=True)
    row = inventory.inspect_file(path)
    assert row['encryption'] == ('ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR')
    assert row['pdf_xref_sections'] == 2


def test_empty_hybrid_xref_with_shared_previous_section(tmp_path):
    # Reproduce the reported layout using a generated blank PDF, not private data.
    original, path = tmp_path/'original.pdf', tmp_path/'hybrid.pdf'
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.write(original)
    writer = PdfWriter(original, incremental=True)
    writer.add_metadata({'/Title': 'synthetic hybrid regression'})
    writer.write(path)
    xref_stream = int(re.search(rb'startxref\s+(\d+)\s+%%EOF\s*$', path.read_bytes())[1])
    reference = PdfReader(path, strict=True)
    root = reference.trailer.raw_get('/Root')
    previous = int(re.search(rb'startxref\s+(\d+)\s+%%EOF\s*$', original.read_bytes())[1])
    append_table(path, f'/Root {root.idnum} {root.generation} R /Prev {previous} '
                 f'/XRefStm {xref_stream}'.encode(), empty=True, size=reference.trailer['/Size'])
    assert not PdfReader(path, strict=True).is_encrypted
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['pdf_xref_sections'] == 3 and row['pdf_xref_streams'] == 1


def test_empty_subsections_still_obey_section_limit(tmp_path):
    path = tmp_path/'empty-limit.pdf'
    data = b'%PDF-1.7\nxref\n'+b'0 0\n'*(pdf.MAX_SUBSECTIONS+1)
    path.write_bytes(data+b'trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n')
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'PDF_XREF_SUBSECTION_LIMIT'
