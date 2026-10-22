import importlib.util
import json
import sqlite3
from pathlib import Path
import struct
import zipfile
import zlib

import pytest

from bfrs.recovery import container_inventory as module

script = Path(__file__).resolve().parents[1] / 'scripts/inventory_documents.py'
spec = importlib.util.spec_from_file_location('inventory_documents', script)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def zip_fixture(path, office=False, encrypted=False):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('wallet.dat', b'test content')
        if office:
            archive.writestr('[Content_Types].xml', b'<Types/>')
            archive.writestr('word/document.xml', b'<document/>')
    if encrypted:
        # Metadata-only fixture: deliberately flags a member without encrypting payload.
        data = bytearray(path.read_bytes())
        for signature, delta in [(b'PK\x03\x04', 6), (b'PK\x01\x02', 8)]:
            offset = data.index(signature) + delta
            struct.pack_into('<H', data, offset, 1)
        path.write_bytes(data)
    return path


def rar3_header(kind, flags, body):
    content = struct.pack('<BHH', kind, flags, 7+len(body)) + body
    return struct.pack('<H', zlib.crc32(content) & 65535) + content


def vint(number):
    output = bytearray()
    while number >= 128:
        output.append((number & 127) | 128)
        number >>= 7
    output.append(number)
    return bytes(output)


def rar5_header(body):
    payload = vint(len(body)) + body
    return struct.pack('<L', zlib.crc32(payload)) + payload


def ole_fixture(path, streams):
    # Minimal valid CFB v3 with normal FAT streams (4096 bytes each), no mini FAT.
    free, end, fat_sector = 0xffffffff, 0xfffffffe, 0xfffffffd
    header = bytearray(512)
    header[:8] = module.OLE_MAGIC
    struct.pack_into('<HHHHH', header, 24, 0x3e, 3, 0xfffe, 9, 6)
    struct.pack_into('<LLLLLLLLL', header, 40, 0, 1, 1, 0, 4096, end, 0, end, 0)
    struct.pack_into('<109L', header, 76, 0, *([free]*108))
    fat = [free]*128
    fat[0], fat[1] = fat_sector, end
    directory = bytearray(512)
    def entry(index, name, kind, child, sibling, sector, size):
        offset = index*128
        encoded = (name+'\0').encode('utf-16le')
        directory[offset:offset+len(encoded)] = encoded
        struct.pack_into('<HBBLLL', directory, offset+64, len(encoded), kind, 1, free, sibling, child)
        struct.pack_into('<LQ', directory, offset+116, sector, size)
    entry(0, 'Root Entry', 5, 1, free, end, 0)
    payload = []
    for index, (name, content) in enumerate(streams.items(), 1):
        sector = 2+(index-1)*8
        entry(index, name, 2, free, index+1 if index<len(streams) else free, sector, 4096)
        for current in range(sector, sector+8):
            fat[current] = current+1 if current < sector+7 else end
        payload.append(content.ljust(4096, b'\0'))
    path.write_bytes(header + struct.pack('<128L', *fat) + directory + b''.join(payload))
    return path


def test_renamed_zip_docx_and_encrypted_flags(tmp_path):
    row = module.inspect_file(zip_fixture(tmp_path/'random.bin', office=True))
    assert row['format'] == 'DOCX'
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    row = module.inspect_file(zip_fixture(tmp_path/'password.bin', encrypted=True))
    assert row['encryption'] == 'ENCRYPTED'
    assert row['encrypted_members'] == 1
    assert 'wallet.dat' in row['member_names']


def test_budget_truncated_zip_and_non_target_reads(tmp_path, monkeypatch):
    path = tmp_path/'huge.bin'
    with path.open('wb') as stream:
        stream.truncate(100*1024*1024)
    assert module.inspect_file(path)['bytes_read'] == 512
    path.write_bytes(b'PK\x03\x04broken')
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['structure'] == 'INVALID_OR_UNSUPPORTED_METADATA'
    zip_fixture(path)
    monkeypatch.setattr(module, 'MAX_READ_BYTES', 20)
    assert module.inspect_file(path)['structure'] == 'LIMIT_OR_UNSUPPORTED'


def test_rar3_and_rar5_headers(tmp_path):
    path = tmp_path/'renamed.bin'
    for flags, expected in [(0, 'NO_ENCRYPTION_INDICATOR'), (0x80, 'ENCRYPTED')]:
        path.write_bytes(b'Rar!\x1a\x07\x00' + rar3_header(0x73, flags, b'\0'*6) + rar3_header(0x7b, 0, b''))
        assert module.inspect_file(path)['encryption'] == expected
    path.write_bytes(b'Rar!\x1a\x07\x01\x00' + rar5_header(b'\x01\x00\x00') + rar5_header(b'\x05\x00\x00'))
    assert module.inspect_file(path)['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    path.write_bytes(b'Rar!\x1a\x07\x01\x00' + rar5_header(b'\x04\x00\x00\x00\x0f' + b'0'*16))
    assert module.inspect_file(path)['encryption'] == 'ENCRYPTED'
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    assert module.inspect_file(path)['encryption'] == 'UNKNOWN'


def test_7z_and_pdf_are_not_misreported_as_unencrypted(tmp_path):
    path = tmp_path/'random.bin'
    next_header = b'\x17'
    start = struct.pack('<QQL', 0, len(next_header), zlib.crc32(next_header))
    path.write_bytes(b'7z\xbc\xaf\x27\x1c\x00\x04'+struct.pack('<L', zlib.crc32(start))+start+next_header)
    row = module.inspect_file(path)
    assert row['format'] == '7Z'
    assert row['structure'] == 'HEADER_CRC_CHECKED'
    assert row['encryption'] == 'UNKNOWN'
    path.write_bytes(b'%PDF-1.7\n')
    row = module.inspect_file(path)
    assert row['format'] == 'PDF' and row['encryption'] == 'UNKNOWN'


def test_office_encryption_and_legacy_flags(tmp_path):
    pytest.importorskip('olefile')
    path = tmp_path/'unknown.bin'
    ole_fixture(path, {'EncryptionInfo': struct.pack('<HHI', 4, 4, 64), 'EncryptedPackage': struct.pack('<Q', 100)+b'data'})
    row = module.inspect_file(path)
    assert row['format'] == 'OFFICE_ENCRYPTED' and row['encryption'] == 'ENCRYPTED'
    for flags, expected in [(0, 'NO_ENCRYPTION_INDICATOR'), (0x100, 'ENCRYPTED')]:
        fib = bytearray(32)
        fib[:2] = b'\xec\xa5'
        struct.pack_into('<H', fib, 10, flags)
        ole_fixture(path, {'WordDocument': fib})
        row = module.inspect_file(path)
        assert row['format'] == 'DOC' and row['encryption'] == expected
    bof = struct.pack('<HH', 0x0809, 4)+b'\x00\x06\x05\x00'
    for extra, expected in [(b'', 'NO_ENCRYPTION_INDICATOR'), (struct.pack('<HH', 0x2f, 6)+b'\0'*6, 'ENCRYPTED')]:
        ole_fixture(path, {'Workbook': bof+extra+struct.pack('<HH', 0x0a, 0)})
        row = module.inspect_file(path)
        assert row['format'] == 'XLS' and row['encryption'] == expected


def test_resume_change_delete_and_no_repeated_content_reads(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    zip_fixture(source/'a.bin')
    (source/'plain.bin').write_bytes(b'ordinary')
    first = runner.inventory(source, output)
    assert first['complete'] and first['run']['inspected'] == 2
    original = runner.inspect_file
    def forbidden(path):
        raise AssertionError('unchanged sources should not be reread')
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['reused'] == 2
    monkeypatch.setattr(runner, 'inspect_file', original)
    (source/'a.bin').unlink()
    (source/'plain.bin').write_bytes(br'{\rtf1 x}')
    third = runner.inventory(source, output, resume=True)
    rows = [json.loads(line) for line in (output/'inventory.jsonl').read_text().splitlines()]
    assert third['complete'] and len(rows) == 1 and rows[0]['format'] == 'RTF'


def test_interruption_and_links(tmp_path):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    for i in range(3):
        zip_fixture(source/f'{i}.bin')
    calls = 0
    def stop():
        nonlocal calls
        calls += 1
        return calls > 1
    assert not runner.inventory(source, output, should_stop=stop)['complete']
    assert runner.inventory(source, output, resume=True)['complete']
    outside = tmp_path/'outside.zip'
    zip_fixture(outside)
    try:
        (source/'link.zip').symlink_to(outside)
    except OSError:
        pytest.skip('symlinks unavailable')
    runner.inventory(source, output, resume=True)
    rows = [json.loads(line) for line in (output/'inventory.jsonl').read_text().splitlines()]
    assert next(row for row in rows if row['path']=='link.zip')['reason'] == 'LINK_OR_REPARSE_POINT_SKIPPED'


def test_output_inside_source_refused(tmp_path):
    with pytest.raises(ValueError):
        runner.inventory(tmp_path, tmp_path/'results')


def test_rar_file_encryption_without_hidden_names(tmp_path):
    path = tmp_path/'file.bin'
    name = b'wallet.dat'
    file_body = struct.pack('<LLBLLBBHL', 0, 0, 2, 0, 0, 29, 48, len(name), 0) + name
    path.write_bytes(b'Rar!\x1a\x07\x00' + rar3_header(0x73, 0, b'\0'*6)
                     + rar3_header(0x74, 0x8004, file_body) + rar3_header(0x7b, 0, b''))
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['reason'] == 'RAR_FILE_PASSWORD_FLAG'
    enc_record = b'\x01\x00\x00\x0f' + b'0'*32
    extra = vint(len(enc_record)) + enc_record
    file_body = b'\x02\x01' + vint(len(extra)) + b'\0\0\0\0\0' + vint(len(name)) + name + extra
    path.write_bytes(b'Rar!\x1a\x07\x01\x00' + rar5_header(b'\x01\x00\x00') + rar5_header(file_body))
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['reason'] == 'RAR_FILE_ENCRYPTION_RECORD'


def test_unknown_candidates_are_retried_on_resume(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    (source/'file.pdf').write_bytes(b'%PDF-1.7\n')
    runner.inventory(source, output)
    result = runner.inventory(source, output, resume=True)
    assert result['run']['inspected'] == 1 and result['run']['reused'] == 0


def test_old_signature_only_pdf_is_reclassified_on_resume(tmp_path, monkeypatch):
    from pypdf import PdfWriter
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt('test-password')
    writer.write(source/'old.pdf')
    (source/'plain.bin').write_bytes(b'ordinary')
    original = runner.inspect_file
    def old_inspector(path):
        if path.suffix == '.pdf':
            return {'format': 'PDF', 'encryption': 'UNKNOWN', 'structure': 'SIGNATURE_ONLY',
                    'reason': 'PDF_ENCRYPTION_REQUIRES_DEEPER_PARSER', 'bytes_read': 512}
        return original(path)
    monkeypatch.setattr(runner, 'inspect_file', old_inspector)
    runner.inventory(source, output)
    monkeypatch.setattr(runner, 'inspect_file', original)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['inspected'] == 1 and second['run']['reused'] == 1
    assert second['encryption_counts'] == {'ENCRYPTED': 1}
    third = runner.inventory(source, output, resume=True)
    assert third['run']['inspected'] == 0 and third['run']['reused'] == 2


def test_unknown_ole_directory_metadata_adds_no_reads(tmp_path, monkeypatch):
    pytest.importorskip('olefile')
    path = ole_fixture(tmp_path/'design.art', {'Design': b'not a known format', 'Preview': b'example'})
    original = module._ole_directory_metadata
    monkeypatch.setattr(module, '_ole_directory_metadata', lambda ole, row: None)
    before = module.inspect_file(path)
    monkeypatch.setattr(module, '_ole_directory_metadata', original)
    after = module.inspect_file(path)
    assert after['bytes_read'] == before['bytes_read']
    assert after['format'] == 'OLE' and after['encryption'] == 'UNKNOWN'
    assert after['reason'] == 'OLE_TYPE_UNDETERMINED'
    assert after['structure'] == 'DIRECTORY_CHECKED'
    assert after['ole_directory_entry_count'] == 2
    assert [e['name'] for e in after['ole_directory_entries']] == ['Design', 'Preview']
    assert all(e['type'] == 2 and e['size'] == 4096 for e in after['ole_directory_entries'])
    assert not after['ole_directory_entries_truncated']
    monkeypatch.setattr(module, 'MAX_NAMES', 1)
    truncated = module.inspect_file(path)
    assert len(truncated['ole_directory_entries']) == 1
    assert truncated['ole_directory_entries_truncated']
    assert truncated['ole_directory_entry_count'] == 2
    monkeypatch.setattr(module, 'MAX_MEMBERS', 1)
    limited = module.inspect_file(path)
    assert limited['reason'] == 'OLE_DIRECTORY_ENTRY_LIMIT'
    assert limited['encryption'] == 'UNKNOWN'


def test_unknown_ole_resume_migrates_old_checkpoint_and_reuses_metadata(tmp_path, monkeypatch):
    pytest.importorskip('olefile')
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    output.mkdir()
    path = ole_fixture(source/'design.art', {'Design': b'example'})
    (source/'plain.bin').write_bytes(b'ordinary')
    # Exact pre-change schema: old unknown OLE had a NULL cache identity.
    info = (source/'plain.bin').stat()
    identity = json.dumps([info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino])
    with sqlite3.connect(output/'inventory.sqlite') as db:
        db.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO metadata VALUES (?,?)',
                       [('source', str(source.resolve())), ('version', str(module.VERSION)), ('run_id', '1')])
        db.execute('CREATE TABLE files (path TEXT PRIMARY KEY, identity TEXT, result TEXT, run_id INTEGER)')
        db.execute('INSERT INTO files VALUES (?,NULL,?,1)', ('design.art', '{}'))
        db.execute('INSERT INTO files VALUES (?,?,NULL,1)', ('plain.bin', identity))
    first = runner.inventory(source, output, resume=True)
    assert first['run']['inspected'] == 1 and first['run']['reused'] == 1
    original = runner.inspect_file
    def forbidden(path):
        raise AssertionError('stable OLE directory should be reused')
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['inspected'] == 0 and second['run']['reused'] == 2
    assert second['run']['bytes_read'] == 0
    assert second['encryption_counts'] == {'UNKNOWN': 1}
    monkeypatch.setattr(runner, 'inspect_file', original)
    # A future OLE parser revision invalidates only its own cached directories.
    monkeypatch.setattr(module, 'OLE_INVENTORY_REVISION', module.OLE_INVENTORY_REVISION+1)
    monkeypatch.setattr(runner, 'OLE_INVENTORY_REVISION', module.OLE_INVENTORY_REVISION)
    third = runner.inventory(source, output, resume=True)
    assert third['run']['inspected'] == 1 and third['run']['reused'] == 1
    assert runner.inventory(source, output, resume=True)['run']['bytes_read'] == 0
    # A changed source is inspected and may now have a positive encryption marker.
    ole_fixture(path, {'EncryptionInfo': struct.pack('<HHI', 4, 4, 64),
                       'EncryptedPackage': struct.pack('<Q', 100)+b'example'})
    fourth = runner.inventory(source, output, resume=True)
    assert fourth['run']['inspected'] == 1
    assert fourth['encryption_counts'] == {'ENCRYPTED': 1}


@pytest.mark.parametrize('case', ['warnings', 'limit', 'invalid', 'dependency', 'changed'])
def test_unreliable_ole_is_still_retried(tmp_path, monkeypatch, case):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    (source/'sample.art').write_bytes(module.OLE_MAGIC)
    structures = {'warnings': 'DIRECTORY_CHECKED_WITH_WARNINGS', 'limit': 'LIMIT_OR_UNSUPPORTED',
                  'invalid': 'INVALID_OR_UNSUPPORTED_METADATA', 'dependency': 'LIMIT_OR_UNSUPPORTED',
                  'changed': 'SOURCE_CHANGED'}
    reasons = {'warnings': 'OLE_TYPE_UNDETERMINED', 'limit': 'OLE_DIRECTORY_ENTRY_LIMIT',
               'invalid': 'TRUNCATED_METADATA', 'dependency': 'INSTALL_INVENTORY_EXTRA_FOR_OLE',
               'changed': 'SOURCE_CHANGED_DURING_READ'}
    monkeypatch.setattr(runner, 'inspect_file', lambda path: {
        'format': 'OLE', 'encryption': 'UNKNOWN', 'structure': structures[case],
        'reason': reasons[case], 'bytes_read': 8, 'ole_inventory_revision': module.OLE_INVENTORY_REVISION})
    runner.inventory(source, output)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['inspected'] == 1 and second['run']['reused'] == 0
    assert second['encryption_counts'] == {'UNKNOWN': 1}
