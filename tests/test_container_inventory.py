import json
import sqlite3
from pathlib import Path
import struct
import zipfile
import zlib

import pytest

from bfrs.recovery import container_inventory as module

from bfrs.application import document_inventory as runner


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
    # CFB v3 with normal FAT streams; supports multi-MiB synthetic payloads.
    free, end, fat_sector = 0xffffffff, 0xfffffffe, 0xfffffffd
    sizes = [max(4096, len(content)) for content in streams.values()]
    sectors = [(size+511)//512 for size in sizes]
    fat_count = 1
    while fat_count*128 < fat_count+1+sum(sectors):
        fat_count += 1
    assert fat_count <= 109 and len(streams) <= 3
    header = bytearray(512)
    header[:8] = module.OLE_MAGIC
    struct.pack_into('<HHHHH', header, 24, 0x3e, 3, 0xfffe, 9, 6)
    struct.pack_into('<LLLLLLLLL', header, 40, 0, fat_count, fat_count, 0, 4096, end, 0, end, 0)
    struct.pack_into('<109L', header, 76, *range(fat_count), *([free]*(109-fat_count)))
    fat = [free]*(128*fat_count)
    fat[:fat_count] = [fat_sector]*fat_count
    fat[fat_count] = end
    directory = bytearray(512)
    def entry(index, name, kind, child, sibling, sector, size):
        offset = index*128
        encoded = (name+'\0').encode('utf-16le')
        directory[offset:offset+len(encoded)] = encoded
        struct.pack_into('<HBBLLL', directory, offset+64, len(encoded), kind, 1, free, sibling, child)
        struct.pack_into('<LQ', directory, offset+116, sector, size)
    entry(0, 'Root Entry', 5, 1, free, end, 0)
    payload = []
    sector = fat_count+1
    for index, (name, content) in enumerate(streams.items(), 1):
        count = sectors[index-1]
        entry(index, name, 2, free, index+1 if index<len(streams) else free, sector, sizes[index-1])
        for current in range(sector, sector+count):
            fat[current] = current+1 if current < sector+count-1 else end
        payload.append(content.ljust(count*512, b'\0'))
        sector += count
    path.write_bytes(header + struct.pack(f'<{len(fat)}L', *fat) + directory + b''.join(payload))
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
    assert row['structure'] == 'INVALID_OR_UNSUPPORTED_METADATA'
    assert row['reason'] == '7Z_TRUNCATED_HEADER'
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



def test_walk_identity_matches_direct_stat(tmp_path):
    path = tmp_path / 'plain.bin'
    path.write_bytes(b'ordinary')
    [(walked, info, error)] = list(runner.walk(tmp_path))
    assert walked == path and error is None
    assert runner._identity(info) == runner._identity(path.stat())


def test_resume_refreshes_legacy_zero_file_ids_once(tmp_path, monkeypatch):
    source, output = tmp_path / 'source', tmp_path / 'output'
    source.mkdir()
    path = zip_fixture(source / 'a.bin')
    runner.inventory(source, output)
    info = path.stat()
    # Earlier Windows traversal persisted DirEntry.stat()'s zero file IDs.
    with sqlite3.connect(output / 'inventory.sqlite') as db:
        db.execute('UPDATE files SET identity=?',
                   (json.dumps([info.st_size, info.st_mtime_ns, 0, 0]),))
    refreshed = runner.inventory(source, output, resume=True)
    assert refreshed['run']['inspected'] == 1
    assert refreshed['run']['reused'] == 0
    with sqlite3.connect(output / 'inventory.sqlite') as db:
        assert db.execute('SELECT identity FROM files').fetchone()[0] == runner._identity(path.stat())
    def forbidden(path):
        raise AssertionError('refreshed file ID should be reused')
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    resumed = runner.inventory(source, output, resume=True)
    assert resumed['run']['inspected'] == 0
    assert resumed['run']['reused'] == 1
    assert resumed['run']['bytes_read'] == 0

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


def rar3_service(*, name=b'CMT', flags=0x8000, packed_size=0, extra=b'',
                 name_size=None, high_size=0):
    body = struct.pack('<LLBLLBBHL', packed_size, 0, 2, 0, 0, 29, 48,
                       len(name) if name_size is None else name_size, 0)
    if flags & 0x100:
        body += struct.pack('<LL', high_size, 0)
    return rar3_header(0x7a, flags, body + name + extra)


def rar3_archive(*blocks):
    return (b'Rar!\x1a\x07\x00' + rar3_header(0x73, 0, b'\0' * 6)
            + b''.join(blocks) + rar3_header(0x7b, 0, b''))


@pytest.mark.parametrize('name', [b'CMT', b'RR', b'STM', b'custom'])
def test_rar3_service_payload_is_skipped_and_members_follow(tmp_path, name):
    # An apparent encrypted header in service data is not a header marker.
    payload = rar3_header(0x73, 0x80, b'\0' * 6)
    plain = struct.pack('<LLBLLBBHL', 0, 0, 2, 0, 0, 29, 48, 1, 0) + b'a'
    path = tmp_path/'service.rar'
    path.write_bytes(rar3_archive(rar3_service(name=name, packed_size=len(payload)), payload,
                                 rar3_header(0x74, 0x8000, plain)))
    row = module.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['member_count'] == 1 and row['rar_service_headers_checked'] == 1
    path.write_bytes(rar3_archive(rar3_service(name=name, packed_size=len(payload)), payload,
                                 rar3_header(0x74, 0x8004, plain)))
    assert module.inspect_file(path)['reason'] == 'RAR_FILE_PASSWORD_FLAG'


@pytest.mark.parametrize('flags,extra', [(0x8004, b''), (0x8404, b'x' * 8),
                                       (0x8504, b'private metadata' + b'x' * 8)])
def test_rar3_encrypted_service_is_a_marker(tmp_path, flags, extra):
    path = tmp_path/'service.rar'
    path.write_bytes(rar3_archive(rar3_service(flags=flags, extra=extra)))
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['reason'] == 'RAR_SERVICE_PASSWORD_FLAG'


@pytest.mark.parametrize('block,reason', [
    (rar3_service(name=b''), 'RAR_INVALID_SERVICE_HEADER'),
    (rar3_service(name_size=100), 'RAR_INVALID_SERVICE_HEADER'),
    (rar3_service(flags=0), 'RAR_INVALID_SERVICE_HEADER'),
    (rar3_service(flags=0x8404, extra=b'x' * 7), 'RAR_INVALID_SERVICE_HEADER'),
    (rar3_header(0x7a, 0x8000, b'x' * 4), 'RAR_INVALID_FILE_HEADER'),
    (rar3_service(packed_size=9999), 'RAR_TRUNCATED_PAYLOAD'),
    (rar3_service(flags=0x8100, high_size=1), 'RAR_TRUNCATED_PAYLOAD'),
    (rar3_service(flags=0x8001), 'RAR_MULTIVOLUME_INCOMPLETE_SCOPE'),
    (rar3_service(flags=0x8002), 'RAR_MULTIVOLUME_INCOMPLETE_SCOPE'),
    (rar3_header(0x77, 0, b''), 'RAR_BLOCK_UNSUPPORTED'),
])
def test_rar3_invalid_or_incomplete_service_stays_unknown(tmp_path, block, reason):
    path = tmp_path/'service.rar'
    path.write_bytes(rar3_archive(block))
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason


def test_rar3_service_crc_and_main_header_required(tmp_path):
    path = tmp_path/'service.rar'
    damaged = bytearray(rar3_service())
    damaged[-1] ^= 1
    path.write_bytes(rar3_archive(damaged))
    assert module.inspect_file(path)['reason'] == 'RAR_HEADER_CRC_MISMATCH'
    path.write_bytes(b'Rar!\x1a\x07\x00' + rar3_service())
    assert module.inspect_file(path)['encryption'] == 'UNKNOWN'


def test_rar3_service_large_data_not_read(tmp_path, monkeypatch):
    path = tmp_path/'large.rar'
    packed_size = 100 * 1024 * 1024
    main = b'Rar!\x1a\x07\x00' + rar3_header(0x73, 0, b'\0' * 6)
    service = rar3_service(packed_size=packed_size)
    end = rar3_header(0x7b, 0, b'')
    with path.open('wb') as stream:
        stream.write(main + service)
        stream.seek(packed_size, 1)
        stream.write(end)
    calls, original = [], module.BoundedReader.at
    def record(reader, offset, size):
        calls.append((offset, size))
        return original(reader, offset, size)
    monkeypatch.setattr(module.BoundedReader, 'at', record)
    row = module.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR' and row['member_count'] == 0
    end_offset = len(main) + len(service) + packed_size
    assert calls == [(0, 512), (7, 7), (7, 13), (20, 7), (20, len(service)),
                     (end_offset, 7), (end_offset, 7)]
    assert row['bytes_read'] < 1024


def test_rar3_service_block_limit(tmp_path, monkeypatch):
    path = tmp_path/'service.rar'
    path.write_bytes(rar3_archive(rar3_service(), rar3_service()))
    monkeypatch.setattr(module, 'MAX_MEMBERS', 2)
    assert module.inspect_file(path)['reason'] == 'RAR_BLOCK_LIMIT'


def test_rar3_service_resume_retries_old_unknown(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    path = source/'sample.rar'
    path.write_bytes(rar3_archive(rar3_service()))
    (source/'ordinary.bin').write_bytes(b'ordinary')
    original = runner.inspect_file
    def old(target):
        if target == path:
            return dict(format='RAR', encryption='UNKNOWN', structure='LIMIT_OR_UNSUPPORTED',
                        reason='RAR_BLOCK_UNSUPPORTED', bytes_read=32)
        return original(target)
    monkeypatch.setattr(runner, 'inspect_file', old)
    runner.inventory(source, output)
    monkeypatch.setattr(runner, 'inspect_file', original)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['inspected'] == 1 and second['run']['reused'] == 1
    assert second['encryption_counts'] == {'NO_ENCRYPTION_INDICATOR': 1}
    third = runner.inventory(source, output, resume=True)
    assert third['run']['reused'] == 2 and third['run']['bytes_read'] == 0


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


@pytest.mark.parametrize('flags,expected', [(0, 'NO_ENCRYPTION_INDICATOR'), (0x100, 'ENCRYPTED')])
def test_word6_prefix_and_mini_stream(tmp_path, flags, expected):
    pytest.importorskip('olefile')
    fib = bytearray(32)
    struct.pack_into('<HH', fib, 0, 0xa5dc, 0x65)
    struct.pack_into('<H', fib, 10, flags)
    path = ole_fixture(tmp_path/'legacy.bin', {'WordDocument': fib})
    row = module.inspect_file(path)
    assert row['encryption'] == expected and row['doc_fib_version'] == 0x65
    assert row['bytes_read'] < 4096
    # Convert the synthetic directory to a MiniFAT-backed 32-byte FIB.
    data = bytearray(path.read_bytes())
    struct.pack_into('<LL', data, 60, 2, 1)
    struct.pack_into('<LL', data, 512+2*4, 0xfffffffe, 0xfffffffe)
    struct.pack_into('<LQ', data, 1024+116, 3, 64)
    struct.pack_into('<LQ', data, 1024+128+116, 0, 32)
    data[1536:2048] = struct.pack('<128L', 0xfffffffe, *([0xffffffff]*127))
    data[2048:2080] = fib
    path.write_bytes(data)
    assert module.inspect_file(path)['encryption'] == expected
    struct.pack_into('<H', data, 2050, 0x99)
    path.write_bytes(data)
    assert module.inspect_file(path)['reason'] == 'DOC_LEGACY_FIB_VERSION_UNSUPPORTED'


@pytest.mark.parametrize('kind', ['DOC', 'XLS', 'OFFICE_ENCRYPTED'])
@pytest.mark.parametrize('encrypted', [False, True])
def test_large_office_streams_use_bounded_prefix(tmp_path, kind, encrypted):
    pytest.importorskip('olefile')
    tail = b'\0'*(3*1024*1024)
    if kind == 'DOC':
        fib = bytearray(32)
        struct.pack_into('<HH', fib, 0, 0xa5ec, 0xc1)
        struct.pack_into('<H', fib, 10, 0x100 if encrypted else 0)
        streams = {'WordDocument': fib+tail}
    elif kind == 'XLS':
        bof = struct.pack('<HHHH', 0x809, 4, 0x600, 5)
        # A record/header crossing sectors plus a FILEPASS in a later sector.
        extra = struct.pack('<HH', 0x42, 499)+b'\0'*499
        if encrypted:
            extra += struct.pack('<HH', 0x2f, 6)+b'\0'*6
        streams = {'Workbook': bof+extra+struct.pack('<HH', 10, 0)+tail}
    else:
        streams = {'EncryptionInfo': struct.pack('<HHI', 4, 4, 64)+tail,
                   'EncryptedPackage': struct.pack('<Q', 100)}
    row = module.inspect_file(ole_fixture(tmp_path/'large.bin', streams))
    assert row['format'] == kind
    assert row['encryption'] == ('ENCRYPTED' if encrypted or kind == 'OFFICE_ENCRYPTED'
                                 else 'NO_ENCRYPTION_INDICATOR')
    assert row['bytes_read'] < 40*1024
    assert row['ole_stream_scope'] == 'METADATA_PREFIX_ONLY'


@pytest.mark.parametrize('link', [2, 0xfffffffe, 0xffffffff, 0xfffffffd, 120])
def test_ole_prefix_rejects_broken_chain(tmp_path, link):
    pytest.importorskip('olefile')
    content = struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 0x42, 600)+b'\0'*600
    content += struct.pack('<HH', 10, 0)
    path = ole_fixture(tmp_path/'broken.xls', {'Workbook': content})
    data = bytearray(path.read_bytes())
    struct.pack_into('<L', data, 512+2*4, link)
    path.write_bytes(data)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['structure'] == 'INVALID_OR_UNSUPPORTED_METADATA'


def test_fragmented_ole_prefix_and_shared_budgets(tmp_path, monkeypatch):
    pytest.importorskip('olefile')
    content = struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 0x42, 600)+b'\0'*600
    content += struct.pack('<HH', 10, 0)
    path = ole_fixture(tmp_path/'fragmented.xls', {'Workbook': content})
    data = bytearray(path.read_bytes())
    # Move logical sector two to a non-adjacent sector and link it back.
    data[512+7*512:512+8*512] = data[512+3*512:512+4*512]
    struct.pack_into('<L', data, 512+2*4, 7)
    struct.pack_into('<L', data, 512+7*4, 4)
    path.write_bytes(data)
    assert module.inspect_file(path)['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    with monkeypatch.context() as m:
        m.setattr(module, 'MAX_OLE_METADATA_BYTES', 512)
        assert module.inspect_file(path)['reason'] == 'OLE_METADATA_PREFIX_LIMIT'
    with monkeypatch.context() as m:
        m.setattr(module, 'MAX_READ_BYTES', 2048)
        assert module.inspect_file(path)['encryption'] == 'UNKNOWN'
    with monkeypatch.context() as m:
        m.setattr(module, 'MAX_READ_CALLS', 2)
        assert module.inspect_file(path)['encryption'] == 'UNKNOWN'


@pytest.mark.parametrize('content', [
    struct.pack('<HHHHHH', 0x809, 4, 0x500, 5, 10, 0),
    struct.pack('<HHHHHH', 0x809, 4, 0x600, 0x10, 10, 0),
    struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 0x809, 0),
    struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 10, 1)+b'x',
    struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 0x2f, 2)+b'xx',
    struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 0x42, 65535),
])
def test_invalid_xls_globals_stay_unknown(tmp_path, content):
    pytest.importorskip('olefile')
    row = module.inspect_file(ole_fixture(tmp_path/'invalid.xls', {'Workbook': content}))
    assert row['encryption'] == 'UNKNOWN'


def test_old_office_limit_checkpoint_refreshes_only_failed_files(tmp_path, monkeypatch):
    pytest.importorskip('olefile')
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    content = struct.pack('<HHHHHH', 0x809, 4, 0x600, 5, 10, 0)+b'\0'*(2*1024*1024)
    ole_fixture(source/'large.xls', {'Workbook': content})
    ole_fixture(source/'unsupported.bin', {'Design': b'example'})
    (source/'ordinary.bin').write_bytes(b'ordinary')
    original = runner.inspect_file
    def old(path):
        if path.suffix == '.xls':
            return dict(format='XLS', encryption='UNKNOWN', structure='LIMIT_OR_UNSUPPORTED',
                        reason='OLE_STREAM_LIMIT', bytes_read=512)
        return original(path)
    monkeypatch.setattr(runner, 'inspect_file', old)
    runner.inventory(source, output)
    monkeypatch.setattr(runner, 'inspect_file', original)
    second = runner.inventory(source, output, resume=True)
    assert second['run']['inspected'] == 1 and second['run']['reused'] == 2
    third = runner.inventory(source, output, resume=True)
    assert third['run']['inspected'] == 0 and third['run']['bytes_read'] == 0
