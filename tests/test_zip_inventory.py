"""Bounded classic-ZIP directory scanning without extracting member payloads."""
import io
import json
from pathlib import Path
import struct
import tracemalloc
import zipfile

import pytest

from bfrs.recovery import container_inventory as module
from tests.test_container_inventory import runner


def make_zip(path, count, *, office=False, encrypted_last=False):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
        for index in range(count):
            name = f'entry-{index:05}.txt'
            if office and index == count - 2:
                name = '[Content_Types].xml'
            if office and index == count - 1:
                name = 'word/document.xml'
            archive.writestr(name, b'')
    data = bytearray(path.read_bytes())
    eocd = len(data) - 22
    offset = struct.unpack_from('<L', data, eocd + 16)[0]
    starts = []
    cursor = offset
    for _ in range(count):
        starts.append(cursor)
        lengths = struct.unpack_from('<3H', data, cursor + 28)
        cursor += 46 + sum(lengths)
    if encrypted_last:
        # Synthetic encryption marker only: payload encryption is not exercised.
        struct.pack_into('<H', data, starts[-1] + 8, 1)
        path.write_bytes(data)
    return data, starts, eocd


@pytest.mark.parametrize('encrypted', [False, True])
def test_large_zip_checks_every_entry_including_last_encryption_flag(tmp_path, encrypted):
    path = tmp_path/'large.bin'
    make_zip(path, 10000, encrypted_last=encrypted)
    row = module.inspect_file(path)
    assert row['encryption'] == ('ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR')
    assert row['encrypted_members'] == int(encrypted)
    assert row['member_count'] == row['zip_members_checked'] == row['zip_declared_members'] == 10000
    assert len(row['member_names']) == 50 and row['names_truncated']
    assert row['bytes_read'] <= module.MAX_READ_BYTES


def test_large_ooxml_markers_after_report_name_limit(tmp_path):
    path = tmp_path/'office.bin'
    make_zip(path, 6000, office=True)
    row = module.inspect_file(path)
    assert row['format'] == 'DOCX'
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert 'word/document.xml' not in row['member_names']
    assert row['zip_members_checked'] == 6000


def test_large_directory_has_bounded_reads_memory_and_no_payload_extraction(tmp_path, monkeypatch):
    path = tmp_path/'large.zip'
    data, starts, eocd = make_zip(path, 20000)
    directory_size = eocd - starts[0]
    del data
    calls = []
    original = module.BoundedReader.at

    def recording(reader, offset, size):
        calls.append((offset, size))
        return original(reader, offset, size)

    monkeypatch.setattr(module.BoundedReader, 'at', recording)
    tracemalloc.start()
    try:
        row = module.inspect_file(path)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['zip_directory_size'] == directory_size > 1024 * 1024
    assert peak < 700 * 1024  # Includes names, decoding, tail and directory buffer.
    assert calls[:2] == [(0, 512), (path.stat().st_size - 65557, 65557)]
    assert len(calls) < 40  # Buffered I/O, not a disk read for each member.
    assert max(size for _, size in calls[2:]) <= 64 * 1024
    assert all(starts[0] <= offset and offset + size <= eocd for offset, size in calls[2:])
    assert row['bytes_read'] == 512 + 65557 + directory_size


def test_headers_names_extra_and_comments_cross_block_boundaries(tmp_path, monkeypatch):
    path = tmp_path/'boundaries.zip'
    names = ['żółć-' * 300 + '.txt', 'plain.txt', '[Content_Types].xml', 'word/document.xml']
    with zipfile.ZipFile(path, 'w') as archive:
        for name in names:
            entry = zipfile.ZipInfo(name)
            entry.extra = struct.pack('<HH', 0xcafe, 100) + b'x' * 100
            entry.comment = b'comment' * 40
            archive.writestr(entry, b'')
    monkeypatch.setattr(module, 'ZIP_DIRECTORY_BLOCK_BYTES', 31)
    row = module.inspect_file(path)
    assert row['format'] == 'DOCX' and row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['member_names'] == [name[:512] for name in names]
    assert row['zip_members_checked'] == 4


def test_maximum_name_and_skipped_fields_have_bounded_buffers(tmp_path):
    path = tmp_path/'long.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        entry = zipfile.ZipInfo('x' * 65535)
        entry.extra = struct.pack('<HH', 0xcafe, 65531) + b'e' * 65531
        entry.comment = b'c' * 65535
        archive.writestr(entry, b'')
        archive.writestr('last.txt', b'')
    row = module.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['member_names'] == ['x' * 512, 'last.txt']
    assert row['zip_members_checked'] == 2


@pytest.mark.parametrize('mutation,reason', [
    ('signature', 'ZIP_BAD_DIRECTORY_ENTRY'),
    ('name_length', 'ZIP_TRUNCATED_DIRECTORY_ENTRY'),
    ('extra_length', 'ZIP_TRUNCATED_DIRECTORY_ENTRY'),
    ('comment_length', 'ZIP_TRUNCATED_DIRECTORY_ENTRY'),
    ('too_few_entries', 'ZIP_DIRECTORY_TRAILER_UNSUPPORTED'),
    ('too_many_entries', 'ZIP_BAD_DIRECTORY_ENTRY'),
    ('multi_disk_entry', 'ZIP_MULTIVOLUME_UNSUPPORTED'),
    ('layout', 'ZIP_DIRECTORY_LAYOUT_UNSUPPORTED'),
    ('zip64', 'ZIP64_UNSUPPORTED'),
])
def test_malformed_or_unsupported_directory_never_becomes_unencrypted(tmp_path, mutation, reason):
    path = tmp_path/'malformed.zip'
    data, starts, eocd = make_zip(path, 3)
    struct.pack_into('<H', data, starts[0] + 8, 1)
    if mutation == 'signature':
        data[starts[-1]:starts[-1] + 4] = b'bad!'
    elif mutation in ('name_length', 'extra_length', 'comment_length'):
        field = {'name_length': 28, 'extra_length': 30, 'comment_length': 32}[mutation]
        struct.pack_into('<H', data, starts[-1] + field, 65535)
    elif mutation in ('too_few_entries', 'too_many_entries', 'zip64'):
        count = {'too_few_entries': 2, 'too_many_entries': 4, 'zip64': 65535}[mutation]
        struct.pack_into('<HH', data, eocd + 8, count, count)
    elif mutation == 'multi_disk_entry':
        struct.pack_into('<H', data, starts[-1] + 34, 1)
    elif mutation == 'layout':
        struct.pack_into('<L', data, eocd + 16, starts[0] + 1)
    path.write_bytes(data)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason
    assert 'encrypted_members' not in row


def test_over_budget_directory_is_rejected_before_directory_reads(tmp_path):
    path = tmp_path/'budget.zip'
    make_zip(path, 35000)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'METADATA_READ_LIMIT'
    assert row['zip_directory_size'] > module.MAX_READ_BYTES
    assert row['zip_declared_members'] == 35000 and row['zip_members_checked'] == 0
    assert row['bytes_read'] == 512 + 65557


def test_read_call_budget_is_still_enforced(tmp_path, monkeypatch):
    path = tmp_path/'budget.zip'
    make_zip(path, 6000)
    monkeypatch.setattr(module, 'MAX_READ_CALLS', 3)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'METADATA_READ_LIMIT'
    assert 0 < row['zip_members_checked'] < row['zip_declared_members']
    assert row['bytes_read'] <= module.MAX_READ_BYTES


def test_empty_zip_and_fake_end_signature_inside_comment(tmp_path):
    path = tmp_path/'empty.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.comment = b'comment PK\x05\x06 not another end record'
    row = module.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['member_count'] == row['zip_members_checked'] == 0


def test_short_physical_directory_read_remains_an_error():
    # Simulate a source that became shorter than its originally stated size.
    reader = module.BoundedReader(io.BytesIO(b'PK\x01\x02'), 100)
    central = module._ZipDirectoryReader(reader, 0, 100)
    with pytest.raises(ValueError, match='SHORT_READ'):
        central.read(46)


def test_resume_refreshes_old_zip_limit_and_reuses_other_files(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    large = source/'large.zip'
    make_zip(large, 6000, encrypted_last=True)
    make_zip(source/'small.zip', 2)
    (source/'ordinary.bin').write_bytes(b'ordinary')
    original = runner.inspect_file

    def old_inspector(path):
        if path == large:
            return dict(format='ZIP', encryption='UNKNOWN', structure='LIMIT_OR_UNSUPPORTED',
                        reason='ZIP_MEMBER_LIMIT', bytes_read=512)
        return original(path)

    monkeypatch.setattr(runner, 'inspect_file', old_inspector)
    runner.inventory(source, output)
    inspected = []

    def new_inspector(path):
        inspected.append(path)
        assert path == large, 'Unchanged successful files must not be reread'
        return original(path)

    monkeypatch.setattr(runner, 'inspect_file', new_inspector)
    second = runner.inventory(source, output, resume=True)
    assert inspected == [large]
    assert second['run']['inspected'] == 1 and second['run']['reused'] == 2
    rows = [json.loads(line) for line in (output/'inventory.jsonl').read_text().splitlines()]
    row = next(row for row in rows if row['path'] == large.name)
    assert row['encryption'] == 'ENCRYPTED' and row['zip_members_checked'] == 6000
    third = runner.inventory(source, output, resume=True)
    assert third['run']['inspected'] == 0 and third['run']['reused'] == 3
    assert third['run']['bytes_read'] == 0
