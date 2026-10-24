import io
import json
import sqlite3
import struct
from types import SimpleNamespace

import pytest

from bfrs.recovery import container_inventory as inventory
from bfrs.recovery import ppt_inventory as module
from bfrs.recovery.ole_type_hints import ole_type_hint, ppt_candidate, INSTALLER_TYPES
from tests.test_container_inventory import ole_fixture, runner


def records(*, token=0xe391c05f, reference=None, offset=1024, name=b'test', unicode_name=False):
    body = (struct.pack('<LLLHHBBH', 20, token, offset, len(name), 0x03f4, 3, 0, 0)
            + name + struct.pack('<L', 8))
    if unicode_name:
        body += name.decode('ascii').encode('utf-16le')
    current = struct.pack('<HHL', 0, 0x0ff6, len(body)) + body
    edit = struct.pack('<LHBBLLLLHH', 0x100, 0, 0, 3, 0, 64, 1, 10, 1, 0)
    if reference is not None:
        edit += struct.pack('<L', reference)
    document = b'\0' * offset + struct.pack('<HHL', 0, 0x0ff5, len(edit)) + edit
    return current, document


def inspect(tmp_path, current, document):
    pytest.importorskip('olefile')
    return inventory.inspect_file(ole_fixture(tmp_path/'renamed.bin',
        {'Current User': current, 'PowerPoint Document': document}))


@pytest.mark.parametrize('token,reference,state,reason', [
    (0xe391c05f, None, 'NO_ENCRYPTION_INDICATOR', 'PPT_NO_ENCRYPTION_MARKER'),
    (0xf3d1c4df, 2, 'ENCRYPTED', 'PPT_ENCRYPTED_HEADER_TOKEN'),
    # PowerPoint 2002 uses the ordinary token even when encrypted.
    (0xe391c05f, 2, 'ENCRYPTED', 'PPT_ENCRYPTION_REFERENCE'),
])
@pytest.mark.parametrize('unicode_name', [False, True])
def test_ppt_metadata_markers(tmp_path, token, reference, state, reason, unicode_name):
    row = inspect(tmp_path, *records(token=token, reference=reference, unicode_name=unicode_name))
    assert row['format'] == 'PPT' and row['encryption'] == state and row['reason'] == reason
    assert row['ole_type_hint'] == 'POWERPOINT_BINARY'
    assert row['ppt_password_required'] == 'NOT_CHECKED'


@pytest.mark.parametrize('target,offset,fmt,value,reason', [
    ('current', 0, '<H', 1, 'PPT_INVALID_CURRENT_USER'),
    ('current', 2, '<H', 1, 'PPT_INVALID_CURRENT_USER'),
    ('current', 4, '<L', 9999, 'PPT_INVALID_CURRENT_USER_SIZE'),
    ('current', 8, '<L', 19, 'PPT_INVALID_CURRENT_USER'),
    ('current', 12, '<L', 0, 'PPT_HEADER_TOKEN_UNSUPPORTED'),
    ('current', 16, '<L', 0, 'PPT_EDIT_OFFSET_INVALID'),
    ('current', 16, '<L', 0xffffffff, 'PPT_EDIT_OFFSET_INVALID'),
    ('current', 20, '<H', 256, 'PPT_INVALID_CURRENT_USER_SIZE'),
    ('current', 22, '<H', 1, 'PPT_VERSION_UNSUPPORTED'),
    ('current', 24, '<B', 4, 'PPT_VERSION_UNSUPPORTED'),
    ('current', 32, '<L', 0, 'PPT_INVALID_RELEASE_VERSION'),
    ('document', 1024, '<H', 1, 'PPT_INVALID_USER_EDIT'),
    ('document', 1026, '<H', 1, 'PPT_INVALID_USER_EDIT'),
    ('document', 1028, '<L', 100000, 'PPT_INVALID_USER_EDIT'),
    ('document', 1038, '<B', 1, 'PPT_INVALID_USER_EDIT_VERSION'),
    ('document', 1040, '<L', 1024, 'PPT_INVALID_EDIT_REFERENCES'),
    ('document', 1044, '<L', 1024, 'PPT_INVALID_EDIT_REFERENCES'),
    ('document', 1048, '<L', 2, 'PPT_INVALID_EDIT_REFERENCES'),
])
def test_malformed_ppt_metadata_is_unknown(tmp_path, target, offset, fmt, value, reason):
    current, document = map(bytearray, records())
    struct.pack_into(fmt, current if target == 'current' else document, offset, value)
    row = inspect(tmp_path, current, document)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == reason


@pytest.mark.parametrize('reference', [0, 11, 0xffffffff])
def test_invalid_encryption_reference(tmp_path, reference):
    row = inspect(tmp_path, *records(reference=reference))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'PPT_INVALID_ENCRYPTION_REFERENCE'


def test_missing_stream_and_payload_tokens_do_not_prove_encryption(tmp_path):
    pytest.importorskip('olefile')
    current, document = records()
    row = inventory.inspect_file(ole_fixture(tmp_path/'missing.ppt', {'Current User': current}))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'PPT_REQUIRED_STREAM_MISSING'
    # Tokens and a fake encrypted edit outside the actual metadata references.
    document = bytearray(document)
    document[100:104] = struct.pack('<L', 0xf3d1c4df)
    row = inspect(tmp_path, current, document)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'


def test_large_ppt_skips_payload_and_handles_cross_sector_record(tmp_path, monkeypatch):
    current, document = records(offset=2 * 1024 * 1024 + 510)
    calls, original = [], inventory.BoundedReader.at
    def record(reader, offset, size):
        calls.append((offset, size))
        return original(reader, offset, size)
    monkeypatch.setattr(inventory.BoundedReader, 'at', record)
    row = inspect(tmp_path, current, document)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['bytes_read'] < 50 * 1024
    assert max(size for _, size in calls) <= 512


def fake_stream(*, size=2048, sector_size=512, fat=None, mini=None, kind=2):
    entry = SimpleNamespace(entry_type=kind, size=size, isectStart=0)
    ole = SimpleNamespace(direntries=[entry], _find=lambda name: 0,
        minisectorcutoff=4096 if mini is not None else 0, sectorsize=sector_size,
        fat=fat if fat is not None else [1, 2, 3, 0xfffffffe],
        openstream=lambda name: io.BytesIO(mini))
    data = b'H' * 512 + b'A' * 512 + b'B' * 512 + b'C' * 512 + b'D' * 512
    reader = inventory.BoundedReader(io.BytesIO(data), len(data))
    return module._Stream(reader, ole, 'stream'), reader


def test_fragmented_fat_and_minifat_reads():
    stream, reader = fake_stream(fat=[2, 3, 1, 0xfffffffe])
    assert stream.at(510, 4) == b'AACC'
    assert stream.at(1024, 2) == b'BB'
    assert reader.bytes_read == 6
    stream, _ = fake_stream(size=5, mini=b'hello')
    assert stream.at(1, 3) == b'ell'


@pytest.mark.parametrize('fat,reason', [
    ([0, 2, 3, 0xfffffffe], 'PPT_FAT_CYCLE'),
    ([0xfffffffe, 2, 3, 0xfffffffe], 'PPT_FAT_SECTOR_INVALID'),
    ([9] * 10, 'PPT_FAT_SECTOR_OUT_OF_FILE'),
])
def test_bad_fat_chain(fat, reason):
    stream, _ = fake_stream(fat=fat)
    with pytest.raises(ValueError, match=reason):
        stream.at(1024, 4)


def test_ppt_chain_and_shared_read_limits(tmp_path, monkeypatch):
    stream, reader = fake_stream()
    monkeypatch.setattr(module, 'MAX_CHAIN_SECTORS', 1)
    with pytest.raises(module.PPTMetadataLimit, match='PPT_FAT_CHAIN_LIMIT'):
        stream.at(512, 1)
    assert reader.bytes_read == 0
    monkeypatch.setattr(inventory, 'MAX_READ_CALLS', 0)
    with pytest.raises(inventory.InventoryLimit):
        stream.at(0, 1)
    monkeypatch.setattr(inventory, 'MAX_READ_CALLS', 4096)
    row = inspect(tmp_path, *records())
    assert row['reason'] == 'PPT_FAT_CHAIN_LIMIT'


def metadata(names=(), clsid='', **extra):
    return dict(format='OLE', encryption='UNKNOWN', ole_root_clsid=clsid,
        ole_directory_entries=[dict(name=n, type=2) for n in names],
        ole_directory_entry_count=len(names), ole_directory_warnings=False,
        ole_directory_entries_truncated=False, **extra)


@pytest.mark.parametrize('names,kind', [
    (['Current User', 'PowerPoint Document'], 'POWERPOINT_BINARY'),
    (['PP40'], 'POWERPOINT_LEGACY_POSSIBLE'),
    (['\x05WilcomDesignInformationDDD'], 'EMBROIDERY_DESIGN_POSSIBLE'),
    (['SStitches'], 'EMBROIDERY_DESIGN_POSSIBLE'),
    (['Catalog', '1', '2'], 'THUMBNAIL_CACHE_POSSIBLE'),
    (['TravelLog'], 'BROWSER_STATE_POSSIBLE'),
    (['VGCoreDataStream'], 'GRAPHICS_DOCUMENT_POSSIBLE'),
    ([], 'EMPTY_DIRECTORY'),
    (['data', 'Thumbnail'], 'UNDETERMINED'),
])
def test_ole_hints_preserve_encryption(names, kind):
    row = metadata(names)
    original = json.dumps(row)
    assert ole_type_hint(row)['ole_type_hint'] == kind
    assert json.dumps(row) == original


def test_ole_hints_clsid_warnings_and_truncated_list():
    for clsid, kind in INSTALLER_TYPES.items():
        row = metadata(['Data'], clsid.lower())
        assert ole_type_hint(row)['ole_type_hint'] == kind
    row = metadata(['Catalog', '1'])
    row['ole_directory_entries_truncated'] = True
    assert ole_type_hint(row)['ole_type_hint_partial']
    row['ole_directory_warnings'] = True
    assert ole_type_hint(row)['ole_type_hint'] == 'UNDETERMINED'
    assert not ppt_candidate(row)


def test_cache_enrichment_only_reopens_ppt(tmp_path, monkeypatch):
    pytest.importorskip('olefile')
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    ppt = ole_fixture(source/'old.bin', dict(zip(('Current User', 'PowerPoint Document'), records())))
    ole_fixture(source/'design.bin', {'SStitches': b'test'})
    (source/'ordinary.bin').write_bytes(b'ordinary')
    runner.inventory(source, output)
    with sqlite3.connect(output/'inventory.sqlite') as db:
        row = metadata(['Current User', 'PowerPoint Document'])
        row.update(path='old.bin', size=ppt.stat().st_size, reason='OLE_TYPE_UNDETERMINED',
                   structure='DIRECTORY_CHECKED', ole_inventory_revision=inventory.OLE_INVENTORY_REVISION,
                   bytes_read=2000)
        db.execute('UPDATE files SET result=?,inspection_revision=? WHERE path=?',
                   (json.dumps(row), inventory.OLE_INVENTORY_REVISION, 'old.bin'))
        row = json.loads(db.execute("SELECT result FROM files WHERE path='design.bin'").fetchone()[0])
        for key in list(row):
            if key.startswith('ole_type_hint'):
                del row[key]
        db.execute("UPDATE files SET result=? WHERE path='design.bin'", (json.dumps(row),))
        db.execute("DELETE FROM metadata WHERE key='ole_hint_ppt_revision'")
    calls, original = [], runner.inspect_file
    def tracked(path):
        calls.append(path)
        return original(path)
    monkeypatch.setattr(runner, 'inspect_file', tracked)
    result = runner.inventory(source, output, resume=True)
    assert calls == [ppt] and result['run']['reused'] == 2
    rows = [json.loads(line) for line in (output/'inventory.jsonl').read_text().splitlines()]
    assert next(r for r in rows if r['path']=='design.bin')['ole_type_hint'] == 'EMBROIDERY_DESIGN_POSSIBLE'
    calls.clear()
    result = runner.inventory(source, output, resume=True)
    assert not calls and result['run']['bytes_read'] == 0 and result['run']['reused'] == 3
