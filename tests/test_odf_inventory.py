"""Synthetic ODF metadata fixtures: no real documents, wallets or passwords."""
import io
import json
import sqlite3
import struct
import zipfile

import pytest

from bfrs.application import document_inventory as runner
from bfrs.application.inventory_view import read_inventory_page
from bfrs.recovery import container_inventory as inventory
from bfrs.recovery import odf_inventory as odf


def manifest(*, kind='text', encrypted=True, algorithm='Blowfish CFB', extra='', count=1):
    encryption = (f'<m:encryption-data m:checksum="c3ludGhldGlj" m:checksum-type="SHA1/1K">'
                  f'<m:algorithm m:algorithm-name="{algorithm}" m:initialisation-vector="AAAAAAAAAAA="/>'
                  '<m:key-derivation m:key-derivation-name="PBKDF2" m:iteration-count="1024" '
                  'm:salt="AAAAAAAAAAAAAAAAAAAAAA=="/></m:encryption-data>') if encrypted else ''
    return (f'<m:manifest xmlns:m="{odf.NAMESPACE}">'
            f'<m:file-entry m:full-path="/" m:media-type="{odf.MIME_PREFIX}{kind}"/>'
            + ''.join(f'<m:file-entry m:full-path="part-{i}.xml" m:media-type="text/xml">'
                      f'{encryption}</m:file-entry>' for i in range(count))
            + extra + '</m:manifest>').encode()


def package(path, *, xml=None, kind='text', compression=zipfile.ZIP_DEFLATED,
            mimetype=True, include_manifest=True, before=0):
    with zipfile.ZipFile(path, 'w') as archive:
        if mimetype:
            archive.writestr('mimetype', odf.MIME_PREFIX + kind)
        for i in range(before):
            archive.writestr(f'padding-{i}', b'')
        # Ciphertext integrity is intentionally outside this metadata test.
        archive.writestr('part-0.xml', b'Synthetic placeholder, not document content.')
        if include_manifest:
            archive.writestr('META-INF/manifest.xml', xml if xml is not None else manifest(kind=kind),
                             compress_type=compression)
    return path


@pytest.mark.parametrize('kind,expected', [('text', 'ODT'), ('spreadsheet', 'ODS'),
    ('presentation', 'ODP'), ('graphics', 'ODG'), ('text-template', 'OTT')])
@pytest.mark.parametrize('algorithm', ['Blowfish CFB', 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'])
@pytest.mark.parametrize('compression', [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_encryption_independent_of_extension_and_zip_password_flags(tmp_path, kind, expected, algorithm, compression):
    path = package(tmp_path/'renamed.bin', kind=kind,
                   xml=manifest(kind=kind, algorithm=algorithm), compression=compression)
    with zipfile.ZipFile(path) as archive:
        assert all(not member.flag_bits & 1 for member in archive.infolist())
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED' and row['format'] == expected
    assert row['reason'] == 'ODF_MANIFEST_ENCRYPTION_DATA'
    assert row['encrypted_members'] == 0 and row['odf_encrypted_members'] == 1
    assert row['odf_password_required'] == 'NOT_CHECKED'
    assert row['bytes_read'] <= inventory.MAX_READ_BYTES


@pytest.mark.parametrize('extra', ['', '<!-- m:encryption-data -->',
    '<m:file-entry m:full-path="encryption-data" m:media-type="text/xml"/>'])
def test_unencrypted_and_text_mentions_are_not_encryption(tmp_path, extra):
    path = package(tmp_path/'plain.odt', xml=manifest(encrypted=False, extra=extra))
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    assert row['odf_encrypted_members'] == 0 and row['format'] == 'ODT'


def test_namespace_aliases_utf16_and_manifest_after_name_limit(tmp_path):
    xml = manifest().decode().replace('m:', 'different:').replace('xmlns:m=', 'xmlns:different=')
    row = inventory.inspect_file(package(tmp_path/'renamed', xml=xml.encode('utf-16'), before=70))
    assert row['encryption'] == 'ENCRYPTED'
    assert 'META-INF/manifest.xml' not in row['member_names']


def test_manifest_can_identify_package_without_mimetype(tmp_path):
    row = inventory.inspect_file(package(tmp_path/'renamed.bin', mimetype=False))
    assert row['format'] == 'ODT' and row['encryption'] == 'ENCRYPTED'


@pytest.mark.parametrize('xml', [
    manifest()[:-5],
    manifest().replace(odf.NAMESPACE.encode(), b'urn:not-the-odf-namespace'),
    manifest().replace(b'<m:encryption-data ', b'<m:encryption-data /> <m:encryption-data ', 1),
    manifest().replace(b'part-0.xml', b'/'),
    manifest().replace(b'<m:algorithm ', b'<wrong:algorithm xmlns:wrong="urn:fake" '),
    manifest().replace(b'<m:key-derivation ', b'<m:unrecognized '),
    manifest(encrypted=False, extra='<m:encryption-data/>'),
    manifest(encrypted=False, extra='<m:file-entry m:full-path="part-0.xml" m:media-type=""/>'),
    f'<m:manifest xmlns:m="{odf.NAMESPACE}"/>'.encode(),
    b'<!DOCTYPE m:manifest [<!ENTITY example "test">]>' + manifest(),
    b'<!DOCTYPE m:manifest SYSTEM "file:///should-not-be-read">' + manifest(),
])
def test_invalid_ambiguous_and_unsafe_xml_stays_unknown(tmp_path, xml):
    row = inventory.inspect_file(package(tmp_path/'bad.odt', xml=xml))
    assert row['encryption'] == 'UNKNOWN'
    assert row['reason'].startswith('ODF_')


def test_missing_manifest_and_mismatched_mimetype_stay_unknown(tmp_path):
    row = inventory.inspect_file(package(tmp_path/'missing.odt', include_manifest=False))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_MANIFEST_MISSING'
    row = inventory.inspect_file(package(tmp_path/'mismatch.odt', xml=manifest(kind='spreadsheet')))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_MIMETYPE_MISMATCH'


def test_duplicate_metadata_entries_stay_unknown(tmp_path):
    path = package(tmp_path/'duplicate.odt')
    with zipfile.ZipFile(path, 'a') as archive, pytest.warns(UserWarning):
        archive.writestr('META-INF/manifest.xml', manifest(encrypted=False))
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_DUPLICATE_METADATA_ENTRY'


@pytest.mark.parametrize('mutation', ['crc', 'local_name', 'local_method', 'local_size', 'offset'])
def test_metadata_local_headers_and_crc_are_verified(tmp_path, mutation):
    path = package(tmp_path/'corrupt.odt', compression=zipfile.ZIP_STORED)
    with zipfile.ZipFile(path) as archive:
        entry = archive.getinfo('META-INF/manifest.xml')
        central = archive.start_dir
    data = bytearray(path.read_bytes())
    local = entry.header_offset
    if mutation == 'crc':
        data[local + 30 + len(entry.filename) + 4] ^= 1
    elif mutation == 'local_name':
        data[local + 30] ^= 1
    elif mutation == 'local_method':
        struct.pack_into('<H', data, local + 8, 8)
    elif mutation == 'local_size':
        struct.pack_into('<L', data, local + 18, 1)
    else:
        pos = data.index(b'META-INF/manifest.xml', central) - 46
        struct.pack_into('<L', data, pos + 42, central)
    path.write_bytes(data)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'].startswith('ODF_')


def test_manifest_limits_and_unsupported_compression(tmp_path, monkeypatch):
    path = package(tmp_path/'large.odt', xml=manifest(extra=' ' * odf.MAX_MANIFEST_BYTES))
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_METADATA_SIZE_LIMIT'
    row = inventory.inspect_file(package(tmp_path/'bz2.odt', compression=zipfile.ZIP_BZIP2))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_METADATA_ENCODING_UNSUPPORTED'
    monkeypatch.setattr(odf, 'MAX_XML_ELEMENTS', 4)
    row = inventory.inspect_file(package(tmp_path/'many.odt'))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_XML_STRUCTURE_LIMIT'


def test_false_declared_size_cannot_expand_a_manifest_bomb(tmp_path):
    path = package(tmp_path/'bomb.odt', xml=manifest(extra=' ' * 100000))
    with zipfile.ZipFile(path) as archive:
        local = archive.getinfo('META-INF/manifest.xml').header_offset
        central = archive.start_dir
    data = bytearray(path.read_bytes())
    entry = data.index(b'META-INF/manifest.xml', central) - 46
    struct.pack_into('<L', data, local + 22, 100)
    struct.pack_into('<L', data, entry + 24, 100)
    path.write_bytes(data)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['reason'] == 'ODF_DEFLATE_LIMIT_OR_TRUNCATION'


def test_utf16_dtd_is_rejected_and_depth_is_bounded(tmp_path, monkeypatch):
    xml = '<!DOCTYPE m:manifest [<!ENTITY x "expanded">]>' + manifest().decode()
    row = inventory.inspect_file(package(tmp_path/'dtd.odt', xml=xml.encode('utf-16')))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_XML_DTD_OR_ENTITY_UNSUPPORTED'
    monkeypatch.setattr(odf, 'MAX_XML_DEPTH', 3)
    row = inventory.inspect_file(package(tmp_path/'depth.odt'))
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ODF_XML_STRUCTURE_LIMIT'


def test_document_payload_is_never_targeted_for_reading(tmp_path, monkeypatch):
    path = tmp_path/'large.odt'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('mimetype', odf.MIME_PREFIX + 'text')
        archive.writestr('content.xml', b'x' * 1024 * 1024)
        archive.writestr('META-INF/manifest.xml', manifest(), compress_type=zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(path) as archive:
        start = archive.getinfo('content.xml').header_offset
        end = archive.getinfo('META-INF/manifest.xml').header_offset
    calls = []
    original = inventory.BoundedReader.at
    def recording(reader, offset, count):
        calls.append((offset, count))
        return original(reader, offset, count)
    monkeypatch.setattr(inventory.BoundedReader, 'at', recording)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED'
    # Initial signature/tail probes may include adjacent payload bytes.
    assert all(offset + count <= start or offset >= end for offset, count in calls[2:])
    assert row['bytes_read'] < 70 * 1024


def test_shared_physical_read_limit_applies_to_manifest(tmp_path, monkeypatch):
    path = package(tmp_path/'limit.odt')
    monkeypatch.setattr(inventory, 'MAX_READ_CALLS', 5)
    row = inventory.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'METADATA_READ_LIMIT'


def test_encrypted_names_are_bounded(tmp_path):
    row = inventory.inspect_file(package(tmp_path/'many.odt', xml=manifest(count=60)))
    assert row['encryption'] == 'ENCRYPTED' and row['odf_encrypted_members'] == 60
    assert len(row['odf_encrypted_member_names']) == 50 and row['odf_encrypted_names_truncated']


def test_metadata_with_data_descriptor(tmp_path):
    class Unseekable(io.BytesIO):
        def seek(self, *args):
            raise OSError('unseekable')
    stream = Unseekable()
    package(stream)
    path = tmp_path/'descriptor.odt'
    path.write_bytes(stream.getvalue())
    assert inventory.inspect_file(path)['encryption'] == 'ENCRYPTED'


def test_epub_mimetype_does_not_turn_into_odf(tmp_path):
    path = tmp_path/'book.epub'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('mimetype', 'application/epub+zip')
    row = inventory.inspect_file(path)
    assert row['format'] == 'ZIP' and row['encryption'] == 'NO_ENCRYPTION_INDICATOR'


def test_resume_rechecks_old_zip_results_and_exposes_odf_in_encrypted_filter(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'report'
    source.mkdir()
    package(source/'renamed.bin')
    (source/'plain.rtf').write_bytes(br'{\rtf1 plain}')
    runner.inventory(source, output)
    with sqlite3.connect(output/'inventory.sqlite') as db:
        db.execute("UPDATE metadata SET value='3' WHERE key='zip_inventory_revision'")
        db.execute("UPDATE files SET result=json_set(result, '$.format', 'ZIP', "
                   "'$.encryption', 'NO_ENCRYPTION_INDICATOR') WHERE path='renamed.bin'")
    original = runner.inspect_file
    inspected = []
    def recording(path):
        inspected.append(path.name)
        return original(path)
    monkeypatch.setattr(runner, 'inspect_file', recording)
    second = runner.inventory(source, output, resume=True)
    assert inspected == ['renamed.bin'] and second['run']['reused'] == 1
    rows = read_inventory_page(output/'inventory.sqlite').rows
    assert len(rows) == 1 and rows[0]['format'] == 'ODT'
    assert rows[0]['encryption'] == 'ENCRYPTED'
    third = runner.inventory(source, output, resume=True)
    assert third['run']['inspected'] == 0 and third['run']['bytes_read'] == 0


def test_broken_odf_extension_is_retained_in_report(tmp_path):
    source, output = tmp_path/'source', tmp_path/'report'
    source.mkdir()
    (source/'damaged.ODS').write_bytes(b'broken signature')
    runner.inventory(source, output)
    row = json.loads((output/'inventory.jsonl').read_text())
    assert row['path'] == 'damaged.ODS' and row['encryption'] == 'UNKNOWN'


def test_raw_zip_directory_scope_remains_unchanged(tmp_path):
    path = package(tmp_path/'image-part.bin')
    with path.open('rb') as stream:
        row = {'format': 'ZIP', 'encryption': 'UNKNOWN'}
        inventory._zip_directory(inventory.BoundedReader(stream, path.stat().st_size), row)
    assert row['format'] == 'ZIP' and row['structure'] == 'HEADERS_CHECKED'
