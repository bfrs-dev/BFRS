"""Synthetic damaged-ZIP evidence and independent traditional-encryption checks."""
import json
import shutil
import sqlite3
import struct
import subprocess
import zipfile

import pytest

from bfrs.recovery import container_inventory as module
from tests.test_container_inventory import runner, zip_fixture
from tests.test_zip_inventory import make_zip


def local_entry(name=b'wallet.dat', *, flags=1, payload=b'x' * 12,
                packed=None, extra=b'', version=20, method=0):
    """Metadata fixture, not a cryptographically valid encrypted member."""
    size = len(payload) if packed is None else packed
    return (struct.pack('<4s5H3L2H', b'PK\x03\x04', version, flags, method,
                        0, 0, 0, size, 0, len(name), len(extra))
            + name + extra + payload)


@pytest.mark.parametrize('suffix', ['.zip', '.bin'])
def test_missing_directory_keeps_local_password_marker(tmp_path, suffix):
    path = tmp_path / ('recovered' + suffix)
    path.write_bytes(local_entry())
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED'
    assert row['structure'] == 'PARTIAL_LOCAL_HEADER_ONLY'
    assert row['reason'] == 'ZIP_LOCAL_PASSWORD_FLAG'
    assert row['zip_directory_error'] == 'ZIP_END_DIRECTORY_MISSING'
    assert row['zip_local_member_name'] == 'wallet.dat'
    assert row['zip_local_header_offset'] == 0
    assert 'member_count' not in row and 'encrypted_members' not in row


def test_local_scan_skips_payload_and_finds_later_encrypted_member(tmp_path, monkeypatch):
    path = tmp_path / 'recovered.bin'
    payload_size = 100 * 1024 * 1024
    first = local_entry(b'first.txt', flags=0, payload=b'', packed=payload_size)
    second_offset = len(first) + payload_size
    with path.open('wb') as stream:
        stream.write(first)
        stream.seek(second_offset)
        stream.write(local_entry())
    calls = []
    original = module.BoundedReader.at

    def recording(reader, offset, count):
        calls.append((offset, count))
        return original(reader, offset, count)

    monkeypatch.setattr(module.BoundedReader, 'at', recording)
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED'
    assert row['zip_local_header_offset'] == second_offset
    assert row['zip_local_headers_checked'] == 2
    assert row['bytes_read'] < 70 * 1024
    # Initial signature and final-directory probes precede targeted local reads.
    assert all(offset < len(first) or offset >= second_offset for offset, _ in calls[2:])


@pytest.mark.parametrize('data', [
    b'PK\x03\x04broken',
    local_entry(flags=0),
    local_entry(flags=0, payload=local_entry()),  # No payload signature carving.
    local_entry(flags=8, packed=0) + local_entry(),  # Unknown data-descriptor boundary.
    local_entry(name=b''),
    local_entry(name=b'a\x00b'),
    local_entry(extra=b'\x01'),
    local_entry(extra=struct.pack('<HH', 9, 10)),
    local_entry(version=0),
    local_entry(method=99),
    local_entry(flags=0x41),  # Unsupported strong encryption in fallback.
    local_entry(flags=0x2001),  # Masked local fields.
    local_entry(packed=0xffffffff),
    local_entry(extra=struct.pack('<HHQQ', 1, 16, 0, 12)),
    local_entry(payload=b'x', packed=1),  # Cannot hold traditional encryption header.
    local_entry()[:35],  # Incomplete filename.
])
def test_partial_or_unsupported_local_metadata_never_claims_no_encryption(tmp_path, data):
    path = tmp_path / 'damaged.zip'
    path.write_bytes(data)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['bytes_read'] <= module.MAX_READ_BYTES


@pytest.mark.parametrize('descriptor', [False, True])
def test_truncated_ciphertext_can_retain_header_evidence(tmp_path, descriptor):
    path = tmp_path / 'truncated.zip'
    path.write_bytes(local_entry(flags=9 if descriptor else 1, payload=b'',
                                packed=0 if descriptor else 1000))
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED'
    assert row['structure'] == 'PARTIAL_LOCAL_HEADER_ONLY'


def test_local_fallback_obeys_shared_read_budget(tmp_path, monkeypatch):
    path = tmp_path / 'recovered.zip'
    path.write_bytes(local_entry())
    monkeypatch.setattr(module, 'MAX_READ_CALLS', 2)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['zip_local_scan_reason'] == 'METADATA_READ_LIMIT'


def test_local_fallback_stops_at_member_limit(tmp_path, monkeypatch):
    path = tmp_path / 'recovered.zip'
    path.write_bytes(local_entry(flags=0) * 3 + local_entry())
    monkeypatch.setattr(module, 'MAX_MEMBERS', 3)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['zip_local_scan_reason'] == 'ZIP_LOCAL_MEMBER_LIMIT'


def test_fake_end_record_in_comment_cannot_hide_encrypted_directory(tmp_path):
    path = zip_fixture(tmp_path / 'comment.zip', encrypted=True)
    data = bytearray(path.read_bytes())
    # A second, EOF-aligned end record used to classify this as an empty ZIP.
    struct.pack_into('<H', data, len(data) - 2, 22)
    data += struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 0, 0, 0, len(data), 0)
    path.write_bytes(data)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN'
    assert row['reason'] == 'ZIP_AMBIGUOUS_END_DIRECTORY'


@pytest.mark.parametrize('field,width,sentinel', [(20, 'L', 0xffffffff),
    (24, 'L', 0xffffffff), (42, 'L', 0xffffffff), (34, 'H', 0xffff)])
def test_zip64_member_sentinels_are_not_classified_as_classic_zip(tmp_path, field, width, sentinel):
    path = tmp_path / 'zip64.zip'
    data, starts, _ = make_zip(path, 1)
    struct.pack_into('<' + width, data, starts[0] + field, sentinel)
    path.write_bytes(data)
    row = module.inspect_file(path)
    assert row['encryption'] == 'UNKNOWN' and row['reason'] == 'ZIP64_UNSUPPORTED'


def test_old_zip_results_refresh_once_without_rereading_other_formats(tmp_path, monkeypatch):
    source, output = tmp_path / 'source', tmp_path / 'report'
    source.mkdir()
    zip_fixture(source / 'renamed.bin')
    zip_fixture(source / 'office.bin', office=True)
    (source / 'text.rtf').write_bytes(br'{\rtf1 example}')
    (source / 'ordinary.bin').write_bytes(b'ordinary')
    runner.inventory(source, output)
    with sqlite3.connect(output / 'inventory.sqlite') as db:
        db.execute("DELETE FROM metadata WHERE key='zip_inventory_revision'")
    original = runner.inspect_file
    inspected = []

    def recording(path):
        inspected.append(path.name)
        return original(path)

    monkeypatch.setattr(runner, 'inspect_file', recording)
    row = runner.inventory(source, output, resume=True)
    assert set(inspected) == {'renamed.bin', 'office.bin'}
    assert row['run']['reused'] == 2
    inspected.clear()
    row = runner.inventory(source, output, resume=True)
    assert inspected == [] and row['run']['reused'] == 4


def test_real_zipcrypto_archive_and_missing_directory(tmp_path):
    writer = shutil.which('zip')
    if not writer:
        pytest.skip('independent Info-ZIP writer not installed')
    content = b'Synthetic test data only. Not a wallet.\n' * 10
    (tmp_path / 'example.txt').write_bytes(content)
    path = tmp_path / 'encrypted.zip'
    subprocess.run([writer, '-q', '-P', 'synthetic-test-password', str(path), 'example.txt'],
                   cwd=tmp_path, check=True, capture_output=True, timeout=10)
    with zipfile.ZipFile(path) as archive:
        assert archive.read('example.txt', pwd=b'synthetic-test-password') == content
    assert module.inspect_file(path)['encryption'] == 'ENCRYPTED'
    data = path.read_bytes()
    central = data.index(b'PK\x01\x02')
    path.write_bytes(data[:central])
    row = module.inspect_file(path)
    assert row['encryption'] == 'ENCRYPTED'
    assert row['structure'] == 'PARTIAL_LOCAL_HEADER_ONLY'


def test_partial_marker_is_visible_in_default_report_filter(tmp_path):
    from bfrs.application.inventory_view import read_inventory_page
    source, output = tmp_path / 'source', tmp_path / 'report'
    source.mkdir()
    (source / 'recovered.bin').write_bytes(local_entry())
    runner.inventory(source, output)
    rows = read_inventory_page(output / 'inventory.sqlite').rows
    assert len(rows) == 1 and rows[0]['structure'] == 'PARTIAL_LOCAL_HEADER_ONLY'
    assert json.loads((output / 'inventory.jsonl').read_text())['reason'] == 'ZIP_LOCAL_PASSWORD_FLAG'
