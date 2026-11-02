import io
import json
import sqlite3
import struct
import subprocess
import sys
from contextlib import closing

import pytest

from bfrs.application.raw_zip_view import read_raw_efs_page, read_raw_zip_page
from bfrs.recovery.container_inventory import BoundedReader
from bfrs.recovery import raw_efs_inventory as efs
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError
from tests.ntfs_efs_fixtures import filename, nonresident, record, resident, standard


def rows(output):
    return [json.loads(line) for line in (output / 'efs_hits.jsonl').read_text(encoding='utf-8').splitlines()]


@pytest.mark.parametrize('size,stride', [(512, 512), (1024, 512), (4096, 512), (4096, 4096), (65536, 512)])
def test_directory_defaults_do_not_assert_children_are_encrypted(size, stride):
    row = efs.parse_record(record(size=size, stride=stride))
    assert row['record_status'] == 'DIRECTORY_ENCRYPTION_DEFAULT'
    assert row['encryption'] == 'ENCRYPTION_DEFAULT'
    assert row['display_name'] == 'żółty portfel'
    assert row['current_allocation'] == 'UNKNOWN' and row['path_status'] == 'UNRESOLVED'
    assert row['fixup_stride'] == stride


@pytest.mark.parametrize('stream', [resident(0x100, b'synthetic metadata', '$EFS'), nonresident(0x100, '$EFS')])
def test_file_with_efs_stream_and_flag_has_corroborating_metadata(stream):
    row = efs.parse_record(record(standard(), filename('wallet.dat'), stream,
                                  nonresident(flags=0x4000), directory=False))
    assert row['record_status'] == 'EFS_METADATA_AND_ENCRYPTED_FLAG'
    assert row['priority'] == 4
    assert row['efs_stream_headers'][0]['payload_validated'] is False
    assert 'synthetic metadata' not in json.dumps(row)


@pytest.mark.parametrize('attributes,status', [
    ((standard(), filename()), 'ENCRYPTED_FLAG_ONLY'),
    ((standard(0), filename(), nonresident(flags=0x4000)), 'ENCRYPTED_FLAG_ONLY'),
    ((standard(0), filename(), resident(0x100, b'efs', '$EFS')), 'EFS_STREAM_ONLY'),
    ((standard(0), filename(flags=0x4000)), 'FILE_NAME_FLAG_ONLY'),
])
def test_separate_evidence_levels(attributes, status):
    assert efs.parse_record(record(*attributes, directory=False))['record_status'] == status


@pytest.mark.parametrize('extra', [resident(0x100, b'$EFS', '$TXF_DATA'),
                                  resident(0x80, b'FILE $EFS encrypted 0x4000', '$EFS'),
                                  resident(0x80, b'\x00\x40\x00\x00')])
def test_strings_txfs_and_data_stream_name_are_not_efs(extra):
    assert efs.parse_record(record(standard(0), filename(), extra, directory=False)) is None


def test_deleted_and_extension_records_are_not_reported_as_current_files():
    row = efs.parse_record(record(active=False))
    assert row['record_in_use_flag'] is False and row['current_allocation'] == 'UNKNOWN'
    row = efs.parse_record(record(nonresident(flags=0x4000), directory=False, base=(7 << 48) | 123))
    assert row['record_type'] == 'EXTENSION_RECORD'
    assert row['base_reference'] == {'record': 123, 'sequence': 7}
    assert row['display_name'] == ''


def test_both_filename_namespaces_and_parent_sequences_are_preserved():
    row = efs.parse_record(record(standard(), filename('PORTFE~1', namespace=2, parent=77, sequence=9),
                                 filename('portfel-żółty', parent=77, sequence=9)))
    assert row['display_name'] == 'portfel-żółty'
    assert len(row['file_names']) == 2
    assert row['file_names'][0]['parent'] == {'record': 77, 'sequence': 9}


@pytest.mark.parametrize('position,value,width', [
    (4, 8, 2), (4, 49, 2), (6, 0, 2), (6, 4, 2), (16, 0, 2), (20, 48, 2),
    (22, 0x40, 2), (24, 1025, 4), (28, 1000, 4), (510, 0, 2), (1022, 0, 2),
    (56 + 4, 0, 4), (56 + 8, 2, 1), (56 + 20, 8, 2),
])
def test_corrupt_records_are_rejected(position, value, width):
    raw = bytearray(record())
    raw[position:position + width] = value.to_bytes(width, 'little')
    with pytest.raises((NtfsMftRecordError, UnicodeDecodeError)):
        efs.parse_record(bytes(raw))
    assert efs.inspect_record(BoundedReader(io.BytesIO(raw), len(raw)), 0, b'FILE') is None


def test_late_invalid_attribute_invalidates_earlier_encryption_flag():
    bad = bytearray(nonresident(flags=0x4000))
    bad[64:68] = b'\x91\x01\x01\x00'
    with pytest.raises(NtfsMftRecordError):
        efs.parse_record(record(standard(), filename(), bytes(bad)))


@pytest.mark.parametrize('chunk', [4, 7, 511, 1024, 4096])
def test_boundaries_resume_duplicate_records_and_readonly_source(tmp_path, chunk):
    source, output = tmp_path / 'image.bin', tmp_path / 'report'
    content = b'xxF' + record() + b'FILE junk' + record(active=False) + b'FILE'
    source.write_bytes(content)
    original = source.stat().st_mtime_ns
    partial = efs.scan_image(source, output, chunk_size=chunk, max_candidates=1)
    assert not partial['scan_complete'] and partial['stop_reason'] == 'CANDIDATE_LIMIT'
    summary = efs.scan_image(source, output, chunk_size=chunk, resume=True)
    assert summary['scan_complete']
    assert [r['offset'] for r in rows(output)] == [3, 3 + 1024 + 9]
    assert summary['candidate_record_count'] == 2
    assert source.read_bytes() == content and source.stat().st_mtime_ns == original
    before = (output / 'efs_hits.jsonl').read_bytes()
    completed = efs.scan_image(source, output, resume=True)
    assert completed['io_this_run']['linear_read_bytes'] == 0
    assert (output / 'efs_hits.jsonl').read_bytes() == before
    assert len(read_raw_efs_page(output / efs.DATABASE).rows) == 2
    with pytest.raises(ValueError):
        read_raw_zip_page(output / efs.DATABASE)


def test_stop_resume_source_mismatch_and_database_closes(tmp_path):
    source, output = tmp_path / 'image', tmp_path / 'report'
    source.write_bytes(record())
    result = efs.scan_image(source, output, should_stop=lambda: True)
    assert result['stop_reason'] == 'STOP_REQUESTED' and result['scanned_prefix_end'] == 0
    efs.scan_image(source, output, resume=True)
    db = output / efs.DATABASE
    db.rename(output / 'moved.sqlite')
    (output / 'moved.sqlite').rename(db)
    source.write_bytes(record(active=False))
    with pytest.raises(ValueError, match='SOURCE_OR_VERSION_MISMATCH'):
        efs.scan_image(source, output, resume=True)


def test_candidate_read_limit_and_truncated_input():
    for content in (b'FILE', record()[:-1], b'FILE' + b'\xff' * 44):
        reader = BoundedReader(io.BytesIO(content), len(content))
        assert efs.inspect_record(reader, 0, b'FILE') is None
        assert reader.bytes_read <= 48
    data = record(size=65536)
    reader = BoundedReader(io.BytesIO(data), len(data))
    assert efs.inspect_record(reader, 0, b'FILE')
    assert reader.bytes_read == 65536 + 48 and reader.calls == 2


def test_no_wallet_claim_for_plain_name_and_wallet_filter(tmp_path):
    source, output = tmp_path / 'image', tmp_path / 'out'
    source.write_bytes(record(standard(), filename('dokumenty')) + record())
    efs.scan_image(source, output)
    assert len(read_raw_efs_page(output / efs.DATABASE).rows) == 2
    assert len(read_raw_efs_page(output / efs.DATABASE, priority_only=True).rows) == 1


def test_invalid_report_row_is_rejected(tmp_path):
    source, output = tmp_path / 'image', tmp_path / 'out'
    source.write_bytes(record())
    efs.scan_image(source, output)
    with closing(sqlite3.connect(output / efs.DATABASE)) as connection:
        row = rows(output)[0]
        row['encryption'] = 'DECRYPTED_WALLET'
        connection.execute('UPDATE hits SET result=?', (json.dumps(row),))
        connection.commit()
    with pytest.raises(ValueError, match='INVALID_RAW_EFS_RECORD'):
        read_raw_efs_page(output / efs.DATABASE)


def test_cli_runs_without_windows_or_mounted_volume(tmp_path):
    source, output = tmp_path / 'image.dd', tmp_path / 'report'
    source.write_bytes(record())
    process = subprocess.run([sys.executable, 'scripts/inventory_efs_image.py', '--source', str(source),
                              '--output', str(output)], capture_output=True, text=True)
    assert process.returncode == 0, process.stderr
    assert rows(output)[0]['record_type'] == 'DIRECTORY_RECORD'


def test_many_long_names_keep_report_bounded_and_mark_truncation():
    attributes = [standard()] + [filename('x' * 250 + str(n)) for n in range(90)]
    row = efs.parse_record(record(*attributes, size=65536))
    assert row['report_details_truncated']
    assert len(row['display_name']) == 4096
    assert len(json.dumps(row)) < 256 * 1024
