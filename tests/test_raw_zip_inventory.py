import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import tracemalloc
import zipfile

import pytest

from tests.sparse_files import sparse_file

from bfrs.recovery import raw_zip_inventory as module
from tests.test_zip_inventory_recovery import local_entry


def zip_bytes(names=('wallet.dat',), encrypted=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        for name in names:
            archive.writestr(name, b'Synthetic data, not a wallet.')
    data = bytearray(stream.getvalue())
    if encrypted:
        # Metadata-only fixture; independent cryptographic writer tested below.
        for signature, delta in [(b'PK\x03\x04', 6), (b'PK\x01\x02', 8)]:
            struct.pack_into('<H', data, data.index(signature) + delta, 1)
    return bytes(data)


def rows(output, name='zip_hits.jsonl'):
    return [json.loads(line) for line in (output / name).read_text(encoding='utf-8').splitlines()]


def run(tmp_path, data, **kwargs):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(data)
    summary = module.scan_image(source, output, **kwargs)
    return summary, rows(output), source, output


@pytest.mark.parametrize('prefix', [0, 1, 28, 29, 30, 31, 32, 33, 61, 62, 63])
def test_every_signature_crossing_chunk_boundaries_is_found_once(tmp_path, prefix):
    archive = zip_bytes(encrypted=True)
    data = b'x' * prefix + archive + b'y' * 71
    result, hits, source, _ = run(tmp_path, data, chunk_size=31)
    expected = [prefix + archive.index(sig) for sig in (b'PK\x03\x04', b'PK\x01\x02', b'PK\x05\x06')]
    assert sorted(row['offset'] for row in hits) == sorted(expected)
    assert all(row['encryption'] == 'ENCRYPTED' for row in hits)
    assert all(row['priority'] == 4 for row in hits)
    end = next(row for row in hits if row['record_type'] == 'END_DIRECTORY')
    assert end['archive_start_candidate'] == prefix
    assert end['archive_end_candidate'] == prefix + len(archive)
    assert end['archive_origin_status'] == 'FIRST_LOCAL_HEADER_MATCHED'
    assert end['zip_name_hints'][0]['header_offset'] == expected[1]
    assert result['scan_complete'] and result['scanned_prefix_end'] == len(data)
    assert source.read_bytes() == data


@pytest.mark.parametrize('chunk_size', [4, 7, 128, 4096])
def test_multiple_archives_and_no_extension_dependency(tmp_path, chunk_size):
    a, b = zip_bytes(('notes.txt',)), zip_bytes(('ELECTRUM/default_wallet',), encrypted=True)
    result, hits, source, output = run(tmp_path, b'prefix' + a + b'gap' + b, chunk_size=chunk_size)
    assert result['scan_complete'] and len(hits) == 6
    assert len(rows(output, 'zip_priority.jsonl')) == 3
    assert [row['priority'] for row in hits] == sorted([row['priority'] for row in hits], reverse=True)
    source.rename(source.with_suffix('.bin'))
    # An alternate path is deliberately a different checkpoint identity.
    with pytest.raises(ValueError, match='CHECKPOINT_SOURCE'):
        module.scan_image(source.with_suffix('.bin'), output, resume=True)


def test_surviving_local_and_orphan_directory_records_are_preserved(tmp_path):
    archive = zip_bytes(encrypted=True)
    central = archive.index(b'PK\x01\x02')
    end = archive.index(b'PK\x05\x06')
    data = b'junk' + local_entry() + b'junk' + archive[central:end] + b'junk'
    result, hits, _, _ = run(tmp_path, data, chunk_size=32)
    assert result['record_counts'] == {'LOCAL_HEADER': 1, 'CENTRAL_HEADER': 1}
    assert all(row['record_status'] == 'HEADER_ONLY' for row in hits)
    assert all('archive_start_candidate' not in row for row in hits)
    assert all(row['encryption'] == 'ENCRYPTED' for row in hits)


def test_lost_first_header_prevents_confirmed_archive_origin(tmp_path):
    archive = bytearray(zip_bytes())
    archive[:4] = b'gone'
    _, hits, _, _ = run(tmp_path, b'padding' + archive)
    end = next(row for row in hits if row['record_type'] == 'END_DIRECTORY')
    assert end['record_status'] == 'CENTRAL_DIRECTORY_CHECKED'
    assert end['archive_origin_status'] == 'FIRST_LOCAL_HEADER_UNRESOLVED'


def test_mismatched_local_name_does_not_confirm_link(tmp_path):
    archive = bytearray(zip_bytes())
    archive[30] = ord('X')
    _, hits, _, _ = run(tmp_path, archive)
    end = next(row for row in hits if row['record_type'] == 'END_DIRECTORY')
    assert end['archive_origin_status'] == 'FIRST_LOCAL_HEADER_MISMATCH'


@pytest.mark.parametrize('data', [b'', b'plain data', b'PK\x03\x04broken',
    local_entry(version=0), local_entry(method=65535), local_entry(name=b'a\0b'),
    local_entry(name=b'\xff', flags=0x800), local_entry(extra=b'\x00'),
    local_entry(extra=struct.pack('<HH', 7, 100)), local_entry()[:35]])
def test_noise_and_incomplete_metadata_do_not_become_positive_records(tmp_path, data):
    result, hits, _, _ = run(tmp_path, data)
    assert result['scan_complete']
    assert hits == []
    assert result['signature_counts']['rejected_signatures'] == result['signature_counts']['signatures_seen']


def test_unsupported_headers_are_unknown_not_unencrypted(tmp_path):
    data = local_entry(packed=0xffffffff) + b'junk' + local_entry(method=99)
    result, hits, _, _ = run(tmp_path, data)
    assert len(hits) == 2
    assert all(row['encryption'] == 'UNKNOWN' and row['record_status'] == 'UNSUPPORTED_LAYOUT' for row in hits)
    assert result['unresolved_record_count'] == 2


def test_truncated_data_keeps_header_evidence_without_claiming_recovery(tmp_path):
    _, hits, _, _ = run(tmp_path, local_entry(payload=b'', packed=1000))
    assert len(hits) == 1 and hits[0]['encryption'] == 'ENCRYPTED'
    assert not hits[0]['declared_data_fits_image']
    assert hits[0]['scope'] == 'PHYSICAL_METADATA_CANDIDATE_NOT_RECOVERED_WALLET'


def test_raw_scan_finds_embedded_headers_but_does_not_assert_file_ownership(tmp_path):
    data = zip_bytes(('outer.txt',)) + b'padding' + local_entry()
    _, hits, _, _ = run(tmp_path, data)
    inner = next(row for row in hits if row.get('member_name') == 'wallet.dat')
    assert inner['record_status'] == 'HEADER_ONLY'
    assert 'archive_start_candidate' not in inner


def test_interrupt_mid_chunk_rolls_back_hits_and_progress_together(tmp_path, monkeypatch):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    original = module.inspect_record
    calls = 0

    def interrupt(*args):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        return original(*args)

    monkeypatch.setattr(module, 'inspect_record', interrupt)
    result = module.scan_image(source, output)
    assert result['stop_reason'] == 'INTERRUPTED' and not result['scan_complete']
    assert result['scanned_prefix_end'] == 0 and rows(output) == []
    monkeypatch.setattr(module, 'inspect_record', original)
    result = module.scan_image(source, output, resume=True, chunk_size=7)
    assert result['scan_complete'] and len(rows(output)) == 3
    assert result['signature_counts']['signatures_seen'] == 3


def test_candidate_limit_resumes_at_first_unprocessed_signature(tmp_path):
    data = zip_bytes() + b'gap' + zip_bytes(('backup.txt',))
    result, _, source, output = run(tmp_path, data, max_candidates=1)
    assert result['stop_reason'] == 'CANDIDATE_LIMIT' and not result['scan_complete']
    previous = 0
    while not result['scan_complete']:
        assert result['scanned_prefix_end'] > previous
        previous = result['scanned_prefix_end']
        result = module.scan_image(source, output, resume=True, max_candidates=1, chunk_size=17)
    assert len(rows(output)) == result['signature_counts']['signatures_seen'] == 6
    clean_output = tmp_path / 'clean'
    clean = module.scan_image(source, clean_output)
    assert rows(output) == rows(clean_output)
    assert result['signature_counts'] == clean['signature_counts']


def test_stop_after_committed_chunk_does_not_reread_completed_prefix(tmp_path, monkeypatch):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes() + b'x' * 100)
    stopped = False

    def progress(_):
        nonlocal stopped
        stopped = True

    first = module.scan_image(source, output, chunk_size=64, should_stop=lambda: stopped, progress=progress)
    assert first['scanned_prefix_end'] == 64 and first['stop_reason'] == 'STOP_REQUESTED'
    original = module.inspect_record
    offsets = []

    def record(reader, offset, signature):
        offsets.append(offset)
        return original(reader, offset, signature)

    monkeypatch.setattr(module, 'inspect_record', record)
    second = module.scan_image(source, output, resume=True, chunk_size=32)
    assert second['scan_complete'] and all(offset >= 64 for offset in offsets)
    assert second['io_this_run']['linear_read_bytes'] < source.stat().st_size
    third = module.scan_image(source, output, resume=True)
    assert third['io_this_run']['linear_read_bytes'] == third['io_this_run']['metadata_read_bytes'] == 0
    assert third['io_this_run']['identity_read_bytes'] > 0


def test_read_failure_does_not_advance_past_unread_data(tmp_path, monkeypatch):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    original = module._ImageView.read

    def fail(*args):
        raise OSError('SIMULATED_READ_FAILURE')

    monkeypatch.setattr(module._ImageView, 'read', fail)
    result = module.scan_image(source, output)
    assert not result['scan_complete'] and result['scanned_prefix_end'] == 0
    assert result['stop_reason'] == 'SIMULATED_READ_FAILURE'
    monkeypatch.setattr(module._ImageView, 'read', original)
    assert module.scan_image(source, output, resume=True)['scan_complete']


def test_source_change_stops_scan_and_refuses_stale_resume(tmp_path):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes() + b'x' * 100)
    changed = False

    def progress(_):
        nonlocal changed
        if not changed:
            changed = True
            info = source.stat()
            with source.open('r+b') as stream:
                stream.seek(-1, 2)
                stream.write(b'y')
            os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns + 10_000_000))

    result = module.scan_image(source, output, chunk_size=64, progress=progress)
    assert not result['scan_complete'] and not result['source_unchanged']
    assert result['scanned_prefix_end'] == 64
    with pytest.raises(ValueError, match='CHECKPOINT_SOURCE'):
        module.scan_image(source, output, resume=True)


def test_sample_hash_detects_changes_even_if_stat_identity_is_mocked_unchanged(tmp_path, monkeypatch):
    result, _, source, output = run(tmp_path, b'x' * 200000)
    old_key = result['source']['stat']
    with source.open('r+b') as stream:
        stream.seek(100000)
        stream.write(b'y')
    monkeypatch.setattr(module, '_stat_key', lambda _: old_key)
    with pytest.raises(ValueError, match='CHECKPOINT_SOURCE'):
        module.scan_image(source, output, resume=True)


def test_header_validation_budget_is_reported_without_losing_scan_coverage(tmp_path, monkeypatch):
    from bfrs.recovery import container_inventory
    monkeypatch.setattr(container_inventory, 'MAX_READ_BYTES', 150)
    result, hits, _, _ = run(tmp_path, zip_bytes(('notes.txt', 'wallet.dat')))
    assert result['scan_complete']
    end = next(row for row in hits if row['record_type'] == 'END_DIRECTORY')
    assert end['record_status'] == 'DIRECTORY_UNRESOLVED'
    assert end['reason'] == 'METADATA_READ_LIMIT'


def test_parallel_writer_lock_and_existing_output_protection(tmp_path):
    _, _, source, output = run(tmp_path, zip_bytes())
    with pytest.raises(ValueError, match='OUTPUT_EXISTS'):
        module.scan_image(source, output)
    with module._lock(output):
        with pytest.raises(ValueError, match='ALREADY_RUNNING'):
            module.scan_image(source, output, resume=True)


@pytest.mark.parametrize('part', ['source', 'output', 'checkpoint', 'lock'])
def test_links_are_not_followed(tmp_path, part):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    module.scan_image(source, output)
    target = {'source': source, 'output': output,
              'checkpoint': output / 'zip_scan.sqlite', 'lock': output / '.zip_scan.lock'}[part]
    actual = target.with_name(target.name + '.actual')
    target.rename(actual)
    try:
        target.symlink_to(actual, target_is_directory=part == 'output')
    except OSError:
        pytest.skip('symlinks unavailable')
    with pytest.raises((ValueError, OSError)):
        module.scan_image(source, output, resume=True)


@pytest.mark.parametrize('value', [-1, 10**12, True, '100'])
def test_corrupt_checkpoint_offsets_are_rejected(tmp_path, value):
    _, _, source, output = run(tmp_path, zip_bytes())
    with sqlite3.connect(output / 'zip_scan.sqlite') as db:
        db.execute("UPDATE metadata SET value=? WHERE key='next_offset'", (json.dumps(value),))
    with pytest.raises(ValueError, match='CHECKPOINT'):
        module.scan_image(source, output, resume=True)


def test_true_zipcrypto_inside_image(tmp_path):
    writer = shutil.which('zip')
    if not writer:
        pytest.skip('Info-ZIP writer unavailable')
    content = b'Only synthetic test content.\n' * 100
    (tmp_path / 'wallet-example.txt').write_bytes(content)
    path = tmp_path / 'archive.zip'
    subprocess.run([writer, '-q', '-P', 'synthetic-test-password', str(path), 'wallet-example.txt'],
                   cwd=tmp_path, check=True, capture_output=True, timeout=10)
    with zipfile.ZipFile(path) as archive:
        assert archive.read('wallet-example.txt', pwd=b'synthetic-test-password') == content
    result, hits, _, _ = run(tmp_path, b'x' * 4095 + path.read_bytes() + b'padding', chunk_size=4096)
    assert result['scan_complete'] and len(hits) == 3
    assert all(row['encryption'] == 'ENCRYPTED' for row in hits)


def test_cli_scan_and_resume(tmp_path):
    import sys
    source = tmp_path / 'disk.bin'
    source.write_bytes(zip_bytes())
    output = tmp_path / 'report'
    script = Path(__file__).resolve().parents[1] / 'scripts/inventory_zip_image.py'
    command = [sys.executable, str(script), '--source', str(source), '--output', str(output)]
    first = subprocess.run(command + ['--max-candidates', '1'], capture_output=True, text=True)
    assert first.returncode == 3, first.stderr
    second = subprocess.run(command + ['--resume'], capture_output=True, text=True)
    assert second.returncode == 0, second.stderr
    assert json.loads((output / 'summary.json').read_text())['scan_complete']


def test_other_encrypted_member_does_not_promote_plain_wallet_name(tmp_path):
    archive = zip_bytes(('ordinary.txt', 'wallet.dat'), encrypted=True)
    _, hits, _, _ = run(tmp_path, archive)
    end = next(row for row in hits if row['record_type'] == 'END_DIRECTORY')
    assert end['encryption'] == 'ENCRYPTED'
    assert end['zip_wallet_name_hint_count'] == 1
    assert end['zip_encrypted_wallet_name_hint_count'] == 0
    assert end['priority'] == 3


def test_member_metadata_limit_is_unresolved_not_a_rejected_signature(tmp_path, monkeypatch):
    from bfrs.recovery import container_inventory
    monkeypatch.setattr(container_inventory, 'MAX_READ_BYTES', 40)
    result, hits, _, _ = run(tmp_path, local_entry(name=b'wallet-' + b'x' * 100))
    assert len(hits) == 1 and hits[0]['record_status'] == 'METADATA_LIMIT'
    assert hits[0]['encryption'] == 'UNKNOWN'
    assert result['signature_counts']['rejected_signatures'] == 0
    assert result['unresolved_record_count'] == 1


def test_large_sparse_source_has_bounded_memory_and_linear_reads(tmp_path):
    source, output = tmp_path / 'disk.img', tmp_path / 'report'
    with sparse_file(source) as stream:
        stream.seek(32 * 1024 * 1024 - 2)
        stream.write(local_entry())
    tracemalloc.start()
    try:
        result = module.scan_image(source, output, chunk_size=1024 * 1024)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result['scan_complete'] and len(rows(output)) == 1
    assert peak < 12 * 1024 * 1024
    assert source.stat().st_size <= result['io_this_run']['linear_read_bytes'] < source.stat().st_size + 200
    assert result['io_this_run']['metadata_read_bytes'] < 200000


def test_physical_offsets_above_four_gib_remain_exact(tmp_path):
    source = tmp_path / 'large.img'
    base = 2**32 + 4095
    archive = zip_bytes()
    with sparse_file(source) as stream:
        stream.seek(base)
        stream.write(archive)
    eocd = base + archive.index(b'PK\x05\x06')
    io_counts = {'metadata_read_bytes': 0}
    with source.open('rb') as stream:
        view = module._ImageView(stream, source.stat().st_size, 0, b'', io_counts)
        row = module.inspect_record(module.BoundedReader(view, view.size), eocd, b'PK\x05\x06')
    assert row['offset'] == eocd and row['archive_start_candidate'] == base
    assert row['first_local_header_offset'] == base
    assert row['zip_name_hints'][0]['header_offset'] > 2**32
    assert io_counts['metadata_read_bytes'] < 200000
