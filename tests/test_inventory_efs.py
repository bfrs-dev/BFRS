"""Simulate Windows attributes without requiring a certificate or mutating EFS."""
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from tests.test_container_inventory import runner


def attributes(info, flags):
    return SimpleNamespace(**{name: getattr(info, name) for name in
        ('st_mode', 'st_size', 'st_mtime_ns', 'st_dev', 'st_ino')}, st_file_attributes=flags)


def windows_tree(monkeypatch, flags, denied=()):
    """Real temp tree and stat identities, synthetic attribute bits and denials."""
    real_scandir, real_lstat = runner.os.scandir, Path.lstat

    class Entry:
        def __init__(self, entry):
            self.path, self.entry = entry.path, entry

        def stat(self, *, follow_symlinks):
            assert follow_symlinks is False
            return attributes(self.entry.stat(follow_symlinks=False), flags.get(Path(self.path), 0))

    class Scan:
        def __init__(self, path):
            if Path(path) in denied:
                raise PermissionError('Synthetic enumeration denial')
            self.scan = real_scandir(path)

        def __enter__(self):
            return (Entry(entry) for entry in self.scan)

        def __exit__(self, *args):
            self.scan.close()

    monkeypatch.setattr(runner.os, 'scandir', Scan)
    monkeypatch.setattr(Path, 'lstat', lambda path: attributes(real_lstat(path), flags.get(path, 0)))


def rows(output):
    return [json.loads(line) for line in (output/'inventory.jsonl').read_text().splitlines()]


def forbidden(*args):
    raise AssertionError('EFS detection must not open file content')


def test_efs_root_empty_folder_file_and_plain_child(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    empty, encrypted, plain = source/'empty', source/'renamed.bin', source/'plain.rtf'
    empty.mkdir()
    encrypted.write_bytes(b'content must not be read')
    plain.write_bytes(br'{\rtf1 ordinary}')
    flags = {source: 0x4000, empty: 0x4000, encrypted: 0x4000}
    windows_tree(monkeypatch, flags)
    original = runner.inspect_file
    opened = []

    def inspect(path):
        assert path == plain
        opened.append(path)
        return original(path)

    monkeypatch.setattr(runner, 'inspect_file', inspect)
    result = runner.inventory(source, output)
    found = {row['path']: row for row in rows(output)}
    assert result['complete'] and result['run']['errors_or_skips'] == 0
    assert result['efs_counts'] == {'files': 1, 'directories': 2}
    assert result['filesystem_encryption_check'] == 'WINDOWS_FILE_ATTRIBUTES'
    assert result['run']['metadata_only'] == 3 and opened == [plain]
    assert found['.']['entry_kind'] == 'directory' and found['.']['size'] is None
    assert found['empty']['reason'] == 'WINDOWS_EFS_DIRECTORY_DEFAULT'
    assert found['renamed.bin']['reason'] == 'WINDOWS_EFS_FILE_ATTRIBUTE'
    assert found['renamed.bin']['bytes_read'] == 0
    assert found['plain.rtf']['encryption'] == 'NO_ENCRYPTION_INDICATOR'
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    resumed = runner.inventory(source, output, resume=True)
    assert resumed['run']['reused'] == 4 and resumed['run']['bytes_read'] == 0
    assert resumed['efs_counts'] == result['efs_counts']


def test_resume_checks_efs_on_old_null_and_classified_rows_without_mass_reread(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    files = [source/'unknown.bin', source/'document.rtf', source/'unchanged.bin']
    for path in files:
        path.write_bytes(br'{\rtf1 example}' if path.suffix == '.rtf' else b'ordinary')
    # No EFS identity suffix: exactly the old checkpoint identity representation.
    runner.inventory(source, output)
    with sqlite3.connect(output/'inventory.sqlite') as db:
        assert db.execute('SELECT result FROM files WHERE path=?', ('unknown.bin',)).fetchone()[0] is None
    flags = {files[0]: 0x4000, files[1]: 0x4000}
    windows_tree(monkeypatch, flags)
    original = runner.inspect_file
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    result = runner.inventory(source, output, resume=True)
    assert result['efs_counts'] == {'files': 2, 'directories': 0}
    assert result['run']['reused'] == 1 and result['run']['bytes_read'] == 0
    assert result['run']['metadata_only'] == 2
    # Clearing the flag also invalidates EFS results, despite unchanged size/mtime.
    flags.clear()
    monkeypatch.setattr(runner, 'inspect_file', original)
    result = runner.inventory(source, output, resume=True)
    assert result['efs_counts'] == {'files': 0, 'directories': 0}
    assert result['run']['inspected'] == 2 and result['run']['reused'] == 1
    assert [row['path'] for row in rows(output)] == ['document.rtf']


def test_efs_directory_flag_removed_or_path_deleted_disappears(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    folder = source/'empty'
    folder.mkdir()
    flags = {source: 0x4000, folder: 0x4000}
    windows_tree(monkeypatch, flags)
    runner.inventory(source, output)
    flags.clear()
    folder.rmdir()
    result = runner.inventory(source, output, resume=True)
    assert result['complete'] and rows(output) == []
    assert result['efs_counts'] == {'files': 0, 'directories': 0}


def test_efs_directory_denied_keeps_positive_marker_and_retries(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    folder = source/'denied'
    folder.mkdir()
    denied = {folder}
    windows_tree(monkeypatch, {folder: 0x4000}, denied)
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    first = runner.inventory(source, output)
    assert first['run']['errors_or_skips'] == 1
    assert rows(output)[0]['encryption'] == 'ENCRYPTED'
    assert rows(output)[0]['scan_error'] == 'PermissionError'
    denied.clear()
    second = runner.inventory(source, output, resume=True)
    assert second['run']['reused'] == 0 and second['run']['metadata_only'] == 1
    assert 'scan_error' not in rows(output)[0]


def test_efs_reparse_flag_is_skipped_not_followed(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    folder = source/'junction'
    folder.mkdir()
    (folder/'hidden').write_bytes(b'not visited')
    windows_tree(monkeypatch, {folder: 0x4400}, {folder})
    monkeypatch.setattr(runner, 'inspect_file', forbidden)
    result = runner.inventory(source, output)
    assert result['efs_counts'] == {'files': 0, 'directories': 0}
    assert len(rows(output)) == 1
    assert rows(output)[0]['reason'] == 'LINK_OR_REPARSE_POINT_SKIPPED'


def test_access_denial_without_efs_flag_is_unknown(tmp_path, monkeypatch):
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    folder = source/'denied'
    folder.mkdir()
    windows_tree(monkeypatch, {}, {folder})
    result = runner.inventory(source, output)
    assert result['efs_counts'] == {'files': 0, 'directories': 0}
    assert result['run']['errors_or_skips'] == 1
    assert rows(output)[0]['encryption'] == 'UNKNOWN'
    assert rows(output)[0]['reason'] == 'PermissionError'


def test_depth_limit_preserves_efs_attribute(tmp_path):
    info = attributes(tmp_path.stat(), 0x4000)
    found = list(runner.walk(tmp_path, depth=128, root_info=info))
    assert found == [(tmp_path, info, 'DIRECTORY_DEPTH_LIMIT')]


def test_platform_without_windows_attributes_does_not_claim_efs_checked(tmp_path):
    if hasattr(tmp_path.stat(), 'st_file_attributes'):
        pytest.skip('Non-Windows metadata test')
    source, output = tmp_path/'source', tmp_path/'output'
    source.mkdir()
    result = runner.inventory(source, output)
    assert result['filesystem_encryption_check'] == 'UNAVAILABLE_ON_THIS_PLATFORM'
