"""Windows stat differences and handle lifetimes, reproducible on any host."""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from tests.sparse_files import sparse_file
from tests import sparse_files

from bfrs.application import document_inventory
from bfrs.recovery import raw_zip_inventory as raw
from tests.test_raw_zip_inventory import zip_bytes


def stat_result(**changes):
    values = dict(st_mode=0o100600, st_size=100, st_mtime_ns=200,
                  st_ctime_ns=300, st_dev=4, st_ino=5)
    values.update(changes)
    return SimpleNamespace(**values)


def test_windows_ctime_meanings_differ_but_same_file_is_accepted(monkeypatch):
    opened = stat_result()
    path = SimpleNamespace(lstat=lambda: stat_result(st_ctime_ns=100))
    stream = SimpleNamespace(fileno=lambda: 987)
    monkeypatch.setattr(raw, '_WINDOWS_STAT', True)
    monkeypatch.setattr(raw.os, 'fstat', lambda fd: opened)
    raw._check_source(stream, path, raw._stat_key(opened))
    # Other platforms still require the full metadata comparison.
    monkeypatch.setattr(raw, '_WINDOWS_STAT', False)
    with pytest.raises(raw.SourceChanged):
        raw._check_source(stream, path, raw._stat_key(opened))


@pytest.mark.parametrize('channel,change', [
    ('fd', {'st_ctime_ns': 301}), ('fd', {'st_mtime_ns': 201}),
    ('fd', {'st_size': 101}), ('path', {'st_ino': 6}),
    ('path', {'st_dev': 6}), ('path', {'st_size': 101}),
    ('path', {'st_mtime_ns': 201}), ('path', {'st_mode': 0o120777}),
    ('path', {'st_file_attributes': 0x400}),
])
def test_windows_stat_fix_keeps_change_and_replacement_guards(monkeypatch, channel, change):
    expected = raw._stat_key(stat_result())
    opened = stat_result(**change) if channel == 'fd' else stat_result()
    path_stat = stat_result(st_ctime_ns=100, **change) if channel == 'path' else stat_result(st_ctime_ns=100)
    monkeypatch.setattr(raw, '_WINDOWS_STAT', True)
    monkeypatch.setattr(raw.os, 'fstat', lambda fd: opened)
    with pytest.raises(raw.SourceChanged):
        raw._check_source(SimpleNamespace(fileno=lambda: 987),
                          SimpleNamespace(lstat=lambda: path_stat), expected)


def test_scan_and_resume_with_windows_style_path_ctime(tmp_path, monkeypatch):
    source, output = tmp_path / 'image.img', tmp_path / 'report'
    source.write_bytes(zip_bytes())
    original = Path.lstat

    def windows_lstat(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path != source:
            return info
        fields = {name: getattr(info, name) for name in
                  ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_dev', 'st_ino', 'st_mode')}
        fields['st_ctime_ns'] -= 100_000
        return SimpleNamespace(**fields)

    monkeypatch.setattr(raw, '_WINDOWS_STAT', True)
    monkeypatch.setattr(Path, 'lstat', windows_lstat)
    first = raw.scan_image(source, output, max_candidates=1)
    assert first['stop_reason'] == 'CANDIDATE_LIMIT'
    assert raw.scan_image(source, output, resume=True)['scan_complete']
    assert raw.scan_image(source, output, resume=True)['io_this_run']['linear_read_bytes'] == 0


@pytest.mark.parametrize('kind', ['raw', 'documents'])
@pytest.mark.parametrize('ending', ['complete', 'stop', 'resume-error', 'export-error'])
def test_inventory_closes_database_without_waiting_for_gc(tmp_path, monkeypatch, kind, ending):
    source, output = tmp_path / 'source', tmp_path / 'report'
    module = raw if kind == 'raw' else document_inventory
    operation = raw.scan_image if kind == 'raw' else document_inventory.inventory
    if kind == 'raw':
        source.write_bytes(zip_bytes())
    else:
        source.mkdir()
        (source / 'note.rtf').write_bytes(br'{\rtf1 synthetic}')
    real_connect = sqlite3.connect
    connections = []

    def connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connections.append(connection)  # Keep alive, so GC cannot mask a leak.
        return connection

    monkeypatch.setattr(module.sqlite3, 'connect', connect)
    if ending == 'resume-error':
        operation(source, output)
        database = output / ('zip_scan.sqlite' if kind == 'raw' else 'inventory.sqlite')
        with closing(real_connect(database)) as db, db:
            key, value = ('format', '"wrong"') if kind == 'raw' else ('version', 'wrong')
            db.execute('UPDATE metadata SET value=? WHERE key=?', (value, key))
        with pytest.raises(ValueError):
            operation(source, output, resume=True)
    elif ending == 'export-error':
        def fail(*args, **kwargs):
            raise OSError('synthetic export failure')
        monkeypatch.setattr(module, '_export' if kind == 'raw' else 'export_reports', fail)
        with pytest.raises(OSError, match='synthetic export'):
            operation(source, output)
    else:
        operation(source, output, should_stop=lambda: ending == 'stop')
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match='closed'):
            connection.execute('SELECT 1')
    output.rename(tmp_path / 'renamed-report')


def test_sparse_fixture_keeps_large_offsets_without_dense_allocation(tmp_path):
    path = tmp_path / 'sparse.img'
    with sparse_file(path) as stream:
        stream.seek(2**32 + 7)
        stream.write(b'ZIP')
    info = path.stat()
    assert info.st_size == 2**32 + 10
    if os.name == 'nt':
        assert info.st_file_attributes & 0x200  # FILE_ATTRIBUTE_SPARSE_FILE
    elif hasattr(info, 'st_blocks'):
        assert info.st_blocks * 512 < 1024 * 1024
    with path.open('rb') as stream:
        stream.seek(2**32 + 7)
        assert stream.read(3) == b'ZIP'


def test_unsupported_sparse_setup_never_runs_large_write(tmp_path, monkeypatch):
    streams = []

    def unsupported(stream):
        streams.append(stream)
        raise OSError('synthetic unsupported filesystem')

    monkeypatch.setattr(sparse_files, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(sparse_files, '_mark_windows_sparse', unsupported)
    path = tmp_path / 'fixture.img'
    with pytest.raises(pytest.skip.Exception, match='cannot create a sparse fixture'):
        with sparse_file(path):
            pytest.fail('Must not enter fixture writer without sparse support')
    assert path.stat().st_size == 0
    assert streams and streams[0].closed
