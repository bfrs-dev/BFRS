import ctypes
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from bfrs.application.inventory_view import (
    PAGE_SIZE, checked_source_path, read_inventory_page, source_path,
)
from bfrs.gui.windows_reveal import _reveal


def make_report(database, source, entries, run_id=2):
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO metadata VALUES (?,?)',
                       [('version', '1'), ('source', str(source)), ('run_id', str(run_id))])
        # Original schema as well as current checkpoints are supported.
        db.execute('CREATE TABLE files (path TEXT PRIMARY KEY,identity TEXT,result TEXT,run_id INTEGER)')
        for path, state, run in entries:
            row = dict(path=path, format='PDF', encryption=state, size=100,
                       reason='PDF_ENCRYPT_ENTRY' if state == 'ENCRYPTED' else None)
            db.execute('INSERT INTO files VALUES (?,NULL,?,?)',
                       (path, json.dumps(row) if state else None, run))


def test_paging_current_run_filters_and_read_only(tmp_path, monkeypatch):
    database = tmp_path/'inventory.sqlite'
    entries = [(f'folder/{n:04}.pdf', 'ENCRYPTED', 2) for n in range(PAGE_SIZE+3)]
    entries += [('ŻÓŁĆ, 100%_.pdf', 'UNKNOWN', 2), ('plain.pdf', 'NO_ENCRYPTION_INDICATOR', 2),
                ('old.pdf', 'ENCRYPTED', 1), ('ordinary.bin', None, 2)]
    make_report(database, tmp_path/'offline', entries)
    before = hashlib.sha256(database.read_bytes()).digest()
    with monkeypatch.context() as m:
        def forbidden(*args, **kwargs):
            raise AssertionError('Browsing must not stat source files')
        m.setattr(Path, 'stat', forbidden)
        m.setattr(Path, 'lstat', forbidden)
        first = read_inventory_page(database)
        second = read_inventory_page(database, offset=PAGE_SIZE)
        unknown = read_inventory_page(database, 'UNKNOWN', 'żółć, 100%_')
        all_rows = read_inventory_page(database, None, 'plain')
    assert first.counts == {'ENCRYPTED': PAGE_SIZE+3, 'UNKNOWN': 1, 'NO_ENCRYPTION_INDICATOR': 1}
    assert len(first.rows) == PAGE_SIZE and first.has_next
    assert len(second.rows) == 3 and not second.has_next
    assert not {r['path'] for r in first.rows} & {r['path'] for r in second.rows}
    assert len(unknown.rows) == 1 and len(all_rows.rows) == 1
    assert hashlib.sha256(database.read_bytes()).digest() == before


def test_missing_and_malformed_reports(tmp_path):
    missing = tmp_path/'missing.sqlite'
    with pytest.raises(sqlite3.OperationalError):
        read_inventory_page(missing)
    assert not missing.exists()
    database = tmp_path/'invalid.sqlite'
    make_report(database, tmp_path, [('x.pdf', 'ENCRYPTED', 2)])
    with sqlite3.connect(database) as db:
        db.execute("UPDATE files SET result='{}'")
    with pytest.raises(ValueError):
        read_inventory_page(database, None)


@pytest.mark.parametrize('relative', ['../secret', 'a/../../secret', '/absolute', r'C:\secret',
    r'C:relative', r'\\server\share\x', r'\rooted', 'a:stream', 'x\x00y', 'x/./y', 'x./y'])
def test_report_paths_cannot_escape_source(tmp_path, relative):
    with pytest.raises(ValueError):
        source_path(tmp_path, relative)


def test_remap_missing_paths_and_links(tmp_path):
    root = tmp_path/'new root'
    root.mkdir()
    file = root/'polskie żółć, [x] & test.pdf'
    file.write_bytes(b'example')
    assert checked_source_path(root, file.name) == file
    assert source_path(root, r'folder\missing.pdf') == root/'folder'/'missing.pdf'
    with pytest.raises(FileNotFoundError):
        checked_source_path(root, 'missing.pdf')
    with pytest.raises(ValueError):
        checked_source_path(root, '.')
    link = root/'linked.pdf'
    try:
        link.symlink_to(file)
    except OSError:
        pytest.skip('symlinks unavailable')
    with pytest.raises(ValueError):
        checked_source_path(root, link.name)
    directory_link = tmp_path/'linked root'
    directory_link.symlink_to(root, target_is_directory=True)
    with pytest.raises(ValueError):
        checked_source_path(directory_link, file.name)


def test_folder_and_scan_root_reveal_require_explicit_directory_kind(tmp_path):
    folder = tmp_path/'folder'
    folder.mkdir()
    file = tmp_path/'file'
    file.write_bytes(b'example')
    assert checked_source_path(tmp_path, 'folder', directory=True) == folder
    assert checked_source_path(tmp_path, '.', directory=True) == tmp_path
    with pytest.raises(ValueError):
        checked_source_path(tmp_path, 'folder')
    with pytest.raises(ValueError):
        checked_source_path(tmp_path, 'file', directory=True)
    for name in ('..', '../outside', 'folder/../file', '/absolute'):
        with pytest.raises(ValueError):
            source_path(tmp_path, name, directory=True)


def test_directory_reveal_rejects_reparse_points(tmp_path, monkeypatch):
    real_lstat = Path.lstat
    folder = tmp_path/'folder'
    folder.mkdir()
    def fake_lstat(path):
        info = real_lstat(path)
        return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x4400 if path == folder else 0)
    monkeypatch.setattr(Path, 'lstat', fake_lstat)
    with pytest.raises(ValueError, match='ponownej analizy'):
        checked_source_path(tmp_path, 'folder', directory=True)


class FakeCall:
    def __init__(self, implementation):
        self.implementation = implementation
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        return self.implementation(*args)


@pytest.mark.parametrize('parse_code,show_code,init_code', [(0, 0, 0), (-1, 0, 0),
    (0, -1, 0), (0, 0, -2147417850)])
def test_windows_reveal_passes_literal_path_and_releases_resources(parse_code, show_code, init_code):
    def parse(name, bind, output, flags, attributes):
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 123
        return parse_code
    shell = SimpleNamespace(SHParseDisplayName=FakeCall(parse),
                            SHOpenFolderAndSelectItems=FakeCall(lambda *args: show_code))
    com = SimpleNamespace(CoInitializeEx=FakeCall(lambda *args: init_code),
                          CoTaskMemFree=FakeCall(lambda *args: None),
                          CoUninitialize=FakeCall(lambda: None))
    path = r'C:\źródło\plik, [x] & $(test).pdf'
    if parse_code < 0 or show_code < 0:
        with pytest.raises(OSError):
            _reveal(path, shell, com)
    else:
        _reveal(path, shell, com)
    assert shell.SHParseDisplayName.calls[0][0] == path
    assert len(com.CoTaskMemFree.calls) == 1
    assert len(com.CoUninitialize.calls) == (1 if init_code >= 0 else 0)
    if parse_code == 0:
        assert shell.SHOpenFolderAndSelectItems.calls[0][1:] == (0, None, 0)
    else:
        assert not shell.SHOpenFolderAndSelectItems.calls
