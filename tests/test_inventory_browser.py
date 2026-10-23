import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import time
from pathlib import Path
import json
import sqlite3

import pytest
pytest.importorskip('PySide6')
from PySide6.QtWidgets import QApplication
from bfrs.gui import inventory_browser as module
from tests.test_inventory_view import make_report


def finish(app, window):
    deadline = time.monotonic()+10
    while window.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.005)
    assert window.worker is None


def test_browser_default_filter_copy_remap_and_reveal(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    source = tmp_path/'source'
    source.mkdir()
    (source/'żółć.pdf').write_bytes(b'example')
    database = tmp_path/'inventory.sqlite'
    make_report(database, tmp_path/'offline', [('żółć.pdf', 'ENCRYPTED', 2), ('other.xls', 'UNKNOWN', 2)])
    window = module.InventoryBrowser(database)
    finish(app, window)
    assert window.state_combo.currentData() == 'ENCRYPTED'
    assert window.table.rowCount() == 1
    assert not window.reveal_button.isEnabled()
    window.table.selectRow(0)
    assert window.reveal_button.isEnabled()
    assert 'PDF_ENCRYPT_ENTRY' in window.details.toPlainText()
    window.copy_selected()
    assert app.clipboard().text() == str(tmp_path/'offline'/'żółć.pdf')
    window.reveal_selected()
    finish(app, window)
    assert 'Nie udało' in window.message.text()
    window.set_source_root(source)
    window.copy_selected()
    assert app.clipboard().text() == str(source/'żółć.pdf')
    calls = []
    if os.name == 'nt':
        monkeypatch.setattr(module, 'reveal_in_explorer', lambda path: calls.append(path))
    else:
        monkeypatch.setattr(module.QDesktopServices, 'openUrl',
                            lambda url: calls.append(Path(url.toLocalFile())) or True)
    window.reveal_selected()
    finish(app, window)
    assert calls == [source/'żółć.pdf' if os.name == 'nt' else source]
    window.state_combo.setCurrentIndex(1)
    finish(app, window)
    assert window.table.rowCount() == 1 and window.table.item(0, 0).text() == 'other.xls'
    assert not window.reveal_button.isEnabled()
    window.search_edit.setText('absent')
    window.load_page(0)
    finish(app, window)
    assert window.table.rowCount() == 0
    assert 'Brak wyników' in window.message.text()
    window.close()


@pytest.mark.parametrize('relative', ['.', 'empty'])
def test_browser_efs_directory_copy_explanation_and_reveal(tmp_path, monkeypatch, relative):
    app = QApplication.instance() or QApplication([])
    source = tmp_path/'source'
    source.mkdir()
    (source/'empty').mkdir()
    target = source if relative == '.' else source/'empty'
    database = tmp_path/'inventory.sqlite'
    make_report(database, source, [(relative, 'ENCRYPTED', 2)])
    row = dict(path=relative, format='WINDOWS_EFS', encryption='ENCRYPTED', size=None,
               entry_kind='directory', filesystem_encryption='EFS',
               reason='WINDOWS_EFS_DIRECTORY_DEFAULT', scan_error='PermissionError')
    with sqlite3.connect(database) as db:
        db.execute('UPDATE files SET result=?', (json.dumps(row),))
    window = module.InventoryBrowser(database)
    finish(app, window)
    assert window.table.item(0, 1).text() == 'Folder EFS'
    assert window.table.item(0, 2).text() == '—'
    assert window.table.item(0, 0).text() == ('(folder źródłowy)' if relative == '.' else 'empty')
    window.table.selectRow(0)
    assert 'Nie potwierdza szyfrowania wszystkich' in window.details.toPlainText()
    assert 'PermissionError' in window.details.toPlainText()
    window.copy_selected()
    assert app.clipboard().text() == str(target)
    calls = []
    if os.name == 'nt':
        monkeypatch.setattr(module, 'reveal_in_explorer', lambda path: calls.append(path))
    else:
        monkeypatch.setattr(module.QDesktopServices, 'openUrl',
                            lambda url: calls.append(Path(url.toLocalFile())) or True)
    window.reveal_selected()
    finish(app, window)
    assert calls == [target]
    window.close()
