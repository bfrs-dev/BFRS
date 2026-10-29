import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import json
from pathlib import Path
import time

import pytest
pytest.importorskip('PySide6')
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication

from bfrs.gui import raw_zip_panel as module
from bfrs.gui.main_window import MainWindow
from bfrs.gui.settings import GuiSettingsStore
from tests.test_raw_zip_inventory import zip_bytes


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def finish(app, panel):
    deadline = time.monotonic() + 10
    while panel.worker is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.002)
    assert panel.worker is None


def configure(tmp_path, panel):
    source, output = tmp_path / 'image.img', tmp_path / 'report'
    source.write_bytes(zip_bytes(('wallet.dat', 'notes.txt')))
    panel.source_edit.setText(str(source))
    panel.output_edit.setText(str(output))
    return source, output


def test_real_scan_display_resume_and_language(tmp_path, app):
    panel = module.RawZipPanel()
    source, output = configure(tmp_path, panel)
    panel.start_scan()
    assert not panel.start_button.isEnabled()
    finish(app, panel)
    assert 'zakończony' in panel.status.text()
    assert panel.progress_bar.value() == 1000
    assert panel.table.rowCount() == 3
    panel.table.selectRow(0)
    assert 'wallet.dat' in panel.details.toPlainText()
    assert panel.resume_check.isChecked()
    panel.priority_check.setChecked(False)
    finish(app, panel)
    assert panel.table.rowCount() == 5
    panel.set_language('en')
    assert panel.start_button.text() == 'Start scan'
    assert 'Scan complete' in panel.status.text()
    before = (output / 'zip_hits.jsonl').read_bytes()
    panel.start_scan()
    finish(app, panel)
    assert (output / 'zip_hits.jsonl').read_bytes() == before
    assert json.loads((output / 'summary.json').read_text())['scan_complete']
    panel.close()


def test_existing_output_is_not_overwritten_and_errors_are_visible(tmp_path, app):
    panel = module.RawZipPanel('en')
    source, output = configure(tmp_path, panel)
    output.mkdir()
    marker = output / 'keep.txt'
    marker.write_text('keep')
    panel.start_scan()
    finish(app, panel)
    assert 'OUTPUT_EXISTS' in panel.status.text()
    assert marker.read_text() == 'keep'
    assert panel.start_button.isEnabled()
    assert not panel.stop_button.isEnabled()
    panel.close()


def test_main_window_close_requests_cooperative_stop_and_persists_paths(tmp_path, app, monkeypatch):
    real_scan = module.scan_image
    def wait_for_stop(source, output, **kwargs):
        deadline = time.monotonic() + 5
        while not kwargs['should_stop']() and time.monotonic() < deadline:
            time.sleep(.005)
        return real_scan(source, output, **kwargs)
    monkeypatch.setattr(module, 'scan_image', wait_for_stop)
    store = GuiSettingsStore(tmp_path / 'settings.json')
    window = MainWindow(settings_store=store)
    panel = window.raw_zip_panel
    source, output = configure(tmp_path, panel)
    panel.start_scan()
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert panel.worker.stop_requested.is_set()
    finish(app, panel)
    summary = json.loads((output / 'summary.json').read_text())
    assert summary['stop_reason'] == 'STOP_REQUESTED'
    assert not summary['scan_complete']
    assert 'zatrzymany' in panel.status.text()
    assert store.load().raw_zip_source == str(source)
    assert store.load().raw_zip_output == str(output)
    monkeypatch.setattr(module, 'scan_image', real_scan)
    panel.start_scan()
    finish(app, panel)
    assert json.loads((output / 'summary.json').read_text())['scan_complete']
    window.close()
    restored = MainWindow(settings_store=store)
    assert restored.raw_zip_panel.output_edit.text() == str(output)
    assert not restored.raw_zip_panel.resume_check.isChecked()
    restored.close()


def test_open_saved_report_repopulates_resume_paths_without_source(tmp_path, app):
    panel = module.RawZipPanel('en')
    source, output = configure(tmp_path, panel)
    module.scan_image(source, output)
    source.unlink()
    panel.source_edit.clear()
    panel.output_edit.clear()
    panel.open_report(output / 'zip_scan.sqlite')
    finish(app, panel)
    assert panel.source_edit.text() == str(source)
    assert panel.output_edit.text() == str(output)
    assert panel.resume_check.isChecked()
    assert 'Saved results' in panel.status.text()
    assert panel.table.rowCount() == 3
    panel.open_report(tmp_path / 'missing.sqlite')
    finish(app, panel)
    assert panel.table.rowCount() == 0
    assert panel.page is None
    assert 'Error' in panel.status.text()
    panel.close()


def test_progress_speed_excludes_restored_bytes_and_is_throttled(monkeypatch):
    task = module.RawZipTask(lambda task: None)
    values = []
    task.progress.connect(values.append)
    clock = iter((10., 10.01, 11.))
    monkeypatch.setattr(module.time, 'monotonic', lambda: next(clock))
    for scanned in (100 * 1048576, 100 * 1048576 + 100, 102 * 1048576):
        task.report_progress(dict(scanned_bytes=scanned, total_bytes=200 * 1048576))
    assert len(values) == 2
    assert values[-1]['speed_mib'] == 2.0
