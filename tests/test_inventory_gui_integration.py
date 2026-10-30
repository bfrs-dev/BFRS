"""Cross-tab shutdown and rejection of an outdated frozen installer payload."""
import json
import os
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
pytest.importorskip('PySide6')

from bfrs.application import document_inventory
from bfrs.gui import raw_zip_panel
from bfrs.gui.main_window import MainWindow
from bfrs.gui.settings import GuiSettingsStore
from scripts import verify_frozen_inventory
from tests.test_encrypted_inventory_gui import app, wait
from tests.test_raw_zip_inventory import zip_bytes


def test_close_waits_for_both_inventory_workers_and_readers(tmp_path, app, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'notes.rtf').write_bytes(br'{\rtf1 synthetic}')
    image = tmp_path / 'image.img'
    image.write_bytes(zip_bytes())
    folder_entered, raw_entered, folder_release, raw_release = (Event() for _ in range(4))
    inspect, scan = document_inventory.inspect_file, raw_zip_panel.scan_image

    def held_inspect(path):
        folder_entered.set()
        assert folder_release.wait(10)
        return inspect(path)

    def held_scan(*args, **kwargs):
        raw_entered.set()
        assert raw_release.wait(10)
        return scan(*args, **kwargs)

    monkeypatch.setattr(document_inventory, 'inspect_file', held_inspect)
    monkeypatch.setattr(raw_zip_panel, 'scan_image', held_scan)
    window = MainWindow(settings_store=GuiSettingsStore(tmp_path / 'settings.json'))
    folder, raw = window.inventory_panel, window.raw_zip_panel
    folder.source_edit.setText(str(source))
    folder.output_edit.setText(str(tmp_path / 'folder-report'))
    raw.source_edit.setText(str(image))
    raw.output_edit.setText(str(tmp_path / 'raw-report'))
    window.show()
    try:
        folder.start_inventory()
        raw.start_scan()
        wait(app, lambda: folder_entered.is_set() and raw_entered.is_set())
        window.close()
        assert window.isVisible() and window._closing_requested
        assert folder.worker.stop_event.is_set() and raw.worker.stop_requested.is_set()
        folder_release.set()
        wait(app, lambda: not folder.busy)
        assert window.isVisible() and raw.busy
        raw_release.set()
        wait(app, lambda: not raw.busy and not window.isVisible())
        result = json.loads((tmp_path / 'raw-report/summary.json').read_text(encoding='utf-8'))
        assert result['stop_reason'] == 'STOP_REQUESTED'
        assert (tmp_path / 'folder-report/inventory.jsonl').exists()
    finally:
        folder_release.set()
        raw_release.set()
        folder.request_stop()
        raw.request_stop()
        wait(app, lambda: not folder.busy and not raw.busy)
        window.close()


@pytest.mark.parametrize('outdated', [True, False])
def test_frozen_verifier_requires_both_tabs_to_pass(tmp_path, monkeypatch, outdated):
    def fake_run(command, **kwargs):
        destination = Path(command[-1])
        destination.mkdir()
        outcome = dict(ok=True, frozen=True, no_console=True, cli_gui_equal=True, resume=True,
                       tabs=3 if outdated else 4)
        if not outdated:
            outcome.update(raw_zip_scan=True, raw_zip_resume=True, raw_zip_cli_gui_equal=True)
        (destination / 'smoke-result.json').write_text(json.dumps(outcome), encoding='utf-8')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(verify_frozen_inventory.subprocess, 'run', fake_run)
    if outdated:
        with pytest.raises(RuntimeError, match='Frozen inventory check failed'):
            verify_frozen_inventory.verify(tmp_path / 'BFRS.exe', tmp_path / 'work')
    else:
        assert verify_frozen_inventory.verify(tmp_path / 'BFRS.exe', tmp_path / 'work')['tabs'] == 4
