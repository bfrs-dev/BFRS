"""Opt-in frozen-build check, using only a newly created synthetic directory."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import traceback
import zipfile


def run_smoke(directory):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    outcome = {'frozen': bool(getattr(sys,'frozen',False)),
               'no_console': sys.stdout is None and sys.stderr is None,
               'stage': 'imports'}
    window = None
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from bfrs.gui.main_window import MainWindow
        from bfrs.gui.settings import GuiSettingsStore
        from bfrs.application.document_inventory import inventory
        from bfrs.recovery.container_inventory import inspect_file
        from bfrs.recovery import seven_zip_inventory, pdf_inventory, ppt_inventory
        import olefile
        import bfrs.application.document_inventory as engine
        import bfrs.gui.inventory_browser as browser
        import bfrs.gui.inventory_panel as controls
        import bfrs.application.inventory_view as view
        import bfrs.application.raw_zip_view as raw_view
        import bfrs.gui.raw_zip_panel as raw_controls
        import bfrs.recovery.raw_zip_inventory as raw_engine
        import bfrs.recovery.archive_name_hints as name_hints
        modules = (engine,browser,controls,view,seven_zip_inventory,pdf_inventory,ppt_inventory,olefile,
                   raw_view,raw_controls,raw_engine,name_hints)
        if getattr(sys,'frozen',False):
            bundle = Path(sys._MEIPASS).resolve()
            assert all(Path(module.__file__).resolve().is_relative_to(bundle) for module in modules)
            outcome['bundled_modules'] = {module.__name__: str(module.__file__) for module in modules}
        application = QApplication.instance() or QApplication([])
        source = directory/'źródło'
        source.mkdir()
        with zipfile.ZipFile(source/'żółty.zip','w') as archive:
            archive.writestr('backup/wallet.dat','Synthetic fixture, not a wallet')
        (source/'zwykły.rtf').write_bytes(br'{\rtf1 synthetic}')
        (source/'uszkodzony.pdf').write_bytes(b'%PDF-1.7\ntruncated')
        window = MainWindow(settings_store=GuiSettingsStore(directory/'prefs.json'))
        window.show()
        outcome['tabs'] = window.tabs.count()
        assert outcome['tabs'] == 4
        assert window.tabs.tabText(2) in ('Zaszyfrowane pliki i foldery','Encrypted files and folders')
        assert window.tabs.tabText(3) in ('ZIP w obrazie','ZIP in image')
        panel = window.inventory_panel
        panel.source_edit.setText(str(source))
        panel.output_edit.setText(str(directory/'gui'))
        ticks = []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(1)
        def finish():
            deadline = time.monotonic()+60
            while panel.busy and time.monotonic()<deadline:
                application.processEvents()
                time.sleep(.002)
            assert not panel.busy, 'GUI inventory did not finish'
            assert not panel.last_error, panel.last_error
        outcome['stage'] = 'document_inventory'
        panel.start_inventory()
        finish()
        assert panel.last_result['complete']
        gui_lines = (directory/'gui/inventory.jsonl').read_text(encoding='utf-8')
        inventory(source,directory/'cli')
        assert gui_lines == (directory/'cli/inventory.jsonl').read_text(encoding='utf-8')
        outcome['stage'] = 'document_resume'
        panel.start_inventory(resume=True)
        finish()
        assert panel.last_result['run']['reused'] >= 2
        assert (directory/'gui/inventory.jsonl').read_text(encoding='utf-8') == gui_lines
        panel.browser.state_combo.setCurrentIndex(panel.browser.state_combo.findData('NAME_HINT'))
        finish()
        assert panel.browser.table.rowCount() == 1
        assert panel.browser.table.item(0,6).text()

        image = directory/'synthetic.img'
        image.write_bytes(b'prefix' + (source/'żółty.zip').read_bytes() + b'suffix')
        raw = window.raw_zip_panel
        raw.source_edit.setText(str(image))
        raw.output_edit.setText(str(directory/'raw-gui'))
        def finish_raw():
            deadline = time.monotonic()+60
            while raw.busy and time.monotonic()<deadline:
                application.processEvents()
                time.sleep(.002)
            assert not raw.busy, 'GUI raw ZIP scan did not finish'
            assert raw.page is not None, raw.status.text()
        outcome['stage'] = 'raw_zip_scan'
        raw.start_scan()
        finish_raw()
        assert json.loads((directory/'raw-gui/summary.json').read_text(encoding='utf-8'))['scan_complete']
        assert raw.table.rowCount() == 3
        raw_lines = (directory/'raw-gui/zip_hits.jsonl').read_text(encoding='utf-8')
        raw_engine.scan_image(image,directory/'raw-cli')
        assert raw_lines == (directory/'raw-cli/zip_hits.jsonl').read_text(encoding='utf-8')
        outcome['stage'] = 'raw_zip_resume'
        partial = raw_engine.scan_image(image,directory/'raw-resume',max_candidates=1)
        assert not partial['scan_complete'] and partial['stop_reason'] == 'CANDIDATE_LIMIT'
        raw.output_edit.setText(str(directory/'raw-resume'))
        raw.resume_check.setChecked(True)
        raw.start_scan()
        finish_raw()
        assert json.loads((directory/'raw-resume/summary.json').read_text(encoding='utf-8'))['scan_complete']
        assert raw_lines == (directory/'raw-resume/zip_hits.jsonl').read_text(encoding='utf-8')
        outcome['stage'] = 'language_and_shutdown'
        window._language = 'en'
        window._retranslate_ui()
        assert window.tabs.tabText(3) == 'ZIP in image'
        assert window.inventory_panel.browser.table.horizontalHeaderItem(6).text() == 'Name clues'
        assert ticks, 'Qt timer did not run during background inventory'
        timer.stop()
        outcome.update(ok=True, qt_ticks=len(ticks), records=len(gui_lines.splitlines()),
                       optional_ole_available=True, resume=True, cli_gui_equal=True,
                       raw_zip_scan=True, raw_zip_resume=True, raw_zip_cli_gui_equal=True,
                       executable=sys.executable)
        window.close()
        application.processEvents()
        outcome['stage'] = 'complete'
    except Exception as error:
        outcome.update(ok=False,error=f'{type(error).__name__}: {error}', traceback=traceback.format_exc())
        # Do not destroy Qt objects with live workers on a failing smoke run.
        if window is not None:
            window.inventory_panel.request_stop()
            window.raw_zip_panel.request_stop()
            for worker in (window.inventory_panel.worker, window.inventory_panel.browser.worker,
                           window.raw_zip_panel.worker):
                if worker is not None:
                    worker.wait(60000)
    (directory/'smoke-result.json').write_text(json.dumps(outcome,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if outcome.get('ok') else 1
