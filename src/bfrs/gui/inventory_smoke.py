"""Opt-in frozen-build check, using only a newly created synthetic directory."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
import zipfile


def run_smoke(directory):
    directory = Path(directory).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    outcome = {'frozen': bool(getattr(sys,'frozen',False)),
               'no_console': sys.stdout is None and sys.stderr is None}
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
        modules = (engine,browser,controls,view,seven_zip_inventory,pdf_inventory,ppt_inventory,olefile)
        if getattr(sys,'frozen',False):
            bundle = Path(sys._MEIPASS).resolve()
            assert all(Path(module.__file__).resolve().is_relative_to(bundle) for module in modules)
            outcome['bundled_modules'] = {module.__name__: str(module.__file__) for module in modules}
        application = QApplication.instance() or QApplication([])
        source = directory/'źródło'
        source.mkdir()
        with zipfile.ZipFile(source/'żółty.zip','w') as archive:
            archive.writestr('synthetic.txt','No keys or secrets')
        (source/'zwykły.rtf').write_bytes(br'{\rtf1 synthetic}')
        (source/'uszkodzony.pdf').write_bytes(b'%PDF-1.7\ntruncated')
        window = MainWindow(settings_store=GuiSettingsStore(directory/'prefs.json'))
        window.show()
        outcome['tabs'] = window.tabs.count()
        assert window.tabs.tabText(2) in ('Zaszyfrowane pliki i foldery','Encrypted files and folders')
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
        panel.start_inventory()
        finish()
        assert panel.last_result['complete']
        gui_lines = (directory/'gui/inventory.jsonl').read_text(encoding='utf-8')
        inventory(source,directory/'cli')
        assert gui_lines == (directory/'cli/inventory.jsonl').read_text(encoding='utf-8')
        panel.start_inventory(resume=True)
        finish()
        assert panel.last_result['run']['reused'] >= 2
        assert (directory/'gui/inventory.jsonl').read_text(encoding='utf-8') == gui_lines
        assert ticks, 'Qt timer did not run during background inventory'
        timer.stop()
        outcome.update(ok=True, qt_ticks=len(ticks), records=len(gui_lines.splitlines()),
                       optional_ole_available=True, resume=True, cli_gui_equal=True,
                       executable=sys.executable)
        window.close()
        application.processEvents()
    except Exception as error:
        outcome.update(ok=False,error=f'{type(error).__name__}: {error}')
        # Do not destroy Qt objects with live workers on a failing smoke run.
        if window is not None and window.inventory_panel.worker is not None:
            window.inventory_panel.request_stop()
            window.inventory_panel.worker.wait(60000)
    (directory/'smoke-result.json').write_text(json.dumps(outcome,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if outcome.get('ok') else 1
