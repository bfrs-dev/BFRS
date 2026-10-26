"""Background controls around the shared metadata engine and InventoryBrowser."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import threading
import time

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog, QProgressBar)

from bfrs.application.document_inventory import inventory, source_from_checkpoint
from bfrs.gui.inventory_browser import InventoryBrowser


class InventoryWorker(QThread):
    progress = Signal(object)
    source_restored = Signal(str)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, source, output, resume=False, parent=None):
        super().__init__(parent)
        self.source, self.output, self.resume = Path(source) if source else None, Path(output), resume
        self.stop_event = threading.Event()

    def run(self):
        last = 0.0
        def update(counts):
            nonlocal last
            now = time.monotonic()
            if now - last >= .1:
                self.progress.emit(dict(counts))
                last = now
        try:
            if self.source is None and self.resume:
                self.source = source_from_checkpoint(self.output / 'inventory.sqlite')
                self.source_restored.emit(str(self.source))
            result = inventory(self.source, self.output, resume=self.resume,
                               progress=update, should_stop=self.stop_event.is_set)
            self.progress.emit(dict(result['run']))
            self.succeeded.emit(result)
        except Exception as error:
            # Includes read/output/SQLite failures and optional-module failures.
            self.failed.emit(f'{type(error).__name__}: {error}')


class InventoryPanel(QWidget):
    idle = Signal()

    def __init__(self, *, language='pl', parent=None):
        super().__init__(parent)
        self.language = language
        self.worker = None
        self._pending_report = None
        self.last_result = None
        self.last_error = None
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.source_label, self.output_label = QLabel(), QLabel()
        self.source_edit, self.output_edit = QLineEdit(), QLineEdit()
        self.source_button, self.output_button = QPushButton(), QPushButton()
        for index, (label, edit, button) in enumerate(((self.source_label,self.source_edit,self.source_button),
                                                      (self.output_label,self.output_edit,self.output_button))):
            grid.addWidget(label,index,0); grid.addWidget(edit,index,1); grid.addWidget(button,index,2)
        layout.addLayout(grid)
        buttons = QHBoxLayout()
        self.start_button, self.stop_button, self.resume_button = QPushButton(), QPushButton(), QPushButton()
        for button in (self.start_button,self.stop_button,self.resume_button):
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0,1)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.dependency_note = QLabel()
        self.dependency_note.setWordWrap(True)
        layout.addWidget(self.dependency_note)
        self.browser = InventoryBrowser()
        self.browser.idle.connect(self._browser_idle)
        layout.addWidget(self.browser,1)
        self.source_button.clicked.connect(self._choose_source)
        self.output_button.clicked.connect(self._choose_output)
        self.start_button.clicked.connect(lambda: self.start_inventory())
        self.resume_button.clicked.connect(self._choose_resume)
        self.stop_button.clicked.connect(lambda: self.request_stop())
        self.set_language(language)
        self._controls()

    @property
    def busy(self):
        return self.worker is not None or self.browser.worker is not None or self._pending_report is not None

    def tr_text(self, pl, en):
        return pl if self.language == 'pl' else en

    def set_language(self, language):
        self.language = language
        self.source_label.setText(self.tr_text('Folder źródłowy','Source folder'))
        self.output_label.setText(self.tr_text('Nowy katalog wyników','New output directory'))
        for button in (self.source_button,self.output_button):
            button.setText(self.tr_text('Wybierz…','Choose…'))
        self.start_button.setText(self.tr_text('Rozpocznij inwentaryzację','Start inventory'))
        self.stop_button.setText(self.tr_text('Zatrzymaj','Stop'))
        self.resume_button.setText(self.tr_text('Wznów z inventory.sqlite…','Resume from inventory.sqlite…'))
        self.output_edit.setPlaceholderText(self.tr_text('Nowa nazwa poza źródłem; wznowienie użyje istniejącego katalogu',
                                                        'New path outside source; resume uses an existing directory'))
        missing = importlib.util.find_spec('olefile') is None
        self.dependency_note.setText(self.tr_text(
            'Brak olefile: analiza OLE/DOC/XLS/PPT może pozostać UNKNOWN. Zainstaluj pakiet inventory.',
            'olefile is missing: OLE/DOC/XLS/PPT analysis may remain UNKNOWN. Install the inventory extra.') if missing else '')
        self.browser.set_language(language)

    def _choose_source(self):
        name = QFileDialog.getExistingDirectory(self,self.tr_text('Folder źródłowy','Source folder'))
        if name:
            self.source_edit.setText(name)

    def _choose_output(self):
        # A save dialog chooses a NEW directory name; no directory is created here.
        name, _ = QFileDialog.getSaveFileName(self,self.tr_text('Nazwa nowego katalogu wyników','New output directory name'))
        if name:
            self.output_edit.setText(name)

    def _choose_resume(self):
        name, _ = QFileDialog.getOpenFileName(self,'inventory.sqlite','','SQLite (*.sqlite)')
        if name:
            self.start_inventory(resume=True, database=Path(name))

    def start_inventory(self, *, resume=False, database=None):
        if self.worker is not None:
            return
        source = self.source_edit.text().strip()
        output = self.output_edit.text().strip()
        if database is not None:
            if Path(database).name != 'inventory.sqlite':
                self.status.setText(self.tr_text('Wybierz inventory.sqlite.','Choose inventory.sqlite.'))
                return
            output = str(Path(database).absolute().parent)
            self.output_edit.setText(output)
        if (not source and not resume) or not output:
            self.status.setText(self.tr_text('Wskaż źródło i katalog wyników.','Choose the source and output directory.'))
            return
        self.last_error = self.last_result = None
        self.worker = InventoryWorker(source,output,resume,self)
        self.worker.source_restored.connect(self.source_edit.setText)
        self.worker.progress.connect(self._progress)
        self.worker.succeeded.connect(self._succeeded)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self._finished)
        self.status.setText(self.tr_text('Inwentaryzacja…','Inventory running…'))
        self.progress_bar.setRange(0,0)
        self._controls()
        self.worker.start()

    def _progress(self, counts):
        self.status.setText(self.tr_text('Pozycje / odczyt / ponownie użyte / błędy lub pominięcia',
                                        'Entries / inspected / reused / errors or skips') + ': '
            + ' / '.join(str(counts.get(key,0)) for key in ('visited','inspected','reused','errors_or_skips'))
            + f" | {counts.get('bytes_read',0)/1048576:.2f} MiB")

    def _succeeded(self, result):
        self.last_result = result
        self.status.setText(self.status.text() + '\n' + self.tr_text(
            'Zakończono.' if result['complete'] else 'Zatrzymano; zapisano wyniki częściowe.',
            'Completed.' if result['complete'] else 'Stopped; partial results saved.'))
        self._pending_report = self.worker.output / 'inventory.sqlite'

    def _failed(self, message):
        self.last_error = message
        self.status.setText(self.tr_text('Błąd inwentaryzacji: ','Inventory error: ') + message)
        if (self.worker.output/'inventory.sqlite').is_file():
            self._pending_report = self.worker.output/'inventory.sqlite'

    def _finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.progress_bar.setRange(0,1)
        self.progress_bar.setValue(1)
        self._controls()
        self._browser_idle()

    def _browser_idle(self):
        if self._pending_report is not None and self.browser.worker is None:
            path, self._pending_report = self._pending_report, None
            self.browser.open_report(path)
        if not self.busy:
            self.idle.emit()

    def request_stop(self):
        if self.worker is not None:
            self.worker.stop_event.set()
            self.stop_button.setEnabled(False)

    def _controls(self):
        ready = self.worker is None
        for control in (self.source_edit,self.output_edit,self.source_button,self.output_button,
                        self.start_button,self.resume_button):
            control.setEnabled(ready)
        self.stop_button.setEnabled(not ready)

    def closeEvent(self,event):
        if self.busy:
            self.request_stop()
            event.ignore()
        else:
            event.accept()
