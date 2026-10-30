"""Desktop controls for bounded, restartable raw ZIP inventory."""
from datetime import datetime
import json
from pathlib import Path
from threading import Event
import time

from PySide6.QtCore import QThread, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from bfrs.application.raw_zip_view import PAGE_SIZE, read_raw_zip_page
from bfrs.gui.i18n import normalize_language, translate
from bfrs.recovery.raw_zip_inventory import scan_image


class RawZipTask(QThread):
    progress = Signal(object)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, operation, parent=None):
        super().__init__(parent)
        self.operation = operation
        self.stop_requested = Event()
        self._last_emit = 0.0
        self._baseline = None

    def report_progress(self, values):
        now = time.monotonic()
        if self._baseline is None:
            self._baseline = (now, values['scanned_bytes'])
        if now - self._last_emit >= .1 or values['scanned_bytes'] == values['total_bytes']:
            elapsed = now - self._baseline[0]
            speed = ((values['scanned_bytes'] - self._baseline[1]) / elapsed / 1048576
                     if elapsed > 0 else 0.0)
            self.progress.emit(dict(values, speed_mib=round(speed, 2)))
            self._last_emit = now

    def run(self):
        try:
            self.succeeded.emit(self.operation(self))
        except Exception as error:
            self.failed.emit(f'{type(error).__name__}: {error}')


class RawZipPanel(QWidget):
    paths_changed = Signal()
    idle = Signal()

    def __init__(self, language='pl', parent=None):
        super().__init__(parent)
        self.language = normalize_language(language)
        self.worker = None
        self.scanning = False
        self.database = None
        self.page = None
        self._pending_report = None
        self._status_key = 'ready'
        self._status_values = {}
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.source_label, self.output_label = QLabel(), QLabel()
        self.source_edit, self.output_edit = QLineEdit(), QLineEdit()
        self.source_button, self.output_button = QPushButton(), QPushButton()
        for i, widgets in enumerate(((self.source_label, self.source_edit, self.source_button),
                                     (self.output_label, self.output_edit, self.output_button))):
            for j, widget in enumerate(widgets):
                grid.addWidget(widget, i, j)
        layout.addLayout(grid)
        self.resume_check = QCheckBox()
        layout.addWidget(self.resume_check)
        self.note = QLabel()
        self.note.setWordWrap(True)
        layout.addWidget(self.note)
        actions = QHBoxLayout()
        self.start_button, self.stop_button = QPushButton(), QPushButton()
        self.open_button, self.folder_button = QPushButton(), QPushButton()
        for button in (self.start_button, self.stop_button, self.open_button, self.folder_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        layout.addWidget(self.progress_bar)
        self.status, self.progress_label, self.report_label = QLabel(), QLabel(), QLabel()
        for label in (self.status, self.progress_label, self.report_label):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            layout.addWidget(label)
        self.priority_check = QCheckBox()
        self.priority_check.setChecked(True)
        layout.addWidget(self.priority_check)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        for column, width in enumerate((115, 130, 175, 160, 200)):
            self.table.setColumnWidth(column, width)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        pages = QHBoxLayout()
        self.previous_button, self.next_button, self.page_label = QPushButton(), QPushButton(), QLabel()
        pages.addWidget(self.previous_button)
        pages.addWidget(self.page_label)
        pages.addStretch(1)
        pages.addWidget(self.next_button)
        layout.addLayout(pages)
        self.source_button.clicked.connect(self._choose_source)
        self.output_button.clicked.connect(self._choose_output)
        self.open_button.clicked.connect(self._choose_report)
        self.folder_button.clicked.connect(self._open_folder)
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.request_stop)
        self.priority_check.toggled.connect(lambda: self.load_page())
        self.previous_button.clicked.connect(lambda: self.load_page(self.page.offset - PAGE_SIZE))
        self.next_button.clicked.connect(lambda: self.load_page(self.page.offset + PAGE_SIZE))
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.set_language(language)
        self._controls()

    def _t(self, key, **values):
        return translate(self.language, key, **values)

    @property
    def busy(self):
        return self.worker is not None or self._pending_report is not None

    def set_language(self, language):
        self.language = normalize_language(language)
        for widget, key in ((self.source_label, 'source'), (self.output_label, 'raw_zip_output'),
                            (self.source_button, 'choose_file'), (self.output_button, 'choose_folder'),
                            (self.resume_check, 'resume_checkpoint'), (self.note, 'raw_zip_note'),
                            (self.start_button, 'start_scan'), (self.stop_button, 'stop_safely'),
                            (self.open_button, 'raw_zip_open'), (self.folder_button, 'raw_zip_folder'),
                            (self.priority_check, 'raw_zip_priority_only'),
                            (self.previous_button, 'raw_zip_previous'), (self.next_button, 'raw_zip_next')):
            widget.setText(self._t(key))
        self.output_edit.setPlaceholderText(self._t('raw_zip_output_hint'))
        self.table.setHorizontalHeaderLabels([self._t('raw_zip_' + name)
                                             for name in ('offset', 'record', 'priority', 'encryption', 'name')])
        self.status.setText(self._t(self._status_key, **self._status_values))
        if self.page:
            self._display_page(self.page)

    def _set_status(self, key, **values):
        self._status_key, self._status_values = key, values
        self.status.setText(self._t(key, **values))

    def _controls(self):
        idle = self.worker is None
        for widget in (self.source_edit, self.output_edit, self.source_button, self.output_button,
                       self.resume_check, self.start_button, self.open_button, self.priority_check):
            widget.setEnabled(idle)
        self.stop_button.setEnabled(not idle and self.scanning and not self.worker.stop_requested.is_set())
        self.folder_button.setEnabled(idle and self.database is not None)
        self.previous_button.setEnabled(idle and self.page is not None and self.page.offset > 0)
        self.next_button.setEnabled(idle and self.page is not None and self.page.has_next)

    def _choose_source(self):
        path, _ = QFileDialog.getOpenFileName(self, self._t('choose_source_title'))
        if path:
            self.source_edit.setText(path)

    def _choose_output(self):
        path = QFileDialog.getExistingDirectory(self, self._t('raw_zip_choose_output'))
        if path:
            output = Path(path)
            if not self.resume_check.isChecked():
                output /= datetime.now().strftime('zip-image-%Y%m%d-%H%M%S')
            self.output_edit.setText(str(output))

    def _choose_report(self):
        path, _ = QFileDialog.getOpenFileName(self, self._t('raw_zip_open'), '', 'ZIP scan (zip_scan.sqlite)')
        if path:
            self.open_report(path)

    def open_report(self, database, *, preserve_status=False):
        if self.worker:
            return
        self.database = Path(database).absolute()
        self._adopt_report = True
        if not preserve_status:
            self._set_status('raw_zip_saved_report')
        self.load_page()

    def _open_folder(self):
        if self.database:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.database.parent)))

    def _start_task(self, operation, callback, *, scanning=False):
        self.scanning = scanning
        self.worker = RawZipTask(operation, self)
        self.worker.succeeded.connect(callback)
        self.worker.failed.connect(self._failed)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self._controls()
        self.worker.start()

    def start_scan(self):
        if self.worker:
            return
        source, output = self.source_edit.text().strip(), self.output_edit.text().strip()
        if not source or not output:
            self._set_status('raw_zip_paths_required')
            return
        resume = self.resume_check.isChecked()
        self.paths_changed.emit()
        self.database = None
        self._clear_page()
        self.progress_bar.setRange(0, 0)
        self.progress_label.clear()
        self._set_status('starting_scan')
        self._scan_output = Path(output).absolute()
        self._start_task(lambda task: scan_image(source, output, resume=resume,
                         should_stop=task.stop_requested.is_set, progress=task.report_progress),
                         self._scan_done, scanning=True)

    def request_stop(self):
        if self.worker and self.scanning:
            self.worker.stop_requested.set()
            self._set_status('raw_zip_stopping')
            self._controls()

    def _progress(self, values):
        total, done = values['total_bytes'], values['scanned_bytes']
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(round(done / total * 1000) if total else 1000)
        self.progress_label.setText(self._t('raw_zip_progress', done=done, total=total,
                                          speed=values['speed_mib'], hits=values['signatures_seen']))
        if not self.worker.stop_requested.is_set():
            self._set_status('raw_zip_exporting' if done == total else 'scanning')

    def _scan_done(self, summary):
        self.progress_bar.setRange(0, 1000)
        total, done = summary['source_size'], summary['scanned_prefix_end']
        self.progress_bar.setValue(round(done / total * 1000) if total else 1000)
        reason = summary['stop_reason']
        if summary['scan_complete']:
            self._set_status('raw_zip_complete')
        elif reason in ('STOP_REQUESTED', 'INTERRUPTED'):
            self._set_status('raw_zip_stopped')
        elif reason == 'CANDIDATE_LIMIT':
            self._set_status('raw_zip_limit')
        else:
            self._set_status('raw_zip_incomplete', reason=reason)
        self.resume_check.setChecked(True)
        self._pending_report = self._scan_output / 'zip_scan.sqlite'

    def _failed(self, message):
        self.progress_bar.setRange(0, 1000)
        self._set_status('error_prefix', message=message)

    def _finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.scanning = False
        self._controls()
        if self._pending_report:
            report, self._pending_report = self._pending_report, None
            self.open_report(report, preserve_status=True)
        if not self.busy:
            self.idle.emit()

    def _clear_page(self):
        self.page = None
        self.table.setRowCount(0)
        self.details.clear()
        self.report_label.clear()
        self.page_label.clear()

    def load_page(self, offset=0):
        if self.worker or self.database is None:
            return
        database, priority = self.database, self.priority_check.isChecked()
        self._clear_page()
        self._start_task(lambda task: read_raw_zip_page(database, priority_only=priority, offset=offset),
                         self._display_page)

    def _display_page(self, page):
        self.page = page
        if getattr(self, '_adopt_report', False):
            self._adopt_report = False
            self.source_edit.setText(page.source)
            self.output_edit.setText(str(self.database.parent))
            self.resume_check.setChecked(True)
            self.paths_changed.emit()
        self.report_label.setText(self._t('raw_zip_report', path=str(self.database), source=page.source,
                                         done=page.scanned_bytes, total=page.total_bytes))
        self.table.setRowCount(len(page.rows))
        for index, row in enumerate(page.rows):
            names = row.get('member_name') or '; '.join(hint.get('name', '')
                                                       for hint in row.get('zip_name_hints', []))
            values = (str(row['offset']), self._t('raw_zip_' + row['record_type']),
                      self._t('raw_zip_priority_' + str(row.get('priority', 0))),
                      self._t('raw_zip_' + row['encryption']), names)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(index, column, item)
        self.page_label.setText(self._t('raw_zip_page', page=page.offset // PAGE_SIZE + 1, count=len(page.rows)))
        self._controls()

    def _selection_changed(self):
        index = self.table.currentRow()
        if self.page and 0 <= index < len(self.page.rows):
            self.details.setPlainText(json.dumps(self.page.rows[index], ensure_ascii=False, indent=2))
        else:
            self.details.clear()

    def closeEvent(self, event):
        if self.worker:
            self.request_stop()
            event.ignore()
        else:
            super().closeEvent(event)
