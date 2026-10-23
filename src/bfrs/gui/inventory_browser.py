"""Standalone Qt browser for metadata inventory reports."""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PureWindowsPath
import sys

from PySide6.QtCore import QThread, QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView,
)

from bfrs.application.inventory_view import (
    PAGE_SIZE, checked_source_path, read_inventory_page, source_path,
)
from bfrs.gui.windows_reveal import reveal_in_explorer


LABELS = {'ENCRYPTED': 'Znacznik szyfrowania', 'UNKNOWN': 'Nieustalone',
          'NO_ENCRYPTION_INDICATOR': 'Bez znacznika szyfrowania'}

REASONS = {
    '7Z_AES_HEADER': 'Znacznik AES w metadanych szyfrowanego nagłówka 7z',
    '7Z_AES_DATA': 'Znacznik AES w metadanych zawartości 7z',
    '7Z_NO_ENCRYPTION_CODER': 'Brak szyfrowania w sprawdzonych opisach metod 7z',
    'WINDOWS_EFS_FILE_ATTRIBUTE': 'Plik z atrybutem szyfrowania Windows EFS',
    'WINDOWS_EFS_DIRECTORY_DEFAULT': 'Folder z domyślnym szyfrowaniem EFS nowych plików',
    'PDF_ENCRYPT_ENTRY': 'Wpis szyfrowania w metadanych PDF',
    'PDF_ENCRYPT_ENTRY_WITHOUT_ROOT': 'Wpis szyfrowania PDF; brak odwołania do katalogu dokumentu',
    'OFFICE_ENCRYPTION_STREAMS': 'Metadane szyfrowania dokumentu Office',
    'XLS_FILEPASS': 'Rekord szyfrowania skoroszytu XLS',
    'RAR_ENCRYPTED_HEADERS': 'Zaszyfrowane nagłówki archiwum RAR',
    'RAR_FILE_PASSWORD_FLAG': 'Flaga hasła pliku w archiwum RAR',
    'RAR_FILE_ENCRYPTION_RECORD': 'Rekord szyfrowania pliku w archiwum RAR',
    'OLE_TYPE_UNDETERMINED': 'Nierozpoznany typ kontenera OLE',
    'NO_SUPPORTED_START_SIGNATURE': 'Brak obsługiwanej sygnatury pliku',
}


def describe_reason(row):
    if row.get('reason') in REASONS:
        return REASONS[row['reason']]
    if row.get('reason'):
        return 'Nie można rozstrzygnąć — zobacz kod analizy poniżej'
    if row['encryption'] == 'ENCRYPTED':
        if row.get('format') == 'DOC':
            return 'Flaga szyfrowania w nagłówku Worda'
        return 'Flagi szyfrowania w sprawdzonych nagłówkach'
    if row['encryption'] == 'NO_ENCRYPTION_INDICATOR':
        return 'Nie znaleziono znacznika w sprawdzonych metadanych'
    return 'Brak rozstrzygnięcia'


class _Task(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, operation, parent):
        super().__init__(parent)
        self.operation = operation

    def run(self):
        try:
            self.succeeded.emit(self.operation())
        except Exception as error:
            self.failed.emit(str(error))


class InventoryBrowser(QWidget):
    def __init__(self, database=None):
        super().__init__()
        self.setWindowTitle('BFRS — przegląd dokumentów i archiwów')
        self.resize(1180, 740)
        self.database = None
        self.page = None
        self.source_override = None
        self.worker = None
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        self.open_button = QPushButton('Otwórz raport…')
        self.refresh_button = QPushButton('Odśwież')
        self.report_label = QLabel('Wybierz plik inventory.sqlite.')
        self.report_label.setTextFormat(Qt.TextFormat.PlainText)
        self.report_label.setWordWrap(True)
        top.addWidget(self.open_button)
        top.addWidget(self.refresh_button)
        top.addWidget(self.report_label, 1)
        layout.addLayout(top)

        roots = QHBoxLayout()
        self.root_label = QLabel('Folder źródłowy: —')
        self.root_label.setTextFormat(Qt.TextFormat.PlainText)
        self.root_label.setWordWrap(True)
        self.root_button = QPushButton('Wskaż folder źródłowy…')
        self.reset_root_button = QPushButton('Przywróć ścieżkę raportu')
        roots.addWidget(self.root_label, 1)
        roots.addWidget(self.root_button)
        roots.addWidget(self.reset_root_button)
        layout.addLayout(roots)

        filters = QHBoxLayout()
        self.state_combo = QComboBox()
        for value, label in LABELS.items():
            self.state_combo.addItem(label, value)
        self.state_combo.addItem('Wszystkie wyniki', None)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText('Szukaj w nazwie lub ścieżce…')
        self.search_button = QPushButton('Szukaj')
        filters.addWidget(self.state_combo)
        filters.addWidget(self.search_edit, 1)
        filters.addWidget(self.search_button)
        layout.addLayout(filters)

        self.summary_label = QLabel('')
        layout.addWidget(self.summary_label)
        note = QLabel('Znacznik szyfrowania nie oznacza, że plik wymaga hasła przy otwieraniu. '
                      'Widok korzysta z zapisanych wyników ostatniego przebiegu; '
                      'przerwane przebiegi mogą zawierać tylko część źródła.')
        note.setWordWrap(True)
        layout.addWidget(note)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(['Nazwa', 'Format / typ', 'Rozmiar', 'Wynik', 'Powód', 'Folder'])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        for index, width in enumerate((220, 90, 100, 170, 200)):
            self.table.setColumnWidth(index, width)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.table)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText('Wybierz plik lub folder, aby zobaczyć szczegóły raportu.')
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        actions = QHBoxLayout()
        self.reveal_button = QPushButton('Pokaż w Eksploratorze' if os.name == 'nt' else 'Pokaż folder')
        self.copy_button = QPushButton('Kopiuj ścieżkę')
        self.previous_button = QPushButton('Poprzednia')
        self.next_button = QPushButton('Następna')
        self.page_label = QLabel('')
        for item in (self.reveal_button, self.copy_button):
            actions.addWidget(item)
        actions.addStretch(1)
        for item in (self.previous_button, self.page_label, self.next_button):
            actions.addWidget(item)
        layout.addLayout(actions)
        self.message = QLabel('')
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

        self.open_button.clicked.connect(self._choose_report)
        self.refresh_button.clicked.connect(lambda: self.load_page(0))
        self.root_button.clicked.connect(self._choose_root)
        self.reset_root_button.clicked.connect(lambda: self.set_source_root(None))
        self.state_combo.currentIndexChanged.connect(lambda: self.load_page(0))
        self.search_button.clicked.connect(lambda: self.load_page(0))
        self.search_edit.returnPressed.connect(lambda: self.load_page(0))
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(lambda *_: self.reveal_selected())
        self.reveal_button.clicked.connect(self.reveal_selected)
        self.copy_button.clicked.connect(self.copy_selected)
        self.previous_button.clicked.connect(lambda: self.load_page(self.page.offset-PAGE_SIZE))
        self.next_button.clicked.connect(lambda: self.load_page(self.page.offset+PAGE_SIZE))
        self._enable_controls()
        if database:
            self.open_report(database)

    def _choose_report(self):
        name, _ = QFileDialog.getOpenFileName(self, 'Otwórz raport inwentaryzacji', '',
                                             'Raport SQLite (*.sqlite)')
        if name:
            self.open_report(name)

    def open_report(self, database):
        if self.worker:
            return
        self.database = Path(database).absolute()
        self.source_override = None
        self.report_label.setText(str(self.database))
        self.load_page(0)

    def load_page(self, offset=0):
        if self.worker or self.database is None:
            return
        database, state, search = self.database, self.state_combo.currentData(), self.search_edit.text()
        self.table.setRowCount(0)
        self.details.clear()
        self.page = None
        self.page_label.clear()
        self.summary_label.clear()
        self.root_label.setText('Folder źródłowy: wczytywanie raportu…')
        self._start(lambda: read_inventory_page(database, state, search, offset), self._display_page,
                    'Wczytywanie zapisanych wyników…')

    def _start(self, operation, success, message):
        self.message.setText(message)
        self.worker = _Task(operation, self)
        self.worker.succeeded.connect(success)
        self.worker.failed.connect(self._error)
        self.worker.finished.connect(self._finished)
        self._enable_controls()
        self.worker.start()

    def _finished(self):
        self.worker.deleteLater()
        self.worker = None
        self._enable_controls()

    def _error(self, text):
        self.message.setText('Nie udało się wykonać operacji: ' + text +
                             '\nJeśli dysk zmienił literę, wskaż aktualny folder źródłowy.')

    def _display_page(self, page):
        self.page = page
        self.summary_label.setText('   |   '.join(f'{label}: {page.counts.get(state, 0)}'
                                                 for state, label in LABELS.items()))
        self._update_root_label()
        self.table.setRowCount(len(page.rows))
        for index, row in enumerate(page.rows):
            path = PureWindowsPath(row['path'])
            size = row.get('size')
            kind = ('Folder EFS' if row.get('entry_kind') == 'directory' else 'Plik EFS') if row.get('format') == 'WINDOWS_EFS' else row.get('format') or 'Nieznany'
            values = (path.name or '(folder źródłowy)', kind,
                      f'{size:,} B'.replace(',', ' ') if isinstance(size, int) else '—',
                      LABELS[row['encryption']], describe_reason(row), str(path.parent))
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(value))
                self.table.setItem(index, column, item)
        self.page_label.setText(f'Strona {page.offset//PAGE_SIZE+1} · {len(page.rows)} pozycji')
        self.message.setText('Wybierz pozycję i użyj przycisku pokazania lokalizacji.' if page.rows
                             else 'Brak wyników dla wybranego filtra.')
        self._enable_controls()

    def _selected(self):
        index = self.table.currentRow()
        return self.page.rows[index] if self.page and 0 <= index < len(self.page.rows) else None

    def _selection_changed(self):
        row = self._selected()
        self.details.setPlainText(
            f"Ścieżka w źródle: {row['path']}\n"
            f"Wynik: {LABELS[row['encryption']]}\n"
            f"Powód: {describe_reason(row)}\n"
            f"Kod analizy: {row.get('reason') or row.get('structure') or '—'}\n\n"
            'To zapis oceny metadanych. Nie potwierdza poprawności całego pliku '
            'ani konieczności podania hasła przy otwieraniu.' if row else '')
        if row and row.get('filesystem_encryption') == 'EFS':
            self.details.appendPlainText('\nWykryto bieżący atrybut Windows EFS. '
                'Zawartość nie była odczytywana ani odszyfrowywana.')
            if row.get('entry_kind') == 'directory':
                self.details.appendPlainText('Znacznik folderu dotyczy domyślnego szyfrowania '
                    'nowych plików. Nie potwierdza szyfrowania wszystkich istniejących plików; '
                    'każdy plik jest sprawdzany osobno.')
            if row.get('scan_error'):
                self.details.appendPlainText('Niepełne przeglądanie folderu: ' + row['scan_error'])
        self._enable_controls()

    def _enable_controls(self):
        ready = self.worker is None
        for control in (self.open_button, self.state_combo, self.search_edit, self.search_button):
            control.setEnabled(ready)
        self.refresh_button.setEnabled(ready and self.database is not None)
        self.root_button.setEnabled(ready and self.page is not None)
        self.reset_root_button.setEnabled(ready and self.source_override is not None)
        selected = ready and self._selected() is not None
        self.copy_button.setEnabled(selected)
        self.reveal_button.setEnabled(selected)
        self.previous_button.setEnabled(ready and self.page is not None and self.page.offset > 0)
        self.next_button.setEnabled(ready and self.page is not None and self.page.has_next)

    def _source(self):
        return self.source_override if self.source_override is not None else self.page.source

    def _update_root_label(self):
        self.root_label.setText('Folder źródłowy: ' + str(self._source()) if self.page else 'Folder źródłowy: —')

    def _choose_root(self):
        name = QFileDialog.getExistingDirectory(self, 'Wskaż folder odpowiadający źródłu skanu')
        if name:
            self.set_source_root(name)

    def set_source_root(self, root):
        self.source_override = str(root) if root is not None else None
        self._update_root_label()
        self._enable_controls()

    def copy_selected(self):
        row = self._selected()
        if row:
            try:
                path = source_path(self._source(), row['path'], directory=row.get('entry_kind') == 'directory')
                QGuiApplication.clipboard().setText(str(path))
                self.message.setText('Skopiowano ścieżkę. Zawartość pliku nie była odczytywana.')
            except (ValueError, OSError) as error:
                self._error(str(error))

    def reveal_selected(self):
        row = self._selected()
        if row is None or self.worker:
            return
        source, relative = self._source(), row['path']
        directory = row.get('entry_kind') == 'directory'
        def reveal():
            path = checked_source_path(source, relative, directory=directory)
            if os.name == 'nt':
                reveal_in_explorer(path)
                return None
            return path if directory else path.parent
        self._start(reveal, self._revealed, 'Sprawdzanie lokalizacji…')

    def _revealed(self, folder):
        if folder is not None and not QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder))):
            self._error('Nie udało się otworzyć folderu.')
            return
        self.message.setText('Pokazano lokalizację. Dokument nie został otwarty przez BFRS.')

    def closeEvent(self, event):
        if self.worker:
            self.message.setText('Poczekaj na zakończenie bieżącej operacji, aby zamknąć okno.')
            event.ignore()
        else:
            event.accept()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Przegląd raportu inwentaryzacji BFRS.')
    parser.add_argument('--report', type=Path, help='Ścieżka do inventory.sqlite')
    args = parser.parse_args(argv)
    application = QApplication.instance() or QApplication([sys.argv[0]])
    application.setApplicationName('BFRS — inwentaryzacja')
    window = InventoryBrowser(args.report)
    window.show()
    return application.exec()
