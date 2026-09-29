"""Main BFRS desktop window."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Slot
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from bfrs.application import (
    ScanCheckpointSavedEvent,
    ScanCompletedEvent,
    ScanController,
    ScanFailedEvent,
    ScanProgressEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
)
from bfrs.gui.configuration import build_gui_scan_config
from bfrs.gui.scan_worker import ScanWorker


_TARGETS = (
    ("bitcoin-core", "Bitcoin Core"),
    ("electrum", "Electrum"),
    ("multibit", "MultiBit"),
    ("armory", "Armory"),
    ("secrets", "Klucze / sekrety"),
)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BFRS 2.0")
        self.resize(860, 620)

        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._controller: ScanController | None = None

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        source_box = QGroupBox("Źródło i raport")
        source_layout = QGridLayout(source_box)

        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("Obraz dysku, plik lub folder")
        source_file_button = QPushButton("Wybierz plik…")
        source_folder_button = QPushButton("Wybierz folder…")
        source_file_button.clicked.connect(self._choose_source_file)
        source_folder_button.clicked.connect(self._choose_source_folder)

        self.source_type = QComboBox()
        self.source_type.addItem("Automatycznie", None)
        self.source_type.addItem("Obraz dysku", "image")
        self.source_type.addItem("Pojedynczy plik", "file")
        self.source_type.addItem("Folder", "folder")

        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Plik raportu JSON")
        output_button = QPushButton("Wybierz raport…")
        output_button.clicked.connect(self._choose_output)

        source_layout.addWidget(QLabel("Źródło:"), 0, 0)
        source_layout.addWidget(self.source_edit, 0, 1)
        source_layout.addWidget(source_file_button, 0, 2)
        source_layout.addWidget(source_folder_button, 0, 3)
        source_layout.addWidget(QLabel("Typ:"), 1, 0)
        source_layout.addWidget(self.source_type, 1, 1)
        source_layout.addWidget(QLabel("Raport:"), 2, 0)
        source_layout.addWidget(self.output_edit, 2, 1, 1, 2)
        source_layout.addWidget(output_button, 2, 3)
        layout.addWidget(source_box)

        target_box = QGroupBox("Zakres skanowania")
        target_layout = QGridLayout(target_box)
        self.target_checks: dict[str, QCheckBox] = {}
        for index, (name, label) in enumerate(_TARGETS):
            checkbox = QCheckBox(label)
            checkbox.setChecked(True)
            self.target_checks[name] = checkbox
            target_layout.addWidget(checkbox, index // 3, index % 3)

        self.mnemonic_check = QCheckBox("Szukaj seed / mnemonic")
        self.mnemonic_check.setChecked(True)
        self.bitcoin_context_check = QCheckBox("Rozszerzony kontekst Bitcoin")
        target_layout.addWidget(self.mnemonic_check, 2, 0, 1, 2)
        target_layout.addWidget(self.bitcoin_context_check, 2, 2)
        layout.addWidget(target_box)

        settings_box = QGroupBox("Wydajność i checkpoint")
        settings_layout = QFormLayout(settings_box)

        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(0, 32)
        self.workers_spin.setValue(4)
        self.workers_spin.setSpecialValueText("Auto")

        self.file_workers_spin = QSpinBox()
        self.file_workers_spin.setRange(1, 32)
        self.file_workers_spin.setValue(2)

        checkpoint_row = QWidget()
        checkpoint_layout = QHBoxLayout(checkpoint_row)
        checkpoint_layout.setContentsMargins(0, 0, 0, 0)
        self.checkpoint_edit = QLineEdit()
        self.checkpoint_edit.setPlaceholderText("Opcjonalny plik checkpoint")
        checkpoint_button = QPushButton("Wybierz…")
        checkpoint_button.clicked.connect(self._choose_checkpoint)
        checkpoint_layout.addWidget(self.checkpoint_edit)
        checkpoint_layout.addWidget(checkpoint_button)

        self.resume_check = QCheckBox("Wznów z istniejącego checkpointu")

        settings_layout.addRow("Workers:", self.workers_spin)
        settings_layout.addRow("File workers:", self.file_workers_spin)
        settings_layout.addRow("Checkpoint:", checkpoint_row)
        settings_layout.addRow("", self.resume_check)
        layout.addWidget(settings_box)

        progress_box = QGroupBox("Postęp")
        progress_layout = QVBoxLayout(progress_box)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.status_label = QLabel("Gotowy")
        self.detail_label = QLabel("")
        self.detail_label.setWordWrap(True)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.detail_label)
        layout.addWidget(progress_box)

        button_row = QHBoxLayout()
        self.start_button = QPushButton("Rozpocznij skanowanie")
        self.stop_button = QPushButton("Zatrzymaj bezpiecznie")
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self._start_scan)
        self.stop_button.clicked.connect(self._request_stop)
        button_row.addStretch(1)
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        layout.addLayout(button_row)

    @Slot()
    def _choose_source_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Wybierz źródło")
        if path:
            self.source_edit.setText(path)
            if not self.output_edit.text().strip():
                self.output_edit.setText(str(Path(path).with_suffix(".bfrs.json")))

    @Slot()
    def _choose_source_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Wybierz folder")
        if path:
            self.source_edit.setText(path)
            self.source_type.setCurrentIndex(3)
            if not self.output_edit.text().strip():
                self.output_edit.setText(str(Path(path).parent / (Path(path).name + ".bfrs.json")))

    @Slot()
    def _choose_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Wybierz raport", filter="JSON (*.json)"
        )
        if path:
            self.output_edit.setText(path)

    @Slot()
    def _choose_checkpoint(self) -> None:
        if self.resume_check.isChecked():
            path, _ = QFileDialog.getOpenFileName(
                self, "Wybierz checkpoint"
            )
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "Nowy checkpoint"
            )
        if path:
            self.checkpoint_edit.setText(path)

    def _selected_targets(self) -> frozenset[str]:
        return frozenset(
            name for name, checkbox in self.target_checks.items()
            if checkbox.isChecked()
        )

    @Slot()
    def _start_scan(self) -> None:
        if self._thread is not None:
            return

        try:
            config = build_gui_scan_config(
                input_path=self.source_edit.text(),
                output_path=self.output_edit.text(),
                source_type=self.source_type.currentData(),
                targets=self._selected_targets(),
                include_mnemonic=self.mnemonic_check.isChecked(),
                include_bitcoin_context=self.bitcoin_context_check.isChecked(),
                workers=self.workers_spin.value(),
                file_workers=self.file_workers_spin.value(),
                checkpoint_path=self.checkpoint_edit.text(),
                resume_checkpoint=self.resume_check.isChecked(),
            )
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Nieprawidłowa konfiguracja", str(error))
            return

        self._controller = ScanController()
        self._thread = QThread(self)
        self._worker = ScanWorker(config, self._controller)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.event.connect(self._handle_event)
        self._worker.finished.connect(self._scan_finished)
        self._worker.failed.connect(self._scan_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Uruchamianie skanu…")
        self.detail_label.clear()
        self._thread.start()

    @Slot()
    def _request_stop(self) -> None:
        if self._controller is None:
            return
        self._controller.request_stop()
        self.stop_button.setEnabled(False)
        self.status_label.setText(
            "Zatrzymywanie po zakończeniu bezpiecznej jednostki…"
        )

    @Slot(object)
    def _handle_event(self, event: object) -> None:
        if isinstance(event, ScanStartedEvent):
            self.status_label.setText("Skanowanie")
            return
        if isinstance(event, ScanProgressEvent):
            self.progress_bar.setValue(round(event.percent_complete * 10))
            counts = dict(event.raw_by_target)
            targets = " ".join(
                f"{name}={count}" for name, count in counts.items()
            ) or "brak"
            stage = event.stage or "skan"
            self.detail_label.setText(
                f"{event.percent_complete:.1f}% | "
                f"{event.scanned_bytes}/{event.total_bytes} B | "
                f"raw_hits={event.raw_hits} | {targets} | faza={stage}"
            )
            return
        if isinstance(event, ScanCheckpointSavedEvent):
            self.status_label.setText(
                f"Checkpoint zapisany: {event.checkpoint_path}"
            )
            return
        if isinstance(event, ScanStoppedEvent):
            self.status_label.setText("Skan zatrzymany bezpiecznie")
            return
        if isinstance(event, ScanFailedEvent):
            self.status_label.setText(f"Błąd: {event.message}")
            return
        if isinstance(event, ScanCompletedEvent):
            self.progress_bar.setValue(1000)
            self.status_label.setText(
                f"Skan zakończony — status: {event.status}"
            )

    @Slot(object)
    def _scan_finished(self, result: object) -> None:
        if getattr(result, "status", "") == "stopped":
            self.status_label.setText("Skan zatrzymany bezpiecznie")
        elif getattr(result, "completed", False):
            self.status_label.setText(
                f"Skan zakończony — raport: {getattr(result, 'report_path', '')}"
            )

    @Slot(str)
    def _scan_failed(self, message: str) -> None:
        self.status_label.setText("Skan zakończony błędem")
        QMessageBox.critical(self, "Błąd skanowania", message)

    @Slot()
    def _cleanup_thread(self) -> None:
        if self._worker is not None:
            self._worker.deleteLater()
        if self._thread is not None:
            self._thread.deleteLater()
        self._worker = None
        self._thread = None
        self._controller = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
