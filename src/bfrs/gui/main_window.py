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
    QTabWidget,
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
from bfrs.gui.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    normalize_language,
    translate,
)
from bfrs.gui.result_browser import ResultBrowserWidget
from bfrs.gui.scan_worker import ScanWorker


_TARGET_KEYS = {
    "bitcoin-core": "target_bitcoin_core",
    "electrum": "target_electrum",
    "multibit": "target_multibit",
    "armory": "target_armory",
    "secrets": "target_secrets",
}


class MainWindow(QMainWindow):
    def __init__(self, *, language: str = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self._language = normalize_language(language)
        self.setWindowTitle("BFRS 2.0")
        self.resize(860, 660)

        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._controller: ScanController | None = None

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        language_row = QHBoxLayout()
        language_row.addStretch(1)
        self.language_label = QLabel()
        self.language_combo = QComboBox()
        for code, label in SUPPORTED_LANGUAGES.items():
            self.language_combo.addItem(label, code)
        current = self.language_combo.findData(self._language)
        self.language_combo.setCurrentIndex(max(current, 0))
        self.language_combo.currentIndexChanged.connect(self._change_language)
        language_row.addWidget(self.language_label)
        language_row.addWidget(self.language_combo)
        layout.addLayout(language_row)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.scan_tab = QWidget()
        scan_layout = QVBoxLayout(self.scan_tab)
        self.result_browser = ResultBrowserWidget(language=self._language)
        self.tabs.addTab(self.scan_tab, "")
        self.tabs.addTab(self.result_browser, "")

        self.source_box = QGroupBox()
        source_layout = QGridLayout(self.source_box)

        self.source_edit = QLineEdit()
        self.source_file_button = QPushButton()
        self.source_folder_button = QPushButton()
        self.source_file_button.clicked.connect(self._choose_source_file)
        self.source_folder_button.clicked.connect(self._choose_source_folder)

        self.source_type_label = QLabel()
        self.source_type = QComboBox()
        for value in (None, "image", "file", "folder"):
            self.source_type.addItem("", value)

        self.output_edit = QLineEdit()
        self.output_button = QPushButton()
        self.output_button.clicked.connect(self._choose_output)

        self.source_label = QLabel()
        self.report_label = QLabel()
        source_layout.addWidget(self.source_label, 0, 0)
        source_layout.addWidget(self.source_edit, 0, 1)
        source_layout.addWidget(self.source_file_button, 0, 2)
        source_layout.addWidget(self.source_folder_button, 0, 3)
        source_layout.addWidget(self.source_type_label, 1, 0)
        source_layout.addWidget(self.source_type, 1, 1)
        source_layout.addWidget(self.report_label, 2, 0)
        source_layout.addWidget(self.output_edit, 2, 1, 1, 2)
        source_layout.addWidget(self.output_button, 2, 3)
        scan_layout.addWidget(self.source_box)

        self.target_box = QGroupBox()
        target_layout = QGridLayout(self.target_box)
        self.target_checks: dict[str, QCheckBox] = {}
        for index, name in enumerate(_TARGET_KEYS):
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            self.target_checks[name] = checkbox
            target_layout.addWidget(checkbox, index // 3, index % 3)

        self.mnemonic_check = QCheckBox()
        self.mnemonic_check.setChecked(True)
        self.bitcoin_context_check = QCheckBox()
        target_layout.addWidget(self.mnemonic_check, 2, 0, 1, 2)
        target_layout.addWidget(self.bitcoin_context_check, 2, 2)
        scan_layout.addWidget(self.target_box)

        self.settings_box = QGroupBox()
        settings_layout = QFormLayout(self.settings_box)

        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(0, 32)
        self.workers_spin.setValue(4)
        self.workers_spin.setSpecialValueText("Auto")

        self.file_workers_spin = QSpinBox()
        self.file_workers_spin.setRange(1, 32)
        self.file_workers_spin.setValue(1)

        checkpoint_row = QWidget()
        checkpoint_layout = QHBoxLayout(checkpoint_row)
        checkpoint_layout.setContentsMargins(0, 0, 0, 0)
        self.checkpoint_edit = QLineEdit()
        self.checkpoint_button = QPushButton()
        self.checkpoint_button.clicked.connect(self._choose_checkpoint)
        checkpoint_layout.addWidget(self.checkpoint_edit)
        checkpoint_layout.addWidget(self.checkpoint_button)

        self.resume_check = QCheckBox()

        self.workers_label = QLabel()
        self.file_workers_label = QLabel()
        self.checkpoint_label = QLabel()
        settings_layout.addRow(self.workers_label, self.workers_spin)
        settings_layout.addRow(self.file_workers_label, self.file_workers_spin)
        settings_layout.addRow(self.checkpoint_label, checkpoint_row)
        settings_layout.addRow("", self.resume_check)
        scan_layout.addWidget(self.settings_box)

        self.progress_box = QGroupBox()
        progress_layout = QVBoxLayout(self.progress_box)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1000)
        self.progress_bar.setValue(0)
        self.status_label = QLabel()
        self.detail_label = QLabel("")
        self.detail_label.setWordWrap(True)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.detail_label)
        scan_layout.addWidget(self.progress_box)

        button_row = QHBoxLayout()
        self.start_button = QPushButton()
        self.stop_button = QPushButton()
        self.stop_button.setEnabled(False)
        self.start_button.clicked.connect(self._start_scan)
        self.stop_button.clicked.connect(self._request_stop)
        button_row.addStretch(1)
        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        scan_layout.addLayout(button_row)

        self._retranslate_ui()

    def _t(self, key: str, **values: object) -> str:
        return translate(self._language, key, **values)

    @Slot()
    def _change_language(self) -> None:
        self._language = normalize_language(self.language_combo.currentData())
        self._retranslate_ui()

    def _retranslate_ui(self) -> None:
        self.language_label.setText(self._t("language"))
        self.tabs.setTabText(0, self._t("tab_scan"))
        self.tabs.setTabText(1, self._t("tab_results"))
        self.result_browser.set_language(self._language)
        self.source_box.setTitle(self._t("source_report_group"))
        self.source_edit.setPlaceholderText(self._t("source_placeholder"))
        self.source_file_button.setText(self._t("choose_file"))
        self.source_folder_button.setText(self._t("choose_folder"))
        self.source_label.setText(self._t("source"))
        self.source_type_label.setText(self._t("type"))
        self.report_label.setText(self._t("report"))
        self.output_edit.setPlaceholderText(self._t("report_placeholder"))
        self.output_button.setText(self._t("choose_report"))

        source_type_labels = ("auto", "disk_image", "single_file", "folder")
        for index, key in enumerate(source_type_labels):
            self.source_type.setItemText(index, self._t(key))

        self.target_box.setTitle(self._t("scan_scope_group"))
        for name, checkbox in self.target_checks.items():
            checkbox.setText(self._t(_TARGET_KEYS[name]))
        self.mnemonic_check.setText(self._t("search_mnemonic"))
        self.bitcoin_context_check.setText(self._t("bitcoin_context"))

        self.settings_box.setTitle(self._t("performance_group"))
        self.workers_label.setText(self._t("workers"))
        self.file_workers_label.setText(self._t("file_workers"))
        self.checkpoint_label.setText(self._t("checkpoint"))
        self.checkpoint_edit.setPlaceholderText(self._t("checkpoint_placeholder"))
        self.checkpoint_button.setText(self._t("choose"))
        self.resume_check.setText(self._t("resume_checkpoint"))

        self.progress_box.setTitle(self._t("progress_group"))
        if self._thread is None:
            self.status_label.setText(self._t("ready"))
        self.start_button.setText(self._t("start_scan"))
        self.stop_button.setText(self._t("stop_safely"))

    @Slot()
    def _choose_source_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, self._t("choose_source_title"))
        if path:
            self.source_edit.setText(path)
            if not self.output_edit.text().strip():
                self.output_edit.setText(str(Path(path).with_suffix(".bfrs.json")))

    @Slot()
    def _choose_source_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self._t("choose_folder_title"))
        if path:
            self.source_edit.setText(path)
            self.source_type.setCurrentIndex(3)
            if not self.output_edit.text().strip():
                self.output_edit.setText(
                    str(Path(path).parent / (Path(path).name + ".bfrs.json"))
                )

    @Slot()
    def _choose_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, self._t("choose_report_title"), filter="JSON (*.json)"
        )
        if path:
            self.output_edit.setText(path)

    @Slot()
    def _choose_checkpoint(self) -> None:
        title = (
            self._t("choose_checkpoint_title")
            if self.resume_check.isChecked()
            else self._t("new_checkpoint_title")
        )
        if self.resume_check.isChecked():
            path, _ = QFileDialog.getOpenFileName(self, title)
        else:
            path, _ = QFileDialog.getSaveFileName(self, title)
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
                language=self._language,
            )
        except (ValueError, OSError) as error:
            QMessageBox.warning(
                self, self._t("invalid_configuration"), str(error)
            )
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
        self.status_label.setText(self._t("starting_scan"))
        self.detail_label.clear()
        self._thread.start()

    @Slot()
    def _request_stop(self) -> None:
        if self._controller is None:
            return
        self._controller.request_stop()
        self.stop_button.setEnabled(False)
        self.status_label.setText(self._t("stopping_scan"))

    @Slot(object)
    def _handle_event(self, event: object) -> None:
        if isinstance(event, ScanStartedEvent):
            self.status_label.setText(self._t("scanning"))
            return
        if isinstance(event, ScanProgressEvent):
            self.progress_bar.setValue(round(event.percent_complete * 10))
            counts = dict(event.raw_by_target)
            targets = " ".join(
                f"{name}={count}" for name, count in counts.items()
            ) or self._t("none")
            stage = event.stage or self._t("scan_phase")
            self.detail_label.setText(
                f"{event.percent_complete:.1f}% | "
                f"{event.scanned_bytes}/{event.total_bytes} B | "
                f"raw_hits={event.raw_hits} | {targets} | "
                f"{self._t('phase')}={stage}"
            )
            return
        if isinstance(event, ScanCheckpointSavedEvent):
            self.status_label.setText(
                self._t("checkpoint_saved", path=event.checkpoint_path)
            )
            return
        if isinstance(event, ScanStoppedEvent):
            self.status_label.setText(self._t("scan_stopped"))
            return
        if isinstance(event, ScanFailedEvent):
            self.status_label.setText(
                self._t("error_prefix", message=event.message)
            )
            return
        if isinstance(event, ScanCompletedEvent):
            self.progress_bar.setValue(1000)
            self.status_label.setText(
                self._t("scan_completed_status", status=event.status)
            )

    @Slot(object)
    def _scan_finished(self, result: object) -> None:
        if getattr(result, "status", "") == "stopped":
            self.status_label.setText(self._t("scan_stopped"))
        elif getattr(result, "completed", False):
            report_path = getattr(result, "report_path", "")
            self.status_label.setText(
                self._t(
                    "scan_completed_report",
                    path=report_path,
                )
            )
            if report_path and self.result_browser.load_report(report_path):
                self.tabs.setCurrentWidget(self.result_browser)

    @Slot(str)
    def _scan_failed(self, message: str) -> None:
        self.status_label.setText(self._t("scan_failed"))
        QMessageBox.critical(self, self._t("scan_error_title"), message)

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
