"""Qt result browser backed by the presentation-neutral ResultService."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QUrl, Qt, Slot
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bfrs.application import (
    FindingView,
    ResultReport,
    ResultService,
    ResultServiceError,
)
from bfrs.gui.i18n import DEFAULT_LANGUAGE, normalize_language, translate


_DISCOVERY_STATES = ("ACCEPTED", "CANDIDATE", "REJECTED", "RAW")
_CRYPTO_STATES = ("VALID", "UNCHECKED", "INVALID", "NOT_APPLICABLE")
_MAX_RENDERED_FINDINGS = 5000


class _SortableItem(QTableWidgetItem):
    """Use an optional numeric sort key while keeping human-readable text."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        left = self.data(Qt.ItemDataRole.UserRole + 1)
        right = other.data(Qt.ItemDataRole.UserRole + 1)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left < right
        return super().__lt__(other)


class ResultBrowserWidget(QWidget):
    """Open, filter and inspect public BFRS report findings."""

    def __init__(self, *, language: str = DEFAULT_LANGUAGE) -> None:
        super().__init__()
        self._language = normalize_language(language)
        self._service = ResultService()
        self._report: ResultReport | None = None
        self._matching_findings: tuple[FindingView, ...] = ()
        self._visible_findings: tuple[FindingView, ...] = ()
        self._quick_profile: str | None = None

        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        self.open_button = QPushButton()
        self.open_button.clicked.connect(self._choose_report)
        self.report_label = QLabel()
        self.report_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.export_csv_button = QPushButton()
        self.export_json_button = QPushButton()
        self.export_csv_button.clicked.connect(
            lambda: self._export_matching(".csv")
        )
        self.export_json_button.clicked.connect(
            lambda: self._export_matching(".json")
        )
        top_row.addWidget(self.open_button)
        top_row.addWidget(self.export_csv_button)
        top_row.addWidget(self.export_json_button)
        top_row.addWidget(self.report_label, 1)
        layout.addLayout(top_row)

        filters = QGroupBox()
        self.filters_box = filters
        filter_layout = QFormLayout(filters)

        self.target_combo = QComboBox()
        self.state_combo = QComboBox()
        self.crypto_combo = QComboBox()
        self.search_edit = QLineEdit()

        self.target_label = QLabel()
        self.state_label = QLabel()
        self.crypto_label = QLabel()
        self.search_label = QLabel()

        filter_layout.addRow(self.target_label, self.target_combo)
        filter_layout.addRow(self.state_label, self.state_combo)
        filter_layout.addRow(self.crypto_label, self.crypto_combo)
        filter_layout.addRow(self.search_label, self.search_edit)
        layout.addWidget(filters)

        quick_row = QHBoxLayout()
        self.quick_filter_label = QLabel()
        quick_row.addWidget(self.quick_filter_label)
        self.quick_group = QButtonGroup(self)
        self.quick_group.setExclusive(True)
        self.quick_buttons: dict[str | None, QPushButton] = {}
        for profile in (None, "accepted", "review", "rejected", "crypto-valid"):
            button = QPushButton()
            button.setCheckable(True)
            if profile is None:
                button.setChecked(True)
            button.clicked.connect(
                lambda checked=False, value=profile: self._set_quick_profile(value)
            )
            self.quick_group.addButton(button)
            self.quick_buttons[profile] = button
            quick_row.addWidget(button)
        quick_row.addStretch(1)
        layout.addLayout(quick_row)

        summary_row = QHBoxLayout()
        self.summary_total = QLabel()
        self.summary_accepted = QLabel()
        self.summary_review = QLabel()
        self.summary_rejected = QLabel()
        self.summary_crypto_valid = QLabel()
        for label in (
            self.summary_total,
            self.summary_accepted,
            self.summary_review,
            self.summary_rejected,
            self.summary_crypto_valid,
        ):
            summary_row.addWidget(label)
        summary_row.addStretch(1)
        layout.addLayout(summary_row)

        self.render_notice = QLabel()
        self.render_notice.setWordWrap(True)
        layout.addWidget(self.render_notice)

        self.target_combo.currentIndexChanged.connect(self._apply_filters)
        self.state_combo.currentIndexChanged.connect(self._apply_filters)
        self.crypto_combo.currentIndexChanged.connect(self._apply_filters)
        self.search_edit.textChanged.connect(self._apply_filters)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self.table.itemSelectionChanged.connect(self._show_selected_details)
        self.table.itemSelectionChanged.connect(self._update_action_state)
        splitter.addWidget(self.table)

        self.details_box = QGroupBox()
        details_layout = QVBoxLayout(self.details_box)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        details_layout.addWidget(self.details)

        detail_actions = QHBoxLayout()
        self.copy_location_button = QPushButton()
        self.copy_offset_button = QPushButton()
        self.open_folder_button = QPushButton()
        self.copy_location_button.clicked.connect(self._copy_location)
        self.copy_offset_button.clicked.connect(self._copy_offset)
        self.open_folder_button.clicked.connect(self._open_source_folder)
        detail_actions.addWidget(self.copy_location_button)
        detail_actions.addWidget(self.copy_offset_button)
        detail_actions.addWidget(self.open_folder_button)
        detail_actions.addStretch(1)
        details_layout.addLayout(detail_actions)
        splitter.addWidget(self.details_box)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter, 1)
        self._retranslate()
        self._update_action_state()

    def set_language(self, language: str) -> None:
        self._language = normalize_language(language)
        self._retranslate()

    def _t(self, key: str, **values: object) -> str:
        return translate(self._language, key, **values)

    def _retranslate(self) -> None:
        self.open_button.setText(self._t("open_report"))
        self.export_csv_button.setText(self._t("export_csv"))
        self.export_json_button.setText(self._t("export_json"))
        self.copy_location_button.setText(self._t("copy_location"))
        self.copy_offset_button.setText(self._t("copy_offset"))
        self.open_folder_button.setText(self._t("open_source_folder"))
        self.filters_box.setTitle(self._t("results_group"))
        self.target_label.setText(self._t("filter_target"))
        self.state_label.setText(self._t("filter_state"))
        self.crypto_label.setText(self._t("filter_crypto"))
        self.search_label.setText(self._t("filter_search"))
        self.details_box.setTitle(self._t("details_group"))
        self.quick_filter_label.setText(self._t("quick_filters"))
        self.quick_buttons[None].setText(self._t("filter_all"))
        self.quick_buttons["accepted"].setText("Accepted")
        self.quick_buttons["review"].setText("Review")
        self.quick_buttons["rejected"].setText("Rejected")
        self.quick_buttons["crypto-valid"].setText("Crypto-valid")

        self._rebuild_filter_combo(
            self.state_combo,
            ((self._t("filter_all"), None),)
            + tuple((state, state) for state in _DISCOVERY_STATES),
        )
        self._rebuild_filter_combo(
            self.crypto_combo,
            ((self._t("filter_all"), None),)
            + tuple((state, state) for state in _CRYPTO_STATES),
        )
        self._rebuild_target_combo()

        headers = (
            "column_priority",
            "column_target",
            "column_artifact",
            "column_state",
            "column_crypto",
            "column_confidence",
            "column_location",
        )
        self.table.setHorizontalHeaderLabels(
            [self._t(key) for key in headers]
        )
        self.table.horizontalHeader().setStretchLastSection(True)

        if self._report is None:
            self.report_label.setText(self._t("report_not_loaded"))
            self.details.setPlainText(self._t("details_empty"))
        else:
            self.report_label.setText(
                self._t(
                    "report_loaded",
                    path=self._report.path,
                    count=self._report.finding_count,
                )
            )
            self._show_selected_details()
        self._update_summary_labels()
        self._update_action_state()

    @staticmethod
    def _rebuild_filter_combo(
        combo: QComboBox,
        entries: tuple[tuple[str, str | None], ...],
    ) -> None:
        selected = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        for label, value in entries:
            combo.addItem(label, value)
        index = combo.findData(selected)
        combo.setCurrentIndex(index if index >= 0 else 0)
        combo.blockSignals(False)

    def _rebuild_target_combo(self) -> None:
        selected = self.target_combo.currentData()
        targets = self._report.targets if self._report is not None else ()
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self.target_combo.addItem(self._t("filter_all"), None)
        for target in targets:
            self.target_combo.addItem(target, target)
        index = self.target_combo.findData(selected)
        self.target_combo.setCurrentIndex(index if index >= 0 else 0)
        self.target_combo.blockSignals(False)

    @Slot()
    def _choose_report(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            self._t("open_report_title"),
            filter="JSON (*.json)",
        )
        if path:
            self.load_report(path)

    def load_report(self, path: str | Path) -> bool:
        try:
            report = self._service.load(path)
        except ResultServiceError as error:
            QMessageBox.critical(
                self,
                self._t("report_error_title"),
                self._t("report_error", message=error),
            )
            return False

        self._report = report
        self._rebuild_target_combo()
        self.report_label.setText(
            self._t(
                "report_loaded",
                path=report.path,
                count=report.finding_count,
            )
        )
        self._quick_profile = None
        self.quick_buttons[None].setChecked(True)
        self._apply_filters()
        self._update_action_state()
        return True

    def _update_action_state(self) -> None:
        has_report = self._report is not None
        has_matches = bool(self._matching_findings)

        self.export_csv_button.setEnabled(has_report and has_matches)
        self.export_json_button.setEnabled(has_report and has_matches)

        for widget in (
            self.target_combo,
            self.state_combo,
            self.crypto_combo,
            self.search_edit,
        ):
            widget.setEnabled(has_report)
        for button in self.quick_buttons.values():
            button.setEnabled(has_report)

        finding = self._selected_finding()
        self.copy_location_button.setEnabled(
            finding is not None and bool(finding.display_location)
        )
        self.copy_offset_button.setEnabled(
            finding is not None and finding.start_offset is not None
        )
        self.open_folder_button.setEnabled(
            finding is not None and bool(finding.file_path)
        )

    def _selected_finding(self) -> FindingView | None:
        row = self.table.currentRow()
        if row < 0:
            return None
        anchor = self.table.item(row, 0)
        if anchor is None:
            return None
        index = anchor.data(Qt.ItemDataRole.UserRole)
        if not isinstance(index, int) or not (0 <= index < len(self._visible_findings)):
            return None
        return self._visible_findings[index]

    def _export_matching(self, suffix: str) -> None:
        if self._report is None:
            return
        default_name = self._report.path.with_name(
            self._report.path.stem + "-filtered" + suffix
        )
        title_key = "export_title_csv" if suffix == ".csv" else "export_title_json"
        file_filter = "CSV (*.csv)" if suffix == ".csv" else "JSON (*.json)"
        path, _ = QFileDialog.getSaveFileName(
            self,
            self._t(title_key),
            str(default_name),
            file_filter,
        )
        if not path:
            return
        if not Path(path).suffix:
            path += suffix
        try:
            output = self._service.export_findings(path, self._matching_findings)
        except (OSError, ResultServiceError, TypeError, ValueError) as error:
            QMessageBox.critical(
                self,
                self._t("report_error_title"),
                self._t("export_error", message=error),
            )
            return
        QMessageBox.information(
            self,
            self._t("results_group"),
            self._t(
                "export_success",
                count=len(self._matching_findings),
                path=output,
            ),
        )

    @Slot()
    def _copy_location(self) -> None:
        finding = self._selected_finding()
        if finding is None or not finding.display_location:
            return
        QGuiApplication.clipboard().setText(finding.display_location)
        self.render_notice.setText(self._t("location_copied"))
        self.render_notice.setVisible(True)

    @Slot()
    def _copy_offset(self) -> None:
        finding = self._selected_finding()
        if finding is None or finding.start_offset is None:
            return
        QGuiApplication.clipboard().setText(str(finding.start_offset))
        self.render_notice.setText(self._t("offset_copied"))
        self.render_notice.setVisible(True)

    @Slot()
    def _open_source_folder(self) -> None:
        finding = self._selected_finding()
        if finding is None or not finding.file_path:
            QMessageBox.information(
                self,
                self._t("results_group"),
                self._t("source_folder_unavailable"),
            )
            return
        source = Path(finding.file_path)
        folder = source if source.is_dir() else source.parent
        if not folder.exists():
            QMessageBox.information(
                self,
                self._t("results_group"),
                self._t("source_folder_unavailable"),
            )
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    @Slot()
    def _set_quick_profile(self, profile: str | None) -> None:
        self._quick_profile = profile
        self._apply_filters()

    @Slot()
    def _apply_filters(self) -> None:
        if self._report is None:
            self._matching_findings = ()
            self._visible_findings = ()
            self.table.setRowCount(0)
            self._update_summary_labels()
            self._update_action_state()
            return

        target = self.target_combo.currentData()
        state = self.state_combo.currentData()
        crypto = self.crypto_combo.currentData()

        filtered = self._service.filter(
            self._report,
            targets=({target} if target else None),
            discovery_states=({state} if state else None),
            crypto_states=({crypto} if crypto else None),
            profile=self._quick_profile,
            search=self.search_edit.text(),
        )
        self._matching_findings = self._service.prioritize(filtered)
        self._visible_findings = self._matching_findings[:_MAX_RENDERED_FINDINGS]
        self._populate_table()
        self._update_summary_labels()
        self._update_action_state()

    def _populate_table(self) -> None:
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self._visible_findings))
        for row_index, finding in enumerate(self._visible_findings):
            values = (
                finding.review_priority_label,
                finding.target,
                finding.artifact_kind,
                finding.discovery_state,
                finding.crypto_state,
                (
                    ""
                    if finding.confidence is None
                    else f"{finding.confidence:.2f}"
                ),
                finding.display_location,
            )
            for column, value in enumerate(values):
                item = _SortableItem(value)
                item.setToolTip(value)
                item.setData(Qt.ItemDataRole.UserRole, row_index)
                if column == 0:
                    item.setData(
                        Qt.ItemDataRole.UserRole + 1,
                        finding.review_priority,
                    )
                elif column == 5:
                    item.setData(
                        Qt.ItemDataRole.UserRole + 1,
                        finding.confidence if finding.confidence is not None else -1.0,
                    )
                elif column == 6:
                    item.setData(
                        Qt.ItemDataRole.UserRole + 1,
                        finding.start_offset if finding.start_offset is not None else -1,
                    )
                self.table.setItem(row_index, column, item)
        self.table.setSortingEnabled(sorting)
        self.table.resizeColumnsToContents()
        if self._visible_findings:
            self.table.selectRow(0)
        else:
            self.details.setPlainText(self._t("details_empty"))

    @Slot()
    def _show_selected_details(self) -> None:
        selected = self.table.currentRow()
        if selected < 0:
            if self._report is not None:
                self.details.setPlainText(self._t("details_empty"))
            return
        anchor = self.table.item(selected, 0)
        if anchor is None:
            self.details.setPlainText(self._t("details_empty"))
            return
        finding_index = anchor.data(Qt.ItemDataRole.UserRole)
        if not isinstance(finding_index, int) or not (
            0 <= finding_index < len(self._visible_findings)
        ):
            self.details.setPlainText(self._t("details_empty"))
            return

        finding = self._visible_findings[finding_index]
        metadata = json.dumps(
            dict(finding.safe_metadata),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        reasons = ", ".join(finding.reason_codes) or "-"
        lines = [
            f"{self._t('column_priority')}: {finding.review_priority_label}",
            f"{self._t('column_target')}: {finding.target}",
            f"{self._t('column_artifact')}: {finding.artifact_kind}",
            f"{self._t('column_state')}: {finding.discovery_state}",
            f"{self._t('column_crypto')}: {finding.crypto_state}",
            f"{self._t('structural_status')}: {finding.structural_status or '-'}",
            f"{self._t('validation_status')}: {finding.validation_status or '-'}",
            f"{self._t('column_location')}: {finding.display_location or '-'}",
            f"{self._t('reason_codes')}: {reasons}",
            (
                f"{self._t('recovery_action')}: "
                f"{finding.recommended_recovery_action or '-'}"
            ),
            "",
            f"{self._t('safe_metadata')}:",
            metadata,
        ]
        self.details.setPlainText("\n".join(lines))


    def _update_summary_labels(self) -> None:
        if self._report is None:
            displayed = accepted = review = rejected = crypto_valid = 0
        else:
            summary = self._service.summary(self._report)
            displayed = len(self._matching_findings)
            accepted = summary.accepted
            review = summary.review
            rejected = summary.rejected
            crypto_valid = summary.crypto_valid
        self.summary_total.setText(self._t("summary_total", count=displayed))
        self.summary_accepted.setText(
            self._t("summary_accepted", count=accepted)
        )
        self.summary_review.setText(self._t("summary_review", count=review))
        self.summary_rejected.setText(
            self._t("summary_rejected", count=rejected)
        )
        self.summary_crypto_valid.setText(
            self._t("summary_crypto_valid", count=crypto_valid)
        )
        matching = len(self._matching_findings)
        shown = len(self._visible_findings)
        if matching > shown:
            self.render_notice.setText(
                self._t("render_limit", shown=shown, matching=matching)
            )
            self.render_notice.setVisible(True)
        else:
            self.render_notice.clear()
            self.render_notice.setVisible(False)
