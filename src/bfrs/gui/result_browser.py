"""Qt result browser backed by the presentation-neutral ResultService."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt, Slot
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
        top_row.addWidget(self.open_button)
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

        self.target_combo.currentIndexChanged.connect(self._apply_filters)
        self.state_combo.currentIndexChanged.connect(self._apply_filters)
        self.crypto_combo.currentIndexChanged.connect(self._apply_filters)
        self.search_edit.textChanged.connect(self._apply_filters)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 6)
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
        self.table.itemSelectionChanged.connect(self._show_selected_details)
        splitter.addWidget(self.table)

        self.details_box = QGroupBox()
        details_layout = QVBoxLayout(self.details_box)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        details_layout.addWidget(self.details)
        splitter.addWidget(self.details_box)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter, 1)
        self._retranslate()

    def set_language(self, language: str) -> None:
        self._language = normalize_language(language)
        self._retranslate()

    def _t(self, key: str, **values: object) -> str:
        return translate(self._language, key, **values)

    def _retranslate(self) -> None:
        self.open_button.setText(self._t("open_report"))
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
        return True

    @Slot()
    def _set_quick_profile(self, profile: str | None) -> None:
        self._quick_profile = profile
        self._apply_filters()

    @Slot()
    def _apply_filters(self) -> None:
        if self._report is None:
            self._visible_findings = ()
            self.table.setRowCount(0)
            self._update_summary_labels()
            return

        target = self.target_combo.currentData()
        state = self.state_combo.currentData()
        crypto = self.crypto_combo.currentData()

        self._visible_findings = self._service.filter(
            self._report,
            targets=({target} if target else None),
            discovery_states=({state} if state else None),
            crypto_states=({crypto} if crypto else None),
            profile=self._quick_profile,
            search=self.search_edit.text(),
        )
        self._populate_table()
        self._update_summary_labels()

    def _populate_table(self) -> None:
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self._visible_findings))
        for row_index, finding in enumerate(self._visible_findings):
            values = (
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
                if column == 4:
                    item.setData(
                        Qt.ItemDataRole.UserRole + 1,
                        finding.confidence if finding.confidence is not None else -1.0,
                    )
                elif column == 5:
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
            displayed = len(self._visible_findings)
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
