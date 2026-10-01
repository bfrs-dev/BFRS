"""Qt worker that keeps scans off the GUI event loop."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from bfrs.application import ScanConfig, ScanController
from bfrs.application.process_scan_runner import ProcessScanRunner


class ScanWorker(QObject):
    """Supervise one process-isolated ScanService run from a QThread."""

    event = Signal(object)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(
        self,
        config: ScanConfig,
        controller: ScanController,
    ) -> None:
        super().__init__()
        self._config = config
        self._controller = controller

    @Slot()
    def run(self) -> None:
        runner = ProcessScanRunner(
            event_sink=self.event.emit,
            should_stop=self._controller.should_stop,
        )
        try:
            result = runner.run(self._config)
        except Exception as error:
            self.failed.emit(
                f"{type(error).__name__}: {error or 'nieznany błąd'}"
            )
            return
        self.finished.emit(result)
