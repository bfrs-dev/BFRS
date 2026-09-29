"""Qt worker that keeps scans off the GUI event loop."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal, Slot

from bfrs.application import ScanConfig, ScanController, ScanService


class ScanWorker(QObject):
    """Execute one ScanService run inside a dedicated QThread."""

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
        service = ScanService(
            event_sink=self.event.emit,
            controller=self._controller,
        )
        try:
            result = service.run(self._config)
        except Exception as error:
            self.failed.emit(
                f"{type(error).__name__}: {error or 'nieznany błąd'}"
            )
            return
        self.finished.emit(result)
