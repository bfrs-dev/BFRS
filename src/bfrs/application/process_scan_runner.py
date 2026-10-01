"""Process-isolated scan runner for resilient desktop execution."""

from __future__ import annotations

from dataclasses import dataclass
import multiprocessing
from multiprocessing.context import BaseContext
from pathlib import Path
import queue
import threading
from typing import Callable

from bfrs.application.scan_config import ScanConfig
from bfrs.application.scan_events import ScanEvent, ScanFailedEvent
from bfrs.application.scan_service import ScanController, ScanRunResult, ScanService


EventSink = Callable[[ScanEvent], None]


class ProcessScanError(RuntimeError):
    """The isolated scan worker could not complete normally."""


class _ProcessController(ScanController):
    """ScanController-compatible adapter backed by a multiprocessing Event."""

    def __init__(self, stop_event) -> None:
        self._process_stop_event = stop_event

    def request_stop(self) -> None:
        self._process_stop_event.set()

    def reset_stop(self) -> None:
        self._process_stop_event.clear()

    @property
    def stop_requested(self) -> bool:
        return self._process_stop_event.is_set()

    def should_stop(self) -> bool:
        return self._process_stop_event.is_set()


def _worker_entry(config: ScanConfig, messages, stop_event) -> None:
    """Run one ScanService in a spawned child and emit picklable messages."""
    controller = _ProcessController(stop_event)

    def emit(event: ScanEvent) -> None:
        messages.put(("event", event))

    try:
        result = ScanService(
            event_sink=emit,
            controller=controller,
        ).run(config)
    except BaseException as error:
        messages.put((
            "error",
            type(error).__name__,
            str(error) or type(error).__name__,
        ))
        return

    messages.put(("result", result))


@dataclass(frozen=True, slots=True)
class ProcessScanState:
    """Observable parent-side state for one isolated worker."""

    pid: int | None
    running: bool


class ProcessScanRunner:
    """Supervise one ScanService running in a separate spawned process.

    The runner itself is synchronous by design and is intended to be hosted by
    the existing GUI QThread. This keeps Qt out of the child process while
    moving scanning, parsers, and scanner worker pools outside the GUI process.
    """

    def __init__(
        self,
        *,
        event_sink: EventSink | None = None,
        context: BaseContext | None = None,
        poll_seconds: float = 0.05,
        worker_entry: Callable | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be greater than zero")
        self._event_sink = event_sink
        self._context = context or multiprocessing.get_context("spawn")
        self._poll_seconds = poll_seconds
        self._worker_entry = worker_entry or _worker_entry
        self._should_stop = should_stop
        self._lock = threading.Lock()
        self._process = None
        self._stop_event = None

    @property
    def state(self) -> ProcessScanState:
        with self._lock:
            process = self._process
            return ProcessScanState(
                pid=(process.pid if process is not None else None),
                running=bool(process is not None and process.is_alive()),
            )

    def request_stop(self) -> None:
        """Request cooperative stop at the next engine safe boundary."""
        with self._lock:
            stop_event = self._stop_event
        if stop_event is not None:
            stop_event.set()

    def run(self, config: ScanConfig) -> ScanRunResult:
        """Run one isolated scan and relay its public application events."""
        with self._lock:
            if self._process is not None:
                raise ProcessScanError("process scan runner is already active")

            messages = self._context.Queue()
            stop_event = self._context.Event()
            process = self._context.Process(
                target=self._worker_entry,
                args=(config, messages, stop_event),
                name="bfrs-scan-worker",
            )
            self._process = process
            self._stop_event = stop_event

        result: ScanRunResult | None = None
        worker_error: tuple[str, str] | None = None

        try:
            process.start()

            while True:
                if self._should_stop is not None and self._should_stop():
                    stop_event.set()

                try:
                    message = messages.get(timeout=self._poll_seconds)
                except queue.Empty:
                    if not process.is_alive():
                        break
                    continue

                if self._should_stop is not None and self._should_stop():
                    stop_event.set()

                kind = message[0]
                if kind == "event":
                    event = message[1]
                    if self._event_sink is not None:
                        self._event_sink(event)
                elif kind == "result":
                    result = message[1]
                    break
                elif kind == "error":
                    worker_error = (str(message[1]), str(message[2]))
                    break
                else:
                    worker_error = (
                        "ProcessProtocolError",
                        f"unknown worker message: {kind!r}",
                    )
                    break

            process.join(timeout=5.0)
            if process.is_alive():
                raise ProcessScanError(
                    "isolated scan worker did not exit after completion"
                )

            # Drain messages queued immediately before child exit.
            while result is None and worker_error is None:
                try:
                    message = messages.get_nowait()
                except queue.Empty:
                    break
                kind = message[0]
                if kind == "event":
                    if self._event_sink is not None:
                        self._event_sink(message[1])
                elif kind == "result":
                    result = message[1]
                elif kind == "error":
                    worker_error = (str(message[1]), str(message[2]))

            if worker_error is not None:
                error_type, message = worker_error
                raise ProcessScanError(
                    f"{error_type}: {message}"
                )

            if result is None:
                exit_code = process.exitcode
                event = ScanFailedEvent(
                    message=(
                        "isolated scan worker exited unexpectedly "
                        f"(process exit code {exit_code})"
                    ),
                    error_type="ProcessExit",
                    recoverable=True,
                )
                if self._event_sink is not None:
                    self._event_sink(event)
                raise ProcessScanError(event.message)

            return result
        finally:
            with self._lock:
                self._process = None
                self._stop_event = None
            try:
                messages.close()
                messages.join_thread()
            except (AttributeError, OSError, ValueError):
                pass
