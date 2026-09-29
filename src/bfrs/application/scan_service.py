"""Application service bridging front ends to the current BFRS scan engine."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Protocol

from bfrs.application.scan_config import ScanConfig
from bfrs.application.scan_events import (
    ScanCompletedEvent,
    ScanEvent,
    ScanFailedEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
)
from bfrs.core.source_types import SourceType, detect_source_type
from bfrs.scanners.target_registry import AVAILABLE_TARGETS


EventSink = Callable[[ScanEvent], None]
CliRunner = Callable[[list[str]], int]


class ScanServiceError(RuntimeError):
    """The application service could not execute a scan request."""


@dataclass(frozen=True, slots=True)
class ScanRunResult:
    """Presentation-neutral outcome of one scan-service invocation."""

    exit_code: int
    report_path: Path
    status: str

    @property
    def completed(self) -> bool:
        return self.exit_code == 0


class ScanService:
    """Run a validated ScanConfig and publish GUI-independent lifecycle events.

    During the GUI-foundation migration the default backend delegates to the
    existing CLI engine.  This preserves the current, heavily-tested scan
    behavior while front ends move behind one application contract.  The CLI
    adapter is intentionally isolated so it can be replaced by a direct engine
    backend without changing GUI callers.
    """

    def __init__(
        self,
        *,
        event_sink: EventSink | None = None,
        cli_runner: CliRunner | None = None,
    ) -> None:
        self._event_sink = event_sink
        self._cli_runner = cli_runner or _run_current_cli

    def run(self, config: ScanConfig) -> ScanRunResult:
        source_type = self._resolve_source_type(config)
        self._emit(ScanStartedEvent(
            input_path=config.input_path,
            output_path=config.output_path,
            source_type=source_type,
            start=config.start,
            end=config.end,
        ))

        try:
            exit_code = self._cli_runner(build_cli_arguments(config))
        except KeyboardInterrupt:
            self._emit(ScanStoppedEvent(
                processed_bytes=0,
                checkpoint_path=config.checkpoint_path,
                reason="keyboard_interrupt",
            ))
            raise
        except Exception as error:
            self._emit(ScanFailedEvent(
                message=str(error) or type(error).__name__,
                error_type=type(error).__name__,
                recoverable=False,
            ))
            raise

        if exit_code == 130:
            self._emit(ScanStoppedEvent(
                processed_bytes=0,
                checkpoint_path=config.checkpoint_path,
                reason="user_requested",
            ))
            return ScanRunResult(exit_code, config.output_path, "stopped")

        if exit_code != 0:
            self._emit(ScanFailedEvent(
                message=f"BFRS scan exited with code {exit_code}",
                error_type="ScanExitCode",
                recoverable=exit_code in {3, 4},
            ))
            return ScanRunResult(exit_code, config.output_path, "failed")

        status, processed_bytes, total_bytes = _read_completion_metadata(
            config.output_path
        )
        self._emit(ScanCompletedEvent(
            report_path=config.output_path,
            status=status,
            processed_bytes=processed_bytes,
            total_bytes=total_bytes,
        ))
        return ScanRunResult(exit_code, config.output_path, status)

    def _resolve_source_type(self, config: ScanConfig) -> SourceType:
        explicit = (
            config.source_type.value.casefold()
            if config.source_type is not None else None
        )
        try:
            return detect_source_type(config.input_path, explicit)
        except ValueError as error:
            self._emit(ScanFailedEvent(
                message=str(error),
                error_type=type(error).__name__,
                recoverable=True,
            ))
            raise ScanServiceError(str(error)) from error

    def _emit(self, event: ScanEvent) -> None:
        if self._event_sink is not None:
            self._event_sink(event)


def build_cli_arguments(config: ScanConfig) -> list[str]:
    """Translate one ScanConfig into deterministic arguments for current CLI."""

    arguments = [
        "--input", str(config.input_path),
        "--output", str(config.output_path),
        "--start", str(config.start),
        "--chunk-mib", str(config.chunk_mib),
        "--overlap-kib", str(config.overlap_kib),
        "--workers", str(config.workers),
        "--file-workers", str(config.file_workers),
        "--cluster-mib", str(config.cluster_mib),
        "--padding-mib", str(config.padding_mib),
        "--minimum-hits", str(config.minimum_hits),
        "--minimum-distinct-types", str(config.minimum_distinct_types),
    ]

    if config.source_type is not None:
        arguments.extend(("--source-type", config.source_type.value.casefold()))
    if config.end is not None:
        arguments.extend(("--end", str(config.end)))
    if config.targets is not None:
        ordered = [
            target for target in AVAILABLE_TARGETS if target in config.targets
        ]
        unknown = sorted(set(config.targets) - set(AVAILABLE_TARGETS))
        if unknown:
            raise ScanServiceError(
                "unknown scan target(s): " + ", ".join(unknown)
            )
        arguments.extend(("--targets", ",".join(ordered)))
    if config.electrum_only:
        arguments.append("--electrum-only")
    if config.seed_scan_only:
        arguments.append("--seed-scan-only")
    if config.include_mnemonic:
        arguments.append("--include-mnemonic")
    if config.include_bitcoin_context:
        arguments.append("--include-bitcoin-context")
    if config.skip_mnemonic:
        arguments.append("--skip-mnemonic")
    if config.recover_wallets:
        arguments.append("--recover-wallets")
    if config.recovery_dir is not None:
        arguments.extend(("--recovery-dir", str(config.recovery_dir)))
    if config.revalidate_wallet_records is not None:
        arguments.extend((
            "--revalidate-wallet-records",
            str(config.revalidate_wallet_records),
        ))
    if config.checkpoint is not None:
        arguments.extend(("--checkpoint", str(config.checkpoint)))
    if config.resume_checkpoint is not None:
        arguments.extend(("--resume-checkpoint", str(config.resume_checkpoint)))

    return arguments


def _run_current_cli(arguments: list[str]) -> int:
    # Delayed import keeps the application contract independent at import time
    # and makes the temporary CLI adapter easy to remove in the next migration.
    from bfrs.cli import main

    return main(arguments)


def _read_completion_metadata(
    report_path: Path,
) -> tuple[str, int | None, int | None]:
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "completed", None, None
    if not isinstance(payload, dict):
        return "completed", None, None

    status = payload.get("status")
    if not isinstance(status, str) or not status:
        status = "completed"

    scan_range = payload.get("scan_range")
    if not isinstance(scan_range, dict):
        scan_range = payload.get("range")
    if not isinstance(scan_range, dict):
        return status, None, None

    start = scan_range.get("start_offset", scan_range.get("start"))
    end = scan_range.get("end_offset", scan_range.get("end"))
    if not isinstance(start, int) or not isinstance(end, int) or end < start:
        return status, None, None
    total = end - start
    return status, total, total
