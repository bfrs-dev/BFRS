import json

import pytest

from bfrs.application.scan_config import ScanConfig
from bfrs.application.scan_events import (
    ScanCompletedEvent,
    ScanFailedEvent,
    ScanStartedEvent,
    ScanStoppedEvent,
)
from bfrs.application.scan_service import (
    ScanService,
    ScanServiceError,
    build_cli_arguments,
)
from bfrs.core.source_types import SourceType


def config(tmp_path, **overrides):
    source = tmp_path / "source.img"
    source.write_bytes(b"synthetic")
    values = {
        "input_path": source,
        "output_path": tmp_path / "report.json",
    }
    values.update(overrides)
    return ScanConfig(**values)


def test_cli_adapter_maps_current_scan_contract_deterministically(tmp_path):
    value = config(
        tmp_path,
        source_type=SourceType.IMAGE,
        end=8,
        targets=frozenset({"electrum", "bitcoin-core"}),
        include_mnemonic=True,
        include_bitcoin_context=True,
        workers=2,
        checkpoint=tmp_path / "checkpoint.json",
    )

    arguments = build_cli_arguments(value)

    assert arguments[:4] == [
        "--input", str(value.input_path),
        "--output", str(value.output_path),
    ]
    assert arguments[arguments.index("--source-type") + 1] == "image"
    assert arguments[arguments.index("--targets") + 1] == "bitcoin-core,electrum"
    assert "--include-mnemonic" in arguments
    assert "--include-bitcoin-context" in arguments
    assert arguments[arguments.index("--workers") + 1] == "2"
    assert arguments[arguments.index("--checkpoint") + 1] == str(value.checkpoint)


def test_cli_adapter_maps_revalidation_and_recovery_paths(tmp_path):
    recovery = config(
        tmp_path,
        recover_wallets=True,
        recovery_dir=tmp_path / "recovered",
    )
    recovery_args = build_cli_arguments(recovery)
    assert "--recover-wallets" in recovery_args
    assert recovery_args[recovery_args.index("--recovery-dir") + 1] == str(
        recovery.recovery_dir
    )

    old_report = tmp_path / "old.json"
    revalidation = config(tmp_path, revalidate_wallet_records=old_report)
    revalidation_args = build_cli_arguments(revalidation)
    assert revalidation_args[
        revalidation_args.index("--revalidate-wallet-records") + 1
    ] == str(old_report)


def test_cli_adapter_rejects_unknown_targets_before_execution(tmp_path):
    value = config(tmp_path, targets=frozenset({"bitcoin-core", "unknown"}))

    with pytest.raises(ScanServiceError, match="unknown scan target"):
        build_cli_arguments(value)


def test_service_emits_started_and_completed_events(tmp_path):
    events = []
    value = config(tmp_path)

    def runner(arguments):
        value.output_path.write_text(json.dumps({
            "status": "rejected",
            "scan_range": {"start_offset": 0, "end_offset": 9},
        }), encoding="utf-8")
        return 0

    result = ScanService(event_sink=events.append, cli_runner=runner).run(value)

    assert result.completed is True
    assert result.status == "rejected"
    assert isinstance(events[0], ScanStartedEvent)
    assert events[0].source_type is SourceType.IMAGE
    assert isinstance(events[-1], ScanCompletedEvent)
    assert events[-1].processed_bytes == 9
    assert events[-1].total_bytes == 9


def test_service_accepts_seed_report_range_shape(tmp_path):
    events = []
    value = config(tmp_path)

    def runner(arguments):
        value.output_path.write_text(json.dumps({
            "range": {"start": 2, "end": 8},
            "mnemonic_recovery": {},
        }), encoding="utf-8")
        return 0

    result = ScanService(event_sink=events.append, cli_runner=runner).run(value)

    assert result.status == "completed"
    completed = events[-1]
    assert isinstance(completed, ScanCompletedEvent)
    assert completed.processed_bytes == 6
    assert completed.total_bytes == 6


def test_service_allows_completion_when_report_metadata_is_unavailable(tmp_path):
    events = []
    value = config(tmp_path)

    result = ScanService(
        event_sink=events.append,
        cli_runner=lambda arguments: 0,
    ).run(value)

    completed = events[-1]
    assert isinstance(completed, ScanCompletedEvent)
    assert completed.status == "completed"
    assert completed.processed_bytes is None
    assert completed.total_bytes is None


def test_service_maps_interrupt_exit_to_stopped_event(tmp_path):
    events = []
    checkpoint = tmp_path / "checkpoint.json"
    value = config(tmp_path, checkpoint=checkpoint)

    result = ScanService(
        event_sink=events.append,
        cli_runner=lambda arguments: 130,
    ).run(value)

    assert result.status == "stopped"
    assert isinstance(events[-1], ScanStoppedEvent)
    assert events[-1].checkpoint_path == checkpoint


def test_service_maps_controlled_nonzero_exit_to_failed_event(tmp_path):
    events = []
    value = config(tmp_path)

    result = ScanService(
        event_sink=events.append,
        cli_runner=lambda arguments: 3,
    ).run(value)

    assert result.status == "failed"
    assert isinstance(events[-1], ScanFailedEvent)
    assert events[-1].recoverable is True


def test_service_emits_failure_and_reraises_backend_exception(tmp_path):
    events = []
    value = config(tmp_path)

    def runner(arguments):
        raise RuntimeError("synthetic backend failure")

    with pytest.raises(RuntimeError, match="synthetic backend failure"):
        ScanService(event_sink=events.append, cli_runner=runner).run(value)

    assert isinstance(events[-1], ScanFailedEvent)
    assert events[-1].error_type == "RuntimeError"


def test_service_rejects_explicit_folder_type_for_regular_file(tmp_path):
    events = []
    value = config(tmp_path, source_type=SourceType.FOLDER)

    with pytest.raises(ScanServiceError, match="requires a directory"):
        ScanService(
            event_sink=events.append,
            cli_runner=lambda arguments: 0,
        ).run(value)

    assert len(events) == 1
    assert isinstance(events[0], ScanFailedEvent)
