from concurrent.futures import Future
from concurrent.futures.process import BrokenProcessPool
import pickle

import pytest

from bfrs.cli import main
from bfrs.core.worker_control import (
    WorkerExecutionError,
    WorkerPoolBrokenError,
    WorkerStallError,
    abort_executor,
    iter_bounded_results,
    maximum_in_flight,
    safe_worker_limit,
    validate_worker_count,
    wait_for_all_futures,
    wait_for_single_future,
)
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import (
    _initialize_worker,
    _scan_phase_work_unit,
    _scan_work_unit,
)
from bfrs.scanners.target_registry import (
    _initialize_mnemonic_branch,
    _scan_mnemonic_branch,
)


class _ManualExecutor:
    def __init__(self):
        self.shutdown_calls = []

    def submit(self, function, item):
        future = Future()
        future.item = item
        return future

    def shutdown(self, *, wait, cancel_futures=False):
        self.shutdown_calls.append((wait, cancel_futures))


def test_bounded_scheduler_is_lazy_and_refills_after_each_success():
    executor = _ManualExecutor()
    consumed = 0
    maximum_seen = 0

    def items():
        nonlocal consumed
        for value in range(300):
            consumed += 1
            yield value

    def waiter(futures, **unused):
        nonlocal maximum_seen
        maximum_seen = max(maximum_seen, len(futures))
        future = min(futures, key=lambda item: item.item)
        future.set_result(future.item * 2)
        return {future}, set(futures) - {future}

    observed = list(iter_bounded_results(
        executor,
        items(),
        submit=lambda pool, item: pool.submit(None, item),
        unit_id=lambda item: f"unit[{item}]",
        workers=2,
        operation="test scan",
        waiter=waiter,
    ))

    assert consumed == 300
    assert [result for _, result in observed] == [value * 2 for value in range(300)]
    assert maximum_seen == maximum_in_flight(2) == 4


def test_worker_exception_has_unit_diagnostic_and_preserves_cause():
    future = Future()
    cause = ValueError("synthetic failure")
    future.set_exception(cause)
    with pytest.raises(WorkerExecutionError, match=r"phase\[7\].*ValueError") as raised:
        wait_for_single_future(
            future, operation="test scan", unit_id="phase[7]")
    assert raised.value.__cause__ is cause


def test_broken_process_pool_has_explicit_diagnostic():
    future = Future()
    cause = BrokenProcessPool("synthetic terminated worker")
    future.set_exception(cause)
    with pytest.raises(WorkerPoolBrokenError, match="terminated unexpectedly") as raised:
        wait_for_single_future(
            future, operation="test scan", unit_id="unit[9]")
    assert raised.value.__cause__ is cause


def test_stall_detection_uses_injected_clock_without_wall_clock_wait():
    future = Future()
    times = iter((0.0, 1.0, 2.0, 3.0))

    with pytest.raises(WorkerStallError, match=r"unit\[stalled\].*|in-flight"):
        wait_for_single_future(
            future,
            operation="test scan",
            unit_id="unit[stalled]",
            poll_interval=1.0,
            stall_threshold=3.0,
            clock=lambda: next(times),
            waiter=lambda futures, **unused: (set(), set(futures)),
        )


def test_keyboard_interrupt_is_not_wrapped():
    future = Future()

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        wait_for_single_future(
            future, operation="test scan", unit_id="unit[1]", waiter=interrupt)


def test_wait_for_all_preserves_submission_order_after_out_of_order_completion():
    first = Future()
    second = Future()
    calls = 0

    def waiter(futures, **unused):
        nonlocal calls
        calls += 1
        selected = second if calls == 1 else first
        selected.set_result("second" if selected is second else "first")
        return {selected}, set(futures) - {selected}

    assert wait_for_all_futures(
        [(first, "phase[first]"), (second, "phase[second]")],
        operation="test phases",
        waiter=waiter,
    ) == ["first", "second"]


def test_abort_uses_public_nonblocking_shutdown_and_cancels_queued_future():
    executor = _ManualExecutor()
    future = Future()
    abort_executor(executor, (future,))
    assert future.cancelled()
    assert executor.shutdown_calls == [(False, True)]


def test_abort_prefers_public_worker_termination_when_available():
    class TerminatingExecutor(_ManualExecutor):
        def __init__(self):
            super().__init__()
            self.terminated = False

        def terminate_workers(self):
            self.terminated = True

    executor = TerminatingExecutor()
    abort_executor(executor)
    assert executor.terminated is True
    assert executor.shutdown_calls == []


@pytest.mark.parametrize("workers", (1, 2, 4))
def test_normal_worker_counts_are_accepted(workers):
    assert validate_worker_count(workers) == workers


def test_absurd_worker_count_is_rejected(monkeypatch):
    monkeypatch.setattr("bfrs.core.worker_control.os.cpu_count", lambda: 2)
    assert safe_worker_limit() == 4
    with pytest.raises(ValueError, match="safe limit 4"):
        validate_worker_count(1000)


def test_cli_rejects_absurd_worker_count_before_scan(tmp_path, capsys):
    source = tmp_path / "synthetic.bin"
    source.write_bytes(b"synthetic input")
    with pytest.raises(SystemExit) as raised:
        main([
            "--input", str(source),
            "--output", str(tmp_path / "report.json"),
            "--workers", "1000",
        ])
    assert raised.value.code == 2
    assert "workers must not exceed safe limit" in capsys.readouterr().err


@pytest.mark.parametrize(
    "worker_function",
    (_initialize_worker, _scan_work_unit, _scan_phase_work_unit,
     _initialize_mnemonic_branch, _scan_mnemonic_branch),
)
def test_process_entry_points_are_picklable_for_spawn(worker_function):
    assert pickle.loads(pickle.dumps(worker_function)) is worker_function
