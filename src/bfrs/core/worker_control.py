"""Bounded scheduling and explicit diagnostics for process-backed work."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, wait
from concurrent.futures.process import BrokenProcessPool
import os
import time
from typing import TypeVar


PROCESS_POLL_INTERVAL_SECONDS = 1.0
PROCESS_STALL_THRESHOLD_SECONDS = 30.0 * 60.0
PROCESS_IN_FLIGHT_MULTIPLIER = 2
PROCESS_WORKER_HARD_LIMIT = 32

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")


class WorkerControlError(RuntimeError):
    """Base class for a controlled failure in process-backed work."""


class WorkerStallError(WorkerControlError):
    """No submitted unit completed within the conservative threshold."""


class WorkerExecutionError(WorkerControlError):
    """A worker failed while processing an identified unit."""


class WorkerPoolBrokenError(WorkerExecutionError):
    """The process pool terminated unexpectedly."""


def safe_worker_limit(cpu_count: int | None = None) -> int:
    """Return a CPU-derived limit with room for ordinary 1/2/4 settings."""
    cpus = os.cpu_count() if cpu_count is None else cpu_count
    return min(PROCESS_WORKER_HARD_LIMIT, max(4, max(cpus or 1, 1) * 2))


def validate_worker_count(workers: int) -> int:
    """Validate a requested worker count; zero continues to mean auto."""
    if workers < 0:
        raise ValueError("workers must be nonnegative")
    limit = safe_worker_limit()
    if workers > limit:
        raise ValueError(
            f"workers must not exceed safe limit {limit} "
            f"(CPU-derived, hard cap {PROCESS_WORKER_HARD_LIMIT})"
        )
    return workers


def maximum_in_flight(workers: int) -> int:
    return max(1, workers * PROCESS_IN_FLIGHT_MULTIPLIER)


def abort_executor(executor, futures: Iterable[Future] = ()) -> None:
    """Cancel queued work and return without waiting for a damaged worker."""
    for future in tuple(futures):
        future.cancel()
    terminate_workers = getattr(executor, "terminate_workers", None)
    if callable(terminate_workers):
        try:
            terminate_workers()
            return
        except Exception:
            # Preserve the original failure and fall back to nonblocking shutdown.
            pass
    try:
        executor.shutdown(wait=False, cancel_futures=True)
    except Exception:
        # Cleanup must not hide the original worker/interrupt traceback.
        pass


def submit_process_future(executor, function, *args, operation: str,
                          unit_id: str) -> Future:
    """Submit work with a controlled diagnostic for an already-broken pool."""
    try:
        return executor.submit(function, *args)
    except BrokenProcessPool as error:
        raise WorkerPoolBrokenError(
            f"{operation} process pool terminated while submitting {unit_id}"
        ) from error
    except (BrokenPipeError, EOFError) as error:
        raise WorkerPoolBrokenError(
            f"{operation} worker communication failed while submitting {unit_id}: "
            f"{type(error).__name__}"
        ) from error


def _result_or_diagnostic(future: Future[_Result], *, operation: str,
                          unit_id: str) -> _Result:
    try:
        return future.result()
    except BrokenProcessPool as error:
        raise WorkerPoolBrokenError(
            f"{operation} process pool terminated unexpectedly while processing "
            f"{unit_id}"
        ) from error
    except (BrokenPipeError, EOFError) as error:
        raise WorkerPoolBrokenError(
            f"{operation} worker communication failed while processing {unit_id}: "
            f"{type(error).__name__}"
        ) from error
    except Exception as error:
        raise WorkerExecutionError(
            f"{operation} worker failed while processing {unit_id}: "
            f"{type(error).__name__}: {error}"
        ) from error


def _stall_message(operation: str, unit_ids: Iterable[str],
                   threshold: float) -> str:
    identifiers = ", ".join(sorted(unit_ids))
    return (
        f"{operation} made no completed-unit progress for {threshold:g} seconds; "
        f"in-flight: {identifiers}"
    )


def wait_for_single_future(
    future: Future[_Result], *, operation: str, unit_id: str,
    poll_interval: float | None = None, stall_threshold: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    waiter: Callable[..., tuple[set[Future], set[Future]]] = wait,
) -> _Result:
    """Poll one future so a non-progressing branch cannot wait forever."""
    poll = PROCESS_POLL_INTERVAL_SECONDS if poll_interval is None else poll_interval
    threshold = (PROCESS_STALL_THRESHOLD_SECONDS
                 if stall_threshold is None else stall_threshold)
    last_completion = clock()
    while True:
        done, _ = waiter({future}, timeout=poll, return_when=FIRST_COMPLETED)
        if done:
            return _result_or_diagnostic(
                future, operation=operation, unit_id=unit_id)
        if clock() - last_completion >= threshold:
            raise WorkerStallError(
                _stall_message(operation, (unit_id,), threshold))


def wait_for_all_futures(
    futures: Sequence[tuple[Future[_Result], str]], *, operation: str,
    poll_interval: float | None = None, stall_threshold: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    waiter: Callable[..., tuple[set[Future], set[Future]]] = wait,
) -> list[_Result]:
    """Poll a small fixed set and return results in submission order."""
    if not futures:
        return []
    poll = PROCESS_POLL_INTERVAL_SECONDS if poll_interval is None else poll_interval
    threshold = (PROCESS_STALL_THRESHOLD_SECONDS
                 if stall_threshold is None else stall_threshold)
    pending = {future: (index, unit_id)
               for index, (future, unit_id) in enumerate(futures)}
    results: list[_Result | None] = [None] * len(futures)
    last_completion = clock()
    while pending:
        done, _ = waiter(set(pending), timeout=poll, return_when=FIRST_COMPLETED)
        if done:
            last_completion = clock()
            for future in done:
                index, unit_id = pending.pop(future)
                results[index] = _result_or_diagnostic(
                    future, operation=operation, unit_id=unit_id)
            continue
        if clock() - last_completion >= threshold:
            raise WorkerStallError(_stall_message(
                operation, (unit_id for _, unit_id in pending.values()), threshold))
    return results  # type: ignore[return-value]


def iter_bounded_results(
    executor,
    items: Iterable[_Item],
    *,
    submit: Callable[[object, _Item], Future[_Result]],
    unit_id: Callable[[_Item], str],
    workers: int,
    operation: str,
    poll_interval: float | None = None,
    stall_threshold: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    waiter: Callable[..., tuple[set[Future], set[Future]]] = wait,
) -> Iterator[tuple[_Item, _Result]]:
    """Lazily keep at most ``2 * workers`` futures submitted at once."""
    poll = PROCESS_POLL_INTERVAL_SECONDS if poll_interval is None else poll_interval
    threshold = (PROCESS_STALL_THRESHOLD_SECONDS
                 if stall_threshold is None else stall_threshold)
    source = iter(items)
    pending: dict[Future[_Result], tuple[_Item, str]] = {}
    exhausted = False

    def fill() -> None:
        nonlocal exhausted
        while not exhausted and len(pending) < maximum_in_flight(workers):
            try:
                item = next(source)
            except StopIteration:
                exhausted = True
                return
            identifier = unit_id(item)
            try:
                future = submit(executor, item)
            except BrokenProcessPool as error:
                raise WorkerPoolBrokenError(
                    f"{operation} process pool terminated while submitting "
                    f"{identifier}"
                ) from error
            except (BrokenPipeError, EOFError) as error:
                raise WorkerPoolBrokenError(
                    f"{operation} worker communication failed while submitting "
                    f"{identifier}: {type(error).__name__}"
                ) from error
            pending[future] = (item, identifier)

    fill()
    last_completion = clock()
    while pending:
        done, _ = waiter(set(pending), timeout=poll, return_when=FIRST_COMPLETED)
        if not done:
            if clock() - last_completion >= threshold:
                raise WorkerStallError(_stall_message(
                    operation,
                    (identifier for _, identifier in pending.values()),
                    threshold,
                ))
            continue
        last_completion = clock()
        for future in done:
            item, identifier = pending.pop(future)
            yield item, _result_or_diagnostic(
                future, operation=operation, unit_id=identifier)
        fill()
