"""Recursive regular-file source orchestration for P2.7."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import uuid
from typing import Callable, Iterator, Mapping, Sequence

from bfrs.recovery.automatic_wallet_recovery import (
    recover_intact_wallet,
    recover_wallets,
    recovery_not_requested,
    validate_recovery_destination,
)
from bfrs.reporting.json_report import REPORT_SCHEMA_VERSION
from bfrs.scanners.fast_scanner import ScanProgress
from bfrs.scanners.folder_scan_checkpoint import (
    FolderCheckpointError,
    FolderScanCheckpoint,
    folder_snapshot_digest,
)
from bfrs.version import APP_NAME, VERSION


_BATCH_FILE_LIMIT = 32
_BATCH_BYTE_LIMIT = 8 * 1024 * 1024
_QUEUE_MULTIPLIER = 2


class FolderWorkerError(RuntimeError):
    """A file-worker failed outside the normal per-file error boundary."""


class FolderScanStopped(Exception):
    """A child file scan cooperatively stopped by user request."""


@dataclass(frozen=True, slots=True)
class _ScanOutcome:
    index: int
    source: Path
    size: int
    mtime_ns: int
    report: dict | None = None
    error_reason: str | None = None


class _FolderProgress:
    """Thread-safe, throttled aggregate folder progress."""

    def __init__(
        self,
        root: Path,
        *,
        files: int,
        total_bytes: int,
        progress_callback: Callable[[ScanProgress], None] | None = None,
    ) -> None:
        self._root = root
        self._files = files
        self._total_bytes = total_bytes
        self._progress_callback = progress_callback
        self._started = time.monotonic()
        self._last_rendered = 0.0
        self._completed = 0
        self._completed_bytes = 0
        self._raw_hits = 0
        self._validated = 0
        self._rendered = False
        self._lock = threading.Lock()

    def restore(self, outcomes: Sequence[_ScanOutcome]) -> None:
        for outcome in outcomes:
            self._completed += 1
            self._completed_bytes += outcome.size
            if outcome.report is not None:
                self._raw_hits += int(outcome.report.get("raw_hit_count", 0))
                findings = outcome.report.get("target_findings", ())
                if isinstance(findings, list):
                    self._validated += sum(
                        item.get("validation_status") not in (
                            None, "UNVALIDATED", "NOT_APPLICABLE")
                        for item in findings
                        if isinstance(item, dict)
                    )

    def initial(self, skipped: int) -> None:
        percent = (
            100.0 if self._files == 0
            else self._completed * 100.0 / self._files
        )
        if self._progress_callback is not None:
            self._progress_callback(ScanProgress(
                scanned_bytes=self._completed_bytes,
                total_bytes=self._total_bytes,
                raw_hits=self._raw_hits,
                stage="folder-scan",
                complete=(self._files == 0),
            ))
        print(
            "Folder scan: "
            f"files={self._completed}/{self._files} ({percent:.1f}%) "
            f"bytes={self._completed_bytes}/{self._total_bytes} ({percent:.1f}%) "
            f"files/s=0.0 MiB/s=0.0 raw_hits={self._raw_hits} "
            f"validated={self._validated} "
            f"skipped={skipped}",
            file=sys.stderr,
        )

    def update(self, outcome: _ScanOutcome) -> None:
        with self._lock:
            self._completed += 1
            self._completed_bytes += outcome.size
            if outcome.report is not None:
                self._raw_hits += int(outcome.report.get("raw_hit_count", 0))
                findings = outcome.report.get("target_findings", ())
                if isinstance(findings, list):
                    self._validated += sum(
                        item.get("validation_status") not in (
                            None, "UNVALIDATED", "NOT_APPLICABLE")
                        for item in findings
                        if isinstance(item, dict)
                    )
            complete = self._completed >= self._files
            if self._progress_callback is not None:
                self._progress_callback(ScanProgress(
                    scanned_bytes=self._completed_bytes,
                    total_bytes=self._total_bytes,
                    raw_hits=self._raw_hits,
                    stage="folder-scan",
                    complete=complete,
                ))
            now = time.monotonic()
            if not complete and now - self._last_rendered < 0.5:
                return
            self._last_rendered = now
            elapsed = max(now - self._started, 1e-9)
            file_percent = (100.0 if self._files == 0 else
                            self._completed * 100.0 / self._files)
            byte_percent = (100.0 if self._total_bytes == 0 else
                            self._completed_bytes * 100.0 / self._total_bytes)
            try:
                current = outcome.source.relative_to(self._root).as_posix()
            except ValueError:
                current = str(outcome.source)
            print(
                "\rFolder scan: "
                f"files={self._completed}/{self._files} ({file_percent:.1f}%) "
                f"bytes={self._completed_bytes}/{self._total_bytes} "
                f"({byte_percent:.1f}%) files/s={self._completed / elapsed:.1f} "
                f"MiB/s={self._completed_bytes / 2**20 / elapsed:.1f} "
                f"raw_hits={self._raw_hits} validated={self._validated} "
                f"current={current}",
                end="\n" if complete else "",
                file=sys.stderr,
                flush=True,
            )
            self._rendered = not complete

    def finish(self) -> None:
        with self._lock:
            if self._rendered:
                print(file=sys.stderr)
                self._rendered = False


def _is_junction(path: Path) -> bool:
    predicate = getattr(path, "is_junction", None)
    return bool(predicate and predicate())


def discover_regular_files(root: Path) -> tuple[list[tuple[Path, int, int]], list[dict]]:
    """Discover regular files without following links or directory reparse points."""
    files: list[tuple[Path, int, int]] = []
    skipped: list[dict] = []
    pending = [root]
    visited: set[tuple[int, int]] = set()
    while pending:
        directory = pending.pop()
        try:
            identity = directory.stat(follow_symlinks=False)
            key = (identity.st_dev, identity.st_ino)
            if key in visited:
                skipped.append({"path": str(directory), "reason": "DIRECTORY_LOOP"})
                continue
            visited.add(key)
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as error:
            skipped.append({"path": str(directory), "reason": type(error).__name__})
            continue
        try:
            for entry in entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink() or _is_junction(path):
                        skipped.append({"path": str(path), "reason": "LINK_NOT_FOLLOWED"})
                    elif entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        stat = entry.stat(follow_symlinks=False)
                        files.append((path, stat.st_size, stat.st_mtime_ns))
                    else:
                        skipped.append({"path": str(path), "reason": "NOT_REGULAR_FILE"})
                except OSError as error:
                    skipped.append({"path": str(path), "reason": type(error).__name__})
        finally:
            entries.clear()
    files.sort(key=lambda item: str(item[0]).casefold())
    return files, skipped


def _child_arguments(arguments, source: Path, output: Path) -> list[str]:
    values = [
        "--input", str(source), "--output", str(output),
        "--source-type", "file",
        "--chunk-mib", str(arguments.chunk_mib),
        "--overlap-kib", str(arguments.overlap_kib),
        "--cluster-mib", str(arguments.cluster_mib),
        "--padding-mib", str(arguments.padding_mib),
        "--minimum-hits", str(arguments.minimum_hits),
        "--minimum-distinct-types", str(arguments.minimum_distinct_types),
        "--workers", str(arguments.workers),
    ]
    if arguments.targets is not None:
        values += ["--targets", arguments.targets]
    for enabled, flag in (
        (arguments.electrum_only, "--electrum-only"),
        (arguments.seed_scan_only, "--seed-scan-only"),
        (arguments.include_mnemonic, "--include-mnemonic"),
        (arguments.include_bitcoin_context, "--include-bitcoin-context"),
        (arguments.skip_mnemonic, "--skip-mnemonic"),
    ):
        if enabled:
            values.append(flag)
    return values


def _merge_recovery(total: dict, current: dict, prefix: Path) -> None:
    for name in ("eligible_candidates", "recovered_wallets", "failed_wallets"):
        total[name] += int(current.get(name, 0))
    for item in current.get("outputs", []):
        row = dict(item)
        relative = row.get("relative_recovery_path")
        if isinstance(relative, str):
            row["relative_recovery_path"] = (prefix / relative).as_posix()
        total["outputs"].append(row)


def _file_batches(
    files: Sequence[tuple[Path, int, int]],
    workers: int,
    *,
    index_map: Mapping[Path, int] | None = None,
) -> Iterator[tuple[tuple[int, Path, int, int], ...]]:
    # Keep enough batches to occupy small worker pools while retaining a hard
    # cap that amortizes scheduling for directories with hundreds of thousands
    # of tiny files.
    adaptive_file_limit = min(
        _BATCH_FILE_LIMIT,
        max(1, (len(files) + workers * 4 - 1) // (workers * 4)),
    )
    batch: list[tuple[int, Path, int, int]] = []
    batch_bytes = 0
    for fallback_index, (source, size, mtime_ns) in enumerate(files, 1):
        index = (
            index_map.get(source, fallback_index)
            if index_map is not None
            else fallback_index
        )
        if batch and (len(batch) >= adaptive_file_limit or
                      batch_bytes + size > _BATCH_BYTE_LIMIT):
            yield tuple(batch)
            batch = []
            batch_bytes = 0
        batch.append((index, source, size, mtime_ns))
        batch_bytes += size
    if batch:
        yield tuple(batch)


def _scan_batch(
    batch: tuple[tuple[int, Path, int, int], ...],
    temporary_root: Path,
    arguments,
    child_main: Callable[[Sequence[str] | None], int],
    progress: Callable[[_ScanOutcome], None],
) -> list[_ScanOutcome]:
    outcomes = []
    for index, source, size, mtime_ns in batch:
        child_report_path = temporary_root / f"report-{index:09d}.json"
        try:
            code = child_main(_child_arguments(arguments, source, child_report_path))
            if code == 130:
                raise FolderScanStopped
            if code != 0:
                raise OSError(f"CHILD_SCAN_EXIT_{code}")
            child_report = json.loads(child_report_path.read_text(encoding="utf-8"))
            child_findings = child_report.get("target_findings", [])
            if not isinstance(child_findings, list):
                raise ValueError("INVALID_CHILD_REPORT")
            outcome = _ScanOutcome(
                index, source, size, mtime_ns, report=child_report)
        except FolderScanStopped:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            outcome = _ScanOutcome(
                index, source, size, mtime_ns,
                error_reason=type(error).__name__,
            )
        outcomes.append(outcome)
        progress(outcome)
    return outcomes


def _scan_files_bounded(
    files: Sequence[tuple[Path, int, int]],
    temporary_root: Path,
    arguments,
    child_main: Callable[[Sequence[str] | None], int],
    progress: Callable[[_ScanOutcome], None],
    *,
    index_map: Mapping[Path, int] | None = None,
) -> list[_ScanOutcome]:
    workers = arguments.file_workers
    batches = iter(_file_batches(files, workers, index_map=index_map))
    if workers == 1:
        return [
            outcome
            for batch in batches
            for outcome in _scan_batch(
                batch, temporary_root, arguments, child_main, progress)
        ]

    outcomes: list[_ScanOutcome] = []
    pending: dict[Future[list[_ScanOutcome]], tuple[tuple[int, Path, int, int], ...]] = {}
    executor = ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="bfrs-file-worker")

    def submit_next() -> bool:
        try:
            batch = next(batches)
        except StopIteration:
            return False
        future = executor.submit(
            _scan_batch, batch, temporary_root, arguments, child_main, progress)
        pending[future] = batch
        return True

    try:
        for _ in range(workers * _QUEUE_MULTIPLIER):
            if not submit_next():
                break
        while pending:
            completed, _ = wait(tuple(pending), return_when=FIRST_COMPLETED)
            for future in completed:
                batch = pending.pop(future)
                try:
                    outcomes.extend(future.result())
                except FolderScanStopped:
                    for item in pending:
                        item.cancel()
                    raise
                except BaseException as error:
                    for item in pending:
                        item.cancel()
                    paths = ", ".join(str(item[1]) for item in batch[:3])
                    raise FolderWorkerError(
                        f"file worker failed while scanning batch starting with {paths}: "
                        f"{type(error).__name__}: {error}") from error
                submit_next()
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
    return outcomes


def _finding_sort_key(root: Path, finding: dict) -> tuple:
    source = Path(str(finding.get("file_path", "")))
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError:
        relative = str(source)
    return (
        relative.casefold(),
        int(finding.get("file_offset_start", finding.get("start_offset", -1))),
        int(finding.get("file_offset_end", finding.get("end_offset", -1))),
        str(finding.get("target", "")),
        str(finding.get("hit_type", finding.get("type", ""))),
    )


def _folder_checkpoint_semantics(arguments) -> dict:
    return {
        "chunk_mib": arguments.chunk_mib,
        "overlap_kib": arguments.overlap_kib,
        "cluster_mib": arguments.cluster_mib,
        "padding_mib": arguments.padding_mib,
        "minimum_hits": arguments.minimum_hits,
        "minimum_distinct_types": arguments.minimum_distinct_types,
        "workers": arguments.workers,
        "file_workers": arguments.file_workers,
        "targets": arguments.targets or "default",
        "electrum_only": bool(arguments.electrum_only),
        "seed_scan_only": bool(arguments.seed_scan_only),
        "include_mnemonic": bool(arguments.include_mnemonic),
        "include_bitcoin_context": bool(arguments.include_bitcoin_context),
        "skip_mnemonic": bool(arguments.skip_mnemonic),
        "recover_wallets": bool(arguments.recover_wallets),
        "recovery_dir": (
            str(arguments.recovery_dir.resolve(strict=False))
            if arguments.recovery_dir is not None
            else None
        ),
    }


def _checkpoint_outcome(
    checkpoint: FolderScanCheckpoint,
    root: Path,
    outcome: _ScanOutcome,
) -> None:
    checkpoint.save_outcome(
        relative_path=outcome.source.relative_to(root).as_posix(),
        size=outcome.size,
        mtime_ns=outcome.mtime_ns,
        report=outcome.report,
        error_reason=outcome.error_reason,
    )


def scan_folder_source(
    arguments,
    child_main: Callable[[Sequence[str] | None], int],
    *,
    progress_callback: Callable[[ScanProgress], None] | None = None,
) -> int:
    root = arguments.input.resolve()
    files, discovery_skips = discover_regular_files(root)
    bytes_discovered = sum(size for _, size, _ in files)
    snapshot_sha256 = folder_snapshot_digest(root, files)
    semantics = _folder_checkpoint_semantics(arguments)
    index_map = {
        source: index
        for index, (source, _, _) in enumerate(files, 1)
    }
    checkpoint: FolderScanCheckpoint | None = None
    resumed_outcomes: list[_ScanOutcome] = []
    remaining_files = list(files)

    try:
        if arguments.checkpoint is not None:
            checkpoint = FolderScanCheckpoint.create(
                arguments.checkpoint,
                root=root,
                snapshot_sha256=snapshot_sha256,
                semantics=semantics,
            )
        elif arguments.resume_checkpoint is not None:
            checkpoint = FolderScanCheckpoint.resume(
                arguments.resume_checkpoint,
                root=root,
                snapshot_sha256=snapshot_sha256,
                semantics=semantics,
            )
            by_relative = {
                source.relative_to(root).as_posix(): (source, size, mtime_ns)
                for source, size, mtime_ns in files
            }
            completed_paths: set[str] = set()
            for record in checkpoint.records():
                source_info = by_relative.get(record.relative_path)
                if source_info is None:
                    raise FolderCheckpointError(
                        "checkpoint references a file missing from current folder"
                    )
                source, size, mtime_ns = source_info
                if size != record.size or mtime_ns != record.mtime_ns:
                    raise FolderCheckpointError(
                        "checkpoint file metadata mismatch"
                    )
                resumed_outcomes.append(_ScanOutcome(
                    index_map[source],
                    source,
                    size,
                    mtime_ns,
                    report=record.report,
                    error_reason=record.error_reason,
                ))
                completed_paths.add(record.relative_path)
            remaining_files = [
                item for item in files
                if item[0].relative_to(root).as_posix() not in completed_paths
            ]
    except FolderCheckpointError as error:
        print(f"folder checkpoint error: {error}", file=sys.stderr)
        if checkpoint is not None:
            try:
                checkpoint.close()
            except FolderCheckpointError:
                pass
        return 3

    started = time.monotonic()
    progress = _FolderProgress(
        root,
        files=len(files),
        total_bytes=bytes_discovered,
        progress_callback=progress_callback,
    )
    progress.restore(resumed_outcomes)
    progress.initial(len(discovery_skips))
    wallet_recovery = recovery_not_requested()
    if arguments.recover_wallets:
        validate_recovery_destination(root, arguments.recovery_dir)
        wallet_recovery = {
            "requested": True, "eligible_candidates": 0,
            "recovered_wallets": 0, "failed_wallets": 0, "outputs": [],
        }

    def on_outcome(outcome: _ScanOutcome) -> None:
        progress.update(outcome)
        if checkpoint is not None:
            _checkpoint_outcome(checkpoint, root, outcome)

    try:
        with tempfile.TemporaryDirectory(prefix="bfrs-folder-scan-") as temporary:
            scanned_outcomes = _scan_files_bounded(
                remaining_files,
                Path(temporary),
                arguments,
                child_main,
                on_outcome,
                index_map=index_map,
            )
        outcomes = resumed_outcomes + scanned_outcomes
    except FolderScanStopped:
        progress.finish()
        if checkpoint is not None:
            checkpoint.close()
        print("folder scan stopped by request", file=sys.stderr)
        return 130
    except (FolderWorkerError, FolderCheckpointError) as error:
        progress.finish()
        if checkpoint is not None:
            try:
                checkpoint.close()
            except FolderCheckpointError:
                pass
        label = (
            "folder checkpoint error"
            if isinstance(error, FolderCheckpointError)
            else "folder worker error"
        )
        print(f"{label}: {error}", file=sys.stderr)
        return 3
    progress.finish()
    outcomes.sort(key=lambda item: item.index)

    file_rows = []
    flattened_findings = []
    scan_failures = []
    scanned = bytes_scanned = 0
    for outcome in outcomes:
        source = outcome.source
        if outcome.report is None:
            failure = {
                "file_path": str(source.resolve(strict=False)),
                "reason": outcome.error_reason or "UNKNOWN_FILE_ERROR",
            }
            scan_failures.append(failure)
            file_rows.append({
                "file_path": failure["file_path"],
                "size": outcome.size,
                "mtime_ns": outcome.mtime_ns,
                "status": "SKIPPED",
                "reason": failure["reason"],
            })
            continue

        child_report = outcome.report
        child_findings = child_report.get("target_findings", [])
        relative_path = source.relative_to(root).as_posix()
        for item in child_findings:
            row = dict(item)
            row.setdefault("relative_path", relative_path)
            flattened_findings.append(row)
        scanned += 1
        bytes_scanned += outcome.size
        intact = child_report.get("intact_wallet", {})
        wallet_targets = {"bitcoin-core", "electrum", "multibit", "armory"}
        wallet_detected = bool(intact.get("detected")) or any(
            row.get("target") in wallet_targets for row in child_findings)
        if arguments.recover_wallets:
            prefix = Path(f"file_{outcome.index:09d}")
            per_file_root = arguments.recovery_dir / prefix
            if intact.get("detected"):
                recovered = recover_intact_wallet(
                    source, child_report, arguments.recovery_dir,
                    relative_prefix=prefix,
                )
                _merge_recovery(wallet_recovery, recovered, Path())
            else:
                recovered = recover_wallets(source, child_report, per_file_root)
                _merge_recovery(wallet_recovery, recovered, prefix)
        file_rows.append({
            "file_path": str(source.resolve()),
            "relative_path": relative_path,
            "size": outcome.size,
            "mtime_ns": outcome.mtime_ns,
            "status": "SCANNED",
            "finding_count": len(child_findings),
            "wallet_detected": wallet_detected,
            "intact_wallet": intact,
            "report": child_report,
        })

    flattened_findings.sort(key=lambda item: _finding_sort_key(root, item))
    elapsed = time.monotonic() - started
    payload = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "application": {"name": APP_NAME, "version": VERSION},
        "source_type": "FOLDER",
        "source_root": str(root),
        "location_model": {
            "offset_kind": "file_offset",
            "identity": ["file_path", "file_offset"],
        },
        "file_count": len(files),
        "files_discovered": len(files),
        "files_scanned": scanned,
        "files_failed": len(scan_failures),
        "files_skipped": len(discovery_skips) + len(scan_failures),
        "bytes_discovered": bytes_discovered,
        "bytes_scanned": bytes_scanned,
        "elapsed_seconds": elapsed,
        "findings_count": len(flattened_findings),
        "files": file_rows,
        "target_findings": flattened_findings,
        "skipped_entries": discovery_skips + scan_failures,
        "wallet_recovery": wallet_recovery,
        "scanner_semantics": {
            "recursive": True,
            "regular_files_only": True,
            "follow_links": False,
            "file_filter": "ALL_REGULAR_FILES",
            "chunk_mib": arguments.chunk_mib,
            "overlap_kib": arguments.overlap_kib,
            "targets": arguments.targets or "default",
            "file_workers": arguments.file_workers,
            "file_batch_limit": _BATCH_FILE_LIMIT,
            "file_batch_byte_limit": _BATCH_BYTE_LIMIT,
            "maximum_queued_batches": arguments.file_workers * _QUEUE_MULTIPLIER,
        },
        "checkpoint": {
            "supported": True,
            "schema_version": 1,
            "path": (
                str(
                    (arguments.checkpoint or arguments.resume_checkpoint)
                    .resolve(strict=False)
                )
                if (arguments.checkpoint or arguments.resume_checkpoint)
                else None
            ),
            "resumed_files": len(resumed_outcomes),
            "image_checkpoint_unchanged": True,
        },
    }
    output = arguments.output
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_name(f".{output.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary_output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, output)
    except OSError as error:
        temporary_output.unlink(missing_ok=True)
        if checkpoint is not None:
            try:
                checkpoint.close()
            except FolderCheckpointError:
                pass
        print(f"report error: {error}", file=sys.stderr)
        return 4

    if checkpoint is not None:
        try:
            checkpoint.mark_complete()
            checkpoint.close()
        except FolderCheckpointError as error:
            print(f"folder checkpoint error: {error}", file=sys.stderr)
            return 3

    print("source type: FOLDER")
    print(f"source root: {root}")
    print(f"files discovered: {len(files)}")
    print(f"files scanned: {scanned}")
    print(f"files skipped: {len(discovery_skips) + len(scan_failures)}")
    print(f"bytes scanned: {bytes_scanned}")
    print(f"findings: {len(flattened_findings)}")
    print(f"wallets detected: {sum(bool(row.get('wallet_detected')) for row in file_rows)}")
    print(f"report path: {output.resolve()}")
    return 0
