# Folder checkpoint batching (performance stage 1)

Folder scans use a maximum of 32 accepted outcomes per SQLite transaction and
a one-second deadline from the oldest pending outcome. A condition-variable
thread enforces that deadline even when no further file finishes. Transactions
retain `PRAGMA synchronous=FULL` and the existing rollback-journal mode.

An additional 8 MiB budget for serialized report strings flushes large outcomes
early; a single outcome larger than the budget is committed immediately. This
does not bound the size of an individual scan report or change its contents.

The direct `FolderScanCheckpoint` API still saves synchronously by default.
Folder orchestration explicitly calls `set_batching(32, 1.0)`. The policy is a
runtime choice, excluded from scanner semantics and checkpoint metadata. Use
`set_batching(1, 1.0)` before the first save for synchronous library use.

## Durability and stop behavior

* `save_outcome()` in batched mode accepts a serialized outcome, not a durability
  promise. The buffer clears and durable counters advance only after a successful
  FULL commit. SQLite errors are latched and raised by later saves, flushes,
  completion and close; the scan does not emit a successful checkpoint-saved event.
* A shared condition/lock serializes SQLite access from file workers and the
  timer. Scanned-file counting, outcome submission and progress publication are
  ordered so committed outcomes cannot run ahead of the scanned-file counter.
* `flush()`, controlled stop, Ctrl+C cleanup, `mark_complete()` and `close()` flush
  the tail. Cleanup joins the timer; close is idempotent. Worker scheduling stops
  starting subsequent files when cancellation is requested, while already-running
  file work reaches its existing safe boundary.
* A sudden process exit can require replay of at most the one uncommitted batch
  of up to 32 completed outcomes, in addition to files not yet completed. SQLite
  recovers an interrupted transaction atomically. No pending outcome is counted
  as durable. On an SQLite failure, close releases the connection without claiming
  to have saved the failed batch; resume can rescan that batch after the cause is
  resolved.
* Progress exposes `scanned_files`, `checkpoint_durable_files`,
  `checkpoint_pending_files`, and `checkpoint_durable_bytes`. CLI and GUI show
  the separate scanned/durable counters. Resumed outcomes count in both totals;
  durable bytes mean the sizes of files with committed outcomes, including saved
  per-file error outcomes. They do not assert that every file's content was read.
  Restore/report progress uses record counts, which are kept separate from byte
  counters in both stopped and checkpoint-saved events.
  The CLI passes the cooperative stop callback to folder orchestration as well
  as to child scanners, including when every file is already in the checkpoint.

The schema remains version 1, with identical metadata and outcomes columns and
unchanged report JSON serialization. Existing checkpoints, including original
worker settings in `semantics_json`, remain resumable. No recovery module,
detector rule, report schema, or existing user report is modified.

## What was measured and what remains

The reviewed paths are:

* `folder_source_scanner.py`: full discovery and deterministic sorting precede
  scanning; snapshot hashing, index mapping and remaining-file lists retain O(N)
  state. Report sorting and streaming run after file work. This stage preserves
  snapshot validation and report order.
* `folder_scan_checkpoint.py`: the original per-file FULL transactions dominate
  checkpoint I/O on many small files. Grouping reduces commit frequency without
  weakening committed transactions. The buffer and timer are the optimization.
* `disk_list.py`: temporary report lists already commit every 128 appends and
  stream JSON arrays. Their writes, indexing and sorting remain part of report
  cost, with no change to temporary storage semantics.
* `folder_file_scanner.py`: detector indexes are already reused per thread.
  Additional file workers allocate additional indexes. Per-file argument parsing,
  metadata calls and cache cleanup remain; detector behavior is preserved.
* `scan_service.py`: propagates the separate counters and uses committed bytes
  in the checkpoint-saved event. Per-file progress delivery remains an additional
  front-end cost. Recovery behavior is unchanged.

## Repeatable measurement

Run from an editable installation, or set `$env:PYTHONPATH='src'` in PowerShell:

```powershell
python -m bfrs.tools.benchmark_folder_checkpoint --work-dir D:\bfrs-benchmark\small --label before --files 1024 --repeats 3 --batch-size 1
python -m bfrs.tools.benchmark_folder_checkpoint --work-dir D:\bfrs-benchmark\small --label after --files 1024 --repeats 3 --batch-size 32
python -m bfrs.tools.benchmark_folder_checkpoint --work-dir D:\bfrs-benchmark\discovery --label discovery --files 100000 --bytes-per-file 128 --repeats 3 --discovery-only
```

The pre-change measurements were taken on commit `94d6656`, after adding only
the benchmark tool. To reproduce that baseline, use a separate checkout of that
commit and copy the benchmark module into it. Run the second command on this
branch, retaining the same work directory and source files. New sample labels
avoid overwriting existing outputs. The tool validates fixture contents and
preserves source mtimes; the recorded corpus digest must match before/after.

Each sample runs in a fresh process. Worker order alternates between 1/2/4 and
4/2/1. OS caches are not flushed. Samples scan 1024 synthetic 4 KiB files with
public signature markers, all targets enabled, mnemonic enabled, and one chunk
worker. No real private keys or seeds are used. The discovery-only fixture is
separate and is not a full detection benchmark for 100000 files.

Metrics are engine wall time, files/s, source MiB/s, SQLite commit time/count,
aggregate producer save-call time (including lock waits), discovery/checkpoint
initialization up to `folder-scan`, per-thread detector initialization time,
report generation/finalization, process CPU seconds, one-core CPU percentage and
peak working set before correctness-comparison JSON loading. Initialization
excludes Python/CLI imports; detector initialization is measured separately and
included in scan time. Report/finalization includes sorting, JSON publication,
fsync and the completion marker. CPU counts all threads in the sample process;
thread timings can overlap and must not be added to wall time. RSS uses the
Windows process API or `resource` where supported, with no heavy dependency.

The benchmark compares canonical findings and per-file report digests, ignoring
only elapsed-time fields in per-file reports. The full report's expected runtime
differences (output/checkpoint path, workers, elapsed time) are not compared as
content changes. Retain raw result JSON alongside any summary; measured gains
on small cached files must not be extrapolated to another disk or workload.

## Validation

```powershell
python -m pytest -q
git diff --check
```

Regression tests cover the 32-outcome cap, idle and slow-arrival deadlines,
large-report flushing, 1/2/4 workers, exact counters and unique rows, legacy
schema/payload preservation, INSERT/COMMIT/timer failure, interrupted commit,
controlled stop/KeyboardInterrupt, report interruption, and abrupt process exit
with pending rows or a partially written SQLite transaction. Synthetic Bitcoin
Core, Electrum, mnemonic and secret findings are compared across stop/resume.

The one-second target depends on OS scheduling and successful storage access;
a busy/unwritable database cannot be promised a one-second successful commit.
The replay window is the explicit tradeoff for batching. Windows 11 was measured;
Windows 10 requires its own on-device performance measurement. No installer or
merge is part of this stage.

## Measured results (Windows 11, 26 October 2026)

Three-run medians, 1024 × 4096-byte files, before commit 94d6656 vs this branch:

| File Workers | seconds before → after | pliki/seconds before → after | MiB/seconds before → after | measured ratio |
|---:|---:|---:|---:|---:|
| 1 | 17.900 → 9.105 | 57.2 → 112.5 | 0.223 → 0.439 | 1.97× |
| 2 | 11.452 → 8.983 | 89.4 → 114.0 | 0.349 → 0.445 | 1.27× |
| 4 | 12.187 → 9.967 | 84.0 → 102.7 | 0.328 → 0.401 | 1.22× |

Every measured run had identical finding and per-file report digests. Outcome
commits fell from 1024 to 32. The instrumented connection-context-exit counter
was 1027 vs 35, including setup/finalization; it is not an SQL transaction census.
Batching remains enabled on the measured benefit.
