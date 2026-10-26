# Prepared folder-file scans (performance stage 2)

Baseline: commit `4a09e85` (stage 1, FULL checkpoint batching preserved).
Branch: `perf/folder-small-file-optimization`.

## Change and boundaries

The existing folder scanner already reused detector selections per file-worker
thread and cleared sensitive normalization caches after each file. This stage
keeps both mechanisms. It adds a prepared request path:

1. Each worker builds one CLI parser and validates one child-argument template.
2. Every file gets a fresh shallow copy of that template, with its own source and
   virtual output path. Configuration/report collections are still created per
   file, not shared across reports.
3. Both public CLI and prepared requests call the same `_run_scan` engine.
   Actual source checks, file-size/range checks, discovery, validators, document
   enrichment, stop handling and per-file serialization remain in that engine.
4. Prepared children are whole-file, in-memory report requests. They cannot own
   checkpoint, recovery or revalidation writes. The parent retains public CLI
   validation and output/checkpoint/recovery destination protections. A runtime
   guard rejects an unexpected writing child policy before engine execution.
5. Detector selections are keyed by effective chunk-worker configuration, not a
   small/large boolean. With one chunk worker, alternating size classes reuses
   identical indexes instead of allocating two copies. Different worker settings
   remain separate; no new sharing across File Workers is introduced.

The argv adapter remains available for custom folder child callables. The folder
orchestrator uses `scan_file()` when the prepared method is supplied. Source
stat results and file bytes are not cached. Token caches still clear in `finally`
on success, error and KeyboardInterrupt. New configuration objects retain no
secret file contents.

Recovery modules, `fast_scanner.py`, `chunk_reader.py`, report schema and stage-1
checkpoint implementation remain unchanged. All regular files and detectors
remain eligible. Small files still use local mnemonic decoding; requested chunk
workers remain available for large files. Default worker counts are unchanged.

## Reviewed paths

* `folder_file_scanner.py`: selection reuse already existed. Repeated parser
  construction, parsing and non-writing virtual destination checks remained per
  file. Prepared requests remove this repeated adapter work.
* `folder_source_scanner.py`: retains bounded scheduling, stable file identity,
  outcome checkpointing, progress and report ordering. Only child dispatch uses
  the prepared method; custom callable compatibility remains.
* `fast_scanner.py`: scan counters, ownership ranges, detector calls and dedup
  state are per invocation. Retaining a coordinator across files would need a
  wider state audit; it is deliberately not introduced.
* `chunk_reader.py`: handles/stat/ownership plans remain per file and are not
  reused across file boundaries. No read is skipped based on suffix or entropy.
* `cli.py`: public parse/validation is unchanged; the shared engine is extracted
  without changing its scan branches. Profiled validator constructors remain
  unchanged rather than sharing unproven mutable validator instances.

## Reproducible measurement

```powershell
$env:PYTHONPATH = 'src'
python -m bfrs.tools.benchmark_folder_small_files --work-dir D:\bfrs-perf\small1024 --label before --files 1024 --batch-size 32 --repeats 3
python -m bfrs.tools.benchmark_folder_small_files --work-dir D:\bfrs-perf\small10000 --label before --files 10000 --batch-size 32 --repeats 3
python -m bfrs.tools.benchmark_folder_small_files --work-dir D:\bfrs-perf\mixed --label before --files 1024 --mixed --batch-size 32 --repeats 3
```

Run baseline commands from an isolated `4a09e85` source snapshot with only this
benchmark module copied into it. Run again from the candidate with `--label after`
on exactly the same work directories. The tool verifies existing fixture bytes
and preserves mtimes; result corpus hashes must match. It refuses to overwrite
sample outputs. Each command runs 1, 2 and 4 File Workers, three times each, in
fresh processes with alternating worker order. The OS cache is not flushed.

The first two corpora have 1024 and 10000 files of exactly 4096 bytes. The mixed
corpus has 1008 such files and 16 files of 2 MiB + 257 bytes. Chunk size is 1 MiB,
so the latter exercises the large-file configuration and ownership boundaries.
All targets and mnemonic scanning are enabled, with one requested chunk worker.
Fixture bytes are NUL padding and public signature markers, not user keys/seeds.

Wall time includes folder discovery, scanning, FULL checkpoint writes, report
generation and finalization. Python/CLI imports are outside engine timing.
CPU is process time across its threads; peak working set is collected before
JSON loading for result comparison. Detector initialization is a sum of timed
thread calls and may overlap; it must not be added to wall time. Checkpoint time
is time in connection context exits, including commits and a negligible schema
context exit; context counts are not an SQL transaction census.

Compare findings and full per-file reports after removing only `elapsed_seconds`.
Top-level expected execution differences such as output/checkpoint paths and
worker count are not content changes. Separate cProfile runs on 128 synthetic
positive test vectors cover Bitcoin Core, Electrum, MultiBit, Armory, WIF and
mnemonics. Their inclusive times overlap (validation occurs inside detection)
and profiling overhead is excluded from throughput claims.

The accompanying `profile_rich.py` deliverable uses public synthetic test
fixtures from the checkout's test helpers. Set `PYTHONPATH` to the chosen source
snapshot's `src` followed by the checkout root, then run it with a new work
directory and a label. Reuse the same fixture directory for the second label.

Scheduling evaluation can use `--batch-file-limit 8` on the same mixed corpus.
It changes only the benchmark process's scheduling limit, not the 32-outcome
checkpoint transaction policy. The existing production scheduler adapts to file
count and caps groups at 32 files / 8 MiB with at most 2 × workers queued groups.
Retain its default unless repeated measurements establish a benefit.

## Regression and acceptance

```powershell
python -m pytest -q
git diff --check
```

Differential tests cover complete per-file payloads and findings against fresh
CLI scans, every wallet target, mnemonic validity, WIF checks, offsets and source
identity, identical files in separate directories, empty/corrupt/unreadable
files, Polish names, large-file chunk boundaries and cross-file non-matching.
They also cover scan modes, namespace/report independence, cache cleanup after
errors/KeyboardInterrupt, worker configuration reuse, no small-file process pool,
checkpoint stop/resume and KeyboardInterrupt at 1/2/4 workers. Existing path
collision, checkpoint and recovery tests continue to apply to the shared engine.

Measurements apply to this Windows 11 machine and these synthetic file corpora.
They do not establish Windows 10 or disk-image scanning performance. No installer
or merge is part of this stage. Stage 1 is independently committed and preserved.

## Recorded comparison

| Zestaw | File Workers | czas s przed → po | pliki/s przed → po | MiB/s przed → po | iloraz przed/po |
|---|---:|---:|---:|---:|---:|
| small-1024 | 1 | 9.113 → 7.983 | 112.4 → 128.3 | 0.439 → 0.501 | 1.142× |
| small-1024 | 2 | 9.082 → 8.109 | 112.8 → 126.3 | 0.440 → 0.493 | 1.120× |
| small-1024 | 4 | 9.952 → 9.290 | 102.9 → 110.2 | 0.402 → 0.431 | 1.071× |
| small-10000 | 1 | 92.077 → 83.107 | 108.6 → 120.3 | 0.424 → 0.470 | 1.108× |
| small-10000 | 2 | 87.162 → 78.739 | 114.7 → 127.0 | 0.448 → 0.496 | 1.107× |
| small-10000 | 4 | 90.665 → 80.691 | 110.3 → 123.9 | 0.431 → 0.484 | 1.124× |
| mixed | 1 | 21.698 → 20.645 | 47.2 → 49.6 | 1.656 → 1.741 | 1.051× |
| mixed | 2 | 14.967 → 14.449 | 68.4 → 70.9 | 2.401 → 2.487 | 1.036× |
| mixed | 4 | 15.649 → 13.690 | 65.4 → 74.8 | 2.297 → 2.625 | 1.143× |
