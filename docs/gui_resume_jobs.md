# GUI task journal, resume and report publication

Stage 3, based on approved stage-2 commit `84d3d96`.

## Diagnosis and evidence

The reported historical exit code 3 cannot identify a unique cause: no original
diagnostic or scan-source type was retained. Do not classify it as a report-path
error. A synthetic folder scan stopped after 9/25 files (36%) demonstrates:

* Resuming with reset detector/mnemonic settings returns 3. The engine prints
  `folder checkpoint error: scanner settings mismatch: skip_mnemonic, targets`,
  but the old application event carried only `BFRS scan exited with code 3`.
* Resuming the same checkpoint with the original settings and a new report
  filename succeeds. Report paths are not checkpoint identity/semantic fields.
* A blank report path is rejected by GUI form validation before engine start.
  Ordinary report-write failures return 4, while source/checkpoint/worker errors
  can return 3. Parser errors can exit with 2. The diagnostic, not the number,
  determines the action.

The preferences file already saved `last_output` atomically. However it did not
save checkpoint, resume mode, selected targets, source mode or all detector
options. Saving preferences could fail silently; partial form edits could erase
`last_output`, and invalid preferences fell back to defaults. Thus preferences
were neither a complete task snapshot nor evidence of a resumable job.

## Durable request journal

GUI requests are saved before QThread/process start in
`<gui-settings-directory>/scan-jobs/<uuid>.json`, normally
`%APPDATA%/BFRS/scan-jobs`. Preferences remain optional presentation state; the
task journal is required before a GUI scan may start. A journal write failure
blocks that start and displays the real filesystem error.

The journal has its own version 1, independent of checkpoint formats. An explicit
allowlist saves absolute source/report/checkpoint/recovery paths, source type,
targets, scan-mode and mnemonic/context flags, range/geometry/policy settings,
worker counts, and GUI publication policy. It contains no findings, file bytes,
private keys, seeds, passwords or persisted error text. Metadata may reveal case
paths and should remain in the user's protected profile/backups.

Records are UTF-8 JSON, written to an exclusive temporary file, flushed and
fsynced before atomic publication. Updates use atomic replace; creation refuses
an existing record. Files are size bounded and their types/version/IDs/settings
are validated on load. Temporary files from interrupted writes are ignored.
Invalid/future records produce a visible warning without echoing their contents
or falling back to guessed scanner settings. No user checkpoint is migrated.

Each attempt has its own immutable configuration snapshot. Terminal state is
updated separately. A failed incompatible attempt cannot overwrite the last
known working configuration. A successful attempt marks earlier attempts for
the same checkpoint `superseded`, preserving their original configurations and
avoiding a false claim that their former report destinations were written.

## Restart workflow

On startup, unfinished journal records appear in a task selector. Loading a task
restores the complete supported GUI form, including report and checkpoint path,
source type, detectors and numerical parameters. It never starts a scan.
If the restored form's report field was cleared, start restores that path only
when source/checkpoint still match the loaded task. Otherwise ordinary required
field validation applies. A changed output path is permitted.

Start passes the restored settings through the existing engine compatibility
checks in the isolated process. Incompatible source identity, range, geometry,
detectors, schema or scanner versions remain rejected with their real reason.
Worker changes remain allowed only as the existing engine contract permits.
No compatibility check is bypassed or replaced by UI guesses.

A task without a checkpoint cannot resume progress. A missing/unmounted drive
does not silently turn resume into a new scan. Older checkpoints without a task
journal do not contain the historical report name; users must choose a new
report and supply the original compatible settings. The GUI does not infer
unknown settings from an arbitrary checkpoint or scan directories for secrets.
CLI-only saved modes unsupported by the current GUI form are explicitly refused
rather than converted to a different scan mode.

## Report protection and errors

GUI ScanConfig requests set `protect_existing_report=True`. Service preflight
checks source availability, actual write-path collisions, an existing report and
a writable report directory, before scanning. It does not reserve or overwrite
the final filename. Final publication also refuses an existing destination, so a
file created after preflight is preserved. Windows uses no-clobber `os.rename`;
POSIX uses an exclusive hard link, without an unsafe replace fallback. Temporary
reports are written in the destination directory and fsynced before publication.

Legacy CLI callers retain their existing overwrite default. JSON report schema
and values remain compatible. Seed-only JSON publication is now atomic as well.
This publication policy is not stored in scanner semantics or checkpoint schema.

Folder checkpoints remain IN_PROGRESS if report publication fails, permitting
report-path repair and resume with every completed file restored. Unified image
checkpoints already permit reuse of completed ownership state after report
failure; this contract is preserved. Completed folder checkpoints remain rejected
on resume. No format/state migration or recovery algorithm change is introduced.

The child application adapter tees stderr and captures bounded recognized error
lines, including folder diagnostics and parser failures. It deduplicates explicit
engine callbacks and separates error lines from carriage-return progress.
The original engine text is forwarded through existing ProcessScanRunner events.
GUI messages retain it and append localized repair guidance for permissions,
space, unavailable sources/drives, existing reports, identity/setting/version
mismatches and process failure. A final failed result cannot replace a specific
diagnostic with a bare code. Unknown failures are explicitly described as unknown.

The GUI requests cooperative stop and waits for QThread completion when closed.
Forced process termination/reboot can still interrupt it; previously committed
checkpoint units and the durable task snapshot remain the recovery boundary.
There are no per-file journal writes; stages 1 and 2 retain their batching,
detector reuse, cache clearing and worker defaults.

## Verification and limits

Synthetic regressions cover 36% interruption, fresh GUI construction, missing
report in restored form, real spawned-process resume, changed workers,
incompatible targets/geometry/source location, preserved committed rows, full
finding/offset identity, existing reports, publication races, injected permission
and disk-full errors, report repair, atomic metadata failure/process exit, and a
real QObject/QThread/process close. Stage-1/2 regression suites also run.

```powershell
python -m pytest -q
git diff --check
```

This is not a physical Windows Update/reboot or power-cut test. Windows 10 still
needs a packaged-app manual test across an OS restart, with the same user profile
and removable/mapped drives, including DPI/layout and real filesystem ACL/space
conditions. Atomic rename/fsync guarantees still depend on the filesystem and
storage. If the user profile/journal is deleted, missing historical names cannot
be recovered from checkpoints alone. A hard exit may leave a stale journal status;
the engine remains authoritative. Concurrent scans on one checkpoint are not a
supported recovery workflow: stop the previous scan before resuming.

No installer or merge is part of this stage. Existing user reports/checkpoints
were not opened or modified during development; all scan tests use synthetic
temporary material.

The windowed Windows build (console=False) may have stdout/stderr set to None. Diagnostics still reach events in this mode. ProcessScanRunner also rejects a nonzero native process exit after a terminal engine result; the result cannot conceal an abnormal exit, and the user is told a report may already exist.
