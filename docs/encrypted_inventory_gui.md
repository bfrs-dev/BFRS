# Encrypted inventory in the desktop application

Stage 4 starts from `4f607f41dcd017c02f3daa7a26ce87bd833fc982` on
`feature/encrypted-inventory-gui`. It does not change wallet recovery algorithms.

The third main tab is **Zaszyfrowane pliki i foldery** / **Encrypted files and
folders**. Choose a source folder and a new output directory outside the source.
The output name must not exist for a new scan. Stop requests cooperative
cancellation; the current bounded metadata inspection finishes, SQLite is
committed, and partial JSONL/summary reports are exported. The tab opens the
existing paged InventoryBrowser after completion, stop, and recoverable failures
that left a readable database. Reopening reports is read-only.

Resume explicitly selects `inventory.sqlite`. If the source field is empty, its
absolute path is restored from read-only checkpoint metadata in the background.
If a source was entered, the original source/version compatibility checks apply;
there is no automatic conversion of an incompatible checkpoint. An unavailable
drive produces an error instead of a new scan. A changed drive letter requires
the original compatible location; browser source remapping changes only reveal
and copy operations, not checkpoint identity.

## One engine and unchanged formats

The former `scripts/inventory_documents.py` implementation now lives in
`bfrs.application.document_inventory`. The script remains a compatible CLI entry
point with the same `--source`, `--output`, `--resume`, return codes and report
names. Both Qt and CLI call `inventory()`. Existing parser modules, read limits,
classification meanings, SQLite schema/version, OLE migrations/cache revisions,
JSONL fields, summary fields and resume identities are retained. Existing tests
patch the shared package module instead of the old script's globals.

The QThread worker emits copied progress counters at most ten times per second,
plus a final update. No full-tree discovery is needed. The progress bar is
indeterminate: a percentage would require an extra traversal and a changing
denominator. Counts include visited, inspected, reused, errors/skips and MiB read.
The browser is the existing InventoryBrowser, with its 200-row pages and
background SQLite tasks; it now also displays full locations and raw metadata.
Its four filters retain the original status values. Copy/reveal never opens a
document through its associated application.

Unrecognized ordinary files remain cached but omitted from reports unless they
are candidates under the existing inventory rules. `UNKNOWN` does not mean
encrypted. `NO_ENCRYPTION_INDICATOR` is an assessment of checked metadata, not
proof that every payload is unencrypted. EFS attributes are current filesystem
observations; an EFS directory flag does not prove encryption of all children.

## Write safety and lifecycle

New output directories are created exclusively, avoiding the previous
check-then-create race. A process-scoped OS lock on `.inventory.lock` prevents two
inventory writers in one output directory; the OS releases it after a crash.
The small lock file remains in that directory. Symlinks/reparse points are
rejected in source/output ancestors and named report/checkpoint paths. Traversal
retains its link/junction skipping and bounded depth and now checks cancellation
also while walking empty directories. Metadata readers retain their existing
checks and limits. Do not mutate source/output trees concurrently with a scan.

JSONL is published from a unique temporary file after flush/fsync; summary uses
the existing atomic JSON writer. Explicit resume intentionally refreshes derived
reports. SQLite remains authoritative if a failure occurs between the two report
publications. A failed export can leave a temporary file; resume does not treat
it as a report and never executes it. No archive extraction, password attempts
or associated-document applications are used.

GUI close waits for wallet scanning, inventory scanning and browser background
tasks. It requests inventory cancellation instead of destroying a live QThread.
There is no forced termination of a blocked OS read; an unavailable filesystem
may delay cooperative stop. Errors preserve exception type/message. Per-file
read errors remain UNKNOWN rows with reason and a visible error/skip count.

If optional `olefile` is absent, the tab warns that OLE/DOC/XLS/PPT analysis may
remain UNKNOWN. Existing parser diagnostic `INSTALL_INVENTORY_EXTRA_FOR_OLE` is
retained. No substitute detector or optimistic classification is introduced.

## Windows packaging verification

`bfrs_gui.spec` includes the engine, controls, browser/view and parser modules,
plus `olefile`; the Windows build installs the `inventory` extra. The existing
Inno Setup recursive payload rule includes the whole collected application,
including `_internal`. It does not require loose repository Python sources.

`scripts/verify_frozen_inventory.py --exe <absolute BFRS.exe>` runs the production
windowed executable from a separate temporary directory, without PYTHONPATH or
PYTHONHOME. Its opt-in `--inventory-smoke-test <new-directory>` entry point creates
synthetic files, constructs the actual three-tab MainWindow with isolated
preferences, runs the inventory QThread, pumps Qt timers, compares JSONL with the
same CLI engine, and resumes. It verifies `sys.frozen`, absent stdout/stderr and
module origins under `sys._MEIPASS`. It writes only inside the newly created
test directory. The Windows build runs this verification before ZIP/installer
packaging and aborts on failure.

The pytest frozen test is enabled with `BFRS_FROZEN_EXE=<absolute BFRS.exe>`; without
it, that one integration case is explicitly skipped. Use the actual GUI spec
for this check, not a separate miniature test spec. This stage builds a test
PyInstaller payload only; it does not invoke Inno Setup or create a final installer.

## Validation and remaining manual checks

Synthetic tests cover ZIP/RAR/7z/PDF/DOC/XLS/PPT encryption markers, damaged files,
ordinary/empty files, Unicode names, a 1,200-file repeated-content tree, paged
results, CLI/GUI report equality, stop after nine files, resume without replaying
cached files, output/checkpoint/read failures, missing optional modules,
concurrent-writer rejection, simulated EFS/reparse attributes, no-console mode,
Qt responsiveness and safe main-window close. Existing bounded parser and wallet
regressions remain part of the full suite.

The execution host is Windows 11 x64. Real EFS was not enabled: attribute tests
use controlled stat data. Before distribution, test real encrypted files and
folders on NTFS with the appropriate Windows certificate, actual junctions,
removable/network drives, Windows 10 GUI/DPI, stop/restart and installation paths.
The future installer itself still requires installation/uninstallation testing;
static payload verification and a standalone EXE smoke test do not replace it.
