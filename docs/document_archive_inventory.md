# Quick document/archive inventory

This separate CLI script inventories a recovered folder without running wallet
or seed detectors. It reads at most 512 initial bytes of each ordinary file,
independent of its extension, then follows selected metadata only. It never
extracts archive payloads, launches Office, evaluates macros or tries passwords.

## Windows usage

From the checkout containing this change:

```powershell
cd C:\Projects\BFRS-2.0
py -m pip install -e ".[inventory]"
py .\scripts\inventory_documents.py --source "E:\Disk_Drill_Hp" --output "D:\BFRS-inventory-01"
```

The output directory must be new and outside the source tree. `olefile` is an
optional dependency used only for Office/OLE metadata. Without it OLE candidates
remain UNKNOWN with a dependency reason; other formats still work.

Stop with Ctrl+C; restart using the same paths plus `--resume`:

```powershell
py .\scripts\inventory_documents.py --source "E:\Disk_Drill_Hp" --output "D:\BFRS-inventory-01" --resume
```

Outputs:

* `inventory.jsonl`: recognized candidates, suspicious extensions, read errors
  and skipped links, one JSON record per file/path.
* `summary.json`: counts and explicit completeness/scope/limitations.
* `inventory.sqlite`: durable per-file checkpoint; do not delete while resuming.

The ordinary GUI scan is unchanged; this script is a separate inventory mode.
It does not use or modify the GUI/folder-scan checkpoint.

### Browse found files without rescanning

The separate viewer opens an existing `inventory.sqlite` in read-only mode:

```powershell
py -3.13 -m pip install "PySide6>=6.11,<7"
py -3.13 .\scripts\view_inventory.py --report "D:\BFRS-inventory-01\inventory.sqlite"
```

The default filter shows encryption markers. Other filters show UNKNOWN,
NO_ENCRYPTION_INDICATOR or all candidates. Search matches the filename/path,
including case-insensitive Polish characters; results are ordered by path and
paged in groups of 200. The table shows name, format, size, status, reason and
relative folder, with readable details below. Counts cover all candidates in
the last recorded run, independently of the current search/filter. An interrupted
run may contain only part of the source; the viewer does not imply completeness.

Select a row and choose **Pokaż w Eksploratorze**, or double-click the row, to
show and select the original file in Windows Explorer. No document is launched
by the viewer. **Kopiuj ścieżkę** copies its full path, also while the source is
offline. **Wskaż folder źródłowy** remaps the scan root for this viewing session
when a drive letter or folder location changes; choose the equivalent root,
not the selected file's immediate parent. Relative subfolders are preserved.
The original root can be restored with a button. No report or source file is
rewritten; remapping does not verify content identity at the new location.

Browsing reads only SQLite, not source content or source file attributes. Each
page uses a short read-only transaction, and query work runs outside the UI
thread with a 15-second SQLite execution budget. No database connection is held
between operations. Missing or moved files produce an explanatory message when
revealed; no automatic scan is started. The selected path is checked for regular
file status and link/reparse components before revealing. Windows paths are
passed directly to Shell APIs without shell command interpolation. Explorer
itself controls its preview and thumbnail behavior.

The viewer uses the existing optional PySide6 GUI dependency and does not change
scanner performance or require that dependency for CLI scans. It is currently
a separate window, not a new tab in the main BFRS GUI. On other platforms the
reveal action opens the containing folder without selecting the file. Existing
version-1 inventory checkpoints are supported; JSONL alone is not a viewer input.

## Meaning of results

* ENCRYPTED: a supported encryption flag, record, Office stream pair or PDF
  trailer encryption entry was found.
* NO_ENCRYPTION_INDICATOR: no encryption marker was found in the checked headers.
  This does NOT prove the payload is intact, fully readable or wallet-related.
* UNKNOWN: unsupported metadata, a limit, an error, or an undecided format.
  See `structure` and `reason`; do not interpret UNKNOWN as unencrypted.

ZIP central directory entries provide encryption flags and up to 50 filenames.
OOXML marker paths distinguish DOCX/XLSX/PPTX inside ZIP. RAR3/RAR5 header CRCs
are checked and encryption records/flags inspected without reading payloads.
Encrypted Office containers are identified by EncryptionInfo+EncryptedPackage;
legacy DOC uses FibBase.fEncrypted and BIFF8 XLS uses FILEPASS in globals.

Office metadata reads follow regular FAT sectors only as far as the required
prefix: 8 bytes of EncryptionInfo, 32 bytes of WordDocument, or XLS globals up to
FILEPASS/EOF. A stream larger than 1 MiB is no longer rejected solely by size.
The inspected logical prefix is capped at 1 MiB and all physical reads retain
the shared 2 MiB / 4096-call budget. A single sector is buffered at a time;
cycles, invalid links and truncated sectors encountered in that prefix remain
UNKNOWN. MiniFAT streams retain olefile's reader under the shared budget.
`ole_stream_scope=METADATA_PREFIX_ONLY` explicitly excludes validation of the
remaining stream chain or payload. Later damage can therefore coexist with a
classified encryption marker (or its absence in the inspected metadata).

DOC additionally accepts the Word 6.0 FIB pair `wIdent=0xA5DC, nFib=0x0065`, using
the encryption flag at the same header offset. Other versions with that legacy
identifier remain UNKNOWN; arbitrary identifiers are not accepted. Reports
include `doc_fib_ident` and `doc_fib_version`. XLS requires a BIFF8 workbook-globals
BOF, rejects an unexpected nested BOF and requires a zero-length EOF record.
These are metadata checks, not full document validation or text extraction.
Existing failed DOC/XLS results retry on resume; already cached unknown OLE
directories are unaffected because their inspection logic has not changed.

Other OLE containers remain UNKNOWN with `OLE_TYPE_UNDETERMINED`. Their report
now includes `ole_root_clsid` and up to 50 `ole_directory_entries` (directory ID,
name, numeric entry type, declared size and CLSID). These are flat, reachable
entries already loaded by olefile, not full hierarchical paths. The report also
includes the reachable non-root entry count, truncation flag and parsing-warning
flag. Directory slots are capped at 4096. No additional streams are opened and
no extra file reads are needed to collect these fields. Names, extensions and
CLSID values alone do not prove a format, absence of encryption or valid payload.

An unknown OLE container with a checked directory and no parser warnings can
now be cached on resume, while retaining its UNKNOWN encryption result. This
avoids repeatedly reading the same unsupported structure. An OLE-specific
inspection revision invalidates these cached entries when that analysis changes.
Errors, parser warnings, limits, changed sources and missing dependencies are
still retried. The version-1 SQLite schema gains an `inspection_revision` column
automatically; existing reports and successful-file checkpoints are preserved.
The first resume of an older checkpoint reads these unknown OLE files once to
collect the directory metadata; subsequent unchanged resumes reuse it. Actual
format recognition for proprietary OLE payloads remains follow-up work.

7z start/next-header CRCs are checked when within budget, but encryption remains
UNKNOWN pending a deeper coder/header parser. RTF is recognized by its start
signature, without parsing its full body. No integrity guarantee is made for a
payload, document XML or embedded files.

### PDF encryption metadata

PDF files, including renamed files, are checked from the final `startxref` and
`%%EOF`. The bounded parser reads classic trailer dictionaries or cross-reference
stream dictionaries, following `Prev` and hybrid `XRefStm` links.
Empty classic subsections (`0 0`) are supported, including hybrid update trailers;
their metadata links are still followed before classifying encryption. A non-null
top-level `Encrypt` dictionary/reference is an encryption marker. Matching words
in strings, comments or nested unrelated dictionaries are not markers. PDF name
escapes are decoded. Duplicate dictionary keys, malformed fields, cycles and
unsupported layouts produce UNKNOWN with an explicit reason.

Short printable ASCII text/HTML appended after the last `%%EOF` is tolerated
up to 1024 bytes (including surrounding whitespace). Such a suffix is reported
as `pdf_trailing_bytes`; it is not interpreted or validated as document content.
Ordinary whitespace alone reports zero. Binary suffixes, longer text, and suffixes
containing PDF structural keywords remain UNKNOWN. Only the final EOF is used,
so an invalid later revision is not bypassed by choosing an older trailer.

ENCRYPTED does not imply a password prompt: a PDF can use an empty user password.
`pdf_password_required` is always `NOT_CHECKED`. The inventory neither attempts
passwords (including an empty password) nor resolves the encryption dictionary,
loads pages, decodes streams, validates every xref record or checks the payload.
An indirect encryption reference is a marker, not proof that its target exists
or that the document can be recovered. NO_ENCRYPTION_INDICATOR means no marker
in the supported metadata reached by this pass, not a PDF integrity guarantee.

A PDF-based resource container or incomplete document may have a valid encryption
marker but no `Root` reference. This is reported as ENCRYPTED with structure
`PDF_TRAILERS_CHECKED_ROOT_MISSING`, reason `PDF_ENCRYPT_ENTRY_WITHOUT_ROOT`, and
`pdf_root_reference_present=false`. This does not assert a valid document catalog
or recoverable pages. A missing Root without an encryption marker remains UNKNOWN;
invalid metadata or unresolved metadata links also remain UNKNOWN. Detection is
based on structure, not a filename or producer allowlist.

PDF-specific limits: 64 KiB final-tail search, 4 KiB read buffers, 32 linked xref
sections, 256 classic subsections per section, 8192 tokens per section, nesting
depth 32, string length 64 KiB, name/word length 256 bytes and integer length 20
characters. All reads also share the existing 2 MiB / 4096-call per-file budget.
Classic 20-byte xref records are skipped by offset, checking the first and last
record in each subsection, so large tables are not loaded into memory. Xref
stream payloads are not decompressed. Small buffers/tail probes may include
adjacent content bytes without interpreting them.

This implementation uses the Python standard library only. No additional PDF
dependency is needed for the separate inventory script. Checkpoint version 1
is retained: old signature-only UNKNOWN PDF results are already retried by
`--resume`; unchanged successful results for other files are reused. Other
recognized UNKNOWN formats are retried, except checked OLE directories described
above. After classification,
unchanged successful PDF results are reused on subsequent resumes.

## Performance and safety

Read budget: 2 MiB and 4096 read calls per file; 4096 ZIP entries/RAR blocks;
64 KiB RAR header limit; 1 MiB Office metadata prefix limit. Non-candidates use only the
512-byte probe. Large recognized containers may require seeks to their metadata.
No whole-file hashing, decompression, secondary worker pool, or in-memory file
list is used. Directory traversal is streamed; SQLite persists batches of 100.
On interruption the current batch is committed and reports exported. Abrupt
termination can require redoing the last uncommitted batch.

Resume enumerates paths and stats again but reuses unchanged successfully
classified files using size, mtime and filesystem identity. Checked unknown OLE
directories are also reused until their inspection revision changes. Other
undetermined recognized containers are retried (e.g. after installing olefile). It does not
prove content identity if metadata has been deliberately preserved. Reports
include only paths visited in the current run; on a complete run deleted paths
are absent. Incomplete exports have complete=false.

Symlinks, Windows reparse points/junctions and non-regular files are skipped.
The output directory must not overlap the source tree. No deletion or source
modification is performed.

Limits: only signatures at offset zero; no SFX, raw-image carving, nested archives,
embedded-file analysis, complete RTF validation, password checking, ZIP64 or
complete multi-volume archive analysis. An unknown large/fragmented document
remains a candidate for a later focused pass.

Format references: https://www.rarlab.com/technote.htm ;
https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt ;
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/26fb6c06-4e5c-4778-ab4e-edbf26a545bb ;
https://pdf-issues.pdfa.org/32000-2-2020/clause07.html ;
https://pdfa.org/glossary-of-pdf-terms/

Legacy Word header cross-check (LibreOffice WW8Fib reader/writer):
https://dev-builds.libreoffice.org/lcov_reports/master-2015-06-10_23.49.39/sw/source/filter/ww8/ww8scan.cxx.gcov.html
