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

## Meaning of results

* ENCRYPTED: a supported encryption flag, record or Office stream pair was found.
* NO_ENCRYPTION_INDICATOR: no encryption marker was found in the checked headers.
  This does NOT prove the payload is intact, fully readable or wallet-related.
* UNKNOWN: unsupported metadata, a limit, an error, or an undecided format.
  See `structure` and `reason`; do not interpret UNKNOWN as unencrypted.

ZIP central directory entries provide encryption flags and up to 50 filenames.
OOXML marker paths distinguish DOCX/XLSX/PPTX inside ZIP. RAR3/RAR5 header CRCs
are checked and encryption records/flags inspected without reading payloads.
Encrypted Office containers are identified by EncryptionInfo+EncryptedPackage;
legacy DOC uses FibBase.fEncrypted and BIFF8 XLS uses FILEPASS in globals.

7z start/next-header CRCs are checked when within budget, but encryption remains
UNKNOWN pending a deeper coder/header parser. PDF is identified by signature;
its encryption also remains UNKNOWN in this first quick pass. RTF is recognized
by its start signature, without parsing its full body. No integrity guarantee
is made for a payload, document XML or embedded files.

## Performance and safety

Read budget: 2 MiB and 4096 read calls per file; 4096 ZIP entries/RAR blocks;
64 KiB RAR header limit; 1 MiB Office stream limit. Non-candidates use only the
512-byte probe. Large recognized containers may require seeks to their metadata.
No whole-file hashing, decompression, secondary worker pool, or in-memory file
list is used. Directory traversal is streamed; SQLite persists batches of 100.
On interruption the current batch is committed and reports exported. Abrupt
termination can require redoing the last uncommitted batch.

Resume enumerates paths and stats again but reuses unchanged successfully
classified files using size, mtime and filesystem identity. Undetermined
recognized containers are retried (e.g. after installing olefile). It does not
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
https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/26fb6c06-4e5c-4778-ab4e-edbf26a545bb
