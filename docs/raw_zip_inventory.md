# ZIP metadata search inside raw disk images

`scripts/inventory_zip_image.py` scans the entire byte stream of a regular raw
image file (`.img`, `.dd`, `.bin`, `.raw`, or any other filename). It can find ZIP
headers that are no longer reachable as files in a filesystem. It does not
determine whether the bytes belong to a deleted file, a live file, embedded data,
or a duplicate copy. It does not decode E01, compressed images, virtual-disk
containers, encrypted volumes or multipart images.

This is a separate inventory command. It does not run wallet/seed detectors,
change the unified scanner checkpoint, extract archive members, try passwords,
repair ZIPs or reconstruct fragments. The source is opened read-only. Reports
contain metadata and filenames only, never copied member payloads.

## Windows commands

Run from the checkout containing this feature (Python 3.11 or newer):

```powershell
py .\scripts\inventory_zip_image.py --source "E:\ExampleImage.img" --output "C:\BFRS_reports\zip-image-01"
```

Use a new output folder outside the source image. Stop with Ctrl+C and resume
using the same source and output paths:

```powershell
py .\scripts\inventory_zip_image.py --source "E:\ExampleImage.img" --output "C:\BFRS_reports\zip-image-01" --resume
```

No extra runtime dependency is needed. This command is not part of the existing
Windows EXE or the main GUI. The existing document-inventory viewer reads a
different database; do not open `zip_scan.sqlite` with that viewer.

Options:

| Option | Default | Behavior |
| --- | --- | --- |
| `--chunk-mib` | 8 | Sequential input block size, 1–64 MiB. Can change on resume. |
| `--max-candidates` | 1,000,000 | Signature candidates processed in one invocation. Reaching the limit stops before the next candidate; resume continues from that exact byte. |
| `--resume` | off | Require and validate an existing `zip_scan.sqlite`. |

Exit codes: `0` byte scan completed, `130` interrupted, `3` candidate limit reached,
`2` source/read/checkpoint/argument error. A successful byte scan does not mean
every candidate was supported or any archive is recoverable.

## Outputs and interpretation

* `zip_scan.sqlite`: checkpoint and candidate records. Keep it to resume.
* `zip_hits.jsonl`: all accepted metadata candidates, priority first, then offset.
* `zip_priority.jsonl`: records with a filename clue or supported password marker.
* `summary.json`: source identity, scanned prefix, stop reason, counts and limits.

All `offset`, `header_offset`, `data_offset`, candidate archive boundaries and
local-reference positions in these reports are **physical byte offsets in the
input file**, not partition-relative or decompressed offsets. The source image
path and size are recorded in the summary/checkpoint.

Each row describes a **header record**, not a distinct archive. A one-member ZIP
normally produces a local header, central-directory entry and EOCD record. These
three rows must not be counted as three recovered archives or three wallets.
Duplicate copies at different physical offsets remain separate evidence.

| Priority | Label | Meaning |
| --- | --- | --- |
| 4 | `WALLET_NAME_AND_PASSWORD_MARKER` | Wallet-related filename clue and encryption marker on the same checked member/header. |
| 3 | `WALLET_NAME` | Filename contains wallet/electrum/bitcoin/portfel, irrespective of encryption status. |
| 2 | `PASSWORD_MARKER` | Supported encryption marker without a wallet filename clue. |
| 1 | `BACKUP_NAME` | Generic backup filename clue only. |
| 0 | `OTHER_METADATA` | Other accepted metadata candidate. |

Filename clues are case-insensitive substrings in paths, not content detection.
For example, a `wallet.css` asset can match. No category confirms that a wallet,
private key, balance or usable archive exists. `NO_ENCRYPTION_INDICATOR` on a local
or central header applies only to that header, never the rest of an archive or
image. Unsupported layouts remain UNKNOWN.

## Detection and structural checks

Every byte position is searched for local headers (`PK 03 04`), central-directory
entries (`PK 01 02`) and end-of-central-directory records (`PK 05 06`). A three-byte
forward overlap preserves signatures split between chunks. Each signature start
has exactly one owner; variable metadata can be read across chunk boundaries.
Initial header and name/extra-field lengths, version, known method IDs, flags,
name decoding and extra-field boundaries are checked. Implausible or incomplete
headers are rejected and counted; they are not promoted to encryption evidence.

Classic stored/Deflate headers support password-marker classification. Plausible
ZIP64, multidisk, AES/strong-encryption or other supported method-ID records can
be retained as `UNSUPPORTED_LAYOUT` with UNKNOWN encryption. This first version
does not interpret those payload layouts or recover a filename that has itself
been encrypted or overwritten.

A local record can survive without an EOCD or central directory, and an orphan
central entry can survive without its local header. Such records remain
`HEADER_ONLY` and are not automatically assigned to a common archive. Declared
data bounds fitting inside an image do not prove the bytes are intact.

For a plausible classic EOCD, the scanner computes a candidate archive start
from directory size and offset, and validates the contiguous central directory
with the bounded ZIP parser. When possible, it also compares the first entry's
local header, name, flags, method and fixed size/CRC fields. Data-descriptor
entries do not provide all those fixed fields in their local headers. Results
explicitly distinguish matched, mismatched and unresolved first references.
Even `FIRST_LOCAL_HEADER_MATCHED` does not prove all members or payloads are
present: offsets can be stale and an archive can have been fragmented/overwritten.
No archive carving or export is performed.

## Performance, interruption and source identity

Memory is bounded by the configured scan block, small metadata buffers and the
bounded name-clue lists; no full-image or full-hit list is built. SQLite stores
hits incrementally. Metadata within the active scan block reuses cached bytes;
additional metadata reads are limited to 2 MiB / 4096 calls per candidate by the
shared inventory reader. Expensive/unsupported directory checks remain reported
as unresolved while physical signature scanning continues.

Candidate rows, counters and the exact next unprocessed byte are committed in
one SQLite transaction per block (or a deliberate mid-block stop). An interrupted
transaction is rolled back; a restart may repeat that uncommitted block but
does not skip it or duplicate committed rows. Completed prefixes are not scanned
again. Chunk size and per-run candidate limit can change on resume. Reports are
exported using atomic file replacements; SQLite remains authoritative if report
export is interrupted. An OS file lock rejects simultaneous writers to the same
report directory and is released when the process exits.

Resume checks the canonical source path, size, timestamps, filesystem identity,
scanner format version and SHA-256 of bounded beginning/middle/end samples.
These samples are **not a full-image hash**. Metadata changes during scanning,
source replacement or short reads stop the scan without advancing the affected
transaction. Source/sample changes reject stale resume. `io_this_run` separates
sequential reads, extra metadata reads and source-identity sample reads; a fully
completed resume still reads the identity samples.

`scan_complete` means the physical signature pass reached the image end with
the source checks passing. Always inspect `unresolved_record_count`,
`rejected_signatures`, `record_status`, `archive_origin_status` and the documented
scope. A zero-hit or completed scan does not exclude an overwritten, fragmented,
unsupported or volume-encrypted archive.

## Validation scope

Tests use synthetic images and filenames, including unaligned ZIPs, chunk-edge
signatures, orphan/truncated records, conflicting local names, checkpoints,
interruption, I/O errors, source mutation and bounded metadata. An optional
independent Info-ZIP writer produces a real password-encrypted test archive;
Python decrypts it with its known synthetic password before raw-image scanning.
Linux tests do not substitute for native Windows/XP smoke tests.

Format reference: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
