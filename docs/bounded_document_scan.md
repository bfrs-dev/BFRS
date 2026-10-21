# Bounded document scanning — first implementation

Ordinary FILE/FOLDER target scans (including the GUI configuration path) now
perform a supplementary text scan for .docx and .xlsx files. Image scans and
partial file ranges do not invoke it. The existing seed-only pipeline is unchanged.

## Cost and limits

* Unsupported extensions return without additional stat/open/read calls.
* Only selected XML parts are decompressed; no macros, Office processes,
  embedded objects, external links or filesystem extraction are used.
* One parser slot per process bounds concurrency across folder file workers.
* Maximum source size: 32 MiB; 4096 ZIP members; 4 MiB per XML part;
  16 MiB cumulative XML; 4 MiB extracted UTF-8 text.
* DOCX: main text, headers, footers. Formatting runs are concatenated within
  paragraphs, with explicit breaks preserved.
* XLSX: shared strings resolved in worksheet cell order, inline strings and
  stored cell values. Formulas are not evaluated. This is not a layout-aware
  reconstruction of arbitrary multi-cell secret encodings.

The pass reuses validated Bitcoin WIF detection when `secrets` is selected and
mnemonic validation only for requested standards. It performs a bounded second
read of document parts, not a second scan of the entire directory.

`document_scan` records completion, limits/failures, decompressed byte counts,
and a separate mnemonic summary. Existing raw-byte mnemonic and I/O summaries
remain raw-pass metrics. Overall finding summaries include document findings.
Extracted hits use null physical/file offsets, logical UTF-8 offsets in
safe_metadata, and DOCUMENT_EXTRACTED_TEXT provenance. Reports do not contain
extracted text, private keys or seed words.

Folder checkpoint semantics include document_scan_version. Older checkpoints
are rejected with a settings mismatch rather than silently skipping the new
analysis. Retain old checkpoints for their old scanner; use a new checkpoint
for this version. New-version partial checkpoints retain document results.

## Remaining work

This is intentionally the first bounded implementation, not complete Office or
archive recovery. Renamed files, legacy DOC/XLS, PDF integration, encrypted
Office classification, embedded files, RAR/ZIP/7z content and image carving
remain separate work. An OLE header on a .docx/.xlsx reports an unsupported
OLE-or-encrypted container; it is not proof of encryption.

Next steps should begin with a document/archive inventory mode that can run
without repeating wallet detection across unrelated files, followed by legacy
Office and isolated PDF parsers. Reuse the same secret detectors and explicit
coverage/limit reporting. Add budgeted embedded-object traversal only afterward.

## Validation

Synthetic compressed DOCX with a WIF split across runs; XLSX seed words whose
shared-string order differs from cell order; GUI configuration to CLI routing;
FILE/FOLDER reports; checkpoint restart; old checkpoint rejection; no-I/O fast
filter; malformed ZIP/XML, OLE and byte limits; large ignored embedded object.

Local Linux microbenchmark (not a Windows/HDD scan-time prediction): 100,000
non-document filter calls took 0.187 seconds; 100 cached small DOCX/WIF scans took
0.015 seconds. The zero-extra-I/O test is the meaningful guarantee for ordinary
files. Real document-heavy performance still needs measurement on the user's
machine.
