# Bounded document scanning — first implementation

Ordinary FILE/FOLDER target scans (including the GUI configuration path) now
perform a supplementary text scan for .docx, .xlsx and .rtf files. Image scans and
partial file ranges do not invoke it. The seed-only pipeline also uses the bounded RTF reader for .rtf files.

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

## WordPad / RTF support

RTF is parsed directly as data with no external applications or dependencies.
The reader preserves text across formatting groups, decodes hex escapes,
Windows code pages (including 1250 and font charset overrides), Unicode and
fallback bytes, and retains paragraph/tab boundaries. It skips known metadata,
unknown starred destinations, pictures and objects; binary payload lengths are
validated before skipping. Field display text is retained without executing fields.

Limits: 16 MiB source, 4 MiB output, 256 nested groups. Parsing shares the existing
single document slot. Unbalanced/truncated input, unknown encodings, invalid
Unicode and unsupported alternate Unicode destinations produce explicit reasons
rather than a successful empty scan. This is text recovery, not a complete RTF
layout renderer; it does not OCR images or recover embedded objects. RTF controls
not affecting supported text are ignored. The implementation follows Microsoft
RTF text-encoding guidance:
https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfex/1e44fa4c-3ea3-402c-8b21-fb19a617e43b

RTF hits carry `bounded_rtf_v1` provenance and logical UTF-8 offsets.
Document scan version is now 2, so version-1 folder checkpoints cannot silently
reuse an RTF result from before this extension. The existing raw file scan still
runs independently and may find raw bytes in destinations omitted from text.

## Remaining work

This is intentionally the bounded implementation, not complete Office or
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
