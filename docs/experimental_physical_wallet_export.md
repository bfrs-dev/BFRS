# Experimental exact-page wallet export V1

Normal scans only report reconstruction evidence. They never invoke this tool.
Explicit export requires an existing report, an accepted legacy candidate ID,
an unchanged source image and a new output path outside the public repository.
The destination directory must already exist.

```powershell
python -m bfrs.tools.export_reconstructed_wallet `
  --input <IMAGE> --report <REPORT_JSON> --candidate-id <ID> `
  --output <PRIVATE_DIRECTORY>\wallet.dat --allow-private-key-export
```

This copies original validated pages to `page_number * page_size` without any
record serialization, renumbering, repair or checksum regeneration. The entire
file must be mapped from page zero through the outer metadata last-page field.
A single active `main` catalog entry (network-byte-order metadata page number)
and matching nonzero Berkeley file IDs must connect the catalog and wallet
subdatabase. The subdatabase last-page field is not used as the global file size.
Report geometry and counts are checked against freshly read source pages.

V1 deliberately refuses free lists, overflow records/pages, metadata feature flags
(including checksums), encryption, extra subdatabases, unaccounted pages, missing
or conflicting mappings, invalid tree/leaf chains, malformed supported wallet
records and crypto/count mismatches. Other record types are retained verbatim.
This is a conservative supported subset, not a general Berkeley DB repair tool.

The temporary file is flushed and fsynced, reopened read-only and checked with
BFRS metadata, page, tree, chain, wallet-record and cryptographic validators.
Each page hash must match both the original snapshot and a fresh source read.
Publication is atomic and refuses existing files (Windows rename; POSIX atomic
hard-link publication, since POSIX rename would overwrite). The input is opened
read-only. Output and manifest aliases of input/report paths are refused.

A sibling `wallet.dat.manifest.json` contains only safe counters and file metadata.
The wallet and manifest are individually atomic, not a two-file transaction.
If manifest publication fails after the wallet is published, the fixed refusal
code `MANIFEST_PUBLICATION_FAILED_WALLET_CREATED` explicitly reports that state;
the validated wallet is retained and no existing manifest is overwritten.
Handled failures remove temporary files. A process/power interruption can leave
secret-bearing temporary files in the explicit private output directory.

Success means `BFRS_PHYSICAL_RECONSTRUCTION_VALID`. Bitcoin Core loadability
remains `NOT_TESTED` until a separate offline test with compatible Core tooling.
No network, Core process, installation or rescan is started by this tool.
Public tests generate synthetic pages; real evidence is never a repository fixture.
