# BFRS 2.0

BFRS 2.0 (Bitcoin Forensic Recovery System) is an offline, research-oriented
tool for locating, validating, and correlating cryptocurrency wallet artifacts
in disk images and other byte-addressable evidence sources. It is intended for
authorized forensic and recovery work. It does not connect to a blockchain,
move funds, test balances, or replace manual evidentiary review.

The project is pre-1.0 forensic/research tooling. Interfaces, report schemas,
and classifications may change before a stable public release.

## Current scope

The main scanner currently recognizes evidence associated with:

- Bitcoin Core, including Berkeley DB metadata and historical wallet records;
- Electrum, including JSON wallets, ECIES containers, legacy formats, and
  related NTFS provenance;
- MultiBit wallet structures and encrypted/export markers;
- Armory wallet and paper-backup markers;
- secrets such as structurally valid WIF and historical private-key encodings;
- BIP39 and Electrum mnemonic candidates, including checksum/seed validation
  and overlap/wordlist relevance classification;
- NTFS metadata used to correlate allocated, stale, resident, and detached
  wallet evidence.

Detection is evidentiary, not proof of ownership, recoverability, or value.
Weak markers and damaged filesystem context can produce false positives.

## Requirements and installation

- Python 3.11 or newer;
- enough local storage for reports and checkpoints;
- read-only access to the evidence source whenever possible.

For a local editable installation on Windows:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
```

For development and tests:

```powershell
python -m pip install -e ".[dev]"
pytest -q
```

The installed `bfrs` command and `python -m bfrs.cli` invoke the same CLI.

## Usage

The paths below are fictional. Store output on a separate working volume; do
not use the evidence image itself as an output or checkpoint path.

Full scan with the default target set:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\case-001-report.json
```

Select explicit targets:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\selected-targets.json `
  --targets bitcoin-core,electrum,multibit
```

Use mnemonic workers and include mnemonic detection in the shared scan:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\with-mnemonics.json `
  --include-mnemonic --workers 4
```

`--workers 0` lets BFRS choose up to four mnemonic workers. Worker count is an
execution setting and does not change unified checkpoint compatibility.

Create a checkpoint:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\case-001-report.json `
  --checkpoint D:\bfrs-work\case-001.checkpoint.sqlite
```

Resume with the same source, range, chunk geometry, targets, and scanner
semantics:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\case-001-report.json `
  --resume-checkpoint D:\bfrs-work\case-001.checkpoint.sqlite
```

A mnemonic-only scan is available when wallet/container recovery is not
required:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\mnemonic-review.json `
  --seed-scan-only --workers 4
```

Run `bfrs --help` for the complete option list, including bounded `--start` and
`--end` scans, overlap/chunk controls, Bitcoin text context, and report
revalidation.

## Interpreting results

BFRS report schema 3 exposes `normalized_state` with four independent axes:

- `discovery_state`: `RAW`, `REJECTED`, `CANDIDATE`, or `ACCEPTED`;
- `structural_state`: `NONE`, `FRAGMENT`, or `COMPLETE`;
- `crypto_state`: `NOT_APPLICABLE`, `UNCHECKED`, `VALID`, or `INVALID`;
- `recovery_relevance`: `INDEPENDENT`, `CONTEXT_REVIEW`, or
  `LIKELY_FALSE_POSITIVE`.

Legacy target-specific fields remain beside this contract for revalidation and
export compatibility. At a high level:

- raw/anchor-only findings are unconfirmed discovery signals;
- rejected findings failed structural or cryptographic checks;
- fragment findings contain partial structure and require context review;
- candidate/complete/strong findings passed format-specific structural checks;
- crypto-valid mnemonic or secret findings passed their relevant mathematical
  validation, but still require provenance and false-positive review;
- mnemonic relevance distinguishes independent candidates, context-review
  candidates, and likely wordlist false positives without invalidating the
  underlying cryptographic result.

Review reason codes, provenance, allocation state, validation status, and
physical offsets together. Never treat a single marker or confidence label as
conclusive evidence.

## Output and forensic safety

The JSON report is written to `--output`; SQLite checkpoints are written only
to the explicit `--checkpoint` path and updated transactionally when resuming.
Rejected report noise is aggregated while candidate and validated findings keep
their detailed, secret-safe fields.

- Treat source images as read-only and work from verified forensic copies.
- Keep reports, checkpoints, carves, and recovered material outside the source
  tree and on access-controlled storage.
- Reports and checkpoints may contain sensitive paths, offsets, fingerprints,
  metadata, or recovery evidence even when secret values are redacted.
- Never publish `reports/`, `checkpoints/`, `recovered/`, or `carves/`.
- Do not upload disk images, `wallet.dat`, wallet databases, seed phrases,
  private keys, or recovered exports to public services.
- Verify free disk space before long runs and retain hashes and acquisition
  notes outside BFRS.

The CLI rejects output/checkpoint paths that resolve to an input or source
report, including existing filesystem aliases where the platform exposes file
identity.

## Limitations

- False positives remain possible, especially for short textual markers,
  damaged structures, dense wordlist regions, and unallocated filesystem data.
- A structurally or cryptographically valid artifact may be unrelated to the
  investigated wallet and may not be recoverable.
- Scanning large images can be I/O- and CPU-intensive; multiprocessing behavior
  depends on the platform and storage device.
- Unified checkpoints use SQLite format 3 and reject incompatible scanner
  semantics or legacy JSON checkpoints explicitly.
- Reports remain monolithic JSON and may require substantial memory for very
  large sets of retained candidate or validated findings.

## Support BFRS

If BFRS helps you recover a wallet or cryptographic recovery material
and you would like to support development, donations are voluntary.

Bitcoin (PUBLIC_DONATION_ADDRESS):
`bc1qw4yrk7dhc2xcnpneh392xzdp9ey05saaxq8dav`

Donation is optional and does not affect access to any BFRS feature.
The CLI displays this invitation only after validated recovery material is found.

## License

BFRS 2.0 is licensed under the GNU General Public License v3.0.
See LICENSE for details.

See [SECURITY.md](SECURITY.md) for data-handling requirements and
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules.
