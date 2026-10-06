# BFRS 2.0

BFRS 2.0 (Bitcoin Forensic Recovery System) is an offline, research-oriented
tool for locating, validating, and correlating cryptocurrency wallet artifacts
in disk images, individual files, directory trees, and mounted filesystems. It
is intended for
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

The scanner combines structural validation with format-specific cryptographic
validation where the artifact permits it. Its recovery paths include validated
intact-wallet copying and experimental physical Berkeley DB reconstruction for
the conservative subsets documented in
[`docs/automatic_bitcoin_wallet_recovery.md`](docs/automatic_bitcoin_wallet_recovery.md)
and
[`docs/experimental_physical_wallet_export.md`](docs/experimental_physical_wallet_export.md).

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

Scan one ordinary file or a directory recursively:

```powershell
bfrs --input D:\RecoveredFiles\backup.dat `
  --output D:\bfrs-work\file-report.json --targets all

bfrs --input D:\RecoveredFiles `
  --source-type folder `
  --output D:\bfrs-work\folder-report.json --targets all `
  --file-workers 2 --workers 1
```

Directories and mounted volume roots are detected automatically. Folder scans
visit every regular file recursively, do not follow symlinks or junctions, and
continue after inaccessible or broken files. Findings from `FILE` and `FOLDER`
sources use `file_path` plus a file-local offset; `IMAGE` findings retain
physical-offset semantics. Large files still use the shared chunked reader and
overlap policy.

`--file-workers` controls bounded parallel processing of separate files in a
folder scan. Each worker creates isolated scanner and detector state; findings
cannot cross file boundaries. `--workers` keeps its existing meaning and
controls mnemonic processing inside each file scan. Files no larger than one
chunk use local mnemonic decoding to avoid per-file process startup; larger
files retain the requested mnemonic worker count. Detector indexes are reused
within each file worker and per-file reports are passed in memory. Every file
is still read in full with the same detection and validation rules.
Start with two file workers
for rotational media, measure locally, and use four only when the storage and
CPU benefit from it. Image and single-file scans accept neither parallel folder
work nor folder batching.

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

Resume an image or individual file with the same source, range, chunk geometry,
targets, and scanner semantics:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\case-001-report.json `
  --resume-checkpoint D:\bfrs-work\case-001.checkpoint.sqlite
```

Format 4 checkpoints atomically persist each completed ownership unit together
with its compressed, secret-safe finding state, digest, and counters. Resume
restores that state and skips normal target-scan reads for the completed prefix;
only an uncommitted unit is scanned again. Progress starts from the restored
byte count and ETA is based on newly processed bytes. Format 3 checkpoints did
not retain complete state for noisy units and are rejected with an explicit
legacy-replay message instead of being presented as true resume.

Folder scans support SQLite checkpoints with durable outcomes for each completed
file. Keep the checkpoint and report outside the source folder. Resume requires
the same discovered file paths, sizes, modification times, and detection
settings; completed files are skipped. `--workers` and `--file-workers` may be
changed when resuming, including checkpoints created by earlier GUI builds.
Changed detection settings are rejected with the names of the mismatched fields.

```powershell
bfrs --input D:\RecoveredFiles --source-type folder --targets all `
  --output D:\bfrs-work\folder-report.json --file-workers 2 --workers 1 `
  --checkpoint D:\bfrs-work\folder.checkpoint.sqlite

bfrs --input D:\RecoveredFiles --source-type folder --targets all `
  --output D:\bfrs-work\folder-report.json --file-workers 4 --workers 2 `
  --resume-checkpoint D:\bfrs-work\folder.checkpoint.sqlite
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

Opt in to recovery of complete, unambiguous wallets. This can copy a validated
intact wallet file or reconstruct a supported Bitcoin Core wallet from exact
validated Berkeley DB pages:

```powershell
bfrs --input X:\evidence\case-001.img `
  --output D:\bfrs-work\case-001-report.json `
  --targets all --recover-wallets `
  --recovery-dir D:\private-recovered
```

Both recovery flags are required: `--recover-wallets` is explicitly opt-in.
Recovery may write private wallet material. The private recovery directory must
remain outside every Git working tree. Each successful Bitcoin Core candidate
is written beneath `bitcoin-core\candidate_NNN\` as an atomically published
`wallet.dat` plus a secret-free `recovery_manifest.json`. Existing outputs are
never overwritten. Ordinary scans never write wallet files.

## Interpreting results

BFRS report schema 5 exposes `normalized_state` with four independent axes and
an optional-action `wallet_recovery` summary. The summary contains paths,
hashes, counters and fixed refusal codes only; wallet record values are never
embedded. The four finding-state axes are:

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

Review reason codes, provenance, allocation state, validation status, and the
source-specific location model together. Never treat a single marker or confidence label as
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
- Do not publish disk images, `wallet.dat`, wallet databases, private keys,
  mnemonic or seed phrases, recovered exports, or private recovery manifests.
- Public reports are designed to omit secret values, but must still be reviewed
  for sensitive paths, offsets, fingerprints, and case metadata before release.
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
- BFRS cannot recover data that has been overwritten and does not recover wallet
  passwords.
- BFRS does not decrypt encrypted wallets without the required key or password.
- Raw physical-disk devices such as Windows `\\.\PhysicalDriveN` are not a
  supported input. Use an acquired disk image, regular file, directory, or
  mounted filesystem path.
- Windows paths and mounted Windows volume roots are supported; filesystem and
  access-control behavior remains platform dependent.
- Scanning large images can be I/O- and CPU-intensive; multiprocessing behavior
  depends on the platform and storage device.
- Unified checkpoints use SQLite format 4 and reject incompatible scanner
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
