# Seed Phrase Document & Raw Recovery V1

This implementation performs offline, read-only discovery of complete BIP39 and
modern Electrum mnemonic phrases. Normal JSON reports never contain mnemonic
words, entropy, derived seeds, private keys, or surrounding source text. They
contain only validation metadata, physical provenance, and a domain-separated
SHA-256 fingerprint used for deduplication.

## Standards and validation

- BIP39 follows BIP-0039: 12/15/18/21/24 words, one coherent official wordlist,
  11-bit indices, and the ENT/32 SHA-256 checksum. All ten wordlists in the BIP
  repository are bundled unchanged and normalized with Unicode NFKD.
- Modern Electrum follows Electrum's `Mnemonic.normalize_text` and HMAC-SHA512
  `Seed version` prefixes (`01`, `100`, `101`, `102`). The five upstream
  Electrum wordlists are bundled unchanged. A phrase must also consist of words
  from one supported Electrum list.
- Historical Electrum hexadecimal seeds and the legacy pre-2.0 old mnemonic
  codec are not classified as word phrases in V1.

Primary sources: Bitcoin BIPs `bip-0039.mediawiki` and its wordlists; Electrum
`electrum/mnemonic.py`, `electrum/version.py`, and `electrum/wordlist/` in the
official `spesmilo/electrum` repository. BIP39 declares the MIT License and
Electrum's `LICENCE` is MIT; the files here retain their exact upstream contents.

## Sources and formats

The raw scanner reads bounded overlapping chunks and recognizes UTF-8/ASCII,
UTF-16LE, and UTF-16BE. It validates candidates before retention and records
exact half-open byte ranges. Memory use is O(chunk size + overlap + fixed
wordlist indexes); it does not grow with image size.

Known `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.html`, `.htm`, and `.rtf`
content uses the same byte scanner. DOCX extraction opens the ZIP container and
reads only bounded WordprocessingML text parts. Extracted-text positions are not
claimed as physical offsets. PDF text-layer extraction is deliberately reported
as unavailable in V1 because the project has no vetted PDF dependency; no OCR,
JavaScript, macros, embedded programs, or external processes are executed.

`--seed-scan-only` bypasses Bitcoin Core and Electrum wallet recovery paths.
Normal reports are safe to handle. Secret export is a separate rescan command
and requires both an explicit output path and `--allow-seed-export`; it refuses
to overwrite either the secret file or its safe manifest.

## Limitations

V1 retains complete checksum/version-valid phrases only. It counts invalid
BIP39 checksum windows diagnostically but does not put their words in reports.
It does not reconstruct missing words, derive wallet keys, perform OCR, parse
PDFs, or carve compressed DOCX containers from arbitrary raw bytes. Raw offsets
are exact for the decoded byte representation; DOCX results identify only the
container and extracted-text offset space.
