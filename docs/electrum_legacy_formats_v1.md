# Electrum Legacy Raw Formats V1

This note records the format audit used by BFRS. It contains no wallet payloads
or user data. The implementation is intentionally narrower than Electrum's full
historical upgrade matrix.

## Audited primary sources

- Electrum 1.8.1 `lib/wallet.py`: wallet configuration fields, old master
  public key/accounts layout, field-level AES password encoding.
  <https://raw.githubusercontent.com/spesmilo/electrum/1.8.1/lib/wallet.py>
- Electrum 1.9.8 `lib/wallet.py`: `ast.literal_eval` read and `repr(dict)` write,
  `seed_version`, `accounts`, old and BIP32 master-key maps, watch-only logic.
  <https://raw.githubusercontent.com/spesmilo/electrum/1.9.8/lib/wallet.py>
- Electrum 2.0 `lib/wallet.py`: JSON-first read with Python-literal fallback,
  `wallet_type`, account variants, imported account representation, JSON write.
  <https://raw.githubusercontent.com/spesmilo/electrum/2.0/lib/wallet.py>
- Electrum 2.7.18 `lib/storage.py`: versions 4/11/13, legacy upgrade mappings
  for old, BIP32, multisig, hardware, imported and watch-only storage.
  <https://raw.githubusercontent.com/spesmilo/electrum/2.7.18/lib/storage.py>
- Electrum 3.0.6 `lib/storage.py`: retained JSON/Python-literal parsing and BIE1
  whole-file encryption boundary.
  <https://raw.githubusercontent.com/spesmilo/electrum/3.0.6/lib/storage.py>

## Confirmed variants

| Generation | Serialization | Structural identity | Encryption |
|---|---|---|---|
| Electrum 1.x | Python `repr(dict)` / `ast.literal_eval` | integer `seed_version`, `accounts`, and a validated old 128-hex `master_public_key` or pre-keystore public-key map | individual secret fields encoded when `use_encryption` is true |
| Electrum 2.0–2.7 transitional | JSON, with Python-literal backward-compatible input | integer `seed_version`, valid `wallet_type` when present, `accounts`, and old/BIP32/imported public structure | individual secret fields; no independent pre-BIE file framing |
| Electrum 2.7+ converted | JSON with `keystore`/`xN/` objects | modern keystore structure | handled by existing Electrum raw recovery, not legacy V1 |
| Electrum 3.x whole-file | base64 BIE1 (later BIE2) | ECIES framing | handled by existing BIE recovery |

Legacy wallets may contain `seed`, `master_private_keys`, `imported_keys`, or
`keypairs`. BFRS records only their type/presence. It never retains their values.
Old deterministic public identity uses `master_public_key`; BIP32-era storage
uses `master_public_keys`; account entries distinguish old, BIP32, multisig,
pending, and imported structures. `wallet_type` is not required for confirmed
1.x files because 1.9.8 inferred the class from `seed_version` and public-key
shape.

Complete boundaries are balanced outer dictionary braces with quote/escape
tracking. A fragment requires `seed_version`, `accounts`, and at least one of
`master_public_key`, `master_public_keys`, or `wallet_type`; a lone wallet-like
word is never evidence.

## Deliberately unsupported

- A standalone pre-BIE encrypted blob: audited versions encrypt values inside
  the storage dictionary, so there is no confirmed independent framing to scan.
- Unsupported intermediate seed versions 5–10 as distinct formats: Electrum's
  own upgrade code treats several as branch-specific or buggy. They may validate
  only when the common confirmed storage structure is intact; no version-specific
  secret interpretation is attempted.
- Arbitrary Python objects, pickle, source code, config snippets, loose seeds,
  private-key strings, and single-field fragments.
- Decryption, password testing, seed reconstruction, and private-key validation.
