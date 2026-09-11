# Contributing

BFRS is pre-release forensic tooling. Keep changes narrow, reviewable, and
supported by deterministic tests.

- Run `pytest -q` before submitting a change.
- Use only synthetic fixtures. Never contribute real wallets, disk images,
  reports, checkpoints, seeds, private keys, WIF values, or recovered data.
- Do not add large binary fixtures. Build the smallest synthetic byte sequence
  needed by the test in a temporary directory.
- Preserve forensic offsets, provenance, validation outcomes, and secret-safe
  reporting unless the change explicitly updates their contract.
- A change to detector or validation meaning that can affect `RawHit` requires
  a bump of `UNIFIED_SCANNER_SEMANTICS_VERSION` and compatibility tests.
- A serialization change to unified checkpoints requires a bump of
  `UNIFIED_CHECKPOINT_FORMAT_VERSION` and format tests.
- Update user-facing documentation when CLI behavior changes.
- Run `python scripts/check_public_repo_safety.py` before any public release.

Do not open a public issue or pull request containing sensitive evidence. See
`SECURITY.md` for handling and reporting guidance.
