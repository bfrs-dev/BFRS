# Security and forensic data handling

BFRS processes evidence that may contain cryptocurrency secrets and personal
data. Treat every source image, report, checkpoint, carve, and recovery export
as sensitive unless an authorized review proves otherwise.

## Handling recovered material

- Work offline when inspecting recovered seed phrases, private keys, wallet
  databases, or plaintext key exports.
- Use encrypted, access-controlled storage and minimize copies.
- Never paste real seeds, private keys, WIF values, extended private keys, or
  recovered wallet contents into source code, tests, documentation, logs, chat,
  public issues, or pull requests.
- Do not upload disk images or recovery artifacts to public malware scanners,
  file-sharing services, CI systems, or hosted debugging tools.
- Treat reports and checkpoints as sensitive. Even secret-safe output can
  disclose local paths, physical offsets, fingerprints, filesystem history,
  and investigation context.
- Public test fixtures must be synthetic and must not be derived from real
  wallets or evidence images.

The repository safety checker examines tracked path metadata only:

```powershell
python scripts/check_public_repo_safety.py
```

It does not prove that arbitrary source or documentation is free of secrets.
Perform a separate authorized secret review before publication.

## Reporting a vulnerability

Do not include sensitive evidence or secret material in a public issue. Before
public release, the project owner must establish and document a private
security-contact channel. Until then, describe only the affected component and
request a private channel without attaching images, reports, checkpoints,
wallets, secrets, or reproductions derived from real evidence.

If a public issue is unavoidable, use synthetic data and redact machine names,
usernames, local paths, offsets tied to a private case, and all key material.

## Before public release

- establish a private security-contact channel;
- verify that Git history contains no forensic or recovery artifacts;
- run the repository safety checker;
- confirm that examples and tests use synthetic data only;
- confirm that the GPL-3.0 license metadata and LICENSE file are present.
