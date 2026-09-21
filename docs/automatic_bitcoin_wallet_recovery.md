# Automatic Bitcoin Core wallet recovery

Automatic recovery is an explicit private-output action. A normal scan retains
its read-only reporting behavior. To enable recovery, provide both
`--recover-wallets` and `--recovery-dir`; the destination must be outside a Git
working tree.

Candidates are ordered by their earliest physical source offset and written as
`bitcoin-core/candidate_001/wallet.dat`, `candidate_002`, and so on. A candidate
must be accepted, must not be classified as a likely false positive, and must
pass the complete exact-page reconstruction policy. This proves the outer BDB
catalog relationship, wallet subdatabase tree, page geometry and mapping,
absence of missing or ambiguous pages, and post-write structural consistency.

The method copies original validated pages without serializing records or
altering checksums. Complete encrypted wallets are supported when both `ckey`
and `mkey` evidence is coherent; BFRS does not decrypt them or attempt password
recovery. Plaintext key cryptographic validation is additional evidence and is
not required for structurally complete encrypted wallets.

Every successful wallet has a sibling `recovery_manifest.json` containing only
safe identifiers, ranges, hashes, geometry, record counters, encryption state,
and the method `EXACT_VALIDATED_PAGE_COPY`. The scan report schema is version 4
because it adds the top-level `wallet_recovery` contract. Default reports set
`requested` to false and never create a private artifact.
