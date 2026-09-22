# Automatic Bitcoin Core wallet recovery

Automatic recovery is an explicit private-output action. A normal scan retains
its read-only reporting behavior. To enable recovery, provide both
`--recover-wallets` and `--recovery-dir`; the destination must be outside a Git
working tree.

Recovery may write private wallet material. Keep recovered `wallet.dat` files,
private keys, mnemonic or seed phrases, and private recovery manifests out of
Git and public services. Public scan reports omit secret values, but still
require review for sensitive paths, offsets, fingerprints, and case metadata.

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
and the recovery method. Reconstructed image candidates use
`EXACT_VALIDATED_PAGE_COPY`. A complete wallet discovered as an ordinary file
uses `EXACT_INTACT_FILE_COPY` after byte-for-byte hash and format validation;
BFRS does not reconstruct its pages. Folder recovery places each source file
under a deterministic `file_NNNNNN` prefix so identical contents retain distinct
provenance and cannot collide.

The scan report schema is version 5 because P2.7 adds source type, source root,
and source-specific location semantics. Default reports set `requested` to
false and never create a private artifact. FOLDER resume is not yet supported;
folder checkpoint/resume is deferred to P2.7.1. Existing image and
individual-file checkpoint behavior is unchanged.
