"""Safe result models that never retain mnemonic words."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True, slots=True)
class MnemonicCandidate:
    candidate_id: str
    family: str
    mnemonic_standard: str
    validation_status: str
    seed_type: str | None
    language: str | None
    word_count: int
    checksum_valid: bool | None
    completeness: str
    confidence: str
    reason_codes: tuple[str, ...]
    fingerprint: str
    source_kind: str
    source: str
    physical_start: int | None
    physical_end: int | None
    encoding: str | None
    recovery_relevance: str = "INDEPENDENT_CANDIDATE"
    correlation_cluster_id: str | None = None
    mft_record_number: int | None = None
    path: str | None = None
    allocation_state: str = "UNKNOWN_ALLOCATION"
    correlated_sources: tuple[str, ...] = ()
    duplicate_count: int = 1
    safe_metadata: dict = field(default_factory=dict)
    provenance: tuple[dict, ...] = ()

    def safe_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class MnemonicRecovery:
    anchors_found: int
    candidates_total: int
    high_confidence_candidates: int
    bip39_valid: int
    electrum_valid: int
    electrum_2_plus_valid: int
    electrum_v1_valid: int
    structural_fragments: int
    checksum_invalid: int
    known_file_candidates: int
    deleted_file_candidates: int
    raw_candidates: int
    document_candidates: int
    unique_secret_fingerprints: int
    duplicate_occurrences: int
    crypto_valid_occurrences: int
    independent_candidate_occurrences: int
    overlap_cluster_occurrences: int
    likely_wordlist_occurrences: int
    likely_wordlist_unique_fingerprints: int
    review_required_unique_fingerprints: int
    failures: tuple[str, ...]
    candidates: tuple[MnemonicCandidate, ...]

    def safe_dict(self) -> dict:
        return {
            **{name: getattr(self, name) for name in self.__slots__
               if name not in {"failures", "candidates"}},
            "failures": list(self.failures),
            "candidates": [item.safe_dict() for item in self.candidates],
        }
