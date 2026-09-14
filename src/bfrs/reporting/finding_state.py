"""Public-only normalization; never used for scanning or checkpoint decisions."""
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping


class DiscoveryState(str, Enum):
    RAW = "RAW"
    REJECTED = "REJECTED"
    CANDIDATE = "CANDIDATE"
    ACCEPTED = "ACCEPTED"


class StructuralState(str, Enum):
    NONE = "NONE"
    FRAGMENT = "FRAGMENT"
    COMPLETE = "COMPLETE"


class CryptoState(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNCHECKED = "UNCHECKED"
    VALID = "VALID"
    INVALID = "INVALID"


class RecoveryRelevance(str, Enum):
    INDEPENDENT = "INDEPENDENT"
    CONTEXT_REVIEW = "CONTEXT_REVIEW"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"


@dataclass(frozen=True, slots=True)
class PublicFindingState:
    discovery_state: DiscoveryState
    structural_state: StructuralState
    crypto_state: CryptoState
    recovery_relevance: RecoveryRelevance

    def safe_dict(self) -> dict[str, str]:
        return {key: value.value for key, value in asdict(self).items()}


_CRYPTO_VALID = {
    "CRYPTO_VALID", "BASE58CHECK_AND_SECP256K1_VALID", "SECP256K1_VALID",
    "CHECKSUM_VALID", "BIP39_VALID", "ELECTRUM_SEED_VALID",
    "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID",
}
_CRYPTO_INVALID = {
    "CHECKSUM_INVALID", "PRIVATE_SCALAR_INVALID", "PUBLIC_KEY_MISMATCH",
    "BIP39_CHECKSUM_INVALID", "ELECTRUM_SEED_VERSION_INVALID",
    "ELECTRUM_V1_ROUNDTRIP_INVALID",
}
_STRUCTURAL_VALID = {
    "BERKELEY_METADATA_STRUCTURAL_VALID", "BITCOIN_RECORD_STRUCTURAL_VALID",
    "BITCOIN_RECORD_KEY_SIDE_VALID", "ELECTRUM_CONTAINER_STRUCTURAL_VALID",
    "PROTOBUF_STRUCTURAL_VALID", "ARMORY_HEADER_STRUCTURAL_VALID",
}
_FRAGMENT_VALID = {
    "BERKELEY_METADATA_FRAGMENT", "ELECTRUM_CONTAINER_FRAGMENT_VALID",
    "PROTOBUF_FRAGMENT_VALID", "EXPORT_KEY_FORMAT_VALID", "ENCRYPTED_FRAGMENT",
    "JAVA_SERIALIZED_WALLET_FRAGMENT", "ARMORY_FRAGMENT_VALID",
}
_REJECTED = {
    "BITCOIN_RECORD_KEY_SIDE_REJECTED",
    "REJECTED", "INSUFFICIENT_PROTOBUF_STRUCTURE", "INSUFFICIENT_EXPORT_STRUCTURE",
    "INSUFFICIENT_ENCRYPTED_STRUCTURE", "OUT_OF_SCOPE_MULTIBIT_HD",
    "INSUFFICIENT_JAVA_SERIALIZATION_STRUCTURE", "INSUFFICIENT_ARMORY_STRUCTURE",
    "BIP39_WORD_COUNT_INVALID", "BIP39_WORD_INVALID",
    "ELECTRUM_V1_WORD_COUNT_INVALID", "ELECTRUM_V1_WORD_INVALID",
    "ELECTRUM_V1_INVALID_ENTROPY_LENGTH",
    "BITCOIN_RECORD_KEY_COMPACTSIZE_INVALID", "BITCOIN_RECORD_PUBKEY_LENGTH_INVALID",
    "BITCOIN_RECORD_PUBKEY_PREFIX_INVALID",
}
_GENERIC = {
    "RAW", "UNVALIDATED", "REJECTED", "CANDIDATE", "VALIDATED", "STRONG",
    "FRAGMENT", "COMPLETE", "STRUCTURAL", "ANCHOR_ONLY", "CONTEXT_ONLY",
    "NONE", "TRUNCATED", "STRUCTURAL_FRAGMENT", "SERIALIZATION_UNSUPPORTED",
}
_RELEVANCE = {
    "INDEPENDENT_CANDIDATE": RecoveryRelevance.INDEPENDENT,
    **{item.value: item for item in RecoveryRelevance},
    "LIKELY_WORDLIST_FALSE_POSITIVE": RecoveryRelevance.LIKELY_FALSE_POSITIVE,
}


def _text(value: Any) -> str:
    return str(value.value if isinstance(value, Enum) else value).upper()


def normalize_finding(finding: Mapping[str, Any] | Any) -> PublicFindingState:
    """Adapt RawHit, ValidationResult, or an explicitly prepared report row.

    COMPLETE describes the artifact, not necessarily a wallet. STRUCTURAL
    alone confirms evidence, not completeness. Unknown vocabulary is an error.
    """
    if not isinstance(finding, Mapping):
        if hasattr(finding, "safe_dict"):
            finding = finding.safe_dict()
        else:
            finding = {"status": finding.status}
    metadata = finding.get("safe_metadata", {})
    structural = _text(finding.get("structural_status", finding.get("status", "UNVALIDATED")))
    validation = _text(finding.get("validation_status", "UNVALIDATED"))
    completeness = _text(finding.get("completeness", metadata.get("completeness", "NONE")))
    for field, value, allowed in (
        ("structural_status", structural, _GENERIC),
        ("validation_status", validation, _GENERIC | _CRYPTO_VALID | _CRYPTO_INVALID |
         _STRUCTURAL_VALID | _FRAGMENT_VALID | _REJECTED),
        ("completeness", completeness, {"NONE", "COMPLETE", "FRAGMENT", "TRUNCATED", "STRUCTURAL_FRAGMENT"}),
    ):
        if value not in allowed:
            raise ValueError(f"unknown legacy {field}: {value}")
    artifact = str(finding.get("artifact_kind", "")).lower()
    context = artifact in {"bitcoin_address", "bitcoin_public_key"} or structural == "CONTEXT_ONLY"
    secret = artifact in {"mnemonic", "wif_private_key", "ec_private_key_der", "private_key"}
    rejected = structural == "REJECTED" or validation in _REJECTED | _CRYPTO_INVALID
    structure = StructuralState.NONE
    if (structural in {"STRUCTURAL", "FRAGMENT", "TRUNCATED", "STRUCTURAL_FRAGMENT"}
            or validation in _FRAGMENT_VALID | {"TRUNCATED", "FRAGMENT"}
            or completeness in {"FRAGMENT", "TRUNCATED", "STRUCTURAL_FRAGMENT"}):
        structure = StructuralState.FRAGMENT
    if structural in {"COMPLETE", "STRONG"} or completeness == "COMPLETE":
        structure = StructuralState.COMPLETE
    if validation == "ELECTRUM_CONTAINER_STRUCTURAL_VALID":
        structure = StructuralState.COMPLETE
    if context:
        structure = StructuralState.NONE
    crypto = CryptoState.UNCHECKED
    if context or (structural in {"RAW", "UNVALIDATED", "ANCHOR_ONLY"} and not secret):
        crypto = CryptoState.NOT_APPLICABLE
    if validation in _CRYPTO_VALID:
        crypto = CryptoState.VALID
    elif validation in _CRYPTO_INVALID:
        crypto = CryptoState.INVALID
    discovery = DiscoveryState.RAW
    if structure != StructuralState.NONE or structural == "CANDIDATE" or validation == "CANDIDATE":
        discovery = DiscoveryState.CANDIDATE
    if (structural in {"COMPLETE", "STRONG", "VALIDATED", "STRUCTURAL"} or
            validation in _CRYPTO_VALID | _STRUCTURAL_VALID | {"VALIDATED"} or
            completeness == "COMPLETE"):
        discovery = DiscoveryState.ACCEPTED
    if rejected:
        discovery = DiscoveryState.REJECTED
    relevance = (RecoveryRelevance.CONTEXT_REVIEW if context or discovery in {
        DiscoveryState.RAW, DiscoveryState.CANDIDATE, DiscoveryState.REJECTED,
    } else RecoveryRelevance.INDEPENDENT)
    legacy_relevance = finding.get("recovery_relevance", metadata.get("recovery_relevance"))
    if legacy_relevance is not None:
        if legacy_relevance not in _RELEVANCE:
            raise ValueError(f"unknown legacy recovery_relevance: {legacy_relevance}")
        relevance = _RELEVANCE[legacy_relevance]
    return PublicFindingState(discovery, structure, crypto, relevance)


def normalized_row(row: Mapping[str, Any], **adapter_fields: Any) -> dict[str, Any]:
    """Keep all legacy fields; adapter hints are not serialized."""
    return {**row, "normalized_state": normalize_finding({**row, **adapter_fields}).safe_dict()}


def summarize_findings(
    findings, *, scope: str = "target_findings_before_aggregation; recovery views are not additive",
) -> dict[str, Any]:
    """Count canonical target occurrences before noise aggregation.

    Recovery views overlap these occurrences and are not added. Unique secrets
    count available safe fingerprints, never invent identities for missing ones.
    """
    summary = {
        "scope": scope,
        "rejected": 0,
        "review_candidates": 0,
        "accepted_candidates": 0,
        "structurally_complete": 0,
        "crypto_valid_occurrences": 0,
        "crypto_valid_secret_occurrences": 0,
        "crypto_valid_unique_secrets": 0,
        "crypto_valid_secrets_without_fingerprint": 0,
        "unique_secret_scope": "available safe fingerprints; cross-format identity is not inferred",
    }
    secret_kinds = {"mnemonic", "wif_private_key", "ec_private_key_der", "private_key"}
    fingerprints = set()
    # Do not materialize another copy of potentially millions of RawHit rows.
    for item in findings:
        row = item.safe_dict() if hasattr(item, "safe_dict") else item
        state = (PublicFindingState(**row["normalized_state"])
                 if "normalized_state" in row else normalize_finding(row))
        rejected = state.discovery_state == DiscoveryState.REJECTED
        accepted = state.discovery_state == DiscoveryState.ACCEPTED
        summary["rejected"] += rejected
        summary["accepted_candidates"] += accepted
        summary["review_candidates"] += (
            state.discovery_state == DiscoveryState.CANDIDATE or
            (accepted and state.recovery_relevance == RecoveryRelevance.CONTEXT_REVIEW))
        summary["structurally_complete"] += (
            state.structural_state == StructuralState.COMPLETE and not rejected)
        if state.crypto_state != CryptoState.VALID:
            continue
        summary["crypto_valid_occurrences"] += 1
        if str(row.get("artifact_kind", "")).lower() not in secret_kinds:
            continue
        summary["crypto_valid_secret_occurrences"] += 1
        fingerprint = row.get("safe_fingerprint")
        if fingerprint:
            fingerprints.add(fingerprint)
        else:
            summary["crypto_valid_secrets_without_fingerprint"] += 1
    summary["crypto_valid_unique_secrets"] = len(fingerprints)
    return summary
