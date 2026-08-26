"""Public Bitcoin context detectors with strict validation and bounded scope."""

from collections.abc import Callable
import re

from bfrs.core.chunk_reader import Chunk
from bfrs.core.models import RawHit
from bfrs.validators.bitcoin_address import validate_bitcoin_mainnet_address
from bfrs.validators.bitcoin_public_key import (
    validate_sec_public_key,
    validate_textual_sec_public_key,
)


TARGET_BITCOIN_CORE = "bitcoin-core"
BITCOIN_CONTEXT_ARTIFACT_KINDS = frozenset(
    {"bitcoin_address", "bitcoin_public_key"}
)
_BASE58_ADDRESS = re.compile(
    rb"(?<![1-9A-HJ-NP-Za-km-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}"
    rb"(?![1-9A-HJ-NP-Za-km-z])"
)
_BECH32_ADDRESS = re.compile(
    rb"(?<![0-9A-Za-z])(?i:bc1[023456789acdefghjklmnpqrstuvwxyz]{6,87})"
    rb"(?![0-9A-Za-z])"
)
_TEXTUAL_SEC = re.compile(
    rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{130}|[0-9A-Fa-f]{66})"
    rb"(?![0-9A-Fa-f])"
)


class BitcoinTextContextChunkDetector:
    """Scan bounded ASCII tokens; never create structural wallet evidence."""

    required_overlap = 130

    def detect_chunk(
        self,
        chunk: Chunk,
        *,
        source: str,
        ownership_start: int,
        ownership_end: int,
        status: Callable[[str], None] | None = None,
    ):
        findings: list[RawHit] = []
        for pattern in (_BASE58_ADDRESS, _BECH32_ADDRESS):
            for match in pattern.finditer(chunk.data):
                start = chunk.offset + match.start()
                if not ownership_start <= start < ownership_end:
                    continue
                address = match.group(0).decode("ascii")
                validation = validate_bitcoin_mainnet_address(address)
                findings.append(
                    RawHit(
                        start,
                        chunk.offset + match.end(),
                        "bitcoin_address_candidate",
                        0.75 if validation.valid else 0.0,
                        source,
                        {"category": "bitcoin_context_evidence"},
                        target=TARGET_BITCOIN_CORE,
                        artifact_kind="bitcoin_address",
                        structural_status=(
                            "CONTEXT_ONLY" if validation.valid else "REJECTED"
                        ),
                        validation_status=(
                            "CHECKSUM_VALID" if validation.valid else "REJECTED"
                        ),
                        reason_codes=validation.reason_codes,
                        correlated_evidence=(
                            (validation.encoding or "UNKNOWN_ENCODING",)
                            if validation.valid
                            else ()
                        ),
                        safe_metadata={
                            "address": address,
                            "address_type": validation.address_type,
                            "encoding": validation.encoding,
                            "checksum_valid": validation.checksum_valid,
                            "structural_wallet_status": "NOT_EVALUATED",
                        },
                        recommended_recovery_action="BITCOIN_CONTEXT_REVIEW",
                    )
                )

        for match in _TEXTUAL_SEC.finditer(chunk.data):
            start = chunk.offset + match.start()
            if not ownership_start <= start < ownership_end:
                continue
            validation = validate_textual_sec_public_key(
                match.group(0).decode("ascii")
            )
            findings.append(
                RawHit(
                    start,
                    chunk.offset + match.end(),
                    "bitcoin_textual_public_key_candidate",
                    0.70 if validation.valid else 0.0,
                    source,
                    {"category": "bitcoin_context_evidence"},
                    target=TARGET_BITCOIN_CORE,
                    artifact_kind="bitcoin_public_key",
                    structural_status=(
                        "CONTEXT_ONLY" if validation.valid else "REJECTED"
                    ),
                    validation_status=(
                        "SECP256K1_VALID" if validation.valid else "REJECTED"
                    ),
                    reason_codes=validation.reason_codes,
                    correlated_evidence=(("TEXT_HEX",) if validation.valid else ()),
                    safe_fingerprint=validation.safe_fingerprint,
                    safe_metadata={
                        "representation": "TEXT_HEX",
                        "compressed": validation.compressed,
                        "structural_wallet_status": "NOT_EVALUATED",
                    },
                    recommended_recovery_action="BITCOIN_CONTEXT_REVIEW",
                )
            )

        yield from sorted(
            findings,
            key=lambda item: (
                item.start_offset,
                item.end_offset,
                item.hit_type,
            ),
        )


def scan_bitcoin_context_for_sec_pubkeys(
    data: bytes,
    base_offset: int,
    *,
    source: str = "bounded-bitcoin-context",
) -> tuple[RawHit, ...]:
    """Find valid binary SEC keys only inside a caller-provided context."""
    if base_offset < 0:
        raise ValueError("base_offset must not be negative")
    findings: list[RawHit] = []
    for local_offset, prefix in enumerate(data):
        if prefix in (2, 3):
            length = 33
        elif prefix == 4:
            length = 65
        else:
            continue
        end = local_offset + length
        if end > len(data):
            continue
        validation = validate_sec_public_key(data[local_offset:end])
        if not validation.valid:
            continue
        findings.append(
            RawHit(
                base_offset + local_offset,
                base_offset + end,
                "bitcoin_binary_sec_public_key_context",
                0.65,
                source,
                {"category": "bitcoin_context_evidence"},
                target=TARGET_BITCOIN_CORE,
                artifact_kind="bitcoin_public_key",
                source_kind="BOUNDED_BITCOIN_CONTEXT",
                structural_status="CONTEXT_ONLY",
                validation_status="SECP256K1_VALID",
                reason_codes=("BITCOIN_CONTEXT_SEC_PUBKEY_VALID",),
                correlated_evidence=("BOUNDED_BITCOIN_CONTEXT",),
                safe_fingerprint=validation.safe_fingerprint,
                safe_metadata={
                    "representation": "BINARY_SEC",
                    "compressed": validation.compressed,
                    "structural_wallet_status": "NOT_EVALUATED",
                },
                recommended_recovery_action="BITCOIN_CONTEXT_REVIEW",
            )
        )
    return tuple(findings)
