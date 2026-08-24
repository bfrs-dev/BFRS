"""Single registry for wallet targets sharing the streaming image pass."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from bfrs.core.chunk_reader import Chunk
from bfrs.core.models import RawHit
from bfrs.core.secp256k1 import GROUP_ORDER
from bfrs.recovery.electrum_raw_recovery import ELECTRUM_SIGNATURE_PATTERNS
from bfrs.recovery.metadata_less_fragments import FRAMED_BITCOIN_RECORD_PATTERNS
from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner
from bfrs.recovery.ntfs_detached_volume import (
    NTFS_BOOT_SECTOR_PATTERN,
    NTFS_BOOT_SECTOR_SIGNATURE,
)
from bfrs.recovery.ntfs_stale_file import (
    NTFS_FILE_RECORD_PATTERN,
    NTFS_FILE_RECORD_SIGNATURE,
)
from bfrs.recovery.ntfs_stale_indx import (
    NTFS_INDX_RECORD_PATTERN,
    NTFS_INDX_RECORD_SIGNATURE,
)
from bfrs.recovery.orphan_private_key_der import (
    HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
    HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
)
from bfrs.scanners.fast_scanner import Signature, SignatureAssessment
from bfrs.validators.berkeley_metadata import BTREE_MAGIC


TARGET_BITCOIN_CORE = "bitcoin-core"
TARGET_MULTIBIT = "multibit"
TARGET_ARMORY = "armory"
TARGET_ELECTRUM = "electrum"
TARGET_SECRETS = "secrets"
AVAILABLE_TARGETS = (
    TARGET_BITCOIN_CORE,
    TARGET_MULTIBIT,
    TARGET_ARMORY,
    TARGET_ELECTRUM,
    TARGET_SECRETS,
)
LEGACY_TARGETS = frozenset({
    TARGET_BITCOIN_CORE, TARGET_ELECTRUM, TARGET_SECRETS,
})

ARMORY_HEADER = b"\xbaWALLET\x00"
MULTIBIT_NETWORK = b"org.bitcoin.production"
MULTIBIT_EXPORT_HEADER = b"# KEEP YOUR PRIVATE KEYS SAFE"
MULTIBIT_HD_MARKERS = (b"mbhd.wallet.aes", b"org.multibit.hd", b"MultiBit HD")
MULTIBIT_LEGACY_MARKERS = (b"com.google.bitcoin", b"org.multibit.wallet")
ARMORY_PAPER_MARKERS = (b"Armory Paper Backup", b"ARMORY PAPER BACKUP")
_WIF = re.compile(rb"(?<![1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])")


def _bounded(chunk: Chunk, local_offset: int, before: int = 512,
             after: int = 4096) -> bytes:
    return chunk.data[max(0, local_offset - before):local_offset + after]


def _protobuf_network_framed(data: bytes, offset: int) -> bool:
    length = len(MULTIBIT_NETWORK)
    if offset < 2 or data[offset - 1] != length:
        return False
    return data[offset - 2] & 0x07 == 2


def _multibit_network_assessment(signature: Signature, chunk: Chunk,
                                 local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset)
    relative = local_offset - max(0, local_offset - 512)
    framed = _protobuf_network_framed(context, relative)
    public_key = any(marker in context for marker in (b"\x12\x21", b"\x12\x41"))
    private_key = b"\x1a\x20" in context
    encrypted_key = b"Salted__" in context or b"encryptedPrivateKey" in context
    evidence = tuple(name for name, present in (
        ("PROTOBUF_NETWORK_FIELD", framed),
        ("EC_PUBLIC_KEY_FIELD", public_key),
        ("EC_PRIVATE_KEY_FIELD", private_key),
        ("ENCRYPTED_KEY_FIELD", encrypted_key),
    ) if present)
    if framed and public_key and (private_key or encrypted_key):
        return SignatureAssessment(
            0.95, "STRONG", "PROTOBUF_STRUCTURAL_VALID",
            ("MULTIBIT_PROTOBUF_WALLET_CONFIRMED",), evidence,
            {"network": "bitcoin-mainnet", "key_material_kind": (
                "ENCRYPTED" if encrypted_key else "PLAINTEXT")},
            "MULTIBIT_WALLET_RECOVERY")
    if framed and (public_key or private_key or encrypted_key):
        return SignatureAssessment(
            0.65, "FRAGMENT", "PROTOBUF_FRAGMENT_VALID",
            ("MULTIBIT_PROTOBUF_KEY_FRAGMENT",), evidence,
            {"network": "bitcoin-mainnet"}, "MULTIBIT_FRAGMENT_RECOVERY")
    return SignatureAssessment(
        0.15, "WEAK", "ANCHOR_ONLY",
        (("MULTIBIT_NETWORK_ANCHOR_WITHOUT_PROTOBUF_STRUCTURE",)
         if not framed else ("MULTIBIT_NETWORK_FIELD_ONLY",)), evidence,
        {"network": "bitcoin-mainnet"}, "REVIEW_CONTEXT")


def _multibit_export_assessment(signature: Signature, chunk: Chunk,
                                local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 128, 2048)
    encrypted = b"Salted__" in context
    plaintext = _WIF.search(context) is not None
    if encrypted or plaintext:
        return SignatureAssessment(
            0.70, "FRAGMENT", "EXPORT_KEY_FORMAT_VALID",
            (("MULTIBIT_ENCRYPTED_KEY_EXPORT",) if encrypted else
             ("MULTIBIT_PLAINTEXT_KEY_EXPORT",)),
            (("ENCRYPTED_PAYLOAD",) if encrypted else ("WIF_SHAPE",)),
            {"encryption_state": "ENCRYPTED" if encrypted else "PLAINTEXT"},
            "MULTIBIT_KEY_EXPORT_RECOVERY")
    return SignatureAssessment(
        0.20, "WEAK", "MARKER_ONLY", ("MULTIBIT_EXPORT_MARKER_ONLY",),
        (), {}, "REVIEW_CONTEXT")


def _multibit_encrypted_assessment(signature: Signature, chunk: Chunk,
                                   local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 512, 512)
    multibit_marker = (MULTIBIT_NETWORK in context or
                       MULTIBIT_EXPORT_HEADER in context or
                       any(marker in context for marker in MULTIBIT_HD_MARKERS))
    return SignatureAssessment(
        0.65 if multibit_marker else 0.30,
        "FRAGMENT" if multibit_marker else "WEAK",
        "ENCRYPTED_FRAGMENT" if multibit_marker else "GENERIC_ENCRYPTED_ANCHOR",
        (("MULTIBIT_ENCRYPTED_KEY_FRAGMENT",) if multibit_marker else
         ("OPENSSL_SALTED_ANCHOR_ONLY",)),
        (("MULTIBIT_MARKER", "ENCRYPTED_PAYLOAD") if multibit_marker else ()),
        {"encryption_state": "ENCRYPTED"},
        "MULTIBIT_FRAGMENT_RECOVERY" if multibit_marker else "REVIEW_CONTEXT")


def _multibit_hd_assessment(signature: Signature, chunk: Chunk,
                            local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 512, 2048)
    metadata = sum(marker in context for marker in (
        b"wallet", b"recovery", b"encrypted", b"mbhd"))
    return SignatureAssessment(
        0.70 if metadata >= 2 else 0.30,
        "FRAGMENT" if metadata >= 2 else "WEAK",
        "MULTIBIT_HD_METADATA" if metadata >= 2 else "MARKER_ONLY",
        ("MULTIBIT_HD_STRUCTURE",) if metadata >= 2 else ("MULTIBIT_HD_MARKER_ONLY",),
        ("HD_WALLET_MARKER",), {"mnemonic_standard": "UNCONFIRMED"},
        "MULTIBIT_HD_RECOVERY")


def _multibit_legacy_assessment(signature: Signature, chunk: Chunk,
                                local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 1024, 2048)
    serialized = b"\xac\xed\x00\x05" in context
    return SignatureAssessment(
        0.60 if serialized else 0.20,
        "FRAGMENT" if serialized else "WEAK",
        "JAVA_SERIALIZED_WALLET_FRAGMENT" if serialized else "MARKER_ONLY",
        (("MULTIBIT_LEGACY_SERIALIZED_FRAGMENT",) if serialized else
         ("MULTIBIT_LEGACY_MARKER_ONLY",)),
        (("JAVA_SERIALIZATION_HEADER", "MULTIBIT_CLASS_MARKER")
         if serialized else ("MULTIBIT_CLASS_MARKER",)),
        {}, "MULTIBIT_FRAGMENT_RECOVERY" if serialized else "REVIEW_CONTEXT")


def _armory_assessment(signature: Signature, chunk: Chunk,
                       local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 64, 2048)
    wallet_id = b"walletID" in context
    root = any(marker in context for marker in (b"rootKey", b"keyData", b"watching-only"))
    version_bytes = chunk.data[local_offset + len(ARMORY_HEADER):
                               local_offset + len(ARMORY_HEADER) + 4]
    version = int.from_bytes(version_bytes, "little") if len(version_bytes) == 4 else 0
    plausible_version = 1 <= version <= 10_000_000
    if wallet_id and root and plausible_version:
        return SignatureAssessment(
            0.95, "STRONG", "ARMORY_HEADER_STRUCTURAL_VALID",
            ("ARMORY_FULL_HEADER_CONFIRMED",),
            ("BAWALLET_HEADER", "WALLET_ID_FIELD", "ROOT_KEY_FIELD"),
            {}, "ARMORY_WALLET_RECOVERY")
    if wallet_id or root or plausible_version:
        return SignatureAssessment(
            0.60, "FRAGMENT", "ARMORY_FRAGMENT_VALID",
            ("ARMORY_STRUCTURAL_FRAGMENT",),
            tuple(name for name, present in (
                ("WALLET_ID_FIELD", wallet_id), ("ROOT_KEY_FIELD", root),
                ("VERSION_FIELD", plausible_version)) if present),
            {}, "ARMORY_FRAGMENT_RECOVERY")
    return SignatureAssessment(
        0.10, "WEAK", "SIGNATURE_ONLY", ("ARMORY_SIGNATURE_ONLY",),
        ("BAWALLET_HEADER",), {}, "REVIEW_CONTEXT")


def _armory_paper_assessment(signature: Signature, chunk: Chunk,
                             local_offset: int) -> SignatureAssessment:
    return SignatureAssessment(
        0.55, "FRAGMENT", "PAPER_BACKUP_MARKER",
        ("ARMORY_PAPER_BACKUP_MARKER",), ("DOCUMENT_MARKER",),
        {"route": "DOCUMENT_RECOVERY"}, "DOCUMENT_RECOVERY")


class MnemonicChunkDetector:
    """Adapter exposing existing strict mnemonic validators to shared chunks."""

    required_overlap = 4096

    def __init__(self, standards: frozenset[str]) -> None:
        self.standards = standards
        self.scanner = RawMnemonicScanner(overlap=self.required_overlap)

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int,
                     ownership_end: int):
        result = self.scanner.scan_bytes(
            chunk.data, source=source, base_offset=chunk.offset,
            ownership_start=ownership_start, ownership_end=ownership_end)
        for occurrence in result.occurrences:
            candidate = occurrence.candidate
            if candidate.mnemonic_standard not in self.standards:
                continue
            start = candidate.physical_start
            end = candidate.physical_end
            if start is None or end is None:
                continue
            target = (TARGET_ELECTRUM if
                      candidate.mnemonic_standard.startswith("ELECTRUM") else
                      TARGET_SECRETS)
            yield RawHit(
                start, end, f"mnemonic_{candidate.mnemonic_standard.casefold()}",
                0.85 if candidate.confidence == "HIGH" else 0.65, source,
                {"category": "validated_mnemonic"}, target=target,
                artifact_kind="mnemonic",
                structural_status="COMPLETE",
                validation_status=candidate.validation_status,
                reason_codes=tuple(candidate.reason_codes),
                correlated_evidence=(candidate.encoding or "unknown",),
                safe_fingerprint=candidate.fingerprint,
                safe_metadata={
                    "mnemonic_standard": candidate.mnemonic_standard,
                    "word_count": candidate.word_count,
                    "language": candidate.language,
                    "encoding": candidate.encoding,
                },
                recommended_recovery_action="MNEMONIC_CONTEXT_REVIEW")


_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {value: index for index, value in enumerate(_BASE58_ALPHABET)}
_WIF_FINGERPRINT_DOMAIN = b"BFRS-WIF-FINGERPRINT-V1\0"


def _base58_decode(value: bytes) -> bytes | None:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_INDEX[character]
    except KeyError:
        return None
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(value) - len(value.lstrip(b"1"))) + body


class ValidatedSecretChunkDetector:
    """Strict Base58Check WIF validation over shared, owned chunks."""

    required_overlap = 52

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int, ownership_end: int):
        for match in _WIF.finditer(chunk.data):
            start = chunk.offset + match.start()
            if not ownership_start <= start < ownership_end:
                continue
            decoded = _base58_decode(match.group(0))
            if decoded is None or len(decoded) not in {37, 38} or decoded[0] != 0x80:
                continue
            payload, checksum = decoded[:-4], decoded[-4:]
            expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            compressed = len(payload) == 34 and payload[-1] == 1
            if checksum != expected or (len(payload) == 34 and not compressed):
                continue
            private = payload[1:33]
            scalar = int.from_bytes(private, "big")
            if not 1 <= scalar < GROUP_ORDER:
                continue
            fingerprint = hashlib.sha256(
                _WIF_FINGERPRINT_DOMAIN + private).hexdigest()
            yield RawHit(
                start, chunk.offset + match.end(), "validated_wif", 0.98, source,
                {"category": "validated_secret"}, target=TARGET_SECRETS,
                artifact_kind="WIF_PRIVATE_KEY", structural_status="COMPLETE",
                validation_status="BASE58CHECK_AND_SECP256K1_VALID",
                reason_codes=("WIF_BASE58CHECK_VALID", "SECP256K1_SCALAR_VALID"),
                correlated_evidence=("BASE58CHECK", "NETWORK_PREFIX", "SCALAR_RANGE"),
                safe_fingerprint=fingerprint,
                safe_metadata={"network": "bitcoin-mainnet", "compressed": compressed},
                recommended_recovery_action="SECRET_EXPORT_OPT_IN")


@dataclass(frozen=True, slots=True)
class TargetSelection:
    targets: frozenset[str]
    signatures: tuple[Signature, ...]
    chunk_detectors: tuple[MnemonicChunkDetector, ...]


_BITCOIN_TARGET_SIGNATURES = (
    Signature(NTFS_BOOT_SECTOR_SIGNATURE, NTFS_BOOT_SECTOR_PATTERN,
              "ntfs_boot_sector", TARGET_BITCOIN_CORE, "filesystem_anchor"),
    Signature(NTFS_FILE_RECORD_SIGNATURE, NTFS_FILE_RECORD_PATTERN,
              "ntfs_file_record", TARGET_BITCOIN_CORE, "filesystem_record"),
    Signature(NTFS_INDX_RECORD_SIGNATURE, NTFS_INDX_RECORD_PATTERN,
              "ntfs_indx_record", TARGET_BITCOIN_CORE, "filesystem_index"),
    Signature("berkeley_metadata_little_endian", BTREE_MAGIC.to_bytes(4, "little"),
              "berkeley_metadata", TARGET_BITCOIN_CORE, "berkeley_metadata"),
    Signature("berkeley_metadata_big_endian", BTREE_MAGIC.to_bytes(4, "big"),
              "berkeley_metadata", TARGET_BITCOIN_CORE, "berkeley_metadata"),
    *(Signature(name, pattern, "bitcoin_record", TARGET_BITCOIN_CORE,
                "wallet_record") for name, pattern in FRAMED_BITCOIN_RECORD_PATTERNS),
)

_SECRET_SIGNATURES = (
    Signature(HISTORICAL_EC_PRIVATE_KEY_DER_SIGNATURE,
              HISTORICAL_EC_PRIVATE_KEY_DER_ANCHOR,
              "historical_private_key_der", TARGET_SECRETS, "ec_private_key_der"),
)

_ELECTRUM_TARGET_SIGNATURES = (
    *(Signature(name, pattern, "electrum_raw_anchor", TARGET_ELECTRUM,
                "electrum_wallet_anchor") for name, pattern in ELECTRUM_SIGNATURE_PATTERNS),
)

BITCOIN_CORE_SIGNATURES_V1 = (
    *_BITCOIN_TARGET_SIGNATURES,
    *_SECRET_SIGNATURES,
    *_ELECTRUM_TARGET_SIGNATURES,
)

ELECTRUM_ONLY_SIGNATURES_V1 = (
    Signature(NTFS_BOOT_SECTOR_SIGNATURE, NTFS_BOOT_SECTOR_PATTERN,
              "ntfs_boot_sector", TARGET_ELECTRUM, "filesystem_anchor"),
    *_ELECTRUM_TARGET_SIGNATURES,
)

MULTIBIT_SIGNATURES = (
    Signature("multibit_network_anchor", MULTIBIT_NETWORK, "multibit",
              TARGET_MULTIBIT, "MULTIBIT_CLASSIC_PROTOBUF",
              _multibit_network_assessment),
    Signature("multibit_export_header", MULTIBIT_EXPORT_HEADER, "multibit",
              TARGET_MULTIBIT, "MULTIBIT_KEY_EXPORT",
              _multibit_export_assessment),
    Signature("multibit_encrypted_payload", b"Salted__", "multibit",
              TARGET_MULTIBIT, "MULTIBIT_ENCRYPTED_KEY_FRAGMENT",
              _multibit_encrypted_assessment),
    *(Signature(f"multibit_hd_marker_{index}", marker, "multibit",
                TARGET_MULTIBIT, "MULTIBIT_HD", _multibit_hd_assessment)
      for index, marker in enumerate(MULTIBIT_HD_MARKERS, start=1)),
    *(Signature(f"multibit_legacy_marker_{index}", marker, "multibit",
                TARGET_MULTIBIT, "MULTIBIT_CLASSIC_LEGACY",
                _multibit_legacy_assessment)
      for index, marker in enumerate(MULTIBIT_LEGACY_MARKERS, start=1)),
)

ARMORY_SIGNATURES = (
    Signature("armory_wallet_header", ARMORY_HEADER, "armory", TARGET_ARMORY,
              "ARMORY_WALLET", _armory_assessment),
    *(Signature(f"armory_paper_backup_marker_{index}", marker, "armory",
                TARGET_ARMORY, "ARMORY_PAPER_BACKUP", _armory_paper_assessment)
      for index, marker in enumerate(ARMORY_PAPER_MARKERS, start=1)),
)


def parse_targets(value: str) -> frozenset[str]:
    normalized = tuple(item.strip().casefold().replace("_", "-")
                       for item in value.split(",") if item.strip())
    if not normalized:
        raise ValueError("targets must not be empty")
    if "all" in normalized:
        if len(normalized) != 1:
            raise ValueError("all cannot be combined with individual targets")
        return frozenset(AVAILABLE_TARGETS)
    unknown = set(normalized) - set(AVAILABLE_TARGETS)
    if unknown:
        raise ValueError(f"unknown targets: {','.join(sorted(unknown))}")
    return frozenset(normalized)


def build_target_selection(targets: frozenset[str], *,
                           include_mnemonics: bool = True) -> TargetSelection:
    signatures: list[Signature] = []
    if TARGET_BITCOIN_CORE in targets:
        signatures.extend(_BITCOIN_TARGET_SIGNATURES)
    if TARGET_SECRETS in targets:
        signatures.extend(_SECRET_SIGNATURES)
    if TARGET_ELECTRUM in targets:
        signatures.extend(ELECTRUM_ONLY_SIGNATURES_V1)
    if TARGET_MULTIBIT in targets:
        signatures.extend(MULTIBIT_SIGNATURES)
    if TARGET_ARMORY in targets:
        signatures.extend(ARMORY_SIGNATURES)
    unique = {(item.name, item.pattern): item for item in signatures}
    detectors = []
    standards = frozenset({
        *(('ELECTRUM', 'ELECTRUM_V1') if TARGET_ELECTRUM in targets else ()),
        *(('BIP39',) if TARGET_SECRETS in targets else ()),
    })
    if include_mnemonics and standards:
        detectors.append(MnemonicChunkDetector(standards))
    if TARGET_SECRETS in targets:
        detectors.append(ValidatedSecretChunkDetector())
    return TargetSelection(
        targets, tuple(unique.values()), tuple(detectors))
