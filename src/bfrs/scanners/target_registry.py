"""Single registry for wallet targets sharing the streaming image pass."""

from __future__ import annotations

from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import dataclass
import hashlib
import re
from collections.abc import Callable

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
from bfrs.scanners.bitcoin_context import BitcoinTextContextChunkDetector
from bfrs.scanners.fast_scanner import ChunkDetector, Signature, SignatureAssessment
from bfrs.validators.berkeley_metadata import BTREE_MAGIC
from bfrs.validators.bitcoin_encoding import decode_base58check


TARGET_BITCOIN_CORE = "bitcoin-core"
TARGET_MULTIBIT = "multibit"
TARGET_ARMORY = "armory"
TARGET_ELECTRUM = "electrum"
TARGET_SECRETS = "secrets"
TARGET_INTERNAL = "internal"
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
MULTIBIT_NETWORKS = (
    MULTIBIT_NETWORK,
    b"org.bitcoin.test",
    b"org.bitcoin.regtest",
)
MULTIBIT_EXPORT_HEADER = b"# KEEP YOUR PRIVATE KEYS SAFE"
MULTIBIT_HD_MARKERS = (b"mbhd.wallet.aes", b"org.multibit.hd", b"MultiBit HD")
MULTIBIT_LEGACY_MARKERS = (b"com.google.bitcoin", b"org.multibit.wallet")
ARMORY_PAPER_MARKERS = (b"Armory Paper Backup", b"ARMORY PAPER BACKUP")
_WIF = re.compile(rb"(?<![1-9A-HJ-NP-Za-km-z])[5KL][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-HJ-NP-Za-km-z])")


_MNEMONIC_BRANCH_SCANNER: RawMnemonicScanner | None = None
_MNEMONIC_BRANCH_STANDARDS: frozenset[str] = frozenset()


def _initialize_mnemonic_branch(standards: frozenset[str]) -> None:
    """Initialize a byte-only worker; it never receives an input path."""
    global _MNEMONIC_BRANCH_SCANNER, _MNEMONIC_BRANCH_STANDARDS
    _MNEMONIC_BRANCH_SCANNER = RawMnemonicScanner(overlap=4096, phase_workers=1)
    _MNEMONIC_BRANCH_STANDARDS = standards


def _mnemonic_hits(result, standards: frozenset[str], source: str) -> tuple[RawHit, ...]:
    hits: list[RawHit] = []
    for occurrence in result.occurrences:
        candidate = occurrence.candidate
        if candidate.mnemonic_standard not in standards:
            continue
        start = candidate.physical_start
        end = candidate.physical_end
        if start is None or end is None:
            continue
        target = (TARGET_ELECTRUM if
                  candidate.mnemonic_standard.startswith("ELECTRUM") else
                  TARGET_SECRETS)
        hits.append(RawHit(
            start, end, f"mnemonic_{candidate.mnemonic_standard.casefold()}",
            0.85 if candidate.confidence == "HIGH" else 0.65, source,
            {"category": "validated_mnemonic"}, target=target,
            artifact_kind="mnemonic", structural_status="COMPLETE",
            validation_status=candidate.validation_status,
            reason_codes=tuple(candidate.reason_codes),
            correlated_evidence=(candidate.encoding or "unknown",),
            safe_fingerprint=candidate.fingerprint,
            safe_metadata={
                "mnemonic_standard": candidate.mnemonic_standard,
                "seed_type": candidate.seed_type,
                "word_count": candidate.word_count,
                "language": candidate.language,
                "encoding": candidate.encoding,
                "checksum_valid": candidate.checksum_valid,
                "completeness": candidate.completeness,
                "confidence": candidate.confidence,
            },
            recommended_recovery_action="MNEMONIC_CONTEXT_REVIEW"))
    return tuple(hits)


def _scan_mnemonic_branch(
    unit: tuple[bytes, str, int, int, int],
) -> tuple[RawHit, ...]:
    data, source, offset, ownership_start, ownership_end = unit
    assert _MNEMONIC_BRANCH_SCANNER is not None
    result = _MNEMONIC_BRANCH_SCANNER.scan_bytes(
        data, source=source, base_offset=offset,
        ownership_start=ownership_start, ownership_end=ownership_end)
    return _mnemonic_hits(result, _MNEMONIC_BRANCH_STANDARDS, source)


def _bounded(chunk: Chunk, local_offset: int, before: int = 512,
             after: int = 4096) -> bytes:
    return chunk.data[max(0, local_offset - before):local_offset + after]


def _protobuf_network_framed(data: bytes, offset: int) -> bool:
    if offset < 2 or data[offset - 2] != 0x0A:
        return False
    return data[offset - 1] in {len(marker) for marker in MULTIBIT_NETWORKS}


def _protobuf_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7F) << (7 * (index - offset))
        if not byte & 0x80:
            return value, index + 1
    return None


def _protobuf_fields(data: bytes) -> tuple[tuple[int, int, object, bool], ...]:
    """Decode enough protobuf wire structure to validate bitcoinj records."""
    result: list[tuple[int, int, object, bool]] = []
    cursor = 0
    while cursor < len(data):
        decoded = _protobuf_varint(data, cursor)
        if decoded is None:
            break
        tag, cursor = decoded
        field_number, wire_type = tag >> 3, tag & 7
        if field_number == 0:
            break
        if wire_type == 0:
            decoded = _protobuf_varint(data, cursor)
            if decoded is None:
                result.append((field_number, wire_type, 0, False))
                break
            value, cursor = decoded
            result.append((field_number, wire_type, value, True))
        elif wire_type == 2:
            decoded = _protobuf_varint(data, cursor)
            if decoded is None:
                result.append((field_number, wire_type, b"", False))
                break
            length, cursor = decoded
            end = cursor + length
            complete = end <= len(data)
            result.append((field_number, wire_type, data[cursor:min(end, len(data))], complete))
            if not complete:
                break
            cursor = end
        elif wire_type in {1, 5}:
            width = 8 if wire_type == 1 else 4
            end = cursor + width
            complete = end <= len(data)
            result.append((field_number, wire_type, data[cursor:min(end, len(data))], complete))
            if not complete:
                break
            cursor = end
        else:
            break
    return tuple(result)


def _multibit_key_evidence(payload: bytes, complete: bool) -> tuple[set[str], bool]:
    fields = _protobuf_fields(payload)
    key_type = any(field == 1 and wire == 0 and valid and value in {1, 2}
                   for field, wire, value, valid in fields)
    secret = any(
        field == 2 and wire == 2 and valid and isinstance(value, bytes)
        and len(value) == 32 and 1 <= int.from_bytes(value, "big") < GROUP_ORDER
        for field, wire, value, valid in fields
    )
    public = any(
        field == 3 and wire == 2 and valid and isinstance(value, bytes)
        and ((len(value) == 33 and value[:1] in {b"\x02", b"\x03"})
             or (len(value) == 65 and value[:1] == b"\x04"))
        for field, wire, value, valid in fields
    )
    encrypted = False
    for field, wire, value, valid in fields:
        if field != 6 or wire != 2 or not valid or not isinstance(value, bytes):
            continue
        nested = _protobuf_fields(value)
        iv = any(f == 1 and w == 2 and ok and isinstance(v, bytes) and len(v) == 16
                 for f, w, v, ok in nested)
        cipher = any(f == 2 and w == 2 and ok and isinstance(v, bytes) and len(v) >= 16
                     for f, w, v, ok in nested)
        encrypted = iv and cipher
    evidence = set()
    if key_type:
        evidence.add("KEY_TYPE_FIELD")
    if secret:
        evidence.add("EC_PRIVATE_KEY_FIELD")
    if public:
        evidence.add("EC_PUBLIC_KEY_FIELD")
    if encrypted:
        evidence.add("ENCRYPTED_KEY_FIELD")
    structurally_complete = complete and key_type and public and (secret or encrypted)
    return evidence, structurally_complete


def _multibit_network_assessment(signature: Signature, chunk: Chunk,
                                 local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset)
    relative = local_offset - max(0, local_offset - 512)
    framed = _protobuf_network_framed(context, relative)
    network = next((item.decode("ascii") for item in MULTIBIT_NETWORKS
                    if context[relative:relative + len(item)] == item), None)
    key_evidence: set[str] = set()
    complete_key = False
    wallet_fields: tuple[tuple[int, int, object, bool], ...] = ()
    if framed:
        wallet_start = relative - 2
        wallet_fields = _protobuf_fields(context[wallet_start:])
        for field, wire, value, complete in wallet_fields:
            if field == 3 and wire == 2 and isinstance(value, bytes):
                evidence_for_key, valid_key = _multibit_key_evidence(value, complete)
                key_evidence.update(evidence_for_key)
                complete_key = complete_key or valid_key
    evidence = tuple(sorted({"PROTOBUF_NETWORK_FIELD"} | key_evidence)) if framed else ()
    if framed and complete_key:
        encrypted_key = "ENCRYPTED_KEY_FIELD" in key_evidence
        return SignatureAssessment(
            0.95, "STRONG", "PROTOBUF_STRUCTURAL_VALID",
            ("MULTIBIT_PROTOBUF_WALLET_CONFIRMED",), evidence,
            {"network": network, "key_material_kind": (
                "ENCRYPTED" if encrypted_key else "PLAINTEXT")},
            "MULTIBIT_WALLET_RECOVERY")
    known_wallet_field = any(
        field in {2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16}
        for field, _, _, _ in wallet_fields[1:]
    )
    if framed and key_evidence >= {"KEY_TYPE_FIELD"} and (
            key_evidence & {"EC_PUBLIC_KEY_FIELD", "EC_PRIVATE_KEY_FIELD",
                            "ENCRYPTED_KEY_FIELD"}):
        return SignatureAssessment(
            0.65, "FRAGMENT", "PROTOBUF_FRAGMENT_VALID",
            ("MULTIBIT_PROTOBUF_KEY_FRAGMENT",), evidence,
            {"network": network}, "MULTIBIT_FRAGMENT_RECOVERY")
    if framed and known_wallet_field:
        return SignatureAssessment(
            0.55, "FRAGMENT", "PROTOBUF_FRAGMENT_VALID",
            ("MULTIBIT_PROTOBUF_WALLET_FRAGMENT",), evidence,
            {"network": network}, "MULTIBIT_FRAGMENT_RECOVERY")
    return SignatureAssessment(
        0.05, "REJECTED", "INSUFFICIENT_PROTOBUF_STRUCTURE",
        (("MULTIBIT_NETWORK_ANCHOR_WITHOUT_PROTOBUF_STRUCTURE",)
         if not framed else ("MULTIBIT_NETWORK_FIELD_ONLY",)), evidence,
        {"network": network}, "REVIEW_CONTEXT")


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
        0.05, "REJECTED", "INSUFFICIENT_EXPORT_STRUCTURE",
        ("MULTIBIT_EXPORT_MARKER_ONLY",),
        (), {}, "REVIEW_CONTEXT")


def _multibit_encrypted_assessment(signature: Signature, chunk: Chunk,
                                   local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 512, 512)
    # OpenSSL's Salted__ prefix is ubiquitous.  It is attributable to a
    # MultiBit Classic key export only when the export's own warning header is
    # present; a nearby wallet/HD string is not independent structure.
    multibit_marker = MULTIBIT_EXPORT_HEADER in context
    return SignatureAssessment(
        0.65 if multibit_marker else 0.30,
        "FRAGMENT" if multibit_marker else "REJECTED",
        ("ENCRYPTED_FRAGMENT" if multibit_marker else
         "INSUFFICIENT_ENCRYPTED_STRUCTURE"),
        (("MULTIBIT_ENCRYPTED_KEY_FRAGMENT",) if multibit_marker else
         ("OPENSSL_SALTED_ANCHOR_ONLY",)),
        (("MULTIBIT_MARKER", "ENCRYPTED_PAYLOAD") if multibit_marker else ()),
        {"encryption_state": "ENCRYPTED"},
        "MULTIBIT_FRAGMENT_RECOVERY" if multibit_marker else "REVIEW_CONTEXT")


def _multibit_hd_assessment(signature: Signature, chunk: Chunk,
                            local_offset: int) -> SignatureAssessment:
    return SignatureAssessment(
        0.05, "REJECTED", "OUT_OF_SCOPE_MULTIBIT_HD",
        ("MULTIBIT_HD_NOT_CLASSIC",), ("HD_WALLET_MARKER",),
        {"mnemonic_standard": "UNCONFIRMED"}, "REVIEW_CONTEXT")


def _multibit_legacy_assessment(signature: Signature, chunk: Chunk,
                                local_offset: int) -> SignatureAssessment:
    context = _bounded(chunk, local_offset, 1024, 2048)
    serialized = b"\xac\xed\x00\x05" in context
    return SignatureAssessment(
        0.60 if serialized else 0.05,
        "FRAGMENT" if serialized else "REJECTED",
        ("JAVA_SERIALIZED_WALLET_FRAGMENT" if serialized else
         "INSUFFICIENT_JAVA_SERIALIZATION_STRUCTURE"),
        (("MULTIBIT_LEGACY_SERIALIZED_FRAGMENT",) if serialized else
         ("MULTIBIT_LEGACY_MARKER_ONLY",)),
        (("JAVA_SERIALIZATION_HEADER", "MULTIBIT_CLASS_MARKER")
         if serialized else ("MULTIBIT_CLASS_MARKER",)),
        {}, "MULTIBIT_FRAGMENT_RECOVERY" if serialized else "REVIEW_CONTEXT")


def _armory_assessment(signature: Signature, chunk: Chunk,
                       local_offset: int) -> SignatureAssessment:
    data = chunk.data[local_offset:local_offset + 4096]
    version = int.from_bytes(data[8:12], "little") if len(data) >= 12 else 0
    network_magic = data[12:16] if len(data) >= 16 else b""
    networks = {
        b"\xf9\xbe\xb4\xd9": ("bitcoin-mainnet", 0x00),
        b"\xfa\xbf\xb5\xda": ("bitcoin-old-testnet", 0x6F),
        b"\x0b\x11\x09\x07": ("bitcoin-testnet3", 0x6F),
    }
    plausible_version = 10_000_000 <= version < 100_000_000
    known_network = network_magic in networks
    flags = int.from_bytes(data[16:24], "little") if len(data) >= 24 else None
    plausible_flags = flags is not None and flags & ~0x3 == 0
    unique_id = data[24:30] if len(data) >= 30 else b""
    network_id = networks.get(network_magic, (None, None))[1]
    plausible_id = len(unique_id) == 6 and unique_id[-1] == network_id
    created = int.from_bytes(data[30:38], "little") if len(data) >= 38 else 0
    plausible_date = created == 0 or 1_231_006_505 <= created <= 4_102_444_800
    full_header = len(data) >= 2107
    root_section = data[846:1083] if full_header else b""
    reserved = data[1083:2107] if full_header else b""
    complete_layout = full_header and any(root_section) and reserved.count(0) >= 1000
    evidence = tuple(name for name, present in (
        ("BAWALLET_HEADER", True),
        ("VERSION_FIELD", plausible_version),
        ("NETWORK_MAGIC", known_network),
        ("WALLET_FLAGS", plausible_flags),
        ("BINARY_UNIQUE_ID", plausible_id),
        ("CREATION_TIME", plausible_date and len(data) >= 38),
        ("FIXED_HEADER_LAYOUT", complete_layout),
    ) if present)
    metadata = {
        "format_version_integer": version or None,
        "network": networks.get(network_magic, (None, None))[0],
    }
    if (plausible_version and known_network and plausible_flags and
            plausible_id and plausible_date and complete_layout):
        return SignatureAssessment(
            0.95, "STRONG", "ARMORY_HEADER_STRUCTURAL_VALID",
            ("ARMORY_FULL_HEADER_CONFIRMED",),
            evidence, metadata, "ARMORY_WALLET_RECOVERY")
    if plausible_version and known_network and sum(
            (plausible_flags, plausible_id, plausible_date and len(data) >= 38)
    ) >= 1:
        return SignatureAssessment(
            0.60, "FRAGMENT", "ARMORY_FRAGMENT_VALID",
            ("ARMORY_STRUCTURAL_FRAGMENT",),
            evidence, metadata, "ARMORY_FRAGMENT_RECOVERY")
    return SignatureAssessment(
        0.05, "REJECTED", "INSUFFICIENT_ARMORY_STRUCTURE",
        ("ARMORY_SIGNATURE_ONLY",),
        ("BAWALLET_HEADER",), metadata, "REVIEW_CONTEXT")


def _armory_paper_assessment(signature: Signature, chunk: Chunk,
                             local_offset: int) -> SignatureAssessment:
    return SignatureAssessment(
        0.55, "FRAGMENT", "PAPER_BACKUP_MARKER",
        ("ARMORY_PAPER_BACKUP_MARKER",), ("DOCUMENT_MARKER",),
        {"route": "DOCUMENT_RECOVERY"}, "DOCUMENT_RECOVERY")


class MnemonicChunkDetector:
    """Adapter exposing existing strict mnemonic validators to shared chunks."""

    required_overlap = 4096

    def __init__(self, standards: frozenset[str], *, workers: int = 1) -> None:
        self.standards = standards
        self.branch_workers = workers
        self.scanner = RawMnemonicScanner(
            overlap=self.required_overlap, phase_workers=workers)
        self._branch_executor: ProcessPoolExecutor | None = None

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int,
                     ownership_end: int,
                     status: Callable[[str], None] | None = None):
        result = self.scanner.scan_bytes(
            chunk.data, source=source, base_offset=chunk.offset,
            ownership_start=ownership_start, ownership_end=ownership_end,
            phase_progress=status)
        yield from _mnemonic_hits(result, self.standards, source)

    def submit_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int,
                     ownership_end: int) -> Future[tuple[RawHit, ...]]:
        """Submit one already-read chunk to the isolated mnemonic branch."""
        if self._branch_executor is None:
            self._branch_executor = ProcessPoolExecutor(
                max_workers=1, initializer=_initialize_mnemonic_branch,
                initargs=(self.standards,))
        return self._branch_executor.submit(_scan_mnemonic_branch, (
            chunk.data, source, chunk.offset, ownership_start, ownership_end))

    def close(self) -> None:
        if self._branch_executor is not None:
            self._branch_executor.shutdown(wait=True, cancel_futures=True)
            self._branch_executor = None
        self.scanner.close()


_WIF_FINGERPRINT_DOMAIN = b"BFRS-WIF-FINGERPRINT-V1\0"


class ValidatedSecretChunkDetector:
    """Strict Base58Check WIF validation over shared, owned chunks."""

    required_overlap = 52

    def detect_chunk(self, chunk: Chunk, *, source: str,
                     ownership_start: int, ownership_end: int,
                     status: Callable[[str], None] | None = None):
        for match in _WIF.finditer(chunk.data):
            start = chunk.offset + match.start()
            if not ownership_start <= start < ownership_end:
                continue
            payload = decode_base58check(match.group(0))
            if payload is None or len(payload) not in {33, 34} or payload[0] != 0x80:
                continue
            compressed = len(payload) == 34 and payload[-1] == 1
            if len(payload) == 34 and not compressed:
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
    chunk_detectors: tuple[ChunkDetector, ...]


_SHARED_NTFS_SIGNATURES = (
    Signature(NTFS_BOOT_SECTOR_SIGNATURE, NTFS_BOOT_SECTOR_PATTERN,
              "ntfs_boot_sector", TARGET_INTERNAL, "filesystem_anchor"),
    Signature(NTFS_FILE_RECORD_SIGNATURE, NTFS_FILE_RECORD_PATTERN,
              "ntfs_file_record", TARGET_INTERNAL, "filesystem_record"),
    Signature(NTFS_INDX_RECORD_SIGNATURE, NTFS_INDX_RECORD_PATTERN,
              "ntfs_indx_record", TARGET_INTERNAL, "filesystem_index"),
)

_BITCOIN_TARGET_SIGNATURES = (
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
    *_SHARED_NTFS_SIGNATURES,
    *_BITCOIN_TARGET_SIGNATURES,
    *_SECRET_SIGNATURES,
    *_ELECTRUM_TARGET_SIGNATURES,
)

ELECTRUM_ONLY_SIGNATURES_V1 = (
    _SHARED_NTFS_SIGNATURES[0],
    *_ELECTRUM_TARGET_SIGNATURES,
)

MULTIBIT_SIGNATURES = (
    *(Signature(("multibit_network_anchor" if index == 1 else
                 f"multibit_network_anchor_{index}"), network, "multibit",
                TARGET_MULTIBIT, "MULTIBIT_CLASSIC_PROTOBUF",
                _multibit_network_assessment)
      for index, network in enumerate(MULTIBIT_NETWORKS, start=1)),
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
                           include_mnemonics: bool = True,
                           include_bitcoin_context: bool = False,
                           mnemonic_workers: int = 1) -> TargetSelection:
    signatures: list[Signature] = []
    if targets & {TARGET_BITCOIN_CORE, TARGET_ELECTRUM}:
        signatures.append(_SHARED_NTFS_SIGNATURES[0])
    if TARGET_BITCOIN_CORE in targets:
        signatures.extend(_SHARED_NTFS_SIGNATURES[1:])
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
        detectors.append(MnemonicChunkDetector(
            standards, workers=mnemonic_workers))
    if TARGET_SECRETS in targets:
        detectors.append(ValidatedSecretChunkDetector())
    if include_bitcoin_context and TARGET_BITCOIN_CORE in targets:
        detectors.append(BitcoinTextContextChunkDetector())
    return TargetSelection(
        targets, tuple(unique.values()), tuple(detectors))
