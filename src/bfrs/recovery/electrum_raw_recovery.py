"""Secret-safe structural recovery of raw Electrum wallet containers."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError


ELECTRUM_BIE1_BASE64_SIGNATURE = "electrum_bie1_base64_anchor"
ELECTRUM_BIE2_BASE64_SIGNATURE = "electrum_bie2_base64_anchor"
ELECTRUM_BIE1_RAW_SIGNATURE = "electrum_bie1_raw_anchor"
ELECTRUM_BIE2_RAW_SIGNATURE = "electrum_bie2_raw_anchor"
ELECTRUM_SEED_VERSION_SIGNATURE = "electrum_seed_version_anchor"
ELECTRUM_WALLET_TYPE_SIGNATURE = "electrum_wallet_type_anchor"
ELECTRUM_KEYSTORE_SIGNATURE = "electrum_keystore_anchor"

ELECTRUM_SIGNATURE_PATTERNS = (
    (ELECTRUM_BIE1_BASE64_SIGNATURE, b"QklFMQ"),
    (ELECTRUM_BIE2_BASE64_SIGNATURE, b"QklFMg"),
    (ELECTRUM_BIE1_RAW_SIGNATURE, b"BIE1"),
    (ELECTRUM_BIE2_RAW_SIGNATURE, b"BIE2"),
    (ELECTRUM_SEED_VERSION_SIGNATURE, b'"seed_version"'),
    (ELECTRUM_WALLET_TYPE_SIGNATURE, b'"wallet_type"'),
    (ELECTRUM_KEYSTORE_SIGNATURE, b'"keystore"'),
)
ELECTRUM_SIGNATURE_NAMES = frozenset(name for name, _ in ELECTRUM_SIGNATURE_PATTERNS)

MAX_ELECTRUM_WALLET_SIZE = 32 * 1024 * 1024
MAX_BACKWARD_CONTEXT = 1024 * 1024
MAX_SCANNER_CANDIDATE_WINDOW = 2 * 1024 * 1024
BASE64_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
SECRET_KEYS = frozenset({
    "seed", "seed_extra_words", "passphrase", "xprv", "prv", "privkey",
    "private_key", "keypairs", "master_private_key", "master_private_keys",
})
KNOWN_KEYSTORE_TYPES = frozenset({"bip32", "old", "hardware", "imported"})


@dataclass(frozen=True, slots=True)
class KnownElectrumArtifact:
    name: str
    source: str
    allocation_state: str
    active: bool
    logical_size: int | None
    extents: tuple[Any, ...]
    correlated_sources: tuple[str, ...] = ("MFT",)
    sha256: str | None = None
    volume_start: int | None = None
    mft_record_number: int | None = None
    physical_mft_record_offset: int | None = None
    resident_attribute_id: int | None = None
    resident_value_offset: int | None = None
    resident_data: bytes | None = None
    read_failure: str | None = None


@dataclass(frozen=True, slots=True)
class ElectrumRawCandidate:
    candidate_id: str
    family: str
    serialization_type: str
    completeness: str
    encryption_state: str
    confidence: str
    reason_codes: tuple[str, ...]
    source: str
    physical_start: int
    physical_end: int
    allocation_state: str
    correlated_sources: tuple[str, ...]
    known_active_duplicate: bool
    safe_metadata: dict[str, Any]
    provenance: tuple[dict[str, Any], ...]
    anchor_types: tuple[str, ...]
    state: str = "UNKNOWN_REFERENCE"


@dataclass(frozen=True, slots=True)
class ElectrumRawRecovery:
    enabled: bool
    anchors_found: int
    candidates_total: int
    complete_candidates: int
    fragment_candidates: int
    encrypted_candidates: int
    plaintext_candidates: int
    known_active_duplicates: int
    new_unknown_candidates: int
    failures: tuple[str, ...]
    candidates: tuple[ElectrumRawCandidate, ...]


class ElectrumStructuralValidator:
    """Validate bounded containers without retaining secret values."""

    def validate_plaintext(self, raw: bytes, *, source: str,
                           physical_start: int,
                           anchors: tuple[str, ...],
                           provenance=()) -> ElectrumRawCandidate | None:
        try:
            text = raw.decode("utf-8")
            value = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        seed_version = value.get("seed_version")
        wallet_type = value.get("wallet_type")
        if (type(seed_version) is not int or not 1 <= seed_version <= 10_000
                or not isinstance(wallet_type, str)
                or not 1 <= len(wallet_type) <= 64):
            return None
        keystores = self._keystores(value, wallet_type)
        if not keystores:
            return None
        keystore_types = []
        for keystore in keystores:
            kind = keystore.get("type")
            if kind not in KNOWN_KEYSTORE_TYPES:
                return None
            keystore_types.append(kind)
            if kind == "bip32" and not any(
                    isinstance(keystore.get(key), str)
                    for key in ("xpub", "xprv", "seed")):
                return None
            if kind == "old" and not (
                    isinstance(keystore.get("mpk"), str)
                    and isinstance(keystore.get("seed"), str)):
                return None
            if kind == "hardware" and not (
                    isinstance(keystore.get("hw_type"), str)
                    and isinstance(keystore.get("xpub"), str)):
                return None
            if kind == "imported" and not isinstance(
                    keystore.get("keypairs"), dict):
                return None
        safe = {
            "wallet_type": wallet_type,
            "seed_version": seed_version,
            "keystore_types": sorted(set(keystore_types)),
            "keystore_count": len(keystores),
            "has_seed_material": self._contains_secret_key(value),
            "has_public_master_metadata": any(
                key in json.dumps(self._shape_only(value), sort_keys=True)
                for key in ("xpub", "mpk", "master_public")
            ),
        }
        return self._candidate(
            raw, source, physical_start, "ELECTRUM_JSON", "COMPLETE",
            "PLAINTEXT_STRUCTURE", "HIGH",
            ("ELECTRUM_PLAINTEXT_STRUCTURE_VALID",), safe, anchors,
            provenance,
        )

    def validate_encrypted(self, token: bytes, *, source: str,
                           physical_start: int, anchors: tuple[str, ...],
                           provenance=()) -> ElectrumRawCandidate | None:
        try:
            decoded = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error):
            return None
        if len(decoded) < 4 + 33 + 16 + 32:
            return None
        magic = decoded[:4]
        if magic not in (b"BIE1", b"BIE2"):
            return None
        ephemeral = decoded[4:37]
        ciphertext = decoded[37:-32]
        if (ephemeral[0] not in (2, 3) or len(ciphertext) < 16
                or len(ciphertext) % 16):
            return None
        safe = {
            "container_magic": magic.decode("ascii"),
            "ephemeral_pubkey_encoding": "COMPRESSED_SECP256K1",
            "ciphertext_length": len(ciphertext),
            "mac_length": 32,
        }
        return self._candidate(
            token, source, physical_start, "ELECTRUM_ECIES_BASE64",
            "COMPLETE", "ENCRYPTED_CONTAINER", "HIGH",
            ("ELECTRUM_ENCRYPTED_CONTAINER_VALID",), safe, anchors,
            provenance,
        )

    def fragment(self, raw: bytes, *, source: str, physical_start: int,
                 serialization_type: str, anchors: tuple[str, ...],
                 provenance=()) -> ElectrumRawCandidate:
        return self._candidate(
            raw, source, physical_start, serialization_type, "TRUNCATED",
            "UNKNOWN", "LOW",
            ("ELECTRUM_SERIALIZATION_TRUNCATED", "ELECTRUM_FRAGMENT_VALID"),
            {}, anchors, provenance,
        )

    @staticmethod
    def _keystores(value: dict, wallet_type: str) -> tuple[dict, ...]:
        output = []
        if isinstance(value.get("keystore"), dict):
            output.append(value["keystore"])
        for key, item in value.items():
            if re.fullmatch(r"x\d+/", key) and isinstance(item, dict):
                output.append(item)
        if wallet_type == "imported" and isinstance(value.get("keystore"), dict):
            return tuple(output)
        return tuple(output)

    @classmethod
    def _contains_secret_key(cls, value: Any) -> bool:
        if isinstance(value, dict):
            return any(key.casefold() in SECRET_KEYS or cls._contains_secret_key(item)
                       for key, item in value.items())
        if isinstance(value, list):
            return any(cls._contains_secret_key(item) for item in value)
        return False

    @classmethod
    def _shape_only(cls, value: Any):
        if isinstance(value, dict):
            return {key: cls._shape_only(item) for key, item in value.items()
                    if key.casefold() not in SECRET_KEYS}
        if isinstance(value, list):
            return [cls._shape_only(item) for item in value[:1]]
        return type(value).__name__

    @staticmethod
    def _candidate(raw, source, start, serialization, completeness,
                   encryption, confidence, reasons, safe, anchors, provenance):
        digest = hashlib.sha256(raw).hexdigest()
        default_provenance = ({"source": source, "physical_start": start,
                               "physical_end": start + len(raw)},)
        selected_provenance = tuple(provenance) or default_provenance
        physical_start = min(item["physical_start"] for item in selected_provenance)
        physical_end = max(item["physical_end"] for item in selected_provenance)
        return ElectrumRawCandidate(
            f"electrum-{digest}", "ELECTRUM", serialization,
            completeness, encryption, confidence, tuple(reasons), source,
            physical_start, physical_end, "UNKNOWN_ALLOCATION", (), False, safe,
            selected_provenance, tuple(sorted(set(anchors))),
        )


class ElectrumCandidateAssembler:
    def __init__(self) -> None:
        self.validator = ElectrumStructuralValidator()

    def analyze_bytes(self, data: bytes, *, source: str,
                      physical_start: int = 0,
                      required_anchor_offset: int | None = None,
                      anchor_types: Iterable[str] = (),
                      provenance=()) -> tuple[ElectrumRawCandidate, ...]:
        candidates: dict[tuple[int, int, str], ElectrumRawCandidate] = {}
        anchors = tuple(anchor_types)
        for start, end in self._base64_tokens(data):
            if required_anchor_offset is not None and not (
                    start <= required_anchor_offset < end):
                continue
            candidate = self.validator.validate_encrypted(
                data[start:end], source=source,
                physical_start=physical_start + start, anchors=anchors,
                provenance=provenance,
            )
            if candidate is not None:
                candidates[(start, end, candidate.serialization_type)] = candidate
        for start, end, value in self._json_objects(data):
            if required_anchor_offset is not None and not (
                    start <= required_anchor_offset < end):
                continue
            candidate = self.validator.validate_plaintext(
                data[start:end], source=source,
                physical_start=physical_start + start, anchors=anchors,
                provenance=provenance,
            )
            if candidate is not None:
                candidates[(start, end, candidate.serialization_type)] = candidate
        if not candidates:
            fragment = self._fragment(data, source, physical_start,
                                      required_anchor_offset, anchors, provenance)
            if fragment is not None:
                candidates[(fragment.physical_start - physical_start,
                            fragment.physical_end - physical_start,
                            fragment.serialization_type)] = fragment
        return tuple(sorted(candidates.values(),
                            key=lambda item: (item.physical_start,
                                              item.physical_end)))

    @staticmethod
    def _base64_tokens(data: bytes):
        index = 0
        while index < len(data):
            if data[index] not in BASE64_BYTES:
                index += 1
                continue
            start = index
            while index < len(data) and data[index] in BASE64_BYTES:
                index += 1
            token = data[start:index]
            for magic in (b"QklFMQ", b"QklFMg"):
                relative = token.find(magic)
                while relative >= 0:
                    candidate_start = start + relative
                    if (index - candidate_start >= 8 and
                            (index - candidate_start) % 4 == 0):
                        yield candidate_start, index
                    relative = token.find(magic, relative + 1)

    @staticmethod
    def _json_objects(data: bytes):
        for start, byte in enumerate(data):
            if byte != 0x7B:
                continue
            depth, in_string, escaped = 0, False, False
            for end in range(start, len(data)):
                current = data[end]
                if in_string:
                    if escaped:
                        escaped = False
                    elif current == 0x5C:
                        escaped = True
                    elif current == 0x22:
                        in_string = False
                    continue
                if current == 0x22:
                    in_string = True
                elif current == 0x7B:
                    depth += 1
                elif current == 0x7D:
                    depth -= 1
                    if depth == 0:
                        raw = data[start:end + 1]
                        try:
                            value = json.loads(raw.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            break
                        if isinstance(value, dict):
                            yield start, end + 1, value
                        break

    def _fragment(self, data, source, physical_start, required, anchors, provenance):
        anchor_count = sum(pattern in data for _, pattern in
                           ELECTRUM_SIGNATURE_PATTERNS)
        if data.startswith((b"QklFMQ", b"QklFMg", b"BIE1", b"BIE2")):
            if data.startswith((b"QklFMQ", b"QklFMg")):
                try:
                    decoded = base64.b64decode(data, validate=True)
                except (ValueError, binascii.Error):
                    decoded = b""
                if len(decoded) >= 4 + 33 + 16 + 32:
                    return None
            return self.validator.fragment(
                data, source=source, physical_start=physical_start,
                serialization_type="ELECTRUM_ECIES_FRAGMENT", anchors=anchors,
                provenance=provenance,
            )
        if anchor_count < 2:
            return None
        if (b'"seed_version"' in data and b'"wallet_type"' in data
                and b"{" in data):
            start = data.find(b"{")
            start = max(0, start)
            if data.rstrip().endswith(b"}"):
                try:
                    json.loads(data[start:].decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
                else:
                    return None
            raw = data[start:]
            return self.validator.fragment(
                raw, source=source, physical_start=physical_start + start,
                serialization_type="ELECTRUM_JSON_FRAGMENT", anchors=anchors,
                provenance=provenance,
            )
        return None


class ElectrumRawRecoveryPipeline:
    """Assemble scanner hits or analyze one explicitly bounded reader range."""

    def __init__(self, *, source: str | Path,
                 known_artifacts: Iterable[KnownElectrumArtifact] = ()) -> None:
        self.path = Path(source).resolve()
        self.known_artifacts = tuple(known_artifacts)
        self.assembler = ElectrumCandidateAssembler()

    def run_hits(self, hits: Iterable[RawHit], *, range_start: int = 0,
                 range_end: int | None = None) -> ElectrumRawRecovery:
        relevant = tuple(hit for hit in hits if hit.hit_type in ELECTRUM_SIGNATURE_NAMES)
        end = self.path.stat().st_size if range_end is None else range_end
        found: dict[tuple[int, int, str], ElectrumRawCandidate] = {}
        failures = []
        with self.path.open("rb") as image:
            for hit in relevant:
                window_start = max(range_start, hit.start_offset - MAX_BACKWARD_CONTEXT)
                window_end = min(end, window_start + MAX_SCANNER_CANDIDATE_WINDOW)
                try:
                    image.seek(window_start)
                    data = image.read(window_end - window_start)
                except OSError as exc:
                    failures.append(f"electrum_candidate_read_failure:{type(exc).__name__}")
                    continue
                local_anchor = hit.start_offset - window_start
                assembled = self.assembler.analyze_bytes(
                        data, source=str(self.path), physical_start=window_start,
                        required_anchor_offset=local_anchor,
                        anchor_types=(hit.hit_type,))
                if not assembled:
                    failures.append(
                        "ELECTRUM_FRAMING_INVALID"
                        if "bie" in hit.hit_type
                        else "ELECTRUM_STRUCTURE_INCONSISTENT"
                    )
                for candidate in assembled:
                    correlated = self._correlate(candidate)
                    found[(correlated.physical_start, correlated.physical_end,
                           correlated.serialization_type)] = correlated
        return self._result(len(relevant), tuple(found.values()), failures)

    def analyze_range(self, *, start: int, end: int,
                      allocation_state: str = "UNKNOWN_ALLOCATION",
                      correlated_sources: Iterable[str] = ()) -> ElectrumRawRecovery:
        if start < 0 or end <= start or end > self.path.stat().st_size:
            raise ValueError("invalid Electrum analysis range")
        if end - start > MAX_ELECTRUM_WALLET_SIZE:
            raise ValueError("Electrum analysis range too large")
        with self.path.open("rb") as image:
            image.seek(start)
            data = image.read(end - start)
        candidates = tuple(
            replace_candidate(candidate, allocation_state=allocation_state,
                              correlated_sources=tuple(correlated_sources))
            for candidate in self.assembler.analyze_bytes(
                data, source=str(self.path), physical_start=start)
        )
        correlated = tuple(self._correlate(item) for item in candidates)
        return self._result(0, correlated, ())

    def analyze_known_artifact(self, artifact: KnownElectrumArtifact) -> ElectrumRawRecovery:
        if artifact.read_failure is not None:
            return self._result(0, (), (artifact.read_failure,))
        if artifact.resident_data is not None:
            if (artifact.volume_start is None
                    or artifact.mft_record_number is None
                    or artifact.physical_mft_record_offset is None
                    or artifact.resident_attribute_id is None
                    or artifact.resident_value_offset is None):
                return self._result(0, (), ("resident_electrum_provenance_incomplete",))
            if len(artifact.resident_data) > MAX_ELECTRUM_WALLET_SIZE:
                return self._result(0, (), ("known_electrum_file_too_large",))
            physical_start = (artifact.physical_mft_record_offset
                              + artifact.resident_value_offset)
            provenance = ({
                "source": str(self.path),
                "source_kind": "NTFS_RESIDENT_DATA",
                "volume_start": artifact.volume_start,
                "mft_record_number": artifact.mft_record_number,
                "physical_mft_record_offset": artifact.physical_mft_record_offset,
                "resident_attribute_id": artifact.resident_attribute_id,
                "logical_size": len(artifact.resident_data),
                "allocation_state": artifact.allocation_state,
                "physical_start": physical_start,
                "physical_end": physical_start + len(artifact.resident_data),
            },)
            candidates = self.assembler.analyze_bytes(
                artifact.resident_data, source=str(self.path),
                physical_start=physical_start, provenance=provenance,
            )
            updated = tuple(replace_candidate(
                item, allocation_state=artifact.allocation_state,
                correlated_sources=artifact.correlated_sources,
                known_active_duplicate=artifact.active,
                state="ACTIVE_CURRENT" if artifact.active else "UNKNOWN_REFERENCE",
                add_reason="KNOWN_ACTIVE_ELECTRUM_DUPLICATE"
                if artifact.active else None,
            ) for item in candidates)
            return self._result(0, updated, ())
        if not artifact.extents:
            return self._result(0, (), ("known_electrum_data_unreadable",))
        data = bytearray()
        provenance = []
        remaining = artifact.logical_size
        with self.path.open("rb") as image:
            for extent in sorted(artifact.extents, key=lambda item: item.vcn_start):
                if extent.sparse or extent.physical_byte_start is None:
                    return self._result(0, (), ("known_electrum_extent_sparse",))
                length = extent.physical_byte_end - extent.physical_byte_start
                if remaining is not None:
                    length = min(length, remaining)
                image.seek(extent.physical_byte_start)
                chunk = image.read(length)
                if len(chunk) != length:
                    return self._result(0, (), ("known_electrum_extent_short_read",))
                data.extend(chunk)
                provenance.append({"source": str(self.path),
                                   "physical_start": extent.physical_byte_start,
                                   "physical_end": extent.physical_byte_start + length})
                if remaining is not None:
                    remaining -= length
                    if remaining <= 0:
                        break
        if len(data) > MAX_ELECTRUM_WALLET_SIZE:
            return self._result(0, (), ("known_electrum_file_too_large",))
        start = min(item["physical_start"] for item in provenance)
        candidates = self.assembler.analyze_bytes(
            bytes(data), source=str(self.path), physical_start=start,
            provenance=tuple(provenance),
        )
        updated = tuple(replace_candidate(
            item, allocation_state=artifact.allocation_state,
            correlated_sources=artifact.correlated_sources,
            known_active_duplicate=artifact.active,
            state="ACTIVE_CURRENT" if artifact.active else "UNKNOWN_REFERENCE",
            add_reason="KNOWN_ACTIVE_ELECTRUM_DUPLICATE" if artifact.active else None,
        ) for item in candidates)
        return self._result(0, updated, ())

    def _correlate(self, candidate):
        for artifact in self.known_artifacts:
            exact_extent = False
            allocated_extents = tuple(extent for extent in artifact.extents
                                      if not extent.sparse)
            if len(allocated_extents) == 1 and candidate.completeness == "COMPLETE":
                extent = allocated_extents[0]
                logical_end = extent.physical_byte_end
                if artifact.logical_size is not None:
                    logical_end = min(logical_end, extent.physical_byte_start
                                      + artifact.logical_size)
                exact_extent = (
                    extent.physical_byte_start <= candidate.physical_start
                    and candidate.physical_end <= logical_end
                )
            same_hash = artifact.sha256 == candidate.candidate_id.removeprefix(
                "electrum-") if artifact.sha256 else False
            resident_extent = False
            if (artifact.resident_data is not None
                    and artifact.physical_mft_record_offset is not None
                    and artifact.resident_value_offset is not None):
                resident_start = (artifact.physical_mft_record_offset
                                  + artifact.resident_value_offset)
                resident_end = resident_start + len(artifact.resident_data)
                resident_extent = (resident_start <= candidate.physical_start
                                   and candidate.physical_end <= resident_end)
            if exact_extent or resident_extent or same_hash:
                resident_provenance = None
                if resident_extent:
                    resident_start = (artifact.physical_mft_record_offset
                                      + artifact.resident_value_offset)
                    resident_provenance = ({
                        "source": str(self.path),
                        "source_kind": "NTFS_RESIDENT_DATA",
                        "volume_start": artifact.volume_start,
                        "mft_record_number": artifact.mft_record_number,
                        "physical_mft_record_offset": artifact.physical_mft_record_offset,
                        "resident_attribute_id": artifact.resident_attribute_id,
                        "logical_size": len(artifact.resident_data),
                        "allocation_state": artifact.allocation_state,
                        "physical_start": resident_start,
                        "physical_end": resident_start + len(artifact.resident_data),
                    },)
                return replace_candidate(
                    candidate, allocation_state=artifact.allocation_state,
                    correlated_sources=artifact.correlated_sources,
                    known_active_duplicate=artifact.active,
                    state="ACTIVE_CURRENT" if artifact.active else "UNKNOWN_REFERENCE",
                    provenance=resident_provenance,
                    add_reason="KNOWN_ACTIVE_ELECTRUM_DUPLICATE"
                    if artifact.active else None,
                )
        return candidate

    @staticmethod
    def _result(anchor_count, candidates, failures):
        ordered = tuple(sorted(candidates, key=lambda item: (
            item.physical_start, item.physical_end, item.candidate_id)))
        return ElectrumRawRecovery(
            True, anchor_count, len(ordered),
            sum(item.completeness == "COMPLETE" for item in ordered),
            sum(item.completeness != "COMPLETE" for item in ordered),
            sum(item.encryption_state == "ENCRYPTED_CONTAINER" for item in ordered),
            sum(item.encryption_state == "PLAINTEXT_STRUCTURE" for item in ordered),
            sum(item.known_active_duplicate for item in ordered),
            sum(not item.known_active_duplicate for item in ordered),
            tuple(dict.fromkeys(failures)), ordered,
        )


def replace_candidate(candidate: ElectrumRawCandidate, *,
                      allocation_state: str | None = None,
                      correlated_sources: tuple[str, ...] = (),
                      known_active_duplicate: bool | None = None,
                      state: str | None = None,
                      provenance: tuple[dict[str, Any], ...] | None = None,
                      add_reason: str | None = None) -> ElectrumRawCandidate:
    reasons = candidate.reason_codes + (() if add_reason is None else (add_reason,))
    return ElectrumRawCandidate(
        candidate.candidate_id, candidate.family, candidate.serialization_type,
        candidate.completeness, candidate.encryption_state, candidate.confidence,
        tuple(dict.fromkeys(reasons)), candidate.source, candidate.physical_start,
        candidate.physical_end,
        candidate.allocation_state if allocation_state is None else allocation_state,
        tuple(dict.fromkeys((*candidate.correlated_sources, *correlated_sources))),
        candidate.known_active_duplicate if known_active_duplicate is None
        else known_active_duplicate,
        candidate.safe_metadata,
        candidate.provenance if provenance is None else provenance,
        candidate.anchor_types,
        candidate.state if state is None else state,
    )


def known_electrum_artifacts_from_contexts(contexts) -> tuple[KnownElectrumArtifact, ...]:
    output = []
    for context in contexts:
        records = context.current_records_by_number
        for record in records.values():
            if record.data is None:
                continue
            selected_name = None
            for alias in record.aliases:
                path = _mft_path(alias, records)
                low_path = path.casefold()
                if (alias.filename.casefold() in {"electrum.dat", "default_wallet"}
                        or "\\electrum\\wallets\\" in low_path):
                    selected_name = alias.filename
                    break
            if selected_name is None:
                continue
            resident = None
            resident_failure = None
            physical_mft_offset = context.physical_offset_for_mft_record(record.number)
            if record.data.resident:
                try:
                    resident = context.read_resident_unnamed_data(record.number)
                except (OSError, ValueError, NtfsMftRecordError) as error:
                    resident_failure = f"resident_electrum_read_failure:{error}"
            output.append(KnownElectrumArtifact(
                selected_name, context.source,
                "ALLOCATED_FILE" if record.allocated else "UNALLOCATED",
                record.allocated, record.data.logical_size, record.data.extents,
                ("MFT",),
                volume_start=context.boot.volume_offset,
                mft_record_number=record.number,
                physical_mft_record_offset=physical_mft_offset,
                resident_attribute_id=(None if resident is None
                                       else resident.attribute_id),
                resident_value_offset=(None if resident is None
                                       else resident.resident_value_offset),
                resident_data=None if resident is None else resident.value,
                read_failure=resident_failure,
            ))
    return tuple(output)


def _mft_path(alias, records) -> str:
    parts = [alias.filename]
    current = alias.parent_mft_record_number
    seen = set()
    while current in records and current not in seen and len(parts) < 64:
        seen.add(current)
        parent = records[current]
        if not parent.aliases:
            break
        parent_alias = parent.aliases[0]
        if parent_alias.filename != ".":
            parts.append(parent_alias.filename)
        if parent_alias.parent_mft_record_number == current:
            break
        current = parent_alias.parent_mft_record_number
    return "\\" + "\\".join(reversed(parts))
