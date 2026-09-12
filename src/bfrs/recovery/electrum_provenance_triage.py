"""Targeted, secret-safe provenance triage for raw Electrum candidates."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Iterable

from bfrs.core.ranges import intersects
from bfrs.recovery.electrum_raw_recovery import (
    ElectrumCandidateAssembler,
    KnownElectrumArtifact,
    _mft_path,
    known_electrum_artifacts_from_contexts,
)
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
    NTFSStaleRecoveryContext,
    _LogicalStream,
    _Image,
)


BITMAP_MFT_RECORD_NUMBER = 6  # Fixed by the NTFS on-disk specification.
SAFE_RELATIONS = frozenset({
    "BYTE_IDENTICAL", "STRUCTURALLY_SIMILAR", "SIZE_MATCH_ONLY",
    "NO_MATCH", "UNKNOWN",
})


@dataclass(frozen=True, slots=True)
class TargetRange:
    candidate: str
    physical_start: int
    physical_end: int


@dataclass(frozen=True, slots=True)
class BitmapResult:
    first_lcn: int
    last_lcn: int
    cluster_count: int
    allocated_cluster_count: int
    unallocated_cluster_count: int
    state: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OwnerMatch:
    relation: str
    mft_record: int
    sequence: int
    active_state: str
    filename: str | None
    parent_reference: int | None
    path: str | None
    logical_size: int | None
    extent_start: int
    extent_end: int
    allocation_state: str
    validation_strength: str


@dataclass(frozen=True, slots=True)
class SafeFingerprint:
    complete_container_length: int
    decoded_bie_length: int
    bie_version: str
    ephemeral_public_key_fingerprint: str
    container_sha256: str
    ciphertext_sha256: str
    mac_fingerprint: str


@dataclass(frozen=True, slots=True)
class ActiveComparison:
    name: str | None
    mft_record: int | None
    physical_start: int | None
    physical_end: int | None
    size: int | None
    relation: str
    fingerprint: SafeFingerprint | None


@dataclass(frozen=True, slots=True)
class TriageResult:
    candidate: str
    physical_start: int
    physical_end: int
    size: int
    volume_start: int | None
    cluster_size: int | None
    first_lcn: int | None
    last_lcn: int | None
    clusters_touched: int | None
    start_cluster_offset: int | None
    end_cluster_offset: int | None
    bitmap_state: str
    allocated_cluster_count: int
    unallocated_cluster_count: int
    current_mft_owner: OwnerMatch | None
    stale_mft_match: OwnerMatch | None
    historical_path: str | None
    closest_active_electrum_size_match: ActiveComparison | None
    safe_relation: str
    confidence: str
    classification: str
    candidate_fingerprint: SafeFingerprint | None
    reason_codes: tuple[str, ...]

    def safe_dict(self) -> dict:
        return asdict(self)


class NTFSBitmapResolver:
    """Read allocation bits from a validated NTFS $Bitmap DATA stream."""

    def __init__(self, read_at: Callable[[int, int], bytes], size: int) -> None:
        self._read_at = read_at
        self.size = size

    @classmethod
    def from_context(cls, context: NTFSStaleRecoveryContext):
        record = context.current_records_by_number.get(BITMAP_MFT_RECORD_NUMBER)
        if (record is None or not record.allocated or record.data is None
                or record.data.resident or not record.data.extents
                or any(extent.sparse for extent in record.data.extents)):
            raise ValueError("ntfs_bitmap_data_unavailable")
        stream_extents = tuple(SimpleNamespace(
            logical_start=extent.vcn_start * context.boot.cluster_size,
            logical_end=extent.vcn_end * context.boot.cluster_size,
            physical_start=extent.physical_byte_start,
            length=(extent.vcn_end - extent.vcn_start) * context.boot.cluster_size,
        ) for extent in record.data.extents)
        stream = _LogicalStream(
            _Image(Path(context.source)), stream_extents,
            record.data.logical_size,
        )
        return cls(stream.read_at, stream.size)

    def allocation(self, first_lcn: int, last_lcn: int) -> BitmapResult:
        if first_lcn < 0 or last_lcn < first_lcn:
            raise ValueError("invalid_lcn_range")
        first_byte = first_lcn // 8
        last_byte = last_lcn // 8
        if last_byte >= self.size:
            return BitmapResult(
                first_lcn, last_lcn, last_lcn - first_lcn + 1, 0, 0,
                "UNKNOWN", ("BITMAP_RANGE_OUTSIDE_STREAM",),
            )
        try:
            raw = self._read_at(first_byte, last_byte - first_byte + 1)
        except (OSError, ValueError):
            return BitmapResult(
                first_lcn, last_lcn, last_lcn - first_lcn + 1, 0, 0,
                "UNKNOWN", ("BITMAP_READ_FAILED",),
            )
        allocated = sum(
            bool(raw[lcn // 8 - first_byte] & (1 << (lcn % 8)))
            for lcn in range(first_lcn, last_lcn + 1)
        )
        count = last_lcn - first_lcn + 1
        unallocated = count - allocated
        state = ("ALLOCATED" if allocated == count else
                 "UNALLOCATED" if not allocated else "MIXED")
        return BitmapResult(
            first_lcn, last_lcn, count, allocated, unallocated, state,
            (f"BITMAP_{state}",),
        )


def safe_fingerprint(container: bytes) -> SafeFingerprint | None:
    """Fingerprint one BIE base64 container without exposing its components."""
    try:
        decoded = base64.b64decode(container, validate=True)
    except ValueError:
        return None
    if (len(decoded) < 85 or decoded[:4] not in (b"BIE1", b"BIE2")
            or decoded[4] not in (2, 3)):
        return None
    ephemeral = decoded[4:37]
    ciphertext = decoded[37:-32]
    mac = decoded[-32:]
    if not ciphertext or len(ciphertext) % 16:
        return None
    short = lambda value: hashlib.sha256(value).hexdigest()[:16]
    return SafeFingerprint(
        len(container), len(decoded), decoded[:4].decode("ascii"),
        short(ephemeral), hashlib.sha256(container).hexdigest(),
        hashlib.sha256(ciphertext).hexdigest(), short(mac),
    )


def compare_fingerprints(candidate: SafeFingerprint | None,
                         active: SafeFingerprint | None) -> str:
    if candidate is None or active is None:
        return "UNKNOWN"
    if candidate.container_sha256 == active.container_sha256:
        return "BYTE_IDENTICAL"
    if candidate.complete_container_length == active.complete_container_length:
        if (candidate.decoded_bie_length == active.decoded_bie_length
                and candidate.bie_version == active.bie_version
                and candidate.ephemeral_public_key_fingerprint
                    == active.ephemeral_public_key_fingerprint):
            return "STRUCTURALLY_SIMILAR"
        return "SIZE_MATCH_ONLY"
    return "NO_MATCH"


def _record_match(context, record, extent, target, *, stale: bool) -> OwnerMatch:
    start, end = extent.physical_byte_start, extent.physical_byte_end
    if start == target.physical_start and end == target.physical_end:
        relation = "EXACT_EXTENT"
    elif start <= target.physical_start and target.physical_end <= end:
        relation = "INSIDE_EXTENT"
    else:
        relation = "PARTIAL_OVERLAP"
    alias = record.aliases[0] if record.aliases else None
    return OwnerMatch(
        relation, record.number, record.sequence,
        "STALE_OR_DELETED" if stale else "ACTIVE",
        None if alias is None else alias.filename,
        None if alias is None else alias.parent_mft_record_number,
        None if alias is None else _mft_path(alias, context.current_records_by_number),
        None if record.data is None else record.data.logical_size,
        start, end, "UNALLOCATED_RECORD" if stale else "ALLOCATED_RECORD",
        "STRUCTURAL_STALE_EXTENT" if stale else "CURRENT_MFT_EXTENT",
    )


def extent_matches(context: NTFSStaleRecoveryContext, target: TargetRange,
                   *, active: bool) -> tuple[OwnerMatch, ...]:
    matches = []
    for record in context.current_records_by_number.values():
        if record.allocated != active or record.data is None:
            continue
        for extent in record.data.extents:
            if (extent.sparse or extent.physical_byte_start is None
                    or extent.physical_byte_end is None):
                continue
            if intersects(
                    target.physical_start, target.physical_end,
                    extent.physical_byte_start, extent.physical_byte_end):
                matches.append(_record_match(
                    context, record, extent, target, stale=not active,
                ))
    rank = {"EXACT_EXTENT": 0, "INSIDE_EXTENT": 1, "PARTIAL_OVERLAP": 2}
    return tuple(sorted(matches, key=lambda item: (rank[item.relation], item.mft_record)))


def _artifact_bytes(path: Path, artifact: KnownElectrumArtifact) -> tuple[bytes, int | None, int | None] | None:
    if artifact.resident_data is not None:
        start = (artifact.physical_mft_record_offset or 0) + (artifact.resident_value_offset or 0)
        return artifact.resident_data, start, start + len(artifact.resident_data)
    if not artifact.extents or artifact.logical_size is None:
        return None
    remaining = artifact.logical_size
    output = bytearray()
    first = last = None
    with path.open("rb") as source:
        for extent in sorted(artifact.extents, key=lambda item: item.vcn_start):
            if extent.sparse or extent.physical_byte_start is None:
                return None
            length = min(remaining, extent.physical_byte_end - extent.physical_byte_start)
            source.seek(extent.physical_byte_start)
            chunk = source.read(length)
            if len(chunk) != length:
                return None
            output.extend(chunk)
            first = extent.physical_byte_start if first is None else min(first, extent.physical_byte_start)
            last = extent.physical_byte_start + length if last is None else max(last, extent.physical_byte_start + length)
            remaining -= length
            if remaining <= 0:
                break
    return (bytes(output), first, last) if remaining <= 0 else None


class ElectrumProvenanceTriage:
    def __init__(self, source: str | Path) -> None:
        self.path = Path(source).resolve()

    def run(self, targets: Iterable[TargetRange]) -> tuple[TriageResult, ...]:
        targets = tuple(targets)
        locator = NTFSBitcoinArtifactLocator()
        selected_offset = None
        for offset in self._partition_offsets():
            try:
                boot = locator.validate_ntfs_boot_sector_at(self.path, offset)
            except (OSError, ValueError):
                continue
            if all(boot.volume_offset <= item.physical_start
                   and item.physical_end <= boot.volume_end for item in targets):
                selected_offset = offset
                break
        if selected_offset is None:
            return tuple(self._unknown(target, "NTFS_VOLUME_CONTEXT_UNAVAILABLE")
                         for target in targets)
        locator.index(self.path, volume_offset=selected_offset)
        context = locator.stale_recovery_context
        if context is None:
            return tuple(self._unknown(target, "NTFS_VOLUME_CONTEXT_UNAVAILABLE")
                         for target in targets)
        try:
            bitmap = NTFSBitmapResolver.from_context(context)
            bitmap_failure = None
        except ValueError as error:
            bitmap = None
            bitmap_failure = str(error).upper()
        artifacts = tuple(item for item in known_electrum_artifacts_from_contexts((context,))
                          if item.active)
        active = []
        for artifact in artifacts:
            material = _artifact_bytes(self.path, artifact)
            if material is None:
                continue
            raw, start, end = material
            candidates = ElectrumCandidateAssembler().analyze_bytes(
                raw, source=str(self.path), physical_start=start or 0,
            )
            for item in candidates:
                token = raw[item.physical_start - (start or 0):item.physical_end - (start or 0)]
                active.append((artifact, item, safe_fingerprint(token), start, end))
        return tuple(self._one(context, bitmap, bitmap_failure, active, target)
                     for target in targets)

    def _partition_offsets(self) -> tuple[int, ...]:
        """Return bounded MBR/GPT partition starts without scanning the image."""
        size = self.path.stat().st_size
        offsets = [0]
        with self.path.open("rb") as source:
            sector = source.read(512)
            if len(sector) != 512:
                return tuple(offsets)
            entries = [sector[446 + index * 16:462 + index * 16]
                       for index in range(4)]
            offsets.extend(int.from_bytes(item[8:12], "little") * 512
                           for item in entries if int.from_bytes(item[8:12], "little"))
            if any(item[4] == 0xEE for item in entries):
                source.seek(512)
                header = source.read(512)
                if header[:8] == b"EFI PART":
                    table_offset = int.from_bytes(header[72:80], "little") * 512
                    count = int.from_bytes(header[80:84], "little")
                    entry_size = int.from_bytes(header[84:88], "little")
                    if 0 < count <= 4096 and 128 <= entry_size <= 4096:
                        table_size = count * entry_size
                        if table_offset <= size and table_size <= size - table_offset:
                            source.seek(table_offset)
                            table = source.read(table_size)
                            for index in range(count):
                                item = table[index * entry_size:(index + 1) * entry_size]
                                if any(item[:16]):
                                    offsets.append(int.from_bytes(item[32:40], "little") * 512)
        return tuple(dict.fromkeys(offsets))

    def _one(self, context, bitmap, bitmap_failure, active, target):
        reasons = []
        volume_start = context.boot.volume_offset
        cluster = context.boot.cluster_size
        if not (volume_start <= target.physical_start < target.physical_end <= context.boot.volume_end):
            return self._unknown(target, "CANDIDATE_OUTSIDE_VOLUME")
        first = (target.physical_start - volume_start) // cluster
        last = (target.physical_end - 1 - volume_start) // cluster
        allocation = (bitmap.allocation(first, last) if bitmap else
                      BitmapResult(first, last, last - first + 1, 0, 0,
                                   "UNKNOWN", (bitmap_failure,)))
        reasons.extend(allocation.reason_codes)
        current = extent_matches(context, target, active=True)
        stale = extent_matches(context, target, active=False)
        reasons.append("CURRENT_MFT_OWNER_FOUND" if current else "NO_ACTIVE_MFT_OWNER")
        reasons.append("STALE_EXTENT_MATCH_FOUND" if stale else "NO_STALE_EXTENT_MATCH")
        with self.path.open("rb") as source:
            source.seek(target.physical_start)
            token = source.read(target.physical_end - target.physical_start)
        fingerprint = safe_fingerprint(token)
        comparisons = []
        for artifact, item, active_fp, start, end in active:
            relation = compare_fingerprints(fingerprint, active_fp)
            comparisons.append(ActiveComparison(
                artifact.name, artifact.mft_record_number, start, end,
                None if active_fp is None else active_fp.complete_container_length,
                relation, active_fp,
            ))
        order = {"BYTE_IDENTICAL": 0, "STRUCTURALLY_SIMILAR": 1,
                 "SIZE_MATCH_ONLY": 2, "NO_MATCH": 3, "UNKNOWN": 4}
        closest = min(comparisons, key=lambda item: (
            order[item.relation],
            abs((item.size or 0) - len(token)), item.mft_record or 0,
        ), default=None)
        relation = "UNKNOWN" if closest is None else closest.relation
        reasons.append(f"ACTIVE_COMPARISON_{relation}")
        owner = current[0] if current else None
        stale_owner = stale[0] if stale else None
        if owner:
            classification, confidence = "ALLOCATED_OTHER_FILE", "HIGH"
        elif relation == "BYTE_IDENTICAL" and allocation.state in {"UNALLOCATED", "MIXED"}:
            classification, confidence = "LIKELY_ACTIVE_WALLET_OLD_COPY", "HIGH"
        elif stale_owner:
            classification, confidence = "POSSIBLE_HISTORICAL_WALLET", "HIGH"
        elif allocation.state == "UNALLOCATED":
            classification, confidence = "POSSIBLE_HISTORICAL_WALLET", "MEDIUM"
        elif allocation.state == "UNKNOWN":
            classification, confidence = "UNRESOLVED", "LOW"
        else:
            classification, confidence = "DISTINCT_UNKNOWN_WALLET", "MEDIUM"
        return TriageResult(
            target.candidate, target.physical_start, target.physical_end,
            target.physical_end - target.physical_start, volume_start, cluster,
            first, last, last - first + 1,
            (target.physical_start - volume_start) % cluster,
            (target.physical_end - volume_start) % cluster,
            allocation.state, allocation.allocated_cluster_count,
            allocation.unallocated_cluster_count, owner, stale_owner,
            None if stale_owner is None else stale_owner.path, closest, relation,
            confidence, classification, fingerprint, tuple(reasons),
        )

    @staticmethod
    def _unknown(target, reason):
        return TriageResult(
            target.candidate, target.physical_start, target.physical_end,
            target.physical_end - target.physical_start,
            None, None, None, None, None, None, None, "UNKNOWN", 0, 0,
            None, None, None, None, "UNKNOWN", "LOW", "UNRESOLVED", None,
            (reason,),
        )
