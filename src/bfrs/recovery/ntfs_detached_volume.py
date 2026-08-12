"""Strict discovery of current and detached NTFS volume geometries."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
    NTFSStaleRecoveryContext,
    _Boot,
    _Image,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError


NTFS_BOOT_SECTOR_SIGNATURE = "ntfs_boot_sector_oem_anchor"
NTFS_BOOT_SECTOR_PATTERN = b"NTFS    "


@dataclass(frozen=True, slots=True)
class NTFSDetachedVolumeCandidate:
    classification: str
    validation_strength: str
    provenance: str
    volume_start: int
    volume_end: int
    volume_size_bytes: int
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_lcn: int
    mftmirr_lcn: int
    mft_record_size: int
    index_block_size: int
    volume_serial: int | None
    boot_copy_count: int
    primary_boot_offsets: tuple[int, ...]
    backup_boot_offsets: tuple[int, ...]
    mft0_physical_offset: int | None
    mft0_valid: bool
    mft0_failure_reason: str | None
    mftmirr0_physical_offset: int | None
    mftmirr0_valid: bool
    mftmirr0_failure_reason: str | None
    boot_pair_valid: bool
    reasons: tuple[str, ...]

    @property
    def volume_size(self) -> int:
        """Backward-compatible alias for the exact byte count."""
        return self.volume_size_bytes


@dataclass(frozen=True, slots=True)
class NTFSDetachedVolumeDiscovery:
    source: str
    raw_boot_anchor_count: int
    candidate_boot_sector_count: int
    valid_boot_sector_count: int
    invalid_boot_sector_count: int
    geometry_hypothesis_count: int
    boot_only_geometry_count: int
    correlated_geometry_count: int
    detached_volume_count: int
    current_volume_copy_count: int
    rejection_counts: tuple[tuple[str, int], ...]
    volumes: tuple[NTFSDetachedVolumeCandidate, ...]
    diagnostics: tuple[str, ...]


class NTFSDetachedVolumeDiscoveryPipeline:
    """Consume OEM anchors emitted by the coordinator's single scanner pass."""

    def __init__(
        self,
        *,
        source: str | Path,
        current_context: NTFSStaleRecoveryContext | None,
        locator: NTFSBitcoinArtifactLocator,
    ) -> None:
        self._path = Path(source).resolve()
        self._image = _Image(self._path)
        self._current = current_context
        self._locator = locator
        self._raw_count = 0
        self._candidate_count = 0
        self._seen: set[int] = set()
        self._valid_boot_offsets: set[int] = set()
        self._rejections: Counter[str] = Counter()
        self._hypotheses: dict[tuple[int, ...], dict[str, object]] = {}

    def process_hit(self, hit: RawHit) -> None:
        if hit.hit_type != NTFS_BOOT_SECTOR_SIGNATURE:
            raise ValueError("unexpected NTFS boot anchor hit type")
        self._raw_count += 1
        self._candidate_count += 1
        if hit.start_offset < 3:
            self._rejections["anchor_before_boot_start"] += 1
            return
        offset = hit.start_offset - 3
        if offset in self._seen:
            return
        self._seen.add(offset)
        try:
            boot = self._locator.validate_ntfs_boot_sector_at(
                self._path,
                offset,
                allow_truncated_volume=True,
            )
            if offset % boot.bytes_per_sector:
                raise ValueError("boot_sector_not_physically_aligned")
        except (OSError, ValueError) as error:
            self._rejections[str(error)] += 1
            return
        self._valid_boot_offsets.add(offset)
        self._add_hypothesis(boot, offset, "primary")
        backup_start = offset - (boot.total_sectors - 1) * boot.bytes_per_sector
        if backup_start < 0:
            self._rejections["backup_volume_start_negative"] += 1
        else:
            self._add_hypothesis(replace(boot, volume_offset=backup_start), offset, "backup")

    def _identity(self, boot: _Boot) -> tuple[int, ...]:
        return (
            boot.volume_offset, boot.bytes_per_sector, boot.sectors_per_cluster,
            boot.total_sectors, boot.mft_lcn, boot.mft_mirror_lcn,
            boot.record_size, boot.index_block_size,
            -1 if boot.volume_serial is None else boot.volume_serial,
        )

    def _add_hypothesis(self, boot: _Boot, copy_offset: int, role: str) -> None:
        volume_size = boot.total_sectors * boot.bytes_per_sector
        volume_end = boot.volume_offset + volume_size
        if volume_end <= boot.volume_offset:
            self._rejections["volume_geometry_overflow"] += 1
            return
        boot = replace(boot, volume_end=volume_end)
        entry = self._hypotheses.setdefault(
            self._identity(boot), {"boot": boot, "primary": set(), "backup": set()}
        )
        entry[role].add(copy_offset)  # type: ignore[union-attr]

    def _validate_mft0(self, boot: _Boot, offset: int) -> tuple[bool, str | None]:
        if offset < boot.volume_offset or offset > boot.volume_end - boot.record_size:
            return False, "record_outside_volume"
        if offset < 0 or offset > self._image.size - boot.record_size:
            return False, "record_outside_image"
        try:
            raw = self._image.read_at(offset, boot.record_size)
            fixed, _, _, _, _ = self._locator._validated_record_header(raw, boot)
            if int.from_bytes(fixed[44:48], "little") != 0:
                raise NtfsMftRecordError("mft0_record_number_invalid")
            self._locator._parse_record(raw, 0, boot, boot.volume_end)
        except (OSError, ValueError, NtfsMftRecordError) as error:
            return False, str(error)
        return True, None

    def finish(self) -> NTFSDetachedVolumeDiscovery:
        candidates: list[NTFSDetachedVolumeCandidate] = []
        current_identity = (
            None if self._current is None else self._identity(self._current.boot)
        )
        for identity, entry in sorted(self._hypotheses.items()):
            boot = entry["boot"]
            assert isinstance(boot, _Boot)
            primary = tuple(sorted(entry["primary"]))
            backup = tuple(sorted(entry["backup"]))
            mft0 = boot.volume_offset + boot.mft_lcn * boot.cluster_size
            mirror0 = boot.volume_offset + boot.mft_mirror_lcn * boot.cluster_size
            mft_valid, mft_reason = self._validate_mft0(boot, mft0)
            mirror_valid, mirror_reason = self._validate_mft0(boot, mirror0)
            expected_backup = boot.volume_end - boot.bytes_per_sector
            pair = bool(primary and expected_backup in backup)
            correlated = mft_valid or mirror_valid or pair
            is_current = current_identity == identity
            complete_volume = 0 <= boot.volume_offset < boot.volume_end <= self._image.size
            if is_current:
                classification = "current"
            elif correlated and complete_volume:
                classification = "detached"
            else:
                classification = "boot_only_unconfirmed"
            strength = (
                "detached_volume_structural"
                if classification == "detached"
                else "geometry_correlated"
                if correlated
                else "boot_structural"
            )
            reasons = () if correlated else ("independent_geometry_corroboration_missing",)
            candidates.append(NTFSDetachedVolumeCandidate(
                classification, strength, "unknown", boot.volume_offset, boot.volume_end,
                boot.total_sectors * boot.bytes_per_sector, boot.bytes_per_sector,
                boot.sectors_per_cluster, boot.cluster_size, boot.total_sectors,
                boot.mft_lcn, boot.mft_mirror_lcn, boot.record_size,
                boot.index_block_size, boot.volume_serial,
                len(set(primary) | set(backup)), primary, backup,
                mft0, mft_valid, mft_reason, mirror0, mirror_valid, mirror_reason,
                pair, reasons,
            ))
        volumes = tuple(candidates)
        return NTFSDetachedVolumeDiscovery(
            source=str(self._path), raw_boot_anchor_count=self._raw_count,
            candidate_boot_sector_count=self._candidate_count,
            valid_boot_sector_count=len(self._valid_boot_offsets),
            invalid_boot_sector_count=self._candidate_count - len(self._valid_boot_offsets),
            geometry_hypothesis_count=len(volumes),
            boot_only_geometry_count=sum(v.validation_strength == "boot_structural" for v in volumes),
            correlated_geometry_count=sum(v.validation_strength != "boot_structural" for v in volumes),
            detached_volume_count=sum(v.classification == "detached" for v in volumes),
            current_volume_copy_count=sum(v.boot_copy_count for v in volumes if v.classification == "current"),
            rejection_counts=tuple(sorted(self._rejections.items())), volumes=volumes,
            diagnostics=(),
        )
