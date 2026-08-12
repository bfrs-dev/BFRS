"""Stream structural recovery of stale NTFS FILE records from raw anchors."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
    NTFSDataExtent,
    NTFSFileNameAlias,
    NTFSStaleRecoveryContext,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError


NTFS_FILE_RECORD_SIGNATURE = "ntfs_file_record_anchor"
NTFS_FILE_RECORD_PATTERN = b"FILE"
STALE_VALIDATION_STRENGTH = "structural_stale_ntfs_file"
DEFAULT_DIAGNOSTIC_SAMPLE_LIMIT = 100


@dataclass(frozen=True, slots=True)
class NTFSStaleFileRecord:
    physical_offset: int
    embedded_record_number: int
    sequence_number: int
    allocation_state: str
    flags: int
    aliases: tuple[NTFSFileNameAlias, ...]
    artifact_class: str | None
    parent_mft_record_number: int | None
    parent_sequence_number: int | None
    path: str | None
    partial_path: bool
    resident: bool | None
    nonresident: bool | None
    logical_size: int | None
    allocated_size: int | None
    extent_count: int
    extents: tuple[NTFSDataExtent, ...]
    extent_trust: str
    data_recovery_state: str
    comparison_to_current: str
    validation_strength: str = STALE_VALIDATION_STRENGTH


@dataclass(frozen=True, slots=True)
class NTFSStaleFileRecordRecovery:
    source: str
    raw_file_hit_count: int
    current_mft_excluded_count: int
    mftmirr_excluded_count: int
    candidate_record_count: int
    structural_stale_record_count: int
    rejected_record_count: int
    wallet_candidate_count: int
    bitcoin_context_candidate_count: int
    rejection_counts: tuple[tuple[str, int], ...]
    records: tuple[NTFSStaleFileRecord, ...]
    diagnostic_sample_limit: int
    diagnostics: tuple[str, ...]
    outside_current_volume_before_count: int = 0
    outside_current_volume_after_count: int = 0
    image_end_truncated_count: int = 0
    cli_range_truncated_count: int = 0


class NTFSStaleFileRecordRecoveryPipeline:
    """Consume FILE hits one at a time without retaining raw records."""

    def __init__(
        self,
        *,
        source: str | Path,
        range_start: int,
        range_end: int,
        context: NTFSStaleRecoveryContext | None,
        locator: NTFSBitcoinArtifactLocator,
        diagnostic_sample_limit: int = DEFAULT_DIAGNOSTIC_SAMPLE_LIMIT,
    ) -> None:
        self._path = Path(source).resolve()
        self._image_size = self._path.stat().st_size
        self._range_start = range_start
        self._range_end = range_end
        self._context = context
        self._locator = locator
        self._sample_limit = diagnostic_sample_limit
        self._seen: set[int] = set()
        self._source: BinaryIO | None = None
        self._raw_count = 0
        self._current_excluded = 0
        self._mirror_excluded = 0
        self._candidate_count = 0
        self._structural_count = 0
        self._rejected_count = 0
        self._wallet_count = 0
        self._context_count = 0
        self._rejections: Counter[str] = Counter()
        self._artifact_records: list[NTFSStaleFileRecord] = []
        self._sample_records: list[NTFSStaleFileRecord] = []
        self._diagnostics: list[str] = []
        if range_start < 0 or range_end < range_start:
            raise ValueError("invalid stale recovery range")
        if diagnostic_sample_limit < 0:
            raise ValueError("diagnostic_sample_limit must not be negative")

    def process_hit(self, hit: RawHit) -> None:
        if hit.hit_type != NTFS_FILE_RECORD_SIGNATURE:
            raise ValueError("unexpected stale FILE hit type")
        self._raw_count += 1
        offset = hit.start_offset
        if offset in self._seen:
            return
        self._seen.add(offset)
        context = self._context
        if context is None:
            self._reject("ntfs_context_unavailable")
            return
        record_size = context.boot.record_size
        if context.current_mft_record_at(offset) is not None:
            self._current_excluded += 1
            return
        if context.is_mft_mirror_record(offset):
            self._mirror_excluded += 1
            return
        self._candidate_count += 1
        reason = self._range_rejection(offset, record_size, context)
        if reason is not None:
            self._reject(reason)
            return
        try:
            raw = self._read_at(offset, record_size)
            fixed, _, _, _, flags = self._locator._validated_record_header(
                raw, context.boot
            )
            embedded_number = int.from_bytes(fixed[44:48], "little")
            record = self._locator._parse_record(
                raw,
                embedded_number,
                context.boot,
                context.boot.volume_end,
                allow_invalid_data=True,
            )
        except (OSError, ValueError, NtfsMftRecordError) as error:
            self._reject(str(error))
            return

        artifact_class = self._locator._classify(
            record, context.current_records
        )
        path, partial_path = self._locator._path(
            record, context.current_records
        )
        primary = (
            self._locator._primary_alias(record.aliases)
            if record.aliases
            else None
        )
        data = record.data
        extents = () if data is None else data.extents
        data_state = "data_attribute_missing" if data is None else data.state
        if data_state.startswith("invalid:") or data_state in {
            "extent_outside_image",
            "sparse_flag_without_sparse_run",
        }:
            extents = ()
        comparison = self._comparison_to_current(
            raw, embedded_number, record.sequence
        )
        result = NTFSStaleFileRecord(
            physical_offset=offset,
            embedded_record_number=embedded_number,
            sequence_number=record.sequence,
            allocation_state="allocated" if record.allocated else "deleted",
            flags=flags,
            aliases=record.aliases,
            artifact_class=artifact_class,
            parent_mft_record_number=(
                None if primary is None else primary.parent_mft_record_number
            ),
            parent_sequence_number=(
                None if primary is None else primary.parent_sequence_number
            ),
            path=path,
            partial_path=partial_path,
            resident=None if data is None else data.resident,
            nonresident=None if data is None else not data.resident,
            logical_size=None if data is None else data.logical_size,
            allocated_size=None if data is None else data.allocated_size,
            extent_count=len(extents),
            extents=extents,
            extent_trust="stale_record_possible",
            data_recovery_state=data_state,
            comparison_to_current=comparison,
        )
        self._structural_count += 1
        if artifact_class in {"wallet_dat", "wallet_backup_like"}:
            self._wallet_count += 1
            self._artifact_records.append(result)
        elif artifact_class == "bitcoin_context_artifact":
            self._context_count += 1
            self._artifact_records.append(result)
        elif len(self._sample_records) < self._sample_limit:
            self._sample_records.append(result)

    def finish(self) -> NTFSStaleFileRecordRecovery:
        self.close()
        records = tuple(
            sorted(
                self._artifact_records + self._sample_records,
                key=lambda item: item.physical_offset,
            )
        )
        diagnostics = list(self._diagnostics)
        if self._context is None:
            diagnostics.append("ntfs_stale_recovery_context_unavailable")
        return NTFSStaleFileRecordRecovery(
            source=str(self._path),
            raw_file_hit_count=self._raw_count,
            current_mft_excluded_count=self._current_excluded,
            mftmirr_excluded_count=self._mirror_excluded,
            candidate_record_count=self._candidate_count,
            structural_stale_record_count=self._structural_count,
            rejected_record_count=self._rejected_count,
            wallet_candidate_count=self._wallet_count,
            bitcoin_context_candidate_count=self._context_count,
            rejection_counts=tuple(sorted(self._rejections.items())),
            records=records,
            diagnostic_sample_limit=self._sample_limit,
            diagnostics=tuple(diagnostics),
            outside_current_volume_before_count=self._rejections["outside_current_ntfs_volume_before"],
            outside_current_volume_after_count=self._rejections["outside_current_ntfs_volume_after"],
            image_end_truncated_count=self._rejections["image_end_truncated"],
            cli_range_truncated_count=self._rejections["cli_range_truncated"],
        )

    def _range_rejection(self, offset, size, context):
        if offset < self._range_start:
            return "before_cli_range"
        if offset + size > self._image_size:
            return "image_end_truncated"
        if offset + size > self._range_end:
            return "cli_range_truncated"
        if offset < context.boot.volume_offset:
            return "outside_current_ntfs_volume_before"
        if offset + size > context.boot.volume_end:
            return "outside_current_ntfs_volume_after"
        return None

    def close(self) -> None:
        if self._source is not None:
            self._source.close()
            self._source = None

    def _read_at(self, offset: int, length: int) -> bytes:
        if self._source is None:
            self._source = self._path.open("rb")
        self._source.seek(offset)
        data = self._source.read(length)
        if len(data) != length:
            raise OSError("short_stale_record_read")
        return data

    def _comparison_to_current(
        self,
        raw: bytes,
        embedded_number: int,
        sequence_number: int,
    ) -> str:
        context = self._context
        assert context is not None
        record_count = context.mft_logical_size // context.boot.record_size
        if embedded_number >= record_count:
            return "stale_copy_record_number_out_of_range"
        current = context.current_records_by_number.get(embedded_number)
        current_raw = context.read_current_record(embedded_number)
        if current is None or current_raw is None:
            return "stale_copy_differs_current"
        stale_hash = self._locator._fixed_record_hash(raw, context.boot)
        current_hash = self._locator._fixed_record_hash(
            current_raw, context.boot
        )
        if (
            stale_hash == current_hash
            and sequence_number == current.sequence
        ):
            return "stale_copy_matches_current"
        return "stale_copy_differs_current"

    def _reject(self, reason: str) -> None:
        self._rejected_count += 1
        self._rejections[reason] += 1
