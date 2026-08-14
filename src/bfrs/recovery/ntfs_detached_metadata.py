"""Targeted logical metadata and stale-anchor recovery for detached NTFS."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    MAX_MFT_RECORDS,
    NTFSBitcoinArtifactLocator,
    NTFSDataExtent,
    NTFSFileNameAlias,
    NTFSStaleRecoveryContext,
    _Boot,
    _Image,
    _LogicalStream,
    _Record,
)
from bfrs.recovery.ntfs_detached_volume import (
    NTFSDetachedVolumeCandidate,
    NTFSDetachedVolumeDiscovery,
)
from bfrs.recovery.ntfs_directory_index import (
    NTFSDirectoryIndexArtifactRecoveryPipeline,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftDataExtractor, NtfsMftRecordError
from bfrs.recovery.ntfs_stale_file import (
    NTFS_FILE_RECORD_SIGNATURE,
    NTFSStaleFileRecordRecoveryPipeline,
)
from bfrs.recovery.ntfs_stale_indx import (
    NTFS_INDX_RECORD_SIGNATURE,
    NTFSStaleINDXRecoveryPipeline,
)


@dataclass(frozen=True, slots=True)
class NTFSDetachedFileCandidate:
    volume_start: int
    volume_end: int
    provenance: str
    source_layer: str
    artifact_class: str
    filename: str
    aliases: tuple[NTFSFileNameAlias, ...]
    path: str | None
    partial_path: bool
    mft_record_number: int | None
    sequence_number: int | None
    allocation_state: str | None
    resident: bool | None
    nonresident: bool | None
    logical_size: int | None
    allocated_size: int | None
    initialized_size: int | None
    extents: tuple[NTFSDataExtent, ...]
    extent_trust: str | None
    physical_metadata_offset: int | None
    source_directory_mft_record: int | None
    entry_offset: int | None
    entry_state: str | None
    file_reference_record: int | None
    file_reference_sequence: int | None
    reference_state: str | None
    validation_strength: str


@dataclass(frozen=True, slots=True)
class NTFSDetachedVolumeMetadataResult:
    volume_start: int
    volume_end: int
    volume_size_bytes: int
    provenance: str
    validation_strength: str
    mft_logical_size: int
    mft_record_count: int
    mft_records_scanned: int
    mft_records_valid: int
    mft_records_invalid: int
    directory_record_count: int
    index_root_count: int
    index_allocation_stream_count: int
    indx_block_count: int
    indx_block_valid_count: int
    indx_block_invalid_count: int
    active_index_entry_count: int
    structural_index_slack_entry_count: int
    raw_file_hit_count_within_volume: int
    detached_current_mft_excluded_count: int
    structural_stale_file_count: int
    raw_indx_hit_count_within_volume: int
    detached_current_indx_excluded_count: int
    structural_stale_indx_count: int
    wallet_candidate_count: int
    bitcoin_context_candidate_count: int
    rejection_counts: tuple[tuple[str, int], ...]
    candidates: tuple[NTFSDetachedFileCandidate, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NTFSDetachedMetadataRecovery:
    source: str
    volume_count: int
    volumes: tuple[NTFSDetachedVolumeMetadataResult, ...]
    wallet_candidate_count: int
    bitcoin_context_candidate_count: int
    logical_wallet_candidate_count: int
    stale_wallet_candidate_count: int
    diagnostics: tuple[str, ...]
    volume_contexts: tuple[NTFSStaleRecoveryContext, ...] = ()


@dataclass(frozen=True, slots=True)
class NTFSDetachedContextBuild:
    contexts: tuple[NTFSStaleRecoveryContext, ...]
    failures: tuple[str, ...]


class NTFSDetachedMetadataRecoveryPipeline:
    """Read only mapped detached metadata and reuse already-scanned anchors."""

    def __init__(
        self,
        *,
        source: str | Path,
        discovery: NTFSDetachedVolumeDiscovery,
        locator: NTFSBitcoinArtifactLocator,
        raw_file_offsets: Iterable[int] = (),
        raw_indx_offsets: Iterable[int] = (),
        range_start: int = 0,
        range_end: int | None = None,
    ) -> None:
        self._path = Path(source).resolve()
        self._image = _Image(self._path)
        self._discovery = discovery
        self._locator = locator
        self._raw_file_offsets = tuple(raw_file_offsets)
        self._raw_indx_offsets = tuple(raw_indx_offsets)
        self._range_start = range_start
        self._range_end = self._image.size if range_end is None else range_end
        self._volume_contexts: list[NTFSStaleRecoveryContext] = []
        if range_start < 0 or self._range_end < range_start or self._range_end > self._image.size:
            raise ValueError("invalid detached metadata recovery range")

    def run(self) -> NTFSDetachedMetadataRecovery:
        results = tuple(
            self._recover_volume(volume)
            for volume in self._discovery.volumes
            if volume.classification == "detached"
            and volume.validation_strength == "detached_volume_structural"
        )
        candidates = tuple(item for result in results for item in result.candidates)
        wallets = tuple(
            item for item in candidates
            if item.artifact_class in {"wallet_dat", "wallet_backup_like"}
        )
        return NTFSDetachedMetadataRecovery(
            source=str(self._path),
            volume_count=len(results),
            volumes=results,
            wallet_candidate_count=len(wallets),
            bitcoin_context_candidate_count=sum(
                item.artifact_class == "bitcoin_context_artifact" for item in candidates
            ),
            logical_wallet_candidate_count=sum(
                item.source_layer.startswith("detached_logical_") for item in wallets
            ),
            stale_wallet_candidate_count=sum(
                item.source_layer.startswith("detached_stale_") for item in wallets
            ),
            diagnostics=(),
            volume_contexts=tuple(self._volume_contexts),
        )

    def build_confirmed_volume_contexts(self) -> NTFSDetachedContextBuild:
        """Build only MFT contexts, avoiding unrelated recovery layers/scans."""
        contexts: list[NTFSStaleRecoveryContext] = []
        failures: list[str] = []
        seen: set[tuple[int, ...]] = set()
        for volume in self._discovery.volumes:
            if (volume.classification != "detached" or
                    volume.validation_strength != "detached_volume_structural"):
                continue
            identity = (volume.volume_start, volume.volume_end,
                        volume.bytes_per_sector, volume.cluster_size,
                        volume.mft_lcn, volume.mft_record_size)
            if identity in seen:
                continue
            seen.add(identity)
            boot = self._boot(volume)
            try:
                context, _, _, _ = self._logical_mft(volume, boot)
            except (OSError, ValueError, NtfsMftRecordError) as error:
                reason = f"volume:{volume.volume_start}:context_build_failure:{error}"
                failures.append(reason)
                context = NTFSStaleRecoveryContext(
                    source=str(self._path), boot=boot, mft_extents=(),
                    mft_logical_size=0, current_records={},
                    current_records_by_number={},
                    provenance="detached_structural",
                    initialization_failures=(reason,),
                )
            contexts.append(context)
        return NTFSDetachedContextBuild(tuple(contexts), tuple(failures))

    def _recover_volume(
        self, volume: NTFSDetachedVolumeCandidate
    ) -> NTFSDetachedVolumeMetadataResult:
        counters: Counter[str] = Counter()
        rejections: Counter[str] = Counter()
        diagnostics: list[str] = []
        candidates: list[NTFSDetachedFileCandidate] = []
        boot = self._boot(volume)
        context: NTFSStaleRecoveryContext | None = None
        index = None
        try:
            context, logical_candidates, logical_counts, logical_failures = self._logical_mft(
                volume, boot
            )
            candidates.extend(logical_candidates)
            counters.update(logical_counts)
            rejections.update(logical_failures)
        except (OSError, ValueError, NtfsMftRecordError) as error:
            rejections[str(error)] += 1
            diagnostics.append(f"detached_logical_mft_unavailable:{error}")

        if context is not None:
            self._volume_contexts.append(context)
            index = NTFSDirectoryIndexArtifactRecoveryPipeline(
                context=context, locator=self._locator
            ).run()
            counters["directory_record_count"] = index.directory_record_count
            counters["index_root_count"] = index.index_root_count
            counters["index_allocation_stream_count"] = index.index_allocation_stream_count
            counters["indx_block_count"] = index.indx_block_count
            counters["indx_block_valid_count"] = index.indx_block_valid_count
            counters["indx_block_invalid_count"] = index.indx_block_invalid_count
            counters["active_index_entry_count"] = index.active_entry_count
            counters["structural_index_slack_entry_count"] = index.structural_slack_entry_count
            rejections.update(dict(index.rejection_counts))
            diagnostics.extend(index.diagnostics)
            candidates.extend(self._index_candidates(volume, index.candidates))

            file_offsets = tuple(
                offset for offset in self._raw_file_offsets
                if volume.volume_start <= offset < volume.volume_end
            )
            counters["raw_file_hit_count_within_volume"] = len(file_offsets)
            stale_file = NTFSStaleFileRecordRecoveryPipeline(
                source=self._path, range_start=self._range_start,
                range_end=self._range_end, context=context, locator=self._locator,
                diagnostic_sample_limit=0,
            )
            for offset in file_offsets:
                stale_file.process_hit(self._hit(offset, NTFS_FILE_RECORD_SIGNATURE, 4))
            stale_file_result = stale_file.finish()
            counters["detached_current_mft_excluded_count"] = (
                stale_file_result.current_mft_excluded_count
            )
            counters["structural_stale_file_count"] = (
                stale_file_result.structural_stale_record_count
            )
            rejections.update(dict(stale_file_result.rejection_counts))
            candidates.extend(self._stale_file_candidates(volume, stale_file_result.records))

            indx_offsets = tuple(
                offset for offset in self._raw_indx_offsets
                if volume.volume_start <= offset < volume.volume_end
            )
            counters["raw_indx_hit_count_within_volume"] = len(indx_offsets)
            stale_indx = NTFSStaleINDXRecoveryPipeline(
                source=self._path, range_start=self._range_start,
                range_end=self._range_end, context=context, locator=self._locator,
                current_index=index, diagnostic_sample_limit=0,
            )
            for offset in indx_offsets:
                stale_indx.process_hit(self._hit(offset, NTFS_INDX_RECORD_SIGNATURE, 4))
            stale_indx_result = stale_indx.finish()
            counters["detached_current_indx_excluded_count"] = (
                stale_indx_result.current_indx_excluded_count
            )
            counters["structural_stale_indx_count"] = (
                stale_indx_result.structural_stale_indx_count
            )
            rejections.update(dict(stale_indx_result.rejection_counts))
            candidates.extend(self._stale_indx_candidates(volume, stale_indx_result.candidates))

        if context is None:
            self._volume_contexts.append(NTFSStaleRecoveryContext(
                source=str(self._path), boot=boot, mft_extents=(),
                mft_logical_size=0, current_records={},
                current_records_by_number={}, provenance="detached_structural",
                initialization_failures=tuple(diagnostics),
            ))

        ordered = tuple(sorted(candidates, key=self._candidate_key))
        return NTFSDetachedVolumeMetadataResult(
            volume_start=volume.volume_start,
            volume_end=volume.volume_end,
            volume_size_bytes=volume.volume_size_bytes,
            provenance="unknown",
            validation_strength=volume.validation_strength,
            mft_logical_size=counters["mft_logical_size"],
            mft_record_count=counters["mft_record_count"],
            mft_records_scanned=counters["mft_records_scanned"],
            mft_records_valid=counters["mft_records_valid"],
            mft_records_invalid=counters["mft_records_invalid"],
            directory_record_count=counters["directory_record_count"],
            index_root_count=counters["index_root_count"],
            index_allocation_stream_count=counters["index_allocation_stream_count"],
            indx_block_count=counters["indx_block_count"],
            indx_block_valid_count=counters["indx_block_valid_count"],
            indx_block_invalid_count=counters["indx_block_invalid_count"],
            active_index_entry_count=counters["active_index_entry_count"],
            structural_index_slack_entry_count=counters["structural_index_slack_entry_count"],
            raw_file_hit_count_within_volume=counters["raw_file_hit_count_within_volume"],
            detached_current_mft_excluded_count=counters["detached_current_mft_excluded_count"],
            structural_stale_file_count=counters["structural_stale_file_count"],
            raw_indx_hit_count_within_volume=counters["raw_indx_hit_count_within_volume"],
            detached_current_indx_excluded_count=counters["detached_current_indx_excluded_count"],
            structural_stale_indx_count=counters["structural_stale_indx_count"],
            wallet_candidate_count=sum(
                item.artifact_class in {"wallet_dat", "wallet_backup_like"}
                for item in ordered
            ),
            bitcoin_context_candidate_count=sum(
                item.artifact_class == "bitcoin_context_artifact" for item in ordered
            ),
            rejection_counts=tuple(sorted(rejections.items())),
            candidates=ordered,
            diagnostics=tuple(dict.fromkeys(diagnostics))[:200],
        )

    def _logical_mft(self, volume, boot):
        record_zero_offset = volume.mft0_physical_offset
        if record_zero_offset is None:
            raise NtfsMftRecordError("mft0_physical_offset_unavailable")
        self._require_range(record_zero_offset, boot.record_size, volume)
        raw_zero = self._image.read_at(record_zero_offset, boot.record_size)
        mapping = NtfsMftDataExtractor().extract(
            raw_zero, bytes_per_sector=boot.bytes_per_sector,
            cluster_size=boot.cluster_size, partition_offset=boot.volume_offset,
        )
        if mapping is None:
            raise NtfsMftRecordError("mft_unnamed_nonresident_data_missing")
        if mapping.partial_extent_mapping:
            raise NtfsMftRecordError("mft_partial_extent_mapping_unsupported")
        if mapping.extent_mapping.sparse_ranges:
            raise NtfsMftRecordError("mft_sparse_run_unsupported")
        if mapping.file_size <= 0 or mapping.file_size // boot.record_size > MAX_MFT_RECORDS:
            raise NtfsMftRecordError("mft_logical_size_invalid")
        for extent in mapping.extent_mapping.extents:
            self._require_range(extent.physical_start, extent.length, volume)
        stream = _LogicalStream(
            self._image, mapping.extent_mapping.extents, mapping.file_size
        )
        count = mapping.file_size // boot.record_size
        counters = Counter(
            mft_logical_size=mapping.file_size,
            mft_record_count=count,
        )
        if mapping.file_size % boot.record_size:
            counters["mft_trailing_partial_record"] += 1
        records_by_identity: dict[tuple[int, int], _Record] = {}
        records_by_number: dict[int, _Record] = {}
        failures: Counter[str] = Counter()
        for number in range(count):
            counters["mft_records_scanned"] += 1
            logical = number * boot.record_size
            try:
                raw = stream.read_at(logical, boot.record_size)
                record = self._locator._parse_record(
                    raw, number, boot, min(self._image.size, volume.volume_end)
                )
            except (OSError, ValueError, NtfsMftRecordError) as error:
                counters["mft_records_invalid"] += 1
                failures[f"mft_record_invalid:{error}"] += 1
                continue
            counters["mft_records_valid"] += 1
            records_by_identity[(number, record.sequence)] = record
            records_by_number[number] = record
        context = NTFSStaleRecoveryContext(
            source=str(self._path), boot=boot,
            mft_extents=mapping.extent_mapping.extents,
            mft_logical_size=mapping.file_size,
            current_records=records_by_identity,
            current_records_by_number=records_by_number,
            provenance="detached_structural",
        )
        candidates: list[NTFSDetachedFileCandidate] = []
        for number, record in sorted(records_by_number.items()):
            artifact = self._locator._classify(record, records_by_identity)
            if artifact is None:
                continue
            path, partial = self._locator._path(record, records_by_identity)
            physical = stream.physical_offset_for(
                number * boot.record_size, boot.record_size
            )
            candidates.append(self._record_candidate(
                volume, record, artifact, path, partial, physical,
                "detached_logical_mft", "structural_detached_logical_mft_record",
            ))
        return context, candidates, counters, failures

    def _require_range(self, offset: int, length: int, volume) -> None:
        end = offset + length
        if (
            offset < volume.volume_start or end > volume.volume_end
            or offset < self._range_start or end > self._range_end
            or offset < 0 or end > self._image.size or end < offset
        ):
            raise NtfsMftRecordError("detached_extent_outside_safe_range")

    @staticmethod
    def _boot(volume) -> _Boot:
        return _Boot(
            volume_offset=volume.volume_start,
            bytes_per_sector=volume.bytes_per_sector,
            cluster_size=volume.cluster_size,
            mft_lcn=volume.mft_lcn,
            mft_mirror_lcn=volume.mftmirr_lcn,
            record_size=volume.mft_record_size,
            volume_end=volume.volume_end,
            sectors_per_cluster=volume.sectors_per_cluster,
            total_sectors=volume.total_sectors,
            index_block_size=volume.index_block_size,
            volume_serial=volume.volume_serial,
        )

    @staticmethod
    def _hit(offset: int, hit_type: str, length: int) -> RawHit:
        return RawHit(offset, offset + length, hit_type, 1.0, "shared_fast_scanner", {})

    def _record_candidate(
        self, volume, record, artifact, path, partial, physical,
        source_layer, validation,
    ) -> NTFSDetachedFileCandidate:
        data = record.data
        primary = self._locator._primary_alias(record.aliases) if record.aliases else None
        return NTFSDetachedFileCandidate(
            volume.volume_start, volume.volume_end, "unknown", source_layer,
            artifact, "" if primary is None else primary.filename,
            record.aliases, path, partial, record.number, record.sequence,
            "allocated" if record.allocated else "deleted",
            None if data is None else data.resident,
            None if data is None else not data.resident,
            None if data is None else data.logical_size,
            None if data is None else data.allocated_size,
            None if data is None else data.initialized_size,
            () if data is None else data.extents,
            None if data is None else "detached_logical_mft",
            physical, None, None, None, None, None, None, validation,
        )

    def _index_candidates(self, volume, items):
        mapped = {
            "current_reference_matches": "detached_reference_matches",
            "current_record_reused_sequence_differs": "detached_record_reused_sequence_differs",
            "current_record_missing": "detached_record_missing",
            "record_number_out_of_range": "detached_record_number_out_of_range",
        }
        return tuple(
            NTFSDetachedFileCandidate(
                volume.volume_start, volume.volume_end, "unknown",
                "detached_logical_index_active" if item.entry_state == "active"
                else "detached_logical_index_slack",
                item.artifact_class, item.filename, (), item.recovered_path,
                item.partial_path, None, None, None, None, None, None, None,
                None, (), None, None, item.source_directory_mft_record,
                item.entry_offset, item.entry_state, item.file_reference_record,
                item.file_reference_sequence, mapped.get(item.reference_state, item.reference_state),
                "active_detached_logical_index_entry" if item.entry_state == "active"
                else "structural_detached_logical_index_slack_entry",
            )
            for item in items
        )

    def _stale_file_candidates(self, volume, items):
        comparison = {
            "stale_copy_matches_current": "stale_copy_matches_detached_logical_mft",
            "stale_copy_differs_current": "stale_copy_differs_detached_logical_mft",
            "stale_copy_record_number_out_of_range": "detached_record_number_out_of_range",
        }
        return tuple(
            NTFSDetachedFileCandidate(
                volume.volume_start, volume.volume_end, "unknown", "detached_stale_file",
                item.artifact_class, item.aliases[0].filename if item.aliases else "",
                item.aliases, item.path, item.partial_path, item.embedded_record_number,
                item.sequence_number, item.allocation_state, item.resident, item.nonresident,
                item.logical_size, item.allocated_size, None, item.extents,
                "detached_stale_file", item.physical_offset, None, None, None,
                None, None, comparison.get(item.comparison_to_current, item.comparison_to_current),
                "structural_stale_file_within_detached_volume",
            )
            for item in items if item.artifact_class is not None
        )

    @staticmethod
    def _stale_indx_candidates(volume, items):
        mapped = {
            "current_reference_matches": "detached_reference_matches",
            "current_record_reused_sequence_differs": "detached_record_reused_sequence_differs",
            "current_record_missing": "detached_record_missing",
            "record_number_out_of_range": "detached_record_number_out_of_range",
        }
        return tuple(
            NTFSDetachedFileCandidate(
                volume.volume_start, volume.volume_end, "unknown",
                "detached_stale_indx_active" if item.entry_state == "active"
                else "detached_stale_indx_slack",
                item.artifact_class, item.filename, (), None, True, None, None,
                None, None, None, None, None, None, (), None,
                item.source_block_physical_offset, None, item.entry_offset,
                item.entry_state, item.file_reference_record,
                item.file_reference_sequence, mapped.get(item.reference_state, item.reference_state),
                "structural_stale_indx_within_detached_volume",
            )
            for item in items if item.artifact_class is not None
        )

    @staticmethod
    def _candidate_key(item):
        return (
            item.volume_start, item.source_layer,
            -1 if item.physical_metadata_offset is None else item.physical_metadata_offset,
            -1 if item.mft_record_number is None else item.mft_record_number,
            -1 if item.entry_offset is None else item.entry_offset,
            item.filename.casefold(),
        )
