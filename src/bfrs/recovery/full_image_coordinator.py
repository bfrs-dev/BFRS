"""Coordinate conservative Bitcoin wallet recovery over an image range."""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bfrs.core.chunk_reader import ChunkReader
from bfrs.core.hotspot_reader import HotspotReader
from bfrs.core.models import Hotspot, RawHit, ValidationStatus
from bfrs.recovery.berkeley_database_pipeline import (
    BerkeleyDatabaseRecoveryPipeline,
    BerkeleyDatabaseRecoveryResult,
)
from bfrs.recovery.fragmented_berkeley_reassembler import (
    FragmentedBerkeleyPageReassembler,
    PhysicalBerkeleyMetadataCandidate,
    PhysicalBerkeleyPageCandidate,
    ReconstructedBerkeleyDatabase,
)
from bfrs.recovery.logical_berkeley_reader import PhysicalRangeReadError
from bfrs.recovery.logical_berkeley_database_pipeline import (
    LogicalBerkeleyDatabaseRecoveryPipeline,
    LogicalBerkeleyDatabaseRecoveryResult,
)
from bfrs.recovery.logical_page_map import (
    LogicalBerkeleyPageMap,
    LogicalPageLocation,
)
from bfrs.recovery.metadata_less_fragments import (
    MetadataLessBerkeleyFragmentRecovery,
    MetadataLessBerkeleyFragmentRecoveryPipeline,
)
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactIndex,
    NTFSBitcoinArtifactLocator,
)
from bfrs.recovery.ntfs_directory_index import (
    NTFSDirectoryIndexArtifactRecovery,
    NTFSDirectoryIndexArtifactRecoveryPipeline,
)
from bfrs.recovery.ntfs_detached_volume import (
    NTFS_BOOT_SECTOR_SIGNATURE,
    NTFSDetachedVolumeDiscovery,
    NTFSDetachedVolumeDiscoveryPipeline,
)
from bfrs.recovery.ntfs_detached_metadata import (
    NTFSDetachedMetadataRecovery,
    NTFSDetachedMetadataRecoveryPipeline,
)
from bfrs.recovery.ntfs_historical_wallet_recovery import (
    NtfsHistoricalWalletRecovery,
    NtfsHistoricalWalletRecoveryPipeline,
)
from bfrs.recovery.ntfs_stale_file import (
    NTFS_FILE_RECORD_SIGNATURE,
    NTFSStaleFileRecordRecovery,
    NTFSStaleFileRecordRecoveryPipeline,
)
from bfrs.recovery.ntfs_stale_indx import (
    NTFS_INDX_RECORD_SIGNATURE,
    NTFSStaleINDXRecovery,
    NTFSStaleINDXRecoveryPipeline,
)
from bfrs.recovery.orphan_record_key_diagnostic import (
    OrphanBitcoinRecordKeyDiagnostic,
    OrphanBitcoinRecordKeyDiagnosticPipeline,
)
from bfrs.recovery.orphan_private_key_der import (
    OrphanHistoricalECPrivateKeyRecovery,
    OrphanHistoricalECPrivateKeyRecoveryPipeline,
)
from bfrs.recovery.orphan_private_key_fragment import (
    OrphanHistoricalECPrivateKeyFragmentRecovery,
    OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline,
)
from bfrs.recovery.reconstructed_wallet_pipeline import (
    ReconstructedBerkeleyWalletPipeline,
    ReconstructedBerkeleyWalletRecovery,
)
from bfrs.recovery.electrum_raw_recovery import (
    ELECTRUM_SIGNATURE_NAMES,
    ElectrumRawRecovery,
    ElectrumRawRecoveryPipeline,
    known_electrum_artifacts_from_contexts,
)
from bfrs.scanners.fast_scanner import FastScanner, Signature
from bfrs.scanners.hotspot_builder import (
    DEFAULT_CLUSTER_GAP,
    DEFAULT_PADDING,
    HotspotBuilder,
)
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import (
    BTREE_MAGIC,
    MAGIC_OFFSET,
    MAX_PAGE_SIZE,
    BerkeleyMetadataValidator,
)
from bfrs.validators.berkeley_page import PAGE_HEADER_SIZE, BerkeleyPageValidator
from bfrs.validators.candidate_policy import CandidatePolicy


@dataclass(frozen=True, slots=True)
class FullImageRecoveryResult:
    source: str
    start_offset: int
    end_offset: int
    status: ValidationStatus
    raw_hit_count: int
    hotspot_count: int
    accepted_hotspot_count: int
    direct_results: tuple[BerkeleyDatabaseRecoveryResult, ...]
    reconstructed_databases: tuple[ReconstructedBerkeleyDatabase, ...]
    reconstructed_wallet_results: tuple[
        ReconstructedBerkeleyWalletRecovery, ...
    ]
    logical_wallet_results: tuple[LogicalBerkeleyDatabaseRecoveryResult, ...]
    metadata_less_fragment_recovery: MetadataLessBerkeleyFragmentRecovery
    orphan_record_key_diagnostic: OrphanBitcoinRecordKeyDiagnostic
    orphan_private_key_recovery: OrphanHistoricalECPrivateKeyRecovery
    orphan_private_key_fragment_recovery: (
        OrphanHistoricalECPrivateKeyFragmentRecovery
    )
    structural_wallet_count: int
    fragment_wallet_count: int
    reasons: tuple[str, ...]
    evidence: dict[str, Any]
    logical_ntfs_results: tuple[Any, ...] = ()
    ntfs_bitcoin_artifact_index: NTFSBitcoinArtifactIndex | None = None
    ntfs_stale_file_record_recovery: NTFSStaleFileRecordRecovery | None = None
    ntfs_directory_index_artifact_recovery: (
        NTFSDirectoryIndexArtifactRecovery | None
    ) = None
    ntfs_stale_indx_recovery: NTFSStaleINDXRecovery | None = None
    ntfs_detached_volume_discovery: NTFSDetachedVolumeDiscovery | None = None
    ntfs_detached_metadata_recovery: NTFSDetachedMetadataRecovery | None = None
    ntfs_historical_wallet_recovery: NtfsHistoricalWalletRecovery | None = None
    electrum_raw_recovery: ElectrumRawRecovery | None = None


class _AcceptedContextRangeReader:
    """Serve reads solely from accepted hotspot buffers already in memory."""

    def __init__(self, contexts: Iterable[ValidationContext]) -> None:
        self._contexts = tuple(
            sorted(contexts, key=lambda item: (item.start_offset, item.end_offset))
        )

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        available: list[tuple[int, int, bytes]] = []
        for context in self._contexts:
            if context.start_offset <= offset < context.end_offset:
                local = offset - context.start_offset
                data = context.data[local : local + length]
                available.append((len(data), -context.start_offset, data))
        if not available:
            raise PhysicalRangeReadError("range is outside accepted hotspots")
        return max(available, key=lambda item: (item[0], item[1]))[2]

    def read_before(
        self,
        end_offset: int,
        maximum_length: int,
        lower_bound: int,
    ) -> tuple[int, bytes]:
        if maximum_length < 0 or lower_bound < 0 or end_offset < lower_bound:
            raise ValueError("invalid bounded backward read")
        covering = tuple(
            context
            for context in self._contexts
            if context.start_offset < end_offset <= context.end_offset
        )
        if not covering:
            raise PhysicalRangeReadError("hit is outside accepted hotspots")
        context = min(covering, key=lambda item: item.start_offset)
        start = max(lower_bound, context.start_offset, end_offset - maximum_length)
        local_start = start - context.start_offset
        local_end = end_offset - context.start_offset
        return start, context.data[local_start:local_end]


class FullImageRecoveryCoordinator:
    """Run scan, admission, direct recovery, and global page reassembly."""

    def __init__(
        self,
        signatures: Iterable[Signature],
        candidate_policy: CandidatePolicy,
        chunk_size: int = 64 * 1024 * 1024,
        overlap: int | None = None,
        cluster_gap: int = DEFAULT_CLUSTER_GAP,
        hotspot_padding: int = DEFAULT_PADDING,
    ) -> None:
        collected = tuple(signatures)
        self._scanner = FastScanner(collected)
        if not isinstance(candidate_policy, CandidatePolicy):
            raise ValueError("candidate_policy must be CandidatePolicy")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        required_overlap = max(len(signature.pattern) for signature in collected) - 1
        selected_overlap = required_overlap if overlap is None else overlap
        if selected_overlap < 0 or selected_overlap >= chunk_size:
            raise ValueError("overlap must be nonnegative and less than chunk_size")
        self._candidate_policy = candidate_policy
        self._chunk_size = chunk_size
        self._overlap = selected_overlap
        self._hotspot_builder = HotspotBuilder(cluster_gap, hotspot_padding)

    def scan(
        self,
        path: str | Path,
        start: int = 0,
        end: int | None = None,
    ) -> FullImageRecoveryResult:
        reader = ChunkReader(path, chunk_size=self._chunk_size, overlap=self._overlap)
        range_end = reader.file_size if end is None else end
        ntfs_locator = NTFSBitcoinArtifactLocator()
        ntfs_bitcoin_artifact_index = ntfs_locator.index(reader.path)
        ntfs_directory_index_artifact_recovery = (
            NTFSDirectoryIndexArtifactRecoveryPipeline(
                context=ntfs_locator.stale_recovery_context,
                locator=ntfs_locator,
            ).run()
        )
        stale_pipeline = NTFSStaleFileRecordRecoveryPipeline(
            source=reader.path,
            range_start=start,
            range_end=range_end,
            context=ntfs_locator.stale_recovery_context,
            locator=ntfs_locator,
        )
        stale_indx_pipeline = NTFSStaleINDXRecoveryPipeline(
            source=reader.path,
            range_start=start,
            range_end=range_end,
            context=ntfs_locator.stale_recovery_context,
            locator=ntfs_locator,
            current_index=ntfs_directory_index_artifact_recovery,
        )
        detached_pipeline = NTFSDetachedVolumeDiscoveryPipeline(
            source=reader.path,
            current_context=ntfs_locator.stale_recovery_context,
            locator=ntfs_locator,
        )
        recovery_hits: list[RawHit] = []
        electrum_hits: list[RawHit] = []
        detached_file_offsets: list[int] = []
        detached_indx_offsets: list[int] = []
        raw_hit_counts: Counter[str] = Counter()
        try:
            for hit in self._scanner.scan(reader, start=start, end=range_end):
                raw_hit_counts[hit.hit_type] += 1
                if hit.hit_type == NTFS_FILE_RECORD_SIGNATURE:
                    detached_file_offsets.append(hit.start_offset)
                    stale_pipeline.process_hit(hit)
                elif hit.hit_type == NTFS_INDX_RECORD_SIGNATURE:
                    detached_indx_offsets.append(hit.start_offset)
                    stale_indx_pipeline.process_hit(hit)
                elif hit.hit_type == NTFS_BOOT_SECTOR_SIGNATURE:
                    detached_pipeline.process_hit(hit)
                elif hit.hit_type in ELECTRUM_SIGNATURE_NAMES:
                    electrum_hits.append(hit)
                else:
                    recovery_hits.append(hit)
        except BaseException:
            stale_pipeline.close()
            stale_indx_pipeline.close()
            raise
        ntfs_stale_file_record_recovery = stale_pipeline.finish()
        ntfs_stale_indx_recovery = stale_indx_pipeline.finish()
        ntfs_detached_volume_discovery = detached_pipeline.finish()
        ntfs_detached_metadata_recovery = NTFSDetachedMetadataRecoveryPipeline(
            source=reader.path,
            discovery=ntfs_detached_volume_discovery,
            locator=ntfs_locator,
            raw_file_offsets=detached_file_offsets,
            raw_indx_offsets=detached_indx_offsets,
            range_start=start,
            range_end=range_end,
        ).run()
        historical_contexts = tuple(
            context for context in (
                ntfs_locator.stale_recovery_context,
                *ntfs_detached_metadata_recovery.volume_contexts,
            ) if context is not None
        )
        ntfs_historical_wallet_recovery = (
            NtfsHistoricalWalletRecoveryPipeline().run(historical_contexts)
        )
        electrum_raw_recovery = ElectrumRawRecoveryPipeline(
            source=reader.path,
            known_artifacts=known_electrum_artifacts_from_contexts(
                historical_contexts
            ),
        ).run_hits(electrum_hits, range_start=start, range_end=range_end)
        hits = tuple(recovery_hits)
        hotspots = self._range_hotspots(hits, start, range_end)

        decisions = tuple(
            (hotspot, self._candidate_policy.evaluate(hotspot))
            for hotspot in hotspots
        )
        accepted = tuple(hotspot for hotspot, decision in decisions if decision.accepted)
        contexts: list[ValidationContext] = []
        direct_with_ranges: list[
            tuple[int, int, BerkeleyDatabaseRecoveryResult]
        ] = []
        errors: list[tuple[int, int, str, str]] = []
        hotspot_reader = HotspotReader(path)
        direct_pipeline = BerkeleyDatabaseRecoveryPipeline()
        for hotspot in accepted:
            try:
                context = hotspot_reader.read(hotspot)
            except OSError as error:
                errors.append(
                    (hotspot.start_offset, hotspot.end_offset, "hotspot_read_error", type(error).__name__)
                )
                continue
            contexts.append(context)
            try:
                direct = direct_pipeline.run(context)
            except ValueError as error:
                if str(error) != "database_base_offset must not be negative":
                    raise
                errors.append(
                    (hotspot.start_offset, hotspot.end_offset, "direct_grid_unavailable", type(error).__name__)
                )
            else:
                direct_with_ranges.append(
                    (hotspot.start_offset, hotspot.end_offset, direct)
                )

        metadata = self._metadata_candidates(contexts)
        pages = self._page_candidates(contexts, metadata)
        range_reader = _AcceptedContextRangeReader(contexts)
        databases = FragmentedBerkeleyPageReassembler(
            pages, range_reader=range_reader
        ).reconstruct(metadata)
        wallet_results = tuple(
            ReconstructedBerkeleyWalletPipeline(
                database, range_reader=range_reader
            ).run()
            for database in databases
        )
        logical_wallet_results: list[LogicalBerkeleyDatabaseRecoveryResult] = []
        for database in databases:
            identity = database.identity
            locations = (
                LogicalPageLocation(
                    identity.metadata_page_number,
                    identity.metadata_physical_offset,
                    identity.page_size,
                    identity.source,
                ),
                *(
                    LogicalPageLocation(
                        page.page_number,
                        page.physical_offset,
                        page.page_size,
                        identity.source,
                    )
                    for page in database.selected_pages
                ),
            )
            try:
                page_map = LogicalBerkeleyPageMap(
                    identity.source,
                    identity.page_size,
                    identity.byte_order,
                    locations,
                )
                logical_wallet_results.append(
                    LogicalBerkeleyDatabaseRecoveryPipeline(
                        page_map,
                        logical_file_id=(
                            f"reconstructed-{identity.metadata_physical_offset:x}-"
                            f"{identity.root_page_number}"
                        ),
                        range_reader=range_reader,
                    ).run()
                )
            except (OSError, ValueError) as error:
                errors.append(
                    (
                        identity.metadata_physical_offset,
                        identity.metadata_physical_offset + identity.page_size,
                        "logical_wallet_pipeline_error",
                        type(error).__name__,
                    )
                )
        accepted_hits = tuple(
            hit
            for hit in hits
            if any(
                context.start_offset
                <= hit.start_offset
                <= hit.end_offset
                <= context.end_offset
                for context in contexts
            )
        )
        metadata_less = MetadataLessBerkeleyFragmentRecoveryPipeline(
            accepted_hits,
            source=str(reader.path.resolve()),
            range_start=start,
            range_end=range_end,
            range_reader=range_reader,
        ).run()
        orphan_record_keys = OrphanBitcoinRecordKeyDiagnosticPipeline(
            accepted_hits,
            source=str(reader.path.resolve()),
            range_start=start,
            range_end=range_end,
            range_reader=range_reader,
        ).run()
        orphan_private_keys = OrphanHistoricalECPrivateKeyRecoveryPipeline(
            accepted_hits,
            source=str(reader.path.resolve()),
            range_start=start,
            range_end=range_end,
            range_reader=range_reader,
        ).run()
        orphan_private_key_fragments = (
            OrphanHistoricalECPrivateKeyFragmentRecoveryPipeline(
                accepted_hits,
                source=str(reader.path.resolve()),
                range_start=start,
                range_end=range_end,
                range_reader=range_reader,
            ).run()
        )
        ordered_direct = tuple(item[2] for item in sorted(direct_with_ranges))
        all_statuses = tuple(result.status for result in ordered_direct) + tuple(
            result.status for result in wallet_results
        )
        all_statuses += (metadata_less.status,)
        structural_count = sum(
            status is ValidationStatus.STRUCTURAL for status in all_statuses
        )
        fragment_count = sum(
            status is ValidationStatus.FRAGMENT for status in all_statuses
        )
        if structural_count:
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif fragment_count:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_bitcoin_wallet_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = ("no_confirmed_bitcoin_wallet_evidence",)

        return FullImageRecoveryResult(
            source=str(reader.path.resolve()),
            start_offset=start,
            end_offset=range_end,
            status=status,
            raw_hit_count=sum(raw_hit_counts.values()),
            hotspot_count=len(hotspots),
            accepted_hotspot_count=len(accepted),
            direct_results=ordered_direct,
            reconstructed_databases=databases,
            reconstructed_wallet_results=wallet_results,
            logical_wallet_results=tuple(logical_wallet_results),
            metadata_less_fragment_recovery=metadata_less,
            orphan_record_key_diagnostic=orphan_record_keys,
            orphan_private_key_recovery=orphan_private_keys,
            orphan_private_key_fragment_recovery=(
                orphan_private_key_fragments
            ),
            ntfs_bitcoin_artifact_index=ntfs_bitcoin_artifact_index,
            ntfs_stale_file_record_recovery=(
                ntfs_stale_file_record_recovery
            ),
            ntfs_directory_index_artifact_recovery=(
                ntfs_directory_index_artifact_recovery
            ),
            ntfs_stale_indx_recovery=ntfs_stale_indx_recovery,
            ntfs_detached_volume_discovery=ntfs_detached_volume_discovery,
            ntfs_detached_metadata_recovery=ntfs_detached_metadata_recovery,
            ntfs_historical_wallet_recovery=ntfs_historical_wallet_recovery,
            electrum_raw_recovery=electrum_raw_recovery,
            structural_wallet_count=structural_count,
            fragment_wallet_count=fragment_count,
            reasons=reasons,
            evidence={
                "hotspot_ranges": tuple(
                    (item.start_offset, item.end_offset) for item in hotspots
                ),
                "hotspot_decisions": tuple(
                    (
                        hotspot.start_offset,
                        hotspot.end_offset,
                        decision.accepted,
                        decision.reasons,
                    )
                    for hotspot, decision in decisions
                ),
                "read_hotspot_ranges": tuple(
                    (context.start_offset, context.end_offset) for context in contexts
                ),
                "direct_result_ranges": tuple(
                    (start_offset, end_offset)
                    for start_offset, end_offset, _ in sorted(direct_with_ranges)
                ),
                "physical_metadata_candidates": tuple(
                    (
                        item.physical_offset,
                        item.metadata_page_number,
                        item.page_size,
                        item.byte_order,
                        item.root_page,
                        item.validation.status.value,
                    )
                    for item in metadata
                ),
                "physical_page_candidates": tuple(
                    (
                        item.physical_offset,
                        item.page_number,
                        item.page_size,
                        item.byte_order,
                        item.validation.status.value,
                    )
                    for item in pages
                ),
                "errors": tuple(errors),
                "raw_hit_counts_by_signature": tuple(
                    sorted(raw_hit_counts.items())
                ),
            },
        )

    def _range_hotspots(
        self,
        hits: tuple[RawHit, ...],
        start: int,
        end: int,
    ) -> tuple[Hotspot, ...]:
        relative_hits = tuple(
            RawHit(
                start_offset=hit.start_offset - start,
                end_offset=hit.end_offset - start,
                hit_type=hit.hit_type,
                confidence=hit.confidence,
                source=hit.source,
                evidence=hit.evidence,
            )
            for hit in hits
        )
        relative_hotspots = self._hotspot_builder.build(relative_hits, end - start)
        return tuple(
            Hotspot(
                start_offset=item.start_offset + start,
                end_offset=item.end_offset + start,
                score=item.score,
                source=item.source,
                evidence={
                    **item.evidence,
                    "hit_offsets": tuple(
                        offset + start for offset in item.evidence["hit_offsets"]
                    ),
                },
            )
            for item in relative_hotspots
        )

    @staticmethod
    def _metadata_candidates(
        contexts: Iterable[ValidationContext],
    ) -> tuple[PhysicalBerkeleyMetadataCandidate, ...]:
        validator = BerkeleyMetadataValidator()
        candidates: dict[
            tuple[str, int, int, str], PhysicalBerkeleyMetadataCandidate
        ] = {}
        patterns = (
            BTREE_MAGIC.to_bytes(4, "little"),
            BTREE_MAGIC.to_bytes(4, "big"),
        )
        for context in contexts:
            local_starts: set[int] = set()
            for pattern in patterns:
                position = context.data.find(pattern)
                while position != -1:
                    if position >= MAGIC_OFFSET:
                        local_starts.add(position - MAGIC_OFFSET)
                    position = context.data.find(pattern, position + 1)
            for local_start in sorted(local_starts):
                absolute = context.start_offset + local_start
                data = context.data[local_start : local_start + MAX_PAGE_SIZE]
                validation = validator.validate(
                    ValidationContext(context.source, absolute, data)
                )
                if validation.start_offset != absolute or validation.status is ValidationStatus.REJECTED:
                    continue
                evidence = validation.evidence
                required = ("page_number", "page_size", "byte_order", "root_page")
                if any(evidence.get(name) is None for name in required):
                    continue
                candidate = PhysicalBerkeleyMetadataCandidate(
                    source=context.source,
                    physical_offset=absolute,
                    metadata_page_number=evidence["page_number"],
                    page_size=evidence["page_size"],
                    byte_order=evidence["byte_order"],
                    root_page=evidence["root_page"],
                    validation=validation,
                )
                identity = (
                    candidate.source,
                    candidate.physical_offset,
                    candidate.page_size,
                    candidate.byte_order,
                )
                existing = candidates.get(identity)
                candidates[identity] = FullImageRecoveryCoordinator._stronger_candidate(
                    existing, candidate, "metadata"
                )
        return tuple(candidates[identity] for identity in sorted(candidates))

    @staticmethod
    def _page_candidates(
        contexts: Iterable[ValidationContext],
        metadata: Iterable[PhysicalBerkeleyMetadataCandidate],
    ) -> tuple[PhysicalBerkeleyPageCandidate, ...]:
        context_tuple = tuple(contexts)
        grids = tuple(
            sorted(
                {
                    (
                        item.page_size,
                        item.byte_order,
                        item.physical_offset % item.page_size,
                    )
                    for item in metadata
                    if item.validation.status is ValidationStatus.STRUCTURAL
                }
            )
        )
        candidates: dict[
            tuple[str, int, int, str], PhysicalBerkeleyPageCandidate
        ] = {}
        for context in context_tuple:
            for page_size, byte_order, residue in grids:
                offset = context.start_offset + (
                    (residue - context.start_offset) % page_size
                )
                validator = BerkeleyPageValidator(page_size, byte_order)
                while offset < context.end_offset:
                    local = offset - context.start_offset
                    data = context.data[local : local + page_size]
                    if len(data) >= PAGE_HEADER_SIZE:
                        validation = validator.validate(
                            ValidationContext(context.source, offset, data)
                        )
                        if validation.status is not ValidationStatus.REJECTED:
                            candidate = PhysicalBerkeleyPageCandidate(
                                source=context.source,
                                physical_offset=offset,
                                page_size=page_size,
                                byte_order=byte_order,
                                validation=validation,
                            )
                            identity = (
                                candidate.source,
                                candidate.physical_offset,
                                candidate.page_size,
                                candidate.byte_order,
                            )
                            existing = candidates.get(identity)
                            candidates[identity] = FullImageRecoveryCoordinator._stronger_candidate(
                                existing, candidate, "page"
                            )
                    offset += page_size
        return tuple(candidates[identity] for identity in sorted(candidates))

    @staticmethod
    def _stronger_candidate(existing, candidate, kind: str):
        if existing is None or existing == candidate:
            return candidate
        priority = {
            ValidationStatus.STRUCTURAL: 2,
            ValidationStatus.FRAGMENT: 1,
            ValidationStatus.REJECTED: 0,
        }
        existing_priority = priority[existing.validation.status]
        candidate_priority = priority[candidate.validation.status]
        if existing_priority != candidate_priority:
            return candidate if candidate_priority > existing_priority else existing
        existing_end = existing.validation.end_offset
        candidate_end = candidate.validation.end_offset
        if existing_end != candidate_end:
            return candidate if candidate_end > existing_end else existing
        raise ValueError(f"conflicting {kind} candidate at physical offset")
