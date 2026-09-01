"""Coordinate conservative Bitcoin wallet recovery over an image range."""

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
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
from bfrs.recovery.mnemonic.mnemonic_correlation import (
    CONTEXT_REVIEW,
    INDEPENDENT_CANDIDATE,
    LIKELY_WORDLIST_FALSE_POSITIVE,
    CorrelationOccurrence,
    correlate_mnemonic_occurrences,
    correlation_statistics,
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
from bfrs.scanners.fast_scanner import (
    ChunkDetector,
    FastScanner,
    ScanProgress,
    Signature,
)
from bfrs.scanners.bitcoin_context import (
    BITCOIN_CONTEXT_ARTIFACT_KINDS,
    scan_bitcoin_context_for_sec_pubkeys,
)
from bfrs.scanners.target_registry import TARGET_ARMORY, TARGET_MULTIBIT
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
from bfrs.validators.bitcoin_record_key import (
    BITCOIN_RECORD_KEY_SIDE_VALID,
    MAX_RAW_KEY_SIDE_BYTES,
    RAW_KEY_SIDE_RECORD_TYPES,
    RawBitcoinRecordKeySideValidator,
)


_RAW_KEY_SIDE_HIT_TYPES = {
    f"bitcoin_{record_type}": record_type
    for record_type in RAW_KEY_SIDE_RECORD_TYPES
}


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
    target_findings: tuple[RawHit, ...] = ()


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
        chunk_detectors: Iterable[ChunkDetector] = (),
        cluster_gap: int = DEFAULT_CLUSTER_GAP,
        hotspot_padding: int = DEFAULT_PADDING,
    ) -> None:
        collected = tuple(signatures)
        self._scanner = FastScanner(collected, chunk_detectors=chunk_detectors)
        self._mnemonic_standards = frozenset(
            standard
            for detector in chunk_detectors
            for standard in getattr(detector, "standards", ())
        )
        if not isinstance(candidate_policy, CandidatePolicy):
            raise ValueError("candidate_policy must be CandidatePolicy")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        required_overlap = self._scanner.required_overlap
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
        *,
        electrum_only: bool = False,
        targets: frozenset[str] | None = None,
        progress: Callable[[ScanProgress], None] | None = None,
        electrum_progress: Callable[[int, int, float], None] | None = None,
        resume_results: Mapping[tuple[int, int], tuple[RawHit, ...]] | None = None,
        unit_complete: Callable[[tuple[int, int], tuple[RawHit, ...], int, int], None]
        | None = None,
    ) -> FullImageRecoveryResult:
        reader = ChunkReader(path, chunk_size=self._chunk_size, overlap=self._overlap)
        range_end = reader.file_size if end is None else end
        ntfs_locator = NTFSBitcoinArtifactLocator()
        ntfs_bitcoin_artifact_index = ntfs_locator.index(reader.path)
        if electrum_only:
            return self._scan_electrum_only(
                reader, start, range_end, ntfs_locator,
                ntfs_bitcoin_artifact_index, progress,
                electrum_progress, resume_results, unit_complete,
            )
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
        target_findings: list[RawHit] = []
        detached_file_offsets: list[int] = []
        detached_indx_offsets: list[int] = []
        raw_hit_counts: Counter[str] = Counter()
        try:
            for hit in self._scanner.scan(
                    reader, start=start, end=range_end, progress=progress,
                    resume_results=resume_results, unit_complete=unit_complete):
                raw_hit_counts[hit.hit_type] += 1
                if (hit.target != "unknown" and
                        hit.artifact_kind not in {
                            "filesystem_anchor", "filesystem_record",
                            "filesystem_index"}):
                    target_findings.append(hit)
                if (hit.target in {TARGET_MULTIBIT, TARGET_ARMORY} or
                        hit.artifact_kind == "mnemonic" or
                        hit.artifact_kind in BITCOIN_CONTEXT_ARTIFACT_KINDS):
                    continue
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
        ).run_hits(
            electrum_hits, range_start=start, range_end=range_end,
            progress=electrum_progress,
        )
        key_side_reads = tuple(
            hit for hit in recovery_hits if hit.hit_type in _RAW_KEY_SIDE_HIT_TYPES)
        hits, binary_context_findings = self._assess_raw_key_side_hits(
            reader.path, tuple(recovery_hits), range_end
        )
        assessed_by_identity = {
            (hit.start_offset, hit.end_offset, hit.hit_type): hit
            for hit in hits
        }
        target_findings = [
            assessed_by_identity.get(
                (hit.start_offset, hit.end_offset, hit.hit_type), hit
            )
            for hit in target_findings
        ]
        target_findings.extend(binary_context_findings)
        admission_hits = tuple(
            hit
            for hit in hits
            if hit.hit_type not in _RAW_KEY_SIDE_HIT_TYPES
            or hit.validation_status == BITCOIN_RECORD_KEY_SIDE_VALID
        )
        hotspots = self._range_hotspots(admission_hits, start, range_end)

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
            for hit in admission_hits
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
        target_structural_count = sum(
            item.structural_status == "STRONG" for item in target_findings)
        target_fragment_count = sum(
            item.structural_status in {"FRAGMENT", "COMPLETE"}
            for item in target_findings)
        electrum_structural_count = sum(
            item.structural_status == "STRONG"
            for item in electrum_raw_recovery.candidates
        )
        electrum_fragment_count = sum(
            item.structural_status == "FRAGMENT"
            for item in electrum_raw_recovery.candidates
        )
        structural_count = sum(
            status is ValidationStatus.STRUCTURAL for status in all_statuses
        )
        fragment_count = sum(
            status is ValidationStatus.FRAGMENT for status in all_statuses
        )
        structural_count += target_structural_count + electrum_structural_count
        fragment_count += target_fragment_count + electrum_fragment_count
        if structural_count:
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif fragment_count:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_bitcoin_wallet_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = ("no_confirmed_bitcoin_wallet_evidence",)

        secondary_key_bytes = sum(
            min(MAX_RAW_KEY_SIDE_BYTES, range_end - hit.start_offset)
            for hit in key_side_reads)
        secondary_hotspot_bytes = sum(
            hotspot.end_offset - hotspot.start_offset for hotspot in accepted)
        ntfs_record_bytes = (
            ntfs_bitcoin_artifact_index.mft_records_scanned *
            (ntfs_bitcoin_artifact_index.mft_record_size or 0))
        secondary_read_count = (
            len(key_side_reads) + len(accepted) +
            ntfs_bitcoin_artifact_index.mft_records_scanned)
        target_findings_tuple = self._correlate_mnemonic_findings(
            tuple(target_findings))
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
            target_findings=target_findings_tuple,
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
                "selected_targets": tuple(sorted(targets or ())),
                "mnemonic_coverage": {
                    "performed": bool(self._mnemonic_standards),
                    "standards": tuple(sorted(self._mnemonic_standards)),
                },
                "mnemonic_recovery": self._mnemonic_summary(target_findings_tuple),
                "io_metrics": {
                    "full_image_linear_pass_count": 1 if range_end > start else 0,
                    "linear_pass_count": 1 if range_end > start else 0,
                    "linear_bytes_read": range_end - start,
                    "physical_linear_bytes_read": reader.linear_bytes_read,
                    "linear_read_count": reader.linear_read_count,
                    "secondary_read_count": secondary_read_count,
                    "secondary_bytes_read": (
                        secondary_key_bytes + secondary_hotspot_bytes + ntfs_record_bytes),
                },
            },
        )

    def _scan_electrum_only(
        self,
        reader: ChunkReader,
        start: int,
        range_end: int,
        ntfs_locator: NTFSBitcoinArtifactLocator,
        ntfs_index: NTFSBitcoinArtifactIndex,
        progress: Callable[[ScanProgress], None] | None,
        electrum_progress: Callable[[int, int, float], None] | None,
        resume_results: Mapping[tuple[int, int], tuple[RawHit, ...]] | None,
        unit_complete: Callable[[tuple[int, int], tuple[RawHit, ...], int, int], None]
        | None,
    ) -> FullImageRecoveryResult:
        """Run only raw Electrum validation and required NTFS correlation."""
        detached_pipeline = NTFSDetachedVolumeDiscoveryPipeline(
            source=reader.path,
            current_context=ntfs_locator.stale_recovery_context,
            locator=ntfs_locator,
        )
        electrum_hits: list[RawHit] = []
        raw_hit_counts: Counter[str] = Counter()
        for hit in self._scanner.scan(
                reader, start=start, end=range_end, progress=progress,
                resume_results=resume_results, unit_complete=unit_complete):
            raw_hit_counts[hit.hit_type] += 1
            if hit.hit_type == NTFS_BOOT_SECTOR_SIGNATURE:
                detached_pipeline.process_hit(hit)
            elif hit.hit_type in ELECTRUM_SIGNATURE_NAMES:
                electrum_hits.append(hit)
        discovery = detached_pipeline.finish()
        detached_contexts = NTFSDetachedMetadataRecoveryPipeline(
            source=reader.path,
            discovery=discovery,
            locator=ntfs_locator,
            range_start=start,
            range_end=range_end,
        ).build_confirmed_volume_contexts()
        contexts = tuple(
            context for context in (
                ntfs_locator.stale_recovery_context,
                *detached_contexts.contexts,
            ) if context is not None
        )
        electrum = ElectrumRawRecoveryPipeline(
            source=reader.path,
            known_artifacts=known_electrum_artifacts_from_contexts(contexts),
        ).run_hits(
            electrum_hits, range_start=start, range_end=range_end,
            progress=electrum_progress,
        )
        if detached_contexts.failures:
            electrum = replace(
                electrum,
                failures=tuple(dict.fromkeys((
                    *electrum.failures,
                    *detached_contexts.failures,
                ))),
            )
        if electrum.complete_candidates:
            status = ValidationStatus.STRUCTURAL
            reasons: tuple[str, ...] = ()
        elif electrum.fragment_candidates:
            status = ValidationStatus.FRAGMENT
            reasons = ("partial_electrum_wallet_evidence",)
        else:
            status = ValidationStatus.REJECTED
            reasons = ("no_confirmed_electrum_wallet_evidence",)
        source = str(reader.path.resolve())
        empty = self._empty_bitcoin_results(source)
        return FullImageRecoveryResult(
            source=source,
            start_offset=start,
            end_offset=range_end,
            status=status,
            raw_hit_count=sum(raw_hit_counts.values()),
            hotspot_count=0,
            accepted_hotspot_count=0,
            direct_results=(),
            reconstructed_databases=(),
            reconstructed_wallet_results=(),
            logical_wallet_results=(),
            metadata_less_fragment_recovery=empty[0],
            orphan_record_key_diagnostic=empty[1],
            orphan_private_key_recovery=empty[2],
            orphan_private_key_fragment_recovery=empty[3],
            structural_wallet_count=electrum.complete_candidates,
            fragment_wallet_count=electrum.fragment_candidates,
            reasons=reasons,
            evidence={
                "hotspot_ranges": (),
                "hotspot_decisions": (),
                "read_hotspot_ranges": (),
                "direct_result_ranges": (),
                "physical_metadata_candidates": (),
                "physical_page_candidates": (),
                "errors": (),
                "raw_hit_counts_by_signature": tuple(
                    sorted(raw_hit_counts.items())
                ),
                "mnemonic_coverage": {
                    "performed": bool(self._mnemonic_standards),
                    "standards": tuple(sorted(self._mnemonic_standards)),
                },
                "mnemonic_recovery": self._mnemonic_summary(()),
                "io_metrics": {
                    "full_image_linear_pass_count": 1 if range_end > start else 0,
                    "linear_pass_count": 1 if range_end > start else 0,
                    "linear_bytes_read": range_end - start,
                    "physical_linear_bytes_read": reader.linear_bytes_read,
                    "linear_read_count": reader.linear_read_count,
                    "secondary_read_count": ntfs_index.mft_records_scanned,
                    "secondary_bytes_read": (
                        ntfs_index.mft_records_scanned *
                        (ntfs_index.mft_record_size or 0)),
                },
            },
            ntfs_bitcoin_artifact_index=ntfs_index,
            ntfs_detached_volume_discovery=discovery,
            electrum_raw_recovery=electrum,
        )

    @staticmethod
    def _correlate_mnemonic_findings(
        findings: tuple[RawHit, ...],
    ) -> tuple[RawHit, ...]:
        positions = [index for index, item in enumerate(findings)
                     if item.artifact_kind == "mnemonic"]
        mnemonic_items = [findings[index] for index in positions]
        inputs = tuple(CorrelationOccurrence(
            item.start_offset,
            item.end_offset,
            item.safe_fingerprint or "",
            str(item.safe_metadata.get("mnemonic_standard", "UNKNOWN")),
            int(item.safe_metadata.get("word_count", 0)),
            item.safe_metadata.get("language"),
            item.safe_metadata.get("encoding"),
        ) for item in mnemonic_items)
        annotations = correlate_mnemonic_occurrences(inputs)
        correlated = list(findings)
        actions = {
            INDEPENDENT_CANDIDATE: "MNEMONIC_CONTEXT_REVIEW",
            CONTEXT_REVIEW: "MNEMONIC_OVERLAP_CONTEXT_REVIEW",
            LIKELY_WORDLIST_FALSE_POSITIVE: "MNEMONIC_WORDLIST_FALSE_POSITIVE_REVIEW",
        }
        for position, item, annotation in zip(positions, mnemonic_items, annotations):
            correlated[position] = replace(
                item,
                reason_codes=tuple(dict.fromkeys(
                    item.reason_codes + annotation.reason_codes)),
                safe_metadata={
                    **item.safe_metadata,
                    **annotation.safe_metadata(),
                },
                recommended_recovery_action=actions[annotation.recovery_relevance],
            )
        return tuple(correlated)

    @staticmethod
    def _mnemonic_summary(findings: tuple[RawHit, ...]) -> dict[str, object]:
        findings = FullImageRecoveryCoordinator._correlate_mnemonic_findings(findings)
        candidates = tuple(item for item in findings
                           if item.artifact_kind == "mnemonic")
        inputs = tuple(CorrelationOccurrence(
            item.start_offset,
            item.end_offset,
            item.safe_fingerprint or "",
            str(item.safe_metadata.get("mnemonic_standard", "UNKNOWN")),
            int(item.safe_metadata.get("word_count", 0)),
            item.safe_metadata.get("language"),
            item.safe_metadata.get("encoding"),
        ) for item in candidates)
        annotations = correlate_mnemonic_occurrences(inputs)
        fingerprints = {item.safe_fingerprint for item in candidates
                        if item.safe_fingerprint is not None}
        count = lambda standard: sum(
            item.safe_metadata.get("mnemonic_standard") == standard
            for item in candidates)
        return {
            "candidates_total": len(candidates),
            "unique_secret_fingerprints": len(fingerprints),
            "bip39_valid": count("BIP39"),
            "electrum_2_plus_valid": count("ELECTRUM"),
            "electrum_v1_valid": count("ELECTRUM_V1"),
            "electrum_valid": count("ELECTRUM") + count("ELECTRUM_V1"),
            **correlation_statistics(inputs, annotations),
            "candidates": tuple(item.safe_dict() for item in candidates),
        }

    @staticmethod
    def _empty_bitcoin_results(source: str):
        reason = ("disabled_in_electrum_only_mode",)
        metadata_less = MetadataLessBerkeleyFragmentRecovery(
            status=ValidationStatus.REJECTED,
            source=source,
            candidate_page_count=0,
            structural_leaf_count=0,
            fragment_leaf_count=0,
            record_pair_count=0,
            valid_plaintext_key_count=0,
            valid_ckey_count=0,
            valid_mkey_count=0,
            recognized_wkey_count=0,
            recognized_defaultkey_count=0,
            recognized_keymeta_count=0,
            page_locations=(),
            record_locations=(),
            reasons=reason,
            evidence={},
        )
        record_keys = OrphanBitcoinRecordKeyDiagnostic(
            source=source,
            raw_strong_hit_count=0,
            valid_record_key_count=0,
            valid_key_count=0,
            valid_wkey_count=0,
            valid_ckey_keyside_count=0,
            valid_mkey_keyside_count=0,
            valid_defaultkey_count=0,
            valid_keymeta_count=0,
            canonical_framing_count=0,
            noncanonical_framing_count=0,
            locations=(),
            evidence={},
        )
        private_keys = OrphanHistoricalECPrivateKeyRecovery(
            source=source,
            raw_der_anchor_count=0,
            candidate_der_count=0,
            valid_secp256k1_der_count=0,
            canonical_der_count=0,
            valid_with_embedded_pubkey_count=0,
            valid_without_embedded_pubkey_count=0,
            locations=(),
            reasons=reason,
            evidence={},
        )
        fragments = OrphanHistoricalECPrivateKeyFragmentRecovery(
            source=source,
            raw_inner_anchor_count=0,
            candidate_inner_fragment_count=0,
            valid_inner_fragment_count=0,
            locations=(),
            reasons=reason,
            evidence={},
        )
        return metadata_less, record_keys, private_keys, fragments

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
    def _assess_raw_key_side_hits(
        path: Path,
        hits: tuple[RawHit, ...],
        range_end: int,
    ) -> tuple[tuple[RawHit, ...], tuple[RawHit, ...]]:
        validator = RawBitcoinRecordKeySideValidator()
        assessed: list[RawHit] = []
        context_findings: list[RawHit] = []
        with path.open("rb") as source:
            for hit in hits:
                record_type = _RAW_KEY_SIDE_HIT_TYPES.get(hit.hit_type)
                if record_type is None:
                    assessed.append(hit)
                    continue
                source.seek(hit.start_offset)
                data = source.read(
                    min(MAX_RAW_KEY_SIDE_BYTES, range_end - hit.start_offset)
                )
                validation = validator.validate(
                    data,
                    expected_record_type=record_type,
                )
                if validation.valid:
                    public_key_offset = validation.evidence.get(
                        "public_key_offset"
                    )
                    public_key_length = validation.evidence.get("pubkey_length")
                    if not isinstance(public_key_offset, int) or not isinstance(
                        public_key_length, int
                    ):
                        raise RuntimeError(
                            "key-side validator omitted public key location"
                        )
                    context_findings.extend(
                        scan_bitcoin_context_for_sec_pubkeys(
                            data[
                                public_key_offset:
                                public_key_offset + public_key_length
                            ],
                            hit.start_offset + public_key_offset,
                            source=hit.source,
                        )
                    )
                assessed.append(
                    replace(
                        hit,
                        structural_status=(
                            "ANCHOR_ONLY" if validation.valid else "REJECTED"
                        ),
                        validation_status=(
                            BITCOIN_RECORD_KEY_SIDE_VALID
                            if validation.valid
                            else "BITCOIN_RECORD_KEY_SIDE_REJECTED"
                        ),
                        reason_codes=validation.reason_codes,
                        correlated_evidence=(
                            ("CANONICAL_COMPACTSIZE", "SECP256K1_POINT")
                            if validation.valid
                            else ()
                        ),
                        safe_metadata={
                            **hit.safe_metadata,
                            "record_type": validation.record_type,
                            **validation.evidence,
                        },
                    )
                )
        unique_context_findings = {
            (
                finding.start_offset,
                finding.end_offset,
                finding.safe_fingerprint,
            ): finding
            for finding in context_findings
        }
        return tuple(assessed), tuple(
            unique_context_findings[identity]
            for identity in sorted(unique_context_findings)
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
