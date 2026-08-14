"""Failure-isolated orchestration for NTFS wallet history discovery."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSStaleRecoveryContext
from bfrs.recovery.ntfs_system_files import NtfsSystemFileResolver
from bfrs.recovery.ntfs_wallet_history import HistoricalWalletArtifact, NtfsWalletHistoryAnalyzer
from bfrs.recovery.usn_journal import UsnJournalReader


@dataclass(frozen=True, slots=True)
class NtfsHistoricalVolumeResult:
    volume_start: int | None
    volume_end: int | None
    bytes_per_sector: int | None
    sectors_per_cluster: int | None
    cluster_size: int | None
    mft_lcn: int | None
    mft_physical_start: int | None
    mft_record_size: int | None
    provenance: str
    selected_usn_mft_record: int | None
    usn_j_extension_records: tuple[int, ...]
    usn_journal_found: bool
    usn_j_stream_found: bool
    physical_bytes_examined: int
    valid_usn_records: int
    failures: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NtfsHistoricalWalletRecovery:
    enabled: bool
    volumes_examined: int
    detached_volumes_examined: int
    primary_contexts: int
    detached_contexts: int
    total_unique_contexts: int
    usn_journals_found: int
    usn_j_streams_found: int
    usn_physical_bytes_examined: int
    valid_usn_records: int
    historical_wallet_artifacts: tuple[HistoricalWalletArtifact, ...]
    active_current_count: int
    historical_count: int
    deleted_count: int
    unknown_reference_count: int
    failures: tuple[str, ...]
    volumes: tuple[NtfsHistoricalVolumeResult, ...]


class NtfsHistoricalWalletRecoveryPipeline:
    def run(self, contexts: NTFSStaleRecoveryContext | Iterable[NTFSStaleRecoveryContext] | None
            ) -> NtfsHistoricalWalletRecovery:
        if contexts is None:
            collected = ()
        elif isinstance(contexts, NTFSStaleRecoveryContext) or hasattr(contexts, "boot"):
            collected = (contexts,)
        else:
            collected = tuple(contexts)
        unique = self._deduplicate(collected)
        if not unique:
            return NtfsHistoricalWalletRecovery(
                True, 0, 0, 0, 0, 0, 0, 0, 0, 0, (), 0, 0, 0, 0,
                ("ntfs_volume_not_available",), (),
            )

        all_artifacts: list[HistoricalWalletArtifact] = []
        volume_results: list[NtfsHistoricalVolumeResult] = []
        failures: list[str] = []
        for context in unique:
            artifacts, result = self._run_volume(context)
            all_artifacts.extend(artifacts)
            volume_results.append(result)
            failures.extend(
                f"volume:{result.volume_start}:{item}" for item in result.failures
            )
        artifacts = tuple(sorted(
            all_artifacts,
            key=lambda item: (item.volume_start, item.family,
                              item.name.casefold(), item.file_reference),
        ))
        counts = {state: sum(a.state == state for a in artifacts) for state in
                  ("ACTIVE_CURRENT", "HISTORICAL", "DELETED", "UNKNOWN_REFERENCE")}
        detached_count = sum(
            item.provenance.startswith("detached") for item in volume_results
        )
        return NtfsHistoricalWalletRecovery(
            True, len(volume_results), detached_count,
            len(volume_results) - detached_count, detached_count,
            len(volume_results),
            sum(item.usn_journal_found for item in volume_results),
            sum(item.usn_j_stream_found for item in volume_results),
            sum(item.physical_bytes_examined for item in volume_results),
            sum(item.valid_usn_records for item in volume_results), artifacts,
            counts["ACTIVE_CURRENT"], counts["HISTORICAL"], counts["DELETED"],
            counts["UNKNOWN_REFERENCE"], tuple(dict.fromkeys(failures)),
            tuple(volume_results),
        )

    def _run_volume(self, context):
        failures: list[str] = list(getattr(context, "initialization_failures", ()))
        records = ()
        byte_count = 0
        journal_found = stream_found = False
        selected_usn = None
        extension_records: tuple[int, ...] = ()
        try:
            resolver = NtfsSystemFileResolver(context)
            system = resolver.resolve()
            journal_found = system.usn_jrnl_record_number is not None
            stream_found = system.usn_j is not None
            selected_usn = system.usn_jrnl_record_number
            extension_records = (() if system.usn_j is None
                                 else getattr(system.usn_j, "extension_records", ()))
            failures.extend(system.failures)
            if system.usn_j is not None:
                def counted_chunks():
                    nonlocal byte_count
                    for chunk in resolver.iter_stream_chunks(system.usn_j):
                        byte_count += len(chunk.data)
                        yield chunk
                parsed = UsnJournalReader().parse_stream(
                    counted_chunks(), source_image=context.source,
                )
                records = parsed.records
                failures.extend(parsed.failures)
            failures.extend(item for item in resolver.failures if item not in failures)
        except (OSError, ValueError) as exc:
            failures.append(f"ntfs_volume_failure:{type(exc).__name__}:{exc}")
        try:
            artifacts = NtfsWalletHistoryAnalyzer().analyze(tuple(records), context)
        except (ValueError, OSError) as exc:
            failures.append(f"wallet_history_analysis_failure:{type(exc).__name__}:{exc}")
            artifacts = ()
        boot = getattr(context, "boot", None)
        start = getattr(boot, "volume_offset", None)
        mft_lcn = getattr(boot, "mft_lcn", None)
        cluster = getattr(boot, "cluster_size", None)
        result = NtfsHistoricalVolumeResult(
            start, getattr(boot, "volume_end", None),
            getattr(boot, "bytes_per_sector", None),
            getattr(boot, "sectors_per_cluster", None), cluster, mft_lcn,
            None if start is None or mft_lcn is None or cluster is None
            else start + mft_lcn * cluster,
            getattr(boot, "record_size", None),
            getattr(context, "provenance", "unknown"), selected_usn,
            extension_records, journal_found,
            stream_found, byte_count, len(records), tuple(dict.fromkeys(failures)),
        )
        return tuple(artifacts), result

    @staticmethod
    def _deduplicate(contexts):
        output, seen = [], set()
        for context in contexts:
            try:
                boot = context.boot
                extent_key = tuple((e.logical_start, e.physical_start, e.length)
                                   for e in context.mft_extents)
                key = (context.source, boot.volume_offset, boot.volume_end,
                       boot.bytes_per_sector, boot.cluster_size, boot.mft_lcn,
                       boot.record_size, extent_key)
            except (AttributeError, TypeError):
                key = ("invalid_context", id(context))
            if key not in seen:
                seen.add(key)
                output.append(context)
        return tuple(output)
