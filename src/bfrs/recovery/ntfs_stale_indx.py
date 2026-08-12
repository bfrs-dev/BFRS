"""Streaming recovery of structural stale NTFS INDX blocks from raw anchors."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import BinaryIO

from bfrs.core.models import RawHit
from bfrs.recovery.ntfs_bitcoin_artifacts import (
    NTFSBitcoinArtifactLocator,
    NTFSStaleRecoveryContext,
    _Record,
)
from bfrs.recovery.ntfs_directory_index import (
    NTFSDirectoryIndexArtifactRecovery,
    NTFSDirectoryIndexArtifactRecoveryPipeline,
    _IndexEntry,
)
from bfrs.recovery.ntfs_mft_data import NtfsMftRecordError


NTFS_INDX_RECORD_SIGNATURE = "ntfs_indx_record_anchor"
NTFS_INDX_RECORD_PATTERN = b"INDX"
STALE_INDX_VALIDATION_STRENGTH = "structural_stale_ntfs_indx"
DEFAULT_DIAGNOSTIC_SAMPLE_LIMIT = 100


@dataclass(frozen=True, slots=True)
class NTFSStaleINDXBlock:
    physical_offset: int
    index_block_size: int
    embedded_vcn: int
    validation_strength: str
    comparison_to_current: str
    active_entry_count: int
    structural_slack_entry_count: int


@dataclass(frozen=True, slots=True)
class NTFSStaleINDXArtifactCandidate:
    source_block_physical_offset: int
    embedded_vcn: int
    entry_offset: int
    entry_state: str
    file_reference_record: int
    file_reference_sequence: int
    filename: str
    namespace: str
    reference_state: str
    artifact_class: str | None
    validation_strength: str
    source_directory_known: bool = False


@dataclass(frozen=True, slots=True)
class NTFSStaleINDXRecovery:
    source: str
    raw_indx_hit_count: int
    current_indx_excluded_count: int
    candidate_block_count: int
    structural_stale_indx_count: int
    rejected_block_count: int
    active_entry_count: int
    slack_candidate_count: int
    structural_slack_entry_count: int
    wallet_candidate_count: int
    bitcoin_context_candidate_count: int
    rejection_counts: tuple[tuple[str, int], ...]
    blocks: tuple[NTFSStaleINDXBlock, ...]
    candidates: tuple[NTFSStaleINDXArtifactCandidate, ...]
    diagnostic_sample_limit: int
    diagnostics: tuple[str, ...]
    outside_current_volume_before_count: int = 0
    outside_current_volume_after_count: int = 0
    image_end_truncated_count: int = 0
    cli_range_truncated_count: int = 0


class NTFSStaleINDXRecoveryPipeline:
    """Consume INDX anchors one at a time without retaining block bytes."""

    def __init__(
        self,
        *,
        source: str | Path,
        range_start: int,
        range_end: int,
        context: NTFSStaleRecoveryContext | None,
        locator: NTFSBitcoinArtifactLocator,
        current_index: NTFSDirectoryIndexArtifactRecovery | None,
        diagnostic_sample_limit: int = DEFAULT_DIAGNOSTIC_SAMPLE_LIMIT,
    ) -> None:
        self._path = Path(source).resolve()
        self._image_size = self._path.stat().st_size
        self._range_start = range_start
        self._range_end = range_end
        self._context = context
        self._locator = locator
        self._current_index = current_index
        self._block_sizes = (
            () if current_index is None else current_index.index_block_sizes
        )
        self._current_starts = set(
            ()
            if current_index is None
            else current_index.current_indx_physical_starts
        )
        self._current_hashes = set(
            ()
            if current_index is None
            else current_index.current_indx_fixed_sha256
        )
        self._parser = NTFSDirectoryIndexArtifactRecoveryPipeline(
            context=context, locator=locator
        )
        self._sample_limit = diagnostic_sample_limit
        self._source: BinaryIO | None = None
        self._seen_blocks: set[int] = set()
        self._seen_entries: set[tuple[object, ...]] = set()
        self._raw_count = 0
        self._current_excluded = 0
        self._candidate_count = 0
        self._structural_count = 0
        self._rejected_count = 0
        self._active_count = 0
        self._slack_candidate_count = 0
        self._structural_slack_count = 0
        self._wallet_count = 0
        self._context_count = 0
        self._rejections: Counter[str] = Counter()
        self._artifact_entries: list[NTFSStaleINDXArtifactCandidate] = []
        self._sample_entries: list[NTFSStaleINDXArtifactCandidate] = []
        self._sample_blocks: list[NTFSStaleINDXBlock] = []
        self._diagnostics: list[str] = []
        if range_start < 0 or range_end < range_start:
            raise ValueError("invalid stale INDX recovery range")
        if diagnostic_sample_limit < 0:
            raise ValueError("diagnostic_sample_limit must not be negative")

    def process_hit(self, hit: RawHit) -> None:
        if hit.hit_type != NTFS_INDX_RECORD_SIGNATURE:
            raise ValueError("unexpected stale INDX hit type")
        self._raw_count += 1
        offset = hit.start_offset
        if offset in self._seen_blocks:
            return
        self._seen_blocks.add(offset)

        context = self._context
        current = self._current_index
        if context is None or current is None:
            self._candidate_count += 1
            self._reject("ntfs_context_unavailable")
            return
        if offset in self._current_starts:
            self._current_excluded += 1
            return
        self._candidate_count += 1

        block_sizes = self._block_sizes
        if not block_sizes:
            self._reject("index_block_geometry_unavailable")
            return
        safe_sizes = tuple(
            size
            for size in block_sizes
            if (
                offset >= self._range_start
                and offset + size <= self._range_end
                and offset + size <= self._image_size
                and offset >= context.boot.volume_offset
                and offset + size <= context.boot.volume_end
            )
        )
        if not safe_sizes:
            self._reject(self._range_rejection(offset, min(block_sizes), context))
            return

        valid: list[
            tuple[int, bytes, int, list[_IndexEntry], list[_IndexEntry], int]
        ] = []
        errors: list[str] = []
        for block_size in safe_sizes:
            try:
                raw = self._read_at(offset, block_size)
                fixed, vcn = self._parser._validated_indx(
                    raw, None, context
                )
                if (
                    vcn * context.boot.cluster_size
                ) % block_size:
                    raise NtfsMftRecordError("indx_vcn_invalid")
                active, slack, slack_attempts = self._parser._parse_node(
                    fixed,
                    header_offset=24,
                    entry_offset_base=0,
                    source_kind="raw_stale_indx",
                )
            except (OSError, ValueError, NtfsMftRecordError) as error:
                errors.append(str(error))
                continue
            valid.append(
                (block_size, fixed, vcn, active, slack, slack_attempts)
            )
        if not valid:
            self._reject(errors[0] if errors else "indx_validation_failed")
            return
        if len(valid) != 1:
            self._reject("ambiguous_index_block_geometry")
            return

        block_size, fixed, vcn, active, slack, slack_attempts = valid[0]
        comparison = (
            "content_matches_current_indx"
            if hashlib.sha256(fixed).hexdigest()
            in self._current_hashes
            else "content_differs_current_indx"
        )
        self._structural_count += 1
        self._active_count += len(active)
        self._slack_candidate_count += slack_attempts
        self._structural_slack_count += len(slack)
        block = NTFSStaleINDXBlock(
            physical_offset=offset,
            index_block_size=block_size,
            embedded_vcn=vcn,
            validation_strength=STALE_INDX_VALIDATION_STRENGTH,
            comparison_to_current=comparison,
            active_entry_count=len(active),
            structural_slack_entry_count=len(slack),
        )
        if len(self._sample_blocks) < self._sample_limit:
            self._sample_blocks.append(block)
        for entry in active + slack:
            self._collect_entry(offset, vcn, entry, context)

    def finish(self) -> NTFSStaleINDXRecovery:
        self.close()
        blocks = tuple(
            sorted(self._sample_blocks, key=lambda item: item.physical_offset)
        )
        candidates = tuple(
            sorted(
                self._artifact_entries + self._sample_entries,
                key=lambda item: (
                    item.source_block_physical_offset,
                    item.entry_offset,
                    item.entry_state,
                    item.filename.casefold(),
                ),
            )
        )
        diagnostics = list(self._diagnostics)
        if self._context is None:
            diagnostics.append("ntfs_stale_recovery_context_unavailable")
        return NTFSStaleINDXRecovery(
            source=str(self._path),
            raw_indx_hit_count=self._raw_count,
            current_indx_excluded_count=self._current_excluded,
            candidate_block_count=self._candidate_count,
            structural_stale_indx_count=self._structural_count,
            rejected_block_count=self._rejected_count,
            active_entry_count=self._active_count,
            slack_candidate_count=self._slack_candidate_count,
            structural_slack_entry_count=self._structural_slack_count,
            wallet_candidate_count=self._wallet_count,
            bitcoin_context_candidate_count=self._context_count,
            rejection_counts=tuple(sorted(self._rejections.items())),
            blocks=blocks,
            candidates=candidates,
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
        return "candidate_outside_safe_range"

    def close(self) -> None:
        if self._source is not None:
            self._source.close()
            self._source = None

    def _collect_entry(
        self,
        block_offset: int,
        vcn: int,
        entry: _IndexEntry,
        context: NTFSStaleRecoveryContext,
    ) -> None:
        record_number = entry.file_reference & ((1 << 48) - 1)
        sequence = entry.file_reference >> 48
        identity = (
            block_offset,
            entry.offset,
            record_number,
            entry.alias.filename.casefold(),
            entry.state,
        )
        if identity in self._seen_entries:
            return
        self._seen_entries.add(identity)
        synthetic = _Record(
            record_number,
            sequence,
            False,
            False,
            (entry.alias,),
            None,
        )
        artifact_class = self._locator._classify(synthetic, {})
        validation = (
            "raw_stale_indx_active_entry"
            if entry.state == "active"
            else "raw_stale_indx_slack_entry"
        )
        candidate = NTFSStaleINDXArtifactCandidate(
            source_block_physical_offset=block_offset,
            embedded_vcn=vcn,
            entry_offset=entry.offset,
            entry_state=entry.state,
            file_reference_record=record_number,
            file_reference_sequence=sequence,
            filename=entry.alias.filename,
            namespace=entry.alias.namespace,
            reference_state=self._parser._reference_state(
                record_number, sequence, context
            ),
            artifact_class=artifact_class,
            validation_strength=validation,
            source_directory_known=False,
        )
        if artifact_class in {"wallet_dat", "wallet_backup_like"}:
            self._wallet_count += 1
            self._artifact_entries.append(candidate)
        elif artifact_class == "bitcoin_context_artifact":
            self._context_count += 1
            self._artifact_entries.append(candidate)
        elif len(self._sample_entries) < self._sample_limit:
            self._sample_entries.append(candidate)

    def _read_at(self, offset: int, length: int) -> bytes:
        if self._source is None:
            self._source = self._path.open("rb")
        self._source.seek(offset)
        data = self._source.read(length)
        if len(data) != length:
            raise OSError("short_stale_indx_read")
        return data

    def _reject(self, reason: str) -> None:
        self._rejected_count += 1
        self._rejections[reason] += 1
