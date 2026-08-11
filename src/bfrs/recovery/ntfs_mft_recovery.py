"""Secret-safe result models for targeted NTFS MFT recovery diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bfrs.recovery.ntfs_bitcoin_artifacts import (
        NTFSDataExtent,
        NTFSFileNameAlias,
    )


@dataclass(frozen=True, slots=True)
class NTFSMirrorRecordComparison:
    mft_record_number: int
    classification: str
    main_valid: bool
    mirror_valid: bool
    main_sequence_number: int | None
    mirror_sequence_number: int | None
    sequence_equal: bool | None
    flags_equal: bool | None
    bytes_in_use_equal: bool | None
    first_attribute_offset_equal: bool | None
    filename_metadata_equal: bool | None
    data_metadata_equal: bool | None
    fixed_record_sha256_equal: bool | None
    main_fixed_sha256: str | None
    mirror_fixed_sha256: str | None


@dataclass(frozen=True, slots=True)
class NTFSInvalidMainRecordDiagnostic:
    mft_record_number: int
    logical_mft_offset: int
    physical_offset: int | None
    failure_stage: str
    failure_reason: str


@dataclass(frozen=True, slots=True)
class NTFSMirrorArtifactCandidate:
    mft_record_number: int
    sequence_number: int
    allocation_state: str
    filename: str
    aliases: tuple[NTFSFileNameAlias, ...]
    artifact_class: str
    resident: bool | None
    nonresident: bool | None
    logical_size: int | None
    allocated_size: int | None
    extents: tuple[NTFSDataExtent, ...]
    source_kind: str = "mft_mirror"


@dataclass(frozen=True, slots=True)
class NTFSPartialFileRecordSalvage:
    mft_record_number: int
    logical_mft_offset: int
    physical_offset: int | None
    failure_stage: str
    failure_reason: str
    valid_prefix_attribute_count: int
    aliases: tuple[NTFSFileNameAlias, ...]
    artifact_class: str | None
    resident: bool | None
    nonresident: bool | None
    logical_size: int | None
    allocated_size: int | None
    extents: tuple[NTFSDataExtent, ...]
    extent_trust: str
    confidence: str
    source_kind: str = "invalid_mft_partial"


@dataclass(frozen=True, slots=True)
class NTFSMFTRecoveryDiagnostic:
    source: str
    mirror_physical_offset: int | None
    mirror_record_count_expected: int
    mirror_record_count_read: int
    mirror_record_count_valid: int
    mirror_record_count_invalid: int
    mirror_difference_counts: tuple[tuple[str, int], ...]
    mirror_comparisons: tuple[NTFSMirrorRecordComparison, ...]
    invalid_main_record_count: int
    invalid_reason_counts: tuple[tuple[str, int], ...]
    invalid_main_records: tuple[NTFSInvalidMainRecordDiagnostic, ...]
    partial_salvage_count: int
    salvaged_wallet_candidate_count: int
    salvaged_bitcoin_context_count: int
    mirror_artifact_candidates: tuple[NTFSMirrorArtifactCandidate, ...]
    partial_salvage_candidates: tuple[NTFSPartialFileRecordSalvage, ...]
    diagnostics: tuple[str, ...]


def empty_ntfs_mft_recovery_diagnostic(
    source: str,
    diagnostic: str,
) -> NTFSMFTRecoveryDiagnostic:
    return NTFSMFTRecoveryDiagnostic(
        source=source,
        mirror_physical_offset=None,
        mirror_record_count_expected=0,
        mirror_record_count_read=0,
        mirror_record_count_valid=0,
        mirror_record_count_invalid=0,
        mirror_difference_counts=(),
        mirror_comparisons=(),
        invalid_main_record_count=0,
        invalid_reason_counts=(),
        invalid_main_records=(),
        partial_salvage_count=0,
        salvaged_wallet_candidate_count=0,
        salvaged_bitcoin_context_count=0,
        mirror_artifact_candidates=(),
        partial_salvage_candidates=(),
        diagnostics=(diagnostic,),
    )
