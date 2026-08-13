"""Explicit, secret-safe JSON reporting for full-image recovery."""

import json
from pathlib import Path
from typing import Any, Mapping

from bfrs.recovery.full_image_coordinator import FullImageRecoveryResult
from bfrs.version import APP_NAME, VERSION


def _identity(identity) -> dict[str, Any]:
    return {
        "source": identity.source,
        "metadata_physical_offset": identity.metadata_physical_offset,
        "metadata_page_number": identity.metadata_page_number,
        "root_page_number": identity.root_page_number,
        "page_size": identity.page_size,
        "byte_order": identity.byte_order,
    }


def _direct_result(result) -> dict[str, Any]:
    encrypted = result.encrypted_wallet_evidence
    summary = result.summary
    return {
        "source": result.source,
        "status": result.status.value,
        "reasons": list(result.reasons),
        "anchor_count": len(result.anchors),
        "anchors": [
            {
                "metadata_offset": anchor.metadata_absolute_offset,
                "metadata_page_number": anchor.metadata_page_number,
                "database_base_offset": anchor.database_base_offset,
                "page_size": anchor.page_size,
                "byte_order": anchor.byte_order,
            }
            for anchor in result.anchors
        ],
        "page_locations": [
            {
                "start_offset": page.start_offset,
                "end_offset": page.end_offset,
                "status": page.status.value,
                "page_number": page.evidence.get("page_number"),
                "page_type": page.evidence.get("page_type"),
                "level": page.evidence.get("level"),
            }
            for page in result.page_results
        ],
        "record_page_locations": [
            {
                "page_number": page.page_number,
                "page_start_offset": page.page_start_offset,
                "page_status": page.page_status.value,
                "complete_record_count": page.complete_record_count,
                "record_pair_count": page.record_pair_count,
                "deleted_record_count": page.deleted_record_count,
                "incomplete_slot_count": page.incomplete_slot_count,
                "reasons": list(page.reasons),
            }
            for page in result.record_pages
        ],
        "plaintext_key_count": result.plaintext_key_count,
        "encrypted_wallet_summary": {
            "database_count": encrypted.database_count,
            "structural_database_count": encrypted.structural_database_count,
            "fragment_database_count": encrypted.fragment_database_count,
            "rejected_database_count": encrypted.rejected_database_count,
            "context_count": encrypted.context_count,
        },
        "summary": {
            name: getattr(summary, name)
            for name in (
                "metadata_structural_count",
                "metadata_fragment_count",
                "anchor_count",
                "page_structural_count",
                "page_fragment_count",
                "page_rejected_count",
                "leaf_page_count",
                "record_pair_count",
                "valid_plaintext_key_count",
                "structural_plaintext_key_count",
                "fragment_plaintext_key_count",
                "canonical_plaintext_key_count",
                "noncanonical_plaintext_key_count",
                "encrypted_database_count",
                "encrypted_structural_database_count",
                "encrypted_fragment_database_count",
            )
        },
        "diagnostics": {
            "berkeley_only_evidence": bool(
                result.evidence.get("berkeley_only_evidence", False)
            ),
            "metadata_results": result.evidence.get("metadata_results", ()),
            "plaintext_key_locations": result.evidence.get(
                "plaintext_key_locations", ()
            ),
        },
    }


def _reconstructed_database(database) -> dict[str, Any]:
    return {
        "identity": _identity(database.identity),
        "status": database.status.value,
        "reasons": list(database.reasons),
        "selected_pages": [
            {
                "page_number": page.page_number,
                "physical_offset": page.physical_offset,
                "page_size": page.page_size,
                "page_type": page.page_type,
                "level": page.level,
                "validation_status": page.validation_status.value,
            }
            for page in database.selected_pages
        ],
        "internal_page_numbers": list(database.internal_page_numbers),
        "leaf_page_numbers": list(database.leaf_page_numbers),
        "missing_page_numbers": list(database.missing_page_numbers),
        "ambiguous_page_numbers": list(database.ambiguous_page_numbers),
        "rejected_page_numbers": list(database.rejected_page_numbers),
        "confirmed_edge_count": database.confirmed_edge_count,
        "diagnostics": {
            "confirmed_edges": database.evidence.get("confirmed_edges", ()),
            "fragment_page_numbers": database.evidence.get(
                "fragment_page_numbers", ()
            ),
            "ambiguous_candidate_offsets": database.evidence.get(
                "ambiguous_candidate_offsets", ()
            ),
        },
    }


def _reconstructed_wallet(wallet) -> dict[str, Any]:
    return {
        "identity": _identity(wallet.identity),
        "database_status": wallet.database_status.value,
        "status": wallet.status.value,
        "reasons": list(wallet.reasons),
        "selected_leaf_count": wallet.selected_leaf_count,
        "record_pair_count": wallet.record_pair_count,
        "valid_plaintext_key_count": wallet.valid_plaintext_key_count,
        "structural_plaintext_key_count": wallet.structural_plaintext_key_count,
        "fragment_plaintext_key_count": wallet.fragment_plaintext_key_count,
        "valid_ckey_count": wallet.valid_ckey_count,
        "valid_mkey_count": wallet.valid_mkey_count,
        "structural_ckey_count": wallet.structural_ckey_count,
        "structural_mkey_count": wallet.structural_mkey_count,
        "fragment_ckey_count": wallet.fragment_ckey_count,
        "fragment_mkey_count": wallet.fragment_mkey_count,
        "page_numbers": list(wallet.page_numbers),
        "deleted_valid_record_count": wallet.deleted_valid_record_count,
        "safe_locations": {
            "plaintext_key_locations": wallet.evidence.get(
                "plaintext_key_locations", ()
            ),
            "ckey_locations": wallet.evidence.get("ckey_locations", ()),
            "mkey_locations": wallet.evidence.get("mkey_locations", ()),
            "read_failure_page_numbers": wallet.evidence.get(
                "read_failure_page_numbers", ()
            ),
            "rejected_extraction_page_numbers": wallet.evidence.get(
                "rejected_extraction_page_numbers", ()
            ),
        },
    }


def _legacy_wallet_recovery(result: FullImageRecoveryResult) -> dict[str, Any]:
    logical_results = result.logical_wallet_results
    candidates = tuple(
        candidate
        for logical in logical_results
        for candidate in logical.wallet_candidate_reports
    )
    candidates = tuple(sorted(candidates, key=lambda item: item["candidate_id"]))
    priorities = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for candidate in candidates:
        priority = candidate["priority"]
        if priority in priorities:
            priorities[priority] += 1
    return {
        "source": result.source,
        "summary": {
            "logical_records_examined": sum(
                item.logical_records_examined for item in logical_results
            ),
            "wallet_records_valid": sum(
                item.wallet_records_valid for item in logical_results
            ),
            "wallet_records_partial": sum(
                item.wallet_records_partial for item in logical_results
            ),
            "wallet_records_rejected": sum(
                item.wallet_records_rejected for item in logical_results
            ),
            "wallet_candidates": len(candidates),
            "critical_candidates": priorities["CRITICAL"],
            "high_candidates": priorities["HIGH"],
            "medium_candidates": priorities["MEDIUM"],
            "low_candidates": priorities["LOW"],
            "crypto_valid_key_occurrences": sum(
                item["crypto_summary"]["crypto_valid_plain_keys"]
                for item in candidates
            ),
            "unique_crypto_valid_private_keys": sum(
                item["crypto_summary"]["unique_crypto_valid_plain_keys"]
                for item in candidates
            ),
            "crypto_duplicate_occurrences": sum(
                item["crypto_summary"]["crypto_duplicate_occurrences"]
                for item in candidates
            ),
            "encrypted_complete_candidates": sum(
                item["encryption_state"] == "ENCRYPTED_COMPLETE_EVIDENCE"
                for item in candidates
            ),
        },
        "candidates": list(candidates),
        "pipeline_failures": [
            list(item)
            for item in result.evidence.get("errors", ())
            if len(item) >= 3 and item[2] == "logical_wallet_pipeline_error"
        ],
    }


def _metadata_less_fragment(result) -> dict[str, Any]:
    return {
        "status": result.status.value,
        "source": result.source,
        "candidate_page_count": result.candidate_page_count,
        "structural_leaf_count": result.structural_leaf_count,
        "fragment_leaf_count": result.fragment_leaf_count,
        "record_pair_count": result.record_pair_count,
        "valid_plaintext_key_count": result.valid_plaintext_key_count,
        "valid_ckey_count": result.valid_ckey_count,
        "valid_mkey_count": result.valid_mkey_count,
        "recognized_wkey_count": result.recognized_wkey_count,
        "recognized_defaultkey_count": result.recognized_defaultkey_count,
        "recognized_keymeta_count": result.recognized_keymeta_count,
        "page_locations": [
            {
                "physical_offset": page.physical_offset,
                "page_number": page.page_number,
                "page_size": page.page_size,
                "byte_order": page.byte_order,
                "validation_status": page.validation_status.value,
            }
            for page in result.page_locations
        ],
        "record_locations": [
            {
                "record_type": record.record_type,
                "physical_page_offset": record.physical_page_offset,
                "page_number": record.page_number,
                "page_size": record.page_size,
                "byte_order": record.byte_order,
                "page_status": record.page_status.value,
                "key_offset": record.key_offset,
                "value_offset": record.value_offset,
                "discovery_hit_offset": record.discovery_hit_offset,
            }
            for record in result.record_locations
        ],
        "reasons": list(result.reasons),
        "diagnostics": {
            name: result.evidence.get(name, 0)
            for name in (
                "candidate_page_starts_tested",
                "candidate_geometry_count",
                "page_validation_attempt_count",
                "page_validator_structural_count",
                "page_validator_fragment_count",
                "strong_hit_count",
            )
        },
    }


def _orphan_record_key_diagnostic(result) -> dict[str, Any]:
    return {
        "source": result.source,
        "raw_strong_hit_count": result.raw_strong_hit_count,
        "valid_record_key_count": result.valid_record_key_count,
        "valid_key_count": result.valid_key_count,
        "valid_wkey_count": result.valid_wkey_count,
        "valid_ckey_keyside_count": result.valid_ckey_keyside_count,
        "valid_mkey_keyside_count": result.valid_mkey_keyside_count,
        "valid_defaultkey_count": result.valid_defaultkey_count,
        "valid_keymeta_count": result.valid_keymeta_count,
        "canonical_framing_count": result.canonical_framing_count,
        "noncanonical_framing_count": result.noncanonical_framing_count,
        "locations": [
            {
                "record_type": location.record_type,
                "absolute_offset": location.absolute_offset,
                "canonical_framing": location.canonical_framing,
                "master_key_id": location.master_key_id,
            }
            for location in result.locations
        ],
        "diagnostics": {
            name: result.evidence.get(name, 0)
            for name in (
                "maximum_read_size",
                "read_failure_count",
                "short_read_count",
                "record_type_mismatch_count",
            )
        },
    }


def _orphan_private_key_recovery(result) -> dict[str, Any]:
    return {
        "source": result.source,
        "raw_der_anchor_count": result.raw_der_anchor_count,
        "candidate_der_count": result.candidate_der_count,
        "valid_secp256k1_der_count": result.valid_secp256k1_der_count,
        "canonical_der_count": result.canonical_der_count,
        "valid_with_embedded_pubkey_count": (
            result.valid_with_embedded_pubkey_count
        ),
        "valid_without_embedded_pubkey_count": (
            result.valid_without_embedded_pubkey_count
        ),
        "locations": [
            {
                "absolute_der_offset": location.absolute_der_offset,
                "der_length": location.der_length,
                "public_key_encoding": location.public_key_encoding,
                "validation_strength": location.validation_strength,
            }
            for location in result.locations
        ],
        "reasons": list(result.reasons),
        "diagnostics": {
            "maximum_read_size": result.evidence.get("maximum_read_size", 0),
            "read_failure_count": result.evidence.get("read_failure_count", 0),
            "truncated_read_count": result.evidence.get(
                "truncated_read_count", 0
            ),
            "rejection_counts": result.evidence.get("rejection_counts", ()),
        },
    }


def _orphan_private_key_fragment_recovery(result) -> dict[str, Any]:
    return {
        "source": result.source,
        "raw_inner_anchor_count": result.raw_inner_anchor_count,
        "candidate_inner_fragment_count": result.candidate_inner_fragment_count,
        "valid_inner_fragment_count": result.valid_inner_fragment_count,
        "locations": [
            {
                "absolute_anchor_offset": location.absolute_anchor_offset,
                "recovered_fragment_length": location.recovered_fragment_length,
                "public_key_encoding": location.public_key_encoding,
                "validation_strength": location.validation_strength,
            }
            for location in result.locations
        ],
        "reasons": list(result.reasons),
        "diagnostics": {
            "maximum_read_size": result.evidence.get("maximum_read_size", 0),
            "read_failure_count": result.evidence.get("read_failure_count", 0),
            "truncated_read_count": result.evidence.get(
                "truncated_read_count", 0
            ),
            "rejection_counts": result.evidence.get("rejection_counts", ()),
        },
    }


def _ntfs_bitcoin_artifact_index(index) -> dict[str, Any]:
    if index is None:
        return {
            "source": None,
            "volume_offset": None,
            "cluster_size": None,
            "mft_record_size": None,
            "mft_records_scanned": 0,
            "mft_records_valid": 0,
            "mft_records_invalid": 0,
            "allocated_record_count": 0,
            "deleted_record_count": 0,
            "wallet_dat_candidate_count": 0,
            "bitcoin_context_artifact_count": 0,
            "mft_attribute_list_present": False,
            "mft_stream_may_be_incomplete": False,
            "candidates": [],
            "diagnostics": ["ntfs_index_not_available"],
        }
    return {
        "source": index.source,
        "volume_offset": index.volume_offset,
        "cluster_size": index.cluster_size,
        "mft_record_size": index.mft_record_size,
        "mft_records_scanned": index.mft_records_scanned,
        "mft_records_valid": index.mft_records_valid,
        "mft_records_invalid": index.mft_records_invalid,
        "allocated_record_count": index.allocated_record_count,
        "deleted_record_count": index.deleted_record_count,
        "wallet_dat_candidate_count": index.wallet_dat_candidate_count,
        "bitcoin_context_artifact_count": index.bitcoin_context_artifact_count,
        "mft_attribute_list_present": index.mft_attribute_list_present,
        "mft_stream_may_be_incomplete": index.mft_stream_may_be_incomplete,
        "candidates": [
            {
                "mft_record_number": candidate.mft_record_number,
                "sequence_number": candidate.sequence_number,
                "allocation_state": candidate.allocation_state,
                "filename": candidate.filename,
                "namespace": candidate.namespace,
                "aliases": [
                    {
                        "filename": alias.filename,
                        "namespace": alias.namespace,
                        "parent_mft_record_number": alias.parent_mft_record_number,
                        "parent_sequence_number": alias.parent_sequence_number,
                    }
                    for alias in candidate.aliases
                ],
                "path": candidate.path,
                "partial_path": candidate.partial_path,
                "artifact_class": candidate.artifact_class,
                "resident": candidate.resident,
                "nonresident": candidate.nonresident,
                "logical_size": candidate.logical_size,
                "allocated_size": candidate.allocated_size,
                "extent_count": candidate.extent_count,
                "extents": [
                    {
                        "vcn_start": extent.vcn_start,
                        "vcn_end": extent.vcn_end,
                        "physical_lcn_start": extent.physical_lcn_start,
                        "physical_byte_start": extent.physical_byte_start,
                        "physical_byte_end": extent.physical_byte_end,
                        "sparse": extent.sparse,
                    }
                    for extent in candidate.extents
                ],
                "extent_trust": candidate.extent_trust,
                "data_recovery_state": candidate.data_recovery_state,
            }
            for candidate in index.candidates
        ],
        "diagnostics": list(index.diagnostics),
    }


def _ntfs_extent(extent) -> dict[str, Any]:
    return {
        "vcn_start": extent.vcn_start,
        "vcn_end": extent.vcn_end,
        "physical_lcn_start": extent.physical_lcn_start,
        "physical_byte_start": extent.physical_byte_start,
        "physical_byte_end": extent.physical_byte_end,
        "sparse": extent.sparse,
    }


def _ntfs_alias(alias) -> dict[str, Any]:
    return {
        "filename": alias.filename,
        "namespace": alias.namespace,
        "parent_mft_record_number": alias.parent_mft_record_number,
        "parent_sequence_number": alias.parent_sequence_number,
    }


def _ntfs_mft_recovery_diagnostic(index) -> dict[str, Any]:
    diagnostic = None if index is None else index.mft_recovery_diagnostic
    if diagnostic is None:
        return {
            "source": None,
            "mirror_physical_offset": None,
            "mirror_record_count_expected": 0,
            "mirror_record_count_read": 0,
            "mirror_record_count_valid": 0,
            "mirror_record_count_invalid": 0,
            "mirror_difference_counts": {},
            "mirror_comparisons": [],
            "invalid_main_record_count": 0,
            "invalid_reason_counts": {},
            "invalid_main_records": [],
            "partial_salvage_count": 0,
            "salvaged_wallet_candidate_count": 0,
            "salvaged_bitcoin_context_count": 0,
            "mirror_artifact_candidates": [],
            "partial_salvage_candidates": [],
            "diagnostics": ["ntfs_mft_recovery_diagnostic_not_available"],
        }
    return {
        "source": diagnostic.source,
        "mirror_physical_offset": diagnostic.mirror_physical_offset,
        "mirror_record_count_expected": (
            diagnostic.mirror_record_count_expected
        ),
        "mirror_record_count_read": diagnostic.mirror_record_count_read,
        "mirror_record_count_valid": diagnostic.mirror_record_count_valid,
        "mirror_record_count_invalid": diagnostic.mirror_record_count_invalid,
        "mirror_difference_counts": dict(
            diagnostic.mirror_difference_counts
        ),
        "mirror_comparisons": [
            {
                "mft_record_number": item.mft_record_number,
                "classification": item.classification,
                "main_valid": item.main_valid,
                "mirror_valid": item.mirror_valid,
                "main_sequence_number": item.main_sequence_number,
                "mirror_sequence_number": item.mirror_sequence_number,
                "sequence_equal": item.sequence_equal,
                "flags_equal": item.flags_equal,
                "bytes_in_use_equal": item.bytes_in_use_equal,
                "first_attribute_offset_equal": (
                    item.first_attribute_offset_equal
                ),
                "filename_metadata_equal": item.filename_metadata_equal,
                "data_metadata_equal": item.data_metadata_equal,
                "fixed_record_sha256_equal": item.fixed_record_sha256_equal,
                "main_fixed_sha256": item.main_fixed_sha256,
                "mirror_fixed_sha256": item.mirror_fixed_sha256,
            }
            for item in diagnostic.mirror_comparisons
        ],
        "invalid_main_record_count": diagnostic.invalid_main_record_count,
        "invalid_reason_counts": dict(diagnostic.invalid_reason_counts),
        "invalid_main_records": [
            {
                "mft_record_number": item.mft_record_number,
                "logical_mft_offset": item.logical_mft_offset,
                "physical_offset": item.physical_offset,
                "failure_stage": item.failure_stage,
                "failure_reason": item.failure_reason,
            }
            for item in diagnostic.invalid_main_records
        ],
        "partial_salvage_count": diagnostic.partial_salvage_count,
        "salvaged_wallet_candidate_count": (
            diagnostic.salvaged_wallet_candidate_count
        ),
        "salvaged_bitcoin_context_count": (
            diagnostic.salvaged_bitcoin_context_count
        ),
        "mirror_artifact_candidates": [
            {
                "mft_record_number": item.mft_record_number,
                "sequence_number": item.sequence_number,
                "allocation_state": item.allocation_state,
                "filename": item.filename,
                "aliases": [_ntfs_alias(alias) for alias in item.aliases],
                "artifact_class": item.artifact_class,
                "resident": item.resident,
                "nonresident": item.nonresident,
                "logical_size": item.logical_size,
                "allocated_size": item.allocated_size,
                "extent_count": len(item.extents),
                "extents": [_ntfs_extent(extent) for extent in item.extents],
                "source_kind": item.source_kind,
            }
            for item in diagnostic.mirror_artifact_candidates
        ],
        "partial_salvage_candidates": [
            {
                "mft_record_number": item.mft_record_number,
                "logical_mft_offset": item.logical_mft_offset,
                "physical_offset": item.physical_offset,
                "failure_stage": item.failure_stage,
                "failure_reason": item.failure_reason,
                "valid_prefix_attribute_count": (
                    item.valid_prefix_attribute_count
                ),
                "aliases": [_ntfs_alias(alias) for alias in item.aliases],
                "artifact_class": item.artifact_class,
                "resident": item.resident,
                "nonresident": item.nonresident,
                "logical_size": item.logical_size,
                "allocated_size": item.allocated_size,
                "extent_count": len(item.extents),
                "extents": [_ntfs_extent(extent) for extent in item.extents],
                "extent_trust": item.extent_trust,
                "confidence": item.confidence,
                "source_kind": item.source_kind,
            }
            for item in diagnostic.partial_salvage_candidates
        ],
        "diagnostics": list(diagnostic.diagnostics),
    }


def _ntfs_stale_file_record_recovery(result) -> dict[str, Any]:
    if result is None:
        return {
            "source": None,
            "raw_file_hit_count": 0,
            "current_mft_excluded_count": 0,
            "mftmirr_excluded_count": 0,
            "candidate_record_count": 0,
            "structural_stale_record_count": 0,
            "rejected_record_count": 0,
            "wallet_candidate_count": 0,
            "bitcoin_context_candidate_count": 0,
            "rejection_counts": {},
            "diagnostic_sample_limit": 0,
            "records": [],
            "diagnostics": ["ntfs_stale_file_record_recovery_not_available"],
            "outside_current_volume_before_count": 0,
            "outside_current_volume_after_count": 0,
            "image_end_truncated_count": 0,
            "cli_range_truncated_count": 0,
        }
    return {
        "source": result.source,
        "raw_file_hit_count": result.raw_file_hit_count,
        "current_mft_excluded_count": result.current_mft_excluded_count,
        "mftmirr_excluded_count": result.mftmirr_excluded_count,
        "candidate_record_count": result.candidate_record_count,
        "structural_stale_record_count": (
            result.structural_stale_record_count
        ),
        "rejected_record_count": result.rejected_record_count,
        "wallet_candidate_count": result.wallet_candidate_count,
        "bitcoin_context_candidate_count": (
            result.bitcoin_context_candidate_count
        ),
        "rejection_counts": dict(result.rejection_counts),
        "diagnostic_sample_limit": result.diagnostic_sample_limit,
        "records": [
            {
                "physical_offset": record.physical_offset,
                "embedded_record_number": record.embedded_record_number,
                "sequence_number": record.sequence_number,
                "allocation_state": record.allocation_state,
                "flags": record.flags,
                "aliases": [_ntfs_alias(alias) for alias in record.aliases],
                "artifact_class": record.artifact_class,
                "parent_mft_record_number": (
                    record.parent_mft_record_number
                ),
                "parent_sequence_number": record.parent_sequence_number,
                "path": record.path,
                "partial_path": record.partial_path,
                "resident": record.resident,
                "nonresident": record.nonresident,
                "logical_size": record.logical_size,
                "allocated_size": record.allocated_size,
                "extent_count": record.extent_count,
                "extents": [_ntfs_extent(extent) for extent in record.extents],
                "extent_trust": record.extent_trust,
                "data_recovery_state": record.data_recovery_state,
                "comparison_to_current": record.comparison_to_current,
                "validation_strength": record.validation_strength,
            }
            for record in result.records
        ],
        "diagnostics": list(result.diagnostics),
        "outside_current_volume_before_count": result.outside_current_volume_before_count,
        "outside_current_volume_after_count": result.outside_current_volume_after_count,
        "image_end_truncated_count": result.image_end_truncated_count,
        "cli_range_truncated_count": result.cli_range_truncated_count,
    }


def _ntfs_directory_index_artifact_recovery(result) -> dict[str, Any]:
    if result is None:
        return {
            "source": None,
            "directory_record_count": 0,
            "index_root_count": 0,
            "index_allocation_stream_count": 0,
            "indx_block_count": 0,
            "indx_block_valid_count": 0,
            "indx_block_invalid_count": 0,
            "active_entry_count": 0,
            "slack_candidate_count": 0,
            "structural_slack_entry_count": 0,
            "wallet_candidate_count": 0,
            "active_wallet_candidate_count": 0,
            "slack_wallet_candidate_count": 0,
            "bitcoin_context_candidate_count": 0,
            "rejection_counts": {},
            "candidates": [],
            "diagnostics": [
                "ntfs_directory_index_artifact_recovery_not_available"
            ],
        }
    return {
        "source": result.source,
        "directory_record_count": result.directory_record_count,
        "index_root_count": result.index_root_count,
        "index_allocation_stream_count": result.index_allocation_stream_count,
        "indx_block_count": result.indx_block_count,
        "indx_block_valid_count": result.indx_block_valid_count,
        "indx_block_invalid_count": result.indx_block_invalid_count,
        "active_entry_count": result.active_entry_count,
        "slack_candidate_count": result.slack_candidate_count,
        "structural_slack_entry_count": result.structural_slack_entry_count,
        "wallet_candidate_count": result.wallet_candidate_count,
        "active_wallet_candidate_count": result.active_wallet_candidate_count,
        "slack_wallet_candidate_count": result.slack_wallet_candidate_count,
        "bitcoin_context_candidate_count": (
            result.bitcoin_context_candidate_count
        ),
        "rejection_counts": dict(result.rejection_counts),
        "candidates": [
            {
                "source_directory_mft_record": (
                    item.source_directory_mft_record
                ),
                "source_directory_sequence": item.source_directory_sequence,
                "source_directory_path": item.source_directory_path,
                "recovered_path": item.recovered_path,
                "partial_path": item.partial_path,
                "index_source": item.index_source,
                "index_vcn": item.index_vcn,
                "entry_offset": item.entry_offset,
                "file_reference_record": item.file_reference_record,
                "file_reference_sequence": item.file_reference_sequence,
                "filename": item.filename,
                "namespace": item.namespace,
                "entry_state": item.entry_state,
                "reference_state": item.reference_state,
                "parent_reference_state": item.parent_reference_state,
                "artifact_class": item.artifact_class,
                "validation_strength": item.validation_strength,
            }
            for item in result.candidates
        ],
        "diagnostics": list(result.diagnostics),
    }


def _ntfs_stale_indx_recovery(result) -> dict[str, Any]:
    if result is None:
        return {
            "source": None,
            "raw_indx_hit_count": 0,
            "current_indx_excluded_count": 0,
            "candidate_block_count": 0,
            "structural_stale_indx_count": 0,
            "rejected_block_count": 0,
            "active_entry_count": 0,
            "slack_candidate_count": 0,
            "structural_slack_entry_count": 0,
            "wallet_candidate_count": 0,
            "bitcoin_context_candidate_count": 0,
            "rejection_counts": {},
            "diagnostic_sample_limit": 0,
            "blocks": [],
            "candidates": [],
            "diagnostics": ["ntfs_stale_indx_recovery_not_available"],
            "outside_current_volume_before_count": 0,
            "outside_current_volume_after_count": 0,
            "image_end_truncated_count": 0,
            "cli_range_truncated_count": 0,
        }
    return {
        "source": result.source,
        "raw_indx_hit_count": result.raw_indx_hit_count,
        "current_indx_excluded_count": result.current_indx_excluded_count,
        "candidate_block_count": result.candidate_block_count,
        "structural_stale_indx_count": result.structural_stale_indx_count,
        "rejected_block_count": result.rejected_block_count,
        "active_entry_count": result.active_entry_count,
        "slack_candidate_count": result.slack_candidate_count,
        "structural_slack_entry_count": result.structural_slack_entry_count,
        "wallet_candidate_count": result.wallet_candidate_count,
        "bitcoin_context_candidate_count": (
            result.bitcoin_context_candidate_count
        ),
        "rejection_counts": dict(result.rejection_counts),
        "diagnostic_sample_limit": result.diagnostic_sample_limit,
        "blocks": [
            {
                "physical_offset": block.physical_offset,
                "index_block_size": block.index_block_size,
                "embedded_vcn": block.embedded_vcn,
                "validation_strength": block.validation_strength,
                "comparison_to_current": block.comparison_to_current,
                "active_entry_count": block.active_entry_count,
                "structural_slack_entry_count": (
                    block.structural_slack_entry_count
                ),
            }
            for block in result.blocks
        ],
        "candidates": [
            {
                "source_block_physical_offset": (
                    item.source_block_physical_offset
                ),
                "embedded_vcn": item.embedded_vcn,
                "entry_offset": item.entry_offset,
                "entry_state": item.entry_state,
                "file_reference_record": item.file_reference_record,
                "file_reference_sequence": item.file_reference_sequence,
                "filename": item.filename,
                "namespace": item.namespace,
                "reference_state": item.reference_state,
                "artifact_class": item.artifact_class,
                "validation_strength": item.validation_strength,
                "source_directory_known": item.source_directory_known,
            }
            for item in result.candidates
        ],
        "diagnostics": list(result.diagnostics),
        "outside_current_volume_before_count": result.outside_current_volume_before_count,
        "outside_current_volume_after_count": result.outside_current_volume_after_count,
        "image_end_truncated_count": result.image_end_truncated_count,
        "cli_range_truncated_count": result.cli_range_truncated_count,
    }


def _ntfs_detached_volume_discovery(result) -> dict[str, Any]:
    if result is None:
        return {"source": None, "raw_boot_anchor_count": 0,
                "candidate_boot_sector_count": 0, "valid_boot_sector_count": 0,
                "invalid_boot_sector_count": 0, "geometry_hypothesis_count": 0,
                "boot_only_geometry_count": 0, "correlated_geometry_count": 0,
                "detached_volume_count": 0, "current_volume_copy_count": 0,
                "rejection_counts": {}, "volumes": [], "diagnostics": ["ntfs_detached_volume_discovery_not_available"]}
    return {
        "source": result.source,
        "raw_boot_anchor_count": result.raw_boot_anchor_count,
        "candidate_boot_sector_count": result.candidate_boot_sector_count,
        "valid_boot_sector_count": result.valid_boot_sector_count,
        "invalid_boot_sector_count": result.invalid_boot_sector_count,
        "geometry_hypothesis_count": result.geometry_hypothesis_count,
        "boot_only_geometry_count": result.boot_only_geometry_count,
        "correlated_geometry_count": result.correlated_geometry_count,
        "detached_volume_count": result.detached_volume_count,
        "current_volume_copy_count": result.current_volume_copy_count,
        "rejection_counts": dict(result.rejection_counts),
        "volumes": [
            {name: getattr(volume, name) for name in (
                "classification", "validation_strength", "provenance", "volume_start", "volume_end",
                "volume_size_bytes", "bytes_per_sector", "sectors_per_cluster", "cluster_size",
                "total_sectors", "mft_lcn", "mftmirr_lcn", "mft_record_size",
                "index_block_size", "volume_serial", "boot_copy_count",
                "primary_boot_offsets", "backup_boot_offsets", "mft0_physical_offset",
                "mft0_valid", "mft0_failure_reason", "mftmirr0_physical_offset",
                "mftmirr0_valid", "mftmirr0_failure_reason", "boot_pair_valid", "reasons")}
            for volume in result.volumes
        ],
        "diagnostics": list(result.diagnostics),
    }


def _ntfs_detached_metadata_recovery(result) -> dict[str, Any]:
    if result is None:
        return {
            "source": None, "volume_count": 0, "volumes": [],
            "wallet_candidate_count": 0,
            "bitcoin_context_candidate_count": 0,
            "logical_wallet_candidate_count": 0,
            "stale_wallet_candidate_count": 0,
            "diagnostics": ["ntfs_detached_metadata_recovery_not_available"],
        }
    scalar_names = (
        "volume_start", "volume_end", "volume_size_bytes", "provenance",
        "validation_strength", "mft_logical_size", "mft_record_count",
        "mft_records_scanned", "mft_records_valid", "mft_records_invalid",
        "directory_record_count", "index_root_count",
        "index_allocation_stream_count", "indx_block_count",
        "indx_block_valid_count", "indx_block_invalid_count",
        "active_index_entry_count", "structural_index_slack_entry_count",
        "raw_file_hit_count_within_volume",
        "detached_current_mft_excluded_count", "structural_stale_file_count",
        "raw_indx_hit_count_within_volume",
        "detached_current_indx_excluded_count", "structural_stale_indx_count",
        "wallet_candidate_count", "bitcoin_context_candidate_count",
    )
    candidate_names = (
        "volume_start", "volume_end", "provenance", "source_layer",
        "artifact_class", "filename", "path", "partial_path",
        "mft_record_number", "sequence_number", "allocation_state",
        "resident", "nonresident", "logical_size", "allocated_size",
        "initialized_size", "extent_trust", "physical_metadata_offset",
        "source_directory_mft_record", "entry_offset", "entry_state",
        "file_reference_record", "file_reference_sequence", "reference_state",
        "validation_strength",
    )
    return {
        "source": result.source,
        "volume_count": result.volume_count,
        "wallet_candidate_count": result.wallet_candidate_count,
        "bitcoin_context_candidate_count": result.bitcoin_context_candidate_count,
        "logical_wallet_candidate_count": result.logical_wallet_candidate_count,
        "stale_wallet_candidate_count": result.stale_wallet_candidate_count,
        "volumes": [
            {
                **{name: getattr(volume, name) for name in scalar_names},
                "rejection_counts": dict(volume.rejection_counts),
                "candidates": [
                    {
                        **{name: getattr(item, name) for name in candidate_names},
                        "aliases": [_ntfs_alias(alias) for alias in item.aliases],
                        "extents": [_ntfs_extent(extent) for extent in item.extents],
                    }
                    for item in volume.candidates
                ],
                "diagnostics": list(volume.diagnostics),
            }
            for volume in result.volumes
        ],
        "diagnostics": list(result.diagnostics),
    }


def serialize_full_image_result(
    result: FullImageRecoveryResult,
    configuration: Mapping[str, Any],
) -> dict[str, Any]:
    """Select only explicitly approved scalar diagnostics and locations."""
    if not isinstance(result, FullImageRecoveryResult):
        raise ValueError("result must be FullImageRecoveryResult")
    safe_configuration = {
        name: configuration[name]
        for name in (
            "chunk_mib",
            "overlap_kib",
            "cluster_mib",
            "padding_mib",
            "minimum_hits",
            "minimum_distinct_types",
            "signature_set",
        )
        if name in configuration
    }
    diagnostics = {
        name: result.evidence.get(name, ())
        for name in (
            "hotspot_ranges",
            "hotspot_decisions",
            "read_hotspot_ranges",
            "direct_result_ranges",
            "physical_metadata_candidates",
            "physical_page_candidates",
            "errors",
        )
    }
    return {
        "application": {"name": APP_NAME, "version": VERSION},
        "source": result.source,
        "scan_range": {
            "start_offset": result.start_offset,
            "end_offset": result.end_offset,
        },
        "configuration": safe_configuration,
        "status": result.status.value,
        "raw_hit_count": result.raw_hit_count,
        "hotspot_count": result.hotspot_count,
        "accepted_hotspot_count": result.accepted_hotspot_count,
        "direct_results": [_direct_result(item) for item in result.direct_results],
        "reconstructed_databases": [
            _reconstructed_database(item)
            for item in result.reconstructed_databases
        ],
        "reconstructed_wallet_results": [
            _reconstructed_wallet(item)
            for item in result.reconstructed_wallet_results
        ],
        "legacy_wallet_recovery": _legacy_wallet_recovery(result),
        "metadata_less_fragment_summary": _metadata_less_fragment(
            result.metadata_less_fragment_recovery
        ),
        "orphan_record_key_diagnostic": _orphan_record_key_diagnostic(
            result.orphan_record_key_diagnostic
        ),
        "orphan_private_key_recovery": _orphan_private_key_recovery(
            result.orphan_private_key_recovery
        ),
        "orphan_private_key_fragment_recovery": (
            _orphan_private_key_fragment_recovery(
                result.orphan_private_key_fragment_recovery
            )
        ),
        "ntfs_bitcoin_artifact_index": _ntfs_bitcoin_artifact_index(
            result.ntfs_bitcoin_artifact_index
        ),
        "ntfs_mft_recovery_diagnostic": _ntfs_mft_recovery_diagnostic(
            result.ntfs_bitcoin_artifact_index
        ),
        "ntfs_stale_file_record_recovery": (
            _ntfs_stale_file_record_recovery(
                result.ntfs_stale_file_record_recovery
            )
        ),
        "ntfs_directory_index_artifact_recovery": (
            _ntfs_directory_index_artifact_recovery(
                result.ntfs_directory_index_artifact_recovery
            )
        ),
        "ntfs_stale_indx_recovery": _ntfs_stale_indx_recovery(
            result.ntfs_stale_indx_recovery
        ),
        "ntfs_detached_volume_discovery": _ntfs_detached_volume_discovery(
            result.ntfs_detached_volume_discovery
        ),
        "ntfs_detached_metadata_recovery": _ntfs_detached_metadata_recovery(
            result.ntfs_detached_metadata_recovery
        ),
        "raw_hit_counts_by_signature": dict(
            result.evidence.get("raw_hit_counts_by_signature", ())
        ),
        "structural_result_count": result.structural_wallet_count,
        "fragment_result_count": result.fragment_wallet_count,
        "diagnostics": {
            "reasons": list(result.reasons),
            "evidence": diagnostics,
        },
    }


def write_json_report(
    path: str | Path,
    result: FullImageRecoveryResult,
    configuration: Mapping[str, Any],
) -> Path:
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = serialize_full_image_result(result, configuration)
    with report_path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, indent=2, sort_keys=True, ensure_ascii=False)
        output.write("\n")
    return report_path.resolve()
