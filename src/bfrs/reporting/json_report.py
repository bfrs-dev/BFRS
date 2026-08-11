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
