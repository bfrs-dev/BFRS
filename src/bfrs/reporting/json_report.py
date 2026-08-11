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
