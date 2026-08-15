"""Targeted NTFS identity and safe Electrum metadata comparison."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from bfrs.recovery.electrum_provenance_triage import safe_fingerprint
from bfrs.recovery.ntfs_bitcoin_artifacts import NTFSBitcoinArtifactLocator
from bfrs.recovery.ntfs_file_identity import NTFSFileIdentityResolver


def _named_record(value):
    try:
        name, record = value.split(":", 1)
        return name, int(record, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected NAME:MFT_RECORD") from error


def _record_container(path, record, context):
    if record.data is None:
        return None
    if record.data.resident:
        try:
            value = context.read_resident_unnamed_data(record.number).value
        except (OSError, ValueError):
            return None
        return safe_fingerprint(value)
    if not record.data.extents:
        return None
    remaining = record.data.logical_size
    output = bytearray()
    with path.open("rb") as source:
        for extent in sorted(record.data.extents, key=lambda item: item.vcn_start):
            if extent.sparse or extent.physical_byte_start is None:
                return None
            length = min(remaining, extent.physical_byte_end - extent.physical_byte_start)
            source.seek(extent.physical_byte_start)
            chunk = source.read(length)
            if len(chunk) != length:
                return None
            output.extend(chunk)
            remaining -= length
            if remaining <= 0:
                break
    return safe_fingerprint(bytes(output)) if remaining <= 0 else None


def _compare(target, active, target_fp, active_fp):
    if target.mft_record == active.mft_record and target.sequence == active.sequence:
        return "SAME_FILESYSTEM_OBJECT", ("MFT_IDENTITY_EQUAL",), "HIGH"
    target_size = target.data_attributes[0].logical_size if target.data_attributes else None
    active_size = active.data_attributes[0].logical_size if active.data_attributes else None
    if target_fp and active_fp and target_fp.container_sha256 == active_fp.container_sha256:
        return "LIKELY_COPY_OF_ACTIVE_WALLET", ("ENCRYPTED_CONTAINER_BYTE_IDENTICAL",), "HIGH"
    if target_size != active_size:
        return "NO_RELATION_ESTABLISHED", ("LOGICAL_SIZE_DIFFERS",), "LOW"
    target_si, active_si = target.standard_information_timestamps, active.standard_information_timestamps
    same_modified = bool(target_si and active_si and target_si.modified == active_si.modified)
    same_fn_modified = any(
        left.timestamps.modified == right.timestamps.modified
        for left in target.file_names for right in active.file_names
        if left.timestamps.modified is not None
    )
    if same_modified and same_fn_modified:
        return "LIKELY_COPY_OF_ACTIVE_WALLET", (
            "LOGICAL_SIZE_EQUAL", "SI_MODIFIED_EQUAL", "FILE_NAME_MODIFIED_EQUAL",
        ), "HIGH"
    recovery = any(item.category == "RECOVERY_DIRECTORY"
                   for item in target.directory_contexts)
    if same_modified or same_fn_modified or recovery:
        reasons = ["LOGICAL_SIZE_EQUAL"]
        if target_fp and active_fp:
            reasons.append("BIE_VERSION_EQUAL" if target_fp.bie_version == active_fp.bie_version
                           else "BIE_VERSION_DIFFERS")
            if target_fp.container_sha256 != active_fp.container_sha256:
                reasons.append("ENCRYPTED_CONTAINER_FINGERPRINT_DIFFERS_NOT_EXCLUSIONARY")
        if same_modified:
            reasons.append("SI_MODIFIED_EQUAL")
        if same_fn_modified:
            reasons.append("FILE_NAME_MODIFIED_EQUAL")
        if recovery:
            reasons.append("TARGET_IN_RECOVERY_DIRECTORY")
        return "POSSIBLE_COPY", tuple(reasons), "MEDIUM"
    return "SIZE_MATCH_ONLY", ("LOGICAL_SIZE_EQUAL",), "LOW"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--volume-start", required=True, type=int)
    parser.add_argument("--target", required=True, action="append", type=_named_record)
    parser.add_argument("--active", required=True, action="append", type=_named_record)
    args = parser.parse_args()
    locator = NTFSBitcoinArtifactLocator()
    locator.index(args.input, volume_offset=args.volume_start)
    context = locator.stale_recovery_context
    if context is None:
        raise SystemExit("validated NTFS context unavailable")
    resolver = NTFSFileIdentityResolver(context)
    target_identities = {name: resolver.resolve(number) for name, number in args.target}
    active_identities = {name: resolver.resolve(number) for name, number in args.active}
    target_fp = {name: _record_container(args.input, context.current_records_by_number[number], context)
                 for name, number in args.target}
    active_fp = {name: _record_container(args.input, context.current_records_by_number[number], context)
                 for name, number in args.active}
    output = []
    for name, identity in target_identities.items():
        comparisons = []
        for active_name, active in active_identities.items():
            relation, reasons, confidence = _compare(
                identity, active, target_fp[name], active_fp[active_name]
            )
            comparisons.append({"active_wallet": active_name,
                                "active_mft_record": active.mft_record,
                                "active_logical_size": (active.data_attributes[0].logical_size
                                                        if active.data_attributes else None),
                                "active_si_timestamps": (None if active.standard_information_timestamps is None
                                                         else asdict(active.standard_information_timestamps)),
                                "active_paths": [item.path for item in active.paths],
                                "active_fingerprint": (None if active_fp[active_name] is None
                                                       else asdict(active_fp[active_name])),
                                "relation": relation, "confidence": confidence,
                                "reason_codes": reasons})
        rank = {"SAME_FILESYSTEM_OBJECT": 0, "LIKELY_COPY_OF_ACTIVE_WALLET": 1,
                "POSSIBLE_COPY": 2, "SIZE_MATCH_ONLY": 3,
                "NO_RELATION_ESTABLISHED": 4}
        closest = min(comparisons, key=lambda item: (rank[item["relation"]],
                                                     item["active_mft_record"]))
        recovery_context = any(
            item.category == "RECOVERY_DIRECTORY"
            and item.generated_name_series
            and item.index_state == "ACTIVE_INDX_ENTRY_CONFIRMED"
            for item in identity.directory_contexts
        )
        if recovery_context:
            classification = "KNOWN_RECOVERY_COPY"
        elif closest["relation"] == "LIKELY_COPY_OF_ACTIVE_WALLET":
            classification = "LIKELY_ACTIVE_WALLET_COPY"
        elif closest["relation"] in {"POSSIBLE_COPY", "SIZE_MATCH_ONLY"}:
            classification = "POSSIBLE_ACTIVE_WALLET_COPY"
        elif identity.confidence == "HIGH" and identity.allocated:
            classification = "INDEPENDENT_ACTIVE_ELECTRUM_FILE"
        else:
            classification = "UNRESOLVED"
        output.append({
            "candidate": name, "identity": identity.safe_dict(),
            "candidate_fingerprint": None if target_fp[name] is None else asdict(target_fp[name]),
            "closest_active_wallet": closest, "classification": classification,
            "all_active_comparisons": comparisons,
        })
    payload = {"schema": "targeted_ntfs_file_identity_v1",
               "source": str(args.input.resolve()),
               "volume_start": context.boot.volume_offset,
               "targeted_only": True, "candidates": output}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2,
                                      sort_keys=True) + "\n", encoding="utf-8")
    print(f"targeted identities: {len(output)}")
    print(f"report path: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
