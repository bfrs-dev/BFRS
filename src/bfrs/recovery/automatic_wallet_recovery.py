"""Conservative automatic exact-page recovery for accepted Bitcoin wallets."""
from __future__ import annotations

from pathlib import Path
import copy
import hashlib
import json
import os
import uuid

from bfrs.core.path_safety import paths_refer_to_same_file
from bfrs.recovery.physical_berkeley_reconstructor import (
    ExportRefused,
    export_wallet_from_report,
    prepare,
)


def _empty_summary(*, requested: bool) -> dict:
    return {
        "requested": requested,
        "eligible_candidates": 0,
        "recovered_wallets": 0,
        "failed_wallets": 0,
        "outputs": [],
    }


def recovery_not_requested() -> dict:
    """Return the stable report section used by ordinary scans."""
    return _empty_summary(requested=False)


def _inside_git_worktree(path: Path) -> bool:
    current = path.resolve(strict=False)
    if not current.is_dir():
        current = current.parent
    return any((parent / ".git").exists() for parent in (current, *current.parents))


def validate_recovery_destination(source: Path, recovery_dir: Path) -> None:
    """Reject recovery roots that could expose secrets or alias the source."""
    if _inside_git_worktree(Path(recovery_dir)):
        raise ExportRefused("RECOVERY_DIRECTORY_INSIDE_GIT_WORKTREE")
    if paths_refer_to_same_file(source, recovery_dir):
        raise ExportRefused("PATH_COLLISION")
    source_resolved = source.resolve(strict=False)
    recovery_resolved = recovery_dir.resolve(strict=False)
    if source_resolved.is_dir() and source_resolved in recovery_resolved.parents:
        raise ExportRefused("RECOVERY_DIRECTORY_INSIDE_SOURCE")


def _physical_start(candidate: dict) -> int:
    ranges = candidate.get("physical_image_ranges", candidate.get("file_ranges", ()))
    values = [item[0] for item in ranges
              if isinstance(item, (list, tuple)) and len(item) == 2
              and type(item[0]) is int and item[0] >= 0]
    return min(values) if values else 2**63 - 1


def _candidate_allowed(candidate: dict) -> bool:
    state = candidate.get("normalized_state", {})
    return (state.get("discovery_state") == "ACCEPTED"
            and state.get("recovery_relevance") != "LIKELY_FALSE_POSITIVE")


def _encryption_state(candidate: dict) -> bool:
    return candidate.get("encryption_state") != "NO_ENCRYPTION_EVIDENCE"


def _internal_physical_location_view(report: dict) -> dict:
    """Restore legacy location labels on a private copy for the reconstructor."""
    reverse = {
        "file_offset_start": "physical_start",
        "file_offset_end": "physical_end",
        "file_offset": "physical_offset",
        "file_ranges": "physical_image_ranges",
        "metadata_file_offset": "metadata_physical_offset",
    }

    def convert(value):
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        return {reverse.get(key, key): convert(item) for key, item in value.items()}

    return convert(copy.deepcopy(report))


def recover_wallets(source: Path, report: dict, recovery_dir: Path) -> dict:
    """Recover every eligible candidate in deterministic physical-offset order.

    Eligibility is finally decided by the physical reconstructor. Refusals are
    represented only by fixed reason codes and never include record bytes.
    """
    source, recovery_dir = Path(source), Path(recovery_dir)
    validate_recovery_destination(source, recovery_dir)
    report = _internal_physical_location_view(report)

    candidates = report.get("legacy_wallet_recovery", {}).get("candidates", ())
    ordered = sorted(
        (candidate for candidate in candidates if _candidate_allowed(candidate)),
        key=lambda item: (_physical_start(item), item.get("candidate_id", "")),
    )
    summary = _empty_summary(requested=True)
    for index, candidate in enumerate(ordered, 1):
        candidate_id = candidate.get("candidate_id")
        relative = Path("bitcoin-core") / f"candidate_{index:03d}" / "wallet.dat"
        wallet = recovery_dir / relative
        manifest = wallet.with_name("recovery_manifest.json")
        entry = {
            "candidate_id": candidate_id if isinstance(candidate_id, str) else "INVALID",
            "relative_recovery_path": relative.as_posix(),
            "status": "REFUSED",
            "format": "BDB",
            "encrypted": _encryption_state(candidate),
        }
        try:
            if not isinstance(candidate_id, str):
                raise ExportRefused("INVALID_CANDIDATE_ID")
            if candidate.get("encryption_state") in {
                "ENCRYPTED_KEYS_WITHOUT_MASTER_KEY",
                "MASTER_KEY_WITHOUT_CKEY",
            }:
                raise ExportRefused("INCOMPLETE_ENCRYPTION_EVIDENCE")
            with source.open("rb") as stream:
                plan = prepare(source, report, candidate_id, stream)
            summary["eligible_candidates"] += 1
            if os.path.lexists(wallet) or os.path.lexists(manifest):
                raise ExportRefused("OUTPUT_EXISTS")
            wallet.parent.mkdir(parents=True, exist_ok=True)
            result = export_wallet_from_report(
                source,
                report,
                candidate_id,
                wallet,
                allow_private_key_export=True,
                manifest_path=manifest,
                manifest_fields={
                    "source_physical_range": [
                        min(plan.offsets.values()),
                        max(plan.offsets.values()) + plan.page_size,
                    ],
                    "structural_status": "VALID",
                    "encrypted": _encryption_state(candidate),
                    "crypto_valid_count": candidate.get("crypto_summary", {}).get(
                        "crypto_valid_plain_keys", 0),
                    "duplicate_count": candidate.get("crypto_summary", {}).get(
                        "crypto_duplicate_occurrences", 0),
                    "reconstruction_method": "EXACT_VALIDATED_PAGE_COPY",
                },
            )
        except ExportRefused as error:
            entry["reason_code"] = str(error)
            summary["failed_wallets"] += 1
        except OSError:
            entry["reason_code"] = "IO_OR_PUBLICATION_FAILURE"
            summary["failed_wallets"] += 1
        else:
            summary["recovered_wallets"] += 1
            entry.update({
                "status": "RECOVERED",
                "sha256": result["sha256"],
                "size": result["size"],
                "page_size": result["page_size"],
                "page_count": result["page_count"],
                "structural_status": result["structural_validation_status"],
                "record_counts": result["record_counts"],
                "crypto_valid_count": result["crypto_summary"]["crypto_valid_plain_keys"],
                "unique_crypto_valid_count": result["crypto_summary"][
                    "unique_crypto_valid_plain_keys"],
                "duplicate_count": result["crypto_summary"]["crypto_duplicate_occurrences"],
            })
        summary["outputs"].append(entry)
    return summary



def _publish_no_replace(temporary: Path, destination: Path) -> None:
    """Atomically publish a same-volume temporary without overwriting."""
    try:
        os.link(temporary, destination)
    except FileExistsError as error:
        raise ExportRefused("OUTPUT_EXISTS") from error
    except OSError as error:
        raise ExportRefused("ATOMIC_PUBLICATION_FAILURE") from error
    else:
        temporary.unlink()


def recover_intact_wallet(
    source: Path,
    report: dict,
    recovery_dir: Path,
    *,
    relative_prefix: Path = Path(),
) -> dict:
    """Copy one already validated intact wallet with post-copy verification."""
    source, recovery_dir = Path(source), Path(recovery_dir)
    validate_recovery_destination(source, recovery_dir)
    marker = report.get("intact_wallet", {})
    summary = _empty_summary(requested=True)
    family = marker.get("wallet_family")
    if not marker.get("detected") or family not in {"BITCOIN_CORE", "ELECTRUM"}:
        return summary
    family_dir = "bitcoin-core" if family == "BITCOIN_CORE" else "electrum"
    wallet_name = "wallet.dat" if family == "BITCOIN_CORE" else source.name
    relative = relative_prefix / family_dir / "intact" / wallet_name
    destination = recovery_dir / relative
    manifest = destination.with_name("recovery_manifest.json")
    entry = {
        "candidate_id": "INTACT_FILE",
        "relative_recovery_path": relative.as_posix(),
        "status": "REFUSED",
        "format": marker.get("format"),
        "encrypted": None,
    }
    summary["eligible_candidates"] = 1
    temporary = destination.with_name(f".{destination.name}.tmp-{uuid.uuid4().hex}")
    manifest_temporary = manifest.with_name(f".{manifest.name}.tmp-{uuid.uuid4().hex}")
    try:
        if os.path.lexists(destination) or os.path.lexists(manifest):
            raise ExportRefused("OUTPUT_EXISTS")
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        with source.open("rb") as src, temporary.open("xb") as dst:
            while True:
                block = src.read(1024 * 1024)
                if not block:
                    break
                dst.write(block)
                digest.update(block)
                size += len(block)
            dst.flush()
            os.fsync(dst.fileno())
        copied_digest = hashlib.sha256()
        with temporary.open("rb") as copied:
            prefix = copied.read(64)
            copied_digest.update(prefix)
            while True:
                block = copied.read(1024 * 1024)
                if not block:
                    break
                copied_digest.update(block)
        if copied_digest.hexdigest() != digest.hexdigest():
            raise ExportRefused("POST_COPY_HASH_MISMATCH")
        if family == "BITCOIN_CORE":
            from bfrs.validators.berkeley_metadata import BTREE_MAGIC, MAGIC_OFFSET
            magic = prefix[MAGIC_OFFSET:MAGIC_OFFSET + 4]
            if magic not in {
                BTREE_MAGIC.to_bytes(4, "little"),
                BTREE_MAGIC.to_bytes(4, "big"),
            }:
                raise ExportRefused("POST_COPY_BDB_VALIDATION_FAILED")
        manifest_payload = {
            "source_basename": source.name,
            "relative_recovery_path": relative.as_posix(),
            "format": marker.get("format"),
            "wallet_family": family,
            "reconstruction_method": "EXACT_INTACT_FILE_COPY",
            "post_copy_validation": (
                "HASH_AND_BDB_HEADER_VALID"
                if family == "BITCOIN_CORE"
                else "HASH_MATCH_AND_PREVALIDATED_FORMAT"
            ),
            "sha256": digest.hexdigest(),
            "size": size,
        }
        with manifest_temporary.open("x", encoding="utf-8", newline="\n") as out:
            json.dump(manifest_payload, out, indent=2, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        _publish_no_replace(temporary, destination)
        try:
            _publish_no_replace(manifest_temporary, manifest)
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    except ExportRefused as error:
        entry["reason_code"] = str(error)
        summary["failed_wallets"] = 1
    except OSError:
        entry["reason_code"] = "IO_OR_PUBLICATION_FAILURE"
        summary["failed_wallets"] = 1
    else:
        entry.update({
            "status": "RECOVERED",
            "sha256": digest.hexdigest(),
            "size": size,
            "structural_status": "INTACT_FILE_VALID",
            "reconstruction_method": "EXACT_INTACT_FILE_COPY",
        })
        summary["recovered_wallets"] = 1
    finally:
        temporary.unlink(missing_ok=True)
        manifest_temporary.unlink(missing_ok=True)
    summary["outputs"].append(entry)
    return summary
