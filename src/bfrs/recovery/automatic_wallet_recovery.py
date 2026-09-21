"""Conservative automatic exact-page recovery for accepted Bitcoin wallets."""
from __future__ import annotations

from pathlib import Path
import os

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


def _physical_start(candidate: dict) -> int:
    ranges = candidate.get("physical_image_ranges", ())
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


def recover_wallets(source: Path, report: dict, recovery_dir: Path) -> dict:
    """Recover every eligible candidate in deterministic physical-offset order.

    Eligibility is finally decided by the physical reconstructor. Refusals are
    represented only by fixed reason codes and never include record bytes.
    """
    source, recovery_dir = Path(source), Path(recovery_dir)
    validate_recovery_destination(source, recovery_dir)

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
