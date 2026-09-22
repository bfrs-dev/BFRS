"""Recursive regular-file source orchestration for P2.7."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid
from typing import Callable, Sequence

from bfrs.recovery.automatic_wallet_recovery import (
    recover_intact_wallet,
    recover_wallets,
    recovery_not_requested,
    validate_recovery_destination,
)
from bfrs.reporting.json_report import REPORT_SCHEMA_VERSION
from bfrs.version import APP_NAME, VERSION


def _is_junction(path: Path) -> bool:
    predicate = getattr(path, "is_junction", None)
    return bool(predicate and predicate())


def discover_regular_files(root: Path) -> tuple[list[tuple[Path, int, int]], list[dict]]:
    """Discover regular files without following links or directory reparse points."""
    files: list[tuple[Path, int, int]] = []
    skipped: list[dict] = []
    pending = [root]
    visited: set[tuple[int, int]] = set()
    while pending:
        directory = pending.pop()
        try:
            identity = directory.stat(follow_symlinks=False)
            key = (identity.st_dev, identity.st_ino)
            if key in visited:
                skipped.append({"path": str(directory), "reason": "DIRECTORY_LOOP"})
                continue
            visited.add(key)
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name.casefold())
        except OSError as error:
            skipped.append({"path": str(directory), "reason": type(error).__name__})
            continue
        try:
            for entry in entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink() or _is_junction(path):
                        skipped.append({"path": str(path), "reason": "LINK_NOT_FOLLOWED"})
                    elif entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        stat = entry.stat(follow_symlinks=False)
                        files.append((path, stat.st_size, stat.st_mtime_ns))
                    else:
                        skipped.append({"path": str(path), "reason": "NOT_REGULAR_FILE"})
                except OSError as error:
                    skipped.append({"path": str(path), "reason": type(error).__name__})
        finally:
            entries.clear()
    files.sort(key=lambda item: str(item[0]).casefold())
    return files, skipped


def _child_arguments(arguments, source: Path, output: Path) -> list[str]:
    values = [
        "--input", str(source), "--output", str(output),
        "--source-type", "file",
        "--chunk-mib", str(arguments.chunk_mib),
        "--overlap-kib", str(arguments.overlap_kib),
        "--cluster-mib", str(arguments.cluster_mib),
        "--padding-mib", str(arguments.padding_mib),
        "--minimum-hits", str(arguments.minimum_hits),
        "--minimum-distinct-types", str(arguments.minimum_distinct_types),
        "--workers", str(arguments.workers),
    ]
    if arguments.targets is not None:
        values += ["--targets", arguments.targets]
    for enabled, flag in (
        (arguments.electrum_only, "--electrum-only"),
        (arguments.seed_scan_only, "--seed-scan-only"),
        (arguments.include_mnemonic, "--include-mnemonic"),
        (arguments.include_bitcoin_context, "--include-bitcoin-context"),
        (arguments.skip_mnemonic, "--skip-mnemonic"),
    ):
        if enabled:
            values.append(flag)
    return values


def _merge_recovery(total: dict, current: dict, prefix: Path) -> None:
    for name in ("eligible_candidates", "recovered_wallets", "failed_wallets"):
        total[name] += int(current.get(name, 0))
    for item in current.get("outputs", []):
        row = dict(item)
        relative = row.get("relative_recovery_path")
        if isinstance(relative, str):
            row["relative_recovery_path"] = (prefix / relative).as_posix()
        total["outputs"].append(row)


def scan_folder_source(
    arguments,
    child_main: Callable[[Sequence[str] | None], int],
) -> int:
    root = arguments.input.resolve()
    files, discovery_skips = discover_regular_files(root)
    print(
        f"Folder scan: files discovered={len(files)} files scanned=0 "
        f"files skipped={len(discovery_skips)} bytes scanned=0 findings=0",
        file=sys.stderr,
    )
    file_rows = []
    flattened_findings = []
    scanned = bytes_scanned = findings = 0
    scan_failures = []
    wallet_recovery = recovery_not_requested()
    if arguments.recover_wallets:
        validate_recovery_destination(root, arguments.recovery_dir)
        wallet_recovery = {
            "requested": True, "eligible_candidates": 0,
            "recovered_wallets": 0, "failed_wallets": 0, "outputs": [],
        }
    with tempfile.TemporaryDirectory(prefix="bfrs-folder-scan-") as temporary:
        temporary_root = Path(temporary)
        for index, (source, size, mtime_ns) in enumerate(files, 1):
            child_report_path = temporary_root / f"report-{index:06d}.json"
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = child_main(_child_arguments(arguments, source, child_report_path))
                if code != 0:
                    raise OSError(f"CHILD_SCAN_EXIT_{code}")
                child_report = json.loads(child_report_path.read_text(encoding="utf-8"))
                child_findings = child_report.get("target_findings", [])
                if not isinstance(child_findings, list):
                    raise ValueError("INVALID_CHILD_REPORT")
                flattened_findings.extend(child_findings)
                findings += len(child_findings)
                scanned += 1
                bytes_scanned += size
                intact = child_report.get("intact_wallet", {})
                wallet_targets = {"bitcoin-core", "electrum", "multibit", "armory"}
                wallet_detected = bool(intact.get("detected")) or any(
                    row.get("target") in wallet_targets for row in child_findings
                )
                if arguments.recover_wallets:
                    prefix = Path(f"file_{index:06d}")
                    per_file_root = arguments.recovery_dir / prefix
                    if intact.get("detected"):
                        recovered = recover_intact_wallet(
                            source, child_report, arguments.recovery_dir,
                            relative_prefix=prefix,
                        )
                        _merge_recovery(wallet_recovery, recovered, Path())
                    else:
                        recovered = recover_wallets(
                            source, child_report, per_file_root
                        )
                        _merge_recovery(wallet_recovery, recovered, prefix)
                file_rows.append({
                    "file_path": str(source.resolve()),
                    "size": size,
                    "mtime_ns": mtime_ns,
                    "status": "SCANNED",
                    "finding_count": len(child_findings),
                    "wallet_detected": wallet_detected,
                    "intact_wallet": intact,
                    "report": child_report,
                })
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
                scan_failures.append({
                    "file_path": str(source.resolve(strict=False)),
                    "reason": type(error).__name__,
                })
                file_rows.append({
                    "file_path": str(source.resolve(strict=False)),
                    "size": size,
                    "mtime_ns": mtime_ns,
                    "status": "SKIPPED",
                    "reason": type(error).__name__,
                })
            print(
                f"Folder scan: files discovered={len(files)} files scanned={scanned} "
                f"files skipped={len(discovery_skips) + len(scan_failures)} "
                f"bytes scanned={bytes_scanned} current file={source} findings={findings}",
                file=sys.stderr,
            )
    payload = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "application": {"name": APP_NAME, "version": VERSION},
        "source_type": "FOLDER",
        "source_root": str(root),
        "location_model": {
            "offset_kind": "file_offset",
            "identity": ["file_path", "file_offset"],
        },
        "file_count": len(files),
        "files_discovered": len(files),
        "files_scanned": scanned,
        "files_skipped": len(discovery_skips) + len(scan_failures),
        "bytes_scanned": bytes_scanned,
        "findings_count": findings,
        "files": file_rows,
        "target_findings": flattened_findings,
        "skipped_entries": discovery_skips + scan_failures,
        "wallet_recovery": wallet_recovery,
        "scanner_semantics": {
            "recursive": True,
            "regular_files_only": True,
            "follow_links": False,
            "file_filter": "ALL_REGULAR_FILES",
            "chunk_mib": arguments.chunk_mib,
            "overlap_kib": arguments.overlap_kib,
            "targets": arguments.targets or "default",
        },
        "checkpoint": {
            "supported": False,
            "status": "DEFERRED_TO_P2.7.1",
            "image_checkpoint_unchanged": True,
        },
    }
    output = arguments.output
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_name(f".{output.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary_output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_output, output)
    except OSError as error:
        temporary_output.unlink(missing_ok=True)
        print(f"report error: {error}", file=sys.stderr)
        return 4
    print(f"source type: FOLDER")
    print(f"source root: {root}")
    print(f"files discovered: {len(files)}")
    print(f"files scanned: {scanned}")
    print(f"files skipped: {len(discovery_skips) + len(scan_failures)}")
    print(f"bytes scanned: {bytes_scanned}")
    print(f"findings: {findings}")
    print(f"wallets detected: {sum(bool(row.get('wallet_detected')) for row in file_rows)}")
    print(f"report path: {output.resolve()}")
    return 0
