"""Revalidate legacy Electrum 2+ report occurrences against the current scanner."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sys
from typing import BinaryIO, Sequence

from bfrs.recovery.mnemonic.raw_mnemonic_scanner import RawMnemonicScanner


FORMAT = "BFRS_ELECTRUM2_REVALIDATION_V1"
DEFAULT_CONTEXT_BYTES = 4096
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024
MAX_CANDIDATE_SPAN = 64 * 1024


@dataclass(slots=True)
class _Occurrence:
    start: int | None
    end: int | None
    old_encodings: set[str] = field(default_factory=set)
    source_entries: int = 1
    status: str | None = None
    failure_reason: str | None = None
    current: dict[str, object] | None = None


@dataclass(slots=True)
class _Candidate:
    source: dict[str, object]
    occurrences: list[_Occurrence]
    occurrences_total: int
    duplicate_ranges: int


@dataclass(slots=True)
class _Window:
    start: int
    end: int
    ranges: list[tuple[int, int]]


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _old_encoding(value: object) -> str:
    return str(value) if isinstance(value, str) else "unknown"


def _candidate_occurrences(candidate: dict[str, object]) -> _Candidate:
    provenance = candidate.get("provenance")
    raw_entries = [item for item in provenance if isinstance(item, dict) and
                   item.get("source_kind") == "RAW_BYTES"] if isinstance(provenance, list) else []
    if not raw_entries and (candidate.get("source_kind") == "RAW_BYTES" or
                            "RAW_BYTES" in candidate.get("correlated_sources", [])):
        raw_entries = [{
            "physical_start": candidate.get("physical_start"),
            "physical_end": candidate.get("physical_end"),
            "encoding": candidate.get("encoding"),
            "source_kind": "RAW_BYTES",
        }]

    unique: dict[tuple[object, object], _Occurrence] = {}
    malformed: list[_Occurrence] = []
    for item in raw_entries:
        start = _integer(item.get("physical_start"))
        end = _integer(item.get("physical_end"))
        encoding = _old_encoding(item.get("encoding", candidate.get("encoding")))
        if start is None or end is None:
            malformed.append(_Occurrence(start, end, {encoding}, status="READ_FAILED",
                                         failure_reason="INVALID_PHYSICAL_RANGE"))
            continue
        key = (start, end)
        occurrence = unique.get(key)
        if occurrence is None:
            unique[key] = _Occurrence(start, end, {encoding})
        else:
            occurrence.old_encodings.add(encoding)
            occurrence.source_entries += 1
    occurrences = [*unique.values(), *malformed]
    occurrences.sort(key=lambda item: (
        item.start is None, item.start if item.start is not None else -1,
        item.end if item.end is not None else -1))
    return _Candidate(candidate, occurrences, len(raw_entries),
                      len(raw_entries) - len(occurrences))


def _extract_candidates(report: dict[str, object]) -> list[_Candidate]:
    recovery = report.get("mnemonic_recovery")
    payload = recovery.get("candidates") if isinstance(recovery, dict) else None
    if not isinstance(payload, list):
        raise ValueError("report has no mnemonic_recovery.candidates list")
    selected = [item for item in payload if isinstance(item, dict) and
                item.get("mnemonic_standard") == "ELECTRUM"]
    selected.sort(key=lambda item: (str(item.get("fingerprint", "")),
                                    str(item.get("candidate_id", ""))))
    return [_candidate_occurrences(item) for item in selected]


def _validate_ranges(candidates: list[_Candidate], image_size: int
                     ) -> dict[tuple[int, int], list[tuple[_Candidate, _Occurrence]]]:
    ranges: dict[tuple[int, int], list[tuple[_Candidate, _Occurrence]]] = {}
    for candidate in candidates:
        for occurrence in candidate.occurrences:
            if occurrence.status is not None:
                continue
            assert occurrence.start is not None and occurrence.end is not None
            if (occurrence.start < 0 or occurrence.end <= occurrence.start or
                    occurrence.end > image_size or
                    occurrence.end - occurrence.start > MAX_CANDIDATE_SPAN):
                occurrence.status = "READ_FAILED"
                occurrence.failure_reason = "INVALID_PHYSICAL_RANGE"
                continue
            ranges.setdefault((occurrence.start, occurrence.end), []).append(
                (candidate, occurrence))
    return ranges


def _plan_windows(ranges: Sequence[tuple[int, int]], image_size: int,
                  context_bytes: int, max_window_bytes: int) -> list[_Window]:
    requested = []
    for start, end in sorted(ranges):
        window_start = max(0, start - context_bytes)
        window_start -= window_start % 2
        window_end = min(image_size, end + context_bytes)
        if window_end < image_size and window_end % 2:
            window_end += 1
        requested.append((window_start, window_end, (start, end)))
    windows: list[_Window] = []
    for start, end, physical_range in requested:
        if end - start > max_window_bytes:
            raise ValueError("context produces a window larger than max-window-bytes")
        if windows and start <= windows[-1].end and end - windows[-1].start <= max_window_bytes:
            windows[-1].end = max(windows[-1].end, end)
            windows[-1].ranges.append(physical_range)
        else:
            windows.append(_Window(start, end, [physical_range]))
    return windows


def _scan_windows(stream: BinaryIO, image: Path, windows: list[_Window],
                  references: dict[tuple[int, int], list[tuple[_Candidate, _Occurrence]]],
                  scanner: RawMnemonicScanner) -> tuple[int, int]:
    windows_read = bytes_read = 0
    for window in windows:
        try:
            stream.seek(window.start)
            data = stream.read(window.end - window.start)
            if len(data) != window.end - window.start:
                raise OSError("short image read")
        except OSError as error:
            for physical_range in window.ranges:
                for _, occurrence in references[physical_range]:
                    occurrence.status = "READ_FAILED"
                    occurrence.failure_reason = type(error).__name__
            continue
        windows_read += 1
        bytes_read += len(data)
        result = scanner.scan_bytes(data, source=str(image), base_offset=window.start)
        current: dict[tuple[int, int, str], list[dict[str, object]]] = {}
        for item in result.occurrences:
            candidate = item.candidate
            if candidate.mnemonic_standard != "ELECTRUM":
                continue
            key = (candidate.physical_start, candidate.physical_end,
                   candidate.fingerprint)
            current.setdefault(key, []).append(candidate.safe_dict())
        for physical_range in window.ranges:
            start, end = physical_range
            for candidate, occurrence in references[physical_range]:
                fingerprint = str(candidate.source.get("fingerprint", ""))
                matches = current.get((start, end, fingerprint), [])
                if matches:
                    matches.sort(key=lambda item: str(item.get("encoding", "")))
                    occurrence.status = "SURVIVED"
                    occurrence.current = matches[0]
                else:
                    occurrence.status = "REJECTED_NO_CURRENT_MATCH"
    return windows_read, bytes_read


def _known_correlation(candidate: dict[str, object]) -> bool:
    correlated = candidate.get("correlated_sources", [])
    if isinstance(correlated, list) and any(item != "RAW_BYTES" for item in correlated):
        return True
    provenance = candidate.get("provenance", [])
    return isinstance(provenance, list) and any(
        isinstance(item, dict) and item.get("source_kind") not in {None, "RAW_BYTES"}
        for item in provenance)


def _priority(candidate: _Candidate, survived: int) -> str | None:
    if not survived:
        return None
    duplicate_count = _integer(candidate.source.get("duplicate_count")) or 1
    if _known_correlation(candidate.source) or (
            duplicate_count == 1 and len(candidate.occurrences) <= 3):
        return "HIGH_REVIEW"
    if duplicate_count <= 25 and len(candidate.occurrences) <= 25:
        return "MEDIUM_REVIEW"
    return "LOW_REVIEW"


def _occurrence_dict(occurrence: _Occurrence) -> dict[str, object]:
    result: dict[str, object] = {
        "physical_start": occurrence.start,
        "physical_end": occurrence.end,
        "old_encoding": sorted(occurrence.old_encodings)[0],
        "status": occurrence.status,
    }
    if len(occurrence.old_encodings) > 1:
        result["old_encodings"] = sorted(occurrence.old_encodings)
    if occurrence.failure_reason is not None:
        result["failure_reason"] = occurrence.failure_reason
    if occurrence.current is not None:
        current = occurrence.current
        result.update({
            "new_encoding": current.get("encoding"),
            "validation_status": current.get("validation_status"),
            "seed_type": current.get("seed_type"),
            "word_count": current.get("word_count"),
            "reason_codes": current.get("reason_codes", []),
        })
    return result


def _candidate_dict(candidate: _Candidate) -> dict[str, object]:
    survived = sum(item.status == "SURVIVED" for item in candidate.occurrences)
    rejected = sum(item.status == "REJECTED_NO_CURRENT_MATCH"
                   for item in candidate.occurrences)
    failures = sum(item.status == "READ_FAILED" for item in candidate.occurrences)
    checked = survived + rejected
    if survived and (rejected or failures):
        status = "PARTIAL"
    elif survived:
        status = "SURVIVED"
    else:
        status = "REJECTED"
    source = candidate.source
    result: dict[str, object] = {
        "candidate_id": source.get("candidate_id"),
        "fingerprint": source.get("fingerprint"),
        "mnemonic_standard": "ELECTRUM",
        "old_seed_type": source.get("seed_type"),
        "old_word_count": source.get("word_count"),
        "duplicate_count": source.get("duplicate_count", 1),
        "status": status,
        "occurrences_total": candidate.occurrences_total,
        "occurrences_unique": len(candidate.occurrences),
        "occurrences_deduplicated": candidate.duplicate_ranges,
        "occurrences_checked": checked,
        "occurrences_survived": survived,
        "occurrences_rejected": rejected,
        "read_failures": failures,
        "occurrences": [_occurrence_dict(item) for item in candidate.occurrences],
    }
    priority = _priority(candidate, survived)
    if priority is not None:
        result["revalidation_priority"] = priority
    return result


def _distribution(candidates: list[dict[str, object]]) -> dict[str, object]:
    survived_candidates = [item for item in candidates
                           if item["status"] in {"SURVIVED", "PARTIAL"}]
    survived_occurrences = [occurrence for item in survived_candidates
                            for occurrence in item["occurrences"]
                            if occurrence["status"] == "SURVIVED"]
    count = lambda values: dict(sorted(Counter(str(value) for value in values).items()))
    return {
        "survived_occurrences_by_encoding": count(
            item.get("new_encoding") for item in survived_occurrences),
        "survived_candidates_by_word_count": count(
            item.get("old_word_count") for item in survived_candidates),
        "survived_occurrences_by_seed_type": count(
            item.get("seed_type") for item in survived_occurrences),
        "survived_candidates_by_duplicate_count": count(
            item.get("duplicate_count", 1) for item in survived_candidates),
        "survived_candidates_by_occurrence_count": count(
            item.get("occurrences_unique", 0) for item in survived_candidates),
        "survived_candidates_by_priority": count(
            item.get("revalidation_priority") for item in survived_candidates),
    }


def revalidate_report(report: dict[str, object], image: str | Path, *,
                      context_bytes: int = DEFAULT_CONTEXT_BYTES,
                      max_window_bytes: int = DEFAULT_MAX_WINDOW_BYTES,
                      scanner: RawMnemonicScanner | None = None) -> dict[str, object]:
    if context_bytes < 0:
        raise ValueError("context-bytes must be nonnegative")
    if max_window_bytes <= 0 or 2 * context_bytes + MAX_CANDIDATE_SPAN > max_window_bytes:
        raise ValueError("max-window-bytes is too small for context and candidate limit")
    image_path = Path(image).resolve()
    candidates = _extract_candidates(report)
    scanner = scanner or RawMnemonicScanner()
    with image_path.open("rb") as stream:
        image_size = os.fstat(stream.fileno()).st_size
        references = _validate_ranges(candidates, image_size)
        windows = _plan_windows(tuple(references), image_size, context_bytes,
                                max_window_bytes)
        windows_read, bytes_read = _scan_windows(
            stream, image_path, windows, references, scanner)
    results = [_candidate_dict(item) for item in candidates]
    summary: dict[str, object] = {
        "input_candidates": len(results),
        "input_occurrences": sum(item.occurrences_total for item in candidates),
        "unique_occurrences": sum(item["occurrences_unique"] for item in results),
        "deduplicated_occurrences": sum(item["occurrences_deduplicated"] for item in results),
        "occurrences_checked": sum(item["occurrences_checked"] for item in results),
        "survived_candidates": sum(item["status"] == "SURVIVED" for item in results),
        "rejected_candidates": sum(item["status"] == "REJECTED" for item in results),
        "partial_candidates": sum(item["status"] == "PARTIAL" for item in results),
        "survived_occurrences": sum(item["occurrences_survived"] for item in results),
        "rejected_occurrences": sum(item["occurrences_rejected"] for item in results),
        "read_failures": sum(item["read_failures"] for item in results),
        "io_windows_planned": len(windows),
        "io_windows_read": windows_read,
        "image_bytes_read": bytes_read,
        **_distribution(results),
    }
    return {
        "format": FORMAT,
        "configuration": {
            "report_standard_filter": "ELECTRUM",
            "context_bytes": context_bytes,
            "max_window_bytes": max_window_bytes,
            "matching_rule": "fingerprint_and_exact_physical_span",
        },
        "source": {"image": str(image_path), "size": image_size},
        "candidates": results,
        "summary": summary,
    }


def write_report(payload: dict[str, object], output: str | Path) -> None:
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m bfrs.tools.revalidate_electrum_candidates",
        description=__doc__,
    )
    parser.add_argument("--report", required=True, type=Path,
                        help="legacy BFRS JSON report")
    parser.add_argument("--image", required=True, type=Path,
                        help="source image opened read-only")
    parser.add_argument("--output", required=True, type=Path,
                        help="secret-free revalidation JSON")
    parser.add_argument("--context-bytes", type=int, default=DEFAULT_CONTEXT_BYTES)
    parser.add_argument("--max-window-bytes", type=int,
                        default=DEFAULT_MAX_WINDOW_BYTES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        report = json.loads(arguments.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report root must be an object")
        result = revalidate_report(
            report, arguments.image, context_bytes=arguments.context_bytes,
            max_window_bytes=arguments.max_window_bytes)
        write_report(result, arguments.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Electrum revalidation failed: {error}", file=sys.stderr)
        return 2
    summary = result["summary"]
    print(f"input candidates: {summary['input_candidates']}")
    print(f"input RAW occurrences: {summary['input_occurrences']}")
    print(f"survived/partial/rejected candidates: "
          f"{summary['survived_candidates']}/{summary['partial_candidates']}/"
          f"{summary['rejected_candidates']}")
    print(f"image bytes read: {summary['image_bytes_read']}")
    print(f"safe report: {arguments.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
