"""Classify local context for selected, already-revalidated Electrum 2+ hits."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import sys
from typing import BinaryIO, Callable, ContextManager, Sequence

from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.mnemonic_normalizer import electrum_normalize


FORMAT = "BFRS_ELECTRUM_CONTEXT_ANALYSIS_V1"
DEFAULT_CONTEXT_BYTES = 64 * 1024
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024
MAX_OCCURRENCE_SPAN = 64 * 1024
DENSITY_RADIUS = 8 * 1024
_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")

_KEYWORDS = (
    "seed", "seed_version", "wallet_type", "keystore", "master_public_key",
    "master_public_keys", "xpub", "xprv", "accounts", "receiving", "change",
    "electrum", "seed_type",
)
_HTML_MARKERS = ("<!doctype", "<html", "<script", "<style", "</body>", "</html>")
_JAVASCRIPT_PATTERN = re.compile(r"\b(?:function|var|const|let)\b|document\.|window\.")
_CSS_PROPERTY_PATTERN = re.compile(
    r"\b(?:background|border|color|display|font|height|margin|padding|width)"
    r"(?:-[a-z]+)*\s*:")
_CSS_SELECTOR_PATTERN = re.compile(r"(?:^|[}\s])(?:\.[a-z_-][\w-]*|#[a-z_-][\w-]*)\s*{")
_DOCUMENTATION_MARKERS = (
    "documentation", "example seed", "mnemonic example", "sample seed",
    "technical reference", "tutorial", "word list", "wordlist", "thesaurus",
)
_CORE_ELECTRUM_REASONS = {
    "ELECTRUM_KEYSTORE_SIGNAL", "ELECTRUM_WALLET_TYPE_SIGNAL",
    "ELECTRUM_MASTER_PUBLIC_KEY_SIGNAL", "ELECTRUM_SEED_METADATA_SIGNAL",
}
_FALSE_POSITIVE_REASONS = {
    "HTML_CONTEXT", "CSS_CONTEXT", "JAVASCRIPT_CONTEXT",
    "DOCUMENTATION_CONTEXT", "WORDLIST_CONTEXT",
    "HIGH_LOCAL_MNEMONIC_DENSITY", "OVERLAPPING_MNEMONIC_CANDIDATES",
}


@dataclass(slots=True)
class _Occurrence:
    candidate_id: str
    fingerprint: str
    encoding: str
    word_count: int
    physical_start: int | None
    physical_end: int | None
    source: dict[str, object]
    context_start: int | None = None
    context_end: int | None = None
    classification: str | None = None
    reason_codes: set[str] = field(default_factory=set)
    artifacts: set[str] = field(default_factory=set)
    nearby_count: int = 0
    nearest_distance: int | None = None
    overlapping_count: int = 0
    local_density: float = 0.0

    @property
    def identity(self) -> tuple[str, str, int | None, int | None]:
        return (self.candidate_id, self.fingerprint,
                self.physical_start, self.physical_end)


@dataclass(slots=True)
class _Candidate:
    candidate_id: str
    fingerprint: str
    source: dict[str, object]
    occurrences: list[_Occurrence]


@dataclass(slots=True)
class _Window:
    start: int
    end: int
    occurrences: list[_Occurrence]


StreamFactory = Callable[[Path], ContextManager[BinaryIO]]


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _select(report: dict[str, object]) -> tuple[int, list[_Candidate]]:
    payload = report.get("candidates")
    if not isinstance(payload, list):
        raise ValueError("context input has no candidates list")
    selected: list[_Candidate] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()
    for item in payload:
        if not isinstance(item, dict) or item.get("mnemonic_standard") != "ELECTRUM":
            continue
        if item.get("revalidation_priority") != "HIGH_REVIEW":
            continue
        candidate_id = str(item.get("candidate_id", ""))
        fingerprint = str(item.get("fingerprint", ""))
        occurrences = []
        source_occurrences = item.get("occurrences", [])
        if not isinstance(source_occurrences, list):
            continue
        for occurrence in source_occurrences:
            if not isinstance(occurrence, dict):
                continue
            word_count = _integer(occurrence.get("word_count"))
            if (occurrence.get("status") != "SURVIVED" or
                    occurrence.get("validation_status") != "ELECTRUM_SEED_VALID" or
                    word_count not in {12, 13}):
                continue
            selected_occurrence = _Occurrence(
                candidate_id=candidate_id,
                fingerprint=fingerprint,
                encoding=str(occurrence.get("new_encoding") or
                             occurrence.get("old_encoding") or "unknown"),
                word_count=word_count,
                physical_start=_integer(occurrence.get("physical_start")),
                physical_end=_integer(occurrence.get("physical_end")),
                source=occurrence,
            )
            if selected_occurrence.identity in seen:
                continue
            seen.add(selected_occurrence.identity)
            occurrences.append(selected_occurrence)
        if occurrences:
            occurrences.sort(key=lambda value: (
                value.physical_start is None,
                value.physical_start if value.physical_start is not None else -1,
                value.physical_end if value.physical_end is not None else -1))
            selected.append(_Candidate(candidate_id, fingerprint, item, occurrences))
    selected.sort(key=lambda value: (value.fingerprint, value.candidate_id))
    return len(payload), selected


def _prepare_occurrences(candidates: list[_Candidate], image_size: int,
                         context_bytes: int) -> list[_Occurrence]:
    valid = []
    for candidate in candidates:
        for occurrence in candidate.occurrences:
            start, end = occurrence.physical_start, occurrence.physical_end
            if (start is None or end is None or start < 0 or end <= start or
                    end > image_size or end - start > MAX_OCCURRENCE_SPAN):
                occurrence.classification = "READ_FAILED"
                occurrence.reason_codes.add("READ_FAILURE")
                continue
            context_start = max(0, start - context_bytes)
            context_start -= context_start % 2
            context_end = min(image_size, end + context_bytes)
            if context_end < image_size and context_end % 2:
                context_end += 1
            occurrence.context_start = context_start
            occurrence.context_end = context_end
            valid.append(occurrence)
    return valid


def _plan_windows(occurrences: list[_Occurrence], max_window_bytes: int) -> list[_Window]:
    ordered = sorted(occurrences, key=lambda item: (
        item.context_start, item.context_end, item.fingerprint, item.candidate_id))
    windows: list[_Window] = []
    for occurrence in ordered:
        assert occurrence.context_start is not None and occurrence.context_end is not None
        start, end = occurrence.context_start, occurrence.context_end
        if end - start > max_window_bytes:
            raise ValueError("context produces a window larger than max-window-bytes")
        if windows and start <= windows[-1].end and end - windows[-1].start <= max_window_bytes:
            windows[-1].end = max(windows[-1].end, end)
            windows[-1].occurrences.append(occurrence)
        else:
            windows.append(_Window(start, end, [occurrence]))
    return windows


def _distance(left: _Occurrence, right: _Occurrence) -> int:
    assert left.physical_start is not None and left.physical_end is not None
    assert right.physical_start is not None and right.physical_end is not None
    if left.physical_start < right.physical_end and right.physical_start < left.physical_end:
        return 0
    if left.physical_end <= right.physical_start:
        return right.physical_start - left.physical_end
    return left.physical_start - right.physical_end


def _density(occurrences: list[_Occurrence]) -> None:
    for occurrence in occurrences:
        others = [item for item in occurrences
                  if item.fingerprint != occurrence.fingerprint]
        distances = [_distance(occurrence, item) for item in others]
        occurrence.nearest_distance = min(distances) if distances else None
        occurrence.nearby_count = sum(distance <= DENSITY_RADIUS for distance in distances)
        occurrence.overlapping_count = sum(distance == 0 for distance in distances)
        occurrence.local_density = round(
            (occurrence.nearby_count + 1) / (2 * DENSITY_RADIUS / 1024), 6)
        if occurrence.overlapping_count:
            occurrence.reason_codes.add("OVERLAPPING_MNEMONIC_CANDIDATES")
        if occurrence.nearby_count >= 4 or occurrence.overlapping_count:
            occurrence.reason_codes.add("HIGH_LOCAL_MNEMONIC_DENSITY")


def _wordlist_metrics(text: str, words: frozenset[str]) -> tuple[int, int, int]:
    matches = list(_TOKEN.finditer(text))
    total_members = longest_run = run = 0
    previous_end: int | None = None
    for match in matches:
        normalized = electrum_normalize(match.group(0))
        member = normalized in words
        separator = "" if previous_end is None else text[previous_end:match.start()]
        if member:
            total_members += 1
            run = run + 1 if previous_end is not None and separator.isspace() else 1
            longest_run = max(longest_run, run)
        else:
            run = 0
        previous_end = match.end()
    return total_members, longest_run, len(matches)


def _analyze_context(data: bytes, occurrence: _Occurrence,
                     wordlist: frozenset[str]) -> None:
    reasons = set(occurrence.reason_codes)
    artifacts: set[str] = set()
    max_wordlist_members = max_wordlist_run = max_tokens = 0
    for encoding in _ENCODINGS:
        text = data.decode(encoding, errors="ignore").casefold()
        for keyword in _KEYWORDS:
            if re.search(rf"(?<![\w]){re.escape(keyword)}(?![\w])", text):
                artifacts.add(keyword)
        if any(marker in text for marker in _HTML_MARKERS):
            reasons.add("HTML_CONTEXT")
        if _JAVASCRIPT_PATTERN.search(text):
            reasons.add("JAVASCRIPT_CONTEXT")
        css_property = bool(_CSS_PROPERTY_PATTERN.search(text))
        css_selector = bool(_CSS_SELECTOR_PATTERN.search(text))
        if css_property or css_selector or (
                text.count(";") >= 4 and text.count("{") + text.count("}") >= 2):
            reasons.add("CSS_CONTEXT")
        if any(marker in text for marker in _DOCUMENTATION_MARKERS):
            reasons.add("DOCUMENTATION_CONTEXT")
        members, longest, tokens = _wordlist_metrics(text, wordlist)
        max_wordlist_members = max(max_wordlist_members, members)
        max_wordlist_run = max(max_wordlist_run, longest)
        max_tokens = max(max_tokens, tokens)

    if max_wordlist_run >= 24 or (
            max_wordlist_members >= 48 and max_tokens and
            max_wordlist_members / max_tokens >= 0.75):
        reasons.add("WORDLIST_CONTEXT")
    if "wallet_type" in artifacts:
        reasons.add("ELECTRUM_WALLET_TYPE_SIGNAL")
    if "keystore" in artifacts:
        reasons.add("ELECTRUM_KEYSTORE_SIGNAL")
    if {"master_public_key", "master_public_keys", "xpub", "xprv"} & artifacts:
        reasons.add("ELECTRUM_MASTER_PUBLIC_KEY_SIGNAL")
    if {"seed_version", "seed_type"} & artifacts:
        reasons.add("ELECTRUM_SEED_METADATA_SIGNAL")
    if ({"accounts", "receiving", "change"} & artifacts and
            ("electrum" in artifacts or reasons & _CORE_ELECTRUM_REASONS)):
        reasons.add("ELECTRUM_WALLET_STRUCTURE_SIGNAL")

    false_positive = bool(reasons & _FALSE_POSITIVE_REASONS)
    core_count = len(reasons & _CORE_ELECTRUM_REASONS)
    if false_positive:
        occurrence.classification = "TEXTUAL_FALSE_POSITIVE"
    elif core_count >= 2:
        occurrence.classification = "ELECTRUM_CONTEXT_CONFIRMED"
    else:
        occurrence.classification = "INCONCLUSIVE"
        reasons.add("NO_ELECTRUM_CONTEXT" if core_count == 0 else
                    "INSUFFICIENT_ELECTRUM_CONTEXT")
    occurrence.reason_codes = reasons
    occurrence.artifacts = artifacts


def _read_windows(stream: BinaryIO, windows: list[_Window],
                  wordlist: frozenset[str]) -> tuple[int, int]:
    windows_read = bytes_read = 0
    for window in windows:
        try:
            stream.seek(window.start)
            data = stream.read(window.end - window.start)
            if len(data) != window.end - window.start:
                raise OSError("short image read")
        except OSError:
            for occurrence in window.occurrences:
                occurrence.classification = "READ_FAILED"
                occurrence.reason_codes.add("READ_FAILURE")
            continue
        windows_read += 1
        bytes_read += len(data)
        for occurrence in window.occurrences:
            assert occurrence.context_start is not None and occurrence.context_end is not None
            local_start = occurrence.context_start - window.start
            local_end = occurrence.context_end - window.start
            _analyze_context(data[local_start:local_end], occurrence, wordlist)
    return windows_read, bytes_read


def _occurrence_dict(occurrence: _Occurrence) -> dict[str, object]:
    return {
        "candidate_id": occurrence.candidate_id,
        "fingerprint": occurrence.fingerprint,
        "physical_start": occurrence.physical_start,
        "physical_end": occurrence.physical_end,
        "encoding": occurrence.encoding,
        "word_count": occurrence.word_count,
        "classification": occurrence.classification,
        "reason_codes": sorted(occurrence.reason_codes),
        "detected_artifacts": sorted(occurrence.artifacts),
        "context_bytes_requested": (
            occurrence.context_end - occurrence.context_start
            if occurrence.context_start is not None and occurrence.context_end is not None else 0),
        "nearby_survived_candidate_count": occurrence.nearby_count,
        "nearest_candidate_distance": occurrence.nearest_distance,
        "overlapping_candidate_count": occurrence.overlapping_count,
        "local_candidate_density": occurrence.local_density,
    }


def _candidate_dict(candidate: _Candidate) -> dict[str, object]:
    classes = Counter(item.classification for item in candidate.occurrences)
    if len(classes) == 1:
        classification = next(iter(classes))
    else:
        classification = "INCONCLUSIVE"
    return {
        "candidate_id": candidate.candidate_id,
        "fingerprint": candidate.fingerprint,
        "mnemonic_standard": "ELECTRUM",
        "revalidation_priority": "HIGH_REVIEW",
        "classification": classification,
        "occurrence_classification_distribution": dict(sorted(classes.items())),
        "occurrences": [_occurrence_dict(item) for item in candidate.occurrences],
    }


def _wordlist() -> frozenset[str]:
    electrum = ElectrumSeedValidator()
    bip39 = BIP39Validator()
    return frozenset(word for values in (*electrum.wordlists.values(),
                                         *bip39.wordlists.values()) for word in values)


def analyze_report(report: dict[str, object], image: str | Path, *,
                   context_bytes: int = DEFAULT_CONTEXT_BYTES,
                   max_window_bytes: int = DEFAULT_MAX_WINDOW_BYTES,
                   stream_factory: StreamFactory | None = None) -> dict[str, object]:
    if context_bytes < 0:
        raise ValueError("context-bytes must be nonnegative")
    if max_window_bytes <= 0 or 2 * context_bytes + MAX_OCCURRENCE_SPAN > max_window_bytes:
        raise ValueError("max-window-bytes is too small for context and occurrence limit")
    image_path = Path(image).resolve()
    image_size = image_path.stat().st_size
    input_candidates, candidates = _select(report)
    occurrences = [item for candidate in candidates for item in candidate.occurrences]
    readable = _prepare_occurrences(candidates, image_size, context_bytes)
    _density(readable)
    windows = _plan_windows(readable, max_window_bytes)
    factory = stream_factory or (lambda path: path.open("rb"))
    with factory(image_path) as stream:
        windows_read, bytes_read = _read_windows(stream, windows, _wordlist())
    results = [_candidate_dict(candidate) for candidate in candidates]
    occurrence_classes = Counter(item.classification for item in occurrences)
    candidate_classes = Counter(item["classification"] for item in results)
    reasons = Counter(reason for item in occurrences for reason in item.reason_codes)
    summary = {
        "input_candidates": input_candidates,
        "selected_candidates": len(candidates),
        "selected_occurrences": len(occurrences),
        "confirmed_candidates": candidate_classes["ELECTRUM_CONTEXT_CONFIRMED"],
        "false_positive_candidates": candidate_classes["TEXTUAL_FALSE_POSITIVE"],
        "inconclusive_candidates": candidate_classes["INCONCLUSIVE"],
        "read_failed_candidates": candidate_classes["READ_FAILED"],
        "confirmed_occurrences": occurrence_classes["ELECTRUM_CONTEXT_CONFIRMED"],
        "false_positive_occurrences": occurrence_classes["TEXTUAL_FALSE_POSITIVE"],
        "inconclusive_occurrences": occurrence_classes["INCONCLUSIVE"],
        "read_failures": occurrence_classes["READ_FAILED"],
        "io_windows_planned": len(windows),
        "io_windows_read": windows_read,
        "image_bytes_read": bytes_read,
        "candidate_classification_distribution": dict(sorted(candidate_classes.items())),
        "occurrence_classification_distribution": dict(sorted(occurrence_classes.items())),
        "reason_code_distribution": dict(sorted(reasons.items())),
    }
    return {
        "format": FORMAT,
        "configuration": {
            "priority_filter": "HIGH_REVIEW",
            "standard_filter": "ELECTRUM",
            "word_counts": [12, 13],
            "context_bytes": context_bytes,
            "max_window_bytes": max_window_bytes,
            "density_radius_bytes": DENSITY_RADIUS,
        },
        "source": {"image": str(image_path), "size": image_size},
        "summary": summary,
        "candidates": results,
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
        prog="python -m bfrs.tools.analyze_electrum_candidate_context",
        description=__doc__,
    )
    parser.add_argument("--report", required=True, type=Path,
                        help="Electrum 2+ revalidation JSON")
    parser.add_argument("--image", required=True, type=Path,
                        help="source image opened once and read-only")
    parser.add_argument("--output", required=True, type=Path,
                        help="secret-free context analysis JSON")
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
        result = analyze_report(
            report, arguments.image, context_bytes=arguments.context_bytes,
            max_window_bytes=arguments.max_window_bytes)
        write_report(result, arguments.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Electrum context analysis failed: {error}", file=sys.stderr)
        return 2
    summary = result["summary"]
    print(f"selected candidates/occurrences: "
          f"{summary['selected_candidates']}/{summary['selected_occurrences']}")
    print(f"confirmed/false-positive/inconclusive occurrences: "
          f"{summary['confirmed_occurrences']}/{summary['false_positive_occurrences']}/"
          f"{summary['inconclusive_occurrences']}")
    print(f"image bytes read: {summary['image_bytes_read']}")
    print(f"safe report: {arguments.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
