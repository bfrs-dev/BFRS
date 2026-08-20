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


FORMAT = "BFRS_ELECTRUM_CONTEXT_ANALYSIS_V2"
DEFAULT_CONTEXT_BYTES = 64 * 1024
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024
MAX_OCCURRENCE_SPAN = 64 * 1024
DENSITY_RADIUS = 8 * 1024
LOCAL_SIGNAL_RADIUS = 2 * 1024
WALLET_SIGNAL_RADIUS = 4 * 1024
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
    "documentation", "example", "example seed", "test seed", "sample",
    "sample seed", "mnemonic example", "technical reference", "test vector",
    "fixture", "unit test", "tutorial", "word list", "wordlist", "thesaurus",
)
_CORE_ELECTRUM_REASONS = {
    "ELECTRUM_KEYSTORE_SIGNAL", "ELECTRUM_WALLET_TYPE_SIGNAL",
    "ELECTRUM_MASTER_PUBLIC_KEY_SIGNAL", "ELECTRUM_SEED_METADATA_SIGNAL",
}
_STRONG_BOUNDARIES = {
    "BEGINNING_OF_IMAGE", "END_OF_IMAGE", "NEWLINE", "NUL",
    "QUOTE", "DELIMITER", "PUNCTUATION",
}
_RANKING_ORDER = {
    "REJECTED": 0, "LOW_REVIEW": 1, "MEDIUM_REVIEW": 2,
    "HIGH_REVIEW": 3, "VERY_HIGH_REVIEW": 4,
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
    at_image_start: bool = False
    at_image_end: bool = False
    preceding_dictionary_word_count: int = 0
    following_dictionary_word_count: int = 0
    contiguous_dictionary_words_before: int = 0
    contiguous_dictionary_words_after: int = 0
    total_contiguous_dictionary_run_length: int = 0
    left_boundary_type: str = "UNKNOWN"
    right_boundary_type: str = "UNKNOWN"
    standalone_phrase: bool = False
    line_isolation: bool = False
    surrounding_text_length: int = 0
    near_html_signal: bool = False
    near_css_signal: bool = False
    near_javascript_signal: bool = False
    signal_distance: dict[str, int] = field(default_factory=dict)
    review_ranking: str = "LOW_REVIEW"

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
                occurrence.review_ranking = "REJECTED"
                continue
            context_start = max(0, start - context_bytes)
            context_start -= context_start % 2
            context_end = min(image_size, end + context_bytes)
            if context_end < image_size and context_end % 2:
                context_end += 1
            occurrence.context_start = context_start
            occurrence.context_end = context_end
            occurrence.at_image_start = start == 0
            occurrence.at_image_end = end == image_size
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
        if occurrence.nearby_count >= 4:
            occurrence.reason_codes.add("HIGH_LOCAL_MNEMONIC_DENSITY")


def _dictionary_count(text: str, words: frozenset[str]) -> int:
    return sum(electrum_normalize(match.group(0)) in words
               for match in _TOKEN.finditer(text))


def _contiguous_before(text: str, words: frozenset[str]) -> int:
    matches = list(_TOKEN.finditer(text))
    cursor = len(text)
    count = 0
    for match in reversed(matches):
        separator = text[match.end():cursor]
        if not separator or any(character not in " \t" for character in separator):
            break
        if electrum_normalize(match.group(0)) not in words:
            break
        count += 1
        cursor = match.start()
    return count


def _contiguous_after(text: str, words: frozenset[str]) -> int:
    cursor = 0
    count = 0
    for match in _TOKEN.finditer(text):
        separator = text[cursor:match.start()]
        if not separator or any(character not in " \t" for character in separator):
            break
        if electrum_normalize(match.group(0)) not in words:
            break
        count += 1
        cursor = match.end()
    return count


def _left_boundary(text: str, at_image_start: bool) -> str:
    if not text:
        return "BEGINNING_OF_IMAGE" if at_image_start else "CONTEXT_LIMIT"
    stripped = text.rstrip(" \t")
    if not stripped:
        return "BEGINNING_OF_IMAGE" if at_image_start else "WHITESPACE"
    character = stripped[-1]
    if character in "\r\n":
        return "NEWLINE"
    if character == "\x00":
        return "NUL"
    if character in "\"'":
        return "QUOTE"
    if character in ":;,=()[]{}<>":
        return "DELIMITER"
    if character in ".!?":
        return "PUNCTUATION"
    return "TEXT"


def _right_boundary(text: str, at_image_end: bool) -> str:
    if not text:
        return "END_OF_IMAGE" if at_image_end else "CONTEXT_LIMIT"
    stripped = text.lstrip(" \t")
    if not stripped:
        return "END_OF_IMAGE" if at_image_end else "WHITESPACE"
    character = stripped[0]
    if character in "\r\n":
        return "NEWLINE"
    if character == "\x00":
        return "NUL"
    if character in "\"'":
        return "QUOTE"
    if character in ":;,=()[]{}<>":
        return "DELIMITER"
    if character in ".!?":
        return "PUNCTUATION"
    return "TEXT"


def _line_isolation(before: str, after: str) -> bool:
    left = re.split(r"[\r\n\x00]", before)[-1].strip(" \t")
    right = re.split(r"[\r\n\x00]", after)[0].strip(" \t")
    left_ok = not left or bool(re.fullmatch(
        r"(?i)(?:electrum\s+)?(?:seed|mnemonic)\s*[:=]?\s*[\"']?", left))
    right_ok = not right or bool(re.fullmatch(r"[\"'.,;:)}\]>]*", right))
    return left_ok and right_ok


def _match_distance(patterns: Sequence[str] | re.Pattern[str], text: str,
                    seed_start: int, seed_end: int, byte_width: int) -> int | None:
    if isinstance(patterns, re.Pattern):
        matches = patterns.finditer(text)
    else:
        expression = re.compile("|".join(re.escape(item) for item in patterns))
        matches = expression.finditer(text)
    distances = []
    for match in matches:
        if match.end() <= seed_start:
            distance = seed_start - match.end()
        elif match.start() >= seed_end:
            distance = match.start() - seed_end
        else:
            distance = 0
        distances.append(distance * byte_width)
    return min(distances) if distances else None


def _analyze_context(data: bytes, occurrence: _Occurrence,
                     wordlist: frozenset[str]) -> None:
    assert occurrence.context_start is not None
    assert occurrence.physical_start is not None and occurrence.physical_end is not None
    encoding = occurrence.encoding if occurrence.encoding in _ENCODINGS else "utf-8"
    seed_start_bytes = occurrence.physical_start - occurrence.context_start
    seed_end_bytes = occurrence.physical_end - occurrence.context_start
    before = data[:seed_start_bytes].decode(encoding, errors="ignore").casefold()
    seed = data[seed_start_bytes:seed_end_bytes].decode(
        encoding, errors="ignore").casefold()
    after = data[seed_end_bytes:].decode(encoding, errors="ignore").casefold()
    text = before + seed + after
    seed_start = len(before)
    seed_end = seed_start + len(seed)
    byte_width = 2 if encoding.startswith("utf-16") else 1

    occurrence.preceding_dictionary_word_count = _dictionary_count(before, wordlist)
    occurrence.following_dictionary_word_count = _dictionary_count(after, wordlist)
    occurrence.contiguous_dictionary_words_before = _contiguous_before(before, wordlist)
    occurrence.contiguous_dictionary_words_after = _contiguous_after(after, wordlist)
    occurrence.total_contiguous_dictionary_run_length = (
        occurrence.contiguous_dictionary_words_before + occurrence.word_count +
        occurrence.contiguous_dictionary_words_after)
    occurrence.left_boundary_type = _left_boundary(before, occurrence.at_image_start)
    occurrence.right_boundary_type = _right_boundary(after, occurrence.at_image_end)
    left_strong = occurrence.left_boundary_type in _STRONG_BOUNDARIES
    right_strong = occurrence.right_boundary_type in _STRONG_BOUNDARIES
    occurrence.line_isolation = _line_isolation(before, after)
    occurrence.standalone_phrase = (
        left_strong and right_strong and
        occurrence.total_contiguous_dictionary_run_length == occurrence.word_count)
    occurrence.surrounding_text_length = len(before) + len(after)

    reasons = set(occurrence.reason_codes)
    if occurrence.standalone_phrase:
        reasons.add("STANDALONE_MNEMONIC_PHRASE")
    if left_strong:
        reasons.add("STRONG_LEFT_BOUNDARY")
    if right_strong:
        reasons.add("STRONG_RIGHT_BOUNDARY")
    if occurrence.line_isolation:
        reasons.add("ISOLATED_TEXT_LINE")
    artifacts: set[str] = set()
    keyword_distances: dict[str, int] = {}
    for keyword in _KEYWORDS:
        pattern = re.compile(rf"(?<![\w]){re.escape(keyword)}(?![\w])")
        distance = _match_distance(pattern, text, seed_start, seed_end, byte_width)
        if distance is not None:
            artifacts.add(keyword)
            keyword_distances[keyword] = distance

    category_patterns: tuple[tuple[str, Sequence[str] | re.Pattern[str]], ...] = (
        ("html", _HTML_MARKERS), ("css", re.compile(
            rf"{_CSS_PROPERTY_PATTERN.pattern}|{_CSS_SELECTOR_PATTERN.pattern}")),
        ("javascript", _JAVASCRIPT_PATTERN),
        ("example_or_test", _DOCUMENTATION_MARKERS),
    )
    for name, patterns in category_patterns:
        distance = _match_distance(patterns, text, seed_start, seed_end, byte_width)
        if distance is not None:
            occurrence.signal_distance[name] = distance
    occurrence.near_html_signal = occurrence.signal_distance.get(
        "html", LOCAL_SIGNAL_RADIUS + 1) <= LOCAL_SIGNAL_RADIUS
    occurrence.near_css_signal = occurrence.signal_distance.get(
        "css", LOCAL_SIGNAL_RADIUS + 1) <= LOCAL_SIGNAL_RADIUS
    occurrence.near_javascript_signal = occurrence.signal_distance.get(
        "javascript", LOCAL_SIGNAL_RADIUS + 1) <= LOCAL_SIGNAL_RADIUS
    local_example = occurrence.signal_distance.get(
        "example_or_test", LOCAL_SIGNAL_RADIUS + 1) <= LOCAL_SIGNAL_RADIUS
    if occurrence.near_html_signal:
        reasons.add("LOCAL_HTML_CONTEXT")
    if occurrence.near_css_signal:
        reasons.add("LOCAL_CSS_CONTEXT")
    if occurrence.near_javascript_signal:
        reasons.add("LOCAL_JAVASCRIPT_CONTEXT")
    if local_example:
        reasons.add("EXAMPLE_OR_TEST_CONTEXT")

    local_artifacts = {name for name, distance in keyword_distances.items()
                       if distance <= WALLET_SIGNAL_RADIUS}
    if "wallet_type" in local_artifacts:
        reasons.add("ELECTRUM_WALLET_TYPE_SIGNAL")
    if "keystore" in local_artifacts:
        reasons.add("ELECTRUM_KEYSTORE_SIGNAL")
    if {"master_public_key", "master_public_keys", "xpub", "xprv"} & local_artifacts:
        reasons.add("ELECTRUM_MASTER_PUBLIC_KEY_SIGNAL")
    if {"seed_version", "seed_type"} & local_artifacts:
        reasons.add("ELECTRUM_SEED_METADATA_SIGNAL")
    if ({"accounts", "receiving", "change"} & local_artifacts and
            ("electrum" in local_artifacts or reasons & _CORE_ELECTRUM_REASONS)):
        reasons.add("ELECTRUM_WALLET_STRUCTURE_SIGNAL")

    adjacent_dictionary_words = (
        occurrence.contiguous_dictionary_words_before +
        occurrence.contiguous_dictionary_words_after)
    long_wordlist = (occurrence.total_contiguous_dictionary_run_length >= 24 and
                     adjacent_dictionary_words >= 8)
    if long_wordlist:
        reasons.update({"LONG_WORDLIST_RUN", "MNEMONIC_EMBEDDED_IN_WORDLIST"})
    sliding_windows = occurrence.overlapping_count > 0 and adjacent_dictionary_words > 0
    if sliding_windows:
        reasons.add("SLIDING_WINDOW_PATTERN")

    before_seed = text[:seed_start]
    inside_script = before_seed.rfind("<script") > before_seed.rfind("</script>")
    inside_style = before_seed.rfind("<style") > before_seed.rfind("</style>")
    near_code = occurrence.near_javascript_signal or occurrence.near_css_signal
    code_embedded = inside_script or inside_style or (
        near_code and min((occurrence.signal_distance.get("javascript", 10**9),
                           occurrence.signal_distance.get("css", 10**9))) <= 512 and
        not occurrence.line_isolation)
    if code_embedded:
        reasons.add("MNEMONIC_EMBEDDED_IN_CODE")

    core_count = len(reasons & _CORE_ELECTRUM_REASONS)
    strong_false_positive = long_wordlist or sliding_windows or local_example or code_embedded
    if strong_false_positive:
        occurrence.classification = "TEXTUAL_FALSE_POSITIVE"
        occurrence.review_ranking = "REJECTED"
    elif core_count >= 2:
        occurrence.classification = "ELECTRUM_WALLET_CONTEXT_CONFIRMED"
        occurrence.review_ranking = "VERY_HIGH_REVIEW"
    elif occurrence.standalone_phrase or (
            left_strong and right_strong and occurrence.line_isolation):
        occurrence.classification = "PLAINTEXT_SEED_CANDIDATE"
        occurrence.review_ranking = "HIGH_REVIEW" if left_strong and right_strong else (
            "MEDIUM_REVIEW")
    else:
        occurrence.classification = "INCONCLUSIVE"
        occurrence.review_ranking = "LOW_REVIEW"
        reasons.add("NO_STRONG_CONTEXT")
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
                occurrence.review_ranking = "REJECTED"
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
        "review_ranking": occurrence.review_ranking,
        "reason_codes": sorted(occurrence.reason_codes),
        "detected_artifacts": sorted(occurrence.artifacts),
        "context_bytes_requested": (
            occurrence.context_end - occurrence.context_start
            if occurrence.context_start is not None and occurrence.context_end is not None else 0),
        "nearby_survived_candidate_count": occurrence.nearby_count,
        "nearest_candidate_distance": occurrence.nearest_distance,
        "overlapping_candidate_count": occurrence.overlapping_count,
        "local_candidate_density": occurrence.local_density,
        "preceding_dictionary_word_count": occurrence.preceding_dictionary_word_count,
        "following_dictionary_word_count": occurrence.following_dictionary_word_count,
        "contiguous_dictionary_words_before": occurrence.contiguous_dictionary_words_before,
        "contiguous_dictionary_words_after": occurrence.contiguous_dictionary_words_after,
        "total_contiguous_dictionary_run_length": (
            occurrence.total_contiguous_dictionary_run_length),
        "left_boundary_type": occurrence.left_boundary_type,
        "right_boundary_type": occurrence.right_boundary_type,
        "standalone_phrase": occurrence.standalone_phrase,
        "line_isolation": occurrence.line_isolation,
        "surrounding_text_length": occurrence.surrounding_text_length,
        "near_html_signal": occurrence.near_html_signal,
        "near_css_signal": occurrence.near_css_signal,
        "near_javascript_signal": occurrence.near_javascript_signal,
        "signal_distance": dict(sorted(occurrence.signal_distance.items())),
    }


def _candidate_dict(candidate: _Candidate) -> dict[str, object]:
    classes = Counter(item.classification for item in candidate.occurrences)
    if len(classes) == 1:
        classification = next(iter(classes))
        ranking = min((item.review_ranking for item in candidate.occurrences),
                      key=_RANKING_ORDER.__getitem__)
    else:
        classification = "INCONCLUSIVE"
        ranking = "LOW_REVIEW"
    return {
        "candidate_id": candidate.candidate_id,
        "fingerprint": candidate.fingerprint,
        "mnemonic_standard": "ELECTRUM",
        "revalidation_priority": "HIGH_REVIEW",
        "classification": classification,
        "review_ranking": ranking,
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
    rankings = Counter(item.review_ranking for item in occurrences)
    candidate_rankings = Counter(item["review_ranking"] for item in results)
    reasons = Counter(reason for item in occurrences for reason in item.reason_codes)
    summary = {
        "input_candidates": input_candidates,
        "selected_candidates": len(candidates),
        "selected_occurrences": len(occurrences),
        "wallet_confirmed_candidates": candidate_classes[
            "ELECTRUM_WALLET_CONTEXT_CONFIRMED"],
        "plaintext_seed_candidates": candidate_classes["PLAINTEXT_SEED_CANDIDATE"],
        "textual_false_positive_candidates": candidate_classes["TEXTUAL_FALSE_POSITIVE"],
        "inconclusive_candidates": candidate_classes["INCONCLUSIVE"],
        "read_failed_candidates": candidate_classes["READ_FAILED"],
        "wallet_confirmed_occurrences": occurrence_classes[
            "ELECTRUM_WALLET_CONTEXT_CONFIRMED"],
        "plaintext_seed_occurrences": occurrence_classes["PLAINTEXT_SEED_CANDIDATE"],
        "textual_false_positive_occurrences": occurrence_classes[
            "TEXTUAL_FALSE_POSITIVE"],
        "inconclusive_occurrences": occurrence_classes["INCONCLUSIVE"],
        "read_failures": occurrence_classes["READ_FAILED"],
        "io_windows_planned": len(windows),
        "io_windows_read": windows_read,
        "image_bytes_read": bytes_read,
        "candidate_classification_distribution": dict(sorted(candidate_classes.items())),
        "occurrence_classification_distribution": dict(sorted(occurrence_classes.items())),
        "ranking_distribution": dict(sorted(rankings.items())),
        "candidate_ranking_distribution": dict(sorted(candidate_rankings.items())),
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
            "local_signal_radius_bytes": LOCAL_SIGNAL_RADIUS,
            "wallet_signal_radius_bytes": WALLET_SIGNAL_RADIUS,
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
    print(f"wallet/plaintext/false-positive/inconclusive occurrences: "
          f"{summary['wallet_confirmed_occurrences']}/"
          f"{summary['plaintext_seed_occurrences']}/"
          f"{summary['textual_false_positive_occurrences']}/"
          f"{summary['inconclusive_occurrences']}")
    print(f"image bytes read: {summary['image_bytes_read']}")
    print(f"safe report: {arguments.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
