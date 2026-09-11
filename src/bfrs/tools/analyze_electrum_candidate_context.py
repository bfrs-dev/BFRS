"""Classify local context for selected, already-validated Electrum hits."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
from typing import BinaryIO, Callable, ContextManager, Sequence

from bfrs.core.path_safety import paths_refer_to_same_file
from bfrs.recovery.mnemonic.bip39_validator import BIP39Validator
from bfrs.recovery.mnemonic.electrum_seed_validator import ElectrumSeedValidator
from bfrs.recovery.mnemonic.electrum_v1_validator import ElectrumV1Validator
from bfrs.recovery.mnemonic.mnemonic_normalizer import electrum_normalize


FORMAT = "BFRS_ELECTRUM_CONTEXT_ANALYSIS_V2_4"
DEFAULT_CONTEXT_BYTES = 64 * 1024
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024
MAX_OCCURRENCE_SPAN = 64 * 1024
DENSITY_RADIUS = 8 * 1024
LOCAL_SIGNAL_RADIUS = 2 * 1024
WALLET_SIGNAL_RADIUS = 4 * 1024
NEARBY_LABEL_RADIUS = 512
RIGHT_BOUNDARY_INSPECTION_BYTES = 128
_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be")
_STANDARDS = ("ELECTRUM", "ELECTRUM_V1")
_FINGERPRINT_DOMAIN = b"BFRS-MNEMONIC-FINGERPRINT-V1\0"

_KEYWORDS = (
    "seed", "seed_version", "wallet_type", "keystore", "master_public_key",
    "master_public_keys", "xpub", "xprv", "accounts", "receiving", "change",
    "electrum", "seed_type",
    "use_encryption", "addresses", "imported_keys", "seed_encrypted",
    "password",
)
_NEARBY_LABELS = (
    "seed", "mnemonic", "recovery", "recovery phrase", "wallet", "bitcoin",
    "electrum", "backup", "password", "passphrase", "private", "key",
    "restore", "words",
)
_POSITIVE_LABELS = {
    "seed", "mnemonic", "recovery", "recovery phrase", "wallet", "electrum",
    "backup", "restore",
}
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
    left_immediate_char_class: str = "BINARY"
    right_immediate_char_class: str = "BINARY"
    bytes_to_previous_newline: int | None = None
    bytes_to_next_newline: int | None = None
    bytes_to_previous_nul: int | None = None
    bytes_to_next_nul: int | None = None
    line_length_bytes: int = 0
    phrase_starts_line: bool = False
    phrase_ends_line: bool = False
    phrase_is_whole_line: bool = False
    nul_delimited: bool = False
    quote_delimited: bool = False
    key_value_like_boundary: bool = False
    nearby_labels: list[dict[str, object]] = field(default_factory=list)
    local_cluster_id: str | None = None
    nearby_selected_occurrence_count: int = 0
    normalized_fingerprint: str | None = field(default=None, repr=False)
    normalized_word_count: int | None = field(default=None, repr=False)
    printable_text_ratio: float = 0.0
    expected_nul_ratio: float = 0.0
    opposite_nul_ratio: float = 0.0
    aligned_context_code_units: int = 0
    bom_aligned: bool = False
    alignment_score: float = field(default=0.0, repr=False)
    encoding_alignment_assessment: str = "AMBIGUOUS"
    paired_provenance: list[dict[str, object]] = field(default_factory=list)
    paired_span_delta: list[dict[str, int]] = field(default_factory=list)
    same_fingerprint: bool | None = None
    same_normalized_word_count: bool | None = None
    bytes_examined_after_phrase: int = 0
    immediate_right_decoded_char_count: int = 0
    immediate_right_printable_ratio: float = 0.0
    immediate_right_nul_ratio: float = 0.0
    immediate_right_whitespace_prefix_length: int = 0
    immediate_right_delimiter_class: str = "NONE"
    next_structural_boundary_distance: int | None = None
    right_side_text_continuity: str = "AMBIGUOUS"
    immediate_right_first_char_class: str = "NONE"
    immediate_right_decoded_printable_ratio: float = 0.0
    immediate_right_decoded_control_ratio: float = 0.0
    immediate_right_raw_nul_ratio: float = 0.0
    utf16_zero_lane_consistency: float | None = None

    @property
    def identity(self) -> tuple[str, str, str, int | None, int | None]:
        return (self.candidate_id, self.fingerprint,
                self.encoding, self.physical_start, self.physical_end)


@dataclass(slots=True)
class _Candidate:
    candidate_id: str
    fingerprint: str
    mnemonic_standard: str
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


def _candidate_payload(report: dict[str, object]) -> object:
    payload = report.get("candidates")
    if isinstance(payload, list):
        return payload
    recovery = report.get("mnemonic_recovery")
    if isinstance(recovery, dict):
        return recovery.get("candidates")
    return None


def _select(report: dict[str, object], *, standard: str,
            candidate_id_filter: str | None,
            physical_start_filter: int | None) -> tuple[int, list[_Candidate]]:
    payload = _candidate_payload(report)
    if not isinstance(payload, list):
        raise ValueError("context input has no candidates list")
    selected: list[_Candidate] = []
    seen: set[tuple[str, str, str, int | None, int | None]] = set()
    for item in payload:
        if not isinstance(item, dict) or item.get("mnemonic_standard") != standard:
            continue
        candidate_id = str(item.get("candidate_id", ""))
        if candidate_id_filter is not None and candidate_id != candidate_id_filter:
            continue
        fingerprint = str(item.get("fingerprint", ""))
        if standard == "ELECTRUM":
            if item.get("revalidation_priority") != "HIGH_REVIEW":
                continue
            source_occurrences = item.get("occurrences", [])
        else:
            if (item.get("validation_status") != "ELECTRUM_V1_STRICT_VALID" or
                    _integer(item.get("word_count")) != 12):
                continue
            source_occurrences = item.get("provenance", [])
        occurrences = []
        if not isinstance(source_occurrences, list):
            continue
        for provenance in source_occurrences:
            if not isinstance(provenance, dict):
                continue
            if standard == "ELECTRUM":
                occurrence = provenance
                word_count = _integer(occurrence.get("word_count"))
                if (occurrence.get("status") != "SURVIVED" or
                        occurrence.get("validation_status") != "ELECTRUM_SEED_VALID" or
                        word_count not in {12, 13}):
                    continue
            else:
                if provenance.get("source_kind") != "RAW_BYTES":
                    continue
                occurrence = {**item, **provenance}
                word_count = 12
            physical_start = _integer(occurrence.get("physical_start"))
            if (physical_start_filter is not None and
                    physical_start != physical_start_filter):
                continue
            selected_occurrence = _Occurrence(
                candidate_id=candidate_id,
                fingerprint=fingerprint,
                encoding=str(occurrence.get("new_encoding") or
                             occurrence.get("old_encoding") or
                             occurrence.get("encoding") or "unknown"),
                word_count=word_count,
                physical_start=physical_start,
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
            selected.append(_Candidate(
                candidate_id, fingerprint, standard, item, occurrences))
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


def _assign_clusters(occurrences: list[_Occurrence]) -> list[dict[str, object]]:
    ordered = sorted(occurrences, key=lambda item: (
        item.physical_start, item.physical_end, item.fingerprint, item.candidate_id))
    groups: list[list[_Occurrence]] = []
    for occurrence in ordered:
        assert occurrence.physical_start is not None and occurrence.physical_end is not None
        group_end = (max(int(item.physical_end) for item in groups[-1])
                     if groups else None)
        if (group_end is not None and
                occurrence.physical_start - group_end <= DENSITY_RADIUS):
            groups[-1].append(occurrence)
        else:
            groups.append([occurrence])
    clusters = []
    for number, group in enumerate(groups, start=1):
        cluster_id = f"cluster-{number:04d}"
        for occurrence in group:
            occurrence.local_cluster_id = cluster_id
            occurrence.nearby_selected_occurrence_count = len(group) - 1
        starts = [item.physical_start for item in group]
        ends = [item.physical_end for item in group]
        assert all(value is not None for value in starts + ends)
        distances = [abs(int(right) - int(left))
                     for index, left in enumerate(starts)
                     for right in starts[index + 1:]]
        distance_summary = {
            "pair_count": len(distances),
            "minimum_bytes": min(distances) if distances else None,
            "maximum_bytes": max(distances) if distances else None,
            "mean_bytes": (round(sum(distances) / len(distances), 3)
                           if distances else None),
        }
        cluster_start = min(int(value) for value in starts)
        cluster_end = max(int(value) for value in ends)
        clusters.append({
            "cluster_id": cluster_id,
            "cluster_start": cluster_start,
            "cluster_end": cluster_end,
            "cluster_span_bytes": cluster_end - cluster_start,
            "cluster_occurrence_count": len(group),
            "pairwise_distance_summary": distance_summary,
        })
    return clusters


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


def _immediate_char_class(text: str, *, left: bool, at_image_edge: bool) -> str:
    if not text:
        if at_image_edge:
            return "BOF" if left else "EOF"
        return "BINARY"
    if (left and text.endswith("\r\n")) or (not left and text.startswith("\r\n")):
        return "CRLF"
    character = text[-1] if left else text[0]
    if character in "\r\n":
        return "NEWLINE"
    if character == "\x00":
        return "NUL"
    if character in " \t":
        return "WHITESPACE"
    if character == ":":
        return "COLON"
    if character == "=":
        return "EQUALS"
    if character == '"':
        return "QUOTE"
    if character == "'":
        return "APOSTROPHE"
    if character == ",":
        return "COMMA"
    if character == ";":
        return "SEMICOLON"
    if character in "[]{}<>":
        return "BRACKET"
    if character in "()":
        return "PAREN"
    if character.isalnum():
        return "ALPHANUMERIC"
    if character.isprintable():
        return "OTHER_PRINTABLE"
    return "BINARY"


def _previous_distance(text: str, characters: str, byte_width: int) -> int | None:
    index = max((text.rfind(character) for character in characters), default=-1)
    return (len(text) - index - 1) * byte_width if index >= 0 else None


def _next_distance(text: str, characters: str, byte_width: int) -> int | None:
    indexes = [index for character in characters
               if (index := text.find(character)) >= 0]
    return min(indexes) * byte_width if indexes else None


def _nearby_labels(before: str, after: str, byte_width: int
                   ) -> list[dict[str, object]]:
    radius_chars = max(1, NEARBY_LABEL_RADIUS // byte_width)
    nearby_before = before[-radius_chars:]
    nearby_after = after[:radius_chars]
    found = []
    for label in _NEARBY_LABELS:
        pattern = re.compile(rf"(?<![\w]){re.escape(label)}(?![\w])")
        choices = []
        for match in pattern.finditer(nearby_before):
            choices.append(((len(nearby_before) - match.end()) * byte_width, "BEFORE"))
        for match in pattern.finditer(nearby_after):
            choices.append((match.start() * byte_width, "AFTER"))
        if choices:
            distance, direction = min(choices, key=lambda item: (item[0], item[1]))
            found.append({"label": label, "distance": distance, "direction": direction})
    return sorted(found, key=lambda item: (
        item["distance"], item["label"], item["direction"]))


def _boundary_details(before: str, seed: str, after: str,
                      occurrence: _Occurrence, byte_width: int) -> tuple[bool, bool]:
    occurrence.left_immediate_char_class = _immediate_char_class(
        before, left=True, at_image_edge=occurrence.at_image_start)
    occurrence.right_immediate_char_class = _immediate_char_class(
        after, left=False, at_image_edge=occurrence.at_image_end)
    occurrence.bytes_to_previous_newline = _previous_distance(before, "\r\n", byte_width)
    occurrence.bytes_to_next_newline = _next_distance(after, "\r\n", byte_width)
    occurrence.bytes_to_previous_nul = _previous_distance(before, "\x00", byte_width)
    occurrence.bytes_to_next_nul = _next_distance(after, "\x00", byte_width)

    previous_newline = max(before.rfind("\r"), before.rfind("\n"))
    next_newlines = [index for marker in "\r\n"
                     if (index := after.find(marker)) >= 0]
    next_newline = min(next_newlines) if next_newlines else len(after)
    left_line = before[previous_newline + 1:]
    right_line = after[:next_newline]
    occurrence.line_length_bytes = (
        len(left_line) + len(seed) + len(right_line)) * byte_width
    occurrence.phrase_starts_line = not left_line.strip(" \t")
    occurrence.phrase_ends_line = not right_line.strip(" \t")
    occurrence.phrase_is_whole_line = (
        occurrence.phrase_starts_line and occurrence.phrase_ends_line)
    occurrence.nul_delimited = (
        occurrence.left_immediate_char_class == "NUL" and
        occurrence.right_immediate_char_class == "NUL")
    occurrence.quote_delimited = (
        occurrence.left_immediate_char_class in {"QUOTE", "APOSTROPHE"} and
        occurrence.right_immediate_char_class in {"QUOTE", "APOSTROPHE"})
    occurrence.key_value_like_boundary = bool(re.search(
        r"(?i)[a-z_][\w -]{0,63}\s*[:=]\s*[\"']?\s*$", left_line))
    occurrence.nearby_labels = _nearby_labels(before, after, byte_width)
    positive_before = any(
        item["label"] in _POSITIVE_LABELS and item["direction"] == "BEFORE"
        for item in occurrence.nearby_labels)
    label_value = positive_before and occurrence.key_value_like_boundary

    left_words = len(_TOKEN.findall(left_line))
    right_words = len(_TOKEN.findall(right_line))
    prose_embedded = (
        left_words >= 3 and right_words >= 3 and not occurrence.phrase_is_whole_line and
        not occurrence.nul_delimited and not occurrence.quote_delimited and
        not occurrence.key_value_like_boundary)
    return label_value, prose_embedded


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


def _fingerprint(standard: str, normalized: str) -> str:
    material = (_FINGERPRINT_DOMAIN + standard.encode("ascii") + b"\0" +
                normalized.encode("utf-8"))
    return hashlib.sha256(material).hexdigest()


def _alignment_metrics(data: bytes, seed_start: int, seed_end: int,
                       encoding: str, occurrence: _Occurrence) -> None:
    if not encoding.startswith("utf-16"):
        occurrence.encoding_alignment_assessment = "NATURAL"
        return
    radius = 1024
    start = max(0, seed_start - radius)
    start += (seed_start - start) % 2
    end = min(len(data), seed_end + radius)
    end -= (end - start) % 2
    sample = data[start:end]
    units = len(sample) // 2
    if not units:
        return
    decoded = sample.decode(encoding, errors="replace")
    textual = sum(character.isprintable() or character in "\r\n\t"
                  for character in decoded)
    occurrence.printable_text_ratio = round(textual / len(decoded), 6) if decoded else 0.0
    high_index = 1 if encoding == "utf-16-le" else 0
    expected_nuls = sum(sample[index + high_index] == 0
                        for index in range(0, len(sample), 2))
    opposite_nuls = sum(sample[index + (1 - high_index)] == 0
                        for index in range(0, len(sample), 2))
    occurrence.expected_nul_ratio = round(expected_nuls / units, 6)
    occurrence.opposite_nul_ratio = round(opposite_nuls / units, 6)
    occurrence.aligned_context_code_units = units
    bom = b"\xff\xfe" if encoding == "utf-16-le" else b"\xfe\xff"
    occurrence.bom_aligned = any(
        sample[index:index + 2] == bom for index in range(0, len(sample), 2))
    nul_direction = max(
        0.0, occurrence.expected_nul_ratio - occurrence.opposite_nul_ratio)
    occurrence.alignment_score = (
        0.65 * occurrence.printable_text_ratio + 0.25 * nul_direction +
        (0.10 if occurrence.bom_aligned else 0.0))


def _decoded_char_class(character: str) -> str:
    if character == "\ufffd":
        return "DECODE_FAILURE"
    if character in "\r\n":
        return "NEWLINE"
    if character == "\x00":
        return "NUL"
    if character.isspace():
        return "WHITESPACE"
    if character in "\"'":
        return "QUOTE"
    if character in ":;,=()[]{}<>":
        return "DELIMITER"
    if character in ".!?":
        return "PUNCTUATION"
    if character.isalnum():
        return "ALPHANUMERIC"
    if character.isprintable():
        return "OTHER_PRINTABLE"
    return "CONTROL"


def _encoded_prefix_length(text: str, character_count: int, encoding: str) -> int:
    return len(text[:character_count].encode(encoding, errors="replace"))


def _right_side_metrics(after: bytes, encoding: str,
                        occurrence: _Occurrence) -> None:
    sample = after[:RIGHT_BOUNDARY_INSPECTION_BYTES]
    if encoding.startswith("utf-16") and len(sample) % 2:
        sample = sample[:-1]
    occurrence.bytes_examined_after_phrase = len(sample)
    if not sample:
        occurrence.immediate_right_delimiter_class = "EOF"
        occurrence.next_structural_boundary_distance = 0
        occurrence.right_side_text_continuity = "TERMINATED"
        return

    decoded = sample.decode(encoding, errors="replace")
    occurrence.immediate_right_decoded_char_count = len(decoded)
    printable = sum(character.isprintable() for character in decoded)
    decoded_printable_ratio = round(
        printable / len(decoded), 6) if decoded else 0.0
    occurrence.immediate_right_printable_ratio = decoded_printable_ratio
    occurrence.immediate_right_decoded_printable_ratio = decoded_printable_ratio
    raw_nul_ratio = round(
        sample.count(0) / len(sample), 6)
    occurrence.immediate_right_nul_ratio = raw_nul_ratio
    occurrence.immediate_right_raw_nul_ratio = raw_nul_ratio
    controls = sum(
        unicodedata.category(character) in {"Cc", "Cf", "Cs"} and
        not character.isspace() and character != "\x00"
        for character in decoded)
    occurrence.immediate_right_decoded_control_ratio = round(
        controls / len(decoded), 6) if decoded else 0.0

    if encoding.startswith("utf-16"):
        high_lane = 1 if encoding == "utf-16-le" else 0
        expected_zeros = sum(sample[index + high_lane] == 0
                             for index in range(0, len(sample), 2))
        opposite_zeros = sum(sample[index + (1 - high_lane)] == 0
                             for index in range(0, len(sample), 2))
        zero_count = expected_zeros + opposite_zeros
        occurrence.utf16_zero_lane_consistency = (
            round(expected_zeros / zero_count, 6) if zero_count else None)

    occurrence.immediate_right_first_char_class = _decoded_char_class(decoded[0])

    whitespace_prefix = len(decoded) - len(decoded.lstrip(" \t"))
    occurrence.immediate_right_whitespace_prefix_length = whitespace_prefix
    remainder = decoded[whitespace_prefix:]
    if not remainder:
        occurrence.immediate_right_delimiter_class = "EOF_OR_WINDOW_LIMIT"
        occurrence.right_side_text_continuity = "WHITESPACE_ONLY"
        return

    occurrence.immediate_right_delimiter_class = _decoded_char_class(remainder[0])
    structural = "\r\n\x00\"':;,=()[]{}<>.!?"
    structural_indexes = [index for index, character in enumerate(decoded)
                          if character in structural]
    if structural_indexes:
        occurrence.next_structural_boundary_distance = _encoded_prefix_length(
            decoded, min(structural_indexes), encoding)

    delimiter_class = occurrence.immediate_right_delimiter_class
    if delimiter_class in {
            "NEWLINE", "NUL", "QUOTE", "DELIMITER", "PUNCTUATION"}:
        occurrence.right_side_text_continuity = "TERMINATED"
        return

    replacement_ratio = decoded.count("\ufffd") / len(decoded) if decoded else 0.0
    decoded_control_ratio = occurrence.immediate_right_decoded_control_ratio
    zero_lane_inconsistent = bool(
        encoding.startswith("utf-16") and raw_nul_ratio >= 0.15 and
        occurrence.utf16_zero_lane_consistency is not None and
        occurrence.utf16_zero_lane_consistency < 0.75)
    if (replacement_ratio >= 0.20 or decoded_control_ratio >= 0.20 or
            decoded_printable_ratio < 0.60 or zero_lane_inconsistent):
        occurrence.right_side_text_continuity = "BINARY_OR_MISDECODED"
        return

    if delimiter_class == "CONTROL":
        occurrence.right_side_text_continuity = "TERMINATED"
        return

    words = _TOKEN.findall(remainder)
    alphabetic_count = sum(character.isalpha() for character in remainder)
    if (delimiter_class == "ALPHANUMERIC" and
            (words or alphabetic_count > 0)):
        occurrence.right_side_text_continuity = "CONTINUOUS_PROSE"
    else:
        occurrence.right_side_text_continuity = "AMBIGUOUS"


def _analyze_context(data: bytes, occurrence: _Occurrence,
                     wordlist: frozenset[str]) -> None:
    assert occurrence.context_start is not None
    assert occurrence.physical_start is not None and occurrence.physical_end is not None
    encoding = occurrence.encoding if occurrence.encoding in _ENCODINGS else "utf-8"
    seed_start_bytes = occurrence.physical_start - occurrence.context_start
    seed_end_bytes = occurrence.physical_end - occurrence.context_start
    before_bytes = data[:seed_start_bytes]
    raw_after_bytes = data[seed_end_bytes:]
    _right_side_metrics(raw_after_bytes, encoding, occurrence)
    after_bytes = raw_after_bytes
    if encoding.startswith("utf-16"):
        before_bytes = before_bytes[len(before_bytes) % 2:]
        after_bytes = after_bytes[:len(after_bytes) - len(after_bytes) % 2]
    before = before_bytes.decode(encoding, errors="ignore").casefold()
    seed = data[seed_start_bytes:seed_end_bytes].decode(
        encoding, errors="ignore").casefold()
    normalized_seed = electrum_normalize(seed)
    occurrence.normalized_fingerprint = _fingerprint(
        occurrence.source.get("mnemonic_standard", "ELECTRUM"), normalized_seed)
    occurrence.normalized_word_count = len(normalized_seed.split())
    _alignment_metrics(
        data, seed_start_bytes, seed_end_bytes, encoding, occurrence)
    after = after_bytes.decode(encoding, errors="ignore").casefold()
    text = before + seed + after
    seed_start = len(before)
    seed_end = seed_start + len(seed)
    byte_width = 2 if encoding.startswith("utf-16") else 1
    label_value, prose_embedded = _boundary_details(
        before, seed, after, occurrence, byte_width)

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
    if occurrence.phrase_is_whole_line:
        reasons.add("WHOLE_LINE_PHRASE")
    if occurrence.nul_delimited:
        reasons.add("NUL_DELIMITED_STRING")
    if occurrence.quote_delimited:
        reasons.add("QUOTED_VALUE_PATTERN")
    if occurrence.key_value_like_boundary:
        reasons.add("KEY_VALUE_PATTERN")
    if label_value:
        reasons.add("LABEL_VALUE_PATTERN")
    label_reason_codes = {
        "seed": "NEARBY_SEED_LABEL",
        "mnemonic": "NEARBY_MNEMONIC_LABEL",
        "wallet": "NEARBY_WALLET_LABEL",
        "electrum": "NEARBY_ELECTRUM_LABEL",
        "backup": "NEARBY_BACKUP_LABEL",
    }
    for item in occurrence.nearby_labels:
        reason = label_reason_codes.get(str(item["label"]))
        if reason is not None:
            reasons.add(reason)
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
    if prose_embedded:
        reasons.add("PROSE_EMBEDDED_PHRASE")
    strong_false_positive = (
        long_wordlist or sliding_windows or local_example or code_embedded or
        prose_embedded)
    exact_dictionary_run = (
        occurrence.total_contiguous_dictionary_run_length == occurrence.word_count and
        adjacent_dictionary_words == 0)
    positive_nearby_label = any(
        item["label"] in _POSITIVE_LABELS for item in occurrence.nearby_labels)
    plaintext_boundary = (
        occurrence.phrase_is_whole_line or occurrence.nul_delimited or
        occurrence.quote_delimited or occurrence.key_value_like_boundary or
        label_value or occurrence.standalone_phrase or
        (positive_nearby_label and (left_strong or right_strong)))
    v1_line_start_plaintext = (
        occurrence.source.get("mnemonic_standard") == "ELECTRUM_V1" and
        occurrence.source.get("validation_status") == "ELECTRUM_V1_STRICT_VALID" and
        occurrence.word_count == 12 and occurrence.phrase_starts_line and
        adjacent_dictionary_words == 0 and
        occurrence.right_side_text_continuity in {
            "TERMINATED", "WHITESPACE_ONLY", "BINARY_OR_MISDECODED"})
    if v1_line_start_plaintext:
        reasons.add("V1_LINE_START_WITH_NON_PROSE_RIGHT_BOUNDARY")
    if strong_false_positive:
        occurrence.classification = "TEXTUAL_FALSE_POSITIVE"
        occurrence.review_ranking = "REJECTED"
    elif core_count >= 2:
        occurrence.classification = "ELECTRUM_WALLET_CONTEXT_CONFIRMED"
        occurrence.review_ranking = "VERY_HIGH_REVIEW"
    elif exact_dictionary_run and (plaintext_boundary or v1_line_start_plaintext):
        occurrence.classification = "PLAINTEXT_SEED_CANDIDATE"
        occurrence.review_ranking = (
            "HIGH_REVIEW" if v1_line_start_plaintext or
            (left_strong and right_strong) else "MEDIUM_REVIEW")
    else:
        occurrence.classification = "INCONCLUSIVE"
        occurrence.review_ranking = "LOW_REVIEW"
        reasons.update({"NO_STRONG_CONTEXT", "WEAK_TEXT_BOUNDARIES"})
    occurrence.reason_codes = reasons
    occurrence.artifacts = artifacts


def _pair_provenance(candidates: list[_Candidate]) -> None:
    for candidate in candidates:
        occurrences = candidate.occurrences
        for index, left in enumerate(occurrences):
            if left.classification == "READ_FAILED":
                continue
            for right in occurrences[index + 1:]:
                if right.classification == "READ_FAILED":
                    continue
                if ({left.encoding, right.encoding} != {"utf-16-le", "utf-16-be"} or
                        left.physical_start is None or right.physical_start is None or
                        left.physical_end is None or right.physical_end is None):
                    continue
                start_delta = right.physical_start - left.physical_start
                end_delta = right.physical_end - left.physical_end
                if abs(start_delta) != 1 or abs(end_delta) != 1:
                    continue
                same_fingerprint = bool(
                    left.normalized_fingerprint and
                    left.normalized_fingerprint == right.normalized_fingerprint)
                same_word_count = bool(
                    left.normalized_word_count is not None and
                    left.normalized_word_count == right.normalized_word_count ==
                    left.word_count == right.word_count)
                for current, partner, delta_start, delta_end in (
                        (left, right, start_delta, end_delta),
                        (right, left, -start_delta, -end_delta)):
                    current.paired_provenance.append({
                        "encoding": partner.encoding,
                        "physical_start": partner.physical_start,
                        "physical_end": partner.physical_end,
                    })
                    current.paired_span_delta.append({
                        "physical_start": delta_start,
                        "physical_end": delta_end,
                    })
                    current.same_fingerprint = same_fingerprint
                    current.same_normalized_word_count = same_word_count
                score_delta = left.alignment_score - right.alignment_score
                if abs(score_delta) >= 0.05:
                    natural, alternate = ((left, right) if score_delta > 0 else
                                          (right, left))
                    natural.encoding_alignment_assessment = "NATURAL"
                    alternate.encoding_alignment_assessment = "ALTERNATE_INTERPRETATION"
                else:
                    left.encoding_alignment_assessment = "AMBIGUOUS"
                    right.encoding_alignment_assessment = "AMBIGUOUS"


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
        "left_immediate_char_class": occurrence.left_immediate_char_class,
        "right_immediate_char_class": occurrence.right_immediate_char_class,
        "bytes_to_previous_newline": occurrence.bytes_to_previous_newline,
        "bytes_to_next_newline": occurrence.bytes_to_next_newline,
        "bytes_to_previous_nul": occurrence.bytes_to_previous_nul,
        "bytes_to_next_nul": occurrence.bytes_to_next_nul,
        "line_length_bytes": occurrence.line_length_bytes,
        "phrase_starts_line": occurrence.phrase_starts_line,
        "phrase_ends_line": occurrence.phrase_ends_line,
        "phrase_is_whole_line": occurrence.phrase_is_whole_line,
        "nul_delimited": occurrence.nul_delimited,
        "quote_delimited": occurrence.quote_delimited,
        "key_value_like_boundary": occurrence.key_value_like_boundary,
        "nearby_labels": occurrence.nearby_labels,
        "local_cluster_id": occurrence.local_cluster_id,
        "nearby_selected_occurrence_count": (
            occurrence.nearby_selected_occurrence_count),
        "printable_text_ratio": occurrence.printable_text_ratio,
        "expected_nul_ratio": occurrence.expected_nul_ratio,
        "opposite_nul_ratio": occurrence.opposite_nul_ratio,
        "aligned_context_code_units": occurrence.aligned_context_code_units,
        "bom_aligned": occurrence.bom_aligned,
        "encoding_alignment_assessment": (
            occurrence.encoding_alignment_assessment),
        "paired_provenance": occurrence.paired_provenance,
        "paired_span_delta": occurrence.paired_span_delta,
        "same_fingerprint": occurrence.same_fingerprint,
        "same_normalized_word_count": occurrence.same_normalized_word_count,
        "bytes_examined_after_phrase": occurrence.bytes_examined_after_phrase,
        "immediate_right_decoded_char_count": (
            occurrence.immediate_right_decoded_char_count),
        "immediate_right_printable_ratio": (
            occurrence.immediate_right_printable_ratio),
        "immediate_right_nul_ratio": occurrence.immediate_right_nul_ratio,
        "immediate_right_whitespace_prefix_length": (
            occurrence.immediate_right_whitespace_prefix_length),
        "immediate_right_delimiter_class": (
            occurrence.immediate_right_delimiter_class),
        "next_structural_boundary_distance": (
            occurrence.next_structural_boundary_distance),
        "right_side_text_continuity": occurrence.right_side_text_continuity,
        "immediate_right_first_char_class": (
            occurrence.immediate_right_first_char_class),
        "immediate_right_decoded_printable_ratio": (
            occurrence.immediate_right_decoded_printable_ratio),
        "immediate_right_decoded_control_ratio": (
            occurrence.immediate_right_decoded_control_ratio),
        "immediate_right_raw_nul_ratio": occurrence.immediate_right_raw_nul_ratio,
        "utf16_zero_lane_consistency": occurrence.utf16_zero_lane_consistency,
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
        "mnemonic_standard": candidate.mnemonic_standard,
        "revalidation_priority": candidate.source.get("revalidation_priority"),
        "classification": classification,
        "review_ranking": ranking,
        "occurrence_classification_distribution": dict(sorted(classes.items())),
        "occurrences": [_occurrence_dict(item) for item in candidate.occurrences],
    }


def _wordlist() -> frozenset[str]:
    electrum = ElectrumSeedValidator()
    electrum_v1 = ElectrumV1Validator()
    bip39 = BIP39Validator()
    return frozenset(word for values in (*electrum.wordlists.values(),
                                         *bip39.wordlists.values(),
                                         electrum_v1.wordlist) for word in values)


def analyze_report(report: dict[str, object], image: str | Path, *,
                   context_bytes: int = DEFAULT_CONTEXT_BYTES,
                   max_window_bytes: int = DEFAULT_MAX_WINDOW_BYTES,
                   standard: str = "ELECTRUM",
                   candidate_id: str | None = None,
                   physical_start: int | None = None,
                   stream_factory: StreamFactory | None = None) -> dict[str, object]:
    if context_bytes < 0:
        raise ValueError("context-bytes must be nonnegative")
    if max_window_bytes <= 0 or 2 * context_bytes + MAX_OCCURRENCE_SPAN > max_window_bytes:
        raise ValueError("max-window-bytes is too small for context and occurrence limit")
    if standard not in _STANDARDS:
        raise ValueError(f"unsupported standard: {standard}")
    if physical_start is not None and physical_start < 0:
        raise ValueError("physical-start must be nonnegative")
    image_path = Path(image).resolve()
    image_size = image_path.stat().st_size
    input_candidates, candidates = _select(
        report, standard=standard, candidate_id_filter=candidate_id,
        physical_start_filter=physical_start)
    occurrences = [item for candidate in candidates for item in candidate.occurrences]
    readable = _prepare_occurrences(candidates, image_size, context_bytes)
    _density(readable)
    clusters = _assign_clusters(readable)
    windows = _plan_windows(readable, max_window_bytes)
    factory = stream_factory or (lambda path: path.open("rb"))
    with factory(image_path) as stream:
        windows_read, bytes_read = _read_windows(stream, windows, _wordlist())
    _pair_provenance(candidates)
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
        "cluster_count": len(clusters),
        "candidate_classification_distribution": dict(sorted(candidate_classes.items())),
        "occurrence_classification_distribution": dict(sorted(occurrence_classes.items())),
        "ranking_distribution": dict(sorted(rankings.items())),
        "candidate_ranking_distribution": dict(sorted(candidate_rankings.items())),
        "reason_code_distribution": dict(sorted(reasons.items())),
    }
    return {
        "format": FORMAT,
        "configuration": {
            "priority_filter": ("HIGH_REVIEW" if standard == "ELECTRUM" else None),
            "standard_filter": standard,
            "candidate_id_filter": candidate_id,
            "physical_start_filter": physical_start,
            "word_counts": [12, 13] if standard == "ELECTRUM" else [12],
            "context_bytes": context_bytes,
            "max_window_bytes": max_window_bytes,
            "density_radius_bytes": DENSITY_RADIUS,
            "local_signal_radius_bytes": LOCAL_SIGNAL_RADIUS,
            "wallet_signal_radius_bytes": WALLET_SIGNAL_RADIUS,
            "nearby_label_radius_bytes": NEARBY_LABEL_RADIUS,
        },
        "source": {"image": str(image_path), "size": image_size},
        "summary": summary,
        "clusters": clusters,
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
                        help="Electrum candidate JSON")
    parser.add_argument("--image", required=True, type=Path,
                        help="source image opened once and read-only")
    parser.add_argument("--output", required=True, type=Path,
                        help="secret-free context analysis JSON")
    parser.add_argument("--context-bytes", type=int, default=DEFAULT_CONTEXT_BYTES)
    parser.add_argument("--max-window-bytes", type=int,
                        default=DEFAULT_MAX_WINDOW_BYTES)
    parser.add_argument("--standard", choices=_STANDARDS, default="ELECTRUM",
                        help="mnemonic standard (default: ELECTRUM)")
    parser.add_argument("--candidate-id",
                        help="analyze only this exact candidate id")
    parser.add_argument("--physical-start", type=int,
                        help="optionally restrict to one exact physical start")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if paths_refer_to_same_file(arguments.output, arguments.report):
        parser.error("output path resolves to source report path")
    if paths_refer_to_same_file(arguments.output, arguments.image):
        parser.error("output path resolves to input image path")
    try:
        report = json.loads(arguments.report.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError("report root must be an object")
        result = analyze_report(
            report, arguments.image, context_bytes=arguments.context_bytes,
            max_window_bytes=arguments.max_window_bytes,
            standard=arguments.standard, candidate_id=arguments.candidate_id,
            physical_start=arguments.physical_start)
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
