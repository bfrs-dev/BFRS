"""Bounded-memory recovery of validated mnemonic phrases from byte streams."""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import re
import signal
import unicodedata
from typing import Callable

from bfrs.core.worker_control import (
    abort_executor,
    iter_bounded_results,
    submit_process_future,
    validate_worker_count,
    wait_for_all_futures,
)

from .bip39_validator import BIP39Validator, WORD_COUNTS
from .electrum_seed_validator import ElectrumSeedValidator
from .electrum_v1_validator import ElectrumV1Validator
from .mnemonic_normalizer import electrum_normalize
from .mnemonic_candidate import MnemonicCandidate


# Python's ``\w`` does not include combining marks.  BIP39 wordlists are NFKD,
# so an already-decomposed accented word must remain one source token.  Marks
# cannot start a token and punctuation is deliberately excluded.
_COMBINING_MARK = (
    r"\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff"
    r"\u20d0-\u20ff\ufe20-\ufe2f\u3099\u309a"
)
_TOKEN = re.compile(
    rf"[^\W\d_](?:[^\W\d_]|[{_COMBINING_MARK}])*", re.UNICODE)
_DECODE_PASSES = (("utf-8", 0), ("utf-16-le", 0), ("utf-16-le", 1),
                  ("utf-16-be", 0), ("utf-16-be", 1))
_DOMAIN = b"BFRS-MNEMONIC-FINGERPRINT-V1\0"
_MAX_PARALLEL_OWNERSHIP = 16 * 1024 * 1024
_PREFILTER_MIN_RUN = 10
_PREFILTER_CONTEXT = 4096
_UNICODE_WHITESPACE = (
    " ",
    "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x1c", "\x1d", "\x1e", "\x1f",
    "\x85", "\xa0", "\u1680", "\u2000", "\u2001", "\u2002", "\u2003", "\u2004",
    "\u2005", "\u2006", "\u2007", "\u2008", "\u2009", "\u200a", "\u2028", "\u2029",
    "\u202f", "\u205f", "\u3000",
)
_ASCII_WHITESPACE_TRANSLATION = bytes.maketrans(
    bytes(range(256)),
    bytes(0x20 if byte in b" \t\n\v\f\r\x1c\x1d\x1e\x1f" else byte
          for byte in range(256)),
)
_PREFILTER_BATCH = 1024 * 1024
_WORKER_SCANNER: RawMnemonicScanner | None = None


def resolve_worker_count(workers: int) -> int:
    validate_worker_count(workers)
    return min(max((os.cpu_count() or 1) - 1, 1), 4) if workers == 0 else workers


@dataclass(frozen=True, slots=True)
class MnemonicSecret:
    """A deliberately non-printing container used only by the opt-in exporter."""

    _value: str = field(repr=False)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "MnemonicSecret(<redacted>)"


@dataclass(frozen=True, slots=True)
class MnemonicOccurrence:
    candidate: MnemonicCandidate
    secret: MnemonicSecret = field(repr=False)


@dataclass(frozen=True, slots=True)
class RawMnemonicScanResult:
    occurrences: tuple[MnemonicOccurrence, ...]
    anchors_found: int
    checksum_invalid: int
    failures: tuple[str, ...]
    prefilter_windows: int = 0
    expensive_validations: int = 0
    bip39_validations: int = 0
    electrum_validations: int = 0
    electrum_v1_validations: int = 0


def _initialize_worker(chunk_size: int, overlap: int) -> None:
    """Initialize immutable wordlist indexes once in each child process."""
    global _WORKER_SCANNER
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    _WORKER_SCANNER = RawMnemonicScanner(chunk_size=chunk_size, overlap=overlap)


def _scan_work_unit(unit: tuple[str, int, int, int, int]) -> RawMnemonicScanResult:
    path, scan_start, scan_end, ownership_start, ownership_end = unit
    if _WORKER_SCANNER is None:  # pragma: no cover - protects non-pool callers
        raise RuntimeError("mnemonic worker was not initialized")
    with Path(path).open("rb") as source:
        source.seek(scan_start)
        data = source.read(scan_end - scan_start)
    return _WORKER_SCANNER.scan_bytes(
        data, source=str(Path(path).resolve()), base_offset=scan_start,
        ownership_start=ownership_start, ownership_end=ownership_end)


def _scan_phase_work_unit(
    unit: tuple[bytes, str, int, str, int | None, int | None, tuple[str, int]],
) -> RawMnemonicScanResult:
    data, source, base_offset, source_kind, ownership_start, ownership_end, phase = unit
    if _WORKER_SCANNER is None:  # pragma: no cover - protects non-pool callers
        raise RuntimeError("mnemonic worker was not initialized")
    return _WORKER_SCANNER.scan_bytes(
        data,
        source=source,
        base_offset=base_offset,
        source_kind=source_kind,
        ownership_start=ownership_start,
        ownership_end=ownership_end,
        decode_passes=(phase,),
    )


UnitComplete = Callable[[tuple[str, int, int, int, int], RawMnemonicScanResult,
                         int, int], None]


class RawMnemonicScanner:
    """Scan overlapping chunks; retained state is bounded by one chunk and overlap."""

    def __init__(self, *, chunk_size: int = 64 * 1024 * 1024,
                 overlap: int = 64 * 1024, phase_workers: int = 1) -> None:
        if overlap < 4096:
            raise ValueError("mnemonic overlap must be at least 4096 bytes")
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.phase_workers = min(resolve_worker_count(phase_workers), len(_DECODE_PASSES))
        self._phase_executor: ProcessPoolExecutor | None = None
        self.bip39 = BIP39Validator()
        self.electrum = ElectrumSeedValidator()
        self.electrum_v1 = ElectrumV1Validator()
        membership: dict[str, list[int]] = {}
        for bit, words in enumerate(self.bip39.wordlists.values()):
            for word in words:
                membership.setdefault(word, [0, 0, 0])[0] |= 1 << bit
        for bit, words in enumerate(self.electrum.wordlists.values()):
            for word in words:
                membership.setdefault(word, [0, 0, 0])[1] |= 1 << bit
        for word in self.electrum_v1.wordlist:
            membership.setdefault(word, [0, 0, 0])[2] = 1
        self._membership = {word: (masks[0], masks[1], masks[2])
                            for word, masks in membership.items()}
        self._max_token_chars = max(map(len, self._membership))
        self._normalize_token = lru_cache(maxsize=8192)(self._normalize_token_uncached)
        encodings = {item[0] for item in _DECODE_PASSES}
        self._encoded_whitespace = {
            encoding: tuple(character.encode(encoding)
                            for character in _UNICODE_WHITESPACE)
            for encoding in encodings
        }
        self._max_encoded_token = {
            encoding: max(len(word.encode(encoding)) for word in self._membership)
            for encoding in encodings
        }
        self._encoded_membership = {
            encoding: frozenset(
                form.encode(encoding)
                for word in self._membership
                for form in (word, unicodedata.normalize("NFC", word), word.upper())
            )
            for encoding in encodings
        }
        self._encoded_word_index = {}
        for encoding, words in self._encoded_membership.items():
            mutable_index: dict[int, dict[int, set[bytes]]] = {}
            for word in words:
                mutable_index.setdefault(word[0], {}).setdefault(
                    len(word), set()).add(word)
            self._encoded_word_index[encoding] = {
                first: {length: frozenset(bucket)
                        for length, bucket in lengths.items()}
                for first, lengths in mutable_index.items()
            }

    @staticmethod
    def _normalize_token_uncached(token: str) -> tuple[str, str]:
        return (unicodedata.normalize("NFKD", token).casefold(),
                electrum_normalize(token))

    @staticmethod
    def _fingerprint(standard: str, normalized: str) -> str:
        material = _DOMAIN + standard.encode("ascii") + b"\0" + normalized.encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def scan_path(self, source: str | Path, *, start: int = 0,
                  end: int | None = None,
                  progress: Callable[[int, int], None] | None = None,
                  workers: int = 1,
                  resume_results: dict[tuple[int, int], RawMnemonicScanResult] | None = None,
                  unit_complete: UnitComplete | None = None) -> RawMnemonicScanResult:
        path = Path(source).resolve()
        range_end = path.stat().st_size if end is None else end
        worker_count = resolve_worker_count(workers)
        resumed = resume_results or {}
        if resumed:
            planned = {(unit[3], unit[4])
                       for unit in self._iter_work_units(path, start, range_end)}
            if set(resumed) - planned:
                raise ValueError("checkpoint contains incompatible ownership ranges")
        results = [(end_offset - start_offset, result)
                   for (start_offset, end_offset), result in resumed.items()]
        completed = sum(size for size, _ in results)
        total = range_end - start
        pending = (
            unit for unit in self._iter_work_units(path, start, range_end)
            if (unit[3], unit[4]) not in resumed
        )
        if progress is not None and completed:
            progress(completed, total)
        if worker_count == 1:
            for unit in pending:
                result = self._scan_local_unit(unit)
                owned = unit[4] - unit[3]
                results.append((owned, result))
                completed += owned
                if unit_complete is not None:
                    unit_complete(unit, result, completed, total)
                if progress is not None:
                    progress(completed, total)
        else:
            results.extend(self._scan_path_parallel(
                pending, worker_count, progress, unit_complete, completed, total))
        return self._merge_results(results)

    def _plan_work_units(self, source: Path, start: int, range_end: int
                         ) -> list[tuple[str, int, int, int, int]]:
        return list(self._iter_work_units(source, start, range_end))

    def _iter_work_units(self, source: Path, start: int, range_end: int
                         ) -> Iterator[tuple[str, int, int, int, int]]:
        step = min(self.chunk_size - self.overlap, _MAX_PARALLEL_OWNERSHIP)
        path = str(source)
        ownership_start = start
        while ownership_start < range_end:
            ownership_end = min(ownership_start + step, range_end)
            scan_end = min(ownership_end + self.overlap, range_end)
            if scan_end >= range_end:
                ownership_end = range_end
            yield (path, ownership_start, scan_end,
                   ownership_start, ownership_end)
            ownership_start = ownership_end

    def _scan_local_unit(self, unit: tuple[str, int, int, int, int]
                         ) -> RawMnemonicScanResult:
        path, scan_start, scan_end, ownership_start, ownership_end = unit
        with Path(path).open("rb") as source:
            source.seek(scan_start)
            data = source.read(scan_end - scan_start)
        return self.scan_bytes(data, source=path, base_offset=scan_start,
                               ownership_start=ownership_start,
                               ownership_end=ownership_end)

    def _scan_path_parallel(self, units: Iterable[tuple[str, int, int, int, int]],
                            workers: int, progress: Callable[[int, int], None] | None,
                            unit_complete: UnitComplete | None, completed: int, total: int
                            ) -> list[tuple[int, RawMnemonicScanResult]]:
        results: list[tuple[int, RawMnemonicScanResult]] = []
        executor = ProcessPoolExecutor(
            max_workers=workers, initializer=_initialize_worker,
            initargs=(self.chunk_size, self.overlap))
        try:
            for unit, result in iter_bounded_results(
                executor,
                units,
                submit=lambda pool, item: pool.submit(_scan_work_unit, item),
                unit_id=lambda item: f"ownership[{item[3]}..{item[4]})",
                workers=workers,
                operation="mnemonic path scan",
            ):
                owned = unit[4] - unit[3]
                results.append((owned, result))
                completed += owned
                if unit_complete is not None:
                    unit_complete(unit, result, completed, total)
                if progress is not None:
                    progress(completed, total)
        except BaseException:
            abort_executor(executor)
            raise
        else:
            executor.shutdown(wait=True)
        return results

    @staticmethod
    def _merge_results(results: list[tuple[int, RawMnemonicScanResult]]) -> RawMnemonicScanResult:
        occurrences: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = windows = validations = 0
        bip39_validations = electrum_validations = electrum_v1_validations = 0
        failures: list[str] = []
        for _, result in results:
            anchors += result.anchors_found
            invalid += result.checksum_invalid
            windows += result.prefilter_windows
            validations += result.expensive_validations
            bip39_validations += result.bip39_validations
            electrum_validations += result.electrum_validations
            electrum_v1_validations += result.electrum_v1_validations
            failures.extend(result.failures)
            for occurrence in result.occurrences:
                item = occurrence.candidate
                key = (item.encoding or "", item.physical_start or 0,
                       item.physical_end or 0, item.mnemonic_standard)
                occurrences[key] = occurrence
        ordered = tuple(occurrences[key] for key in sorted(occurrences))
        return RawMnemonicScanResult(ordered, anchors, invalid,
                                     tuple(sorted(set(failures))), windows, validations,
                                     bip39_validations, electrum_validations,
                                     electrum_v1_validations)

    def _prefilter_member(self, field: bytes, encoding: str) -> bool:
        """Cheap exact-word test used only to nominate a bounded validation region."""
        if not field or len(field) > self._max_encoded_token[encoding]:
            return False
        bucket = self._encoded_word_index[encoding].get(field[0], {}).get(len(field))
        if bucket is None:
            return False
        if field in bucket:
            return True
        try:
            original = field.decode(encoding, errors="strict")
        except UnicodeError:
            return False
        if not original.isalpha() or len(original) > self._max_token_chars:
            return False
        word, electrum_word = self._normalize_token(original)
        membership = self._membership.get(word, (0, 0, 0))
        return bool(membership[0] or membership[2] or membership[1] or
                    self._membership.get(electrum_word, (0, 0, 0))[1])

    @staticmethod
    def _merge_prefilter_region(regions: list[tuple[int, int]], start: int,
                                end: int) -> None:
        if regions and start <= regions[-1][1]:
            regions[-1] = (regions[-1][0], max(regions[-1][1], end))
        else:
            regions.append((start, end))

    def _prefilter_stream(self, transformed: bytes, encoding: str,
                          delimiter: bytes) -> tuple[tuple[int, int], ...]:
        """Nominate runs from an equal-length byte transform of the source."""
        run: deque[tuple[int, int]] = deque(maxlen=_PREFILTER_MIN_RUN)
        regions: list[tuple[int, int]] = []
        max_token = self._max_encoded_token[encoding]

        def process_field(field: bytes, field_start: int) -> None:
            if not field:
                return
            if not self._prefilter_member(field, encoding):
                run.clear()
                return
            field_end = field_start + len(field)
            run.append((field_start, field_end))
            if len(run) != _PREFILTER_MIN_RUN:
                return
            start = max(0, run[0][0] - _PREFILTER_CONTEXT)
            end = min(len(transformed), field_end + _PREFILTER_CONTEXT)
            if encoding != "utf-8":
                start -= start % 2
                end -= end % 2
            self._merge_prefilter_region(regions, start, end)

        carry = b""
        carry_start = 0
        in_long_field = False
        delimiter_length = len(delimiter)
        for block_start in range(0, len(transformed), _PREFILTER_BATCH):
            block = transformed[block_start:block_start + _PREFILTER_BATCH]
            parts = block.split(delimiter)
            if len(parts) == 1:
                if not in_long_field:
                    if len(carry) + len(block) <= max_token:
                        carry += block
                    else:
                        carry = b""
                        in_long_field = True
                        run.clear()
                continue

            first = parts[0]
            if in_long_field:
                run.clear()
            elif carry:
                process_field(carry + first, carry_start)
            else:
                process_field(first, block_start)

            cursor = block_start + len(first) + delimiter_length
            for field in parts[1:-1]:
                process_field(field, cursor)
                cursor += len(field) + delimiter_length

            carry = parts[-1]
            carry_start = cursor
            in_long_field = len(carry) > max_token
            if in_long_field:
                carry = b""
                run.clear()
        if carry and not in_long_field:
            process_field(carry, carry_start)
        return tuple(regions)

    def _prefilter_regions(self, encoded_data: bytes, encoding: str
                           ) -> tuple[tuple[int, int], ...]:
        """Find conservative byte regions which can contain at least 12 words.

        In a 12-word phrase, at least the ten interior whitespace-delimited
        fields are exact words even when punctuation touches both outer words.
        Context is one full overlap on each side, and overlapping triggers are
        merged before any Unicode tokenization or cryptographic validation.
        """
        if encoding == "utf-8":
            transformed = encoded_data.lower()
            for whitespace in self._encoded_whitespace[encoding]:
                if len(whitespace) > 1:
                    transformed = transformed.replace(
                        whitespace, b" " * len(whitespace))
            transformed = transformed.translate(_ASCII_WHITESPACE_TRANSLATION)
            return self._prefilter_stream(transformed, encoding, b" ")

        # Both bytes are nonzero so delimiter matching cannot begin on the
        # trailing NUL of an adjacent ASCII UTF-16 code unit.
        marker = b"\xff\xfe"
        transformed = bytearray(encoded_data)
        for whitespace in self._encoded_whitespace[encoding]:
            search_start = 0
            while True:
                position = encoded_data.find(whitespace, search_start)
                if position < 0:
                    break
                if position % 2 == 0:
                    transformed[position:position + 2] = marker
                search_start = position + 1
        return self._prefilter_stream(bytes(transformed), encoding, marker)

    def scan_bytes(self, data: bytes, *, source: str = "<memory>",
                   base_offset: int = 0, source_kind: str = "RAW_BYTES",
                   ownership_start: int | None = None,
                   ownership_end: int | None = None,
                   phase_progress: Callable[[str], None] | None = None,
                   decode_passes: tuple[tuple[str, int], ...] = _DECODE_PASSES,
                   _prefiltered: bool = False,
                   ) -> RawMnemonicScanResult:
        if self.phase_workers > 1 and len(decode_passes) > 1:
            return self._scan_bytes_parallel_phases(
                data,
                source=source,
                base_offset=base_offset,
                source_kind=source_kind,
                ownership_start=ownership_start,
                ownership_end=ownership_end,
                phase_progress=phase_progress,
                decode_passes=decode_passes,
            )
        found: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = prefilter_windows = expensive_validations = 0
        bip39_validations = electrum_validations = electrum_v1_validations = 0
        failures: list[str] = []
        # UTF-16 code units may begin at either byte phase within a raw chunk.
        # UTF-8 is deliberately scanned once; each UTF-16 endian is scanned at
        # phases 0 and 1, with phase_offset retained in every physical mapping.
        for encoding, phase_offset in decode_passes:
            if phase_progress is not None:
                phase_progress(
                    f"mnemonic:{encoding.replace('-', '')}-{phase_offset}")
            try:
                phase_data = data[phase_offset:]
                encoded_data = (phase_data if encoding == "utf-8" else
                                phase_data[:len(phase_data) // 2 * 2])
                if not _prefiltered:
                    regions = self._prefilter_regions(encoded_data, encoding)
                    prefilter_windows += len(regions)
                    for region_start, region_end in regions:
                        result = self.scan_bytes(
                            encoded_data[region_start:region_end],
                            source=source,
                            base_offset=(base_offset + phase_offset + region_start),
                            source_kind=source_kind,
                            ownership_start=ownership_start,
                            ownership_end=ownership_end,
                            decode_passes=((encoding, 0),),
                            _prefiltered=True,
                        )
                        anchors += result.anchors_found
                        invalid += result.checksum_invalid
                        expensive_validations += result.expensive_validations
                        bip39_validations += result.bip39_validations
                        electrum_validations += result.electrum_validations
                        electrum_v1_validations += result.electrum_v1_validations
                        failures.extend(result.failures)
                        for occurrence in result.occurrences:
                            candidate = occurrence.candidate
                            key = (candidate.encoding or "",
                                   candidate.physical_start or 0,
                                   candidate.physical_end or 0,
                                   candidate.mnemonic_standard)
                            found[key] = occurrence
                    continue
                error_mode = "surrogateescape" if encoding == "utf-8" else "surrogatepass"
                text = encoded_data.decode(encoding, errors=error_mode)
                # Token boundaries are mapped in one monotonic pass.  Each span is
                # encoded at most once, preserving the decoder's exact error policy
                # without a per-character offset table.
                window: deque[tuple[str, str, int, int, int, int, int, str]] = deque(maxlen=24)
                previous_end: int | None = None
                previous_v1_member = False
                previous_raw_end: int | None = None
                v1_run_length = 0
                char_cursor = byte_cursor = 0
                for match in _TOKEN.finditer(text):
                    original = match.group(0)
                    if len(original) > self._max_token_chars:
                        word = electrum_word = ""
                        bip_mask = electrum_mask = electrum_v1_member = 0
                    elif original.isascii():
                        word = electrum_word = original.casefold()
                        membership = self._membership.get(word, (0, 0, 0))
                        bip_mask, electrum_mask, electrum_v1_member = membership
                    else:
                        word, electrum_word = self._normalize_token(original)
                        membership = self._membership.get(word, (0, 0, 0))
                        bip_mask = membership[0]
                        electrum_mask = (membership[1] if electrum_word == word else
                                         self._membership.get(
                                             electrum_word, (0, 0, 0))[1])
                        electrum_v1_member = membership[2]
                    known = bool(bip_mask or electrum_mask or electrum_v1_member)
                    separator = "" if previous_end is None else text[previous_end:match.start()]
                    separator_invalid = (len(separator) > 32 or "\x00" in separator or
                                         any(character.isalnum() or character == "_"
                                             for character in separator))
                    if separator_invalid or not known:
                        window.clear()
                    previous_end = match.end()
                    raw_start = byte_cursor + len(text[char_cursor:match.start()].encode(
                        encoding, errors=error_mode))
                    raw_end = raw_start + len(original.encode(encoding, errors=error_mode))
                    char_cursor, byte_cursor = match.end(), raw_end
                    v1_extends_run = (bool(electrum_v1_member) and previous_v1_member and
                                      bool(separator) and len(separator) <= 32 and
                                      separator.isspace())
                    if v1_extends_run and previous_raw_end is not None:
                        # A V1 candidate is valid only when the entire maximal old-word
                        # run has exactly 12 or 24 words.  Invalidate a candidate that
                        # was tentatively emitted before a following word was observed.
                        previous_physical_end = (
                            base_offset + phase_offset + previous_raw_end)
                        for key in tuple(found):
                            if (key[0] == encoding and key[2] == previous_physical_end and
                                    key[3] == "ELECTRUM_V1"):
                                del found[key]
                                anchors -= 1
                        v1_run_length += 1
                    else:
                        v1_run_length = 1 if electrum_v1_member else 0
                    previous_v1_member = bool(electrum_v1_member)
                    previous_raw_end = raw_end
                    if not known:
                        continue
                    window.append((original, word, electrum_word, bip_mask, electrum_mask,
                                   raw_start, raw_end, separator))
                    available = tuple(window)
                    for count in range(12, min(24, len(available)) + 1):
                        selected = available[-count:]
                        physical_start = base_offset + phase_offset + selected[0][5]
                        physical_end = base_offset + phase_offset + selected[-1][6]
                        if ((ownership_start is not None and physical_start < ownership_start) or
                                (ownership_end is not None and physical_start >= ownership_end)):
                            continue
                        bip_languages = (1 << len(self.bip39.wordlists)) - 1
                        electrum_languages = (1 << len(self.electrum.wordlists)) - 1
                        for item in selected:
                            bip_languages &= item[3]
                            electrum_languages &= item[4]
                        validations = []
                        # Mnemonic words must be adjacent source tokens separated only
                        # by reasonable whitespace.  Punctuation, markup, and foreign
                        # tokens may never be filtered out to manufacture a phrase.
                        contiguous_source = all(
                            item[7] and len(item[7]) <= 32 and item[7].isspace()
                            for item in selected[1:])
                        bip39_span_integrity = electrum_span_integrity = False
                        if contiguous_source and (
                                bip_languages or electrum_languages or
                                (count in {12, 24} and v1_run_length == count)):
                            span_start, span_end = selected[0][5], selected[-1][6]
                            span_bytes = encoded_data[span_start:span_end]
                            span_text = span_bytes.decode(encoding, errors=error_mode)
                            span_parts = span_text.split()
                            normalized_parts = tuple(
                                (unicodedata.normalize("NFKD", part),
                                 electrum_normalize(part))
                                for part in span_parts
                            )
                            bip39_span_integrity = (
                                len(span_parts) == count and
                                tuple(item[0] for item in normalized_parts) ==
                                tuple(item[1] for item in selected)
                            )
                            electrum_span_integrity = (
                                len(span_parts) == count and
                                tuple(item[1] for item in normalized_parts) ==
                                tuple(item[2] for item in selected)
                            )
                        if (count in WORD_COUNTS and bip_languages and
                                contiguous_source and bip39_span_integrity):
                            words = tuple(item[1] for item in selected)
                            normalized = " ".join(words)
                            languages = tuple(name for bit, name in enumerate(self.bip39.wordlists)
                                              if bip_languages & (1 << bit))
                            validations.append(("BIP39", self.bip39.validate_words(
                                words, normalized=normalized, languages=languages)))
                        if (count in {12, 24} and v1_run_length == count and
                                contiguous_source and electrum_span_integrity and
                                all(item[2] in self.electrum_v1.indices for item in selected)):
                            words = tuple(item[2] for item in selected)
                            normalized = " ".join(words)
                            validations.append(("ELECTRUM_V1",
                                                self.electrum_v1.validate_words(
                                                    words, normalized=normalized)))
                        strict_v1 = any(
                            standard == "ELECTRUM_V1" and validation.status in {
                                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}
                            for standard, validation in validations)
                        if (electrum_languages and contiguous_source and
                                electrum_span_integrity and not strict_v1):
                            words = tuple(item[2] for item in selected)
                            languages = tuple(name for bit, name in enumerate(self.electrum.wordlists)
                                              if electrum_languages & (1 << bit))
                            validations.append(("ELECTRUM", self.electrum.validate_words(
                                words, languages=languages)))
                        expensive_validations += len(validations)
                        bip39_validations += sum(
                            standard == "BIP39" for standard, _ in validations)
                        electrum_validations += sum(
                            standard == "ELECTRUM" for standard, _ in validations)
                        electrum_v1_validations += sum(
                            standard == "ELECTRUM_V1" for standard, _ in validations)
                        for standard, validation in validations:
                            valid = validation.status in {
                                "BIP39_VALID", "ELECTRUM_SEED_VALID",
                                "ELECTRUM_V1_STRICT_VALID", "ELECTRUM_V1_COMPAT_VALID"}
                            if validation.status == "BIP39_CHECKSUM_INVALID":
                                invalid += 1
                            if not valid:
                                continue
                            anchors += 1
                            normalized = validation.normalized
                            fingerprint = self._fingerprint(standard, normalized)
                            candidate_id = hashlib.sha256(
                                f"{source}|{physical_start}|{physical_end}|{standard}|{fingerprint}"
                                .encode("utf-8")).hexdigest()[:24]
                            reason_codes = validation.reason_codes
                            if standard == "ELECTRUM_V1":
                                reason_codes += ("ELECTRUM_V1_SOURCE_SPAN_VALID",)
                            elif standard == "ELECTRUM":
                                reason_codes += ("ELECTRUM_SOURCE_SPAN_VALID",)
                            candidate = MnemonicCandidate(
                                candidate_id=candidate_id, family="MNEMONIC",
                                mnemonic_standard=standard,
                                validation_status=validation.status,
                                seed_type=getattr(validation, "seed_type", None),
                                language=validation.language,
                                word_count=validation.word_count,
                                checksum_valid=getattr(validation, "checksum_valid", None),
                                completeness="COMPLETE",
                                confidence=("MEDIUM" if standard == "ELECTRUM_V1" or
                                            source_kind == "RAW_BYTES" else "HIGH"),
                                reason_codes=reason_codes,
                                fingerprint=fingerprint, source_kind=source_kind,
                                source=source, physical_start=physical_start,
                                physical_end=physical_end, encoding=encoding,
                            )
                            key = (encoding, physical_start, physical_end, standard)
                            found[key] = MnemonicOccurrence(candidate, MnemonicSecret(normalized))
            except (UnicodeError, ValueError) as error:
                failures.append(f"{encoding}:{type(error).__name__}")
        return RawMnemonicScanResult(tuple(found.values()), anchors, invalid,
                                     tuple(dict.fromkeys(failures)),
                                     prefilter_windows, expensive_validations,
                                     bip39_validations, electrum_validations,
                                     electrum_v1_validations)

    def _scan_bytes_parallel_phases(
        self,
        data: bytes,
        *,
        source: str,
        base_offset: int,
        source_kind: str,
        ownership_start: int | None,
        ownership_end: int | None,
        phase_progress: Callable[[str], None] | None,
        decode_passes: tuple[tuple[str, int], ...],
    ) -> RawMnemonicScanResult:
        if self._phase_executor is None:
            self._phase_executor = ProcessPoolExecutor(
                max_workers=self.phase_workers,
                initializer=_initialize_worker,
                initargs=(self.chunk_size, self.overlap),
            )
        if phase_progress is not None:
            phase_progress(f"mnemonic:parallel-{self.phase_workers}")
        futures = []
        try:
            futures = [
                submit_process_future(
                    self._phase_executor, _scan_phase_work_unit,
                    (data, source, base_offset, source_kind,
                     ownership_start, ownership_end, phase),
                    operation="mnemonic decode",
                    unit_id=f"phase[{phase[0]}:{phase[1]}]",
                )
                for phase in decode_passes
            ]
            results = wait_for_all_futures(
                [(future, f"phase[{encoding}:{alignment}]")
                 for future, (encoding, alignment) in zip(futures, decode_passes)],
                operation="mnemonic decode",
            )
        except BaseException:
            executor = self._phase_executor
            abort_executor(executor, futures)
            self._phase_executor = None
            raise
        return self._merge_phase_results(results)

    @staticmethod
    def _merge_phase_results(
        results: list[RawMnemonicScanResult],
    ) -> RawMnemonicScanResult:
        found: dict[tuple[str, int, int, str], MnemonicOccurrence] = {}
        anchors = invalid = windows = validations = 0
        bip39_validations = electrum_validations = electrum_v1_validations = 0
        failures: list[str] = []
        for result in results:
            anchors += result.anchors_found
            invalid += result.checksum_invalid
            windows += result.prefilter_windows
            validations += result.expensive_validations
            bip39_validations += result.bip39_validations
            electrum_validations += result.electrum_validations
            electrum_v1_validations += result.electrum_v1_validations
            failures.extend(result.failures)
            for occurrence in result.occurrences:
                candidate = occurrence.candidate
                key = (
                    candidate.encoding or "",
                    candidate.physical_start or 0,
                    candidate.physical_end or 0,
                    candidate.mnemonic_standard,
                )
                found[key] = occurrence
        return RawMnemonicScanResult(
            tuple(found.values()), anchors, invalid,
            tuple(dict.fromkeys(failures)), windows, validations,
            bip39_validations, electrum_validations, electrum_v1_validations,
        )

    def close(self) -> None:
        if self._phase_executor is not None:
            self._phase_executor.shutdown(wait=True, cancel_futures=True)
            self._phase_executor = None

    def abort(self) -> None:
        """Cancel queued phase work without waiting for a stalled child."""
        if self._phase_executor is not None:
            abort_executor(self._phase_executor)
            self._phase_executor = None
